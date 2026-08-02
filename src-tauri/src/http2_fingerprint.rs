use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_CAPTURED_FRAME_BYTES: usize = 4 * 1024;
const MAX_SETTINGS: usize = 64;
const MAX_WINDOW_UPDATES: usize = 8;
const MAX_PRIORITY_FRAMES: usize = 16;
const MAX_PRIORITY_UPDATES: usize = 16;
const MAX_PRIORITY_FIELD_BYTES: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Http2Fingerprint {
    pub hash: String,
    pub canonical: String,
    pub settings: Vec<Http2Setting>,
    pub connection_window_updates: Vec<u32>,
    pub priority_frames: Vec<Http2PriorityFrame>,
    pub priority_updates: Vec<Http2PriorityUpdate>,
    pub pseudo_header_order: Option<Vec<String>>,
    pub complete: bool,
    pub note: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Http2Setting {
    pub id: u16,
    pub name: String,
    pub value: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Http2PriorityFrame {
    pub stream_id: u32,
    pub exclusive: bool,
    pub dependency: u32,
    pub weight: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Http2PriorityUpdate {
    pub prioritized_stream_id: u32,
    pub field_value: String,
}

#[derive(Default)]
pub struct Http2FingerprintCollector {
    state: Mutex<ObserverState>,
}

impl Http2FingerprintCollector {
    pub fn observe(&self, bytes: &[u8]) {
        if let Ok(mut state) = self.state.lock() {
            state.observe(bytes);
        }
    }

    pub fn snapshot(&self) -> Option<Http2Fingerprint> {
        self.state.lock().ok()?.snapshot()
    }
}

pub struct Http2ObservedIo<S> {
    inner: S,
    collector: std::sync::Arc<Http2FingerprintCollector>,
}

impl<S> Http2ObservedIo<S> {
    pub fn new(inner: S, collector: std::sync::Arc<Http2FingerprintCollector>) -> Self {
        Self { inner, collector }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Http2ObservedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let previous = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.collector.observe(&buffer.filled()[previous..]);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Http2ObservedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[derive(Default)]
struct ObserverState {
    preface_offset: usize,
    frame_header: [u8; 9],
    frame_header_offset: usize,
    frame: Option<ObservedFrame>,
    settings: Vec<Http2Setting>,
    connection_window_updates: Vec<u32>,
    priority_frames: Vec<Http2PriorityFrame>,
    priority_updates: Vec<Http2PriorityUpdate>,
    issues: Vec<String>,
    headers_seen: bool,
    stopped: bool,
}

struct ObservedFrame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    remaining: usize,
    payload: Vec<u8>,
    capture_payload: bool,
}

impl ObserverState {
    fn observe(&mut self, bytes: &[u8]) {
        for byte in bytes.iter().copied() {
            if self.stopped {
                return;
            }
            if self.preface_offset < CLIENT_PREFACE.len() {
                if byte != CLIENT_PREFACE[self.preface_offset] {
                    self.issues.push("HTTP/2 客户端连接前言不匹配".to_string());
                    self.stopped = true;
                    return;
                }
                self.preface_offset += 1;
                continue;
            }
            if let Some(frame) = self.frame.as_mut() {
                if frame.capture_payload {
                    frame.payload.push(byte);
                }
                frame.remaining -= 1;
                if frame.remaining == 0 {
                    let frame = self.frame.take().expect("observed frame exists");
                    self.finish_frame(frame);
                }
                continue;
            }

            self.frame_header[self.frame_header_offset] = byte;
            self.frame_header_offset += 1;
            if self.frame_header_offset != self.frame_header.len() {
                continue;
            }
            self.frame_header_offset = 0;
            let length = ((self.frame_header[0] as usize) << 16)
                | ((self.frame_header[1] as usize) << 8)
                | self.frame_header[2] as usize;
            let frame_type = self.frame_header[3];
            let flags = self.frame_header[4];
            let stream_id = u32::from_be_bytes([
                self.frame_header[5],
                self.frame_header[6],
                self.frame_header[7],
                self.frame_header[8],
            ]) & 0x7fff_ffff;

            if frame_type == 0x1 {
                self.headers_seen = true;
                self.stopped = true;
                continue;
            }
            let relevant = matches!(frame_type, 0x2 | 0x4 | 0x8 | 0x10);
            let capture_payload = relevant && length <= MAX_CAPTURED_FRAME_BYTES;
            if relevant && !capture_payload {
                self.issues.push(format!(
                    "HTTP/2 帧类型 0x{frame_type:02x} 的载荷超过 4 KiB 观察上限"
                ));
            }
            let frame = ObservedFrame {
                frame_type,
                flags,
                stream_id,
                remaining: length,
                payload: Vec::with_capacity(length.min(MAX_CAPTURED_FRAME_BYTES)),
                capture_payload,
            };
            if length == 0 {
                self.finish_frame(frame);
            } else {
                self.frame = Some(frame);
            }
        }
    }

    fn finish_frame(&mut self, frame: ObservedFrame) {
        if !frame.capture_payload {
            return;
        }
        match frame.frame_type {
            0x2 => self.observe_priority(frame),
            0x4 => self.observe_settings(frame),
            0x8 => self.observe_window_update(frame),
            0x10 => self.observe_priority_update(frame),
            _ => {}
        }
    }

    fn observe_settings(&mut self, frame: ObservedFrame) {
        if frame.flags & 0x1 != 0 {
            return;
        }
        if frame.stream_id != 0 || frame.payload.len() % 6 != 0 {
            self.issues.push("HTTP/2 SETTINGS 帧格式无效".to_string());
            return;
        }
        for setting in frame.payload.chunks_exact(6).take(MAX_SETTINGS) {
            let id = u16::from_be_bytes([setting[0], setting[1]]);
            self.settings.push(Http2Setting {
                id,
                name: setting_name(id).to_string(),
                value: u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]),
            });
        }
        if frame.payload.len() / 6 > MAX_SETTINGS {
            self.issues
                .push("HTTP/2 SETTINGS 项目超过 64 个观察上限".to_string());
        }
    }

    fn observe_window_update(&mut self, frame: ObservedFrame) {
        if frame.stream_id != 0 || frame.payload.len() != 4 {
            return;
        }
        if self.connection_window_updates.len() < MAX_WINDOW_UPDATES {
            self.connection_window_updates.push(
                u32::from_be_bytes([
                    frame.payload[0],
                    frame.payload[1],
                    frame.payload[2],
                    frame.payload[3],
                ]) & 0x7fff_ffff,
            );
        }
    }

    fn observe_priority(&mut self, frame: ObservedFrame) {
        if frame.stream_id == 0 || frame.payload.len() != 5 {
            return;
        }
        if self.priority_frames.len() >= MAX_PRIORITY_FRAMES {
            return;
        }
        let dependency_raw = u32::from_be_bytes([
            frame.payload[0],
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]);
        self.priority_frames.push(Http2PriorityFrame {
            stream_id: frame.stream_id,
            exclusive: dependency_raw & 0x8000_0000 != 0,
            dependency: dependency_raw & 0x7fff_ffff,
            weight: frame.payload[4] as u16 + 1,
        });
    }

    fn observe_priority_update(&mut self, frame: ObservedFrame) {
        if frame.payload.len() < 4 || self.priority_updates.len() >= MAX_PRIORITY_UPDATES {
            return;
        }
        let prioritized_stream_id = u32::from_be_bytes([
            frame.payload[0],
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]) & 0x7fff_ffff;
        let field = &frame.payload[4..frame.payload.len().min(4 + MAX_PRIORITY_FIELD_BYTES)];
        self.priority_updates.push(Http2PriorityUpdate {
            prioritized_stream_id,
            field_value: String::from_utf8_lossy(field).into_owned(),
        });
    }

    fn snapshot(&self) -> Option<Http2Fingerprint> {
        if self.preface_offset != CLIENT_PREFACE.len()
            || (!self.headers_seen && self.settings.is_empty())
        {
            return None;
        }
        let settings = self
            .settings
            .iter()
            .map(|setting| format!("{}:{}", setting.id, setting.value))
            .collect::<Vec<_>>()
            .join(";");
        let windows = self
            .connection_window_updates
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let priorities = self
            .priority_frames
            .iter()
            .map(|priority| {
                format!(
                    "{}:{}:{}:{}",
                    priority.stream_id,
                    u8::from(priority.exclusive),
                    priority.dependency,
                    priority.weight
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let priority_updates = self
            .priority_updates
            .iter()
            .map(|priority| {
                format!(
                    "{}:{}",
                    priority.prioritized_stream_id,
                    hex(priority.field_value.as_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let canonical = format!(
            "settings={settings}|window={windows}|priority={priorities}|priority_update={priority_updates}|pseudo=?"
        );
        let complete = self.headers_seen && !self.settings.is_empty() && self.issues.is_empty();
        let mut note = "记录首个 HEADERS 前的客户端 HTTP/2 连接帧；SETTINGS 顺序保留。Hyper 不暴露 HPACK 解码前的伪首部顺序，因此伪首部不参与哈希。".to_string();
        if !self.issues.is_empty() {
            note.push_str(" 观察限制：");
            note.push_str(&self.issues.join("；"));
        }
        Some(Http2Fingerprint {
            hash: hex(&Sha256::digest(canonical.as_bytes())),
            canonical,
            settings: self.settings.clone(),
            connection_window_updates: self.connection_window_updates.clone(),
            priority_frames: self.priority_frames.clone(),
            priority_updates: self.priority_updates.clone(),
            pseudo_header_order: None,
            complete,
            note,
        })
    }
}

fn setting_name(id: u16) -> &'static str {
    match id {
        1 => "HEADER_TABLE_SIZE",
        2 => "ENABLE_PUSH",
        3 => "MAX_CONCURRENT_STREAMS",
        4 => "INITIAL_WINDOW_SIZE",
        5 => "MAX_FRAME_SIZE",
        6 => "MAX_HEADER_LIST_SIZE",
        8 => "ENABLE_CONNECT_PROTOCOL",
        9 => "NO_RFC7540_PRIORITIES",
        _ => "UNKNOWN",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let length = payload.len();
        let mut bytes = vec![
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
            frame_type,
            flags,
        ];
        bytes.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn parses_fragmented_settings_window_and_priority_frames() {
        let collector = Http2FingerprintCollector::default();
        let mut bytes = CLIENT_PREFACE.to_vec();
        bytes.extend(frame(
            0x4,
            0,
            0,
            &[0, 1, 0, 0, 16, 0, 0, 4, 0, 96, 0, 0, 0, 8, 0, 0, 0, 1],
        ));
        bytes.extend(frame(0x8, 0, 0, &[0, 239, 0, 1]));
        bytes.extend(frame(0x2, 0, 3, &[0x80, 0, 0, 1, 15]));
        bytes.extend(frame(0x1, 0x4, 1, &[]));
        for chunk in bytes.chunks(3) {
            collector.observe(chunk);
        }

        let fingerprint = collector.snapshot().unwrap();
        assert!(fingerprint.complete);
        assert_eq!(
            fingerprint
                .settings
                .iter()
                .map(|setting| setting.id)
                .collect::<Vec<_>>(),
            vec![1, 4, 8]
        );
        assert_eq!(fingerprint.settings[1].value, 6_291_456);
        assert_eq!(fingerprint.connection_window_updates, vec![15_663_105]);
        assert_eq!(fingerprint.priority_frames[0].stream_id, 3);
        assert!(fingerprint.priority_frames[0].exclusive);
        assert_eq!(fingerprint.priority_frames[0].weight, 16);
        assert_eq!(fingerprint.hash.len(), 64);
        assert!(fingerprint.canonical.ends_with("|pseudo=?"));
        assert!(fingerprint.pseudo_header_order.is_none());
    }

    #[test]
    fn rejects_a_non_http2_preface_without_exposing_a_fingerprint() {
        let collector = Http2FingerprintCollector::default();
        collector.observe(b"GET / HTTP/1.1\r\n");
        assert!(collector.snapshot().is_none());
    }

    #[test]
    fn bounds_relevant_frame_payloads_without_blocking_later_bytes() {
        let collector = Http2FingerprintCollector::default();
        let mut bytes = CLIENT_PREFACE.to_vec();
        bytes.extend(frame(0x10, 0, 0, &vec![b'x'; MAX_CAPTURED_FRAME_BYTES + 1]));
        bytes.extend(frame(0x4, 0, 0, &[0, 2, 0, 0, 0, 0]));
        bytes.extend(frame(0x1, 0x4, 1, &[]));
        collector.observe(&bytes);
        let fingerprint = collector.snapshot().unwrap();
        assert!(!fingerprint.complete);
        assert!(fingerprint.note.contains("超过 4 KiB"));
        assert_eq!(fingerprint.settings[0].name, "ENABLE_PUSH");
    }
}
