use crate::http2_fingerprint::Http2Fingerprint;
use crate::storage::Storage;
use md5::Md5;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_CLIENT_HELLO_BYTES: usize = 256 * 1024;
const MAX_TLS_RECORDS: usize = 8;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsFingerprintRecord {
    pub capture_mode: String,
    pub inbound: ClientTlsFingerprint,
    pub outbound: OutboundTlsFingerprint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http2: Option<Http2Fingerprint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientTlsFingerprint {
    pub ja3: String,
    pub ja3_raw: String,
    pub ja4: String,
    pub ja4_raw: String,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub legacy_version: String,
    pub offered_versions: Vec<String>,
    pub cipher_suites: Vec<String>,
    pub extensions: Vec<String>,
    pub supported_groups: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub grease: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundTlsFingerprint {
    pub mode: String,
    pub profile: String,
    pub ja3: Option<String>,
    /// The stable half of the pair, and the only one worth comparing against
    /// `inbound.ja4`. JA3 covers the GREASE values Chrome randomises per
    /// connection, so inbound JA3 differs on every handshake — measured on one
    /// page load, sixteen distinct inbound JA3s carried one identical JA4. Until
    /// this field existed the measurement was computed and then dropped into the
    /// free-text note, so nothing could actually check the two sides matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fidelity_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated_alpn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_from_inbound: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja3_parity: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_protocol: Option<String>,
}

pub struct ClientHelloRead {
    pub bytes: Vec<u8>,
    pub fingerprint: Result<ClientTlsFingerprint, String>,
}

/// Why a ClientHello read failed, and whether anyone needs to hear about it.
///
/// A browser pre-opens CONNECT tunnels it may never use — pre-connect, a racing
/// connection that loses — and closes before sending a hello. `read_exact`
/// reports that as an EOF. The proxy stays quiet about it; a measurement tool
/// reports every failure. Carrying the reason as a field rather than a marker in
/// the message means a caller that forgets cannot corrupt its own output.
#[derive(Debug)]
pub struct ClientHelloError {
    pub message: String,
    pub abandoned: bool,
}

impl std::fmt::Display for ClientHelloError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn client_hello_read_error(error: &std::io::Error, context: &str) -> ClientHelloError {
    ClientHelloError {
        message: format!("{context}: {error}"),
        abandoned: matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::NotConnected
        ),
    }
}

pub async fn read_client_hello<R>(stream: &mut R) -> Result<ClientHelloRead, ClientHelloError>
where
    R: AsyncRead + Unpin,
{
    let mut wire_bytes = Vec::new();
    let mut handshake_bytes = Vec::new();

    for _ in 0..MAX_TLS_RECORDS {
        let mut header = [0_u8; 5];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|error| client_hello_read_error(&error, "读取 TLS ClientHello 失败"))?;
        wire_bytes.extend_from_slice(&header);

        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if record_len == 0 || wire_bytes.len() + record_len > MAX_CLIENT_HELLO_BYTES {
            return Ok(ClientHelloRead {
                bytes: wire_bytes,
                fingerprint: Err("TLS ClientHello 长度无效或超过 256 KiB 限制".to_string()),
            });
        }
        let mut record = vec![0_u8; record_len];
        stream
            .read_exact(&mut record)
            .await
            .map_err(|error| client_hello_read_error(&error, "TLS ClientHello 记录不完整"))?;
        wire_bytes.extend_from_slice(&record);

        if header[0] != 22 {
            return Ok(ClientHelloRead {
                bytes: wire_bytes,
                fingerprint: Err(format!(
                    "CONNECT 后首个记录不是 TLS Handshake（类型 {}）",
                    header[0]
                )),
            });
        }
        handshake_bytes.extend_from_slice(&record);

        if handshake_bytes.len() >= 4 {
            if handshake_bytes[0] != 1 {
                return Ok(ClientHelloRead {
                    bytes: wire_bytes,
                    fingerprint: Err(format!(
                        "TLS 首个握手消息不是 ClientHello（类型 {}）",
                        handshake_bytes[0]
                    )),
                });
            }
            let hello_len = ((handshake_bytes[1] as usize) << 16)
                | ((handshake_bytes[2] as usize) << 8)
                | handshake_bytes[3] as usize;
            if hello_len + 4 > MAX_CLIENT_HELLO_BYTES {
                return Ok(ClientHelloRead {
                    bytes: wire_bytes,
                    fingerprint: Err("TLS ClientHello 消息超过 256 KiB 限制".to_string()),
                });
            }
            if handshake_bytes.len() >= hello_len + 4 {
                return Ok(ClientHelloRead {
                    bytes: wire_bytes,
                    fingerprint: parse_client_hello(&handshake_bytes[..hello_len + 4]),
                });
            }
        }
    }

    Ok(ClientHelloRead {
        bytes: wire_bytes,
        fingerprint: Err("TLS ClientHello 跨越过多记录".to_string()),
    })
}

pub fn mitm_fingerprint(inbound: ClientTlsFingerprint) -> TlsFingerprintRecord {
    mitm_fingerprint_with_selection(inbound, None, None, None)
}

/// Build MITM fingerprint using the resolved outbound profile and optional negotiated ALPN/app protocol.
pub fn mitm_fingerprint_with_selection(
    inbound: ClientTlsFingerprint,
    profile: Option<crate::tls_outbound::OutboundTlsProfile>,
    selected_from_inbound: Option<bool>,
    negotiated_alpn: Option<String>,
) -> TlsFingerprintRecord {
    let (resolved, from_inbound) = match profile {
        Some(p) => (p, selected_from_inbound.unwrap_or(false)),
        None => crate::tls_outbound::resolve_profile_for_connection(Some(&inbound)),
    };
    let engine = crate::tls_outbound::active_engine();
    let app_protocol = negotiated_alpn.as_deref().map(|alpn| {
        if alpn.eq_ignore_ascii_case("h2") {
            "h2".to_string()
        } else {
            "http/1.1".to_string()
        }
    });
    TlsFingerprintRecord {
        capture_mode: "mitm".to_string(),
        inbound,
        outbound: OutboundTlsFingerprint {
            mode: if from_inbound {
                "mapped-from-inbound".to_string()
            } else {
                "independent".to_string()
            },
            profile: resolved.as_str().to_string(),
            // Measured after connect_verified_tls_measured; never pre-filled.
            ja3: None,
            ja4: None,
            note: format!(
                "{} 入站 ClientHello 用于分析与档位选择；目标站看到的是 ShowNet 出站握手（engine={}）。parity 仅在实测 JA3 与浏览器目标一致时为真。",
                resolved.note(),
                engine.as_str()
            ),
            fidelity_label: Some(resolved.fidelity_label().to_string()),
            engine: Some(engine.as_str().to_string()),
            negotiated_alpn,
            selected_from_inbound: Some(from_inbound),
            // Never pre-claim parity before measured ClientHello (always false/None until measure).
            ja3_parity: Some(false),
            application_protocol: app_protocol,
        },
        http2: None,
    }
}

pub fn tunnel_fingerprint(inbound: ClientTlsFingerprint) -> TlsFingerprintRecord {
    let client_ja3 = inbound.ja3.clone();
    // Pass-through means the origin receives the client's own ClientHello, so the
    // two sides are the same handshake by definition — the one case where parity
    // needs no measurement.
    let client_ja4 = inbound.ja4.clone();
    TlsFingerprintRecord {
        capture_mode: "tunnel".to_string(),
        inbound,
        outbound: OutboundTlsFingerprint {
            mode: "pass-through".to_string(),
            profile: "client-pass-through".to_string(),
            ja3: Some(client_ja3),
            ja4: Some(client_ja4),
            note: "目标站收到客户端原始 ClientHello；ShowNet 不终止 TLS，因此无法读取请求正文。"
                .to_string(),
            fidelity_label: Some("pass-through-client-ja3".into()),
            engine: Some("pass-through".into()),
            negotiated_alpn: None,
            selected_from_inbound: Some(false),
            ja3_parity: Some(true),
            application_protocol: None,
        },
        http2: None,
    }
}

/// List stored TLS fingerprints for a session (UI + agent tool shared path).
///
/// Returns `{ inboundFingerprints: [...], outbound: status, boundaryNote }` matching
/// the Advanced Console / agent tool contract.
pub fn list_session_tls_fingerprints(storage: &Storage, session_id: &str) -> Result<Value, String> {
    let session_id = session_id.trim();
    if session_id.is_empty() {
        return Err("sessionId 不能为空".into());
    }
    let fingerprints = storage
        .list_requests(session_id, Some(10_000), Some(0))?
        .into_iter()
        .filter_map(|request| {
            request.tls_fingerprint.map(|fingerprint| {
                json!({
                    "requestId": request.id,
                    "order": request.order,
                    "host": request.host,
                    "path": request.path,
                    "fingerprint": fingerprint,
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "inboundFingerprints": fingerprints,
        "outbound": crate::tls_outbound::status_json(),
        "boundaryNote": "Inbound JA3/JA4 is browser-side; outbound MITM profile is independent and labeled under outbound.fidelityLabel.",
    }))
}

/// Parse a TLS handshake ClientHello message (type 1, without record layer).
pub fn fingerprint_client_hello_handshake(message: &[u8]) -> Result<ClientTlsFingerprint, String> {
    parse_client_hello(message)
}

/// Parse ClientHello from one or more TLS records (content type 22).
pub fn fingerprint_client_hello_wire(records: &[u8]) -> Result<ClientTlsFingerprint, String> {
    let mut handshake = Vec::new();
    let mut offset = 0usize;
    while offset + 5 <= records.len() {
        let content_type = records[offset];
        let record_len = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;
        offset += 5;
        if offset + record_len > records.len() {
            break;
        }
        if content_type == 22 {
            handshake.extend_from_slice(&records[offset..offset + record_len]);
        }
        offset += record_len;
        if handshake.len() >= 4 && handshake[0] == 1 {
            let hello_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if handshake.len() >= hello_len + 4 {
                return parse_client_hello(&handshake[..hello_len + 4]);
            }
        }
    }
    Err("wire bytes 中未找到完整 ClientHello".into())
}

fn parse_client_hello(message: &[u8]) -> Result<ClientTlsFingerprint, String> {
    let mut reader = Reader::new(message);
    if reader.u8()? != 1 {
        return Err("不是 TLS ClientHello".to_string());
    }
    let body_len = reader.u24()?;
    if body_len != reader.remaining() {
        return Err("TLS ClientHello 声明长度不匹配".to_string());
    }

    let legacy_version = reader.u16()?;
    reader.take(32)?;
    let session_len = reader.u8()? as usize;
    reader.take(session_len)?;
    let cipher_bytes = reader.vector_u16()?;
    let cipher_suites = parse_u16_list(cipher_bytes, "密码套件")?;
    let compression_len = reader.u8()? as usize;
    reader.take(compression_len)?;

    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut point_formats = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut offered_versions = Vec::new();
    let mut sni = None;
    let mut alpn = Vec::new();

    if reader.remaining() > 0 {
        let extension_block = reader.vector_u16()?;
        let mut extension_reader = Reader::new(extension_block);
        while extension_reader.remaining() > 0 {
            let extension_type = extension_reader.u16()?;
            let extension_data = extension_reader.vector_u16()?;
            extensions.push(extension_type);
            match extension_type {
                0 => sni = parse_sni(extension_data)?,
                10 => supported_groups = parse_u16_vector(extension_data, "supported_groups")?,
                11 => point_formats = parse_u8_vector(extension_data, "ec_point_formats")?,
                13 => {
                    signature_algorithms = parse_u16_vector(extension_data, "signature_algorithms")?
                }
                16 => alpn = parse_alpn(extension_data)?,
                43 => offered_versions = parse_supported_versions(extension_data)?,
                _ => {}
            }
        }
    }
    if reader.remaining() != 0 {
        return Err("TLS ClientHello 尾部包含未解析数据".to_string());
    }

    let filtered_ciphers = without_grease(&cipher_suites);
    let filtered_extensions = without_grease(&extensions);
    let filtered_groups = without_grease(&supported_groups);
    let ja3_raw = format!(
        "{},{},{},{},{}",
        legacy_version,
        decimal_list(&filtered_ciphers),
        decimal_list(&filtered_extensions),
        decimal_list(&filtered_groups),
        point_formats
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-")
    );
    let ja3 = hex_digest::<Md5>(ja3_raw.as_bytes());

    let version = highest_tls_version(&offered_versions).unwrap_or(legacy_version);
    let alpn_code = ja4_alpn_code(alpn.first().map(String::as_str));
    let ja4_a = format!(
        "t{}{}{:02}{:02}{}",
        ja4_version(version),
        if sni.is_some() { 'd' } else { 'i' },
        filtered_ciphers.len().min(99),
        filtered_extensions.len().min(99),
        alpn_code
    );
    let sorted_ciphers = sorted_hex_list(&filtered_ciphers);
    let ja4_extensions = filtered_extensions
        .iter()
        .copied()
        .filter(|value| !matches!(value, 0 | 16))
        .collect::<Vec<_>>();
    let sorted_extensions = sorted_hex_list(&ja4_extensions);
    let signature_list = hex_list(&without_grease(&signature_algorithms));
    let ja4_b = short_sha256(&sorted_ciphers);
    let ja4_c_input = format!("{sorted_extensions}_{signature_list}");
    let ja4_c = short_sha256(&ja4_c_input);
    let ja4 = format!("{ja4_a}_{ja4_b}_{ja4_c}");
    let ja4_raw = format!("{ja4_a}_{sorted_ciphers}_{ja4_c_input}");

    let grease = cipher_suites
        .iter()
        .chain(&extensions)
        .chain(&supported_groups)
        .any(|value| is_grease(*value));

    Ok(ClientTlsFingerprint {
        ja3,
        ja3_raw,
        ja4,
        ja4_raw,
        sni,
        alpn,
        legacy_version: tls_version_name(legacy_version),
        offered_versions: offered_versions
            .iter()
            .map(|value| tls_version_name(*value))
            .collect(),
        cipher_suites: cipher_suites
            .iter()
            .map(|value| format!("{value:04x}"))
            .collect(),
        extensions: extensions
            .iter()
            .map(|value| format!("{value:04x}"))
            .collect(),
        supported_groups: supported_groups
            .iter()
            .map(|value| format!("{value:04x}"))
            .collect(),
        signature_algorithms: signature_algorithms
            .iter()
            .map(|value| format!("{value:04x}"))
            .collect(),
        grease,
    })
}

fn parse_sni(data: &[u8]) -> Result<Option<String>, String> {
    let mut reader = Reader::new(data);
    let list = reader.vector_u16()?;
    let mut names = Reader::new(list);
    while names.remaining() > 0 {
        let name_type = names.u8()?;
        let name = names.vector_u16()?;
        if name_type == 0 {
            return String::from_utf8(name.to_vec())
                .map(Some)
                .map_err(|_| "SNI 不是有效 UTF-8".to_string());
        }
    }
    Ok(None)
}

fn parse_alpn(data: &[u8]) -> Result<Vec<String>, String> {
    let mut reader = Reader::new(data);
    let list = reader.vector_u16()?;
    let mut protocols = Reader::new(list);
    let mut result = Vec::new();
    while protocols.remaining() > 0 {
        let length = protocols.u8()? as usize;
        let protocol = protocols.take(length)?;
        result.push(String::from_utf8_lossy(protocol).to_string());
    }
    Ok(result)
}

fn parse_supported_versions(data: &[u8]) -> Result<Vec<u16>, String> {
    let mut reader = Reader::new(data);
    let length = reader.u8()? as usize;
    let versions = reader.take(length)?;
    parse_u16_list(versions, "supported_versions")
}

fn parse_u16_vector(data: &[u8], field: &str) -> Result<Vec<u16>, String> {
    let mut reader = Reader::new(data);
    let values = reader.vector_u16()?;
    if reader.remaining() != 0 {
        return Err(format!("{field} 扩展长度无效"));
    }
    parse_u16_list(values, field)
}

fn parse_u8_vector(data: &[u8], field: &str) -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(data);
    let length = reader.u8()? as usize;
    let values = reader.take(length)?.to_vec();
    if reader.remaining() != 0 {
        return Err(format!("{field} 扩展长度无效"));
    }
    Ok(values)
}

fn parse_u16_list(data: &[u8], field: &str) -> Result<Vec<u16>, String> {
    if data.len() % 2 != 0 {
        return Err(format!("{field} 列表长度不是偶数"));
    }
    Ok(data
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect())
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}

fn decimal_list(values: &[u16]) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn sorted_hex_list(values: &[u16]) -> String {
    let mut values = values.to_vec();
    values.sort_unstable();
    hex_list(&values)
}

fn hex_digest<D: Digest + Default>(input: &[u8]) -> String {
    let mut digest = D::new();
    digest.update(input);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn short_sha256(input: &str) -> String {
    hex_digest::<Sha256>(input.as_bytes())[..12].to_string()
}

fn highest_tls_version(versions: &[u16]) -> Option<u16> {
    versions
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .max()
}

fn ja4_version(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    }
}

fn tls_version_name(version: u16) -> String {
    match version {
        0x0304 => "TLS 1.3".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        _ if is_grease(version) => format!("GREASE {version:04x}"),
        _ => format!("0x{version:04x}"),
    }
}

fn ja4_alpn_code(alpn: Option<&str>) -> String {
    let Some(alpn) = alpn.filter(|value| !value.is_empty()) else {
        return "00".to_string();
    };
    let first = alpn.as_bytes()[0];
    let last = *alpn.as_bytes().last().unwrap_or(&first);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        format!("{}{}", first as char, last as char)
    } else {
        format!("{first:02x}{last:02x}")
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| "TLS 长度溢出".to_string())?;
        if end > self.bytes.len() {
            return Err("TLS ClientHello 数据不完整".to_string());
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let value = self.take(2)?;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }

    fn u24(&mut self) -> Result<usize, String> {
        let value = self.take(3)?;
        Ok(((value[0] as usize) << 16) | ((value[1] as usize) << 8) | value[2] as usize)
    }

    fn vector_u16(&mut self) -> Result<&'a [u8], String> {
        let length = self.u16()? as usize;
        self.take(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_abandoned_connection_is_flagged_but_a_stalled_one_is_not() {
        use std::io::ErrorKind;
        // A browser pre-opens CONNECT tunnels it may never use, then closes
        // before sending a ClientHello. read_exact reports that as an EOF, and
        // it used to reach the user as "读取 TLS ClientHello 失败: …".
        for kind in [
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::NotConnected,
        ] {
            let error =
                client_hello_read_error(&std::io::Error::from(kind), "读取 TLS ClientHello 失败");
            assert!(error.abandoned, "{kind:?} is a client that went away");
            assert!(error.message.starts_with("读取 TLS ClientHello 失败: "));
        }

        // A stalled or broken peer is a real problem and still reports.
        for kind in [ErrorKind::TimedOut, ErrorKind::InvalidData] {
            let error =
                client_hello_read_error(&std::io::Error::from(kind), "TLS ClientHello 记录不完整");
            assert!(!error.abandoned, "{kind:?} must still be reported");
        }

        // Display is the message, so a caller that just prints it cannot leak
        // the reason flag into output.
        let error =
            client_hello_read_error(&std::io::Error::from(ErrorKind::UnexpectedEof), "读取失败");
        assert_eq!(format!("{error}"), error.message);
    }

    #[test]
    fn recognizes_all_grease_codepoints() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0a1a));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn parses_client_hello_and_generates_stable_fingerprints() {
        let message = fixture_client_hello();
        let parsed = parse_client_hello(&message).unwrap();

        assert_eq!(parsed.sni.as_deref(), Some("api.example.test"));
        assert_eq!(parsed.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(
            parsed.offered_versions,
            vec!["GREASE 0a0a", "TLS 1.3", "TLS 1.2"]
        );
        assert!(parsed.grease);
        assert_eq!(parsed.ja3_raw, "771,4865-4866,0-10-11-13-16-43,29-23,0");
        assert_eq!(parsed.ja3.len(), 32);
        assert!(parsed.ja4.starts_with("t13d0206h2_"));
        assert_eq!(parsed.ja4.split('_').count(), 3);
    }

    #[tokio::test]
    async fn reads_client_hello_split_across_tls_records_without_changing_bytes() {
        let message = fixture_client_hello();
        let mut wire = tls_record(&message[..24]);
        wire.extend_from_slice(&tls_record(&message[24..]));
        let mut input = wire.as_slice();

        let read = read_client_hello(&mut input).await.unwrap();

        assert_eq!(read.bytes, wire);
        assert_eq!(
            read.fingerprint.unwrap().sni.as_deref(),
            Some("api.example.test")
        );
    }

    fn fixture_client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0);
        push_u16_vector(&mut body, &[0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[1, 0]);

        let mut extensions = Vec::new();
        let hostname = b"api.example.test";
        let mut sni = Vec::new();
        let name_list_len = 1 + 2 + hostname.len();
        sni.extend_from_slice(&(name_list_len as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni.extend_from_slice(hostname);
        push_extension(&mut extensions, 0, &sni);
        push_extension(&mut extensions, 10, &[0, 6, 0x0a, 0x0a, 0, 29, 0, 23]);
        push_extension(&mut extensions, 11, &[1, 0]);
        push_extension(&mut extensions, 13, &[0, 4, 4, 3, 8, 4]);
        push_extension(
            &mut extensions,
            16,
            &[
                0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
            ],
        );
        push_extension(&mut extensions, 43, &[6, 0x0a, 0x0a, 3, 4, 3, 3]);
        push_u16_vector(&mut body, &extensions);

        let mut message = vec![1];
        let length = body.len();
        message.extend_from_slice(&[
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
        ]);
        message.extend_from_slice(&body);
        message
    }

    fn push_u16_vector(target: &mut Vec<u8>, value: &[u8]) {
        target.extend_from_slice(&(value.len() as u16).to_be_bytes());
        target.extend_from_slice(value);
    }

    fn push_extension(target: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        target.extend_from_slice(&extension_type.to_be_bytes());
        push_u16_vector(target, value);
    }

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }
}
