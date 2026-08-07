//! Loopback ClientHello probe — the capture end of the golden workflow.
//!
//! Phase 0 of `docs/plan-real-browser-ja3-impersonate.md`. A golden is a
//! fingerprint captured from the *target client itself*, so the probe has to be
//! a server: it accepts a connection, records the first flight, and parses it.
//!
//! It deliberately never completes the handshake. Only the ClientHello carries
//! JA3/JA4 material, so there is nothing to gain from replying — and skipping the
//! reply means the probe needs no certificate and no trust relationship with the
//! client. A real browser pointed at this listener will show a certificate error
//! *after* the flight we already captured.
//!
//! This is a normal module rather than `#[cfg(test)]` because the capture tool
//! that populates `testdata/tls-golden/` needs it too.

use crate::tls_fingerprint::{read_client_hello, ClientTlsFingerprint};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// One captured first flight.
pub struct CapturedClientHello {
    pub fingerprint: ClientTlsFingerprint,
    /// Raw wire bytes of the ClientHello record(s), exactly as received.
    pub raw: Vec<u8>,
    pub peer: SocketAddr,
}

impl CapturedClientHello {
    pub fn raw_hex(&self) -> String {
        self.raw.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The `golden` sub-object of a `testdata/tls-golden` entry, ready to paste.
    ///
    /// Emitting it from the capture rather than having a human transcribe four
    /// fingerprint strings is the point: a mistyped golden is a silently wrong gate.
    pub fn to_golden_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ja3": self.fingerprint.ja3,
            "ja3Raw": self.fingerprint.ja3_raw,
            "ja4": self.fingerprint.ja4,
            "ja4Raw": self.fingerprint.ja4_raw,
            "clientHelloHex": self.raw_hex(),
        })
    }
}

/// A loopback listener that records ClientHellos.
pub struct ClientHelloProbe {
    listener: TcpListener,
}

impl ClientHelloProbe {
    /// Bind an ephemeral loopback port. Loopback-only by construction — a probe
    /// that recorded handshakes from the network would be a capture surface of
    /// its own.
    pub async fn bind_loopback() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| format!("探针监听失败: {error}"))?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, String> {
        self.listener
            .local_addr()
            .map_err(|error| format!("读取探针地址失败: {error}"))
    }

    /// Accept one connection and capture its ClientHello. The connection is
    /// dropped immediately afterwards; the peer sees the handshake abort.
    pub async fn capture_one(&self) -> Result<CapturedClientHello, String> {
        let (mut stream, peer) = self
            .listener
            .accept()
            .await
            .map_err(|error| format!("探针接受连接失败: {error}"))?;
        Self::capture_from(&mut stream, peer).await
    }

    /// `capture_one` with a deadline, so a client that connects but never speaks
    /// cannot hang a capture session or a test.
    pub async fn capture_one_within(
        &self,
        budget: Duration,
    ) -> Result<CapturedClientHello, String> {
        tokio::time::timeout(budget, self.capture_one())
            .await
            .map_err(|_| format!("探针在 {budget:?} 内未捕获到 ClientHello"))?
    }

    async fn capture_from(
        stream: &mut TcpStream,
        peer: SocketAddr,
    ) -> Result<CapturedClientHello, String> {
        // The probe is a measurement tool: a connection that went away is a
        // failed measurement and must be reported. Strip the marker the proxy
        // uses to stay quiet about the same event, so it cannot reach output.
        let read = read_client_hello(stream)
            .await
            .map_err(|error| crate::proxy::split_failure_report(error).1)?;
        let fingerprint = read.fingerprint?;
        Ok(CapturedClientHello {
            fingerprint,
            raw: read.bytes,
            peer,
        })
    }
}

/// Measure what the **rustls recipe path** emits for a catalog preset.
///
/// This is a development instrument: the result is *not* a browser/tool golden
/// and must never be written into an entry as `tool-matched` or `browser-matched`.
/// Use it to confirm the probe + fingerprint pipeline and to record recipe-only
/// wire differences between presets.
pub async fn measure_rustls_preset(preset_id: &str) -> Result<CapturedClientHello, String> {
    use crate::tls_outbound;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    tls_outbound::set_active_preset(preset_id)?;
    let config = tls_outbound::build_client_config_for_preset(preset_id)?;
    let probe = ClientHelloProbe::bind_loopback().await?;
    let addr = probe.local_addr()?;
    let sni = format!("probe.{preset_id}.local");
    let server_name =
        ServerName::try_from(sni.clone()).map_err(|error| format!("invalid SNI: {error}"))?;

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(addr).await?;
        let _ = TlsConnector::from(config).connect(server_name, tcp).await;
        Ok::<(), std::io::Error>(())
    });

    let captured = probe
        .capture_one_within(Duration::from_secs(5))
        .await
        .map_err(|error| format!("rustls measure failed for {preset_id}: {error}"))?;
    let _ = client.await;
    Ok(captured)
}

/// Wait for an *external* TLS client (curl-impersonate, browser, etc.) to connect
/// to a loopback probe and return the first ClientHello.
///
/// Prints the listen address as a single line `PROBE_ADDR host:port` on stderr so
/// a driver script can point the tool at it.
pub async fn wait_for_external_client(
    budget: Duration,
) -> Result<(SocketAddr, CapturedClientHello), String> {
    let probe = ClientHelloProbe::bind_loopback().await?;
    let addr = probe.local_addr()?;
    eprintln!("PROBE_ADDR {addr}");
    let captured = probe.capture_one_within(budget).await?;
    Ok((addr, captured))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_outbound;
    use std::sync::OnceLock;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    /// Preset selection is process-global; serialise tests that move it.
    ///
    /// tokio's mutex rather than std's: the guard is deliberately held across
    /// awaits (the whole capture must be serialised, not just the preset write),
    /// and a std guard held across an await point is a deadlock waiting to happen
    /// on a multi-threaded runtime.
    async fn preset_lock() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await
    }

    /// Drive one outbound handshake at the probe using a catalog preset and
    /// return what the probe observed on the wire.
    async fn capture_preset(preset_id: &str, sni: &str) -> CapturedClientHello {
        tls_outbound::set_active_preset(preset_id).unwrap();
        let config = tls_outbound::build_client_config_for_preset(preset_id).unwrap();
        let probe = ClientHelloProbe::bind_loopback().await.unwrap();
        let addr = probe.local_addr().unwrap();

        let server_name = ServerName::try_from(sni.to_string()).unwrap();
        // The handshake cannot complete — the probe never replies — so this task
        // is expected to end in an error. We only care that the flight was sent.
        let client = tokio::spawn(async move {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let _ = TlsConnector::from(config).connect(server_name, tcp).await;
        });

        let captured = probe
            .capture_one_within(Duration::from_secs(5))
            .await
            .expect("probe captured a ClientHello");
        let _ = client.await;
        captured
    }

    #[tokio::test]
    async fn captures_and_parses_a_real_client_hello() {
        let _guard = preset_lock().await;
        let captured = capture_preset("chrome150", "probe.chrome150.test").await;

        assert_eq!(captured.fingerprint.ja3.len(), 32, "ja3 is an md5 digest");
        assert!(captured
            .fingerprint
            .ja3
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
        assert!(!captured.fingerprint.ja3_raw.is_empty());
        assert!(!captured.fingerprint.ja4.is_empty());
        assert!(captured.peer.ip().is_loopback());

        // SNI must survive, otherwise the capture cannot be attributed to a host.
        assert_eq!(
            captured.fingerprint.sni.as_deref(),
            Some("probe.chrome150.test")
        );

        // The raw flight is the authoritative artefact; it must start with a TLS
        // handshake record and round-trip through hex.
        assert_eq!(
            captured.raw[0], 22,
            "first byte is the handshake record type"
        );
        let hex = captured.raw_hex();
        assert_eq!(hex.len(), captured.raw.len() * 2);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn golden_json_matches_the_parsed_fingerprint() {
        let _guard = preset_lock().await;
        let captured = capture_preset("chrome150", "probe.golden.test").await;
        let golden = captured.to_golden_json();

        assert_eq!(golden["ja3"], captured.fingerprint.ja3);
        assert_eq!(golden["ja3Raw"], captured.fingerprint.ja3_raw);
        assert_eq!(golden["ja4"], captured.fingerprint.ja4);
        assert_eq!(golden["clientHelloHex"], captured.raw_hex());
        // Shape must match the schema's golden object exactly, so it can be pasted in.
        let keys: Vec<_> = golden.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            vec!["clientHelloHex", "ja3", "ja3Raw", "ja4", "ja4Raw"]
        );
    }

    /// The probe is a measuring instrument: two presets that differ on the wire
    /// must be distinguishable through it, otherwise it cannot gate anything.
    #[tokio::test]
    async fn distinguishes_presets_that_differ_on_the_wire() {
        let _guard = preset_lock().await;
        let c120 = capture_preset("chrome120", "probe.c120.test").await;
        let c150 = capture_preset("chrome150", "probe.c150.test").await;
        assert_ne!(
            c120.fingerprint.ja3, c150.fingerprint.ja3,
            "chrome120 and chrome150 use different cipher recipes"
        );
    }

    /// A capture is only a golden once a human records where it came from, so a
    /// freshly measured fingerprint must not satisfy the gate on its own.
    #[tokio::test]
    async fn a_capture_alone_does_not_align_a_preset() {
        let _guard = preset_lock().await;
        let captured = capture_preset("chrome150", "probe.gate.test").await;
        assert_eq!(
            crate::tls_golden::evaluate("chrome150", &captured.fingerprint.ja3),
            crate::tls_golden::AlignmentLevel::Recipe,
            "measuring our own rustls output must never authorise an alignment claim"
        );
    }

    #[tokio::test]
    async fn times_out_when_the_peer_never_speaks() {
        let probe = ClientHelloProbe::bind_loopback().await.unwrap();
        let addr = probe.local_addr().unwrap();
        let _silent = TcpStream::connect(addr).await.unwrap();
        let result = probe.capture_one_within(Duration::from_millis(250)).await;
        assert!(result.is_err(), "a silent peer must not hang the probe");
    }
}
