//! Outbound (MITM → origin) TLS profile selection.
//!
//! Full browser JA3 parity needs a specialized stack (e.g. BoringSSL impersonate).
//! Here we provide a **chrome-like** rustls profile: TLS1.2+1.3, ALPN ordered like
//! Chrome for HTTP/1.1-forwarding MITM paths, with explicit fidelity labels.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

static PROFILE: AtomicU8 = AtomicU8::new(0);
static ADDITIONAL_ROOTS: OnceLock<RwLock<Vec<CertificateDer<'static>>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum OutboundTlsProfile {
    #[default]
    Default = 0,
    /// Chrome-like rustls profile (HTTP/1.1 MITM-safe ALPN; not full JA3 clone).
    ChromeLike = 1,
}

impl OutboundTlsProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ChromeLike => "chrome-like",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "chrome" | "chrome-like" | "chromelike" | "impersonate" => Self::ChromeLike,
            _ => Self::Default,
        }
    }

    pub fn fidelity_label(self) -> &'static str {
        match self {
            Self::Default => "outbound-mitm-independent-rustls",
            Self::ChromeLike => "outbound-chrome-like-rustls-http11",
        }
    }

    pub fn note(self) -> &'static str {
        match self {
            Self::Default => {
                "MITM egress uses independent rustls defaults; do not equate outbound JA3 with inbound browser JA3/JA4."
            }
            Self::ChromeLike => {
                "MITM egress uses chrome-like rustls (TLS1.2/1.3, Chrome-ordered ALPN preference kept HTTP/1.1-primary for current MITM stack). Not a full JA3/curl-impersonate clone."
            }
        }
    }
}

pub fn set_global_profile(profile: OutboundTlsProfile) {
    PROFILE.store(profile as u8, Ordering::Relaxed);
}

pub fn global_profile() -> OutboundTlsProfile {
    match PROFILE.load(Ordering::Relaxed) {
        1 => OutboundTlsProfile::ChromeLike,
        _ => OutboundTlsProfile::Default,
    }
}

fn parse_root_certificates(pem_bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let certificates = pem::parse_many(pem_bytes)
        .map_err(|error| format!("解析额外上游根证书失败: {error}"))?
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| CertificateDer::from(block.contents().to_vec()))
        .collect::<Vec<_>>();
    if certificates.is_empty() {
        return Err("额外上游根证书文件中没有 CERTIFICATE".to_string());
    }
    let mut verifier = RootCertStore::empty();
    for certificate in &certificates {
        verifier
            .add(certificate.clone())
            .map_err(|error| format!("额外上游根证书无效: {error}"))?;
    }
    Ok(certificates)
}

/// Only the isolated release-soak startup path may call this function.
pub fn set_soak_root_certificates_from_pem(path: &Path) -> Result<usize, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("读取 release soak 上游根证书失败: {error}"))?;
    let certificates = parse_root_certificates(&bytes)?;
    let count = certificates.len();
    *ADDITIONAL_ROOTS
        .get_or_init(|| RwLock::new(Vec::new()))
        .write()
        .map_err(|_| "release soak 上游根证书状态已损坏".to_string())? = certificates;
    Ok(count)
}

fn additional_roots() -> Vec<CertificateDer<'static>> {
    ADDITIONAL_ROOTS
        .get()
        .and_then(|roots| roots.read().ok().map(|roots| roots.clone()))
        .unwrap_or_default()
}

pub fn build_client_config(profile: OutboundTlsProfile) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for certificate in additional_roots() {
        // Certificates are validated before entering ADDITIONAL_ROOTS.
        roots
            .add(certificate)
            .expect("validated release soak root certificate");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    match profile {
        OutboundTlsProfile::Default => {
            // Historical ShowNet MITM path: HTTP/1.1 only to origin.
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        OutboundTlsProfile::ChromeLike => {
            // Prefer h2 advertisement order like Chrome, but keep http/1.1 first so the
            // existing hyper HTTP/1.1 client path continues to work after ALPN.
            // (True h2 origin forwarding is a separate transport upgrade.)
            config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
            config.enable_sni = true;
        }
    }
    Arc::new(config)
}

pub fn status_json() -> serde_json::Value {
    let profile = global_profile();
    serde_json::json!({
        "profile": profile.as_str(),
        "fidelityLabel": profile.fidelity_label(),
        "note": profile.note(),
        "ja3Parity": false,
        "supportsFullBrowserJa3": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_like_sets_alpn_including_http11() {
        set_global_profile(OutboundTlsProfile::ChromeLike);
        assert_eq!(global_profile(), OutboundTlsProfile::ChromeLike);
        let cfg = build_client_config(OutboundTlsProfile::ChromeLike);
        assert!(cfg.alpn_protocols.iter().any(|p| p == b"http/1.1"));
        set_global_profile(OutboundTlsProfile::Default);
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(
            OutboundTlsProfile::parse("chrome-like"),
            OutboundTlsProfile::ChromeLike
        );
        assert_eq!(
            OutboundTlsProfile::parse("default"),
            OutboundTlsProfile::Default
        );
    }

    #[test]
    fn accepts_only_certificate_pem_blocks_for_additional_roots() {
        let authority = crate::ca::CertificateAuthority::load_or_create(None)
            .unwrap()
            .0;
        let certificates = parse_root_certificates(authority.certificate_pem().as_bytes()).unwrap();
        assert_eq!(certificates.len(), 1);

        let private_key_only = pem::encode(&pem::Pem::new("PRIVATE KEY", vec![1, 2, 3]));
        assert!(parse_root_certificates(private_key_only.as_bytes()).is_err());
    }
}
