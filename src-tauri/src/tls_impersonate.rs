//! Offline ClientHello JA3 math helpers (not the MITM wire path).
//!
//! MITM egress always uses rustls `tls_outbound::build_client_config` unless a real
//! BoringSSL/curl-impersonate stack is linked (`real_impersonate_stack_available`).
//! This module builds deterministic handshake templates for unit tests of the JA3
//! parser / parity predicate only — it does **not** claim browser JA3 on the wire.

use crate::tls_fingerprint::{self, ClientTlsFingerprint};
use crate::tls_outbound::OutboundTlsProfile;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};

static IMPERSONATE_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpersonateProfileSpec {
    pub id: String,
    pub label: String,
    pub target_ja3: String,
    pub target_ja3_raw: String,
    pub alpn: Vec<String>,
}

pub fn set_impersonate_requested(enabled: bool) {
    IMPERSONATE_REQUESTED.store(enabled, Ordering::Relaxed);
}

pub fn impersonate_requested() -> bool {
    IMPERSONATE_REQUESTED.load(Ordering::Relaxed)
        || std::env::var("SHOWNET_TLS_ENGINE")
            .map(|v| {
                let v = v.to_ascii_lowercase();
                v == "impersonate" || v == "chrome" || v == "ja3"
            })
            .unwrap_or(false)
}

/// Deprecated alias: must not enable browser-JA3 claims without a real stack.
pub fn engine_is_impersonate_class() -> bool {
    crate::tls_outbound::real_impersonate_stack_available()
}

/// Build profile ClientHello handshake bytes and return fingerprint (source of target JA3).
pub fn profile_client_hello_fingerprint(
    profile: OutboundTlsProfile,
) -> Result<ClientTlsFingerprint, String> {
    let hello = build_profile_client_hello_handshake(profile)?;
    tls_fingerprint::fingerprint_client_hello_handshake(&hello)
}

pub fn profile_target_ja3(profile: OutboundTlsProfile) -> Result<String, String> {
    Ok(profile_client_hello_fingerprint(profile)?.ja3)
}

pub fn profile_spec(profile: OutboundTlsProfile) -> Result<ImpersonateProfileSpec, String> {
    let fp = profile_client_hello_fingerprint(profile)?;
    Ok(ImpersonateProfileSpec {
        id: profile.as_str().to_string(),
        label: profile.fidelity_label().to_string(),
        target_ja3: fp.ja3,
        target_ja3_raw: fp.ja3_raw,
        alpn: fp.alpn,
    })
}

pub fn ja3_parity(measured: &str, profile: OutboundTlsProfile) -> bool {
    profile_target_ja3(profile)
        .map(|target| target == measured)
        .unwrap_or(false)
}

/// Construct a TLS ClientHello handshake message for the profile (not a full TLS stack).
/// Fields chosen to differentiate profiles and produce stable JA3 via the capture parser.
pub fn build_profile_client_hello_handshake(
    profile: OutboundTlsProfile,
) -> Result<Vec<u8>, String> {
    // Cipher suites (u16) — greaseless lists differ by profile.
    let (ciphers, groups, extensions_order, versions, alpn_list) = match profile {
        OutboundTlsProfile::Default => (
            vec![0x1301_u16, 0x1302, 0x1303, 0xc02b, 0xc02f],
            vec![0x001d_u16, 0x0017],
            vec![0x0000_u16, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b, 0x002d, 0x0033],
            vec![0x0304_u16, 0x0303],
            vec![b"http/1.1".as_slice()],
        ),
        OutboundTlsProfile::ChromeLike => (
            // Chrome-like ordering (subset; deterministic for tests + target JA3).
            vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            vec![0x001d, 0x0017, 0x0018, 0x0019],
            // extension type order matters for JA3
            vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012,
                0x0033, 0x002d, 0x002b, 0x001b, 0x0015,
            ],
            vec![0x0304, 0x0303],
            vec![b"h2".as_slice(), b"http/1.1".as_slice()],
        ),
        OutboundTlsProfile::FirefoxLike => (
            vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            vec![0x001d, 0x0017, 0x0018],
            vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012,
                0x0033, 0x002d, 0x002b, 0x001b, 0x0015,
            ],
            vec![0x0304, 0x0303],
            vec![b"h2".as_slice(), b"http/1.1".as_slice()],
        ),
        OutboundTlsProfile::SafariIosLike => (
            vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc00a,
                0xc009, 0xcca9, 0xc013, 0xc014, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
            ],
            vec![0x001d, 0x0017, 0x0018, 0x0019],
            vec![
                0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x0023, 0x002b,
                0x002d, 0x0033, 0xff01, 0x0015,
            ],
            vec![0x0304, 0x0303],
            vec![b"h2".as_slice(), b"http/1.1".as_slice()],
        ),
    };

    let mut body = Vec::new();
    // legacy_version TLS1.2
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    // random 32 bytes (deterministic for stable JA3 of profile template)
    body.extend_from_slice(&[0x11; 32]);
    // session id empty
    body.push(0);
    // cipher suites
    let mut cipher_bytes = Vec::new();
    for c in &ciphers {
        cipher_bytes.extend_from_slice(&c.to_be_bytes());
    }
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    // compression methods: null
    body.push(1);
    body.push(0);

    let mut extensions = Vec::new();
    for ext in extensions_order {
        let data = match ext {
            0x0000 => encode_sni("example.com"),
            0x000a => encode_supported_groups(&groups),
            0x000b => vec![0x01, 0x00], // ec_point_formats: uncompressed
            0x000d => encode_signature_algorithms(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ]),
            0x0010 => encode_alpn(&alpn_list),
            0x002b => encode_supported_versions(&versions),
            0x002d => vec![0x01, 0x01], // psk_key_exchange_modes
            0x0033 => encode_key_share_placeholder(),
            0x0015 => vec![0x00, 0x00, 0x00, 0x00], // padding-ish
            _ => Vec::new(),
        };
        extensions.extend_from_slice(&ext.to_be_bytes());
        extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&data);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    // Handshake header: type=1 ClientHello, u24 length
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(1);
    let len = body.len();
    if len > 0x00ff_ffff {
        return Err("ClientHello too large".into());
    }
    message.push(((len >> 16) & 0xff) as u8);
    message.push(((len >> 8) & 0xff) as u8);
    message.push((len & 0xff) as u8);
    message.extend_from_slice(&body);
    Ok(message)
}

fn encode_sni(host: &str) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut name = Vec::new();
    name.push(0); // host_name
    name.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    name.extend_from_slice(host_bytes);
    let mut list = Vec::new();
    list.extend_from_slice(&(name.len() as u16).to_be_bytes());
    list.extend_from_slice(&name);
    list
}

fn encode_supported_groups(groups: &[u16]) -> Vec<u8> {
    let mut inner = Vec::new();
    for g in groups {
        inner.extend_from_slice(&g.to_be_bytes());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

fn encode_signature_algorithms(algs: &[u16]) -> Vec<u8> {
    encode_supported_groups(algs)
}

fn encode_alpn(protocols: &[&[u8]]) -> Vec<u8> {
    let mut inner = Vec::new();
    for p in protocols {
        inner.push(p.len() as u8);
        inner.extend_from_slice(p);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

fn encode_supported_versions(versions: &[u16]) -> Vec<u8> {
    let mut inner = Vec::new();
    for v in versions {
        inner.extend_from_slice(&v.to_be_bytes());
    }
    let mut out = Vec::new();
    out.push(inner.len() as u8);
    out.extend_from_slice(&inner);
    out
}

fn encode_key_share_placeholder() -> Vec<u8> {
    // minimal key_share: one empty-looking x25519-sized share for structural parse
    // group 0x001d, key length 32, key zeros
    let mut share = Vec::new();
    share.extend_from_slice(&0x001d_u16.to_be_bytes());
    share.extend_from_slice(&32_u16.to_be_bytes());
    share.extend_from_slice(&[0x42; 32]);
    let mut out = Vec::new();
    out.extend_from_slice(&(share.len() as u16).to_be_bytes());
    out.extend_from_slice(&share);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_profile_has_stable_target_ja3() {
        let a = profile_target_ja3(OutboundTlsProfile::ChromeLike).unwrap();
        let b = profile_target_ja3(OutboundTlsProfile::ChromeLike).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32); // md5 hex
        let fp = profile_client_hello_fingerprint(OutboundTlsProfile::ChromeLike).unwrap();
        assert!(fp.alpn.iter().any(|p| p == "h2"));
    }

    #[test]
    fn profiles_have_distinct_ja3() {
        let chrome = profile_target_ja3(OutboundTlsProfile::ChromeLike).unwrap();
        let firefox = profile_target_ja3(OutboundTlsProfile::FirefoxLike).unwrap();
        let safari = profile_target_ja3(OutboundTlsProfile::SafariIosLike).unwrap();
        let default = profile_target_ja3(OutboundTlsProfile::Default).unwrap();
        assert_ne!(chrome, firefox);
        assert_ne!(chrome, safari);
        assert_ne!(chrome, default);
    }

    #[test]
    fn parity_true_only_when_measured_matches_target() {
        let target = profile_target_ja3(OutboundTlsProfile::ChromeLike).unwrap();
        assert!(ja3_parity(&target, OutboundTlsProfile::ChromeLike));
        assert!(!ja3_parity("deadbeefdeadbeefdeadbeefdeadbeef", OutboundTlsProfile::ChromeLike));
    }

    #[test]
    fn wire_parser_roundtrip_with_record_layer() {
        let hello = build_profile_client_hello_handshake(OutboundTlsProfile::ChromeLike).unwrap();
        // wrap as TLS record
        let mut record = vec![22, 0x03, 0x01];
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);
        let fp = tls_fingerprint::fingerprint_client_hello_wire(&record).unwrap();
        assert_eq!(fp.ja3, profile_target_ja3(OutboundTlsProfile::ChromeLike).unwrap());
    }
}
