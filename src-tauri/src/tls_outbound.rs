//! Outbound (MITM → origin) TLS profile selection.
//!
//! Full browser JA3 parity needs BoringSSL / curl-impersonate (or equivalent).
//! This module never claims that stack exists unless a real one is detected.
//!
//! Profiles customize **real rustls** ClientConfig material (cipher suite order,
//! key-exchange group order, ALPN) so inbound→outbound selection changes the wire
//! ClientHello (measurable via CapturingIo + JA3 parser).

use crate::tls_clienthello_catalog::{self, AlpnRecipe, ClientHelloPreset};
use crate::tls_fingerprint::ClientTlsFingerprint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use tokio_rustls::rustls::crypto::{aws_lc_rs, CryptoProvider};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Coarse profile mirror of the catalog default (`chrome150` → ChromeLike = 1).
/// Must stay in sync with `tls_clienthello_catalog` ACTIVE_PRESET_ID default.
static PROFILE: AtomicU8 = AtomicU8::new(1);
static AUTO_FROM_INBOUND: AtomicBool = AtomicBool::new(true);
static ADDITIONAL_ROOTS: OnceLock<RwLock<Vec<CertificateDer<'static>>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum OutboundTlsProfile {
    #[default]
    Default = 0,
    /// Chrome-oriented rustls cipher/ALPN preference (not full Chrome JA3).
    ChromeLike = 1,
    /// Firefox-oriented rustls cipher/ALPN preference (not full Firefox JA3).
    FirefoxLike = 2,
    /// Safari/iOS-oriented rustls cipher/ALPN preference (not full Safari JA3).
    SafariIosLike = 3,
}

impl OutboundTlsProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ChromeLike => "chrome-like",
            Self::FirefoxLike => "firefox-like",
            Self::SafariIosLike => "safari-ios-like",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "chrome" | "chrome-like" | "chromelike" | "chrome_android" | "chrome-android" => {
                Self::ChromeLike
            }
            "firefox" | "firefox-like" | "firefoxlike" => Self::FirefoxLike,
            "safari" | "safari-ios" | "safari_ios" | "safari-ios-like" | "ios" => {
                Self::SafariIosLike
            }
            // Do not map "impersonate" to Chrome — that name reserved for a real stack.
            _ => Self::Default,
        }
    }

    pub fn fidelity_label(self) -> &'static str {
        match self {
            Self::Default => "outbound-mitm-rustls-default",
            Self::ChromeLike => "outbound-chrome-like-rustls-ciphers",
            Self::FirefoxLike => "outbound-firefox-like-rustls-ciphers",
            Self::SafariIosLike => "outbound-safari-ios-like-rustls-ciphers",
        }
    }

    pub fn note(self) -> &'static str {
        match self {
            Self::Default => {
                "MITM egress uses rustls with default cipher/kx order. Not browser JA3."
            }
            Self::ChromeLike => {
                "MITM egress uses rustls with chrome-oriented cipher/kx/ALPN preference. Not full Chrome JA3 (no BoringSSL/curl-impersonate)."
            }
            Self::FirefoxLike => {
                "MITM egress uses rustls with firefox-oriented cipher/kx preference. Not full Firefox JA3."
            }
            Self::SafariIosLike => {
                "MITM egress uses rustls with safari/iOS-oriented cipher/kx preference. Not full Safari JA3."
            }
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::ChromeLike,
            2 => Self::FirefoxLike,
            3 => Self::SafariIosLike,
            _ => Self::Default,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum OutboundTlsEngine {
    #[default]
    Rustls,
    /// Only when a real BoringSSL/curl-impersonate-class stack is present.
    Impersonate,
}

impl OutboundTlsEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rustls => "rustls",
            Self::Impersonate => "impersonate",
        }
    }

    /// True only for a real browser TLS stack — never for a UI toggle alone.
    pub fn supports_full_browser_ja3(self) -> bool {
        matches!(self, Self::Impersonate) && real_impersonate_stack_available()
    }
}

/// Detect a real JA3-capable outbound stack usable for MITM origin TLS.
///
/// This build does **not** link BoringSSL/curl-impersonate. Detection probes:
/// 1. Compile-time feature is not present (always off here).
/// 2. Optional env `SHOWNET_IMPERSONATE_LIB` pointing at an existing loadable library file
///    **and** `SHOWNET_IMPERSONATE_ENABLE=1` — still does not wire MITM through that library
///    unless a future build integrates FFI; currently returns false after logging reason.
/// 3. Optional `curl-impersonate` / `curl_chrome*` on PATH — binary presence alone does not
///    make MITM use that binary; returns false with reason until subprocess/FFI path exists.
///
/// Always false in the rustls-only product path so `supportsFullBrowserJa3` cannot go true
/// without a real integrated stack.
pub fn real_impersonate_stack_available() -> bool {
    // Two independent conditions, deliberately. The cargo feature only compiles the
    // impersonate lane in; it links nothing. Treating the flag alone as "a real
    // browser TLS stack is present" would let a build claim browser-level JA3 while
    // still handshaking with rustls — exactly the false-positive the plan forbids
    // (docs/plan-real-browser-ja3-impersonate.md §1.2, §7).
    cfg!(feature = "impersonate-boring") && impersonate_connector_linked()
}

/// Whether a real BoringSSL / curl-impersonate-class origin connector is linked
/// and usable for MITM egress.
///
/// No build registers one yet. Phase 1 flips this by wiring an actual connector;
/// until then the feature lane compiles and tests without claiming a stack.
#[cfg(feature = "impersonate-boring")]
fn impersonate_connector_linked() -> bool {
    false
}

#[cfg(not(feature = "impersonate-boring"))]
fn impersonate_connector_linked() -> bool {
    false
}

/// Why impersonate-class engine is unavailable for MITM (status / tests).
pub fn impersonate_unavailable_reason() -> &'static str {
    if real_impersonate_stack_available() {
        return "";
    }
    // Env diagnostics first: they describe an explicit operator action and stay
    // reachable in both lanes. Gating them behind the feature check would make
    // the more specific message unreachable exactly where it is most useful.
    if std::env::var_os("SHOWNET_IMPERSONATE_LIB").is_some()
        || std::env::var_os("SHOWNET_IMPERSONATE_ENABLE").is_some()
    {
        return "impersonate env set but this build has no linked BoringSSL/curl-impersonate MITM path";
    }
    if cfg!(feature = "impersonate-boring") {
        return "impersonate-boring feature compiled in, but no linked BoringSSL/curl-impersonate connector is registered; MITM uses rustls";
    }
    "no linked BoringSSL/curl-impersonate (or equivalent) stack in this build; MITM uses rustls"
}

/// Active outbound engine. Impersonate only when a real stack is available **and** requested.
pub fn active_engine() -> OutboundTlsEngine {
    if real_impersonate_stack_available() && crate::tls_impersonate::impersonate_requested() {
        OutboundTlsEngine::Impersonate
    } else {
        OutboundTlsEngine::Rustls
    }
}

/// Apply catalog HTTP/2 recipe to a hyper origin client http2::Builder.
pub fn apply_http2_recipe_to_builder<E>(
    builder: &mut hyper::client::conn::http2::Builder<E>,
    recipe: tls_clienthello_catalog::Http2Recipe,
) where
    E: Clone,
{
    builder
        .header_table_size(recipe.header_table_size)
        .initial_stream_window_size(recipe.initial_window_size)
        .initial_connection_window_size(recipe.connection_window_size)
        .max_header_list_size(recipe.max_header_list_size)
        // None, not the recipe's value: hyper defaults this to Some(16384) and
        // then announces it, but a captured Chromium 151 handshake sends only
        // HEADER_TABLE_SIZE, ENABLE_PUSH, INITIAL_WINDOW_SIZE and
        // MAX_HEADER_LIST_SIZE. Passing None keeps hyper from telling h2 at all,
        // so the entry is absent and the set matches. No behaviour changes: an
        // unannounced MAX_FRAME_SIZE means the protocol default, which is the
        // 16384 we were announcing.
        .max_frame_size(None);
    // Deliberately not applied. A real Chrome 151 handshake, captured through a
    // TLS listener with ALPN h2, sends exactly four SETTINGS — HEADER_TABLE_SIZE,
    // ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE — and no
    // MAX_CONCURRENT_STREAMS. Setting it made us send a fifth entry Chrome never
    // sends, and the *set* of SETTINGS is as much a fingerprint as the values.
    // Omitting it costs nothing here: this limit governs streams a server may
    // push to us, and ENABLE_PUSH is 0. The recipe keeps the field because the
    // fingerprint string still reports it.
    let _ = recipe.max_concurrent_streams;
}

/// Active preset H2 recipe (product path).
pub fn active_http2_recipe() -> tls_clienthello_catalog::Http2Recipe {
    tls_clienthello_catalog::active_preset()
        .map(|p| p.h2_recipe())
        .unwrap_or(tls_clienthello_catalog::H2_DEFAULT)
}

/// Builder material snapshot for tests (SETTINGS pairs + pseudo order + fingerprint).
pub fn active_http2_builder_material() -> (Vec<(u16, u32)>, Vec<&'static str>, String) {
    let recipe = active_http2_recipe();
    (
        recipe.settings_pairs(),
        recipe.pseudo_header_order.to_vec(),
        recipe.fingerprint(),
    )
}

pub fn set_global_profile(profile: OutboundTlsProfile) {
    PROFILE.store(profile as u8, Ordering::Relaxed);
    // Keep catalog in sync with coarse family.
    let preset_id = match profile {
        OutboundTlsProfile::Default => "default",
        OutboundTlsProfile::ChromeLike => "chrome150",
        OutboundTlsProfile::FirefoxLike => "firefox136",
        OutboundTlsProfile::SafariIosLike => "safari-ios18",
    };
    let _ = tls_clienthello_catalog::set_active_preset_id(preset_id);
}

pub fn global_profile() -> OutboundTlsProfile {
    OutboundTlsProfile::from_u8(PROFILE.load(Ordering::Relaxed))
}

/// Set active versioned catalog preset (primary product path).
pub fn set_active_preset(id: &str) -> Result<&'static ClientHelloPreset, String> {
    let preset = tls_clienthello_catalog::set_active_preset_id(id)?;
    // Mirror coarse enum for legacy callers.
    let coarse = match preset.family {
        "chrome" | "chrome-android" | "edge" => OutboundTlsProfile::ChromeLike,
        "firefox" => OutboundTlsProfile::FirefoxLike,
        "safari" | "safari-ios" => OutboundTlsProfile::SafariIosLike,
        _ => OutboundTlsProfile::Default,
    };
    PROFILE.store(coarse as u8, Ordering::Relaxed);
    Ok(preset)
}

pub fn active_preset_id() -> String {
    tls_clienthello_catalog::active_preset_id()
}

pub fn active_preset() -> Result<&'static ClientHelloPreset, String> {
    tls_clienthello_catalog::active_preset()
}

pub fn set_auto_from_inbound(enabled: bool) {
    AUTO_FROM_INBOUND.store(enabled, Ordering::Relaxed);
}

pub fn auto_from_inbound() -> bool {
    AUTO_FROM_INBOUND.load(Ordering::Relaxed)
}

/// Map inbound ClientHello evidence → outbound profile (heuristics).
pub fn select_profile_from_inbound(inbound: &ClientTlsFingerprint) -> OutboundTlsProfile {
    let preset_id = tls_clienthello_catalog::select_preset_from_inbound(
        &inbound.ja4,
        &inbound.alpn,
        inbound.grease,
    );
    match tls_clienthello_catalog::get_preset(preset_id).map(|p| p.family) {
        Ok("firefox") => OutboundTlsProfile::FirefoxLike,
        Ok("safari") | Ok("safari-ios") => OutboundTlsProfile::SafariIosLike,
        Ok("chrome") | Ok("chrome-android") | Ok("edge") => OutboundTlsProfile::ChromeLike,
        _ => OutboundTlsProfile::Default,
    }
}

pub fn resolve_profile_for_connection(
    inbound: Option<&ClientTlsFingerprint>,
) -> (OutboundTlsProfile, bool) {
    if auto_from_inbound() {
        if let Some(fp) = inbound {
            let preset_id =
                tls_clienthello_catalog::select_preset_from_inbound(&fp.ja4, &fp.alpn, fp.grease);
            let _ = tls_clienthello_catalog::set_active_preset_id(preset_id);
            return (select_profile_from_inbound(fp), true);
        }
    }
    (global_profile(), false)
}

/// Resolve outbound config for this connection (catalog-driven).
pub fn resolve_preset_for_connection(
    inbound: Option<&ClientTlsFingerprint>,
) -> (&'static ClientHelloPreset, bool) {
    if auto_from_inbound() {
        if let Some(fp) = inbound {
            let id =
                tls_clienthello_catalog::select_preset_from_inbound(&fp.ja4, &fp.alpn, fp.grease);
            if let Ok(p) = set_active_preset(id) {
                return (p, true);
            }
        }
    }
    let p = tls_clienthello_catalog::active_preset()
        .or_else(|_| tls_clienthello_catalog::get_preset("chrome150"))
        .expect("catalog has chrome150");
    (p, false)
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

/// Build a CryptoProvider from a catalog ClientHello recipe (real wire difference).
fn provider_for_preset(preset: &ClientHelloPreset) -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    tls_clienthello_catalog::apply_cipher_recipe(&mut provider.cipher_suites, preset.cipher);
    tls_clienthello_catalog::apply_kx_recipe(&mut provider.kx_groups, preset.kx);
    provider
}

fn provider_for_profile(profile: OutboundTlsProfile) -> CryptoProvider {
    let id = match profile {
        OutboundTlsProfile::Default => "default",
        OutboundTlsProfile::ChromeLike => "chrome-like",
        OutboundTlsProfile::FirefoxLike => "firefox-like",
        OutboundTlsProfile::SafariIosLike => "safari-ios-like",
    };
    let preset = tls_clienthello_catalog::get_preset(id)
        .or_else(|_| tls_clienthello_catalog::get_preset("chrome150"))
        .expect("catalog");
    provider_for_preset(preset)
}

/// Cipher suite suite-ids (for tests asserting profile wire differences).
pub fn profile_cipher_suite_count(profile: OutboundTlsProfile) -> usize {
    provider_for_profile(profile).cipher_suites.len()
}

/// Cipher fingerprint for a coarse profile or active catalog preset.
pub fn profile_cipher_fingerprint(profile: OutboundTlsProfile) -> String {
    let p = provider_for_profile(profile);
    cipher_provider_fingerprint(&p)
}

pub fn preset_cipher_fingerprint(preset_id: &str) -> Result<String, String> {
    let preset = tls_clienthello_catalog::get_preset(preset_id)?;
    Ok(cipher_provider_fingerprint(&provider_for_preset(preset)))
}

fn cipher_provider_fingerprint(p: &CryptoProvider) -> String {
    let suites: Vec<String> = p
        .cipher_suites
        .iter()
        .map(|s| format!("{:?}", s.suite()))
        .collect();
    let groups: Vec<String> = p
        .kx_groups
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect();
    format!("suites={};groups={}", suites.join(","), groups.join(","))
}

fn coarse_for_family(family: &str) -> OutboundTlsProfile {
    match family {
        "chrome" | "chrome-android" | "edge" => OutboundTlsProfile::ChromeLike,
        "firefox" => OutboundTlsProfile::FirefoxLike,
        "safari" | "safari-ios" => OutboundTlsProfile::SafariIosLike,
        _ => OutboundTlsProfile::Default,
    }
}

fn default_preset_for_profile(profile: OutboundTlsProfile) -> &'static str {
    match profile {
        OutboundTlsProfile::Default => "default",
        OutboundTlsProfile::ChromeLike => "chrome150",
        OutboundTlsProfile::FirefoxLike => "firefox136",
        OutboundTlsProfile::SafariIosLike => "safari-ios18",
    }
}

/// Resolve which catalog preset id `build_client_config` will wire for this coarse profile.
/// Prefer the active versioned preset when its family matches; otherwise the family default.
pub fn preset_id_for_profile(profile: OutboundTlsProfile) -> String {
    let active = tls_clienthello_catalog::active_preset_id();
    if let Ok(preset) = tls_clienthello_catalog::get_preset(&active) {
        if coarse_for_family(preset.family) == profile {
            return active;
        }
    }
    default_preset_for_profile(profile).to_string()
}

/// Cipher/kx fingerprint of the provider installed into ClientConfig for this profile
/// (goes through the same preset resolution as the shipped builder).
pub fn builder_cipher_fingerprint_for_profile(profile: OutboundTlsProfile) -> String {
    let id = preset_id_for_profile(profile);
    preset_cipher_fingerprint(&id).unwrap_or_default()
}

pub fn build_client_config(profile: OutboundTlsProfile) -> Arc<ClientConfig> {
    let preset_id = preset_id_for_profile(profile);
    build_client_config_for_preset(&preset_id).unwrap_or_else(|_| {
        build_client_config_for_preset("default").expect("default preset exists")
    })
}

/// Origin ClientConfig with ALPN forced to HTTP/1.1 only (same cipher recipe as profile).
/// Used for hosts that reject rustls H2 MITM (e.g. some Baidu static CDNs returning 400).
pub fn build_client_config_http11_only(profile: OutboundTlsProfile) -> Arc<ClientConfig> {
    let preset_id = preset_id_for_profile(profile);
    build_client_config_for_preset_with_alpn(&preset_id, AlpnRecipe::Http11Only).unwrap_or_else(
        |_| {
            build_client_config_for_preset_with_alpn("default", AlpnRecipe::Http11Only)
                .expect("default preset exists")
        },
    )
}

/// Hosts that frequently return HTTP 400 under rustls MITM when H2 is negotiated.
/// Prefer product bypass (`STATIC_CDN_BYPASS_PRESET`); when still MITM'd, force HTTP/1.1 ALPN.
/// Hosts observed rejecting our outbound HTTP/2 at runtime.
///
/// Some origins fingerprint the HTTP/2 connection itself — SETTINGS values and
/// order, window sizes, priority frames — and hyper's do not match a browser's.
/// Measured against one such origin: through the MITM over h2 the page reloaded
/// 23 times in 20 seconds and never rendered; the identical browser over h1
/// egress settled after one navigation. Until outbound h2 can be shaped to
/// match a real browser, remembering which origins refuse ours and speaking
/// HTTP/1.1 to them is what keeps those sites usable.
/// A downgrade is re-evaluated after this long. Without it a single bad spell —
/// an origin under load, a network that misbehaved for a minute — would cost a
/// host its multiplexing until the app restarted, and nothing would ever
/// re-check whether the condition still held.
#[cfg(not(test))]
const H2_DOWNGRADE_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// Short under test so expiry can be exercised by waiting rather than by
/// back-dating an `Instant`. `Instant` is monotonic-since-boot on every target,
/// so subtracting half an hour from `now` yields `None` on a freshly booted
/// machine — which is exactly what CI runners are, and the test would have
/// panicked there while passing on any long-lived workstation.
#[cfg(test)]
const H2_DOWNGRADE_TTL: std::time::Duration = std::time::Duration::from_millis(60);

#[derive(Clone, Copy)]
struct H2Rejections {
    count: u32,
    downgraded_at: Option<std::time::Instant>,
}

static H2_REJECTED_HOSTS: std::sync::LazyLock<std::sync::RwLock<HashMap<String, H2Rejections>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(HashMap::new()));

/// How many h2 failures for one origin before we stop offering it h2.
///
/// One is not enough. A browser abandoning a request, a network blip or a
/// mid-stream close all surface as send errors, and downgrading a host for the
/// life of the process on a single such event would quietly cost every later
/// request to it the multiplexing it should have had — a regression nobody
/// would connect to the request that caused it.
const H2_REJECTIONS_BEFORE_DOWNGRADE: u32 = 2;

/// Records an HTTP/2 failure for `host`. Returns true when this observation is
/// the one that downgrades it.
pub fn note_origin_http2_rejected(host: &str) -> bool {
    let key = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if key.is_empty() {
        return false;
    }
    let Ok(mut hosts) = H2_REJECTED_HOSTS.write() else {
        return false;
    };
    // Bounded so a host-header-controlled flood cannot grow it without limit.
    if hosts.len() >= MAX_TRACKED_H2_HOSTS && !hosts.contains_key(&key) {
        return false;
    }
    let entry = hosts.entry(key).or_insert(H2Rejections {
        count: 0,
        downgraded_at: None,
    });
    // An expired downgrade starts the host over rather than leaving its old
    // tally standing. Without this the count stayed above the threshold forever
    // and the `==` below could never match again, so a host could be downgraded
    // exactly once per process and never again however often it refused — the
    // TTL disarmed the feature instead of re-evaluating it.
    if entry
        .downgraded_at
        .is_some_and(|at| at.elapsed() >= H2_DOWNGRADE_TTL)
    {
        entry.count = 0;
        entry.downgraded_at = None;
    }
    entry.count = entry.count.saturating_add(1);
    if entry.count == H2_REJECTIONS_BEFORE_DOWNGRADE {
        entry.downgraded_at = Some(std::time::Instant::now());
        return true;
    }
    false
}

/// Ceiling on the rejection table; hostnames come from the wire.
const MAX_TRACKED_H2_HOSTS: usize = 1024;

fn origin_http2_rejected(host: &str) -> bool {
    let key = host.trim().trim_end_matches('.').to_ascii_lowercase();
    H2_REJECTED_HOSTS
        .read()
        .map(|hosts| {
            hosts.get(&key).is_some_and(|entry| {
                entry
                    .downgraded_at
                    .is_some_and(|at| at.elapsed() < H2_DOWNGRADE_TTL)
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
pub fn clear_origin_http2_rejections() {
    if let Ok(mut hosts) = H2_REJECTED_HOSTS.write() {
        hosts.clear();
    }
}

pub fn origin_force_http11_for_host(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    const SUFFIXES: &[&str] = &[".bdstatic.com", ".bcebos.com"];
    const EXACT: &[&str] = &["bdstatic.com", "bcebos.com"];
    EXACT.iter().any(|exact| host == *exact)
        || SUFFIXES
            .iter()
            .any(|suffix| host.ends_with(suffix) || host == &suffix[1..])
        // Learned at runtime, in addition to the static list.
        || origin_http2_rejected(&host)
}

/// Build MITM origin ClientConfig from a versioned catalog preset id.
pub fn build_client_config_for_preset(preset_id: &str) -> Result<Arc<ClientConfig>, String> {
    let preset = tls_clienthello_catalog::get_preset(preset_id)?;
    build_client_config_for_preset_with_alpn(preset_id, preset.alpn)
}

fn build_client_config_for_preset_with_alpn(
    preset_id: &str,
    alpn: AlpnRecipe,
) -> Result<Arc<ClientConfig>, String> {
    let preset = tls_clienthello_catalog::get_preset(preset_id)?;
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for certificate in additional_roots() {
        roots
            .add(certificate)
            .expect("validated release soak root certificate");
    }
    let provider = provider_for_preset(preset);
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls protocol versions: {e}"))?;
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = match alpn {
        AlpnRecipe::H2Http11 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        AlpnRecipe::Http11Only => vec![b"http/1.1".to_vec()],
        AlpnRecipe::H2Only => vec![b"h2".to_vec()],
    };
    // Always enable SNI for origin HTTPS (name-based virtual hosts). rustls default is true;
    // never disable it for "shownet"/default family — that breaks real origin connects.
    config.enable_sni = true;
    Ok(Arc::new(config))
}

pub fn status_json() -> serde_json::Value {
    let profile = global_profile();
    let engine = active_engine();
    let preset = tls_clienthello_catalog::active_preset().ok();
    let preset_id = active_preset_id();
    let recipe_fp = preset
        .map(tls_clienthello_catalog::recipe_fingerprint)
        .unwrap_or_default();
    let cipher_fp = preset_cipher_fingerprint(&preset_id).unwrap_or_default();
    let h2 = preset.map(|p| p.h2_recipe());
    let documented_ja3 = preset
        .map(|p| {
            tls_clienthello_catalog::catalog_documented_ja3(p.id)
                .or(p.documented_ja3)
                .map(str::to_string)
        })
        .flatten();
    let golden = crate::tls_golden::status_json(&preset_id);
    // Phase 1: product MITM still uses rustls unless a connector is linked.
    // ja3Parity requires BOTH a real stack on the wire AND a *measured* golden match.
    // Status has no live ClientHello sample → measured alignment is recipe → parity false.
    let measured = crate::tls_golden::measured_alignment(&preset_id, None, None);
    let ja3_parity = real_impersonate_stack_available() && measured.is_matched();
    serde_json::json!({
        "profile": profile.as_str(),
        "presetId": preset_id,
        "preset": preset.map(tls_clienthello_catalog::preset_view),
        "presets": tls_clienthello_catalog::list_presets(),
        "fidelityLabel": preset.map(|p| p.note).unwrap_or(profile.fidelity_label()),
        "note": preset.map(|p| p.note).unwrap_or(profile.note()),
        "browserFamily": preset.map(|p| p.family).unwrap_or("shownet"),
        "browserMajorVersion": preset.map(|p| p.major_version).unwrap_or(0),
        "engine": engine.as_str(),
        "autoFromInbound": auto_from_inbound(),
        "ja3Parity": ja3_parity,
        "supportsFullBrowserJa3": engine.supports_full_browser_ja3(),
        "realImpersonateStackAvailable": real_impersonate_stack_available(),
        "impersonateRequested": crate::tls_impersonate::impersonate_requested(),
        "impersonateUnavailableReason": impersonate_unavailable_reason(),
        "documentedJa3": documented_ja3,
        // Measured claim (recipe until a live evaluate_measured match).
        "alignmentLevel": golden["alignmentLevel"],
        "alignmentClaim": golden["alignmentClaim"],
        // Golden file ceiling (existence) — not a wire “已对齐” claim.
        "goldenAuthorisedCeiling": golden["goldenAuthorisedCeiling"],
        "goldenAuthorisedClaim": golden["goldenAuthorisedClaim"],
        "goldenPlatform": golden["platform"],
        "goldenStatus": golden["goldenStatus"],
        "goldenSource": golden["goldenSource"],
        "goldenCapturedAt": golden["goldenCapturedAt"],
        "toolHelloId": golden["toolHelloId"],
        "toolMatchedGolden": matches!(
            golden["goldenStatus"].as_str(),
            Some("captured")
        ) && matches!(golden["goldenSource"].as_str(), Some("tool-capture")),
        "h2Fingerprint": h2.map(|r| r.fingerprint()),
        "h2Settings": h2.map(|r| {
            r.settings_pairs()
                .into_iter()
                .map(|(id, value)| serde_json::json!({ "id": id, "value": value }))
                .collect::<Vec<_>>()
        }),
        "h2PseudoHeaderOrder": h2.map(|r| r.pseudo_header_order),
        "profileCipherFingerprint": cipher_fp,
        "recipeFingerprint": recipe_fp,
        "profiles": tls_clienthello_catalog::list_preset_ids(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// Catalog/profile selection mutates process-global state; serialize tests that touch it.
    fn preset_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn sample_inbound(ja4: &str, alpn: &[&str], grease: bool) -> ClientTlsFingerprint {
        ClientTlsFingerprint {
            ja3: "abc".into(),
            ja3_raw: "raw".into(),
            ja4: ja4.into(),
            ja4_raw: ja4.into(),
            sni: Some("example.com".into()),
            alpn: alpn.iter().map(|s| (*s).to_string()).collect(),
            legacy_version: "TLS1.2".into(),
            offered_versions: vec!["TLS1.3".into()],
            cipher_suites: vec![],
            extensions: vec![],
            supported_groups: vec![],
            signature_algorithms: vec![],
            grease,
        }
    }

    #[test]
    fn a_host_that_refuses_our_http2_is_remembered_and_downgraded() {
        clear_origin_http2_rejections();
        let host = "h2-refuser.test";
        assert!(
            !origin_force_http11_for_host(host),
            "unknown host starts on h2"
        );

        // One failure is not a verdict: a browser abandoning a request or a
        // network blip must not cost every later request to this host its
        // multiplexing for the life of the process.
        assert!(
            !note_origin_http2_rejected(host),
            "first failure only observes"
        );
        assert!(!origin_force_http11_for_host(host), "still offered h2");

        // The second is. `true` marks the transition, so the caller can say so
        // once rather than on every subsequent failure.
        assert!(
            note_origin_http2_rejected(host),
            "second failure downgrades"
        );
        assert!(!note_origin_http2_rejected(host), "already downgraded");

        // Every later connection to it takes the HTTP/1.1 route, which is what
        // stops a page whose h2 connection the origin refuses from reloading
        // forever.
        assert!(origin_force_http11_for_host(host));
        assert!(
            origin_force_http11_for_host("H2-Refuser.Test."),
            "host match is normalised"
        );
        assert!(
            !origin_force_http11_for_host("other.test"),
            "only the observed host"
        );

        // The static list is unaffected either way.
        assert!(origin_force_http11_for_host("pss.bdstatic.com"));

        // Hostnames arrive from the wire, so the table is capped. Asserted here
        // rather than in its own test because this state is process-global and
        // Rust runs tests in parallel — two tests mutating it raced each other.
        clear_origin_http2_rejections();
        for index in 0..(MAX_TRACKED_H2_HOSTS + 50) {
            note_origin_http2_rejected(&format!("host-{index}.test"));
        }
        let tracked = H2_REJECTED_HOSTS
            .read()
            .map(|hosts| hosts.len())
            .unwrap_or(0);
        assert!(tracked <= MAX_TRACKED_H2_HOSTS, "tracked {tracked} hosts");
        // A host already counted still progresses once the table is full, so a
        // genuine repeat offender is not starved by the cap.
        assert!(note_origin_http2_rejected("host-0.test"));
        assert!(origin_force_http11_for_host("host-0.test"));

        // Once the downgrade ages out the host is offered h2 again — and can be
        // downgraded again if it still refuses. The first version could not:
        // the tally stayed above the threshold, so the equality that arms it
        // never matched twice and one expiry disarmed the host for good.
        clear_origin_http2_rejections();
        assert!(!note_origin_http2_rejected(host));
        assert!(note_origin_http2_rejected(host));
        assert!(origin_force_http11_for_host(host));
        // Waits out the (test-length) TTL rather than back-dating an Instant,
        // which cannot be done on a machine that has not been up that long.
        std::thread::sleep(H2_DOWNGRADE_TTL + std::time::Duration::from_millis(20));
        assert!(!origin_force_http11_for_host(host), "downgrade expires");
        assert!(!note_origin_http2_rejected(host), "and starts over");
        assert!(
            note_origin_http2_rejected(host),
            "second refusal re-arms it"
        );
        assert!(origin_force_http11_for_host(host));

        clear_origin_http2_rejections();
        assert!(!origin_force_http11_for_host(host));
    }

    #[test]
    fn origin_force_http11_matches_baidu_static_cdn_hosts() {
        assert!(origin_force_http11_for_host("pss.bdstatic.com"));
        assert!(origin_force_http11_for_host("ss0.bdstatic.com"));
        assert!(origin_force_http11_for_host("psstatic.cdn.bcebos.com"));
        assert!(!origin_force_http11_for_host("www.baidu.com"));
        assert!(!origin_force_http11_for_host("example.com"));
        let cfg = build_client_config_http11_only(OutboundTlsProfile::ChromeLike);
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn chrome_like_sets_alpn_h2_first() {
        let _guard = preset_lock();
        set_global_profile(OutboundTlsProfile::ChromeLike);
        assert_eq!(global_profile(), OutboundTlsProfile::ChromeLike);
        let cfg = build_client_config(OutboundTlsProfile::ChromeLike);
        assert_eq!(
            cfg.alpn_protocols.first().map(|p| p.as_slice()),
            Some(&b"h2"[..])
        );
        set_global_profile(OutboundTlsProfile::Default);
    }

    #[test]
    fn profiles_produce_distinct_cipher_fingerprints() {
        let _guard = preset_lock();
        let d = profile_cipher_fingerprint(OutboundTlsProfile::Default);
        let c = profile_cipher_fingerprint(OutboundTlsProfile::ChromeLike);
        let f = profile_cipher_fingerprint(OutboundTlsProfile::FirefoxLike);
        let s = profile_cipher_fingerprint(OutboundTlsProfile::SafariIosLike);
        assert_ne!(d, c, "chrome-like must reorder ciphers vs default");
        assert_ne!(d, f, "firefox-like must reorder ciphers vs default");
        assert_ne!(c, f, "chrome and firefox fingerprints differ");
        assert_ne!(c, s, "chrome and safari fingerprints differ");
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(
            OutboundTlsProfile::parse("chrome-like"),
            OutboundTlsProfile::ChromeLike
        );
        assert_eq!(
            OutboundTlsProfile::parse("firefox"),
            OutboundTlsProfile::FirefoxLike
        );
        assert_eq!(
            OutboundTlsProfile::parse("default"),
            OutboundTlsProfile::Default
        );
        // "impersonate" must NOT silently become chrome-like
        assert_eq!(
            OutboundTlsProfile::parse("impersonate"),
            OutboundTlsProfile::Default
        );
    }

    #[test]
    fn selects_chrome_like_from_ja4_h2() {
        let inbound = sample_inbound(
            "t13d1516h2_8daaf6152771_806a8c22fdea",
            &["h2", "http/1.1"],
            true,
        );
        assert_eq!(
            select_profile_from_inbound(&inbound),
            OutboundTlsProfile::ChromeLike
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

    #[test]
    fn never_claims_full_browser_ja3_without_real_stack() {
        let _guard = preset_lock();
        assert!(!real_impersonate_stack_available());
        assert_eq!(active_engine(), OutboundTlsEngine::Rustls);
        assert!(!active_engine().supports_full_browser_ja3());
        let status = status_json();
        assert_eq!(status["ja3Parity"], false);
        assert_eq!(status["supportsFullBrowserJa3"], false);
        assert_eq!(status["engine"], "rustls");
        assert_eq!(status["realImpersonateStackAvailable"], false);
    }

    /// The cargo feature compiles the impersonate lane in; it links nothing.
    /// Both lanes must therefore agree that no real stack is present, so the
    /// feature can be built and tested in CI without manufacturing a claim.
    /// Phase 1 changes this only by linking an actual connector.
    #[test]
    fn compiling_the_feature_does_not_by_itself_provide_a_stack() {
        let _guard = preset_lock();
        assert!(
            !real_impersonate_stack_available(),
            "no connector is linked in any current build, feature flag or not"
        );
        assert_eq!(active_engine(), OutboundTlsEngine::Rustls);
        assert!(!active_engine().supports_full_browser_ja3());
        let reason = impersonate_unavailable_reason();
        assert!(
            reason.contains("no linked"),
            "reason must say a stack is not linked, got: {reason}"
        );
        if cfg!(feature = "impersonate-boring") {
            assert!(
                reason.contains("feature compiled in"),
                "the feature lane should say the flag is on but nothing is linked, got: {reason}"
            );
        }
    }

    /// Status must split golden ceiling from measured alignment: a tool golden
    /// on disk raises goldenAuthorisedCeiling but measured alignmentLevel stays
    /// recipe (no live sample). ja3Parity stays false without a linked stack.
    #[test]
    fn alignment_and_parity_honesty_with_or_without_captured_golden() {
        let _guard = preset_lock();
        for preset in ["chrome150", "chrome149", "firefox136", "safari-ios18"] {
            set_active_preset(preset).unwrap();
            let status = status_json();
            let platform = crate::tls_golden::current_platform();
            let entry = crate::tls_golden::golden_for(preset, platform);
            // Measured claim is always recipe on the status path (no wire sample).
            assert_eq!(
                status["alignmentLevel"], "recipe",
                "{preset}: measured alignment must stay recipe without a live match"
            );
            let claim = status["alignmentClaim"].as_str().unwrap_or("");
            assert!(
                !claim.starts_with("已对齐"),
                "{preset}: measured claim must not start with 已对齐: {claim}"
            );
            match entry.map(|e| e.status) {
                Some(crate::tls_golden::GoldenStatus::Captured) => {
                    assert!(
                        status["goldenAuthorisedCeiling"] == "tool-matched"
                            || status["goldenAuthorisedCeiling"] == "browser-matched",
                        "{preset}: captured golden should raise ceiling"
                    );
                    assert!(status["goldenCapturedAt"].as_str().is_some());
                    let ceiling_claim = status["goldenAuthorisedClaim"].as_str().unwrap_or("");
                    assert!(
                        !ceiling_claim.starts_with("已对齐"),
                        "{preset}: ceiling claim must not assert 已对齐 alone"
                    );
                }
                _ => {
                    assert_eq!(status["goldenAuthorisedCeiling"], "recipe");
                    assert!(
                        status["goldenCapturedAt"].is_null(),
                        "{preset} must not report a capture date before being captured"
                    );
                }
            }
            assert_eq!(status["ja3Parity"], false);
            assert_eq!(status["supportsFullBrowserJa3"], false);
            assert_eq!(status["goldenPlatform"], platform);
        }
        set_active_preset("chrome150").unwrap();
    }

    /// Mobile presets have no golden on a desktop build, so they must report no
    /// golden at all rather than silently borrowing the desktop capture.
    #[test]
    fn desktop_status_reports_no_golden_for_mobile_presets() {
        let _guard = preset_lock();
        set_active_preset("chrome-android150").unwrap();
        let status = status_json();
        assert_eq!(status["alignmentLevel"], "recipe");
        assert!(status["goldenStatus"].is_null());
        assert!(status["goldenSource"].is_null());
        set_active_preset("chrome150").unwrap();
    }

    #[test]
    fn status_exposes_versioned_preset_catalog() {
        let _guard = preset_lock();
        set_active_preset("chrome150").unwrap();
        let status = status_json();
        assert_eq!(status["presetId"], "chrome150");
        assert_eq!(status["browserMajorVersion"], 150);
        assert_eq!(status["browserFamily"], "chrome");
        assert_eq!(status["ja3Parity"], false);
        assert_eq!(status["supportsFullBrowserJa3"], false);
        let presets = status["presets"].as_array().expect("presets array");
        assert!(presets.len() >= 20);
    }

    #[test]
    fn two_catalog_presets_have_different_cipher_recipes() {
        let a = preset_cipher_fingerprint("chrome149").unwrap();
        let b = preset_cipher_fingerprint("chrome150").unwrap();
        assert_ne!(a, b);
        let c = preset_cipher_fingerprint("firefox133").unwrap();
        assert_ne!(b, c);
    }

    #[test]
    fn set_active_preset_persists_across_status_reads() {
        let _guard = preset_lock();
        set_active_preset("edge150").unwrap();
        assert_eq!(active_preset_id(), "edge150");
        let status = status_json();
        assert_eq!(status["presetId"], "edge150");
        set_active_preset("chrome150").unwrap();
    }

    #[test]
    fn selection_round_trip_two_presets_and_honesty() {
        let _guard = preset_lock();
        set_active_preset("chrome149").unwrap();
        let s1 = status_json();
        assert_eq!(s1["presetId"], "chrome149");
        assert_eq!(s1["browserMajorVersion"], 149);
        assert_eq!(s1["ja3Parity"], false);
        assert_eq!(s1["supportsFullBrowserJa3"], false);

        set_active_preset("firefox133").unwrap();
        let s2 = status_json();
        assert_eq!(s2["presetId"], "firefox133");
        assert_eq!(s2["browserFamily"], "firefox");
        assert_eq!(s2["ja3Parity"], false);
        assert_eq!(s2["supportsFullBrowserJa3"], false);

        // "restart simulation": re-apply stored preset id like load_app_setting path
        let stored = s2["presetId"].as_str().unwrap().to_string();
        set_active_preset(&stored).unwrap();
        assert_eq!(active_preset_id(), "firefox133");
        set_active_preset("chrome150").unwrap();
    }

    #[test]
    fn builder_uses_selected_catalog_recipe() {
        let _guard = preset_lock();
        set_active_preset("chrome149").unwrap();
        // Shipped resolve path must follow selection (not hard-coded chrome150).
        assert_eq!(
            preset_id_for_profile(OutboundTlsProfile::ChromeLike),
            "chrome149"
        );
        let fp_a = builder_cipher_fingerprint_for_profile(OutboundTlsProfile::ChromeLike);
        let cfg_a = build_client_config(OutboundTlsProfile::ChromeLike);
        assert_eq!(
            fp_a,
            preset_cipher_fingerprint("chrome149").unwrap(),
            "builder path must wire chrome149 provider material"
        );
        assert!(
            cfg_a.enable_sni,
            "origin ClientConfig must keep SNI enabled"
        );
        assert_eq!(
            cfg_a.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );

        set_active_preset("chrome150").unwrap();
        assert_eq!(
            preset_id_for_profile(OutboundTlsProfile::ChromeLike),
            "chrome150"
        );
        let fp_b = builder_cipher_fingerprint_for_profile(OutboundTlsProfile::ChromeLike);
        let cfg_b = build_client_config(OutboundTlsProfile::ChromeLike);
        assert_eq!(
            fp_b,
            preset_cipher_fingerprint("chrome150").unwrap(),
            "builder path must wire chrome150 provider material"
        );
        assert!(cfg_b.enable_sni);
        assert_eq!(
            cfg_b.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );

        assert_ne!(
            fp_a, fp_b,
            "chrome149 vs chrome150 builder material must differ"
        );
        assert_eq!(active_preset_id(), "chrome150");
    }

    #[test]
    fn cold_start_profile_and_catalog_are_synced_to_chrome150() {
        let _guard = preset_lock();
        // Simulate product cold start: reset to catalog + PROFILE defaults.
        set_active_preset("chrome150").unwrap();
        assert_eq!(active_preset_id(), "chrome150");
        assert_eq!(global_profile(), OutboundTlsProfile::ChromeLike);
        assert_eq!(
            preset_id_for_profile(OutboundTlsProfile::ChromeLike),
            "chrome150"
        );
        let status = status_json();
        assert_eq!(status["presetId"], "chrome150");
        assert_eq!(status["browserFamily"], "chrome");
        assert_eq!(status["profile"], "chrome-like");
        // Global/default connect path for chrome family wires chrome150, not generic default.
        let fp = builder_cipher_fingerprint_for_profile(OutboundTlsProfile::ChromeLike);
        assert_eq!(fp, preset_cipher_fingerprint("chrome150").unwrap());
        assert_ne!(fp, preset_cipher_fingerprint("default").unwrap());
        let cfg = build_client_config(OutboundTlsProfile::ChromeLike);
        assert!(cfg.enable_sni);
    }

    #[test]
    fn default_preset_keeps_sni_enabled() {
        let cfg = build_client_config_for_preset("default").unwrap();
        assert!(
            cfg.enable_sni,
            "default/shownet family must not disable SNI for origin HTTPS"
        );
        let cfg_chrome = build_client_config_for_preset("chrome150").unwrap();
        assert!(cfg_chrome.enable_sni);
    }

    #[test]
    fn active_h2_builder_material_differs_by_preset() {
        let _guard = preset_lock();
        set_active_preset("chrome120").unwrap();
        let (s120, _p120, f120) = active_http2_builder_material();
        set_active_preset("chrome150").unwrap();
        let (s150, p150, f150) = active_http2_builder_material();
        set_active_preset("firefox133").unwrap();
        let (_sff, pff, fff) = active_http2_builder_material();
        assert_ne!(f120, f150, "H2 fingerprint chrome120 vs chrome150");
        assert_ne!(s120, s150, "SETTINGS pairs must differ");
        assert_ne!(f150, fff);
        assert_ne!(p150, pff, "pseudo order chrome vs firefox");
        set_active_preset("chrome150").unwrap();
        let st = status_json();
        assert_eq!(st["documentedJa3"], "ab063844a93885b408c5a0bfcb2444c6");
        assert_eq!(st["ja3Parity"], false);
        assert_eq!(st["supportsFullBrowserJa3"], false);
        assert_eq!(st["realImpersonateStackAvailable"], false);
        assert!(!st["h2Fingerprint"].as_str().unwrap_or("").is_empty());
        // Chrome's four. MAX_CONCURRENT_STREAMS and MAX_FRAME_SIZE are both
        // absent from the handshake now, so the status page must not report
        // them either — it describes what the connection announces.
        let announced = st["h2Settings"].as_array().unwrap();
        assert_eq!(announced.len(), 4, "{announced:?}");
        for absent in [0x3, 0x5] {
            assert!(
                !announced.iter().any(|s| s["id"] == absent),
                "setting {absent:#x} is not announced and must not be listed: {announced:?}"
            );
        }
    }

    #[test]
    fn documented_ja3_never_alone_enables_parity() {
        let _guard = preset_lock();
        set_active_preset("chrome150").unwrap();
        let st = status_json();
        assert!(st["documentedJa3"].as_str().unwrap().len() == 32);
        assert_eq!(st["ja3Parity"], false);
        assert_eq!(st["supportsFullBrowserJa3"], false);
        assert_eq!(active_engine(), OutboundTlsEngine::Rustls);
        assert!(!impersonate_unavailable_reason().is_empty());
    }

    #[test]
    fn impersonate_engine_stays_rustls_without_linked_stack() {
        let _guard = preset_lock();
        crate::tls_impersonate::set_impersonate_requested(true);
        assert!(!real_impersonate_stack_available());
        assert_eq!(active_engine(), OutboundTlsEngine::Rustls);
        assert!(!active_engine().supports_full_browser_ja3());
        let st = status_json();
        assert_eq!(st["supportsFullBrowserJa3"], false);
        assert_eq!(st["impersonateRequested"], true);
        assert!(st["impersonateUnavailableReason"]
            .as_str()
            .unwrap()
            .contains("no linked"));
        crate::tls_impersonate::set_impersonate_requested(false);
    }
}
