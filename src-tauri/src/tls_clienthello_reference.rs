//! Industry reference matrix for versioned ClientHello presets.
//!
//! These IDs are **audited from public open-source catalogs** (not vendored code).
//! Tests check that ShowNet's product catalog covers the same *version floor* and
//! that our shipped builder path is **internally consistent** for those IDs.
//!
//! Sources (read-only references):
//! - bogdanfinn/tls-client `profiles/profiles.go` `MappedTLSClients` + `DefaultClientProfile = Chrome_150`
//! - refraction-networking/utls `HelloChrome_*` / `HelloFirefox_*` in `u_common.go`
//! - lwthiker/curl-impersonate `browsers.json` (older majors; active fork: lexiforest/curl-impersonate)
//! - 0x676e67/wreq Emulation::ChromeNNN naming class
//!
//! Honesty: rustls recipe presets are **not** bit-identical to uTLS/curl-impersonate
//! ClientHello; tests never require measured JA3 == real browser JA3.

use crate::tls_clienthello_catalog::{self, ClientHelloPreset};
// ClientHelloPreset used in preset_row
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// One industry preset we map onto a ShowNet catalog id.
#[derive(Clone, Copy, Debug)]
pub struct IndustryRef {
    /// Id as published by the upstream project (e.g. `chrome_150`, `HelloChrome_131`).
    pub industry_id: &'static str,
    /// Upstream project key.
    pub source: &'static str,
    /// ShowNet catalog id that should cover this reference.
    pub our_id: &'static str,
    /// Must exist in catalog for acceptance (core floor).
    pub required: bool,
}

/// Core industry coverage floor — versions that serious clients ship and we must have.
pub const INDUSTRY_REFS: &[IndustryRef] = &[
    // ---- bogdanfinn/tls-client (profiles.go) ----
    IndustryRef {
        industry_id: "chrome_120",
        source: "bogdanfinn/tls-client",
        our_id: "chrome120",
        required: true,
    },
    IndustryRef {
        industry_id: "chrome_124",
        source: "bogdanfinn/tls-client",
        our_id: "chrome124",
        required: true,
    },
    IndustryRef {
        industry_id: "chrome_131",
        source: "bogdanfinn/tls-client",
        our_id: "chrome131",
        required: true,
    },
    IndustryRef {
        industry_id: "chrome_133",
        source: "bogdanfinn/tls-client",
        our_id: "chrome133",
        required: true,
    },
    IndustryRef {
        industry_id: "chrome_144",
        source: "bogdanfinn/tls-client",
        our_id: "chrome144",
        required: true,
    },
    IndustryRef {
        industry_id: "chrome_146",
        source: "bogdanfinn/tls-client",
        our_id: "chrome146",
        required: true,
    },
    IndustryRef {
        industry_id: "chrome_150",
        source: "bogdanfinn/tls-client",
        our_id: "chrome150",
        required: true,
    },
    IndustryRef {
        industry_id: "DefaultClientProfile=Chrome_150",
        source: "bogdanfinn/tls-client",
        our_id: "chrome150",
        required: true,
    },
    IndustryRef {
        industry_id: "firefox_133",
        source: "bogdanfinn/tls-client",
        our_id: "firefox133",
        required: true,
    },
    IndustryRef {
        industry_id: "safari_ios_18_0",
        source: "bogdanfinn/tls-client",
        our_id: "safari-ios18",
        required: true,
    },
    // ---- refraction-networking/utls ----
    IndustryRef {
        industry_id: "HelloChrome_120",
        source: "refraction-networking/utls",
        our_id: "chrome120",
        required: true,
    },
    IndustryRef {
        industry_id: "HelloChrome_131",
        source: "refraction-networking/utls",
        our_id: "chrome131",
        required: true,
    },
    IndustryRef {
        industry_id: "HelloChrome_133",
        source: "refraction-networking/utls",
        our_id: "chrome133",
        required: true,
    },
    IndustryRef {
        industry_id: "HelloFirefox_133",
        source: "refraction-networking/utls",
        our_id: "firefox133",
        required: true,
    },
    // ---- curl-impersonate browsers.json (legacy floor) ----
    IndustryRef {
        industry_id: "chrome116",
        source: "lwthiker/curl-impersonate",
        our_id: "chrome120", // nearest catalog major ≥ 116 era
        required: false,
    },
    IndustryRef {
        industry_id: "ff117",
        source: "lwthiker/curl-impersonate",
        our_id: "firefox128",
        required: false,
    },
    // ---- wreq class ----
    IndustryRef {
        industry_id: "Emulation::Chrome149",
        source: "0x676e67/wreq",
        our_id: "chrome149",
        required: true,
    },
    IndustryRef {
        industry_id: "Emulation::Chrome150-class",
        source: "0x676e67/wreq+tls-client",
        our_id: "chrome150",
        required: true,
    },
];

/// Normalize industry-style ids (`chrome_150`, `HelloChrome_131`, `Chrome_150`) → our `chrome150`.
pub fn normalize_industry_id(raw: &str) -> String {
    let s = raw.trim().to_ascii_lowercase();
    let s = s
        .strip_prefix("hello")
        .unwrap_or(&s)
        .trim_matches(|c: char| c == '_' || c == '-');
    let s = s
        .replace("chrome_", "chrome")
        .replace("firefox_", "firefox")
        .replace("edge_", "edge")
        .replace("safari_ios_", "safari-ios")
        .replace("safari_ios", "safari-ios")
        .replace("emulation::", "")
        .replace("emulation:", "");
    // chrome150-class → chrome150
    if let Some(base) = s.strip_suffix("-class") {
        return base.to_string();
    }
    s.replace('_', "")
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageRow {
    pub industry_id: String,
    pub source: String,
    pub our_id: String,
    pub required: bool,
    pub present: bool,
    pub major_version: Option<u16>,
    pub family: Option<String>,
    pub recipe_fingerprint: Option<String>,
    pub claims_full_browser_ja3: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsistencyReport {
    pub catalog_len: usize,
    pub required_ok: bool,
    pub missing_required: Vec<String>,
    pub chrome_majors: Vec<u16>,
    pub unique_chrome_recipes: bool,
    pub default_preset_id: String,
    pub rows: Vec<CoverageRow>,
    pub note: String,
}

fn preset_row(r: &IndustryRef, p: Option<&ClientHelloPreset>) -> CoverageRow {
    CoverageRow {
        industry_id: r.industry_id.to_string(),
        source: r.source.to_string(),
        our_id: r.our_id.to_string(),
        required: r.required,
        present: p.is_some(),
        major_version: p.map(|x| x.major_version),
        family: p.map(|x| x.family.to_string()),
        recipe_fingerprint: p.map(tls_clienthello_catalog::recipe_fingerprint),
        claims_full_browser_ja3: false,
    }
}

/// Build a full coverage report vs industry references.
pub fn consistency_report() -> ConsistencyReport {
    let mut missing = Vec::new();
    let mut rows = Vec::new();
    for r in INDUSTRY_REFS {
        let p = tls_clienthello_catalog::get_preset(r.our_id).ok();
        if r.required && p.is_none() {
            missing.push(format!("{} → {}", r.industry_id, r.our_id));
        }
        rows.push(preset_row(r, p));
    }
    let chrome_majors: Vec<u16> = tls_clienthello_catalog::catalog()
        .iter()
        .filter(|p| p.family == "chrome" && p.major_version > 0)
        .map(|p| p.major_version)
        .collect();
    let mut fps = BTreeSet::new();
    let mut unique = true;
    for p in tls_clienthello_catalog::catalog()
        .iter()
        .filter(|p| p.family == "chrome" && p.major_version > 0)
    {
        let fp = tls_clienthello_catalog::recipe_fingerprint(p);
        if !fps.insert(fp) {
            unique = false;
        }
    }
    ConsistencyReport {
        catalog_len: tls_clienthello_catalog::catalog_len(),
        required_ok: missing.is_empty(),
        missing_required: missing,
        chrome_majors,
        unique_chrome_recipes: unique,
        default_preset_id: tls_clienthello_catalog::active_preset_id(),
        rows,
        note: "rustls recipe catalog approximates version tags; not bit-level uTLS/curl-impersonate parity."
            .into(),
    }
}

/// All required industry `our_id`s that must exist.
pub fn required_our_ids() -> BTreeSet<&'static str> {
    INDUSTRY_REFS
        .iter()
        .filter(|r| r.required)
        .map(|r| r.our_id)
        .collect()
}

/// Chrome majors that industry clients commonly version (floor for coverage).
pub const INDUSTRY_CHROME_MAJORS_FLOOR: &[u16] = &[120, 124, 131, 133, 144, 146, 149, 150];

/// Pairwise recipe fingerprints for a list of catalog ids (for wire/builder tests).
pub fn recipe_fingerprints(ids: &[&str]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for id in ids {
        let p = tls_clienthello_catalog::get_preset(id)?;
        out.insert(
            (*id).to_string(),
            tls_clienthello_catalog::recipe_fingerprint(p),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_outbound::{
        self, builder_cipher_fingerprint_for_profile, preset_cipher_fingerprint,
        preset_id_for_profile, OutboundTlsProfile,
    };
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn industry_required_ids_exist_in_catalog() {
        let report = consistency_report();
        assert!(
            report.required_ok,
            "missing required industry mappings: {:?}",
            report.missing_required
        );
        for id in required_our_ids() {
            let p = tls_clienthello_catalog::get_preset(id).expect(id);
            let view = tls_clienthello_catalog::preset_view(p);
            assert!(
                !view.claims_full_browser_ja3,
                "{id} must not claim full browser JA3 under rustls"
            );
        }
    }

    #[test]
    fn industry_chrome_major_floor_covered() {
        let majors: HashSet<u16> = tls_clienthello_catalog::catalog()
            .iter()
            .filter(|p| p.family == "chrome" && p.major_version > 0)
            .map(|p| p.major_version)
            .collect();
        for m in INDUSTRY_CHROME_MAJORS_FLOOR {
            assert!(
                majors.contains(m),
                "catalog missing Chrome major {m} required by industry floor"
            );
        }
    }

    #[test]
    fn all_versioned_chrome_recipes_are_unique() {
        let report = consistency_report();
        assert!(
            report.unique_chrome_recipes,
            "two chrome majors share recipe fingerprint — label-only duplicate"
        );
        // Explicit pairwise for industry floor
        let ids: Vec<String> = INDUSTRY_CHROME_MAJORS_FLOOR
            .iter()
            .map(|m| format!("chrome{m}"))
            .collect();
        let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
        let fps = recipe_fingerprints(&refs).unwrap();
        let set: HashSet<_> = fps.values().cloned().collect();
        assert_eq!(
            set.len(),
            fps.len(),
            "industry chrome floor recipes must be pairwise unique: {fps:?}"
        );
    }

    #[test]
    fn normalize_industry_ids_to_our_form() {
        assert_eq!(normalize_industry_id("chrome_150"), "chrome150");
        assert_eq!(normalize_industry_id("HelloChrome_131"), "chrome131");
        assert_eq!(normalize_industry_id("firefox_133"), "firefox133");
        assert_eq!(normalize_industry_id("Emulation::Chrome149"), "chrome149");
    }

    #[test]
    fn selection_builder_path_matches_industry_chrome_ids() {
        let _g = lock();
        for id in [
            "chrome120",
            "chrome131",
            "chrome133",
            "chrome150",
            "chrome146",
        ] {
            tls_outbound::set_active_preset(id).unwrap();
            assert_eq!(
                preset_id_for_profile(OutboundTlsProfile::ChromeLike),
                id,
                "active {id} must drive ChromeLike builder resolution"
            );
            let fp = builder_cipher_fingerprint_for_profile(OutboundTlsProfile::ChromeLike);
            assert_eq!(
                fp,
                preset_cipher_fingerprint(id).unwrap(),
                "builder material for {id}"
            );
            let cfg = tls_outbound::build_client_config(OutboundTlsProfile::ChromeLike);
            assert!(cfg.enable_sni);
            assert_eq!(
                cfg.alpn_protocols.first().map(|p| p.as_slice()),
                Some(&b"h2"[..])
            );
            let status = tls_outbound::status_json();
            assert_eq!(status["presetId"], id);
            assert_eq!(status["ja3Parity"], false);
            assert_eq!(status["supportsFullBrowserJa3"], false);
        }
        tls_outbound::set_active_preset("chrome150").unwrap();
    }

    #[test]
    fn cross_family_industry_ids_differ_in_builder_material() {
        let _g = lock();
        tls_outbound::set_active_preset("chrome150").unwrap();
        let chrome = builder_cipher_fingerprint_for_profile(OutboundTlsProfile::ChromeLike);
        tls_outbound::set_active_preset("firefox133").unwrap();
        let firefox = builder_cipher_fingerprint_for_profile(OutboundTlsProfile::FirefoxLike);
        tls_outbound::set_active_preset("safari-ios18").unwrap();
        let safari = builder_cipher_fingerprint_for_profile(OutboundTlsProfile::SafariIosLike);
        assert_ne!(chrome, firefox);
        assert_ne!(chrome, safari);
        assert_ne!(firefox, safari);
        tls_outbound::set_active_preset("chrome150").unwrap();
    }

    #[test]
    fn default_product_preset_aligns_tls_client_chrome_150() {
        let _g = lock();
        tls_outbound::set_active_preset("chrome150").unwrap();
        assert_eq!(tls_outbound::active_preset_id(), "chrome150");
        assert_eq!(
            tls_outbound::global_profile(),
            OutboundTlsProfile::ChromeLike
        );
        // tls-client DefaultClientProfile = Chrome_150
        assert_eq!(
            preset_id_for_profile(OutboundTlsProfile::ChromeLike),
            "chrome150"
        );
    }

    #[test]
    fn consistency_report_serializable_for_audit() {
        let report = consistency_report();
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("chrome150"));
        assert!(json.contains("bogdanfinn/tls-client"));
        assert!(report.catalog_len >= 25);
        assert!(report.required_ok);
    }
}
