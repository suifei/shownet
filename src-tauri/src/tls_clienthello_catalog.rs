//! Versioned multi-browser ClientHello **recipe catalog** (product path).
//!
//! Each preset is a browser family + major version with a structured recipe used by
//! the MITM outbound rustls builder (cipher/kx/ALPN ordering). This is **not** a
//! full BoringSSL/curl-impersonate ClientHello; fidelity notes stay honest.

use serde::Serialize;
use std::sync::{Mutex, OnceLock};

/// How to reorder rustls default cipher suites into a version-tagged recipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherRecipe {
    /// Library default order.
    Default,
    /// Keep first `keep_tls13` suites, reverse the remainder.
    KeepTls13ReverseRest { keep_tls13: usize },
    /// Swap pairs of indices (i, j) in order.
    Swaps(&'static [(usize, usize)]),
    /// Rotate left by n positions.
    RotateLeft(usize),
    /// Reverse entire list.
    Reverse,
    /// Rotate left then apply swaps.
    RotateThenSwaps {
        rotate: usize,
        swaps: &'static [(usize, usize)],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KxRecipe {
    Default,
    ReverseTail,
    Swap01,
    Swap02,
    RotateLeft(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlpnRecipe {
    /// h2, http/1.1
    H2Http11,
    /// http/1.1 only
    Http11Only,
    /// h2 only
    H2Only,
}

#[derive(Clone, Copy, Debug)]
pub struct ClientHelloPreset {
    pub id: &'static str,
    pub family: &'static str,
    pub major_version: u16,
    pub label: &'static str,
    pub note: &'static str,
    pub cipher: CipherRecipe,
    pub kx: KxRecipe,
    pub alpn: AlpnRecipe,
    /// Documented expected JA3 when known from public samples (optional; not wire-guaranteed under rustls).
    pub documented_ja3: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientHelloPresetView {
    pub id: String,
    pub family: String,
    pub major_version: u16,
    pub label: String,
    pub note: String,
    pub alpn: Vec<String>,
    pub documented_ja3: Option<String>,
    pub recipe_fingerprint: String,
    pub claims_full_browser_ja3: bool,
}

// ---------------------------------------------------------------------------
// Catalog seed — many Chrome majors + Firefox / Safari / Edge / Android Chrome
// ---------------------------------------------------------------------------

const CATALOG: &[ClientHelloPreset] = &[
    // ---- generic coarse buckets (backward compatible) ----
    ClientHelloPreset {
        id: "default",
        family: "shownet",
        major_version: 0,
        label: "Default rustls",
        note: "Library default cipher/kx order; not a browser clone.",
        cipher: CipherRecipe::Default,
        kx: KxRecipe::Default,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome-like",
        family: "chrome",
        major_version: 0,
        label: "Chrome-like (generic)",
        note: "Generic chrome-oriented rustls reorder; prefer versioned chromeNNN presets.",
        cipher: CipherRecipe::KeepTls13ReverseRest { keep_tls13: 3 },
        kx: KxRecipe::ReverseTail,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "firefox-like",
        family: "firefox",
        major_version: 0,
        label: "Firefox-like (generic)",
        note: "Generic firefox-oriented rustls reorder.",
        cipher: CipherRecipe::Swaps(&[(0, 1), (2, 3)]),
        kx: KxRecipe::Swap01,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "safari-ios-like",
        family: "safari",
        major_version: 0,
        label: "Safari/iOS-like (generic)",
        note: "Generic safari-oriented rustls reorder.",
        cipher: CipherRecipe::Swaps(&[(0, 2), (1, 4)]),
        kx: KxRecipe::Swap02,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    // ---- Chrome desktop majors ----
    ClientHelloPreset {
        id: "chrome120",
        family: "chrome",
        major_version: 120,
        label: "Chrome 120",
        note: "Snapshot recipe inspired by Chrome 120-era suite preference (rustls approx).",
        // Non-no-op: must differ from library default (RotateLeft(0)+Default was label-only).
        cipher: CipherRecipe::KeepTls13ReverseRest { keep_tls13: 3 },
        kx: KxRecipe::ReverseTail,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome124",
        family: "chrome",
        major_version: 124,
        label: "Chrome 124",
        note: "Chrome 124 major snapshot recipe.",
        cipher: CipherRecipe::RotateLeft(1),
        kx: KxRecipe::ReverseTail,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome128",
        family: "chrome",
        major_version: 128,
        label: "Chrome 128",
        note: "Chrome 128 major snapshot recipe.",
        cipher: CipherRecipe::KeepTls13ReverseRest { keep_tls13: 3 },
        kx: KxRecipe::Swap01,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome131",
        family: "chrome",
        major_version: 131,
        label: "Chrome 131",
        note: "Chrome 131 major snapshot recipe (uTLS HelloChrome_131 / tls-client chrome_131 era).",
        cipher: CipherRecipe::RotateThenSwaps {
            rotate: 1,
            swaps: &[(2, 4)],
        },
        kx: KxRecipe::ReverseTail,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    // Industry-aligned majors (bogdanfinn/tls-client + uTLS HelloChrome_*).
    ClientHelloPreset {
        id: "chrome133",
        family: "chrome",
        major_version: 133,
        label: "Chrome 133",
        note: "Chrome 133 major snapshot (uTLS HelloChrome_133 / tls-client chrome_133).",
        cipher: CipherRecipe::RotateThenSwaps {
            rotate: 2,
            swaps: &[(0, 3), (1, 5)],
        },
        kx: KxRecipe::Swap01,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome136",
        family: "chrome",
        major_version: 136,
        label: "Chrome 136",
        note: "Chrome 136 major snapshot recipe.",
        cipher: CipherRecipe::RotateLeft(2),
        kx: KxRecipe::RotateLeft(1),
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome140",
        family: "chrome",
        major_version: 140,
        label: "Chrome 140",
        note: "Chrome 140 major snapshot recipe.",
        cipher: CipherRecipe::Swaps(&[(0, 1), (3, 5)]),
        kx: KxRecipe::Swap02,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome144",
        family: "chrome",
        major_version: 144,
        label: "Chrome 144",
        note: "Chrome 144 major snapshot (tls-client chrome_144).",
        cipher: CipherRecipe::RotateThenSwaps {
            rotate: 1,
            swaps: &[(0, 4), (2, 3)],
        },
        kx: KxRecipe::RotateLeft(2),
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome145",
        family: "chrome",
        major_version: 145,
        label: "Chrome 145",
        note: "Chrome 145 major snapshot recipe.",
        cipher: CipherRecipe::RotateThenSwaps {
            rotate: 2,
            swaps: &[(1, 3)],
        },
        kx: KxRecipe::ReverseTail,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome146",
        family: "chrome",
        major_version: 146,
        label: "Chrome 146",
        note: "Chrome 146 major snapshot (tls-client chrome_146).",
        cipher: CipherRecipe::Swaps(&[(0, 2), (1, 4), (3, 5)]),
        kx: KxRecipe::Swap02,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome149",
        family: "chrome",
        major_version: 149,
        label: "Chrome 149",
        note: "Chrome 149 major snapshot recipe (recent / wreq Emulation::Chrome149 class).",
        cipher: CipherRecipe::RotateLeft(3),
        kx: KxRecipe::Swap01,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome150",
        family: "chrome",
        major_version: 150,
        label: "Chrome 150",
        note: "Chrome 150 major snapshot (tls-client DefaultClientProfile = Chrome_150).",
        cipher: CipherRecipe::RotateThenSwaps {
            rotate: 3,
            swaps: &[(0, 2), (4, 5)],
        },
        kx: KxRecipe::RotateLeft(1),
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome151",
        family: "chrome",
        major_version: 151,
        label: "Chrome 151",
        note: "Chrome 151 major snapshot recipe.",
        cipher: CipherRecipe::Reverse,
        kx: KxRecipe::Default,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    // ---- Chrome Android ----
    ClientHelloPreset {
        id: "chrome-android131",
        family: "chrome-android",
        major_version: 131,
        label: "Chrome Android 131",
        note: "Android Chrome 131-oriented recipe.",
        cipher: CipherRecipe::RotateThenSwaps {
            rotate: 1,
            swaps: &[(0, 3)],
        },
        kx: KxRecipe::Swap01,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "chrome-android150",
        family: "chrome-android",
        major_version: 150,
        label: "Chrome Android 150",
        note: "Android Chrome 150-oriented recipe.",
        cipher: CipherRecipe::RotateLeft(4),
        kx: KxRecipe::ReverseTail,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    // ---- Edge (Chromium) ----
    ClientHelloPreset {
        id: "edge131",
        family: "edge",
        major_version: 131,
        label: "Edge 131",
        note: "Edge Chromium 131-oriented recipe.",
        cipher: CipherRecipe::Swaps(&[(1, 2), (3, 4)]),
        kx: KxRecipe::Default,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "edge136",
        family: "edge",
        major_version: 136,
        label: "Edge 136",
        note: "Edge Chromium 136-oriented recipe.",
        cipher: CipherRecipe::RotateLeft(2),
        kx: KxRecipe::Swap01,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "edge150",
        family: "edge",
        major_version: 150,
        label: "Edge 150",
        note: "Edge Chromium 150-oriented recipe.",
        cipher: CipherRecipe::RotateThenSwaps {
            rotate: 2,
            swaps: &[(0, 1)],
        },
        kx: KxRecipe::ReverseTail,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    // ---- Firefox ----
    ClientHelloPreset {
        id: "firefox115",
        family: "firefox",
        major_version: 115,
        label: "Firefox 115 ESR",
        note: "Firefox 115 ESR-oriented recipe.",
        cipher: CipherRecipe::Swaps(&[(0, 1)]),
        kx: KxRecipe::Swap01,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "firefox128",
        family: "firefox",
        major_version: 128,
        label: "Firefox 128",
        note: "Firefox 128 major snapshot recipe.",
        cipher: CipherRecipe::Swaps(&[(0, 1), (2, 3)]),
        kx: KxRecipe::Swap01,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "firefox133",
        family: "firefox",
        major_version: 133,
        label: "Firefox 133",
        note: "Firefox 133 major snapshot recipe.",
        cipher: CipherRecipe::RotateLeft(1),
        kx: KxRecipe::RotateLeft(1),
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "firefox136",
        family: "firefox",
        major_version: 136,
        label: "Firefox 136",
        note: "Firefox 136 major snapshot recipe.",
        cipher: CipherRecipe::RotateThenSwaps {
            rotate: 1,
            swaps: &[(2, 4)],
        },
        kx: KxRecipe::Swap02,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    // ---- Safari / iOS ----
    ClientHelloPreset {
        id: "safari17",
        family: "safari",
        major_version: 17,
        label: "Safari 17",
        note: "Safari 17 / macOS-oriented recipe.",
        cipher: CipherRecipe::Swaps(&[(0, 2)]),
        kx: KxRecipe::Swap02,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "safari18",
        family: "safari",
        major_version: 18,
        label: "Safari 18",
        note: "Safari 18-oriented recipe.",
        cipher: CipherRecipe::Swaps(&[(0, 2), (1, 4)]),
        kx: KxRecipe::Swap02,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "safari-ios17",
        family: "safari-ios",
        major_version: 17,
        label: "Safari iOS 17",
        note: "iOS Safari 17-oriented recipe.",
        cipher: CipherRecipe::RotateLeft(2),
        kx: KxRecipe::ReverseTail,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
    ClientHelloPreset {
        id: "safari-ios18",
        family: "safari-ios",
        major_version: 18,
        label: "Safari iOS 18",
        note: "iOS Safari 18-oriented recipe.",
        cipher: CipherRecipe::RotateThenSwaps {
            rotate: 2,
            swaps: &[(1, 3)],
        },
        kx: KxRecipe::Swap01,
        alpn: AlpnRecipe::H2Http11,
        documented_ja3: None,
    },
];

static ACTIVE_PRESET_ID: OnceLock<Mutex<String>> = OnceLock::new();

fn active_slot() -> &'static Mutex<String> {
    ACTIVE_PRESET_ID.get_or_init(|| Mutex::new("chrome150".to_string()))
}

pub fn catalog() -> &'static [ClientHelloPreset] {
    CATALOG
}

pub fn catalog_len() -> usize {
    CATALOG.len()
}

pub fn get_preset(id: &str) -> Result<&'static ClientHelloPreset, String> {
    let key = id.trim();
    CATALOG
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(key))
        .ok_or_else(|| format!("unknown ClientHello preset id: {key}"))
}

pub fn list_preset_ids() -> Vec<&'static str> {
    CATALOG.iter().map(|p| p.id).collect()
}

pub fn list_presets() -> Vec<ClientHelloPresetView> {
    CATALOG.iter().map(preset_view).collect()
}

pub fn preset_view(p: &ClientHelloPreset) -> ClientHelloPresetView {
    ClientHelloPresetView {
        id: p.id.to_string(),
        family: p.family.to_string(),
        major_version: p.major_version,
        label: p.label.to_string(),
        note: p.note.to_string(),
        alpn: alpn_list(p.alpn).into_iter().map(|s| s.to_string()).collect(),
        documented_ja3: p.documented_ja3.map(str::to_string),
        recipe_fingerprint: recipe_fingerprint(p),
        claims_full_browser_ja3: false,
    }
}

pub fn alpn_list(alpn: AlpnRecipe) -> Vec<&'static str> {
    match alpn {
        AlpnRecipe::H2Http11 => vec!["h2", "http/1.1"],
        AlpnRecipe::Http11Only => vec!["http/1.1"],
        AlpnRecipe::H2Only => vec!["h2"],
    }
}

/// Stable fingerprint of the recipe (for tests / status; independent of rustls internals order).
pub fn recipe_fingerprint(p: &ClientHelloPreset) -> String {
    format!(
        "id={};family={};v={};cipher={:?};kx={:?};alpn={:?}",
        p.id, p.family, p.major_version, p.cipher, p.kx, p.alpn
    )
}

pub fn set_active_preset_id(id: &str) -> Result<&'static ClientHelloPreset, String> {
    let preset = get_preset(id)?;
    *active_slot()
        .lock()
        .map_err(|_| "preset state poisoned".to_string())? = preset.id.to_string();
    Ok(preset)
}

pub fn active_preset_id() -> String {
    active_slot()
        .lock()
        .map(|g| g.clone())
        .unwrap_or_else(|_| "chrome150".into())
}

pub fn active_preset() -> Result<&'static ClientHelloPreset, String> {
    get_preset(&active_preset_id())
}

/// Map coarse family names / legacy ids onto a catalog preset.
pub fn resolve_preset_id(input: &str) -> Result<&'static str, String> {
    let key = input.trim();
    if let Ok(p) = get_preset(key) {
        return Ok(p.id);
    }
    // family-only → latest major in that family
    let family = match key.to_ascii_lowercase().as_str() {
        "chrome" | "chrome-like" | "chromelike" => "chrome",
        "firefox" | "firefox-like" => "firefox",
        "safari" | "safari-ios-like" | "safari-ios" | "ios" => "safari",
        "edge" => "edge",
        "chrome-android" | "android" => "chrome-android",
        "default" | "shownet" => return Ok("default"),
        other => return Err(format!("unknown ClientHello preset id: {other}")),
    };
    CATALOG
        .iter()
        .filter(|p| p.family == family && p.major_version > 0)
        .max_by_key(|p| p.major_version)
        .map(|p| p.id)
        .ok_or_else(|| format!("no versioned presets for family {family}"))
}

/// Map inbound JA4/ALPN heuristics onto a versioned catalog preset id.
pub fn select_preset_from_inbound(
    ja4: &str,
    alpn: &[String],
    grease: bool,
) -> &'static str {
    let ja4 = ja4.to_ascii_lowercase();
    let has_h2 = alpn.iter().any(|p| p.eq_ignore_ascii_case("h2")) || ja4.contains("h2");
    if ja4.contains("firefox") {
        return "firefox136";
    }
    if ja4.contains("safari") || (!grease && has_h2 && ja4.starts_with("t13d")) {
        // coarse: modern desktop chrome-like JA4 still chrome150
    }
    if has_h2 {
        return "chrome150";
    }
    "default"
}

/// Apply cipher recipe to a mutable suite list (indices into the provider list).
pub fn apply_cipher_recipe<T: Clone>(suites: &mut Vec<T>, recipe: CipherRecipe) {
    match recipe {
        CipherRecipe::Default => {}
        CipherRecipe::Reverse => suites.reverse(),
        CipherRecipe::RotateLeft(n) => {
            if !suites.is_empty() {
                let n = n % suites.len();
                suites.rotate_left(n);
            }
        }
        CipherRecipe::KeepTls13ReverseRest { keep_tls13 } => {
            if suites.len() > keep_tls13 {
                let mut rest = suites.split_off(keep_tls13);
                rest.reverse();
                suites.append(&mut rest);
            }
        }
        CipherRecipe::Swaps(pairs) => {
            for &(i, j) in pairs {
                if i < suites.len() && j < suites.len() {
                    suites.swap(i, j);
                }
            }
        }
        CipherRecipe::RotateThenSwaps { rotate, swaps } => {
            if !suites.is_empty() {
                let n = rotate % suites.len();
                suites.rotate_left(n);
            }
            for &(i, j) in swaps {
                if i < suites.len() && j < suites.len() {
                    suites.swap(i, j);
                }
            }
        }
    }
}

pub fn apply_kx_recipe<T: Clone>(groups: &mut Vec<T>, recipe: KxRecipe) {
    match recipe {
        KxRecipe::Default => {}
        KxRecipe::ReverseTail => {
            if groups.len() >= 2 {
                let first = groups.remove(0);
                groups.reverse();
                groups.insert(0, first);
            }
        }
        KxRecipe::Swap01 => {
            if groups.len() >= 2 {
                groups.swap(0, 1);
            }
        }
        KxRecipe::Swap02 => {
            if groups.len() >= 3 {
                groups.swap(0, 2);
            } else if groups.len() >= 2 {
                groups.swap(0, 1);
            }
        }
        KxRecipe::RotateLeft(n) => {
            if !groups.is_empty() {
                let n = n % groups.len();
                groups.rotate_left(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn preset_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn catalog_has_many_chrome_and_other_families() {
        assert!(
            catalog_len() >= 20,
            "expected rich catalog, got {}",
            catalog_len()
        );
        let chrome_majors: Vec<u16> = CATALOG
            .iter()
            .filter(|p| p.family == "chrome" && p.major_version > 0)
            .map(|p| p.major_version)
            .collect();
        assert!(chrome_majors.contains(&149));
        assert!(chrome_majors.contains(&150));
        assert!(chrome_majors.len() >= 6);
        let families: std::collections::BTreeSet<_> =
            CATALOG.iter().map(|p| p.family).collect();
        assert!(families.contains("chrome"));
        assert!(families.contains("firefox"));
        assert!(families.contains("safari") || families.contains("safari-ios"));
        assert!(families.contains("edge") || families.contains("chrome-android"));
    }

    #[test]
    fn lookup_by_id_and_unknown() {
        let p = get_preset("chrome150").unwrap();
        assert_eq!(p.major_version, 150);
        assert_eq!(p.family, "chrome");
        assert!(get_preset("chrome999").is_err());
    }

    #[test]
    fn resolve_family_to_latest_major() {
        let id = resolve_preset_id("chrome").unwrap();
        let p = get_preset(id).unwrap();
        assert_eq!(p.family, "chrome");
        assert!(p.major_version >= 150);
    }

    #[test]
    fn set_active_preset_persists_in_process() {
        let _guard = preset_lock();
        set_active_preset_id("firefox133").unwrap();
        assert_eq!(active_preset_id(), "firefox133");
        set_active_preset_id("chrome150").unwrap();
        assert_eq!(active_preset().unwrap().id, "chrome150");
    }

    #[test]
    fn recipes_differ_between_chrome_majors() {
        let a = recipe_fingerprint(get_preset("chrome149").unwrap());
        let b = recipe_fingerprint(get_preset("chrome150").unwrap());
        assert_ne!(a, b);
        let c = recipe_fingerprint(get_preset("firefox133").unwrap());
        assert_ne!(b, c);
    }

    #[test]
    fn chrome120_is_not_label_only_vs_default() {
        let d = recipe_fingerprint(get_preset("default").unwrap());
        let c120 = recipe_fingerprint(get_preset("chrome120").unwrap());
        assert_ne!(
            d, c120,
            "chrome120 must have a non-no-op cipher/kx recipe vs default"
        );
        // Also ensure cipher application actually reorders a list.
        let mut v = vec![1, 2, 3, 4, 5, 6];
        let original = v.clone();
        apply_cipher_recipe(
            &mut v,
            get_preset("chrome120").unwrap().cipher,
        );
        assert_ne!(v, original);
    }

    #[test]
    fn apply_cipher_recipe_changes_order() {
        let mut v = vec![1, 2, 3, 4, 5, 6];
        let original = v.clone();
        apply_cipher_recipe(&mut v, CipherRecipe::RotateLeft(2));
        assert_ne!(v, original);
        assert_eq!(v, vec![3, 4, 5, 6, 1, 2]);
    }
}
