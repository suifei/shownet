//! Golden ClientHello fingerprints and the alignment ladder.
//!
//! A preset may only claim it resembles a real client when a *measured* outbound
//! JA3 equals a golden captured from that client. This module owns the golden
//! store and the ladder; it deliberately owns no connector and performs no I/O.
//!
//! Data lives in `src-tauri/testdata/tls-golden/`; see the README there and
//! `docs/plan-real-browser-ja3-impersonate.md` §4.
//!
//! Nothing here can raise `ja3Parity` on its own: parity additionally requires a
//! real impersonate stack to be linked (see `tls_outbound::real_impersonate_stack_available`).

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// How closely a preset's outbound ClientHello has been *shown* to match a target.
///
/// Strictly ascending. The rung is capped by how the golden was captured: a
/// capture from an impersonation tool can never authorise `BrowserMatched`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AlignmentLevel {
    /// rustls cipher/kx/ALPN reordering only. Produces distinguishable material,
    /// but says nothing about resembling a browser.
    #[default]
    Recipe,
    /// Measured JA3 equals a golden captured from an impersonation tool.
    ToolMatched,
    /// Measured JA3 equals a golden captured from the real browser.
    BrowserMatched,
}

impl AlignmentLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recipe => "recipe",
            Self::ToolMatched => "tool-matched",
            Self::BrowserMatched => "browser-matched",
        }
    }

    /// Wording the UI, Agent tools and generated code are allowed to use.
    /// Never let a caller invent its own phrasing for these rungs.
    pub fn claim(self) -> &'static str {
        match self {
            Self::Recipe => "出站预置（rustls 配方），不代表浏览器级对齐",
            Self::ToolMatched => "已对齐 impersonate 工具金标（非真实浏览器抓包）",
            Self::BrowserMatched => "已对齐真实浏览器抓包金标",
        }
    }

    /// True once a measurement has actually matched something.
    pub fn is_matched(self) -> bool {
        !matches!(self, Self::Recipe)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GoldenStatus {
    /// Placeholder. Fingerprints are absent and the gate treats it as no golden.
    PendingCapture,
    Captured,
    /// Target client moved on; the gate must fall back to `Recipe`.
    Superseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureKind {
    BrowserCapture,
    ToolCapture,
    Pending,
}

impl CaptureKind {
    /// The highest rung this capture method may ever authorise.
    fn ceiling(self) -> AlignmentLevel {
        match self {
            Self::BrowserCapture => AlignmentLevel::BrowserMatched,
            Self::ToolCapture => AlignmentLevel::ToolMatched,
            Self::Pending => AlignmentLevel::Recipe,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureSource {
    pub kind: CaptureKind,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub captured_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoldenFingerprint {
    pub ja3: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja4: Option<String>,
    pub ja4_raw: Option<String>,
    /// Authoritative artefact — ja3/ja4 above are derived and can be recomputed.
    pub client_hello_hex: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoldenEntry {
    pub preset_id: String,
    pub platform: String,
    pub family: String,
    pub major: u32,
    pub stack: String,
    #[serde(default)]
    pub stack_version: Option<String>,
    pub status: GoldenStatus,
    pub alignment: AlignmentLevel,
    pub source: CaptureSource,
    pub golden: GoldenFingerprint,
    #[serde(default)]
    pub notes: Option<String>,
}

impl GoldenEntry {
    /// Usable by the gate only when captured *and* carrying a JA3.
    pub fn is_usable(&self) -> bool {
        matches!(self.status, GoldenStatus::Captured) && self.golden.ja3.is_some()
    }

    /// The rung this entry may authorise, clamped by its capture method.
    /// A declared `alignment` can never exceed what the capture supports.
    pub fn authorised_level(&self) -> AlignmentLevel {
        if !self.is_usable() {
            return AlignmentLevel::Recipe;
        }
        self.alignment.min(self.source.kind.ceiling())
    }
}

/// Embedded golden entries.
///
/// `include_str!` cannot glob, so the set is explicit. `embedded_matches_testdata_dir`
/// fails if a file is added to the directory without being listed here — otherwise a
/// new golden would silently never reach the gate.
const EMBEDDED: &[(&str, &str)] = &[
    // Multi-version desktop-windows industry floor (pending-capture stubs).
    (
        "chrome120--desktop-windows",
        include_str!("../testdata/tls-golden/entries/chrome120--desktop-windows.json"),
    ),
    (
        "chrome124--desktop-windows",
        include_str!("../testdata/tls-golden/entries/chrome124--desktop-windows.json"),
    ),
    (
        "chrome131--desktop-linux",
        include_str!("../testdata/tls-golden/entries/chrome131--desktop-linux.json"),
    ),
    (
        "chrome131--desktop-macos",
        include_str!("../testdata/tls-golden/entries/chrome131--desktop-macos.json"),
    ),
    (
        "chrome131--desktop-windows",
        include_str!("../testdata/tls-golden/entries/chrome131--desktop-windows.json"),
    ),
    (
        "chrome133--desktop-windows",
        include_str!("../testdata/tls-golden/entries/chrome133--desktop-windows.json"),
    ),
    (
        "chrome144--desktop-windows",
        include_str!("../testdata/tls-golden/entries/chrome144--desktop-windows.json"),
    ),
    (
        "chrome146--desktop-windows",
        include_str!("../testdata/tls-golden/entries/chrome146--desktop-windows.json"),
    ),
    (
        "chrome149--desktop-windows",
        include_str!("../testdata/tls-golden/entries/chrome149--desktop-windows.json"),
    ),
    // P0 matrix: chrome150 multi-platform + mobile + iOS.
    (
        "chrome150--desktop-macos",
        include_str!("../testdata/tls-golden/entries/chrome150--desktop-macos.json"),
    ),
    (
        "chrome150--desktop-windows",
        include_str!("../testdata/tls-golden/entries/chrome150--desktop-windows.json"),
    ),
    (
        "chrome150--desktop-linux",
        include_str!("../testdata/tls-golden/entries/chrome150--desktop-linux.json"),
    ),
    (
        "chrome-android131--android",
        include_str!("../testdata/tls-golden/entries/chrome-android131--android.json"),
    ),
    (
        "chrome-android150--android",
        include_str!("../testdata/tls-golden/entries/chrome-android150--android.json"),
    ),
    (
        "safari-ios18--ios",
        include_str!("../testdata/tls-golden/entries/safari-ios18--ios.json"),
    ),
];

fn entries() -> &'static Vec<GoldenEntry> {
    static ENTRIES: OnceLock<Vec<GoldenEntry>> = OnceLock::new();
    ENTRIES.get_or_init(|| {
        EMBEDDED
            .iter()
            .map(|(name, raw)| {
                serde_json::from_str::<GoldenEntry>(raw)
                    .unwrap_or_else(|error| panic!("golden entry {name} is malformed: {error}"))
            })
            .collect()
    })
}

/// Build-target platform key, matching the `platform` field in the store.
///
/// Desktop only — a mobile golden is never selected by a desktop build, which is
/// what keeps a desktop capture from gating an Android or iOS preset.
pub fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "desktop-macos"
    } else if cfg!(target_os = "windows") {
        "desktop-windows"
    } else {
        "desktop-linux"
    }
}

pub fn golden_for(preset_id: &str, platform: &str) -> Option<&'static GoldenEntry> {
    entries()
        .iter()
        .find(|e| e.preset_id == preset_id && e.platform == platform)
}

/// Rung a preset may claim on this platform *before* the measurement check.
/// Always `Recipe` while nothing is captured.
pub fn alignment_for(preset_id: &str) -> AlignmentLevel {
    golden_for(preset_id, current_platform())
        .map(GoldenEntry::authorised_level)
        .unwrap_or_default()
}

/// The gate: a measured JA3 promotes a preset only on an exact match against a
/// usable golden. Any mismatch, or no golden at all, stays at `Recipe`.
pub fn evaluate(preset_id: &str, measured_ja3: &str) -> AlignmentLevel {
    let Some(entry) = golden_for(preset_id, current_platform()) else {
        return AlignmentLevel::Recipe;
    };
    if !entry.is_usable() {
        return AlignmentLevel::Recipe;
    }
    match entry.golden.ja3.as_deref() {
        Some(golden) if golden.eq_ignore_ascii_case(measured_ja3) => entry.authorised_level(),
        _ => AlignmentLevel::Recipe,
    }
}

/// Status surface for `tls_outbound::status_json` and the Agent tools.
pub fn status_json(preset_id: &str) -> serde_json::Value {
    let platform = current_platform();
    let entry = golden_for(preset_id, platform);
    serde_json::json!({
        "alignmentLevel": alignment_for(preset_id).as_str(),
        "alignmentClaim": alignment_for(preset_id).claim(),
        "platform": platform,
        "goldenStatus": entry.map(|e| match e.status {
            GoldenStatus::PendingCapture => "pending-capture",
            GoldenStatus::Captured => "captured",
            GoldenStatus::Superseded => "superseded",
        }),
        "goldenSource": entry.map(|e| match e.source.kind {
            CaptureKind::BrowserCapture => "browser-capture",
            CaptureKind::ToolCapture => "tool-capture",
            CaptureKind::Pending => "pending",
        }),
        "goldenCapturedAt": entry.and_then(|e| e.source.captured_at.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_embedded_entry_parses() {
        assert_eq!(entries().len(), EMBEDDED.len());
    }

    #[test]
    fn embedded_matches_testdata_dir() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/tls-golden/entries");
        let mut on_disk: Vec<String> = std::fs::read_dir(dir)
            .expect("golden entries directory")
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".json"))
            .map(|n| n.trim_end_matches(".json").to_string())
            .collect();
        on_disk.sort();
        let mut embedded: Vec<String> = EMBEDDED.iter().map(|(n, _)| n.to_string()).collect();
        embedded.sort();
        assert_eq!(
            embedded, on_disk,
            "a golden file exists that is not embedded (or vice versa); it would never reach the gate"
        );
    }

    // The whole point of the store: nothing is captured yet, so nothing may claim alignment.
    #[test]
    fn nothing_is_aligned_before_capture() {
        for entry in entries() {
            assert_eq!(
                entry.authorised_level(),
                AlignmentLevel::Recipe,
                "{} is still pending capture and must stay at recipe",
                entry.preset_id
            );
            assert!(!entry.is_usable());
        }
        assert_eq!(alignment_for("chrome150"), AlignmentLevel::Recipe);
    }

    #[test]
    fn unknown_preset_is_recipe() {
        assert_eq!(alignment_for("does-not-exist"), AlignmentLevel::Recipe);
        assert_eq!(
            evaluate("does-not-exist", "ab063844a93885b408c5a0bfcb2444c6"),
            AlignmentLevel::Recipe
        );
    }

    /// A documented JA3 from the catalog must not slip through as a match.
    #[test]
    fn documented_ja3_does_not_satisfy_the_gate() {
        let documented = crate::tls_clienthello_catalog::catalog_documented_ja3("chrome150")
            .expect("chrome150 has a documented ja3");
        assert_eq!(evaluate("chrome150", documented), AlignmentLevel::Recipe);
    }

    #[test]
    fn capture_kind_caps_the_declared_level() {
        let mut entry = entries()[0].clone();
        entry.status = GoldenStatus::Captured;
        entry.golden.ja3 = Some("00112233445566778899aabbccddeeff".into());
        // A tool capture may not be promoted to browser-matched by declaration alone.
        entry.source.kind = CaptureKind::ToolCapture;
        entry.alignment = AlignmentLevel::BrowserMatched;
        assert_eq!(entry.authorised_level(), AlignmentLevel::ToolMatched);
    }

    #[test]
    fn mismatched_measurement_stays_at_recipe() {
        let mut entry = entries()[0].clone();
        entry.status = GoldenStatus::Captured;
        entry.golden.ja3 = Some("00112233445566778899aabbccddeeff".into());
        entry.source.kind = CaptureKind::BrowserCapture;
        entry.alignment = AlignmentLevel::BrowserMatched;
        assert_eq!(entry.authorised_level(), AlignmentLevel::BrowserMatched);
        // but a different measurement must not match
        assert_eq!(
            evaluate(&entry.preset_id, "ffffffffffffffffffffffffffffffff"),
            AlignmentLevel::Recipe
        );
    }

    #[test]
    fn superseded_golden_is_not_usable() {
        let mut entry = entries()[0].clone();
        entry.status = GoldenStatus::Superseded;
        entry.golden.ja3 = Some("00112233445566778899aabbccddeeff".into());
        assert!(!entry.is_usable());
        assert_eq!(entry.authorised_level(), AlignmentLevel::Recipe);
    }

    #[test]
    fn alignment_ladder_is_ordered() {
        assert!(AlignmentLevel::Recipe < AlignmentLevel::ToolMatched);
        assert!(AlignmentLevel::ToolMatched < AlignmentLevel::BrowserMatched);
        assert!(!AlignmentLevel::Recipe.is_matched());
        assert!(AlignmentLevel::ToolMatched.is_matched());
    }

    #[test]
    fn status_json_reports_recipe_and_pending() {
        let status = status_json("chrome150");
        assert_eq!(status["alignmentLevel"], "recipe");
        assert_eq!(status["goldenStatus"], "pending-capture");
        assert_eq!(status["goldenSource"], "pending");
        assert!(status["goldenCapturedAt"].is_null());
    }

    #[test]
    fn apple_client_is_not_labelled_boringssl() {
        let ios = golden_for("safari-ios18", "ios").expect("ios entry");
        assert_ne!(ios.stack, "chromium-boringssl");
        assert_eq!(ios.stack, "apple-network");
    }

    /// A desktop build must never pick up the Android or iOS golden.
    #[test]
    fn desktop_platform_never_selects_a_mobile_golden() {
        assert!(golden_for("chrome-android150", current_platform()).is_none());
        assert!(golden_for("safari-ios18", current_platform()).is_none());
        assert_eq!(alignment_for("chrome-android150"), AlignmentLevel::Recipe);
    }
}
