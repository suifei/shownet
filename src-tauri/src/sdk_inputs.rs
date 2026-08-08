//! Gathers what `sdk_build` needs out of a stored session.
//!
//! Kept apart from the generator so the generator stays testable without a
//! database: `sdk_build` takes `SdkInputs` as data and never reaches for
//! storage itself. This is the only place that knows where each part lives.

use crate::algorithm_replay;
use crate::dataflow::build_dataflow;
use crate::endpoint_model::{build_endpoint_model, EndpointModel};
use crate::sdk_build::{FingerprintContract, SdkInputs, VerifiedCryptoStep};
use crate::storage::Storage;
use crate::tls_outbound;

/// Which curl_cffi target stands in for a ShowNet ClientHello preset.
///
/// Approximate on purpose, and the package says so. ShowNet's rustls presets
/// carry a `documented_ja3` that the catalog itself marks as "not
/// wire-guaranteed under rustls", while curl_cffi's targets are real browser
/// handshakes — so the generated client may present a *closer* match than the
/// capture did, or a different one. `check_fingerprint()` is what settles it,
/// which is the reason the SDK measures instead of asserting.
fn impersonate_for(family: &str) -> &'static str {
    match family {
        "firefox" => "firefox133",
        "safari" | "ios" => "safari17_0",
        _ => "chrome124",
    }
}

fn fingerprint_contract(storage: &Storage, session_id: &str) -> FingerprintContract {
    let preset = tls_outbound::active_preset().ok();
    let recipe = tls_outbound::active_http2_recipe();
    let mut notes = Vec::new();

    // A JA3 measured from this session's own traffic is worth more than one
    // derived from a preset, so it is preferred when present.
    let measured = crate::tls_fingerprint::list_session_tls_fingerprints(storage, session_id)
        .ok()
        .and_then(|value| {
            value
                .get("fingerprints")
                .and_then(|list| list.as_array())
                .and_then(|list| list.first().cloned())
        })
        .and_then(|entry| {
            entry
                .pointer("/fingerprint/inbound/ja3")
                .and_then(|ja3| ja3.as_str())
                .map(str::to_string)
        });

    let target_ja3 = match measured {
        Some(ja3) => {
            notes.push("target measured from this session's own ClientHello".to_string());
            Some(ja3)
        }
        None => {
            let documented = preset.and_then(|preset| preset.documented_ja3);
            notes.push(match documented {
                Some(_) => "no ClientHello was captured in this session; the target below is the \
                            preset's documented JA3, which the catalog marks as not \
                            wire-guaranteed under rustls"
                    .to_string(),
                None => "no ClientHello was captured and the active preset documents no JA3, so \
                         the package states no target and check_fingerprint() can only report \
                         what it measured"
                    .to_string(),
            });
            documented.map(str::to_string)
        }
    };

    let family = preset.map(|preset| preset.family).unwrap_or("chrome");
    FingerprintContract {
        profile_id: preset
            .map(|preset| preset.id.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        target_ja3,
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        impersonate: impersonate_for(family).to_string(),
        http2_settings: recipe.settings_pairs(),
        notes,
    }
}

/// Splits the replay package's Python agent steps into ones that ran and ones
/// that only got as far as being identified.
fn crypto_from_replay(
    storage: &Storage,
    session_id: &str,
) -> (Vec<VerifiedCryptoStep>, Vec<String>) {
    let Ok(package) = algorithm_replay::build_algorithm_replay(storage, session_id, "python")
    else {
        return (Vec::new(), Vec::new());
    };

    // `crypto_verified` is the gate the replay builder already applies: steps
    // that reproduced the values this capture recorded. Anything short of that
    // is named, never emitted.
    if !package.crypto_verified {
        let unverified = package
            .can_emit_runnable_crypto
            .then(|| {
                vec![format!(
                    "{} (identified, never reproduced)",
                    package.adapter_id
                )]
            })
            .unwrap_or_default();
        return (Vec::new(), unverified);
    }

    let source = package
        .files
        .iter()
        .find(|file| file.name == "replay.py")
        .map(|file| file.content.clone());

    match source {
        Some(content) => (
            vec![VerifiedCryptoStep {
                name: package.adapter_id.clone(),
                python_source: content,
                entry_point: "AGENT_STEPS".to_string(),
            }],
            Vec::new(),
        ),
        None => (Vec::new(), Vec::new()),
    }
}

/// Everything the generator needs for one session.
pub fn collect(storage: &Storage, session_id: &str) -> Result<(EndpointModel, SdkInputs), String> {
    let bundle = storage.export_session_bundle(session_id)?;
    let model = build_endpoint_model(&bundle);
    let dataflow = build_dataflow(&bundle, &model);
    let (verified_crypto, unverified_crypto) = crypto_from_replay(storage, session_id);

    Ok((
        model,
        SdkInputs {
            fingerprint: fingerprint_contract(storage, session_id),
            dataflow,
            verified_crypto,
            unverified_crypto,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_through_real_storage() {
        use crate::models::{CapturedRequestInput, HeaderEntry};
        const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.sig-9f2c11";
        let storage = Storage::in_memory().expect("memory storage");
        let session = storage.create_session(Some("e2e".into())).expect("session");

        let store = |method: &str, path: &str, headers: Vec<HeaderEntry>, response: &str| {
            let input = CapturedRequestInput {
                id: None,
                session_id: session.id.clone(),
                source: "browser".into(),
                source_instance_id: Some("sdk-test".into()),
                timestamp: Some(1_785_393_200_000),
                method: method.into(),
                scheme: Some("https".into()),
                host: "api.example.com".into(),
                port: Some(443),
                path: path.into(),
                query: None,
                status: 200,
                resource_type: "fetch".into(),
                size_bytes: 100,
                duration_ms: 10,
                protocol: "h2".into(),
                tls_version: Some("TLS 1.3".into()),
                tls_fingerprint: None,
                risk_level: "none".into(),
                request_headers: headers,
                response_headers: vec![HeaderEntry {
                    name: "content-type".into(),
                    value: "application/json".into(),
                }],
                request_body: None,
                response_body: Some(response.to_string()),
                response_body_metadata: None,
                crypto_snippets: None,
                hook: None,
            };
            storage.store_request(input).expect("store");
        };

        store(
            "POST",
            "/api/v1/auth/login",
            Vec::new(),
            &format!(r#"{{"token":"{TOKEN}"}}"#),
        );
        for id in ["1001", "1002"] {
            store(
                "GET",
                &format!("/api/v1/users/{id}"),
                vec![HeaderEntry {
                    name: "Authorization".into(),
                    value: format!("Bearer {TOKEN}"),
                }],
                &format!(r#"{{"id":{id}}}"#),
            );
        }

        let exported = export(&storage, &session.id, Some(std::path::Path::new("/private/tmp/claude-501/-Users-suifei-works-shownet/18a99b54-e55c-4d61-9804-0cf417ccc7dd/scratchpad/e2e")))
            .expect("export");
        assert!(exported.readiness.endpoints_total >= 2, "{exported:?}");
        assert!(!exported.files.is_empty());
    }

    #[test]
    fn each_browser_family_maps_to_its_own_impersonation_target() {
        // Collapsing families onto one browser would have the package claim a
        // Firefox capture presents as Chrome, which check_fingerprint() would
        // then report as a mismatch the user cannot explain.
        assert_ne!(impersonate_for("firefox"), impersonate_for("chrome"));
        assert_ne!(impersonate_for("safari"), impersonate_for("chrome"));
        assert_eq!(impersonate_for("ios"), impersonate_for("safari"));
        // An unknown family falls back rather than failing the whole build.
        assert_eq!(impersonate_for("something-new"), impersonate_for("chrome"));
    }

    #[test]
    fn a_session_with_no_capture_still_produces_inputs() {
        let storage = Storage::in_memory().expect("memory storage");
        let session = storage
            .create_session(Some("empty".into()))
            .expect("session");
        let (model, inputs) = collect(&storage, &session.id).expect("collect");
        assert!(model.endpoints.is_empty());
        assert!(inputs.verified_crypto.is_empty());
        // The contract still names a profile; only the target may be unknown.
        assert!(!inputs.fingerprint.impersonate.is_empty());
        assert!(
            !inputs.fingerprint.notes.is_empty(),
            "the absence is stated"
        );
    }
}

/// Writes a generated package to disk, following the same shape the replay and
/// evaluation exports already use: a directory per package, an index beside it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkExportResult {
    pub session_id: String,
    pub language: String,
    pub directory: String,
    pub files: Vec<String>,
    pub readiness: crate::sdk_build::SdkReadiness,
    pub bytes_written: usize,
}

pub fn export(
    storage: &Storage,
    session_id: &str,
    output_dir: Option<&std::path::Path>,
) -> Result<SdkExportResult, String> {
    let session = storage.get_session(session_id)?;
    let (model, inputs) = collect(storage, session_id)?;
    let package = crate::sdk_build::build_python_sdk(&model, &inputs);

    let directory = match output_dir {
        Some(path) => path.join(format!("shownet-sdk-{}-python", session.id)),
        None => std::env::temp_dir().join(format!("shownet-sdk-{}-python", session.id)),
    };
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("创建导出目录失败 {}: {error}", directory.display()))?;

    let mut written = Vec::new();
    let mut bytes_written = 0usize;
    for file in &package.files {
        let path = directory.join(&file.name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("创建导出子目录失败 {}: {error}", parent.display()))?;
        }
        std::fs::write(&path, file.content.as_bytes())
            .map_err(|error| format!("写入 {} 失败: {error}", path.display()))?;
        bytes_written += file.content.len();
        written.push(path.to_string_lossy().to_string());
    }

    Ok(SdkExportResult {
        session_id: package.session_id,
        language: package.language,
        directory: directory.to_string_lossy().to_string(),
        files: written,
        readiness: package.readiness,
        bytes_written,
    })
}
