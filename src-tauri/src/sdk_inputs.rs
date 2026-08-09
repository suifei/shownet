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
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

    // One entry per step rather than the whole replay.py. Taking the file
    // wholesale put an unrelated HTTP client, a manifest loader and every
    // step into a single "step" named after the adapter, so crypto.py held one
    // opaque blob and the count in GAPS.md read 1 no matter how many steps
    // actually ran.
    let steps: Vec<VerifiedCryptoStep> = package
        .verified_steps
        .iter()
        .map(|step| VerifiedCryptoStep {
            name: step.name.clone(),
            python_source: step.source.clone(),
            entry_point: step.entry_point.clone(),
        })
        .collect();

    // crypto_verified without a step to show for it means the verification
    // lives somewhere this cannot reach; say so rather than emit nothing
    // silently.
    if steps.is_empty() {
        return (
            Vec::new(),
            vec![format!(
                "{} (marked verified, but the package carried no step source)",
                package.adapter_id
            )],
        );
    }
    (steps, Vec::new())
}

/// Everything the generator needs for one session.

/// What an agent decided about a proposed API surface.
///
/// The deterministic layer proposes: it extracts endpoints, parameters and
/// dataflow from a capture and says what it could not establish. It does not
/// decide which of them are *the API*, because that judgement is about the site
/// and belongs to whoever looked at it — not to a list of vendor paths compiled
/// into the binary. `/cdn-cgi/…` is Cloudflare, `/_next/…` is Next.js, and the
/// next capture will bring a vendor nobody here has heard of; a product that
/// hardcodes them is a product that only works on sites someone already knew
/// about.
///
/// So the decisions arrive as data, from an agent that read the evidence, and
/// the same binary serves any capture. Absent, nothing is dropped: an export
/// without curation is the raw proposal, which is what it has always been.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkCuration {
    /// Operations to leave out, by operation id, each with the reason it was
    /// left out. The reason is not decoration: it goes into GAPS.md, so a reader
    /// can see what was excluded and disagree.
    #[serde(default)]
    pub drop: Vec<CurationDrop>,
    /// Better names for operations whose generated name is unusable.
    #[serde(default)]
    pub rename: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurationDrop {
    pub operation_id: String,
    pub reason: String,
}

/// Applies an agent's decisions to a proposed surface.
///
/// Every drop becomes a gap, so the package always states what is missing from
/// it. A curation that names an operation which does not exist is not an error
/// — captures change between the proposal and the decision — but it is recorded
/// rather than ignored.
pub fn apply_curation(model: &mut EndpointModel, curation: &SdkCuration) {
    // An agent reads the generated client, where operations are snake_case
    // method names, but the model keys them camelCase. Requiring the caller to
    // know that conversion is a trap with no error: the first curation written
    // against the method names matched nothing, changed nothing, and the export
    // reported success. Accept either spelling.
    let matches = |endpoint: &crate::endpoint_model::Endpoint, wanted: &str| {
        endpoint.operation_id == wanted
            || crate::sdk_build::snake_case(&endpoint.operation_id) == wanted
    };
    let present = |wanted: &str| model.endpoints.iter().any(|e| matches(e, wanted));

    for drop in &curation.drop {
        if present(&drop.operation_id) {
            model.gaps.push(crate::endpoint_model::Gap {
                kind: crate::endpoint_model::GapKind::CuratedOut,
                operation_id: drop.operation_id.clone(),
                detail: drop.reason.clone(),
            });
        }
    }
    model.endpoints.retain(|endpoint| {
        !curation
            .drop
            .iter()
            .any(|drop| matches(endpoint, &drop.operation_id))
    });

    for endpoint in &mut model.endpoints {
        if let Some(name) = curation.rename.get(&endpoint.operation_id).or_else(|| {
            curation
                .rename
                .get(&crate::sdk_build::snake_case(&endpoint.operation_id))
        }) {
            endpoint.operation_id = name.clone();
        }
    }
}

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

        let exported = export(&storage, &session.id, Some(std::path::Path::new("/private/tmp/claude-501/-Users-suifei-works-shownet/18a99b54-e55c-4d61-9804-0cf417ccc7dd/scratchpad/e2e")), None)
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
    curation: Option<&SdkCuration>,
) -> Result<SdkExportResult, String> {
    let session = storage.get_session(session_id)?;
    let (mut model, inputs) = collect(storage, session_id)?;
    if let Some(curation) = curation {
        apply_curation(&mut model, curation);
    }
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

#[cfg(test)]
mod curation_tests {
    use super::*;
    use crate::endpoint_model::{Endpoint, GapKind};

    fn endpoint(id: &str) -> Endpoint {
        Endpoint {
            operation_id: id.to_string(),
            method: "GET".into(),
            server: "https://example.test".into(),
            path_template: format!("/{id}"),
            sample_count: 1,
            path_params: Vec::new(),
            query_params: Vec::new(),
            headers: Vec::new(),
            request_body: None,
            responses: Vec::new(),
            sample_paths: Vec::new(),
        }
    }

    fn model() -> EndpointModel {
        EndpointModel {
            session_id: "s".into(),
            servers: vec!["https://example.test".into()],
            endpoints: vec![endpoint("get_api_orders"), endpoint("get_cdn_cgi_probe")],
            gaps: Vec::new(),
            request_count: 2,
            skipped_count: 0,
        }
    }

    /// Dropping is a decision someone made, so the package has to say it was
    /// made. A quietly shorter SDK reads as "the capture contained this much",
    /// which is a different and false claim.
    #[test]
    fn a_dropped_operation_leaves_a_gap_that_names_the_reason() {
        let mut surface = model();
        apply_curation(
            &mut surface,
            &SdkCuration {
                drop: vec![CurationDrop {
                    operation_id: "get_cdn_cgi_probe".into(),
                    reason: "风控探针，不属于站点 API".into(),
                }],
                rename: BTreeMap::new(),
            },
        );

        assert_eq!(surface.endpoints.len(), 1);
        assert_eq!(surface.endpoints[0].operation_id, "get_api_orders");

        let gap = surface
            .gaps
            .iter()
            .find(|gap| gap.kind == GapKind::CuratedOut)
            .expect("a drop must be recorded");
        assert_eq!(gap.operation_id, "get_cdn_cgi_probe");
        assert!(gap.detail.contains("风控探针"), "the reason must survive");
    }

    /// No curation is not the same as empty curation, and neither may invent a
    /// judgement: the raw proposal is what the deterministic layer found.
    #[test]
    fn without_a_decision_nothing_is_removed() {
        let mut surface = model();
        apply_curation(&mut surface, &SdkCuration::default());
        assert_eq!(surface.endpoints.len(), 2);
        assert!(surface.gaps.is_empty());
    }

    /// Captures change between proposing and deciding. Naming something that is
    /// no longer there is not an error, and must not drop a bystander.
    #[test]
    fn a_decision_about_an_operation_that_is_gone_changes_nothing() {
        let mut surface = model();
        apply_curation(
            &mut surface,
            &SdkCuration {
                drop: vec![CurationDrop {
                    operation_id: "get_something_else".into(),
                    reason: "已不存在".into(),
                }],
                rename: BTreeMap::new(),
            },
        );
        assert_eq!(surface.endpoints.len(), 2);
        assert!(
            surface.gaps.is_empty(),
            "a gap for an operation the package never had would mislead"
        );
    }

    /// The trap this cost an hour to find: an agent curates against the method
    /// names it can see in the generated client, which are snake_case, while the
    /// model keys operations camelCase. A curation written the readable way
    /// matched nothing, removed nothing, and the export still reported success.
    #[test]
    fn a_decision_written_against_the_generated_method_name_still_applies() {
        let mut surface = EndpointModel {
            endpoints: vec![endpoint("getShieldVerify")],
            ..model()
        };
        apply_curation(
            &mut surface,
            &SdkCuration {
                drop: vec![CurationDrop {
                    // What the client calls it.
                    operation_id: "get_shield_verify".into(),
                    reason: "HTML 过渡页,不是接口".into(),
                }],
                rename: BTreeMap::new(),
            },
        );
        assert!(
            surface.endpoints.is_empty(),
            "the snake_case spelling has to reach the camelCase operation"
        );
        assert_eq!(surface.gaps.len(), 1, "and still leave its reason behind");
    }

    #[test]
    fn renaming_replaces_the_generated_name() {
        let mut surface = model();
        let mut rename = BTreeMap::new();
        rename.insert("get_api_orders".to_string(), "list_orders".to_string());
        apply_curation(
            &mut surface,
            &SdkCuration {
                drop: Vec::new(),
                rename,
            },
        );
        assert!(surface
            .endpoints
            .iter()
            .any(|endpoint| endpoint.operation_id == "list_orders"));
    }
}

#[cfg(test)]
mod real_session_tests {
    /// Runs the whole capture-to-SDK pipeline against a real captured session,
    /// which is the only way to see what it makes of traffic nobody curated.
    /// Unit tests build their own fixtures and therefore only ever exercise
    /// shapes the author already had in mind.
    ///
    ///   SHOWNET_SESSION=session-... npm run test:sdk-real
    #[test]
    #[ignore = "needs a real captured session; run via npm run test:sdk-real"]
    fn export_a_real_session_and_describe_what_it_produced() {
        let session = std::env::var("SHOWNET_SESSION")
            .unwrap_or_else(|_| panic!("set SHOWNET_SESSION to a captured session id"));
        let database = std::env::var("SHOWNET_DB")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
                    .join("Library/Application Support/com.shownet.desktop/shownet.sqlite3")
            });
        let storage = crate::storage::Storage::open(&database).expect("open the app database");
        let out = std::env::temp_dir().join("shownet-sdk-real");
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).expect("output dir");

        // SHOWNET_CURATION points at the decision document an agent produced, so
        // the same test covers both halves: the raw proposal, and the proposal
        // with judgement applied.
        let curation: Option<super::SdkCuration> = std::env::var("SHOWNET_CURATION")
            .ok()
            .filter(|path| !path.trim().is_empty())
            .map(|path| {
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("read {path}: {error}"));
                serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {path}: {error}"))
            });
        if curation.is_some() {
            eprintln!("SDK applying a curation document");
        }
        let result =
            super::export(&storage, &session, Some(&out), curation.as_ref()).expect("export");
        eprintln!(
            "SDK dir={} files={} bytes={}",
            result.directory,
            result.files.len(),
            result.bytes_written
        );
        for file in &result.files {
            let path = std::path::Path::new(&result.directory).join(file);
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            eprintln!("SDK   {file}  {size} bytes");
        }
        eprintln!("SDK readiness: {:?}", result.readiness);

        assert!(
            !result.files.is_empty(),
            "an export with no files is not one"
        );

        // The one check that cannot be argued with: an SDK that does not parse is
        // not an SDK. Every generated .py, compiled by the interpreter it targets.
        // Emitting Python from Rust string literals makes indentation a thing you
        // can get wrong silently — a helper came out flush-left and still passed
        // every other assertion here.
        for file in result.files.iter().filter(|f| f.ends_with(".py")) {
            let path = std::path::Path::new(&result.directory).join(file);
            let output = std::process::Command::new("python3")
                .arg("-m")
                .arg("py_compile")
                .arg(&path)
                .output()
                .expect("run python3");
            assert!(
                output.status.success(),
                "{file} does not compile:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        eprintln!("SDK every generated python file compiles");
    }
}
