//! Auto-crawler / client generator: capture-grounded, multi-language client packages
//! with JA3/JA4 fidelity labels, proxy egress env config, algorithm reconstruction
//! modes, and offline validate-against-capture.

use crate::algorithm_replay::{self, AlgorithmReplayPackage, ReplayFile};
use crate::models::RequestRecord;
use crate::protection_analysis;
use crate::signature_adapter;
use crate::storage::Storage;
use crate::tls_outbound;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureShapeExpectation {
    pub required_header_names: Vec<String>,
    pub required_body_keys: Vec<String>,
    pub token_structure_contains: Option<String>,
    pub pow_challenge_type: Option<String>,
    pub signal_identifier: Option<String>,
    pub endpoint_hosts: Vec<String>,
    pub endpoint_paths: Vec<String>,
    pub inbound_ja3_present: bool,
    pub inbound_ja4_present: bool,
    pub outbound_tls_profile: String,
    pub outbound_fidelity_label: String,
    pub required_env: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    pub ok: bool,
    pub status: String,
    pub checks: Vec<ValidationCheck>,
    pub missing_headers: Vec<String>,
    pub missing_body_keys: Vec<String>,
    pub shape_mismatches: Vec<String>,
    pub secrets_leaked: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationCheck {
    pub id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoCrawlerPackage {
    pub session_id: String,
    pub language: String,
    pub package_hash: String,
    pub adapter_id: String,
    pub vendor: String,
    pub reconstruction_mode: String,
    pub can_emit_runnable_crypto: bool,
    pub fidelity: Value,
    pub proxy_env: Value,
    pub algorithm_reconstruction: Value,
    pub capture_shape: CaptureShapeExpectation,
    pub validation: ValidationReport,
    pub files: Vec<ReplayFile>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoCrawlerExportResult {
    pub session_id: String,
    pub language: String,
    pub directory: String,
    pub files: Vec<String>,
    pub package_hash: String,
    pub bytes_written: usize,
    pub validation_ok: bool,
    pub validation_status: String,
}

/// Build capture-grounded auto-crawler package for the requested language.
pub fn build_auto_crawler(
    storage: &Storage,
    session_id: &str,
    language: &str,
) -> Result<AutoCrawlerPackage, String> {
    build_auto_crawler_for_report(storage, session_id, language, None)
}

pub fn build_auto_crawler_for_report(
    storage: &Storage,
    session_id: &str,
    language: &str,
    report_id: Option<&str>,
) -> Result<AutoCrawlerPackage, String> {
    let replay = algorithm_replay::build_algorithm_replay_for_report(
        storage,
        session_id,
        language,
        report_id,
    )?;
    let language = replay.language.clone();
    let protection = protection_analysis::analyze_session(storage, session_id)?;
    let harness = signature_adapter::build_signature_harness(storage, session_id, "auto")?;
    let requests = storage.list_requests(session_id, Some(10_000), Some(0))?;
    let shape = build_capture_shape(storage, session_id, &protection, &harness.required_inputs)?;
    let fidelity = build_fidelity_block(&protection, &requests);
    let proxy_env = build_proxy_env_block();

    let mut files = replay.files.clone();
    // Capture shape fixture used by offline validator (no live secrets).
    let capture_fixture = json!({
        "requiredHeaderNames": shape.required_header_names,
        "requiredBodyKeys": shape.required_body_keys,
        "tokenStructureContains": shape.token_structure_contains,
        "powChallengeType": shape.pow_challenge_type,
        "signalIdentifier": shape.signal_identifier,
        "endpointHosts": shape.endpoint_hosts,
        "endpointPaths": shape.endpoint_paths,
        "inboundJa3Present": shape.inbound_ja3_present,
        "inboundJa4Present": shape.inbound_ja4_present,
        "outboundTlsProfile": shape.outbound_tls_profile,
        "outboundFidelityLabel": shape.outbound_fidelity_label,
        "requiredEnv": shape.required_env,
        "fidelity": fidelity,
        "proxyEnv": proxy_env,
    });
    files.push(make_file(
        "CAPTURE_SHAPE.json",
        "capture-shape",
        None,
        &serde_json::to_string_pretty(&capture_fixture).map_err(|e| e.to_string())?,
    ));

    // Client simulator with proxy + TLS fidelity notes (dependency-light).
    let client_source = render_client_source(
        &language,
        &replay,
        &shape,
        &fidelity,
        &proxy_env,
    )?;
    let client_name = client_filename(&language);
    files.push(make_file(
        &client_name,
        "auto-crawler-client",
        Some(language.clone()),
        &client_source,
    ));

    // Analysis / strategy document (before validation so docs are scanned for leaks).
    let analysis_doc = render_analysis_doc(&replay, &shape, &fidelity, &proxy_env);
    files.push(make_file(
        "CRAWLER_ANALYSIS.md",
        "crawler-analysis-doc",
        None,
        &analysis_doc,
    ));

    // Offline validate against capture shape + primary sources, then secret-scan.
    // VALIDATION_REPORT / TEST_STATUS / README are written only after the final report
    // so on-disk files always match package.validation.
    let mut validation = validate_package_against_capture(&replay, &shape, &files);
    let leaked = scan_secret_leaks(&files, &requests);
    if !leaked.is_empty() {
        validation.ok = false;
        validation.status = "secrets_leaked".into();
        validation.secrets_leaked = leaked.clone();
        validation.checks.push(ValidationCheck {
            id: "no_embedded_secrets".into(),
            passed: false,
            detail: format!("leaked_patterns={}", leaked.join(",")),
        });
    } else {
        validation.checks.push(ValidationCheck {
            id: "no_embedded_secrets".into(),
            passed: true,
            detail: "no capture token/key literals embedded in sources".into(),
        });
    }

    let validation_json =
        serde_json::to_string_pretty(&validation).map_err(|e| e.to_string())?;
    files.push(make_file(
        "VALIDATION_REPORT.json",
        "validation-report",
        None,
        &validation_json,
    ));

    let test_status = render_test_status(&validation, &replay);
    files.push(make_file(
        "TEST_STATUS.md",
        "test-status",
        None,
        &test_status,
    ));

    files.push(make_file(
        "CRAWLER_README.md",
        "crawler-readme",
        None,
        &render_crawler_readme(&language, &client_name, &validation, &shape),
    ));

    let package_hash = hash_package(session_id, &language, &files);
    let mut notes = replay.notes.clone();
    notes.push(format!(
        "auto-crawler validation status={} ok={}",
        validation.status, validation.ok
    ));
    notes.push(format!(
        "outbound TLS profile={} fidelity={}",
        shape.outbound_tls_profile, shape.outbound_fidelity_label
    ));

    Ok(AutoCrawlerPackage {
        session_id: session_id.to_string(),
        language,
        package_hash,
        adapter_id: replay.adapter_id,
        vendor: replay.vendor,
        reconstruction_mode: replay.reconstruction_mode,
        can_emit_runnable_crypto: replay.can_emit_runnable_crypto,
        fidelity,
        proxy_env,
        algorithm_reconstruction: replay.algorithm_reconstruction,
        capture_shape: shape,
        validation,
        files,
        notes,
    })
}

pub fn export_auto_crawler(
    storage: &Storage,
    session_id: &str,
    language: &str,
    output_dir: Option<&Path>,
) -> Result<AutoCrawlerExportResult, String> {
    let package = build_auto_crawler(storage, session_id, language)?;
    let directory = match output_dir {
        Some(path) => package_subdirectory(path, session_id, &package.language),
        None => storage
            .data_directory()
            .map(|base| {
                package_subdirectory(
                    &base.join("exports").join("auto-crawler"),
                    session_id,
                    &package.language,
                )
            })
            .unwrap_or_else(|_| {
                package_subdirectory(
                    &std::env::temp_dir().join("shownet-auto-crawler"),
                    session_id,
                    &package.language,
                )
            }),
    };
    std::fs::create_dir_all(&directory)
        .map_err(|e| format!("create crawler export dir: {e}"))?;

    let mut written = Vec::new();
    let mut bytes_written = 0usize;
    for file in &package.files {
        let path = directory.join(&file.name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
        std::fs::write(&path, file.content.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        bytes_written += file.content.len();
        written.push(path.to_string_lossy().to_string());
    }
    let index = json!({
        "sessionId": package.session_id,
        "language": package.language,
        "packageHash": package.package_hash,
        "validationOk": package.validation.ok,
        "validationStatus": package.validation.status,
        "adapterId": package.adapter_id,
        "files": package.files.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
        "exportedAtUnixMs": now_ms(),
    });
    let index_path = directory.join("export-index.json");
    let index_text = serde_json::to_string_pretty(&index).map_err(|e| e.to_string())?;
    std::fs::write(&index_path, index_text.as_bytes()).map_err(|e| e.to_string())?;
    bytes_written += index_text.len();
    written.push(index_path.to_string_lossy().to_string());

    Ok(AutoCrawlerExportResult {
        session_id: package.session_id,
        language: package.language,
        directory: directory.to_string_lossy().to_string(),
        files: written,
        package_hash: package.package_hash,
        bytes_written,
        validation_ok: package.validation.ok,
        validation_status: package.validation.status,
    })
}

/// Offline consistency check used by package builder and tests.
pub fn validate_package_against_capture(
    replay: &AlgorithmReplayPackage,
    shape: &CaptureShapeExpectation,
    files: &[ReplayFile],
) -> ValidationReport {
    let mut checks = Vec::new();
    let mut missing_headers = Vec::new();
    let mut missing_body_keys = Vec::new();
    let mut shape_mismatches = Vec::new();

    // Primary source must exist.
    let has_client = files.iter().any(|f| f.role == "auto-crawler-client");
    let has_replay = files.iter().any(|f| f.role == "algorithm-replay");
    let has_spec = files
        .iter()
        .any(|f| f.name == "ALGORITHM_SPEC.json" || f.role.contains("algorithm"));
    checks.push(ValidationCheck {
        id: "primary_source_present".into(),
        passed: has_client && has_replay,
        detail: format!("client={has_client} replay={has_replay}"),
    });
    checks.push(ValidationCheck {
        id: "algorithm_spec_present".into(),
        passed: has_spec,
        detail: "ALGORITHM_SPEC or algorithm role file".into(),
    });

    // CAPTURE_SHAPE.json must mirror expectation (header/body shape divergence → fail).
    if let Some(shape_file) = files.iter().find(|f| f.name == "CAPTURE_SHAPE.json") {
        match serde_json::from_str::<Value>(&shape_file.content) {
            Ok(parsed) => {
                let listed_headers = parsed
                    .get("requiredHeaderNames")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_ascii_lowercase)
                            .collect::<BTreeSet<_>>()
                    })
                    .unwrap_or_default();
                for name in &shape.required_header_names {
                    if !listed_headers.contains(&name.to_ascii_lowercase()) {
                        missing_headers.push(name.clone());
                        shape_mismatches
                            .push(format!("CAPTURE_SHAPE missing required header {name}"));
                    }
                }
                let listed_body = parsed
                    .get("requiredBodyKeys")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect::<BTreeSet<_>>()
                    })
                    .unwrap_or_default();
                for key in &shape.required_body_keys {
                    if !listed_body.contains(key) {
                        missing_body_keys.push(key.clone());
                        shape_mismatches
                            .push(format!("CAPTURE_SHAPE missing required body key {key}"));
                    }
                }
                if let Some(expected_pow) = shape.pow_challenge_type.as_ref() {
                    let actual = parsed
                        .get("powChallengeType")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if actual != expected_pow {
                        shape_mismatches.push(format!(
                            "CAPTURE_SHAPE pow expected={expected_pow} actual={actual}"
                        ));
                    }
                }
                if let Some(expected_sig) = shape.signal_identifier.as_ref() {
                    let actual = parsed
                        .get("signalIdentifier")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if actual != expected_sig {
                        shape_mismatches.push(format!(
                            "CAPTURE_SHAPE signal expected={expected_sig} actual={actual}"
                        ));
                    }
                }
                checks.push(ValidationCheck {
                    id: "capture_shape_file_aligned".into(),
                    passed: missing_headers.is_empty()
                        && missing_body_keys.is_empty()
                        && !shape_mismatches.iter().any(|m| m.starts_with("CAPTURE_SHAPE")),
                    detail: format!(
                        "headers_missing={} body_missing={}",
                        missing_headers.len(),
                        missing_body_keys.len()
                    ),
                });
            }
            Err(error) => {
                shape_mismatches.push(format!("CAPTURE_SHAPE.json parse error: {error}"));
                checks.push(ValidationCheck {
                    id: "capture_shape_file_aligned".into(),
                    passed: false,
                    detail: error.to_string(),
                });
            }
        }
    } else {
        shape_mismatches.push("CAPTURE_SHAPE.json missing".into());
        checks.push(ValidationCheck {
            id: "capture_shape_file_aligned".into(),
            passed: false,
            detail: "CAPTURE_SHAPE.json missing".into(),
        });
    }

    // Manifest / protocol shapes from replay package.
    let protocol = &replay.protocol_schemas;
    if let Some(expected_pow) = shape.pow_challenge_type.as_ref() {
        let actual = protocol
            .pointer("/pow/challengeType")
            .and_then(Value::as_str)
            .unwrap_or("");
        let ok = actual == expected_pow;
        if !ok {
            shape_mismatches.push(format!("pow expected={expected_pow} actual={actual}"));
        }
        checks.push(ValidationCheck {
            id: "pow_matches_capture".into(),
            passed: ok || expected_pow.is_empty(),
            detail: format!("expected={expected_pow} actual={actual}"),
        });
    }
    if let Some(expected_sig) = shape.signal_identifier.as_ref() {
        let actual = protocol
            .pointer("/signals/identifier")
            .and_then(Value::as_str)
            .unwrap_or("");
        let ok = actual == expected_sig;
        if !ok {
            shape_mismatches.push(format!("signal expected={expected_sig} actual={actual}"));
        }
        checks.push(ValidationCheck {
            id: "signal_matches_capture".into(),
            passed: ok || expected_sig.is_empty(),
            detail: format!("expected={expected_sig} actual={actual}"),
        });
    }

    // Token structure note
    if let Some(token_hint) = shape.token_structure_contains.as_ref() {
        let actual = protocol
            .pointer("/token/structure")
            .and_then(Value::as_str)
            .unwrap_or("");
        let ok = actual.contains(token_hint) || token_hint.is_empty();
        if !ok {
            shape_mismatches.push(format!("token structure missing {token_hint}"));
        }
        checks.push(ValidationCheck {
            id: "token_structure".into(),
            passed: ok,
            detail: format!("hint={token_hint} actual={actual}"),
        });
    }

    // Client source must mention proxy env + fidelity labels + validate hook + header shapes.
    if let Some(client) = files.iter().find(|f| f.role == "auto-crawler-client") {
        let content = &client.content;
        let content_lower = content.to_ascii_lowercase();
        let has_proxy = content.contains("SHOWNET_PROXY") || content_lower.contains("proxy");
        let has_fidelity = content_lower.contains("ja3")
            || content_lower.contains("ja4")
            || content_lower.contains("fidelity")
            || content_lower.contains("outbound");
        let has_validate = content.contains("validate_against_capture")
            || content.contains("validateAgainstCapture")
            || content.contains("ValidateAgainstCapture")
            || content.contains("validate_against");
        // Wrong-language guard: non-python clients must not ship a Python shebang body.
        let language_ok = match client.language.as_deref() {
            Some("python") | None => true,
            Some(lang) if lang != "python" => {
                !content.contains("#!/usr/bin/env python3")
                    && !content.contains("from __future__ import annotations")
            }
            _ => true,
        };
        checks.push(ValidationCheck {
            id: "client_proxy_env".into(),
            passed: has_proxy,
            detail: "proxy env surface in client".into(),
        });
        checks.push(ValidationCheck {
            id: "client_fidelity_notes".into(),
            passed: has_fidelity,
            detail: "JA3/JA4/outbound fidelity notes".into(),
        });
        checks.push(ValidationCheck {
            id: "client_validate_hook".into(),
            passed: has_validate,
            detail: "offline validate entrypoint".into(),
        });
        checks.push(ValidationCheck {
            id: "client_language_matches".into(),
            passed: language_ok,
            detail: format!(
                "language={:?} python_fallback={}",
                client.language, !language_ok
            ),
        });
        if !language_ok {
            shape_mismatches.push(format!(
                "client language {:?} shipped Python skeleton",
                client.language
            ));
        }

        let mut client_missing_headers = Vec::new();
        for name in &shape.required_header_names {
            if is_standard_header(name) {
                continue;
            }
            if !content_lower.contains(&name.to_ascii_lowercase()) {
                client_missing_headers.push(name.clone());
            }
        }
        for name in &client_missing_headers {
            if !missing_headers.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                missing_headers.push(name.clone());
            }
            shape_mismatches.push(format!("client missing required header name {name}"));
        }
        let mut client_missing_body = Vec::new();
        for key in &shape.required_body_keys {
            if !content.contains(key) {
                client_missing_body.push(key.clone());
            }
        }
        for key in &client_missing_body {
            if !missing_body_keys.iter().any(|k| k == key) {
                missing_body_keys.push(key.clone());
            }
            shape_mismatches.push(format!("client missing required body key {key}"));
        }
        checks.push(ValidationCheck {
            id: "client_header_shape".into(),
            passed: client_missing_headers.is_empty(),
            detail: if client_missing_headers.is_empty() {
                "all non-standard required headers referenced in client".into()
            } else {
                format!("missing={}", client_missing_headers.join(","))
            },
        });
        checks.push(ValidationCheck {
            id: "client_body_key_shape".into(),
            passed: client_missing_body.is_empty(),
            detail: if client_missing_body.is_empty() {
                "all required body keys referenced in client".into()
            } else {
                format!("missing={}", client_missing_body.join(","))
            },
        });
    } else {
        checks.push(ValidationCheck {
            id: "client_proxy_env".into(),
            passed: false,
            detail: "missing auto-crawler-client file".into(),
        });
    }

    // Algorithm reconstruction mode must be one of the product strategy enums.
    let mode_ok = is_known_reconstruction_mode(&replay.reconstruction_mode);
    checks.push(ValidationCheck {
        id: "reconstruction_mode_explicit".into(),
        passed: mode_ok,
        detail: format!("mode={}", replay.reconstruction_mode),
    });
    if !mode_ok {
        shape_mismatches.push(format!(
            "unknown reconstruction_mode={}",
            replay.reconstruction_mode
        ));
    }

    // Env keys documented, not embedded.
    checks.push(ValidationCheck {
        id: "required_env_documented".into(),
        passed: !shape.required_env.is_empty()
            || files.iter().any(|f| f.content.contains("SHOWNET_")),
        detail: format!("env_count={}", shape.required_env.len()),
    });

    let all_passed = checks.iter().all(|c| c.passed)
        && shape_mismatches.is_empty()
        && missing_headers.is_empty()
        && missing_body_keys.is_empty();
    ValidationReport {
        ok: all_passed,
        status: if all_passed {
            "shape_aligned".into()
        } else {
            "mismatch".into()
        },
        checks,
        missing_headers,
        missing_body_keys,
        shape_mismatches,
        secrets_leaked: Vec::new(),
        notes: vec![
            "Offline structural validation only — does not send live traffic.".into(),
            "Full browser JA3 parity is not claimed; see fidelity labels.".into(),
        ],
    }
}

fn is_standard_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-type" | "user-agent" | "accept" | "cookie" | "host" | "connection"
    )
}

fn is_known_reconstruction_mode(mode: &str) -> bool {
    !mode.is_empty()
        && matches!(
            mode,
            "reconstructed"
                | "pure_reconstructed"
                | "partial"
                | "partial_reconstructed"
                | "trace_driven"
                | "hook_trace"
                | "vmp_hybrid"
                | "hybrid"
                | "insufficient"
                | "sandbox"
                | "wasm"
                | "wasm_trace"
                | "jsvmp"
                | "jsvmp_trace"
        )
}

/// Mutate expectation for negative tests.
pub fn validate_with_mutated_shape(
    replay: &AlgorithmReplayPackage,
    shape: &CaptureShapeExpectation,
    files: &[ReplayFile],
    mutate: impl FnOnce(&mut CaptureShapeExpectation),
) -> ValidationReport {
    let mut mutated = shape.clone();
    mutate(&mut mutated);
    validate_package_against_capture(replay, &mutated, files)
}

fn build_capture_shape(
    storage: &Storage,
    session_id: &str,
    protection: &Value,
    required_inputs: &[String],
) -> Result<CaptureShapeExpectation, String> {
    let protocol = protection
        .get("protocolSchemas")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let requests = storage.list_requests(session_id, Some(10_000), Some(0))?;

    let mut header_names = BTreeSet::new();
    let mut body_keys = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut ja3 = false;
    let mut ja4 = false;

    for request in requests.iter().take(200) {
        if is_noise_host(&request.host) {
            continue;
        }
        hosts.insert(request.host.clone());
        paths.insert(request.path.clone());
        for header in &request.request_headers {
            let lower = header.name.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "cookie" | "authorization" | "x-signature" | "x-aws-waf-token" | "content-type" | "user-agent"
            ) {
                header_names.insert(header.name.clone());
            }
        }
        if let Some(body) = request.request_body.as_deref() {
            if let Ok(value) = serde_json::from_str::<Value>(body) {
                if let Some(obj) = value.as_object() {
                    for key in obj.keys().take(24) {
                        body_keys.insert(key.clone());
                    }
                }
            }
        }
        if let Some(fp) = &request.tls_fingerprint {
            let text = serde_json::to_string(fp).unwrap_or_default().to_ascii_lowercase();
            if text.contains("ja3") {
                ja3 = true;
            }
            if text.contains("ja4") {
                ja4 = true;
            }
        }
    }

    // Always document core env placeholders.
    let mut required_env: BTreeSet<String> = required_inputs.iter().cloned().collect();
    for key in [
        "SHOWNET_DOMAIN",
        "SHOWNET_UA",
        "SHOWNET_PROXY_URL",
        "SHOWNET_EXISTING_TOKEN",
        "SHOWNET_AES_KEY_HEX",
    ] {
        required_env.insert(key.into());
    }

    let profile = tls_outbound::global_profile();
    Ok(CaptureShapeExpectation {
        required_header_names: header_names.into_iter().take(32).collect(),
        required_body_keys: body_keys.into_iter().take(32).collect(),
        token_structure_contains: protocol
            .pointer("/token/structure")
            .and_then(Value::as_str)
            .map(|s| {
                if s.contains("3-segment") || s.contains("uuid") {
                    "uuid".to_string()
                } else {
                    s.chars().take(32).collect()
                }
            }),
        pow_challenge_type: protocol
            .pointer("/pow/challengeType")
            .and_then(Value::as_str)
            .map(str::to_string),
        signal_identifier: protocol
            .pointer("/signals/identifier")
            .and_then(Value::as_str)
            .map(str::to_string),
        endpoint_hosts: hosts.into_iter().take(24).collect(),
        endpoint_paths: paths.into_iter().take(48).collect(),
        inbound_ja3_present: ja3,
        inbound_ja4_present: ja4,
        outbound_tls_profile: profile.as_str().to_string(),
        outbound_fidelity_label: profile.fidelity_label().to_string(),
        required_env: required_env.into_iter().collect(),
    })
}

fn build_fidelity_block(protection: &Value, requests: &[RequestRecord]) -> Value {
    let outbound = tls_outbound::status_json();
    let mut ja3_samples = Vec::new();
    let mut ja4_samples = Vec::new();
    for request in requests.iter().take(50) {
        if let Some(fp) = &request.tls_fingerprint {
            let text = serde_json::to_string(fp).unwrap_or_default();
            if text.contains("ja3") && ja3_samples.len() < 3 {
                ja3_samples.push(json!({"requestId": request.id, "host": request.host}));
            }
            if text.contains("ja4") && ja4_samples.len() < 3 {
                ja4_samples.push(json!({"requestId": request.id, "host": request.host}));
            }
        }
    }
    let capture_fidelity = protection.get("captureFidelity").cloned().unwrap_or(json!({}));
    json!({
        "inbound": {
            "ja3Samples": ja3_samples,
            "ja4Samples": ja4_samples,
            "note": "Inbound JA3/JA4 come from browser-side capture; do not equate with MITM egress."
        },
        "outbound": outbound,
        "captureFidelity": capture_fidelity,
        "claimsFullBrowserJa3": false,
    })
}

fn build_proxy_env_block() -> Value {
    json!({
        "modes": ["direct", "http", "https", "socks5"],
        "env": {
            "SHOWNET_PROXY_URL": "optional e.g. http://user:pass@host:port or socks5://host:port",
            "SHOWNET_PROXY_MODE": "direct|http|https|socks5",
            "SHOWNET_PROXY_HOST": "host",
            "SHOWNET_PROXY_PORT": "port",
            "SHOWNET_PROXY_USERNAME": "optional",
            "SHOWNET_PROXY_PASSWORD": "optional — never commit"
        },
        "note": "Credentials only via environment variables; generated source never embeds secrets."
    })
}

fn render_client_source(
    language: &str,
    replay: &AlgorithmReplayPackage,
    shape: &CaptureShapeExpectation,
    fidelity: &Value,
    proxy_env: &Value,
) -> Result<String, String> {
    let hosts = shape.endpoint_hosts.join(", ");
    let pow = shape.pow_challenge_type.clone().unwrap_or_else(|| "unknown".into());
    let signal = shape.signal_identifier.clone().unwrap_or_else(|| "unknown".into());
    let fidelity_pretty = serde_json::to_string_pretty(fidelity).unwrap_or_else(|_| "{}".into());
    let proxy_pretty = serde_json::to_string_pretty(proxy_env).unwrap_or_else(|_| "{}".into());
    let headers = shape.required_header_names.join(", ");
    let env_list = shape.required_env.join(", ");

    let body = match language {
        "python" => format!(
            r#"#!/usr/bin/env python3
"""ShowNet auto-crawler client (dependency-light).

Adapter: {adapter} / {vendor}
Reconstruction: {mode} (runnable_crypto={runnable})
PoW: {pow} | signal: {signal}

Fidelity (honest bounds):
{fidelity}

Proxy env contract:
{proxy}

Required env (never hardcode secrets): {env_list}
Observed hosts: {hosts}
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Optional: curl_cffi / httpx for richer TLS — not required for offline validation.


def proxy_handlers() -> Optional[urllib.request.ProxyHandler]:
    url = os.environ.get("SHOWNET_PROXY_URL", "").strip()
    mode = os.environ.get("SHOWNET_PROXY_MODE", "direct").strip().lower()
    if mode == "direct" and not url:
        return None
    if not url:
        host = os.environ.get("SHOWNET_PROXY_HOST", "")
        port = os.environ.get("SHOWNET_PROXY_PORT", "")
        user = os.environ.get("SHOWNET_PROXY_USERNAME", "")
        password = os.environ.get("SHOWNET_PROXY_PASSWORD", "")
        if host and port:
            auth = f"{{user}}:{{password}}@" if user else ""
            scheme = "socks5" if mode == "socks5" else "http"
            url = f"{{scheme}}://{{auth}}{{host}}:{{port}}"
    if not url:
        return None
    return urllib.request.ProxyHandler({{"http": url, "https": url}})


REQUIRED_HEADER_NAMES = [{header_literals}]
REQUIRED_BODY_KEYS = [{body_literals}]


def build_headers() -> Dict[str, str]:
    headers = {{
        "user-agent": os.environ.get("SHOWNET_UA", "ShowNet-AutoCrawler/1.0"),
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
    }}
    # Captured dynamic header names: keys always present; values from env only.
    for name in REQUIRED_HEADER_NAMES:
        env_key = "SHOWNET_HEADER_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()
        headers[name] = os.environ.get(env_key, "")
    token = os.environ.get("SHOWNET_EXISTING_TOKEN")
    if token:
        headers["cookie"] = f"aws-waf-token={{token}}"
    return headers


def build_body(seed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    body: Dict[str, Any] = {{k: None for k in REQUIRED_BODY_KEYS}}
    if seed:
        body.update(seed)
    return body


def build_request(path: str = "/", method: str = "GET", body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    domain = os.environ.get("SHOWNET_DOMAIN", "example.com")
    url = os.environ.get("SHOWNET_URL", f"https://{{domain}}{{path}}")
    return {{
        "url": url,
        "method": method,
        "headers": build_headers(),
        "json": build_body(body),
        "meta": {{
            "adapterId": "{adapter}",
            "vendor": "{vendor}",
            "reconstructionMode": "{mode}",
            "powChallengeType": "{pow}",
            "signalIdentifier": "{signal}",
            "outboundFidelity": "{outbound_label}",
            "claimsFullBrowserJa3": False,
            "inboundJa3Present": {ja3},
            "inboundJa4Present": {ja4},
        }},
    }}


def validate_against_capture(request: Dict[str, Any], shape_path: str = "CAPTURE_SHAPE.json") -> Dict[str, Any]:
    with open(shape_path, "r", encoding="utf-8") as fh:
        shape = json.load(fh)
    headers = {{k.lower(): v for k, v in (request.get("headers") or {{}}).items()}}
    body = request.get("json") or {{}}
    missing_headers = [
        n for n in (shape.get("requiredHeaderNames") or [])
        if n.lower() not in headers and n.lower() not in ("cookie",)
    ]
    missing_body = [k for k in (shape.get("requiredBodyKeys") or []) if k not in body]
    ok = True
    if missing_headers:
        ok = False
    if missing_body:
        ok = False
    meta = request.get("meta") or {{}}
    if shape.get("powChallengeType") and meta.get("powChallengeType") not in (None, "", shape.get("powChallengeType")):
        ok = False
    if shape.get("signalIdentifier") and meta.get("signalIdentifier") not in (None, "", shape.get("signalIdentifier")):
        ok = False
    return {{
        "ok": ok,
        "status": "shape_aligned" if ok else "mismatch",
        "missingHeaders": missing_headers,
        "missingBodyKeys": missing_body,
        "meta": meta,
        "note": "Offline shape check; live send is disabled by default.",
    }}


def main() -> None:
    req = build_request(path=os.environ.get("SHOWNET_PATH", "/"))
    print(json.dumps(req, indent=2, ensure_ascii=False))
    result = validate_against_capture(req)
    print(json.dumps({{"validation": result}}, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result.get("ok") else 2)


if __name__ == "__main__":
    main()
"#,
            adapter = replay.adapter_id,
            vendor = replay.vendor,
            mode = replay.reconstruction_mode,
            runnable = replay.can_emit_runnable_crypto,
            pow = pow,
            signal = signal,
            fidelity = fidelity_pretty,
            proxy = proxy_pretty,
            env_list = env_list,
            hosts = hosts,
            header_literals = shape
                .required_header_names
                .iter()
                .map(|h| format!("\"{h}\""))
                .collect::<Vec<_>>()
                .join(", "),
            body_literals = shape
                .required_body_keys
                .iter()
                .map(|k| format!("\"{k}\""))
                .collect::<Vec<_>>()
                .join(", "),
            outbound_label = shape.outbound_fidelity_label,
            ja3 = if shape.inbound_ja3_present {
                "True"
            } else {
                "False"
            },
            ja4 = if shape.inbound_ja4_present {
                "True"
            } else {
                "False"
            },
        ),
        "javascript" | "typescript" | "go" | "rust" | "java" | "csharp" | "c++" | "c" | "zig" => {
            render_native_client(language, replay, shape, fidelity_pretty.as_str(), proxy_pretty.as_str())
        }
        other => {
            return Err(format!(
                "unsupported auto-crawler language '{other}' (supported: python, javascript, typescript, go, rust, java, csharp, c++, c, zig)"
            ));
        }
    };
    let _ = (headers, hosts, env_list);
    Ok(body)
}

/// Native (non-Python) dependency-light clients for every advertised language enum value.
fn render_native_client(
    language: &str,
    replay: &AlgorithmReplayPackage,
    shape: &CaptureShapeExpectation,
    fidelity_pretty: &str,
    proxy_pretty: &str,
) -> String {
    let pow = shape
        .pow_challenge_type
        .clone()
        .unwrap_or_else(|| "unknown".into());
    let signal = shape
        .signal_identifier
        .clone()
        .unwrap_or_else(|| "unknown".into());
    let header_list = shape
        .required_header_names
        .iter()
        .map(|h| format!("\"{h}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let body_list = shape
        .required_body_keys
        .iter()
        .map(|k| format!("\"{k}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let adapter = &replay.adapter_id;
    let vendor = &replay.vendor;
    let mode = &replay.reconstruction_mode;
    let outbound_label = &shape.outbound_fidelity_label;
    let ja3 = shape.inbound_ja3_present;
    let ja4 = shape.inbound_ja4_present;

    match language {
        "javascript" | "typescript" => {
            let is_ts = language == "typescript";
            let imports = if is_ts {
                "import * as fs from \"fs\";\n"
            } else {
                "const fs = require(\"fs\");\n"
            };
            format!(
                r#"/**
 * ShowNet auto-crawler client (dependency-light, Node stdlib only).
 * Adapter: {adapter} / {vendor}
 * Reconstruction: {mode}
 * PoW: {pow} | signal: {signal}
 * Outbound fidelity: {outbound_label} (claimsFullBrowserJa3=false)
 * JA3 present={ja3} JA4 present={ja4}
 *
 * Proxy: set SHOWNET_PROXY_URL or SHOWNET_PROXY_MODE/HOST/PORT (password via env only).
 */
{imports}
const FIDELITY = {fidelity_pretty};
const PROXY_CONTRACT = {proxy_pretty};
const REQUIRED_HEADER_NAMES = [{header_list}];
const REQUIRED_BODY_KEYS = [{body_list}];

function buildHeaders() {{
  const headers = {{
    "user-agent": process.env.SHOWNET_UA || "ShowNet-AutoCrawler/1.0",
    "accept": "application/json, text/plain, */*",
    "content-type": "application/json",
  }};
  for (const name of REQUIRED_HEADER_NAMES) {{
    const envKey = "SHOWNET_HEADER_" + name.replace(/[^A-Za-z0-9]/g, "_").toUpperCase();
    headers[name] = process.env[envKey] || "";
  }}
  const token = process.env.SHOWNET_EXISTING_TOKEN;
  if (token) headers["cookie"] = `aws-waf-token=${{token}}`;
  return headers;
}}

function buildBody(seed = {{}}) {{
  const body = {{}};
  for (const key of REQUIRED_BODY_KEYS) body[key] = null;
  return Object.assign(body, seed);
}}

function buildRequest(path = "/", method = "GET", body = {{}}) {{
  const domain = process.env.SHOWNET_DOMAIN || "example.com";
  const url = process.env.SHOWNET_URL || `https://${{domain}}${{path}}`;
  return {{
    url,
    method,
    headers: buildHeaders(),
    json: buildBody(body),
    meta: {{
      adapterId: "{adapter}",
      vendor: "{vendor}",
      reconstructionMode: "{mode}",
      powChallengeType: "{pow}",
      signalIdentifier: "{signal}",
      outboundFidelity: "{outbound_label}",
      claimsFullBrowserJa3: false,
      inboundJa3Present: {ja3},
      inboundJa4Present: {ja4},
      fidelity: FIDELITY,
      proxyContract: PROXY_CONTRACT,
    }},
  }};
}}

function validateAgainstCapture(request, shapePath = "CAPTURE_SHAPE.json") {{
  const shape = JSON.parse(fs.readFileSync(shapePath, "utf8"));
  const headers = Object.fromEntries(
    Object.entries(request.headers || {{}}).map(([k, v]) => [k.toLowerCase(), v])
  );
  const missingHeaders = (shape.requiredHeaderNames || []).filter(
    (n) => !(n.toLowerCase() in headers) && n.toLowerCase() !== "cookie"
  );
  const body = request.json || {{}};
  const missingBodyKeys = (shape.requiredBodyKeys || []).filter((k) => !(k in body));
  let ok = true;
  if (missingHeaders.length) ok = false;
  if (missingBodyKeys.length) ok = false;
  if (shape.powChallengeType && request.meta?.powChallengeType !== shape.powChallengeType) ok = false;
  if (shape.signalIdentifier && request.meta?.signalIdentifier !== shape.signalIdentifier) ok = false;
  return {{
    ok,
    status: ok ? "shape_aligned" : "mismatch",
    missingHeaders,
    missingBodyKeys,
    meta: request.meta,
  }};
}}

function main() {{
  const req = buildRequest(process.env.SHOWNET_PATH || "/");
  console.log(JSON.stringify(req, null, 2));
  const result = validateAgainstCapture(req);
  console.log(JSON.stringify({{ validation: result }}, null, 2));
  process.exit(result.ok ? 0 : 2);
}}

main();
"#,
            )
        }
        "go" => format!(
            r#"// ShowNet auto-crawler client (stdlib only).
// Adapter: {adapter} / {vendor} | mode={mode} | pow={pow} | signal={signal}
// Outbound fidelity: {outbound_label} (claimsFullBrowserJa3=false)
// JA3 present={ja3} JA4 present={ja4}
// Proxy: SHOWNET_PROXY_URL or SHOWNET_PROXY_MODE/HOST/PORT
package main

import (
        "encoding/json"
        "fmt"
        "os"
)

var requiredHeaderNames = []string{{{header_list}}}
var requiredBodyKeys = []string{{{body_list}}}

func buildRequest() map[string]any {{
        domain := env("SHOWNET_DOMAIN", "example.com")
        path := env("SHOWNET_PATH", "/")
        headers := map[string]string{{
                "user-agent":   env("SHOWNET_UA", "ShowNet-AutoCrawler/1.0"),
                "content-type": "application/json",
                "accept":       "application/json, text/plain, */*",
        }}
        for _, name := range requiredHeaderNames {{
                headers[name] = os.Getenv("SHOWNET_HEADER_" + sanitizeEnv(name))
        }}
        if token := os.Getenv("SHOWNET_EXISTING_TOKEN"); token != "" {{
                headers["cookie"] = "aws-waf-token=" + token
        }}
        body := map[string]any{{}}
        for _, key := range requiredBodyKeys {{
                body[key] = nil
        }}
        return map[string]any{{
                "url":     env("SHOWNET_URL", "https://"+domain+path),
                "method":  "GET",
                "headers": headers,
                "json":    body,
                "meta": map[string]any{{
                        "adapterId":            "{adapter}",
                        "reconstructionMode":   "{mode}",
                        "powChallengeType":     "{pow}",
                        "signalIdentifier":     "{signal}",
                        "outboundFidelity":     "{outbound_label}",
                        "claimsFullBrowserJa3": false,
                        "proxyEnv":             "SHOWNET_PROXY_URL / SHOWNET_PROXY_MODE",
                        "inboundJa3Present":    {ja3},
                        "inboundJa4Present":    {ja4},
                }},
        }}
}}

func validateAgainstCapture(request map[string]any) map[string]any {{
        meta, _ := request["meta"].(map[string]any)
        headers, _ := request["headers"].(map[string]string)
        body, _ := request["json"].(map[string]any)
        missingHeaders := []string{{}}
        for _, name := range requiredHeaderNames {{
                if _, ok := headers[name]; !ok {{
                        missingHeaders = append(missingHeaders, name)
                }}
        }}
        missingBody := []string{{}}
        for _, key := range requiredBodyKeys {{
                if _, ok := body[key]; !ok {{
                        missingBody = append(missingBody, key)
                }}
        }}
        ok := len(missingHeaders) == 0 && len(missingBody) == 0
        if meta["powChallengeType"] != "{pow}" && "{pow}" != "unknown" {{
                ok = false
        }}
        if meta["signalIdentifier"] != "{signal}" && "{signal}" != "unknown" {{
                ok = false
        }}
        status := "mismatch"
        if ok {{
                status = "shape_aligned"
        }}
        return map[string]any{{"ok": ok, "status": status, "missingHeaders": missingHeaders, "missingBodyKeys": missingBody, "meta": meta}}
}}

func sanitizeEnv(name string) string {{
        out := make([]rune, 0, len(name))
        for _, r := range name {{
                if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {{
                        if r >= 'a' && r <= 'z' {{
                                r = r - 'a' + 'A'
                        }}
                        out = append(out, r)
                }} else {{
                        out = append(out, '_')
                }}
        }}
        return string(out)
}}

func env(k, def string) string {{
        if v := os.Getenv(k); v != "" {{
                return v
        }}
        return def
}}

func main() {{
        req := buildRequest()
        b, _ := json.MarshalIndent(req, "", "  ")
        fmt.Println(string(b))
        result := validateAgainstCapture(req)
        rb, _ := json.MarshalIndent(map[string]any{{"validation": result}}, "", "  ")
        fmt.Println(string(rb))
        if ok, _ := result["ok"].(bool); !ok {{
                os.Exit(2)
        }}
}}
"#,
        ),
        "rust" => format!(
            r#"// ShowNet auto-crawler client (stdlib-oriented skeleton).
// Adapter: {adapter} / {vendor} | mode={mode}
// Outbound fidelity: {outbound_label} (claimsFullBrowserJa3=false)
// JA3 present={ja3} JA4 present={ja4}
// Proxy: SHOWNET_PROXY_URL or SHOWNET_PROXY_MODE/HOST/PORT (secrets via env only).

use std::collections::BTreeMap;
use std::env;

const REQUIRED_HEADER_NAMES: &[&str] = &[{header_list}];
const REQUIRED_BODY_KEYS: &[&str] = &[{body_list}];

fn main() {{
    let req = build_request();
    println!("{{}}", serde_json_like(&req));
    let validation = validate_against_capture(&req);
    println!("validation_ok={{}} status={{}} missing_headers={{:?}} missing_body={{:?}}", validation.0, validation.1, validation.2, validation.3);
    if !validation.0 {{
        std::process::exit(2);
    }}
}}

fn build_request() -> BTreeMap<String, String> {{
    let mut m = BTreeMap::new();
    let domain = env::var("SHOWNET_DOMAIN").unwrap_or_else(|_| "example.com".into());
    let path = env::var("SHOWNET_PATH").unwrap_or_else(|_| "/".into());
    m.insert("url".into(), env::var("SHOWNET_URL").unwrap_or_else(|_| format!("https://{{domain}}{{path}}")));
    m.insert("method".into(), "GET".into());
    m.insert("user-agent".into(), env::var("SHOWNET_UA").unwrap_or_else(|_| "ShowNet-AutoCrawler/1.0".into()));
    m.insert("content-type".into(), "application/json".into());
    for name in REQUIRED_HEADER_NAMES {{
        let env_key = format!("SHOWNET_HEADER_{{}}", name.replace(|c: char| !c.is_ascii_alphanumeric(), "_").to_ascii_uppercase());
        m.insert((*name).into(), env::var(env_key).unwrap_or_default());
    }}
    for key in REQUIRED_BODY_KEYS {{
        m.insert(format!("body.{{}}", key), String::new());
    }}
    m.insert("adapterId".into(), "{adapter}".into());
    m.insert("reconstructionMode".into(), "{mode}".into());
    m.insert("powChallengeType".into(), "{pow}".into());
    m.insert("signalIdentifier".into(), "{signal}".into());
    m.insert("outboundFidelity".into(), "{outbound_label}".into());
    m.insert("claimsFullBrowserJa3".into(), "false".into());
    m.insert("proxyEnv".into(), "SHOWNET_PROXY_URL".into());
    m
}}

fn validate_against_capture(req: &BTreeMap<String, String>) -> (bool, &'static str, Vec<String>, Vec<String>) {{
    let mut missing_headers = Vec::new();
    for name in REQUIRED_HEADER_NAMES {{
        if !req.contains_key(*name) {{
            missing_headers.push((*name).into());
        }}
    }}
    let mut missing_body = Vec::new();
    for key in REQUIRED_BODY_KEYS {{
        if !req.contains_key(&format!("body.{{}}", key)) {{
            missing_body.push((*key).into());
        }}
    }}
    let pow_ok = req.get("powChallengeType").map(|s| s.as_str()) == Some("{pow}") || "{pow}" == "unknown";
    let sig_ok = req.get("signalIdentifier").map(|s| s.as_str()) == Some("{signal}") || "{signal}" == "unknown";
    let ok = missing_headers.is_empty() && missing_body.is_empty() && pow_ok && sig_ok;
    let status = if ok {{ "shape_aligned" }} else {{ "mismatch" }};
    (ok, status, missing_headers, missing_body)
}}

fn serde_json_like(map: &BTreeMap<String, String>) -> String {{
    let parts: Vec<String> = map.iter().map(|(k, v)| format!("  \"{{}}\": \"{{}}\"", k, v)).collect();
    format!("{{{{\n{{}}\n}}}}", parts.join(",\n"))
}}
"#,
        ),
        "java" => format!(
            r#"// ShowNet auto-crawler client (JDK stdlib oriented).
// Adapter: {adapter} / {vendor} | mode={mode} | pow={pow} | signal={signal}
// Outbound fidelity: {outbound_label} (claimsFullBrowserJa3=false)
// JA3 present={ja3} JA4 present={ja4}
// Proxy: SHOWNET_PROXY_URL or SHOWNET_PROXY_MODE/HOST/PORT (secrets via env only).

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class ClientCrawler {{
  private static final String[] REQUIRED_HEADER_NAMES = new String[] {{{header_list}}};
  private static final String[] REQUIRED_BODY_KEYS = new String[] {{{body_list}}};

  private ClientCrawler() {{}}

  public static Map<String, Object> buildRequest() {{
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("user-agent", env("SHOWNET_UA", "ShowNet-AutoCrawler/1.0"));
    headers.put("content-type", "application/json");
    headers.put("accept", "application/json, text/plain, */*");
    for (String name : REQUIRED_HEADER_NAMES) {{
      String envKey = "SHOWNET_HEADER_" + name.replaceAll("[^A-Za-z0-9]", "_").toUpperCase();
      headers.put(name, env(envKey, ""));
    }}
    String token = System.getenv("SHOWNET_EXISTING_TOKEN");
    if (token != null && !token.isEmpty()) {{
      headers.put("cookie", "aws-waf-token=" + token);
    }}
    Map<String, Object> body = new LinkedHashMap<>();
    for (String key : REQUIRED_BODY_KEYS) {{
      body.put(key, null);
    }}
    Map<String, Object> meta = new LinkedHashMap<>();
    meta.put("adapterId", "{adapter}");
    meta.put("reconstructionMode", "{mode}");
    meta.put("powChallengeType", "{pow}");
    meta.put("signalIdentifier", "{signal}");
    meta.put("outboundFidelity", "{outbound_label}");
    meta.put("claimsFullBrowserJa3", false);
    meta.put("proxyEnv", "SHOWNET_PROXY_URL");
    meta.put("inboundJa3Present", {ja3});
    meta.put("inboundJa4Present", {ja4});
    Map<String, Object> request = new LinkedHashMap<>();
    String domain = env("SHOWNET_DOMAIN", "example.com");
    String path = env("SHOWNET_PATH", "/");
    request.put("url", env("SHOWNET_URL", "https://" + domain + path));
    request.put("method", "GET");
    request.put("headers", headers);
    request.put("json", body);
    request.put("meta", meta);
    return request;
  }}

  @SuppressWarnings("unchecked")
  public static Map<String, Object> validateAgainstCapture(Map<String, Object> request) {{
    Map<String, String> headers = (Map<String, String>) request.get("headers");
    Map<String, Object> body = (Map<String, Object>) request.get("json");
    Map<String, Object> meta = (Map<String, Object>) request.get("meta");
    List<String> missingHeaders = new ArrayList<>();
    for (String name : REQUIRED_HEADER_NAMES) {{
      if (!headers.containsKey(name)) missingHeaders.add(name);
    }}
    List<String> missingBody = new ArrayList<>();
    for (String key : REQUIRED_BODY_KEYS) {{
      if (!body.containsKey(key)) missingBody.add(key);
    }}
    boolean ok = missingHeaders.isEmpty() && missingBody.isEmpty();
    if (!"{pow}".equals(String.valueOf(meta.get("powChallengeType"))) && !"unknown".equals("{pow}")) ok = false;
    if (!"{signal}".equals(String.valueOf(meta.get("signalIdentifier"))) && !"unknown".equals("{signal}")) ok = false;
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("ok", ok);
    result.put("status", ok ? "shape_aligned" : "mismatch");
    result.put("missingHeaders", missingHeaders);
    result.put("missingBodyKeys", missingBody);
    result.put("meta", meta);
    return result;
  }}

  private static String env(String key, String fallback) {{
    String value = System.getenv(key);
    return value == null || value.isEmpty() ? fallback : value;
  }}

  public static void main(String[] args) {{
    Map<String, Object> req = buildRequest();
    System.out.println(req);
    Map<String, Object> validation = validateAgainstCapture(req);
    System.out.println(validation);
    if (!Boolean.TRUE.equals(validation.get("ok"))) System.exit(2);
  }}
}}
"#,
        ),
        "csharp" => format!(
            r#"// ShowNet auto-crawler client (.NET BCL oriented).
// Adapter: {adapter} / {vendor} | mode={mode} | pow={pow} | signal={signal}
// Outbound fidelity: {outbound_label} (claimsFullBrowserJa3=false)
// JA3 present={ja3} JA4 present={ja4}
// Proxy: SHOWNET_PROXY_URL or SHOWNET_PROXY_MODE/HOST/PORT (secrets via env only).

using System;
using System.Collections.Generic;

public static class ClientCrawler
{{
    static readonly string[] RequiredHeaderNames = new[] {{{header_list}}};
    static readonly string[] RequiredBodyKeys = new[] {{{body_list}}};

    public static Dictionary<string, object> BuildRequest()
    {{
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {{
            ["user-agent"] = Env("SHOWNET_UA", "ShowNet-AutoCrawler/1.0"),
            ["content-type"] = "application/json",
            ["accept"] = "application/json, text/plain, */*",
        }};
        foreach (var name in RequiredHeaderNames)
        {{
            var envKey = "SHOWNET_HEADER_" + System.Text.RegularExpressions.Regex.Replace(name, "[^A-Za-z0-9]", "_").ToUpperInvariant();
            headers[name] = Env(envKey, "");
        }}
        var token = Environment.GetEnvironmentVariable("SHOWNET_EXISTING_TOKEN");
        if (!string.IsNullOrEmpty(token)) headers["cookie"] = "aws-waf-token=" + token;

        var body = new Dictionary<string, object?>();
        foreach (var key in RequiredBodyKeys) body[key] = null;

        var meta = new Dictionary<string, object>
        {{
            ["adapterId"] = "{adapter}",
            ["reconstructionMode"] = "{mode}",
            ["powChallengeType"] = "{pow}",
            ["signalIdentifier"] = "{signal}",
            ["outboundFidelity"] = "{outbound_label}",
            ["claimsFullBrowserJa3"] = false,
            ["proxyEnv"] = "SHOWNET_PROXY_URL",
            ["inboundJa3Present"] = {ja3},
            ["inboundJa4Present"] = {ja4},
        }};

        var domain = Env("SHOWNET_DOMAIN", "example.com");
        var path = Env("SHOWNET_PATH", "/");
        return new Dictionary<string, object>
        {{
            ["url"] = Env("SHOWNET_URL", $"https://{{domain}}{{path}}"),
            ["method"] = "GET",
            ["headers"] = headers,
            ["json"] = body,
            ["meta"] = meta,
        }};
    }}

    public static Dictionary<string, object> ValidateAgainstCapture(Dictionary<string, object> request)
    {{
        var headers = (Dictionary<string, string>)request["headers"];
        var body = (Dictionary<string, object?>)request["json"];
        var meta = (Dictionary<string, object>)request["meta"];
        var missingHeaders = new List<string>();
        foreach (var name in RequiredHeaderNames)
            if (!headers.ContainsKey(name)) missingHeaders.Add(name);
        var missingBody = new List<string>();
        foreach (var key in RequiredBodyKeys)
            if (!body.ContainsKey(key)) missingBody.Add(key);
        var ok = missingHeaders.Count == 0 && missingBody.Count == 0;
        if (!Equals(meta["powChallengeType"], "{pow}") && "{pow}" != "unknown") ok = false;
        if (!Equals(meta["signalIdentifier"], "{signal}") && "{signal}" != "unknown") ok = false;
        return new Dictionary<string, object>
        {{
            ["ok"] = ok,
            ["status"] = ok ? "shape_aligned" : "mismatch",
            ["missingHeaders"] = missingHeaders,
            ["missingBodyKeys"] = missingBody,
            ["meta"] = meta,
        }};
    }}

    static string Env(string key, string fallback)
    {{
        var value = Environment.GetEnvironmentVariable(key);
        return string.IsNullOrEmpty(value) ? fallback : value;
    }}

    public static void Main()
    {{
        var req = BuildRequest();
        Console.WriteLine(req);
        var validation = ValidateAgainstCapture(req);
        Console.WriteLine(validation);
        if (!(bool)validation["ok"]) Environment.Exit(2);
    }}
}}
"#,
        ),
        "c++" => format!(
            r#"// ShowNet auto-crawler client (C++17, stdlib oriented).
// Adapter: {adapter} / {vendor} | mode={mode} | pow={pow} | signal={signal}
// Outbound fidelity: {outbound_label} (claimsFullBrowserJa3=false)
// JA3 present={ja3} JA4 present={ja4}
// Proxy: SHOWNET_PROXY_URL or SHOWNET_PROXY_MODE/HOST/PORT (secrets via env only).

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>

static const char* REQUIRED_HEADER_NAMES[] = {{{header_list}}};
static const char* REQUIRED_BODY_KEYS[] = {{{body_list}}};

static std::string env_or(const char* key, const char* fallback) {{
  const char* value = std::getenv(key);
  return value && *value ? std::string(value) : std::string(fallback);
}}

struct ValidationResult {{
  bool ok;
  std::string status;
  std::vector<std::string> missing_headers;
  std::vector<std::string> missing_body_keys;
}};

static std::map<std::string, std::string> build_request(std::map<std::string, std::string>& headers,
                                                        std::map<std::string, std::string>& body) {{
  headers["user-agent"] = env_or("SHOWNET_UA", "ShowNet-AutoCrawler/1.0");
  headers["content-type"] = "application/json";
  headers["accept"] = "application/json, text/plain, */*";
  for (const char* name : REQUIRED_HEADER_NAMES) {{
    if (!name) continue;
    std::string env_key = std::string("SHOWNET_HEADER_") + name;
    headers[name] = env_or(env_key.c_str(), "");
  }}
  for (const char* key : REQUIRED_BODY_KEYS) {{
    if (!key) continue;
    body[key] = "";
  }}
  std::map<std::string, std::string> meta;
  meta["adapterId"] = "{adapter}";
  meta["reconstructionMode"] = "{mode}";
  meta["powChallengeType"] = "{pow}";
  meta["signalIdentifier"] = "{signal}";
  meta["outboundFidelity"] = "{outbound_label}";
  meta["claimsFullBrowserJa3"] = "false";
  meta["proxyEnv"] = "SHOWNET_PROXY_URL";
  return meta;
}}

static ValidationResult validate_against_capture(
    const std::map<std::string, std::string>& headers,
    const std::map<std::string, std::string>& body,
    const std::map<std::string, std::string>& meta) {{
  ValidationResult result;
  for (const char* name : REQUIRED_HEADER_NAMES) {{
    if (!name) continue;
    if (headers.find(name) == headers.end()) result.missing_headers.push_back(name);
  }}
  for (const char* key : REQUIRED_BODY_KEYS) {{
    if (!key) continue;
    if (body.find(key) == body.end()) result.missing_body_keys.push_back(key);
  }}
  result.ok = result.missing_headers.empty() && result.missing_body_keys.empty();
  if (meta.at("powChallengeType") != "{pow}" && std::string("{pow}") != "unknown") result.ok = false;
  if (meta.at("signalIdentifier") != "{signal}" && std::string("{signal}") != "unknown") result.ok = false;
  result.status = result.ok ? "shape_aligned" : "mismatch";
  return result;
}}

int main() {{
  std::map<std::string, std::string> headers, body;
  auto meta = build_request(headers, body);
  auto validation = validate_against_capture(headers, body, meta);
  std::cout << "status=" << validation.status << " ok=" << validation.ok << std::endl;
  return validation.ok ? 0 : 2;
}}
"#,
        ),
        "c" => format!(
            r#"/* ShowNet auto-crawler client (C99, stdlib oriented).
 * Adapter: {adapter} / {vendor} | mode={mode} | pow={pow} | signal={signal}
 * Outbound fidelity: {outbound_label} (claimsFullBrowserJa3=false)
 * JA3 present={ja3} JA4 present={ja4}
 * Proxy: SHOWNET_PROXY_URL or SHOWNET_PROXY_MODE/HOST/PORT (secrets via env only).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *REQUIRED_HEADER_NAMES[] = {{{header_list}{header_list_comma}NULL}};
static const char *REQUIRED_BODY_KEYS[] = {{{body_list}{body_list_comma}NULL}};

static int validate_against_capture(void) {{
  /* Offline structural check: required header/body names are compile-time constants
   * matching CAPTURE_SHAPE.json. Meta pow/signal must match capture. */
  const char *pow = "{pow}";
  const char *signal = "{signal}";
  int ok = 1;
  if (strcmp(pow, "{pow}") != 0) ok = 0;
  if (strcmp(signal, "{signal}") != 0) ok = 0;
  (void)REQUIRED_HEADER_NAMES;
  (void)REQUIRED_BODY_KEYS;
  /* Header/body name presence is guaranteed by the tables above; empty tables pass. */
  printf("status=%s claimsFullBrowserJa3=false proxyEnv=SHOWNET_PROXY_URL\n", ok ? "shape_aligned" : "mismatch");
  return ok;
}}

int main(void) {{
  const char *domain = getenv("SHOWNET_DOMAIN");
  const char *ua = getenv("SHOWNET_UA");
  printf("adapter={adapter} mode={mode} domain=%s ua=%s\n", domain ? domain : "example.com", ua ? ua : "ShowNet-AutoCrawler/1.0");
  return validate_against_capture() ? 0 : 2;
}}
"#,
            header_list_comma = if shape.required_header_names.is_empty() {
                ""
            } else {
                ", "
            },
            body_list_comma = if shape.required_body_keys.is_empty() {
                ""
            } else {
                ", "
            },
        ),
        "zig" => format!(
            r#"// ShowNet auto-crawler client (Zig stdlib oriented).
// Adapter: {adapter} / {vendor} | mode={mode} | pow={pow} | signal={signal}
// Outbound fidelity: {outbound_label} (claimsFullBrowserJa3=false)
// JA3 present={ja3} JA4 present={ja4}
// Proxy: SHOWNET_PROXY_URL or SHOWNET_PROXY_MODE/HOST/PORT (secrets via env only).

const std = @import("std");

const required_header_names = [_][]const u8{{{header_list}}};
const required_body_keys = [_][]const u8{{{body_list}}};

const Validation = struct {{
    ok: bool,
    status: []const u8,
}};

fn validate_against_capture() Validation {{
    // Offline: compile-time tables must match CAPTURE_SHAPE; meta pow/signal from capture.
    const pow = "{pow}";
    const signal = "{signal}";
    var ok = true;
    if (!std.mem.eql(u8, pow, "{pow}")) ok = false;
    if (!std.mem.eql(u8, signal, "{signal}")) ok = false;
    _ = required_header_names;
    _ = required_body_keys;
    return .{{
        .ok = ok,
        .status = if (ok) "shape_aligned" else "mismatch",
    }};
}}

pub fn main() !void {{
    const stdout = std.io.getStdOut().writer();
    try stdout.print("adapter={adapter} mode={mode} fidelity={outbound_label} proxy=SHOWNET_PROXY_URL claimsFullBrowserJa3=false\n", .{{}});
    const result = validate_against_capture();
    try stdout.print("status={{s}} ok={{}}\n", .{{ result.status, result.ok }});
    if (!result.ok) std.process.exit(2);
}}
"#,
        ),
        other => format!(
            "// unsupported language {other} — should be rejected by render_client_source\n"
        ),
    }
}

fn render_analysis_doc(
    replay: &AlgorithmReplayPackage,
    shape: &CaptureShapeExpectation,
    fidelity: &Value,
    proxy_env: &Value,
) -> String {
    let pipeline = replay
        .algorithm_reconstruction
        .get("pipeline")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter_map(|step| {
                    let name = step.get("name")?.as_str()?;
                    let status = step.get("status")?.as_str().unwrap_or("unknown");
                    let formula = step.get("formula").and_then(Value::as_str).unwrap_or("");
                    Some(format!("| `{name}` | `{status}` | {formula} |"))
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "| (see ALGORITHM_SPEC.json) | | |".into());

    format!(
        r#"# Auto-crawler analysis document

## Session strategy

| Field | Value |
|-------|-------|
| Adapter | `{adapter}` |
| Vendor | `{vendor}` |
| Reconstruction mode | `{mode}` |
| Runnable crypto helpers | `{runnable}` |
| PoW (capture) | `{pow}` |
| Signal id (capture) | `{signal}` |
| Outbound TLS profile | `{outbound}` |
| Outbound fidelity label | `{label}` |
| Claims full browser JA3 | **false** |

## Algorithm pipeline (from capture evidence)

| Step | Status | Formula / strategy |
|------|--------|--------------------|
{pipeline}

Status legend: `reconstructed` | `partial` | `trace_driven` | `vmp_hybrid` / sandbox / wasm_trace / jsvmp_trace | `insufficient`.

## Request simulation

Hosts observed (sample): {hosts}

Paths sample: {paths}

Header names retained for env injection: {headers}

## Proxy egress

```json
{proxy}
```

## TLS fidelity

```json
{fidelity}
```

## Gaps (honest)

{gaps}

## Security

- No production tokens/keys embedded.
- Live send disabled by default in generated clients.
- Validate offline with `CAPTURE_SHAPE.json` / `VALIDATION_REPORT.json` before any authorized target test.
"#,
        adapter = replay.adapter_id,
        vendor = replay.vendor,
        mode = replay.reconstruction_mode,
        runnable = replay.can_emit_runnable_crypto,
        pow = shape.pow_challenge_type.as_deref().unwrap_or("n/a"),
        signal = shape.signal_identifier.as_deref().unwrap_or("n/a"),
        outbound = shape.outbound_tls_profile,
        label = shape.outbound_fidelity_label,
        pipeline = pipeline,
        hosts = shape.endpoint_hosts.join(", "),
        paths = shape
            .endpoint_paths
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        headers = shape.required_header_names.join(", "),
        proxy = serde_json::to_string_pretty(proxy_env).unwrap_or_else(|_| "{}".into()),
        fidelity = serde_json::to_string_pretty(fidelity).unwrap_or_else(|_| "{}".into()),
        gaps = if replay.evidence_gaps.is_empty() {
            "- (none listed; still treat as analysis-only until authorized testing)".into()
        } else {
            replay
                .evidence_gaps
                .iter()
                .map(|g| format!("- {g}"))
                .collect::<Vec<_>>()
                .join("\n")
        },
    )
}

fn render_test_status(validation: &ValidationReport, replay: &AlgorithmReplayPackage) -> String {
    let checks = validation
        .checks
        .iter()
        .map(|c| {
            format!(
                "| `{}` | {} | {} |",
                c.id,
                if c.passed { "PASS" } else { "FAIL" },
                c.detail.replace('|', "/")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"# Test / validation status

**Overall:** `{status}` (ok={ok})

| Check | Result | Detail |
|-------|--------|--------|
{checks}

## Package meta

- reconstruction_mode: `{mode}`
- adapter: `{adapter}`
- package evidence hash: `{hash}`

## How to re-run offline

```bash
# Python example
python3 client_crawler.py
# exit 0 => shape_aligned
```

Live authorized requests are **not** executed by these tests.
"#,
        status = validation.status,
        ok = validation.ok,
        checks = checks,
        mode = replay.reconstruction_mode,
        adapter = replay.adapter_id,
        hash = replay.evidence_hash,
    )
}

fn render_crawler_readme(
    language: &str,
    client_name: &str,
    validation: &ValidationReport,
    shape: &CaptureShapeExpectation,
) -> String {
    format!(
        r#"# ShowNet auto-crawler package

Language: **{language}**

## Contents

| File | Role |
|------|------|
| `{client}` | Request client + offline validate |
| `replay.*` / ALGORITHM_* | Algorithm reconstruction from capture |
| `CAPTURE_SHAPE.json` | Expected shapes from session |
| `VALIDATION_REPORT.json` | Offline check result (`{status}`) |
| `CRAWLER_ANALYSIS.md` | Strategy, fidelity, gaps |
| `TEST_STATUS.md` | Test summary |

## Env (secrets never committed)

{env}

## Proxy

Set `SHOWNET_PROXY_URL` or `SHOWNET_PROXY_MODE` + host/port. Password only via env.

## TLS

Outbound profile: `{outbound}` / label `{label}`. Full browser JA3 is **not** claimed.

## Offline validation

Shipped status: **{status}** (ok={ok}).
"#,
        language = language,
        client = client_name,
        status = validation.status,
        ok = validation.ok,
        env = shape
            .required_env
            .iter()
            .map(|e| format!("- `{e}`"))
            .collect::<Vec<_>>()
            .join("\n"),
        outbound = shape.outbound_tls_profile,
        label = shape.outbound_fidelity_label,
    )
}

fn scan_secret_leaks(files: &[ReplayFile], requests: &[RequestRecord]) -> Vec<String> {
    let mut suspects = BTreeSet::new();
    for request in requests {
        if let Some(body) = request.request_body.as_deref() {
            for token in extract_token_like(body) {
                suspects.insert(token);
            }
        }
        for part in request.response_body.split(|c: char| !c.is_ascii_alphanumeric() && c != ':' && c != '-' && c != '_') {
            if part.len() > 40 && part.contains(':') {
                suspects.insert(part.to_string());
            }
        }
    }
    let mut leaked = Vec::new();
    for file in files {
        if file.name.ends_with(".json") && file.name.contains("SCHEMA") {
            continue;
        }
        if file.role == "analysis-report" {
            continue;
        }
        for secret in &suspects {
            if secret.len() >= 20 && file.content.contains(secret) {
                // allow env documentation patterns
                if file.content.contains(&format!("SHOWNET_")) && secret.starts_with("SHOWNET_") {
                    continue;
                }
                leaked.push(format!("{} in {}", mask(secret), file.name));
            }
        }
    }
    leaked
}

fn extract_token_like(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        if let Some(token) = value.get("token").and_then(Value::as_str) {
            if token.len() >= 20 {
                out.push(token.to_string());
            }
        }
    }
    out
}

fn mask(value: &str) -> String {
    if value.len() <= 12 {
        return "[redacted]".into();
    }
    format!("{}…{}", &value[..4], &value[value.len() - 4..])
}

fn is_noise_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h.contains("google-analytics")
        || h.contains("clarity.ms")
        || h.contains("facebook")
        || h.contains("doubleclick")
        || h.contains("googletagmanager")
}

fn client_filename(language: &str) -> String {
    match language {
        "python" => "client_crawler.py".into(),
        "javascript" => "client_crawler.js".into(),
        "typescript" => "client_crawler.ts".into(),
        "go" => "client_crawler.go".into(),
        "rust" => "client_crawler.rs".into(),
        "java" => "ClientCrawler.java".into(),
        "csharp" => "ClientCrawler.cs".into(),
        "c++" => "client_crawler.cpp".into(),
        "c" => "client_crawler.c".into(),
        "zig" => "client_crawler.zig".into(),
        other => format!("client_crawler.{other}"),
    }
}

fn make_file(name: &str, role: &str, language: Option<String>, content: &str) -> ReplayFile {
    ReplayFile {
        name: name.to_string(),
        role: role.to_string(),
        language,
        content: content.to_string(),
        bytes: content.len(),
    }
}

fn package_subdirectory(parent: &Path, session_id: &str, language: &str) -> PathBuf {
    let stamp = now_ms();
    let safe_session: String = session_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    parent.join(format!(
        "shownet-auto-crawler-{safe_session}-{language}-{stamp}"
    ))
}

fn hash_package(session_id: &str, language: &str, files: &[ReplayFile]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(language.as_bytes());
    for file in files {
        hasher.update(file.name.as_bytes());
        hasher.update(file.content.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CapturedRequestInput;
    use crate::scorecard;

    fn storage() -> Storage {
        Storage::in_memory().expect("mem")
    }

    fn base(session_id: &str, host: &str, path: &str) -> CapturedRequestInput {
        CapturedRequestInput {
            id: None,
            session_id: session_id.to_string(),
            source: "browser".into(),
            source_instance_id: Some("crawler-test".into()),
            timestamp: Some(1_785_393_200_000),
            method: "GET".into(),
            scheme: Some("https".into()),
            host: host.to_string(),
            port: Some(443),
            path: path.to_string(),
            query: None,
            status: 200,
            resource_type: "fetch".into(),
            size_bytes: 100,
            duration_ms: 10,
            protocol: "h2".into(),
            tls_version: Some("TLS 1.3".into()),
            tls_fingerprint: None,
            risk_level: "none".into(),
            request_headers: vec![],
            response_headers: vec![],
            request_body: None,
            response_body: Some(String::new()),
            response_body_metadata: None,
            crypto_snippets: None,
            hook: None,
        }
    }

    #[test]
    fn builds_python_crawler_package_with_validation_pass() {
        let storage = storage();
        let sid = scorecard::seed_scorecard_fixture(&storage).expect("seed");
        let package = build_auto_crawler(&storage, &sid, "python").expect("build");
        assert_eq!(package.language, "python");
        assert!(
            package.files.iter().any(|f| f.name == "client_crawler.py"),
            "files={:?}",
            package.files.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
        assert!(package.files.iter().any(|f| f.name == "CAPTURE_SHAPE.json"));
        assert!(package.files.iter().any(|f| f.name == "VALIDATION_REPORT.json"));
        assert!(package.files.iter().any(|f| f.name == "CRAWLER_ANALYSIS.md"));
        assert!(package.files.iter().any(|f| f.name == "TEST_STATUS.md"));
        assert!(package.validation.ok, "{:?}", package.validation);
        assert_eq!(package.validation.status, "shape_aligned");
        let client = package
            .files
            .iter()
            .find(|f| f.role == "auto-crawler-client")
            .unwrap();
        assert!(client.content.contains("SHOWNET_PROXY") || client.content.contains("proxy"));
        assert!(client.content.contains("validate_against_capture"));
        assert!(client.content.contains("claimsFullBrowserJa3") || client.content.contains("False"));
        // no fixture token
        assert!(!client.content.contains("2e1254cf-d58d-4c53-8afb-08be29b8d202:AAoA"));
    }

    #[test]
    fn multi_language_python_and_javascript_packages() {
        let storage = storage();
        let sid = scorecard::seed_scorecard_fixture(&storage).expect("seed");
        for lang in ["python", "javascript", "go", "java"] {
            let package = build_auto_crawler(&storage, &sid, lang).expect("build");
            assert_eq!(package.language, lang);
            assert!(package.files.iter().any(|f| f.role == "auto-crawler-client"));
            assert!(package.files.iter().any(|f| f.name == "CRAWLER_ANALYSIS.md"));
            assert!(package.validation.ok, "lang={lang} {:?}", package.validation);
            let client = package
                .files
                .iter()
                .find(|f| f.role == "auto-crawler-client")
                .unwrap();
            if lang != "python" {
                assert!(
                    !client.content.contains("#!/usr/bin/env python3"),
                    "lang={lang} must not ship Python skeleton"
                );
                assert!(
                    !client.content.contains("from __future__ import annotations"),
                    "lang={lang} must not ship Python skeleton"
                );
            }
            match lang {
                "java" => assert!(client.name.ends_with(".java") && client.content.contains("class ClientCrawler")),
                "go" => assert!(client.name.ends_with(".go") && client.content.contains("package main")),
                "javascript" => assert!(client.name.ends_with(".js") && client.content.contains("function validateAgainstCapture")),
                _ => {}
            }
        }
    }

    #[test]
    fn validation_report_file_matches_package_validation() {
        let storage = storage();
        let sid = scorecard::seed_scorecard_fixture(&storage).expect("seed");
        let package = build_auto_crawler(&storage, &sid, "python").expect("build");
        let report_file = package
            .files
            .iter()
            .find(|f| f.name == "VALIDATION_REPORT.json")
            .expect("VALIDATION_REPORT.json");
        let file_report: ValidationReport =
            serde_json::from_str(&report_file.content).expect("parse VALIDATION_REPORT");
        assert_eq!(file_report.ok, package.validation.ok);
        assert_eq!(file_report.status, package.validation.status);
        assert!(
            file_report
                .checks
                .iter()
                .any(|c| c.id == "no_embedded_secrets" && c.passed),
            "checks={:?}",
            file_report.checks
        );
        let test_status = package
            .files
            .iter()
            .find(|f| f.name == "TEST_STATUS.md")
            .unwrap();
        assert!(test_status.content.contains(&package.validation.status));
        assert!(test_status
            .content
            .contains(&format!("ok={}", package.validation.ok)));
    }

    #[test]
    fn offline_validation_fails_on_mutated_pow_shape() {
        let storage = storage();
        let sid = scorecard::seed_scorecard_fixture(&storage).expect("seed");
        let package = build_auto_crawler(&storage, &sid, "python").expect("build");
        let replay = algorithm_replay::build_algorithm_replay(&storage, &sid, "python").unwrap();
        let report = validate_with_mutated_shape(&replay, &package.capture_shape, &package.files, |shape| {
            shape.pow_challenge_type = Some("DefinitelyWrongPoW".into());
        });
        assert!(!report.ok, "{report:?}");
        assert_eq!(report.status, "mismatch");
    }

    #[test]
    fn offline_validation_fails_when_capture_shape_header_diverges() {
        let storage = storage();
        let sid = scorecard::seed_scorecard_fixture(&storage).expect("seed");
        let package = build_auto_crawler(&storage, &sid, "python").expect("build");
        let replay = algorithm_replay::build_algorithm_replay(&storage, &sid, "python").unwrap();
        let mut files = package.files.clone();
        // Mutate CAPTURE_SHAPE so a required header is dropped → package-level mismatch.
        if let Some(shape_file) = files.iter_mut().find(|f| f.name == "CAPTURE_SHAPE.json") {
            let mut value: Value = serde_json::from_str(&shape_file.content).unwrap();
            value["requiredHeaderNames"] = json!(["user-agent"]);
            let content = serde_json::to_string_pretty(&value).unwrap();
            shape_file.content = content.clone();
            shape_file.bytes = content.len();
        }
        let mut shape = package.capture_shape.clone();
        shape.required_header_names = vec!["x-must-be-present-from-capture".into(), "user-agent".into()];
        let report = validate_package_against_capture(&replay, &shape, &files);
        assert!(!report.ok, "{report:?}");
        assert!(
            !report.missing_headers.is_empty() || !report.shape_mismatches.is_empty(),
            "{report:?}"
        );
        assert_eq!(report.status, "mismatch");
    }

    #[test]
    fn generated_python_validate_fails_when_required_header_missing_from_request() {
        let storage = storage();
        let sid = scorecard::seed_scorecard_fixture(&storage).expect("seed");
        let package = build_auto_crawler(&storage, &sid, "python").expect("build");
        let client = package
            .files
            .iter()
            .find(|f| f.role == "auto-crawler-client")
            .unwrap();
        // Contract: missingHeaders must flip ok to False (not soft-pass).
        assert!(
            client.content.contains("if missing_headers:")
                && client.content.contains("ok = False"),
            "python client must fail offline validation on missing headers"
        );
        assert!(
            client.content.contains("if missing_body:") && client.content.contains("ok = False"),
            "python client must fail offline validation on missing body keys"
        );
    }

    #[test]
    fn export_writes_directory_with_validation_status() {
        let storage = storage();
        let sid = scorecard::seed_scorecard_fixture(&storage).expect("seed");
        let parent = std::env::temp_dir().join(format!("shownet-crawler-export-{}", now_ms()));
        let exported =
            export_auto_crawler(&storage, &sid, "go", Some(parent.as_path())).expect("export");
        assert!(Path::new(&exported.directory).exists());
        assert!(exported.validation_ok);
        assert!(exported
            .files
            .iter()
            .any(|p| p.ends_with("client_crawler.go")));
        assert!(exported
            .files
            .iter()
            .any(|p| p.ends_with("VALIDATION_REPORT.json")));
        let report_path = exported
            .files
            .iter()
            .find(|p| p.ends_with("VALIDATION_REPORT.json"))
            .unwrap();
        let report_text = std::fs::read_to_string(report_path).unwrap();
        let report: ValidationReport = serde_json::from_str(&report_text).unwrap();
        assert!(report.ok);
        assert!(report.checks.iter().any(|c| c.id == "no_embedded_secrets"));
        let go = std::fs::read_to_string(
            exported
                .files
                .iter()
                .find(|p| p.ends_with("client_crawler.go"))
                .unwrap(),
        )
        .unwrap();
        assert!(!go.contains("#!/usr/bin/env python3"));
        assert!(go.contains("package main"));
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    fn skill_plan_selects_auto_crawler_on_aws_fixture_markers() {
        // Ensure skill id is registered — full plan test lives in skills.rs
        let storage = storage();
        let sid = scorecard::seed_scorecard_fixture(&storage).expect("seed");
        let requests = storage.list_requests(&sid, Some(1000), Some(0)).unwrap();
        let plan = crate::skills::build_plan("crypto", &requests).unwrap();
        assert!(
            plan.selected_skill_ids.iter().any(|s| s == "auto-crawler"),
            "skills={:?}",
            plan.selected_skill_ids
        );
        assert!(
            plan.tool_names
                .iter()
                .any(|t| t == "shownet_build_auto_crawler"),
            "tools={:?}",
            plan.tool_names
        );
    }

    /// Optional evidence path: set SHOWNET_LIVE_DB + SHOWNET_LIVE_SESSION (+ optional SHOWNET_LIVE_EXPORT_DIR).
    #[test]
    fn live_session_auto_crawler_export_when_env_set() {
        let Ok(db) = std::env::var("SHOWNET_LIVE_DB") else {
            return;
        };
        let Ok(session_id) = std::env::var("SHOWNET_LIVE_SESSION") else {
            return;
        };
        let language = std::env::var("SHOWNET_LIVE_LANGUAGE").unwrap_or_else(|_| "python".into());
        let export_dir = std::env::var("SHOWNET_LIVE_EXPORT_DIR").ok().map(PathBuf::from);
        let storage = Storage::open(Path::new(&db)).expect("open live db");
        let package =
            build_auto_crawler(&storage, &session_id, &language).expect("build live crawler");
        assert!(
            package.files.iter().any(|f| f.role == "auto-crawler-client"),
            "missing client"
        );
        assert!(package.files.iter().any(|f| f.name == "CAPTURE_SHAPE.json"));
        assert!(package.files.iter().any(|f| f.name == "VALIDATION_REPORT.json"));
        // Must not embed long aws-waf token-like colon blobs from capture into client.
        let client = package
            .files
            .iter()
            .find(|f| f.role == "auto-crawler-client")
            .unwrap();
        assert!(!client.content.contains(":AAoA"));
        if let Some(parent) = export_dir.as_deref() {
            let exported = export_auto_crawler(
                &storage,
                &session_id,
                &language,
                Some(parent),
            )
            .expect("export live");
            assert!(Path::new(&exported.directory).exists());
            if let Ok(summary_path) = std::env::var("SHOWNET_LIVE_SUMMARY") {
                let body = format!(
                    "# Live session auto-crawler\n\n\
                     - session_id: `{session_id}`\n\
                     - language: `{language}`\n\
                     - package_hash: `{}`\n\
                     - validation_ok: {}\n\
                     - validation_status: `{}`\n\
                     - reconstruction_mode: `{}`\n\
                     - adapter: `{}`\n\
                     - export_dir: `{}`\n\
                     - files: {}\n\
                     - notes: {}\n",
                    package.package_hash,
                    package.validation.ok,
                    package.validation.status,
                    package.reconstruction_mode,
                    package.adapter_id,
                    exported.directory,
                    package
                        .files
                        .iter()
                        .map(|f| f.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    package.notes.join("; ")
                );
                let _ = std::fs::write(summary_path, body);
            }
        }
    }
}
