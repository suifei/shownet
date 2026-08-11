//! Deterministic algorithm-replay package builder.
//!
//! Builds multi-language replay skeletons from captured session evidence and
//! optional analysis reports. Runtime credentials and live bypass solvers are supplied by callers;
//! callers must fill `compute_dynamic_fields` from authorized Hook/code evidence
//! and validate against the original capture before hitting production targets.

use crate::algorithm_reconstruction::{self, AlgorithmReconstruction};
use crate::protection_analysis;
use crate::signature_adapter::{self, SignatureAdapterHarness};
use crate::storage::Storage;
use crate::verification_manifest::{
    self, ArtifactVerificationManifest, GeneratedFileDigest, ManifestInput, VerificationVerdict,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SUPPORTED_LANGUAGES: &[&str] =
    &["python", "javascript", "typescript", "go", "java", "csharp"];

/// One agent-written step that ran against this capture's values and
/// reproduced them.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedStep {
    pub name: String,
    pub source: String,
    pub entry_point: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayFile {
    pub name: String,
    pub role: String,
    pub language: Option<String>,
    pub content: String,
    pub bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmReplayPackage {
    pub session_id: String,
    pub language: String,
    pub adapter_id: String,
    pub vendor: String,
    pub confidence: String,
    pub evidence_hash: String,
    pub package_hash: String,
    pub report_available: bool,
    pub report_id: Option<String>,
    pub reconstruction_mode: String,
    pub reconstruction_confidence: String,
    /// The steps that reproduced captured values, as data. Emitting them is
    /// `render_agent_algorithms`'s job; carrying them out lets another
    /// generator — the SDK builder — emit one function per step instead of
    /// treating the whole replay file as a single opaque blob.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_steps: Vec<VerifiedStep>,
    /// Pipeline steps that have no verified implementation in this package's
    /// language. They are named for downstream generators, never emitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unverified_steps: Vec<String>,
    pub can_emit_runnable_crypto: bool,
    /// Whether the emitted crypto was executed against captured values and
    /// reproduced them. Distinct from `can_emit_runnable_crypto`, which only
    /// says ShowNet had a template for these step names.
    pub crypto_verified: bool,
    pub provider_candidates: Value,
    pub protocol_schemas: Value,
    pub algorithm_reconstruction: Value,
    pub required_inputs: Vec<String>,
    pub evidence_gaps: Vec<String>,
    pub validation_checklist: Vec<String>,
    pub verification_manifest: ArtifactVerificationManifest,
    pub files: Vec<ReplayFile>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmReplayExportResult {
    pub session_id: String,
    pub language: String,
    pub directory: String,
    pub files: Vec<String>,
    pub package_hash: String,
    pub gate_verdict: VerificationVerdict,
    pub bytes_written: usize,
}

pub fn supported_languages() -> Vec<&'static str> {
    SUPPORTED_LANGUAGES.to_vec()
}

pub fn normalize_language(language: &str) -> Result<String, String> {
    let normalized = language.trim().to_ascii_lowercase();
    let mapped = match normalized.as_str() {
        "py" | "python3" | "python" => "python",
        "js" | "node" | "nodejs" | "javascript" => "javascript",
        "ts" | "tsx" | "typescript" => "typescript",
        "golang" | "go" => "go",
        "java" => "java",
        "c#" | "cs" | "csharp" => "csharp",
        other if SUPPORTED_LANGUAGES.contains(&other) => other,
        other => {
            return Err(format!(
                "不支持的重播语言: {other}。可选: {}",
                SUPPORTED_LANGUAGES.join(", ")
            ))
        }
    };
    Ok(mapped.to_string())
}

pub fn build_algorithm_replay(
    storage: &Storage,
    session_id: &str,
    language: &str,
) -> Result<AlgorithmReplayPackage, String> {
    build_algorithm_replay_for_report(storage, session_id, language, None)
}

pub fn build_algorithm_replay_for_report(
    storage: &Storage,
    session_id: &str,
    language: &str,
    report_id: Option<&str>,
) -> Result<AlgorithmReplayPackage, String> {
    storage.get_session(session_id)?;
    let language = normalize_language(language)?;
    let protection = protection_analysis::analyze_session(storage, session_id)?;
    let harness = signature_adapter::build_signature_harness(storage, session_id, "auto")?;
    let report = match report_id {
        Some(report_id) => {
            let report = storage.get_analysis_report(report_id)?;
            if report.session_id != session_id {
                return Err("分析报告不属于当前会话".to_string());
            }
            Some(report)
        }
        None => storage.latest_analysis_report(session_id)?,
    };

    let provider_candidates = protection
        .get("providerCandidates")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let protocol_schemas = protection
        .get("protocolSchemas")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let evidence_discipline = protection
        .get("evidenceDiscipline")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let mut evidence_gaps = harness.evidence_gaps.clone();
    if let Some(gaps) = evidence_discipline
        .get("notCapturedOrInsufficient")
        .and_then(Value::as_array)
    {
        for gap in gaps.iter().filter_map(Value::as_str) {
            if !evidence_gaps.iter().any(|item| item == gap) {
                evidence_gaps.push(gap.to_string());
            }
        }
    }

    let report_markdown = report
        .as_ref()
        .map(|item| item.content.clone())
        .unwrap_or_else(|| {
            "# ShowNet 分析报告\n\n本会话尚无 AI 分析报告。重播包基于确定性防护聚合、Hook 与代码片段做算法还原。\n"
                .to_string()
        });
    let report_id = report.as_ref().map(|item| item.id.clone());

    let hooks = storage.list_browser_hooks(session_id, Some(2_000))?;
    let mut snippets = Vec::new();
    let requests = storage.list_requests(session_id, Some(10_000), Some(0))?;
    for request in requests
        .iter()
        .filter(|request| request.crypto_snippet_count > 0)
        .take(24)
    {
        for snippet in storage.get_crypto_snippets(&request.id)? {
            snippets.push((request.order, snippet));
        }
    }
    let matched_requests = requests
        .iter()
        .filter(|request| {
            harness
                .matched_requests
                .iter()
                .any(|matched| matched.request_id == request.id)
        })
        .cloned()
        .collect::<Vec<_>>();

    let reconstruction = algorithm_reconstruction::reconstruct(
        &report_markdown,
        &harness,
        &protocol_schemas,
        &provider_candidates,
        &hooks,
        &snippets,
        &matched_requests,
    );
    let reconstruction_value =
        serde_json::to_value(&reconstruction).map_err(|error| error.to_string())?;

    for note in &reconstruction.notes {
        if !evidence_gaps.iter().any(|gap| gap == note)
            && (note.contains("VMP") || note.contains("不足") || note.contains("incomplete"))
        {
            evidence_gaps.push(note.clone());
        }
    }
    if reconstruction.vmp_or_custom_vm {
        evidence_gaps.push(
            "VMP/custom-VM markers present: full static algorithm dump is not claimed; use hybrid/trace-driven steps."
                .into(),
        );
    }
    evidence_gaps = complete_evidence_gaps(
        &evidence_gaps,
        &reconstruction,
        &language,
        &harness.dynamic_fields,
    );

    let (files, verification_manifest) = build_files(
        session_id,
        &language,
        &harness,
        &provider_candidates,
        &protocol_schemas,
        &evidence_discipline,
        &evidence_gaps,
        &report_markdown,
        &reconstruction,
    )?;

    let package_hash = package_hash(session_id, &language, &harness.evidence_hash, &files);
    let validation_checklist = validation_checklist(
        &harness,
        &protocol_schemas,
        &evidence_gaps,
        &reconstruction,
        &language,
    );
    let mut notes = notes(&harness, report_id.is_some(), &reconstruction);
    notes.extend(reconstruction.notes.iter().cloned());

    // Computed before the struct so `language` is still owned here rather than
    // read after it has moved into the field above it.
    let verified_steps = verified_agent_steps(&reconstruction, &language)
        .into_iter()
        .map(|(name, source, entry_point)| VerifiedStep {
            name: name.to_string(),
            source: source.to_string(),
            entry_point: entry_point.to_string(),
        })
        .collect::<Vec<_>>();
    let unverified_steps = unverified_algorithm_step_names(&reconstruction, &language)
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let crypto_verified =
        crypto_verified_for_package(&reconstruction, &language, &harness.dynamic_fields);

    Ok(AlgorithmReplayPackage {
        session_id: session_id.to_string(),
        language,
        adapter_id: harness.adapter_id,
        vendor: harness.vendor,
        confidence: harness.confidence,
        evidence_hash: harness.evidence_hash,
        package_hash,
        report_available: report_id.is_some(),
        report_id,
        reconstruction_mode: reconstruction.reconstruction_mode.clone(),
        reconstruction_confidence: reconstruction.confidence.clone(),
        verified_steps,
        unverified_steps,
        can_emit_runnable_crypto: reconstruction.can_emit_runnable_crypto,
        crypto_verified,
        provider_candidates,
        protocol_schemas,
        algorithm_reconstruction: reconstruction_value,
        required_inputs: harness.required_inputs,
        evidence_gaps,
        validation_checklist,
        verification_manifest,
        files,
        notes,
    })
}

pub fn export_algorithm_replay(
    storage: &Storage,
    session_id: &str,
    language: &str,
    output_dir: Option<&Path>,
) -> Result<AlgorithmReplayExportResult, String> {
    export_algorithm_replay_for_report(storage, session_id, language, None, output_dir)
}

pub fn export_algorithm_replay_for_report(
    storage: &Storage,
    session_id: &str,
    language: &str,
    report_id: Option<&str>,
    output_dir: Option<&Path>,
) -> Result<AlgorithmReplayExportResult, String> {
    let package = build_algorithm_replay_for_report(storage, session_id, language, report_id)?;
    let directory = match output_dir {
        // Parent chosen by the user (UI folder picker); nest a unique package folder inside.
        Some(path) => package_subdirectory(path, session_id, &package.language),
        None => default_export_directory(storage, session_id, &package.language)?,
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

    // Sidecar index for tooling. It is created after the package and therefore
    // intentionally sits outside VERIFICATION_MANIFEST.json's file digests.
    let index = json!({
        "sessionId": package.session_id,
        "language": package.language,
        "adapterId": package.adapter_id,
        "vendor": package.vendor,
        "evidenceHash": package.evidence_hash,
        "packageHash": package.package_hash,
        "gateVerdict": package.verification_manifest.gate.verdict,
        "files": package.files.iter().map(|file| {
            json!({
                "name": file.name,
                "role": file.role,
                "bytes": file.bytes,
            })
        }).collect::<Vec<_>>(),
        "exportedAtUnixMs": now_ms(),
    });
    let index_path = directory.join("export-index.json");
    let index_text = serde_json::to_string_pretty(&index).map_err(|error| error.to_string())?;
    std::fs::write(&index_path, index_text.as_bytes())
        .map_err(|error| format!("写入 export-index.json 失败: {error}"))?;
    bytes_written += index_text.len();
    written.push(index_path.to_string_lossy().to_string());

    Ok(AlgorithmReplayExportResult {
        session_id: package.session_id,
        language: package.language,
        directory: directory.to_string_lossy().to_string(),
        files: written,
        package_hash: package.package_hash,
        gate_verdict: package.verification_manifest.gate.verdict,
        bytes_written,
    })
}

fn package_subdirectory(parent: &Path, session_id: &str, language: &str) -> PathBuf {
    let stamp = now_ms();
    let nonce = uuid::Uuid::new_v4().simple();
    let safe_session = session_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    parent.join(format!(
        "shownet-algorithm-replay-{safe_session}-{language}-{stamp}-{nonce}"
    ))
}

fn default_export_directory(
    storage: &Storage,
    session_id: &str,
    language: &str,
) -> Result<PathBuf, String> {
    // Headless / MCP fallback only — UI always passes an explicit output_dir.
    Ok(package_subdirectory(
        &storage
            .data_directory()?
            .join("exports")
            .join("algorithm-replay"),
        session_id,
        language,
    ))
}

fn build_files(
    session_id: &str,
    language: &str,
    harness: &SignatureAdapterHarness,
    provider_candidates: &Value,
    protocol_schemas: &Value,
    evidence_discipline: &Value,
    evidence_gaps: &[String],
    report_markdown: &str,
    reconstruction: &AlgorithmReconstruction,
) -> Result<(Vec<ReplayFile>, ArtifactVerificationManifest), String> {
    let evidence_gaps = complete_evidence_gaps(
        evidence_gaps,
        reconstruction,
        language,
        &harness.dynamic_fields,
    );
    let reconstruction_json =
        serde_json::to_value(reconstruction).map_err(|error| error.to_string())?;
    let manifest = json!({
        "sessionId": session_id,
        "adapterId": harness.adapter_id,
        "adapterVersion": harness.adapter_version,
        "vendor": harness.vendor,
        "confidence": harness.confidence,
        "evidenceHash": harness.evidence_hash,
        "language": language,
        "requiredInputs": harness.required_inputs,
        "dynamicFields": harness.dynamic_fields,
        "cookieNames": harness.cookie_names,
        "cryptoAlgorithms": harness.crypto_algorithms,
        "fingerprintDependencies": harness.fingerprint_dependencies,
        "matchedRequests": harness.matched_requests,
        "providerCandidates": provider_candidates,
        "protocolSchemas": protocol_schemas,
        "algorithmReconstruction": reconstruction_json,
        "evidenceGaps": &evidence_gaps,
        "evidenceDiscipline": evidence_discipline,
    });
    let manifest_pretty =
        serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?;
    let schema_pretty =
        serde_json::to_string_pretty(protocol_schemas).map_err(|error| error.to_string())?;
    let providers_pretty =
        serde_json::to_string_pretty(provider_candidates).map_err(|error| error.to_string())?;
    let reconstruction_pretty =
        serde_json::to_string_pretty(&reconstruction_json).map_err(|error| error.to_string())?;
    let reconstruction_md =
        algorithm_reconstruction::render_reconstruction_markdown(reconstruction);
    // Shipped as its own file rather than buried in ALGORITHM_SPEC.json: this is
    // the answer to "is this code right", and the operator should not have to
    // find it inside a document that describes what the code is supposed to do.
    let language_reports = reconstruction
        .verification
        .iter()
        .filter(|report| report.language.eq_ignore_ascii_case(language))
        .collect::<Vec<_>>();
    let language_crypto_verified =
        crypto_verified_for_package(reconstruction, language, &harness.dynamic_fields);
    let verification_pretty = serde_json::to_string_pretty(&json!({
        "language": language,
        "cryptoVerified": language_crypto_verified,
        "claimBasis": if language_crypto_verified {
            format!("every emitted {language} agent step reproduced values recorded in this capture, and no pipeline step was withheld")
        } else if language_reports.is_empty() {
            format!("no {language} candidate implementation was supplied, so nothing was executed and no executable algorithm claim is made")
        } else {
            format!("at least one {language} pipeline step was not verified and emitted — see runs[] and evidenceGaps")
        },
        "runs": language_reports,
        "note": format!("`canEmitRunnableCrypto` describes template availability. `cryptoVerified` is scoped to this {language} package and requires every emitted algorithm step to have reproduced captured values, with no withheld pipeline step."),
    }))
    .map_err(|error| error.to_string())?;

    let replay_name = replay_filename(language);
    let replay_code = render_replay_source(
        language,
        harness,
        protocol_schemas,
        &evidence_gaps,
        reconstruction,
    )?;
    let readme = render_readme(
        session_id,
        language,
        harness,
        &evidence_gaps,
        reconstruction,
    );
    let checklist = validation_checklist(
        harness,
        protocol_schemas,
        &evidence_gaps,
        reconstruction,
        language,
    )
    .join("\n- ");

    let mut files = vec![
        file(
            "ANALYSIS_REPORT.md",
            "analysis-report",
            None,
            report_markdown,
        ),
        file(
            "ALGORITHM_RECONSTRUCTION.md",
            "algorithm-reconstruction",
            None,
            &reconstruction_md,
        ),
        file(
            "ALGORITHM_SPEC.json",
            "algorithm-spec",
            None,
            &reconstruction_pretty,
        ),
        file(
            "VERIFICATION.json",
            "algorithm-verification",
            None,
            &verification_pretty,
        ),
        file(
            "PROTOCOL_SCHEMA.json",
            "protocol-schema",
            None,
            &schema_pretty,
        ),
        file(
            "PROVIDER_CANDIDATES.json",
            "provider-candidates",
            None,
            &providers_pretty,
        ),
        file("MANIFEST.json", "manifest", None, &manifest_pretty),
        file(
            "VALIDATION_CHECKLIST.md",
            "validation-checklist",
            None,
            &format!("# Validation checklist\n\n- {checklist}\n"),
        ),
        file("README.md", "readme", None, &readme),
        file(
            &replay_name,
            "algorithm-replay",
            Some(language.to_string()),
            &replay_code,
        ),
    ];

    if language == "go" {
        files.push(file(
            "replay_demo.go",
            "replay-demo",
            Some("go".into()),
            GO_REPLAY_DEMO,
        ));
    }

    // Compiled languages carry their agent code as separate compilation units
    // rather than spliced into the replay file — see `agent_step_files`.
    for (name, content) in agent_step_files(reconstruction, language) {
        files.push(file(&name, "agent-step", Some(language.into()), &content));
    }

    // Also keep the Node harness from signature_adapter for JS ecosystems.
    if matches!(language, "javascript" | "typescript") {
        files.push(file(
            "signature-adapter.mjs",
            "signature-adapter",
            Some("javascript".into()),
            &harness.code,
        ));
    }

    let mut evidence_identifiers = verification_manifest::evidence_identifiers_for_language(
        &reconstruction.verification,
        language,
    );
    evidence_identifiers.extend(
        harness
            .matched_requests
            .iter()
            .map(|request| format!("request:{}", request.request_id)),
    );
    let mut evidence_hashes =
        verification_manifest::evidence_hashes_for_language(&reconstruction.verification, language);
    evidence_hashes.push(harness.evidence_hash.clone());
    let verification_manifest = ArtifactVerificationManifest::build(ManifestInput {
        kind: "algorithm-replay".to_string(),
        session_id: session_id.to_string(),
        language: language.to_string(),
        evidence_identifiers,
        evidence_hashes,
        runtimes: verification_manifest::runtime_verifications_for_language(
            &reconstruction.verification,
            language,
        )?,
        generated_files: files
            .iter()
            .map(|file| GeneratedFileDigest::from_content(&file.name, &file.role, &file.content))
            .collect(),
        gaps: evidence_gaps,
        executable_verified_logic_emitted: !verified_agent_steps(reconstruction, language)
            .is_empty(),
        package_runtime_required: false,
        package_runtime_verified: false,
    });
    let manifest_pretty =
        serde_json::to_string_pretty(&verification_manifest).map_err(|error| error.to_string())?;
    files.push(file(
        "VERIFICATION_MANIFEST.json",
        "verification-manifest",
        None,
        &manifest_pretty,
    ));

    Ok((files, verification_manifest))
}

fn file(name: &str, role: &str, language: Option<String>, content: &str) -> ReplayFile {
    ReplayFile {
        name: name.to_string(),
        role: role.to_string(),
        language,
        bytes: content.len(),
        content: content.to_string(),
    }
}

fn replay_filename(language: &str) -> String {
    match language {
        "python" => "replay.py".into(),
        "javascript" => "replay.js".into(),
        "typescript" => "replay.ts".into(),
        "go" => "replay.go".into(),
        "java" => "Replay.java".into(),
        "csharp" => "Replay.cs".into(),
        other => format!("replay.{other}"),
    }
}

fn render_readme(
    session_id: &str,
    language: &str,
    harness: &SignatureAdapterHarness,
    evidence_gaps: &[String],
    reconstruction: &AlgorithmReconstruction,
) -> String {
    let gaps = if evidence_gaps.is_empty() {
        "- （无额外缺口记录）".to_string()
    } else {
        evidence_gaps
            .iter()
            .map(|gap| format!("- {gap}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let pipeline = reconstruction
        .pipeline
        .iter()
        .map(|step| format!("- `{}` [{}] {}", step.name, step.status, step.formula))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"# ShowNet Algorithm Replay Package

Session: `{session_id}`
Language: `{language}`
Adapter: `{adapter}` ({vendor})
Evidence hash: `{hash}`
Adapter confidence: `{confidence}`
Reconstruction mode: `{recon_mode}` (confidence `{recon_conf}`)
Verified executable steps emitted: `{verified_step_count}`

## Purpose

This package **restores algorithms from analysis evidence**, not blank stubs:

1. Read `ALGORITHM_RECONSTRUCTION.md` / `ALGORITHM_SPEC.json` for the pipeline.
2. Run `{replay}` which executes only agent-written steps verified against this capture in `{language}`.
3. Use `validate_against_capture()` to check field shapes against capture before authorized live tests.
4. For **VMP / custom VM / heavily mutated JS**, only hybrid/trace-driven steps are claimed — static full decompilation is not invented.

## Contents

| File | Role |
|------|------|
| `ANALYSIS_REPORT.md` | Latest AI analysis report |
| `ALGORITHM_RECONSTRUCTION.md` | Human-readable algorithm restore pipeline |
| `ALGORITHM_SPEC.json` | Machine-readable restore spec |
| `PROTOCOL_SCHEMA.json` | Deterministic protection protocol schemas |
| `PROVIDER_CANDIDATES.json` | Provider recognition |
| `MANIFEST.json` | Full evidence index |
| `VALIDATION_CHECKLIST.md` | Capture / target validation steps |
| `{replay}` | Language implementation of reconstructed algorithm |
| `export-index.json` | Written on disk export only |

## Restored pipeline

{pipeline}

## Required env (no secrets embedded in files)

{inputs}

## Evidence gaps

{gaps}

## Safety

- Secrets / tokens / AES keys are never embedded; use env vars listed above.
- A pipeline label such as `reconstructed` is descriptive, not a runtime pass. Only steps listed in `VERIFICATION.json` as verified for `{language}` are emitted as executable logic.
- VMP code requires Hook traces or authorized runtime capture — do not expect a pure static dump.
- Use only against systems you are authorized to test.

## Next steps

1. Set env secrets recovered offline (if any) — never commit them.
2. `python replay.py --validate-fixture capture-sample.json` (or language equivalent).
3. Compare generated headers/body keys to capture.
4. Authorized live call only after offline validation passes.
"#,
        session_id = session_id,
        language = language,
        adapter = harness.adapter_id,
        vendor = harness.vendor,
        hash = harness.evidence_hash,
        confidence = harness.confidence,
        recon_mode = reconstruction.reconstruction_mode,
        recon_conf = reconstruction.confidence,
        verified_step_count = verified_agent_steps(reconstruction, language).len(),
        replay = replay_filename(language),
        pipeline = if pipeline.is_empty() {
            "- (empty)".to_string()
        } else {
            pipeline
        },
        inputs = {
            let mut items = reconstruction.required_env.clone();
            for item in &harness.required_inputs {
                if !items.iter().any(|env| env == item) {
                    items.push(item.clone());
                }
            }
            if items.is_empty() {
                "- （见 MANIFEST / ALGORITHM_SPEC）".to_string()
            } else {
                items
                    .iter()
                    .map(|item| format!("- `{item}`"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        },
        gaps = gaps,
    )
}

fn validation_checklist(
    harness: &SignatureAdapterHarness,
    protocol_schemas: &Value,
    evidence_gaps: &[String],
    reconstruction: &AlgorithmReconstruction,
    language: &str,
) -> Vec<String> {
    let mut items = vec![
        "Read ALGORITHM_SPEC.json and confirm each reconstructed step formula matches the report.".to_string(),
        "Run offline validate_against_capture against a complete captured sample; keep reusable source parameters separate from the fixture values.".to_string(),
        "Secrets only via env; never paste production tokens into source.".to_string(),
        "For VMP/custom VM steps, attach Hook I/O traces before claiming pass.".to_string(),
    ];
    if !verified_agent_steps(reconstruction, language).is_empty() {
        items.push(
            format!("Execute the emitted {language} agent steps and compare their outputs to the captured values.")
                .to_string(),
        );
    }
    if reconstruction.vmp_or_custom_vm {
        items.push(
            "VMP detected: do not expect 100% static restore; verify residual constants + hook intermediates."
                .to_string(),
        );
    }
    if !harness.cookie_names.is_empty() {
        items.push(format!(
            "Restore cookies if present in capture: {}.",
            harness.cookie_names.join(", ")
        ));
    }
    if protocol_schemas
        .pointer("/pow/challengeType")
        .and_then(Value::as_str)
        .is_some()
    {
        items.push(
            "PoW challengeType present: only run the observed solver type/difficulty.".to_string(),
        );
    }
    if protocol_schemas
        .pointer("/telemetry/sessionChain")
        .and_then(Value::as_bool)
        == Some(true)
    {
        items.push(
            "Telemetry session chain: null start → echo server value → next_interval.".to_string(),
        );
    }
    if !evidence_gaps.is_empty() {
        items.push(
            "Close evidenceGaps before claiming the replay passes target risk checks.".to_string(),
        );
    }
    items
}

fn notes(
    harness: &SignatureAdapterHarness,
    report_available: bool,
    reconstruction: &AlgorithmReconstruction,
) -> Vec<String> {
    let mut notes = vec![
        format!(
            "Algorithm reconstruction mode={} confidence={} runnable={}.",
            reconstruction.reconstruction_mode,
            reconstruction.confidence,
            reconstruction.can_emit_runnable_crypto
        ),
        format!(
            "Adapter {} / vendor {} / confidence {}.",
            harness.adapter_id, harness.vendor, harness.confidence
        ),
    ];
    if report_available {
        notes.push(
            "ANALYSIS_REPORT.md included; prefer embedded ```algorithm-spec``` when Agent emits it."
                .into(),
        );
    } else {
        notes.push(
            "No AI report yet — reconstruction synthesized from hooks/snippets/protocol only."
                .into(),
        );
    }
    notes
}

fn package_hash(
    session_id: &str,
    language: &str,
    evidence_hash: &str,
    files: &[ReplayFile],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"shownet-algorithm-replay-package-v1\0");
    hash_framed(&mut hasher, session_id.as_bytes());
    hash_framed(&mut hasher, language.as_bytes());
    hash_framed(&mut hasher, evidence_hash.as_bytes());
    hasher.update((files.len() as u64).to_be_bytes());
    for file in files {
        hash_framed(&mut hasher, file.name.as_bytes());
        hash_framed(&mut hasher, file.role.as_bytes());
        match &file.language {
            Some(language) => {
                hasher.update([1]);
                hash_framed(&mut hasher, language.as_bytes());
            }
            None => hasher.update([0]),
        }
        hash_framed(&mut hasher, file.content.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn hash_framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0)
}

/// Emit the agent's own code for steps the built-in catalogue has no template
/// for — but only the ones that were executed against the capture and got the
/// right answer.
///
/// This is what makes the agent seam more than decoration: without it a step
/// named anything outside the fixed list degrades to a placeholder no matter how
/// good the reconstruction was. The verification gate is what makes it safe:
/// unreviewed model output is not run by the operator on the strength of the
/// model's own confidence, only on the strength of it having reproduced values
/// the site really returned.
fn strictly_verified_agent_steps<'a>(
    reconstruction: &'a AlgorithmReconstruction,
    language: &str,
) -> Vec<(&'a str, &'a str, &'a str)> {
    reconstruction
        .pipeline
        .iter()
        .filter_map(|step| {
            if step.status != "reconstructed"
                || reconstruction
                    .pipeline
                    .iter()
                    .filter(|candidate| candidate.id == step.id)
                    .count()
                    != 1
                || reconstruction
                    .pipeline
                    .iter()
                    .filter(|candidate| candidate.name == step.name)
                    .count()
                    != 1
            {
                return None;
            }

            let mut implementations = step
                .implementations
                .iter()
                .filter(|item| item.normalized_language() == language);
            let implementation = implementations.next()?;
            if implementations.next().is_some() {
                return None;
            }

            // A report currently identifies an implementation by step and
            // language. Requiring exactly one of each keeps that association
            // one-to-one; otherwise a passing sibling could license different
            // source from the same step.
            let mut reports = reconstruction.verification.iter().filter(|report| {
                report.step_id == step.id && report.language.eq_ignore_ascii_case(language)
            });
            let report = reports.next()?;
            if reports.next().is_some()
                || report.step_name != step.name
                || report.implementation_sha256 != implementation.sha256()
                || !report.is_verified()
            {
                return None;
            }

            Some((
                step.name.as_str(),
                implementation.source.as_str(),
                implementation.entry_point.as_str(),
            ))
        })
        .collect()
}

fn verified_agent_steps<'a>(
    reconstruction: &'a AlgorithmReconstruction,
    language: &str,
) -> Vec<(&'a str, &'a str, &'a str)> {
    let steps = strictly_verified_agent_steps(reconstruction, language);
    // Each compiled candidate was verified as its own compilation unit. Putting
    // multiple units that all declare Candidate/ComputeSignature into one
    // package changes that environment and can produce duplicate symbols. Keep
    // the package closed until those units can be isolated without rewriting
    // code that was already verified.
    if (matches!(language, "go" | "java" | "csharp") && steps.len() > 1)
        || steps
            .first()
            .is_some_and(|(_, source, _)| !generated_symbol_collisions(source, language).is_empty())
    {
        Vec::new()
    } else {
        steps
    }
}

fn generated_symbol_collisions(source: &str, language: &str) -> Vec<&'static str> {
    let reserved: &[&str] = match language {
        "go" => &[
            "Manifest",
            "ReplayContext",
            "loadManifest",
            "AgentStepInput",
            "ComputeDynamicFields",
            "BuildRequest",
            "getenv",
            "AgentSteps",
        ],
        "java" | "csharp" => &["Replay", "AgentSteps"],
        _ => &[],
    };
    reserved
        .iter()
        .copied()
        .filter(|name| contains_ascii_identifier(source, name))
        .collect()
}

fn contains_ascii_identifier(source: &str, identifier: &str) -> bool {
    source.match_indices(identifier).any(|(start, _)| {
        let before = source[..start].chars().next_back();
        let end = start + identifier.len();
        let after = source[end..].chars().next();
        !before.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
            && !after.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
    })
}

fn compiled_step_collision_gap(
    reconstruction: &AlgorithmReconstruction,
    language: &str,
) -> Option<String> {
    if !matches!(language, "go" | "java" | "csharp") {
        return None;
    }
    let steps = strictly_verified_agent_steps(reconstruction, language);
    if steps.len() > 1 {
        return Some(format!(
            "{} verified {language} algorithm steps reuse one compilation namespace; all were withheld to prevent candidate symbol collisions",
            steps.len()
        ));
    }
    let (_, source, _) = steps.first()?;
    let collisions = generated_symbol_collisions(source, language);
    (!collisions.is_empty()).then(|| {
        format!(
            "verified {language} candidate contains generated-package symbol(s) {}; it was withheld because the exported compilation unit would differ from the verified one",
            collisions.join(", ")
        )
    })
}

fn unverified_algorithm_step_gaps(
    reconstruction: &AlgorithmReconstruction,
    language: &str,
) -> Vec<String> {
    unverified_algorithm_steps(reconstruction, language)
        .into_iter()
        .map(|step| {
            format!(
                "algorithm step '{}' ({}) has no runtime-verified {} implementation and was not emitted",
                step.name, step.status, language
            )
        })
        .collect()
}

fn unverified_algorithm_step_names<'a>(
    reconstruction: &'a AlgorithmReconstruction,
    language: &str,
) -> Vec<&'a str> {
    unverified_algorithm_steps(reconstruction, language)
        .into_iter()
        .map(|step| step.name.as_str())
        .collect()
}

fn unverified_algorithm_steps<'a>(
    reconstruction: &'a AlgorithmReconstruction,
    language: &str,
) -> Vec<&'a algorithm_reconstruction::AlgorithmStep> {
    let verified_names = verified_agent_steps(reconstruction, language)
        .into_iter()
        .map(|(name, _, _)| name)
        .collect::<BTreeSet<_>>();
    reconstruction
        .pipeline
        .iter()
        .filter(|step| !verified_names.contains(step.name.as_str()))
        .collect()
}

fn dynamic_field_gaps(
    reconstruction: &AlgorithmReconstruction,
    language: &str,
    dynamic_fields: &[String],
) -> Vec<String> {
    let emitted_names = verified_agent_steps(reconstruction, language)
        .into_iter()
        .map(|(name, _, _)| name)
        .collect::<BTreeSet<_>>();
    dynamic_fields
        .iter()
        .filter(|field| !emitted_names.contains(field.as_str()))
        .map(|field| {
            format!(
                "dynamic field '{field}' has no emitted runtime-verified {language} step named exactly '{field}'"
            )
        })
        .collect()
}

fn complete_evidence_gaps(
    existing: &[String],
    reconstruction: &AlgorithmReconstruction,
    language: &str,
    dynamic_fields: &[String],
) -> Vec<String> {
    let mut gaps = existing.to_vec();
    let mut generated = unverified_algorithm_step_gaps(reconstruction, language);
    generated.extend(dynamic_field_gaps(reconstruction, language, dynamic_fields));
    if let Some(gap) = compiled_step_collision_gap(reconstruction, language) {
        generated.push(gap);
    }
    for gap in generated {
        if !gaps.iter().any(|item| item == &gap) {
            gaps.push(gap);
        }
    }
    gaps
}

fn crypto_verified_for_package(
    reconstruction: &AlgorithmReconstruction,
    language: &str,
    dynamic_fields: &[String],
) -> bool {
    !verified_agent_steps(reconstruction, language).is_empty()
        && unverified_algorithm_step_names(reconstruction, language).is_empty()
        && dynamic_field_gaps(reconstruction, language, dynamic_fields).is_empty()
}

/// Inline agent code for the interpreted languages, whose templates carry an
/// `{agent_algorithms}` slot. Compiled languages get their own files instead —
/// see `agent_step_files`.
fn render_agent_algorithms(reconstruction: &AlgorithmReconstruction, language: &str) -> String {
    let verified_steps = verified_agent_steps(reconstruction, language);
    match language {
        "python" => render_agent_algorithms_python(&verified_steps),
        "javascript" | "typescript" => render_agent_algorithms_js(&verified_steps, language),
        _ => String::new(),
    }
}

fn render_agent_algorithms_python(verified_steps: &[(&str, &str, &str)]) -> String {
    if verified_steps.is_empty() {
        return "# (no agent-written step passed verification against this capture)\n\
                AGENT_STEPS: Dict[str, Any] = {}\n"
            .to_string();
    }

    let mut out = String::from(concat!(
        "# --- Agent-reconstructed steps ------------------------------------------\n",
        "# Written by the analysis agent, then executed against values this capture\n",
        "# recorded. Only steps that reproduced those values exactly appear here.\n",
        "# See VERIFICATION.json for the cases each one passed.\n\n",
        "def _load_verified_agent_step(source, entry_point, label):\n",
        "    namespace = {\"__name__\": \"shownet_verified_candidate\"}\n",
        "    exec(compile(source, \"<shownet-verified-candidate>\", \"exec\"), namespace)\n",
        "    step = namespace.get(entry_point)\n",
        "    if not callable(step):\n",
        "        raise RuntimeError(f\"verified agent entry point is not callable: {label}.{entry_point}\")\n",
        "    return step\n\n",
    ));
    let mut registry = Vec::new();
    for (index, (name, source, entry_point)) in verified_steps.iter().enumerate() {
        let module_alias = format!("_agent_step_{index}");
        out.push_str(&format!("# step: {name}\n"));
        // The private dictionary and fixed module identity are the same ones
        // used by verification, while sibling steps remain isolated.
        out.push_str(&format!(
            "{module_alias} = _load_verified_agent_step({}, {}, {})\n\n",
            serde_json::to_string(source).unwrap_or_else(|_| "\"\"".into()),
            serde_json::to_string(entry_point).unwrap_or_else(|_| "\"\"".into()),
            serde_json::to_string(name).unwrap_or_else(|_| "\"\"".into()),
        ));
        registry.push(format!(
            "    {}: {module_alias},",
            serde_json::to_string(name).unwrap_or_else(|_| "\"\"".into())
        ));
    }
    out.push_str("AGENT_STEPS: Dict[str, Any] = {\n");
    out.push_str(&registry.join("\n"));
    out.push_str("\n}\n");
    out
}

/// Declared wherever the TypeScript package annotates AGENT_STEPS with it,
/// which is both the empty and the populated shape.
const AGENT_STEP_INPUT_TYPE: &str = "export type AgentStepInput = {\n\
                                     \x20 method: string;\n\
                                     \x20 host: string;\n\
                                     \x20 path: string;\n\
                                     \x20 query: string | null;\n\
                                     \x20 headers: Record<string, string>;\n\
                                     \x20 body: string | null;\n\
                                     };\n\n";

fn render_agent_algorithms_js(verified_steps: &[(&str, &str, &str)], language: &str) -> String {
    let typed = language == "typescript";
    let registry_type = if typed {
        ": Record<string, (request: AgentStepInput) => string>"
    } else {
        ""
    };
    if verified_steps.is_empty() {
        // The declaration below sits after this return, so the empty package
        // annotated AGENT_STEPS with a name it never declared and tsc rejected
        // replay.ts outright. Emitting no step is the ordinary outcome — most
        // captures verify none — so this was the common shape of the package,
        // not an edge case.
        let declaration = if typed { AGENT_STEP_INPUT_TYPE } else { "" };
        return format!(
            "{declaration}\
             // (no agent-written step passed verification against this capture)\n\
             export const AGENT_STEPS{registry_type} = {{}};\n"
        );
    }

    // Keep the exact source string that earned the verification report. Adding
    // indentation changes multiline template literals, so Node evaluates it in
    // an isolated VM context instead. One context per step also preserves the
    // same stateful, load-once lifecycle used by verification.
    let mut out = String::from(
        r#"// --- Agent-reconstructed steps ------------------------------------------
// Written by the analysis agent, then executed against values this capture
// recorded. Only steps that reproduced those values exactly appear here.
// See VERIFICATION.json for the cases each one passed.

import { createHash, createHmac } from "node:crypto";
import { createContext, runInContext } from "node:vm";

const shownet = {
  sha256Hex: (data) => createHash("sha256").update(String(data)).digest("hex"),
  md5Hex: (data) => createHash("md5").update(String(data)).digest("hex"),
  hmacSha256Hex: (key, message) =>
    createHmac("sha256", String(key)).update(String(message)).digest("hex"),
  base64Encode: (data) => Buffer.from(String(data), "utf8").toString("base64"),
};

"#,
    );
    if typed {
        out = out.replace(
            "const shownet = {",
            &format!("{AGENT_STEP_INPUT_TYPE}const shownet = {{"),
        );
        out.push_str(
            r#"function _loadVerifiedAgentStep(source: string, entryPoint: string, label: string): (request: AgentStepInput) => string {
  const context = createContext({ shownet });
  const step = runInContext(source + "\n;" + entryPoint, context, {
    timeout: 1_000,
    filename: `shownet-agent-${label}.js`,
  });
  if (typeof step !== "function") {
    throw new Error(`verified agent entry point is not callable: ${label}.${entryPoint}`);
  }
  Reflect.set(context, "__shownetEntry", step);
  return (request: AgentStepInput) => {
    Reflect.set(context, "__shownetRequest", request);
    try {
      return String(runInContext("__shownetEntry(__shownetRequest)", context, { timeout: 1_000 }));
    } finally {
      Reflect.deleteProperty(context, "__shownetRequest");
    }
  };
}

"#,
        );
    } else {
        out.push_str(
            r#"function _loadVerifiedAgentStep(source, entryPoint, label) {
  const context = createContext({ shownet });
  const step = runInContext(source + "\n;" + entryPoint, context, {
    timeout: 1_000,
    filename: `shownet-agent-${label}.js`,
  });
  if (typeof step !== "function") {
    throw new Error(`verified agent entry point is not callable: ${label}.${entryPoint}`);
  }
  Reflect.set(context, "__shownetEntry", step);
  return (request) => {
    Reflect.set(context, "__shownetRequest", request);
    try {
      return String(runInContext("__shownetEntry(__shownetRequest)", context, { timeout: 1_000 }));
    } finally {
      Reflect.deleteProperty(context, "__shownetRequest");
    }
  };
}

"#,
        );
    }

    let mut registry = Vec::new();
    for (index, (name, source, entry_point)) in verified_steps.iter().enumerate() {
        let alias = format!("_agentStep{index}");
        out.push_str(&format!("// step: {name}\n"));
        out.push_str(&format!(
            "const {alias} = _loadVerifiedAgentStep({}, {}, {});\n\n",
            serde_json::to_string(source).unwrap_or_else(|_| "\"\"".into()),
            serde_json::to_string(entry_point).unwrap_or_else(|_| "\"\"".into()),
            serde_json::to_string(name).unwrap_or_else(|_| "\"\"".into()),
        ));
        registry.push(format!(
            "  {}: {alias},",
            serde_json::to_string(name).unwrap_or_else(|_| "\"\"".into())
        ));
    }
    out.push_str(&format!("export const AGENT_STEPS{registry_type} = {{\n"));
    out.push_str(&registry.join("\n"));
    out.push_str("\n};\n");
    out
}

/// The Go replay demo entry point, kept in its own file.
///
/// `package main` allows exactly one `func main`, and the auto-crawler package
/// copies these replay files in beside its own client — which has one. Shipping
/// the demo separately lets the crawler simply leave it out instead of editing
/// generated source.
const GO_REPLAY_DEMO: &str = r#"package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	ctx := ReplayContext{
		Domain:    getenv("SHOWNET_DOMAIN", "example.com"),
		UserAgent: getenv("SHOWNET_UA", "ShowNet-Replay/1.0"),
	}
	req, err := BuildRequest(ctx)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(req)
}
"#;

/// Agent code for languages that compile: emitted as their own files.
///
/// Inlining is wrong here — Java allows one public class per file, and splicing
/// a Go candidate into another file would mean merging its imports by hand. The
/// candidate is verified as a standalone compilation unit, so shipping it as one
/// keeps the code that was checked byte-identical to the code that runs.
fn agent_step_files(
    reconstruction: &AlgorithmReconstruction,
    language: &str,
) -> Vec<(String, String)> {
    let steps = verified_agent_steps(reconstruction, language);
    match language {
        "go" => {
            let mut files = vec![
                ("shownet_request.go".into(), GO_REQUEST_TYPE.into()),
                ("agent_steps.go".into(), go_agent_steps(&steps)),
            ];
            // The candidate itself, verbatim: it was verified as a standalone
            // `package main` file and ships as one, so its imports stay intact.
            for (index, (_, source, _)) in steps.iter().enumerate() {
                files.push((format!("agent_candidate_{index}.go"), (*source).to_string()));
            }
            files
        }
        "java" => {
            let mut files = vec![("Request.java".into(), JAVA_REQUEST_TYPE.into())];
            files.push(("AgentSteps.java".into(), java_agent_registry(&steps)));
            for (_, source, _) in &steps {
                // Verification compiles this exact source as Candidate.java and
                // the package permits at most one Java candidate. Deriving a
                // path from source text lets a comment spoof the class name and
                // escape the export directory.
                files.push(("Candidate.java".into(), (*source).to_string()));
            }
            files
        }
        "csharp" => {
            let mut files = vec![("Request.cs".into(), CSHARP_REQUEST_TYPE.into())];
            files.push(("AgentSteps.cs".into(), csharp_agent_registry(&steps)));
            for (index, (_, source, _)) in steps.iter().enumerate() {
                files.push((format!("Candidate{index}.cs"), (*source).to_string()));
            }
            files
        }
        _ => Vec::new(),
    }
}

const GO_REQUEST_TYPE: &str = r#"package main

// Request is the shape every agent step was verified against. It must stay
// identical to the one ShowNet fed the step during verification: a field read
// here that verification never supplied means the step runs unchecked.
type Request struct {
	Method  string            `json:"method"`
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Query   string            `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}
"#;

const JAVA_REQUEST_TYPE: &str = r#"import java.util.Map;

/**
 * The shape every agent step was verified against. It must stay identical to
 * the one ShowNet fed the step during verification: a field read here that
 * verification never supplied means the step runs unchecked.
 */
public record Request(
    String method,
    String host,
    String path,
    String query,
    Map<String, String> headers,
    String body) {}
"#;

// Usings are declared rather than inherited: Replay.cs already declares its
// own, and these files are meant to be dropped into a project whose settings
// are not ours to assume. Without them the package builds only where
// ImplicitUsings is on — the template default, but not a guarantee.
const CSHARP_REQUEST_TYPE: &str = r#"using System.Collections.Generic;

namespace ShowNetReplay;

/// <summary>
/// The shape every agent step was verified against. It must stay identical to
/// the one ShowNet fed the step during verification: a field read here that
/// verification never supplied means the step runs unchecked.
/// </summary>
public sealed record Request(
    string Method,
    string Host,
    string Path,
    string? Query,
    Dictionary<string, string> Headers,
    string? Body);
"#;

// The five spaces that used to precede the second and third comment lines were
// Rust source indentation baked into the literal, and they reached the Go, Java
// and C# packages verbatim.
const AGENT_FILE_HEADER: &str = "// Written by the analysis agent, then compiled and run against values this\n// capture recorded. Only steps that reproduced those values appear here.\n// See VERIFICATION.json for the cases each one passed.\n";

fn go_agent_steps(steps: &[(&str, &str, &str)]) -> String {
    let mut out = format!("package main\n\n{AGENT_FILE_HEADER}\n");
    if steps.is_empty() {
        out.push_str("// (no agent-written step passed verification against this capture)\n");
        out.push_str("var AgentSteps = map[string]func(Request) string{}\n");
        return out;
    }
    out.push_str("var AgentSteps = map[string]func(Request) string{\n");
    for (name, _, entry_point) in steps {
        out.push_str(&format!("\t{name:?}: {entry_point},\n"));
    }
    out.push_str("}\n");
    out
}

fn java_agent_registry(steps: &[(&str, &str, &str)]) -> String {
    let mut out = format!(
        "import java.util.LinkedHashMap;\nimport java.util.Map;\nimport java.util.function.Function;\n\n{AGENT_FILE_HEADER}\npublic final class AgentSteps {{\n    private AgentSteps() {{}}\n\n    public static Map<String, Function<Request, String>> all() {{\n        Map<String, Function<Request, String>> steps = new LinkedHashMap<>();\n"
    );
    for (name, _, entry_point) in steps {
        out.push_str(&format!(
            "        steps.put({name:?}, request -> {{\n            try {{\n                return Candidate.{entry_point}(request);\n            }} catch (Exception exception) {{\n                throw new RuntimeException(exception);\n            }}\n        }});\n"
        ));
    }
    out.push_str("        return steps;\n    }\n}\n");
    out
}

fn csharp_agent_registry(steps: &[(&str, &str, &str)]) -> String {
    let mut out = format!(
        "using System;\nusing System.Collections.Generic;\n\nnamespace ShowNetReplay;\n\n{AGENT_FILE_HEADER}\npublic static class AgentSteps\n{{\n    public static IReadOnlyDictionary<string, Func<Request, string>> All {{ get; }} =\n        new Dictionary<string, Func<Request, string>>\n        {{\n"
    );
    for (name, _, entry_point) in steps {
        out.push_str(&format!(
            "            [{name:?}] = Candidate.{entry_point},\n"
        ));
    }
    out.push_str("        };\n}\n");
    out
}

fn render_replay_source(
    language: &str,
    harness: &SignatureAdapterHarness,
    protocol_schemas: &Value,
    evidence_gaps: &[String],
    reconstruction: &AlgorithmReconstruction,
) -> Result<String, String> {
    let endpoints = harness
        .matched_requests
        .iter()
        .take(12)
        .map(|request| {
            format!(
                "  - {} {} ({})",
                request.method, request.url, request.status
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    // Go, Java and C# embed this in `//` line comments, where an unprefixed
    // continuation line is a syntax error rather than prose. Found by compiling
    // the generated package — a text assertion cannot see it.
    let endpoints_line_comment = endpoints
        .lines()
        .map(|line| format!("//{line}"))
        .collect::<Vec<_>>()
        .join("\n");
    // Collapsed to one line each: these are interpolated into single-line
    // comments in three of the six templates, where an embedded newline ends the
    // comment and the rest becomes code.
    let one_line = |text: String| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let fields = one_line(harness.dynamic_fields.join(", "));
    let inputs = one_line(harness.required_inputs.join(", "));
    let gaps = one_line(evidence_gaps.join(" | "));
    // javac reads source in the platform charset unless told otherwise, so on a
    // Windows default (windows-1252) any non-ASCII in these comments is a hard
    // compile error — and the evidence gaps are written in Chinese. Escaping to
    // \uXXXX keeps the file pure ASCII on disk while javac and every IDE still
    // render the original text, so `javac *.java` works on any machine.
    let java_ascii = |text: &str| {
        text.chars()
            .flat_map(|ch| {
                if ch.is_ascii() {
                    vec![ch]
                } else {
                    format!("\\u{:04x}", ch as u32).chars().collect()
                }
            })
            .collect::<String>()
    };
    let java_fields = java_ascii(&fields);
    let java_inputs = java_ascii(&inputs);
    let java_gaps = java_ascii(&gaps);
    let java_endpoints = java_ascii(&endpoints_line_comment);
    let java_adapter = java_ascii(&harness.adapter_id);
    let java_vendor = java_ascii(&harness.vendor);
    let pow = protocol_schemas
        .pointer("/pow/challengeType")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let signal = protocol_schemas
        .pointer("/signals/identifier")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let java_pow = java_ascii(pow);
    let java_signal = java_ascii(signal);
    let adapter = &harness.adapter_id;
    let vendor = &harness.vendor;
    let hash = &harness.evidence_hash;
    let recon_mode = &reconstruction.reconstruction_mode;
    let vmp = reconstruction.vmp_or_custom_vm;
    let agent_algorithms = render_agent_algorithms(reconstruction, language);
    let py_bool = |value: bool| if value { "True" } else { "False" };
    let vmp_py = py_bool(vmp);
    let pipeline_summary = reconstruction
        .pipeline
        .iter()
        .map(|step| format!("{}:{}:{}", step.name, step.status, step.formula))
        .collect::<Vec<_>>()
        .join(" || ");

    let body = match language {
        "python" => format!(
            r##"#!/usr/bin/env python3
"""ShowNet reconstructed algorithm replay.

This is NOT an empty stub. Steps marked reconstructed are implemented from
session evidence / ALGORITHM_SPEC.json. Secrets stay in env vars.

Adapter: {adapter} ({vendor})
Evidence hash: {hash}
Reconstruction mode: {recon_mode}
PoW type (observed): {pow}
Signal identifier (observed): {signal}
VMP/custom VM: {vmp}

Matched endpoints:
{endpoints}

Dynamic fields: {fields}
Required inputs: {inputs}
Pipeline: {pipeline_summary}
Gaps: {gaps}
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore

@dataclass
class ReplayContext:
    domain: str
    user_agent: str
    existing_token: Optional[str] = None
    path: str = "/"
    request_time: Optional[str] = None
    nonce: Optional[str] = None
    client_machine_id: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


def agent_step_input(ctx: ReplayContext, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """The shape an agent step was verified against, rebuilt at run time.

    This must stay identical to the input ShowNet fed the step during
    verification. If the two drift, the step is being called with something it
    was never checked on and the verified badge on it means nothing.
    """
    # Freshly generated per-request values go where the capture had them — in
    # the headers — rather than as extra top-level keys. Adding keys here that
    # verification never supplied would let a step read a field at run time that
    # was absent when it was checked.
    headers = {{k.lower(): v for k, v in (ctx.extra.get("headers") or {{}}).items()}}
    for name, value in (
        ("x-request-time", ctx.request_time),
        ("x-request-nonce", ctx.nonce),
        ("x-client-machine-id", ctx.client_machine_id),
        ("user-agent", ctx.user_agent),
    ):
        if value and name not in headers:
            headers[name] = value

    return {{
        "method": ctx.extra.get("method", "POST"),
        "host": ctx.domain,
        "path": ctx.path,
        "query": ctx.extra.get("query"),
        "headers": headers,
        "body": ctx.extra.get("body"),
    }}


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_manifest(path: str = "MANIFEST.json") -> Dict[str, Any]:
    return load_json(path)


def load_algorithm_spec(path: str = "ALGORITHM_SPEC.json") -> Dict[str, Any]:
    if not os.path.exists(path):
        return {{}}
    return load_json(path)


VMP_HYBRID = {vmp_py}


{agent_algorithms}

def compute_dynamic_fields(ctx: ReplayContext, manifest: Dict[str, Any], spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute only agent steps verified against this capture in Python."""
    spec = spec or load_algorithm_spec()
    out: Dict[str, Any] = {{}}
    out["_reconstructionMode"] = spec.get("reconstructionMode") or "{recon_mode}"
    out["_vmpHybrid"] = bool(spec.get("vmpOrCustomVm") or VMP_HYBRID)

    step_input = agent_step_input(ctx, manifest)
    for name, step in AGENT_STEPS.items():
        out[name] = step(step_input)
    out["_agentVerifiedSteps"] = sorted(AGENT_STEPS)

    for name in manifest.get("dynamicFields") or []:
        if name not in out and name in ctx.extra:
            out[name] = ctx.extra[name]
    unresolved = [name for name in manifest.get("dynamicFields") or [] if name not in out]
    if unresolved:
        raise RuntimeError(
            "no verified reconstruction for: " + ", ".join(unresolved) + ". "
            "Supply a Python implementation in the analysis report's algorithm-spec block "
            "or provide the value from authorized capture evidence."
        )
    return out


def build_request(ctx: ReplayContext, manifest_path: str = "MANIFEST.json") -> Dict[str, Any]:
    manifest = load_manifest(manifest_path)
    spec = load_algorithm_spec()
    dynamic = compute_dynamic_fields(ctx, manifest, spec)
    endpoint = (manifest.get("matchedRequests") or [None])[0]
    if not endpoint:
        raise RuntimeError("No matched endpoint in manifest")
    headers = {{
        "user-agent": ctx.user_agent,
        "content-type": "application/json",
    }}
    for key in ("X-Signature", "X-Request-Time", "X-Request-Nonce", "X-Client-Machine-ID", "X-Aws-Waf-Token"):
        if key in dynamic:
            headers[key] = str(dynamic[key])
        lower = key.lower()
        if lower in dynamic:
            headers[key] = str(dynamic[lower])
    body: Dict[str, Any] = {{
        "domain": ctx.domain,
        "existing_token": ctx.existing_token,
    }}
    if "solution" in dynamic:
        body["solution"] = dynamic["solution"]
    if "telemetry" in dynamic:
        body = dynamic["telemetry"]
    if "signals_encrypted" in dynamic:
        body.setdefault("signals", [{{
            "name": os.environ.get("SHOWNET_SIGNAL_NAME", "{signal}"),
            "value": {{"Present": dynamic["signals_encrypted"]}},
        }}])
        body["checksum"] = dynamic.get("signals_checksum")
    return {{
        "url": endpoint.get("url"),
        "method": endpoint.get("method"),
        "headers": headers,
        "json": body,
        "dynamic": dynamic,
        "meta": {{
            "adapterId": manifest.get("adapterId"),
            "evidenceHash": manifest.get("evidenceHash"),
            "reconstructionMode": spec.get("reconstructionMode"),
            "canEmitRunnableCrypto": spec.get("canEmitRunnableCrypto"),
        }},
    }}


def validate_against_capture(request: Dict[str, Any], fixture_path: str) -> Dict[str, Any]:
    """Offline structural validation against a complete capture sample JSON.

    Expected fixture example:
    {{"requiredHeaderNames": ["X-Signature"], "requiredBodyKeys": ["domain"], "signatureHexLen": 64}}
    """
    fixture = load_json(fixture_path)
    headers = {{k.lower(): v for k, v in (request.get("headers") or {{}}).items()}}
    body = request.get("json") or {{}}
    missing_headers = []
    for name in fixture.get("requiredHeaderNames") or []:
        if name.lower() not in headers:
            missing_headers.append(name)
    missing_body = []
    for key in fixture.get("requiredBodyKeys") or []:
        if key not in body:
            missing_body.append(key)
    sig = headers.get("x-signature") or ""
    sig_len_ok = True
    if "signatureHexLen" in fixture:
        sig_len_ok = bool(re.fullmatch(r"[0-9a-fA-F]+", sig or "")) and len(sig) == int(fixture["signatureHexLen"])
    ok = not missing_headers and not missing_body and sig_len_ok
    return {{
        "ok": ok,
        "missingHeaders": missing_headers,
        "missingBodyKeys": missing_body,
        "signatureHexLenOk": sig_len_ok,
        "reconstructionMode": (request.get("meta") or {{}}).get("reconstructionMode"),
    }}


def main() -> None:
    parser = argparse.ArgumentParser(description="ShowNet reconstructed algorithm replay")
    parser.add_argument("--manifest", default="MANIFEST.json")
    parser.add_argument("--validate-fixture", default="", help="offline capture shape fixture JSON")
    parser.add_argument("--print-request", action="store_true", default=True)
    args = parser.parse_args()

    ctx = ReplayContext(
        domain=os.environ.get("SHOWNET_DOMAIN", "example.com"),
        user_agent=os.environ.get("SHOWNET_UA", "ShowNet-Replay/1.0"),
        existing_token=os.environ.get("SHOWNET_EXISTING_TOKEN"),
        path=os.environ.get("SHOWNET_PATH", "/"),
        client_machine_id=os.environ.get("SHOWNET_CLIENT_MACHINE_ID"),
    )
    request = build_request(ctx, args.manifest)
    if args.print_request:
        print(json.dumps(request, indent=2, ensure_ascii=False))
    if args.validate_fixture:
        result = validate_against_capture(request, args.validate_fixture)
        print(json.dumps({{"validation": result}}, indent=2, ensure_ascii=False))
        raise SystemExit(0 if result.get("ok") else 2)
    if httpx is None:
        print("# optional: pip install httpx  # for live authorized tests")
    # Live send intentionally disabled by default.
    # with httpx.Client(http2=True, timeout=30.0) as client:
    #     resp = client.request(request["method"], request["url"], headers=request["headers"], json=request["json"])
    #     print(resp.status_code, resp.text[:500])


if __name__ == "__main__":
    main()
"##
        ),
        "javascript" => format!(
            r#"/**
 * ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
 * Adapter: {adapter} ({vendor})
 * Evidence hash: {hash}
 * PoW: {pow} | signal: {signal}
 *
 * Endpoints:
{endpoints}
 *
 * Dynamic fields: {fields}
 * Required inputs: {inputs}
 * Gaps: {gaps}
 */

import {{ readFileSync }} from "node:fs";

export function loadManifest(path = "MANIFEST.json") {{
  return JSON.parse(readFileSync(path, "utf8"));
}}

{agent_algorithms}

/**
 * Rebuild the request as the signer saw it. Must stay identical to the shape
 * each agent step was verified against — a field read here that verification
 * never supplied means the step is running unchecked.
 */
export function agentStepInput(context, manifest) {{
  const headers = {{}};
  for (const [name, value] of Object.entries(context.headers ?? {{}})) {{
    headers[String(name).toLowerCase()] = value;
  }}
  for (const [name, value] of [
    ["x-request-time", context.requestTime],
    ["x-request-nonce", context.nonce],
    ["x-client-machine-id", context.clientMachineId],
    ["user-agent", context.userAgent],
  ]) {{
    if (value && !(name in headers)) headers[name] = value;
  }}
  const endpoint = (manifest.matchedRequests ?? [])[0] ?? {{}};
  const url = endpoint.url ? new URL(endpoint.url) : null;
  return {{
    method: endpoint.method ?? "POST",
    host: context.domain ?? url?.hostname ?? "",
    path: url?.pathname ?? context.path ?? "/",
    query: url?.search ? url.search.slice(1) : null,
    headers,
    body: context.body ?? null,
  }};
}}

/**
 * Runs the agent steps this capture verified. Any dynamic field with no
 * verified step behind it is reported, not guessed: a plausible wrong value
 * fails at the site with no clue why, while a named gap points straight at the
 * step still to reconstruct. Read secrets from process.env only.
 */
export async function computeDynamicFields(context, manifest) {{
  const out = {{}};
  const input = agentStepInput(context, manifest);
  for (const [name, step] of Object.entries(AGENT_STEPS)) {{
    out[name] = step(input);
  }}
  out._agentVerifiedSteps = Object.keys(AGENT_STEPS).sort();

  const unresolved = (manifest.dynamicFields ?? []).filter((name) => !(name in out));
  if (unresolved.length) {{
    throw new Error(
      `no verified reconstruction for: ${{unresolved.join(", ")}}. ` +
        "Supply an implementation for these steps in the analysis report's " +
        "algorithm-spec block, or fill them from authorized capture evidence.",
    );
  }}
  return out;
}}

export async function buildRequest(context, compute = computeDynamicFields) {{
  const manifest = loadManifest(context.manifestPath ?? "MANIFEST.json");
  const dynamicFields = await compute(context, manifest);
  for (const name of manifest.dynamicFields ?? []) {{
    if (!(name in dynamicFields)) {{
      throw new Error(`dynamic field missing: ${{name}}`);
    }}
  }}
  const endpoint = (manifest.matchedRequests ?? [])[0];
  if (!endpoint) throw new Error("No matched endpoint in manifest");
  return {{
    url: endpoint.url,
    method: endpoint.method,
    headers: {{
      "user-agent": context.userAgent ?? "ShowNet-Replay/1.0",
      "content-type": "application/json",
    }},
    body: JSON.stringify({{
      domain: context.domain,
      existing_token: context.existingToken ?? null,
      ...dynamicFields,
    }}),
    meta: {{
      adapterId: manifest.adapterId,
      evidenceHash: manifest.evidenceHash,
    }},
  }};
}}

// Example (offline):
// const request = await buildRequest({{ domain: process.env.SHOWNET_DOMAIN }});
// console.log(request);
"#
        ),
        "typescript" => format!(
            r#"/**
 * ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
 * Adapter: {adapter} ({vendor}) | hash: {hash}
 * PoW: {pow} | signal: {signal}
 *
 * Endpoints:
{endpoints}
 */

import {{ readFileSync }} from "node:fs";

export type Manifest = {{
  adapterId: string;
  evidenceHash: string;
  dynamicFields: string[];
  requiredInputs: string[];
  matchedRequests: Array<{{ url: string; method: string; status: number }}>;
}};

export type ReplayContext = {{
  domain: string;
  userAgent?: string;
  existingToken?: string;
  manifestPath?: string;
  [key: string]: unknown;
}};

export function loadManifest(path = "MANIFEST.json"): Manifest {{
  return JSON.parse(readFileSync(path, "utf8")) as Manifest;
}}

{agent_algorithms}

/**
 * Rebuild the request as the signer saw it. Must stay identical to the shape
 * each agent step was verified against — a field read here that verification
 * never supplied means the step is running unchecked.
 */
export function agentStepInput(context: ReplayContext, manifest: Manifest): AgentStepInput {{
  const headers: Record<string, string> = {{}};
  for (const [name, value] of Object.entries((context.headers as Record<string, string>) ?? {{}})) {{
    headers[String(name).toLowerCase()] = String(value);
  }}
  for (const [name, value] of [
    ["x-request-time", context.requestTime],
    ["x-request-nonce", context.nonce],
    ["x-client-machine-id", context.clientMachineId],
    ["user-agent", context.userAgent],
  ] as Array<[string, unknown]>) {{
    if (value && !(name in headers)) headers[name] = String(value);
  }}
  const endpoint = (manifest.matchedRequests ?? [])[0];
  const url = endpoint?.url ? new URL(endpoint.url) : null;
  return {{
    method: endpoint?.method ?? "POST",
    host: context.domain ?? url?.hostname ?? "",
    path: url?.pathname ?? "/",
    query: url?.search ? url.search.slice(1) : null,
    headers,
    body: (context.body as string | null) ?? null,
  }};
}}

/**
 * Runs the agent steps this capture verified. Any dynamic field with no
 * verified step behind it is reported, not guessed. Read secrets from
 * process.env only.
 */
export async function computeDynamicFields(
  context: ReplayContext,
  manifest: Manifest,
): Promise<Record<string, unknown>> {{
  const out: Record<string, unknown> = {{}};
  const input = agentStepInput(context, manifest);
  for (const [name, step] of Object.entries(AGENT_STEPS)) {{
    out[name] = step(input);
  }}
  out._agentVerifiedSteps = Object.keys(AGENT_STEPS).sort();

  const unresolved = (manifest.dynamicFields ?? []).filter((name) => !(name in out));
  if (unresolved.length) {{
    throw new Error(
      `no verified reconstruction for: ${{unresolved.join(", ")}}. ` +
        "Supply an implementation for these steps in the analysis report's " +
        "algorithm-spec block, or fill them from authorized capture evidence.",
    );
  }}
  return out;
}}

export async function buildRequest(
  context: ReplayContext,
  compute: typeof computeDynamicFields = computeDynamicFields,
) {{
  const manifest = loadManifest(context.manifestPath ?? "MANIFEST.json");
  const dynamicFields = await compute(context, manifest);
  for (const name of manifest.dynamicFields ?? []) {{
    if (!(name in dynamicFields)) {{
      throw new Error(`dynamic field missing: ${{name}}`);
    }}
  }}
  const endpoint = (manifest.matchedRequests ?? [])[0];
  if (!endpoint) throw new Error("No matched endpoint in manifest");
  return {{
    url: endpoint.url,
    method: endpoint.method,
    headers: {{
      "user-agent": context.userAgent ?? "ShowNet-Replay/1.0",
      "content-type": "application/json",
    }},
    body: JSON.stringify({{
      domain: context.domain,
      existing_token: context.existingToken ?? null,
      ...dynamicFields,
    }}),
    meta: {{
      adapterId: manifest.adapterId,
      evidenceHash: manifest.evidenceHash,
      vendor: "{vendor}",
      gaps: "{gaps}",
      fields: "{fields}",
      inputs: "{inputs}",
    }},
  }};
}}
"#
        ),
        "go" => format!(
            r#"// ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
// Adapter: {adapter} ({vendor}) | hash: {hash}
// PoW: {pow} | signal: {signal}
//
// Endpoints:
{endpoints_line_comment}
//
// Dynamic fields: {fields}
// Required inputs: {inputs}
// Gaps: {gaps}

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

type Manifest struct {{
	AdapterID       string                   `json:"adapterId"`
	EvidenceHash    string                   `json:"evidenceHash"`
	DynamicFields   []string                 `json:"dynamicFields"`
	RequiredInputs  []string                 `json:"requiredInputs"`
	MatchedRequests []map[string]interface{{}} `json:"matchedRequests"`
}}

type ReplayContext struct {{
	Domain          string
	UserAgent       string
	ExistingToken   string
	Path            string
	Body            string
	RequestTime     string
	Nonce           string
	ClientMachineID string
	Headers         map[string]string
}}

func loadManifest(path string) (*Manifest, error) {{
	raw, err := os.ReadFile(path)
	if err != nil {{
		return nil, err
	}}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {{
		return nil, err
	}}
	return &manifest, nil
}}

// AgentStepInput rebuilds the request as each verified step was checked on.
// It must stay identical to the shape used during verification: a field read
// here that verification never supplied means the step runs unchecked.
func AgentStepInput(ctx ReplayContext, manifest *Manifest) Request {{
	headers := map[string]string{{}}
	for name, value := range ctx.Headers {{
		headers[strings.ToLower(name)] = value
	}}
	for _, pair := range [][2]string{{
		{{"x-request-time", ctx.RequestTime}},
		{{"x-request-nonce", ctx.Nonce}},
		{{"x-client-machine-id", ctx.ClientMachineID}},
		{{"user-agent", ctx.UserAgent}},
	}} {{
		if pair[1] != "" {{
			if _, seen := headers[pair[0]]; !seen {{
				headers[pair[0]] = pair[1]
			}}
		}}
	}}
	request := Request{{Method: "POST", Host: ctx.Domain, Path: ctx.Path, Headers: headers, Body: ctx.Body}}
	if len(manifest.MatchedRequests) > 0 {{
		endpoint := manifest.MatchedRequests[0]
		if method, ok := endpoint["method"].(string); ok {{
			request.Method = method
		}}
		if raw, ok := endpoint["url"].(string); ok {{
			if parsed, err := url.Parse(raw); err == nil {{
				request.Host = parsed.Hostname()
				request.Path = parsed.Path
				request.Query = parsed.RawQuery
			}}
		}}
	}}
	return request
}}

// ComputeDynamicFields runs the agent steps this capture verified. A dynamic
// field with no verified step behind it is reported, not guessed: a plausible
// wrong value fails at the site with no clue why, while a named gap points
// straight at the step still to reconstruct.
func ComputeDynamicFields(ctx ReplayContext, manifest *Manifest) (map[string]interface{{}}, error) {{
	out := map[string]interface{{}}{{}}
	input := AgentStepInput(ctx, manifest)
	verified := make([]string, 0, len(AgentSteps))
	for name, step := range AgentSteps {{
		out[name] = step(input)
		verified = append(verified, name)
	}}
	sort.Strings(verified)
	out["_agentVerifiedSteps"] = verified

	missing := []string{{}}
	for _, name := range manifest.DynamicFields {{
		if _, ok := out[name]; !ok {{
			missing = append(missing, name)
		}}
	}}
	if len(missing) > 0 {{
		return nil, fmt.Errorf("no verified reconstruction for: %s. Supply an implementation for these steps in the analysis report's algorithm-spec block", strings.Join(missing, ", "))
	}}
	return out, nil
}}

func BuildRequest(ctx ReplayContext) (map[string]interface{{}}, error) {{
	manifest, err := loadManifest("MANIFEST.json")
	if err != nil {{
		return nil, err
	}}
	dynamic, err := ComputeDynamicFields(ctx, manifest)
	if err != nil {{
		return nil, err
	}}
	for _, name := range manifest.DynamicFields {{
		if _, ok := dynamic[name]; !ok {{
			return nil, fmt.Errorf("dynamic field missing: %s", name)
		}}
	}}
	if len(manifest.MatchedRequests) == 0 {{
		return nil, fmt.Errorf("no matched endpoint")
	}}
	endpoint := manifest.MatchedRequests[0]
	return map[string]interface{{}}{{
		"url":    endpoint["url"],
		"method": endpoint["method"],
		"headers": map[string]string{{
			"user-agent":   ctx.UserAgent,
			"content-type": "application/json",
		}},
		"body": dynamic,
		"meta": map[string]string{{
			"adapterId":    manifest.AdapterID,
			"evidenceHash": manifest.EvidenceHash,
		}},
	}}, nil
}}

func getenv(key, fallback string) string {{
	if value := os.Getenv(key); value != "" {{
		return value
	}}
	return fallback
}}
"#
        ),
        "java" => format!(
            r#"// ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
// Adapter: {java_adapter} ({java_vendor}) | hash: {hash}
// PoW: {java_pow} | signal: {java_signal}
// Endpoints:
{java_endpoints}
// Fields: {java_fields} | Inputs: {java_inputs} | Gaps: {java_gaps}

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public final class Replay {{
  private Replay() {{}}

  public static String loadManifest(String path) throws Exception {{
    return Files.readString(Path.of(path));
  }}

  /**
   * Rebuild the request as each verified step was checked on. Must stay
   * identical to the shape used during verification: a field read here that
   * verification never supplied means the step runs unchecked.
   */
  public static Request agentStepInput(Map<String, Object> context) {{
    Map<String, String> headers = new java.util.LinkedHashMap<>();
    Object raw = context.get("headers");
    if (raw instanceof Map<?, ?> supplied) {{
      supplied.forEach((key, value) ->
          headers.put(String.valueOf(key).toLowerCase(java.util.Locale.ROOT), String.valueOf(value)));
    }}
    for (String[] pair : new String[][] {{
        {{"x-request-time", (String) context.get("requestTime")}},
        {{"x-request-nonce", (String) context.get("nonce")}},
        {{"x-client-machine-id", (String) context.get("clientMachineId")}},
        {{"user-agent", (String) context.get("userAgent")}},
    }}) {{
      if (pair[1] != null && !pair[1].isEmpty()) {{
        headers.putIfAbsent(pair[0], pair[1]);
      }}
    }}
    return new Request(
        (String) context.getOrDefault("method", "POST"),
        (String) context.getOrDefault("host", ""),
        (String) context.getOrDefault("path", "/"),
        (String) context.get("query"),
        headers,
        (String) context.get("body"));
  }}

  /**
   * Runs the agent steps this capture verified. A dynamic field with no verified
   * step behind it is reported, not guessed: a plausible wrong value fails at
   * the site with no clue why, while a named gap points at the step still to
   * reconstruct.
   */
  public static Map<String, Object> computeDynamicFields(Map<String, Object> context) {{
    Map<String, Object> out = new HashMap<>();
    Request input = agentStepInput(context);
    AgentSteps.all().forEach((name, step) -> out.put(name, step.apply(input)));
    out.put("_agentVerifiedSteps", AgentSteps.all().keySet().stream().sorted().toList());
    if (AgentSteps.all().isEmpty()) {{
      throw new UnsupportedOperationException(
          "no agent-written step passed verification against this capture; see VERIFICATION.json, then supply an implementation in the analysis report's algorithm-spec block");
    }}
    return out;
  }}

  public static Map<String, Object> buildRequest(Map<String, Object> context) throws Exception {{
    String manifest = loadManifest("MANIFEST.json");
    Map<String, Object> dynamic = computeDynamicFields(context);
    Map<String, Object> request = new HashMap<>();
    request.put("manifestChars", manifest.length());
    request.put("dynamic", dynamic);
    request.put("userAgent", context.getOrDefault("userAgent", "ShowNet-Replay/1.0"));
    request.put("note", "Parse MANIFEST.json with your JSON library and fill endpoint URL/method");
    return request;
  }}

  public static void main(String[] args) throws Exception {{
    Map<String, Object> context = new HashMap<>();
    context.put("domain", System.getenv().getOrDefault("SHOWNET_DOMAIN", "example.com"));
    try {{
      System.out.println(buildRequest(context));
    }} catch (UnsupportedOperationException error) {{
      System.err.println(error.getMessage());
    }}
  }}
}}
"#
        ),
        "csharp" => format!(
            r#"// ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
// Adapter: {adapter} ({vendor}) | hash: {hash}
// PoW: {pow} | signal: {signal}
// Endpoints:
{endpoints_line_comment}
// Fields: {fields} | Inputs: {inputs} | Gaps: {gaps}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

// Same namespace as Request.cs, AgentSteps.cs and the agent candidates, so the
// generated files form one compilation unit rather than three that cannot see
// each other.
namespace ShowNetReplay;

public static class Replay
{{
    public static JsonDocument LoadManifest(string path = "MANIFEST.json")
        => JsonDocument.Parse(File.ReadAllText(path));

    /// <summary>
    /// Rebuild the request as each verified step was checked on. Must stay
    /// identical to the shape used during verification: a field read here that
    /// verification never supplied means the step runs unchecked.
    /// </summary>
    public static Request AgentStepInput(Dictionary<string, object?> context)
    {{
        var headers = new Dictionary<string, string>();
        if (context.TryGetValue("headers", out var raw) && raw is Dictionary<string, string> supplied)
        {{
            foreach (var pair in supplied)
            {{
                headers[pair.Key.ToLowerInvariant()] = pair.Value;
            }}
        }}
        foreach (var (name, value) in new (string, object?)[]
                 {{
                     ("x-request-time", context.GetValueOrDefault("requestTime")),
                     ("x-request-nonce", context.GetValueOrDefault("nonce")),
                     ("x-client-machine-id", context.GetValueOrDefault("clientMachineId")),
                     ("user-agent", context.GetValueOrDefault("userAgent")),
                 }})
        {{
            if (value is string text && text.Length > 0 && !headers.ContainsKey(name))
            {{
                headers[name] = text;
            }}
        }}
        return new Request(
            context.GetValueOrDefault("method") as string ?? "POST",
            context.GetValueOrDefault("host") as string ?? string.Empty,
            context.GetValueOrDefault("path") as string ?? "/",
            context.GetValueOrDefault("query") as string,
            headers,
            context.GetValueOrDefault("body") as string);
    }}

    /// <summary>
    /// Runs the agent steps this capture verified. A dynamic field with no
    /// verified step behind it is reported, not guessed.
    /// </summary>
    public static Dictionary<string, object?> ComputeDynamicFields(
        Dictionary<string, object?> context,
        JsonDocument manifest)
    {{
        if (AgentSteps.All.Count == 0)
        {{
            throw new NotImplementedException(
                "no agent-written step passed verification against this capture; see VERIFICATION.json, then supply an implementation in the analysis report's algorithm-spec block");
        }}
        var input = AgentStepInput(context);
        var out_ = new Dictionary<string, object?>();
        foreach (var pair in AgentSteps.All)
        {{
            out_[pair.Key] = pair.Value(input);
        }}
        out_["_agentVerifiedSteps"] = AgentSteps.All.Keys.OrderBy(name => name).ToArray();
        return out_;
    }}

    public static Dictionary<string, object?> BuildRequest(Dictionary<string, object?> context)
    {{
        using var manifest = LoadManifest();
        var dynamic = ComputeDynamicFields(context, manifest);
        return new Dictionary<string, object?>
        {{
            ["dynamic"] = dynamic,
            ["adapterId"] = manifest.RootElement.GetProperty("adapterId").GetString(),
            ["evidenceHash"] = manifest.RootElement.GetProperty("evidenceHash").GetString(),
            ["userAgent"] = context.GetValueOrDefault("userAgent") ?? "ShowNet-Replay/1.0",
        }};
    }}

    public static void Main()
    {{
        var context = new Dictionary<string, object?>
        {{
            ["domain"] = Environment.GetEnvironmentVariable("SHOWNET_DOMAIN") ?? "example.com",
        }};
        try
        {{
            Console.WriteLine(JsonSerializer.Serialize(BuildRequest(context)));
        }}
        catch (NotImplementedException ex)
        {{
            Console.Error.WriteLine(ex.Message);
        }}
    }}
}}
"#
        ),
        other => return Err(format!("未实现的语言模板: {other}")),
    };

    // Ensure no accidental secret-like long tokens from harness code leak: we only embed field names.
    let lowered = body.to_ascii_lowercase();
    for banned in ["aws-waf-token=", "authorization: bearer", "api_key="] {
        if lowered.contains(banned) {
            return Err("replay template unexpectedly contained sensitive markers".to_string());
        }
    }
    let _ = fields;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CapturedRequestInput, HeaderEntry};
    use crate::storage::Storage;

    fn storage() -> Storage {
        Storage::in_memory().expect("memory storage")
    }

    fn base(session_id: &str, host: &str, path: &str) -> CapturedRequestInput {
        CapturedRequestInput {
            id: None,
            session_id: session_id.to_string(),
            source: "browser".into(),
            source_instance_id: Some("test".into()),
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
    fn builds_python_replay_package_from_aws_waf_session() {
        let storage = storage();
        let session = storage.create_session(Some("replay".into())).unwrap();
        let sid = session.id.clone();

        let mut script = base(
            &sid,
            "73472ccc2f21.edge.sdk.awswaf.com",
            "/73472ccc2f21/0416b5675b4f/challenge.js",
        );
        script.resource_type = "script".into();
        script.response_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: "application/javascript".into(),
        }];
        script.response_body = Some(
            r#"function a0_0x1(){var _0x1=["awswaf_session_storage","mp_verify"];}
crypto.subtle.encrypt({name:"AES-GCM",tagLength:128},k,d);
const difficulty=1; const t="awswaf";
"#
            .into(),
        );
        storage.store_request(script).unwrap();

        let mut verify = base(
            &sid,
            "73472ccc2f21.edge.sdk.awswaf.com",
            "/73472ccc2f21/0416b5675b4f/mp_verify",
        );
        verify.method = "POST".into();
        verify.request_body = Some(
            r#"{"challenge":{"input":"eyJ","hmac":"x","region":"ap-east-1"},"signals":[{"name":"Zoey"}],"checksum":"AA"}"#
                .into(),
        );
        verify.response_body =
            Some(r#"{"token":"2e1254cf-d58d-4c53-8afb-08be29b8d202:AAoA:xx"}"#.into());
        storage.store_request(verify).unwrap();

        let package = build_algorithm_replay(&storage, &sid, "python").unwrap();
        assert_eq!(package.language, "python");
        assert_eq!(package.adapter_id, "aws-waf-bot-control");
        assert!(package.files.iter().any(|file| file.name == "replay.py"));
        assert!(package
            .files
            .iter()
            .any(|file| file.name == "ANALYSIS_REPORT.md"));
        assert!(package
            .files
            .iter()
            .any(|file| file.name == "ALGORITHM_SPEC.json"));
        assert!(package
            .files
            .iter()
            .any(|file| file.name == "ALGORITHM_RECONSTRUCTION.md"));
        assert!(package
            .files
            .iter()
            .any(|file| file.name == "PROTOCOL_SCHEMA.json"));
        assert!(package
            .files
            .iter()
            .any(|file| file.name == "MANIFEST.json"));
        let replay = package
            .files
            .iter()
            .find(|file| file.role == "algorithm-replay")
            .unwrap();
        assert!(replay.content.contains("compute_dynamic_fields"));
        assert!(replay.content.contains("validate_against_capture"));
        assert!(replay.content.contains("AGENT_STEPS: Dict[str, Any] = {}"));
        assert!(!replay.content.contains("def hmac_sha256_hex"));
        assert!(!replay.content.contains("def solve_network_bandwidth"));
        assert!(!replay.content.contains("def encrypt_signals_aes_gcm"));
        assert!(!replay.content.contains("def telemetry_payload"));
        assert!(!replay.content.contains("<missing:"));
        assert!(package.evidence_gaps.iter().any(|gap| {
            gap.contains("has no runtime-verified python implementation")
                && gap.contains("was not emitted")
        }));
        assert!(!replay
            .content
            .contains("2e1254cf-d58d-4c53-8afb-08be29b8d202:AAoA:xx"));
        assert!(!package.reconstruction_mode.is_empty());
    }

    #[test]
    fn exports_package_to_disk_and_supports_language_aliases() {
        let storage = storage();
        let session = storage.create_session(Some("export".into())).unwrap();
        let sid = session.id.clone();
        let mut sensor = base(&sid, "www.example.com", "/_bm/sensor");
        sensor.method = "POST".into();
        sensor.request_body = Some(r#"{"sensor_data":"1"}"#.into());
        sensor.request_headers = vec![HeaderEntry {
            name: "cookie".into(),
            value: "_abck=1; bm_sz=2".into(),
        }];
        storage.store_request(sensor).unwrap();

        assert_eq!(normalize_language("py").unwrap(), "python");
        assert_eq!(normalize_language("ts").unwrap(), "typescript");

        let parent = std::env::temp_dir().join(format!("shownet-replay-test-{}", now_ms()));
        std::fs::create_dir_all(&parent).unwrap();
        let exported =
            export_algorithm_replay(&storage, &sid, "go", Some(parent.as_path())).unwrap();
        let second = export_algorithm_replay(&storage, &sid, "go", Some(parent.as_path())).unwrap();
        // UI picks a parent folder; package is nested under a unique subdir.
        let package_dir = Path::new(&exported.directory);
        assert!(package_dir.exists());
        assert!(package_dir.starts_with(&parent));
        assert_ne!(package_dir, parent.as_path());
        assert_ne!(
            exported.directory, second.directory,
            "back-to-back exports must not share or overwrite a package directory"
        );
        assert!(exported
            .files
            .iter()
            .any(|path| path.ends_with("replay.go")));
        assert!(exported
            .files
            .iter()
            .any(|path| path.ends_with("ANALYSIS_REPORT.md")));
        assert!(exported
            .files
            .iter()
            .any(|path| path.ends_with("export-index.json")));
        let replay = std::fs::read_to_string(package_dir.join("replay.go")).unwrap();
        assert!(replay.contains("ComputeDynamicFields"));
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    fn exports_the_selected_historical_report_and_rejects_cross_session_reports() {
        let storage = storage();
        let session = storage
            .create_session(Some("selected-report".into()))
            .unwrap();
        let sid = session.id.clone();
        let mut sensor = base(&sid, "www.example.com", "/_bm/sensor");
        sensor.method = "POST".into();
        sensor.request_body = Some(r#"{"sensor_data":"1"}"#.into());
        storage.store_request(sensor).unwrap();

        let older = storage
            .create_analysis_report(&sid, "crypto", 1, "test", "test-model")
            .unwrap();
        storage
            .finish_analysis_report(&older.id, "# SELECTED_OLDER_REPORT")
            .unwrap();
        let newer = storage
            .create_analysis_report(&sid, "crypto", 1, "test", "test-model")
            .unwrap();
        storage
            .finish_analysis_report(&newer.id, "# NEWER_REPORT")
            .unwrap();

        let parent = std::env::temp_dir().join(format!("shownet-selected-report-{}", now_ms()));
        std::fs::create_dir_all(&parent).unwrap();
        let exported = export_algorithm_replay_for_report(
            &storage,
            &sid,
            "python",
            Some(&older.id),
            Some(parent.as_path()),
        )
        .unwrap();
        let report =
            std::fs::read_to_string(Path::new(&exported.directory).join("ANALYSIS_REPORT.md"))
                .unwrap();
        assert!(report.contains("SELECTED_OLDER_REPORT"));
        assert!(!report.contains("NEWER_REPORT"));
        let _ = std::fs::remove_dir_all(parent);

        let other_session = storage.create_session(Some("other-report".into())).unwrap();
        let other_report = storage
            .create_analysis_report(&other_session.id, "crypto", 0, "test", "test-model")
            .unwrap();
        let error =
            build_algorithm_replay_for_report(&storage, &sid, "python", Some(&other_report.id))
                .unwrap_err();
        assert!(error.contains("不属于当前会话"));
    }

    #[test]
    fn rejects_unknown_language() {
        let err = normalize_language("brainfuck").unwrap_err();
        assert!(err.contains("不支持的重播语言"));
    }

    #[test]
    fn typescript_replay_declares_the_type_it_annotates() {
        // The package shipped `AGENT_STEPS: Record<string, (request:
        // AgentStepInput) => string>` while the declaration of AgentStepInput
        // lived past an early return taken whenever no agent step verified —
        // the ordinary outcome — so tsc rejected replay.ts with TS2304. Caught
        // by compiling the export, not by reading it: every other language in
        // the package built cleanly.
        let storage = storage();
        let session = storage.create_session(Some("ts-types".into())).unwrap();
        let sid = session.id.clone();
        let mut sensor = base(&sid, "www.example.com", "/_bm/sensor");
        sensor.method = "POST".into();
        sensor.request_body = Some(r#"{"sensor_data":"1"}"#.into());
        storage.store_request(sensor).unwrap();

        let package = build_algorithm_replay(&storage, &sid, "typescript").unwrap();
        let replay = package
            .files
            .iter()
            .find(|file| file.name == "replay.ts")
            .expect("typescript package must carry replay.ts");
        assert!(
            replay.content.contains("AgentStepInput"),
            "fixture no longer annotates with AgentStepInput, so it checks nothing"
        );
        assert_eq!(
            replay.content.matches("export type AgentStepInput").count(),
            1,
            "replay.ts must declare AgentStepInput exactly once, not zero or twice"
        );

        // The JavaScript package is untyped and must stay free of the annotation.
        let js = build_algorithm_replay(&storage, &sid, "javascript").unwrap();
        let js_replay = js
            .files
            .iter()
            .find(|file| file.name == "replay.js")
            .expect("javascript package must carry replay.js");
        assert!(
            !js_replay.content.contains("AgentStepInput"),
            "the untyped package picked up a TypeScript annotation"
        );
    }

    #[test]
    fn generated_packages_carry_their_own_imports_and_unindented_comments() {
        // Found by compiling the export rather than reading it. Request.cs and
        // AgentSteps.cs declared no usings at all while Replay.cs declared five,
        // so the package built only where ImplicitUsings is on — the template
        // default, but not something we get to assume about the project a user
        // drops these files into.
        for line in AGENT_FILE_HEADER.lines() {
            assert!(
                !line.starts_with(char::is_whitespace),
                "Rust source indentation reached the generated comment: {line:?}"
            );
        }

        let storage = storage();
        let session = storage.create_session(Some("imports".into())).unwrap();
        let sid = session.id.clone();
        let mut sensor = base(&sid, "www.example.com", "/_bm/sensor");
        sensor.method = "POST".into();
        sensor.request_body = Some(r#"{"sensor_data":"1"}"#.into());
        storage.store_request(sensor).unwrap();

        let package = build_algorithm_replay(&storage, &sid, "csharp").unwrap();
        let content = |name: &str| {
            package
                .files
                .iter()
                .find(|file| file.name == name)
                .unwrap_or_else(|| panic!("csharp package must carry {name}"))
                .content
                .clone()
        };
        // Each names the namespace it actually uses: Dictionary and
        // IReadOnlyDictionary come from one, Func from the other.
        assert!(content("Request.cs").contains("using System.Collections.Generic;"));
        assert!(content("AgentSteps.cs").contains("using System.Collections.Generic;"));
        assert!(content("AgentSteps.cs").contains("using System;"));
    }

    #[test]
    fn builds_every_supported_replay_language() {
        let storage = storage();
        let session = storage
            .create_session(Some("all-languages".into()))
            .unwrap();
        let sid = session.id.clone();
        let mut sensor = base(&sid, "www.example.com", "/_bm/sensor");
        sensor.method = "POST".into();
        sensor.request_body = Some(r#"{"sensor_data":"1"}"#.into());
        storage.store_request(sensor).unwrap();

        let expected = [
            ("python", "replay.py"),
            ("javascript", "replay.js"),
            ("typescript", "replay.ts"),
            ("go", "replay.go"),
            ("java", "Replay.java"),
            ("csharp", "Replay.cs"),
        ];
        assert_eq!(supported_languages().len(), expected.len());
        for (language, filename) in expected {
            let package = build_algorithm_replay(&storage, &sid, language).unwrap();
            assert_eq!(package.language, language);
            assert!(
                package.files.iter().any(|file| file.name == filename),
                "language={language} missing {filename}"
            );
        }
    }

    // --- Agent-written steps ------------------------------------------------

    fn reconstruction_with_agent_step(
        language: &str,
        source: &str,
        verdict: &str,
    ) -> AlgorithmReconstruction {
        use crate::algorithm_verification::{Implementation, VerificationReport};
        let implementation = Implementation {
            language: language.into(),
            source: source.into(),
            entry_point: "computeSignature".into(),
        };
        let step = crate::algorithm_reconstruction::AlgorithmStep {
            id: "1".into(),
            name: "vendor_custom_sign".into(),
            status: "reconstructed".into(),
            formula: "sha256(method + path)".into(),
            evidence: vec!["hook pair".into()],
            implementation_hint: "agent".into(),
            implementations: vec![implementation.clone()],
        };
        let mut report = VerificationReport::for_test(verdict);
        report.step_id = "1".into();
        report.step_name = "vendor_custom_sign".into();
        report.implementation_sha256 = implementation.sha256();
        report.language = language.into();
        report.attempted = usize::from(verdict != "unverifiable");
        report.passed = usize::from(verdict == "verified");
        report.failed = usize::from(verdict == "failed");
        AlgorithmReconstruction {
            reconstruction_mode: "pure_reconstructed".into(),
            confidence: "high".into(),
            algorithms: vec!["SHA-256".into()],
            pipeline: vec![step],
            vmp_or_custom_vm: false,
            vmp_indicators: vec![],
            hook_traces: vec![],
            snippet_algorithms: vec![],
            dynamic_fields: vec!["vendor_custom_sign".into()],
            required_env: vec![],
            test_field_shapes: vec![],
            report_spec_embedded: true,
            can_emit_runnable_crypto: true,
            verification: vec![report],
            crypto_verified: verdict == "verified",
            notes: vec![],
        }
    }

    const AGENT_PY: &str = "import hashlib\n\ndef computeSignature(request):\n    base = request[\"method\"] + request[\"path\"]\n    return hashlib.sha256(base.encode()).hexdigest()\n";

    fn replay_files_for_verdict(verdict: &str) -> (Vec<ReplayFile>, ArtifactVerificationManifest) {
        let reconstruction = reconstruction_with_agent_step("python", AGENT_PY, verdict);
        replay_files_for_reconstruction(&reconstruction)
    }

    fn replay_files_for_reconstruction(
        reconstruction: &AlgorithmReconstruction,
    ) -> (Vec<ReplayFile>, ArtifactVerificationManifest) {
        replay_files_for_reconstruction_with_fields(reconstruction, &["vendor_custom_sign"])
    }

    fn replay_files_for_reconstruction_with_fields(
        reconstruction: &AlgorithmReconstruction,
        dynamic_fields: &[&str],
    ) -> (Vec<ReplayFile>, ArtifactVerificationManifest) {
        let harness = crate::signature_adapter::SignatureAdapterHarness {
            adapter_id: "generic-dynamic-signature".into(),
            adapter_version: "1.0.0".into(),
            vendor: "Generic".into(),
            confidence: "high".into(),
            evidence_hash: "capture-evidence-sha256".into(),
            matched_requests: vec![],
            dynamic_fields: dynamic_fields.iter().map(|field| (*field).into()).collect(),
            cookie_names: vec![],
            hook_names: vec![],
            crypto_algorithms: vec!["SHA-256".into()],
            fingerprint_dependencies: vec![],
            required_inputs: vec![],
            evidence_gaps: vec![],
            language: "python".into(),
            code: String::new(),
        };
        build_files(
            "session-1",
            "python",
            &harness,
            &json!([]),
            &json!({}),
            &json!({}),
            &[],
            "# Analysis\n",
            reconstruction,
        )
        .expect("build replay files")
    }

    #[test]
    fn replay_package_gate_preserves_all_three_runtime_verdicts() {
        for (runtime_verdict, expected) in [
            ("verified", VerificationVerdict::Verified),
            ("failed", VerificationVerdict::Failed),
            ("unverifiable", VerificationVerdict::Unverifiable),
        ] {
            let (files, manifest) = replay_files_for_verdict(runtime_verdict);
            assert_eq!(manifest.gate.verdict, expected);

            let replay = files
                .iter()
                .find(|file| file.name == "replay.py")
                .expect("python replay file");
            assert_eq!(
                replay.content.contains("# step: vendor_custom_sign"),
                runtime_verdict == "verified",
                "{runtime_verdict} candidate emission disagrees with its package gate"
            );
        }
    }

    #[test]
    fn a_verified_step_name_must_cover_the_dynamic_field_exactly() {
        let reconstruction = reconstruction_with_agent_step("python", AGENT_PY, "verified");
        let (files, manifest) =
            replay_files_for_reconstruction_with_fields(&reconstruction, &["x-signature"]);

        assert_eq!(manifest.gate.verdict, VerificationVerdict::Unverifiable);
        assert!(manifest.gaps.iter().any(|gap| {
            gap.contains("dynamic field 'x-signature'")
                && gap.contains("named exactly 'x-signature'")
        }));
        let verification = files
            .iter()
            .find(|file| file.name == "VERIFICATION.json")
            .expect("verification file");
        let parsed: Value = serde_json::from_str(&verification.content).expect("verification JSON");
        assert_eq!(parsed["cryptoVerified"], json!(false));
    }

    #[test]
    fn duplicate_implementations_cannot_borrow_a_siblings_verification() {
        use crate::algorithm_verification::{Implementation, VerificationReport};

        let mut reconstruction = reconstruction_with_agent_step("python", AGENT_PY, "verified");
        let rejected = Implementation {
            language: "python".into(),
            source: "def computeSignature(request):\n    return 'wrong-source'\n".into(),
            entry_point: "computeSignature".into(),
        };
        reconstruction.pipeline[0]
            .implementations
            .insert(0, rejected.clone());
        let mut failed = VerificationReport::for_test("failed");
        failed.step_id = "1".into();
        failed.step_name = "vendor_custom_sign".into();
        failed.implementation_sha256 = rejected.sha256();
        failed.language = "python".into();
        failed.attempted = 1;
        failed.failed = 1;
        reconstruction.verification.insert(0, failed);

        assert!(verified_agent_steps(&reconstruction, "python").is_empty());
        let (files, manifest) = replay_files_for_reconstruction(&reconstruction);
        let replay = files
            .iter()
            .find(|file| file.name == "replay.py")
            .expect("python replay file");
        assert!(!replay.content.contains("wrong-source"));
        assert!(!replay.content.contains("import hashlib"));
        assert!(!manifest.gate.executable_verified_logic_emitted);
        assert_eq!(manifest.gate.verdict, VerificationVerdict::Failed);
    }

    #[test]
    fn a_verification_report_cannot_license_source_changed_after_the_run() {
        let mut reconstruction = reconstruction_with_agent_step("python", AGENT_PY, "verified");
        reconstruction.pipeline[0].implementations[0]
            .source
            .push_str("\n# changed after verification\n");

        assert!(verified_agent_steps(&reconstruction, "python").is_empty());
        let (files, manifest) = replay_files_for_reconstruction(&reconstruction);
        let replay = files
            .iter()
            .find(|file| file.name == "replay.py")
            .expect("python replay file");
        assert!(!replay.content.contains("changed after verification"));
        assert_eq!(manifest.gate.verdict, VerificationVerdict::Unverifiable);
        assert!(!manifest.gate.executable_verified_logic_emitted);
    }

    #[test]
    fn replay_gate_is_scoped_to_the_exported_language() {
        let mut reconstruction = reconstruction_with_agent_step("python", AGENT_PY, "verified");
        reconstruction.pipeline[0].implementations.push(
            crate::algorithm_verification::Implementation {
                language: "javascript".into(),
                source: "function computeSignature() { return 'wrong'; }".into(),
                entry_point: "computeSignature".into(),
            },
        );
        let mut javascript_failure =
            crate::algorithm_verification::VerificationReport::for_test("failed");
        javascript_failure.step_id = "1".into();
        javascript_failure.step_name = "vendor_custom_sign".into();
        javascript_failure.implementation_sha256 =
            reconstruction.pipeline[0].implementations[1].sha256();
        javascript_failure.language = "javascript".into();
        javascript_failure.attempted = 1;
        javascript_failure.failed = 1;
        reconstruction.verification.push(javascript_failure);
        reconstruction.crypto_verified = false;

        let harness = crate::signature_adapter::SignatureAdapterHarness {
            adapter_id: "generic-dynamic-signature".into(),
            adapter_version: "1.0.0".into(),
            vendor: "Generic".into(),
            confidence: "high".into(),
            evidence_hash: "capture-evidence-sha256".into(),
            matched_requests: vec![],
            dynamic_fields: vec!["vendor_custom_sign".into()],
            cookie_names: vec![],
            hook_names: vec![],
            crypto_algorithms: vec!["SHA-256".into()],
            fingerprint_dependencies: vec![],
            required_inputs: vec![],
            evidence_gaps: vec![],
            language: "python".into(),
            code: String::new(),
        };
        let (files, manifest) = build_files(
            "session-1",
            "python",
            &harness,
            &json!([]),
            &json!({}),
            &json!({}),
            &[],
            "# Analysis\n",
            &reconstruction,
        )
        .expect("build python replay");

        assert_eq!(manifest.gate.verdict, VerificationVerdict::Verified);
        assert_eq!(manifest.runtimes.len(), 1);
        assert_eq!(manifest.runtimes[0].language, "python");
        let verification = files
            .iter()
            .find(|file| file.name == "VERIFICATION.json")
            .expect("verification file");
        let parsed: Value = serde_json::from_str(&verification.content).expect("verification JSON");
        assert_eq!(parsed["cryptoVerified"], json!(true));
        assert_eq!(parsed["runs"].as_array().map(Vec::len), Some(1));
        assert_eq!(parsed["runs"][0]["language"], json!("python"));
    }

    #[test]
    fn a_verified_step_survives_a_failed_sibling_in_the_same_language() {
        use crate::algorithm_reconstruction::AlgorithmStep;
        use crate::algorithm_verification::{Implementation, VerificationReport};

        let mut reconstruction = reconstruction_with_agent_step("python", AGENT_PY, "verified");
        let rejected_source = "def rejectedSignature(request):\n    return \"must-not-ship\"\n";
        let rejected = Implementation {
            language: "python".into(),
            source: rejected_source.into(),
            entry_point: "rejectedSignature".into(),
        };
        reconstruction.pipeline.push(AlgorithmStep {
            id: "2".into(),
            name: "rejected_sign".into(),
            status: "reconstructed".into(),
            formula: "unverified candidate".into(),
            evidence: vec!["hook pair".into()],
            implementation_hint: "agent".into(),
            implementations: vec![rejected.clone()],
        });
        let mut failed = VerificationReport::for_test("failed");
        failed.step_id = "2".into();
        failed.step_name = "rejected_sign".into();
        failed.implementation_sha256 = rejected.sha256();
        failed.language = "python".into();
        failed.attempted = 1;
        failed.failed = 1;
        reconstruction.verification.push(failed);
        reconstruction.crypto_verified = false;

        assert_eq!(
            verified_agent_steps(&reconstruction, "python")
                .into_iter()
                .map(|(name, _, _)| name)
                .collect::<Vec<_>>(),
            vec!["vendor_custom_sign"]
        );
        assert_eq!(
            unverified_algorithm_step_names(&reconstruction, "python"),
            vec!["rejected_sign"]
        );

        let (files, manifest) = replay_files_for_reconstruction(&reconstruction);
        let replay = files
            .iter()
            .find(|file| file.name == "replay.py")
            .expect("python replay file");
        assert!(replay.content.contains("# step: vendor_custom_sign"));
        assert!(!replay.content.contains("must-not-ship"));
        assert!(manifest.gate.executable_verified_logic_emitted);
        assert_eq!(manifest.verdict_counts.verified, 1);
        assert_eq!(manifest.verdict_counts.failed, 1);
        assert_eq!(manifest.gate.verdict, VerificationVerdict::Failed);

        let verification = files
            .iter()
            .find(|file| file.name == "VERIFICATION.json")
            .expect("verification file");
        let parsed: Value = serde_json::from_str(&verification.content).expect("verification JSON");
        assert_eq!(parsed["cryptoVerified"], json!(false));
        assert_eq!(parsed["runs"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn replay_verification_manifest_hashes_match_the_package_files() {
        let (files, manifest) = replay_files_for_verdict("verified");
        assert_eq!(manifest.generated_files.len() + 1, files.len());
        assert!(
            manifest
                .generated_files
                .iter()
                .all(|digest| digest.name != "VERIFICATION_MANIFEST.json"),
            "the manifest cannot recursively digest itself"
        );

        for digest in &manifest.generated_files {
            let packaged = files
                .iter()
                .find(|file| file.name == digest.name)
                .unwrap_or_else(|| panic!("digest references missing file {}", digest.name));
            assert_eq!(digest.role, packaged.role);
            assert_eq!(digest.bytes, packaged.content.len());
            assert_eq!(
                digest.sha256,
                format!("{:x}", Sha256::digest(packaged.content.as_bytes())),
                "digest mismatch for {}",
                digest.name
            );
        }

        let encoded = files
            .iter()
            .find(|file| file.name == "VERIFICATION_MANIFEST.json")
            .expect("package carries verification manifest");
        assert_eq!(
            serde_json::from_str::<Value>(&encoded.content).expect("valid manifest JSON"),
            serde_json::to_value(&manifest).expect("serialize manifest")
        );
    }

    #[test]
    fn replay_package_hash_frames_metadata_and_file_boundaries() {
        let first = vec![file("a", "code", Some("python".into()), "bc")];
        let same_file_bytes_with_another_boundary =
            vec![file("ab", "code", Some("python".into()), "c")];

        assert_ne!(
            package_hash("ab", "c", "evidence", &first),
            package_hash("a", "bc", "evidence", &first),
            "session and language boundaries must be part of the package identity"
        );
        assert_ne!(
            package_hash("session", "python", "evidence", &first),
            package_hash(
                "session",
                "python",
                "evidence",
                &same_file_bytes_with_another_boundary,
            ),
            "file name and content boundaries must be part of the package identity"
        );
    }

    /// The test that decides whether the agent seam is real: a step the built-in
    /// catalogue has never heard of must reach the generated package and run.
    #[test]
    fn a_verified_agent_step_is_emitted_and_actually_executes() {
        let reconstruction = reconstruction_with_agent_step("python", AGENT_PY, "verified");
        let emitted = render_agent_algorithms(&reconstruction, "python");
        assert!(
            emitted.contains("vendor_custom_sign"),
            "the step must be registered: {emitted}"
        );

        let Some(python) = test_python() else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("shownet-agent-emit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let module = format!(
            "from typing import Any, Dict\n{emitted}\n\
             import json\n\
             print(json.dumps({{k: v({{\"method\": \"POST\", \"path\": \"/v1/order\"}}) for k, v in AGENT_STEPS.items()}}))\n"
        );
        std::fs::write(dir.join("emitted.py"), module).expect("write");
        let output = std::process::Command::new(&python)
            .arg("emitted.py")
            .current_dir(&dir)
            .output()
            .expect("run emitted module");
        let stdout = String::from_utf8_lossy(&output.stdout);
        std::fs::remove_dir_all(&dir).ok();

        let expected = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"POST/v1/order")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert!(
            stdout.contains(&expected),
            "the emitted agent step must produce its real answer:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The gate: code the agent wrote but that did not reproduce the capture
    /// must not reach the package at all. Emitting it would hand the operator
    /// unreviewed model output to run against a live site.
    #[test]
    fn an_unverified_agent_step_is_not_emitted() {
        for verdict in ["failed", "unverifiable"] {
            let reconstruction = reconstruction_with_agent_step("python", AGENT_PY, verdict);
            let emitted = render_agent_algorithms(&reconstruction, "python");
            assert!(
                !emitted.contains("hashlib"),
                "{verdict} code must not be emitted: {emitted}"
            );
            assert!(
                emitted.contains("AGENT_STEPS: Dict[str, Any] = {}"),
                "the registry must still exist and be empty: {emitted}"
            );
        }
    }

    /// A JavaScript pass says nothing about the agent's Python port, and Python
    /// is what the operator runs.
    #[test]
    fn verification_in_one_language_does_not_license_emitting_another() {
        let reconstruction = reconstruction_with_agent_step(
            "javascript",
            "function computeSignature(r) { return 'x'; }",
            "verified",
        );
        let emitted = render_agent_algorithms(&reconstruction, "python");
        assert!(
            emitted.contains("AGENT_STEPS: Dict[str, Any] = {}"),
            "a javascript-only verification must not emit a python step: {emitted}"
        );
    }

    /// The invariant that makes verification mean anything at run time: the dict
    /// the step is called with in the generated client must carry the same keys
    /// the verifier fed it. Drift here silently voids every verified badge.
    #[test]
    fn the_runtime_input_shape_matches_the_verified_input_shape() {
        let source = render_replay_source_for_shape_test();
        for key in [
            "\"method\"",
            "\"host\"",
            "\"path\"",
            "\"query\"",
            "\"headers\"",
            "\"body\"",
        ] {
            assert!(
                source.contains(&format!("{key}:")),
                "agent_step_input must supply {key}, which ground truth includes"
            );
        }
        // Ground truth supplies exactly these six and nothing else; an extra
        // top-level key would be a field the step was never checked on.
        let block = source
            .split("def agent_step_input")
            .nth(1)
            .and_then(|rest| rest.split("def load_json").next())
            .expect("agent_step_input is emitted");
        let top_level = block.matches("        \"").count();
        assert_eq!(
            top_level, 6,
            "agent_step_input returns keys verification never supplied:\n{block}"
        );
    }

    #[test]
    fn unresolved_dynamic_fields_fail_instead_of_becoming_placeholders() {
        let Some(python) = test_python() else {
            return;
        };
        let source = render_replay_source_for_shape_test();
        assert!(!source.contains("<missing:"));

        let dir = std::env::temp_dir().join(format!(
            "shownet-replay-missing-field-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("replay.py"), source).expect("write replay");
        std::fs::write(
            dir.join("drive.py"),
            r#"from replay import ReplayContext, compute_dynamic_fields

try:
    compute_dynamic_fields(
        ReplayContext(domain="example.com", user_agent="test"),
        {"dynamicFields": ["x-signature"]},
        {},
    )
except RuntimeError as error:
    assert "x-signature" in str(error), error
    print(error)
else:
    raise AssertionError("missing dynamic field did not fail")
"#,
        )
        .expect("write driver");

        let output = std::process::Command::new(&python)
            .arg("drive.py")
            .current_dir(&dir)
            .output()
            .expect("run generated replay");
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            output.status.success(),
            "generated replay accepted an unresolved field:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn render_replay_source_for_shape_test() -> String {
        let reconstruction = reconstruction_with_agent_step("python", AGENT_PY, "verified");
        let harness = crate::signature_adapter::SignatureAdapterHarness {
            adapter_id: "generic-dynamic-signature".into(),
            adapter_version: "1.0.0".into(),
            vendor: "Generic".into(),
            confidence: "medium".into(),
            evidence_hash: "abc".into(),
            matched_requests: vec![],
            dynamic_fields: vec!["x-signature".into()],
            cookie_names: vec![],
            hook_names: vec![],
            crypto_algorithms: vec!["SHA-256".into()],
            fingerprint_dependencies: vec![],
            required_inputs: vec![],
            evidence_gaps: vec![],
            language: "python".into(),
            code: String::new(),
        };
        render_replay_source("python", &harness, &json!({}), &[], &reconstruction)
            .expect("python replay source renders")
    }

    fn test_python() -> Option<String> {
        for candidate in ["python3", "python"] {
            if std::process::Command::new(candidate)
                .arg("--version")
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false)
            {
                return Some(candidate.to_string());
            }
        }
        None
    }

    /// The verdict has to reach the person who runs the code, not just sit in
    /// the reconstruction struct. Without this file the operator sees "runnable
    /// crypto: true" and has no way to learn it was never checked.
    #[test]
    fn the_package_ships_the_verification_verdict_and_says_what_it_means() {
        let storage = storage();
        let session = storage
            .create_session(Some("verify-surface".into()))
            .unwrap();
        let sid = session.id.clone();
        storage
            .store_request(base(&sid, "api.example.com", "/v1/order"))
            .expect("seed");
        let package = build_algorithm_replay(&storage, &sid, "python").expect("build");

        let file = package
            .files
            .iter()
            .find(|f| f.name == "VERIFICATION.json")
            .expect("package ships VERIFICATION.json");
        let parsed: Value = serde_json::from_str(&file.content).expect("valid json");

        // No agent code was supplied here, so the claim must be off and the
        // reason must be stated rather than left to inference.
        assert_eq!(parsed["cryptoVerified"], json!(false));
        assert!(
            parsed["claimBasis"]
                .as_str()
                .is_some_and(|basis| basis.contains("nothing was executed")),
            "the file must say why the claim is off: {parsed}"
        );
        assert!(
            parsed["note"]
                .as_str()
                .is_some_and(|note| note.contains("scoped to this python package")),
            "the file must scope the verification claim to the package language: {parsed}"
        );
    }

    const AGENT_JS: &str = "function computeSignature(request) {\n  return shownet.hmacSha256Hex('Jefe', request.method + request.path);\n}\n";

    #[test]
    fn a_real_typescript_verification_licenses_the_typescript_export() {
        let mut reconstruction =
            reconstruction_with_agent_step("typescript", AGENT_JS, "unverifiable");
        let implementation = reconstruction.pipeline[0].implementations[0].clone();
        let mut report = crate::algorithm_verification::verify(
            &implementation,
            &[crate::algorithm_ground_truth::GroundTruthCase {
                id: "request:1:vendor_custom_sign".into(),
                origin: "request".into(),
                field: "vendor_custom_sign".into(),
                algorithm_hint: "HMAC".into(),
                input: json!({
                    "method": "POST",
                    "host": "api.example.com",
                    "path": "/v1/order",
                    "query": null,
                    "headers": {},
                    "body": null,
                }),
                expected: expected_hmac("POST/v1/order"),
                request_id: Some("1".into()),
                sequence: 1,
            }],
        );
        report.step_id = "1".into();
        report.step_name = "vendor_custom_sign".into();
        reconstruction.verification = vec![report];

        assert_eq!(
            verified_agent_steps(&reconstruction, "typescript").len(),
            1,
            "a TypeScript candidate must retain its package language after Boa verification"
        );
        let emitted = render_agent_algorithms(&reconstruction, "typescript");
        assert!(emitted.contains("hmacSha256Hex('Jefe'"));
    }

    /// Same standard the Python path is held to: the emitted JavaScript has to
    /// run under node and produce the real answer, not merely contain the text.
    #[test]
    fn a_verified_agent_step_runs_in_the_emitted_javascript() {
        let Some(node) = test_node() else {
            return;
        };
        let reconstruction = reconstruction_with_agent_step("javascript", AGENT_JS, "verified");
        let emitted = render_agent_algorithms(&reconstruction, "javascript");

        let dir = std::env::temp_dir().join(format!("shownet-agent-js-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("package.json"), r#"{"type":"module"}"#).expect("write");
        std::fs::write(dir.join("steps.mjs"), &emitted).expect("write");
        std::fs::write(
            dir.join("drive.mjs"),
            "import { AGENT_STEPS } from './steps.mjs';\n\
             const input = { method: 'POST', host: 'h', path: '/v1/order', query: null, headers: {}, body: null };\n\
             console.log(JSON.stringify(Object.fromEntries(Object.entries(AGENT_STEPS).map(([k, f]) => [k, f(input)]))));\n",
        )
        .expect("write");

        let output = std::process::Command::new(&node)
            .arg("drive.mjs")
            .current_dir(&dir)
            .output()
            .expect("run emitted javascript");
        let stdout = String::from_utf8_lossy(&output.stdout);
        std::fs::remove_dir_all(&dir).ok();

        // The reference answer, computed independently of the emitted code.
        let expected = {
            use sha2::{Digest, Sha256};
            let key = b"Jefe";
            let mut padded = [0u8; 64];
            padded[..key.len()].copy_from_slice(key);
            let mut ipad = [0x36u8; 64];
            let mut opad = [0x5cu8; 64];
            for i in 0..64 {
                ipad[i] ^= padded[i];
                opad[i] ^= padded[i];
            }
            let mut inner = Sha256::new();
            inner.update(ipad);
            inner.update(b"POST/v1/order");
            let inner = inner.finalize();
            let mut outer = Sha256::new();
            outer.update(opad);
            outer.update(inner);
            outer
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert!(
            stdout.contains(&expected),
            "the emitted javascript step must produce its real answer:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn emitted_javascript_preserves_source_bytes_and_candidate_state() {
        let Some(node) = test_node() else {
            return;
        };
        let source = "let calls = 0;\nfunction computeSignature() {\n  calls += 1;\n  return `first line\nsecond line:${calls}`;\n}\n";
        let reconstruction = reconstruction_with_agent_step("javascript", source, "verified");
        let emitted = render_agent_algorithms(&reconstruction, "javascript");
        let dir = std::env::temp_dir().join(format!(
            "shownet-agent-js-source-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("package.json"), r#"{"type":"module"}"#).expect("write");
        std::fs::write(dir.join("steps.mjs"), &emitted).expect("write");
        std::fs::write(
            dir.join("drive.mjs"),
            "import { AGENT_STEPS } from './steps.mjs';\n\
             const step = AGENT_STEPS.vendor_custom_sign;\n\
             if (step({}) !== 'first line\\nsecond line:1') throw new Error('first call changed');\n\
             if (step({}) !== 'first line\\nsecond line:2') throw new Error('state lifecycle changed');\n",
        )
        .expect("write");

        let output = std::process::Command::new(&node)
            .arg("drive.mjs")
            .current_dir(&dir)
            .output()
            .expect("run emitted javascript");
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            output.status.success(),
            "emitted JavaScript changed verified source semantics:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The primitives the candidate was verified against must exist in the
    /// emitted runtime under the same names. If boa's `shownet.*` surface and
    /// node's differ, verification checked code that never runs.
    #[test]
    fn the_emitted_javascript_provides_the_primitives_verification_used() {
        let reconstruction = reconstruction_with_agent_step("javascript", AGENT_JS, "verified");
        let emitted = render_agent_algorithms(&reconstruction, "javascript");
        for primitive in ["sha256Hex", "md5Hex", "hmacSha256Hex", "base64Encode"] {
            assert!(
                emitted.contains(primitive),
                "{primitive} is offered to candidates during verification and must exist at run time"
            );
        }
    }

    /// A language whose template has nowhere to call agent code from must emit
    /// none, rather than pasting Python or JavaScript into a Go file.
    #[test]
    fn languages_without_an_agent_seam_emit_nothing_rather_than_broken_code() {
        let reconstruction = reconstruction_with_agent_step("python", AGENT_PY, "verified");
        for language in ["go", "java", "csharp"] {
            assert!(
                render_agent_algorithms(&reconstruction, language).is_empty(),
                "{language} has no agent seam yet and must not receive foreign syntax"
            );
        }
    }

    /// Unverified code must be withheld in JavaScript exactly as in Python.
    #[test]
    fn an_unverified_agent_step_is_not_emitted_in_javascript() {
        for verdict in ["failed", "unverifiable"] {
            let reconstruction = reconstruction_with_agent_step("javascript", AGENT_JS, verdict);
            let emitted = render_agent_algorithms(&reconstruction, "javascript");
            assert!(
                !emitted.contains("hmacSha256Hex('Jefe'"),
                "{verdict} code must not be emitted: {emitted}"
            );
        }
    }

    fn test_node() -> Option<String> {
        std::process::Command::new("node")
            .arg("--version")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|_| "node".to_string())
    }

    /// Every supported language must be able to receive verified agent code.
    /// A language in the menu with no seam behind it is a promise the export
    /// cannot keep — the operator picks it and gets a skeleton.
    #[test]
    fn every_supported_language_has_an_agent_seam() {
        for language in SUPPORTED_LANGUAGES {
            let reconstruction = match *language {
                "go" => reconstruction_with_agent_step("go", GO_AGENT, "verified"),
                "java" => reconstruction_with_agent_step("java", JAVA_AGENT, "verified"),
                "csharp" => reconstruction_with_agent_step("csharp", CSHARP_AGENT, "verified"),
                "python" => reconstruction_with_agent_step("python", AGENT_PY, "verified"),
                other => reconstruction_with_agent_step(other, AGENT_JS, "verified"),
            };
            let mut reconstruction = reconstruction;
            if matches!(*language, "go" | "csharp") {
                reconstruction.pipeline[0].implementations[0].entry_point =
                    "ComputeSignature".into();
                reconstruction.verification[0].implementation_sha256 =
                    reconstruction.pipeline[0].implementations[0].sha256();
            }
            let entry = reconstruction.pipeline[0].implementations[0]
                .entry_point
                .clone();
            let emitted = format!(
                "{}{}",
                render_agent_algorithms(&reconstruction, language),
                agent_step_files(&reconstruction, language)
                    .iter()
                    .map(|(_, content)| content.clone())
                    .collect::<String>()
            );
            assert!(
                emitted.contains(&entry),
                "{language} accepts verified agent code but emits none of it"
            );
            assert!(
                emitted.contains(&reconstruction.pipeline[0].name),
                "{language} must register the step under its name so the client can call it"
            );
        }
    }

    // --- Compiled-language agent steps --------------------------------------
    //
    // Held to the same standard as Python and JavaScript: the emitted files must
    // compile and produce the real answer, not merely contain the right text.

    fn expected_hmac(message: &str) -> String {
        use sha2::{Digest, Sha256};
        let key = b"Jefe";
        let mut padded = [0u8; 64];
        padded[..key.len()].copy_from_slice(key);
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= padded[i];
            opad[i] ^= padded[i];
        }
        let mut inner = Sha256::new();
        inner.update(ipad);
        inner.update(message.as_bytes());
        let inner = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner);
        outer
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn stage(tag: &str, files: &[(String, String)], extra: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("shownet-emit-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("temp dir");
        for (name, content) in files {
            std::fs::write(dir.join(name), content).expect("write emitted file");
        }
        for (name, content) in extra {
            std::fs::write(dir.join(name), content).expect("write driver");
        }
        dir
    }

    const GO_AGENT: &str = "package main\n\nimport (\n\t\"crypto/hmac\"\n\t\"crypto/sha256\"\n\t\"encoding/hex\"\n)\n\nfunc ComputeSignature(request Request) string {\n\tmac := hmac.New(sha256.New, []byte(\"Jefe\"))\n\tmac.Write([]byte(request.Method + request.Path))\n\treturn hex.EncodeToString(mac.Sum(nil))\n}\n";

    #[test]
    fn emitted_go_agent_steps_compile_and_produce_the_real_answer() {
        if !std::process::Command::new("go")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return;
        }
        let mut reconstruction = reconstruction_with_agent_step("go", GO_AGENT, "verified");
        reconstruction.pipeline[0].implementations[0].entry_point = "ComputeSignature".into();
        reconstruction.verification[0].implementation_sha256 =
            reconstruction.pipeline[0].implementations[0].sha256();
        let files = agent_step_files(&reconstruction, "go");

        let dir = stage(
            "go",
            &files,
            &[
                ("go.mod", "module shownetemit\n\ngo 1.21\n"),
                (
                    "main.go",
                    "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tinput := Request{Method: \"POST\", Path: \"/v1/order\", Headers: map[string]string{}}\n\tfor name, step := range AgentSteps {\n\t\tfmt.Printf(\"%s=%s\\n\", name, step(input))\n\t}\n}\n",
                ),
            ],
        );
        let output = std::process::Command::new("go")
            .args(["run", "."])
            .current_dir(&dir)
            .output()
            .expect("run emitted go");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            stdout.contains(&expected_hmac("POST/v1/order")),
            "emitted go must produce the real answer:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    const JAVA_AGENT: &str = "import javax.crypto.Mac;\nimport javax.crypto.spec.SecretKeySpec;\nimport java.nio.charset.StandardCharsets;\n\npublic class Candidate {\n    public static String computeSignature(Request request) throws Exception {\n        Mac mac = Mac.getInstance(\"HmacSHA256\");\n        mac.init(new SecretKeySpec(\"Jefe\".getBytes(StandardCharsets.UTF_8), \"HmacSHA256\"));\n        byte[] digest = mac.doFinal((request.method() + request.path()).getBytes(StandardCharsets.UTF_8));\n        StringBuilder out = new StringBuilder();\n        for (byte b : digest) { out.append(String.format(\"%02x\", b)); }\n        return out.toString();\n    }\n}\n";

    #[test]
    fn java_candidate_comments_cannot_choose_an_export_path() {
        let source = format!("// public class ../../outside\n{JAVA_AGENT}");
        let reconstruction = reconstruction_with_agent_step("java", &source, "verified");
        let files = agent_step_files(&reconstruction, "java");
        let candidate = files
            .iter()
            .find(|(name, _)| name == "Candidate.java")
            .expect("verified Java source uses the same fixed file name as verification");

        assert_eq!(candidate.1, source);
        assert!(files
            .iter()
            .all(|(name, _)| !name.contains("..") && !name.contains('/') && !name.contains('\\')));
    }

    #[test]
    fn emitted_java_agent_steps_compile_and_produce_the_real_answer() {
        if !std::process::Command::new("javac")
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return;
        }
        let reconstruction = reconstruction_with_agent_step("java", JAVA_AGENT, "verified");
        let files = agent_step_files(&reconstruction, "java");

        let dir = stage(
            "java",
            &files,
            &[(
                "Main.java",
                "import java.util.LinkedHashMap;\n\npublic class Main {\n    public static void main(String[] args) {\n        Request input = new Request(\"POST\", \"h\", \"/v1/order\", null, new LinkedHashMap<>(), null);\n        AgentSteps.all().forEach((name, step) -> System.out.println(name + \"=\" + step.apply(input)));\n    }\n}\n",
            )],
        );
        let names: Vec<String> = files
            .iter()
            .map(|(name, _)| name.clone())
            .chain(["Main.java".to_string()])
            .collect();
        let compile = std::process::Command::new("javac")
            .args(&names)
            .current_dir(&dir)
            .output()
            .expect("compile emitted java");
        assert!(
            compile.status.success(),
            "emitted java must compile:\n{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let output = std::process::Command::new("java")
            .arg("Main")
            .current_dir(&dir)
            .output()
            .expect("run emitted java");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            stdout.contains(&expected_hmac("POST/v1/order")),
            "emitted java must produce the real answer:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    const CSHARP_AGENT: &str = "using System.Security.Cryptography;\nusing System.Text;\n\nnamespace ShowNetReplay;\n\npublic static class Candidate\n{\n    public static string ComputeSignature(Request request)\n    {\n        using var mac = new HMACSHA256(Encoding.UTF8.GetBytes(\"Jefe\"));\n        var digest = mac.ComputeHash(Encoding.UTF8.GetBytes(request.Method + request.Path));\n        return Convert.ToHexString(digest).ToLowerInvariant();\n    }\n}\n";

    #[test]
    fn emitted_csharp_agent_steps_compile_and_produce_the_real_answer() {
        if !std::process::Command::new("dotnet")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return;
        }
        let mut reconstruction =
            reconstruction_with_agent_step("csharp", CSHARP_AGENT, "unverifiable");
        reconstruction.pipeline[0].implementations[0].entry_point = "ComputeSignature".into();
        let implementation = reconstruction.pipeline[0].implementations[0].clone();
        let mut report = crate::algorithm_verification::verify(
            &implementation,
            &[crate::algorithm_ground_truth::GroundTruthCase {
                id: "request:1:vendor_custom_sign".into(),
                origin: "request".into(),
                field: "vendor_custom_sign".into(),
                algorithm_hint: "HMAC".into(),
                input: json!({
                    "method": "POST",
                    "host": "h",
                    "path": "/v1/order",
                    "query": null,
                    "headers": {},
                    "body": null,
                }),
                expected: expected_hmac("POST/v1/order"),
                request_id: Some("1".into()),
                sequence: 1,
            }],
        );
        assert_eq!(report.verdict, "verified", "{report:?}");
        report.step_id = "1".into();
        report.step_name = "vendor_custom_sign".into();
        reconstruction.verification = vec![report];
        reconstruction.crypto_verified = true;
        let files = agent_step_files(&reconstruction, "csharp");

        let dir = stage(
            "csharp",
            &files,
            &[
                (
                    "emit.csproj",
                    "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>net8.0</TargetFramework>\n    <Nullable>enable</Nullable>\n    <ImplicitUsings>enable</ImplicitUsings>\n    <AssemblyName>shownetemit</AssemblyName>\n  </PropertyGroup>\n</Project>\n",
                ),
                (
                    "Main.cs",
                    "using ShowNetReplay;\n\ninternal static class EmitMain\n{\n    private static void Main()\n    {\n        var input = new Request(\"POST\", \"h\", \"/v1/order\", null, new Dictionary<string, string>(), null);\n        foreach (var pair in AgentSteps.All)\n        {\n            Console.WriteLine($\"{pair.Key}={pair.Value(input)}\");\n        }\n    }\n}\n",
                ),
            ],
        );
        let output = std::process::Command::new("dotnet")
            .args(["run", "--project", "emit.csproj", "-v", "quiet", "--nologo"])
            .current_dir(&dir)
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            .output()
            .expect("run emitted csharp");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            stdout.contains(&expected_hmac("POST/v1/order")),
            "emitted csharp must produce the real answer:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The gate holds for compiled languages too: unverified code must not be
    /// emitted, in any of them.
    #[test]
    fn unverified_agent_code_is_withheld_in_every_compiled_language() {
        for (language, source) in [
            ("go", GO_AGENT),
            ("java", JAVA_AGENT),
            ("csharp", CSHARP_AGENT),
        ] {
            for verdict in ["failed", "unverifiable"] {
                let reconstruction = reconstruction_with_agent_step(language, source, verdict);
                let emitted = agent_step_files(&reconstruction, language)
                    .iter()
                    .map(|(_, content)| content.clone())
                    .collect::<String>();
                assert!(
                    !emitted.contains("Jefe"),
                    "{language}/{verdict} code must not be emitted"
                );
            }
        }
    }

    #[test]
    fn compiled_candidates_are_withheld_when_their_verified_units_would_collide() {
        use crate::algorithm_reconstruction::AlgorithmStep;
        use crate::algorithm_verification::{Implementation, VerificationReport};

        for (language, source, entry_point) in [
            ("go", GO_AGENT, "ComputeSignature"),
            ("java", JAVA_AGENT, "computeSignature"),
            ("csharp", CSHARP_AGENT, "ComputeSignature"),
        ] {
            let mut reconstruction = reconstruction_with_agent_step(language, source, "verified");
            reconstruction.pipeline[0].implementations[0].entry_point = entry_point.into();
            reconstruction.verification[0].implementation_sha256 =
                reconstruction.pipeline[0].implementations[0].sha256();
            let second_implementation = Implementation {
                language: language.into(),
                source: source.into(),
                entry_point: entry_point.into(),
            };
            reconstruction.pipeline.push(AlgorithmStep {
                id: "2".into(),
                name: "vendor_custom_token".into(),
                status: "reconstructed".into(),
                formula: "second verified output".into(),
                evidence: vec!["hook pair 2".into()],
                implementation_hint: "agent".into(),
                implementations: vec![second_implementation.clone()],
            });
            let mut report = VerificationReport::for_test("verified");
            report.step_id = "2".into();
            report.step_name = "vendor_custom_token".into();
            report.implementation_sha256 = second_implementation.sha256();
            report.language = language.into();
            report.attempted = 1;
            report.passed = 1;
            reconstruction.verification.push(report);

            assert_eq!(
                strictly_verified_agent_steps(&reconstruction, language).len(),
                2
            );
            assert!(verified_agent_steps(&reconstruction, language).is_empty());
            let emitted = agent_step_files(&reconstruction, language)
                .into_iter()
                .map(|(_, content)| content)
                .collect::<String>();
            assert!(
                !emitted.contains("Jefe"),
                "{language} collision must withhold both candidate sources"
            );
            let gaps = complete_evidence_gaps(
                &[],
                &reconstruction,
                language,
                &["vendor_custom_sign".into(), "vendor_custom_token".into()],
            );
            assert!(gaps.iter().any(|gap| {
                gap.contains("reuse one compilation namespace") && gap.contains("all were withheld")
            }));
        }
    }

    #[test]
    fn compiled_candidates_cannot_collide_with_generated_package_symbols() {
        for (language, source, entry_point, reserved) in [
            (
                "go",
                format!("{GO_AGENT}\nfunc BuildRequest() {{}}\n"),
                "ComputeSignature",
                "BuildRequest",
            ),
            (
                "java",
                format!("{JAVA_AGENT}\nfinal class Replay {{}}\n"),
                "computeSignature",
                "Replay",
            ),
            (
                "csharp",
                format!("{CSHARP_AGENT}\npublic static class AgentSteps {{}}\n"),
                "ComputeSignature",
                "AgentSteps",
            ),
        ] {
            let mut reconstruction = reconstruction_with_agent_step(language, &source, "verified");
            reconstruction.pipeline[0].implementations[0].entry_point = entry_point.into();
            reconstruction.verification[0].implementation_sha256 =
                reconstruction.pipeline[0].implementations[0].sha256();

            assert_eq!(
                strictly_verified_agent_steps(&reconstruction, language).len(),
                1
            );
            assert!(verified_agent_steps(&reconstruction, language).is_empty());
            let emitted = agent_step_files(&reconstruction, language)
                .into_iter()
                .map(|(_, content)| content)
                .collect::<String>();
            assert!(
                !emitted.contains("Jefe"),
                "{language} collision source must be withheld"
            );
            let gap = compiled_step_collision_gap(&reconstruction, language)
                .expect("collision must be machine-readable");
            assert!(gap.contains(reserved), "{gap}");
            assert!(gap.contains("withheld"), "{gap}");
        }
    }

    /// javac reads source in the platform charset unless told otherwise, so a
    /// generated `.java` file carrying non-ASCII fails to compile on a Windows
    /// default — and the evidence gaps this project writes are in Chinese. Only
    /// the Windows runner caught it; this asserts it everywhere.
    #[test]
    fn generated_java_sources_are_pure_ascii() {
        let storage = storage();
        let session = storage.create_session(Some("java-ascii".into())).unwrap();
        let sid = session.id.clone();
        let mut request = base(&sid, "api.example.com", "/v1/order");
        // Non-ASCII reaches the header comment through the evidence gaps, which
        // are prose written by the analysis side.
        request.response_body = Some("缺少关键运行时 Hook，尚不能确认字段生成顺序".into());
        storage.store_request(request).expect("seed");

        let package = build_algorithm_replay(&storage, &sid, "java").expect("build");
        for file in package.files.iter().filter(|f| f.name.ends_with(".java")) {
            let offending: Vec<char> = file
                .content
                .chars()
                .filter(|ch| !ch.is_ascii())
                .take(5)
                .collect();
            assert!(
                offending.is_empty(),
                "{} must be pure ASCII so `javac *.java` works on any platform; found {offending:?}",
                file.name
            );
        }
    }
}
