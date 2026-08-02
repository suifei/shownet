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
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SUPPORTED_LANGUAGES: &[&str] = &[
    "python",
    "javascript",
    "typescript",
    "go",
    "rust",
    "java",
    "csharp",
    "c++",
    "c",
    "zig",
];

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
    pub can_emit_runnable_crypto: bool,
    pub provider_candidates: Value,
    pub protocol_schemas: Value,
    pub algorithm_reconstruction: Value,
    pub required_inputs: Vec<String>,
    pub evidence_gaps: Vec<String>,
    pub validation_checklist: Vec<String>,
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
        "rs" | "rust" => "rust",
        "java" => "java",
        "c#" | "cs" | "csharp" => "csharp",
        "c++" | "cpp" | "cxx" | "cc" | "cplusplus" => "c++",
        "c" | "c11" | "c17" | "c23" => "c",
        "zig" | "ziglang" => "zig",
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

    let files = build_files(
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
    let validation_checklist =
        validation_checklist(&harness, &protocol_schemas, &evidence_gaps, &reconstruction);
    let mut notes = notes(&harness, report_id.is_some(), &reconstruction);
    notes.extend(reconstruction.notes.iter().cloned());

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
        can_emit_runnable_crypto: reconstruction.can_emit_runnable_crypto,
        provider_candidates,
        protocol_schemas,
        algorithm_reconstruction: reconstruction_value,
        required_inputs: harness.required_inputs,
        evidence_gaps,
        validation_checklist,
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

    // Sidecar index for tooling.
    let index = json!({
        "sessionId": package.session_id,
        "language": package.language,
        "adapterId": package.adapter_id,
        "vendor": package.vendor,
        "evidenceHash": package.evidence_hash,
        "packageHash": package.package_hash,
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
        bytes_written,
    })
}

fn package_subdirectory(parent: &Path, session_id: &str, language: &str) -> PathBuf {
    let stamp = now_ms();
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
        "shownet-algorithm-replay-{safe_session}-{language}-{stamp}"
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
) -> Result<Vec<ReplayFile>, String> {
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
        "evidenceGaps": evidence_gaps,
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

    let replay_name = replay_filename(language);
    let replay_code = render_replay_source(
        language,
        harness,
        protocol_schemas,
        evidence_gaps,
        reconstruction,
    )?;
    let readme = render_readme(session_id, language, harness, evidence_gaps, reconstruction);
    let checklist =
        validation_checklist(harness, protocol_schemas, evidence_gaps, reconstruction).join("\n- ");

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

    // Also keep the Node harness from signature_adapter for JS ecosystems.
    if matches!(language, "javascript" | "typescript") {
        files.push(file(
            "signature-adapter.mjs",
            "signature-adapter",
            Some("javascript".into()),
            &harness.code,
        ));
    }

    Ok(files)
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
        "rust" => "replay.rs".into(),
        "java" => "Replay.java".into(),
        "csharp" => "Replay.cs".into(),
        "c++" => "replay.cpp".into(),
        "c" => "replay.c".into(),
        "zig" => "replay.zig".into(),
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
Runnable reconstructed crypto: `{runnable}`

## Purpose

This package **restores algorithms from analysis evidence**, not blank stubs:

1. Read `ALGORITHM_RECONSTRUCTION.md` / `ALGORITHM_SPEC.json` for the pipeline.
2. Run `{replay}` which implements **reconstructed** steps (HMAC / NetworkBandwidth / telemetry chain, etc.).
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
- Only steps marked `reconstructed` are claimed runnable from evidence.
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
        runnable = reconstruction.can_emit_runnable_crypto,
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
) -> Vec<String> {
    let mut items = vec![
        "Read ALGORITHM_SPEC.json and confirm each reconstructed step formula matches the report.".to_string(),
        "Run offline validate_against_capture against a complete captured sample; keep reusable source parameters separate from the fixture values.".to_string(),
        "Secrets only via env; never paste production tokens into source.".to_string(),
        "For VMP/custom VM steps, attach Hook I/O traces before claiming pass.".to_string(),
    ];
    if reconstruction.can_emit_runnable_crypto {
        items.push(
            "Execute reconstructed crypto helpers (HMAC / PoW / telemetry) and compare outputs' formats to capture."
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
    hasher.update(session_id.as_bytes());
    hasher.update(language.as_bytes());
    hasher.update(evidence_hash.as_bytes());
    for file in files {
        hasher.update(file.name.as_bytes());
        hasher.update(file.content.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0)
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
    let fields = harness.dynamic_fields.join(", ");
    let inputs = harness.required_inputs.join(", ");
    let gaps = evidence_gaps.join(" | ");
    let pow = protocol_schemas
        .pointer("/pow/challengeType")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let signal = protocol_schemas
        .pointer("/signals/identifier")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let adapter = &harness.adapter_id;
    let vendor = &harness.vendor;
    let hash = &harness.evidence_hash;
    let recon_mode = &reconstruction.reconstruction_mode;
    let has_hmac = reconstruction
        .pipeline
        .iter()
        .any(|step| step.name == "hmac_sign" && step.status == "reconstructed");
    let has_nb = reconstruction.pipeline.iter().any(|step| {
        step.name == "pow_network_bandwidth"
            && matches!(step.status.as_str(), "reconstructed" | "partial")
    });
    let has_telemetry = reconstruction
        .pipeline
        .iter()
        .any(|step| step.name == "telemetry_session_chain");
    let has_aes = reconstruction
        .pipeline
        .iter()
        .any(|step| step.name == "encrypt_signals_aes_gcm");
    let vmp = reconstruction.vmp_or_custom_vm;
    let py_bool = |value: bool| if value { "True" } else { "False" };
    let has_hmac_py = py_bool(has_hmac);
    let has_nb_py = py_bool(has_nb);
    let has_telemetry_py = py_bool(has_telemetry);
    let has_aes_py = py_bool(has_aes);
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
import base64
import hashlib
import hmac
import json
import os
import re
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover
    AESGCM = None  # type: ignore

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore

# Difficulty → NetworkBandwidth body size (only used when challenge_type matches).
NETWORK_BANDWIDTH_SIZES = {{1: 1024, 2: 10240, 3: 102400, 4: 1048576, 5: 10485760}}


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


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_manifest(path: str = "MANIFEST.json") -> Dict[str, Any]:
    return load_json(path)


def load_algorithm_spec(path: str = "ALGORITHM_SPEC.json") -> Dict[str, Any]:
    if not os.path.exists(path):
        return {{}}
    return load_json(path)


# --- Reconstructed primitives (enabled only when evidence supports them) ---

HAS_HMAC = {has_hmac_py}
HAS_NETWORK_BANDWIDTH = {has_nb_py}
HAS_TELEMETRY_CHAIN = {has_telemetry_py}
HAS_AES_GCM = {has_aes_py}
VMP_HYBRID = {vmp_py}


def compose_sign_base(ctx: ReplayContext, business_suffix: str = "") -> str:
    """Reconstructed sign-base composition when report/evidence shows path:time:machine:nonce."""
    time_value = ctx.request_time or str(int(__import__("time").time() * 1000))
    nonce = ctx.nonce or os.urandom(8).hex()
    machine = ctx.client_machine_id or os.environ.get("SHOWNET_CLIENT_MACHINE_ID", "")
    base = f"{{ctx.path}}:{{time_value}}:{{machine}}:{{nonce}}"
    if business_suffix:
        base = f"{{base}}:{{business_suffix}}"
    return base


def hmac_sha256_hex(message: str, secret: Optional[str] = None) -> str:
    if not HAS_HMAC:
        raise RuntimeError("HMAC step not reconstructed from evidence")
    key = (secret or os.environ.get("SHOWNET_HMAC_SECRET") or "").encode("utf-8")
    if not key:
        raise RuntimeError("Set SHOWNET_HMAC_SECRET for reconstructed HMAC signing")
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def solve_network_bandwidth(difficulty: int) -> str:
    if not HAS_NETWORK_BANDWIDTH:
        raise RuntimeError("NetworkBandwidth PoW not reconstructed from evidence")
    size = NETWORK_BANDWIDTH_SIZES.get(int(difficulty))
    if size is None:
        raise ValueError(f"unsupported NetworkBandwidth difficulty: {{difficulty}}")
    return base64.b64encode(bytes(size)).decode("ascii")


def crc32_hex8(data: bytes) -> str:
    return format(zlib.crc32(data) & 0xFFFFFFFF, "08X")


def encrypt_signals_aes_gcm(signals_obj: Dict[str, Any], key_hex: Optional[str] = None) -> Dict[str, str]:
    """Partial reconstruction: CRC32#JSON then AES-GCM when key is provided via env."""
    if not HAS_AES_GCM:
        raise RuntimeError("AES-GCM signal encryption not reconstructed from evidence")
    if AESGCM is None:
        raise RuntimeError("install cryptography package for AES-GCM")
    key_hex = key_hex or os.environ.get("SHOWNET_AES_KEY_HEX") or ""
    key_hex = re.sub(r"[^0-9a-fA-F]", "", key_hex)
    if len(key_hex) != 64:
        raise RuntimeError("SHOWNET_AES_KEY_HEX must be 64 hex chars (AES-256) when encrypting signals")
    json_str = json.dumps(signals_obj, separators=(",", ":"), ensure_ascii=False)
    checksum = crc32_hex8(json_str.encode("utf-8"))
    plaintext = f"{{checksum}}#{{json_str}}".encode("utf-8")
    nonce = os.urandom(12)
    aesgcm = AESGCM(bytes.fromhex(key_hex))
    encrypted = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    return {{
        "checksum": checksum,
        "encrypted": f"{{base64.b64encode(nonce).decode()}}::{{tag.hex()}}::{{ciphertext.hex()}}",
    }}


def telemetry_payload(existing_token: Optional[str], session_storage: str = "null", signals: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    if not HAS_TELEMETRY_CHAIN:
        raise RuntimeError("telemetry chain not reconstructed from evidence")
    return {{
        "existing_token": existing_token,
        "awswaf_session_storage": session_storage,
        "client": "Browser",
        "signals": signals or [],
        "metrics": [{{"name": "6", "value": 50.0, "unit": "2"}}],
    }}


def compute_dynamic_fields(ctx: ReplayContext, manifest: Dict[str, Any], spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Materialize reconstructed steps. Partial/VMP steps stay explicit errors or hook-trace placeholders."""
    spec = spec or load_algorithm_spec()
    out: Dict[str, Any] = {{}}
    pipeline = (spec.get("pipeline") or [])

    # Always attach reconstruction metadata for debugging.
    out["_reconstructionMode"] = spec.get("reconstructionMode") or "{recon_mode}"
    out["_vmpHybrid"] = bool(spec.get("vmpOrCustomVm") or VMP_HYBRID)

    for step in pipeline:
        name = step.get("name") or ""
        status = step.get("status") or ""
        if name == "compose_sign_base" and status == "reconstructed":
            out["signBase"] = compose_sign_base(ctx, str(ctx.extra.get("businessSuffix", "")))
        elif name == "hmac_sign" and status == "reconstructed":
            base = out.get("signBase") or compose_sign_base(ctx)
            out["x-signature"] = hmac_sha256_hex(base)
            out["X-Signature"] = out["x-signature"]
            out["X-Request-Time"] = ctx.request_time or str(int(__import__("time").time() * 1000))
            out["X-Request-Nonce"] = ctx.nonce or os.urandom(8).hex()
            if ctx.client_machine_id:
                out["X-Client-Machine-ID"] = ctx.client_machine_id
        elif name == "pow_network_bandwidth" and status in ("reconstructed", "partial"):
            difficulty = int(ctx.extra.get("difficulty") or os.environ.get("SHOWNET_POW_DIFFICULTY") or 1)
            out["solution"] = solve_network_bandwidth(difficulty)
            out["challenge_type"] = "NetworkBandwidth"
        elif name == "encrypt_signals_aes_gcm":
            if status == "reconstructed" or os.environ.get("SHOWNET_AES_KEY_HEX"):
                signals = ctx.extra.get("signals") or {{"client": "Browser"}}
                frame = encrypt_signals_aes_gcm(signals)
                out["signals_checksum"] = frame["checksum"]
                out["signals_encrypted"] = frame["encrypted"]
            else:
                out["_aes_gcm"] = "partial: set SHOWNET_AES_KEY_HEX after offline key recovery"
        elif name == "telemetry_session_chain" and status == "reconstructed":
            out["telemetry"] = telemetry_payload(
                ctx.existing_token,
                session_storage=str(ctx.extra.get("awswaf_session_storage", "null")),
                signals=ctx.extra.get("telemetry_signals"),
            )
        elif name == "vmp_or_custom_vm_strategy" or status == "trace_driven":
            out["_vmp_trace"] = {{
                "strategy": "hook_trace",
                "note": "Fill intermediates from ShowNet Hook capture; static VM dump not claimed",
                "hookTraces": (spec.get("hookTraces") or [])[:20],
            }}
        elif status == "insufficient":
            out["_insufficient"] = step.get("formula")

    # Ensure declared dynamic fields exist as placeholders when still missing.
    for name in manifest.get("dynamicFields") or []:
        if name not in out:
            out[name] = ctx.extra.get(name, f"<missing:{{name}}>")
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
        print("# optional: pip install httpx cryptography  # for live authorized tests / AES-GCM")
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

/**
 * Implement from ShowNet Hook / crypto snippet evidence.
 * Must return every dynamicFields entry. Read secrets from process.env only.
 */
export async function computeDynamicFields(context, manifest) {{
  throw new Error(
    "Fill computeDynamicFields from authorized capture evidence before live validation",
  );
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

/** Implement from ShowNet Hook / crypto snippet evidence. */
export async function computeDynamicFields(
  _context: ReplayContext,
  _manifest: Manifest,
): Promise<Record<string, unknown>> {{
  throw new Error(
    "Fill computeDynamicFields from authorized capture evidence before live validation",
  );
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
{endpoints}
//
// Dynamic fields: {fields}
// Required inputs: {inputs}
// Gaps: {gaps}

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Manifest struct {{
	AdapterID       string                   `json:"adapterId"`
	EvidenceHash    string                   `json:"evidenceHash"`
	DynamicFields   []string                 `json:"dynamicFields"`
	RequiredInputs  []string                 `json:"requiredInputs"`
	MatchedRequests []map[string]interface{{}} `json:"matchedRequests"`
}}

type ReplayContext struct {{
	Domain        string
	UserAgent     string
	ExistingToken string
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

// ComputeDynamicFields must be implemented from authorized ShowNet evidence.
func ComputeDynamicFields(ctx ReplayContext, manifest *Manifest) (map[string]interface{{}}, error) {{
	return nil, fmt.Errorf("fill ComputeDynamicFields from capture evidence before live validation")
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

func main() {{
	ctx := ReplayContext{{
		Domain:    getenv("SHOWNET_DOMAIN", "example.com"),
		UserAgent: getenv("SHOWNET_UA", "ShowNet-Replay/1.0"),
	}}
	req, err := BuildRequest(ctx)
	if err != nil {{
		fmt.Println("error:", err)
		return
	}}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(req)
}}

func getenv(key, fallback string) string {{
	if value := os.Getenv(key); value != "" {{
		return value
	}}
	return fallback
}}
"#
        ),
        "rust" => format!(
            r#"// ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
// Adapter: {adapter} ({vendor}) | hash: {hash}
// PoW: {pow} | signal: {signal}
// Endpoints:
{endpoints}
// Fields: {fields} | Inputs: {inputs} | Gaps: {gaps}

use serde_json::{{json, Value}};
use std::fs;

pub struct ReplayContext {{
    pub domain: String,
    pub user_agent: String,
    pub existing_token: Option<String>,
}}

pub fn load_manifest(path: &str) -> Result<Value, Box<dyn std::error::Error>> {{
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}}

/// Implement from authorized ShowNet Hook / crypto evidence.
pub fn compute_dynamic_fields(
    _ctx: &ReplayContext,
    _manifest: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {{
    Err("fill compute_dynamic_fields from capture evidence before live validation".into())
}}

pub fn build_request(ctx: &ReplayContext) -> Result<Value, Box<dyn std::error::Error>> {{
    let manifest = load_manifest("MANIFEST.json")?;
    let dynamic = compute_dynamic_fields(ctx, &manifest)?;
    let endpoint = manifest
        .get("matchedRequests")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .ok_or("no matched endpoint")?;
    Ok(json!({{
        "url": endpoint.get("url"),
        "method": endpoint.get("method"),
        "headers": {{
            "user-agent": ctx.user_agent,
            "content-type": "application/json"
        }},
        "body": {{
            "domain": ctx.domain,
            "existing_token": ctx.existing_token,
            "dynamic": dynamic
        }},
        "meta": {{
            "adapterId": manifest.get("adapterId"),
            "evidenceHash": manifest.get("evidenceHash")
        }}
    }}))
}}

fn main() {{
    let ctx = ReplayContext {{
        domain: std::env::var("SHOWNET_DOMAIN").unwrap_or_else(|_| "example.com".into()),
        user_agent: std::env::var("SHOWNET_UA").unwrap_or_else(|_| "ShowNet-Replay/1.0".into()),
        existing_token: std::env::var("SHOWNET_EXISTING_TOKEN").ok(),
    }};
    match build_request(&ctx) {{
        Ok(value) => println!("{{}}", serde_json::to_string_pretty(&value).unwrap_or_default()),
        Err(error) => eprintln!("error: {{error}}"),
    }}
}}
"#
        ),
        "java" => format!(
            r#"// ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
// Adapter: {adapter} ({vendor}) | hash: {hash}
// PoW: {pow} | signal: {signal}
// Endpoints:
{endpoints}
// Fields: {fields} | Inputs: {inputs} | Gaps: {gaps}

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public final class Replay {{
  private Replay() {{}}

  public static String loadManifest(String path) throws Exception {{
    return Files.readString(Path.of(path));
  }}

  /** Implement from authorized ShowNet capture evidence. */
  public static Map<String, Object> computeDynamicFields(Map<String, Object> context) {{
    throw new UnsupportedOperationException(
        "Fill computeDynamicFields from capture evidence before live validation");
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
{endpoints}
// Fields: {fields} | Inputs: {inputs} | Gaps: {gaps}

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

public static class Replay
{{
    public static JsonDocument LoadManifest(string path = "MANIFEST.json")
        => JsonDocument.Parse(File.ReadAllText(path));

    // Implement from authorized ShowNet capture evidence.
    public static Dictionary<string, object?> ComputeDynamicFields(
        Dictionary<string, object?> context,
        JsonDocument manifest)
        => throw new NotImplementedException(
            "Fill ComputeDynamicFields from capture evidence before live validation");

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
        "c++" => format!(
            r##"// ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
// Adapter: {adapter} ({vendor}) | hash: {hash}
// PoW: {pow} | signal: {signal}
// Endpoints:
{endpoints}
// Fields: {fields} | Inputs: {inputs} | Gaps: {gaps}
//
// Build: g++ -std=c++17 -O2 replay.cpp -o replay
// Runtime deps: none required for the skeleton. Use nlohmann/json or similar to parse MANIFEST.json.

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>

struct ReplayContext {{
  std::string domain;
  std::string user_agent;
  std::string existing_token;
}};

static std::string getenv_or(const char* key, const char* fallback) {{
  if (const char* value = std::getenv(key)) {{
    return value;
  }}
  return fallback;
}}

static std::string load_manifest(const std::string& path = "MANIFEST.json") {{
  std::ifstream input(path);
  if (!input) {{
    throw std::runtime_error("failed to open MANIFEST.json");
  }}
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}}

// Implement from authorized ShowNet Hook / crypto evidence.
// Must populate every dynamicFields entry from MANIFEST.json.
static std::unordered_map<std::string, std::string> compute_dynamic_fields(
    const ReplayContext& /*ctx*/,
    const std::string& /*manifest_json*/) {{
  throw std::runtime_error(
      "Fill compute_dynamic_fields from capture evidence before live validation");
}}

static std::string build_request_json(const ReplayContext& ctx) {{
  const std::string manifest = load_manifest();
  auto dynamic = compute_dynamic_fields(ctx, manifest);
  std::ostringstream out;
  out << "{{"
      << "\"domain\":\"" << ctx.domain << "\","
      << "\"userAgent\":\"" << ctx.user_agent << "\","
      << "\"existingToken\":\"" << ctx.existing_token << "\","
      << "\"adapter\":\"{adapter}\","
      << "\"evidenceHash\":\"{hash}\","
      << "\"dynamic\":{{";
  bool first = true;
  for (const auto& [key, value] : dynamic) {{
    if (!first) {{
      out << ",";
    }}
    first = false;
    out << "\"" << key << "\":\"" << value << "\"";
  }}
  out << "}},"
      << "\"note\":\"Parse matchedRequests from MANIFEST.json and send with your HTTP client\""
      << "}}";
  return out.str();
}}

int main() {{
  ReplayContext ctx{{
      getenv_or("SHOWNET_DOMAIN", "example.com"),
      getenv_or("SHOWNET_UA", "ShowNet-Replay/1.0"),
      getenv_or("SHOWNET_EXISTING_TOKEN", ""),
  }};
  try {{
    std::cout << build_request_json(ctx) << std::endl;
  }} catch (const std::exception& error) {{
    std::cerr << "error: " << error.what() << std::endl;
    return 1;
  }}
  return 0;
}}
"##
        ),
        "c" => format!(
            r##"/* ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
 * Adapter: {adapter} ({vendor}) | hash: {hash}
 * PoW: {pow} | signal: {signal}
 * Endpoints:
{endpoints}
 * Fields: {fields} | Inputs: {inputs} | Gaps: {gaps}
 *
 * Build: cc -std=c11 -O2 replay.c -o replay
 * Skeleton only prints a JSON-ish request shell; fill compute_dynamic_fields and
 * parse MANIFEST.json with cJSON / yyjson before authorized live validation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {{
  const char *domain;
  const char *user_agent;
  const char *existing_token;
}} ReplayContext;

static const char *getenv_or(const char *key, const char *fallback) {{
  const char *value = getenv(key);
  return (value && value[0]) ? value : fallback;
}}

static char *load_manifest(const char *path) {{
  FILE *file = fopen(path, "rb");
  if (!file) {{
    return NULL;
  }}
  if (fseek(file, 0, SEEK_END) != 0) {{
    fclose(file);
    return NULL;
  }}
  long size = ftell(file);
  if (size < 0) {{
    fclose(file);
    return NULL;
  }}
  rewind(file);
  char *buffer = (char *)malloc((size_t)size + 1);
  if (!buffer) {{
    fclose(file);
    return NULL;
  }}
  size_t read = fread(buffer, 1, (size_t)size, file);
  fclose(file);
  buffer[read] = '\0';
  return buffer;
}}

/* Implement from authorized ShowNet capture evidence.
 * Return 0 on success and write key=value pairs into out (caller-owned).
 */
static int compute_dynamic_fields(const ReplayContext *ctx, const char *manifest_json,
                                  char *out, size_t out_len) {{
  (void)ctx;
  (void)manifest_json;
  if (out && out_len) {{
    out[0] = '\0';
  }}
  fprintf(stderr,
          "Fill compute_dynamic_fields from capture evidence before live validation\n");
  return -1;
}}

static int build_request(const ReplayContext *ctx) {{
  char *manifest = load_manifest("MANIFEST.json");
  if (!manifest) {{
    fprintf(stderr, "failed to open MANIFEST.json\n");
    return -1;
  }}
  char dynamic[4096];
  if (compute_dynamic_fields(ctx, manifest, dynamic, sizeof(dynamic)) != 0) {{
    free(manifest);
    return -1;
  }}
  printf("{{\n");
  printf("  \"domain\": \"%s\",\n", ctx->domain);
  printf("  \"userAgent\": \"%s\",\n", ctx->user_agent);
  printf("  \"existingToken\": \"%s\",\n",
         ctx->existing_token ? ctx->existing_token : "");
  printf("  \"adapter\": \"{adapter}\",\n");
  printf("  \"evidenceHash\": \"{hash}\",\n");
  printf("  \"dynamic\": \"%s\",\n", dynamic);
  printf("  \"note\": \"Parse matchedRequests from MANIFEST.json before HTTP send\"\n");
  printf("}}\n");
  free(manifest);
  return 0;
}}

int main(void) {{
  ReplayContext ctx = {{
      getenv_or("SHOWNET_DOMAIN", "example.com"),
      getenv_or("SHOWNET_UA", "ShowNet-Replay/1.0"),
      getenv_or("SHOWNET_EXISTING_TOKEN", ""),
  }};
  return build_request(&ctx) == 0 ? 0 : 1;
}}
"##
        ),
        "zig" => format!(
            r##"//! ShowNet algorithm replay skeleton - runtime credentials supplied by caller.
//! Adapter: {adapter} ({vendor}) | hash: {hash}
//! PoW: {pow} | signal: {signal}
//! Endpoints:
{endpoints}
//! Fields: {fields} | Inputs: {inputs} | Gaps: {gaps}
//!
//! Build: zig build-exe replay.zig -O ReleaseSafe
//! Parse MANIFEST.json with std.json after implementing computeDynamicFields.

const std = @import("std");

pub const ReplayContext = struct {{
    domain: []const u8,
    user_agent: []const u8,
    existing_token: ?[]const u8 = null,
}};

pub fn loadManifest(allocator: std.mem.Allocator, path: []const u8) ![]u8 {{
    return try std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024 * 1024);
}}

/// Implement from authorized ShowNet Hook / crypto evidence.
pub fn computeDynamicFields(
    allocator: std.mem.Allocator,
    ctx: ReplayContext,
    manifest_json: []const u8,
) !std.StringHashMap([]const u8) {{
    _ = allocator;
    _ = ctx;
    _ = manifest_json;
    return error.NotImplemented;
}}

pub fn buildRequest(allocator: std.mem.Allocator, ctx: ReplayContext) ![]u8 {{
    const manifest = try loadManifest(allocator, "MANIFEST.json");
    defer allocator.free(manifest);
    var dynamic = computeDynamicFields(allocator, ctx, manifest) catch |err| {{
        if (err == error.NotImplemented) {{
            return error.NotImplemented;
        }}
        return err;
    }};
    defer {{
        var it = dynamic.iterator();
        while (it.next()) |entry| {{
            allocator.free(entry.value_ptr.*);
        }}
        dynamic.deinit();
    }};

    return try std.fmt.allocPrint(
        allocator,
        "{{\"domain\":\"{{s}}\",\"userAgent\":\"{{s}}\",\"adapter\":\"{adapter}\",\"evidenceHash\":\"{hash}\",\"note\":\"parse matchedRequests from MANIFEST.json\"}}",
        .{{ ctx.domain, ctx.user_agent }},
    );
}}

pub fn main() !void {{
    var gpa = std.heap.GeneralPurposeAllocator(.{{}}){{}};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const domain = std.posix.getenv("SHOWNET_DOMAIN") orelse "example.com";
    const ua = std.posix.getenv("SHOWNET_UA") orelse "ShowNet-Replay/1.0";
    const ctx = ReplayContext{{
        .domain = domain,
        .user_agent = ua,
        .existing_token = std.posix.getenv("SHOWNET_EXISTING_TOKEN"),
    }};

    const request = buildRequest(allocator, ctx) catch |err| {{
        if (err == error.NotImplemented) {{
            std.debug.print("Fill computeDynamicFields from capture evidence before live validation\n", .{{}});
            return;
        }}
        return err;
    }};
    defer allocator.free(request);
    std.debug.print("{{s}}\n", .{{request}});
}}
"##
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
    let _ = BTreeSet::<String>::new();
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
        // Reconstructed helpers should appear as real functions, not pure empty stubs.
        assert!(
            replay.content.contains("def hmac_sha256_hex")
                || replay.content.contains("def solve_network_bandwidth")
                || replay.content.contains("def telemetry_payload")
        );
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
        // UI picks a parent folder; package is nested under a unique subdir.
        let package_dir = Path::new(&exported.directory);
        assert!(package_dir.exists());
        assert!(package_dir.starts_with(&parent));
        assert_ne!(package_dir, parent.as_path());
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
    fn builds_c_cpp_and_zig_replay_templates() {
        let storage = storage();
        let session = storage.create_session(Some("native-langs".into())).unwrap();
        let sid = session.id.clone();
        let mut sensor = base(&sid, "www.example.com", "/_bm/sensor");
        sensor.method = "POST".into();
        sensor.request_body = Some(r#"{"sensor_data":"1"}"#.into());
        sensor.request_headers = vec![HeaderEntry {
            name: "cookie".into(),
            value: "_abck=1; bm_sz=2".into(),
        }];
        storage.store_request(sensor).unwrap();

        assert_eq!(normalize_language("cpp").unwrap(), "c++");
        assert_eq!(normalize_language("cxx").unwrap(), "c++");
        assert_eq!(normalize_language("c11").unwrap(), "c");
        assert_eq!(normalize_language("ziglang").unwrap(), "zig");

        for (lang, filename, marker) in [
            ("c++", "replay.cpp", "compute_dynamic_fields"),
            ("cpp", "replay.cpp", "compute_dynamic_fields"),
            ("c", "replay.c", "compute_dynamic_fields"),
            ("zig", "replay.zig", "computeDynamicFields"),
        ] {
            let package = build_algorithm_replay(&storage, &sid, lang).unwrap();
            assert!(
                package.files.iter().any(|file| file.name == filename),
                "lang={lang} missing {filename}"
            );
            let replay = package
                .files
                .iter()
                .find(|file| file.role == "algorithm-replay")
                .unwrap_or_else(|| panic!("lang={lang} missing algorithm-replay file"));
            assert!(
                replay.content.contains(marker),
                "lang={lang} missing {marker}"
            );
            assert!(
                replay.content.contains("MANIFEST.json"),
                "lang={lang} should reference MANIFEST.json"
            );
            assert!(
                !replay.content.contains("aws-waf-token="),
                "lang={lang} leaked secret-like marker"
            );
        }
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
            ("rust", "replay.rs"),
            ("java", "Replay.java"),
            ("csharp", "Replay.cs"),
            ("c++", "replay.cpp"),
            ("c", "replay.c"),
            ("zig", "replay.zig"),
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
}
