//! Evidence-driven algorithm reconstruction used by algorithm replay packages.
//!
//! Goal: turn analysis reports + hooks + crypto snippets + protection schemas
//! into an explicit pipeline (not empty stubs). VMP / heavily protected JS is
//! classified as hybrid/trace-driven rather than fake static decompilation.

use crate::models::{BrowserHookEvent, CryptoCodeSnippet, RequestRecord};
use crate::signature_adapter::SignatureAdapterHarness;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmStep {
    pub id: String,
    pub name: String,
    pub status: String,
    pub formula: String,
    pub evidence: Vec<String>,
    pub implementation_hint: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookTraceSummary {
    pub sequence: i64,
    pub kind: String,
    pub name: String,
    pub algorithm_hint: String,
    pub has_input: bool,
    pub has_output: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmReconstruction {
    pub reconstruction_mode: String,
    pub confidence: String,
    pub algorithms: Vec<String>,
    pub pipeline: Vec<AlgorithmStep>,
    pub vmp_or_custom_vm: bool,
    pub vmp_indicators: Vec<String>,
    pub hook_traces: Vec<HookTraceSummary>,
    pub snippet_algorithms: Vec<String>,
    pub dynamic_fields: Vec<String>,
    pub required_env: Vec<String>,
    pub test_field_shapes: Vec<String>,
    pub report_spec_embedded: bool,
    pub can_emit_runnable_crypto: bool,
    pub notes: Vec<String>,
}

pub fn reconstruct(
    report_markdown: &str,
    harness: &SignatureAdapterHarness,
    protocol_schemas: &Value,
    provider_candidates: &Value,
    hooks: &[BrowserHookEvent],
    snippets: &[(i64, CryptoCodeSnippet)],
    matched_requests: &[RequestRecord],
) -> AlgorithmReconstruction {
    if let Some(embedded) = parse_embedded_algorithm_spec(report_markdown) {
        return merge_embedded_with_evidence(
            embedded,
            harness,
            protocol_schemas,
            hooks,
            snippets,
            matched_requests,
        );
    }

    let mut algorithms = BTreeSet::new();
    for algo in &harness.crypto_algorithms {
        algorithms.insert(normalize_algo(algo));
    }
    for (_, snippet) in snippets {
        for algo in &snippet.algorithms {
            algorithms.insert(normalize_algo(algo));
        }
    }

    let report_lower = report_markdown.to_ascii_lowercase();
    for token in [
        "hmac-sha256",
        "hmac_sha256",
        "sha-256",
        "sha256",
        "aes-gcm",
        "aes_gcm",
        "scrypt",
        "networkbandwidth",
        "md5",
        "rsa",
        "pbkdf2",
    ] {
        if report_lower.contains(token) {
            algorithms.insert(normalize_algo(token));
        }
    }

    let vmp_indicators = detect_vmp_indicators(report_markdown, snippets);
    let vmp_or_custom_vm = !vmp_indicators.is_empty();

    let mut pipeline = Vec::new();
    let mut required_env = BTreeSet::new();
    let mut step_id = 1u32;

    // Business / generic signature
    if algorithms.iter().any(|a| a.contains("HMAC"))
        || harness
            .dynamic_fields
            .iter()
            .any(|f| f.to_ascii_lowercase().contains("signature") || f.contains("x-signature"))
        || report_lower.contains("x-signature")
        || report_lower.contains("hmac")
    {
        pipeline.push(step(
            &mut step_id,
            "compose_sign_base",
            "reconstructed",
            "base = path + ':' + requestTime + ':' + clientMachineId + ':' + nonce [+ optional business fields]",
            vec![
                "report pseudocode / header matrix".into(),
                "dynamicFields signature markers".into(),
            ],
            "Implement string composition exactly as report evidence; do not invent field order.",
        ));
        pipeline.push(step(
            &mut step_id,
            "hmac_sign",
            "reconstructed",
            "signature = hex(HMAC_SHA256(key=env.SHOWNET_HMAC_SECRET, msg=base))",
            vec!["algorithm evidence HMAC".into()],
            "Secret only from env; never hard-code production keys.",
        ));
        required_env.insert("SHOWNET_HMAC_SECRET".into());
    }

    // AWS WAF / protection protocol
    let pow_type = protocol_schemas
        .pointer("/pow/challengeType")
        .and_then(Value::as_str)
        .unwrap_or("");
    let has_aws = provider_candidates
        .as_array()
        .into_iter()
        .flatten()
        .any(|item| item["provider"].as_str() == Some("AWS WAF"))
        || harness.adapter_id.contains("aws-waf");

    if has_aws || !pow_type.is_empty() {
        pipeline.push(step(
            &mut step_id,
            "load_challenge_input",
            "reconstructed",
            "decode challenge.input (base64 JSON) → difficulty, challenge_type, region, attempt_id",
            vec!["protocolSchemas.challengeSubmit / pow".into()],
            "Use captured challenge input shape; refresh from live challenge.js only when authorized.",
        ));
        if pow_type.eq_ignore_ascii_case("NetworkBandwidth") || pow_type.is_empty() && has_aws {
            let status = if pow_type.eq_ignore_ascii_case("NetworkBandwidth") {
                "reconstructed"
            } else {
                "partial"
            };
            pipeline.push(step(
                &mut step_id,
                "pow_network_bandwidth",
                status,
                "solution = base64(zeros(size_for_difficulty)); sizes {{1:1KiB,2:10KiB,3:100KiB,4:1MiB,5:10MiB}}",
                vec!["protocolSchemas.pow.challengeType".into()],
                "Only emit NetworkBandwidth solver when challenge_type is observed.",
            ));
        }
        if pow_type.to_ascii_lowercase().contains("scrypt")
            || algorithms.iter().any(|a| a.contains("scrypt"))
        {
            pipeline.push(step(
                &mut step_id,
                "pow_scrypt",
                "partial",
                "nonce s.t. leading_zero_bits(scrypt(input+checksum+nonce, salt=checksum, n=memory)) >= difficulty",
                vec!["script/static scrypt markers".into()],
                "Parameters must come from capture; do not guess N/r/p.",
            ));
        }
        if algorithms
            .iter()
            .any(|a| a.contains("SHA-256") || a.contains("SHA256"))
            && (pow_type.to_ascii_lowercase().contains("sha")
                || report_lower.contains("hashcash")
                || report_lower.contains("leading zero"))
        {
            pipeline.push(step(
                &mut step_id,
                "pow_sha256",
                "partial",
                "nonce s.t. leading_zero_bits(SHA256(input+checksum+nonce)) >= difficulty",
                vec!["PoW markers".into()],
                "Confirm bit-count semantics from evidence before live use.",
            ));
        }
    }

    if algorithms
        .iter()
        .any(|a| a.contains("AES-GCM") || a.contains("AES_GCM"))
        || report_lower.contains("aes-gcm")
        || protocol_schemas
            .pointer("/signals/encryptedFrameFormat")
            .and_then(Value::as_str)
            .is_some()
    {
        let key_ready = false; // key recovery is non-goal without decoder
        pipeline.push(step(
            &mut step_id,
            "encrypt_signals_aes_gcm",
            if key_ready { "reconstructed" } else { "partial" },
            "plaintext = CRC32_hex8(json) + '#' + compact_json; ct = AES-256-GCM(key, nonce=12B, plaintext); frame ~= nonce::tag::ciphertext variants",
            vec![
                "AES-GCM static markers".into(),
                "signals encrypted frame format".into(),
            ],
            "Key from env SHOWNET_AES_KEY_HEX when recovered offline; otherwise leave partial and use hook traces.",
        ));
        required_env.insert("SHOWNET_AES_KEY_HEX".into());
    }

    if protocol_schemas
        .pointer("/telemetry/sessionChain")
        .and_then(Value::as_bool)
        == Some(true)
        || has_aws
    {
        pipeline.push(step(
            &mut step_id,
            "telemetry_session_chain",
            "reconstructed",
            "awswaf_session_storage starts as null/\"null\"; echo server value; honor next_interval",
            vec!["protocolSchemas.telemetry".into()],
            "Replay chain order from orderedProtectionChain.",
        ));
    }

    // Hook traces always valuable for VMP / custom
    let hook_traces = hooks
        .iter()
        .filter(|hook| {
            let blob = format!(
                "{} {} {}",
                hook.kind,
                hook.name,
                hook.stack.as_deref().unwrap_or_default()
            )
            .to_ascii_lowercase();
            blob.contains("crypto")
                || blob.contains("subtle")
                || blob.contains("hmac")
                || blob.contains("aes")
                || blob.contains("sign")
                || blob.contains("digest")
                || blob.contains("encrypt")
                || hook.kind.to_ascii_lowercase().contains("crypto")
        })
        .take(40)
        .map(|hook| HookTraceSummary {
            sequence: hook.sequence,
            kind: hook.kind.clone(),
            name: hook.name.clone(),
            algorithm_hint: infer_hook_algo(hook),
            has_input: !hook.input.is_null(),
            has_output: !hook.output.is_null(),
        })
        .collect::<Vec<_>>();

    if vmp_or_custom_vm {
        pipeline.push(step(
            &mut step_id,
            "vmp_or_custom_vm_strategy",
            "trace_driven",
            "Static full decompilation unavailable; use Hook I/O traces + residual constants + protocol field shapes",
            vmp_indicators.clone(),
            "Do not invent VM bytecode semantics. Prefer runtime-assisted capture of intermediate values in authorized lab.",
        ));
    }

    if pipeline.is_empty() {
        pipeline.push(step(
            &mut step_id,
            "insufficient_evidence",
            "insufficient",
            "No reconstructable crypto/protocol pipeline yet",
            vec!["session evidence incomplete".into()],
            "Re-run crypto/dynamic analysis and ensure hooks capture crypto.subtle / signature calls.",
        ));
    }

    let reconstructed = pipeline
        .iter()
        .filter(|step| step.status == "reconstructed")
        .count();
    let partial = pipeline
        .iter()
        .filter(|step| step.status == "partial" || step.status == "trace_driven")
        .count();
    let can_emit_runnable_crypto = reconstructed > 0
        && pipeline.iter().any(|step| {
            matches!(
                step.name.as_str(),
                "hmac_sign"
                    | "pow_network_bandwidth"
                    | "telemetry_session_chain"
                    | "compose_sign_base"
            )
        });

    let reconstruction_mode = if vmp_or_custom_vm {
        "vmp_hybrid"
    } else if can_emit_runnable_crypto && partial == 0 {
        "pure_reconstructed"
    } else if can_emit_runnable_crypto {
        "partial_reconstructed"
    } else if !hook_traces.is_empty() {
        "hook_trace"
    } else {
        "insufficient"
    };

    let confidence = if reconstructed >= 3 && !vmp_or_custom_vm {
        "high"
    } else if reconstructed >= 1 || can_emit_runnable_crypto {
        "medium"
    } else {
        "low"
    };

    let mut test_field_shapes = BTreeSet::new();
    for field in &harness.dynamic_fields {
        test_field_shapes.insert(format!("dynamicField:{field}"));
    }
    for request in matched_requests.iter().take(20) {
        for header in &request.request_headers {
            let name = header.name.to_ascii_lowercase();
            if name.contains("sign")
                || name.contains("token")
                || name.contains("nonce")
                || name.contains("device")
                || name.contains("waf")
            {
                test_field_shapes.insert(format!(
                    "header:{}:len≈{}",
                    header.name,
                    header.value.len()
                ));
            }
        }
    }

    let mut notes = vec![
        "Reconstruction prefers evidence over generic WAF encyclopedias.".into(),
        "Runnable code is emitted only for steps marked reconstructed; partial steps need env keys or more hooks.".into(),
    ];
    if vmp_or_custom_vm {
        notes.push(
            "VMP/custom-VM markers detected: static full algorithm dump is not claimed; package uses hybrid/trace strategy."
                .into(),
        );
    }
    if report_markdown.trim().is_empty() || report_markdown.contains("尚无 AI 分析报告") {
        notes.push(
            "No AI report body — reconstruction is deterministic-evidence only. Re-run Agent analysis for richer formulas."
                .into(),
        );
    }

    required_env.insert("SHOWNET_DOMAIN".into());
    required_env.insert("SHOWNET_UA".into());

    AlgorithmReconstruction {
        reconstruction_mode: reconstruction_mode.into(),
        confidence: confidence.into(),
        algorithms: algorithms.into_iter().collect(),
        pipeline,
        vmp_or_custom_vm,
        vmp_indicators,
        hook_traces,
        snippet_algorithms: snippets
            .iter()
            .flat_map(|(_, snippet)| snippet.algorithms.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        dynamic_fields: harness.dynamic_fields.clone(),
        required_env: required_env.into_iter().collect(),
        test_field_shapes: test_field_shapes.into_iter().collect(),
        report_spec_embedded: false,
        can_emit_runnable_crypto,
        notes,
    }
}

pub fn render_reconstruction_markdown(spec: &AlgorithmReconstruction) -> String {
    let mut out = String::from("# Algorithm Reconstruction\n\n");
    out.push_str(&format!(
        "- mode: `{}`\n- confidence: `{}`\n- VMP/custom VM: `{}`\n- runnable crypto steps: `{}`\n\n",
        spec.reconstruction_mode,
        spec.confidence,
        spec.vmp_or_custom_vm,
        spec.can_emit_runnable_crypto
    ));
    out.push_str("## Algorithms\n\n");
    if spec.algorithms.is_empty() {
        out.push_str("- (none classified yet)\n");
    } else {
        for algo in &spec.algorithms {
            out.push_str(&format!("- `{algo}`\n"));
        }
    }
    out.push_str("\n## Pipeline\n\n");
    for step in &spec.pipeline {
        out.push_str(&format!(
            "### {}. {} (`{}`)\n\n- formula: `{}`\n- hint: {}\n- evidence:\n",
            step.id, step.name, step.status, step.formula, step.implementation_hint
        ));
        for item in &step.evidence {
            out.push_str(&format!("  - {item}\n"));
        }
        out.push('\n');
    }
    if !spec.vmp_indicators.is_empty() {
        out.push_str("## VMP / custom protection indicators\n\n");
        for item in &spec.vmp_indicators {
            out.push_str(&format!("- {item}\n"));
        }
        out.push('\n');
    }
    if !spec.hook_traces.is_empty() {
        out.push_str("## Hook traces (for VMP / residual reconstruction)\n\n");
        for hook in &spec.hook_traces {
            out.push_str(&format!(
                "- #{} `{}` / `{}` algo≈`{}` in={} out={}\n",
                hook.sequence,
                hook.kind,
                hook.name,
                hook.algorithm_hint,
                hook.has_input,
                hook.has_output
            ));
        }
        out.push('\n');
    }
    out.push_str("## Required environment\n\n");
    for env in &spec.required_env {
        out.push_str(&format!("- `{env}`\n"));
    }
    out.push_str("\n## Notes\n\n");
    for note in &spec.notes {
        out.push_str(&format!("- {note}\n"));
    }
    out.push_str(
        "\n## Agent contract\n\nReports should embed a fenced `algorithm-spec` JSON block so replay can materialize exact formulas. Without it, ShowNet synthesizes this reconstruction from deterministic evidence only.\n",
    );
    out
}

fn parse_embedded_algorithm_spec(report: &str) -> Option<Value> {
    // ```algorithm-spec ... ```
    let marker = "```algorithm-spec";
    let start = report.find(marker)?;
    let after = &report[start + marker.len()..];
    let end = after.find("```")?;
    let body = after[..end].trim();
    serde_json::from_str(body).ok()
}

fn merge_embedded_with_evidence(
    embedded: Value,
    harness: &SignatureAdapterHarness,
    protocol_schemas: &Value,
    hooks: &[BrowserHookEvent],
    snippets: &[(i64, CryptoCodeSnippet)],
    matched_requests: &[RequestRecord],
) -> AlgorithmReconstruction {
    let mut base = reconstruct(
        "",
        harness,
        protocol_schemas,
        &json!([]),
        hooks,
        snippets,
        matched_requests,
    );
    base.report_spec_embedded = true;
    if let Some(mode) = embedded.get("reconstructionMode").and_then(Value::as_str) {
        base.reconstruction_mode = mode.to_string();
    }
    if let Some(confidence) = embedded.get("confidence").and_then(Value::as_str) {
        base.confidence = confidence.to_string();
    }
    if let Some(steps) = embedded.get("pipeline").and_then(Value::as_array) {
        let mut pipeline = Vec::new();
        for (index, step_val) in steps.iter().enumerate() {
            pipeline.push(AlgorithmStep {
                id: step_val
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or(&format!("{}", index + 1))
                    .to_string(),
                name: step_val
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("step")
                    .to_string(),
                status: step_val
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("partial")
                    .to_string(),
                formula: step_val
                    .get("formula")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                evidence: step_val
                    .get("evidence")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
                implementation_hint: step_val
                    .get("implementationHint")
                    .or_else(|| step_val.get("hint"))
                    .and_then(Value::as_str)
                    .unwrap_or("from embedded algorithm-spec")
                    .to_string(),
            });
        }
        if !pipeline.is_empty() {
            base.pipeline = pipeline;
            base.can_emit_runnable_crypto = base
                .pipeline
                .iter()
                .any(|step| step.status == "reconstructed");
        }
    }
    if let Some(algos) = embedded.get("algorithms").and_then(Value::as_array) {
        for algo in algos.iter().filter_map(Value::as_str) {
            if !base.algorithms.iter().any(|item| item == algo) {
                base.algorithms.push(algo.to_string());
            }
        }
    }
    base.notes.insert(
        0,
        "Embedded `algorithm-spec` from analysis report was applied and merged with session evidence."
            .into(),
    );
    base
}

fn detect_vmp_indicators(report: &str, snippets: &[(i64, CryptoCodeSnippet)]) -> Vec<String> {
    let mut hits = BTreeSet::new();
    let blob = {
        let mut text = report.to_ascii_lowercase();
        for (_, snippet) in snippets {
            text.push('\n');
            text.push_str(&snippet.code.to_ascii_lowercase());
        }
        text
    };
    for marker in [
        "vmp",
        "virtual machine",
        "vm protect",
        "bytecode",
        "opcode dispatcher",
        "custom vm",
        "jsjiami",
        "obfuscator.io",
        "control flow flattening",
        "string array rotation",
        "a0_0x",
        "while(!![])",
    ] {
        if blob.contains(marker) {
            hits.insert(format!("marker:{marker}"));
        }
    }
    hits.into_iter().collect()
}

fn normalize_algo(value: &str) -> String {
    let upper = value.trim().to_ascii_uppercase().replace('_', "-");
    match upper.as_str() {
        "HMACSHA256" | "HMAC-SHA-256" => "HMAC-SHA256".into(),
        "SHA256" | "SHA-256" => "SHA-256".into(),
        "AESGCM" | "AES-GCM" => "AES-GCM".into(),
        "NETWORKBANDWIDTH" => "NetworkBandwidth".into(),
        other => other.to_string(),
    }
}

fn step(
    id: &mut u32,
    name: &str,
    status: &str,
    formula: &str,
    evidence: Vec<String>,
    hint: &str,
) -> AlgorithmStep {
    let step = AlgorithmStep {
        id: id.to_string(),
        name: name.into(),
        status: status.into(),
        formula: formula.into(),
        evidence,
        implementation_hint: hint.into(),
    };
    *id += 1;
    step
}

fn infer_hook_algo(hook: &BrowserHookEvent) -> String {
    let blob = format!("{} {}", hook.kind, hook.name).to_ascii_lowercase();
    if blob.contains("hmac") {
        "HMAC".into()
    } else if blob.contains("aes") || blob.contains("encrypt") {
        "AES".into()
    } else if blob.contains("digest") || blob.contains("sha") {
        "SHA".into()
    } else if blob.contains("sign") {
        "sign".into()
    } else {
        "unknown".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_adapter::{SignatureAdapterHarness, SignatureRequestEvidence};

    fn harness() -> SignatureAdapterHarness {
        SignatureAdapterHarness {
            adapter_id: "generic-dynamic-signature".into(),
            adapter_version: "1.0.0".into(),
            vendor: "Generic".into(),
            confidence: "medium".into(),
            evidence_hash: "abc".into(),
            matched_requests: vec![SignatureRequestEvidence {
                request_id: "r1".into(),
                order: 1,
                method: "POST".into(),
                url: "https://api.example.com/booking".into(),
                status: 200,
                protocol: "h2".into(),
            }],
            dynamic_fields: vec!["x-signature".into(), "x-request-nonce".into()],
            cookie_names: vec![],
            hook_names: vec![],
            crypto_algorithms: vec!["HMAC-SHA256".into()],
            fingerprint_dependencies: vec![],
            required_inputs: vec!["timestamp".into()],
            evidence_gaps: vec![],
            language: "javascript".into(),
            code: String::new(),
        }
    }

    #[test]
    fn reconstructs_hmac_pipeline_from_algorithms() {
        let spec = reconstruct(
            "业务签名使用 HMAC-SHA256，X-Signature = hex(HMAC(...))",
            &harness(),
            &json!({}),
            &json!([]),
            &[],
            &[],
            &[],
        );
        assert!(spec.algorithms.iter().any(|a| a.contains("HMAC")));
        assert!(spec.pipeline.iter().any(|s| s.name == "hmac_sign"));
        assert!(spec.can_emit_runnable_crypto);
        assert_ne!(spec.reconstruction_mode, "insufficient");
    }

    #[test]
    fn detects_vmp_and_marks_hybrid() {
        let snippets = [(
            1,
            CryptoCodeSnippet {
                ordinal: 1,
                kind: "function".into(),
                name: Some("vm".into()),
                algorithms: vec![],
                start_line: 1,
                end_line: 10,
                code: "while(!![]){ /* vmp bytecode dispatcher */ }".into(),
                truncated: false,
                source_truncated: false,
            },
        )];
        let spec = reconstruct("", &harness(), &json!({}), &json!([]), &[], &snippets, &[]);
        assert!(spec.vmp_or_custom_vm);
        assert_eq!(spec.reconstruction_mode, "vmp_hybrid");
    }

    #[test]
    fn prefers_embedded_algorithm_spec_from_report() {
        let report = r##"
# report
```algorithm-spec
{
  "reconstructionMode": "pure_reconstructed",
  "confidence": "high",
  "algorithms": ["HMAC-SHA256"],
  "pipeline": [
    {"id":"1","name":"hmac_sign","status":"reconstructed","formula":"HMAC_SHA256(path:time, secret)","evidence":["order-59"]}
  ]
}
```
"##;
        let spec = reconstruct(report, &harness(), &json!({}), &json!([]), &[], &[], &[]);
        assert!(spec.report_spec_embedded);
        assert_eq!(spec.pipeline[0].name, "hmac_sign");
        assert_eq!(spec.pipeline[0].formula, "HMAC_SHA256(path:time, secret)");
    }
}
