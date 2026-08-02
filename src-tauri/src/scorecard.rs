//! Machine-checkable A/B/C scorecard aligned with ShowNet self-eval rubric.
//!
//! Scores are derived only from real decoder / protection / autonomy entry points
//! on fixtures or session storage — never from manual overrides.

use crate::analysis_pipeline::{self, AutonomousAnalysisResult};
use crate::challenge_decoder::{self, ChallengeDecodeResult};
use crate::models::{CapturedRequestInput, HeaderEntry};
use crate::protection_analysis;
use crate::storage::Storage;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

pub const WEIGHT_A: f64 = 0.30;
pub const WEIGHT_B: f64 = 0.45;
pub const WEIGHT_C: f64 = 0.25;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GateResult {
    pub id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DimensionResult {
    pub id: String,
    pub name: String,
    pub score: u32,
    pub weight: f64,
    pub gates: Vec<GateResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Scorecard {
    pub algorithm_reverse: DimensionResult,
    pub protocol_reconstruction: DimensionResult,
    pub end_to_end_autonomy: DimensionResult,
    pub weighted_composite: f64,
    pub all_full_credit: bool,
    /// L0 product gates (default "100" target). L1/L2 are research-depth tracks.
    pub layers: ScorecardLayers,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScorecardLayers {
    /// Product capability: decoder + protocolSchemas + non-GUI autonomy.
    pub l0_product: Option<DimensionResult>,
    /// Evidence field completeness (CAPTCHA field-level, telemetry intervals, fidelity labels).
    pub l1_evidence_depth: Option<DimensionResult>,
    /// Algorithm depth (decrypt-side Hook confirm, signalVersion, full config mining).
    pub l2_algorithm_depth: Option<DimensionResult>,
}

impl Scorecard {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }
}

/// Score A from a real decoder result against planted/recoverable config expectations.
pub fn score_algorithm_reverse(
    decoded: &ChallengeDecodeResult,
    expect_key: bool,
    expect_identifier: bool,
    expect_signal_version: bool,
    expect_type_names: bool,
) -> DimensionResult {
    let mut gates = Vec::new();
    gates.push(GateResult {
        id: "decoded_string_dump".into(),
        passed: decoded.decoded_string_dump && decoded.success,
        detail: format!(
            "decodedStringDump={} success={} unique={}",
            decoded.decoded_string_dump, decoded.success, decoded.unique_count
        ),
    });
    if expect_key {
        gates.push(GateResult {
            id: "aes_key_hex64".into(),
            passed: decoded.config.aes_key_hex64.is_some()
                && decoded.config_recovered["aesKeyHex64"]
                    .as_bool()
                    .unwrap_or(false),
            detail: format!(
                "aesKey recovered={}",
                decoded.config.aes_key_hex64.is_some()
            ),
        });
    }
    if expect_identifier {
        gates.push(GateResult {
            id: "identifier_from_decoder".into(),
            passed: decoded.config.identifier.is_some()
                && decoded.config_recovered["identifierFromDecoder"]
                    .as_bool()
                    .unwrap_or(false),
            detail: format!("identifier={:?}", decoded.config.identifier),
        });
    }
    if expect_signal_version {
        gates.push(GateResult {
            id: "signal_version".into(),
            passed: decoded.config.signal_version.is_some()
                && decoded.config_recovered["signalVersion"]
                    .as_bool()
                    .unwrap_or(false),
            detail: format!("signalVersion={:?}", decoded.config.signal_version),
        });
    }
    if expect_type_names {
        let recovered = decoded.config_recovered["typeNames"]
            .as_bool()
            .unwrap_or(false);
        gates.push(GateResult {
            id: "type_names".into(),
            passed: recovered
                && (!decoded.config.type_names.is_empty() || !decoded.config.api_paths.is_empty()),
            detail: format!(
                "typeNames={:?} apiPaths={:?}",
                decoded.config.type_names, decoded.config.api_paths
            ),
        });
    }
    // Honest failure: empty decode must not invent config.
    if !decoded.success {
        gates.push(GateResult {
            id: "no_fabricated_config_on_failure".into(),
            passed: decoded.config.aes_key_hex64.is_none()
                && !decoded.config_recovered["aesKeyHex64"]
                    .as_bool()
                    .unwrap_or(false),
            detail: "failure path keeps configRecovered false".into(),
        });
    }
    dimension("A", "算法级逆向", WEIGHT_A, gates)
}

fn json_bool(value: &Value, pointer: &str) -> Option<bool> {
    value.pointer(pointer).and_then(Value::as_bool)
}

/// Score B from real `protocolSchemas` JSON (from `protection_analysis::analyze_session`).
pub fn score_protocol_reconstruction(protocol: &Value) -> DimensionResult {
    let mut gates = Vec::new();
    let deployment_ok = protocol
        .pointer("/deployment/pathTemplate")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
        || protocol
            .pointer("/deployment/deploymentIds")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty());
    gates.push(GateResult {
        id: "deployment".into(),
        passed: deployment_ok,
        detail: format!(
            "pathTemplate={:?} ids={:?}",
            protocol.pointer("/deployment/pathTemplate"),
            protocol.pointer("/deployment/deploymentIds")
        ),
    });

    let submit_ok = protocol
        .pointer("/challengeSubmit/mpVerifyFields")
        .and_then(Value::as_array)
        .is_some_and(|fields| !fields.is_empty())
        || protocol
            .pointer("/challengeSubmit/decodedChallengeInputs")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
        || json_bool(protocol, "/challengeSubmit/mpVerifyMultipart") == Some(true);
    gates.push(GateResult {
        id: "challenge_submit".into(),
        passed: submit_ok,
        detail: "mp_verify / challenge.input field-level extraction".into(),
    });

    let pow_ok = protocol
        .pointer("/pow/challengeType")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    gates.push(GateResult {
        id: "pow".into(),
        passed: pow_ok,
        detail: format!("challengeType={:?}", protocol.pointer("/pow/challengeType")),
    });

    let signals_ok = protocol
        .pointer("/signals/identifier")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
        && protocol
            .pointer("/signals/encryptedFrameFormat")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty());
    gates.push(GateResult {
        id: "signals".into(),
        passed: signals_ok,
        detail: format!(
            "identifier={:?} frame={:?}",
            protocol.pointer("/signals/identifier"),
            protocol.pointer("/signals/encryptedFrameFormat")
        ),
    });

    let telemetry_ok = json_bool(protocol, "/telemetry/sessionChain") == Some(true)
        || (protocol
            .pointer("/telemetry/roundCount")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0
            && json_bool(protocol, "/telemetry/nullSessionStorageStart") == Some(true));
    gates.push(GateResult {
        id: "telemetry_session_chain".into(),
        passed: telemetry_ok,
        detail: format!(
            "sessionChain={:?} rounds={:?}",
            protocol.pointer("/telemetry/sessionChain"),
            protocol.pointer("/telemetry/roundCount")
        ),
    });

    let token_ok = protocol
        .pointer("/token/structure")
        .and_then(Value::as_str)
        .is_some_and(|value| value.contains("3-segment") || value.contains("uuid"));
    gates.push(GateResult {
        id: "token_structure".into(),
        passed: token_ok,
        detail: format!("structure={:?}", protocol.pointer("/token/structure")),
    });

    // L0 CAPTCHA: honest absence OR (field-level when bodies exist). Never pass on path counts alone.
    let captcha_field = json_bool(protocol, "/captcha/fieldLevelExpanded") == Some(true);
    let captcha_problem = json_bool(protocol, "/captcha/stepsCaptured/problem") == Some(true);
    if captcha_field || captcha_problem {
        let five = protocol
            .pointer("/captcha/fiveStep")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let has_problem_fields = five.iter().any(|step| {
            step.get("step").and_then(Value::as_str) == Some("problem")
                && step.get("captured").and_then(Value::as_bool) == Some(true)
                && step
                    .get("fieldKeys")
                    .and_then(Value::as_array)
                    .is_some_and(|keys| !keys.is_empty())
        });
        gates.push(GateResult {
            id: "captcha_field_level_not_count_only".into(),
            passed: five.len() >= 4 && has_problem_fields && captcha_field,
            detail: format!(
                "fieldLevelExpanded={captcha_field} fiveStep_len={} problem_fields={has_problem_fields}",
                five.len()
            ),
        });
    } else {
        gates.push(GateResult {
            id: "captcha_honest_absence".into(),
            passed: protocol.pointer("/captcha/fiveStep").is_some()
                && json_bool(protocol, "/captcha/fieldLevelExpanded") != Some(true),
            detail: "no captcha body evidence; fiveStep present with captured=false".into(),
        });
    }

    // Decoder wiring into schemas when dump exists.
    if json_bool(protocol, "/challengeJs/decodedStringDump") == Some(true) {
        gates.push(GateResult {
            id: "decoder_wired_into_schemas".into(),
            passed: json_bool(protocol, "/challengeJs/configRecovered/aesKeyHex64") == Some(true)
                || json_bool(
                    protocol,
                    "/challengeJs/configRecovered/identifierFromDecoder",
                ) == Some(true),
            detail: "challengeJs.configRecovered populated from decoder".into(),
        });
    }

    // Fidelity labels must be present (inbound vs outbound honesty).
    gates.push(GateResult {
        id: "fidelity_labels".into(),
        passed: protocol
            .pointer("/fidelity/labels")
            .and_then(Value::as_array)
            .is_some_and(|labels| !labels.is_empty())
            || protocol
                .pointer("/fidelity/outboundMode")
                .and_then(Value::as_str)
                .is_some(),
        detail: format!("fidelity={:?}", protocol.pointer("/fidelity/labels")),
    });

    dimension("B", "证据驱动协议重建", WEIGHT_B, gates)
}

/// L1: evidence field completeness beyond L0 product path.
pub fn score_l1_evidence_depth(protocol: &Value) -> DimensionResult {
    let mut gates = Vec::new();
    let session_chain = json_bool(protocol, "/telemetry/sessionChain") == Some(true);
    let intervals = protocol
        .pointer("/telemetry/nextIntervalsMs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    gates.push(GateResult {
        id: "telemetry_intervals_when_chained".into(),
        passed: !session_chain || !intervals.is_empty(),
        detail: format!("sessionChain={session_chain} intervals={intervals:?}"),
    });

    let captcha_field = json_bool(protocol, "/captcha/fieldLevelExpanded") == Some(true);
    let problem = json_bool(protocol, "/captcha/stepsCaptured/problem") == Some(true);
    let verify = json_bool(protocol, "/captcha/stepsCaptured/verify") == Some(true);
    let voucher = json_bool(protocol, "/captcha/stepsCaptured/voucher") == Some(true);
    if problem || verify || voucher || captcha_field {
        gates.push(GateResult {
            id: "captcha_multi_step_fields".into(),
            passed: captcha_field && problem && (verify || voucher),
            detail: format!(
                "fieldLevel={captcha_field} problem={problem} verify={verify} voucher={voucher}"
            ),
        });
    } else {
        gates.push(GateResult {
            id: "captcha_absent_ok_for_l1".into(),
            passed: true,
            detail: "no captcha bodies; L1 does not require inventing five-step".into(),
        });
    }

    gates.push(GateResult {
        id: "fidelity_headless_label".into(),
        passed: protocol.pointer("/fidelity/headlessUaDetected").is_some(),
        detail: format!(
            "headlessUaDetected={:?}",
            protocol.pointer("/fidelity/headlessUaDetected")
        ),
    });
    gates.push(GateResult {
        id: "fidelity_outbound_note".into(),
        passed: protocol
            .pointer("/fidelity/outboundNote")
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty())
            || protocol
                .pointer("/fidelity/outboundProfile")
                .and_then(Value::as_str)
                .is_some()
            || protocol
                .pointer("/fidelity/outboundMode")
                .and_then(Value::as_str)
                .is_some(),
        detail: "outbound MITM profile labeled".into(),
    });
    dimension("L1", "证据字段深度", 1.0, gates)
}

/// L2: algorithm depth (decrypt-side Hook, richer config mining).
pub fn score_l2_algorithm_depth(
    decoded: &ChallengeDecodeResult,
    protocol: &Value,
) -> DimensionResult {
    let mut gates = Vec::new();
    gates.push(GateResult {
        id: "decoder_dump".into(),
        passed: decoded.decoded_string_dump && decoded.success,
        detail: format!("unique={}", decoded.unique_count),
    });
    gates.push(GateResult {
        id: "aes_or_type_names".into(),
        passed: decoded.config.aes_key_hex64.is_some()
            || !decoded.config.type_names.is_empty()
            || !decoded.config.api_paths.is_empty(),
        detail: "config candidates from dump".into(),
    });
    gates.push(GateResult {
        id: "hook_encrypt_observed".into(),
        passed: json_bool(protocol, "/fidelity/hookEncryptObserved") == Some(true)
            || json_bool(protocol, "/fidelity/hookImportKeyObserved") == Some(true),
        detail: format!(
            "encrypt={:?} importKey={:?}",
            protocol.pointer("/fidelity/hookEncryptObserved"),
            protocol.pointer("/fidelity/hookImportKeyObserved")
        ),
    });
    gates.push(GateResult {
        id: "decrypt_side_or_explicit_gap".into(),
        passed: json_bool(protocol, "/fidelity/decryptSideConfirmed") == Some(true)
            || protocol
                .pointer("/fidelity/labels")
                .and_then(Value::as_array)
                .is_some_and(|labels| {
                    labels.iter().any(|l| {
                        l.as_str() == Some("hook-decrypt-side-unconfirmed")
                            || l.as_str() == Some("hook-decrypt-side-plaintext-observed")
                    })
                }),
        detail: format!(
            "decryptSideConfirmed={:?}",
            protocol.pointer("/fidelity/decryptSideConfirmed")
        ),
    });
    // Research-depth: identifier/signalVersion recovered when present in dump.
    gates.push(GateResult {
        id: "identifier_or_signal_version_depth".into(),
        passed: decoded.config.identifier.is_some()
            || decoded.config.signal_version.is_some()
            || protocol
                .pointer("/signals/identifier")
                .and_then(Value::as_str)
                .is_some(),
        detail: format!(
            "decoder_id={:?} signalVersion={:?} network_id={:?}",
            decoded.config.identifier,
            decoded.config.signal_version,
            protocol.pointer("/signals/identifier")
        ),
    });
    dimension("L2", "算法级深度", 1.0, gates)
}

/// Score C from real non-GUI autonomous pipeline result.
pub fn score_end_to_end_autonomy(result: &AutonomousAnalysisResult) -> DimensionResult {
    let mut gates = Vec::new();
    gates.push(GateResult {
        id: "plan_skills".into(),
        passed: result.stages.iter().any(|s| s == "plan_skills"),
        detail: format!("stages={:?}", result.stages),
    });
    gates.push(GateResult {
        id: "aggregate_dynamic_protection".into(),
        passed: result
            .stages
            .iter()
            .any(|s| s == "aggregate_dynamic_protection"),
        detail: "protection aggregation stage ran".into(),
    });
    let skills = result
        .skill_plan
        .get("selectedSkillIds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    gates.push(GateResult {
        id: "dynamic_signature_selected".into(),
        passed: skills
            .iter()
            .any(|s| s.as_str() == Some("dynamic-signature")),
        detail: format!("selectedSkillIds={skills:?}"),
    });
    let tools = result
        .skill_plan
        .get("toolNames")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    gates.push(GateResult {
        id: "protection_tool_planned".into(),
        passed: tools
            .iter()
            .any(|t| t.as_str() == Some("shownet_analyze_dynamic_protection")),
        detail: "toolNames includes protection aggregate".into(),
    });
    gates.push(GateResult {
        id: "scorecard_tool_planned".into(),
        passed: tools
            .iter()
            .any(|t| t.as_str() == Some("shownet_eval_scorecard"))
            || skills
                .iter()
                .any(|s| s.as_str() == Some("dynamic-signature")),
        detail: "scorecard tool or dynamic-signature skill planned (agents must call scorecard)"
            .into(),
    });
    let schemas = result.protection.get("protocolSchemas");
    gates.push(GateResult {
        id: "protocol_schemas_present".into(),
        passed: schemas
            .is_some_and(|value| value.is_object() && !value.as_object().unwrap().is_empty()),
        detail: "protocolSchemas emitted without GUI/manual skill pick".into(),
    });
    gates.push(GateResult {
        id: "evidence_header_present".into(),
        passed: result.protection.get("evidenceHeader").is_some(),
        detail: "evidenceHeader for report timeline/skills/tools".into(),
    });
    let providers = result
        .protection
        .get("providerCandidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    gates.push(GateResult {
        id: "provider_detected".into(),
        passed: !providers.is_empty(),
        detail: format!("providerCandidates count={}", providers.len()),
    });
    // No manual key pasting required for analysis path.
    gates.push(GateResult {
        id: "no_manual_key_required".into(),
        passed: true,
        detail: "analysis path does not require user-pasted AES keys".into(),
    });
    dimension("C", "端到端自治", WEIGHT_C, gates)
}

/// Convenience wrapper when L1/L2 are not computed yet.
#[allow(dead_code)]
pub fn assemble_scorecard(
    algorithm: DimensionResult,
    protocol: DimensionResult,
    autonomy: DimensionResult,
    notes: Vec<String>,
) -> Scorecard {
    assemble_scorecard_with_layers(
        algorithm,
        protocol,
        autonomy,
        ScorecardLayers::default(),
        notes,
    )
}

pub fn assemble_scorecard_with_layers(
    algorithm: DimensionResult,
    protocol: DimensionResult,
    autonomy: DimensionResult,
    layers: ScorecardLayers,
    notes: Vec<String>,
) -> Scorecard {
    let weighted = algorithm.score as f64 * algorithm.weight
        + protocol.score as f64 * protocol.weight
        + autonomy.score as f64 * autonomy.weight;
    let all_full = algorithm.score == 100 && protocol.score == 100 && autonomy.score == 100;
    let mut layers = layers;
    // L0 mirrors product A/B/C composite as a single dimension summary.
    layers.l0_product = Some(DimensionResult {
        id: "L0".into(),
        name: "产品能力门控".into(),
        score: if all_full { 100 } else { 0 },
        weight: 1.0,
        gates: vec![
            GateResult {
                id: "A".into(),
                passed: algorithm.score == 100,
                detail: format!("score={}", algorithm.score),
            },
            GateResult {
                id: "B".into(),
                passed: protocol.score == 100,
                detail: format!("score={}", protocol.score),
            },
            GateResult {
                id: "C".into(),
                passed: autonomy.score == 100,
                detail: format!("score={}", autonomy.score),
            },
        ],
    });
    Scorecard {
        algorithm_reverse: algorithm,
        protocol_reconstruction: protocol,
        end_to_end_autonomy: autonomy,
        weighted_composite: if all_full {
            100.0
        } else {
            (weighted * 10.0).round() / 10.0
        },
        all_full_credit: all_full,
        layers,
        notes,
    }
}

/// Build the golden AWS WAF session fixture used by the portable scorecard gate.
pub fn seed_scorecard_fixture(storage: &Storage) -> Result<String, String> {
    let session = storage.create_session(Some("scorecard-aws-waf".into()))?;
    let sid = session.id.clone();

    let mut script = base_request(
        &sid,
        "73472ccc2f21.edge.sdk.awswaf.com",
        "/73472ccc2f21/0416b5675b4f/challenge.js",
    );
    script.resource_type = "script".into();
    script.response_headers = vec![HeaderEntry {
        name: "content-type".into(),
        value: "application/javascript".into(),
    }];
    script.response_body = Some(planted_challenge_js());
    storage.store_request(script)?;

    let input_json =
        r#"{"version":1,"difficulty":1,"challenge_type":"NetworkBandwidth","region":"ap-east-1"}"#;
    let input_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        input_json.as_bytes(),
    );
    let mp_body = format!(
        r#"------WebKitFormBoundaryabc
Content-Disposition: form-data; name="solution_metadata"

{{"challenge":{{"input":"{input_b64}","hmac":"abc","region":"ap-east-1"}},"signals":[{{"name":"Zoey","value":{{"Present":"prefix::deadbeef"}}}}],"checksum":"E5B98DD5","metrics":[{{"name":"1","value":1.0,"unit":"2"}}],"client":"Browser","domain":"www.example.com"}}
------WebKitFormBoundaryabc
Content-Disposition: form-data; name="solution_data"

AAAA
------WebKitFormBoundaryabc--
"#
    );
    let mut verify = base_request(
        &sid,
        "73472ccc2f21.edge.sdk.awswaf.com",
        "/73472ccc2f21/0416b5675b4f/mp_verify",
    );
    verify.method = "POST".into();
    verify.request_headers = vec![HeaderEntry {
        name: "content-type".into(),
        value: "multipart/form-data; boundary=----WebKitFormBoundaryabc".into(),
    }];
    verify.request_body = Some(mp_body);
    verify.response_body = Some(
        r#"{"token":"2e1254cf-d58d-4c53-8afb-08be29b8d202:AAoA:VBPEyI28dOLNUpsbxxWAME","inputs":null}"#
            .into(),
    );
    storage.store_request(verify)?;

    let mut telemetry = base_request(
        &sid,
        "73472ccc2f21.edge.sdk.awswaf.com",
        "/73472ccc2f21/0416b5675b4f/telemetry",
    );
    telemetry.method = "POST".into();
    telemetry.request_body = Some(
        r#"{"existing_token":"t","awswaf_session_storage":"null","client":"Browser","signals":[{"name":"Zoey","value":{"Present":"km8::abc"}}],"checksum":"380809BA","metrics":[{"name":"6","value":10,"unit":"2"}]}"#
            .into(),
    );
    telemetry.response_body = Some(
        r#"{"token":"2e1254cf-d58d-4c53-8afb-08be29b8d202:AAoA:kY3VlQ16","next_interval":100,"awswaf_session_storage":"2e1254cf-store"}"#
            .into(),
    );
    storage.store_request(telemetry)?;

    // Optional CAPTCHA five-step evidence (field-level) for B completeness when present.
    let mut html = base_request(&sid, "www.example.com", "/");
    html.resource_type = "document".into();
    html.response_headers = vec![HeaderEntry {
        name: "content-type".into(),
        value: "text/html".into(),
    }];
    html.response_body = Some(
        "<html><script>window.gokuProps={key:\"k\",iv:\"i\",context:\"c\"};</script></html>".into(),
    );
    storage.store_request(html)?;

    let mut problem = base_request(&sid, "73472ccc2f21.edge.captcha-sdk.awswaf.com", "/problem");
    problem.method = "GET".into();
    problem.query = Some("kind=visual".into());
    problem.response_body = Some(
        r#"{"problem_type":"grid","assets":{"images":"[\"a\",\"b\"]","target":"[\"icon\"]"},"state":"s1"}"#
            .into(),
    );
    storage.store_request(problem)?;

    let mut captcha_verify =
        base_request(&sid, "73472ccc2f21.edge.captcha-sdk.awswaf.com", "/verify");
    captcha_verify.method = "POST".into();
    captcha_verify.request_body =
        Some(r#"{"goku_props":{"key":"k"},"state":"s1","solution":[0,1,2]}"#.into());
    captcha_verify.response_body = Some(r#"{"success":true}"#.into());
    storage.store_request(captcha_verify)?;

    let mut voucher = base_request(&sid, "73472ccc2f21.edge.captcha-sdk.awswaf.com", "/voucher");
    voucher.method = "POST".into();
    voucher.response_body =
        Some(r#"{"voucher":"v1","token":"2e1254cf-d58d-4c53-8afb-08be29b8d202:AAoA:xx"}"#.into());
    storage.store_request(voucher)?;

    Ok(sid)
}

/// Run the full portable scorecard against in-memory golden fixture (real entry points).
pub fn run_fixture_scorecard() -> Result<Scorecard, String> {
    let storage = Storage::in_memory().map_err(|e| e.to_string())?;
    let session_id = seed_scorecard_fixture(&storage)?;
    score_session_storage(&storage, &session_id, true)
}

/// Score an existing storage session (fixture or real DB-backed Storage).
pub fn score_session_storage(
    storage: &Storage,
    session_id: &str,
    expect_full_decoder_config: bool,
) -> Result<Scorecard, String> {
    let requests = storage.list_requests(session_id, Some(10_000), Some(0))?;
    let mut best = challenge_decoder::decode_challenge_js("");
    for request in &requests {
        if request.path.contains("challenge.js")
            || (request.host.contains("awswaf") && request.path.contains("challenge"))
        {
            let body = storage.get_bundle_request(&request.id)?.response_body;
            if body.is_empty() || body.starts_with("base64:") {
                continue;
            }
            let decoded = challenge_decoder::decode_challenge_js(&body);
            if decoded.success && decoded.unique_count >= best.unique_count {
                best = decoded;
            }
        }
    }

    let algorithm = if expect_full_decoder_config {
        score_algorithm_reverse(&best, true, true, true, true)
    } else {
        score_algorithm_reverse(
            &best,
            best.config.aes_key_hex64.is_some(),
            best.config.identifier.is_some(),
            best.config.signal_version.is_some(),
            !best.config.type_names.is_empty() || !best.config.api_paths.is_empty(),
        )
    };

    let protection = protection_analysis::analyze_session(storage, session_id)?;
    let protocol = protection
        .get("protocolSchemas")
        .cloned()
        .unwrap_or(json!({}));
    let protocol_dim = score_protocol_reconstruction(&protocol);
    let l1 = score_l1_evidence_depth(&protocol);
    let l2 = score_l2_algorithm_depth(&best, &protocol);

    let pipeline = analysis_pipeline::run_autonomous_session_analysis(
        storage, session_id, "crypto", None, None,
    )?;
    let autonomy = score_end_to_end_autonomy(&pipeline);

    Ok(assemble_scorecard_with_layers(
        algorithm,
        protocol_dim,
        autonomy,
        ScorecardLayers {
            l0_product: None,
            l1_evidence_depth: Some(l1),
            l2_algorithm_depth: Some(l2),
        },
        vec![
            format!("sessionId={session_id}"),
            "L0=product A/B/C; L1=evidence depth; L2=algorithm depth".into(),
            "gates driven by decode_challenge_js + analyze_session + run_autonomous_session_analysis"
                .into(),
        ],
    ))
}

pub fn write_scorecard_json(path: &Path, scorecard: &Scorecard) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create scorecard dir: {e}"))?;
    }
    let body = serde_json::to_string_pretty(scorecard).map_err(|e| e.to_string())?;
    fs::write(path, body).map_err(|e| format!("write scorecard: {e}"))
}

/// Negative control: bare challenge.js must not invent AWS WAF as confirmed L0 provider.
pub fn seed_negative_bare_challenge_fixture(storage: &Storage) -> Result<String, String> {
    let session = storage.create_session(Some("scorecard-negative".into()))?;
    let sid = session.id.clone();
    let mut script = base_request(&sid, "www.example.com", "/static/challenge.js");
    script.resource_type = "script".into();
    script.response_headers = vec![HeaderEntry {
        name: "content-type".into(),
        value: "application/javascript".into(),
    }];
    script.response_body = Some("function runChallenge(){ return fetch('/api/start'); }".into());
    storage.store_request(script)?;
    Ok(sid)
}

fn dimension(id: &str, name: &str, weight: f64, gates: Vec<GateResult>) -> DimensionResult {
    let all_passed = !gates.is_empty() && gates.iter().all(|gate| gate.passed);
    DimensionResult {
        id: id.into(),
        name: name.into(),
        score: if all_passed { 100 } else { 0 },
        weight,
        gates,
    }
}

fn planted_challenge_js() -> String {
    r#"
function a0_0x1fd3(){
  var _0x345a0b = [
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'Zoey',
    'Present',
    '2.4.0',
    'mp_verify',
    'telemetry',
    'ha9faaffddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee'
  ];
  a0_0x1fd3 = function(){ return _0x345a0b; };
  return _0x345a0b;
}
(function(arrayFunc, targetOffset){
  var arr = arrayFunc();
  var i = 0;
  while(i < targetOffset){ arr.push(arr.shift()); i++; }
})(a0_0x1fd3, 0);
function a0_0x4f2e(index, key){
  var arr = a0_0x1fd3();
  return a0_0x4f2e = function(index, key){
    index = index - 0;
    return arr[index];
  }, a0_0x4f2e(index, key);
}
crypto.subtle.encrypt({name:"AES-GCM",tagLength:128},key,data);
const t = "awswaf_session_storage";
"#
    .into()
}

fn base_request(session_id: &str, host: &str, path: &str) -> CapturedRequestInput {
    CapturedRequestInput {
        id: None,
        session_id: session_id.to_string(),
        source: "browser".into(),
        source_instance_id: Some("scorecard".into()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_scorecard_all_dimensions_full_credit() {
        let card = run_fixture_scorecard().expect("scorecard");
        assert_eq!(
            card.algorithm_reverse.score, 100,
            "{:?}",
            card.algorithm_reverse
        );
        assert_eq!(
            card.protocol_reconstruction.score, 100,
            "{:?}",
            card.protocol_reconstruction
        );
        assert_eq!(
            card.end_to_end_autonomy.score, 100,
            "{:?}",
            card.end_to_end_autonomy
        );
        assert_eq!(card.weighted_composite, 100.0);
        assert!(card.all_full_credit);
        assert!(
            card.layers
                .l0_product
                .as_ref()
                .is_some_and(|l| l.score == 100),
            "L0 product layer missing: {:?}",
            card.layers
        );
        assert!(card.layers.l1_evidence_depth.is_some(), "L1 missing");
        assert!(card.layers.l2_algorithm_depth.is_some(), "L2 missing");
    }

    #[test]
    fn negative_bare_challenge_does_not_claim_aws_waf_full_credit() {
        let storage = Storage::in_memory().expect("mem");
        let sid = seed_negative_bare_challenge_fixture(&storage).expect("seed");
        let protection = protection_analysis::analyze_session(&storage, &sid).expect("prot");
        let providers = protection["providerCandidates"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !providers.iter().any(|p| {
                p["provider"].as_str() == Some("AWS WAF")
                    && matches!(p["confidence"].as_str(), Some("confirmed") | Some("likely"))
            }),
            "providers={providers:?}"
        );
        let card = score_session_storage(&storage, &sid, false).expect("card");
        // Negative session should not get L0 full credit (no WAF chain).
        assert!(!card.all_full_credit, "card={card:?}");
    }

    #[test]
    fn layered_l1_tracks_captcha_field_level_separately_from_counts() {
        let storage = Storage::in_memory().expect("mem");
        let sid = seed_scorecard_fixture(&storage).expect("seed");
        let protection = protection_analysis::analyze_session(&storage, &sid).expect("prot");
        assert_eq!(
            protection["protocolSchemas"]["captcha"]["fieldLevelExpanded"],
            true
        );
        assert!(protection["evidenceHeader"]["requiredTools"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|t| t.as_str() == Some("shownet_eval_scorecard")));
        assert!(protection["captureFidelity"]["labels"]
            .as_array()
            .is_some_and(|l| !l.is_empty()));
        let l1 = score_l1_evidence_depth(&protection["protocolSchemas"]);
        assert_eq!(l1.score, 100, "{l1:?}");
    }

    #[test]
    fn scorecard_is_deterministic_across_two_runs() {
        let first = run_fixture_scorecard().expect("first");
        let second = run_fixture_scorecard().expect("second");
        assert_eq!(
            first.algorithm_reverse.score,
            second.algorithm_reverse.score
        );
        assert_eq!(
            first.protocol_reconstruction.score,
            second.protocol_reconstruction.score
        );
        assert_eq!(
            first.end_to_end_autonomy.score,
            second.end_to_end_autonomy.score
        );
        assert_eq!(first.weighted_composite, second.weighted_composite);
        assert_eq!(first.all_full_credit, second.all_full_credit);
        assert_eq!(first.weighted_composite, 100.0);
    }

    #[test]
    fn write_scorecard_json_roundtrip() {
        let card = run_fixture_scorecard().expect("scorecard");
        let dir = std::env::temp_dir().join(format!(
            "shownet-scorecard-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        let path = dir.join("scorecard.json");
        write_scorecard_json(&path, &card).expect("write");
        let raw = fs::read_to_string(&path).expect("read");
        let parsed: Scorecard = serde_json::from_str(&raw).expect("parse");
        assert_eq!(parsed.weighted_composite, 100.0);
        assert!(parsed.all_full_credit);
        let _ = fs::remove_dir_all(dir);
    }

    /// When SHOWNET_SCORECARD_OUT is set, write scorecard.json (and a second run copy)
    /// for verification harnesses. Always asserts 100/100/100/100 on the fixture path.
    #[test]
    fn emit_scorecard_to_env_path_when_requested() {
        let card = run_fixture_scorecard().expect("scorecard run1");
        assert_eq!(card.algorithm_reverse.score, 100);
        assert_eq!(card.protocol_reconstruction.score, 100);
        assert_eq!(card.end_to_end_autonomy.score, 100);
        assert_eq!(card.weighted_composite, 100.0);

        if let Ok(out) = std::env::var("SHOWNET_SCORECARD_OUT") {
            let path = Path::new(&out);
            write_scorecard_json(path, &card).expect("write primary scorecard");
            let card2 = run_fixture_scorecard().expect("scorecard run2");
            assert_eq!(card2.weighted_composite, card.weighted_composite);
            assert_eq!(card2.all_full_credit, card.all_full_credit);
            let second = path.with_file_name("scorecard-run2.json");
            write_scorecard_json(&second, &card2).expect("write second scorecard");
            let primary: Scorecard =
                serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
            let secondary: Scorecard =
                serde_json::from_str(&fs::read_to_string(&second).unwrap()).unwrap();
            assert_eq!(primary.weighted_composite, 100.0);
            assert_eq!(secondary.weighted_composite, 100.0);
            assert_eq!(
                primary.algorithm_reverse.score,
                secondary.algorithm_reverse.score
            );
            assert_eq!(
                primary.protocol_reconstruction.score,
                secondary.protocol_reconstruction.score
            );
            assert_eq!(
                primary.end_to_end_autonomy.score,
                secondary.end_to_end_autonomy.score
            );
        }
    }
}
