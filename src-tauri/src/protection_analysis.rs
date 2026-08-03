use crate::analysis;
use crate::challenge_decoder::{self, ChallengeDecodeResult};
use crate::crypto_code;
use crate::models::{BrowserHookEvent, CryptoCodeSnippet, HeaderEntry, RequestRecord};
use crate::storage::Storage;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CHAIN_ENTRIES: usize = 140;
const MAX_SCRIPT_ENTRIES: usize = 64;
const MAX_HOOK_ENTRIES: usize = 90;
const MAX_SCRIPT_SCAN_BYTES: usize = 1_500_000;
const MAX_PREVIEW_BYTES: usize = 1_200;
const MAX_CONTEXT_BYTES: usize = 220;

#[derive(Default)]
struct ScriptFeatures {
    algorithms: BTreeSet<String>,
    protection_markers: BTreeSet<String>,
    obfuscation: BTreeSet<String>,
    crypto_frame: BTreeSet<String>,
    pow: BTreeSet<String>,
    config_keys: BTreeSet<String>,
    browser_signals: BTreeSet<String>,
    contexts: Vec<Value>,
    hex32_count: usize,
    hex64_count: usize,
}

pub fn analyze_session(storage: &Storage, session_id: &str) -> Result<Value, String> {
    let requests = storage.list_requests(session_id, Some(10_000), Some(0))?;
    let hooks = storage.list_browser_hooks(session_id, Some(2_000))?;
    let request_orders = requests
        .iter()
        .map(|request| (request.id.clone(), request.order))
        .collect::<BTreeMap<_, _>>();

    let mut provider_evidence = BTreeMap::<String, BTreeSet<String>>::new();
    let mut category_counts = BTreeMap::<String, usize>::new();
    let mut chain_entries = Vec::new();
    let mut script_entries = Vec::new();
    let mut feature_counts = BTreeMap::<String, usize>::new();
    let mut best_challenge_decode: Option<ChallengeDecodeResult> = None;

    for request in &requests {
        let signals = request_signals(request);
        for signal in &signals {
            register_provider_signal(
                &mut provider_evidence,
                signal,
                format!(
                    "#{} {} {}{}",
                    request.order, request.method, request.host, request.path
                ),
            );
        }

        let categories = request_categories(request, &signals);
        for category in &categories {
            *category_counts.entry(category.clone()).or_default() += 1;
        }
        if !categories.is_empty() && chain_entries.len() < MAX_CHAIN_ENTRIES {
            chain_entries.push(request_chain_entry(request, &categories, &signals));
        }

        if is_script_candidate(request) && script_entries.len() < MAX_SCRIPT_ENTRIES {
            let bundle_request = storage.get_bundle_request(&request.id)?;
            let snippets = storage.get_crypto_snippets(&request.id).unwrap_or_default();
            let features = script_features(&bundle_request.response_body, &snippets);
            let is_challenge_js = request.path.contains("challenge.js")
                || bundle_request.response_body.contains("mp_verify")
                    && bundle_request.response_body.contains("function a0_0x");
            if is_challenge_js
                && !bundle_request.response_body.is_empty()
                && !bundle_request.response_body.starts_with("base64:")
            {
                let decoded = challenge_decoder::decode_challenge_js(&bundle_request.response_body);
                let replace = match &best_challenge_decode {
                    None => true,
                    Some(current) => {
                        decoded.success
                            && (!current.success || decoded.unique_count > current.unique_count)
                    }
                };
                if replace {
                    best_challenge_decode = Some(decoded);
                }
            }
            if features_has_evidence(&features) {
                for marker in &features.protection_markers {
                    register_provider_signal(
                        &mut provider_evidence,
                        marker,
                        format!("#{} script {}", request.order, request.path),
                    );
                }
                for feature in features
                    .obfuscation
                    .iter()
                    .chain(features.crypto_frame.iter())
                    .chain(features.pow.iter())
                    .chain(features.config_keys.iter())
                    .chain(features.browser_signals.iter())
                {
                    *feature_counts.entry(feature.clone()).or_default() += 1;
                }
                script_entries.push(json!({
                    "requestId": request.id,
                    "order": request.order,
                    "host": request.host,
                    "path": request.path,
                    "status": request.status,
                    "snippetCount": snippets.len(),
                    "algorithms": values(&features.algorithms),
                    "protectionMarkers": values(&features.protection_markers),
                    "obfuscation": values(&features.obfuscation),
                    "cryptoFrame": values(&features.crypto_frame),
                    "pow": values(&features.pow),
                    "deploymentConfigHints": {
                        "hex32PlusValues": features.hex32_count,
                        "hex64PlusValues": features.hex64_count,
                        "keysSeen": values(&features.config_keys),
                        "note": "hex values and likely keys are preserved in bounded evidence contexts"
                    },
                    "browserSignalMarkers": values(&features.browser_signals),
                    "evidenceContexts": features.contexts,
                }));
            }
        }
    }

    let hook_entries = hooks
        .iter()
        .filter_map(|hook| hook_entry(hook, &request_orders))
        .take(MAX_HOOK_ENTRIES)
        .collect::<Vec<_>>();
    for hook in &hook_entries {
        if let Some(signals) = hook.get("signals").and_then(Value::as_array) {
            for signal in signals.iter().filter_map(Value::as_str) {
                register_provider_signal(
                    &mut provider_evidence,
                    signal,
                    "browser hook evidence".to_string(),
                );
            }
        }
    }

    let provider_candidates = provider_candidates(provider_evidence);
    let protocol_reconstruction =
        reconstruct_protocol_schemas(&requests, &script_entries, best_challenge_decode.as_ref());
    let fidelity = capture_fidelity(&requests, &hooks, &protocol_reconstruction);
    // Merge fidelity into protocolSchemas for scorecard/agents.
    let mut protocol_with_fidelity = protocol_reconstruction;
    if let Some(object) = protocol_with_fidelity.as_object_mut() {
        object.insert("fidelity".into(), fidelity.clone());
    }
    let limitations = limitations(
        &category_counts,
        script_entries.len(),
        hook_entries.len(),
        &requests,
        &protocol_with_fidelity,
    );
    let confirmed = confirmed_facts(
        &category_counts,
        &feature_counts,
        &provider_candidates,
        &protocol_with_fidelity,
    );
    let inferred = reasonable_inferences(
        &provider_candidates,
        &feature_counts,
        &protocol_with_fidelity,
    );
    let evidence_header = evidence_header(
        session_id,
        &provider_candidates,
        &protocol_with_fidelity,
        best_challenge_decode.as_ref(),
        &fidelity,
        &category_counts,
    );

    Ok(json!({
        "sessionId": session_id,
        "evidenceHeader": evidence_header,
        "summary": {
            "requestCount": requests.len(),
            "chainEntryCount": chain_entries.len(),
            "scriptEntryCount": script_entries.len(),
            "hookEntryCount": hook_entries.len(),
            "categoryCounts": category_counts,
            "featureCounts": feature_counts,
        },
        "providerCandidates": provider_candidates,
        "orderedProtectionChain": chain_entries,
        "protocolSchemas": protocol_with_fidelity,
        "captureFidelity": fidelity,
        "scriptStaticEvidence": script_entries,
        "hookRuntimeEvidence": hook_entries,
        "evidenceDiscipline": {
            "confirmed": confirmed,
            "reasonableInferences": inferred,
            "notCapturedOrInsufficient": limitations,
            "reportingRule": "Final reports must keep confirmed facts, reasonable inferences and not-captured gaps separate; do not invent CAPTCHA, token lifetime or bypass details without session evidence. CAPTCHA entry counts are not field-level schemas. Score with shownet_eval_scorecard L0/L1/L2 — never invent allFullCredit."
        },
        "analysisChecklist": [
            "Map challenge, captcha, telemetry, token and business API requests by #order.",
            "Use protocolSchemas for field-level challenge/telemetry/token/captcha facts extracted from captured bodies.",
            "CAPTCHA: entry count ≠ field-level five-step; require problem/verify/voucher fieldKeys when claiming field-level.",
            "For JavaScript protection code, report obfuscation, deployment path hashes, AES-GCM frame hints, PoW type hints and browser signal markers only when observed.",
            "For TLS/HTTP2, use captureFidelity labels: inbound browser JA3/JA4 vs independent MITM outbound; flag Headless UA risk.",
            "Call shownet_eval_scorecard and report L0 product / L1 evidence depth / L2 algorithm depth separately.",
            "If CAPTCHA /problem, /verify or /voucher was not captured, mark it as not captured instead of filling generic protocol knowledge.",
            "Do not claim full challenge.js deobfuscation or AES key recovery unless the session evidence actually yields them; decryptSideConfirmed only when Hook/plaintext evidence exists."
        ]
    }))
}

fn evidence_header(
    session_id: &str,
    providers: &[Value],
    protocol: &Value,
    decode: Option<&ChallengeDecodeResult>,
    fidelity: &Value,
    category_counts: &BTreeMap<String, usize>,
) -> Value {
    let top = providers
        .first()
        .and_then(|item| item.get("provider"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    json!({
        "sessionId": session_id,
        "topProvider": top,
        "selectedSkillsHint": ["noise-filter", "dynamic-signature", "crypto-reverse"],
        "requiredTools": [
            "shownet_analyze_dynamic_protection",
            "shownet_decode_challenge_js",
            "shownet_eval_scorecard"
        ],
        "decoder": {
            "success": decode.map(|d| d.success).unwrap_or(false),
            "decodedStringDump": decode.map(|d| d.decoded_string_dump).unwrap_or(false),
            "uniqueCount": decode.map(|d| d.unique_count).unwrap_or(0),
            "configRecovered": decode.map(|d| d.config_recovered.clone()).unwrap_or(json!({})),
        },
        "protocolHighlights": {
            "pow": protocol.pointer("/pow/challengeType").cloned().unwrap_or(Value::Null),
            "signal": protocol.pointer("/signals/identifier").cloned().unwrap_or(Value::Null),
            "telemetrySessionChain": protocol.pointer("/telemetry/sessionChain").cloned().unwrap_or(Value::Null),
            "tokenStructure": protocol.pointer("/token/structure").cloned().unwrap_or(Value::Null),
            "captchaFieldLevel": protocol.pointer("/captcha/fieldLevelExpanded").cloned().unwrap_or(Value::Null),
        },
        "categoryCounts": category_counts,
        "fidelityLabels": fidelity.get("labels").cloned().unwrap_or(json!([])),
        "scorecardInstruction": "Agents must call shownet_eval_scorecard; if tool fails, say so and do not invent allFullCredit=true."
    })
}

fn capture_fidelity(
    requests: &[RequestRecord],
    hooks: &[BrowserHookEvent],
    protocol: &Value,
) -> Value {
    let mut headless = false;
    let mut headless_samples = Vec::new();
    let mut inbound_tls = false;
    for request in requests {
        if request.tls_fingerprint.is_some() {
            inbound_tls = true;
        }
        for header in &request.request_headers {
            if header.name.eq_ignore_ascii_case("user-agent") {
                let ua = header.value.to_ascii_lowercase();
                if ua.contains("headless") || ua.contains("headlesschrome") {
                    headless = true;
                    if headless_samples.len() < 3 {
                        headless_samples.push(truncate_utf8(&header.value, 96));
                    }
                }
            }
        }
    }
    let mut import_key = false;
    let mut encrypt = false;
    let mut decrypt_side = false;
    let mut plaintext_markers = BTreeSet::new();
    for hook in hooks {
        let kind = hook.kind.to_ascii_lowercase();
        let name = hook.name.to_ascii_lowercase();
        let input_text = hook.input.to_string();
        let output_text = hook.output.to_string();
        let blob = format!("{kind} {name} {input_text} {output_text}");
        let lower = blob.to_ascii_lowercase();
        if lower.contains("importkey") || lower.contains("import_key") {
            import_key = true;
        }
        if lower.contains("encrypt") || lower.contains("aes-gcm") || lower.contains("aesgcm") {
            encrypt = true;
        }
        // Decrypt-side confirmation: plaintext shaped like checksum#JSON before encrypt.
        if (input_text.contains('#') && input_text.contains('{'))
            || input_text.contains("CRC32")
            || output_text.contains("CRC32#")
            || (lower.contains("encrypt")
                && input_text.contains('{')
                && input_text.contains('}')
                && !input_text.contains("ciphertext"))
        {
            if lower.contains("encrypt")
                || lower.contains("aes")
                || lower.contains("subtle")
                || kind.contains("crypto")
            {
                decrypt_side = true;
                plaintext_markers.insert("checksum_hash_json_or_object_pre_encrypt".into());
            }
        }
        if lower.contains("digest") && lower.contains("sha-256") {
            plaintext_markers.insert("sha256_digest_hook".into());
        }
    }
    let outbound_profile = crate::tls_outbound::global_profile();
    let mut labels = vec![
        if inbound_tls {
            "inbound-browser-tls-fingerprint"
        } else {
            "inbound-tls-fingerprint-missing"
        }
        .to_string(),
        outbound_profile.fidelity_label().into(),
    ];
    if headless {
        labels.push("headless-ua-risk".into());
    } else {
        labels.push("headless-ua-not-observed".into());
    }
    if import_key {
        labels.push("hook-importKey-observed".into());
    }
    if encrypt {
        labels.push("hook-encrypt-observed".into());
    }
    if decrypt_side {
        labels.push("hook-decrypt-side-plaintext-observed".into());
    } else {
        labels.push("hook-decrypt-side-unconfirmed".into());
    }
    if protocol
        .pointer("/challengeJs/decodedStringDump")
        .and_then(Value::as_bool)
        == Some(true)
    {
        labels.push("decoder-string-dump".into());
    }

    // AES closed-loop from decoder trial / network Present frames (attached under challengeJs).
    let mut aes_closed_loop = false;
    let aes_frame_decrypts = protocol
        .pointer("/challengeJs/networkFrameDecrypts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if protocol
        .pointer("/challengeJs/aesDecryptSideConfirmed")
        .and_then(Value::as_bool)
        == Some(true)
        || !aes_frame_decrypts.is_empty()
    {
        aes_closed_loop = true;
        decrypt_side = true;
        plaintext_markers.insert("decoder_aes_gcm_trial".into());
        labels.push("aes-gcm-decrypt-side-confirmed".into());
    }

    json!({
        "inboundTlsPresent": inbound_tls,
        "outboundMode": outbound_profile.as_str(),
        "outboundProfile": outbound_profile.as_str(),
        "outboundNote": outbound_profile.note(),
        "outboundJa3Parity": false,
        "headlessUaDetected": headless,
        "headlessUaSamples": headless_samples,
        "hookImportKeyObserved": import_key,
        "hookEncryptObserved": encrypt,
        "decryptSideConfirmed": decrypt_side || aes_closed_loop,
        "aesGcmClosedLoop": aes_closed_loop,
        "aesFrameDecryptSamples": aes_frame_decrypts,
        "plaintextMarkers": values(&plaintext_markers),
        "labels": labels,
        "reportingRule": "Product reports must label fidelity. Research-depth claims (full signal matrix, production bypass) are out of default L0 scorecard."
    })
}

fn request_chain_entry(
    request: &RequestRecord,
    categories: &[String],
    signals: &[String],
) -> Value {
    json!({
        "requestId": request.id,
        "order": request.order,
        "time": request.time,
        "method": request.method,
        "host": request.host,
        "path": request.path,
        "query": request.query.as_deref().map(analysis::bounded_query),
        "status": request.status,
        "type": request.resource_type,
        "durationMs": request.duration,
        "categories": categories,
        "signals": signals,
        "requestHeaderNames": header_names(&request.request_headers),
        "responseHeaderNames": header_names(&request.response_headers),
        "requestHeaders": analysis::bounded_headers(&request.request_headers),
        "responseHeaders": analysis::bounded_headers(&request.response_headers),
        "setCookieNames": set_cookie_names(&request.response_headers),
        "requestJsonKeys": request.request_body.as_deref().map(json_keys).unwrap_or_default(),
        "responseJsonKeys": json_keys(&request.response_body),
        "requestPreview": request.request_body.as_deref().map(bounded_preview),
        "responsePreview": (!request.response_body.is_empty()).then(|| bounded_preview(&request.response_body)),
        "tlsFingerprint": request.tls_fingerprint,
    })
}

fn request_signals(request: &RequestRecord) -> Vec<String> {
    let lower = request_evidence_text(request);
    let mut signals = BTreeSet::new();
    let aws = is_aws_waf_context(&lower);
    add_signal(
        &mut signals,
        "AWS WAF token",
        &lower,
        &["aws-waf-token", "x-aws-waf-token", "awswaf_token"],
    );
    add_signal(
        &mut signals,
        "AWS WAF session storage",
        &lower,
        &["awswaf_session_storage", "awswaf-session-storage"],
    );
    // Require real AWS WAF context — bare paths like /static/challenge.js must not invent AWS WAF.
    if aws
        && (lower.contains("mp_verify")
            || lower.contains("challenge.js")
            || lower.contains("/challenge")
            || lower.contains("edge.sdk.awswaf")
            || lower.contains("token.awswaf")
            || lower.contains("edge.captcha")
            || lower.contains("captcha.awswaf")
            || lower.contains("telemetry")
            || lower.contains("aws-waf-token")
            || lower.contains("awswaf_session_storage"))
    {
        signals.insert("AWS WAF challenge".to_string());
    }
    if aws
        && (lower.contains("captcha.js")
            || lower.contains("captcha.awswaf")
            || lower.contains("edge.captcha")
            || lower.contains("/problem")
            || lower.contains("/voucher")
            || (lower.contains("/verify") && !lower.contains("recaptcha")))
    {
        signals.insert("AWS WAF captcha".to_string());
    }
    if aws && lower.contains("telemetry") {
        signals.insert("AWS WAF telemetry".to_string());
    }
    add_signal(
        &mut signals,
        "Akamai Bot Manager",
        &lower,
        &[
            "akamai",
            "_abck",
            "bm_sz",
            "sensor_data",
            "sensordata",
            "sec-cpt",
            "ak_bmsc",
            "bm_sv",
            "bot-manager",
        ],
    );
    add_signal(
        &mut signals,
        "Cloudflare challenge",
        &lower,
        &[
            "cf-chl",
            "cf_clearance",
            "__cf_bm",
            "turnstile",
            "challenges.cloudflare.com",
            "cf-ray",
            "/cdn-cgi/challenge",
            "cf-challenge",
        ],
    );
    add_signal(
        &mut signals,
        "reCAPTCHA",
        &lower,
        &[
            "recaptcha",
            "grecaptcha",
            "g-recaptcha-response",
            "www.google.com/recaptcha",
            "www.gstatic.com/recaptcha",
            "recaptcha/enterprise",
        ],
    );
    add_signal(
        &mut signals,
        "PerimeterX / HUMAN",
        &lower,
        &[
            "perimeterx",
            "humansecurity",
            "px-cdn",
            "pxchk",
            "px-client",
            "px-captcha",
            "_px3",
            "_pxvid",
            "_pxhd",
            "pxcts",
            "ecdata",
            "client.perimeterx",
            "captcha.px-cdn",
            "/api/v2/collector",
        ],
    );
    add_signal(
        &mut signals,
        "business API signature",
        &lower,
        &[
            "x-signature",
            "x-request-time",
            "x-request-nonce",
            "x-device-id",
            "x-client-machine-id",
            "x-session-id",
            "x-pow-nonce",
            "signature=",
            "sign=",
        ],
    );
    add_signal(
        &mut signals,
        "PoW challenge",
        &lower,
        &[
            "pow",
            "hashcash",
            "difficulty",
            "scrypt",
            "networkbandwidth",
        ],
    );
    signals.into_iter().collect()
}

fn is_aws_waf_context(lower: &str) -> bool {
    [
        "awswaf",
        "aws-waf",
        "edge.sdk.awswaf",
        "edge.captcha",
        "token.awswaf",
        "captcha.awswaf",
        "mp_verify",
        "awswaf_session_storage",
        "x-aws-waf-token",
        "aws-waf-token",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn request_categories(request: &RequestRecord, signals: &[String]) -> Vec<String> {
    let lower = request_evidence_text(request);
    let mut categories = BTreeSet::new();
    let aws = is_aws_waf_context(&lower);
    if request.resource_type == "script" || lower.contains(".js") {
        if signals.iter().any(|signal| {
            signal.contains("AWS WAF")
                || signal.contains("Akamai")
                || signal.contains("Cloudflare")
                || signal.contains("reCAPTCHA")
        }) {
            categories.insert("dynamic-script".to_string());
        }
    }
    if aws
        && (lower.contains("mp_verify")
            || lower.contains("challenge.js")
            || lower.contains("/challenge"))
    {
        categories.insert("challenge".to_string());
    }
    if aws && lower.contains("telemetry") {
        categories.insert("telemetry".to_string());
    }
    if aws && lower.contains("/problem") {
        categories.insert("captcha-problem".to_string());
    }
    if aws && lower.contains("/verify") && !lower.contains("recaptcha") {
        categories.insert("captcha-verify".to_string());
    }
    if aws && lower.contains("/voucher") {
        categories.insert("captcha-voucher".to_string());
    }
    if aws
        && (lower.contains("/captcha")
            || lower.contains("captcha.js")
            || lower.contains("edge.captcha"))
    {
        categories.insert("captcha".to_string());
    }
    if lower.contains("aws-waf-token")
        || lower.contains("x-aws-waf-token")
        || lower.contains("awswaf_session_storage")
        || (aws
            && lower.contains("set-cookie")
            && (lower.contains("aws") || lower.contains("token")))
    {
        categories.insert("token-or-session".to_string());
    }
    if signals
        .iter()
        .any(|signal| signal == "business API signature")
    {
        categories.insert("business-api-signature".to_string());
    }
    if lower.contains("recaptcha") || lower.contains("grecaptcha") {
        categories.insert("third-party-captcha".to_string());
    }
    if signals.iter().any(|signal| signal == "Akamai Bot Manager") {
        categories.insert("akamai-bot".to_string());
        if lower.contains("sensor") || lower.contains("_abck") || lower.contains("bm_sz") {
            categories.insert("akamai-sensor".to_string());
        }
    }
    if signals
        .iter()
        .any(|signal| signal == "Cloudflare challenge")
    {
        categories.insert("cloudflare-challenge".to_string());
    }
    if signals.iter().any(|signal| signal == "PoW challenge") {
        categories.insert("proof-of-work".to_string());
    }
    categories.into_iter().collect()
}

fn request_evidence_text(request: &RequestRecord) -> String {
    let headers = request
        .request_headers
        .iter()
        .chain(request.response_headers.iter())
        .map(|header| format!("{}:{}", header.name, header.value))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{} {} {} {} {} {} {}",
        request.host,
        request.path,
        request.query.as_deref().unwrap_or_default(),
        headers,
        request.request_body.as_deref().unwrap_or_default(),
        request.response_body,
        request.resource_type
    )
    .to_ascii_lowercase()
}

fn script_features(source: &str, snippets: &[CryptoCodeSnippet]) -> ScriptFeatures {
    if source.is_empty() || source.starts_with("base64:") {
        return ScriptFeatures::default();
    }
    let scan_end = floor_char_boundary(source, source.len().min(MAX_SCRIPT_SCAN_BYTES));
    let source = &source[..scan_end];
    let lower = source.to_ascii_lowercase();
    let mut features = ScriptFeatures::default();

    for snippet in snippets {
        for algorithm in &snippet.algorithms {
            features.algorithms.insert(algorithm.clone());
        }
    }

    detect_feature(
        &mut features.protection_markers,
        "AWS WAF SDK",
        &lower,
        &[
            "awswaf",
            "aws-waf-token",
            "awswaf_session_storage",
            "mp_verify",
            "edge.sdk.awswaf",
        ],
    );
    if source.contains("function a0_0x") {
        features
            .obfuscation
            .insert("a0_0x* decoder/array function pattern".to_string());
    }
    if source.contains("function a0_0x")
        && (source.contains("=_[") || (source.contains("=[") && source.contains("_0x")))
    {
        features
            .obfuscation
            .insert("string-array function with hex locals".to_string());
    }
    if is_aws_waf_context(&lower)
        && (lower.contains("challenge.js")
            || lower.contains("captcha.js")
            || lower.contains("captcha.awswaf")
            || lower.contains("edge.captcha")
            || lower.contains("/problem")
            || lower.contains("/voucher")
            || (lower.contains("/verify") && !lower.contains("recaptcha"))
            || lower.contains("mp_verify"))
    {
        features
            .protection_markers
            .insert("AWS WAF challenge/captcha flow".to_string());
    }
    detect_feature(
        &mut features.protection_markers,
        "Akamai sensor",
        &lower,
        &["akamai", "_abck", "bm_sz", "sensor_data", "sensordata"],
    );
    detect_feature(
        &mut features.protection_markers,
        "Cloudflare challenge",
        &lower,
        &["cf-chl", "cf_clearance", "__cf_bm", "turnstile"],
    );
    detect_feature(
        &mut features.protection_markers,
        "reCAPTCHA",
        &lower,
        &["recaptcha", "grecaptcha", "g-recaptcha-response"],
    );

    if lower.matches("_0x").count() >= 5 {
        features
            .obfuscation
            .insert("hex-named decoder identifiers".to_string());
    }
    if lower.contains(".push(") && lower.contains(".shift(") {
        features
            .obfuscation
            .insert("rotating string array / IIFE".to_string());
    }
    if source.matches("',").count() >= 20 || source.matches("\",").count() >= 20 {
        features
            .obfuscation
            .insert("large string array".to_string());
    }
    if lower.contains("atob(") || lower.contains("fromcharcode") {
        features
            .obfuscation
            .insert("runtime string decoder".to_string());
    }

    detect_feature(
        &mut features.crypto_frame,
        "AES-GCM",
        &lower,
        &["aes-gcm", "crypto.subtle.encrypt"],
    );
    detect_feature(
        &mut features.crypto_frame,
        "CRC32/checksum prefix",
        &lower,
        &["crc32", "edb88320", "3988292384", "checksum#"],
    );
    if lower.contains("checksum") && lower.contains("json") {
        features
            .crypto_frame
            .insert("checksum plus JSON payload".to_string());
    }
    if source.contains("::") && lower.contains("tag") && lower.contains("cipher") {
        features
            .crypto_frame
            .insert("nonce::tag::ciphertext style separator".to_string());
    }
    if lower.contains("uint8array(12") || lower.contains("ivlength:12") || lower.contains("nonce") {
        features.crypto_frame.insert("nonce/iv hint".to_string());
    }
    if lower.contains("taglength:128") || lower.contains("uint8array(16") {
        features.crypto_frame.insert("16-byte tag hint".to_string());
    }
    detect_feature(
        &mut features.crypto_frame,
        "HMAC",
        &lower,
        &["hmac", "cryptojs.hmac"],
    );
    detect_feature(
        &mut features.crypto_frame,
        "SHA-256",
        &lower,
        &["sha-256", "sha256", "crypto.subtle.digest"],
    );

    if lower.contains("networkbandwidth")
        || (lower.contains("bandwidth") && lower.contains("challenge"))
    {
        features.pow.insert("NetworkBandwidth PoW hint".to_string());
    }
    if lower.contains("difficulty") && (lower.contains("sha-256") || lower.contains("sha256")) {
        features
            .pow
            .insert("SHA-256 difficulty PoW hint".to_string());
    }
    if lower.contains("scrypt") {
        features.pow.insert("scrypt PoW hint".to_string());
    }
    if lower.contains("hashcash") || lower.contains("leadingzero") || lower.contains("leading zero")
    {
        features.pow.insert("Hashcash-style PoW hint".to_string());
    }

    for key in [
        "signal",
        "signalidentifier",
        "signalversion",
        "challengetype",
        "challengeinput",
        "difficulty",
        "memory",
        "hmac",
        "region",
        "captcha",
        "voucher",
        "telemetry",
        "zoey.present",
    ] {
        if lower.contains(key) {
            features.config_keys.insert(key.to_string());
        }
    }

    for marker in [
        "navigator.useragent",
        "navigator.webdriver",
        "navigator.platform",
        "navigator.language",
        "navigator.languages",
        "hardwareconcurrency",
        "devicememory",
        "screen.width",
        "screen.height",
        "colordepth",
        "timezone",
        "gettimezoneoffset",
        "intl.datetimeformat",
        "canvas",
        "webgl",
        "audiocontext",
        "plugins",
        "mimetypes",
        "cookieenabled",
        "localstorage",
        "sessionstorage",
        "performance.now",
        "crypto.getrandomvalues",
        "permissions.query",
        "mousemove",
        "pointermove",
        "keydown",
        "touchstart",
        "visibilitystate",
        "document.referrer",
        "window.innerwidth",
        "window.innerheight",
    ] {
        if lower.contains(marker) {
            features.browser_signals.insert(marker.to_string());
        }
    }

    let (hex32_count, hex64_count) = count_hex_runs(source);
    features.hex32_count = hex32_count;
    features.hex64_count = hex64_count;
    if hex64_count > 0 {
        features
            .config_keys
            .insert("64+ hex deployment value".to_string());
    } else if hex32_count > 0 {
        features
            .config_keys
            .insert("32+ hex deployment value".to_string());
    }

    features.contexts = evidence_contexts(
        source,
        &[
            "awswaf",
            "aws-waf-token",
            "awswaf_session_storage",
            "mp_verify",
            "Zoey.Present",
            "AES-GCM",
            "crc32",
            "checksum",
            "difficulty",
            "scrypt",
            "NetworkBandwidth",
            "challengeType",
            "signalVersion",
            "telemetry",
            "voucher",
        ],
    );
    features
}

fn features_has_evidence(features: &ScriptFeatures) -> bool {
    !features.algorithms.is_empty()
        || !features.protection_markers.is_empty()
        || !features.obfuscation.is_empty()
        || !features.crypto_frame.is_empty()
        || !features.pow.is_empty()
        || !features.config_keys.is_empty()
        || !features.browser_signals.is_empty()
}

fn hook_entry(hook: &BrowserHookEvent, request_orders: &BTreeMap<String, i64>) -> Option<Value> {
    let text = format!(
        "{} {} {} {} {}",
        hook.kind,
        hook.name,
        hook.url.as_deref().unwrap_or_default(),
        hook.input,
        hook.output
    )
    .to_ascii_lowercase();
    let mut signals = BTreeSet::new();
    add_signal(
        &mut signals,
        "AWS WAF runtime",
        &text,
        &[
            "awswaf",
            "aws-waf-token",
            "awswaf_session_storage",
            "mp_verify",
        ],
    );
    add_signal(
        &mut signals,
        "WebCrypto runtime",
        &text,
        &[
            "crypto.subtle",
            "subtle.digest",
            "subtle.encrypt",
            "aes-gcm",
        ],
    );
    add_signal(
        &mut signals,
        "CryptoJS runtime",
        &text,
        &["cryptojs", "hmacsha256", "sha256", "aes"],
    );
    add_signal(
        &mut signals,
        "storage token runtime",
        &text,
        &[
            "localstorage",
            "sessionstorage",
            "setitem",
            "getitem",
            "token",
        ],
    );
    add_signal(
        &mut signals,
        "fetch/xhr runtime",
        &text,
        &["fetch", "xmlhttprequest", "telemetry", "captcha"],
    );
    if signals.is_empty() {
        return None;
    }
    Some(json!({
        "id": hook.id,
        "sequence": hook.sequence,
        "requestId": hook.request_id,
        "requestOrder": hook.request_id.as_ref().and_then(|id| request_orders.get(id)).copied(),
        "kind": hook.kind,
        "name": hook.name,
        "url": hook.url.as_deref().map(bounded_url),
        "method": hook.method,
        "input": hook.input,
        "output": hook.output,
        "signals": values(&signals),
        "stackPreview": hook.stack.as_deref().map(|stack| truncate_utf8(stack, 900)),
        "durationMs": hook.duration_ms,
        "correlation": hook.correlation,
    }))
}

fn provider_candidates(provider_evidence: BTreeMap<String, BTreeSet<String>>) -> Vec<Value> {
    let mut candidates = provider_evidence
        .into_iter()
        .map(|(provider, evidence)| {
            let score = evidence.len();
            json!({
                "provider": provider,
                "score": score,
                "confidence": if score >= 4 { "confirmed" } else if score >= 2 { "likely" } else { "weak" },
                "evidence": evidence.into_iter().take(14).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right["score"]
            .as_u64()
            .cmp(&left["score"].as_u64())
            .then_with(|| {
                left["provider"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["provider"].as_str().unwrap_or_default())
            })
    });
    candidates
}

fn limitations(
    category_counts: &BTreeMap<String, usize>,
    script_count: usize,
    hook_count: usize,
    requests: &[RequestRecord],
    protocol: &Value,
) -> Vec<String> {
    let mut gaps = Vec::new();
    if !category_counts.contains_key("captcha-problem") {
        gaps.push("No captured CAPTCHA /problem request in this session.".to_string());
    }
    if !category_counts.contains_key("captcha-verify") {
        gaps.push("No captured CAPTCHA /verify request in this session.".to_string());
    }
    if !category_counts.contains_key("captcha-voucher") {
        gaps.push("No captured CAPTCHA /voucher request in this session.".to_string());
    }
    if !category_counts.contains_key("telemetry") {
        gaps.push("No telemetry request was classified from captured traffic.".to_string());
    }
    if script_count == 0 {
        gaps.push(
            "No dynamic protection JavaScript body with recognizable static evidence was captured."
                .to_string(),
        );
    }
    if hook_count == 0 {
        gaps.push(
            "No matching JavaScript Hook runtime evidence was captured or correlated.".to_string(),
        );
    }
    if !requests
        .iter()
        .any(|request| request.tls_fingerprint.is_some())
    {
        gaps.push(
            "No inbound JA3/JA4 or HTTP/2 fingerprint record is available for this session."
                .to_string(),
        );
    }
    if protocol["challengeJs"]["decodedStringDump"].as_bool() != Some(true) {
        gaps.push(
            "challenge.js string-array decoder was not executed; deployment AES key / signalVersion / typeNames were not recovered from a full decoded string dump."
                .to_string(),
        );
    }
    if protocol["signals"]["plaintextBrowserDimensions"]
        .as_array()
        .map(|items| items.is_empty())
        .unwrap_or(true)
    {
        gaps.push(
            "Plaintext 25+ browser signal dimensions were not recovered; only encrypted signal frames or static script markers are available."
                .to_string(),
        );
    }
    if protocol["captcha"]["gokuPropsSeen"].as_bool() != Some(true)
        && !category_counts.contains_key("captcha-problem")
    {
        gaps.push(
            "No gokuProps / visual CAPTCHA problem payload was captured; silent challenge may have been sufficient in this session."
                .to_string(),
        );
    }
    gaps
}

fn confirmed_facts(
    category_counts: &BTreeMap<String, usize>,
    feature_counts: &BTreeMap<String, usize>,
    provider_candidates: &[Value],
    protocol: &Value,
) -> Vec<String> {
    let mut facts = Vec::new();
    if let Some(provider) = provider_candidates
        .first()
        .and_then(|item| item["provider"].as_str())
    {
        facts.push(format!(
            "Top dynamic protection provider candidate: {provider}."
        ));
    }
    for (category, count) in category_counts {
        facts.push(format!("Captured {count} {category} request entries."));
    }
    for (feature, count) in feature_counts.iter().take(12) {
        facts.push(format!(
            "Observed static feature `{feature}` in {count} script(s)."
        ));
    }
    if let Some(pow) = protocol["pow"]["challengeType"].as_str() {
        facts.push(format!(
            "Challenge input decoded challenge_type={pow} from network evidence."
        ));
    }
    if let Some(name) = protocol["signals"]["identifier"].as_str() {
        facts.push(format!(
            "Signal identifier observed in request payload: {name}."
        ));
    }
    if let Some(format) = protocol["signals"]["encryptedFrameFormat"].as_str() {
        facts.push(format!("Encrypted signal frame format: {format}."));
    }
    if let Some(token_format) = protocol["token"]["structure"].as_str() {
        facts.push(format!("Token structure observed: {token_format}."));
    }
    if protocol["telemetry"]["sessionChain"].as_bool() == Some(true) {
        facts.push(
            "Telemetry session chain observed: awswaf_session_storage starts null then returns a server value."
                .to_string(),
        );
    }
    if let Some(deployment) = protocol["deployment"]["pathTemplate"].as_str() {
        facts.push(format!("Deployment path template: {deployment}."));
    }
    if protocol["challengeJs"]["decodedStringDump"].as_bool() == Some(true) {
        facts.push(format!(
            "challenge.js sandbox decoder dumped {} unique strings.",
            protocol["challengeJs"]["uniqueDecodedCount"]
                .as_u64()
                .unwrap_or(0)
        ));
        if protocol["challengeJs"]["configRecovered"]["identifierFromDecoder"].as_bool()
            == Some(true)
        {
            if let Some(identifier) =
                protocol["challengeJs"]["configCandidates"]["identifier"].as_str()
            {
                facts.push(format!(
                    "Decoder recovered signal identifier candidate: {identifier}."
                ));
            }
        }
        if protocol["challengeJs"]["configRecovered"]["aesKeyHex64"].as_bool() == Some(true) {
            facts.push("Decoder recovered a 64-hex AES key candidate.".to_string());
        }
        if protocol["challengeJs"]["configRecovered"]["signalVersion"].as_bool() == Some(true) {
            if let Some(version) =
                protocol["challengeJs"]["configCandidates"]["signalVersion"].as_str()
            {
                facts.push(format!(
                    "Decoder recovered signalVersion candidate: {version}."
                ));
            }
        }
    }
    facts
}

fn reasonable_inferences(
    provider_candidates: &[Value],
    feature_counts: &BTreeMap<String, usize>,
    protocol: &Value,
) -> Vec<String> {
    let mut inferred = Vec::new();
    let has_aws = provider_candidates
        .iter()
        .any(|item| item["provider"].as_str() == Some("AWS WAF"));
    if has_aws && feature_counts.keys().any(|key| key.contains("AES-GCM")) {
        inferred.push("AWS WAF evidence plus AES-GCM static hints suggest encrypted client telemetry or challenge payloads, but exact frame fields still require direct request/body evidence.".to_string());
    }
    if has_aws
        && protocol["pow"]["challengeType"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case("NetworkBandwidth"))
    {
        inferred.push(
            "NetworkBandwidth challenge_type implies a sized payload/bandwidth cost rather than pure hash search; confirm solution_data size against difficulty when body evidence is complete."
                .to_string(),
        );
    } else if has_aws && feature_counts.keys().any(|key| key.contains("PoW")) {
        inferred.push("PoW markers are present in JavaScript; classify the concrete PoW type only when request fields or code contexts identify NetworkBandwidth, SHA-256 difficulty, or scrypt.".to_string());
    }
    if has_aws
        && protocol["signals"]["encryptedFrameFormat"]
            .as_str()
            .is_some_and(|value| value.contains("::"))
    {
        inferred.push(
            "Signal Present values use a multi-segment `::` frame; combined with AES-GCM script hints this is consistent with nonce/tag/ciphertext packaging, but plaintext CRC32#JSON framing still needs decrypt-side confirmation."
                .to_string(),
        );
    }
    if provider_candidates
        .iter()
        .any(|item| item["provider"].as_str() == Some("Akamai Bot Manager"))
    {
        inferred.push("Akamai markers imply dynamic sensor/cookie handling; do not emit a replay bypass unless a versioned adapter contract is explicitly produced by ShowNet.".to_string());
    }
    if provider_candidates
        .iter()
        .any(|item| item["provider"].as_str() == Some("Cloudflare"))
    {
        inferred.push(
            "Cloudflare markers are present; report challenge cookies and script endpoints from captured evidence only."
                .to_string(),
        );
    }
    inferred
}

fn reconstruct_protocol_schemas(
    requests: &[RequestRecord],
    script_entries: &[Value],
    challenge_decode: Option<&ChallengeDecodeResult>,
) -> Value {
    let mut deployment_ids = BTreeSet::new();
    let mut path_templates = BTreeSet::new();
    let mut edge_hosts = BTreeSet::new();
    let mut challenge_inputs = Vec::new();
    let mut pow_types = BTreeSet::new();
    let mut difficulties = BTreeSet::new();
    let mut regions = BTreeSet::new();
    let mut signal_identifiers = BTreeSet::new();
    let mut signal_frame_formats = BTreeSet::new();
    let mut checksums = BTreeSet::new();
    let mut metric_names = BTreeSet::new();
    let mut token_structures = BTreeSet::new();
    let mut token_samples = 0usize;
    let mut telemetry_null_start = false;
    let mut telemetry_server_storage = false;
    let mut next_intervals = BTreeSet::new();
    let mut mp_verify_multipart = false;
    let mut mp_verify_fields = BTreeSet::new();
    let mut goku_props = false;
    let mut captcha_assets_double_encoded = false;
    let mut captcha_problem_keys = BTreeSet::new();
    let mut captcha_verify_keys = BTreeSet::new();
    let mut captcha_voucher_keys = BTreeSet::new();
    let mut captcha_problem_captured = false;
    let mut captcha_verify_captured = false;
    let mut captcha_voucher_captured = false;
    let mut captcha_verify_uses_goku_props = false;
    let mut content_types = BTreeSet::new();
    let mut telemetry_rounds = 0usize;
    let mut browser_dimensions = BTreeSet::new();

    for request in requests {
        let lower_host = request.host.to_ascii_lowercase();
        if lower_host.contains("awswaf")
            || lower_host.contains("akamai")
            || lower_host.contains("cloudflare")
            || lower_host.contains("recaptcha")
        {
            edge_hosts.insert(request.host.clone());
        }
        if let Some((template, ids)) = deployment_path_info(&request.path) {
            path_templates.insert(template);
            deployment_ids.extend(ids);
        }

        let request_body = request.request_body.as_deref().unwrap_or_default();
        let response_body = request.response_body.as_str();
        let lower_path = request.path.to_ascii_lowercase();

        if lower_path.contains("mp_verify") {
            if request_body.contains("WebKitFormBoundary") || request_body.contains("form-data") {
                mp_verify_multipart = true;
            }
            for field in ["solution_metadata", "solution_data"] {
                if request_body.contains(field) {
                    mp_verify_fields.insert(field.to_string());
                }
            }
            if let Some(json_blob) = extract_json_object_near(request_body, "challenge") {
                collect_challenge_metadata(
                    &json_blob,
                    &mut challenge_inputs,
                    &mut pow_types,
                    &mut difficulties,
                    &mut regions,
                    &mut signal_identifiers,
                    &mut signal_frame_formats,
                    &mut checksums,
                    &mut metric_names,
                );
            }
            collect_token_structure(response_body, &mut token_structures, &mut token_samples);
        }

        if lower_path.contains("telemetry") {
            telemetry_rounds += 1;
            if request_body.contains("\"awswaf_session_storage\":\"null\"")
                || request_body.contains("\"awswaf_session_storage\": \"null\"")
            {
                telemetry_null_start = true;
            }
            if response_body.contains("awswaf_session_storage")
                && !response_body.contains("\"awswaf_session_storage\":null")
                && !response_body.contains("\"awswaf_session_storage\": null")
            {
                telemetry_server_storage = true;
            }
            if let Ok(value) = serde_json::from_str::<Value>(request_body) {
                collect_challenge_metadata(
                    &value,
                    &mut challenge_inputs,
                    &mut pow_types,
                    &mut difficulties,
                    &mut regions,
                    &mut signal_identifiers,
                    &mut signal_frame_formats,
                    &mut checksums,
                    &mut metric_names,
                );
            } else if let Some(json_blob) = extract_json_object_near(request_body, "signals") {
                collect_challenge_metadata(
                    &json_blob,
                    &mut challenge_inputs,
                    &mut pow_types,
                    &mut difficulties,
                    &mut regions,
                    &mut signal_identifiers,
                    &mut signal_frame_formats,
                    &mut checksums,
                    &mut metric_names,
                );
            }
            if let Ok(value) = serde_json::from_str::<Value>(response_body) {
                if let Some(interval) = value.get("next_interval").and_then(Value::as_u64) {
                    next_intervals.insert(interval);
                }
                collect_token_structure(
                    value
                        .get("token")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    &mut token_structures,
                    &mut token_samples,
                );
            } else {
                collect_token_structure(response_body, &mut token_structures, &mut token_samples);
            }
        }

        let looks_like_html = response_body.contains("<html")
            || response_body.contains("<!DOCTYPE")
            || content_type(&request.response_headers)
                .is_some_and(|value| value.contains("text/html"));
        if lower_path.contains("/problem") {
            captcha_problem_captured = true;
            if let Ok(value) = serde_json::from_str::<Value>(response_body) {
                collect_json_key_names(&value, "", 0, &mut captcha_problem_keys);
                if let Some(assets) = value.get("assets") {
                    if assets
                        .get("images")
                        .and_then(Value::as_str)
                        .is_some_and(|raw| raw.trim_start().starts_with('['))
                        || assets
                            .get("target")
                            .and_then(Value::as_str)
                            .is_some_and(|raw| raw.trim_start().starts_with('['))
                    {
                        captcha_assets_double_encoded = true;
                    }
                }
            }
        } else if lower_path.contains("/captcha") && !lower_path.contains("recaptcha") {
            if let Ok(value) = serde_json::from_str::<Value>(response_body) {
                collect_json_key_names(&value, "", 0, &mut captcha_problem_keys);
            }
        }
        // AWS captcha /verify (not reCAPTCHA): field-level keys only from real body.
        if lower_path.contains("/verify")
            && !lower_path.contains("recaptcha")
            && (lower_host.contains("awswaf")
                || lower_host.contains("captcha")
                || request_body.contains("goku_props")
                || request_body.contains("gokuProps")
                || response_body.contains("state") && response_body.contains("problem"))
        {
            captcha_verify_captured = true;
            if let Ok(value) = serde_json::from_str::<Value>(request_body) {
                collect_json_key_names(&value, "", 0, &mut captcha_verify_keys);
            } else if let Some(json_blob) = extract_json_object_near(request_body, "goku") {
                collect_json_key_names(&json_blob, "", 0, &mut captcha_verify_keys);
            }
            if request_body.contains("goku_props") || request_body.contains("\"gokuProps\"") {
                captcha_verify_uses_goku_props = true;
                captcha_verify_keys.insert("goku_props".into());
            }
        }
        if lower_path.contains("/voucher") {
            captcha_voucher_captured = true;
            if let Ok(value) = serde_json::from_str::<Value>(response_body) {
                collect_json_key_names(&value, "", 0, &mut captcha_voucher_keys);
            } else if let Ok(value) = serde_json::from_str::<Value>(request_body) {
                collect_json_key_names(&value, "", 0, &mut captcha_voucher_keys);
            }
        }
        // Only treat page-level gokuProps as CAPTCHA bootstrap evidence; script string tables often mention the key name without a live CAPTCHA.
        if looks_like_html
            && (response_body.contains("window.gokuProps") || response_body.contains("gokuProps"))
        {
            goku_props = true;
        }
        if request_body.contains("goku_props") || request_body.contains("\"gokuProps\"") {
            goku_props = true;
        }

        for header in &request.request_headers {
            if header.name.eq_ignore_ascii_case("content-type")
                && (lower_path.contains("mp_verify")
                    || lower_path.contains("telemetry")
                    || lower_path.contains("/verify")
                    || lower_path.contains("/voucher")
                    || lower_path.contains("/problem"))
            {
                content_types.insert(header.value.clone());
            }
        }
    }

    for script in script_entries {
        if let Some(markers) = script.get("browserSignalMarkers").and_then(Value::as_array) {
            for marker in markers.iter().filter_map(Value::as_str) {
                browser_dimensions.insert(marker.to_string());
            }
        }
    }

    let challenge_type = pow_types.iter().next().cloned();
    // Prefer network-observed identifier; fall back to decoder recovery.
    let signal_identifier = signal_identifiers
        .iter()
        .next()
        .cloned()
        .or_else(|| challenge_decode.and_then(|decoded| decoded.config.identifier.clone()));
    let signal_format = signal_frame_formats.iter().next().cloned();
    let token_structure = token_structures.iter().next().cloned();
    let path_template = path_templates.iter().next().cloned();

    let challenge_js = match challenge_decode {
        Some(decoded) => {
            let mut limitations = decoded.limitations.clone();
            if !decoded.success {
                limitations.push(
                    "challenge.js sandbox decoder did not produce a usable string dump.".into(),
                );
            }
            // Offline AES closed-loop against network Present frames collected below is applied later;
            // surface decoder-local trial here.
            let mut network_decrypts = Vec::new();
            if let Some(key) = decoded.config.aes_key_hex64.as_ref() {
                let frames: Vec<String> = requests
                    .iter()
                    .filter_map(|r| r.request_body.as_deref())
                    .flat_map(|body| extract_present_frames(body))
                    .take(16)
                    .collect();
                network_decrypts = challenge_decoder::decrypt_signal_present_frames(key, &frames);
            }
            let aes_decrypt_side =
                decoded.aes_decrypt_side_confirmed || !network_decrypts.is_empty();
            json!({
                "scriptEntries": script_entries.len(),
                "obfuscationHints": script_entries.iter()
                    .filter_map(|entry| entry.get("obfuscation").and_then(Value::as_array))
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>(),
                "decodedStringDump": decoded.decoded_string_dump,
                "decodedCount": decoded.decoded_count,
                "uniqueDecodedCount": decoded.unique_count,
                "arrayFunction": decoded.array_function,
                "decoderFunction": decoded.decoder_function,
                "rotationFound": decoded.rotation_found,
                "callSiteKeyCount": decoded.call_site_key_count,
                "callSiteKeysEffective": decoded.call_site_keys_effective,
                "aesDecryptSideConfirmed": aes_decrypt_side,
                "aesDecryptSampleKind": decoded.aes_decrypt_sample_kind,
                "networkFrameDecrypts": network_decrypts,
                "configRecovered": decoded.config_recovered,
                "configCandidates": {
                    "aesKeyHex64Present": decoded.config.aes_key_hex64.is_some(),
                    "aesKeyHex64": decoded.config.aes_key_hex64,
                    "identifier": decoded.config.identifier,
                    "signalVersion": decoded.config.signal_version,
                    "typeNames": decoded.config.type_names,
                    "apiPaths": decoded.config.api_paths,
                },
                "sampleDecodedStrings": decoded.sample_strings,
                "errors": decoded.errors,
                "limitations": limitations,
                "durationMs": decoded.duration_ms,
            })
        }
        None => json!({
            "scriptEntries": script_entries.len(),
            "obfuscationHints": script_entries.iter()
                .filter_map(|entry| entry.get("obfuscation").and_then(Value::as_array))
                .flatten()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>(),
            "decodedStringDump": false,
            "configRecovered": {
                "aesKeyHex64": false,
                "signalVersion": false,
                "typeNames": false,
                "identifierFromDecoder": false
            },
            "limitation": "No challenge.js body was available for sandbox decoder recovery in this session."
        }),
    };

    json!({
        "deployment": {
            "edgeHosts": values(&edge_hosts),
            "deploymentIds": values(&deployment_ids),
            "pathTemplate": path_template,
            "note": "Path segments like /{hash1}/{hash2}/ are deployment-scoped identifiers observed from URLs."
        },
        "challengeJs": challenge_js,
        "challengeSubmit": {
            "mpVerifyMultipart": mp_verify_multipart,
            "mpVerifyFields": values(&mp_verify_fields),
            "contentTypes": values(&content_types),
            "decodedChallengeInputs": challenge_inputs,
        },
        "pow": {
            "challengeType": challenge_type,
            "observedTypes": values(&pow_types),
            "difficulties": difficulties.into_iter().collect::<Vec<_>>(),
            "regions": values(&regions),
            "classificationNote": "challenge_type is taken from base64-decoded challenge.input when present in mp_verify/telemetry bodies."
        },
        "signals": {
            "identifier": signal_identifier,
            "encryptedFrameFormat": signal_format,
            "checksumsObserved": values(&checksums),
            "metricNames": values(&metric_names),
            "plaintextBrowserDimensions": values(&browser_dimensions),
        },
        "telemetry": {
            "roundCount": telemetry_rounds,
            "sessionChain": telemetry_null_start && telemetry_server_storage,
            "nullSessionStorageStart": telemetry_null_start,
            "serverReturnedSessionStorage": telemetry_server_storage,
            "nextIntervalsMs": next_intervals.into_iter().collect::<Vec<_>>(),
        },
        "token": {
            "structure": token_structure,
            "samplesCounted": token_samples,
            "formatNote": "aws-waf-token commonly appears as uuid:base64:base64 when captured in verify/telemetry responses."
        },
        "captcha": {
            "gokuPropsSeen": goku_props,
            "problemKeys": values(&captcha_problem_keys),
            "verifyKeys": values(&captcha_verify_keys),
            "voucherKeys": values(&captcha_voucher_keys),
            "assetsImagesDoubleEncoded": captcha_assets_double_encoded,
            "verifyUsesGokuPropsSnakeCase": captcha_verify_uses_goku_props,
            "stepsCaptured": {
                "gokuProps": goku_props,
                "problem": captcha_problem_captured,
                "verify": captcha_verify_captured,
                "voucher": captcha_voucher_captured,
            },
            "fiveStep": [
                {
                    "step": "gokuProps",
                    "captured": goku_props,
                    "note": "HTML/bootstrap window.gokuProps only when page evidence present"
                },
                {
                    "step": "problem",
                    "captured": captcha_problem_captured,
                    "fieldKeys": values(&captcha_problem_keys),
                    "assetsImagesDoubleEncoded": captcha_assets_double_encoded
                },
                {
                    "step": "verify",
                    "captured": captcha_verify_captured,
                    "fieldKeys": values(&captcha_verify_keys),
                    "goku_props_snake_case": captcha_verify_uses_goku_props
                },
                {
                    "step": "voucher",
                    "captured": captcha_voucher_captured,
                    "fieldKeys": values(&captcha_voucher_keys)
                },
                {
                    "step": "token_or_session_after_captcha",
                    "captured": token_samples > 0 && (captcha_problem_captured || captcha_verify_captured || captcha_voucher_captured),
                    "note": "token samples counted only when captcha traffic coexists"
                }
            ],
            "fieldLevelExpanded": captcha_problem_captured
                || captcha_verify_captured
                || captcha_voucher_captured
                || goku_props,
            "entryCountOnly": !captcha_problem_captured
                && !captcha_verify_captured
                && !captcha_voucher_captured
                && !goku_props,
            "reportingRule": "Entry counts from path classification are not field-level five-step schemas; require fieldKeys on problem/verify/voucher bodies.",
        }
    })
}

fn deployment_path_info(path: &str) -> Option<(String, Vec<String>)> {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 2 {
        return None;
    }
    let looks_like_id = |value: &str| {
        let lower = value.to_ascii_lowercase();
        (8..48).contains(&lower.len())
            && lower
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() || ch == '-' || ch == '_')
    };
    if looks_like_id(segments[0]) {
        let mut ids = vec![segments[0].to_string()];
        let mut template = String::from("/{deployId}");
        if segments.len() >= 2 && looks_like_id(segments[1]) {
            ids.push(segments[1].to_string());
            template.push_str("/{pathId}");
            if let Some(rest) = segments.get(2..) {
                for segment in rest {
                    template.push('/');
                    template.push_str(segment);
                }
            }
        } else {
            for segment in &segments[1..] {
                template.push('/');
                template.push_str(segment);
            }
        }
        return Some((template, ids));
    }
    None
}

fn extract_json_object_near(body: &str, marker: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        return Some(value);
    }
    let marker_pos = body.find(marker)?;
    let start = body[..marker_pos].rfind('{')?;
    let slice = &body[start..];
    let mut depth = 0i32;
    let mut end = None;
    for (index, ch) in slice.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(index + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end?;
    serde_json::from_str(&slice[..end]).ok()
}

fn collect_challenge_metadata(
    value: &Value,
    challenge_inputs: &mut Vec<Value>,
    pow_types: &mut BTreeSet<String>,
    difficulties: &mut BTreeSet<i64>,
    regions: &mut BTreeSet<String>,
    signal_identifiers: &mut BTreeSet<String>,
    signal_frame_formats: &mut BTreeSet<String>,
    checksums: &mut BTreeSet<String>,
    metric_names: &mut BTreeSet<String>,
) {
    if let Some(challenge) = value
        .pointer("/challenge")
        .or_else(|| value.get("challenge"))
    {
        if let Some(region) = challenge.get("region").and_then(Value::as_str) {
            regions.insert(region.to_string());
        }
        if let Some(input) = challenge.get("input").and_then(Value::as_str) {
            if let Some(decoded) = decode_challenge_input(input) {
                if let Some(challenge_type) = decoded
                    .get("challenge_type")
                    .or_else(|| decoded.get("challengeType"))
                    .and_then(Value::as_str)
                {
                    pow_types.insert(challenge_type.to_string());
                }
                if let Some(difficulty) = decoded.get("difficulty").and_then(Value::as_i64) {
                    difficulties.insert(difficulty);
                }
                if let Some(region) = decoded.get("region").and_then(Value::as_str) {
                    regions.insert(region.to_string());
                }
                if challenge_inputs.len() < 6 {
                    challenge_inputs.push(json!({
                        "source": "challenge.input base64",
                        "decodedKeys": json_keys_shallow(&decoded),
                        "challengeType": decoded.get("challenge_type").or_else(|| decoded.get("challengeType")).cloned().unwrap_or(Value::Null),
                        "difficulty": decoded.get("difficulty").cloned().unwrap_or(Value::Null),
                        "region": decoded.get("region").cloned().unwrap_or(Value::Null),
                    }));
                }
            }
        }
    }
    if let Some(region) = value.get("region").and_then(Value::as_str) {
        regions.insert(region.to_string());
    }
    if let Some(checksum) = value.get("checksum").and_then(Value::as_str) {
        if checksum.len() <= 16 {
            checksums.insert(checksum.to_string());
        } else {
            checksums.insert(format!("{}…", truncate_utf8(checksum, 12)));
        }
    }
    if let Some(signals) = value.get("signals").and_then(Value::as_array) {
        for signal in signals {
            if let Some(name) = signal.get("name").and_then(Value::as_str) {
                signal_identifiers.insert(name.to_string());
            }
            if let Some(present) = signal
                .pointer("/value/Present")
                .or_else(|| signal.pointer("/value/present"))
                .and_then(Value::as_str)
            {
                signal_frame_formats.insert(classify_signal_frame(present));
            }
        }
    }
    if let Some(metrics) = value.get("metrics").and_then(Value::as_array) {
        for metric in metrics {
            if let Some(name) = metric.get("name").and_then(Value::as_str) {
                metric_names.insert(name.to_string());
            } else if let Some(name) = metric.get("name").and_then(Value::as_i64) {
                metric_names.insert(name.to_string());
            }
        }
    }
}

fn decode_challenge_input(input: &str) -> Option<Value> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    let trimmed = input.trim();
    if trimmed.len() < 8 {
        return None;
    }
    let decoded = STANDARD
        .decode(trimmed)
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    serde_json::from_str(&text).ok()
}

fn classify_signal_frame(present: &str) -> String {
    let parts = present.split("::").count();
    if parts >= 3 {
        "segment::segment::segment (likely nonce::tag::ciphertext)".to_string()
    } else if parts == 2 {
        "prefix::payload (two-segment encrypted frame)".to_string()
    } else if present.len() > 64 {
        "opaque-long-blob".to_string()
    } else {
        "short-opaque".to_string()
    }
}

fn extract_present_frames(body: &str) -> Vec<String> {
    let mut frames = Vec::new();
    // "Present":"...."
    let markers = ["\"Present\":\"", "\"present\":\""];
    for marker in markers {
        let mut search = 0usize;
        while let Some(rel) = body[search..].find(marker) {
            let start = search + rel + marker.len();
            if let Some(end_rel) = body[start..].find('"') {
                let frame = &body[start..start + end_rel];
                if frame.contains("::") && frame.len() > 16 {
                    frames.push(frame.to_string());
                }
                search = start + end_rel + 1;
            } else {
                break;
            }
            if frames.len() >= 16 {
                return frames;
            }
        }
    }
    frames
}

fn collect_token_structure(
    body_or_token: &str,
    structures: &mut BTreeSet<String>,
    samples: &mut usize,
) {
    for candidate in extract_token_candidates(body_or_token) {
        *samples += 1;
        let parts = candidate.split(':').count();
        if parts == 3 {
            structures.insert("uuid:base64:base64 (3-segment aws-waf-token)".to_string());
        } else if parts > 1 {
            structures.insert(format!("{parts}-segment colon token"));
        } else {
            structures.insert("opaque token".to_string());
        }
        if *samples >= 8 {
            break;
        }
    }
}

fn extract_token_candidates(body: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        if let Some(token) = value.get("token").and_then(Value::as_str) {
            candidates.push(token.to_string());
        }
    }
    if let Some(index) = body.find("\"token\":\"") {
        let rest = &body[index + 9..];
        if let Some(end) = rest.find('"') {
            candidates.push(rest[..end].to_string());
        }
    }
    // bare token-looking values
    for chunk in body.split(|ch: char| ch == '"' || ch.is_whitespace() || ch == ',') {
        if chunk.matches(':').count() == 2 && chunk.len() > 40 && chunk.len() < 600 {
            if let Some(first) = chunk.split(':').next() {
                if first.len() >= 32 && first.contains('-') {
                    candidates.push(chunk.to_string());
                }
            }
        }
    }
    candidates.into_iter().take(8).collect()
}

fn collect_json_key_names(value: &Value, prefix: &str, depth: usize, keys: &mut BTreeSet<String>) {
    if depth >= 3 || keys.len() >= 40 {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                keys.insert(path.clone());
                collect_json_key_names(child, &path, depth + 1, keys);
            }
        }
        Value::Array(items) => {
            if let Some(first) = items.first() {
                collect_json_key_names(first, prefix, depth + 1, keys);
            }
        }
        _ => {}
    }
}

fn json_keys_shallow(value: &Value) -> Vec<String> {
    match value {
        Value::Object(object) => object.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

fn register_provider_signal(
    provider_evidence: &mut BTreeMap<String, BTreeSet<String>>,
    signal: &str,
    evidence: String,
) {
    let provider = if signal.contains("AWS WAF") {
        Some("AWS WAF")
    } else if signal.contains("Akamai") {
        Some("Akamai Bot Manager")
    } else if signal.contains("Cloudflare") {
        Some("Cloudflare")
    } else if signal.contains("reCAPTCHA") {
        Some("Google reCAPTCHA")
    } else {
        None
    };
    if let Some(provider) = provider {
        provider_evidence
            .entry(provider.to_string())
            .or_default()
            .insert(format!("{signal}: {evidence}"));
    }
}

fn add_signal(target: &mut BTreeSet<String>, name: &str, lower: &str, markers: &[&str]) {
    if markers.iter().any(|marker| lower.contains(marker)) {
        target.insert(name.to_string());
    }
}

fn detect_feature(target: &mut BTreeSet<String>, name: &str, lower: &str, markers: &[&str]) {
    if markers
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
    {
        target.insert(name.to_string());
    }
}

fn is_script_candidate(request: &RequestRecord) -> bool {
    request.resource_type == "script"
        || request.crypto_snippet_count > 0
        || request.path.ends_with(".js")
        || request.path.ends_with(".mjs")
        || request.path.contains(".chunk.js")
        || content_type(&request.response_headers)
            .is_some_and(|value| value.contains("javascript") || value.contains("ecmascript"))
}

fn content_type(headers: &[HeaderEntry]) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.to_ascii_lowercase())
}

fn header_names(headers: &[HeaderEntry]) -> Vec<String> {
    headers
        .iter()
        .map(|header| header.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn set_cookie_names(headers: &[HeaderEntry]) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|header| header.value.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn json_keys(body: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let mut keys = BTreeSet::new();
    collect_json_keys(&value, "", 0, &mut keys);
    keys.into_iter().take(60).collect()
}

fn collect_json_keys(value: &Value, prefix: &str, depth: usize, keys: &mut BTreeSet<String>) {
    if depth >= 4 || keys.len() >= 80 {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                keys.insert(path.clone());
                collect_json_keys(child, &path, depth + 1, keys);
            }
        }
        Value::Array(items) => {
            if let Some(first) = items.first() {
                collect_json_keys(first, prefix, depth + 1, keys);
            }
        }
        _ => {}
    }
}

fn bounded_preview(body: &str) -> String {
    truncate_utf8(body, MAX_PREVIEW_BYTES)
}

fn bounded_url(url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return truncate_utf8(url, 2_048);
    };
    format!(
        "{}?{}",
        truncate_utf8(base, 1_024),
        analysis::bounded_query(query)
    )
}

fn evidence_contexts(source: &str, markers: &[&str]) -> Vec<Value> {
    let lower = source.to_ascii_lowercase();
    let mut contexts = Vec::new();
    let mut seen = BTreeSet::new();
    for marker in markers {
        let marker_lower = marker.to_ascii_lowercase();
        let Some(position) = lower.find(&marker_lower) else {
            continue;
        };
        if !seen.insert(marker_lower.clone()) {
            continue;
        }
        let start = floor_char_boundary(source, position.saturating_sub(MAX_CONTEXT_BYTES / 2));
        let end = floor_char_boundary(source, (position + MAX_CONTEXT_BYTES / 2).min(source.len()));
        let preview = truncate_utf8(
            &crypto_code::bounded_code(&source[start..end]),
            MAX_CONTEXT_BYTES,
        );
        contexts.push(json!({
            "marker": marker,
            "line": line_at(source, position),
            "preview": preview,
        }));
        if contexts.len() >= 16 {
            break;
        }
    }
    contexts
}

fn count_hex_runs(source: &str) -> (usize, usize) {
    let mut hex32 = 0usize;
    let mut hex64 = 0usize;
    let mut run = 0usize;
    for byte in source.bytes().chain(std::iter::once(b' ')) {
        if byte.is_ascii_hexdigit() {
            run += 1;
        } else {
            if run >= 32 {
                hex32 += 1;
            }
            if run >= 64 {
                hex64 += 1;
            }
            run = 0;
        }
    }
    (hex32, hex64)
}

fn values(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}

fn line_at(source: &str, offset: usize) -> i64 {
    source.as_bytes()[..offset.min(source.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as i64
        + 1
}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[TRUNCATED]", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BodyCaptureMetadata, CapturedRequestInput, HeaderEntry};
    use crate::storage::Storage;

    fn storage() -> Storage {
        Storage::in_memory().expect("in-memory storage")
    }

    fn base_input(session_id: &str, host: &str, path: &str) -> CapturedRequestInput {
        CapturedRequestInput {
            id: None,
            session_id: session_id.to_string(),
            source: "browser".to_string(),
            source_instance_id: Some("test".to_string()),
            timestamp: Some(1_785_393_200_000),
            method: "GET".to_string(),
            scheme: Some("https".to_string()),
            host: host.to_string(),
            port: Some(443),
            path: path.to_string(),
            query: None,
            status: 200,
            resource_type: "fetch".to_string(),
            size_bytes: 1_024,
            duration_ms: 50,
            protocol: "h2".to_string(),
            tls_version: Some("TLS 1.3".to_string()),
            tls_fingerprint: None,
            risk_level: "none".to_string(),
            request_headers: vec![],
            response_headers: vec![],
            request_body: None,
            response_body: Some(String::new()),
            response_body_metadata: Some(BodyCaptureMetadata::default()),
            crypto_snippets: None,
            hook: None,
        }
    }

    fn provider_names(result: &Value) -> Vec<String> {
        result["providerCandidates"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item["provider"].as_str().map(str::to_string))
            .collect()
    }

    fn confirmed_providers(result: &Value) -> Vec<String> {
        result["providerCandidates"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|item| {
                matches!(
                    item["confidence"].as_str(),
                    Some("confirmed") | Some("likely")
                )
            })
            .filter_map(|item| item["provider"].as_str().map(str::to_string))
            .collect()
    }

    fn chain_categories(result: &Value) -> BTreeSet<String> {
        result["orderedProtectionChain"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry["categories"].as_array())
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn bare_challenge_js_path_does_not_invent_aws_waf_provider() {
        let storage = storage();
        let session = storage
            .create_session(Some("generic-challenge-js".into()))
            .unwrap();
        let sid = session.id.clone();

        let mut script = base_input(&sid, "www.example.com", "/static/challenge.js");
        script.resource_type = "script".into();
        script.response_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: "application/javascript".into(),
        }];
        // Filename is challenge.js only — no awswaf / mp_verify / aws-waf-token markers.
        script.response_body = Some(
            r#"
function runChallenge() {
  console.log("generic app challenge flow");
  return fetch("/api/start");
}
"#
            .into(),
        );
        storage.store_request(script).unwrap();

        let result = analyze_session(&storage, &sid).unwrap();
        let providers = provider_names(&result);
        assert!(
            !providers.iter().any(|p| p == "AWS WAF"),
            "bare /static/challenge.js must not invent AWS WAF: providers={providers:?} result={}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        assert!(
            !confirmed_providers(&result).iter().any(|p| p == "AWS WAF"),
            "AWS WAF must not appear as confirmed/likely: {:?}",
            confirmed_providers(&result)
        );

        // Static script path also must not attach AWS protection markers via script_features.
        let scripts = result["scriptStaticEvidence"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for entry in &scripts {
            let markers = entry["protectionMarkers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            assert!(
                markers.iter().all(|m| !m.contains("AWS WAF")),
                "script protectionMarkers leaked AWS WAF: {markers:?}"
            );
        }
    }

    #[test]
    fn analyzes_aws_waf_session_one_shot_aggregation() {
        let storage = storage();
        let session = storage
            .create_session(Some("aws-waf-fixture".into()))
            .unwrap();
        let sid = session.id.clone();

        let input_json = r#"{"version":1,"difficulty":1,"challenge_type":"NetworkBandwidth","region":"ap-east-1"}"#;
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

        let mut script = base_input(
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
const frame = nonce + "::" + tag + "::" + ciphertext;
const checksum = crc32(JSON.stringify(payload));
const difficulty = 3; const hashcash = true;
const t = "awswaf_session_storage"; const y = "mp_verify";
"#
            .into(),
        );
        storage.store_request(script).unwrap();

        let mut verify = base_input(
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
        storage.store_request(verify).unwrap();

        let mut telemetry = base_input(
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
        storage.store_request(telemetry).unwrap();

        let result = analyze_session(&storage, &sid).unwrap();
        let providers = provider_names(&result);
        assert!(
            providers.iter().any(|p| p == "AWS WAF"),
            "providers={providers:?}"
        );
        assert!(
            !providers.iter().any(|p| p == "Akamai Bot Manager"),
            "AWS fixture must not invent Akamai: {providers:?}"
        );
        assert!(
            !providers.iter().any(|p| p == "Cloudflare"),
            "AWS fixture must not invent Cloudflare: {providers:?}"
        );

        let categories = chain_categories(&result);
        assert!(
            categories.contains("challenge") || categories.contains("telemetry"),
            "chain categories={categories:?}"
        );
        assert!(
            categories.contains("token-or-session") || categories.contains("telemetry"),
            "token/telemetry categories={categories:?}"
        );

        let features = &result["summary"]["featureCounts"];
        let feature_blob = features.to_string().to_ascii_lowercase();
        assert!(
            feature_blob.contains("aes-gcm")
                || feature_blob.contains("crc")
                || feature_blob.contains("checksum")
                || feature_blob.contains("pow")
                || feature_blob.contains("obfus")
                || feature_blob.contains("rotat")
                || feature_blob.contains("sha-256"),
            "static features missing PoW/AES/CRC/obfuscation: {features}"
        );

        let gaps = result["evidenceDiscipline"]["notCapturedOrInsufficient"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let gap_text = gaps
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            gap_text.to_ascii_lowercase().contains("problem")
                || gap_text.to_ascii_lowercase().contains("captcha")
                || gap_text.to_ascii_lowercase().contains("voucher"),
            "CAPTCHA gaps must be explicit when /problem not captured: {gap_text}"
        );
        assert_eq!(
            result["protocolSchemas"]["pow"]["challengeType"].as_str(),
            Some("NetworkBandwidth")
        );
        assert_eq!(
            result["protocolSchemas"]["signals"]["identifier"].as_str(),
            Some("Zoey")
        );
        assert_eq!(result["protocolSchemas"]["telemetry"]["sessionChain"], true);
        // Sandbox decoder path must surface recovered config, not invent CAPTCHA.
        assert_eq!(
            result["protocolSchemas"]["challengeJs"]["decodedStringDump"], true,
            "challengeJs={}",
            result["protocolSchemas"]["challengeJs"]
        );
        assert_eq!(
            result["protocolSchemas"]["challengeJs"]["configRecovered"]["aesKeyHex64"],
            true
        );
        assert_eq!(
            result["protocolSchemas"]["challengeJs"]["configRecovered"]["identifierFromDecoder"],
            true
        );
        assert_eq!(
            result["protocolSchemas"]["challengeJs"]["configCandidates"]["identifier"].as_str(),
            Some("Zoey")
        );
        let challenge_js_text = result["protocolSchemas"]["challengeJs"].to_string();
        assert!(
            challenge_js_text
                .contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "raw AES key missing from aggregation output"
        );
        let gaps = result["evidenceDiscipline"]["notCapturedOrInsufficient"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let gap_text = gaps
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            gap_text.to_ascii_lowercase().contains("problem")
                || gap_text.to_ascii_lowercase().contains("captcha")
                || gap_text.to_ascii_lowercase().contains("voucher"),
            "CAPTCHA gaps must remain explicit: {gap_text}"
        );
    }

    #[test]
    fn analyzes_akamai_fixture_without_other_confirmed_providers() {
        let storage = storage();
        let session = storage
            .create_session(Some("akamai-fixture".into()))
            .unwrap();
        let sid = session.id.clone();

        let mut script = base_input(&sid, "www.example.com", "/akam/13/sensor.js");
        script.resource_type = "script".into();
        script.response_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: "application/javascript".into(),
        }];
        script.response_body = Some(
            r#"// akamai bot manager sensor
function sendSensor(sensor_data){ fetch('/_bm/sensor',{method:'POST',body:sensor_data}); }
const _abck = document.cookie; const bm_sz = '1';
"#
            .into(),
        );
        storage.store_request(script).unwrap();

        let mut sensor = base_input(&sid, "www.example.com", "/_bm/sensor");
        sensor.method = "POST".into();
        sensor.request_body = Some(r#"{"sensor_data":"3;0;1;0;..."}"#.into());
        sensor.request_headers = vec![HeaderEntry {
            name: "cookie".into(),
            value: "_abck=abc; bm_sz=xyz".into(),
        }];
        sensor.response_headers = vec![HeaderEntry {
            name: "set-cookie".into(),
            value: "_abck=updated; Path=/".into(),
        }];
        storage.store_request(sensor).unwrap();

        let result = analyze_session(&storage, &sid).unwrap();
        let providers = provider_names(&result);
        assert!(
            providers.iter().any(|p| p.contains("Akamai")),
            "providers={providers:?}"
        );
        assert!(
            !confirmed_providers(&result)
                .iter()
                .any(|p| p == "AWS WAF" || p == "Cloudflare" || p == "Google reCAPTCHA"),
            "Akamai-only fixture leaked other confirmed providers: {:?}",
            confirmed_providers(&result)
        );
        let categories = chain_categories(&result);
        assert!(
            categories.iter().any(|c| c.contains("akamai")),
            "categories={categories:?}"
        );
    }

    #[test]
    fn analyzes_cloudflare_fixture_without_other_confirmed_providers() {
        let storage = storage();
        let session = storage
            .create_session(Some("cloudflare-fixture".into()))
            .unwrap();
        let sid = session.id.clone();

        let mut challenge = base_input(
            &sid,
            "challenges.cloudflare.com",
            "/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page",
        );
        challenge.resource_type = "script".into();
        challenge.response_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: "application/javascript".into(),
        }];
        challenge.response_body = Some(
            r#"window._cf_chl_opt={}; /* cf-chl challenge */ turnstile.render('#cf');"#.into(),
        );
        challenge.response_headers.push(HeaderEntry {
            name: "set-cookie".into(),
            value: "__cf_bm=1; Path=/".into(),
        });
        storage.store_request(challenge).unwrap();

        let mut clearance = base_input(&sid, "www.example.com", "/");
        clearance.response_headers = vec![
            HeaderEntry {
                name: "set-cookie".into(),
                value: "cf_clearance=token; Path=/".into(),
            },
            HeaderEntry {
                name: "cf-ray".into(),
                value: "7a1b2c3d4e5f-SIN".into(),
            },
        ];
        clearance.response_body = Some("<html>cf-chl-bypass</html>".into());
        storage.store_request(clearance).unwrap();

        let result = analyze_session(&storage, &sid).unwrap();
        let providers = provider_names(&result);
        assert!(
            providers.iter().any(|p| p == "Cloudflare"),
            "providers={providers:?}"
        );
        assert!(
            !confirmed_providers(&result)
                .iter()
                .any(|p| p == "AWS WAF" || p.contains("Akamai") || p == "Google reCAPTCHA"),
            "Cloudflare-only fixture leaked other confirmed providers: {:?}",
            confirmed_providers(&result)
        );
        let categories = chain_categories(&result);
        assert!(
            categories.contains("cloudflare-challenge") || categories.contains("dynamic-script"),
            "categories={categories:?}"
        );
    }

    #[test]
    fn analyzes_recaptcha_fixture_without_other_confirmed_providers() {
        let storage = storage();
        let session = storage
            .create_session(Some("recaptcha-fixture".into()))
            .unwrap();
        let sid = session.id.clone();

        let mut script = base_input(&sid, "www.google.com", "/recaptcha/enterprise.js");
        script.resource_type = "script".into();
        script.query = Some("render=6LfTestKey".into());
        script.response_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: "application/javascript".into(),
        }];
        script.response_body =
            Some("grecaptcha.enterprise.ready(function(){}); /* recaptcha */".into());
        storage.store_request(script).unwrap();

        let mut api = base_input(&sid, "api.example.com", "/booking/recaptcha_v3");
        api.method = "POST".into();
        api.query = Some("token=03AGdBq24...".into());
        api.request_body = Some(r#"{"g-recaptcha-response":"03AGdBq24..."}"#.into());
        storage.store_request(api).unwrap();

        let result = analyze_session(&storage, &sid).unwrap();
        let providers = provider_names(&result);
        assert!(
            providers
                .iter()
                .any(|p| p == "Google reCAPTCHA" || p == "reCAPTCHA"),
            "providers={providers:?}"
        );
        assert!(
            !confirmed_providers(&result)
                .iter()
                .any(|p| p == "AWS WAF" || p.contains("Akamai") || p == "Cloudflare"),
            "reCAPTCHA-only fixture leaked other confirmed providers: {:?}",
            confirmed_providers(&result)
        );
        let categories = chain_categories(&result);
        assert!(
            categories.contains("third-party-captcha") || categories.contains("dynamic-script"),
            "categories={categories:?}"
        );
    }

    #[test]
    fn detects_aws_waf_crypto_frame_and_pow_hints() {
        let script = r#"
const cfg = { signalVersion: "1", challengeType: "sha256", key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
function pack(payload) {
  const checksum = crc32(JSON.stringify(payload));
  return nonce + "::" + tag + "::" + ciphertext;
}
crypto.subtle.encrypt({ name: "AES-GCM", tagLength: 128 }, key, data);
while (!![]) { arr.push(arr.shift()); break; }
const x = "awswaf_session_storage"; const y = "mp_verify"; const z = "difficulty";
"#;
        let features = script_features(script, &[]);
        assert!(features.protection_markers.contains("AWS WAF SDK"));
        assert!(features.crypto_frame.contains("AES-GCM"));
        assert!(features
            .crypto_frame
            .contains("nonce::tag::ciphertext style separator"));
        assert!(features.pow.contains("SHA-256 difficulty PoW hint"));
        assert_eq!(features.hex64_count, 1);
        assert!(!features.contexts.is_empty());
    }

    #[test]
    fn preserves_long_hex_values_in_evidence_contexts() {
        let contexts = evidence_contexts(
            "key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &["key="],
        );
        assert!(contexts[0]["preview"]
            .as_str()
            .unwrap()
            .contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn reconstructs_aws_waf_protocol_from_network_evidence() {
        use crate::models::{BodyCaptureMetadata, HeaderEntry, RequestRecord};

        let input_json = r#"{"version":1,"difficulty":1,"challenge_type":"NetworkBandwidth","region":"ap-east-1"}"#;
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
        let requests = vec![
            RequestRecord {
                id: "r1".into(),
                order: 1,
                time: "now".into(),
                method: "GET".into(),
                host: "73472.edge.sdk.awswaf.com".into(),
                path: "/73472ccc2f21/0416b5675b4f/challenge.js".into(),
                query: None,
                status: 200,
                resource_type: "script".into(),
                size: "1 KB".into(),
                duration: 10,
                source: "browser".into(),
                protocol: "h2".into(),
                tls: "TLS 1.3".into(),
                tls_fingerprint: None,
                risk: "none".into(),
                request_headers: vec![],
                response_headers: vec![HeaderEntry {
                    name: "content-type".into(),
                    value: "application/javascript".into(),
                }],
                request_body: None,
                response_body: r#"function a0_0x1fd3(){var _0x345a0b=["x"];return _0x345a0b;} crypto.subtle.encrypt({name:"AES-GCM",tagLength:128},k,d); arr.push(arr.shift()); const t="awswaf_session_storage"; const y="mp_verify";"#.into(),
                response_body_metadata: BodyCaptureMetadata::default(),
                crypto_snippet_count: 0,
                hook: None,
            },
            RequestRecord {
                id: "r2".into(),
                order: 2,
                time: "now".into(),
                method: "POST".into(),
                host: "73472.edge.sdk.awswaf.com".into(),
                path: "/73472ccc2f21/0416b5675b4f/mp_verify".into(),
                query: None,
                status: 200,
                resource_type: "fetch".into(),
                size: "1 KB".into(),
                duration: 20,
                source: "browser".into(),
                protocol: "h2".into(),
                tls: "TLS 1.3".into(),
                tls_fingerprint: None,
                risk: "none".into(),
                request_headers: vec![HeaderEntry {
                    name: "content-type".into(),
                    value: "multipart/form-data; boundary=----WebKitFormBoundaryabc".into(),
                }],
                response_headers: vec![],
                request_body: Some(mp_body),
                response_body: r#"{"token":"2e1254cf-d58d-4c53-8afb-08be29b8d202:AAoA:VBPEyI28dOLNUpsbxxWAME","inputs":null}"#.into(),
                response_body_metadata: BodyCaptureMetadata::default(),
                crypto_snippet_count: 0,
                hook: None,
            },
            RequestRecord {
                id: "r3".into(),
                order: 3,
                time: "now".into(),
                method: "POST".into(),
                host: "73472.edge.sdk.awswaf.com".into(),
                path: "/73472ccc2f21/0416b5675b4f/telemetry".into(),
                query: None,
                status: 200,
                resource_type: "fetch".into(),
                size: "1 KB".into(),
                duration: 15,
                source: "browser".into(),
                protocol: "h2".into(),
                tls: "TLS 1.3".into(),
                tls_fingerprint: None,
                risk: "none".into(),
                request_headers: vec![],
                response_headers: vec![],
                request_body: Some(
                    r#"{"existing_token":"t","awswaf_session_storage":"null","client":"Browser","signals":[{"name":"Zoey","value":{"Present":"km8::abc"}}],"checksum":"380809BA","metrics":[{"name":"6","value":10,"unit":"2"}]}"#
                        .into(),
                ),
                response_body: r#"{"token":"2e1254cf-d58d-4c53-8afb-08be29b8d202:AAoA:kY3VlQ16","next_interval":100,"awswaf_session_storage":"2e1254cf-d58d-4c53-8afb-08be29b8d202:store"}"#.into(),
                response_body_metadata: BodyCaptureMetadata::default(),
                crypto_snippet_count: 0,
                hook: None,
            },
        ];
        let scripts = vec![json!({
            "obfuscation": ["rotating string array / IIFE", "a0_0x* decoder/array function pattern"],
            "browserSignalMarkers": ["navigator.webdriver", "canvas"]
        })];
        let protocol = reconstruct_protocol_schemas(&requests, &scripts, None);
        assert_eq!(
            protocol["pow"]["challengeType"].as_str(),
            Some("NetworkBandwidth")
        );
        assert_eq!(protocol["signals"]["identifier"].as_str(), Some("Zoey"));
        assert_eq!(protocol["telemetry"]["sessionChain"], true);
        assert_eq!(protocol["challengeSubmit"]["mpVerifyMultipart"], true);
        assert!(protocol["token"]["structure"]
            .as_str()
            .unwrap_or_default()
            .contains("3-segment"));
        assert_eq!(protocol["challengeJs"]["decodedStringDump"], false);
        assert!(protocol["deployment"]["pathTemplate"]
            .as_str()
            .unwrap_or_default()
            .contains("{deployId}"));
    }

    #[test]
    fn expands_captcha_five_step_fields_from_network_evidence_only() {
        let storage = storage();
        let session = storage
            .create_session(Some("captcha-five-step".into()))
            .unwrap();
        let sid = session.id.clone();

        let mut html = base_input(&sid, "www.example.com", "/");
        html.resource_type = "document".into();
        html.response_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: "text/html".into(),
        }];
        html.response_body =
            Some("<html><body><script>window.gokuProps={key:\"k\"}</script></body></html>".into());
        storage.store_request(html).unwrap();

        let mut problem = base_input(&sid, "73472ccc2f21.edge.captcha-sdk.awswaf.com", "/problem");
        problem.response_body = Some(
            r#"{"problem_type":"grid","assets":{"images":"[\"img1\"]","target":"[\"t\"]"},"state":"s"}"#
                .into(),
        );
        storage.store_request(problem).unwrap();

        let mut verify = base_input(&sid, "73472ccc2f21.edge.captcha-sdk.awswaf.com", "/verify");
        verify.method = "POST".into();
        verify.request_body =
            Some(r#"{"goku_props":{"key":"k"},"state":"s","solution":[1,2]}"#.into());
        storage.store_request(verify).unwrap();

        let mut voucher = base_input(&sid, "73472ccc2f21.edge.captcha-sdk.awswaf.com", "/voucher");
        voucher.method = "POST".into();
        voucher.response_body = Some(r#"{"voucher":"abc"}"#.into());
        storage.store_request(voucher).unwrap();

        let result = analyze_session(&storage, &sid).unwrap();
        let captcha = &result["protocolSchemas"]["captcha"];
        assert_eq!(captcha["gokuPropsSeen"], true);
        assert_eq!(captcha["fieldLevelExpanded"], true);
        assert_eq!(captcha["stepsCaptured"]["problem"], true);
        assert_eq!(captcha["stepsCaptured"]["verify"], true);
        assert_eq!(captcha["stepsCaptured"]["voucher"], true);
        assert_eq!(captcha["assetsImagesDoubleEncoded"], true);
        assert_eq!(captcha["verifyUsesGokuPropsSnakeCase"], true);
        let five = captcha["fiveStep"].as_array().expect("fiveStep");
        assert!(five.len() >= 4);
        assert!(
            captcha["problemKeys"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|key| key.contains("problem_type") || key.contains("assets")),
            "problemKeys={:?}",
            captcha["problemKeys"]
        );
    }
}
