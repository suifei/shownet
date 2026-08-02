use crate::models::{BrowserHookEvent, RequestRecord};
use crate::storage::Storage;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_MATCHED_REQUESTS: usize = 100;
const MAX_DYNAMIC_FIELDS: usize = 64;
const MAX_SNIPPET_REQUESTS: usize = 20;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRequestEvidence {
    pub request_id: String,
    pub order: i64,
    pub method: String,
    pub url: String,
    pub status: i64,
    pub protocol: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureAdapterHarness {
    pub adapter_id: String,
    pub adapter_version: String,
    pub vendor: String,
    pub confidence: String,
    pub evidence_hash: String,
    pub matched_requests: Vec<SignatureRequestEvidence>,
    pub dynamic_fields: Vec<String>,
    pub cookie_names: Vec<String>,
    pub hook_names: Vec<String>,
    pub crypto_algorithms: Vec<String>,
    pub fingerprint_dependencies: Vec<String>,
    pub required_inputs: Vec<String>,
    pub evidence_gaps: Vec<String>,
    pub language: String,
    pub code: String,
}

pub fn build_signature_harness(
    storage: &Storage,
    session_id: &str,
    requested_adapter: &str,
) -> Result<SignatureAdapterHarness, String> {
    storage.get_session(session_id)?;
    let requests = storage.list_requests(session_id, Some(10_000), Some(0))?;
    let hooks = storage.list_browser_hooks(session_id, Some(2_000))?;
    let adapter_id = select_adapter(requested_adapter, &requests)?;
    let is_akamai = adapter_id == "akamai-bot-manager";
    let is_aws_waf = adapter_id == "aws-waf-bot-control";

    let mut matched = requests
        .iter()
        .filter(|request| matches_adapter(request, &adapter_id))
        .take(MAX_MATCHED_REQUESTS)
        .collect::<Vec<_>>();
    if matched.is_empty() && adapter_id == "generic-dynamic-signature" {
        matched = requests
            .iter()
            .filter(|request| generic_signature_marker(request))
            .take(MAX_MATCHED_REQUESTS)
            .collect();
    }

    let matched_ids = matched
        .iter()
        .map(|request| request.id.as_str())
        .collect::<BTreeSet<_>>();
    let relevant_hooks = hooks
        .iter()
        .filter(|hook| {
            hook.request_id
                .as_deref()
                .is_some_and(|request_id| matched_ids.contains(request_id))
                || hook_marker(hook)
        })
        .collect::<Vec<_>>();

    let mut snippets_by_request = BTreeMap::new();
    for request in matched
        .iter()
        .filter(|request| request.crypto_snippet_count > 0)
        .take(MAX_SNIPPET_REQUESTS)
    {
        snippets_by_request.insert(
            request.id.clone(),
            storage.get_crypto_snippets(&request.id)?,
        );
    }

    let mut dynamic_fields = BTreeSet::new();
    let mut cookie_names = BTreeSet::new();
    let mut crypto_algorithms = BTreeSet::new();
    let mut fingerprint_dependencies = BTreeSet::new();
    for request in &matched {
        collect_request_fields(request, &mut dynamic_fields, &mut cookie_names);
        if let Some(hook) = request.hook.as_ref() {
            crypto_algorithms.insert(hook.algorithm.clone());
        }
        if let Some(fingerprint) = request.tls_fingerprint.as_ref() {
            fingerprint_dependencies.insert(format!("JA3:{}", fingerprint.inbound.ja3));
            fingerprint_dependencies.insert(format!("JA4:{}", fingerprint.inbound.ja4));
            if let Some(http2) = fingerprint.http2.as_ref() {
                fingerprint_dependencies.insert(format!("H2:{}", http2.hash));
            }
        }
        if let Some(snippets) = snippets_by_request.get(&request.id) {
            for algorithm in snippets.iter().flat_map(|snippet| &snippet.algorithms) {
                crypto_algorithms.insert(algorithm.clone());
            }
        }
    }
    let hook_names = relevant_hooks
        .iter()
        .map(|hook| format!("{}:{}", hook.kind, hook.name))
        .collect::<BTreeSet<_>>();

    let mut required_inputs = BTreeSet::from(["timestamp".to_string(), "userAgent".to_string()]);
    if is_akamai {
        required_inputs.extend([
            "language".to_string(),
            "performanceTiming".to_string(),
            "screen".to_string(),
            "timezone".to_string(),
            "viewport".to_string(),
        ]);
    }
    if is_aws_waf {
        required_inputs.extend([
            "domain".to_string(),
            "challengeInput".to_string(),
            "challengeHmac".to_string(),
            "region".to_string(),
            "browserSignals".to_string(),
            "existingToken".to_string(),
        ]);
    }
    if !cookie_names.is_empty() {
        required_inputs.insert("cookies".to_string());
    }
    if !fingerprint_dependencies.is_empty() {
        required_inputs.insert("clientFingerprint".to_string());
    }
    if !hook_names.is_empty() {
        required_inputs.insert("runtimeHooks".to_string());
    }

    let mut evidence_gaps = Vec::new();
    if matched.is_empty() {
        evidence_gaps.push("未检测到与适配器匹配的请求，需先抓取目标页面完整交互".to_string());
    }
    if relevant_hooks.is_empty() {
        evidence_gaps.push("缺少关联运行时 Hook，尚不能确认字段生成顺序和原始输入".to_string());
    }
    if snippets_by_request.values().all(Vec::is_empty) {
        evidence_gaps
            .push("缺少可用加密代码片段，computeDynamicFields 需要人工或 Agent 补全".to_string());
    }
    if fingerprint_dependencies.is_empty() {
        evidence_gaps.push("缺少客户端 TLS/HTTP2 指纹，无法判断签名与网络指纹的耦合".to_string());
    }
    if is_akamai {
        evidence_gaps.push(
            "Akamai 版本会持续变化；适配器必须用当前会话的真实响应与 Cookie 状态回归验证"
                .to_string(),
        );
    }
    if is_aws_waf {
        evidence_gaps.push(
            "AWS WAF 适配器只固化本会话观察到的 challenge/telemetry/token 字段契约；AES 密钥、PoW 求解与 CAPTCHA 需由 computeDynamicFields 按当前部署实现"
                .to_string(),
        );
        if !matched.iter().any(|request| {
            request.path.to_ascii_lowercase().contains("mp_verify")
                || request.path.to_ascii_lowercase().contains("/verify")
        }) {
            evidence_gaps
                .push("未捕获 mp_verify/verify 提交请求，token 签发流程不完整".to_string());
        }
        if !matched
            .iter()
            .any(|request| request.path.to_ascii_lowercase().contains("telemetry"))
        {
            evidence_gaps.push("未捕获 telemetry 固化请求，token 会话链可能不完整".to_string());
        }
    }

    let matched_requests = matched
        .iter()
        .map(|request| SignatureRequestEvidence {
            request_id: request.id.clone(),
            order: request.order,
            method: request.method.clone(),
            url: format!("https://{}{}", request.host, request.path),
            status: request.status,
            protocol: request.protocol.clone(),
        })
        .collect::<Vec<_>>();
    let dynamic_fields = dynamic_fields
        .into_iter()
        .take(MAX_DYNAMIC_FIELDS)
        .collect::<Vec<_>>();
    let cookie_names = cookie_names.into_iter().collect::<Vec<_>>();
    let hook_names = hook_names.into_iter().collect::<Vec<_>>();
    let crypto_algorithms = crypto_algorithms.into_iter().collect::<Vec<_>>();
    let fingerprint_dependencies = fingerprint_dependencies.into_iter().collect::<Vec<_>>();
    let required_inputs = required_inputs.into_iter().collect::<Vec<_>>();
    let evidence_hash = evidence_hash(
        &adapter_id,
        &matched_requests,
        &dynamic_fields,
        &cookie_names,
        &hook_names,
        &crypto_algorithms,
        &fingerprint_dependencies,
    );
    let adapter_version = match adapter_id.as_str() {
        "aws-waf-bot-control" => "1.0.0",
        "akamai-bot-manager" => "1.0.0",
        _ => "1.0.0",
    }
    .to_string();
    let vendor = if is_aws_waf {
        "AWS WAF"
    } else if is_akamai {
        "Akamai"
    } else {
        "Generic"
    }
    .to_string();
    let confidence = confidence(
        is_akamai || is_aws_waf,
        matched_requests.len(),
        relevant_hooks.len(),
        snippets_by_request.values().map(Vec::len).sum(),
        fingerprint_dependencies.len(),
        cookie_names.len(),
    );
    let code = render_harness(
        &adapter_id,
        &adapter_version,
        &evidence_hash,
        &matched_requests,
        &dynamic_fields,
        &cookie_names,
        &required_inputs,
    )?;

    Ok(SignatureAdapterHarness {
        adapter_id,
        adapter_version,
        vendor,
        confidence,
        evidence_hash,
        matched_requests,
        dynamic_fields,
        cookie_names,
        hook_names,
        crypto_algorithms,
        fingerprint_dependencies,
        required_inputs,
        evidence_gaps,
        language: "javascript".to_string(),
        code,
    })
}

fn select_adapter(requested: &str, requests: &[RequestRecord]) -> Result<String, String> {
    match requested.trim() {
        "" | "auto" => Ok(if requests.iter().any(aws_waf_marker) {
            "aws-waf-bot-control"
        } else if requests.iter().any(akamai_marker) {
            "akamai-bot-manager"
        } else {
            "generic-dynamic-signature"
        }
        .to_string()),
        "aws-waf-bot-control" | "akamai-bot-manager" | "generic-dynamic-signature" => {
            Ok(requested.trim().to_string())
        }
        other => Err(format!("不支持的动态签名适配器: {other}")),
    }
}

fn matches_adapter(request: &RequestRecord, adapter_id: &str) -> bool {
    match adapter_id {
        "aws-waf-bot-control" => aws_waf_marker(request),
        "akamai-bot-manager" => akamai_marker(request),
        _ => generic_signature_marker(request) || akamai_marker(request) || aws_waf_marker(request),
    }
}

fn aws_waf_marker(request: &RequestRecord) -> bool {
    let evidence = request_evidence(request);
    [
        "awswaf",
        "aws-waf",
        "aws-waf-token",
        "x-aws-waf-token",
        "awswaf_session_storage",
        "challenge.js",
        "captcha.js",
        "mp_verify",
        "edge.sdk.awswaf",
        "edge.captcha",
        "token.awswaf",
        "captcha.awswaf",
        "gokuprops",
        "/voucher",
    ]
    .iter()
    .any(|marker| evidence.contains(marker))
        || request.path.to_ascii_lowercase().contains("telemetry") && evidence.contains("awswaf")
}

fn akamai_marker(request: &RequestRecord) -> bool {
    let evidence = request_evidence(request);
    [
        "akamai",
        "sensor_data",
        "sensor-data",
        "/sensor",
        "_abck",
        "bm_sz",
        "bm_mi",
        "ak_bmsc",
        "sec-cpt",
        "bot-manager",
    ]
    .iter()
    .any(|marker| evidence.contains(marker))
}

fn generic_signature_marker(request: &RequestRecord) -> bool {
    let evidence = request_evidence(request);
    [
        "signature",
        "x-sign",
        "x-signature",
        "sign=",
        "nonce",
        "sensor",
        "fingerprint",
    ]
    .iter()
    .any(|marker| evidence.contains(marker))
        || request.hook.is_some()
        || request.crypto_snippet_count > 0
}

fn request_evidence(request: &RequestRecord) -> String {
    format!(
        "{} {} {} {} {} {} {}",
        request.host,
        request.path,
        request.query.as_deref().unwrap_or_default(),
        request.request_body.as_deref().unwrap_or_default(),
        header_text(&request.request_headers),
        header_text(&request.response_headers),
        request
            .hook
            .as_ref()
            .map(|hook| hook.algorithm.as_str())
            .unwrap_or_default(),
    )
    .to_ascii_lowercase()
}

fn header_text(headers: &[crate::models::HeaderEntry]) -> String {
    headers
        .iter()
        .map(|header| format!("{}={}", header.name, header.value))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hook_marker(hook: &BrowserHookEvent) -> bool {
    let evidence = format!(
        "{} {} {}",
        hook.name,
        hook.url.as_deref().unwrap_or_default(),
        hook.stack.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase();
    ["akamai", "sensor", "signature", "fingerprint"]
        .iter()
        .any(|marker| evidence.contains(marker))
}

fn collect_request_fields(
    request: &RequestRecord,
    fields: &mut BTreeSet<String>,
    cookies: &mut BTreeSet<String>,
) {
    if let Some(query) = request.query.as_deref() {
        collect_form_keys(query, fields);
    }
    if let Some(body) = request.request_body.as_deref() {
        if let Ok(value) = serde_json::from_str::<Value>(body) {
            collect_json_keys(&value, "", fields);
        } else if body.contains('=') {
            collect_form_keys(body, fields);
        }
    }
    for header in &request.request_headers {
        if header.name.eq_ignore_ascii_case("cookie") {
            collect_cookie_names(&header.value, cookies);
        }
        if dynamic_field_marker(&header.name) {
            fields.insert(header.name.to_ascii_lowercase());
        }
    }
    for header in &request.response_headers {
        if header.name.eq_ignore_ascii_case("set-cookie") {
            if let Some((name, _)) = header.value.split_once('=') {
                let name = name.trim();
                if !name.is_empty() {
                    cookies.insert(name.to_string());
                }
            }
        }
    }
}

fn collect_form_keys(value: &str, fields: &mut BTreeSet<String>) {
    for part in value.split('&') {
        let key = part.split_once('=').map_or(part, |(key, _)| key).trim();
        if !key.is_empty() && (dynamic_field_marker(key) || fields.len() < 16) {
            fields.insert(key.to_string());
        }
    }
}

fn collect_json_keys(value: &Value, prefix: &str, fields: &mut BTreeSet<String>) {
    if fields.len() >= MAX_DYNAMIC_FIELDS {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                if dynamic_field_marker(key) || fields.len() < 16 {
                    fields.insert(path.clone());
                }
                collect_json_keys(value, &path, fields);
            }
        }
        Value::Array(values) => {
            if let Some(value) = values.first() {
                collect_json_keys(value, prefix, fields);
            }
        }
        _ => {}
    }
}

fn dynamic_field_marker(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "sign",
        "sensor",
        "nonce",
        "timestamp",
        "token",
        "fingerprint",
        "device",
        "_abck",
        "bm_",
        "challenge",
        "signal",
        "checksum",
        "hmac",
        "solution",
        "metrics",
        "voucher",
        "awswaf",
        "goku",
        "captcha",
        "difficulty",
        "region",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

fn collect_cookie_names(value: &str, cookies: &mut BTreeSet<String>) {
    for part in value.split(';') {
        if let Some((name, _)) = part.trim().split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                cookies.insert(name.to_string());
            }
        }
    }
}

fn evidence_hash(
    adapter_id: &str,
    requests: &[SignatureRequestEvidence],
    fields: &[String],
    cookies: &[String],
    hooks: &[String],
    algorithms: &[String],
    fingerprints: &[String],
) -> String {
    let canonical = format!(
        "adapter={adapter_id}|requests={}|fields={}|cookies={}|hooks={}|algorithms={}|fingerprints={}",
        requests
            .iter()
            .map(|request| format!("{}:{}:{}", request.method, request.url, request.protocol))
            .collect::<Vec<_>>()
            .join(","),
        fields.join(","),
        cookies.join(","),
        hooks.join(","),
        algorithms.join(","),
        fingerprints.join(","),
    );
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

fn confidence(
    is_akamai: bool,
    requests: usize,
    hooks: usize,
    snippets: usize,
    fingerprints: usize,
    cookies: usize,
) -> String {
    let score = usize::from(is_akamai) * 2
        + usize::from(requests > 0) * 2
        + usize::from(hooks > 0) * 2
        + usize::from(snippets > 0)
        + usize::from(fingerprints > 0)
        + usize::from(cookies > 0);
    if score >= 7 {
        "high"
    } else if score >= 4 {
        "medium"
    } else {
        "low"
    }
    .to_string()
}

fn render_harness(
    adapter_id: &str,
    adapter_version: &str,
    evidence_hash: &str,
    requests: &[SignatureRequestEvidence],
    dynamic_fields: &[String],
    cookie_names: &[String],
    required_inputs: &[String],
) -> Result<String, String> {
    let manifest = serde_json::json!({
        "adapterId": adapter_id,
        "adapterVersion": adapter_version,
        "evidenceHash": evidence_hash,
        "endpoints": requests,
        "dynamicFields": dynamic_fields,
        "cookieNames": cookie_names,
        "requiredInputs": required_inputs,
    });
    let manifest = serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?;
    Ok(format!(
        r#"// Generated by ShowNet. Runtime credentials and dynamic values are supplied through context; captured evidence remains in ShowNet.
export const manifest = Object.freeze({manifest});

export function createSignatureAdapter(computeDynamicFields) {{
  if (typeof computeDynamicFields !== "function") {{
    throw new TypeError("computeDynamicFields must be implemented from current Hook/code evidence");
  }}

  return Object.freeze({{
    manifest,
    async buildRequest(context) {{
      const missingInputs = manifest.requiredInputs.filter((name) => context?.[name] == null);
      if (missingInputs.length) {{
        throw new Error(`Missing adapter inputs: ${{missingInputs.join(", ")}}`);
      }}

      const dynamicFields = await computeDynamicFields({{
        context,
        evidenceHash: manifest.evidenceHash,
        adapterVersion: manifest.adapterVersion,
      }});
      const missingFields = manifest.dynamicFields.filter((name) => !(name in dynamicFields));
      if (missingFields.length) {{
        throw new Error(`Dynamic implementation did not produce: ${{missingFields.join(", ")}}`);
      }}

      const endpoint = context.endpoint ?? manifest.endpoints[0];
      if (!endpoint) throw new Error("No captured endpoint is available");
      return {{
        url: endpoint.url,
        method: context.method ?? endpoint.method,
        headers: {{ ...context.headers }},
        body: context.encodeBody
          ? context.encodeBody({{ ...context.staticFields, ...dynamicFields }})
          : JSON.stringify({{ ...context.staticFields, ...dynamicFields }}),
      }};
    }},
  }});
}}
"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BodyCaptureMetadata, HeaderEntry, HookRecord};

    fn request(path: &str) -> RequestRecord {
        RequestRecord {
            id: "request-akamai".to_string(),
            order: 7,
            time: "now".to_string(),
            method: "POST".to_string(),
            host: "example.test".to_string(),
            path: path.to_string(),
            query: Some("sensor_data=dynamic&nonce=1".to_string()),
            status: 200,
            resource_type: "fetch".to_string(),
            size: "1 KB".to_string(),
            duration: 100,
            source: "browser".to_string(),
            protocol: "h2".to_string(),
            tls: "TLS 1.3".to_string(),
            tls_fingerprint: None,
            risk: "none".to_string(),
            request_headers: vec![HeaderEntry {
                name: "cookie".to_string(),
                value: "_abck=COOKIE_VALUE_SHOULD_NOT_APPEAR; bm_sz=ANOTHER_PRIVATE_VALUE"
                    .to_string(),
            }],
            response_headers: Vec::new(),
            request_body: Some(r#"{"sensorData":"value","device":{"screen":"x"}}"#.to_string()),
            response_body: String::new(),
            response_body_metadata: BodyCaptureMetadata::default(),
            crypto_snippet_count: 0,
            hook: Some(HookRecord {
                algorithm: "Akamai Sensor".to_string(),
                input: "secret".to_string(),
                output: "secret".to_string(),
            }),
        }
    }

    #[test]
    fn detects_akamai_and_collects_names_without_values() {
        let request = request("/_bm/_data");
        assert_eq!(
            select_adapter("auto", std::slice::from_ref(&request)).unwrap(),
            "akamai-bot-manager"
        );
        let mut fields = BTreeSet::new();
        let mut cookies = BTreeSet::new();
        collect_request_fields(&request, &mut fields, &mut cookies);
        assert!(fields.contains("sensor_data"));
        assert!(fields.contains("sensorData"));
        assert!(cookies.contains("_abck"));
        assert!(cookies.contains("bm_sz"));
        let rendered = render_harness(
            "akamai-bot-manager",
            "1.0.0",
            "hash",
            &[],
            &fields.into_iter().collect::<Vec<_>>(),
            &cookies.into_iter().collect::<Vec<_>>(),
            &["timestamp".to_string()],
        )
        .unwrap();
        assert!(rendered.contains("computeDynamicFields"));
        assert!(!rendered.contains("COOKIE_VALUE_SHOULD_NOT_APPEAR"));
        assert!(!rendered.contains("ANOTHER_PRIVATE_VALUE"));
    }

    #[test]
    fn rejects_unknown_adapter_versions() {
        assert!(select_adapter("unknown", &[]).is_err());
    }
}
