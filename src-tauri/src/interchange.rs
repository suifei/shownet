use crate::models::{
    BodyCaptureMetadata, CaptureRule, CaptureRuleRun, CryptoCodeSnippet, HeaderEntry, HookRecord,
    RequestAnnotation,
};
use crate::tls_fingerprint::TlsFingerprintRecord;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const BUNDLE_FORMAT: &str = "shownet-session";
pub const BUNDLE_VERSION: u32 = 1;
pub const MAX_BUNDLE_REQUESTS: usize = 100_000;
pub const MAX_BUNDLE_EVENTS: usize = 500_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionBundle {
    pub format: String,
    pub version: u32,
    pub exported_at: String,
    pub session: BundleSession,
    #[serde(default)]
    pub requests: Vec<BundleRequest>,
    #[serde(default)]
    pub events: Vec<BundleEvent>,
    #[serde(default)]
    pub annotations: Vec<RequestAnnotation>,
    #[serde(default)]
    pub rules: Vec<CaptureRule>,
    #[serde(default)]
    pub rule_traces: Vec<CaptureRuleRun>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleSession {
    pub name: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleRequest {
    pub id: String,
    pub sequence: i64,
    pub source: String,
    pub source_instance_id: String,
    pub started_at: i64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: Option<i64>,
    pub path: String,
    pub query: Option<String>,
    pub status: i64,
    pub resource_type: String,
    pub size_bytes: i64,
    pub duration_ms: i64,
    pub protocol: String,
    pub tls_version: String,
    pub risk_level: String,
    #[serde(default)]
    pub request_headers: Vec<HeaderEntry>,
    #[serde(default)]
    pub response_headers: Vec<HeaderEntry>,
    pub request_body: Option<String>,
    pub response_body: String,
    #[serde(default)]
    pub response_body_metadata: BodyCaptureMetadata,
    #[serde(default)]
    pub crypto_snippets: Vec<CryptoCodeSnippet>,
    pub hook: Option<HookRecord>,
    pub tls_fingerprint: Option<TlsFingerprintRecord>,
    #[serde(default)]
    pub replayed_from_request_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleEvent {
    pub sequence: i64,
    pub timestamp: i64,
    pub source: String,
    pub source_instance_id: String,
    pub request_id: String,
    pub phase: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    ShowNet,
    Har,
    Postman,
    OpenApi,
}

impl ExportFormat {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "shownet" => Ok(Self::ShowNet),
            "har" => Ok(Self::Har),
            "postman" => Ok(Self::Postman),
            "openapi" => Ok(Self::OpenApi),
            _ => Err(format!("不支持的导出格式: {value}")),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ShowNet => "ShowNet Session",
            Self::Har => "HAR 1.2",
            Self::Postman => "Postman Collection 2.1",
            Self::OpenApi => "OpenAPI 3.1",
        }
    }
}

pub fn validate_bundle(bundle: &SessionBundle) -> Result<(), String> {
    if bundle.format != BUNDLE_FORMAT {
        return Err("不是有效的 ShowNet Session 文件".to_string());
    }
    if bundle.version != BUNDLE_VERSION {
        return Err(format!("不支持的 ShowNet Session 版本: {}", bundle.version));
    }
    if bundle.requests.len() > MAX_BUNDLE_REQUESTS || bundle.events.len() > MAX_BUNDLE_EVENTS {
        return Err("会话文件包含过多请求或事件".to_string());
    }
    if bundle.session.name.trim().is_empty() {
        return Err("会话文件缺少名称".to_string());
    }

    let mut request_ids = BTreeSet::new();
    let mut request_sequences = BTreeSet::new();
    for request in &bundle.requests {
        if request.id.is_empty()
            || request.host.trim().is_empty()
            || request.path.trim().is_empty()
            || request.sequence <= 0
        {
            return Err("会话文件包含无效请求".to_string());
        }
        if !request_ids.insert(request.id.as_str()) || !request_sequences.insert(request.sequence) {
            return Err("会话文件包含重复的请求 ID 或顺序号".to_string());
        }
    }
    let mut annotated_request_ids = BTreeSet::new();
    for annotation in &bundle.annotations {
        if !request_ids.contains(annotation.request_id.as_str())
            || !annotated_request_ids.insert(annotation.request_id.as_str())
            || annotation.note.chars().count() > 20_000
            || annotation.tags.len() > 20
        {
            return Err("会话文件包含无效请求标注".to_string());
        }
        if annotation
            .color
            .as_deref()
            .is_some_and(|color| !matches!(color, "red" | "yellow" | "green" | "blue" | "gray"))
        {
            return Err("会话文件包含无效标注颜色".to_string());
        }
    }
    if bundle.requests.iter().any(|request| {
        request
            .replayed_from_request_id
            .as_deref()
            .is_some_and(|id| !request_ids.contains(id))
    }) {
        return Err("会话文件包含无效重放来源".to_string());
    }
    let mut rule_ids = BTreeSet::new();
    if bundle
        .rules
        .iter()
        .any(|rule| rule.id.is_empty() || !rule_ids.insert(rule.id.as_str()))
        || bundle.rule_traces.len() > MAX_BUNDLE_EVENTS
        || bundle.rule_traces.iter().any(|trace| {
            !request_ids.contains(trace.request_id.as_str())
                || !rule_ids.contains(trace.rule_id.as_str())
        })
    {
        return Err("会话文件包含无效规则轨迹".to_string());
    }
    let mut event_sequences = BTreeSet::new();
    for event in &bundle.events {
        if event.sequence <= 0 || !event_sequences.insert(event.sequence) {
            return Err("会话文件包含无效或重复的事件顺序号".to_string());
        }
    }
    Ok(())
}

pub fn render_export(bundle: &SessionBundle, format: ExportFormat) -> Result<String, String> {
    validate_bundle(bundle)?;
    let value = match format {
        ExportFormat::ShowNet => return pretty_json(bundle),
        ExportFormat::Har => render_har(bundle),
        ExportFormat::Postman => render_postman(bundle),
        ExportFormat::OpenApi => render_openapi(bundle),
    };
    pretty_json(&value)
}

pub fn generate_code(request: &BundleRequest, template: &str) -> Result<String, String> {
    let url = request_url(request);
    let headers = request.request_headers.clone();
    match template {
        "curl" => Ok(curl_code(request, &url, &headers)),
        "httpie" => Ok(httpie_code(request, &url, &headers)),
        "python" => Ok(python_code(request, &url, &headers)),
        "java" => Ok(java_code(request, &url, &headers)),
        "fetch" => Ok(fetch_code(request, &url, &headers)),
        "axios" => Ok(axios_code(request, &url, &headers)),
        "go" => Ok(go_code(request, &url, &headers)),
        _ => Err(format!("不支持的代码模板: {template}")),
    }
}

fn render_har(bundle: &SessionBundle) -> Value {
    let annotations = bundle
        .annotations
        .iter()
        .map(|annotation| (annotation.request_id.as_str(), annotation))
        .collect::<BTreeMap<_, _>>();
    let entries = bundle
        .requests
        .iter()
        .map(|request| {
            let request_headers = request.request_headers.clone();
            let response_headers = request.response_headers.clone();
            let mut har_request = json!({
                "method": request.method,
                "url": request_url(request),
                "httpVersion": request.protocol,
                "cookies": [],
                "headers": har_headers(&request_headers),
                "queryString": query_pairs(request.query.as_deref()),
                "headersSize": -1,
                "bodySize": request.request_body.as_ref().map_or(0, |body| body.len()),
            });
            if let Some(body) = &request.request_body {
                har_request["postData"] = json!({
                    "mimeType": content_type(&request_headers),
                    "text": body,
                });
            }
            let decoded_size = if request.response_body_metadata.decoded_bytes > 0 {
                request.response_body_metadata.decoded_bytes
            } else {
                request.response_body.len() as i64
            };
            let mut content = json!({
                "size": decoded_size,
                "mimeType": content_type(&response_headers),
                "text": request.response_body,
            });
            if request.response_body_metadata.format == "base64" {
                content["text"] = json!(request
                    .response_body
                    .strip_prefix("base64:")
                    .unwrap_or(&request.response_body));
                content["encoding"] = json!("base64");
            }
            if request.response_body_metadata.decoded
                && request.response_body_metadata.wire_bytes > 0
                && decoded_size >= request.response_body_metadata.wire_bytes
            {
                content["compression"] =
                    json!(decoded_size - request.response_body_metadata.wire_bytes);
            }
            let mut entry = json!({
                "startedDateTime": timestamp_to_rfc3339(request.started_at),
                "time": request.duration_ms,
                "request": har_request,
                "response": {
                    "status": request.status,
                    "statusText": "",
                    "httpVersion": request.protocol,
                    "cookies": [],
                    "headers": har_headers(&response_headers),
                    "content": content,
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": request.size_bytes,
                },
                "cache": {},
                "timings": { "send": 0, "wait": request.duration_ms, "receive": 0 },
                "comment": format!("ShowNet source={} risk={}", request.source, request.risk_level),
            });
            if let Some(fingerprint) = &request.tls_fingerprint {
                entry["_shownetTlsFingerprint"] =
                    serde_json::to_value(fingerprint).unwrap_or(Value::Null);
            }
            if request.response_body_metadata.captured {
                entry["_shownetBodyCapture"] =
                    serde_json::to_value(&request.response_body_metadata).unwrap_or(Value::Null);
            }
            if let Some(annotation) = annotations.get(request.id.as_str()) {
                entry["_shownet"] = json!({ "annotation": annotation });
            }
            entry
        })
        .collect::<Vec<_>>();
    json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "ShowNet", "version": env!("CARGO_PKG_VERSION") },
            "pages": [{
                "startedDateTime": timestamp_to_rfc3339(bundle.session.created_at),
                "id": "shownet-session",
                "title": bundle.session.name,
                "pageTimings": {},
            }],
            "entries": entries,
        }
    })
}

fn render_postman(bundle: &SessionBundle) -> Value {
    let items = bundle
        .requests
        .iter()
        .map(|request| {
            let headers = request.request_headers.clone();
            let mut postman_request = json!({
                "method": request.method,
                "header": headers.iter().map(|header| json!({
                    "key": header.name,
                    "value": header.value,
                    "type": "text",
                })).collect::<Vec<_>>(),
                "url": request_url(request),
            });
            if let Some(body) = &request.request_body {
                postman_request["body"] = json!({ "mode": "raw", "raw": body });
            }
            json!({
                "name": format!("{} {}", request.method, request.path),
                "request": postman_request,
                "response": [],
            })
        })
        .collect::<Vec<_>>();
    json!({
        "info": {
            "name": bundle.session.name,
            "description": "Exported by ShowNet",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    })
}

fn render_openapi(bundle: &SessionBundle) -> Value {
    let mut paths = Map::new();
    let mut servers = BTreeSet::new();
    for request in &bundle.requests {
        if request.method == "CONNECT" {
            continue;
        }
        let server = request_origin(request);
        servers.insert(server.clone());
        let method = request.method.to_ascii_lowercase();
        let path_item = paths
            .entry(request.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(operations) = path_item.as_object_mut() else {
            continue;
        };
        if operations.contains_key(&method) {
            continue;
        }
        let headers = request.request_headers.clone();
        let parameters = query_pairs(request.query.as_deref())
            .into_iter()
            .map(|pair| {
                json!({
                    "name": pair["name"],
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "example": pair["value"],
                })
            })
            .collect::<Vec<_>>();
        let mut operation = json!({
            "summary": format!("{} {}", request.method, request.path),
            "operationId": format!("shownet_{}_{}", method, sanitize_identifier(&request.path)),
            "servers": [{ "url": server }],
            "parameters": parameters,
            "responses": {
                request.status.to_string(): {
                    "description": "Captured response",
                    "content": {
                        content_type(&request.response_headers): {
                            "example": parse_example(&request.response_body),
                        }
                    }
                }
            },
            "x-shownet-source": request.source,
        });
        if let Some(body) = &request.request_body {
            operation["requestBody"] = json!({
                "content": {
                    content_type(&headers): { "example": parse_example(body) }
                }
            });
        }
        operations.insert(method, operation);
    }
    json!({
        "openapi": "3.1.0",
        "info": { "title": bundle.session.name, "version": "1.0.0" },
        "servers": servers.into_iter().map(|url| json!({ "url": url })).collect::<Vec<_>>(),
        "paths": paths,
    })
}

fn curl_code(request: &BundleRequest, url: &str, headers: &[HeaderEntry]) -> String {
    let mut lines = vec![format!(
        "curl --request {} {}",
        request.method,
        shell_quote(url)
    )];
    for header in code_headers(headers) {
        lines.push(format!(
            "  --header {}",
            shell_quote(&format!("{}: {}", header.name, header.value))
        ));
    }
    if let Some(body) = &request.request_body {
        lines.push(format!("  --data-raw {}", shell_quote(body)));
    }
    lines.join(" \\\n")
}

fn httpie_code(request: &BundleRequest, url: &str, headers: &[HeaderEntry]) -> String {
    let mut parts = vec!["http".to_string(), request.method.clone(), shell_quote(url)];
    for header in code_headers(headers) {
        parts.push(shell_quote(&format!("{}:{}", header.name, header.value)));
    }
    if let Some(body) = &request.request_body {
        parts.push(format!("<<< {}", shell_quote(body)));
    }
    parts.join(" \\\n  ")
}

fn python_code(request: &BundleRequest, url: &str, headers: &[HeaderEntry]) -> String {
    let headers = headers_object(headers);
    let mut arguments = vec![
        json_string(&request.method),
        json_string(url),
        format!("headers={}", python_dict(&headers)),
    ];
    if let Some(body) = &request.request_body {
        arguments.push(format!("data={}", json_string(body)));
    }
    format!(
        "import requests\n\nresponse = requests.request(\n    {},\n)\nresponse.raise_for_status()\nprint(response.text)",
        arguments.join(",\n    ")
    )
}

fn java_code(request: &BundleRequest, url: &str, headers: &[HeaderEntry]) -> String {
    let body_publisher = request
        .request_body
        .as_deref()
        .map(|body| {
            format!(
                "HttpRequest.BodyPublishers.ofString({}, StandardCharsets.UTF_8)",
                json_string(body)
            )
        })
        .unwrap_or_else(|| "HttpRequest.BodyPublishers.noBody()".to_string());
    let header_lines = code_headers(headers)
        .map(|header| {
            format!(
                "    .header({}, {})",
                json_string(&header.name),
                json_string(&header.value)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "import java.net.URI;\nimport java.net.http.HttpClient;\nimport java.net.http.HttpRequest;\nimport java.net.http.HttpResponse;\nimport java.nio.charset.StandardCharsets;\n\npublic class Main {{\n    public static void main(String[] args) throws Exception {{\n        HttpClient client = HttpClient.newHttpClient();\n        HttpRequest request = HttpRequest.newBuilder()\n            .uri(URI.create({})){}\n            .method({}, {})\n            .build();\n\n        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());\n        System.out.println(response.statusCode());\n        System.out.println(response.body());\n    }}\n}}",
        json_string(url),
        if header_lines.is_empty() {
            "".to_string()
        } else {
            format!("\n{header_lines}")
        },
        json_string(&request.method),
        body_publisher,
    )
}

fn fetch_code(request: &BundleRequest, url: &str, headers: &[HeaderEntry]) -> String {
    let mut options = vec![format!("  method: {},", json_string(&request.method))];
    options.push(format!(
        "  headers: {},",
        serde_json::to_string_pretty(&headers_object(headers)).unwrap_or_else(|_| "{}".to_string())
    ));
    if let Some(body) = &request.request_body {
        options.push(format!("  body: {},", json_string(body)));
    }
    format!(
        "const response = await fetch({}, {{\n{}\n}});\n\nif (!response.ok) throw new Error(`HTTP ${{response.status}}`);\nconsole.log(await response.text());",
        json_string(url),
        options.join("\n")
    )
}

fn axios_code(request: &BundleRequest, url: &str, headers: &[HeaderEntry]) -> String {
    let mut fields = vec![
        format!(
            "  method: {},",
            json_string(&request.method.to_ascii_lowercase())
        ),
        format!("  url: {},", json_string(url)),
        format!(
            "  headers: {},",
            serde_json::to_string_pretty(&headers_object(headers))
                .unwrap_or_else(|_| "{}".to_string())
        ),
    ];
    if let Some(body) = &request.request_body {
        fields.push(format!("  data: {},", json_string(body)));
    }
    format!(
        "import axios from \"axios\";\n\nconst response = await axios({{\n{}\n}});\nconsole.log(response.data);",
        fields.join("\n")
    )
}

fn go_code(request: &BundleRequest, url: &str, headers: &[HeaderEntry]) -> String {
    let body = request
        .request_body
        .as_deref()
        .map(json_string)
        .unwrap_or_else(|| "\"\"".to_string());
    let mut header_lines = Vec::new();
    for header in code_headers(headers) {
        header_lines.push(format!(
            "req.Header.Set({}, {})",
            json_string(&header.name),
            json_string(&header.value)
        ));
    }
    format!(
        "package main\n\nimport (\n    \"fmt\"\n    \"io\"\n    \"net/http\"\n    \"strings\"\n)\n\nfunc main() {{\n    req, err := http.NewRequest({}, {}, strings.NewReader({}))\n    if err != nil {{ panic(err) }}\n    {}\n\n    response, err := http.DefaultClient.Do(req)\n    if err != nil {{ panic(err) }}\n    defer response.Body.Close()\n    data, err := io.ReadAll(response.Body)\n    if err != nil {{ panic(err) }}\n    fmt.Println(string(data))\n}}",
        json_string(&request.method),
        json_string(url),
        body,
        header_lines.join("\n    ")
    )
}

fn request_url(request: &BundleRequest) -> String {
    let mut url = format!("{}://{}", request.scheme, authority(request));
    if request.path.starts_with('/') {
        url.push_str(&request.path);
    } else {
        url.push('/');
        url.push_str(&request.path);
    }
    if let Some(query) = request.query.as_deref().filter(|value| !value.is_empty()) {
        url.push('?');
        url.push_str(query);
    }
    url
}

fn request_origin(request: &BundleRequest) -> String {
    format!("{}://{}", request.scheme, authority(request))
}

fn authority(request: &BundleRequest) -> String {
    match request.port {
        Some(port)
            if !(request.scheme == "https" && port == 443)
                && !(request.scheme == "http" && port == 80) =>
        {
            format!("{}:{port}", request.host)
        }
        _ => request.host.clone(),
    }
}

fn code_headers(headers: &[HeaderEntry]) -> impl Iterator<Item = &HeaderEntry> {
    headers.iter().filter(|header| {
        let name = header.name.to_ascii_lowercase();
        !name.starts_with(':') && !matches!(name.as_str(), "host" | "content-length" | "connection")
    })
}

fn headers_object(headers: &[HeaderEntry]) -> BTreeMap<String, String> {
    code_headers(headers)
        .map(|header| (header.name.clone(), header.value.clone()))
        .collect()
}

fn har_headers(headers: &[HeaderEntry]) -> Vec<Value> {
    headers
        .iter()
        .map(|header| json!({ "name": header.name, "value": header.value }))
        .collect()
}

fn content_type(headers: &[HeaderEntry]) -> String {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| {
            header
                .value
                .split(';')
                .next()
                .unwrap_or("text/plain")
                .to_string()
        })
        .unwrap_or_else(|| "text/plain".to_string())
}

fn query_pairs(query: Option<&str>) -> Vec<Value> {
    query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            json!({ "name": name, "value": value })
        })
        .collect()
}

fn parse_example(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.to_string()))
}

fn sanitize_identifier(path: &str) -> String {
    let value = path
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    value.trim_matches('_').to_string()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn python_dict(headers: &BTreeMap<String, String>) -> String {
    let entries = headers
        .iter()
        .map(|(name, value)| format!("{}: {}", json_string(name), json_string(value)))
        .collect::<Vec<_>>();
    format!("{{{}}}", entries.join(", "))
}

fn pretty_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|error| error.to_string())
}

fn timestamp_to_rfc3339(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp_millis(timestamp)
        .unwrap_or_else(Utc::now)
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_authentication_headers_in_exports_and_code() {
        let request = request();
        let code = generate_code(&request, "curl").unwrap();
        assert!(code.contains("Authorization: Bearer secret"));

        let har = render_export(&bundle(request), ExportFormat::Har).unwrap();
        assert!(har.contains("Bearer secret"));
    }

    #[test]
    fn shownet_exports_complete_rule_operations() {
        let mut bundle = bundle(request());
        bundle.rules = vec![
            rule(
                "request-rule",
                "request",
                json!({"kind":"rewrite","operations":[
                    {"target":"request.body","op":"replace","pattern":"request-pattern-secret","value":"request-body-rule-secret"},
                    {"target":"request.header","op":"set","name":"Authorization","value":"Bearer rule-header-secret"},
                    {"target":"query","op":"set","name":"api_token","value":"rule-query-secret"},
                    {"target":"request.header","op":"set","name":"X-Public","value":"visible-rule-value"}
                ]}),
            ),
            rule(
                "response-rule",
                "response",
                json!({"kind":"rewrite","operations":[
                    {"target":"response.body","op":"set","value":"response-body-rule-secret"}
                ]}),
            ),
            rule(
                "redirect-rule",
                "request",
                json!({
                    "kind":"redirect",
                    "targetTemplate":"https://stage.example.test/*?api_token=redirect-target-secret&view=full",
                    "excludePattern":"https://api.example.test/*?auth=redirect-exclude-secret&keep=yes"
                }),
            ),
        ];

        let exported = render_export(&bundle, ExportFormat::ShowNet).unwrap();
        for expected in [
            "request-pattern-secret",
            "request-body-rule-secret",
            "rule-header-secret",
            "rule-query-secret",
            "response-body-rule-secret",
            "redirect-target-secret",
            "redirect-exclude-secret",
            "visible-rule-value",
        ] {
            assert!(exported.contains(expected), "missing {expected}");
        }
        let decoded: SessionBundle = serde_json::from_str(&exported).unwrap();
        assert_eq!(
            serde_json::to_value(decoded.rules).unwrap(),
            serde_json::to_value(bundle.rules).unwrap()
        );
    }

    #[test]
    fn shell_quoting_survives_apostrophes_and_trailing_backslashes() {
        // The TypeScript twin in src/shellQuote.ts has tests; this one had
        // none, and it is a separate implementation using a different idiom —
        // '\'' where the TypeScript side emits '"'"'. Both are POSIX, and the
        // outputs below were round-tripped through bash, zsh and sh against
        // thirteen values, apostrophes, trailing backslashes, $(whoami),
        // newlines, globs and history bangs included. Pinned here so the
        // property does not need a shell to stay checked.
        assert_eq!(
            shell_quote("https://example.com/a?b=1"),
            "'https://example.com/a?b=1'"
        );
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("a'b'c"), r"'a'\''b'\''c'");
        // A trailing backslash is literal inside single quotes, so it must not
        // be doubled: this is the shape that breaks hand-written escaping
        // elsewhere.
        assert_eq!(shell_quote("trailing\\"), "'trailing\\'");
        assert_eq!(shell_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn renders_supported_exchange_formats() {
        let bundle = bundle(request());
        let har = render_export(&bundle, ExportFormat::Har).unwrap();
        let postman = render_export(&bundle, ExportFormat::Postman).unwrap();
        let openapi = render_export(&bundle, ExportFormat::OpenApi).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&har).unwrap()["log"]["version"],
            "1.2"
        );
        assert!(postman.contains("collection/v2.1.0"));
        assert_eq!(
            serde_json::from_str::<Value>(&openapi).unwrap()["openapi"],
            "3.1.0"
        );
    }

    #[test]
    fn generates_every_supported_request_template() {
        let request = request();
        for template in ["curl", "httpie", "python", "java", "fetch", "axios", "go"] {
            let code = generate_code(&request, template).unwrap();
            assert!(!code.trim().is_empty(), "empty {template} template");
            assert!(
                code.contains("api.example.test"),
                "missing URL in {template}"
            );
            assert!(
                code.contains("Bearer secret"),
                "missing authentication in {template}"
            );
        }
    }

    #[test]
    fn har_export_carries_every_field_a_har_reader_requires() {
        // The version marker the other test checks says nothing about whether
        // Chrome DevTools will take the file: it refuses an entry that is
        // missing a required member. Verified against the real export by
        // walking HAR 1.2 rather than by matching on strings.
        let har = render_har(&bundle(request()));
        let mut missing: Vec<String> = Vec::new();
        let mut require = |value: &Value, path: &str, keys: &[&str]| {
            for key in keys {
                if value.get(key).is_none() {
                    missing.push(format!("{path}.{key}"));
                }
            }
        };

        require(&har["log"], "log", &["version", "creator", "entries"]);
        require(&har["log"]["creator"], "log.creator", &["name", "version"]);
        for (index, entry) in har["log"]["entries"]
            .as_array()
            .expect("entries must be an array")
            .iter()
            .enumerate()
        {
            let at = format!("entries[{index}]");
            require(
                entry,
                &at,
                &[
                    "startedDateTime",
                    "time",
                    "request",
                    "response",
                    "cache",
                    "timings",
                ],
            );
            require(
                &entry["request"],
                &format!("{at}.request"),
                &[
                    "method",
                    "url",
                    "httpVersion",
                    "cookies",
                    "headers",
                    "queryString",
                    "headersSize",
                    "bodySize",
                ],
            );
            require(
                &entry["response"],
                &format!("{at}.response"),
                &[
                    "status",
                    "statusText",
                    "httpVersion",
                    "cookies",
                    "headers",
                    "content",
                    "redirectURL",
                    "headersSize",
                    "bodySize",
                ],
            );
            require(
                &entry["response"]["content"],
                &format!("{at}.response.content"),
                &["size", "mimeType"],
            );
            require(
                &entry["timings"],
                &format!("{at}.timings"),
                &["send", "wait", "receive"],
            );
        }

        assert!(
            missing.is_empty(),
            "HAR is missing required members: {missing:?}"
        );

        // Required to be ISO 8601 with a timezone, which is the part a reader
        // silently gets wrong if the export ever formats it locally.
        let started = har["log"]["entries"][0]["startedDateTime"]
            .as_str()
            .expect("startedDateTime must be a string");
        assert!(
            started.ends_with('Z') || started.contains('+'),
            "startedDateTime carries no timezone: {started}"
        );
    }

    #[test]
    fn har_exports_binary_response_with_standard_base64_encoding() {
        let mut request = request();
        request.response_body = "base64:AJ+Slg==".to_string();
        request.response_body_metadata = BodyCaptureMetadata {
            captured: true,
            content_encoding: None,
            decoded: false,
            truncated: false,
            complete: true,
            wire_bytes: 4,
            decoded_bytes: 4,
            format: "base64".to_string(),
            error: None,
            omitted_reason: None,
        };
        let har = render_har(&bundle(request));
        let content = &har["log"]["entries"][0]["response"]["content"];
        assert_eq!(content["encoding"], "base64");
        assert_eq!(content["text"], "AJ+Slg==");
        assert_eq!(content["size"], 4);
        assert_eq!(
            har["log"]["entries"][0]["_shownetBodyCapture"]["format"],
            "base64"
        );
    }

    #[test]
    fn rejects_duplicate_bundle_sequences() {
        let mut bundle = bundle(request());
        bundle.requests.push(bundle.requests[0].clone());
        assert!(validate_bundle(&bundle).is_err());
    }

    fn request() -> BundleRequest {
        BundleRequest {
            id: "request-1".to_string(),
            sequence: 1,
            source: "browser".to_string(),
            source_instance_id: "browser-1".to_string(),
            started_at: 1_785_393_200_000,
            method: "POST".to_string(),
            scheme: "https".to_string(),
            host: "api.example.test".to_string(),
            port: Some(443),
            path: "/v1/items".to_string(),
            query: Some("limit=20".to_string()),
            status: 200,
            resource_type: "fetch".to_string(),
            size_bytes: 2,
            duration_ms: 42,
            protocol: "h2".to_string(),
            tls_version: "TLS 1.3".to_string(),
            risk_level: "none".to_string(),
            request_headers: vec![
                HeaderEntry {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                HeaderEntry {
                    name: "Authorization".to_string(),
                    value: "Bearer secret".to_string(),
                },
            ],
            response_headers: vec![],
            request_body: Some("{\"name\":\"demo\"}".to_string()),
            response_body: "{}".to_string(),
            response_body_metadata: BodyCaptureMetadata::default(),
            crypto_snippets: Vec::new(),
            hook: None,
            tls_fingerprint: None,
            replayed_from_request_id: None,
        }
    }

    fn bundle(request: BundleRequest) -> SessionBundle {
        SessionBundle {
            format: BUNDLE_FORMAT.to_string(),
            version: BUNDLE_VERSION,
            exported_at: "2026-07-30T00:00:00.000Z".to_string(),
            session: BundleSession {
                name: "API capture".to_string(),
                created_at: 1_785_393_200_000,
            },
            requests: vec![request],
            events: vec![BundleEvent {
                sequence: 1,
                timestamp: 1_785_393_200_000,
                source: "browser".to_string(),
                source_instance_id: "browser-1".to_string(),
                request_id: "request-1".to_string(),
                phase: "response".to_string(),
                payload: json!({ "requestId": "request-1" }),
            }],
            annotations: vec![],
            rules: vec![],
            rule_traces: vec![],
        }
    }

    fn rule(id: &str, stage: &str, action: Value) -> CaptureRule {
        CaptureRule {
            id: id.to_string(),
            name: id.to_string(),
            enabled: false,
            priority: 100,
            stage: stage.to_string(),
            matcher: crate::models::FilterExpression::Predicate {
                field: "host".to_string(),
                operator: "equals".to_string(),
                value: Some(json!("api.example.test")),
            },
            action,
            created_by: "user".to_string(),
            revision: 1,
            hit_count: 0,
            last_error: None,
            created_at: 1,
            updated_at: 1,
        }
    }
}
