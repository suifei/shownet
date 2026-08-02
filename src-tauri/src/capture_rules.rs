use crate::breakpoints::{RuntimeBreakpointRule, DEFAULT_BREAKPOINT_TIMEOUT_MS};
use crate::interchange::BundleRequest;
use crate::mirror::{format_authority, route_from_rule, RuntimeMirrorRoute};
use crate::models::{
    CaptureRule, CaptureRuleRun, FilterExpression, HeaderEntry, RulePreviewResult,
};
use crate::storage::Storage;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;
use uuid::Uuid;

pub const MAX_RULE_BODY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RuntimeRuleRequest {
    pub request_id: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
    pub source: String,
    pub protocol: String,
    pub request_headers: Vec<HeaderEntry>,
    pub request_body: Option<String>,
    pub body_unavailable_reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeRuleControl {
    pub delay_ms: u64,
    pub blocked: bool,
    pub block_status: Option<u16>,
    pub block_message: Option<String>,
    pub upload_bytes_per_second: Option<u64>,
    pub download_bytes_per_second: Option<u64>,
    pub request_body_changed: bool,
    pub redirected: bool,
    pub cross_origin_redirect: bool,
    pub redirect_preserve_host: bool,
}

pub struct RuntimeRuleOutcome {
    pub control: RuntimeRuleControl,
    pub traces: Vec<CaptureRuleRun>,
}

#[derive(Clone, Debug)]
pub struct RuntimeRuleResponse {
    pub request: RuntimeRuleRequest,
    pub status: u16,
    pub response_headers: Vec<HeaderEntry>,
    pub response_body: Option<String>,
    pub body_unavailable_reason: Option<String>,
}

pub struct RuntimeResponseRuleOutcome {
    pub traces: Vec<CaptureRuleRun>,
    pub body_changed: bool,
}

pub fn matching_runtime_request_breakpoints(
    storage: &Storage,
    request: &RuntimeRuleRequest,
) -> Result<Vec<RuntimeBreakpointRule>, String> {
    storage
        .list_capture_rules()?
        .into_iter()
        .filter(|rule| {
            rule.enabled && rule.stage == "request" && capture_rule_kind(rule) == "breakpoint"
        })
        .filter_map(
            |rule| match matches_runtime_filter(&rule.matcher, request) {
                Ok(true) => Some(Ok(runtime_breakpoint_rule(&rule))),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            },
        )
        .collect()
}

pub fn matching_runtime_response_breakpoints(
    storage: &Storage,
    response: &RuntimeRuleResponse,
) -> Result<Vec<RuntimeBreakpointRule>, String> {
    storage
        .list_capture_rules()?
        .into_iter()
        .filter(|rule| {
            rule.enabled && rule.stage == "response" && capture_rule_kind(rule) == "breakpoint"
        })
        .filter_map(
            |rule| match matches_runtime_response_filter(&rule.matcher, response) {
                Ok(true) => Some(Ok(runtime_breakpoint_rule(&rule))),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            },
        )
        .collect()
}

fn runtime_breakpoint_rule(rule: &CaptureRule) -> RuntimeBreakpointRule {
    RuntimeBreakpointRule {
        id: rule.id.clone(),
        name: rule.name.clone(),
        stage: rule.stage.clone(),
        revision: rule.revision,
        timeout_ms: rule
            .action
            .get("timeoutMs")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BREAKPOINT_TIMEOUT_MS),
        abort_on_timeout: rule.action.get("onTimeout").and_then(Value::as_str) == Some("abort"),
    }
}

fn capture_rule_kind(rule: &CaptureRule) -> &str {
    rule.action
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

pub fn resolve_runtime_mirror_route(
    storage: &Storage,
    request: &RuntimeRuleRequest,
) -> Result<Option<RuntimeMirrorRoute>, String> {
    for rule in storage.list_capture_rules()?.into_iter().filter(|rule| {
        rule.enabled && rule.stage == "connection" && capture_rule_kind(rule) == "mirror"
    }) {
        if matches_runtime_filter(&rule.matcher, request)? {
            return route_from_rule(&rule, &request.host, request.port).map(Some);
        }
    }
    Ok(None)
}

pub fn apply_runtime_request_rules(
    storage: &Storage,
    request: &mut RuntimeRuleRequest,
) -> Result<RuntimeRuleOutcome, String> {
    let rules = storage.list_capture_rules()?;
    let mut control = RuntimeRuleControl::default();
    let mut traces = Vec::new();
    for rule in rules.into_iter().filter(|rule| {
        rule.enabled && rule.stage == "request" && capture_rule_kind(rule) != "breakpoint"
    }) {
        let started = Instant::now();
        let matched = match matches_runtime_filter(&rule.matcher, request) {
            Ok(matched) => matched,
            Err(error) => {
                traces.push(runtime_trace(
                    request,
                    &rule,
                    "error",
                    Vec::new(),
                    false,
                    Some(error),
                    started,
                ));
                continue;
            }
        };
        if !matched {
            continue;
        }
        let mut candidate = request.clone();
        let mut candidate_control = control.clone();
        match apply_runtime_action(&rule, &mut candidate, &mut candidate_control) {
            Ok(RequestActionResult::Applied {
                changes,
                body_changed,
            }) => {
                *request = candidate;
                control = candidate_control;
                traces.push(runtime_trace(
                    request,
                    &rule,
                    "applied",
                    changes,
                    body_changed,
                    None,
                    started,
                ));
            }
            Ok(RequestActionResult::Skipped(reason)) => traces.push(runtime_trace(
                request,
                &rule,
                "skipped",
                vec![reason],
                false,
                None,
                started,
            )),
            Err(error) => traces.push(runtime_trace(
                request,
                &rule,
                "error",
                Vec::new(),
                false,
                Some(error),
                started,
            )),
        }
        if control.blocked {
            break;
        }
    }
    Ok(RuntimeRuleOutcome { control, traces })
}

pub fn runtime_request_body_required(
    storage: &Storage,
    request: &RuntimeRuleRequest,
) -> Result<bool, String> {
    let mut candidate = request.clone();
    let mut control = RuntimeRuleControl::default();
    for rule in storage
        .list_capture_rules()?
        .into_iter()
        .filter(|rule| rule.enabled && rule.stage == "request")
    {
        if !matches_runtime_filter(&rule.matcher, &candidate)? {
            continue;
        }
        if capture_rule_kind(&rule) == "breakpoint"
            || rule
                .action
                .get("operations")
                .and_then(Value::as_array)
                .is_some_and(|operations| {
                    operations.iter().any(|operation| {
                        operation.get("target").and_then(Value::as_str) == Some("request.body")
                    })
                })
        {
            return Ok(true);
        }
        let mut next = candidate.clone();
        let mut next_control = control.clone();
        if matches!(
            apply_runtime_action(&rule, &mut next, &mut next_control),
            Ok(RequestActionResult::Applied { .. })
        ) {
            candidate = next;
            control = next_control;
        }
        if control.blocked {
            break;
        }
    }
    Ok(false)
}

pub fn runtime_response_body_required(
    storage: &Storage,
    response: &RuntimeRuleResponse,
) -> Result<bool, String> {
    let mut candidate = response.clone();
    for rule in storage
        .list_capture_rules()?
        .into_iter()
        .filter(|rule| rule.enabled && rule.stage == "response")
    {
        if !matches_runtime_response_filter(&rule.matcher, &candidate)? {
            continue;
        }
        if capture_rule_kind(&rule) == "breakpoint"
            || rule
                .action
                .get("operations")
                .and_then(Value::as_array)
                .is_some_and(|operations| {
                    operations.iter().any(|operation| {
                        operation.get("target").and_then(Value::as_str) == Some("response.body")
                    })
                })
        {
            return Ok(true);
        }
        let mut next = candidate.clone();
        if matches!(
            apply_runtime_response_action(&rule, &mut next),
            Ok(ResponseActionResult::Applied { .. })
        ) {
            candidate = next;
        }
    }
    Ok(false)
}

pub fn apply_runtime_response_rules(
    storage: &Storage,
    response: &mut RuntimeRuleResponse,
) -> Result<RuntimeResponseRuleOutcome, String> {
    let rules = storage.list_capture_rules()?;
    let mut traces = Vec::new();
    let mut body_changed = false;
    for rule in rules.into_iter().filter(|rule| {
        rule.enabled && rule.stage == "response" && capture_rule_kind(rule) != "breakpoint"
    }) {
        let started = Instant::now();
        let matched = match matches_runtime_response_filter(&rule.matcher, response) {
            Ok(matched) => matched,
            Err(error) => {
                traces.push(runtime_response_trace(
                    response,
                    &rule,
                    "error",
                    Vec::new(),
                    false,
                    Some(error),
                    started,
                ));
                continue;
            }
        };
        if !matched {
            continue;
        }
        let mut candidate = response.clone();
        match apply_runtime_response_action(&rule, &mut candidate) {
            Ok(ResponseActionResult::Applied {
                changes,
                body_changed: changed,
            }) => {
                if changed && !runtime_response_allows_body(&candidate) {
                    traces.push(runtime_response_trace(
                        response,
                        &rule,
                        "error",
                        Vec::new(),
                        false,
                        Some("HEAD、1xx、204 或 304 响应不能写入正文".to_string()),
                        started,
                    ));
                    continue;
                }
                *response = candidate;
                body_changed |= changed;
                traces.push(runtime_response_trace(
                    response, &rule, "applied", changes, changed, None, started,
                ));
            }
            Ok(ResponseActionResult::Skipped(reason)) => {
                traces.push(runtime_response_trace(
                    response,
                    &rule,
                    "skipped",
                    vec![reason],
                    false,
                    None,
                    started,
                ));
            }
            Err(error) => traces.push(runtime_response_trace(
                response,
                &rule,
                "error",
                Vec::new(),
                false,
                Some(error),
                started,
            )),
        }
    }
    Ok(RuntimeResponseRuleOutcome {
        traces,
        body_changed,
    })
}

fn matches_runtime_filter(
    filter: &FilterExpression,
    request: &RuntimeRuleRequest,
) -> Result<bool, String> {
    match filter {
        FilterExpression::Group { operator, children } => match operator.as_str() {
            "and" => children
                .iter()
                .map(|child| matches_runtime_filter(child, request))
                .collect::<Result<Vec<_>, _>>()
                .map(|values| values.into_iter().all(|value| value)),
            "or" => children
                .iter()
                .map(|child| matches_runtime_filter(child, request))
                .collect::<Result<Vec<_>, _>>()
                .map(|values| values.into_iter().any(|value| value)),
            _ => Err("规则匹配组仅支持 and/or".to_string()),
        },
        FilterExpression::Predicate {
            field,
            operator,
            value,
        } => {
            let actual = match field.as_str() {
                "method" => json!(request.method),
                "scheme" => json!(request.scheme),
                "host" => json!(request.host),
                "path" => json!(request.path),
                "url" => json!(runtime_url(request)),
                "source" => json!(request.source),
                "protocol" => json!(request.protocol),
                "requestHeader" => json!(headers_text(&request.request_headers)),
                other => return Err(format!("请求阶段不支持匹配字段: {other}")),
            };
            compare_value(&actual, operator, value.as_ref())
        }
    }
}

fn matches_runtime_response_filter(
    filter: &FilterExpression,
    response: &RuntimeRuleResponse,
) -> Result<bool, String> {
    match filter {
        FilterExpression::Group { operator, children } => match operator.as_str() {
            "and" => children
                .iter()
                .map(|child| matches_runtime_response_filter(child, response))
                .collect::<Result<Vec<_>, _>>()
                .map(|values| values.into_iter().all(|value| value)),
            "or" => children
                .iter()
                .map(|child| matches_runtime_response_filter(child, response))
                .collect::<Result<Vec<_>, _>>()
                .map(|values| values.into_iter().any(|value| value)),
            _ => Err("规则匹配组仅支持 and/or".to_string()),
        },
        FilterExpression::Predicate {
            field,
            operator,
            value,
        } => {
            let actual = match field.as_str() {
                "method" => json!(response.request.method),
                "scheme" => json!(response.request.scheme),
                "host" => json!(response.request.host),
                "path" => json!(response.request.path),
                "url" => json!(runtime_url(&response.request)),
                "source" => json!(response.request.source),
                "protocol" => json!(response.request.protocol),
                "requestHeader" => json!(headers_text(&response.request.request_headers)),
                "status" => json!(response.status),
                "responseHeader" => json!(headers_text(&response.response_headers)),
                other => return Err(format!("响应阶段不支持匹配字段: {other}")),
            };
            compare_value(&actual, operator, value.as_ref())
        }
    }
}

enum ResponseActionResult {
    Applied {
        changes: Vec<String>,
        body_changed: bool,
    },
    Skipped(String),
}

enum RequestActionResult {
    Applied {
        changes: Vec<String>,
        body_changed: bool,
    },
    Skipped(String),
}

fn apply_runtime_response_action(
    rule: &CaptureRule,
    response: &mut RuntimeRuleResponse,
) -> Result<ResponseActionResult, String> {
    if rule.action.get("kind").and_then(Value::as_str) != Some("rewrite") {
        return Err("响应阶段仅支持响应重写".to_string());
    }
    let operations = rule
        .action
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| "响应重写规则缺少 operations".to_string())?;
    if operations.len() > 50 {
        return Err("单条规则最多 50 个重写操作".to_string());
    }
    if operations
        .iter()
        .any(|operation| operation.get("target").and_then(Value::as_str) == Some("response.body"))
        && response.response_body.is_none()
    {
        return Ok(ResponseActionResult::Skipped(
            response
                .body_unavailable_reason
                .clone()
                .unwrap_or_else(|| "响应正文不可安全缓冲，已跳过整条规则".to_string()),
        ));
    }

    let mut changes = Vec::new();
    let mut body_changed = false;
    for operation in operations {
        let target = operation
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let action = operation.get("op").and_then(Value::as_str).unwrap_or("set");
        let name = operation
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let value = operation
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match target {
            "response.header" => {
                if is_runtime_managed_header("response", name) {
                    return Err(format!("响应 Header {name} 由代理自动维护"));
                }
                response
                    .response_headers
                    .retain(|header| !header.name.eq_ignore_ascii_case(name));
                if action == "set" {
                    response.response_headers.push(HeaderEntry {
                        name: name.to_string(),
                        value: value.to_string(),
                    });
                } else if action != "delete" {
                    return Err(format!("响应 Header 重写操作无效: {action}"));
                }
                changes.push(format!("响应 Header {action} {name}"));
            }
            "response.status" => {
                let status = operation
                    .get("value")
                    .and_then(|value| {
                        value
                            .as_u64()
                            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
                    })
                    .filter(|status| (100..=599).contains(status))
                    .ok_or_else(|| "响应状态码必须在 100 到 599 之间".to_string())?;
                response.status = status as u16;
                changes.push(format!("响应状态设置为 {status}"));
            }
            "response.body" => {
                let original = response.response_body.as_deref().unwrap_or_default();
                let next = if action == "replace" {
                    let pattern = operation
                        .get("pattern")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    Regex::new(pattern)
                        .map_err(|error| format!("正文正则无效: {error}"))?
                        .replace_all(original, value)
                        .into_owned()
                } else if action == "set" {
                    value.to_string()
                } else {
                    return Err(format!("响应正文重写操作无效: {action}"));
                };
                if next.len() > MAX_RULE_BODY_BYTES {
                    return Err("响应正文重写结果超过 2 MiB 上限".to_string());
                }
                response.response_body = Some(next);
                body_changed = true;
                changes.push(format!("响应正文 {action}"));
            }
            other => return Err(format!("响应阶段不支持重写目标: {other}")),
        }
    }
    Ok(ResponseActionResult::Applied {
        changes,
        body_changed,
    })
}

fn apply_runtime_action(
    rule: &CaptureRule,
    request: &mut RuntimeRuleRequest,
    control: &mut RuntimeRuleControl,
) -> Result<RequestActionResult, String> {
    let mut changes = Vec::new();
    let mut body_changed = false;
    match rule
        .action
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "rewrite" => {
            let operations = rule
                .action
                .get("operations")
                .and_then(Value::as_array)
                .ok_or_else(|| "重写规则缺少 operations".to_string())?;
            if operations.len() > 50 {
                return Err("单条规则最多 50 个重写操作".to_string());
            }
            if operations.iter().any(|operation| {
                operation.get("target").and_then(Value::as_str) == Some("request.body")
            }) && request.request_body.is_none()
            {
                return Ok(RequestActionResult::Skipped(
                    request
                        .body_unavailable_reason
                        .clone()
                        .unwrap_or_else(|| "请求正文不可安全缓冲，已跳过整条规则".to_string()),
                ));
            }
            let original_body = request.request_body.clone();
            for operation in operations {
                let target = operation
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let action = operation.get("op").and_then(Value::as_str).unwrap_or("set");
                let name = operation
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let value = operation
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                match target {
                    "request.header" => {
                        if name.is_empty() {
                            return Err("Header 重写缺少名称".to_string());
                        }
                        if is_runtime_managed_header("request", name) {
                            return Err(format!("请求 Header {name} 由代理自动维护"));
                        }
                        request
                            .request_headers
                            .retain(|header| !header.name.eq_ignore_ascii_case(name));
                        if action == "set" {
                            request.request_headers.push(HeaderEntry {
                                name: name.to_string(),
                                value: value.to_string(),
                            });
                        } else if action != "delete" {
                            return Err(format!("Header 重写操作无效: {action}"));
                        }
                        changes.push(format!("请求 Header {action} {name}"));
                    }
                    "query" => {
                        if name.is_empty() {
                            return Err("Query 重写缺少名称".to_string());
                        }
                        let mut query = url::form_urlencoded::parse(
                            request.query.as_deref().unwrap_or_default().as_bytes(),
                        )
                        .into_owned()
                        .collect::<Vec<_>>();
                        query.retain(|(key, _)| key != name);
                        if action == "set" {
                            query.push((name.to_string(), value.to_string()));
                        } else if action != "delete" {
                            return Err(format!("Query 重写操作无效: {action}"));
                        }
                        let encoded = url::form_urlencoded::Serializer::new(String::new())
                            .extend_pairs(query)
                            .finish();
                        request.query = (!encoded.is_empty()).then_some(encoded);
                        changes.push(format!("Query {action} {name}"));
                    }
                    "request.body" => {
                        let original = request.request_body.as_deref().unwrap_or_default();
                        let next = if action == "replace" {
                            let pattern = operation
                                .get("pattern")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            if pattern.is_empty() || pattern.len() > 256 {
                                return Err("请求正文正则必须在 1 到 256 字节之间".to_string());
                            }
                            Regex::new(pattern)
                                .map_err(|error| format!("请求正文正则无效: {error}"))?
                                .replace_all(original, value)
                                .into_owned()
                        } else if action == "set" {
                            value.to_string()
                        } else {
                            return Err(format!("请求正文重写操作无效: {action}"));
                        };
                        if next.len() > MAX_RULE_BODY_BYTES {
                            return Err("请求正文重写结果超过 2 MiB 上限".to_string());
                        }
                        request.request_body = Some(next);
                        changes.push(format!("请求正文 {action}"));
                    }
                    other => return Err(format!("请求阶段不支持重写目标: {other}")),
                }
            }
            body_changed = request.request_body != original_body;
            control.request_body_changed |= body_changed;
        }
        "redirect" => {
            if control.redirected {
                return Ok(RequestActionResult::Skipped(
                    "请求已由更高优先级的转发规则处理".to_string(),
                ));
            }
            if let Some(exclude) = rule
                .action
                .get("excludePattern")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if exclude.len() > 4096 {
                    return Err("转发排除 URL 不能超过 4096 字节".to_string());
                }
                if wildcard_regex(exclude)?.is_match(&runtime_url(request)) {
                    return Ok(RequestActionResult::Skipped(
                        "命中排除 URL，未执行请求转发".to_string(),
                    ));
                }
            }
            let template = rule
                .action
                .get("targetTemplate")
                .and_then(Value::as_str)
                .ok_or_else(|| "请求转发规则缺少 targetTemplate".to_string())?;
            let target = render_redirect_target(template, request)?;
            let target_scheme = target.scheme().to_string();
            let target_host = target
                .host_str()
                .ok_or_else(|| "请求转发目标缺少 Host".to_string())?
                .to_string();
            let target_port = target
                .port_or_known_default()
                .ok_or_else(|| "请求转发目标端口无效".to_string())?;
            if request.scheme == "https"
                && target_scheme == "http"
                && rule
                    .action
                    .get("allowInsecureDowngrade")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                return Err("HTTPS 请求转发到 HTTP 需要显式允许明文降级".to_string());
            }
            let original_authority = format_authority(&request.host, request.port);
            let target_authority = format_authority(&target_host, target_port);
            let cross_origin = target_scheme != request.scheme
                || target_host != request.host
                || target_port != request.port;
            let preserve_host =
                rule.action.get("preserveHost").and_then(Value::as_bool) == Some(true);
            let preserve_credentials = rule
                .action
                .get("preserveCredentials")
                .and_then(Value::as_bool)
                == Some(true);
            let mut removed_credentials = 0usize;
            if cross_origin && !preserve_credentials {
                removed_credentials += strip_cross_origin_credentials(&mut request.request_headers);
                let mut target_query = target.query().map(ToString::to_string);
                removed_credentials += strip_sensitive_query(&mut target_query);
                request.query = target_query;
            } else {
                request.query = target.query().map(ToString::to_string);
            }
            if cross_origin && !preserve_host {
                request
                    .request_headers
                    .retain(|header| !header.name.eq_ignore_ascii_case("host"));
                request.request_headers.push(HeaderEntry {
                    name: "host".to_string(),
                    value: redirect_host_header(&target_scheme, &target_host, target_port),
                });
            }
            request.scheme = target_scheme;
            request.host = target_host;
            request.port = target_port;
            request.path = target.path().to_string();
            control.redirected = true;
            control.cross_origin_redirect = cross_origin;
            control.redirect_preserve_host = preserve_host;
            if cross_origin {
                changes.push(format!(
                    "请求转发 {original_authority} -> {target_authority}{}",
                    request.path
                ));
                if removed_credentials > 0 {
                    changes.push(format!("跨域凭据已移除 {removed_credentials} 项"));
                }
                if preserve_host {
                    changes.push("保留原 Host".to_string());
                }
            } else {
                changes.push(format!("同源路径转发到 {}", request.path));
            }
        }
        "delay" => {
            let latency = rule
                .action
                .get("latencyMs")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .clamp(0, 30_000) as u64;
            let jitter = rule
                .action
                .get("jitterMs")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .clamp(0, 30_000) as u64;
            let applied_jitter =
                deterministic_range(&request.request_id, &rule.id, "delay-jitter", jitter);
            let applied = latency.saturating_add(applied_jitter).min(30_000);
            control.delay_ms = control.delay_ms.saturating_add(applied).min(30_000);
            changes.push(format!("延迟 {latency}ms + 抖动 {applied_jitter}ms"));
        }
        "block" => {
            if rule
                .action
                .get("direction")
                .and_then(Value::as_str)
                .unwrap_or("outbound")
                != "outbound"
            {
                return Err("请求阶段只支持 outbound 阻断".to_string());
            }
            control.blocked = true;
            control.block_status = Some(403);
            control.block_message = Some("请求已被 ShowNet 规则阻断".to_string());
            changes.push("阻断出站请求".to_string());
        }
        "throttle" => {
            let latency = rule
                .action
                .get("latencyMs")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .clamp(0, 30_000) as u64;
            let jitter = rule
                .action
                .get("jitterMs")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .clamp(0, 30_000) as u64;
            let applied_jitter =
                deterministic_range(&request.request_id, &rule.id, "throttle-jitter", jitter);
            control.delay_ms = control
                .delay_ms
                .saturating_add(latency.saturating_add(applied_jitter))
                .min(30_000);

            let upload_kbps = rule
                .action
                .get("uploadKbps")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let download_kbps = rule
                .action
                .get("downloadKbps")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            control.upload_bytes_per_second = restrictive_rate(
                control.upload_bytes_per_second,
                kilobits_to_bytes(upload_kbps),
            );
            control.download_bytes_per_second = restrictive_rate(
                control.download_bytes_per_second,
                kilobits_to_bytes(download_kbps),
            );

            let loss_percent = rule
                .action
                .get("packetLossPercent")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                .clamp(0.0, 100.0);
            let sample = deterministic_percent(&request.request_id, &rule.id, "packet-loss");
            if loss_percent >= 100.0 || sample < loss_percent {
                control.blocked = true;
                control.block_status = Some(504);
                control.block_message = Some("ShowNet 弱网规则模拟丢包".to_string());
                changes.push(format!("模拟丢包命中（配置 {loss_percent:.2}%）"));
            } else {
                changes.push(format!(
                    "弱网：上行 {upload_kbps} Kbps，下行 {download_kbps} Kbps，延迟 {latency}ms，抖动 {applied_jitter}ms，丢包 {loss_percent:.2}%"
                ));
            }
        }
        kind => return Err(format!("请求阶段尚未执行动作: {kind}")),
    }
    Ok(RequestActionResult::Applied {
        changes,
        body_changed,
    })
}

fn deterministic_hash(request_id: &str, rule_id: &str, salt: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    request_id.hash(&mut hasher);
    rule_id.hash(&mut hasher);
    salt.hash(&mut hasher);
    hasher.finish()
}

fn deterministic_range(request_id: &str, rule_id: &str, salt: &str, max: u64) -> u64 {
    if max == 0 {
        0
    } else {
        deterministic_hash(request_id, rule_id, salt) % (max + 1)
    }
}

fn deterministic_percent(request_id: &str, rule_id: &str, salt: &str) -> f64 {
    (deterministic_hash(request_id, rule_id, salt) % 10_000) as f64 / 100.0
}

fn kilobits_to_bytes(kbps: u64) -> Option<u64> {
    (kbps > 0).then_some(kbps.saturating_mul(1_000) / 8)
}

fn restrictive_rate(current: Option<u64>, candidate: Option<u64>) -> Option<u64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.min(candidate)),
        (Some(current), None) => Some(current),
        (None, Some(candidate)) => Some(candidate),
        (None, None) => None,
    }
}

fn is_runtime_managed_header(stage: &str, name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    matches!(
        name.as_str(),
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || (stage == "request" && name == "host")
        || (stage == "response" && name == "content-encoding")
}

fn runtime_response_allows_body(response: &RuntimeRuleResponse) -> bool {
    !response.request.method.eq_ignore_ascii_case("HEAD")
        && !(100..200).contains(&response.status)
        && !matches!(response.status, 204 | 304)
}

fn runtime_trace(
    request: &RuntimeRuleRequest,
    rule: &CaptureRule,
    result: &str,
    changes: Vec<String>,
    body_changed: bool,
    error: Option<String>,
    started: Instant,
) -> CaptureRuleRun {
    CaptureRuleRun {
        id: format!("rule-run-{}", Uuid::new_v4()),
        request_id: request.request_id.clone(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        revision: rule.revision,
        stage: rule.stage.clone(),
        result: result.to_string(),
        diff_summary: json!({
            "changes": changes,
            "urlAfter": runtime_url(request),
            "bodyChanged": body_changed,
        }),
        duration_ms: started.elapsed().as_millis() as i64,
        error,
        created_at: chrono::Utc::now().timestamp_millis(),
    }
}

fn runtime_response_trace(
    response: &RuntimeRuleResponse,
    rule: &CaptureRule,
    result: &str,
    changes: Vec<String>,
    body_changed: bool,
    error: Option<String>,
    started: Instant,
) -> CaptureRuleRun {
    CaptureRuleRun {
        id: format!("rule-run-{}", Uuid::new_v4()),
        request_id: response.request.request_id.clone(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        revision: rule.revision,
        stage: rule.stage.clone(),
        result: result.to_string(),
        diff_summary: json!({
            "changes": changes,
            "statusAfter": response.status,
            "bodyChanged": body_changed,
        }),
        duration_ms: started.elapsed().as_millis() as i64,
        error,
        created_at: chrono::Utc::now().timestamp_millis(),
    }
}

pub fn runtime_breakpoint_trace(
    request: &RuntimeRuleRequest,
    rule: &RuntimeBreakpointRule,
    result: &str,
    summary: &str,
    duration_ms: i64,
) -> CaptureRuleRun {
    CaptureRuleRun {
        id: format!("rule-run-{}", Uuid::new_v4()),
        request_id: request.request_id.clone(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        revision: rule.revision,
        stage: rule.stage.clone(),
        result: result.to_string(),
        diff_summary: json!({"changes": [summary]}),
        duration_ms,
        error: None,
        created_at: chrono::Utc::now().timestamp_millis(),
    }
}

fn runtime_url(request: &RuntimeRuleRequest) -> String {
    format!(
        "{}://{}:{}{}{}",
        request.scheme,
        request.host,
        request.port,
        request.path,
        request
            .query
            .as_ref()
            .map(|value| format!("?{value}"))
            .unwrap_or_default()
    )
}

pub fn preview_rule(
    storage: &Storage,
    rule_id: &str,
    request_id: &str,
) -> Result<RulePreviewResult, String> {
    let started = Instant::now();
    let rule = storage.get_capture_rule(rule_id)?;
    let request = storage.get_bundle_request(request_id)?;
    let matched = matches_filter(&rule.matcher, &request)?;
    let before = request_snapshot(&request);
    let (after, changes, warnings) = if matched {
        apply_action_preview(&rule, &request, &before)?
    } else {
        (before.clone(), Vec::new(), Vec::new())
    };
    let preview = RulePreviewResult {
        matched,
        request_id: request_id.to_string(),
        stage: rule.stage.clone(),
        before,
        after,
        changes,
        warnings,
    };
    storage.record_capture_rule_run(&CaptureRuleRun {
        id: format!("rule-run-{}", Uuid::new_v4()), request_id: request_id.to_string(), rule_id: rule.id,
        rule_name: rule.name, revision: rule.revision, stage: rule.stage, result: if matched { "preview" } else { "not-matched" }.to_string(),
        diff_summary: json!({"changes":preview.changes,"warnings":preview.warnings,"matched":matched}), duration_ms: started.elapsed().as_millis() as i64,
        error: None, created_at: chrono::Utc::now().timestamp_millis(),
    })?;
    Ok(preview)
}

fn request_snapshot(request: &BundleRequest) -> Value {
    json!({
        "method": request.method, "scheme": request.scheme, "host": request.host, "port": request.port,
        "path": request.path, "query": request.query, "status": request.status,
        "requestHeaders": request.request_headers, "responseHeaders": request.response_headers,
        "requestBody": request.request_body, "responseBody": request.response_body,
    })
}

fn matches_filter(filter: &FilterExpression, request: &BundleRequest) -> Result<bool, String> {
    match filter {
        FilterExpression::Group { operator, children } => match operator.as_str() {
            "and" => children
                .iter()
                .map(|child| matches_filter(child, request))
                .collect::<Result<Vec<_>, _>>()
                .map(|results| results.into_iter().all(|value| value)),
            "or" => children
                .iter()
                .map(|child| matches_filter(child, request))
                .collect::<Result<Vec<_>, _>>()
                .map(|results| results.into_iter().any(|value| value)),
            _ => Err("规则匹配组仅支持 and/or".to_string()),
        },
        FilterExpression::Predicate {
            field,
            operator,
            value,
        } => {
            let actual = request_field(request, field)?;
            compare_value(&actual, operator, value.as_ref())
        }
    }
}

fn request_field(request: &BundleRequest, field: &str) -> Result<Value, String> {
    Ok(match field {
        "method" => json!(request.method),
        "scheme" => json!(request.scheme),
        "host" => json!(request.host),
        "path" => json!(request.path),
        "url" => json!(format!(
            "{}://{}{}{}",
            request.scheme,
            request.host,
            request.path,
            request
                .query
                .as_ref()
                .map(|value| format!("?{value}"))
                .unwrap_or_default()
        )),
        "status" => json!(request.status),
        "type" => json!(request.resource_type),
        "source" => json!(request.source),
        "protocol" => json!(request.protocol),
        "risk" => json!(request.risk_level),
        "requestHeader" => json!(headers_text(&request.request_headers)),
        "responseHeader" => json!(headers_text(&request.response_headers)),
        "requestBody" => json!(request.request_body),
        "responseBody" => json!(request.response_body),
        "hook" => json!(request.hook),
        other => return Err(format!("规则预览暂不支持字段: {other}")),
    })
}

fn compare_value(actual: &Value, operator: &str, expected: Option<&Value>) -> Result<bool, String> {
    let actual_text = value_text(actual).to_ascii_lowercase();
    let expected_text = expected
        .map(value_text)
        .unwrap_or_default()
        .to_ascii_lowercase();
    Ok(match operator {
        "exists" => !actual.is_null() && !actual_text.is_empty(),
        "equals" => actual_text == expected_text,
        "not_equals" => actual_text != expected_text,
        "contains" => actual_text.contains(&expected_text),
        "not_contains" => !actual_text.contains(&expected_text),
        "starts_with" => actual_text.starts_with(&expected_text),
        "ends_with" => actual_text.ends_with(&expected_text),
        "wildcard" => wildcard_regex(&expected_text)?.is_match(&actual_text),
        "regex" => {
            if expected_text.len() > 256 {
                return Err("规则正则最长 256 字符".into());
            }
            Regex::new(&expected_text)
                .map_err(|error| format!("规则正则无效: {error}"))?
                .is_match(&actual_text)
        }
        "gt" | "gte" | "lt" | "lte" => {
            let left = actual
                .as_f64()
                .ok_or_else(|| "规则数值字段无效".to_string())?;
            let right = expected
                .and_then(Value::as_f64)
                .ok_or_else(|| "规则比较值无效".to_string())?;
            match operator {
                "gt" => left > right,
                "gte" => left >= right,
                "lt" => left < right,
                _ => left <= right,
            }
        }
        _ => return Err(format!("规则操作符无效: {operator}")),
    })
}

fn apply_action_preview(
    rule: &CaptureRule,
    request: &BundleRequest,
    before: &Value,
) -> Result<(Value, Vec<String>, Vec<String>), String> {
    let mut after = before.clone();
    let mut changes = Vec::new();
    let mut warnings = Vec::new();
    match rule
        .action
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "redirect" => {
            let default_port = if request.scheme == "https" { 443 } else { 80 };
            let mut runtime = RuntimeRuleRequest {
                request_id: request.id.clone(),
                method: request.method.clone(),
                scheme: request.scheme.clone(),
                host: request.host.clone(),
                port: request
                    .port
                    .and_then(|port| u16::try_from(port).ok())
                    .unwrap_or(default_port),
                path: request.path.clone(),
                query: request.query.clone(),
                source: request.source.clone(),
                protocol: request.protocol.clone(),
                request_headers: request.request_headers.clone(),
                request_body: request.request_body.clone(),
                body_unavailable_reason: None,
            };
            let mut control = RuntimeRuleControl::default();
            match apply_runtime_action(rule, &mut runtime, &mut control)? {
                RequestActionResult::Applied {
                    changes: applied, ..
                } => {
                    changes.extend(applied);
                    let redirect_target = runtime_url(&runtime);
                    after["scheme"] = json!(runtime.scheme.clone());
                    after["host"] = json!(runtime.host.clone());
                    after["port"] = json!(runtime.port);
                    after["path"] = json!(runtime.path.clone());
                    after["query"] = json!(runtime.query.clone());
                    after["requestHeaders"] = json!(runtime.request_headers.clone());
                    after["redirectTarget"] = json!(redirect_target);
                }
                RequestActionResult::Skipped(reason) => warnings.push(reason),
            }
        }
        "rewrite" => {
            let operations = rule
                .action
                .get("operations")
                .and_then(Value::as_array)
                .ok_or_else(|| "重写规则缺少 operations".to_string())?;
            if operations.len() > 50 {
                return Err("单条规则最多 50 个重写操作".to_string());
            }
            for operation in operations {
                apply_rewrite_operation(&mut after, operation, &mut changes, &mut warnings)?;
            }
        }
        "block" => {
            after["blocked"] = json!(true);
            changes.push("阻断匹配方向的流量".to_string());
        }
        "delay" => {
            let latency = rule
                .action
                .get("latencyMs")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .clamp(0, 30_000);
            let jitter = rule
                .action
                .get("jitterMs")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .clamp(0, 30_000);
            after["delayMs"] = json!(latency);
            after["jitterMs"] = json!(jitter);
            changes.push(format!("增加 {latency}ms 延迟与 0-{jitter}ms 抖动"));
        }
        "throttle" => {
            after["throttle"] = rule.action.clone();
            changes.push(format!(
                "模拟上行 {} Kbps、下行 {} Kbps、丢包 {}%",
                rule.action
                    .get("uploadKbps")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                rule.action
                    .get("downloadKbps")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                rule.action
                    .get("packetLossPercent")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0),
            ));
            warnings.push("预览只展示影响范围，不实际等待或模拟丢包".to_string());
        }
        "breakpoint" => {
            let timeout_ms = rule
                .action
                .get("timeoutMs")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_BREAKPOINT_TIMEOUT_MS);
            after["breakpoint"] = json!({
                "stage": rule.stage,
                "timeoutMs": timeout_ms,
                "onTimeout": rule.action.get("onTimeout").and_then(Value::as_str).unwrap_or("continue"),
            });
            changes.push(format!("命中后暂停 {} 秒等待人工处理", timeout_ms / 1_000));
            warnings.push("预览不会暂停当前样本".to_string());
        }
        "mirror" => {
            after["mirror"] = rule.action.clone();
            changes.push("改写目标主机与 SNI 策略".to_string());
            warnings.push("镜像规则启用前应使用测试域名验证证书策略".to_string());
        }
        kind => return Err(format!("不支持的规则动作: {kind}")),
    }
    Ok((after, changes, warnings))
}

fn apply_rewrite_operation(
    after: &mut Value,
    operation: &Value,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let target = operation
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let action = operation.get("op").and_then(Value::as_str).unwrap_or("set");
    let name = operation
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let value = operation
        .get("value")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match target {
        "request.header" | "response.header" => {
            if name.is_empty() {
                return Err("Header 重写缺少名称".to_string());
            }
            let key = if target.starts_with("request") {
                "requestHeaders"
            } else {
                "responseHeaders"
            };
            let headers = after[key]
                .as_array_mut()
                .ok_or_else(|| "Header 快照无效".to_string())?;
            let previous = headers.iter().position(|header| {
                header
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
            });
            match action {
                "delete" => {
                    if let Some(index) = previous {
                        headers.remove(index);
                    }
                }
                "set" => {
                    if let Some(index) = previous {
                        headers[index]["value"] = json!(value);
                    } else {
                        headers.push(json!({"name":name,"value":value}));
                    }
                }
                _ => return Err(format!("Header 重写操作无效: {action}")),
            }
            changes.push(format!("{target} {action} {name}"));
        }
        "query" => {
            let mut query =
                url::form_urlencoded::parse(after["query"].as_str().unwrap_or_default().as_bytes())
                    .into_owned()
                    .collect::<Vec<_>>();
            query.retain(|(key, _)| key != name);
            if action != "delete" {
                query.push((name.to_string(), value.to_string()));
            }
            after["query"] = json!(url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query)
                .finish());
            changes.push(format!("Query {action} {name}"));
        }
        "response.status" => {
            let status = operation
                .get("value")
                .and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
                })
                .filter(|status| (100..=599).contains(status))
                .ok_or_else(|| "响应状态码必须在 100 到 599 之间".to_string())?;
            after["status"] = json!(status);
            changes.push(format!("响应状态设置为 {status}"));
        }
        "request.body" | "response.body" => {
            let key = if target.starts_with("request") {
                "requestBody"
            } else {
                "responseBody"
            };
            let original = after[key].as_str().unwrap_or_default();
            if original.len() > 2 * 1024 * 1024 {
                warnings.push("正文超过 2 MiB，执行时将跳过".to_string());
            }
            let next = if action == "replace" {
                let pattern = operation
                    .get("pattern")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if pattern.len() > 256 {
                    return Err("正文正则最长 256 字符".into());
                }
                Regex::new(pattern)
                    .map_err(|error| format!("正文正则无效: {error}"))?
                    .replace_all(original, value)
                    .into_owned()
            } else if action == "set" {
                value.to_string()
            } else {
                return Err(format!("正文重写操作无效: {action}"));
            };
            if next.len() > MAX_RULE_BODY_BYTES {
                return Err("正文重写结果超过 2 MiB 上限".to_string());
            }
            after[key] = json!(next);
            changes.push(format!("{target} {action}"));
        }
        _ => return Err(format!("不支持的重写目标: {target}")),
    }
    Ok(())
}

fn render_redirect_target(
    template: &str,
    request: &RuntimeRuleRequest,
) -> Result<url::Url, String> {
    let template = template.trim();
    if template.is_empty() || template.len() > 4096 {
        return Err("请求转发目标必须在 1 到 4096 字节之间".to_string());
    }
    if template.contains('\\') {
        return Err("请求转发目标不能包含反斜杠".to_string());
    }
    let original_query = request.query.as_deref().unwrap_or_default();
    let mut rendered = template
        .replace("{{scheme}}", &request.scheme)
        .replace("{{host}}", &request.host)
        .replace("{{port}}", &request.port.to_string())
        .replace("{{path}}", &request.path)
        .replace("{{query}}", original_query);
    let (path_template, explicit_query) = rendered
        .split_once('?')
        .map(|(path, query)| (path.to_string(), Some(query.to_string())))
        .unwrap_or_else(|| (rendered.clone(), None));
    let directory_mapping = path_template.ends_with("/*");
    if directory_mapping {
        let mut mapped = path_template.trim_end_matches('*').to_string();
        mapped.push_str(request.path.trim_start_matches('/'));
        rendered = explicit_query
            .as_ref()
            .map(|query| format!("{mapped}?{query}"))
            .unwrap_or(mapped);
    }
    let base = format!(
        "{}://{}/",
        request.scheme,
        format_authority(&request.host, request.port)
    );
    let mut target = if rendered.starts_with('/') {
        url::Url::parse(&base)
            .and_then(|base| base.join(&rendered))
            .map_err(|error| format!("请求转发目标无效: {error}"))?
    } else {
        url::Url::parse(&rendered).map_err(|error| format!("请求转发目标无效: {error}"))?
    };
    if !matches!(target.scheme(), "http" | "https") {
        return Err("请求转发目标只支持 HTTP 或 HTTPS".to_string());
    }
    if target.host_str().is_none() || !target.username().is_empty() || target.password().is_some() {
        return Err("请求转发目标不能包含凭据，且必须包含有效 Host".to_string());
    }
    if target.fragment().is_some() {
        return Err("请求转发目标不能包含 URL 片段".to_string());
    }
    if directory_mapping && explicit_query.is_none() && !original_query.is_empty() {
        target.set_query(Some(original_query));
    }
    Ok(target)
}

fn strip_cross_origin_credentials(headers: &mut Vec<HeaderEntry>) -> usize {
    let before = headers.len();
    headers.retain(|header| !is_sensitive_redirect_header(&header.name));
    before.saturating_sub(headers.len())
}

fn redirect_host_header(scheme: &str, host: &str, port: u16) -> String {
    let host = host.trim_matches(['[', ']']);
    let formatted = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if scheme == "http" && port == 80 || scheme == "https" && port == 443 {
        formatted
    } else {
        format!("{formatted}:{port}")
    }
}

fn is_sensitive_redirect_header(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "cookie2"
            | "x-api-key"
            | "x-auth-token"
            | "x-access-token"
    ) || normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("api-key")
        || normalized.contains("api_key")
        || normalized.ends_with("-key")
        || normalized.ends_with("_key")
}

fn strip_sensitive_query(query: &mut Option<String>) -> usize {
    let Some(value) = query.as_deref() else {
        return 0;
    };
    let pairs = url::form_urlencoded::parse(value.as_bytes())
        .into_owned()
        .collect::<Vec<_>>();
    let kept = pairs
        .iter()
        .filter(|(name, _)| !is_sensitive_redirect_query(name))
        .cloned()
        .collect::<Vec<_>>();
    let removed = pairs.len().saturating_sub(kept.len());
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(kept)
        .finish();
    *query = (!encoded.is_empty()).then_some(encoded);
    removed
}

fn is_sensitive_redirect_query(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    normalized == "key"
        || normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("auth")
        || normalized.contains("api-key")
        || normalized.contains("api_key")
        || normalized.ends_with("-key")
        || normalized.ends_with("_key")
}

fn headers_text(headers: &[HeaderEntry]) -> String {
    headers
        .iter()
        .map(|header| format!("{}: {}", header.name, header.value))
        .collect::<Vec<_>>()
        .join("\n")
}
fn value_text(value: &Value) -> String {
    value
        .as_str()
        .map(ToString::to_string)
        .unwrap_or_else(|| value.to_string())
}
fn wildcard_regex(value: &str) -> Result<Regex, String> {
    Regex::new(&format!(
        "^{}$",
        regex::escape(value)
            .replace("\\*", ".*")
            .replace("\\?", ".")
    ))
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CaptureRuleInput;
    #[test]
    fn wildcard_is_anchored() {
        let regex = wildcard_regex("*.example.com").unwrap();
        assert!(regex.is_match("api.example.com"));
        assert!(!regex.is_match("api.example.com.evil"));
    }

    #[test]
    fn mirror_route_uses_the_first_priority_match_without_chaining() {
        let path =
            std::env::temp_dir().join(format!("shownet-mirror-runtime-{}.sqlite3", Uuid::new_v4()));
        let storage = Storage::open(&path).unwrap();
        for (priority, matcher, target) in [
            (20, "middle.example.test", "final.example.test"),
            (10, "*.example.test", "middle.example.test"),
            (30, "api.example.test", "ignored.example.test"),
        ] {
            let rule = storage
                .save_capture_rule(CaptureRuleInput {
                    id: None,
                    name: format!("mirror-{priority}"),
                    enabled: false,
                    priority,
                    stage: "connection".to_string(),
                    matcher: FilterExpression::Predicate {
                        field: "host".to_string(),
                        operator: "wildcard".to_string(),
                        value: Some(json!(matcher)),
                    },
                    action: json!({
                        "kind": "mirror",
                        "targetHost": target,
                        "targetPort": 8443,
                        "identity": "target"
                    }),
                    created_by: "user".to_string(),
                })
                .unwrap();
            storage
                .set_capture_rule_enabled(&rule.id, true, true)
                .unwrap();
        }
        let request = RuntimeRuleRequest {
            request_id: "mirror-request".to_string(),
            method: "CONNECT".to_string(),
            scheme: "https".to_string(),
            host: "api.example.test".to_string(),
            port: 443,
            path: "/".to_string(),
            query: None,
            source: "browser".to_string(),
            protocol: "connect".to_string(),
            request_headers: Vec::new(),
            request_body: None,
            body_unavailable_reason: None,
        };
        let route = resolve_runtime_mirror_route(&storage, &request)
            .unwrap()
            .unwrap();
        assert_eq!(route.rule_name, "mirror-10");
        assert_eq!(route.target_host, "middle.example.test");
        assert_eq!(route.target_port, 8443);
        assert_eq!(route.original_host, "api.example.test");
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn runtime_request_rules_apply_in_priority_order_and_emit_compact_traces() {
        let path =
            std::env::temp_dir().join(format!("shownet-rule-runtime-{}.sqlite3", Uuid::new_v4()));
        let storage = Storage::open(&path).unwrap();
        for (priority, name, value) in [
            (10, "first", "internal-secret-a"),
            (20, "second", "internal-secret-b"),
        ] {
            let rule = storage.save_capture_rule(CaptureRuleInput {
                id: None, name: name.to_string(), enabled: false, priority, stage: "request".to_string(),
                matcher: FilterExpression::Predicate { field: "host".to_string(), operator: "equals".to_string(), value: Some(json!("api.example.test")) },
                action: json!({"kind":"rewrite","operations":[{"target":"request.header","op":"set","name":"X-Rule-Order","value":value}]}),
                created_by: "user".to_string(),
            }).unwrap();
            assert!(!rule.enabled);
            storage
                .set_capture_rule_enabled(&rule.id, true, true)
                .unwrap();
        }
        let mut request = RuntimeRuleRequest {
            request_id: "runtime-request".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "api.example.test".to_string(),
            port: 443,
            path: "/v1/items".to_string(),
            query: Some("access_token=runtime-query-secret".to_string()),
            source: "browser".to_string(),
            protocol: "h2".to_string(),
            request_headers: Vec::new(),
            request_body: None,
            body_unavailable_reason: None,
        };
        let outcome = apply_runtime_request_rules(&storage, &mut request).unwrap();
        assert_eq!(
            outcome
                .traces
                .iter()
                .map(|trace| trace.rule_name.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(request.request_headers[0].value, "internal-secret-b");
        let trace_json = serde_json::to_string(&outcome.traces).unwrap();
        assert!(trace_json.contains("access_token=runtime-query-secret"));
        assert!(!trace_json.contains("internal-secret-a"));
        assert!(!trace_json.contains("internal-secret-b"));
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn map_remote_uses_first_effective_rule_and_strips_cross_origin_credentials() {
        let path = std::env::temp_dir().join(format!(
            "shownet-map-remote-runtime-{}.sqlite3",
            Uuid::new_v4()
        ));
        let storage = Storage::open(&path).unwrap();
        for input in [
            CaptureRuleInput {
                id: None,
                name: "excluded".to_string(),
                enabled: false,
                priority: 5,
                stage: "request".to_string(),
                matcher: FilterExpression::Predicate {
                    field: "host".to_string(),
                    operator: "equals".to_string(),
                    value: Some(json!("api.example.test")),
                },
                action: json!({
                    "kind":"redirect",
                    "targetTemplate":"https://excluded.example.test/*",
                    "excludePattern":"https://api.example.test:443/private*"
                }),
                created_by: "user".to_string(),
            },
            CaptureRuleInput {
                id: None,
                name: "map stage".to_string(),
                enabled: false,
                priority: 10,
                stage: "request".to_string(),
                matcher: FilterExpression::Predicate {
                    field: "host".to_string(),
                    operator: "equals".to_string(),
                    value: Some(json!("api.example.test")),
                },
                action: json!({
                    "kind":"redirect",
                    "targetTemplate":"https://stage.example.test:8443/base/*"
                }),
                created_by: "user".to_string(),
            },
            CaptureRuleInput {
                id: None,
                name: "second map".to_string(),
                enabled: false,
                priority: 20,
                stage: "request".to_string(),
                matcher: FilterExpression::Predicate {
                    field: "host".to_string(),
                    operator: "equals".to_string(),
                    value: Some(json!("stage.example.test")),
                },
                action: json!({
                    "kind":"redirect",
                    "targetTemplate":"https://must-not-run.example.test/*"
                }),
                created_by: "user".to_string(),
            },
            CaptureRuleInput {
                id: None,
                name: "rewrite after map".to_string(),
                enabled: false,
                priority: 30,
                stage: "request".to_string(),
                matcher: FilterExpression::Predicate {
                    field: "host".to_string(),
                    operator: "equals".to_string(),
                    value: Some(json!("stage.example.test")),
                },
                action: json!({"kind":"rewrite","operations":[
                    {"target":"request.header","op":"set","name":"X-After-Map","value":"yes"}
                ]}),
                created_by: "user".to_string(),
            },
        ] {
            let rule = storage.save_capture_rule(input).unwrap();
            storage
                .set_capture_rule_enabled(&rule.id, true, true)
                .unwrap();
        }
        let mut request = RuntimeRuleRequest {
            request_id: "map-remote-request".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "api.example.test".to_string(),
            port: 443,
            path: "/private/v1/items".to_string(),
            query: Some("token=query-secret&keep=1".to_string()),
            source: "browser".to_string(),
            protocol: "h2".to_string(),
            request_headers: vec![
                HeaderEntry {
                    name: "host".to_string(),
                    value: "api.example.test".to_string(),
                },
                HeaderEntry {
                    name: "authorization".to_string(),
                    value: "Bearer auth-secret".to_string(),
                },
                HeaderEntry {
                    name: "cookie".to_string(),
                    value: "sid=cookie-secret".to_string(),
                },
                HeaderEntry {
                    name: "x-api-key".to_string(),
                    value: "header-secret".to_string(),
                },
                HeaderEntry {
                    name: "x-client".to_string(),
                    value: "shownet".to_string(),
                },
            ],
            request_body: None,
            body_unavailable_reason: None,
        };
        let outcome = apply_runtime_request_rules(&storage, &mut request).unwrap();
        assert!(outcome.control.redirected);
        assert!(outcome.control.cross_origin_redirect);
        assert!(!outcome.control.redirect_preserve_host);
        assert_eq!(request.scheme, "https");
        assert_eq!(request.host, "stage.example.test");
        assert_eq!(request.port, 8443);
        assert_eq!(request.path, "/base/private/v1/items");
        assert_eq!(request.query.as_deref(), Some("keep=1"));
        assert!(request.request_headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("host") && header.value == "stage.example.test:8443"
        }));
        assert!(request
            .request_headers
            .iter()
            .any(|header| { header.name == "X-After-Map" && header.value == "yes" }));
        assert!(!request.request_headers.iter().any(|header| {
            matches!(
                header.name.to_ascii_lowercase().as_str(),
                "authorization" | "cookie" | "x-api-key"
            )
        }));
        assert_eq!(
            outcome
                .traces
                .iter()
                .map(|trace| trace.result.as_str())
                .collect::<Vec<_>>(),
            vec!["skipped", "applied", "skipped", "applied"]
        );
        let trace_json = serde_json::to_string(&outcome.traces).unwrap();
        assert!(trace_json.contains("token=query-secret&keep=1"));
        for secret in [
            "auth-secret",
            "cookie-secret",
            "header-secret",
            "must-not-run.example.test",
        ] {
            assert!(!trace_json.contains(secret));
        }
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn map_remote_requires_explicit_https_downgrade_and_can_preserve_trusted_identity() {
        let path = std::env::temp_dir().join(format!(
            "shownet-map-remote-downgrade-{}.sqlite3",
            Uuid::new_v4()
        ));
        let storage = Storage::open(&path).unwrap();
        for (priority, name, allow) in [
            (10, "unsafe by default", false),
            (20, "trusted local target", true),
        ] {
            let rule = storage
                .save_capture_rule(CaptureRuleInput {
                    id: None,
                    name: name.to_string(),
                    enabled: false,
                    priority,
                    stage: "request".to_string(),
                    matcher: FilterExpression::Predicate {
                        field: "host".to_string(),
                        operator: "equals".to_string(),
                        value: Some(json!("secure.example.test")),
                    },
                    action: json!({
                        "kind":"redirect",
                        "targetTemplate":"http://127.0.0.1:3000{{path}}?{{query}}",
                        "allowInsecureDowngrade":allow,
                        "preserveHost":allow,
                        "preserveCredentials":allow
                    }),
                    created_by: "user".to_string(),
                })
                .unwrap();
            storage
                .set_capture_rule_enabled(&rule.id, true, true)
                .unwrap();
        }
        let mut request = RuntimeRuleRequest {
            request_id: "map-downgrade".to_string(),
            method: "POST".to_string(),
            scheme: "https".to_string(),
            host: "secure.example.test".to_string(),
            port: 443,
            path: "/submit".to_string(),
            query: Some("token=trusted-token".to_string()),
            source: "browser".to_string(),
            protocol: "http/1.1".to_string(),
            request_headers: vec![
                HeaderEntry {
                    name: "host".to_string(),
                    value: "secure.example.test".to_string(),
                },
                HeaderEntry {
                    name: "authorization".to_string(),
                    value: "Bearer trusted-token".to_string(),
                },
            ],
            request_body: None,
            body_unavailable_reason: None,
        };
        let outcome = apply_runtime_request_rules(&storage, &mut request).unwrap();
        assert_eq!(outcome.traces[0].result, "error");
        assert_eq!(outcome.traces[1].result, "applied");
        assert_eq!(request.scheme, "http");
        assert_eq!(request.host, "127.0.0.1");
        assert_eq!(request.port, 3000);
        assert_eq!(request.query.as_deref(), Some("token=trusted-token"));
        assert!(outcome.control.redirect_preserve_host);
        assert!(request.request_headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("host") && header.value == "secure.example.test"
        }));
        assert!(request
            .request_headers
            .iter()
            .any(|header| { header.name.eq_ignore_ascii_case("authorization") }));
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn runtime_request_body_rules_probe_sequentially_and_apply_atomically() {
        let path = std::env::temp_dir().join(format!(
            "shownet-request-body-rule-runtime-{}.sqlite3",
            Uuid::new_v4()
        ));
        let storage = Storage::open(&path).unwrap();
        for input in [
            CaptureRuleInput {
                id: None,
                name: "mark request".to_string(),
                enabled: false,
                priority: 10,
                stage: "request".to_string(),
                matcher: FilterExpression::Predicate {
                    field: "host".to_string(),
                    operator: "equals".to_string(),
                    value: Some(json!("api.example.test")),
                },
                action: json!({"kind":"rewrite","operations":[
                    {"target":"request.header","op":"set","name":"X-Route","value":"rewrite-body"}
                ]}),
                created_by: "user".to_string(),
            },
            CaptureRuleInput {
                id: None,
                name: "rewrite request body".to_string(),
                enabled: false,
                priority: 20,
                stage: "request".to_string(),
                matcher: FilterExpression::Predicate {
                    field: "requestHeader".to_string(),
                    operator: "contains".to_string(),
                    value: Some(json!("X-Route: rewrite-body")),
                },
                action: json!({"kind":"rewrite","operations":[
                    {"target":"request.header","op":"set","name":"X-Body-Rule","value":"private-header-value"},
                    {"target":"request.body","op":"replace","pattern":"secret-[0-9]+","value":"private-body-value"}
                ]}),
                created_by: "user".to_string(),
            },
        ] {
            let rule = storage.save_capture_rule(input).unwrap();
            storage
                .set_capture_rule_enabled(&rule.id, true, true)
                .unwrap();
        }
        let request = RuntimeRuleRequest {
            request_id: "request-body-runtime".to_string(),
            method: "POST".to_string(),
            scheme: "https".to_string(),
            host: "api.example.test".to_string(),
            port: 443,
            path: "/v1/items".to_string(),
            query: None,
            source: "browser".to_string(),
            protocol: "h2".to_string(),
            request_headers: Vec::new(),
            request_body: None,
            body_unavailable_reason: Some("压缩请求正文保持原样转发，不能安全改写".to_string()),
        };
        assert!(runtime_request_body_required(&storage, &request).unwrap());

        let mut unavailable = request.clone();
        let skipped = apply_runtime_request_rules(&storage, &mut unavailable).unwrap();
        assert!(!skipped.control.request_body_changed);
        assert_eq!(skipped.traces[1].result, "skipped");
        assert!(!unavailable
            .request_headers
            .iter()
            .any(|header| header.name == "X-Body-Rule"));

        let mut available = RuntimeRuleRequest {
            request_body: Some("hello secret-123".to_string()),
            body_unavailable_reason: None,
            ..request
        };
        let applied = apply_runtime_request_rules(&storage, &mut available).unwrap();
        assert!(applied.control.request_body_changed);
        assert_eq!(
            available.request_body.as_deref(),
            Some("hello private-body-value")
        );
        assert!(available.request_headers.iter().any(|header| {
            header.name == "X-Body-Rule" && header.value == "private-header-value"
        }));
        assert_eq!(applied.traces[1].diff_summary["bodyChanged"], true);
        let trace_json = serde_json::to_string(&[skipped.traces, applied.traces]).unwrap();
        for sensitive in [
            "secret-123",
            "secret-[0-9]+",
            "private-body-value",
            "private-header-value",
        ] {
            assert!(!trace_json.contains(sensitive));
        }
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn runtime_response_rules_are_atomic_and_never_trace_body_or_header_values() {
        let path = std::env::temp_dir().join(format!(
            "shownet-response-rule-runtime-{}.sqlite3",
            Uuid::new_v4()
        ));
        let storage = Storage::open(&path).unwrap();
        let rule = storage
            .save_capture_rule(CaptureRuleInput {
                id: None,
                name: "rewrite response".to_string(),
                enabled: false,
                priority: 10,
                stage: "response".to_string(),
                matcher: FilterExpression::Predicate {
                    field: "status".to_string(),
                    operator: "equals".to_string(),
                    value: Some(json!(200)),
                },
                action: json!({
                    "kind": "rewrite",
                    "operations": [
                        {"target":"response.header","op":"set","name":"X-Rule-Value","value":"private-header-value"},
                        {"target":"response.status","op":"set","value":201},
                        {"target":"response.body","op":"replace","pattern":"world","value":"private-body-value"}
                    ]
                }),
                created_by: "user".to_string(),
            })
            .unwrap();
        storage
            .set_capture_rule_enabled(&rule.id, true, true)
            .unwrap();
        let request = RuntimeRuleRequest {
            request_id: "response-runtime-request".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "api.example.test".to_string(),
            port: 443,
            path: "/v1/items".to_string(),
            query: None,
            source: "browser".to_string(),
            protocol: "h2".to_string(),
            request_headers: Vec::new(),
            request_body: None,
            body_unavailable_reason: None,
        };
        let mut unavailable = RuntimeRuleResponse {
            request: request.clone(),
            status: 200,
            response_headers: vec![HeaderEntry {
                name: "content-type".to_string(),
                value: "text/plain".to_string(),
            }],
            response_body: None,
            body_unavailable_reason: Some("响应正文长度未知，已跳过整条正文规则".to_string()),
        };
        assert!(runtime_response_body_required(&storage, &unavailable).unwrap());
        let skipped = apply_runtime_response_rules(&storage, &mut unavailable).unwrap();
        assert!(!skipped.body_changed);
        assert_eq!(unavailable.status, 200);
        assert_eq!(unavailable.response_headers.len(), 1);
        assert_eq!(skipped.traces[0].result, "skipped");

        let mut available = RuntimeRuleResponse {
            request,
            status: 200,
            response_headers: vec![HeaderEntry {
                name: "content-type".to_string(),
                value: "text/plain".to_string(),
            }],
            response_body: Some("hello world".to_string()),
            body_unavailable_reason: None,
        };
        let applied = apply_runtime_response_rules(&storage, &mut available).unwrap();
        assert!(applied.body_changed);
        assert_eq!(available.status, 201);
        assert_eq!(
            available.response_body.as_deref(),
            Some("hello private-body-value")
        );
        assert!(available.response_headers.iter().any(|header| {
            header.name == "X-Rule-Value" && header.value == "private-header-value"
        }));
        let trace_json = serde_json::to_string(&[skipped.traces, applied.traces]).unwrap();
        assert!(!trace_json.contains("private-header-value"));
        assert!(!trace_json.contains("private-body-value"));
        assert!(!trace_json.contains("hello world"));
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn runtime_throttle_applies_rates_jitter_and_deterministic_full_packet_loss() {
        let path = std::env::temp_dir().join(format!(
            "shownet-throttle-rule-runtime-{}.sqlite3",
            Uuid::new_v4()
        ));
        let storage = Storage::open(&path).unwrap();
        let rule = storage
            .save_capture_rule(CaptureRuleInput {
                id: None,
                name: "offline profile".to_string(),
                enabled: false,
                priority: 10,
                stage: "request".to_string(),
                matcher: FilterExpression::Predicate {
                    field: "host".to_string(),
                    operator: "equals".to_string(),
                    value: Some(json!("api.example.test")),
                },
                action: json!({
                    "kind":"throttle",
                    "latencyMs":10,
                    "jitterMs":5,
                    "uploadKbps":64,
                    "downloadKbps":128,
                    "packetLossPercent":100.0
                }),
                created_by: "user".to_string(),
            })
            .unwrap();
        storage
            .set_capture_rule_enabled(&rule.id, true, true)
            .unwrap();
        let mut request = RuntimeRuleRequest {
            request_id: "throttle-runtime-request".to_string(),
            method: "POST".to_string(),
            scheme: "https".to_string(),
            host: "api.example.test".to_string(),
            port: 443,
            path: "/upload".to_string(),
            query: None,
            source: "mobile".to_string(),
            protocol: "h2".to_string(),
            request_headers: Vec::new(),
            request_body: None,
            body_unavailable_reason: None,
        };
        let outcome = apply_runtime_request_rules(&storage, &mut request).unwrap();
        assert!((10..=15).contains(&outcome.control.delay_ms));
        assert_eq!(outcome.control.upload_bytes_per_second, Some(8_000));
        assert_eq!(outcome.control.download_bytes_per_second, Some(16_000));
        assert!(outcome.control.blocked);
        assert_eq!(outcome.control.block_status, Some(504));
        assert_eq!(
            outcome.control.block_message.as_deref(),
            Some("ShowNet 弱网规则模拟丢包")
        );
        assert_eq!(outcome.traces[0].result, "applied");
        drop(storage);
        let _ = std::fs::remove_file(path);
    }
}
