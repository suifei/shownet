//! Parse the real provider error out of chat, Responses, and gateway wrappers.
//!
//! ClaudeGPT and other OpenAI-compatible gateways often wrap a Responses API
//! `response.failed` event as HTTP 502. The HTTP status is not the cause; the
//! cause is `response.error.code` / `type` / `message`. Other failures use the
//! same envelope with a different code, so we surface those fields instead of
//! assuming a context-window overflow.

use reqwest::StatusCode;
use serde_json::Value;

const MAX_PARSE_DEPTH: u8 = 3;
const MAX_ERROR_BYTES: usize = 1_200;

const NON_RETRYABLE_CODES: &[&str] = &[
    "context_length_exceeded",
    "invalid_request_error",
    "invalid_api_key",
    "invalid_api_key_error",
    "model_not_found",
    "model_not_available",
    "insufficient_quota",
    "billing_not_active",
    "content_filter",
    "content_filter_error",
    "content_policy_violation",
    "unsupported_value",
    "string_above_max_length",
    "max_tokens_exceeded",
];

const NON_RETRYABLE_TYPES: &[&str] = &[
    "invalid_request_error",
    "authentication_error",
    "permission_error",
    "not_found_error",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AiProviderError {
    pub code: Option<String>,
    pub error_type: Option<String>,
    pub message: Option<String>,
    pub model: Option<String>,
    pub event: Option<String>,
    pub status: Option<String>,
}

impl AiProviderError {
    pub fn is_terminal(&self) -> bool {
        self.code.is_some()
            || self.message.is_some()
            || self.event.as_deref() == Some("response.failed")
            || self.status.as_deref() == Some("failed")
    }

    pub fn is_retryable(&self) -> bool {
        if self
            .code
            .as_deref()
            .is_some_and(|code| named_in(NON_RETRYABLE_CODES, code))
        {
            return false;
        }
        if self
            .error_type
            .as_deref()
            .is_some_and(|error_type| named_in(NON_RETRYABLE_TYPES, error_type))
        {
            return false;
        }
        if self
            .message
            .as_deref()
            .is_some_and(looks_like_non_retryable_client_error)
        {
            return false;
        }
        true
    }

    fn is_empty(&self) -> bool {
        !self.is_terminal() && self.error_type.is_none()
    }

    fn merge(self, nested: Self) -> Self {
        Self {
            code: nested.code.or(self.code),
            error_type: nested.error_type.or(self.error_type),
            message: nested.message.or(self.message),
            model: nested.model.or(self.model),
            event: nested.event.or(self.event),
            status: nested.status.or(self.status),
        }
    }
}

pub fn extract_ai_provider_error(body: &str) -> Option<AiProviderError> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        return extract_from_value(&value);
    }
    parse_embedded_json(body).and_then(|value| extract_from_value(&value))
}

pub fn extract_from_value(value: &Value) -> Option<AiProviderError> {
    extract_from_value_depth(value, 0)
}

pub fn format_ai_failure(http: Option<StatusCode>, body: &str) -> String {
    match extract_ai_provider_error(body) {
        Some(error) if error.is_terminal() => format_extracted(http, &error),
        _ => fallback_http_error(http, body),
    }
}

pub fn format_extracted(http: Option<StatusCode>, error: &AiProviderError) -> String {
    let mut lines = vec!["AI 请求失败".to_string()];
    if let Some(event) = error.event.as_deref() {
        lines.push(format!("事件：{event}"));
    }
    if let Some(model) = error.model.as_deref() {
        lines.push(format!("模型：{model}"));
    }
    if let Some(code) = error.code.as_deref() {
        lines.push(format!("错误码：{code}"));
    }
    if let Some(error_type) = error.error_type.as_deref() {
        lines.push(format!("类型：{error_type}"));
    }
    if let Some(message) = error.message.as_deref() {
        lines.push(format!("说明：{message}"));
    }
    if let Some(status) = http {
        if error.code.is_some() || error.error_type.is_some() {
            lines.push(format!("HTTP：{status}（传输层状态，根因见上方错误码）"));
        } else {
            lines.push(format!("HTTP：{status}"));
        }
    }
    if error.code.as_deref() == Some("context_length_exceeded") {
        lines.push("可缩短提示词后重试，或改到窗口更大的模型 / 提高端点上下文上限。".to_string());
    }
    lines.join("\n")
}

pub fn is_retryable_ai_failure(status: StatusCode, error: Option<&AiProviderError>) -> bool {
    if error.is_some_and(|error| !error.is_retryable()) {
        return false;
    }
    matches!(status.as_u16(), 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

fn extract_from_value_depth(value: &Value, depth: u8) -> Option<AiProviderError> {
    if depth > MAX_PARSE_DEPTH {
        return None;
    }

    let event = string_field(value, "type");
    let model = value
        .pointer("/response/model")
        .and_then(Value::as_str)
        .or_else(|| value.get("model").and_then(Value::as_str))
        .map(ToOwned::to_owned);
    let status = value
        .pointer("/response/status")
        .or_else(|| value.get("status"))
        .and_then(status_text);

    let error_node = value
        .pointer("/response/error")
        .or_else(|| value.get("error"))
        .or_else(|| value.pointer("/data/error"));

    let mut extracted = match error_node {
        Some(node) => error_node_to_error(node, depth),
        None => AiProviderError::default(),
    };
    if extracted.model.is_none() {
        extracted.model = model;
    }
    if extracted.event.is_none() {
        extracted.event = event;
    }
    if extracted.status.is_none() {
        extracted.status = status;
    }
    if extracted.is_empty() {
        None
    } else {
        Some(extracted)
    }
}

fn error_node_to_error(node: &Value, depth: u8) -> AiProviderError {
    if let Some(text) = node.as_str() {
        if let Some(nested) = parse_embedded_json(text)
            .and_then(|value| extract_from_value_depth(&value, depth.saturating_add(1)))
        {
            return nested;
        }
        return AiProviderError {
            message: Some(text.to_string()),
            ..AiProviderError::default()
        };
    }
    if !node.is_object() {
        return AiProviderError::default();
    }

    let mut error = AiProviderError {
        code: string_field(node, "code"),
        error_type: string_field(node, "type"),
        message: string_field(node, "message"),
        ..AiProviderError::default()
    };

    if let Some(raw) = node.pointer("/metadata/raw").and_then(Value::as_str) {
        if let Some(nested) = parse_embedded_json(raw)
            .and_then(|value| extract_from_value_depth(&value, depth.saturating_add(1)))
        {
            error = error.merge(nested);
        }
    }
    if let Some(message) = error.message.clone() {
        if let Some(nested) = parse_embedded_json(&message)
            .and_then(|value| extract_from_value_depth(&value, depth.saturating_add(1)))
        {
            error = error.merge(nested);
        }
    }
    error
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

fn status_text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .or_else(|| value.as_u64().map(|number| number.to_string()))
        .or_else(|| value.as_i64().map(|number| number.to_string()))
}

fn parse_embedded_json(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        if value.is_object() || value.is_array() {
            return Some(value);
        }
    }
    let start = trimmed.find('{')?;
    let end = trimmed.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&trimmed[start..=end]).ok()
}

fn named_in(names: &[&str], value: &str) -> bool {
    names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(value.trim()))
}

fn looks_like_non_retryable_client_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("context_length")
        || lower.contains("context window")
        || lower.contains("maximum context")
        || lower.contains("too many tokens")
        || lower.contains("incorrect api key")
        || lower.contains("invalid api key")
}

fn fallback_http_error(http: Option<StatusCode>, body: &str) -> String {
    let snippet = truncate_utf8(body, MAX_ERROR_BYTES);
    match http {
        Some(status) if snippet.trim().is_empty() => format!("AI 服务返回 HTTP {status}"),
        Some(status) => format!("AI 服务返回 HTTP {status}: {snippet}"),
        None if snippet.trim().is_empty() => "AI 服务返回了无法解析的错误".to_string(),
        None => snippet,
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RESPONSES_FAILED: &str = r#"{
      "response": {
        "background": false,
        "completed_at": null,
        "created_at": 1786985537,
        "error": {
          "code": "context_length_exceeded",
          "message": "Your input exceeds the context window of this model. Please adjust your input and try again.",
          "type": "invalid_request_error"
        },
        "id": "resp_0152a6261316287f016a833c41309481908926745fc3b4034a",
        "model": "gpt-5.5",
        "object": "response",
        "status": "failed",
        "store": false
      },
      "sequence_number": 3,
      "type": "response.failed"
    }"#;

    #[test]
    fn reads_responses_api_failed_event_fields() {
        let error = extract_ai_provider_error(RESPONSES_FAILED).expect("parsed");
        assert_eq!(error.code.as_deref(), Some("context_length_exceeded"));
        assert_eq!(error.error_type.as_deref(), Some("invalid_request_error"));
        assert_eq!(error.model.as_deref(), Some("gpt-5.5"));
        assert_eq!(error.event.as_deref(), Some("response.failed"));
        assert_eq!(error.status.as_deref(), Some("failed"));
        assert!(error
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("context window"));
        assert!(!error.is_retryable());
    }

    #[test]
    fn surfaces_a_different_code_instead_of_assuming_context() {
        let body = json!({
            "response": {
                "error": {
                    "code": "server_error",
                    "message": "The server had an error while processing your request.",
                    "type": "api_error"
                },
                "model": "gpt-5.5",
                "status": "failed"
            },
            "type": "response.failed"
        });
        let error = extract_from_value(&body).expect("parsed");
        assert_eq!(error.code.as_deref(), Some("server_error"));
        assert!(error.is_retryable());
        let formatted = format_extracted(Some(StatusCode::BAD_GATEWAY), &error);
        assert!(formatted.contains("错误码：server_error"));
        assert!(!formatted.contains("context_length_exceeded"));
        assert!(formatted.contains("HTTP：502"));
    }

    #[test]
    fn unwraps_a_gateway_502_that_embeds_the_raw_event() {
        let wrapped = json!({
            "error": {
                "message": "Your input exceeds the context window of this model.",
                "type": "upstream_error",
                "metadata": { "raw": RESPONSES_FAILED }
            }
        })
        .to_string();
        let error = extract_ai_provider_error(&wrapped).expect("parsed");
        assert_eq!(error.code.as_deref(), Some("context_length_exceeded"));
        assert_eq!(error.error_type.as_deref(), Some("invalid_request_error"));
        assert!(!is_retryable_ai_failure(
            StatusCode::BAD_GATEWAY,
            Some(&error)
        ));
    }

    #[test]
    fn still_retries_a_bare_502_with_no_provider_error() {
        assert!(is_retryable_ai_failure(StatusCode::BAD_GATEWAY, None));
        assert!(!is_retryable_ai_failure(StatusCode::BAD_REQUEST, None));
    }

    #[test]
    fn formatted_failure_keeps_code_type_and_message() {
        let text = format_ai_failure(Some(StatusCode::BAD_GATEWAY), RESPONSES_FAILED);
        assert!(text.contains("错误码：context_length_exceeded"));
        assert!(text.contains("类型：invalid_request_error"));
        assert!(text.contains("模型：gpt-5.5"));
        assert!(text.contains("事件：response.failed"));
        assert!(text.contains("Your input exceeds the context window"));
        assert!(text.contains("HTTP：502"));
    }

    #[test]
    fn ignores_in_progress_response_events() {
        let value = json!({
            "type": "response.created",
            "response": { "status": "in_progress", "model": "gpt-5.5" }
        });
        assert!(extract_from_value(&value).is_none());
    }
}
