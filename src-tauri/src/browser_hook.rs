use crate::models::BrowserHookInput;
use serde_json::{Map, Value};

pub const BRIDGE_NAME: &str = "__SHOWNET_HOOK_BRIDGE__";
const MAX_DEPTH: usize = 8;
const MAX_COLLECTION_ITEMS: usize = 200;
const MAX_NAME_CHARS: usize = 160;
const MAX_URL_CHARS: usize = 8_192;
const MAX_STACK_CHARS: usize = 16_384;
const MAX_VALUE_CHARS: usize = 16_384;

pub fn script() -> &'static str {
    let source = include_str!("../../public/lab/shownet-hook-runtime.js");
    debug_assert!(source.contains(BRIDGE_NAME));
    source
}

pub fn normalize_input(mut input: BrowserHookInput) -> Result<BrowserHookInput, String> {
    input.session_id = bounded_required(input.session_id, "Hook 缺少会话 ID", 256)?;
    input.kind = bounded_required(input.kind.to_ascii_lowercase(), "Hook 缺少类型", 32)?;
    if !matches!(
        input.kind.as_str(),
        "network" | "crypto" | "encoding" | "storage" | "interaction" | "runtime"
    ) {
        return Err(format!("不支持的 Hook 类型: {}", input.kind));
    }
    input.name = bounded_required(input.name, "Hook 缺少调用名称", MAX_NAME_CHARS)?;
    input.source_instance_id = input
        .source_instance_id
        .map(|value| bound_chars(value, 256))
        .filter(|value| !value.is_empty());
    input.request_id = input
        .request_id
        .map(|value| bound_chars(value, 256))
        .filter(|value| !value.is_empty());
    input.url = input
        .url
        .map(|value| bound_chars(value, MAX_URL_CHARS))
        .filter(|value| !value.is_empty());
    input.method = input
        .method
        .map(|value| bound_chars(value.to_ascii_uppercase(), 16))
        .filter(|value| !value.is_empty());
    input.stack = input
        .stack
        .map(|value| bound_chars(value, MAX_STACK_CHARS))
        .filter(|value| !value.is_empty());
    input.duration_ms = input.duration_ms.map(|value| value.clamp(0, 300_000));
    bound_value(&mut input.input, 0);
    bound_value(&mut input.output, 0);
    Ok(input)
}

fn bound_value(value: &mut Value, depth: usize) {
    if depth >= MAX_DEPTH {
        *value = Value::String("[TRUNCATED: depth]".to_string());
        return;
    }
    match value {
        Value::Object(object) => {
            let original = std::mem::take(object);
            let mut bounded = Map::new();
            for (index, (entry_key, mut entry_value)) in original.into_iter().enumerate() {
                if index >= MAX_COLLECTION_ITEMS {
                    bounded.insert(
                        "__shownet_truncated__".to_string(),
                        Value::String("collection limit".to_string()),
                    );
                    break;
                }
                bound_value(&mut entry_value, depth + 1);
                bounded.insert(bound_chars(entry_key, 256), entry_value);
            }
            *object = bounded;
        }
        Value::Array(items) => {
            items.truncate(MAX_COLLECTION_ITEMS);
            for item in items {
                bound_value(item, depth + 1);
            }
        }
        Value::String(text) => {
            *text = bound_chars(std::mem::take(text), MAX_VALUE_CHARS);
        }
        _ => {}
    }
}

fn bounded_required(value: String, message: &str, maximum: usize) -> Result<String, String> {
    let value = bound_chars(value.trim().to_string(), maximum);
    if value.is_empty() {
        Err(message.to_string())
    } else {
        Ok(value)
    }
}

fn bound_chars(value: String, maximum: usize) -> String {
    let count = value.chars().count();
    if count <= maximum {
        value
    } else {
        let mut bounded = value.chars().take(maximum).collect::<String>();
        bounded.push_str("\n[TRUNCATED]");
        bounded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_covers_network_crypto_and_storage_surfaces() {
        let source = script();
        for marker in [
            "window.fetch",
            "XMLHttpRequest",
            "SubtleCrypto",
            "CryptoJS",
            "sm2",
            "sm3",
            "sm4",
            "document.cookie",
            "Storage.prototype",
        ] {
            assert!(source.contains(marker), "missing hook surface: {marker}");
        }
        assert!(source.contains(BRIDGE_NAME));
        assert!(!source.contains("[REDACTED]"));
        assert!(!source.contains("[NOT_CAPTURED]"));
        assert!(source.contains("value: text"));
        assert!(source.contains("...formValue(event.target)"));
    }

    #[test]
    fn normalizes_and_preserves_bounded_hook_values() {
        let input = BrowserHookInput {
            session_id: " session-1 ".to_string(),
            source_instance_id: None,
            request_id: None,
            timestamp: None,
            kind: "CRYPTO".to_string(),
            name: "crypto.subtle.sign".to_string(),
            url: Some("https://example.test/login".to_string()),
            method: Some("post".to_string()),
            input: json!({
                "algorithm": "HMAC",
                "password": "plain",
                "body": "access_token=secret&value=kept"
            }),
            output: json!({ "signature": "abc" }),
            stack: Some("stack".to_string()),
            duration_ms: Some(42),
        };
        let normalized = normalize_input(input).unwrap();
        assert_eq!(normalized.session_id, "session-1");
        assert_eq!(normalized.kind, "crypto");
        assert_eq!(normalized.method.as_deref(), Some("POST"));
        assert_eq!(normalized.input["password"], "plain");
        assert_eq!(normalized.input["body"], "access_token=secret&value=kept");
    }
}
