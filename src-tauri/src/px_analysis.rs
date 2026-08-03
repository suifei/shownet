//! PerimeterX / HUMAN capture analysis helpers (authorized reverse-engineering).
//!
//! Detects PX markers, optional ecData intercept tagging, and best-effort structural
//! decode when payloads are JSON/base64 — never fabricates cryptographic decrypt
//! without key material from capture/hooks.

use crate::models::RequestRecord;
use crate::storage::Storage;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};

static PX_DECRYPT_ENABLED: AtomicBool = AtomicBool::new(false);
static PX_INTERCEPT_ECDATA: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PxSettings {
    pub decrypt_enabled: bool,
    pub intercept_ec_data: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PxEvidenceItem {
    pub request_id: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub markers: Vec<String>,
    pub has_ec_data: bool,
    pub cookie_hints: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PxDecodeResult {
    pub request_id: String,
    pub status: String,
    pub summary: String,
    pub fields: Value,
    pub notes: Vec<String>,
}

pub fn set_px_decrypt_enabled(enabled: bool) {
    PX_DECRYPT_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn set_px_intercept_ec_data(enabled: bool) {
    PX_INTERCEPT_ECDATA.store(enabled, Ordering::Relaxed);
}

pub fn px_decrypt_enabled() -> bool {
    PX_DECRYPT_ENABLED.load(Ordering::Relaxed)
}

pub fn px_intercept_ec_data() -> bool {
    PX_INTERCEPT_ECDATA.load(Ordering::Relaxed)
}

pub fn settings() -> PxSettings {
    PxSettings {
        decrypt_enabled: px_decrypt_enabled(),
        intercept_ec_data: px_intercept_ec_data(),
    }
}

pub fn settings_json() -> Value {
    json!({
        "decryptEnabled": px_decrypt_enabled(),
        "interceptEcData": px_intercept_ec_data(),
        // Expose helper so intercept mode is part of the shipped settings surface.
        "interceptHelper": "should_tag_ecdata_intercept(body, path)",
    })
}

/// True if text looks like PerimeterX / HUMAN bot-defense traffic.
pub fn blob_has_px_markers(blob: &str) -> bool {
    let lower = blob.to_ascii_lowercase();
    [
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
        "pxhd=",
        "ecdata",
        "\"ecdata\"",
        "collector-",
        "/api/v2/collector",
        "px-cloud",
        "client.perimeterx",
        "captcha.px-cdn",
    ]
    .iter()
    .any(|m| lower.contains(m))
}

pub fn extract_markers(blob: &str) -> Vec<String> {
    let lower = blob.to_ascii_lowercase();
    let catalog = [
        ("_px3", "cookie:_px3"),
        ("_pxvid", "cookie:_pxvid"),
        ("_pxhd", "cookie:_pxhd"),
        ("pxcts", "cookie:pxcts"),
        ("ecdata", "field:ecData"),
        ("perimeterx", "vendor:perimeterx"),
        ("humansecurity", "vendor:human"),
        ("px-cdn", "host:px-cdn"),
        ("collector", "path:collector"),
        ("px-captcha", "captcha:px"),
    ];
    catalog
        .iter()
        .filter(|(needle, _)| lower.contains(needle))
        .map(|(_, label)| (*label).to_string())
        .collect()
}

pub fn list_session_evidence(
    storage: &Storage,
    session_id: &str,
    limit: usize,
) -> Result<Vec<PxEvidenceItem>, String> {
    let requests = storage.list_requests(session_id, Some(10_000), Some(0))?;
    let mut items = Vec::new();
    for request in requests {
        if let Some(item) = evidence_from_request(&request) {
            items.push(item);
            if items.len() >= limit {
                break;
            }
        }
    }
    Ok(items)
}

fn evidence_from_request(request: &RequestRecord) -> Option<PxEvidenceItem> {
    let cookie = request
        .request_headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("cookie"))
        .map(|h| h.value.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    let body = request.request_body.as_deref().unwrap_or("");
    let blob = format!(
        "{} {} {} {} {}",
        request.host, request.path, cookie, body, request.response_body
    );
    if !blob_has_px_markers(&blob) {
        return None;
    }
    let markers = extract_markers(&blob);
    let has_ec_data = blob.to_ascii_lowercase().contains("ecdata")
        || should_tag_ecdata_intercept(body, &request.path);
    let cookie_hints = markers
        .iter()
        .filter(|m| m.starts_with("cookie:"))
        .cloned()
        .collect();
    Some(PxEvidenceItem {
        request_id: request.id.clone(),
        method: request.method.clone(),
        host: request.host.clone(),
        path: request.path.clone(),
        markers,
        has_ec_data,
        cookie_hints,
    })
}

/// Best-effort structural decode — not a cryptographic break.
pub fn decode_request_payload(
    storage: &Storage,
    request_id: &str,
) -> Result<PxDecodeResult, String> {
    let request = storage.get_request_detail(request_id)?;
    let body = request.request_body.as_deref().unwrap_or("").trim();
    let mut notes = vec![
        "Structural decode only; full PX decrypt requires session keys from authorized hooks."
            .into(),
    ];
    if !px_decrypt_enabled() {
        notes.push("PX decrypt toggle is off — enable in Advanced Console / Settings.".into());
    }

    if body.is_empty() {
        return Ok(PxDecodeResult {
            request_id: request_id.to_string(),
            status: "empty".into(),
            summary: "No request body".into(),
            fields: json!({}),
            notes,
        });
    }

    // JSON body
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        let has_ec = value
            .pointer("/ecData")
            .or_else(|| value.get("ecData"))
            .or_else(|| value.get("ecdata"))
            .is_some();
        let status = if has_ec && px_decrypt_enabled() {
            "partial"
        } else if has_ec {
            "encrypted_opaque"
        } else {
            "decoded"
        };
        let mut fields = value;
        if let Some(ec) = fields
            .get("ecData")
            .cloned()
            .or_else(|| fields.get("ecdata").cloned())
        {
            if let Some(s) = ec.as_str() {
                notes.push(format!(
                    "ecData length={} (opaque unless keys available)",
                    s.len()
                ));
                // Try base64 envelope only
                if let Ok(bytes) = STANDARD.decode(s) {
                    notes.push(format!("ecData base64-decodes to {} bytes", bytes.len()));
                    if px_decrypt_enabled() {
                        fields.as_object_mut().map(|obj| {
                            obj.insert("ecDataBase64Length".into(), json!(bytes.len()));
                            obj.insert("ecDataPreviewHex".into(), json!(hex_preview(&bytes, 32)));
                        });
                    }
                }
            }
        }
        return Ok(PxDecodeResult {
            request_id: request_id.to_string(),
            status: status.into(),
            summary: "Parsed JSON body; PX fields mapped without claiming full decrypt".into(),
            fields,
            notes,
        });
    }

    // form-urlencoded
    if body.contains('=') && body.contains('&') {
        let mut map = serde_json::Map::new();
        for pair in body.split('&') {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if !k.is_empty() {
                map.insert(k.to_string(), json!(v));
            }
        }
        let has_ec = map.keys().any(|k| k.eq_ignore_ascii_case("ecdata"));
        return Ok(PxDecodeResult {
            request_id: request_id.to_string(),
            status: if has_ec {
                "encrypted_opaque"
            } else {
                "decoded"
            }
            .into(),
            summary: "Parsed form body keys".into(),
            fields: Value::Object(map),
            notes,
        });
    }

    Ok(PxDecodeResult {
        request_id: request_id.to_string(),
        status: "opaque".into(),
        summary: "Body is not JSON/form; left opaque".into(),
        fields: json!({ "rawLength": body.len() }),
        notes,
    })
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

pub fn should_tag_ecdata_intercept(body: &str, path: &str) -> bool {
    if !px_intercept_ec_data() {
        return false;
    }
    let blob = format!("{path} {body}").to_ascii_lowercase();
    blob.contains("ecdata") || blob.contains("/collector") && blob_has_px_markers(&blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_px_cookies() {
        assert!(blob_has_px_markers("cookie: _px3=abc; _pxvid=1"));
        assert!(blob_has_px_markers(r#"{"ecData":"AAAA"}"#));
        assert!(!blob_has_px_markers("normal api call"));
    }

    #[test]
    fn intercept_respects_toggle() {
        set_px_intercept_ec_data(false);
        assert!(!should_tag_ecdata_intercept(r#"{"ecData":"x"}"#, "/api"));
        set_px_intercept_ec_data(true);
        assert!(should_tag_ecdata_intercept(r#"{"ecData":"x"}"#, "/api"));
        set_px_intercept_ec_data(false);
    }
}
