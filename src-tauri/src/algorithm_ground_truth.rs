//! Paired input→output evidence pulled out of a capture, for verifying a
//! reconstructed algorithm by running it.
//!
//! Every other check in this codebase compares *shapes*: is the header present,
//! is the signature the right length, is it hex. A shape check passes for a
//! function that returns the right number of wrong characters, which is exactly
//! the failure mode a reconstructed signer has. This module produces the only
//! thing that can settle the question — cases where the expected output is known
//! because the capture recorded it.
//!
//! Two origins, both genuine:
//!
//! - `hook` — the page called a crypto function and the browser hook recorded
//!   both the argument and the return value. Verifies one step in isolation.
//! - `request` — a request carried a dynamic field whose value we can see, next
//!   to the method/path/headers/body that produced it. Verifies the whole chain
//!   end to end, which is the stronger claim.
//!
//! What this module deliberately does *not* do is invent cases. A capture with
//! no hook pairs and no observed dynamic fields yields zero cases, and the
//! caller must report "unverifiable" rather than "verified".

use crate::models::{BrowserHookEvent, RequestRecord};
use serde::Serialize;
use serde_json::{json, Value};

/// One case: run the candidate on `input`, the answer must be `expected`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroundTruthCase {
    pub id: String,
    /// `hook` or `request` — see the module docs; they authorise different claims.
    pub origin: String,
    /// Which field this case pins, e.g. `x-signature` or the hooked function name.
    pub field: String,
    pub algorithm_hint: String,
    pub input: Value,
    pub expected: String,
    pub request_id: Option<String>,
    pub sequence: i64,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroundTruth {
    pub cases: Vec<GroundTruthCase>,
    /// Why candidate evidence was not usable. Kept so an empty case list can be
    /// explained rather than silently read as "nothing to check".
    pub skipped: Vec<String>,
}

impl GroundTruth {
    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }

    pub fn end_to_end_cases(&self) -> usize {
        self.cases.iter().filter(|c| c.origin == "request").count()
    }
}

/// Longest a recorded value may be and still be treated as a signature-like
/// output. Beyond this it is a response body or a serialised blob, not a field
/// some function returned.
const MAX_EXPECTED_LEN: usize = 512;
/// Below this, a "match" carries almost no information: single characters and
/// short flags collide by chance.
const MIN_EXPECTED_LEN: usize = 8;

pub fn collect(
    hooks: &[BrowserHookEvent],
    requests: &[RequestRecord],
    dynamic_fields: &[String],
) -> GroundTruth {
    let mut truth = GroundTruth::default();
    collect_from_hooks(hooks, &mut truth);
    collect_from_requests(requests, dynamic_fields, &mut truth);
    if truth.cases.is_empty() && truth.skipped.is_empty() {
        truth.skipped.push(
            "capture carries neither crypto hook pairs nor observed dynamic field values".into(),
        );
    }
    truth
}

fn collect_from_hooks(hooks: &[BrowserHookEvent], truth: &mut GroundTruth) {
    for hook in hooks {
        if !is_crypto_hook(hook) {
            continue;
        }
        if hook.input.is_null() {
            truth
                .skipped
                .push(format!("hook {} recorded no input", hook.name));
            continue;
        }
        let Some(expected) = scalar_output(&hook.output) else {
            truth.skipped.push(format!(
                "hook {} recorded no single-value output to compare against",
                hook.name
            ));
            continue;
        };
        if !usable_expected(&expected) {
            truth.skipped.push(format!(
                "hook {} output is {} chars; outside the range a signature comparison is meaningful in",
                hook.name,
                expected.len()
            ));
            continue;
        }
        truth.cases.push(GroundTruthCase {
            id: format!("hook-{}", hook.sequence),
            origin: "hook".into(),
            field: hook.name.clone(),
            algorithm_hint: algorithm_hint(hook),
            input: hook.input.clone(),
            expected,
            request_id: hook.request_id.clone(),
            sequence: hook.sequence,
        });
    }
}

fn collect_from_requests(
    requests: &[RequestRecord],
    dynamic_fields: &[String],
    truth: &mut GroundTruth,
) {
    if dynamic_fields.is_empty() {
        return;
    }
    let wanted: Vec<String> = dynamic_fields
        .iter()
        .map(|field| field.to_ascii_lowercase())
        .collect();

    for request in requests {
        for header in &request.request_headers {
            let name = header.name.to_ascii_lowercase();
            if !wanted.iter().any(|field| field == &name) {
                continue;
            }
            let value = header.value.trim().to_string();
            if !usable_expected(&value) {
                continue;
            }
            truth.cases.push(GroundTruthCase {
                id: format!("request-{}-{}", request.id, name),
                origin: "request".into(),
                field: name.clone(),
                algorithm_hint: "observed on the wire".into(),
                // Everything the signer could have drawn on, minus the field
                // itself: leaving it in would let a candidate "verify" by
                // echoing its own answer back.
                input: request_input(request, &name),
                expected: value,
                request_id: Some(request.id.clone()),
                sequence: request.order,
            });
        }
    }
}

/// The request as the signer would have seen it, with `exclude` stripped.
fn request_input(request: &RequestRecord, exclude: &str) -> Value {
    let headers: serde_json::Map<String, Value> = request
        .request_headers
        .iter()
        .filter(|header| !header.name.eq_ignore_ascii_case(exclude))
        .map(|header| (header.name.to_ascii_lowercase(), json!(header.value)))
        .collect();
    json!({
        "method": request.method,
        "host": request.host,
        "path": request.path,
        "query": request.query,
        "headers": headers,
        "body": request.request_body,
    })
}

/// A hook is worth pairing when it names a crypto operation. Kept loose on
/// purpose: a hook that turns out not to be crypto costs one failed case, while
/// a missed one costs the whole verification.
fn is_crypto_hook(hook: &BrowserHookEvent) -> bool {
    let blob = format!("{} {}", hook.kind, hook.name).to_ascii_lowercase();
    [
        "crypto", "subtle", "digest", "sign", "hmac", "sha", "md5", "encrypt", "cipher", "aes",
        "hash", "token",
    ]
    .iter()
    .any(|marker| blob.contains(marker))
}

fn algorithm_hint(hook: &BrowserHookEvent) -> String {
    // WebCrypto names the algorithm in the argument, not the method:
    // `crypto.subtle.sign({name: "HMAC"}, key, data)`. Reading only kind/name
    // would classify every one of those as unknown.
    let blob = format!(
        "{} {} {}",
        hook.kind,
        hook.name,
        serde_json::to_string(&hook.input).unwrap_or_default()
    )
    .to_ascii_lowercase();
    for (marker, name) in [
        ("hmac", "HMAC"),
        ("sha-256", "SHA-256"),
        ("sha256", "SHA-256"),
        ("sha-1", "SHA-1"),
        ("sha1", "SHA-1"),
        ("md5", "MD5"),
        ("aes", "AES"),
        ("rsa", "RSA"),
    ] {
        if blob.contains(marker) {
            return name.to_string();
        }
    }
    "unclassified".into()
}

/// Hook outputs arrive as whatever the page returned. Only a single scalar can
/// be compared; an object could be compared field-wise but that invites a
/// candidate to pass by matching the easy fields.
fn scalar_output(output: &Value) -> Option<String> {
    match output {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Object(map) => {
            // A hook wrapper commonly records `{ "value": ... }` or `{ "result": ... }`.
            for key in ["value", "result", "output", "signature", "hex"] {
                if let Some(inner) = map.get(key) {
                    if let Some(text) = scalar_output(inner) {
                        return Some(text);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn usable_expected(value: &str) -> bool {
    (MIN_EXPECTED_LEN..=MAX_EXPECTED_LEN).contains(&value.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::HeaderEntry;

    fn hook(sequence: i64, kind: &str, name: &str, input: Value, output: Value) -> BrowserHookEvent {
        BrowserHookEvent {
            id: format!("h{sequence}"),
            session_id: "s".into(),
            source_instance_id: "i".into(),
            request_id: Some("r1".into()),
            sequence,
            timestamp: 0,
            kind: kind.into(),
            name: name.into(),
            url: None,
            method: None,
            input,
            output,
            stack: None,
            duration_ms: None,
            correlation: "c".into(),
        }
    }

    fn request(id: &str, headers: &[(&str, &str)]) -> RequestRecord {
        RequestRecord {
            id: id.into(),
            order: 1,
            time: "00:00:00".into(),
            method: "POST".into(),
            host: "api.example.com".into(),
            path: "/v1/order".into(),
            query: None,
            status: 200,
            resource_type: "xhr".into(),
            size: "0".into(),
            duration: 1,
            source: "proxy".into(),
            protocol: "h2".into(),
            tls: "TLS 1.3".into(),
            tls_fingerprint: None,
            risk: "low".into(),
            request_headers: headers
                .iter()
                .map(|(name, value)| HeaderEntry {
                    name: (*name).into(),
                    value: (*value).into(),
                })
                .collect(),
            response_headers: vec![],
            request_body: Some("{\"amount\":10}".into()),
            response_body: String::new(),
            response_body_metadata: Default::default(),
            crypto_snippet_count: 0,
            hook: None,
        }
    }

    #[test]
    fn hook_pair_becomes_a_case() {
        let hooks = vec![hook(
            7,
            "crypto.subtle",
            "sign",
            json!({"algorithm": "HMAC", "data": "amount=10"}),
            json!("9f8e7d6c5b4a39281706"),
        )];
        let truth = collect(&hooks, &[], &[]);
        assert_eq!(truth.cases.len(), 1, "{truth:?}");
        let case = &truth.cases[0];
        assert_eq!(case.origin, "hook");
        assert_eq!(case.expected, "9f8e7d6c5b4a39281706");
        assert_eq!(case.algorithm_hint, "HMAC");
    }

    #[test]
    fn a_hook_without_a_recorded_return_value_is_skipped_with_a_reason() {
        // The dangerous case: treating this as a pass would let an unverifiable
        // capture look verified.
        let hooks = vec![hook(
            1,
            "crypto.subtle",
            "digest",
            json!({"data": "x"}),
            Value::Null,
        )];
        let truth = collect(&hooks, &[], &[]);
        assert!(truth.cases.is_empty());
        assert!(
            truth.skipped.iter().any(|note| note.contains("digest")),
            "the reason must name the hook: {truth:?}"
        );
    }

    #[test]
    fn observed_dynamic_header_becomes_an_end_to_end_case() {
        let requests = vec![request(
            "r1",
            &[
                ("x-signature", "d41d8cd98f00b204e9800998ecf8427e"),
                ("content-type", "application/json"),
            ],
        )];
        let truth = collect(&[], &requests, &["x-signature".into()]);
        assert_eq!(truth.cases.len(), 1, "{truth:?}");
        let case = &truth.cases[0];
        assert_eq!(case.origin, "request");
        assert_eq!(truth.end_to_end_cases(), 1);
        assert_eq!(case.expected, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(case.input["method"], json!("POST"));
        assert_eq!(case.input["headers"]["content-type"], json!("application/json"));
    }

    /// The whole point of the case is that the candidate has to *produce* the
    /// signature. Handing it the answer in its own input makes every candidate
    /// pass, including a one-line `return input.headers["x-signature"]`.
    #[test]
    fn the_field_under_test_is_stripped_from_its_own_input() {
        let requests = vec![request("r1", &[("x-signature", "d41d8cd98f00b204e980")])];
        let truth = collect(&[], &requests, &["x-signature".into()]);
        let case = &truth.cases[0];
        assert!(
            case.input["headers"].get("x-signature").is_none(),
            "the expected value must not be reachable from the input: {case:?}"
        );
    }

    #[test]
    fn values_too_short_to_be_meaningful_are_not_cases() {
        let requests = vec![request("r1", &[("x-signature", "ok")])];
        let truth = collect(&[], &requests, &["x-signature".into()]);
        assert!(truth.cases.is_empty(), "{truth:?}");
    }

    #[test]
    fn a_capture_with_nothing_to_compare_says_so() {
        let truth = collect(&[], &[], &[]);
        assert!(truth.is_empty());
        assert!(!truth.skipped.is_empty(), "an empty result must be explained");
    }

    #[test]
    fn hook_output_wrapped_in_an_object_is_still_paired() {
        let hooks = vec![hook(
            2,
            "crypto",
            "hmacSha256",
            json!({"data": "x"}),
            json!({"value": "aabbccddeeff0011"}),
        )];
        let truth = collect(&hooks, &[], &[]);
        assert_eq!(truth.cases.len(), 1, "{truth:?}");
        assert_eq!(truth.cases[0].expected, "aabbccddeeff0011");
    }

    #[test]
    fn non_crypto_hooks_are_not_treated_as_algorithm_evidence() {
        let hooks = vec![hook(
            3,
            "dom",
            "querySelector",
            json!({"selector": "#app"}),
            json!("<div id=app></div>"),
        )];
        let truth = collect(&hooks, &[], &[]);
        assert!(truth.cases.is_empty(), "{truth:?}");
    }
}
