//! Where a request's values came from.
//!
//! `endpoint_model` describes each endpoint on its own, which is enough to call
//! one and not enough to use an API: the token in every authorised request was
//! produced by an earlier response, and a client that cannot say which call
//! produces it can only ask the caller for a token it has no way to obtain.
//!
//! This walks the session in order, remembers the values each response emitted,
//! and reports where they turn up again. An edge is only recorded when the value
//! is distinctive enough that the match is unlikely to be coincidence — the
//! whole method rests on "this exact string appeared in both places", and a
//! short or common string makes that worthless.

use crate::endpoint_model::EndpointModel;
use crate::interchange::{BundleRequest, SessionBundle};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Below this length a match carries no information: `"1"` or `"true"` appears
/// in every session for reasons that have nothing to do with data flow.
const MIN_VALUE_LENGTH: usize = 8;
/// A value seen in this many distinct responses is ambient — a locale, a
/// version, a content type — not something one call produced for another.
const MAX_PRODUCERS: usize = 3;
const MAX_EDGES: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsumerSite {
    Header,
    Query,
    Path,
    Body,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowEdge {
    /// The operation whose response carried the value first.
    pub producer: String,
    /// JSON pointer into that response, e.g. `/data/token`.
    pub producer_pointer: String,
    pub consumer: String,
    pub site: ConsumerSite,
    /// Header name, query key, or body pointer — whichever `site` names.
    pub consumer_name: String,
    /// How many times this pairing was seen. One is a coincidence candidate.
    pub occurrences: usize,
    /// The value was carried inside a larger string, as `Bearer <token>` does.
    pub embedded: bool,
    /// What preceded the value in that larger string, so a generator can
    /// rebuild the header rather than sending a bare token where the capture
    /// showed `Bearer `. Empty when the value was the whole thing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// What followed it, for the same reason.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub suffix: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlow {
    pub edges: Vec<DataFlowEdge>,
    /// Consumers that need a credential no captured response produced. The SDK
    /// has to ask its caller for these; nothing in the capture can supply them.
    pub unsourced_credentials: Vec<String>,
}

/// Values worth tracking out of one response body.
fn emitted_values(body: &str) -> Vec<(String, String)> {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    collect(&value, String::new(), &mut found);
    found
}

fn collect(value: &Value, pointer: String, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(text) => {
            if is_distinctive(text) {
                out.push((pointer, text.clone()));
            }
        }
        Value::Object(fields) => {
            for (name, field) in fields {
                collect(field, format!("{pointer}/{name}"), out);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect(item, format!("{pointer}/{index}"), out);
            }
        }
        // Numbers are deliberately skipped. An id like 42 matches far too much
        // to be evidence of anything, and the ids that are distinctive enough
        // arrive as strings anyway.
        _ => {}
    }
}

/// A value whose reappearance elsewhere means something. Length is most of it,
/// but a long word is still a word: something has to vary within the string.
fn is_distinctive(value: &str) -> bool {
    if value.len() < MIN_VALUE_LENGTH || value.len() > 4096 {
        return false;
    }
    if value.contains(' ') {
        return false;
    }
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_alpha = value.chars().any(|c| c.is_ascii_alphabetic());
    let has_separator = value.chars().any(|c| matches!(c, '.' | '-' | '_' | '='));
    (has_digit && has_alpha) || (has_alpha && has_separator && value.len() >= 16)
}

fn query_pairs(query: Option<&str>) -> Vec<(String, String)> {
    query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name.to_string(), value.to_string())
        })
        .collect()
}

/// Which operation a request belongs to, by matching its path against the
/// templates the model produced.
fn operation_for(model: &EndpointModel, request: &BundleRequest) -> Option<String> {
    let request_segments: Vec<&str> = request
        .path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    model
        .endpoints
        .iter()
        .find(|endpoint| {
            if !endpoint.method.eq_ignore_ascii_case(&request.method) {
                return false;
            }
            let template_segments: Vec<&str> = endpoint
                .path_template
                .split('/')
                .filter(|part| !part.is_empty())
                .collect();
            template_segments.len() == request_segments.len()
                && template_segments.iter().zip(request_segments.iter()).all(
                    |(template, actual)| {
                        (template.starts_with('{') && template.ends_with('}')) || template == actual
                    },
                )
        })
        .map(|endpoint| endpoint.operation_id.clone())
}

pub fn build_dataflow(bundle: &SessionBundle, model: &EndpointModel) -> DataFlow {
    // value -> (first producing operation, pointer, how many operations produced it)
    let mut produced: BTreeMap<String, (String, String, usize)> = BTreeMap::new();
    #[allow(clippy::type_complexity)]
    let mut edges: BTreeMap<
        (String, String, String, ConsumerSite, String),
        (usize, bool, String, String),
    > = BTreeMap::new();

    let mut ordered: Vec<&BundleRequest> = bundle.requests.iter().collect();
    ordered.sort_by_key(|request| request.sequence);

    for request in ordered {
        let Some(consumer) = operation_for(model, request) else {
            continue;
        };

        // Consume before producing, so a response that echoes its own request
        // does not look like the source of it.
        let mut consider = |site: ConsumerSite, name: &str, text: &str| {
            if text.is_empty() {
                return;
            }
            for (value, (producer, pointer, producers)) in produced.iter() {
                if *producers > MAX_PRODUCERS || producer == &consumer {
                    continue;
                }
                let Some(offset) = text.find(value.as_str()) else {
                    continue;
                };
                let embedded = text != value;
                let prefix = text[..offset].to_string();
                let suffix = text[offset + value.len()..].to_string();
                let key = (
                    producer.clone(),
                    pointer.clone(),
                    consumer.clone(),
                    site,
                    name.to_string(),
                );
                let entry =
                    edges
                        .entry(key)
                        .or_insert((0, embedded, prefix.clone(), suffix.clone()));
                entry.0 += 1;
                entry.1 = entry.1 || embedded;
                // Keep the first wrapper seen; a later call framing the same
                // value differently is not a reason to rewrite the earlier one.
                if entry.2.is_empty() && entry.3.is_empty() {
                    entry.2 = prefix;
                    entry.3 = suffix;
                }
            }
        };

        for header in &request.request_headers {
            consider(
                ConsumerSite::Header,
                &header.name.to_ascii_lowercase(),
                &header.value,
            );
        }
        for (name, value) in query_pairs(request.query.as_deref()) {
            consider(ConsumerSite::Query, &name, &value);
        }
        for segment in request.path.split('/').filter(|part| !part.is_empty()) {
            consider(ConsumerSite::Path, segment, segment);
        }
        if let Some(body) = request.request_body.as_deref() {
            for (pointer, value) in emitted_values(body) {
                consider(ConsumerSite::Body, &pointer, &value);
            }
        }

        for (pointer, value) in emitted_values(&request.response_body) {
            produced
                .entry(value)
                .and_modify(|entry| entry.2 += 1)
                .or_insert((consumer.clone(), pointer, 1));
        }
    }

    let mut edges: Vec<DataFlowEdge> = edges
        .into_iter()
        .map(
            |(
                (producer, producer_pointer, consumer, site, consumer_name),
                (occurrences, embedded, prefix, suffix),
            )| {
                DataFlowEdge {
                    producer,
                    producer_pointer,
                    consumer,
                    site,
                    consumer_name,
                    occurrences,
                    embedded,
                    prefix,
                    suffix,
                }
            },
        )
        .collect();
    edges.sort_by(|left, right| {
        right
            .occurrences
            .cmp(&left.occurrences)
            .then(left.consumer.cmp(&right.consumer))
    });
    edges.truncate(MAX_EDGES);

    // Credentials with no producer: the capture shows they are needed and
    // shows nothing that makes them.
    let sourced: Vec<&DataFlowEdge> = edges
        .iter()
        .filter(|edge| edge.site == ConsumerSite::Header)
        .collect();
    let mut unsourced = Vec::new();
    for endpoint in &model.endpoints {
        for header in &endpoint.headers {
            if header.secret
                && header.required
                && !sourced.iter().any(|edge| edge.consumer_name == header.name)
                && !unsourced.contains(&header.name)
            {
                unsourced.push(header.name.clone());
            }
        }
    }

    DataFlow {
        edges,
        unsourced_credentials: unsourced,
    }
}

/// The single edge that explains a credential header, if one call clearly
/// produces it. Used by the SDK generator to build a login method rather than
/// asking the caller for a token they would have to obtain by hand.
pub fn credential_source<'a>(flow: &'a DataFlow, header: &str) -> Option<&'a DataFlowEdge> {
    flow.edges
        .iter()
        .filter(|edge| edge.site == ConsumerSite::Header && edge.consumer_name == header)
        .max_by_key(|edge| edge.occurrences)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint_model::build_endpoint_model;
    use crate::interchange::{BundleRequest, BundleSession, SessionBundle};
    use crate::models::{BodyCaptureMetadata, HeaderEntry};

    fn request(method: &str, path: &str) -> BundleRequest {
        BundleRequest {
            id: "id".into(),
            sequence: 1,
            source: "proxy".into(),
            source_instance_id: "instance".into(),
            started_at: 1,
            method: method.into(),
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: None,
            path: path.into(),
            query: None,
            status: 200,
            resource_type: "xhr".into(),
            size_bytes: 0,
            duration_ms: 1,
            protocol: "h2".into(),
            tls_version: "TLS1.3".into(),
            risk_level: "low".into(),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: String::new(),
            response_body_metadata: BodyCaptureMetadata::default(),
            crypto_snippets: Vec::new(),
            hook: None,
            tls_fingerprint: None,
            replayed_from_request_id: None,
        }
    }

    fn bundle(requests: Vec<BundleRequest>) -> SessionBundle {
        SessionBundle {
            format: crate::interchange::BUNDLE_FORMAT.into(),
            version: crate::interchange::BUNDLE_VERSION,
            exported_at: "2026-01-01T00:00:00Z".into(),
            session: BundleSession {
                name: "session".into(),
                created_at: 0,
            },
            requests: requests
                .into_iter()
                .enumerate()
                .map(|(index, mut request)| {
                    request.sequence = index as i64 + 1;
                    request.id = format!("request-{index}");
                    request
                })
                .collect(),
            events: Vec::new(),
            annotations: Vec::new(),
            rules: Vec::new(),
            rule_traces: Vec::new(),
        }
    }

    fn analyse(requests: Vec<BundleRequest>) -> (EndpointModel, DataFlow) {
        let bundle = bundle(requests);
        let model = build_endpoint_model(&bundle);
        let flow = build_dataflow(&bundle, &model);
        (model, flow)
    }

    const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.aGVsbG8.sig-9f2c";

    fn login() -> BundleRequest {
        let mut sample = request("POST", "/v1/auth/login");
        sample.response_body = format!(r#"{{"token":"{TOKEN}","expiresIn":3600}}"#);
        sample
    }

    fn authorised(path: &str) -> BundleRequest {
        let mut sample = request("GET", path);
        sample.request_headers = vec![HeaderEntry {
            name: "Authorization".into(),
            value: format!("Bearer {TOKEN}"),
        }];
        sample
    }

    #[test]
    fn a_token_from_a_login_response_is_traced_to_the_calls_that_use_it() {
        let (_, flow) = analyse(vec![
            login(),
            authorised("/v1/me"),
            authorised("/v1/orders"),
        ]);
        // One edge per consumer, so two calls using the same token are two
        // edges rather than one counted twice — the generator needs to know
        // which operations depend on the login, not only how often.
        let header_edges: Vec<&DataFlowEdge> = flow
            .edges
            .iter()
            .filter(|edge| edge.consumer_name == "authorization")
            .collect();
        assert_eq!(header_edges.len(), 2, "{header_edges:?}");
        assert!(header_edges
            .iter()
            .all(|edge| edge.producer == "postV1AuthLogin" && edge.producer_pointer == "/token"));
        assert!(
            header_edges.iter().all(|edge| edge.embedded),
            "the header carries it inside `Bearer <token>`, not as the whole value"
        );
        // The wrapper itself, so a generated client sends `Bearer <token>`
        // rather than a bare token the server would reject.
        assert!(header_edges.iter().all(|edge| edge.prefix == "Bearer "));
        assert!(header_edges.iter().all(|edge| edge.suffix.is_empty()));

        let source = credential_source(&flow, "authorization").expect("the token has a source");
        assert_eq!(source.producer, "postV1AuthLogin");
        assert!(flow.unsourced_credentials.is_empty());
    }

    #[test]
    fn a_credential_no_response_produced_is_reported_as_unsourced() {
        // The capture shows the header is required and shows nothing that makes
        // it. Saying so is the difference between an SDK that can log in and
        // one that asks for a token the caller has no way to obtain.
        let (_, flow) = analyse(vec![authorised("/v1/me"), authorised("/v1/orders")]);
        assert!(credential_source(&flow, "authorization").is_none());
        assert_eq!(
            flow.unsourced_credentials,
            vec!["authorization".to_string()]
        );
    }

    #[test]
    fn a_response_echoing_its_own_request_is_not_its_own_source() {
        let mut sample = request("POST", "/v1/echo");
        sample.request_body = Some(format!(r#"{{"value":"{TOKEN}"}}"#));
        sample.response_body = format!(r#"{{"value":"{TOKEN}"}}"#);
        let (_, flow) = analyse(vec![sample]);
        assert!(
            flow.edges.is_empty(),
            "an endpoint cannot be the source of its own input: {:?}",
            flow.edges
        );
    }

    #[test]
    fn short_and_common_values_are_not_evidence() {
        // "1" and "true" appear everywhere for unrelated reasons. Matching on
        // them would wire every endpoint to every other one.
        let mut first = request("POST", "/v1/flag");
        first.response_body = r#"{"ok":"true","count":"1","mode":"list"}"#.into();
        let mut second = request("GET", "/v1/items");
        second.query = Some("mode=list&debug=true".into());
        let (_, flow) = analyse(vec![first, second]);
        assert!(flow.edges.is_empty(), "{:?}", flow.edges);
    }

    #[test]
    fn a_value_many_responses_carry_is_ambient_not_a_dependency() {
        // A build id or a locale echoed by every endpoint is not one call
        // feeding another, and treating it as one buries the real edge.
        let ambient = "build-2026-08-08-a1b2";
        let mut requests = Vec::new();
        for index in 0..5 {
            let mut sample = request("GET", &format!("/v1/thing{index}"));
            sample.response_body = format!(r#"{{"build":"{ambient}"}}"#);
            requests.push(sample);
        }
        let mut consumer = request("GET", "/v1/report");
        consumer.query = Some(format!("build={ambient}"));
        requests.push(consumer);

        let (_, flow) = analyse(requests);
        assert!(
            flow.edges.is_empty(),
            "a value five responses carry is ambient: {:?}",
            flow.edges
        );
    }

    #[test]
    fn an_id_taken_from_a_listing_and_used_in_a_path_is_traced() {
        let mut listing = request("GET", "/v1/orders");
        listing.response_body = r#"{"items":[{"id":"ord-8f3a91c2"}]}"#.into();
        let detail = request("GET", "/v1/orders/ord-8f3a91c2");
        let (_, flow) = analyse(vec![listing, detail]);

        let edge = flow
            .edges
            .iter()
            .find(|edge| edge.site == ConsumerSite::Path)
            .expect("the path id has a source");
        assert_eq!(edge.producer, "getV1Orders");
        assert_eq!(edge.producer_pointer, "/items/0/id");
        assert!(!edge.embedded, "the segment is the value, not a wrapper");
    }

    #[test]
    fn a_value_used_in_a_later_request_body_is_traced() {
        let mut start = request("POST", "/v1/checkout/start");
        start.response_body = r#"{"sessionKey":"ck-77d21e0b9f"}"#.into();
        let mut confirm = request("POST", "/v1/checkout/confirm");
        confirm.request_body = Some(r#"{"sessionKey":"ck-77d21e0b9f"}"#.into());
        let (_, flow) = analyse(vec![start, confirm]);

        let edge = flow
            .edges
            .iter()
            .find(|edge| edge.site == ConsumerSite::Body)
            .expect("the body value has a source");
        assert_eq!(edge.producer, "postV1CheckoutStart");
        assert_eq!(edge.consumer, "postV1CheckoutConfirm");
        assert_eq!(edge.consumer_name, "/sessionKey");
    }

    #[test]
    fn order_decides_direction() {
        // The same two calls in the other order must not produce a backwards
        // edge: what was produced later cannot have fed what ran earlier.
        let mut producer = request("POST", "/v1/a");
        producer.response_body = format!(r#"{{"token":"{TOKEN}"}}"#);
        let consumer = authorised("/v1/b");

        let (_, forwards) = analyse(vec![producer.clone(), consumer.clone()]);
        assert_eq!(forwards.edges.len(), 1);

        let (_, backwards) = analyse(vec![consumer, producer]);
        assert!(
            backwards.edges.is_empty(),
            "a later response cannot be the source: {:?}",
            backwards.edges
        );
    }
}
