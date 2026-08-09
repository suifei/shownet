//! Turns a captured session into an API surface.
//!
//! The exports in `interchange.rs` describe requests: one OpenAPI path per
//! literal URL, so `/user/1` and `/user/2` are two endpoints and the second
//! request to either is dropped. An SDK needs the opposite — one endpoint per
//! operation, with the parameters that vary named, the fields that are always
//! present marked required, and the response shape merged across every sample.
//!
//! Two signals drive path templating, and they are not equally trustworthy:
//!
//! * A segment that **varies** across otherwise identical paths is a parameter.
//!   This is evidence, and needs at least two samples.
//! * A segment that merely **looks like** an identifier — all digits, a UUID, a
//!   long hex string — is a guess. `/archive/2024/index` reads as a year to a
//!   person and as an integer id here, and one capture cannot settle it. The
//!   guess is still made, because the alternative is worse: an id left literal
//!   gives the SDK one function per row.
//!
//! Endpoints record which of the two named each parameter, so a generator can
//! print the guesses as gaps rather than as API documentation.

use crate::interchange::{BundleRequest, SessionBundle};
use crate::models::HeaderEntry;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Distinct values kept per field before it stops being treated as an enum.
const MAX_ENUM_VALUES: usize = 12;
/// Literal paths retained per endpoint, so a 100k-request session cannot
/// produce a model larger than the capture it came from.
const MAX_SAMPLE_PATHS: usize = 8;

/// Headers that carry a credential. Their captured value is evidence that the
/// endpoint needs one, never a value to reuse: an SDK with a session's Bearer
/// token baked in is both broken on the next run and a leak in source control.
/// `auto_crawler` holds the same line for the clients it generates.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
];

fn is_credential_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    CREDENTIAL_HEADERS.contains(&lower.as_str())
        || lower.ends_with("-token")
        || lower.ends_with("-key")
        || lower.ends_with("-secret")
}

/// Headers every HTTP client sets on its own. Carrying them into an SDK would
/// hard-code one capture's browser into every future request.
const UNINTERESTING_HEADERS: &[&str] = &[
    "accept",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "host",
    "pragma",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "upgrade-insecure-requests",
    "user-agent",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParamEvidence {
    /// The segment was seen taking more than one value. Evidence.
    Observed,
    /// One sample, and the segment looks like an identifier. A guess.
    ShapeOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathParam {
    pub name: String,
    /// Index into the path's `/`-separated segments.
    pub segment: usize,
    pub kind: String,
    pub evidence: ParamEvidence,
    pub examples: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldModel {
    pub name: String,
    /// Present in every sample of this endpoint.
    pub required: bool,
    pub kind: String,
    /// Populated only when the field took a small, stable set of values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<String>,
    /// Held constant across every sample — a candidate for an SDK default.
    /// Never set for a credential: one capture's token is not a default.
    pub constant: bool,
    /// The caller has to supply this. Its captured value is deliberately absent.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub secret: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyModel {
    pub content_type: String,
    /// A JSON-Schema-shaped description, or null when the body was not
    /// structured data this can describe.
    pub schema: Value,
    pub sample_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseModel {
    pub status: i64,
    pub content_type: String,
    pub schema: Value,
    pub sample_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub operation_id: String,
    pub method: String,
    pub server: String,
    pub path_template: String,
    pub sample_count: usize,
    pub path_params: Vec<PathParam>,
    pub query_params: Vec<FieldModel>,
    pub headers: Vec<FieldModel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<BodyModel>,
    pub responses: Vec<ResponseModel>,
    pub sample_paths: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GapKind {
    /// A path parameter named from one sample's shape, not from variation.
    GuessedPathParam,
    /// A field whose type differed between samples.
    ConflictingFieldType,
    /// A body this cannot describe as a schema.
    OpaqueBody,
    /// Only one sample, so nothing about it is known to be required or optional.
    SingleSample,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    pub kind: GapKind,
    pub operation_id: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointModel {
    pub session_id: String,
    pub servers: Vec<String>,
    pub endpoints: Vec<Endpoint>,
    /// Everything the model could not establish, for a generator to print
    /// rather than to paper over.
    pub gaps: Vec<Gap>,
    pub request_count: usize,
    pub skipped_count: usize,
}

/// Static assets a browser fetches to render the page. A real capture is
/// mostly these — one session of a marketing homepage produced thirty methods
/// named after JS bundles — and an SDK with a function per script tag buries
/// the handful of calls that are the API.
const ASSET_EXTENSIONS: &[&str] = &[
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif",
    ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".pdf",
];

fn is_static_asset(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let tail = lower.rsplit('/').next().unwrap_or(&lower);
    ASSET_EXTENSIONS
        .iter()
        .any(|extension| tail.ends_with(extension))
}

/// A request that carries no API surface: tunnels, the streaming records whose
/// "response" is a frame log rather than a body, and static assets.
fn is_api_request(request: &BundleRequest) -> bool {
    request.method != "CONNECT"
        && !matches!(
            request.resource_type.as_str(),
            "websocket" | "sse" | "eventsource"
        )
        && !is_static_asset(&request.path)
}

fn authority(request: &BundleRequest) -> String {
    match request.port {
        Some(port)
            if !(request.scheme == "https" && port == 443)
                && !(request.scheme == "http" && port == 80) =>
        {
            format!("{}:{}", request.host, port)
        }
        _ => request.host.clone(),
    }
}

fn origin(request: &BundleRequest) -> String {
    format!("{}://{}", request.scheme, authority(request))
}

fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|part| !part.is_empty()).collect()
}

fn is_uuid(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(parts.iter())
            .all(|(expected, part)| {
                part.len() == *expected && part.chars().all(|c| c.is_ascii_hexdigit())
            })
}

/// The shape of a single path segment, when nothing but the segment is known.
/// Word-shaped segments stay literal — `v1` and `users` are part of the route,
/// and promoting them would merge endpoints that differ. Only the shapes a
/// human would also read as an identifier become parameters.
fn identifier_shape(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return None;
    }
    if is_uuid(value) {
        return Some("uuid");
    }
    if value.chars().all(|c| c.is_ascii_digit()) {
        // Including four digits, which reads as a year. Excluding them was
        // tried and is the worse trade: a year in a path is a parameter too
        // (`/archive/2024` and `/archive/2023` are one endpoint), so treating
        // it as one is at worst badly named. Leaving numeric ids literal makes
        // every id its own endpoint, which is an SDK with a function per row.
        return Some("integer");
    }
    if value.len() >= 16 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("hex");
    }
    if value.len() >= 20
        && value.chars().all(is_token_char)
        && value.chars().any(|c| c.is_ascii_digit())
    {
        return Some("token");
    }
    // Charset-independent backstop. The rule above guesses at an alphabet, and
    // guessing wrong costs an endpoint per request: a Cloudflare challenge token
    // carries dots, missed the alphabet by one character, and 917 literal
    // characters became a route — one method per request, each named after the
    // token, in a client that reached 978 KB and 444 "endpoints" of which 30
    // were real. Whatever the alphabet, a segment this long is not a route name;
    // the longest in any real API is a couple of dozen characters.
    if value.len() > MAX_ROUTE_SEGMENT_CHARS {
        return Some("token");
    }
    None
}

/// Characters a token-shaped segment may contain. Beyond alphanumerics: `-`,
/// `_` and `=` for base64url and its padding, `.` because JWTs and Cloudflare's
/// challenge tokens separate their parts with it, and `~` which is unreserved in
/// RFC 3986 and appears in signed URLs.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '=' | '.' | '~')
}

/// Above this, a path segment is opaque data rather than a name someone chose.
const MAX_ROUTE_SEGMENT_CHARS: usize = 48;

/// The route a path belongs to, with identifier-shaped segments blanked out.
/// Requests are grouped by this before anything else, so `/api/v1/users/1001`
/// and `/api/v1/class/2fa` never meet: they are different routes that merely
/// happen to have the same segment count, and grouping on the count alone
/// produced one method taking a `v1_id` that meant nothing.
///
/// Grouping first also keeps one route's values out of another's: with the two
/// mixed, the third position holds {1001, 1002, 2fa} and stops looking like an
/// identifier at all, so even the real parameter would be lost.
fn route_signature(path: &str) -> String {
    let mut signature = String::new();
    for segment in segments(path) {
        signature.push('/');
        if identifier_shape(segment).is_some() {
            signature.push_str("{}");
        } else {
            signature.push_str(segment);
        }
    }
    if signature.is_empty() {
        signature.push('/');
    }
    signature
}

/// `users` -> `user`, so `/users/{id}` reads as `{userId}` rather than
/// `{usersId}`. Only the plain trailing `s`; anything cleverer would need a
/// word list this has no business carrying.
fn singular(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if lower.len() > 3 && lower.ends_with('s') && !lower.ends_with("ss") {
        lower[..lower.len() - 1].to_string()
    } else {
        lower
    }
}

fn camel(value: &str) -> String {
    let mut out = String::new();
    let mut upper_next = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if upper_next {
                out.extend(character.to_uppercase());
                upper_next = false;
            } else {
                out.push(character.to_ascii_lowercase());
            }
        } else {
            upper_next = !out.is_empty();
        }
    }
    out
}

fn param_name(previous: Option<&str>, index: usize, taken: &BTreeSet<String>) -> String {
    let base = match previous {
        Some(word) if word.chars().any(|c| c.is_ascii_alphabetic()) => {
            format!("{}Id", camel(&singular(word)))
        }
        _ => format!("param{index}"),
    };
    if !taken.contains(&base) {
        return base;
    }
    let mut suffix = 2;
    loop {
        let candidate = format!("{base}{suffix}");
        if !taken.contains(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn value_kind(value: &str) -> &'static str {
    if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false") {
        "boolean"
    } else if !value.is_empty() && value.parse::<i64>().is_ok() {
        "integer"
    } else if !value.is_empty() && value.parse::<f64>().is_ok() {
        "number"
    } else {
        "string"
    }
}

fn header_value<'a>(headers: &'a [HeaderEntry], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn content_type_of(headers: &[HeaderEntry]) -> String {
    header_value(headers, "content-type")
        .map(|value| value.split(';').next().unwrap_or(value).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "application/octet-stream".to_string())
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

/// Accumulates the values one named field took across every sample.
#[derive(Default)]
struct FieldAccumulator {
    seen_in: usize,
    values: BTreeSet<String>,
    kinds: BTreeSet<&'static str>,
    overflowed: bool,
}

impl FieldAccumulator {
    fn observe(&mut self, value: &str) {
        self.seen_in += 1;
        self.kinds.insert(value_kind(value));
        if self.values.len() < MAX_ENUM_VALUES {
            self.values.insert(value.to_string());
        } else if !self.values.contains(value) {
            self.overflowed = true;
        }
    }

    fn finish(&self, name: &str, total: usize, secret: bool) -> FieldModel {
        let kind = if self.kinds.len() == 1 {
            self.kinds.iter().next().copied().unwrap_or("string")
        } else if self.kinds.contains("string") {
            "string"
        } else {
            "number"
        };
        // An enum needs a value to have been seen more than once. `page=1` then
        // `page=2` is two distinct values across two samples with no repetition
        // — a free parameter, not a closed set, and typing it as
        // Literal["1","2"] would make the SDK reject page 3. Numbers are
        // excluded outright for the same reason.
        let repeated = self.values.len() < self.seen_in;
        let enum_values =
            if !self.overflowed && kind == "string" && repeated && self.values.len() > 1 {
                self.values.iter().cloned().collect()
            } else {
                Vec::new()
            };
        // A credential that never changed within one capture is still not a
        // constant: it is one session's token.
        let constant =
            !secret && !self.overflowed && self.values.len() == 1 && self.seen_in == total;
        FieldModel {
            name: name.to_string(),
            required: self.seen_in == total,
            kind: kind.to_string(),
            enum_values: if secret { Vec::new() } else { enum_values },
            constant,
            secret,
            example: if secret {
                None
            } else {
                self.values.iter().next().cloned()
            },
        }
    }
}

/// Merges JSON values into one schema. Two samples disagreeing on a field's
/// type collapse to a schema with no `type`, and the caller records a gap —
/// picking one of the two would be inventing an API contract.
fn merge_schema(
    left: Option<Value>,
    right: &Value,
    conflicts: &mut Vec<String>,
    path: &str,
) -> Value {
    let described = describe(right, path, conflicts);
    match left {
        None => described,
        Some(existing) => union_schema(existing, described, conflicts, path),
    }
}

fn describe(value: &Value, path: &str, conflicts: &mut Vec<String>) -> Value {
    match value {
        Value::Null => serde_json::json!({ "type": "null" }),
        Value::Bool(_) => serde_json::json!({ "type": "boolean" }),
        Value::Number(number) => {
            serde_json::json!({ "type": if number.is_i64() || number.is_u64() { "integer" } else { "number" } })
        }
        Value::String(_) => serde_json::json!({ "type": "string" }),
        Value::Array(items) => {
            let mut merged: Option<Value> = None;
            for item in items {
                let item_path = format!("{path}[]");
                merged = Some(merge_schema(merged, item, conflicts, &item_path));
            }
            serde_json::json!({
                "type": "array",
                "items": merged.unwrap_or_else(|| serde_json::json!({})),
            })
        }
        Value::Object(fields) => {
            let mut properties = Map::new();
            let mut required = Vec::new();
            for (name, field) in fields {
                let field_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                properties.insert(name.clone(), describe(field, &field_path, conflicts));
                required.push(Value::String(name.clone()));
            }
            serde_json::json!({
                "type": "object",
                "properties": properties,
                "required": required,
            })
        }
    }
}

fn union_schema(left: Value, right: Value, conflicts: &mut Vec<String>, path: &str) -> Value {
    let left_type = left.get("type").and_then(Value::as_str).map(str::to_string);
    let right_type = right
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_string);

    if left_type == right_type {
        return match left_type.as_deref() {
            Some("object") => union_objects(left, right, conflicts, path),
            Some("array") => {
                let items = union_schema(
                    left.get("items")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({})),
                    right
                        .get("items")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({})),
                    conflicts,
                    &format!("{path}[]"),
                );
                serde_json::json!({ "type": "array", "items": items })
            }
            _ => left,
        };
    }

    // A field that is null in one sample and a string in another is optional,
    // not conflicting — that is the ordinary shape of a nullable field.
    match (left_type.as_deref(), right_type.as_deref()) {
        (Some("null"), Some(other)) | (Some(other), Some("null")) => {
            serde_json::json!({ "type": [other, "null"] })
        }
        (Some("integer"), Some("number")) | (Some("number"), Some("integer")) => {
            serde_json::json!({ "type": "number" })
        }
        (Some(one), Some(two)) => {
            conflicts.push(format!(
                "{}: {} in one sample, {} in another",
                if path.is_empty() { "(root)" } else { path },
                one,
                two
            ));
            serde_json::json!({ "x-shownet-conflict": [one, two] })
        }
        _ => left,
    }
}

fn union_objects(left: Value, right: Value, conflicts: &mut Vec<String>, path: &str) -> Value {
    let mut properties = left
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let right_properties = right
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    for (name, schema) in right_properties.iter() {
        let field_path = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}.{name}")
        };
        let merged = match properties.get(name) {
            Some(existing) => {
                union_schema(existing.clone(), schema.clone(), conflicts, &field_path)
            }
            None => schema.clone(),
        };
        properties.insert(name.clone(), merged);
    }

    // Required only where both samples carried it.
    let required_left: BTreeSet<String> = left
        .get("required")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let required_right: BTreeSet<String> = right
        .get("required")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let required: Vec<Value> = required_left
        .intersection(&required_right)
        .map(|name| Value::String(name.clone()))
        .collect();

    serde_json::json!({ "type": "object", "properties": properties, "required": required })
}

/// One group of requests that share an origin, a method and a segment count —
/// the candidates for being the same operation.
struct Group<'a> {
    server: String,
    method: String,
    requests: Vec<&'a BundleRequest>,
}

pub fn build_endpoint_model(bundle: &SessionBundle) -> EndpointModel {
    let mut groups: BTreeMap<(String, String, String), Group<'_>> = BTreeMap::new();
    let mut skipped = 0usize;

    for request in &bundle.requests {
        if !is_api_request(request) {
            skipped += 1;
            continue;
        }
        let server = origin(request);
        let method = request.method.to_ascii_uppercase();
        let route = route_signature(&request.path);
        groups
            .entry((server.clone(), method.clone(), route))
            .or_insert_with(|| Group {
                server,
                method,
                requests: Vec::new(),
            })
            .requests
            .push(request);
    }

    let mut endpoints = Vec::new();
    let mut gaps = Vec::new();
    let mut servers = BTreeSet::new();

    for group in groups.into_values() {
        servers.insert(group.server.clone());
        for endpoint in endpoints_from_group(&group, &mut gaps) {
            endpoints.push(endpoint);
        }
    }

    endpoints.sort_by(|left, right| {
        left.path_template
            .cmp(&right.path_template)
            .then(left.method.cmp(&right.method))
    });

    EndpointModel {
        session_id: bundle
            .requests
            .first()
            .map(|_| bundle.session.name.clone())
            .unwrap_or_default(),
        servers: servers.into_iter().collect(),
        endpoints,
        gaps,
        request_count: bundle.requests.len(),
        skipped_count: skipped,
    }
}

fn endpoints_from_group(group: &Group<'_>, gaps: &mut Vec<Gap>) -> Vec<Endpoint> {
    let paths: Vec<Vec<String>> = group
        .requests
        .iter()
        .map(|request| {
            segments(&request.path)
                .into_iter()
                .map(str::to_string)
                .collect()
        })
        .collect();
    let Some(width) = paths.first().map(Vec::len) else {
        return Vec::new();
    };

    // Which positions vary across the group. With one request nothing varies,
    // and the shape heuristic below is all there is.
    let mut varying = vec![false; width];
    for index in 0..width {
        let first = paths[0].get(index);
        if paths.iter().any(|segments| segments.get(index) != first) {
            varying[index] = true;
        }
    }

    let mut template = String::new();
    let mut path_params: Vec<PathParam> = Vec::new();
    let mut taken = BTreeSet::new();
    for index in 0..width {
        let values: BTreeSet<&str> = paths
            .iter()
            .filter_map(|segments| segments.get(index).map(String::as_str))
            .collect();
        let representative = paths[0].get(index).map(String::as_str).unwrap_or_default();
        let shape = identifier_shape(representative);
        // The shape alone decides, because route_signature already grouped on
        // it: within a group a literal position holds one repeated value and a
        // blanked position holds identifier-shaped ones. Adding `varying[index]`
        // here was tried and is dead — every position it would catch already
        // has a shape. It still decides the evidence below, which is a
        // different question: whether the parameter was confirmed or guessed.
        let is_param = shape.is_some();
        if is_param {
            let previous = (index > 0).then(|| paths[0][index - 1].as_str());
            let name = param_name(previous, index, &taken);
            taken.insert(name.clone());
            let evidence = if varying[index] {
                ParamEvidence::Observed
            } else {
                ParamEvidence::ShapeOnly
            };
            let kind = shape
                .or_else(|| {
                    values
                        .iter()
                        .all(|value| value.chars().all(|c| c.is_ascii_digit()))
                        .then_some("integer")
                })
                .unwrap_or("string");
            template.push('/');
            template.push('{');
            template.push_str(&name);
            template.push('}');
            path_params.push(PathParam {
                name,
                segment: index,
                kind: kind.to_string(),
                evidence,
                examples: values
                    .iter()
                    .take(3)
                    .map(|value| value.to_string())
                    .collect(),
            });
        } else {
            template.push('/');
            template.push_str(representative);
        }
    }
    if template.is_empty() {
        template.push('/');
    }

    let operation_id = operation_id_for(&group.method, &template);

    for param in &path_params {
        if param.evidence == ParamEvidence::ShapeOnly {
            gaps.push(Gap {
                kind: GapKind::GuessedPathParam,
                operation_id: operation_id.clone(),
                detail: format!(
                    "{{{}}} was named from one sample ({}); a second capture of this endpoint would confirm or refute it",
                    param.name,
                    param.examples.first().map(String::as_str).unwrap_or("")
                ),
            });
        }
    }

    let total = group.requests.len();
    if total == 1 {
        gaps.push(Gap {
            kind: GapKind::SingleSample,
            operation_id: operation_id.clone(),
            detail:
                "one sample only: every field is reported required and every value looks constant"
                    .to_string(),
        });
    }

    let mut query_fields: BTreeMap<String, FieldAccumulator> = BTreeMap::new();
    let mut header_fields: BTreeMap<String, FieldAccumulator> = BTreeMap::new();
    let mut request_schema: Option<Value> = None;
    let mut request_samples = 0usize;
    let mut request_content = String::new();
    let mut opaque_request = false;
    let mut conflicts: Vec<String> = Vec::new();
    let mut responses: BTreeMap<(i64, String), (Option<Value>, usize)> = BTreeMap::new();

    for request in &group.requests {
        for (name, value) in query_pairs(request.query.as_deref()) {
            query_fields.entry(name).or_default().observe(&value);
        }
        for header in &request.request_headers {
            let lower = header.name.to_ascii_lowercase();
            if UNINTERESTING_HEADERS.contains(&lower.as_str()) {
                continue;
            }
            header_fields
                .entry(lower)
                .or_default()
                .observe(&header.value);
        }
        if let Some(body) = request
            .request_body
            .as_deref()
            .filter(|body| !body.trim().is_empty())
        {
            request_samples += 1;
            if request_content.is_empty() {
                request_content = content_type_of(&request.request_headers);
            }
            match serde_json::from_str::<Value>(body) {
                Ok(value) => {
                    request_schema = Some(merge_schema(
                        request_schema.take(),
                        &value,
                        &mut conflicts,
                        "",
                    ))
                }
                Err(_) => opaque_request = true,
            }
        }

        let response_content = content_type_of(&request.response_headers);
        let entry = responses
            .entry((request.status, response_content))
            .or_insert((None, 0));
        entry.1 += 1;
        if !request.response_body.trim().is_empty() {
            if let Ok(value) = serde_json::from_str::<Value>(&request.response_body) {
                entry.0 = Some(merge_schema(entry.0.take(), &value, &mut conflicts, ""));
            }
        }
    }

    for conflict in conflicts {
        gaps.push(Gap {
            kind: GapKind::ConflictingFieldType,
            operation_id: operation_id.clone(),
            detail: conflict,
        });
    }
    if opaque_request {
        gaps.push(Gap {
            kind: GapKind::OpaqueBody,
            operation_id: operation_id.clone(),
            detail: format!(
                "request body is {request_content}, which this does not describe as a schema"
            ),
        });
    }

    let endpoint = Endpoint {
        operation_id,
        method: group.method.clone(),
        server: group.server.clone(),
        path_template: template,
        sample_count: total,
        path_params,
        query_params: query_fields
            .iter()
            .map(|(name, accumulator)| accumulator.finish(name, total, is_credential_header(name)))
            .collect(),
        headers: header_fields
            .iter()
            .map(|(name, accumulator)| accumulator.finish(name, total, is_credential_header(name)))
            .collect(),
        request_body: request_schema.map(|schema| BodyModel {
            content_type: request_content.clone(),
            schema,
            sample_count: request_samples,
        }),
        responses: responses
            .into_iter()
            .map(|((status, content_type), (schema, count))| ResponseModel {
                status,
                content_type,
                schema: schema.unwrap_or(Value::Null),
                sample_count: count,
            })
            .collect(),
        sample_paths: group
            .requests
            .iter()
            .take(MAX_SAMPLE_PATHS)
            .map(|request| request.path.clone())
            .collect(),
    };

    vec![endpoint]
}

fn operation_id_for(method: &str, template: &str) -> String {
    // Lowercased rather than matched against a fixed list, so a method this
    // does not know about still produces a usable name instead of a panic or a
    // leaked static.
    let verb = camel(&method.to_ascii_lowercase());
    let mut name = verb.clone();
    for segment in template.split('/').filter(|part| !part.is_empty()) {
        let is_param = segment.starts_with('{') && segment.ends_with('}');
        let cleaned = segment.trim_matches(|c| c == '{' || c == '}');
        // A parameter is already camelCase from param_name; running it through
        // camel() again would flatten userId to userid.
        let camel_case = if is_param {
            cleaned.to_string()
        } else {
            camel(cleaned)
        };
        if camel_case.is_empty() {
            continue;
        }
        let mut characters = camel_case.chars();
        if let Some(first) = characters.next() {
            name.extend(first.to_uppercase());
            name.push_str(characters.as_str());
        }
    }
    if name == verb {
        name.push_str("Root");
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interchange::{BundleRequest, BundleSession, SessionBundle};
    use crate::models::BodyCaptureMetadata;

    fn request(method: &str, path: &str) -> BundleRequest {
        BundleRequest {
            id: format!("{method}-{path}"),
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
        let requests = requests
            .into_iter()
            .enumerate()
            .map(|(index, mut request)| {
                request.sequence = index as i64 + 1;
                request.id = format!("request-{index}");
                request
            })
            .collect();
        SessionBundle {
            format: crate::interchange::BUNDLE_FORMAT.into(),
            version: crate::interchange::BUNDLE_VERSION,
            exported_at: "2026-01-01T00:00:00Z".into(),
            session: BundleSession {
                name: "session".into(),
                created_at: 0,
            },
            requests,
            events: Vec::new(),
            annotations: Vec::new(),
            rules: Vec::new(),
            rule_traces: Vec::new(),
        }
    }

    #[test]
    fn collapses_paths_that_differ_only_in_an_id() {
        let model = build_endpoint_model(&bundle(vec![
            request("GET", "/v1/users/1001"),
            request("GET", "/v1/users/1002"),
            request("GET", "/v1/users/1003"),
        ]));

        assert_eq!(model.endpoints.len(), 1, "three ids are one endpoint");
        let endpoint = &model.endpoints[0];
        assert_eq!(endpoint.path_template, "/v1/users/{userId}");
        assert_eq!(endpoint.operation_id, "getV1UsersUserId");
        assert_eq!(endpoint.sample_count, 3);
        assert_eq!(endpoint.path_params.len(), 1);
        assert_eq!(endpoint.path_params[0].evidence, ParamEvidence::Observed);
        assert_eq!(endpoint.path_params[0].kind, "integer");
        // Nothing guessed, so nothing to warn about.
        assert!(
            !model
                .gaps
                .iter()
                .any(|gap| gap.kind == GapKind::GuessedPathParam),
            "{:?}",
            model.gaps
        );
    }

    #[test]
    fn a_single_sample_is_a_guess_and_says_so() {
        let model = build_endpoint_model(&bundle(vec![request("GET", "/v1/users/1001")]));
        let endpoint = &model.endpoints[0];
        assert_eq!(endpoint.path_template, "/v1/users/{userId}");
        assert_eq!(endpoint.path_params[0].evidence, ParamEvidence::ShapeOnly);
        assert!(model
            .gaps
            .iter()
            .any(|gap| gap.kind == GapKind::GuessedPathParam));
        assert!(model
            .gaps
            .iter()
            .any(|gap| gap.kind == GapKind::SingleSample));
    }

    #[test]
    fn keeps_word_segments_literal_but_templates_numeric_ones() {
        // v1 carries a letter, so no shape matches and it stays literal — the
        // case that matters, since templating it would merge every API version
        // into one endpoint. The year does become a parameter: see
        // identifier_shape for why that trade runs this way.
        let model = build_endpoint_model(&bundle(vec![request("GET", "/v1/archive/2024/index")]));
        let endpoint = &model.endpoints[0];
        assert_eq!(endpoint.path_template, "/v1/archive/{archiveId}/index");
        assert!(
            endpoint.path_template.starts_with("/v1/"),
            "version stays literal"
        );
        assert_eq!(endpoint.path_params.len(), 1);
        assert_eq!(endpoint.path_params[0].evidence, ParamEvidence::ShapeOnly);
    }

    #[test]
    fn two_routes_of_the_same_shape_do_not_merge() {
        // Found by reading a generated SDK, not by a failing test. Grouping on
        // segment count alone put /api/v1/users/1001 and /api/v1/class/2fa in
        // one group, so the third position "varied" and became a parameter:
        // one method named for a route nobody has, taking a v1Id that means
        // nothing. Word-shaped segments are the route.
        let model = build_endpoint_model(&bundle(vec![
            request("GET", "/api/v1/users/1001"),
            request("GET", "/api/v1/users/1002"),
            request("GET", "/api/v1/class/2fa"),
        ]));

        let templates: Vec<&str> = model
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path_template.as_str())
            .collect();
        assert_eq!(
            templates,
            vec!["/api/v1/class/2fa", "/api/v1/users/{userId}"],
            "the two routes stay apart and the real id still templates"
        );

        let users = model
            .endpoints
            .iter()
            .find(|endpoint| endpoint.path_template.contains("userId"))
            .expect("the users endpoint");
        assert_eq!(users.sample_count, 2, "both user requests land on it");
        assert_eq!(users.path_params[0].evidence, ParamEvidence::Observed);
    }

    #[test]
    fn one_routes_values_do_not_poison_another() {
        // The reason routes are separated before parameters are named: mixed
        // together, the third position holds {1001, 1002, 2fa}, which is not
        // uniformly identifier-shaped, and the genuine parameter would be lost
        // along with the bogus one.
        let model = build_endpoint_model(&bundle(vec![
            request("GET", "/api/v1/users/1001"),
            request("GET", "/api/v1/class/2fa"),
        ]));
        assert!(
            model
                .endpoints
                .iter()
                .any(|endpoint| endpoint.path_template == "/api/v1/users/{userId}"),
            "{:?}",
            model
                .endpoints
                .iter()
                .map(|endpoint| &endpoint.path_template)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn different_methods_on_one_path_are_different_endpoints() {
        let model = build_endpoint_model(&bundle(vec![
            request("GET", "/v1/items"),
            request("POST", "/v1/items"),
        ]));
        assert_eq!(model.endpoints.len(), 2);
        let ids: Vec<&str> = model
            .endpoints
            .iter()
            .map(|endpoint| endpoint.operation_id.as_str())
            .collect();
        assert!(ids.contains(&"getV1Items"), "{ids:?}");
        assert!(ids.contains(&"postV1Items"), "{ids:?}");
    }

    #[test]
    fn required_means_present_in_every_sample() {
        let mut first = request("GET", "/v1/search");
        first.query = Some("q=shoes&page=1".into());
        let mut second = request("GET", "/v1/search");
        second.query = Some("q=hats".into());

        let model = build_endpoint_model(&bundle(vec![first, second]));
        let endpoint = &model.endpoints[0];
        let field = |name: &str| {
            endpoint
                .query_params
                .iter()
                .find(|field| field.name == name)
                .unwrap_or_else(|| panic!("missing {name}"))
        };
        assert!(field("q").required, "q is in both samples");
        assert!(!field("page").required, "page is in one of two samples");
    }

    #[test]
    fn merges_response_schemas_and_keeps_optional_fields_optional() {
        let mut first = request("GET", "/v1/profile");
        first.response_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: "application/json".into(),
        }];
        first.response_body = r#"{"id":1,"name":"a","nickname":"n"}"#.into();
        let mut second = request("GET", "/v1/profile");
        second.response_headers = first.response_headers.clone();
        second.response_body = r#"{"id":2,"name":"b"}"#.into();

        let model = build_endpoint_model(&bundle(vec![first, second]));
        let response = &model.endpoints[0].responses[0];
        assert_eq!(response.sample_count, 2);
        let required: Vec<&str> = response.schema["required"]
            .as_array()
            .expect("required list")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(required.contains(&"id"));
        assert!(required.contains(&"name"));
        assert!(
            !required.contains(&"nickname"),
            "a field missing from one sample is not required"
        );
        assert_eq!(response.schema["properties"]["id"]["type"], "integer");
    }

    #[test]
    fn a_field_that_changes_type_is_a_gap_not_a_guess() {
        let mut first = request("GET", "/v1/thing");
        first.response_body = r#"{"value":1}"#.into();
        let mut second = request("GET", "/v1/thing");
        second.response_body = r#"{"value":"one"}"#.into();

        let model = build_endpoint_model(&bundle(vec![first, second]));
        let conflict = model
            .gaps
            .iter()
            .find(|gap| gap.kind == GapKind::ConflictingFieldType)
            .expect("a type conflict must be reported");
        assert!(conflict.detail.contains("value"), "{}", conflict.detail);
        // And the schema must not pick a side.
        let property = &model.endpoints[0].responses[0].schema["properties"]["value"];
        assert!(property.get("type").is_none(), "{property}");
    }

    #[test]
    fn null_in_one_sample_is_nullable_not_conflicting() {
        let mut first = request("GET", "/v1/thing");
        first.response_body = r#"{"value":"a"}"#.into();
        let mut second = request("GET", "/v1/thing");
        second.response_body = r#"{"value":null}"#.into();

        let model = build_endpoint_model(&bundle(vec![first, second]));
        assert!(
            !model
                .gaps
                .iter()
                .any(|gap| gap.kind == GapKind::ConflictingFieldType),
            "nullable is not a conflict: {:?}",
            model.gaps
        );
        let property = &model.endpoints[0].responses[0].schema["properties"]["value"];
        assert_eq!(property["type"], serde_json::json!(["string", "null"]));
    }

    #[test]
    /// A token the alphabet rule does not recognise still must not become a
    /// route. Measured on a real capture: Cloudflare's challenge tokens carry
    /// dots, fell outside the allowed characters, and each one became its own
    /// endpoint — 444 "endpoints" of which 30 were real, in a 978 KB client
    /// whose method names were the tokens themselves.
    #[test]
    fn an_opaque_path_segment_never_becomes_a_route() {
        // The exact shape that produced the blowup: base64url with dots.
        let cloudflare = "S5ZtxHBW6DikjeX1Gz.dLaMoxlkk1LoK1p08OEfLqHE-1786208700-1.3.1.1-qxrtT_I3JiBSqsDnrhsRlR2X43MOfb1l";
        assert_eq!(super::identifier_shape(cloudflare), Some("token"));

        // A JWT-ish segment, dots and all.
        assert_eq!(
            super::identifier_shape(
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP"
            ),
            Some("token")
        );

        // The backstop must catch what neither earlier rule can: no digits, and
        // characters outside the token alphabet. Length alone decides.
        let outside_alphabet = "zq%!".repeat(super::MAX_ROUTE_SEGMENT_CHARS / 4 + 1);
        assert!(outside_alphabet.len() > super::MAX_ROUTE_SEGMENT_CHARS);
        assert_eq!(super::identifier_shape(&outside_alphabet), Some("token"));

        // And two different tokens must land on one route, which is the point.
        assert_eq!(
            super::route_signature(&format!("/cdn-cgi/challenge-platform/h/b/ci/{cloudflare}")),
            super::route_signature("/cdn-cgi/challenge-platform/h/b/ci/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP")
        );
    }

    /// The backstop must not swallow names people actually chose, or every long
    /// route collapses into one method and the SDK loses endpoints instead.
    #[test]
    fn ordinary_route_names_stay_literal() {
        for name in [
            "challenge-platform",
            "flightrr_api",
            "available-dates",
            "recent_search",
            "api",
            "v1",
            "well-known",
            "authorization-server-metadata",
        ] {
            assert_eq!(
                super::identifier_shape(name),
                None,
                "{name} is a route name, not an identifier"
            );
        }
    }

    fn a_paging_parameter_is_not_an_enum() {
        // Found by reading a dumped model, not by a failing assertion: page=1
        // then page=2 was being reported as enum ["1","2"], which becomes
        // Literal["1","2"] in a generated client and rejects page 3. Numeric
        // fields are what this case pins; the repetition rule that covers
        // string fields is pinned by a_free_text_parameter_is_not_an_enum.
        let mut first = request("GET", "/v1/orders");
        first.query = Some("page=1&status=paid".into());
        let mut second = request("GET", "/v1/orders");
        second.query = Some("page=2&status=paid".into());

        let model = build_endpoint_model(&bundle(vec![first, second]));
        let field = |name: &str| {
            model.endpoints[0]
                .query_params
                .iter()
                .find(|field| field.name == name)
                .unwrap_or_else(|| panic!("missing {name}"))
        };
        assert!(
            field("page").enum_values.is_empty(),
            "two values across two samples show no repetition: {:?}",
            field("page").enum_values
        );
        // The one that really is fixed reads as constant instead.
        assert!(field("status").constant);
    }

    #[test]
    fn a_free_text_parameter_is_not_an_enum() {
        // The case that actually needs the repetition rule. Two searches for
        // two different words are two distinct string values across two
        // samples, and calling that an enum types the SDK so it can only ever
        // search for those two words. Reverting the rule has to fail here —
        // the paging case above is carried by the numeric check instead, which
        // deleting the rule showed.
        let search = |term: &str| {
            let mut sample = request("GET", "/v1/search");
            sample.query = Some(format!("q={term}"));
            sample
        };
        let model = build_endpoint_model(&bundle(vec![search("shoes"), search("hats")]));
        let field = &model.endpoints[0].query_params[0];
        assert_eq!(field.name, "q");
        assert!(
            field.enum_values.is_empty(),
            "no value repeated, so nothing shows the set is closed: {:?}",
            field.enum_values
        );
    }

    #[test]
    fn a_value_seen_more_than_once_is_an_enum() {
        let sort = |value: &str| {
            let mut sample = request("GET", "/v1/orders");
            sample.query = Some(format!("sort={value}"));
            sample
        };
        let model = build_endpoint_model(&bundle(vec![sort("asc"), sort("desc"), sort("asc")]));
        let field = &model.endpoints[0].query_params[0];
        assert_eq!(field.name, "sort");
        assert_eq!(
            field.enum_values,
            vec!["asc".to_string(), "desc".to_string()]
        );
    }

    #[test]
    fn a_captured_credential_is_never_a_default() {
        // The token is the same in both samples, which is exactly what would
        // make it look constant. Baking it into an SDK would ship a dead
        // session token in source control.
        let sample = |_: usize| {
            let mut request = request("GET", "/v1/me");
            request.request_headers = vec![
                HeaderEntry {
                    name: "Authorization".into(),
                    value: "Bearer eyJhbGciOi.secret-value".into(),
                },
                HeaderEntry {
                    name: "X-Trace-Id".into(),
                    value: "constant-trace".into(),
                },
            ];
            request
        };
        let model = build_endpoint_model(&bundle(vec![sample(0), sample(1)]));
        let header = |name: &str| {
            model.endpoints[0]
                .headers
                .iter()
                .find(|header| header.name == name)
                .unwrap_or_else(|| panic!("missing {name}"))
        };

        let authorization = header("authorization");
        assert!(authorization.required, "the endpoint does need one");
        assert!(authorization.secret);
        assert!(
            !authorization.constant,
            "one session's token is not a default"
        );
        assert_eq!(authorization.example, None, "the value must not be carried");

        // A non-credential header that genuinely never varies still is one.
        assert!(header("x-trace-id").constant);
        assert!(!header("x-trace-id").secret);

        // And the value must not survive anywhere else in the model.
        let serialised = serde_json::to_string(&model).expect("model serialises");
        assert!(
            !serialised.contains("secret-value"),
            "a captured credential reached the model"
        );
    }

    #[test]
    fn drops_headers_every_client_sets_for_itself() {
        let mut sample = request("GET", "/v1/items");
        sample.request_headers = vec![
            HeaderEntry {
                name: "User-Agent".into(),
                value: "Mozilla/5.0".into(),
            },
            HeaderEntry {
                name: "Authorization".into(),
                value: "Bearer abc".into(),
            },
        ];
        let model = build_endpoint_model(&bundle(vec![sample]));
        let names: Vec<&str> = model.endpoints[0]
            .headers
            .iter()
            .map(|header| header.name.as_str())
            .collect();
        assert_eq!(names, vec!["authorization"]);
    }

    #[test]
    fn static_assets_are_not_api_endpoints() {
        // A real capture of one marketing homepage produced thirty methods
        // named after JS bundles, which buried the four calls that were the
        // API. Found by generating an SDK from a live site, not by a fixture.
        let model = build_endpoint_model(&bundle(vec![
            request("GET", "/assets/index-Bqwru92u.js"),
            request("GET", "/assets/app.css"),
            request("GET", "/static/logo.svg"),
            request("GET", "/fonts/inter.woff2"),
            request("GET", "/api/v1/flights"),
        ]));
        let templates: Vec<&str> = model
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path_template.as_str())
            .collect();
        assert_eq!(templates, vec!["/api/v1/flights"], "{templates:?}");
        assert_eq!(model.skipped_count, 4);
    }

    #[test]
    fn a_path_that_only_looks_like_an_asset_is_kept() {
        // The filter is on the last segment's extension, so an API path that
        // merely contains the word is unaffected.
        let model = build_endpoint_model(&bundle(vec![
            request("GET", "/api/assets/list"),
            request("GET", "/api/v1/js/config"),
        ]));
        assert_eq!(model.endpoints.len(), 2, "{:?}", model.endpoints);
    }

    #[test]
    fn tunnels_and_streams_carry_no_api_surface() {
        let mut socket = request("GET", "/ws");
        socket.resource_type = "websocket".into();
        let model = build_endpoint_model(&bundle(vec![
            request("CONNECT", "/"),
            socket,
            request("GET", "/v1/items"),
        ]));
        assert_eq!(model.endpoints.len(), 1);
        assert_eq!(model.endpoints[0].path_template, "/v1/items");
        assert_eq!(model.skipped_count, 2);
    }
}
