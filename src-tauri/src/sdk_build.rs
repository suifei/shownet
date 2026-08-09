//! Assembles a session into a Python SDK.
//!
//! This is an orchestrator, not a new capability. The pieces already exist and
//! keep their own rules:
//!
//! * `endpoint_model` says what the API is, and which parts of that are guesses.
//! * `algorithm_replay` supplies crypto steps, but only ones that were executed
//!   against captured values and reproduced them.
//! * `tls_impersonate` supplies the fingerprint the requests have to carry.
//!
//! Two rules govern the output, and they pull in opposite directions:
//!
//! A captured credential is never written into the package. It is one session's
//! token: baked in, the SDK is broken by its next rotation and leaks a secret
//! into source control. But dropping it would produce a client that cannot
//! authenticate, so every credential the capture showed as required becomes a
//! **required constructor argument**. The capture decides *that* a credential is
//! needed; the caller supplies *which*.
//!
//! Anything unproven is stated in the package rather than smoothed over. A
//! guessed path parameter, a body that could not be described, a crypto step
//! that did not reproduce its captured value — each one appears in GAPS.md, in
//! the README's first screen, and as a comment at the site that depends on it.
//! The package is still generated: a client with marked holes is more useful
//! than a refusal, as long as the holes are impossible to miss.

use crate::dataflow::{credential_source, DataFlow, DataFlowEdge};
use crate::endpoint_model::{Endpoint, EndpointModel, FieldModel, Gap, GapKind, ParamEvidence};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkFile {
    pub name: String,
    pub role: String,
    pub content: String,
    pub bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkReadiness {
    /// Endpoints whose path parameters were all confirmed by variation.
    pub endpoints_confirmed: usize,
    pub endpoints_total: usize,
    /// Crypto steps that reproduced captured values, and steps identified but
    /// not reproduced. Only the first kind is emitted as code.
    pub crypto_verified: usize,
    pub crypto_unverified: usize,
    /// Whether a real ClientHello fingerprint target could be stated. Without
    /// it the package still runs, with curl_cffi's own default profile.
    pub fingerprint_target_known: bool,
    pub gap_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkPackage {
    pub session_id: String,
    pub language: String,
    pub package_name: String,
    pub files: Vec<SdkFile>,
    pub readiness: SdkReadiness,
    pub gaps: Vec<Gap>,
}

/// The TLS and HTTP/2 shape the generated client should present. Kept as data
/// rather than as code: ShowNet's own rustls stack cannot be linked into a
/// Python package, so the SDK states the target and lets curl_cffi meet it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintContract {
    pub profile_id: String,
    pub target_ja3: Option<String>,
    pub alpn: Vec<String>,
    /// curl_cffi's impersonation target, e.g. "chrome124".
    pub impersonate: String,
    pub http2_settings: Vec<(u16, u32)>,
    pub notes: Vec<String>,
}

/// A crypto step that reproduced the values a capture recorded.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedCryptoStep {
    pub name: String,
    pub python_source: String,
    pub entry_point: String,
}

/// Everything the builder needs, gathered by the caller. Passing it in rather
/// than reaching for storage keeps this module testable without a database and
/// without a browser.
#[derive(Clone, Debug, Default)]
pub struct SdkInputs {
    pub fingerprint: FingerprintContract,
    /// Where each credential came from. A credential one captured call
    /// produces becomes an `authenticate()` on the client; one nothing
    /// produces stays a required argument, because nothing here can obtain it.
    pub dataflow: DataFlow,
    pub verified_crypto: Vec<VerifiedCryptoStep>,
    /// Steps that were identified but never reproduced a captured value. Named
    /// in the gaps, never emitted as code.
    pub unverified_crypto: Vec<String>,
}

/// A Python string literal, escaped by the JSON writer. Hand-rolled quoting is
/// what broke the injected lab scripts; JSON's escape set is a subset of
/// Python's for the characters that appear here.
fn py_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

const PY_KEYWORDS: &[&str] = &[
    "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif",
    "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",
    "None", "nonlocal", "not", "or", "pass", "raise", "return", "True", "False", "try", "while",
    "with", "yield",
];

/// camelCase or kebab-case to a valid Python identifier. A name that collides
/// with a keyword, or starts with a digit, gets a trailing underscore rather
/// than being silently mangled into something else's name.
pub fn snake_case(value: &str) -> String {
    let mut out = String::new();
    let mut previous_lower = false;
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            if previous_lower && !out.is_empty() {
                out.push('_');
            }
            out.extend(character.to_lowercase());
            previous_lower = false;
        } else if character.is_ascii_alphanumeric() {
            out.push(character);
            previous_lower = character.is_ascii_lowercase() || character.is_ascii_digit();
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
            previous_lower = false;
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    let base = if trimmed.is_empty() {
        "field".to_string()
    } else {
        trimmed
    };
    if base.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        // Prefixed, not suffixed. `2fa_` is as invalid as `2fa` — a Python
        // identifier cannot *start* with a digit, and a trailing underscore
        // does nothing about that. Found by compiling a package generated from
        // a real capture, where a Cloudflare challenge path put a digit-leading
        // segment in a parameter position; every fixture until then had only
        // ever put one mid-name, where it is legal.
        format!("v{base}")
    } else if PY_KEYWORDS.contains(&base.as_str()) {
        format!("{base}_")
    } else {
        base
    }
}

fn python_type(kind: &str) -> &'static str {
    match kind {
        "integer" => "int",
        "number" => "float",
        "boolean" => "bool",
        _ => "str",
    }
}

/// Credentials the capture showed this API requires. They become required
/// keyword arguments on the client: the capture proves one is needed, the
/// caller decides which.
fn required_credentials(model: &EndpointModel) -> Vec<FieldModel> {
    let mut seen = BTreeSet::new();
    let mut credentials = Vec::new();
    for endpoint in &model.endpoints {
        for header in &endpoint.headers {
            if header.secret && header.required && seen.insert(header.name.clone()) {
                credentials.push(header.clone());
            }
        }
    }
    credentials
}

fn gaps_for(gaps: &[Gap], operation_id: &str) -> Vec<String> {
    gaps.iter()
        .filter(|gap| gap.operation_id == operation_id)
        .map(|gap| format!("{:?}: {}", gap.kind, gap.detail))
        .collect()
}

/// Splits credentials into the ones a captured call produces and the ones
/// nothing does. Only the second kind can be a required argument: asking the
/// caller for a token the API itself hands out is the failure this exists to
/// avoid.
fn split_credentials<'a>(
    credentials: &'a [FieldModel],
    flow: &'a DataFlow,
) -> (Vec<(&'a FieldModel, &'a DataFlowEdge)>, Vec<&'a FieldModel>) {
    let mut sourced = Vec::new();
    let mut unsourced = Vec::new();
    for credential in credentials {
        match credential_source(flow, &credential.name) {
            Some(edge) => sourced.push((credential, edge)),
            None => unsourced.push(credential),
        }
    }
    (sourced, unsourced)
}

fn render_client(model: &EndpointModel, inputs: &SdkInputs, credentials: &[FieldModel]) -> String {
    let mut out = String::new();
    out.push_str(
        "\"\"\"Generated by ShowNet from a captured session.\n\n\
         Read GAPS.md before relying on this. Anything ShowNet could not confirm\n\
         from the capture is marked there and at the line that depends on it.\n\
         \"\"\"\n\n\
         from __future__ import annotations\n\n\
         from typing import Any\n\n\
         from curl_cffi import requests\n\n\
         from .fingerprint import CONTRACT, verify_fingerprint\n\n\n\
         def _pointer(payload: Any, pointer: str) -> Any:\n\
         \x20   \"\"\"Resolve a JSON pointer, returning None rather than raising.\"\"\"\n\
         \x20   current = payload\n\
         \x20   for part in pointer.split(\"/\"):\n\
         \x20       if part == \"\":\n\
         \x20           continue\n\
         \x20       if isinstance(current, list):\n\
         \x20           try:\n\
         \x20               current = current[int(part)]\n\
         \x20           except (ValueError, IndexError):\n\
         \x20               return None\n\
         \x20       elif isinstance(current, dict):\n\
         \x20           if part not in current:\n\
         \x20               return None\n\
         \x20           current = current[part]\n\
         \x20       else:\n\
         \x20           return None\n\
         \x20   return current\n\n\n",
    );

    let base_url = model
        .servers
        .first()
        .cloned()
        .unwrap_or_else(|| "https://example.invalid".to_string());

    let (sourced, unsourced) = split_credentials(credentials, &inputs.dataflow);

    out.push_str("class ApiClient:\n");
    out.push_str("    \"\"\"One captured API.\n\n");
    if credentials.is_empty() {
        out.push_str("    No credential appeared in every sample of any endpoint, so none is\n    required here. If a call returns 401, the capture did not include it.\n");
    } else {
        out.push_str(
            "    The credentials below are required arguments because the capture showed\n\
             \x20   them on every sample of at least one endpoint. Their captured values are\n\
             \x20   deliberately absent: one session's token would be dead by the next run\n\
             \x20   and would be a secret committed to source control.\n",
        );
    }
    out.push_str("    \"\"\"\n\n");

    // Constructor: only the credentials nothing in the capture produces are
    // required. For the rest there is an authenticate_* method below, and
    // demanding a token the API itself mints would defeat having traced it.
    out.push_str("    def __init__(\n        self,\n        *,\n");
    for credential in &unsourced {
        out.push_str(&format!("        {}: str,\n", snake_case(&credential.name)));
    }
    for (credential, _) in &sourced {
        out.push_str(&format!(
            "        {}: str | None = None,\n",
            snake_case(&credential.name)
        ));
    }
    out.push_str(&format!(
        "        base_url: str = {},\n        impersonate: str = {},\n        timeout: float = 30.0,\n    ) -> None:\n",
        py_string(&base_url),
        py_string(&inputs.fingerprint.impersonate)
    ));
    out.push_str("        self.base_url = base_url.rstrip(\"/\")\n");
    out.push_str(&format!(
        "        self._primary = {}\n",
        py_string(&base_url)
    ));
    out.push_str("        self.timeout = timeout\n");
    out.push_str(
        "        # impersonate is what actually produces the TLS and HTTP/2 fingerprint;\n",
    );
    out.push_str("        # see fingerprint.py for the target it is meant to match.\n");
    out.push_str("        self.session = requests.Session(impersonate=impersonate)\n");
    for credential in &unsourced {
        let field = snake_case(&credential.name);
        out.push_str(&format!(
            "        self.session.headers[{}] = {}\n",
            py_string(&credential.name),
            field
        ));
    }
    for (credential, _) in &sourced {
        let field = snake_case(&credential.name);
        out.push_str(&format!("        if {field} is not None:\n"));
        out.push_str(&format!(
            "            self.session.headers[{}] = {}\n",
            py_string(&credential.name),
            field
        ));
    }
    out.push('\n');

    for (credential, edge) in &sourced {
        out.push_str(&render_authenticate(credential, edge));
    }

    out.push_str("    def check_fingerprint(self) -> dict[str, Any]:\n");
    out.push_str(
        "        \"\"\"Measure this client's real fingerprint against the captured target.\"\"\"\n",
    );
    out.push_str("        return verify_fingerprint(self.session)\n\n");

    // One site, several hosts. base_url overrides the primary one; the siblings
    // keep the origin they were captured on, so a call to search.* does not go
    // to www.* because that is what sorted first.
    out.push_str(concat!(
        "    def _origin(self, captured: str) -> str:\n",
        "        \"\"\"The origin this endpoint was captured on.\n\n",
        "        base_url overrides the primary host only; the site's other hosts\n",
        "        keep the origin they were captured on, so a call to search.* is not\n",
        "        sent to www.* merely because that one sorted first.\n",
        "        \"\"\"\n",
        "        if captured == self._primary:\n",
        "            return self.base_url\n",
        "        return captured.rstrip(\"/\")\n\n",
    ));

    for endpoint in &model.endpoints {
        out.push_str(&render_method(endpoint, &model.gaps));
    }

    out
}

/// A method that obtains a credential the capture showed one call producing,
/// instead of asking the caller for a token only the API can mint.
///
/// The wrapper matters as much as the value: the capture recorded
/// `Bearer <token>`, and sending the bare token is a different header.
fn render_authenticate(credential: &FieldModel, edge: &DataFlowEdge) -> String {
    let mut out = String::new();
    let method = snake_case(&edge.producer);
    let field = snake_case(&credential.name);
    out.push_str(&format!(
        "    def authenticate_{field}(self, **kwargs: Any) -> str:\n"
    ));
    out.push_str(&format!(
        "        \"\"\"Call {} and keep the {} it returns.\n\n\
         \x20       The capture showed {} produced the value this header carries at\n\
         \x20       ``{}``, in {} later request(s). Arguments are passed through.\n\
         \x20       \"\"\"\n",
        edge.producer, credential.name, edge.producer, edge.producer_pointer, edge.occurrences
    ));
    out.push_str(&format!("        payload = self.{method}(**kwargs)\n"));
    out.push_str(&format!(
        "        value = _pointer(payload, {})\n",
        py_string(&edge.producer_pointer)
    ));
    out.push_str("        if not isinstance(value, str):\n");
    out.push_str(&format!(
        "            raise RuntimeError(\n                {}\n            )\n",
        py_string(&format!(
            "{} did not return a value at {}; the API may have changed since the capture",
            edge.producer, edge.producer_pointer
        ))
    ));
    // Only the wrapper that exists: `"Bearer " + value + ""` runs the same and
    // reads like a generator that did not know what it was writing.
    let mut expression = String::new();
    if !edge.prefix.is_empty() {
        expression.push_str(&format!("{} + ", py_string(&edge.prefix)));
    }
    expression.push_str("value");
    if !edge.suffix.is_empty() {
        expression.push_str(&format!(" + {}", py_string(&edge.suffix)));
    }
    out.push_str(&format!(
        "        self.session.headers[{}] = {expression}\n",
        py_string(&credential.name)
    ));
    out.push_str("        return value\n\n");
    out
}

fn render_method(endpoint: &Endpoint, gaps: &[Gap]) -> String {
    let mut out = String::new();
    let name = snake_case(&endpoint.operation_id);
    let own_gaps = gaps_for(gaps, &endpoint.operation_id);

    let mut signature = vec!["self".to_string()];
    for param in &endpoint.path_params {
        signature.push(format!(
            "{}: {}",
            snake_case(&param.name),
            python_type(&param.kind)
        ));
    }
    let optional_query: Vec<&FieldModel> = endpoint
        .query_params
        .iter()
        .filter(|field| !field.required && !field.secret)
        .collect();
    let required_query: Vec<&FieldModel> = endpoint
        .query_params
        .iter()
        .filter(|field| field.required && !field.constant && !field.secret)
        .collect();
    if !required_query.is_empty() || !optional_query.is_empty() || endpoint.request_body.is_some() {
        signature.push("*".to_string());
    }
    for field in &required_query {
        signature.push(format!(
            "{}: {}",
            snake_case(&field.name),
            python_type(&field.kind)
        ));
    }
    for field in &optional_query {
        signature.push(format!(
            "{}: {} | None = None",
            snake_case(&field.name),
            python_type(&field.kind)
        ));
    }
    if endpoint.request_body.is_some() {
        signature.push("json_body: dict[str, Any] | None = None".to_string());
    }

    out.push_str(&format!(
        "    def {name}({}) -> Any:\n",
        signature.join(", ")
    ));

    // Docstring: what was captured, then what was not.
    out.push_str(&format!(
        "        \"\"\"``{} {}``\n\n        Built from {} captured sample{}.\n",
        endpoint.method,
        endpoint.path_template,
        endpoint.sample_count,
        if endpoint.sample_count == 1 { "" } else { "s" }
    ));
    if !own_gaps.is_empty() {
        out.push_str("\n        NOT CONFIRMED BY THE CAPTURE:\n");
        for gap in &own_gaps {
            out.push_str(&format!("          - {gap}\n"));
        }
    }
    out.push_str("        \"\"\"\n");

    // Path assembly.
    let mut path_expression = py_string(&endpoint.path_template);
    if !endpoint.path_params.is_empty() {
        let replacements: Vec<String> = endpoint
            .path_params
            .iter()
            .map(|param| {
                format!(
                    ".replace({}, str({}))",
                    py_string(&format!("{{{}}}", param.name)),
                    snake_case(&param.name)
                )
            })
            .collect();
        path_expression.push_str(&replacements.join(""));
    }
    out.push_str(&format!("        path = {path_expression}\n"));

    // Query. The constants are emitted unconditionally: gating them on there
    // also being a variable parameter dropped every query string from an
    // endpoint whose parameters happened to all be constant, so the generated
    // call went out bare and the real API would reject it.
    out.push_str("        params: dict[str, Any] = {}\n");
    for field in &required_query {
        out.push_str(&format!(
            "        params[{}] = {}\n",
            py_string(&field.name),
            snake_case(&field.name)
        ));
    }
    for field in endpoint
        .query_params
        .iter()
        .filter(|field| field.constant && field.required && !field.secret)
    {
        // Held identical across every sample and not a credential, so it is
        // part of the call rather than an input.
        out.push_str(&format!(
            "        params[{}] = {}  # constant across every captured sample\n",
            py_string(&field.name),
            py_string(field.example.as_deref().unwrap_or(""))
        ));
    }
    for field in &optional_query {
        let local = snake_case(&field.name);
        out.push_str(&format!("        if {local} is not None:\n"));
        out.push_str(&format!(
            "            params[{}] = {local}\n",
            py_string(&field.name)
        ));
    }

    let mut call = format!(
        "        response = self.session.request(\n            {},\n            self._origin({}) + path,\n            params=params,\n            timeout=self.timeout,\n",
        py_string(&endpoint.method),
        py_string(&endpoint.server)
    );
    if endpoint.request_body.is_some() {
        call.push_str("            json=json_body,\n");
    }
    call.push_str("        )\n");
    out.push_str(&call);
    out.push_str("        response.raise_for_status()\n");
    out.push_str("        try:\n            return response.json()\n        except Exception:\n            return response.text\n\n");
    out
}

fn render_fingerprint(inputs: &SdkInputs) -> String {
    let contract = &inputs.fingerprint;
    let settings: Vec<Value> = contract
        .http2_settings
        .iter()
        .map(|(id, value)| json!([id, value]))
        .collect();
    let contract_json = json!({
        "profileId": contract.profile_id,
        "targetJa3": contract.target_ja3,
        "alpn": contract.alpn,
        "impersonate": contract.impersonate,
        "http2Settings": settings,
        "notes": contract.notes,
    });

    let mut out = String::from(
        "\"\"\"The TLS and HTTP/2 shape this client is supposed to present.\n\n\
         ShowNet's own TLS stack cannot be linked into a Python package, so this\n\
         states the target and curl_cffi is what meets it. The two are not the same\n\
         thing, which is why verify_fingerprint exists: it measures what the client\n\
         really sent rather than trusting that impersonate= did what it claims.\n\
         \"\"\"\n\n\
         from __future__ import annotations\n\n\
         from typing import Any\n\n\
         CONTRACT: dict[str, Any] = ",
    );
    out.push_str(&serde_json::to_string_pretty(&contract_json).unwrap_or_else(|_| "{}".into()));
    out.push_str("\n\n\n");
    out.push_str(
        "def verify_fingerprint(session: Any, probe_url: str = \"https://tls.peet.ws/api/all\") -> dict[str, Any]:\n\
         \x20   \"\"\"Compare the fingerprint this session actually sends against CONTRACT.\n\n\
         \x20   Returns the measured JA3 alongside the target and whether they match.\n\
         \x20   A mismatch is not an exception: the caller decides whether an\n\
         \x20   approximate profile is good enough for the site being called.\n\
         \x20   \"\"\"\n\
         \x20   target = CONTRACT.get(\"targetJa3\")\n\
         \x20   try:\n\
         \x20       measured = session.get(probe_url, timeout=30).json()\n\
         \x20   except Exception as error:  # noqa: BLE001 - reported, not raised\n\
         \x20       return {\"ok\": False, \"error\": str(error), \"target\": target}\n\
         \x20   observed = (measured.get(\"tls\") or {}).get(\"ja3\")\n\
         \x20   return {\n\
         \x20       \"ok\": bool(target) and observed == target,\n\
         \x20       \"target\": target,\n\
         \x20       \"observed\": observed,\n\
         \x20       \"note\": \"no target was recorded for this capture\" if not target else \"\",\n\
         \x20   }\n",
    );
    out
}

fn render_crypto(inputs: &SdkInputs) -> String {
    let mut out = String::from(
        "\"\"\"Algorithm steps recovered from the capture.\n\n\
         Only steps that were executed against values this capture recorded, and\n\
         reproduced them exactly, appear here as code. Steps that were identified\n\
         but never reproduced a captured value are listed in GAPS.md and are not\n\
         guessed at: a signature that is almost right fails the same as no\n\
         signature, and it fails less visibly.\n\
         \"\"\"\n\n\
         from __future__ import annotations\n\n",
    );
    if inputs.verified_crypto.is_empty() {
        out.push_str(
            "# No step reproduced a captured value in this session.\n\
             # Requests needing a signed or encrypted field will have to supply it.\n\n\
             VERIFIED_STEPS: dict[str, object] = {}\n",
        );
        return out;
    }
    for step in &inputs.verified_crypto {
        out.push_str(&format!("# step: {}\n", step.name));
        out.push_str(step.python_source.trim_end());
        out.push_str("\n\n");
    }
    out.push_str("VERIFIED_STEPS: dict[str, object] = {\n");
    for step in &inputs.verified_crypto {
        out.push_str(&format!(
            "    {}: {},\n",
            py_string(&step.name),
            step.entry_point
        ));
    }
    out.push_str("}\n");
    out
}

fn render_gaps(model: &EndpointModel, inputs: &SdkInputs, readiness: &SdkReadiness) -> String {
    let mut out = String::from("# 这个 SDK 里没有被抓包证实的部分\n\n");
    out.push_str(
        "下面每一条都是 ShowNet 无法从这次抓包确认的东西。生成出来是为了能用，\n\
         不是为了让人以为它已经完整。\n\n",
    );
    out.push_str(&format!(
        "- 端点：{} 个中有 {} 个的路径参数由多次请求相互印证，其余是按单个样本的形状推测的\n",
        readiness.endpoints_total, readiness.endpoints_confirmed
    ));
    out.push_str(&format!(
        "- 加解密：{} 个步骤复现了抓到的真实值并被写入代码，{} 个只被识别出来、未能复现，因此没有生成\n",
        readiness.crypto_verified, readiness.crypto_unverified
    ));
    if !inputs.dataflow.edges.is_empty() || !inputs.dataflow.unsourced_credentials.is_empty() {
        out.push_str(&format!(
            "- 依赖链路：追出 {} 条「某次响应的值出现在后续请求里」的边；其中 {} 个凭据在这次抓包里没有任何来源\n",
            inputs.dataflow.edges.len(),
            inputs.dataflow.unsourced_credentials.len()
        ));
    }
    out.push_str(&format!(
        "- 指纹：{}\n\n",
        if readiness.fingerprint_target_known {
            "已记录目标 JA3，运行 client.check_fingerprint() 可实测比对"
        } else {
            "本次抓包没有记录到目标 JA3，客户端使用 curl_cffi 自带的模拟档位，未经比对"
        }
    ));

    if model.gaps.is_empty()
        && inputs.unverified_crypto.is_empty()
        && inputs.dataflow.unsourced_credentials.is_empty()
        && !inputs
            .dataflow
            .edges
            .iter()
            .any(|edge| edge.occurrences == 1)
    {
        out.push_str("## 逐条清单\n\n（无）\n");
        return out;
    }

    out.push_str("## 逐条清单\n\n");
    for gap in &model.gaps {
        let label = match gap.kind {
            GapKind::GuessedPathParam => "路径参数是推测的",
            GapKind::ConflictingFieldType => "同一字段在不同样本里类型不同",
            GapKind::OpaqueBody => "请求体无法描述成结构",
            GapKind::SingleSample => "只有一个样本",
            GapKind::OffSiteHost => "站外主机,未纳入",
        };
        out.push_str(&format!(
            "- **{}** · `{}` — {}\n",
            label, gap.operation_id, gap.detail
        ));
    }
    for edge in inputs
        .dataflow
        .edges
        .iter()
        .filter(|edge| edge.occurrences == 1)
    {
        out.push_str(&format!(
            "- **依赖链路只见过一次** · `{}` → `{}` — `{}` 的值只在一次请求里被复用过；一次相同不足以断定它一定来自这里\n",
            edge.producer, edge.consumer, edge.consumer_name
        ));
    }
    for name in &inputs.dataflow.unsourced_credentials {
        out.push_str(&format!(
            "- **凭据没有来源** · `{name}` — 抓包证明接口需要它，但没有任何一次响应产生过它，所以生成的客户端只能要求调用方传入\n"
        ));
    }
    for name in &inputs.unverified_crypto {
        out.push_str(&format!(
            "- **算法未通过验证** · `{name}` — 识别出来了，但没有用抓到的值复现成功，因此没有生成代码\n"
        ));
    }
    out
}

fn render_readme(
    model: &EndpointModel,
    readiness: &SdkReadiness,
    credentials: &[FieldModel],
    flow: &DataFlow,
) -> String {
    let mut out = String::from("# ShowNet 生成的 API SDK\n\n");
    out.push_str(&format!(
        "从一次抓包生成：{} 条请求 → {} 个端点。\n\n",
        model.request_count, readiness.endpoints_total
    ));

    if readiness.gap_count > 0 {
        out.push_str("> **先读 GAPS.md。** ");
        out.push_str(&format!(
            "这个包里有 {} 处没有被抓包证实，包括推测出来的路径参数和没能复现的算法步骤。\n> 它们在代码里也标注在对应的方法上。\n\n",
            readiness.gap_count
        ));
    } else {
        out.push_str("> 这次抓包里没有留下未确认的部分，但样本量仍然决定了它的覆盖范围。\n\n");
    }

    let (sourced, unsourced) = split_credentials(credentials, flow);

    out.push_str("## 安装\n\n```bash\npip install -r requirements.txt\n```\n\n## 使用\n\n```python\nfrom shownet_sdk import ApiClient\n\nclient = ApiClient(\n");
    for credential in &unsourced {
        out.push_str(&format!(
            "    {}=\"...\",  # 抓包显示这个接口需要它，且没有任何一次响应产生过它\n",
            snake_case(&credential.name)
        ));
    }
    out.push_str(")\n");
    for (credential, edge) in &sourced {
        out.push_str(&format!(
            "\n# 抓包显示 {} 产生了这个凭据，所以不必手工填：\nclient.authenticate_{}(json_body={{...}})\n",
            edge.producer,
            snake_case(&credential.name)
        ));
    }
    out.push_str("```\n\n");

    if !sourced.is_empty() {
        out.push_str("### 登录是从抓包里推出来的\n\n");
        for (credential, edge) in &sourced {
            out.push_str(&format!(
                "`{}` 的值在抓包中由 `{}` 的响应 `{}` 产生，随后出现在 {} 次请求里。\n\
                 所以客户端提供了 `authenticate_{}()`：它调用那个接口并接住返回值。\n\n",
                credential.name,
                edge.producer,
                edge.producer_pointer,
                edge.occurrences,
                snake_case(&credential.name)
            ));
        }
        out.push_str(
            "这条链路是**推断**出来的，不是接口文档：如果目标改了登录响应的结构，\n\
             `authenticate_*` 会抛出错误而不是悄悄发一个空凭据。\n\n",
        );
    }

    if !unsourced.is_empty() {
        out.push_str("### 为什么这些凭据要自己传\n\n");
        out.push_str(
            "抓包里的 token 没有被写进代码。它是那一次会话的凭据：写死之后，下一次\n\
             轮换就会失效，而且等于把一个真实密钥提交进了代码库。而这几个凭据在\n\
             这次抓包里**没有任何一次响应产生过**，所以连推断登录都做不到——抓包能\n\
             证明的只是**这个接口需要一个凭据**，至于它从哪来，这次没拍到。\n\n",
        );
    }

    out.push_str("### 指纹\n\n");
    out.push_str(
        "TLS/HTTP2 指纹由 `curl_cffi` 的 `impersonate` 提供，不是 ShowNet 自己的 TLS 栈——\n\
         那套栈无法链接进 Python 包。因此 `fingerprint.py` 记录的是**目标**，\n\
         而 `client.check_fingerprint()` 会实测客户端真正发出的指纹并和目标比对。\n\
         两者不是一回事，所以这个自检才存在。\n\n",
    );

    out.push_str("## 端点\n\n| 方法 | 路径 | 方法名 | 样本 |\n|---|---|---|---|\n");
    for endpoint in &model.endpoints {
        out.push_str(&format!(
            "| {} | `{}` | `{}` | {} |\n",
            endpoint.method,
            endpoint.path_template,
            snake_case(&endpoint.operation_id),
            endpoint.sample_count
        ));
    }
    out
}

pub fn build_python_sdk(model: &EndpointModel, inputs: &SdkInputs) -> SdkPackage {
    let credentials = required_credentials(model);
    let endpoints_confirmed = model
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint
                .path_params
                .iter()
                .all(|param| param.evidence == ParamEvidence::Observed)
        })
        .count();
    let readiness = SdkReadiness {
        endpoints_confirmed,
        endpoints_total: model.endpoints.len(),
        crypto_verified: inputs.verified_crypto.len(),
        crypto_unverified: inputs.unverified_crypto.len(),
        fingerprint_target_known: inputs.fingerprint.target_ja3.is_some(),
        gap_count: model.gaps.len() + inputs.unverified_crypto.len(),
    };

    let mut files = Vec::new();
    fn push(files: &mut Vec<SdkFile>, name: &str, role: &str, content: String) {
        files.push(SdkFile {
            name: name.to_string(),
            role: role.to_string(),
            bytes: content.len(),
            content,
        });
    }

    push(
        &mut files,
        "README.md",
        "readme",
        render_readme(model, &readiness, &credentials, &inputs.dataflow),
    );
    push(
        &mut files,
        "GAPS.md",
        "gaps",
        render_gaps(model, inputs, &readiness),
    );
    push(
        &mut files,
        "requirements.txt",
        "requirements",
        "curl_cffi>=0.7\n".to_string(),
    );
    push(
        &mut files,
        "shownet_sdk/__init__.py",
        "package-init",
        "from .client import ApiClient\n\n__all__ = [\"ApiClient\"]\n".to_string(),
    );
    push(
        &mut files,
        "shownet_sdk/client.py",
        "client",
        render_client(model, inputs, &credentials),
    );
    push(
        &mut files,
        "shownet_sdk/fingerprint.py",
        "fingerprint",
        render_fingerprint(inputs),
    );
    push(
        &mut files,
        "shownet_sdk/crypto.py",
        "crypto",
        render_crypto(inputs),
    );

    let manifest = json!({
        "kind": "shownet-api-sdk",
        "language": "python",
        "sessionId": model.session_id,
        "servers": model.servers,
        "readiness": readiness,
        "files": files.iter().map(|file| file.name.clone()).collect::<Vec<_>>(),
    });
    push(
        &mut files,
        "MANIFEST.json",
        "manifest",
        serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| "{}".into()),
    );

    SdkPackage {
        session_id: model.session_id.clone(),
        language: "python".to_string(),
        package_name: "shownet_sdk".to_string(),
        files,
        readiness,
        gaps: model.gaps.clone(),
    }
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

    fn authorised(method: &str, path: &str) -> BundleRequest {
        let mut sample = request(method, path);
        sample.request_headers = vec![HeaderEntry {
            name: "Authorization".into(),
            value: "Bearer captured-session-token".into(),
        }];
        sample
    }

    fn file<'a>(package: &'a SdkPackage, name: &str) -> &'a str {
        package
            .files
            .iter()
            .find(|file| file.name == name)
            .unwrap_or_else(|| panic!("package must carry {name}"))
            .content
            .as_str()
    }

    #[test]
    fn a_required_credential_becomes_a_required_argument() {
        // The whole point of not writing the token into the package: the client
        // still has to send one, so the capture's evidence that it is needed
        // turns into an argument the caller must pass.
        let model = build_endpoint_model(&bundle(vec![
            authorised("GET", "/v1/users/1"),
            authorised("GET", "/v1/users/2"),
        ]));
        let package = build_python_sdk(&model, &SdkInputs::default());
        let client = file(&package, "shownet_sdk/client.py");

        assert!(
            client.contains("        authorization: str,\n"),
            "credential must be a required keyword argument:\n{client}"
        );
        assert!(
            client.contains("self.session.headers[\"authorization\"] = authorization"),
            "and must actually be sent"
        );
        assert!(
            !client.contains("captured-session-token"),
            "the captured value must not appear in the package"
        );
    }

    #[test]
    fn a_credential_the_api_hands_out_becomes_a_login_not_an_argument() {
        // The point of tracing data flow. Without it the client asks for a
        // token only the API can mint, which the caller has no way to supply.
        const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.body.sig-9f2c";
        let mut login = request("POST", "/v1/auth/login");
        login.response_body = format!(r#"{{"token":"{TOKEN}"}}"#);
        let mut call = request("GET", "/v1/me");
        call.request_headers = vec![HeaderEntry {
            name: "Authorization".into(),
            value: format!("Bearer {TOKEN}"),
        }];

        let session = bundle(vec![login, call]);
        let model = build_endpoint_model(&session);
        let inputs = SdkInputs {
            dataflow: crate::dataflow::build_dataflow(&session, &model),
            ..SdkInputs::default()
        };
        let package = build_python_sdk(&model, &inputs);
        let client = file(&package, "shownet_sdk/client.py");

        assert!(
            client.contains("authorization: str | None = None,"),
            "a credential with a source is optional, not demanded:\n{client}"
        );
        assert!(
            client.contains("def authenticate_authorization(self, **kwargs: Any) -> str:"),
            "and comes with a way to obtain it:\n{client}"
        );
        assert!(
            client.contains("payload = self.post_v1_auth_login(**kwargs)"),
            "which calls the operation the capture showed producing it"
        );
        // The wrapper, not just the value: a bare token is a different header.
        assert!(
            client.contains(r#"self.session.headers["authorization"] = "Bearer " + value"#),
            "the captured `Bearer ` prefix has to be rebuilt:\n{client}"
        );
        assert!(!client.contains(TOKEN), "still no captured value anywhere");
    }

    #[test]
    fn the_readme_and_gaps_carry_the_login_chain() {
        // The chain lived only in a docstring, where someone deciding whether
        // to trust the package never sees it.
        const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.body.sig-9f2c";
        let mut login = request("POST", "/v1/auth/login");
        login.response_body = format!(r#"{{"token":"{TOKEN}"}}"#);
        let mut first = request("GET", "/v1/me");
        first.request_headers = vec![HeaderEntry {
            name: "Authorization".into(),
            value: format!("Bearer {TOKEN}"),
        }];
        let mut second = request("GET", "/v1/orders");
        second.request_headers = first.request_headers.clone();

        let session = bundle(vec![login, first, second]);
        let model = build_endpoint_model(&session);
        let inputs = SdkInputs {
            dataflow: crate::dataflow::build_dataflow(&session, &model),
            ..SdkInputs::default()
        };
        let package = build_python_sdk(&model, &inputs);

        let readme = file(&package, "README.md");
        assert!(readme.contains("登录是从抓包里推出来的"), "{readme}");
        assert!(
            readme.contains("postV1AuthLogin"),
            "the producing call is named"
        );
        assert!(readme.contains("client.authenticate_authorization("));
        assert!(
            readme.contains("**推断**"),
            "the chain has to be labelled inference, not documentation"
        );
        assert!(!readme.contains(TOKEN));

        let gaps = file(&package, "GAPS.md");
        assert!(gaps.contains("依赖链路"), "{gaps}");
    }

    #[test]
    fn a_credential_with_no_source_is_called_out_in_the_gaps() {
        let model = build_endpoint_model(&bundle(vec![
            authorised("GET", "/v1/users/1"),
            authorised("GET", "/v1/users/2"),
        ]));
        let session = bundle(vec![
            authorised("GET", "/v1/users/1"),
            authorised("GET", "/v1/users/2"),
        ]);
        let inputs = SdkInputs {
            dataflow: crate::dataflow::build_dataflow(&session, &model),
            ..SdkInputs::default()
        };
        let package = build_python_sdk(&model, &inputs);
        assert!(file(&package, "GAPS.md").contains("凭据没有来源"));
        assert!(file(&package, "README.md").contains("没有任何一次响应产生过"));
    }

    #[test]
    fn each_verified_step_is_its_own_entry() {
        // Two steps used to collapse into one blob named after the adapter, so
        // the count in GAPS.md read 1 however many actually ran.
        let model = build_endpoint_model(&bundle(vec![request("GET", "/v1/thing")]));
        let inputs = SdkInputs {
            verified_crypto: vec![
                VerifiedCryptoStep {
                    name: "sign_body".into(),
                    python_source: "def sign_body(request):\n    return \"a\"\n".into(),
                    entry_point: "sign_body".into(),
                },
                VerifiedCryptoStep {
                    name: "sign_header".into(),
                    python_source: "def sign_header(request):\n    return \"b\"\n".into(),
                    entry_point: "sign_header".into(),
                },
            ],
            ..SdkInputs::default()
        };
        let package = build_python_sdk(&model, &inputs);
        assert_eq!(package.readiness.crypto_verified, 2);
        let crypto = file(&package, "shownet_sdk/crypto.py");
        assert!(crypto.contains("\"sign_body\": sign_body,"));
        assert!(crypto.contains("\"sign_header\": sign_header,"));
    }

    #[test]
    fn a_credential_with_no_source_stays_required() {
        // Nothing in the capture produces it, so the caller has to.
        let model = build_endpoint_model(&bundle(vec![
            authorised("GET", "/v1/users/1"),
            authorised("GET", "/v1/users/2"),
        ]));
        let package = build_python_sdk(&model, &SdkInputs::default());
        let client = file(&package, "shownet_sdk/client.py");
        assert!(client.contains("        authorization: str,\n"));
        assert!(
            !client.contains("def authenticate_"),
            "there is nothing to call:\n{client}"
        );
    }

    #[test]
    fn no_captured_credential_reaches_any_file() {
        let model = build_endpoint_model(&bundle(vec![
            authorised("GET", "/v1/users/1"),
            authorised("GET", "/v1/users/2"),
        ]));
        let package = build_python_sdk(&model, &SdkInputs::default());
        for file in &package.files {
            assert!(
                !file.content.contains("captured-session-token"),
                "{} carries the captured token",
                file.name
            );
        }
    }

    #[test]
    fn an_endpoint_whose_query_never_varies_still_sends_it() {
        // Found by reading a generated client, and none of the tests above saw
        // it: a parameter that is required and constant belongs to neither the
        // caller-supplied list nor the optional list, and the constants were
        // only emitted when one of those lists was non-empty. The method went
        // out with no query string at all, which the real API would reject.
        let mut sample = request("GET", "/v1/feed");
        sample.query = Some("format=json&locale=en".into());
        let model = build_endpoint_model(&bundle(vec![sample]));
        let package = build_python_sdk(&model, &SdkInputs::default());
        let client = file(&package, "shownet_sdk/client.py");

        assert!(
            client.contains(r#"params["format"] = "json""#),
            "a constant query parameter must still be sent:\n{client}"
        );
        assert!(client.contains(r#"params["locale"] = "en""#));
    }

    #[test]
    fn a_constant_query_parameter_is_not_an_argument() {
        // The other half: it is sent, but the caller is not asked for a value
        // the capture never saw vary.
        let mut sample = request("GET", "/v1/feed");
        sample.query = Some("format=json".into());
        let model = build_endpoint_model(&bundle(vec![sample]));
        let package = build_python_sdk(&model, &SdkInputs::default());
        let client = file(&package, "shownet_sdk/client.py");
        assert!(
            client.contains("def get_v1_feed(self) -> Any:"),
            "constant parameters do not belong in the signature:\n{client}"
        );
    }

    #[test]
    fn a_guessed_path_parameter_is_marked_where_it_is_used() {
        // One sample, so the id is a shape guess. It has to be visible at the
        // method, not only in a document nobody opens.
        let model = build_endpoint_model(&bundle(vec![request("GET", "/v1/users/1001")]));
        let package = build_python_sdk(&model, &SdkInputs::default());
        let client = file(&package, "shownet_sdk/client.py");
        assert!(
            client.contains("NOT CONFIRMED BY THE CAPTURE"),
            "the docstring must carry the gap:\n{client}"
        );
        assert!(file(&package, "GAPS.md").contains("路径参数是推测的"));
        assert!(file(&package, "README.md").contains("先读 GAPS.md"));
    }

    #[test]
    fn an_unverified_crypto_step_is_named_but_never_emitted() {
        let model = build_endpoint_model(&bundle(vec![request("GET", "/v1/thing")]));
        let inputs = SdkInputs {
            unverified_crypto: vec!["vendor_sign_v2".to_string()],
            ..SdkInputs::default()
        };
        let package = build_python_sdk(&model, &inputs);
        assert!(file(&package, "GAPS.md").contains("vendor_sign_v2"));
        let crypto = file(&package, "shownet_sdk/crypto.py");
        assert!(
            !crypto.contains("vendor_sign_v2"),
            "an unreproduced step must not be emitted as code:\n{crypto}"
        );
        assert!(crypto.contains("VERIFIED_STEPS"));
    }

    #[test]
    fn a_verified_crypto_step_is_emitted_and_registered() {
        let model = build_endpoint_model(&bundle(vec![request("GET", "/v1/thing")]));
        let inputs = SdkInputs {
            verified_crypto: vec![VerifiedCryptoStep {
                name: "vendor_sign".into(),
                python_source: "def vendor_sign(request):\n    return \"signed\"\n".into(),
                entry_point: "vendor_sign".into(),
            }],
            ..SdkInputs::default()
        };
        let package = build_python_sdk(&model, &inputs);
        let crypto = file(&package, "shownet_sdk/crypto.py");
        assert!(crypto.contains("def vendor_sign(request):"));
        assert!(crypto.contains("\"vendor_sign\": vendor_sign,"));
    }

    #[test]
    fn python_identifiers_survive_hostile_names() {
        assert_eq!(
            snake_case("getApiV1UsersUserId"),
            "get_api_v1_users_user_id"
        );
        assert_eq!(snake_case("X-Trace-Id"), "x_trace_id");
        // A field named for a keyword must not generate `def class(...)`.
        assert_eq!(snake_case("class"), "class_");
        // Not "2fa_": that is still not a legal identifier, and this assertion
        // used to pin the bug rather than the behaviour.
        assert_eq!(snake_case("2fa"), "v2fa");
        assert_eq!(snake_case("0401346636"), "v0401346636");
        assert_eq!(snake_case("--"), "field");
    }

    #[test]
    fn the_fingerprint_module_states_a_target_and_measures_against_it() {
        let inputs = SdkInputs {
            fingerprint: FingerprintContract {
                profile_id: "chrome-like".into(),
                target_ja3: Some("771,4865-4866,0-23,29-23,0".into()),
                alpn: vec!["h2".into()],
                impersonate: "chrome124".into(),
                http2_settings: vec![(0x1, 65536), (0x4, 6291456)],
                notes: vec!["measured from the capture".into()],
            },
            ..SdkInputs::default()
        };
        let model = build_endpoint_model(&bundle(vec![request("GET", "/v1/thing")]));
        let package = build_python_sdk(&model, &inputs);
        let fingerprint = file(&package, "shownet_sdk/fingerprint.py");
        assert!(fingerprint.contains("771,4865-4866,0-23,29-23,0"));
        assert!(fingerprint.contains("def verify_fingerprint"));
        assert!(
            file(&package, "shownet_sdk/client.py").contains("impersonate: str = \"chrome124\""),
            "the client has to actually use the contract's profile"
        );
        assert!(package.readiness.fingerprint_target_known);
    }

    #[test]
    fn an_absent_fingerprint_target_is_reported_not_faked() {
        let model = build_endpoint_model(&bundle(vec![request("GET", "/v1/thing")]));
        let package = build_python_sdk(&model, &SdkInputs::default());
        assert!(!package.readiness.fingerprint_target_known);
        assert!(file(&package, "GAPS.md").contains("没有记录到目标 JA3"));
    }
}
