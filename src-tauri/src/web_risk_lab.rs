//! Web risk-control research lab for the built-in Agent.
//!
//! Provides fixed debug profiles, request/response hijack recipes, restricted
//! JS sandbox evaluation, object-hook self-dump scripts, physical click/CDP
//! interaction plans, and vision-captcha prompt packages — without inventing
//! live bypasses.

use crate::challenge_decoder;
use crate::models::{BrowserHookEvent, RequestRecord};
use crate::storage::Storage;
use boa_engine::{Context, Source};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const MAX_SANDBOX_SOURCE: usize = 256_000;
const SANDBOX_WALL: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsDebugProfile {
    pub id: String,
    pub label: String,
    pub user_agent: String,
    pub viewport: Value,
    pub locale: String,
    pub timezone: String,
    pub platform: String,
    pub hardware_concurrency: u32,
    pub device_memory_gb: u32,
    pub webdriver: bool,
    pub languages: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsSandboxResult {
    pub ok: bool,
    pub result: Value,
    pub logs: Vec<String>,
    pub duration_ms: u128,
    pub profile_id: String,
    pub errors: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebRiskLabSession {
    pub session_id: String,
    pub profile: JsDebugProfile,
    pub hijack_script: String,
    pub object_dump_script: String,
    pub fixed_params_script: String,
    pub interaction_plan: Value,
    pub vision_captcha: Value,
    pub sandbox_bootstrap: String,
    pub evidence: Value,
    pub agent_playbook: Vec<String>,
}

pub fn list_debug_profiles() -> Vec<JsDebugProfile> {
    vec![
        profile(
            "chrome-desktop-stable",
            "Chrome Desktop (stable fingerprint)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            1440,
            900,
            "zh-CN",
            "Asia/Shanghai",
            "Win32",
            8,
            8,
            false,
            &["zh-CN", "zh", "en-US", "en"],
            &[
                "Default for AWS WAF / airline booking research",
                "webdriver=false; match sec-ch-ua to Chrome major when replaying HTTP",
            ],
        ),
        profile(
            "chrome-mac-retina",
            "Chrome macOS Retina",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            1512,
            982,
            "zh-CN",
            "Asia/Shanghai",
            "MacIntel",
            10,
            16,
            false,
            &["zh-CN", "en-US"],
            &["devicePixelRatio often 2; useful for canvas/webgl variance"],
        ),
        profile(
            "mobile-safari-like",
            "Mobile Safari-like UA (research only)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            390,
            844,
            "zh-CN",
            "Asia/Shanghai",
            "iPhone",
            6,
            4,
            false,
            &["zh-CN"],
            &["Not full iOS TLS fidelity under MITM; use for layout/click geometry only"],
        ),
        profile(
            "headless-lab",
            "Headless lab (explicit automation marks)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36",
            1280,
            800,
            "en-US",
            "UTC",
            "Linux x86_64",
            4,
            4,
            true,
            &["en-US"],
            &["Intentionally exposes automation for A/B comparison against non-headless"],
        ),
    ]
}

pub fn get_debug_profile(profile_id: &str) -> Result<JsDebugProfile, String> {
    let id = profile_id.trim();
    list_debug_profiles()
        .into_iter()
        .find(|profile| profile.id == id || id.is_empty() && profile.id == "chrome-desktop-stable")
        .or_else(|| list_debug_profiles().into_iter().next())
        .ok_or_else(|| "no debug profile available".into())
}

/// Build a full agent-facing lab session from capture evidence.
pub fn build_lab_session(
    storage: &Storage,
    session_id: &str,
    profile_id: Option<&str>,
) -> Result<WebRiskLabSession, String> {
    storage.get_session(session_id)?;
    let profile = get_debug_profile(profile_id.unwrap_or("chrome-desktop-stable"))?;
    let requests = storage.list_requests(session_id, Some(10_000), Some(0))?;
    let hooks = storage.list_browser_hooks(session_id, Some(2_000))?;

    let captcha_hooks = hooks
        .iter()
        .filter(|hook| {
            let blob = format!(
                "{} {} {}",
                hook.kind,
                hook.name,
                hook.url.as_deref().unwrap_or_default()
            )
            .to_ascii_lowercase();
            blob.contains("captcha")
                || blob.contains("recaptcha")
                || blob.contains("turnstile")
                || blob.contains("click")
                || blob.contains("pointer")
        })
        .take(40)
        .collect::<Vec<_>>();

    let interaction_plan = build_interaction_plan(&hooks, &requests);
    let vision_captcha = build_vision_captcha_package(&requests, &hooks);
    let hijack_script =
        request_hijack_script(&["awswaf", "mp_verify", "telemetry", "captcha", "sensor"]);
    let object_dump_script = object_hook_dump_script(&[
        "window.AwsWafIntegration",
        "window.AwsWafCaptcha",
        "window.grecaptcha",
        "window.turnstile",
        "window.gokuProps",
        "document.cookie",
        "navigator.webdriver",
        "navigator.userAgent",
        "navigator.platform",
        "screen.width",
        "screen.height",
    ]);
    let fixed_params_script = fixed_params_inject_script(&profile);
    let sandbox_bootstrap = sandbox_bootstrap_source(&profile);

    let evidence = json!({
        "requestCount": requests.len(),
        "hookCount": hooks.len(),
        "captchaRelatedHooks": captcha_hooks.len(),
        "hosts": top_hosts(&requests, 12),
        "challengeScripts": requests.iter()
            .filter(|request| request.path.contains("challenge.js") || request.path.contains("captcha.js"))
            .map(|request| json!({
                "order": request.order,
                "host": request.host,
                "path": request.path,
                "status": request.status,
            }))
            .take(12)
            .collect::<Vec<_>>(),
    });

    let agent_playbook = vec![
        "1) Ensure embedded browser is running (shownet_browser_status); launch via UI if needed.".into(),
        "2) Apply fixed profile / hijack / object dump via shownet_browser_evaluate(scripts from this lab).".into(),
        "3) Use shownet_browser_navigate / click / screenshot / insert_text on the unified bus (not a second CDP client).".into(),
        "4) Offline fragments: shownet_eval_js_sandbox; large challenge.js: shownet_decode_challenge_js.".into(),
        "5) Offline E2E without browser: shownet_seed_web_risk_fixture → shownet_run_offline_lab_probe.".into(),
        "6) Live: shownet_browser_install_lab then read returned objectDump / labState.".into(),
        "7) Grids: shownet_solve_vision_captcha (screenshot or imageBase64); dryRunIndices for offline.".into(),
        "8) Correlate with shownet_get_hooks + shownet_analyze_dynamic_protection.".into(),
        "9) Preserve captured values in evidence and reports; parameterize reusable generated source instead of silently deleting runtime fields.".into(),
    ];

    Ok(WebRiskLabSession {
        session_id: session_id.to_string(),
        profile,
        hijack_script,
        object_dump_script,
        fixed_params_script,
        interaction_plan,
        vision_captcha,
        sandbox_bootstrap,
        evidence,
        agent_playbook,
    })
}

/// Restricted JS eval with fixed browser-like globals (no network).
pub fn eval_js_sandbox(
    source: &str,
    profile_id: Option<&str>,
    expression: Option<&str>,
) -> Result<JsSandboxResult, String> {
    let profile = get_debug_profile(profile_id.unwrap_or("chrome-desktop-stable"))?;
    let mut errors = Vec::new();
    let mut limitations = Vec::new();
    let started = Instant::now();

    if source.len() > MAX_SANDBOX_SOURCE {
        return Ok(JsSandboxResult {
            ok: false,
            result: Value::Null,
            logs: vec![],
            duration_ms: 0,
            profile_id: profile.id,
            errors: vec![format!(
                "source exceeds {MAX_SANDBOX_SOURCE} bytes; truncate or use challenge decoder path"
            )],
            limitations: vec![
                "Sandbox is for fragments and helpers, not full 500KB challenge.js UI.".into(),
            ],
        });
    }

    let bootstrap = sandbox_bootstrap_source(&profile);
    let mut context = Context::default();
    if let Err(error) = context.eval(Source::from_bytes(bootstrap.as_bytes())) {
        errors.push(format!("bootstrap failed: {error}"));
    }
    if let Err(error) = context.eval(Source::from_bytes(source.as_bytes())) {
        errors.push(format!("source eval failed: {error}"));
    }

    if let Some(expression) = expression {
        if let Err(error) = context.eval(Source::from_bytes(
            format!("globalThis.__shownet_sandbox_result__ = ({expression});").as_bytes(),
        )) {
            errors.push(format!("expression failed: {error}"));
        }
    }

    let mut result = Value::Null;
    let mut logs = Vec::new();
    match context.eval(Source::from_bytes(
        b"(function(){ try { return JSON.stringify(typeof globalThis.__shownet_sandbox_result__ === 'undefined' ? {ok:true,note:'evaluated'} : globalThis.__shownet_sandbox_result__); } catch (error) { return JSON.stringify({error:String(error)}); } })();",
    )) {
        Ok(serialized) => {
            if let Some(text) = serialized.as_string() {
                let raw = text.to_std_string_escaped();
                result = serde_json::from_str(&raw).unwrap_or(json!(raw));
            }
        }
        Err(error) => errors.push(format!("result serialize failed: {error}")),
    }

    // Collect console-like buffer if present
    if let Ok(log_value) = context.eval(Source::from_bytes(
        b"(globalThis.__shownet_logs__||[]).slice(-50).map(String).join('\\n')",
    )) {
        if let Some(text) = log_value.as_string() {
            let owned = text.to_std_string_escaped();
            if !owned.is_empty() {
                logs = owned.lines().map(str::to_string).collect();
            }
        }
    }

    if started.elapsed() > SANDBOX_WALL {
        limitations.push("sandbox wall time approached".into());
    }
    limitations.push("No DOM layout/network/WebGL; for full page use CDP + hook runtime.".into());

    Ok(JsSandboxResult {
        ok: errors.is_empty(),
        result,
        logs,
        duration_ms: started.elapsed().as_millis(),
        profile_id: profile.id,
        errors,
        limitations,
    })
}

/// Decode challenge.js fragment via existing decoder, then optional sandbox probe.
#[allow(dead_code)]
pub fn sandbox_challenge_fragment(source: &str, profile_id: Option<&str>) -> Result<Value, String> {
    let decoded = challenge_decoder::decode_challenge_js(source);
    let probe = if decoded.success {
        // Tiny probe using recovered identifier presence
        let expr = format!(
            "globalThis.__shownet_sandbox_result__ = {{ decoded: true, identifier: {} }};",
            decoded
                .config
                .identifier
                .as_ref()
                .map(|value| js_string(value))
                .unwrap_or_else(|| "null".into())
        );
        eval_js_sandbox(
            &expr,
            profile_id,
            Some("globalThis.__shownet_sandbox_result__"),
        )
        .ok()
    } else {
        None
    };
    Ok(json!({
        "decoder": decoded,
        "sandboxProbe": probe,
    }))
}

/// A JavaScript string literal, escaped by the JSON writer rather than by hand.
/// The four call sites below escaped only the double quote, so a value ending
/// in a backslash escaped the closing quote instead and the whole injected
/// script failed to parse — inside the page, where nothing reports it back.
fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

pub fn request_hijack_script(url_markers: &[&str]) -> String {
    let markers = url_markers
        .iter()
        .map(|marker| js_string(marker))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"(function(){{
  "use strict";
  const MARKERS = [{markers}];
  const BRIDGE = "__SHOWNET_HOOK_BRIDGE__";
  const matchUrl = (url) => {{
    const text = String(url || "");
    return MARKERS.some((marker) => text.toLowerCase().includes(marker));
  }};
  const emit = (payload) => {{
    try {{
      const bridge = globalThis[BRIDGE];
      if (typeof bridge === "function") bridge(JSON.stringify(Object.assign({{ kind: "network", name: "hijack", timestamp: Date.now() }}, payload)));
      else {{
        globalThis.__SHOWNET_HIJACK_LOG__ = globalThis.__SHOWNET_HIJACK_LOG__ || [];
        globalThis.__SHOWNET_HIJACK_LOG__.push(payload);
        if (globalThis.__SHOWNET_HIJACK_LOG__.length > 300) globalThis.__SHOWNET_HIJACK_LOG__.shift();
      }}
    }} catch {{}}
  }};
  const clip = (value, max = 65536) => {{
    if (value == null) return value;
    if (typeof value === "string") return value.length <= max ? value : value.slice(0, max) + "\n[TRUNCATED]";
    try {{
      const text = JSON.stringify(value);
      return text.length <= max ? value : text.slice(0, max) + "\n[TRUNCATED]";
    }} catch {{ return String(value).slice(0, max); }}
  }};
  const originalFetch = globalThis.fetch;
  if (typeof originalFetch === "function" && !originalFetch.__shownetHijack) {{
    const wrapped = async function shownetHijackFetch(resource, init) {{
      const url = typeof resource === "string" ? resource : resource && resource.url;
      const method = String((init && init.method) || (resource && resource.method) || "GET").toUpperCase();
      const want = matchUrl(url);
      const requestBody = want ? clip(init && init.body) : undefined;
      const started = performance.now();
      const response = await Reflect.apply(originalFetch, this, arguments);
      if (want) {{
        let responseText = null;
        try {{
          const clone = response.clone();
          responseText = clip(await clone.text());
        }} catch (error) {{
          responseText = {{ error: String(error) }};
        }}
        emit({{
          name: "fetch.hijack",
          url,
          method,
          input: {{ body: requestBody, headers: init && init.headers }},
          output: {{ status: response.status, body: responseText }},
          durationMs: performance.now() - started,
        }});
      }}
      return response;
    }};
    wrapped.__shownetHijack = true;
    globalThis.fetch = wrapped;
  }}
  if (globalThis.XMLHttpRequest && !XMLHttpRequest.prototype.__shownetHijackSend) {{
    const open = XMLHttpRequest.prototype.open;
    const send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {{
      this.__shownetHijack = {{ method: String(method || "GET").toUpperCase(), url: String(url || "") }};
      return Reflect.apply(open, this, arguments);
    }};
    XMLHttpRequest.prototype.send = function(body) {{
      const meta = this.__shownetHijack || {{ method: "GET", url: "" }};
      const want = matchUrl(meta.url);
      const started = performance.now();
      if (want) {{
        this.addEventListener("loadend", () => {{
          emit({{
            name: "xhr.hijack",
            url: this.responseURL || meta.url,
            method: meta.method,
            input: {{ body: clip(body) }},
            output: {{ status: this.status, responseType: this.responseType, body: clip(this.responseText) }},
            durationMs: performance.now() - started,
          }});
        }}, {{ once: true }});
      }}
      return Reflect.apply(send, this, arguments);
    }};
    XMLHttpRequest.prototype.__shownetHijackSend = true;
  }}
  globalThis.__SHOWNET_LAB__ = Object.assign(globalThis.__SHOWNET_LAB__ || {{}}, {{
    version: "web-risk-lab/1.0",
    markers: MARKERS,
    getHijackLog: () => (globalThis.__SHOWNET_HIJACK_LOG__ || []).slice(-100),
  }});
  return "shownet request hijack installed";
}})();"#
    )
}

pub fn object_hook_dump_script(paths: &[&str]) -> String {
    let list = paths
        .iter()
        .map(|path| js_string(path))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"(function(){{
  "use strict";
  const PATHS = [{list}];
  const BRIDGE = "__SHOWNET_HOOK_BRIDGE__";
  const emit = (payload) => {{
    try {{
      const bridge = globalThis[BRIDGE];
      if (typeof bridge === "function") bridge(JSON.stringify(Object.assign({{ kind: "runtime", name: "object.dump", timestamp: Date.now() }}, payload)));
    }} catch {{}}
  }};
  const resolve = (path) => {{
    try {{
      return path.split(".").reduce((object, key) => object == null ? undefined : object[key], globalThis);
    }} catch (error) {{ return {{ error: String(error) }}; }}
  }};
  const summarize = (value, depth = 0) => {{
    if (value == null) return value;
    if (typeof value === "function") return {{ type: "function", name: value.name || "anonymous", length: value.length }};
    if (typeof value !== "object") return value;
    if (depth > 2) return Object.prototype.toString.call(value);
    if (Array.isArray(value)) return {{ type: "array", length: value.length, sample: value.slice(0, 5).map((item) => summarize(item, depth + 1)) }};
    const keys = Object.getOwnPropertyNames(value).slice(0, 40);
    const out = {{ type: "object", keys }};
    for (const key of keys.slice(0, 12)) {{
      try {{ out[key] = summarize(value[key], depth + 1); }} catch (error) {{ out[key] = {{ error: String(error) }}; }}
    }}
    return out;
  }};
  const report = {{}};
  for (const path of PATHS) report[path] = summarize(resolve(path));
  emit({{ input: {{ paths: PATHS }}, output: report }});
  globalThis.__SHOWNET_OBJECT_DUMP__ = report;
  return report;
}})();"#
    )
}

pub fn fixed_params_inject_script(profile: &JsDebugProfile) -> String {
    let languages = profile
        .languages
        .iter()
        .map(|item| js_string(item))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"(function(){{
  "use strict";
  const profile = {{
    id: {id:?},
    userAgent: {ua:?},
    platform: {platform:?},
    language: {locale:?},
    languages: [{languages}],
    hardwareConcurrency: {cores},
    deviceMemory: {memory},
    webdriver: {webdriver},
    viewport: {viewport}
  }};
  try {{
    Object.defineProperty(Navigator.prototype, "webdriver", {{ get: () => profile.webdriver }});
  }} catch {{}}
  try {{
    Object.defineProperty(Navigator.prototype, "userAgent", {{ get: () => profile.userAgent }});
  }} catch {{}}
  try {{
    Object.defineProperty(Navigator.prototype, "platform", {{ get: () => profile.platform }});
  }} catch {{}}
  try {{
    Object.defineProperty(Navigator.prototype, "language", {{ get: () => profile.language }});
  }} catch {{}}
  try {{
    Object.defineProperty(Navigator.prototype, "languages", {{ get: () => profile.languages.slice() }});
  }} catch {{}}
  try {{
    Object.defineProperty(Navigator.prototype, "hardwareConcurrency", {{ get: () => profile.hardwareConcurrency }});
  }} catch {{}}
  try {{
    Object.defineProperty(Navigator.prototype, "deviceMemory", {{ get: () => profile.deviceMemory }});
  }} catch {{}}
  globalThis.__SHOWNET_FIXED_PROFILE__ = profile;
  return profile;
}})();"#,
        id = profile.id,
        ua = profile.user_agent,
        platform = profile.platform,
        locale = profile.locale,
        languages = languages,
        cores = profile.hardware_concurrency,
        memory = profile.device_memory_gb,
        webdriver = if profile.webdriver { "true" } else { "false" },
        viewport = profile.viewport,
    )
}

pub fn build_interaction_plan(hooks: &[BrowserHookEvent], requests: &[RequestRecord]) -> Value {
    let mut steps = Vec::new();
    let mut order = 1u32;

    // From interaction hooks
    for hook in hooks
        .iter()
        .filter(|hook| hook.kind == "interaction")
        .take(30)
    {
        let selector = hook
            .input
            .get("selector")
            .and_then(Value::as_str)
            .unwrap_or("");
        if selector.is_empty() {
            continue;
        }
        steps.push(json!({
            "id": order,
            "action": "click",
            "source": "hook",
            "selector": selector,
            "cdp": [
                {"method": "Runtime.evaluate", "params": {
                    "expression": format!("(() => {{ const el = document.querySelector({selector:?}); if(!el) return null; const r = el.getBoundingClientRect(); return {{x:r.x+r.width/2,y:r.y+r.height/2,w:r.width,h:r.height}}; }})()"),
                    "returnByValue": true
                }},
                {"method": "Input.dispatchMouseEvent", "params": {"type": "mousePressed", "button": "left", "clickCount": 1, "x": "$x", "y": "$y"}},
                {"method": "Input.dispatchMouseEvent", "params": {"type": "mouseReleased", "button": "left", "clickCount": 1, "x": "$x", "y": "$y"}},
            ],
            "hookSequence": hook.sequence,
            "note": "Resolve $x/$y from evaluate result before dispatch",
        }));
        order += 1;
    }

    // Captcha-ish requests suggest grid click workflow
    let has_captcha = requests.iter().any(|request| {
        let blob = format!("{}{}", request.host, request.path).to_ascii_lowercase();
        blob.contains("captcha") || blob.contains("recaptcha") || blob.contains("/problem")
    });
    if has_captcha {
        steps.push(json!({
            "id": order,
            "action": "vision_grid_click",
            "source": "protocol",
            "cdp": [
                {"method": "Page.captureScreenshot", "params": {"format": "png"}},
                {"method": "Input.dispatchMouseEvent", "params": {"type": "mousePressed", "button": "left", "clickCount": 1, "x": "$cellX", "y": "$cellY"}},
                {"method": "Input.dispatchMouseEvent", "params": {"type": "mouseReleased", "button": "left", "clickCount": 1, "x": "$cellX", "y": "$cellY"}},
            ],
            "note": "Use visionCaptcha package to map LLM indices → cell center coordinates",
        }));
    }

    if steps.is_empty() {
        steps.push(json!({
            "id": 1,
            "action": "noop",
            "note": "No interaction hooks captured yet; start browser, enable hooks, reproduce UI flow",
        }));
    }

    json!({
        "steps": steps,
        "cdpHints": {
            "mouseMoveBeforeClick": true,
            "humanDelayMs": [40, 180],
            "scrollIntoView": true
        }
    })
}

pub fn build_vision_captcha_package(
    requests: &[RequestRecord],
    hooks: &[BrowserHookEvent],
) -> Value {
    let mut image_requests = Vec::new();
    for request in requests {
        let lower = format!(
            "{} {} {}",
            request.host,
            request.path,
            request
                .request_headers
                .iter()
                .chain(request.response_headers.iter())
                .map(|header| header.name.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        )
        .to_ascii_lowercase();
        if lower.contains("problem")
            || lower.contains("captcha")
            || lower.contains("image")
            || request.path.ends_with(".jpg")
            || request.path.ends_with(".png")
        {
            image_requests.push(json!({
                "order": request.order,
                "host": request.host,
                "path": request.path,
                "status": request.status,
                "requestId": request.id,
            }));
        }
    }

    let prompt = r#"You will see a CAPTCHA grid (often 3x3) as images numbered 0..8 left-to-right, top-to-bottom.
Identify ALL cells matching the target label (e.g. hat / bicycle / traffic light).
Reply with ONLY a JSON array of indices, no explanation.
Example: [0, 2, 5]"#;

    let has_hook_clicks = hooks
        .iter()
        .any(|hook| hook.kind == "interaction" && hook.name.to_ascii_lowercase().contains("click"));

    json!({
        "enabled": !image_requests.is_empty() || has_hook_clicks,
        "prompt": prompt,
        "grid": { "rows": 3, "cols": 3, "cellSizeHint": 100 },
        "coordinateMapping": {
            "formula": "cellX = originX + (index % cols) * cellW + cellW/2; cellY = originY + floor(index / cols) * cellH + cellH/2",
            "requires": ["originX", "originY", "cellW", "cellH"]
        },
        "candidateImageRequests": image_requests.into_iter().take(20).collect::<Vec<_>>(),
        "llmUsage": {
            "mode": "vision",
            "input": ["prompt", "images[] as data:image/jpeg;base64,..."],
            "output": "JSON array of indices",
            "tool": "shownet_solve_vision_captcha",
            "note": "Call shownet_solve_vision_captcha (screenshot or imageBase64); dryRunIndices skips the model for offline tests"
        },
        "submitHints": [
            "Map indices to CDP clicks via shownet_map_vision_captcha_indices or solve tool click=true",
            "For AWS WAF captcha, preserve state/key/hmac_tag and submit goku_props snake_case if that flow is captured"
        ]
    })
}

fn sandbox_bootstrap_source(profile: &JsDebugProfile) -> String {
    format!(
        r#"
var globalThis = globalThis || this;
var window = globalThis;
var self = globalThis;
var document = {{ cookie: "", location: {{ href: "https://lab.shownet.local/" }}, createElement: function(){{ return {{}}; }} }};
var navigator = {{
  userAgent: {ua:?},
  platform: {platform:?},
  language: {locale:?},
  languages: {languages},
  hardwareConcurrency: {cores},
  deviceMemory: {memory},
  webdriver: {webdriver}
}};
var screen = {{ width: {width}, height: {height}, colorDepth: 24, availWidth: {width}, availHeight: {height} }};
var console = {{
  log: function(){{
    globalThis.__shownet_logs__ = globalThis.__shownet_logs__ || [];
    globalThis.__shownet_logs__.push(Array.prototype.slice.call(arguments).map(String).join(" "));
  }},
  warn: function(){{ return console.log.apply(console, arguments); }},
  error: function(){{ return console.log.apply(console, arguments); }}
}};
globalThis.__shownet_logs__ = [];
globalThis.__SHOWNET_FIXED_PROFILE__ = {{
  id: {id:?},
  userAgent: navigator.userAgent,
  platform: navigator.platform,
  locale: navigator.language
}};
"#,
        ua = profile.user_agent,
        platform = profile.platform,
        locale = profile.locale,
        languages = serde_json::to_string(&profile.languages).unwrap_or_else(|_| "[]".into()),
        cores = profile.hardware_concurrency,
        memory = profile.device_memory_gb,
        webdriver = if profile.webdriver { "true" } else { "false" },
        width = profile
            .viewport
            .get("width")
            .and_then(Value::as_u64)
            .unwrap_or(1440),
        height = profile
            .viewport
            .get("height")
            .and_then(Value::as_u64)
            .unwrap_or(900),
        id = profile.id,
    )
}

fn profile(
    id: &str,
    label: &str,
    ua: &str,
    width: u32,
    height: u32,
    locale: &str,
    timezone: &str,
    platform: &str,
    cores: u32,
    memory: u32,
    webdriver: bool,
    languages: &[&str],
    notes: &[&str],
) -> JsDebugProfile {
    JsDebugProfile {
        id: id.into(),
        label: label.into(),
        user_agent: ua.into(),
        viewport: json!({ "width": width, "height": height, "deviceScaleFactor": if id.contains("retina") { 2.0 } else { 1.0 } }),
        locale: locale.into(),
        timezone: timezone.into(),
        platform: platform.into(),
        hardware_concurrency: cores,
        device_memory_gb: memory,
        webdriver,
        languages: languages.iter().map(|item| (*item).to_string()).collect(),
        notes: notes.iter().map(|item| (*item).to_string()).collect(),
    }
}

fn top_hosts(requests: &[RequestRecord], limit: usize) -> Vec<String> {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for request in requests {
        *counts.entry(request.host.clone()).or_default() += 1;
    }
    let mut items = counts.into_iter().collect::<Vec<_>>();
    items.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    items
        .into_iter()
        .take(limit)
        .map(|(host, count)| format!("{host}×{count}"))
        .collect()
}

/// CDP expression that reads Lab self-dump after install_lab scripts run.
pub fn lab_state_evaluate_expression() -> &'static str {
    r#"(function(){
  return {
    fixedProfile: globalThis.__SHOWNET_FIXED_PROFILE__ || null,
    objectDump: globalThis.__SHOWNET_OBJECT_DUMP__ || null,
    hijackLog: (globalThis.__SHOWNET_HIJACK_LOG__ || []).slice(-50),
    lab: globalThis.__SHOWNET_LAB__ ? {
      version: globalThis.__SHOWNET_LAB__.version || null,
      markers: globalThis.__SHOWNET_LAB__.markers || null
    } : null
  };
})()"#
}

/// Seed a finishable VJ/AWS-WAF-shaped session (no live airline needed).
pub fn seed_web_risk_fixture_session(storage: &Storage) -> Result<Value, String> {
    use crate::models::{BrowserHookInput, CapturedRequestInput, HeaderEntry};

    let session = storage.create_session(Some("web-risk-lab-fixture".into()))?;
    let session_id = session.id.clone();
    let host = "73472.edge.sdk.awswaf.com";

    let requests = [
        (
            "GET",
            host,
            "/challenge.js",
            200,
            "script",
            Some("/* fixture challenge.js awswaf NetworkBandwidth */ window.AwsWafIntegration={};"),
            None,
        ),
        (
            "GET",
            host,
            "/problem",
            200,
            "xhr",
            Some(r#"{"images":["a.jpg","b.jpg"],"target":"hat"}"#),
            Some("application/json"),
        ),
        (
            "POST",
            host,
            "/verify",
            200,
            "xhr",
            Some(r#"{"success":true,"voucher":"fixture-voucher"}"#),
            Some("application/json"),
        ),
        (
            "POST",
            "www.vietjetair.com",
            "/api/mp_verify",
            200,
            "fetch",
            Some(r#"{"token":"fixture-token"}"#),
            Some("application/json"),
        ),
        (
            "GET",
            host,
            "/captcha/image/0.png",
            200,
            "image",
            None,
            Some("image/png"),
        ),
    ];

    for (index, (method, host, path, status, resource, body, content_type)) in
        requests.into_iter().enumerate()
    {
        let mut response_headers = vec![];
        if let Some(content_type) = content_type {
            response_headers.push(HeaderEntry {
                name: "content-type".into(),
                value: content_type.into(),
            });
        }
        storage.store_request(CapturedRequestInput {
            id: None,
            session_id: session_id.clone(),
            source: "browser".into(),
            source_instance_id: Some("fixture".into()),
            timestamp: Some(1_700_000_000_000 + index as i64),
            method: method.into(),
            scheme: Some("https".into()),
            host: host.into(),
            port: Some(443),
            path: path.into(),
            query: None,
            status,
            resource_type: resource.into(),
            size_bytes: body.map(|text| text.len() as i64).unwrap_or(64),
            duration_ms: 12,
            protocol: "h2".into(),
            tls_version: Some("TLS 1.3".into()),
            tls_fingerprint: None,
            risk_level: "none".into(),
            request_headers: vec![],
            response_headers,
            request_body: if method == "POST" {
                Some(r#"{"fixture":true}"#.into())
            } else {
                None
            },
            response_body: body.map(str::to_string),
            response_body_metadata: None,
            crypto_snippets: None,
            hook: None,
        })?;
    }

    storage.store_browser_hook(BrowserHookInput {
        session_id: session_id.clone(),
        source_instance_id: Some("fixture".into()),
        request_id: None,
        timestamp: Some(1_700_000_000_100),
        kind: "interaction".into(),
        name: "pointer.click".into(),
        url: Some(format!("https://{host}/captcha")),
        method: None,
        input: json!({ "selector": ".captcha-cell", "button": 0, "x": 120, "y": 240 }),
        output: Value::Null,
        stack: None,
        duration_ms: Some(1),
    })?;
    storage.store_browser_hook(BrowserHookInput {
        session_id: session_id.clone(),
        source_instance_id: Some("fixture".into()),
        request_id: None,
        timestamp: Some(1_700_000_000_110),
        kind: "runtime".into(),
        name: "object.dump".into(),
        url: None,
        method: None,
        input: json!({ "paths": ["window.AwsWafIntegration"] }),
        output: json!({ "window.AwsWafIntegration": { "type": "object", "keys": ["getToken"] } }),
        stack: None,
        duration_ms: Some(2),
    })?;

    let lab = build_lab_session(storage, &session_id, Some("chrome-desktop-stable"))?;
    Ok(json!({
        "ok": true,
        "sessionId": session_id,
        "sessionName": session.name,
        "profileId": lab.profile.id,
        "evidence": lab.evidence,
        "visionCaptchaEnabled": lab.vision_captcha.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        "next": [
            "shownet_run_offline_lab_probe",
            "shownet_browser_install_lab (browser running)",
            "shownet_solve_vision_captcha (screenshot or dryRunIndices)",
        ]
    }))
}

/// Offline E2E: fixture session → install scripts contract → object self-dump in sandbox.
pub fn run_offline_lab_probe(
    storage: &Storage,
    session_id: &str,
    profile_id: Option<&str>,
) -> Result<Value, String> {
    let lab = build_lab_session(storage, session_id, profile_id)?;
    let plant = r#"
globalThis.window = globalThis;
globalThis.document = globalThis.document || { cookie: "aws-waf-token=fixture", location: { href: "https://lab.shownet.local/" } };
globalThis.AwsWafIntegration = {
  getToken: function(){ return Promise.resolve("fixture-token"); },
  hasToken: function(){ return true; }
};
globalThis.AwsWafCaptcha = { renderCaptcha: function(){} };
globalThis.gokuProps = {
  key: "fixture-key",
  iv: "fixture-iv",
  context: "fixture-ctx",
  challenge_script: "https://73472.edge.sdk.awswaf.com/challenge.js",
  challenge_url: "https://73472.edge.sdk.awswaf.com/problem"
};
globalThis.grecaptcha = { ready: function(cb){ if (cb) cb(); } };
globalThis.turnstile = { render: function(){} };
globalThis.__SHOWNET_HIJACK_LOG__ = [{
  name: "fetch.hijack",
  method: "POST",
  url: "https://www.vietjetair.com/api/mp_verify",
  input: { body: "{\"fixture\":true}" },
  output: { status: 200 }
}];
"#;
    let source = format!(
        "{plant}\n{};\n{};\n",
        lab.fixed_params_script.trim_end_matches(';'),
        lab.object_dump_script.trim_end_matches(';')
    );
    let dump = eval_js_sandbox(
        &source,
        Some(lab.profile.id.as_str()),
        Some("globalThis.__SHOWNET_OBJECT_DUMP__"),
    )?;

    let dump_ok = dump.ok
        && dump
            .result
            .as_object()
            .map(|object| {
                object.contains_key("window.AwsWafIntegration")
                    || object.contains_key("window.gokuProps")
                    || object
                        .keys()
                        .any(|key| key.contains("AwsWaf") || key.contains("goku"))
            })
            .unwrap_or(false);

    Ok(json!({
        "ok": dump_ok && dump.errors.is_empty(),
        "mode": "offline_sandbox",
        "sessionId": session_id,
        "profileId": lab.profile.id,
        "steps": [
            { "step": "build_lab_session", "ok": true },
            { "step": "fixedParams+objectDump", "ok": dump.ok, "errors": dump.errors, "durationMs": dump.duration_ms },
            { "step": "selfDump", "ok": dump_ok }
        ],
        "objectDump": dump.result,
        "hijackLogSample": json!([{
            "name": "fetch.hijack",
            "url": "https://www.vietjetair.com/api/mp_verify"
        }]),
        "interactionPlan": lab.interaction_plan,
        "visionCaptcha": lab.vision_captcha,
        "agentPlaybook": lab.agent_playbook,
        "limitations": dump.limitations,
        "nextLive": [
            "Launch embedded browser",
            "shownet_browser_install_lab → returns objectDump via labState",
            "shownet_browser_evaluate with lab_state_evaluate_expression if needed",
        ]
    }))
}

/// Parse VLM output into captcha grid indices (JSON array of integers).
pub fn parse_vision_indices(text: &str) -> Result<Vec<u32>, String> {
    let trimmed = text
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();
    // Prefer first [...] span for models that add prose.
    let candidate = if let (Some(start), Some(end)) = (trimmed.find('['), trimmed.rfind(']')) {
        if end >= start {
            &trimmed[start..=end]
        } else {
            trimmed
        }
    } else {
        trimmed
    };
    let value: Value = serde_json::from_str(candidate).map_err(|error| {
        format!(
            "VLM 输出不是 JSON 数组: {error}; raw={}",
            truncate_for_error(text)
        )
    })?;
    let array = value
        .as_array()
        .ok_or_else(|| "VLM 输出必须是索引 JSON 数组，例如 [0,2,5]".to_string())?;
    let mut indices = Vec::with_capacity(array.len());
    for item in array {
        let index = item
            .as_u64()
            .or_else(|| item.as_i64().map(|v| v as u64))
            .or_else(|| item.as_f64().map(|v| v as u64))
            .ok_or_else(|| format!("非法索引: {item}"))?;
        if index > 64 {
            return Err(format!("索引过大: {index}"));
        }
        indices.push(index as u32);
    }
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

/// Map grid cell indices to click centers.
pub fn map_grid_indices_to_points(
    indices: &[u32],
    origin_x: f64,
    origin_y: f64,
    cell_w: f64,
    cell_h: f64,
    cols: u32,
) -> Result<Vec<Value>, String> {
    if cell_w <= 0.0 || cell_h <= 0.0 {
        return Err("cellW/cellH 必须为正".into());
    }
    let cols = cols.max(1);
    Ok(indices
        .iter()
        .map(|index| {
            let col = (*index) % cols;
            let row = (*index) / cols;
            let x = origin_x + f64::from(col) * cell_w + cell_w / 2.0;
            let y = origin_y + f64::from(row) * cell_h + cell_h / 2.0;
            json!({ "index": index, "x": x, "y": y, "row": row, "col": col })
        })
        .collect())
}

/// OpenAI-compatible multimodal user message for vision captcha.
pub fn build_vision_chat_messages(
    prompt: &str,
    image_base64: &str,
    mime: &str,
    target_label: Option<&str>,
) -> Vec<Value> {
    let mime = match mime.trim().to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" | "image/jpeg" => "image/jpeg",
        "webp" | "image/webp" => "image/webp",
        _ => "image/png",
    };
    let label_line = target_label
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|label| format!("\nTarget label for this image: {label}\n"))
        .unwrap_or_default();
    let text = format!("{prompt}{label_line}");
    let data_url = format!("data:{mime};base64,{image_base64}");
    vec![
        json!({
            "role": "system",
            "content": "You solve visual captcha grids for authorized security research. Reply with ONLY a JSON array of matching cell indices."
        }),
        json!({
            "role": "user",
            "content": [
                { "type": "text", "text": text },
                {
                    "type": "image_url",
                    "image_url": { "url": data_url }
                }
            ]
        }),
    ]
}

/// Pure map step: package + indices → click points (no model, no browser).
pub fn apply_vision_indices(
    package: &Value,
    indices: &[u32],
    origin_x: f64,
    origin_y: f64,
    cell_w: Option<f64>,
    cell_h: Option<f64>,
    cols: Option<u32>,
) -> Result<Value, String> {
    let grid = package
        .get("grid")
        .cloned()
        .unwrap_or(json!({ "rows": 3, "cols": 3 }));
    let cols = cols
        .or_else(|| grid.get("cols").and_then(Value::as_u64).map(|v| v as u32))
        .unwrap_or(3);
    let hint = grid
        .get("cellSizeHint")
        .and_then(Value::as_f64)
        .unwrap_or(100.0);
    let cell_w = cell_w.unwrap_or(hint);
    let cell_h = cell_h.unwrap_or(hint);
    let points = map_grid_indices_to_points(indices, origin_x, origin_y, cell_w, cell_h, cols)?;
    Ok(json!({
        "indices": indices,
        "points": points,
        "grid": { "cols": cols, "cellW": cell_w, "cellH": cell_h, "originX": origin_x, "originY": origin_y },
        "cdpClicks": points.iter().map(|point| json!({
            "method": "Input.dispatchMouseEvent",
            "params": {
                "type": "mousePressed",
                "button": "left",
                "clickCount": 1,
                "x": point.get("x"),
                "y": point.get("y")
            }
        })).collect::<Vec<_>>(),
    }))
}

fn truncate_for_error(text: &str) -> String {
    let end = text
        .char_indices()
        .nth(240)
        .map(|(index, _)| index)
        .unwrap_or(text.len());
    let mut out = text[..end].to_string();
    if end < text.len() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CapturedRequestInput, HeaderEntry};
    use crate::storage::Storage;

    fn storage() -> Storage {
        Storage::in_memory().expect("memory")
    }

    #[test]
    fn lists_profiles_and_builds_lab_session() {
        let profiles = list_debug_profiles();
        assert!(profiles.len() >= 3);
        let storage = storage();
        let session = storage.create_session(Some("lab".into())).unwrap();
        let request = CapturedRequestInput {
            id: None,
            session_id: session.id.clone(),
            source: "browser".into(),
            source_instance_id: Some("t".into()),
            timestamp: Some(1),
            method: "GET".into(),
            scheme: Some("https".into()),
            host: "73472.edge.sdk.awswaf.com".into(),
            port: Some(443),
            path: "/x/challenge.js".into(),
            query: None,
            status: 200,
            resource_type: "script".into(),
            size_bytes: 10,
            duration_ms: 1,
            protocol: "h2".into(),
            tls_version: Some("TLS 1.3".into()),
            tls_fingerprint: None,
            risk_level: "none".into(),
            request_headers: vec![],
            response_headers: vec![HeaderEntry {
                name: "content-type".into(),
                value: "application/javascript".into(),
            }],
            request_body: None,
            response_body: Some("/* awswaf */".into()),
            response_body_metadata: None,
            crypto_snippets: None,
            hook: None,
        };
        storage.store_request(request).unwrap();

        let lab = build_lab_session(&storage, &session.id, Some("chrome-desktop-stable")).unwrap();
        assert_eq!(lab.profile.id, "chrome-desktop-stable");
        assert!(lab.hijack_script.contains("fetch"));
        assert!(lab.object_dump_script.contains("AwsWafIntegration"));
        assert!(lab.fixed_params_script.contains("webdriver"));
        assert!(!lab.agent_playbook.is_empty());
        assert!(lab.interaction_plan.get("steps").is_some());
    }

    #[test]
    fn sandbox_eval_runs_with_fixed_profile_globals() {
        let result = eval_js_sandbox(
            "globalThis.__shownet_sandbox_result__ = { ua: navigator.userAgent, wd: navigator.webdriver, w: screen.width };",
            Some("chrome-desktop-stable"),
            Some("globalThis.__shownet_sandbox_result__"),
        )
        .unwrap();
        assert!(result.ok, "{:?}", result.errors);
        // result may be object via JSON stringify path or null fallback; at least no crash
        assert_eq!(result.profile_id, "chrome-desktop-stable");
    }

    #[test]
    fn injected_markers_survive_backslashes_and_newlines() {
        // The old escaping handled the double quote and nothing else, so a
        // marker ending in a backslash escaped the closing quote and the whole
        // injected script failed to parse. It fails inside the page, so the
        // only symptom is a hook that never fires. Confirmed against
        // `node --check` while investigating; asserted here by round-trip,
        // which is the same property without a Node process.
        let hostile = [
            "/api/",
            "a\\",
            "a\"b",
            "a\nb",
            "\\d+",
            "</script>",
            "tab\there",
        ];
        for value in hostile {
            let literal = js_string(value);
            let parsed: String = serde_json::from_str(&literal)
                .unwrap_or_else(|error| panic!("{value:?} produced {literal:?}: {error}"));
            assert_eq!(parsed, value, "literal did not round-trip");
        }

        // And the array as it is actually embedded, not just the helper.
        let script = request_hijack_script(&hostile);
        let line = script
            .lines()
            .find(|line| line.trim_start().starts_with("const MARKERS = ["))
            .expect("script must declare MARKERS");
        let array = line
            .trim_start()
            .trim_start_matches("const MARKERS = ")
            .trim_end_matches(';');
        let decoded: Vec<String> = serde_json::from_str(array)
            .unwrap_or_else(|error| panic!("MARKERS is not a valid array: {array} ({error})"));
        assert_eq!(decoded, hostile);
    }

    #[test]
    fn hijack_script_includes_configured_markers() {
        let script = request_hijack_script(&["mp_verify", "captcha"]);
        assert!(script.contains("mp_verify"));
        assert!(script.contains("captcha"));
        assert!(script.contains("response.clone"));
    }

    #[test]
    fn vision_package_has_prompt_and_grid_mapping() {
        let package = build_vision_captcha_package(&[], &[]);
        assert!(package["prompt"].as_str().unwrap().contains("JSON array"));
        assert_eq!(package["grid"]["rows"], 3);
    }

    #[test]
    fn fixture_session_offline_probe_dumps_objects() {
        let storage = storage();
        let seeded = seed_web_risk_fixture_session(&storage).unwrap();
        let session_id = seeded["sessionId"].as_str().unwrap();
        assert!(seeded["visionCaptchaEnabled"].as_bool().unwrap_or(false));

        let probe =
            run_offline_lab_probe(&storage, session_id, Some("chrome-desktop-stable")).unwrap();
        assert!(
            probe["ok"].as_bool().unwrap_or(false),
            "probe failed: {probe}"
        );
        let dump = &probe["objectDump"];
        assert!(
            dump.get("window.AwsWafIntegration").is_some()
                || dump.get("window.gokuProps").is_some(),
            "dump={dump}"
        );
        assert!(probe["visionCaptcha"]["prompt"]
            .as_str()
            .unwrap()
            .contains("JSON array"));
    }

    #[test]
    fn parse_vision_indices_accepts_fenced_and_prose() {
        assert_eq!(parse_vision_indices("[0, 2, 5]").unwrap(), vec![0, 2, 5]);
        assert_eq!(
            parse_vision_indices("```json\n[1, 1, 3]\n```").unwrap(),
            vec![1, 3]
        );
        assert_eq!(
            parse_vision_indices("cells: [8, 0] match hat").unwrap(),
            vec![0, 8]
        );
    }

    #[test]
    fn map_grid_indices_centers_cells() {
        let points = map_grid_indices_to_points(&[0, 1, 3], 100.0, 200.0, 100.0, 100.0, 3).unwrap();
        assert_eq!(points[0]["x"], 150.0);
        assert_eq!(points[0]["y"], 250.0);
        assert_eq!(points[1]["x"], 250.0);
        assert_eq!(points[2]["x"], 150.0);
        assert_eq!(points[2]["y"], 350.0);
    }

    #[test]
    fn vision_messages_include_image_url_content() {
        let messages = build_vision_chat_messages("pick hats", "AAAA", "png", Some("hat"));
        assert_eq!(messages.len(), 2);
        let content = messages[1]["content"].as_array().unwrap();
        assert!(content.iter().any(|part| part["type"] == "image_url"));
        assert!(content
            .iter()
            .any(|part| part["text"].as_str().unwrap_or_default().contains("hat")));
    }
}
