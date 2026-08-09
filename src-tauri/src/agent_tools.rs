use crate::algorithm_replay;
use crate::analysis;
use crate::analysis_pipeline;
use crate::auto_crawler;
use crate::challenge_decoder;
use crate::crypto_code;
use crate::interchange::generate_code;
use crate::protection_analysis;
use crate::px_analysis;
use crate::scorecard;
use crate::signature_adapter;
use crate::skills;
use crate::tls_outbound;
use crate::web_risk_lab;
use crate::AppState;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub access: String,
}

pub fn read_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            "shownet_list_sessions",
            "列出 ShowNet 统一抓包会话及来源统计",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
        tool(
            "shownet_list_requests",
            "列出会话请求摘要；查询参数保留实际值并受统一长度上限约束",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 200 }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_get_request",
            "按请求 ID 读取完整标头、正文、正文解码状态、TLS 指纹和关联 Hook",
            json!({
                "type": "object",
                "properties": { "requestId": { "type": "string" } },
                "required": ["requestId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_get_hooks",
            "读取会话中已关联的加密 Hook 及完整输入输出",
            json!({
                "type": "object",
                "properties": { "sessionId": { "type": "string" } },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_get_crypto_snippets",
            "按请求 ID 读取从 JavaScript 语法树提取的完整有界加密代码片段",
            json!({
                "type": "object",
                "properties": { "requestId": { "type": "string" } },
                "required": ["requestId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_get_websocket_frames",
            "按请求 ID 读取保留实际值的有界 WebSocket 消息、方向和控制帧",
            json!({
                "type": "object",
                "properties": {
                    "requestId": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 2000, "default": 500 }
                },
                "required": ["requestId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_get_sse_events",
            "按请求 ID 读取保留实际值的有界 SSE 事件、字段、注释与流完整性证据",
            json!({
                "type": "object",
                "properties": {
                    "requestId": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 2000, "default": 500 }
                },
                "required": ["requestId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_get_tls_fingerprints",
            "读取会话的入站 JA3/JA4、HTTP/2 SETTINGS/窗口/优先级特征与独立出站 TLS 说明（抓包后证据增强；分析取证只读）",
            json!({
                "type": "object",
                "properties": { "sessionId": { "type": "string" } },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_get_outbound_tls_status",
            "读取当前 MITM 出站 TLS 预置、engine、ja3Parity、supportsFullBrowserJa3 与诚实说明（rustls 配方，不宣称位级浏览器 JA3 全量对齐；分析取证只读）",
            json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_list_px_evidence",
            "列出会话中 PerimeterX/HUMAN/ecData 相关请求证据摘要（抓包后证据；结构线索，非无密钥硬破）",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 200 }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_decode_px_payload",
            "对单条请求做 PerimeterX 相关载荷结构解码（字段形态解析，非无密钥硬破；分析取证只读）",
            json!({
                "type": "object",
                "properties": { "requestId": { "type": "string" } },
                "required": ["requestId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_analyze_dynamic_protection",
            "按会话聚合 AWS WAF、Akamai、Cloudflare、reCAPTCHA 等动态防护证据，输出 challenge/captcha/telemetry/token 时序、协议字段 schema、JS 静态特征、PoW/AES-GCM/混淆线索与未捕获项",
            json!({
                "type": "object",
                "properties": { "sessionId": { "type": "string" } },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_get_report",
            "读取会话最新的 AI 分析报告",
            json!({
                "type": "object",
                "properties": { "sessionId": { "type": "string" } },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_get_skill_runs",
            "读取会话最新分析的 Skill 版本、权限、工具调用、状态与耗时审计记录",
            json!({
                "type": "object",
                "properties": { "sessionId": { "type": "string" } },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_generate_code",
            "为请求生成包含完整标头、Cookie、认证和正文值的调用代码",
            json!({
                "type": "object",
                "properties": {
                    "requestId": { "type": "string" },
                    "template": { "type": "string", "enum": ["curl", "httpie", "python", "java", "fetch", "axios", "go"] }
                },
                "required": ["requestId", "template"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_build_signature_harness",
            "根据完整会话证据生成版本化 AWS WAF/Akamai/通用动态签名适配器清单与凭据运行时注入的 Node.js 重放骨架",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "adapter": {
                        "type": "string",
                        "enum": ["auto", "aws-waf-bot-control", "akamai-bot-manager", "generic-dynamic-signature"],
                        "default": "auto"
                    }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_build_algorithm_replay",
            "从分析报告/Hook/代码片段/协议 schema 还原算法流水线，生成 ALGORITHM_SPEC 与可校验的多语言重播实现（VMP 走 trace 混合策略；不嵌入密钥/token）",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "language": {
                        "type": "string",
                        "enum": ["python", "javascript", "typescript", "go", "rust", "java", "csharp", "c++", "c", "zig"],
                        "default": "python",
                        "description": "目标编程语言；也接受 py/js/ts/golang/cpp/cxx 等别名"
                    }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_build_auto_crawler",
            "从抓包会话生成自动爬虫/客户端包：多语言依赖尽量少的 client 源码、JA3/JA4 保真标签、代理 env、算法还原模式、CAPTURE_SHAPE 与离线 validate-against-capture 报告（不嵌入密钥/token）",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "language": {
                        "type": "string",
                        "enum": ["python", "javascript", "typescript", "go", "rust", "java", "csharp", "c++", "c", "zig"],
                        "default": "python",
                        "description": "目标编程语言；也接受 py/js/ts/golang 等别名"
                    }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_decode_challenge_js",
            "对会话中 challenge.js（或给定 requestId 的脚本体）运行受限沙箱 string-array decoder，恢复完整配置候选",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "requestId": {
                        "type": "string",
                        "description": "可选；省略时自动选择路径含 challenge.js 的脚本请求"
                    }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_eval_scorecard",
            "按自裁判 rubric 机检 A/B/C 与加权综合分：可对 golden fixture 或已有 sessionId 跑真实 decoder + protocolSchemas + 自治流水线门控（无人工改分）",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": {
                        "type": "string",
                        "description": "可选；省略时使用内置 AWS WAF golden fixture（portable 满分门控）"
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["auto", "api", "security", "performance", "crypto"],
                        "default": "crypto"
                    },
                    "outputPath": {
                        "type": "string",
                        "description": "可选；写入 scorecard.json 的本地路径"
                    }
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_list_js_debug_profiles",
            "列出 Web 风控调试固定参数档（UA/viewport/locale/webdriver 等），便于 Agent 稳定复现实验",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
        tool(
            "shownet_build_web_risk_lab",
            "为会话生成 Web 风控研究 lab：固定参数注入脚本、请求体劫持脚本、对象自吐脚本、物理点击 CDP 计划、视觉验证码 prompt 包",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "profileId": {
                        "type": "string",
                        "description": "调试档 id，默认 chrome-desktop-stable"
                    }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_eval_js_sandbox",
            "在受限 JS 沙箱中虚拟运行代码片段（注入固定 navigator/screen 等，无网络/无真实 DOM）",
            json!({
                "type": "object",
                "properties": {
                    "source": { "type": "string", "description": "要执行的 JS 源码片段" },
                    "expression": {
                        "type": "string",
                        "description": "可选表达式，结果写入 __shownet_sandbox_result__"
                    },
                    "profileId": { "type": "string" }
                },
                "required": ["source"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_build_request_hijack_script",
            "生成请求/响应体劫持脚本（fetch/XHR），按 URL 标记过滤并回传 Hook",
            json!({
                "type": "object",
                "properties": {
                    "urlMarkers": {
                        "type": "array",
                        "items": { "type": "string" },
                        "default": ["awswaf", "mp_verify", "telemetry", "captcha", "sensor"]
                    }
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_build_object_dump_script",
            "生成 JS 对象 Hook 自吐脚本（AwsWafIntegration/grecaptcha/gokuProps 等路径摘要）",
            json!({
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "globalThis 点分路径；省略使用默认风控对象集"
                    }
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_plan_physical_interactions",
            "根据会话 interaction Hook 与 captcha 线索生成物理点击/CDP 鼠标序列计划",
            json!({
                "type": "object",
                "properties": { "sessionId": { "type": "string" } },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_build_vision_captcha_package",
            "生成视觉验证码研究包：VLM prompt、3x3 宫格坐标映射、候选图片请求与提交提示",
            json!({
                "type": "object",
                "properties": { "sessionId": { "type": "string" } },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_run_offline_lab_probe",
            "离线 E2E：基于会话 Lab 脚本在沙箱注入 fixture 对象并读取 objectDump（无需浏览器）",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "profileId": { "type": "string" }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_map_vision_captcha_indices",
            "将宫格索引映射为点击坐标与 CDP 鼠标序列（纯本地，不调用模型）",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "indices": {
                        "type": "array",
                        "items": { "type": "integer" },
                        "description": "VLM 返回的格子索引，如 [0,2,5]"
                    },
                    "originX": { "type": "number", "default": 0 },
                    "originY": { "type": "number", "default": 0 },
                    "cellW": { "type": "number" },
                    "cellH": { "type": "number" },
                    "cols": { "type": "integer", "default": 3 }
                },
                "required": ["sessionId", "indices"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_list_skills",
            "列出内置 Skill 的版本、触发规则、权限、工具与输出契约",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
        tool(
            "shownet_plan_analysis",
            "根据会话证据和分析模式生成内置 Agent 的 Skill 与工具执行计划",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "mode": { "type": "string", "enum": ["auto", "api", "security", "performance", "crypto"], "default": "auto" }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
    ]
}

pub fn definitions_for_names(names: &[String]) -> Vec<ToolDefinition> {
    let mut definitions = read_tool_definitions()
        .into_iter()
        .filter(|definition| names.iter().any(|name| name == &definition.name))
        .collect::<Vec<_>>();
    // Write / browser tools may be authorized by Skill plans even if not in read_tool_definitions.
    for definition in extra_write_tool_definitions()
        .into_iter()
        .chain(browser_write_tool_definitions())
    {
        if names.iter().any(|name| name == &definition.name)
            && !definitions.iter().any(|item| item.name == definition.name)
        {
            definitions.push(definition);
        }
    }
    definitions
}

#[cfg(test)]
pub fn mcp_tool_values() -> Vec<Value> {
    read_tool_definitions()
        .into_iter()
        .map(|definition| {
            json!({
                "name": definition.name,
                "description": definition.description,
                "inputSchema": definition.input_schema,
            })
        })
        .collect()
}

pub fn openai_tool_values(definitions: &[ToolDefinition]) -> Vec<Value> {
    definitions
        .iter()
        .map(|definition| {
            json!({
                "type": "function",
                "function": {
                    "name": definition.name,
                    "description": definition.description,
                    "parameters": definition.input_schema,
                    "strict": false,
                }
            })
        })
        .collect()
}

pub fn execute_read_tool(
    state: &AppState,
    name: &str,
    arguments: &Value,
) -> Option<Result<Value, String>> {
    let result = match name {
        "shownet_list_sessions" => state
            .storage
            .list_sessions()
            .and_then(|sessions| serde_json::to_value(sessions).map_err(|error| error.to_string())),
        "shownet_list_requests" => list_requests(state, arguments),
        "shownet_get_request" => get_request(state, arguments),
        "shownet_get_hooks" => get_hooks(state, arguments),
        "shownet_get_crypto_snippets" => get_crypto_snippets(state, arguments),
        "shownet_get_websocket_frames" => get_websocket_frames(state, arguments),
        "shownet_get_sse_events" => get_sse_events(state, arguments),
        "shownet_get_tls_fingerprints" => get_tls_fingerprints(state, arguments),
        "shownet_get_outbound_tls_status" => Ok(tls_outbound::status_json()),
        "shownet_list_px_evidence" => list_px_evidence_tool(state, arguments),
        "shownet_decode_px_payload" => decode_px_payload_tool(state, arguments),
        "shownet_analyze_dynamic_protection" => analyze_dynamic_protection(state, arguments),
        "shownet_get_report" => {
            let session_id = match required_string(arguments, "sessionId") {
                Ok(value) => value,
                Err(error) => return Some(Err(error)),
            };
            state
                .storage
                .latest_analysis_report(&session_id)
                .and_then(|report| serde_json::to_value(report).map_err(|error| error.to_string()))
        }
        "shownet_get_skill_runs" => get_skill_runs(state, arguments),
        "shownet_generate_code" => generate_request_code(state, arguments),
        "shownet_build_signature_harness" => build_signature_harness(state, arguments),
        "shownet_build_algorithm_replay" => build_algorithm_replay_tool(state, arguments),
        "shownet_build_auto_crawler" => build_auto_crawler_tool(state, arguments),
        "shownet_decode_challenge_js" => decode_challenge_js_tool(state, arguments),
        "shownet_eval_scorecard" => eval_scorecard_tool(state, arguments),
        "shownet_list_js_debug_profiles" => {
            serde_json::to_value(web_risk_lab::list_debug_profiles())
                .map_err(|error| error.to_string())
        }
        "shownet_build_web_risk_lab" => build_web_risk_lab_tool(state, arguments),
        "shownet_eval_js_sandbox" => eval_js_sandbox_tool(arguments),
        "shownet_build_request_hijack_script" => build_hijack_script_tool(arguments),
        "shownet_build_object_dump_script" => build_object_dump_tool(arguments),
        "shownet_plan_physical_interactions" => plan_physical_interactions_tool(state, arguments),
        "shownet_build_vision_captcha_package" => build_vision_captcha_tool(state, arguments),
        "shownet_run_offline_lab_probe" => run_offline_lab_probe_tool(state, arguments),
        "shownet_map_vision_captcha_indices" => map_vision_captcha_indices_tool(state, arguments),
        "shownet_list_skills" => {
            serde_json::to_value(skills::built_in_skills()).map_err(|error| error.to_string())
        }
        "shownet_plan_analysis" => plan_analysis(state, arguments),
        _ => return None,
    };
    Some(result)
}

fn build_web_risk_lab_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let profile_id = arguments.get("profileId").and_then(Value::as_str);
    let lab = web_risk_lab::build_lab_session(&state.storage, &session_id, profile_id)?;
    serde_json::to_value(lab).map_err(|error| error.to_string())
}

fn eval_js_sandbox_tool(arguments: &Value) -> Result<Value, String> {
    let source = required_string(arguments, "source")?;
    let expression = arguments.get("expression").and_then(Value::as_str);
    let profile_id = arguments.get("profileId").and_then(Value::as_str);
    let result = web_risk_lab::eval_js_sandbox(&source, profile_id, expression)?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}

fn build_hijack_script_tool(arguments: &Value) -> Result<Value, String> {
    let markers = arguments
        .get("urlMarkers")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| vec!["awswaf", "mp_verify", "telemetry", "captcha", "sensor"]);
    let script = web_risk_lab::request_hijack_script(&markers);
    Ok(
        json!({ "script": script, "urlMarkers": markers, "install": "Page.addScriptToEvaluateOnNewDocument or Runtime.evaluate" }),
    )
}

fn build_object_dump_tool(arguments: &Value) -> Result<Value, String> {
    let default_paths = [
        "window.AwsWafIntegration",
        "window.AwsWafCaptcha",
        "window.grecaptcha",
        "window.turnstile",
        "window.gokuProps",
        "document.cookie",
        "navigator.webdriver",
        "navigator.userAgent",
    ];
    let owned = arguments
        .get("paths")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty());
    let refs: Vec<&str> = match &owned {
        Some(items) => items.iter().map(String::as_str).collect(),
        None => default_paths.to_vec(),
    };
    let script = web_risk_lab::object_hook_dump_script(&refs);
    Ok(json!({ "script": script, "paths": refs, "hookKind": "runtime" }))
}

fn plan_physical_interactions_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let requests = state
        .storage
        .list_requests(&session_id, Some(10_000), Some(0))?;
    let hooks = state.storage.list_browser_hooks(&session_id, Some(2_000))?;
    Ok(web_risk_lab::build_interaction_plan(&hooks, &requests))
}

fn build_vision_captcha_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let requests = state
        .storage
        .list_requests(&session_id, Some(10_000), Some(0))?;
    let hooks = state.storage.list_browser_hooks(&session_id, Some(2_000))?;
    Ok(web_risk_lab::build_vision_captcha_package(
        &requests, &hooks,
    ))
}

/// Write-side export used by MCP when allow_writes is enabled.
pub fn execute_write_tool(
    state: &AppState,
    name: &str,
    arguments: &Value,
) -> Option<Result<Value, String>> {
    let result = match name {
        "shownet_export_analysis_artifacts" => export_analysis_artifacts(state, arguments),
        "shownet_export_auto_crawler" => export_auto_crawler_tool(state, arguments),
        "shownet_build_sdk" => build_sdk_tool(state, arguments),
        "shownet_export_evaluation_package" => export_evaluation_package_tool(state, arguments),
        "shownet_run_autonomous_analysis" => run_autonomous_analysis_tool(state, arguments),
        "shownet_seed_web_risk_fixture" => {
            web_risk_lab::seed_web_risk_fixture_session(&state.storage)
        }
        _ => return None,
    };
    Some(result)
}

/// Async browser bus tools (Agent/MCP execute path).
pub async fn execute_browser_tool(
    state: &AppState,
    name: &str,
    arguments: &Value,
) -> Option<Result<Value, String>> {
    let result = match name {
        "shownet_browser_status" => browser_status_tool(state),
        "shownet_browser_evaluate" => browser_evaluate_tool(state, arguments).await,
        "shownet_browser_click" => browser_click_tool(state, arguments).await,
        "shownet_browser_screenshot" => browser_screenshot_tool(state, arguments).await,
        "shownet_browser_navigate" => browser_navigate_tool(state, arguments).await,
        "shownet_browser_insert_text" => browser_insert_text_tool(state, arguments).await,
        "shownet_browser_install_lab" => browser_install_lab_tool(state, arguments).await,
        "shownet_solve_vision_captcha" => solve_vision_captcha_tool(state, arguments).await,
        _ => return None,
    };
    Some(result)
}

async fn browser_install_lab_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let profile_id = arguments.get("profileId").and_then(Value::as_str);
    let lab = web_risk_lab::build_lab_session(&state.storage, &session_id, profile_id)?;
    let bus = browser_bus(state)?;
    let mut steps = Vec::new();
    for (name, script) in [
        ("fixedParams", lab.fixed_params_script.as_str()),
        ("requestHijack", lab.hijack_script.as_str()),
        ("objectDump", lab.object_dump_script.as_str()),
    ] {
        // objectDump IIFE already returns the report; others just need to run.
        let expression = if name == "objectDump" {
            script.to_string()
        } else {
            // The newline before the semicolon is load-bearing. The script is
            // embedded as code, and the generators in web_risk_lab.rs happen to
            // end in `})();` today — end one in a line comment instead and
            // everything after it on the same line, closing braces included,
            // would be commented out. This costs nothing and removes the
            // dependency rather than leaving it to be discovered.
            format!("(() => {{ {script}\n; return {{ installed: {name:?} }}; }})()")
        };
        let evaluated = bus.evaluate(&expression, false).await?;
        steps.push(json!({
            "step": name,
            "exception": evaluated.exception,
            "value": evaluated.value,
        }));
        if evaluated.exception.is_some() {
            return Ok(json!({
                "ok": false,
                "profileId": lab.profile.id,
                "steps": steps,
                "error": format!("{name} install failed"),
            }));
        }
    }

    let lab_state = bus
        .evaluate(web_risk_lab::lab_state_evaluate_expression(), false)
        .await?;
    let object_dump = lab_state
        .value
        .get("objectDump")
        .cloned()
        .or_else(|| {
            steps
                .iter()
                .find(|step| step.get("step").and_then(Value::as_str) == Some("objectDump"))
                .and_then(|step| step.get("value").cloned())
        })
        .unwrap_or(Value::Null);

    Ok(json!({
        "ok": lab_state.exception.is_none(),
        "profileId": lab.profile.id,
        "sessionId": session_id,
        "steps": steps,
        "labState": lab_state.value,
        "objectDump": object_dump,
        "labStateException": lab_state.exception,
        "next": [
            "shownet_browser_navigate to target if needed",
            "shownet_solve_vision_captcha for grid captcha",
            "shownet_get_hooks to collect hijack/object dumps",
        ],
        "interactionPlan": lab.interaction_plan,
        "visionCaptcha": lab.vision_captcha,
    }))
}

fn run_offline_lab_probe_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let profile_id = arguments.get("profileId").and_then(Value::as_str);
    web_risk_lab::run_offline_lab_probe(&state.storage, &session_id, profile_id)
}

fn map_vision_captcha_indices_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let indices = parse_indices_arg(arguments)?;
    let origin_x = arguments
        .get("originX")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let origin_y = arguments
        .get("originY")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let cell_w = arguments.get("cellW").and_then(Value::as_f64);
    let cell_h = arguments.get("cellH").and_then(Value::as_f64);
    let cols = arguments
        .get("cols")
        .and_then(Value::as_u64)
        .map(|value| value as u32);
    let requests = state
        .storage
        .list_requests(&session_id, Some(10_000), Some(0))?;
    let hooks = state.storage.list_browser_hooks(&session_id, Some(2_000))?;
    let package = web_risk_lab::build_vision_captcha_package(&requests, &hooks);
    let mapped = web_risk_lab::apply_vision_indices(
        &package, &indices, origin_x, origin_y, cell_w, cell_h, cols,
    )?;
    Ok(json!({
        "ok": true,
        "sessionId": session_id,
        "visionCaptcha": package,
        "mapping": mapped,
    }))
}

fn parse_indices_arg(arguments: &Value) -> Result<Vec<u32>, String> {
    let Some(array) = arguments.get("indices").and_then(Value::as_array) else {
        return Err("缺少参数 indices".into());
    };
    let mut indices = Vec::with_capacity(array.len());
    for item in array {
        let index = item
            .as_u64()
            .or_else(|| item.as_i64().map(|value| value as u64))
            .or_else(|| item.as_f64().map(|value| value as u64))
            .ok_or_else(|| format!("非法索引: {item}"))?;
        if index > 64 {
            return Err(format!("索引过大: {index}"));
        }
        indices.push(index as u32);
    }
    Ok(indices)
}

async fn solve_vision_captcha_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let requests = state
        .storage
        .list_requests(&session_id, Some(10_000), Some(0))?;
    let hooks = state.storage.list_browser_hooks(&session_id, Some(2_000))?;
    let package = web_risk_lab::build_vision_captcha_package(&requests, &hooks);
    let target_label = arguments.get("targetLabel").and_then(Value::as_str);
    let click = arguments
        .get("click")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let origin_x = arguments
        .get("originX")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let origin_y = arguments
        .get("originY")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let cell_w = arguments.get("cellW").and_then(Value::as_f64);
    let cell_h = arguments.get("cellH").and_then(Value::as_f64);
    let cols = arguments
        .get("cols")
        .and_then(Value::as_u64)
        .map(|value| value as u32);

    // dryRunIndices: offline path without model or screenshot.
    let (indices, model_text, image_meta) = if let Some(array) =
        arguments.get("dryRunIndices").and_then(Value::as_array)
    {
        let mut indices = Vec::new();
        for item in array {
            let index = item
                .as_u64()
                .or_else(|| item.as_i64().map(|value| value as u64))
                .ok_or_else(|| format!("dryRunIndices 非法: {item}"))?;
            indices.push(index as u32);
        }
        (
            indices,
            Value::String("dry-run".into()),
            json!({ "source": "dryRunIndices" }),
        )
    } else {
        let format = arguments
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("png");
        let (image_base64, image_source, mime) =
            if let Some(base64) = arguments.get("imageBase64").and_then(Value::as_str) {
                if base64.trim().is_empty() {
                    return Err("imageBase64 不能为空".into());
                }
                if base64.len() > 6_000_000 {
                    return Err("imageBase64 过大（上限约 4.5MB 二进制）".into());
                }
                (
                    base64.to_string(),
                    "argument",
                    if format.eq_ignore_ascii_case("jpeg") || format.eq_ignore_ascii_case("jpg") {
                        "image/jpeg"
                    } else {
                        "image/png"
                    },
                )
            } else {
                let bus = browser_bus(state)?;
                let shot = bus.screenshot(format).await?;
                let mime = if shot.format == "jpeg" {
                    "image/jpeg"
                } else {
                    "image/png"
                };
                (shot.base64, "browser_screenshot", mime)
            };

        let prompt = package
            .get("prompt")
            .and_then(Value::as_str)
            .unwrap_or("Return JSON array of captcha cell indices.");
        let messages =
            web_risk_lab::build_vision_chat_messages(prompt, &image_base64, mime, target_label);
        let settings = state.storage.effective_ai_provider_settings()?;
        if settings.base_url.trim().is_empty() {
            return Err("未配置 AI Base URL，无法调用视觉模型；可用 dryRunIndices 离线映射".into());
        }
        let upstream = state.storage.effective_upstream_proxy()?;
        let client = analysis::build_egress_client(&upstream, &settings.base_url)?;
        let raw = analysis::chat_completion_once(&client, &settings, &messages).await?;
        let indices = web_risk_lab::parse_vision_indices(&raw)?;
        (
            indices,
            Value::String(raw),
            json!({
                "source": image_source,
                "format": format,
                "bytesApprox": image_base64.len() * 3 / 4,
            }),
        )
    };

    let mapping = web_risk_lab::apply_vision_indices(
        &package, &indices, origin_x, origin_y, cell_w, cell_h, cols,
    )?;

    let mut clicks = Vec::new();
    if click {
        let bus = browser_bus(state)?;
        if let Some(points) = mapping.get("points").and_then(Value::as_array) {
            for point in points {
                let x = point.get("x").and_then(Value::as_f64).unwrap_or(0.0);
                let y = point.get("y").and_then(Value::as_f64).unwrap_or(0.0);
                let result = bus.click_xy(x, y).await?;
                clicks.push(json!({
                    "index": point.get("index"),
                    "x": result.x,
                    "y": result.y,
                    "mode": result.mode,
                }));
            }
        }
    }

    Ok(json!({
        "ok": true,
        "sessionId": session_id,
        "indices": indices,
        "mapping": mapping,
        "clicks": clicks,
        "clicked": click,
        "modelText": model_text,
        "image": image_meta,
        "visionCaptcha": package,
        "next": [
            if click { "Verify page state / submit captcha flow from capture evidence" }
            else { "Re-run with click=true after confirming originX/Y/cell sizes" },
            "shownet_get_hooks / shownet_analyze_dynamic_protection for protocol correlation",
        ],
    }))
}

fn browser_status_tool(state: &AppState) -> Result<Value, String> {
    let mut guard = state
        .browser
        .lock()
        .map_err(|_| "浏览器运行状态已损坏".to_string())?;
    let status = guard.as_mut().map(|handle| handle.status());
    serde_json::to_value(status).map_err(|error| error.to_string())
}

fn browser_bus(state: &AppState) -> Result<std::sync::Arc<crate::browser_bus::BrowserBus>, String> {
    let mut guard = state
        .browser
        .lock()
        .map_err(|_| "浏览器运行状态已损坏".to_string())?;
    let handle = guard
        .as_mut()
        .ok_or_else(|| "内嵌浏览器未启动".to_string())?;
    if !handle.status().running {
        return Err("内嵌浏览器未在运行".into());
    }
    Ok(handle.bus())
}

async fn browser_evaluate_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let expression = required_string(arguments, "expression")?;
    let await_promise = arguments
        .get("awaitPromise")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let bus = browser_bus(state)?;
    let result = bus.evaluate(&expression, await_promise).await?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}

async fn browser_click_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let bus = browser_bus(state)?;
    let result = if let Some(selector) = arguments
        .get("selector")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        bus.click_selector(selector).await?
    } else {
        let x = arguments
            .get("x")
            .and_then(Value::as_f64)
            .ok_or_else(|| "需要 selector 或 x/y".to_string())?;
        let y = arguments
            .get("y")
            .and_then(Value::as_f64)
            .ok_or_else(|| "需要 selector 或 x/y".to_string())?;
        bus.click_xy(x, y).await?
    };
    serde_json::to_value(result).map_err(|error| error.to_string())
}

async fn browser_screenshot_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let format = arguments
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("png");
    let bus = browser_bus(state)?;
    let result = bus.screenshot(format).await?;
    // Cap huge payloads in tool responses by returning metadata + prefix only when large
    let mut value = serde_json::to_value(&result).map_err(|error| error.to_string())?;
    if result.base64.len() > 120_000 {
        let prefix: String = result.base64.chars().take(256).collect();
        value["base64"] = json!(format!(
            "{prefix}…[TRUNCATED {} chars; use Tauri browser_screenshot for full frame]",
            result.base64.len()
        ));
        value["truncatedInToolResponse"] = json!(true);
    }
    Ok(value)
}

async fn browser_navigate_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let url = required_string(arguments, "url")?;
    let bus = browser_bus(state)?;
    bus.navigate(&url).await
}

async fn browser_insert_text_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let text = required_string(arguments, "text")?;
    let bus = browser_bus(state)?;
    bus.insert_text(&text).await
}

pub fn browser_write_tool_definitions() -> Vec<ToolDefinition> {
    let mut definitions = vec![
        tool(
            "shownet_browser_status",
            "读取统一 Browser 执行总线状态（内嵌代理 Chrome 是否运行）",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
        tool(
            "shownet_browser_evaluate",
            "通过统一 Browser 总线执行 Runtime.evaluate（点/截/评中的「评」）",
            json!({
                "type": "object",
                "properties": {
                    "expression": { "type": "string" },
                    "awaitPromise": { "type": "boolean", "default": false }
                },
                "required": ["expression"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_browser_click",
            "通过统一 Browser 总线物理点击：selector 或 x/y 坐标",
            json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string" },
                    "x": { "type": "number" },
                    "y": { "type": "number" }
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_browser_screenshot",
            "通过统一 Browser 总线截取当前页面（base64 png/jpeg）",
            json!({
                "type": "object",
                "properties": {
                    "format": { "type": "string", "enum": ["png", "jpeg"], "default": "png" }
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_browser_navigate",
            "通过统一 Browser 总线导航到 URL",
            json!({
                "type": "object",
                "properties": { "url": { "type": "string" } },
                "required": ["url"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_browser_insert_text",
            "通过统一 Browser 总线向当前焦点插入文本",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_browser_install_lab",
            "一键在当前页面注入 Web 风控 Lab：固定参数 + 请求劫持 + 对象自吐（基于会话证据），并返回 objectDump",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "profileId": { "type": "string" }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_solve_vision_captcha",
            "视觉验证码：截图或 imageBase64 → VLM 返回格子索引 → 坐标映射；可选 click 点击。dryRunIndices 跳过模型",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "imageBase64": { "type": "string", "description": "可选；省略则 browser_screenshot" },
                    "format": { "type": "string", "enum": ["png", "jpeg"], "default": "png" },
                    "targetLabel": { "type": "string" },
                    "originX": { "type": "number", "default": 0 },
                    "originY": { "type": "number", "default": 0 },
                    "cellW": { "type": "number" },
                    "cellH": { "type": "number" },
                    "cols": { "type": "integer", "default": 3 },
                    "click": { "type": "boolean", "default": false },
                    "dryRunIndices": {
                        "type": "array",
                        "items": { "type": "integer" },
                        "description": "离线测试：跳过 VLM，直接使用这些索引"
                    }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
    ];
    for definition in &mut definitions {
        definition.access = "write".to_string();
    }
    definitions
}

/// Write-only tool definitions that are not browser-bus tools.
pub fn extra_write_tool_definitions() -> Vec<ToolDefinition> {
    let mut definitions = vec![
        tool(
            "shownet_build_sdk",
            "把一次抓包归纳成端点并生成 Python API SDK（curl_cffi + 指纹自检 + 已验证的加解密）；未经抓包证实的部分写入 GAPS.md 而不是省略。\n\n不带 curation 时返回的是原始提议：抓包里所有看起来像接口的东西，包括风控、埋点、CDN 探针。哪些属于这个站点的 API 是关于站点的判断，本工具不替你做——把厂商路径写进软件只会在下一个没人见过的厂商面前失效。\n\n建议先不带 curation 调一次拿到提议，用 shownet_get_request / shownet_list_requests 看证据，再带 curation 调一次。drop 的每一条都要写 reason，它会进 GAPS.md 供人复核。是否可用由用户的 MCP 写入设置决定",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "outputDir": { "type": "string" },
                    "curation": {
                        "type": "object",
                        "description": "对提议出来的接口面的判断。缺省表示照单全收。",
                        "properties": {
                            "drop": {
                                "type": "array",
                                "description": "判定不属于本 API 的操作。每条都要给理由——理由会写进 GAPS.md，读的人可以不同意。",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "operationId": { "type": "string" },
                                        "reason": { "type": "string" }
                                    },
                                    "required": ["operationId", "reason"],
                                    "additionalProperties": false
                                }
                            },
                            "rename": {
                                "type": "object",
                                "description": "给生成名字不可用的操作改名，键是 operationId。",
                                "additionalProperties": { "type": "string" }
                            }
                        },
                        "additionalProperties": false
                    }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_seed_web_risk_fixture",
            "创建可结束的 VJ/AWS-WAF 形态 fixture 会话（challenge/captcha/mp_verify + interaction hooks），供 Lab/视觉链路自测",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
        tool(
            "shownet_export_analysis_artifacts",
            "将分析报告、协议 schema 与算法重播包导出到磁盘；是否可用由用户的 MCP 写入设置决定",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "language": {
                        "type": "string",
                        "enum": ["python", "javascript", "typescript", "go", "rust", "java", "csharp", "c++", "c", "zig"],
                        "default": "python"
                    },
                    "outputDir": { "type": "string" }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
        tool(
            "shownet_export_auto_crawler",
            "将自动爬虫包（client 源码 + CAPTURE_SHAPE + 分析/测试文档 + VALIDATION_REPORT）导出到磁盘",
            json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "language": {
                        "type": "string",
                        "enum": ["python", "javascript", "typescript", "go", "rust", "java", "csharp", "c++", "c", "zig"],
                        "default": "python"
                    },
                    "outputDir": {
                        "type": "string",
                        "description": "可选绝对目录；省略则写入 ShowNet 数据目录 exports/auto-crawler/"
                    }
                },
                "required": ["sessionId"],
                "additionalProperties": false
            }),
        ),
    ];
    for definition in &mut definitions {
        definition.access = "write".to_string();
    }
    definitions
}

fn decode_challenge_js_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let request_id = arguments
        .get("requestId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let body = if let Some(request_id) = request_id {
        let requests = state
            .storage
            .list_requests(&session_id, Some(10_000), Some(0))?;
        if !requests.iter().any(|request| request.id == request_id) {
            return Err("requestId 不属于该 sessionId".into());
        }
        state.storage.get_bundle_request(request_id)?.response_body
    } else {
        let requests = state
            .storage
            .list_requests(&session_id, Some(10_000), Some(0))?;
        // Prefer the largest non-empty challenge.js body (sessions may contain empty stubs).
        let mut best: Option<(usize, String)> = None;
        for request in requests {
            let is_candidate = request.path.contains("challenge.js")
                || (request.resource_type == "script"
                    && request.host.to_ascii_lowercase().contains("awswaf")
                    && request.path.contains("challenge"));
            if !is_candidate {
                continue;
            }
            let body = state
                .storage
                .get_bundle_request(&request.id)
                .map(|bundle| bundle.response_body)
                .unwrap_or_default();
            if body.is_empty() || body.starts_with("base64:") {
                continue;
            }
            let score = body.len();
            if best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
                best = Some((score, body));
            }
        }
        let Some((_, body)) = best else {
            return Err("会话中未找到 challenge.js 脚本请求".into());
        };
        body
    };
    serde_json::to_value(challenge_decoder::decode_challenge_js(&body))
        .map_err(|error| error.to_string())
}

fn eval_scorecard_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let mode = arguments
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("crypto");
    let output_path = arguments
        .get("outputPath")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(path) = output_path.as_ref() {
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("outputPath 不能包含 ..".to_string());
        }
    }

    let _ = mode; // reserved for future mode-specific gate weights
    let card = if let Some(session_id) = arguments
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        scorecard::score_session_storage(&state.storage, session_id, false)?
    } else {
        scorecard::run_fixture_scorecard()?
    };

    if let Some(path) = output_path.as_ref() {
        scorecard::write_scorecard_json(path, &card)?;
    }
    Ok(card.to_json())
}

fn run_autonomous_analysis_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let mode = arguments
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("crypto");
    let language = arguments
        .get("language")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let output_dir = arguments
        .get("outputDir")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(path) = output_dir.as_ref() {
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("outputDir 不能包含 ..".to_string());
        }
    }
    let result = analysis_pipeline::run_autonomous_session_analysis(
        &state.storage,
        &session_id,
        mode,
        language,
        output_dir.as_deref(),
    )?;
    // Bound protection payload in tool response
    let summary = analysis_pipeline::pipeline_summary_json(&result);
    Ok(json!({
        "summary": summary,
        "skillPlan": result.skill_plan,
        "stages": result.stages,
        "export": result.export,
        "notes": result.notes,
        "protection": {
            "providerCandidates": result.protection.get("providerCandidates"),
            "protocolSchemas": result.protection.get("protocolSchemas"),
            "evidenceDiscipline": result.protection.get("evidenceDiscipline"),
            "summary": result.protection.get("summary"),
        }
    }))
}

fn build_algorithm_replay_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let language = arguments
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or("python");
    let package = algorithm_replay::build_algorithm_replay(&state.storage, &session_id, language)?;
    // Keep tool payload bounded: omit full report text duplication when huge by summarizing files.
    let mut value = serde_json::to_value(&package).map_err(|error| error.to_string())?;
    truncate_large_file_contents(&mut value, "shownet_export_analysis_artifacts");
    Ok(value)
}

fn build_auto_crawler_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let language = arguments
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or("python");
    let package = auto_crawler::build_auto_crawler(&state.storage, &session_id, language)?;
    let mut value = serde_json::to_value(&package).map_err(|error| error.to_string())?;
    truncate_large_file_contents(&mut value, "shownet_export_auto_crawler");
    Ok(value)
}

fn export_auto_crawler_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let language = arguments
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or("python");
    let output_dir = arguments
        .get("outputDir")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(path) = output_dir.as_ref() {
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("outputDir 不能包含 ..".to_string());
        }
    }
    let exported = auto_crawler::export_auto_crawler(
        &state.storage,
        &session_id,
        language,
        output_dir.as_deref(),
    )?;
    serde_json::to_value(exported).map_err(|error| error.to_string())
}

fn truncate_large_file_contents(value: &mut Value, export_tool: &str) {
    if let Some(files) = value.get_mut("files").and_then(Value::as_array_mut) {
        for file in files.iter_mut() {
            let bytes = file.get("bytes").and_then(Value::as_u64).unwrap_or(0);
            if bytes > 48_000 {
                if let Some(content) = file.get_mut("content") {
                    let text = content.as_str().unwrap_or_default();
                    let end = text
                        .char_indices()
                        .nth(4_000)
                        .map(|(index, _)| index)
                        .unwrap_or(text.len());
                    *content = json!(format!(
                        "{}\n\n/* truncated in tool response; use {export_tool} to write full files */",
                        &text[..end]
                    ));
                }
                file["truncatedInToolResponse"] = json!(true);
            }
        }
    }
}

fn export_analysis_artifacts(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let language = arguments
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or("python");
    let output_dir = arguments
        .get("outputDir")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(path) = output_dir.as_ref() {
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("outputDir 不能包含 ..".to_string());
        }
    }
    let exported = algorithm_replay::export_algorithm_replay(
        &state.storage,
        &session_id,
        language,
        output_dir.as_deref(),
    )?;
    serde_json::to_value(exported).map_err(|error| error.to_string())
}

fn build_sdk_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let output_dir = arguments
        .get("outputDir")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(path) = output_dir.as_ref() {
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("outputDir 不能包含 ..".to_string());
        }
    }
    // The agent's judgement about the surface, if it made one. Absent, the
    // export is the raw proposal — the deterministic layer never decides on its
    // own which endpoints are "the API", because that answer is about the site
    // and would otherwise have to be a vendor list compiled into the binary.
    let curation: Option<crate::sdk_inputs::SdkCuration> = match arguments.get("curation") {
        Some(value) if !value.is_null() => Some(
            serde_json::from_value(value.clone())
                .map_err(|error| format!("curation 结构无效: {error}"))?,
        ),
        _ => None,
    };
    let result = crate::sdk_inputs::export(
        &state.storage,
        &session_id,
        output_dir.as_deref(),
        curation.as_ref(),
    )?;
    // The readiness goes back with the paths, so an agent reporting on this
    // has the gap count in hand and cannot describe a package with holes as a
    // finished SDK.
    serde_json::to_value(result).map_err(|error| error.to_string())
}

fn export_evaluation_package_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let analysis_id = arguments
        .get("analysisId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let output_dir = arguments
        .get("outputDir")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(path) = output_dir.as_ref() {
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("outputDir 不能包含 ..".to_string());
        }
    }
    let exported = crate::evaluation_export::export_evaluation_package(
        &state.storage,
        &session_id,
        analysis_id,
        output_dir.as_deref(),
    )?;
    serde_json::to_value(exported).map_err(|error| error.to_string())
}

fn get_skill_runs(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let Some(report) = state.storage.latest_analysis_report(&session_id)? else {
        return Ok(json!([]));
    };
    serde_json::to_value(state.storage.list_analysis_skill_runs(&report.id)?)
        .map_err(|error| error.to_string())
}

fn list_requests(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let limit = arguments
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(200)
        .clamp(1, 500);
    let requests = state
        .storage
        .list_requests(&session_id, Some(limit), Some(0))?;
    Ok(Value::Array(
        requests
            .into_iter()
            .map(|request| {
                json!({
                    "id": request.id,
                    "order": request.order,
                    "time": request.time,
                    "method": request.method,
                    "host": request.host,
                    "path": request.path,
                    "query": request.query.as_deref().map(analysis::bounded_query),
                    "status": request.status,
                    "type": request.resource_type,
                    "durationMs": request.duration,
                    "source": request.source,
                    "protocol": request.protocol,
                    "tls": request.tls,
                    "risk": request.risk,
                    "hasHook": request.hook.is_some(),
                    "cryptoSnippetCount": request.crypto_snippet_count,
                })
            })
            .collect(),
    ))
}

fn get_crypto_snippets(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let request_id = required_string(arguments, "requestId")?;
    let request = state.storage.get_bundle_request(&request_id)?;
    let snippets = state
        .storage
        .get_crypto_snippets(&request_id)?
        .into_iter()
        .map(|mut snippet| {
            snippet.code = crypto_code::bounded_code(&snippet.code);
            snippet
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "requestId": request.id,
        "order": request.sequence,
        "host": request.host,
        "path": request.path,
        "snippetCount": snippets.len(),
        "snippets": snippets,
    }))
}

fn get_websocket_frames(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let request_id = required_string(arguments, "requestId")?;
    let limit = arguments
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(500)
        .clamp(1, 2_000);
    let events = state
        .storage
        .list_websocket_events(&request_id, Some(limit))?;
    serde_json::to_value(events).map_err(|error| error.to_string())
}

fn get_sse_events(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let request_id = required_string(arguments, "requestId")?;
    let limit = arguments
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(500)
        .clamp(1, 2_000);
    get_sse_events_from_storage(&state.storage, &request_id, limit)
}

fn get_sse_events_from_storage(
    storage: &crate::storage::Storage,
    request_id: &str,
    limit: i64,
) -> Result<Value, String> {
    let events = storage.list_sse_events(request_id, Some(limit))?;
    serde_json::to_value(events).map_err(|error| error.to_string())
}

fn get_request(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let request_id = required_string(arguments, "requestId")?;
    let request = state.storage.get_bundle_request(&request_id)?;
    let hooks = state
        .storage
        .list_request_browser_hooks(&request_id, Some(100))?;
    Ok(json!({
        "id": request.id,
        "order": request.sequence,
        "source": request.source,
        "startedAt": request.started_at,
        "method": request.method,
        "scheme": request.scheme,
        "host": request.host,
        "port": request.port,
        "path": request.path,
        "query": request.query.as_deref().map(analysis::bounded_query),
        "status": request.status,
        "type": request.resource_type,
        "sizeBytes": request.size_bytes,
        "durationMs": request.duration_ms,
        "protocol": request.protocol,
        "tlsVersion": request.tls_version,
        "risk": request.risk_level,
        "requestHeaders": analysis::bounded_headers(&request.request_headers),
        "responseHeaders": analysis::bounded_headers(&request.response_headers),
        "requestBody": request.request_body.as_deref().map(analysis::bounded_body),
        "responseBody": analysis::bounded_body(&request.response_body),
        "responseBodyCapture": (request.response_body_metadata.captured || request.response_body_metadata.omitted_reason.is_some()).then_some(&request.response_body_metadata),
        "hook": request.hook.map(|hook| json!({
            "algorithm": hook.algorithm,
            "input": analysis::bounded_body(&hook.input),
            "output": analysis::bounded_body(&hook.output),
        })),
        "hooks": hooks,
        "tlsFingerprint": request.tls_fingerprint,
    }))
}

fn get_hooks(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let captured = state.storage.list_browser_hooks(&session_id, Some(2_000))?;
    if !captured.is_empty() {
        return serde_json::to_value(captured).map_err(|error| error.to_string());
    }
    let hooks = state
        .storage
        .list_requests(&session_id, Some(10_000), Some(0))?
        .into_iter()
        .filter_map(|request| {
            request.hook.map(|hook| {
                json!({
                    "requestId": request.id,
                    "order": request.order,
                    "method": request.method,
                    "host": request.host,
                    "path": request.path,
                    "algorithm": hook.algorithm,
                    "input": analysis::bounded_body(&hook.input),
                    "output": analysis::bounded_body(&hook.output),
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(Value::Array(hooks))
}

fn get_tls_fingerprints(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    crate::tls_fingerprint::list_session_tls_fingerprints(&state.storage, &session_id)
}

fn list_px_evidence_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(200)
        .clamp(1, 500);
    let items = px_analysis::list_session_evidence(&state.storage, &session_id, limit)?;
    serde_json::to_value(items).map_err(|error| error.to_string())
}

fn decode_px_payload_tool(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let request_id = required_string(arguments, "requestId")?;
    let decoded = px_analysis::decode_request_payload(&state.storage, &request_id)?;
    serde_json::to_value(decoded).map_err(|error| error.to_string())
}

fn analyze_dynamic_protection(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    protection_analysis::analyze_session(&state.storage, &session_id)
}

fn generate_request_code(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let request_id = required_string(arguments, "requestId")?;
    let template = required_string(arguments, "template")?;
    let request = state.storage.get_bundle_request(&request_id)?;
    Ok(json!({
        "template": template,
        "code": generate_code(&request, &template)?,
    }))
}

fn build_signature_harness(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let adapter = arguments
        .get("adapter")
        .and_then(Value::as_str)
        .unwrap_or("auto");
    let harness = signature_adapter::build_signature_harness(&state.storage, &session_id, adapter)?;
    serde_json::to_value(harness).map_err(|error| error.to_string())
}

fn plan_analysis(state: &AppState, arguments: &Value) -> Result<Value, String> {
    let session_id = required_string(arguments, "sessionId")?;
    let mode = arguments
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("auto");
    let requests = state
        .storage
        .list_requests(&session_id, Some(10_000), Some(0))?;
    serde_json::to_value(skills::build_plan(mode, &requests)?).map_err(|error| error.to_string())
}

fn required_string(arguments: &Value, name: &str) -> Result<String, String> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("缺少参数 {name}"))
}

fn tool(name: &str, description: &str, input_schema: Value) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: description.to_string(),
        input_schema,
        access: "read".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_agent_tool_is_also_an_mcp_tool() {
        let definitions = read_tool_definitions();
        let mcp = mcp_tool_values();
        for definition in definitions {
            assert!(mcp.iter().any(|value| value["name"] == definition.name));
        }
    }

    #[test]
    fn dynamic_protection_aggregation_is_read_tool_with_session_id() {
        let definitions = read_tool_definitions();
        let tool = definitions
            .iter()
            .find(|definition| definition.name == "shownet_analyze_dynamic_protection")
            .expect("shownet_analyze_dynamic_protection must be a built-in read tool");
        assert_eq!(tool.access, "read");
        let required = tool.input_schema["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            required
                .iter()
                .any(|value| value.as_str() == Some("sessionId")),
            "schema={:?}",
            tool.input_schema
        );
        assert!(tool.input_schema["properties"]["sessionId"].is_object());

        let mcp = mcp_tool_values();
        let mcp_tool = mcp
            .iter()
            .find(|value| value["name"] == "shownet_analyze_dynamic_protection")
            .expect("MCP surface must list shownet_analyze_dynamic_protection");
        assert!(mcp_tool["inputSchema"]["properties"]["sessionId"].is_object());
    }

    #[test]
    fn sse_tool_is_read_only_and_preserves_every_textual_evidence_surface() {
        use crate::models::CaptureEventInput;
        use crate::storage::Storage;

        let definition = read_tool_definitions()
            .into_iter()
            .find(|definition| definition.name == "shownet_get_sse_events")
            .expect("shownet_get_sse_events must be a built-in read tool");
        assert_eq!(definition.access, "read");
        assert_eq!(
            definition.input_schema["properties"]["limit"]["maximum"],
            2_000
        );

        let storage = Storage::in_memory().expect("memory");
        let session = storage.create_session(None).expect("session");
        storage
            .append_event(CaptureEventInput {
                session_id: session.id,
                source: "browser".to_string(),
                source_instance_id: Some("browser-1".to_string()),
                request_id: Some("request-sse-agent".to_string()),
                timestamp: Some(1_785_393_200_000),
                phase: "sse".to_string(),
                payload: json!({
                    "kind": "event",
                    "event": "account-update",
                    "id": "event-1",
                    "data": "{\"token\":\"DATA_SECRET\",\"message\":\"ready\"}",
                    "raw": "event: account-update\ndata: {\"access_token\":\"RAW_DATA_SECRET\"}\nauthorization: RAW_FIELD_SECRET\n: token=RAW_COMMENT_SECRET\n\n",
                    "fields": [
                        { "name": "authorization", "value": "FIELD_SECRET" },
                        { "name": "metadata", "value": "token=FIELD_TOKEN_SECRET" }
                    ],
                    "comments": ["token=COMMENT_SECRET"],
                    "error": "authorization: ERROR_SECRET",
                    "sizeBytes": 128,
                    "truncated": false,
                    "incomplete": false,
                    "index": 1
                }),
            })
            .expect("event");

        let result = get_sse_events_from_storage(&storage, "request-sse-agent", 500)
            .expect("complete SSE events");
        let serialized = serde_json::to_string(&result).expect("json");
        for secret in [
            "DATA_SECRET",
            "RAW_DATA_SECRET",
            "RAW_FIELD_SECRET",
            "RAW_COMMENT_SECRET",
            "FIELD_SECRET",
            "FIELD_TOKEN_SECRET",
            "COMMENT_SECRET",
            "ERROR_SECRET",
        ] {
            assert!(
                serialized.contains(secret),
                "missing {secret}: {serialized}"
            );
        }
        assert!(!serialized.contains("[REDACTED]"));
        assert_eq!(result[0]["payload"]["event"], "account-update");
        assert_eq!(result[0]["payload"]["id"], "event-1");
    }

    #[test]
    fn definitions_for_names_includes_browser_bus_tools() {
        let names = vec![
            "shownet_get_request".to_string(),
            "shownet_browser_click".to_string(),
            "shownet_browser_install_lab".to_string(),
            "shownet_solve_vision_captcha".to_string(),
            "shownet_seed_web_risk_fixture".to_string(),
        ];
        let definitions = definitions_for_names(&names);
        assert!(definitions
            .iter()
            .any(|item| item.name == "shownet_get_request"));
        assert!(definitions
            .iter()
            .any(|item| item.name == "shownet_browser_click"));
        assert!(definitions
            .iter()
            .any(|item| item.name == "shownet_browser_install_lab"));
        assert!(definitions
            .iter()
            .any(|item| item.name == "shownet_solve_vision_captcha"));
        assert!(definitions
            .iter()
            .any(|item| item.name == "shownet_seed_web_risk_fixture"));
        assert!(browser_write_tool_definitions()
            .iter()
            .any(|item| item.name == "shownet_browser_install_lab"));
    }

    #[test]
    fn offline_lab_and_vision_tools_finish_without_browser() {
        use crate::storage::Storage;

        let storage = Storage::in_memory().expect("memory");
        let seeded = web_risk_lab::seed_web_risk_fixture_session(&storage).unwrap();
        let session_id = seeded["sessionId"].as_str().unwrap().to_string();
        let probe = web_risk_lab::run_offline_lab_probe(
            &storage,
            &session_id,
            Some("chrome-desktop-stable"),
        )
        .unwrap();
        assert!(probe["ok"].as_bool().unwrap_or(false), "{probe}");
        assert!(probe["objectDump"].is_object() || !probe["objectDump"].is_null());

        let mapped = web_risk_lab::apply_vision_indices(
            &probe["visionCaptcha"],
            &[0, 2, 5],
            10.0,
            20.0,
            Some(80.0),
            Some(80.0),
            Some(3),
        )
        .unwrap();
        assert_eq!(mapped["points"].as_array().unwrap().len(), 3);
        assert!(seeded["ok"].as_bool().unwrap_or(false));
        assert!(read_tool_definitions()
            .iter()
            .any(|item| item.name == "shownet_run_offline_lab_probe"));
        assert!(browser_write_tool_definitions()
            .iter()
            .any(|item| item.name == "shownet_solve_vision_captcha"));
    }
}
