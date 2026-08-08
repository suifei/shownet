use crate::agent_tools::{self, ToolDefinition};
use crate::analysis;
use crate::models::StartAnalysisInput;
use crate::skills;
use crate::{emit, runtime_status, AppState};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{
    HeaderValue, ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tauri::{AppHandle, Manager};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
enum McpAuthorization {
    Global,
    Analysis(GraphMcpScope),
}

#[derive(Clone)]
struct GraphMcpScope {
    analysis_id: String,
    audit_lock: Arc<tokio::sync::Mutex<()>>,
}

pub struct McpServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl McpServerHandle {
    pub async fn start(address: SocketAddr, app: AppHandle) -> Result<Self, String> {
        if !address.ip().is_loopback() {
            return Err("MCP 服务仅允许监听本机回环地址".to_string());
        }
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("MCP 服务无法监听 {address}: {error}"))?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    incoming = listener.accept() => {
                        let Ok((stream, _)) = incoming else { continue };
                        let app = app.clone();
                        tokio::spawn(async move {
                            let service = service_fn(move |request| {
                                handle_http(request, app.clone())
                            });
                            let _ = http1::Builder::new()
                                .keep_alive(true)
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                }
            }
        });
        Ok(Self {
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

pub fn tool_count(allow_writes: bool) -> usize {
    tool_definitions(allow_writes).len()
}

async fn handle_http(
    request: Request<Incoming>,
    app: AppHandle,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match process_http(request, &app).await {
        Ok(response) => response,
        Err((status, message)) => json_response(
            status,
            json!({ "error": { "code": status.as_u16(), "message": message } }),
        ),
    };
    Ok(response)
}

async fn process_http(
    request: Request<Incoming>,
    app: &AppHandle,
) -> Result<Response<Full<Bytes>>, (StatusCode, String)> {
    if request.uri().path() == "/health" && request.method() == Method::GET {
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "name": "shownet",
                "status": "ok",
                "transport": "streamable-http",
                "protocolVersion": PROTOCOL_VERSION,
            }),
        ));
    }
    if request.uri().path() != "/mcp" {
        return Err((StatusCode::NOT_FOUND, "未找到 MCP 端点".to_string()));
    }
    validate_origin(&request)?;
    let state = app.state::<AppState>();
    let settings = state
        .storage
        .effective_mcp_server_settings()
        .map_err(internal_error)?;
    if !settings.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "MCP 服务已停用".to_string(),
        ));
    }
    let authorization = resolve_authorization(&request, &state, &settings.access_token)?;
    if request.method() != Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Streamable HTTP 端点仅接受 POST".to_string(),
        ));
    }
    let content_type_supported = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().starts_with("application/json"));
    if !content_type_supported {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "MCP 请求必须使用 application/json".to_string(),
        ));
    }
    if let Some(length) = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
    {
        if length > MAX_REQUEST_BYTES {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "MCP 请求体过大".to_string()));
        }
    }
    let accepts_supported = request
        .headers()
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| {
            value.contains("application/json")
                || value.contains("text/event-stream")
                || value.contains("*/*")
        });
    if !accepts_supported {
        return Err((
            StatusCode::NOT_ACCEPTABLE,
            "客户端必须接受 application/json 或 text/event-stream".to_string(),
        ));
    }
    let body = request
        .into_body()
        .collect()
        .await
        .map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                format!("读取 MCP 请求失败: {error}"),
            )
        })?
        .to_bytes();
    if body.len() > MAX_REQUEST_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "MCP 请求体过大".to_string()));
    }
    let message: Value = serde_json::from_slice(&body)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("JSON 解析失败: {error}")))?;
    crate::record_mcp_request_activity(app, &message);
    let response = dispatch_rpc(app, message, settings.allow_writes, &authorization).await;
    Ok(match response {
        Some(value) => json_response(StatusCode::OK, value),
        None => empty_response(StatusCode::ACCEPTED),
    })
}

pub(crate) fn initialize_client_info(message: &Value) -> Option<(String, Option<String>)> {
    if message.get("method").and_then(Value::as_str) != Some("initialize") {
        return None;
    }
    let client = message.get("params")?.get("clientInfo")?;
    let name = client.get("name")?.as_str()?.trim();
    if name.is_empty() {
        return None;
    }
    let name = name.chars().take(64).collect::<String>();
    let version = client
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(32).collect::<String>());
    Some((name, version))
}

async fn dispatch_rpc(
    app: &AppHandle,
    message: Value,
    allow_writes: bool,
    authorization: &McpAuthorization,
) -> Option<Value> {
    let id = message.get("id").cloned();
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return id.map(|id| rpc_error(id, -32600, "无效的 JSON-RPC 请求", None));
    }
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return id.map(|id| rpc_error(id, -32600, "请求缺少 method", None));
    };
    if id.is_none() {
        return None;
    }
    let id = id.unwrap_or(Value::Null);
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": { "listChanged": false },
                "resources": { "subscribe": false, "listChanged": false },
                "prompts": { "listChanged": false },
            },
            "serverInfo": {
                "name": "shownet",
                "title": "ShowNet Traffic Intelligence",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": "ShowNet 提供本机会话、请求、TLS/Hook 与 AI 报告工具。获准读取后返回保留实际值的有界请求详情。",
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({
            "tools": tools_for_authorization(allow_writes, authorization)
        })),
        "tools/call" => call_tool(app, params, allow_writes, authorization).await,
        "resources/list" => Ok(json!({ "resources": resources() })),
        "resources/templates/list" => Ok(json!({
            "resourceTemplates": [{
                "uriTemplate": "shownet://sessions/{sessionId}/report",
                "name": "session-report",
                "title": "会话最新 AI 报告",
                "mimeType": "text/markdown",
            }]
        })),
        "resources/read" => read_resource(app, params),
        "prompts/list" => Ok(json!({ "prompts": prompts() })),
        "prompts/get" => get_prompt(app, params),
        "logging/setLevel" => Ok(json!({})),
        _ => Err((-32601, format!("不支持的方法: {method}"), None)),
    };
    Some(match result {
        Ok(value) => rpc_result(id, value),
        Err((code, message, data)) => rpc_error(id, code, &message, data),
    })
}

async fn call_tool(
    app: &AppHandle,
    params: Value,
    allow_writes: bool,
    authorization: &McpAuthorization,
) -> Result<Value, (i64, String, Option<Value>)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("tools/call 缺少工具名称"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let McpAuthorization::Analysis(scope) = authorization {
        return graph_call_tool(app, scope, name, arguments, allow_writes).await;
    }
    let active_report = running_analysis_report(app, &arguments);
    if let Some(report) = active_report.as_ref() {
        let _ = analysis::emit_agent_activity(
            app,
            report,
            "tool",
            format!("内置 Agent 正在调用 {name}"),
        );
    }
    let result = execute_tool(app, name, arguments, allow_writes).await;
    if let Some(report) = active_report.as_ref() {
        let (phase, message) = if result.is_ok() {
            ("tool-complete", format!("{name} 已返回取证结果"))
        } else {
            ("tool-error", format!("{name} 取证失败"))
        };
        let _ = analysis::emit_agent_activity(app, report, phase, message);
    }
    match result {
        Ok(value) => Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
            }],
            "structuredContent": value,
            "isError": false,
        })),
        Err(error) => Ok(json!({
            "content": [{ "type": "text", "text": error }],
            "isError": true,
        })),
    }
}

async fn graph_call_tool(
    app: &AppHandle,
    scope: &GraphMcpScope,
    name: &str,
    arguments: Value,
    allow_writes: bool,
) -> Result<Value, (i64, String, Option<Value>)> {
    let result = execute_graph_scoped_tool(app, scope, name, arguments, allow_writes).await;
    Ok(match result {
        Ok(value) => json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
            }],
            "structuredContent": value,
            "isError": false,
        }),
        Err(error) => json!({
            "content": [{ "type": "text", "text": error }],
            "isError": true,
        }),
    })
}

async fn execute_graph_scoped_tool(
    app: &AppHandle,
    scope: &GraphMcpScope,
    name: &str,
    arguments: Value,
    allow_writes: bool,
) -> Result<Value, String> {
    let definition = tool_definitions(allow_writes)
        .into_iter()
        .find(|definition| definition.name == name)
        .ok_or_else(|| format!("ShowNet MCP 未提供能力: {name}"))?;
    let state = app.state::<AppState>();
    let report = state.storage.get_analysis_report(&scope.analysis_id)?;
    let node_id = {
        let _audit_guard = scope.audit_lock.lock().await;
        let mut graph_run = state
            .storage
            .get_analysis_graph_run(&scope.analysis_id)?
            .ok_or_else(|| "分析 Graph 运行记录不存在".to_string())?;
        let node_id = graph_run.route_tool(name, &definition.access, graph_now_ms())?;
        state.storage.save_analysis_graph_run(&graph_run)?;
        node_id
    };
    analysis::emit_agent_activity(
        app,
        &report,
        "graph-node",
        format!("GrokBuild 根据证据切换到 {node_id}"),
    )?;

    analysis::emit_agent_activity(
        app,
        &report,
        "tool",
        format!("Graph 节点 {node_id} 正在调用 {name}"),
    )?;
    let started_at = graph_now_ms();
    let result = execute_tool(app, name, arguments, allow_writes).await;
    let finished_at = graph_now_ms();
    {
        let _audit_guard = scope.audit_lock.lock().await;
        let mut graph_run = state
            .storage
            .get_analysis_graph_run(&scope.analysis_id)?
            .ok_or_else(|| "分析 Graph 运行记录不存在".to_string())?;
        graph_run.record_tool_call(
            &node_id,
            name,
            &definition.access,
            result.as_ref().map(|_| ()).map_err(String::as_str),
            started_at,
            finished_at,
        )?;
        state.storage.save_analysis_graph_run(&graph_run)?;
    }
    match &result {
        Ok(_) => {
            analysis::emit_agent_activity(
                app,
                &report,
                "tool-complete",
                format!("{name} 已返回 GrokBuild"),
            )?;
        }
        Err(_) => {
            analysis::emit_agent_activity(
                app,
                &report,
                "tool-error",
                format!("{name} 在 Graph 节点中执行失败"),
            )?;
        }
    }
    result
}

fn graph_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn running_analysis_report(
    app: &AppHandle,
    arguments: &Value,
) -> Option<crate::models::AnalysisReport> {
    let state = app.state::<AppState>();
    let requested_session = arguments.get("sessionId").and_then(Value::as_str);
    let request_id = arguments.get("requestId").and_then(Value::as_str);
    let executions = state.analysis.lock().ok()?.executions.clone();
    let analysis_id = executions
        .iter()
        .find(|(_, execution)| requested_session == Some(execution.session_id.as_str()))
        .map(|(analysis_id, _)| analysis_id.clone())
        .or_else(|| {
            request_id.and_then(|request_id| {
                executions.keys().find_map(|analysis_id| {
                    state
                        .storage
                        .get_analysis_report(analysis_id)
                        .ok()
                        .filter(|report| {
                            report
                                .selected_request_ids
                                .iter()
                                .any(|id| id == request_id)
                        })
                        .map(|_| analysis_id.clone())
                })
            })
        })
        .or_else(|| {
            (executions.len() == 1)
                .then(|| executions.keys().next().cloned())
                .flatten()
        })?;
    state.storage.get_analysis_report(&analysis_id).ok()
}

pub(crate) async fn execute_tool(
    app: &AppHandle,
    name: &str,
    arguments: Value,
    allow_writes: bool,
) -> Result<Value, String> {
    let state = app.state::<AppState>();
    if let Some(result) = agent_tools::execute_read_tool(&state, name, &arguments) {
        return result;
    }
    if let Some(result) = agent_tools::execute_browser_tool(&state, name, &arguments).await {
        require_writes(allow_writes)?;
        return result;
    }
    match name {
        "shownet_runtime_status" => {
            serde_json::to_value(runtime_status(&state)?).map_err(|error| error.to_string())
        }
        "shownet_create_session" => {
            require_writes(allow_writes)?;
            let name = arguments
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let session = state.storage.create_session(name)?;
            emit(app, "session://created", &session)?;
            serde_json::to_value(session).map_err(|error| error.to_string())
        }
        "shownet_delete_session" => {
            require_writes(allow_writes)?;
            let session_id = required_string(&arguments, "sessionId")?;
            state.storage.delete_session(&session_id)?;
            emit(app, "session://deleted", &session_id)?;
            Ok(json!({ "deleted": true, "sessionId": session_id }))
        }
        "shownet_run_analysis" => {
            require_writes(allow_writes)?;
            let input: StartAnalysisInput = serde_json::from_value(arguments)
                .map_err(|error| format!("分析参数无效: {error}"))?;
            let report = analysis::start_analysis(app, &state, input).await?;
            serde_json::to_value(report).map_err(|error| error.to_string())
        }
        "shownet_followup_analysis" => {
            require_writes(allow_writes)?;
            let input: crate::models::FollowupAnalysisInput = serde_json::from_value(arguments)
                .map_err(|error| format!("追问参数无效: {error}"))?;
            let message = analysis::followup_analysis(app, &state, input).await?;
            serde_json::to_value(message).map_err(|error| error.to_string())
        }
        other => {
            if let Some(result) = agent_tools::execute_write_tool(&state, other, &arguments) {
                require_writes(allow_writes)?;
                return result;
            }
            Err(format!("未知的 ShowNet 工具: {name}"))
        }
    }
}

fn tools(allow_writes: bool) -> Vec<Value> {
    tool_definitions(allow_writes)
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

fn tools_for_authorization(allow_writes: bool, authorization: &McpAuthorization) -> Vec<Value> {
    let _ = authorization;
    let definitions = tool_definitions(allow_writes);
    definitions
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

pub(crate) fn tool_definitions(allow_writes: bool) -> Vec<ToolDefinition> {
    let mut tools = vec![definition(
        "shownet_runtime_status",
        "读取 ShowNet 抓包代理、CA 与运行状态",
        json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        "read",
    )];
    tools.extend(agent_tools::read_tool_definitions());
    if allow_writes {
        tools.extend([
            definition("shownet_create_session", "创建新的统一抓包会话", json!({
                "type": "object", "properties": { "name": { "type": "string" } }, "additionalProperties": false
            }), "write"),
            definition("shownet_delete_session", "删除非活动会话及其请求、报告和日志", json!({
                "type": "object", "properties": { "sessionId": { "type": "string" } },
                "required": ["sessionId"], "additionalProperties": false
            }), "write"),
            definition("shownet_run_analysis", "使用当前 AI 配置与分析策略运行内置 Agent，可能产生模型费用", json!({
                "type": "object",
                "properties": {
                    "sessionId": { "type": "string" },
                    "mode": { "type": "string", "enum": ["auto", "api", "security", "performance", "crypto"] },
                    "includeStatic": { "type": "boolean", "default": false },
                    "manualRequestIds": { "type": "array", "items": { "type": "string" }, "default": [] }
                },
                "required": ["sessionId", "mode"],
                "additionalProperties": false
            }), "write"),
            definition("shownet_followup_analysis", "对已完成的分析报告继续追问（可触发工具再取证），可能产生模型费用", json!({
                "type": "object",
                "properties": {
                    "analysisId": { "type": "string" },
                    "question": { "type": "string", "maxLength": 4000 }
                },
                "required": ["analysisId", "question"],
                "additionalProperties": false
            }), "write"),
            definition(
                "shownet_export_analysis_artifacts",
                "将分析报告、协议 schema 与指定语言的算法重播包导出落盘（默认写入应用数据 exports 目录）",
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
                            "description": "可选绝对目录；省略则写入 ShowNet 数据目录 exports/algorithm-replay/"
                        }
                    },
                    "required": ["sessionId"],
                    "additionalProperties": false
                }),
                "write",
            ),
            definition(
                "shownet_export_auto_crawler",
                "将自动爬虫包（多语言 client 源码 + CAPTURE_SHAPE + 分析/测试文档 + 离线校验报告）导出落盘",
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
                "write",
            ),
            definition(
                "shownet_export_evaluation_package",
                "一键导出评估包：evidenceHeader / protocolSchemas / fidelity / scorecard L0-L2 / 分析报告",
                json!({
                    "type": "object",
                    "properties": {
                        "sessionId": { "type": "string" },
                        "analysisId": { "type": "string" },
                        "outputDir": {
                            "type": "string",
                            "description": "可选绝对目录；省略则写入 ShowNet 数据目录 exports/evaluation/"
                        }
                    },
                    "required": ["sessionId"],
                    "additionalProperties": false
                }),
                "write",
            ),
            definition(
                "shownet_run_autonomous_analysis",
                "无 GUI：对已抓取 sessionId 自动 plan skills → 聚合动态防护（含 challenge.js 沙箱 decoder）→ 可选导出算法包",
                json!({
                    "type": "object",
                    "properties": {
                        "sessionId": { "type": "string" },
                        "mode": {
                            "type": "string",
                            "enum": ["auto", "api", "security", "performance", "crypto"],
                            "default": "crypto"
                        },
                        "language": {
                            "type": "string",
                            "enum": ["python", "javascript", "typescript", "go", "rust", "java", "csharp", "c++", "c", "zig"],
                            "description": "若提供则导出算法重播包"
                        },
                        "outputDir": { "type": "string" }
                    },
                    "required": ["sessionId"],
                    "additionalProperties": false
                }),
                "write",
            ),
        ]);
        for definition in agent_tools::extra_write_tool_definitions() {
            tools.push(definition);
        }
        for definition in agent_tools::browser_write_tool_definitions() {
            tools.push(definition);
        }
    }
    tools
}

fn definition(name: &str, description: &str, input_schema: Value, access: &str) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: description.to_string(),
        input_schema,
        access: access.to_string(),
    }
}

fn resources() -> Vec<Value> {
    vec![
        json!({
            "uri": "shownet://sessions",
            "name": "sessions",
            "title": "ShowNet 会话列表",
            "mimeType": "application/json",
        }),
        json!({
            "uri": "shownet://runtime",
            "name": "runtime",
            "title": "ShowNet 运行状态",
            "mimeType": "application/json",
        }),
        json!({
            "uri": "shownet://skills",
            "name": "skills",
            "title": "ShowNet 内置 Skill 注册表",
            "mimeType": "application/json",
        }),
    ]
}

fn read_resource(app: &AppHandle, params: Value) -> Result<Value, (i64, String, Option<Value>)> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("resources/read 缺少 uri"))?;
    let state = app.state::<AppState>();
    let (mime_type, text) = if uri == "shownet://sessions" {
        (
            "application/json",
            serde_json::to_string_pretty(&state.storage.list_sessions().map_err(tool_error)?)
                .map_err(tool_error)?,
        )
    } else if uri == "shownet://runtime" {
        (
            "application/json",
            serde_json::to_string_pretty(&runtime_status(&state).map_err(tool_error)?)
                .map_err(tool_error)?,
        )
    } else if uri == "shownet://skills" {
        (
            "application/json",
            serde_json::to_string_pretty(&skills::built_in_skills()).map_err(tool_error)?,
        )
    } else if let Some(session_id) = uri
        .strip_prefix("shownet://sessions/")
        .and_then(|value| value.strip_suffix("/report"))
    {
        let report = state
            .storage
            .latest_analysis_report(session_id)
            .map_err(tool_error)?
            .ok_or_else(|| tool_error("该会话尚无分析报告"))?;
        ("text/markdown", report.content)
    } else {
        return Err((
            -32002,
            "资源不存在".to_string(),
            Some(json!({ "uri": uri })),
        ));
    };
    Ok(json!({
        "contents": [{ "uri": uri, "mimeType": mime_type, "text": text }]
    }))
}

fn prompts() -> Vec<Value> {
    [
        ("analyze_session", "自动分析 ShowNet 会话", "auto"),
        ("reverse_api", "API 协议逆向", "api"),
        ("security_audit", "安全审计", "security"),
        ("performance_analysis", "性能分析", "performance"),
        ("crypto_reverse", "JS 加密逆向", "crypto"),
    ]
    .into_iter()
    .map(|(name, title, mode)| {
        json!({
            "name": name,
            "title": title,
            "description": format!("使用 ShowNet 内置 Agent 的 {mode} Skill 编排分析会话"),
            "arguments": [
                { "name": "sessionId", "description": "ShowNet 会话 ID", "required": true }
            ]
        })
    })
    .collect()
}

fn get_prompt(app: &AppHandle, params: Value) -> Result<Value, (i64, String, Option<Value>)> {
    let prompt_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("prompts/get 缺少名称"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let session_id = required_string(&arguments, "sessionId").map_err(tool_error)?;
    let mode = match prompt_name {
        "analyze_session" => "auto",
        "reverse_api" => "api",
        "security_audit" => "security",
        "performance_analysis" => "performance",
        "crypto_reverse" => "crypto",
        _ => return Err((-32602, "未知 Prompt".to_string(), None)),
    };
    let state = app.state::<AppState>();
    let requests = state
        .storage
        .list_requests(&session_id, Some(10_000), Some(0))
        .map_err(tool_error)?;
    let plan = skills::build_plan(mode, &requests).map_err(tool_error)?;
    Ok(json!({
        "description": format!("使用 ShowNet 内置 Skill 编排分析会话，已选择 {} 个 Skill", plan.selected_skill_ids.len()),
        "messages": [{
            "role": "user",
            "content": {
                "type": "text",
                "text": format!(
                    "请按以下 ShowNet Skill 计划分析会话 {session_id}：{}。先调用 shownet_list_requests 获取索引，再按需调用计划中的工具取证；所有结论必须引用请求 #order、方法和路径。",
                    plan.selected_skill_ids.join(" -> ")
                )
            }
        }]
    }))
}

fn validate_origin(request: &Request<Incoming>) -> Result<(), (StatusCode, String)> {
    let Some(origin) = request
        .headers()
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(());
    };
    if origin_is_local(origin) {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "拒绝非本机 Origin".to_string()))
    }
}

fn origin_is_local(origin: &str) -> bool {
    let lower = origin.trim().to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "tauri://localhost" | "https://tauri.localhost"
    ) {
        return true;
    }
    let Some(authority_and_path) = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
    else {
        return false;
    };
    let mut parts = authority_and_path.split('/');
    let authority = parts.next().unwrap_or_default();
    if parts.any(|part| !part.is_empty()) || authority.contains('@') {
        return false;
    }
    let host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map(|(host, _)| format!("{host}]"))
            .unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default().to_string()
    };
    matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
}

fn resolve_authorization(
    request: &Request<Incoming>,
    state: &AppState,
    global_token: &str,
) -> Result<McpAuthorization, (StatusCode, String)> {
    let provided = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if provided.is_some_and(|value| constant_time_eq(value.as_bytes(), global_token.as_bytes())) {
        return Ok(McpAuthorization::Global);
    }
    let provided =
        provided.ok_or_else(|| (StatusCode::UNAUTHORIZED, "MCP 访问令牌无效".to_string()))?;
    let runtime = state.analysis.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "AI 分析运行状态已损坏".to_string(),
        )
    })?;
    runtime
        .executions
        .iter()
        .find_map(|(analysis_id, execution)| {
            execution
                .graph_mcp_token
                .as_deref()
                .filter(|token| constant_time_eq(provided.as_bytes(), token.as_bytes()))
                .map(|_| {
                    McpAuthorization::Analysis(GraphMcpScope {
                        analysis_id: analysis_id.clone(),
                        audit_lock: execution.graph_audit_lock.clone(),
                    })
                })
        })
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "MCP 访问令牌无效".to_string()))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn json_response(status: StatusCode, value: Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(value.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "mcp-protocol-version",
        HeaderValue::from_static(PROTOCOL_VERSION),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn empty_response(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

fn invalid_params(message: &str) -> (i64, String, Option<Value>) {
    (-32602, message.to_string(), None)
}

fn tool_error(error: impl ToString) -> (i64, String, Option<Value>) {
    (-32000, error.to_string(), None)
}

fn internal_error(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn required_string(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("缺少参数 {key}"))
}

fn require_writes(allow_writes: bool) -> Result<(), String> {
    if allow_writes {
        Ok(())
    } else {
        Err("MCP 写入型工具未启用，请在 ShowNet 设置中显式开启".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_token_check_requires_exact_match() {
        assert!(constant_time_eq(b"shownet_mcp_abc", b"shownet_mcp_abc"));
        assert!(!constant_time_eq(b"shownet_mcp_abc", b"shownet_mcp_abd"));
        assert!(!constant_time_eq(b"short", b"longer"));

        // The three above all pass without the length guard: zip stops at the
        // shorter side, and "short" already differs from "longer" at the first
        // byte. A prefix is what separates them — drop the guard and a client
        // sending any leading slice of the real token authenticates, an empty
        // one included.
        assert!(!constant_time_eq(b"shownet_mcp", b"shownet_mcp_abc"));
        assert!(!constant_time_eq(b"shownet_mcp_abc", b"shownet_mcp"));
        assert!(!constant_time_eq(b"", b"shownet_mcp_abc"));
        assert!(!constant_time_eq(b"shownet_mcp_abc", b""));
    }

    #[test]
    fn initialize_client_info_is_bounded_and_ignores_other_requests() {
        let message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "Codex Desktop",
                    "version": "1.2.3",
                }
            }
        });
        assert_eq!(
            initialize_client_info(&message),
            Some(("Codex Desktop".to_string(), Some("1.2.3".to_string())))
        );
        assert!(initialize_client_info(&json!({
            "method": "tools/list",
            "params": { "clientInfo": { "name": "ignored" } }
        }))
        .is_none());
    }

    #[test]
    fn write_tools_are_hidden_until_enabled() {
        let read_names: Vec<String> = tools(false)
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_string))
            .collect();
        let write_names: Vec<String> = tools(true)
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_string))
            .collect();

        // Read surface must include protection aggregation + challenge decoder.
        for required in [
            "shownet_analyze_dynamic_protection",
            "shownet_decode_challenge_js",
            "shownet_list_skills",
            "shownet_plan_analysis",
        ] {
            assert!(
                read_names.iter().any(|name| name == required),
                "missing read tool {required}; have {read_names:?}"
            );
        }

        // Write tools only appear when enabled.
        for write_only in [
            "shownet_run_analysis",
            "shownet_export_analysis_artifacts",
            "shownet_export_auto_crawler",
            "shownet_run_autonomous_analysis",
            "shownet_create_session",
            "shownet_delete_session",
            "shownet_browser_click",
            "shownet_browser_screenshot",
            "shownet_browser_evaluate",
            "shownet_browser_navigate",
            "shownet_browser_install_lab",
            "shownet_seed_web_risk_fixture",
            "shownet_solve_vision_captcha",
        ] {
            assert!(
                !read_names.iter().any(|name| name == write_only),
                "write tool {write_only} leaked into read-only surface"
            );
            assert!(
                write_names.iter().any(|name| name == write_only),
                "missing write tool {write_only}; have {write_names:?}"
            );
        }

        assert!(tool_count(true) > tool_count(false));
        assert_eq!(tool_count(false), read_names.len());
        assert_eq!(tool_count(true), write_names.len());
    }

    #[test]
    fn origin_validation_rejects_dns_rebinding_hosts() {
        assert!(origin_is_local("http://127.0.0.1:1420"));
        assert!(origin_is_local("https://localhost"));
        assert!(origin_is_local("http://[::1]:3000"));
        assert!(!origin_is_local("http://localhost.example.com"));
        assert!(!origin_is_local("https://127.0.0.1.example.com"));
        assert!(!origin_is_local("null"));
    }
}
