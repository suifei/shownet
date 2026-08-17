use crate::agent_runtime;
use crate::models::{
    AgentRuntimeSettings, EffectiveAiProviderSettings, EffectiveMcpServerSettings,
    EffectiveUpstreamProxy,
};
use crate::skills::{self, SkillPlan};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tauri::{AppHandle, Manager};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, Command};

const AGENT_TURN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;
const API_KEY_ENV: &str = "SHOWNET_AGENT_API_KEY";
const MCP_TOKEN_ENV: &str = "SHOWNET_MCP_TOKEN";
const TURN_LIMIT_ERROR: &str = "内置 Agent 达到最大分析轮次，报告未完整生成";

#[derive(Debug)]
pub struct GrokRunResult {
    pub content: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrokActivity {
    Reasoning,
    Generating,
}

fn normalized_agent_turn_limit(configured: u32) -> u32 {
    configured.max(1)
}

fn agent_runtime_timeout(max_agent_turns: u32) -> Duration {
    AGENT_TURN_TIMEOUT.saturating_mul(normalized_agent_turn_limit(max_agent_turns))
}

#[derive(Debug)]
struct StreamResult {
    content: String,
    saw_end: bool,
}

pub async fn try_run<F, A>(
    app: &AppHandle,
    report_id: &str,
    settings: &EffectiveAiProviderSettings,
    mcp: Option<&EffectiveMcpServerSettings>,
    upstream: &EffectiveUpstreamProxy,
    skill_plan: &SkillPlan,
    max_agent_turns: u32,
    runtime_settings: &AgentRuntimeSettings,
    prompt: &str,
    on_delta: F,
    on_activity: A,
) -> Result<Option<GrokRunResult>, String>
where
    F: FnMut(&str) -> Result<(), String>,
    A: FnMut(GrokActivity) -> Result<(), String>,
{
    let runtime = match agent_runtime::resolve(app, runtime_settings).await {
        Ok(runtime) => runtime,
        Err(_) => return Ok(None),
    };
    let base_dir = app
        .path()
        .app_cache_dir()
        .map_err(|error| format!("无法定位内置 Agent 缓存目录: {error}"))?
        .join("agent-runtime");
    let injected_upstream = runtime_settings.use_upstream_proxy.then_some(upstream);
    run_with_binary(
        &runtime.executable,
        &base_dir,
        report_id,
        settings,
        mcp,
        injected_upstream,
        skill_plan,
        max_agent_turns,
        prompt,
        agent_runtime_timeout(max_agent_turns),
        on_delta,
        on_activity,
    )
    .await
    .map(Some)
}

#[allow(clippy::too_many_arguments)]
async fn run_with_binary<F, A>(
    binary: &Path,
    base_dir: &Path,
    report_id: &str,
    settings: &EffectiveAiProviderSettings,
    mcp: Option<&EffectiveMcpServerSettings>,
    upstream: Option<&EffectiveUpstreamProxy>,
    skill_plan: &SkillPlan,
    max_agent_turns: u32,
    prompt: &str,
    timeout: Duration,
    on_delta: F,
    on_activity: A,
) -> Result<GrokRunResult, String>
where
    F: FnMut(&str) -> Result<(), String>,
    A: FnMut(GrokActivity) -> Result<(), String>,
{
    let run_dir = RunDirectory::create(base_dir, report_id)?;
    write_runtime_files(run_dir.path(), settings, mcp, skill_plan, prompt)?;

    let mut command = Command::new(binary);
    command
        .current_dir(run_dir.path())
        .arg("--prompt-file")
        .arg(run_dir.path().join("prompt.md"))
        .arg("--model")
        .arg("shownet")
        .arg("--output-format")
        .arg("streaming-json")
        .arg("--permission-mode")
        .arg("bypassPermissions")
        .arg("--disable-web-search")
        .args(["--deny", "Bash"])
        .args(["--deny", "Read"])
        .args(["--deny", "Edit"])
        .args(["--deny", "Grep"])
        .args(["--deny", "WebFetch"])
        .arg("--max-turns")
        .arg(normalized_agent_turn_limit(max_agent_turns).to_string())
        .arg("--no-auto-update")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear()
        .env("GROK_HOME", run_dir.path().join("home"))
        .env("GROK_DISABLE_AUTOUPDATER", "1")
        .env("GROK_TELEMETRY_ENABLED", "0")
        .env("GROK_TELEMETRY_TRACE_UPLOAD", "0")
        .env("GROK_EXTERNAL_OTEL", "0")
        .env("OTEL_LOGS_EXPORTER", "none")
        .env("OTEL_METRICS_EXPORTER", "none");
    configure_os_sandbox(&mut command);
    copy_minimum_runtime_environment(&mut command);
    if let Some(api_key) = settings.api_key.as_deref() {
        command.env(API_KEY_ENV, api_key);
    } else {
        command.env_remove(API_KEY_ENV);
    }
    if let Some(mcp) = mcp {
        command.env(MCP_TOKEN_ENV, &mcp.access_token);
    } else {
        command.env_remove(MCP_TOKEN_ENV);
    }
    configure_upstream_proxy(&mut command, upstream, &settings.base_url)?;

    let mut child = command
        .spawn()
        .map_err(|error| format!("无法启动内置 Agent 运行时 {}: {error}", binary.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "内置 Agent 标准输出不可用".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "内置 Agent 错误输出不可用".to_string())?;
    let stderr_task = tokio::spawn(read_stderr(stderr));

    let stream = tokio::time::timeout(
        timeout,
        consume_stream(&mut child, stdout, on_delta, on_activity),
    )
    .await;
    let result = match stream {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            terminate_child(&mut child).await;
            let stderr = stderr_task.await.unwrap_or_default();
            return Err(with_stderr(error, &stderr));
        }
        Err(_) => {
            terminate_child(&mut child).await;
            let stderr = stderr_task.await.unwrap_or_default();
            return Err(with_stderr(
                "内置 Agent 分析超时，已终止运行进程".to_string(),
                &stderr,
            ));
        }
    };
    let stderr = stderr_task.await.unwrap_or_default();
    if !result.saw_end {
        return Err(with_stderr(
            "内置 Agent 未返回结束事件".to_string(),
            &stderr,
        ));
    }
    if result.content.trim().is_empty() {
        return Err(with_stderr("内置 Agent 返回了空报告".to_string(), &stderr));
    }
    Ok(GrokRunResult {
        content: result.content,
    })
}

async fn consume_stream<F, A>(
    child: &mut Child,
    stdout: impl tokio::io::AsyncRead + Unpin,
    mut on_delta: F,
    mut on_activity: A,
) -> Result<StreamResult, String>
where
    F: FnMut(&str) -> Result<(), String>,
    A: FnMut(GrokActivity) -> Result<(), String>,
{
    let mut lines = BufReader::new(stdout).lines();
    let mut total_stdout = 0usize;
    let mut content = String::new();
    let mut saw_end = false;
    let mut reasoning_announced = false;
    let mut generating_announced = false;
    loop {
        let line = lines
            .next_line()
            .await
            .map_err(|error| format!("读取内置 Agent 输出失败: {error}"))?;
        let Some(line) = line else { break };
        total_stdout = total_stdout.saturating_add(line.len());
        if total_stdout > MAX_STDOUT_BYTES {
            return Err("内置 Agent 输出超过安全上限".to_string());
        }
        let value = serde_json::from_str::<Value>(&line)
            .map_err(|_| "内置 Agent 返回了无效的流式事件".to_string())?;
        match value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "text" => {
                if !generating_announced {
                    on_activity(GrokActivity::Generating)?;
                    generating_announced = true;
                }
                let delta = value
                    .get("data")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if content.len().saturating_add(delta.len()) > MAX_REPORT_BYTES {
                    return Err("内置 Agent 报告超过安全上限".to_string());
                }
                content.push_str(delta);
                on_delta(delta)?;
            }
            "thought" => {
                if !reasoning_announced {
                    on_activity(GrokActivity::Reasoning)?;
                    reasoning_announced = true;
                }
            }
            "end" => {
                saw_end = true;
            }
            "error" => {
                let message = value
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("内置 Agent 运行失败");
                if crate::ai_error::extract_ai_provider_error(message).is_some() {
                    return Err(crate::ai_error::format_ai_failure(None, message));
                }
                let serialized = value.to_string();
                if crate::ai_error::extract_from_value(&value)
                    .is_some_and(|error| error.is_terminal())
                {
                    return Err(crate::ai_error::format_ai_failure(None, &serialized));
                }
                return Err(format!("内置 Agent 运行失败: {}", truncate(message, 1_200)));
            }
            "max_turns_reached" => {
                return Err(TURN_LIMIT_ERROR.to_string());
            }
            other => {
                if let Some(error) = crate::ai_error::extract_from_value(&value) {
                    if error.is_terminal() {
                        return Err(crate::ai_error::format_extracted(None, &error));
                    }
                }
                let _ = other;
            }
        }
    }
    let status = child
        .wait()
        .await
        .map_err(|error| format!("等待内置 Agent 退出失败: {error}"))?;
    if !status.success() {
        return Err(format!(
            "内置 Agent 异常退出{}",
            status
                .code()
                .map_or(String::new(), |code| format!("（代码 {code}）"))
        ));
    }
    Ok(StreamResult { content, saw_end })
}

async fn read_stderr(stderr: impl tokio::io::AsyncRead + Unpin) -> String {
    let mut bytes = Vec::new();
    let _ = stderr
        .take(MAX_STDERR_BYTES as u64)
        .read_to_end(&mut bytes)
        .await;
    String::from_utf8_lossy(&bytes).trim().to_string()
}

async fn terminate_child(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn write_runtime_files(
    run_dir: &Path,
    settings: &EffectiveAiProviderSettings,
    mcp: Option<&EffectiveMcpServerSettings>,
    skill_plan: &SkillPlan,
    prompt: &str,
) -> Result<(), String> {
    let home = run_dir.join("home");
    let workspace = run_dir.join("workspace");
    fs::create_dir_all(home.join("skills"))
        .and_then(|_| fs::create_dir_all(&workspace))
        .map_err(|error| format!("创建内置 Agent 隔离目录失败: {error}"))?;
    set_private_dir(&home)?;
    set_private_dir(&workspace)?;

    let config = runtime_config(settings, mcp);
    write_private_file(&home.join("config.toml"), config.as_bytes())?;
    write_private_file(&run_dir.join("prompt.md"), prompt.as_bytes())?;
    let definitions = skills::built_in_skills();
    for skill_id in &skill_plan.selected_skill_ids {
        let Some(skill) = definitions.iter().find(|skill| &skill.id == skill_id) else {
            continue;
        };
        let directory = home.join("skills").join(&skill.id);
        fs::create_dir_all(&directory)
            .map_err(|error| format!("创建内置 Skill 目录失败: {error}"))?;
        set_private_dir(&directory)?;
        let body = format!(
            "---\nname: {}\ndescription: {}。{}\n---\n\n# {}\n\n版本：{}\n\n## 目标\n\n{}\n\n## 可用的 ShowNet MCP 工具\n\n{}\n\n## 输出要求\n\n{}\n\n优先依据 ShowNet 会话中保留实际值的有界证据作答，区分已确认事实、合理推断和证据缺口。仅使用本次分析授权的 ShowNet MCP 工具；本地文件、终端与外部网页能力已禁用。\n",
            skill.id,
            yaml_scalar(&skill.summary),
            yaml_scalar(&skill.trigger),
            skill.name,
            skill.version,
            markdown_list(&skill.objectives),
            markdown_list(&skill.tools),
            markdown_list(&skill.outputs),
        );
        write_private_file(&directory.join("SKILL.md"), body.as_bytes())?;
    }
    Ok(())
}

fn runtime_config(
    settings: &EffectiveAiProviderSettings,
    mcp: Option<&EffectiveMcpServerSettings>,
) -> String {
    let mut config = format!(
        "[models]\ndefault = \"shownet\"\nweb_search = \"shownet\"\nsession_summary = \"shownet\"\nimage_description = \"shownet\"\nprompt_suggestion = \"shownet\"\n\n[model.shownet]\nmodel = {}\nbase_url = {}\nname = \"ShowNet AI\"\ndescription = \"ShowNet full-capability packet analysis model\"\napi_backend = \"chat_completions\"\nenv_key = \"{}\"\ncontext_window = {}\n\n[compat.cursor]\nskills = false\nrules = false\nagents = false\nmcps = false\nhooks = false\nsessions = false\n\n[compat.claude]\nskills = false\nrules = false\nagents = false\nmcps = false\nhooks = false\nsessions = false\n\n[compat.codex]\nsessions = false\n\n[features]\ntelemetry = false\n\n[telemetry]\ntrace_upload = false\n",
        toml_string(&settings.model),
        toml_string(settings.base_url.trim_end_matches('/')),
        API_KEY_ENV,
        settings.context_tokens,
    );
    if let Some(mcp) = mcp.filter(|mcp| mcp.enabled) {
        config.push_str(&format!(
            "\n[mcp_servers.shownet]\nurl = \"http://127.0.0.1:{}/mcp\"\nheaders = {{ \"Authorization\" = \"Bearer ${{{}}}\" }}\nenabled = true\nstartup_timeout_sec = 10\ntool_timeout_sec = 60\n",
            mcp.port, MCP_TOKEN_ENV,
        ));
    }
    config
}

fn configure_upstream_proxy(
    command: &mut Command,
    upstream: Option<&EffectiveUpstreamProxy>,
    _target_base_url: &str,
) -> Result<(), String> {
    let Some(upstream) = upstream else {
        command.env("NO_PROXY", "127.0.0.1,localhost,::1");
        command.env("no_proxy", "127.0.0.1,localhost,::1");
        remove_proxy_environment(command);
        return Ok(());
    };
    let no_proxy = agent_no_proxy(&upstream.bypass);
    command.env("NO_PROXY", &no_proxy);
    command.env("no_proxy", &no_proxy);
    if upstream.mode == "direct" {
        remove_proxy_environment(command);
        return Ok(());
    }
    let scheme = if upstream.mode == "socks5" {
        "socks5h"
    } else {
        upstream.mode.as_str()
    };
    let mut url = reqwest::Url::parse(&format!("{scheme}://{}:{}", upstream.host, upstream.port))
        .map_err(|error| format!("出口代理配置无效: {error}"))?;
    if !upstream.username.is_empty() {
        url.set_username(&upstream.username)
            .map_err(|_| "出口代理用户名无效".to_string())?;
        url.set_password(upstream.password.as_deref())
            .map_err(|_| "出口代理密码无效".to_string())?;
    }
    let proxy = url.as_str();
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(name, proxy);
    }
    Ok(())
}

fn copy_minimum_runtime_environment(command: &mut Command) {
    for name in [
        "PATH",
        "HOME",
        "USERPROFILE",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn configure_os_sandbox(command: &mut Command) {
    // Grok's strict OS sandbox is currently supported by its upstream runtime
    // on macOS and Linux. Windows still receives the same denied-tool policy,
    // cleared environment and analysis-scoped MCP surface.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    command.args(["--sandbox", "strict"]);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = command;
}

fn remove_proxy_environment(command: &mut Command) {
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(name);
    }
}

fn agent_no_proxy(configured: &[String]) -> String {
    let mut entries = configured
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && *value != "*")
        .map(str::to_string)
        .collect::<Vec<_>>();
    for local in ["127.0.0.1", "localhost", "::1"] {
        if !entries
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(local))
        {
            entries.push(local.to_string());
        }
    }
    entries.sort_unstable();
    entries.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    entries.join(",")
}

#[cfg(test)]
fn discover_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SHOWNET_GROK_BINARY") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    find_on_path(if cfg!(windows) { "grok.exe" } else { "grok" })
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn toml_string(value: &str) -> String {
    // JSON escaping covers TOML's basic string for every character but one.
    // TOML forbids U+0000—U+0008, U+000A—U+001F and U+007F literally; serde_json
    // escapes the first two ranges and leaves U+007F raw, because JSON permits
    // it. A model name carrying a DEL therefore produced a config the agent
    // runtime refuses to parse, and the error names this generated file rather
    // than the setting the character came from.
    serde_json::to_string(value)
        .unwrap_or_else(|_| "\"\"".to_string())
        .replace('\u{7f}', "\\u007F")
}

fn yaml_scalar(value: &str) -> String {
    value.replace(['\r', '\n'], " ").replace(':', "：")
}

fn markdown_list(values: &[String]) -> String {
    if values.is_empty() {
        "- 无".to_string()
    } else {
        values
            .iter()
            .map(|value| format!("- {value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("写入内置 Agent 隔离文件失败: {error}"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("保存内置 Agent 隔离文件失败: {error}"))
}

fn set_private_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("设置内置 Agent 目录权限失败: {error}"))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn with_stderr(message: String, stderr: &str) -> String {
    if crate::ai_error::extract_ai_provider_error(&message).is_some_and(|error| error.is_terminal())
    {
        return crate::ai_error::format_ai_failure(None, &message);
    }
    if crate::ai_error::extract_ai_provider_error(stderr).is_some_and(|error| error.is_terminal()) {
        return crate::ai_error::format_ai_failure(None, stderr);
    }
    if stderr.trim().is_empty() {
        message
    } else {
        format!("{message}: {}", truncate(stderr, 1_200))
    }
}

fn truncate(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [TRUNCATED]", &value[..end])
}

struct RunDirectory(PathBuf);

impl RunDirectory {
    fn create(base: &Path, report_id: &str) -> Result<Self, String> {
        fs::create_dir_all(base)
            .map_err(|error| format!("创建内置 Agent 缓存目录失败: {error}"))?;
        let safe_id = report_id
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || character == '-' {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let path = base.join(format!("{}-{}", safe_id, uuid::Uuid::new_v4().simple()));
        fs::create_dir(&path).map_err(|error| format!("创建内置 Agent 运行目录失败: {error}"))?;
        set_private_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for RunDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DEFAULT_AI_CONTEXT_TOKENS;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn settings() -> EffectiveAiProviderSettings {
        EffectiveAiProviderSettings {
            provider: "compatible".to_string(),
            base_url: "https://example.com/v1".to_string(),
            model: "gpt-test\"quoted".to_string(),
            context_tokens: DEFAULT_AI_CONTEXT_TOKENS,
            api_key: Some("never-written".to_string()),
        }
    }

    async fn read_http_request(socket: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut expected_length = None;
        loop {
            let mut chunk = [0u8; 8_192];
            let size = socket.read(&mut chunk).await.unwrap();
            assert!(
                size > 0,
                "Grok closed the connection before sending a request"
            );
            request.extend_from_slice(&chunk[..size]);
            assert!(
                request.len() <= 2 * 1024 * 1024,
                "Grok request exceeded test limit"
            );

            if expected_length.is_none() {
                if let Some(header_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let header_end = header_end + 4;
                    let headers =
                        String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .expect("Grok request must include content-length");
                    expected_length = Some(header_end + content_length);
                }
            }
            if expected_length.is_some_and(|length| request.len() >= length) {
                break;
            }
        }
        String::from_utf8(request).unwrap()
    }

    async fn write_http_response(
        socket: &mut TcpStream,
        status: &str,
        content_type: &str,
        body: &[u8],
    ) {
        let headers = format!(
            "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(headers.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
    }

    fn text_sse(text: &str) -> Vec<u8> {
        let chunk = serde_json::json!({
            "id": "chatcmpl-shownet",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "gpt-sidecar-test",
            "choices": [{
                "index": 0,
                "delta": { "role": "assistant", "content": text },
                "finish_reason": "stop",
            }],
        });
        let usage = serde_json::json!({
            "id": "chatcmpl-shownet",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "gpt-sidecar-test",
            "choices": [],
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 },
        });
        format!("data: {chunk}\n\ndata: {usage}\n\ndata: [DONE]\n\n").into_bytes()
    }

    fn tool_call_sse(tool_name: &str, arguments: Value) -> Vec<u8> {
        let chunk = serde_json::json!({
            "id": "chatcmpl-shownet-tool",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "gpt-sidecar-test",
            "choices": [{
                "index": 0,
                "delta": {
                    "role": "assistant",
                    "tool_calls": [{
                        "index": 0,
                        "id": "call-shownet-e2e",
                        "type": "function",
                        "function": {
                            "name": tool_name,
                            "arguments": serde_json::to_string(&arguments).unwrap(),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        });
        let usage = serde_json::json!({
            "id": "chatcmpl-shownet-tool",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "gpt-sidecar-test",
            "choices": [],
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 },
        });
        format!("data: {chunk}\n\ndata: {usage}\n\ndata: [DONE]\n\n").into_bytes()
    }

    #[test]
    fn toml_strings_escape_every_character_toml_forbids() {
        // Not the same set JSON escapes: TOML allows a literal tab and the C1
        // range, and forbids U+007F, which JSON does not escape. Checked against
        // a real TOML parser while investigating; asserted here by character so
        // the test needs no parser of its own.
        let forbidden = |c: char| matches!(c, '\u{0}'..='\u{8}' | '\u{a}'..='\u{1f}' | '\u{7f}');
        for value in [
            "gpt\u{7f}x",
            "a\"b",
            "a\\b",
            "line\nbreak",
            "bell\u{7}",
            "模型-测试",
        ] {
            let quoted = toml_string(value);
            assert!(
                !quoted.chars().any(forbidden),
                "{value:?} left a character TOML forbids inside {quoted:?}"
            );
        }
    }

    #[test]
    fn generated_config_references_environment_secrets_only() {
        let mcp = EffectiveMcpServerSettings {
            enabled: true,
            port: 8899,
            allow_writes: false,
            access_token: "never-written-mcp".to_string(),
        };
        let config = runtime_config(&settings(), Some(&mcp));
        assert!(config.contains("env_key = \"SHOWNET_AGENT_API_KEY\""));
        assert!(config.contains("Bearer ${SHOWNET_MCP_TOKEN}"));
        assert!(!config.contains("never-written"));
        assert!(config.contains("gpt-test\\\"quoted"));
        assert!(config.contains("session_summary = \"shownet\""));
    }

    #[test]
    fn agent_proxy_uses_only_saved_bypass_and_loopback() {
        let bypass = vec!["*.example.com".to_string(), "*".to_string()];
        let no_proxy = agent_no_proxy(&bypass);
        assert!(no_proxy.contains("*.example.com"));
        assert!(no_proxy.contains("localhost"));
        assert!(no_proxy.contains("127.0.0.1"));
        assert!(no_proxy.contains("::1"));
        assert!(!no_proxy.split(',').any(|entry| entry == "*"));
    }

    #[test]
    fn agent_turn_limit_uses_configured_value_without_a_fixed_ceiling() {
        assert_eq!(normalized_agent_turn_limit(0), 1);
        assert_eq!(normalized_agent_turn_limit(8), 8);
        assert_eq!(normalized_agent_turn_limit(128), 128);
        assert_eq!(normalized_agent_turn_limit(u32::MAX), u32::MAX);
        assert_eq!(agent_runtime_timeout(1), Duration::from_secs(10 * 60));
        assert_eq!(agent_runtime_timeout(8), Duration::from_secs(80 * 60));
        assert!(agent_runtime_timeout(u32::MAX) > agent_runtime_timeout(128));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires a compatible system Grok and local socket permissions"]
    async fn real_system_grok_streams_openai_report_and_cleans_runtime_directory() {
        let binary = discover_binary()
            .expect("install Grok globally or set SHOWNET_GROK_BINARY before this test");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_dir = std::env::temp_dir().join(format!(
            "shownet-system-grok-integration-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let server_base_dir = base_dir.clone();
        let response_body = concat!(
            "data: {\"id\":\"chatcmpl-shownet\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"gpt-sidecar-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"checking local evidence\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-shownet\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"gpt-sidecar-test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"# System Grok report\\n\\nSYSTEM_GROK_E2E_OK\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-shownet\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"gpt-sidecar-test\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n",
            "data: [DONE]\n\n"
        )
        .as_bytes()
        .to_vec();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut inspected_runtime = false;
            loop {
                let accepted = tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => accepted,
                };
                let (mut socket, _) = accepted.unwrap();
                let request = read_http_request(&mut socket).await;

                if !inspected_runtime {
                    let run_dir = fs::read_dir(&server_base_dir)
                        .unwrap()
                        .next()
                        .expect("runtime directory should exist while Grok is running")
                        .unwrap()
                        .path();
                    let config = fs::read_to_string(run_dir.join("home/config.toml")).unwrap();
                    let prompt = fs::read_to_string(run_dir.join("prompt.md")).unwrap();
                    assert!(config.contains("env_key = \"SHOWNET_AGENT_API_KEY\""));
                    assert!(!config.contains("integration-secret"));
                    assert_eq!(prompt, "SIDECAR_E2E_PROMPT");
                    inspected_runtime = true;
                }

                let request_line = request.lines().next().unwrap_or_default();
                if request_line.starts_with("POST /v1/chat/completions ") {
                    write_http_response(&mut socket, "200 OK", "text/event-stream", &response_body)
                        .await;
                } else if request_line.starts_with("GET /v1/models ") {
                    write_http_response(
                        &mut socket,
                        "200 OK",
                        "application/json",
                        br#"{"object":"list","data":[{"id":"gpt-sidecar-test","object":"model","created":0,"owned_by":"shownet"}]}"#,
                    )
                    .await;
                } else if request_line.starts_with("GET /v1/settings ") {
                    write_http_response(
                        &mut socket,
                        "200 OK",
                        "application/json",
                        br#"{"allow_access":true}"#,
                    )
                    .await;
                } else if request_line.starts_with("GET /v1/user") {
                    write_http_response(
                        &mut socket,
                        "200 OK",
                        "application/json",
                        br#"{"userId":"shownet-test","email":"test@invalid"}"#,
                    )
                    .await;
                } else {
                    write_http_response(
                        &mut socket,
                        "404 Not Found",
                        "application/json",
                        br#"{"error":{"message":"not found"}}"#,
                    )
                    .await;
                }
                requests.push(request);
            }
            requests
        });

        let settings = EffectiveAiProviderSettings {
            provider: "compatible".to_string(),
            base_url: format!("http://{address}/v1"),
            model: "gpt-sidecar-test".to_string(),
            context_tokens: DEFAULT_AI_CONTEXT_TOKENS,
            api_key: Some("integration-secret".to_string()),
        };
        let upstream = EffectiveUpstreamProxy {
            mode: "direct".to_string(),
            host: String::new(),
            port: 0,
            username: String::new(),
            password: None,
            bypass: Vec::new(),
        };
        let skill_plan = SkillPlan {
            mode: "auto".to_string(),
            selected_skill_ids: Vec::new(),
            tool_names: Vec::new(),
            reasons: Vec::new(),
            stages: Vec::new(),
        };
        let mut output = String::new();
        let mut activities = Vec::new();
        let run_result = run_with_binary(
            &binary,
            &base_dir,
            "system-grok-e2e",
            &settings,
            None,
            Some(&upstream),
            &skill_plan,
            8,
            "SIDECAR_E2E_PROMPT",
            Duration::from_secs(60),
            |delta| {
                output.push_str(delta);
                Ok(())
            },
            |activity| {
                activities.push(activity);
                Ok(())
            },
        )
        .await;
        let _ = shutdown_tx.send(());
        let requests = server.await.unwrap();
        let request_lines = requests
            .iter()
            .map(|request| request.lines().next().unwrap_or_default().to_string())
            .collect::<Vec<_>>();
        let result = run_result
            .unwrap_or_else(|error| panic!("{error}; Grok HTTP requests: {request_lines:?}"));
        let chat_requests = requests
            .iter()
            .filter(|request| request.starts_with("POST /v1/chat/completions HTTP/1.1"))
            .map(|request| {
                let payload = request.split_once("\r\n\r\n").unwrap().1;
                (request, serde_json::from_str::<Value>(payload).unwrap())
            })
            .collect::<Vec<_>>();
        let request_models = chat_requests
            .iter()
            .map(|(_, payload)| payload["model"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>();
        let (request, payload) = chat_requests
            .iter()
            .find(|(_, payload)| {
                payload["messages"].as_array().is_some_and(|messages| {
                    messages.iter().any(|message| {
                        message["content"]
                            .as_str()
                            .is_some_and(|content| content.contains("autonomous agent"))
                    })
                })
            })
            .unwrap_or_else(|| {
                panic!("main Grok prompt was not sent; request models: {request_models:?}")
            });
        let request_lower = request.to_ascii_lowercase();
        assert!(request_lower.contains("authorization: bearer integration-secret"));
        assert!(
            request_models
                .iter()
                .all(|model| model == "gpt-sidecar-test"),
            "an auxiliary request bypassed the configured model: {request_models:?}"
        );
        assert_eq!(
            payload["model"], "gpt-sidecar-test",
            "main request used the wrong model; all request models: {request_models:?}"
        );
        assert_eq!(payload["stream"], true);
        assert_eq!(payload["stream_options"]["include_usage"], true);
        assert!(payload.to_string().contains("SIDECAR_E2E_PROMPT"));
        assert_eq!(result.content, "# System Grok report\n\nSYSTEM_GROK_E2E_OK");
        assert_eq!(output, result.content);
        assert_eq!(
            activities,
            vec![GrokActivity::Reasoning, GrokActivity::Generating]
        );
        assert_eq!(fs::read_dir(&base_dir).unwrap().count(), 0);
        fs::remove_dir(&base_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires a compatible system Grok and local socket permissions"]
    async fn real_system_grok_discovers_calls_and_consumes_shownet_mcp_tool() {
        let binary = discover_binary()
            .expect("install Grok globally or set SHOWNET_GROK_BINARY before this test");
        let model_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let model_address = model_listener.local_addr().unwrap();
        let mcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp_address = mcp_listener.local_addr().unwrap();
        let base_dir = std::env::temp_dir().join(format!(
            "shownet-system-grok-mcp-integration-{}",
            uuid::Uuid::new_v4().simple()
        ));

        let (model_shutdown_tx, mut model_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let model_server = tokio::spawn(async move {
            let mut payloads = Vec::new();
            loop {
                let accepted = tokio::select! {
                    _ = &mut model_shutdown_rx => break,
                    accepted = model_listener.accept() => accepted,
                };
                let (mut socket, _) = accepted.unwrap();
                let request = read_http_request(&mut socket).await;
                assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1"));
                let payload = request.split_once("\r\n\r\n").unwrap().1;
                let payload: Value = serde_json::from_str(payload).unwrap();
                assert_eq!(payload["model"], "gpt-sidecar-test");

                let serialized = payload.to_string();
                let response = if serialized.contains("generating the session title") {
                    text_sse("ShowNet MCP integration")
                } else if serialized.contains("MCP_EVIDENCE_OK") {
                    text_sse("# MCP system Grok report\n\nMCP_TOOL_E2E_OK")
                } else {
                    let tool_names = payload["tools"]
                        .as_array()
                        .map(|tools| {
                            tools
                                .iter()
                                .filter_map(|tool| tool["function"]["name"].as_str())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    assert!(tool_names.contains(&"search_tool"));
                    assert!(tool_names.contains(&"use_tool"));
                    assert!(
                        tool_names.len() > 2,
                        "default GrokBuild tools were unexpectedly restricted"
                    );
                    if serialized.contains("shownet__shownet_list_requests") {
                        tool_call_sse(
                            "use_tool",
                            serde_json::json!({
                                "tool_name": "shownet__shownet_list_requests",
                                "tool_input": { "sessionId": "session-e2e" },
                            }),
                        )
                    } else {
                        tool_call_sse(
                            "search_tool",
                            serde_json::json!({
                                "query": "shownet list requests",
                                "limit": 5,
                            }),
                        )
                    }
                };
                write_http_response(&mut socket, "200 OK", "text/event-stream", &response).await;
                payloads.push(payload);
            }
            payloads
        });

        let (mcp_shutdown_tx, mut mcp_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let mcp_server = tokio::spawn(async move {
            let mut requests = Vec::new();
            loop {
                let accepted = tokio::select! {
                    _ = &mut mcp_shutdown_rx => break,
                    accepted = mcp_listener.accept() => accepted,
                };
                let (mut socket, _) = accepted.unwrap();
                let request = read_http_request(&mut socket).await;
                let request_lower = request.to_ascii_lowercase();
                assert!(request.starts_with("POST /mcp HTTP/1.1"));
                assert!(request_lower.contains("authorization: bearer mcp-integration-secret"));
                let body = request.split_once("\r\n\r\n").unwrap().1;
                let message: Value = serde_json::from_str(body).unwrap();
                let id = message.get("id").cloned().unwrap_or(Value::Null);
                let method = message["method"].as_str().unwrap_or_default();
                let response = match method {
                    "initialize" => Some(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "protocolVersion": message["params"]["protocolVersion"],
                            "capabilities": { "tools": { "listChanged": false } },
                            "serverInfo": { "name": "shownet", "version": "0.1.0" },
                        },
                    })),
                    "tools/list" => Some(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "tools": [{
                                "name": "shownet_list_requests",
                                "description": "Read the bounded ShowNet request index",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": { "sessionId": { "type": "string" } },
                                    "required": ["sessionId"],
                                    "additionalProperties": false,
                                },
                            }],
                        },
                    })),
                    "tools/call" => {
                        assert_eq!(message["params"]["name"], "shownet_list_requests");
                        assert_eq!(message["params"]["arguments"]["sessionId"], "session-e2e");
                        Some(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": "{\"marker\":\"MCP_EVIDENCE_OK\",\"requests\":[]}",
                                }],
                                "structuredContent": {
                                    "marker": "MCP_EVIDENCE_OK",
                                    "requests": [],
                                },
                                "isError": false,
                            },
                        }))
                    }
                    _ if message.get("id").is_none() => None,
                    _ => Some(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "unsupported test method" },
                    })),
                };
                if let Some(response) = response {
                    let body = serde_json::to_vec(&response).unwrap();
                    write_http_response(&mut socket, "200 OK", "application/json", &body).await;
                } else {
                    write_http_response(&mut socket, "202 Accepted", "application/json", b"").await;
                }
                requests.push(message);
            }
            requests
        });

        let settings = EffectiveAiProviderSettings {
            provider: "compatible".to_string(),
            base_url: format!("http://{model_address}/v1"),
            model: "gpt-sidecar-test".to_string(),
            context_tokens: DEFAULT_AI_CONTEXT_TOKENS,
            api_key: Some("model-integration-secret".to_string()),
        };
        let mcp = EffectiveMcpServerSettings {
            enabled: true,
            port: mcp_address.port(),
            allow_writes: false,
            access_token: "mcp-integration-secret".to_string(),
        };
        let upstream = EffectiveUpstreamProxy {
            mode: "direct".to_string(),
            host: String::new(),
            port: 0,
            username: String::new(),
            password: None,
            bypass: Vec::new(),
        };
        let skill_plan = SkillPlan {
            mode: "auto".to_string(),
            selected_skill_ids: Vec::new(),
            tool_names: vec!["shownet_list_requests".to_string()],
            reasons: Vec::new(),
            stages: Vec::new(),
        };
        let mut output = String::new();
        let run_result = run_with_binary(
            &binary,
            &base_dir,
            "system-grok-mcp-e2e",
            &settings,
            Some(&mcp),
            Some(&upstream),
            &skill_plan,
            8,
            "Use the ShowNet request tool before writing the report.",
            Duration::from_secs(60),
            |delta| {
                output.push_str(delta);
                Ok(())
            },
            |_| Ok(()),
        )
        .await;
        let _ = model_shutdown_tx.send(());
        let _ = mcp_shutdown_tx.send(());
        let model_payloads = model_server.await.unwrap();
        let mcp_requests = mcp_server.await.unwrap();
        let result = run_result.unwrap_or_else(|error| {
            let methods = mcp_requests
                .iter()
                .filter_map(|message| message["method"].as_str())
                .collect::<Vec<_>>();
            panic!(
                "{error}; model requests: {}; MCP methods: {methods:?}",
                model_payloads.len()
            )
        });

        assert_eq!(
            result.content,
            "# MCP system Grok report\n\nMCP_TOOL_E2E_OK"
        );
        assert_eq!(output, result.content);
        assert!(mcp_requests
            .iter()
            .any(|request| request["method"] == "initialize"));
        assert!(mcp_requests
            .iter()
            .any(|request| request["method"] == "tools/list"));
        assert!(mcp_requests
            .iter()
            .any(|request| request["method"] == "tools/call"));
        assert!(model_payloads.iter().any(|payload| {
            payload.to_string().contains("MCP_EVIDENCE_OK")
                && payload["messages"].as_array().is_some_and(|messages| {
                    messages.iter().any(|message| message["role"] == "tool")
                })
        }));
        assert_eq!(fs::read_dir(&base_dir).unwrap().count(), 0);
        fs::remove_dir(&base_dir).unwrap();
    }
}
