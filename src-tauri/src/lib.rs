mod agent_tools;
mod algorithm_ground_truth;
mod algorithm_reconstruction;
mod algorithm_replay;
mod algorithm_verification;
mod analysis;
mod analysis_graph;
mod analysis_pipeline;
mod android_setup;
mod auto_crawler;
mod breakpoints;
mod browser;
mod browser_bus;
mod browser_hook;
mod ca;
mod capture_rules;
mod challenge_decoder;
mod client_access;
mod crypto;
mod crypto_code;
mod diagnostics;
mod evaluation_export;
mod external_mcp;
mod grok_runtime;
mod http2_fingerprint;
mod interchange;
mod mcp;
mod mirror;
mod models;
mod protection_analysis;
mod proxy;
mod proxy_terminal;
mod px_analysis;
mod real_capture_probe;
mod request_collections;
mod request_replay;
mod scorecard;
mod signature_adapter;
mod skills;
mod storage;
mod system_proxy;
mod tls_clienthello_catalog;
mod tls_clienthello_reference;
mod tls_fingerprint;
mod tls_golden;
mod tls_impersonate;
mod tls_interception;
mod tls_outbound;
pub mod tls_probe;
mod updates;
mod web_risk_lab;

use breakpoints::{BreakpointCoordinator, BreakpointDecisionInput, BreakpointQueueSnapshot};
use ca::CertificateAuthority;
use client_access::ClientAccessPolicy;
use interchange::{render_export, ExportFormat, SessionBundle};
use mcp::McpServerHandle;
use models::{
    AiAnalysisSettings, AiModelDiscoveryInput, AiProviderSettings, AiProviderSettingsInput,
    AnalysisActivity, AnalysisChatMessage, AnalysisReport, BrowserHookEvent, BrowserHookInput,
    CaptureEvent, CaptureEventInput, CaptureListenerSettings, CaptureRule, CaptureRuleInput,
    CaptureRuleRevision, CaptureRuleRun, CapturedRequestInput, ClientAccessMode,
    CollectionExportResult, CollectionImportCommitInput, CollectionImportPreview,
    CollectionImportResult, CollectionSyncCommitInput, CollectionSyncPreview, CollectionSyncResult,
    ConnectionDiagnostics, CryptoCodeSnippet, DataStorageSettings, DataStorageSettingsInput,
    DetectedEnvProxy, EffectiveUpstreamProxy, EnvironmentInput, EnvironmentRecord,
    EnvironmentVariableInput, FollowupAnalysisInput, McpClientSettings, McpClientSettingsInput,
    McpClientTestResult, McpRecentClient, McpServerSettingsInput, McpServerStatus,
    ProxyBrowserStatus, ReplayBatch, ReplayBatchInput, RequestAnnotation, RequestAnnotationInput,
    RequestCollection, RequestCollectionFolder, RequestCollectionFolderInput,
    RequestCollectionInput, RequestCollectionWorkspace, RequestCookieRecord, RequestDraft,
    RequestDraftBatchUpdateInput, RequestDraftInput, RequestDraftLocationInput, RequestListEvent,
    RequestListItem, RequestListPage, RequestListWindow, RequestQuery, RequestRecord, RequestRun,
    RequestWindowQuery, ReverseProxySettings, ReverseProxySettingsInput, ReverseProxyStatus,
    RulePreviewResult, SavedRequestView, SavedRequestViewInput, SessionRecord, SkillRunAudit,
    StartAnalysisInput, StorageStats, SystemProxySettings, SystemProxySettingsInput,
    UpdateCheckResult, UpstreamProbeResult, UpstreamProxySettings, UpstreamProxySettingsInput,
};
use proxy::{ProxyHandle, ReverseProxyHandle};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use skills::{SkillDefinition, SkillPlan};
use std::collections::HashMap;
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use storage::Storage;
#[cfg(desktop)]
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::{Emitter, Manager, State};
use tls_interception::TlsInterceptionSettings;

#[cfg(desktop)]
fn build_app_menu<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<Menu<R>> {
    let edit_menu = Submenu::with_id_and_items(
        app,
        "shownet-edit-menu",
        "Edit",
        true,
        &[
            &MenuItem::with_id(app, "shownet-edit-undo", "Undo", true, Some("CmdOrCtrl+Z"))?,
            &MenuItem::with_id(
                app,
                "shownet-edit-redo",
                "Redo",
                true,
                Some("CmdOrCtrl+Shift+Z"),
            )?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "shownet-edit-cut", "Cut", true, Some("CmdOrCtrl+X"))?,
            &MenuItem::with_id(app, "shownet-edit-copy", "Copy", true, Some("CmdOrCtrl+C"))?,
            &MenuItem::with_id(
                app,
                "shownet-edit-paste",
                "Paste",
                true,
                Some("CmdOrCtrl+V"),
            )?,
            &MenuItem::with_id(
                app,
                "shownet-edit-select-all",
                "Select All",
                true,
                Some("CmdOrCtrl+A"),
            )?,
        ],
    )?;
    let file_menu = Submenu::with_items(
        app,
        "File",
        true,
        &[
            &PredefinedMenuItem::close_window(app, None)?,
            #[cfg(not(target_os = "macos"))]
            &PredefinedMenuItem::quit(app, None)?,
        ],
    )?;
    let window_menu = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::maximize(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::close_window(app, None)?,
        ],
    )?;
    let help_menu = Submenu::with_items(
        app,
        "Help",
        true,
        &[
            #[cfg(not(target_os = "macos"))]
            &PredefinedMenuItem::about(app, None, None)?,
        ],
    )?;

    Menu::with_items(
        app,
        &[
            #[cfg(target_os = "macos")]
            &Submenu::with_items(
                app,
                app.package_info().name.clone(),
                true,
                &[
                    &PredefinedMenuItem::about(app, None, None)?,
                    &PredefinedMenuItem::separator(app)?,
                    &PredefinedMenuItem::services(app, None)?,
                    &PredefinedMenuItem::separator(app)?,
                    &PredefinedMenuItem::hide(app, None)?,
                    &PredefinedMenuItem::hide_others(app, None)?,
                    &PredefinedMenuItem::separator(app)?,
                    &PredefinedMenuItem::quit(app, None)?,
                ],
            )?,
            &file_menu,
            &edit_menu,
            #[cfg(target_os = "macos")]
            &Submenu::with_items(
                app,
                "View",
                true,
                &[&PredefinedMenuItem::fullscreen(app, None)?],
            )?,
            &window_menu,
            &help_menu,
        ],
    )
}

struct CaptureRuntime {
    running: bool,
    session_id: Option<String>,
    listen_address: Option<SocketAddr>,
    proxy: Option<ProxyHandle>,
}

struct ReverseProxyRuntime {
    handle: ReverseProxyHandle,
    session_id: String,
    bound_address: SocketAddr,
}

const DEFAULT_CAPTURE_PROXY_PORT: u16 = 8888;
const SOAK_CAPTURE_PROXY_PORT: u16 = 18888;
const DATA_DIRECTORY_ENV: &str = "SHOWNET_DATA_DIR";
const SOAK_READY_FILE_ENV: &str = "SHOWNET_SOAK_READY_FILE";
const SOAK_PROXY_PORT_ENV: &str = "SHOWNET_SOAK_PROXY_PORT";
const SOAK_SESSION_NAME_ENV: &str = "SHOWNET_SOAK_SESSION_NAME";
const SOAK_UPSTREAM_CA_FILE_ENV: &str = "SHOWNET_SOAK_UPSTREAM_CA_FILE";
const SOAK_CANCELLATION_TARGET_SAMPLES: usize = 12;
const SOAK_CANCELLATION_MIN_REQUESTS: i64 = 2_000;
const SOAK_CANCELLATION_REQUEST_STRIDE: i64 = 2_000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SoakStartup {
    proxy_port: u16,
    ready_file: PathBuf,
    cancellation_file: PathBuf,
    session_name: String,
    upstream_ca_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SoakCancellationSample {
    query_id: String,
    request_count: i64,
    click_to_idle_ms: f64,
    backend_wait_ms: f64,
    accepted: bool,
    settled: bool,
    measured_at_ms: u64,
}

#[derive(Default)]
struct SoakDiagnosticsRuntime {
    output_file: PathBuf,
    session_id: Option<String>,
    samples: Vec<SoakCancellationSample>,
}

#[derive(Default)]
struct SystemProxyRuntime {
    active: bool,
    last_error: Option<String>,
}

impl Default for CaptureRuntime {
    fn default() -> Self {
        Self {
            running: false,
            session_id: None,
            listen_address: None,
            proxy: None,
        }
    }
}

pub struct AppState {
    analysis: Mutex<AnalysisRuntime>,
    pub(crate) browser: Mutex<Option<browser::ProxyBrowserHandle>>,
    pub(crate) breakpoints: Arc<BreakpointCoordinator>,
    capture: Mutex<CaptureRuntime>,
    mcp: Mutex<McpRuntime>,
    request_queries: Mutex<RequestQueryRuntime>,
    soak_diagnostics: Mutex<Option<SoakDiagnosticsRuntime>>,
    replay: Mutex<ReplayRuntime>,
    reverse_proxy: Mutex<Option<ReverseProxyRuntime>>,
    pub(crate) request_cookie_jar: Arc<reqwest_cookie_store::CookieStoreMutex>,
    system_proxy: Mutex<SystemProxyRuntime>,
    pub storage: Storage,
    data_directory: PathBuf,
    proxy_port: u16,
    certificate_authority: Arc<CertificateAuthority>,
    certificate_path: PathBuf,
    ca_installed: AtomicBool,
}

fn resolve_data_directory(
    default_directory: PathBuf,
    configured_directory: Option<OsString>,
    current_executable: Option<&Path>,
    windows_portable_layout: bool,
) -> Result<(PathBuf, bool), String> {
    if let Some(configured_directory) = configured_directory {
        let directory = PathBuf::from(configured_directory);
        if !directory.is_absolute() {
            return Err(format!("{DATA_DIRECTORY_ENV} 必须是绝对路径"));
        }
        return Ok((directory, true));
    }

    if windows_portable_layout {
        if let Some(directory) = current_executable.and_then(windows_portable_data_directory) {
            return Ok((directory, false));
        }
    }

    Ok((default_directory, false))
}

fn windows_portable_data_directory(executable: &Path) -> Option<PathBuf> {
    let application_directory = executable.parent()?;
    if !path_file_name_eq(application_directory, "ShowNet") {
        return None;
    }
    let app_directory = application_directory.parent()?;
    if !path_file_name_eq(app_directory, "App") {
        return None;
    }
    let portable_root = app_directory.parent()?;
    Some(portable_root.join("Data").join("ShowNet"))
}

fn path_file_name_eq(path: &Path, expected: &str) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(expected))
}

fn soak_startup_from_values(
    ready_file: Option<OsString>,
    proxy_port: Option<OsString>,
    session_name: Option<OsString>,
    upstream_ca_file: Option<OsString>,
    isolated_data_directory: bool,
) -> Result<Option<SoakStartup>, String> {
    let Some(ready_file) = ready_file else {
        if proxy_port.is_some() || session_name.is_some() || upstream_ca_file.is_some() {
            return Err(format!(
                "{SOAK_PROXY_PORT_ENV}、{SOAK_SESSION_NAME_ENV} 和 {SOAK_UPSTREAM_CA_FILE_ENV} 只能与 {SOAK_READY_FILE_ENV} 一起使用"
            ));
        }
        return Ok(None);
    };
    if !isolated_data_directory {
        return Err(format!(
            "soak 模式必须同时设置绝对路径 {DATA_DIRECTORY_ENV}，禁止使用用户正式数据目录"
        ));
    }
    let ready_file = PathBuf::from(ready_file);
    if !ready_file.is_absolute() {
        return Err(format!("{SOAK_READY_FILE_ENV} 必须是绝对路径"));
    }
    let upstream_ca_file = upstream_ca_file
        .map(PathBuf::from)
        .map(|path| {
            if !path.is_absolute() {
                return Err(format!("{SOAK_UPSTREAM_CA_FILE_ENV} 必须是绝对路径"));
            }
            let resolved = std::fs::canonicalize(&path)
                .map_err(|error| format!("{SOAK_UPSTREAM_CA_FILE_ENV} 无法读取: {error}"))?;
            let ready_parent = ready_file
                .parent()
                .ok_or_else(|| format!("{SOAK_READY_FILE_ENV} 缺少父目录"))?;
            let ready_parent = std::fs::canonicalize(ready_parent)
                .map_err(|error| format!("{SOAK_READY_FILE_ENV} 父目录无法读取: {error}"))?;
            if !resolved.starts_with(&ready_parent) {
                return Err(format!(
                    "{SOAK_UPSTREAM_CA_FILE_ENV} 必须位于本次隔离 soak 目录内"
                ));
            }
            Ok(resolved)
        })
        .transpose()?;
    let cancellation_file = ready_file.with_file_name("cancellation-ipc.json");
    let proxy_port = proxy_port
        .map(|value| {
            value
                .to_string_lossy()
                .parse::<u16>()
                .map_err(|_| format!("{SOAK_PROXY_PORT_ENV} 必须是 1 到 65535 的端口"))
        })
        .transpose()?
        .unwrap_or(SOAK_CAPTURE_PROXY_PORT);
    if proxy_port == 0 {
        return Err(format!("{SOAK_PROXY_PORT_ENV} 必须是 1 到 65535 的端口"));
    }
    let session_name = session_name
        .map(|value| value.to_string_lossy().trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Release 长会话 Soak".to_string());
    if session_name.chars().count() > 60 {
        return Err(format!("{SOAK_SESSION_NAME_ENV} 不能超过 60 个字符"));
    }
    Ok(Some(SoakStartup {
        proxy_port,
        ready_file,
        cancellation_file,
        session_name,
        upstream_ca_file,
    }))
}

fn write_json_atomically(path: &Path, payload: &Value) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "soak 就绪文件缺少父目录".to_string())?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(payload).map_err(|error| error.to_string())?;
    std::fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    std::fs::rename(&temporary, path).map_err(|error| error.to_string())
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn write_soak_cancellation_report(runtime: &SoakDiagnosticsRuntime) -> Result<(), String> {
    write_json_atomically(
        &runtime.output_file,
        &json!({
            "schemaVersion": 1,
            "status": if runtime.samples.len() >= SOAK_CANCELLATION_TARGET_SAMPLES { "complete" } else { "collecting" },
            "sessionId": runtime.session_id.as_deref(),
            "targetSamples": SOAK_CANCELLATION_TARGET_SAMPLES,
            "minimumRequestCount": SOAK_CANCELLATION_MIN_REQUESTS,
            "requestStride": SOAK_CANCELLATION_REQUEST_STRIDE,
            "samples": &runtime.samples,
            "updatedAtMs": unix_time_ms(),
        }),
    )
}

async fn initialize_soak_capture(app: tauri::AppHandle, startup: SoakStartup) {
    let state = app.state::<AppState>();
    let initialized = async {
        let upstream_root_count = startup
            .upstream_ca_file
            .as_deref()
            .map(tls_outbound::set_soak_root_certificates_from_pem)
            .transpose()?
            .unwrap_or(0);
        let session = state
            .storage
            .create_session(Some(startup.session_name.clone()))?;
        {
            let mut diagnostics = state
                .soak_diagnostics
                .lock()
                .map_err(|_| "soak 诊断状态已损坏".to_string())?;
            if let Some(diagnostics) = diagnostics.as_mut() {
                diagnostics.session_id = Some(session.id.clone());
                write_soak_cancellation_report(diagnostics)?;
            }
        }
        start_capture_for_session(&app, &state, session.id.clone(), false).await?;
        let stats = state.storage.storage_stats()?;
        Ok::<Value, String>(json!({
            "status": "ready",
            "pid": std::process::id(),
            "appVersion": env!("CARGO_PKG_VERSION"),
            "proxyHost": "127.0.0.1",
            "proxyPort": startup.proxy_port,
            "sessionId": session.id,
            "sessionName": session.name,
            "databasePath": stats.database_path,
            "dataDirectory": stats.data_directory,
            "cancellationIpcPath": startup.cancellation_file,
            "soakUpstreamRootCount": upstream_root_count,
            "systemProxyManaged": false,
            "startedAtMs": unix_time_ms(),
        }))
    }
    .await;
    let payload = match initialized {
        Ok(payload) => payload,
        Err(error) => json!({
            "status": "error",
            "pid": std::process::id(),
            "proxyPort": startup.proxy_port,
            "dataDirectory": state.data_directory.display().to_string(),
            "error": error,
        }),
    };
    if let Err(error) = write_json_atomically(&startup.ready_file, &payload) {
        eprintln!("写入 soak 就绪文件失败: {error}");
    }
}

#[derive(Default)]
struct AnalysisRuntime {
    executions: HashMap<String, AnalysisExecution>,
}

#[derive(Clone)]
struct AnalysisExecution {
    session_id: String,
    cancellation: tokio::sync::watch::Sender<bool>,
    graph_mcp_token: Option<String>,
    graph_audit_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Default)]
struct ReplayRuntime {
    cancellations: HashMap<String, Arc<AtomicBool>>,
    draft_cancellations: HashMap<String, tokio::sync::watch::Sender<bool>>,
}

#[derive(Default)]
struct RequestQueryRuntime {
    active: Option<(String, Arc<AtomicBool>)>,
    cancellations: HashMap<String, Vec<Arc<AtomicBool>>>,
}

impl RequestQueryRuntime {
    fn start(&mut self, query_id: &str) -> Result<Arc<AtomicBool>, String> {
        if query_id.is_empty()
            || query_id.len() > 128
            || !query_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_:".contains(character))
        {
            return Err("请求查询 ID 无效".to_string());
        }
        for cancellations in self.cancellations.values() {
            for cancellation in cancellations {
                cancellation.store(true, Ordering::Release);
            }
        }
        let cancellation = Arc::new(AtomicBool::new(false));
        self.cancellations
            .entry(query_id.to_string())
            .or_default()
            .push(cancellation.clone());
        self.active = Some((query_id.to_string(), cancellation.clone()));
        Ok(cancellation)
    }

    fn cancel(&self, query_id: &str) -> bool {
        self.active
            .as_ref()
            .filter(|(active_id, _)| active_id == query_id)
            .is_some_and(|(_, cancellation)| {
                cancellation.store(true, Ordering::Release);
                true
            })
    }

    fn is_running(&self, query_id: &str) -> bool {
        self.cancellations.contains_key(query_id)
    }

    fn finish(&mut self, query_id: &str, cancellation: &Arc<AtomicBool>) {
        let remove_entry = self
            .cancellations
            .get_mut(query_id)
            .is_some_and(|instances| {
                instances.retain(|instance| !Arc::ptr_eq(instance, cancellation));
                instances.is_empty()
            });
        if remove_entry {
            self.cancellations.remove(query_id);
        }
        if self.active.as_ref().is_some_and(|(active_id, active)| {
            active_id == query_id && Arc::ptr_eq(active, cancellation)
        }) {
            self.active = None;
        }
    }
}

#[tauri::command]
async fn launch_proxy_browser(
    session_id: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ProxyBrowserStatus, String> {
    if !state.ca_installed.load(Ordering::SeqCst) {
        return Err("请先安装并信任 ShowNet Root CA".to_string());
    }
    {
        let capture = state
            .capture
            .lock()
            .map_err(|_| "抓包运行状态已损坏".to_string())?;
        if !capture.running || capture.session_id.as_deref() != Some(session_id.trim()) {
            return Err("请先在当前会话开始抓包".to_string());
        }
    }
    let previous = state
        .browser
        .lock()
        .map_err(|_| "浏览器运行状态已损坏".to_string())?
        .take();
    if let Some(previous) = previous {
        previous.stop().await;
    }
    let mut handle =
        browser::ProxyBrowserHandle::launch(&state.data_directory, state.proxy_port).await?;
    let status = handle.status();
    state
        .browser
        .lock()
        .map_err(|_| "浏览器运行状态已损坏".to_string())?
        .replace(handle);
    emit(&app, "browser://status", &status)?;
    Ok(status)
}

#[tauri::command]
async fn stop_proxy_browser(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let handle = state
        .browser
        .lock()
        .map_err(|_| "浏览器运行状态已损坏".to_string())?
        .take();
    if let Some(handle) = handle {
        handle.stop().await;
    }
    // Same payload type as the start path. Emitting a bare `false` here would
    // mean one event channel carrying two incompatible shapes, so any listener
    // written against the struct would break the moment the browser stops.
    emit(
        &app,
        "browser://status",
        &ProxyBrowserStatus {
            running: false,
            ..Default::default()
        },
    )
}

fn browser_bus_from_state(
    state: &AppState,
) -> Result<std::sync::Arc<browser_bus::BrowserBus>, String> {
    let mut guard = state
        .browser
        .lock()
        .map_err(|_| "浏览器运行状态已损坏".to_string())?;
    let handle = guard
        .as_mut()
        .ok_or_else(|| "内嵌浏览器未启动：请先 launch_proxy_browser".to_string())?;
    let status = handle.status();
    if !status.running {
        return Err("内嵌浏览器未在运行".to_string());
    }
    Ok(handle.bus())
}

#[tauri::command]
fn get_proxy_browser_status(
    state: State<'_, AppState>,
) -> Result<Option<ProxyBrowserStatus>, String> {
    let mut guard = state
        .browser
        .lock()
        .map_err(|_| "浏览器运行状态已损坏".to_string())?;
    Ok(guard.as_mut().map(|handle| handle.status()))
}

#[tauri::command]
async fn browser_evaluate(
    expression: String,
    await_promise: Option<bool>,
    state: State<'_, AppState>,
) -> Result<browser_bus::BrowserEvaluateResult, String> {
    let bus = browser_bus_from_state(&state)?;
    bus.evaluate(expression.trim(), await_promise.unwrap_or(false))
        .await
}

#[tauri::command]
async fn browser_click(
    x: Option<f64>,
    y: Option<f64>,
    selector: Option<String>,
    state: State<'_, AppState>,
) -> Result<browser_bus::BrowserClickResult, String> {
    let bus = browser_bus_from_state(&state)?;
    if let Some(selector) = selector
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return bus.click_selector(selector).await;
    }
    let x = x.ok_or_else(|| "browser_click 需要 selector 或 x/y".to_string())?;
    let y = y.ok_or_else(|| "browser_click 需要 selector 或 x/y".to_string())?;
    bus.click_xy(x, y).await
}

#[tauri::command]
async fn browser_screenshot(
    format: Option<String>,
    state: State<'_, AppState>,
) -> Result<browser_bus::BrowserScreenshotResult, String> {
    let bus = browser_bus_from_state(&state)?;
    bus.screenshot(format.as_deref().unwrap_or("png")).await
}

#[tauri::command]
async fn browser_navigate(url: String, state: State<'_, AppState>) -> Result<Value, String> {
    let bus = browser_bus_from_state(&state)?;
    let url = url.trim();
    if url.is_empty() {
        return Err("url 不能为空".to_string());
    }
    bus.navigate(url).await
}

#[tauri::command]
async fn browser_insert_text(text: String, state: State<'_, AppState>) -> Result<Value, String> {
    let bus = browser_bus_from_state(&state)?;
    bus.insert_text(&text).await
}

#[tauri::command]
async fn browser_dispatch_key(
    key: String,
    code: Option<String>,
    pressed: Option<bool>,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    let bus = browser_bus_from_state(&state)?;
    bus.dispatch_key(key.trim(), code.as_deref(), pressed.unwrap_or(true))
        .await
}

#[tauri::command]
async fn browser_install_lab(
    session_id: String,
    profile_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    let arguments = json!({
        "sessionId": session_id,
        "profileId": profile_id,
    });
    match agent_tools::execute_browser_tool(&state, "shownet_browser_install_lab", &arguments).await
    {
        Some(result) => result,
        None => Err("browser_install_lab 工具不可用".into()),
    }
}

/// One-click fixture probe for UI: seed → offline objectDump → vision dry-run map;
/// optionally live install_lab when embedded browser is running.
#[tauri::command]
async fn run_web_risk_fixture_probe(
    profile_id: Option<String>,
    install_live: Option<bool>,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    let profile = profile_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("chrome-desktop-stable");

    let seeded = web_risk_lab::seed_web_risk_fixture_session(&state.storage)?;
    let session_id = seeded
        .get("sessionId")
        .and_then(Value::as_str)
        .ok_or_else(|| "fixture 未返回 sessionId".to_string())?
        .to_string();

    let probe = web_risk_lab::run_offline_lab_probe(&state.storage, &session_id, Some(profile))?;
    let dry_indices = vec![0_u32, 2, 5];
    let vision_package = probe
        .get("visionCaptcha")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let vision_mapping = web_risk_lab::apply_vision_indices(
        &vision_package,
        &dry_indices,
        100.0,
        200.0,
        Some(100.0),
        Some(100.0),
        Some(3),
    )?;

    let want_live = install_live.unwrap_or(true);
    let live_install = if !want_live {
        None
    } else {
        match agent_tools::execute_browser_tool(
            &state,
            "shownet_browser_install_lab",
            &json!({
                "sessionId": session_id,
                "profileId": profile,
            }),
        )
        .await
        {
            Some(Ok(value)) => Some(value),
            Some(Err(error)) => {
                let skipped = error.contains("未启动") || error.contains("未在运行");
                Some(json!({
                    "ok": false,
                    "skipped": skipped,
                    "error": error,
                    "note": if skipped {
                        "离线探针已完成；启动 Chrome 后可再点「风控 Lab」做实页注入"
                    } else {
                        "实页注入失败"
                    },
                }))
            }
            None => Some(json!({
                "ok": false,
                "skipped": true,
                "error": "browser_install_lab 不可用",
            })),
        }
    };

    let offline_ok = probe.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let dump_keys = probe
        .get("objectDump")
        .and_then(Value::as_object)
        .map(|object| object.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    Ok(json!({
        "ok": offline_ok,
        "profileId": profile,
        "fixtureSessionId": session_id,
        "seeded": seeded,
        "offlineProbe": probe,
        "visionDryRun": {
            "indices": dry_indices,
            "mapping": vision_mapping,
        },
        "liveInstall": live_install,
        "summary": {
            "offlineOk": offline_ok,
            "objectDumpKeys": dump_keys,
            "visionPointCount": vision_mapping
                .get("points")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0),
            "liveOk": live_install
                .as_ref()
                .and_then(|value| value.get("ok"))
                .and_then(Value::as_bool),
            "liveSkipped": live_install
                .as_ref()
                .and_then(|value| value.get("skipped"))
                .and_then(Value::as_bool)
                .unwrap_or(live_install.is_none()),
        },
    }))
}

#[derive(Default)]
struct McpRuntime {
    handle: Option<McpServerHandle>,
    starting: bool,
    last_error: Option<String>,
    recent_clients: Vec<McpRecentClient>,
    last_request_at: Option<i64>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeStatus {
    app_version: String,
    platform: String,
    proxy_port: u16,
    listen_host: String,
    lan_enabled: bool,
    access_mode: ClientAccessMode,
    access_rules: Vec<String>,
    lan_addresses: Vec<String>,
    proxy_running: bool,
    active_session_id: Option<String>,
    ca_installed: bool,
    transparent_mode_available: bool,
    system_proxy_enabled: bool,
    system_proxy_active: bool,
    system_proxy_recovery_pending: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileExportResult {
    path: String,
    format: String,
    bytes: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateAuthorityStatus {
    generated: bool,
    installed: bool,
    fingerprint: String,
    certificate_path: String,
    created_at: i64,
}

#[tauri::command]
fn get_runtime_status(state: State<'_, AppState>) -> Result<RuntimeStatus, String> {
    runtime_status(&state)
}

#[tauri::command]
async fn check_for_updates(state: State<'_, AppState>) -> Result<UpdateCheckResult, String> {
    let upstream = state.storage.effective_upstream_proxy()?;
    updates::check_for_updates(upstream).await
}

#[tauri::command]
fn get_tls_interception_settings(
    state: State<'_, AppState>,
) -> Result<TlsInterceptionSettings, String> {
    state.storage.get_tls_interception_settings()
}

#[tauri::command]
fn save_tls_interception_settings(
    settings: TlsInterceptionSettings,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<TlsInterceptionSettings, String> {
    let settings = state.storage.save_tls_interception_settings(settings)?;
    emit(&app, "settings://tls-interception", &settings)?;
    Ok(settings)
}

#[tauri::command]
fn save_capture_listener_settings(
    settings: CaptureListenerSettings,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<RuntimeStatus, String> {
    {
        let capture = state
            .capture
            .lock()
            .map_err(|_| "抓包运行状态已损坏".to_string())?;
        if capture.running {
            return Err("请先停止抓包，再修改局域网监听设置".to_string());
        }
    }
    state.storage.save_capture_listener_settings(settings)?;
    let status = runtime_status(&state)?;
    emit(&app, "capture://status", &status)?;
    Ok(status)
}

#[tauri::command]
fn get_reverse_proxy_status(state: State<'_, AppState>) -> Result<ReverseProxyStatus, String> {
    reverse_proxy_status(&state)
}

#[tauri::command]
async fn start_reverse_proxy(
    settings: ReverseProxySettingsInput,
    session_id: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ReverseProxyStatus, String> {
    let session_id = session_id.trim().to_string();
    if session_id.is_empty() {
        return Err("免代理接入需要指定当前会话".to_string());
    }
    {
        let capture = state
            .capture
            .lock()
            .map_err(|_| "抓包运行状态已损坏".to_string())?;
        if !capture.running || capture.session_id.as_deref() != Some(session_id.as_str()) {
            return Err("请先在当前会话开始抓包".to_string());
        }
    }
    if settings.local_port == state.proxy_port {
        return Err(format!(
            "{} 已用于 ShowNet 抓包代理，请使用自动端口或其他端口",
            state.proxy_port
        ));
    }
    let settings = ReverseProxySettings {
        target_url: proxy::normalize_reverse_proxy_target(&settings.target_url)?,
        local_port: settings.local_port,
        lan_enabled: settings.lan_enabled,
        preserve_host: settings.preserve_host,
    };
    let listener_settings = state.storage.get_capture_listener_settings()?;
    let client_access =
        ClientAccessPolicy::from_settings(&listener_settings, settings.lan_enabled)?;
    let previous = state
        .reverse_proxy
        .lock()
        .map_err(|_| "免代理入口运行状态已损坏".to_string())?
        .take();
    if let Some(previous) = previous {
        previous.handle.stop().await;
    }
    let address = capture_listen_address(settings.lan_enabled, settings.local_port);
    let upstream = state.storage.effective_upstream_proxy()?;
    let handle = ReverseProxyHandle::start(
        address,
        client_access,
        session_id.clone(),
        settings.target_url.clone(),
        settings.preserve_host,
        upstream,
        app.clone(),
    )
    .await?;
    let bound_address = handle.local_addr();
    let capture_still_matches = state
        .capture
        .lock()
        .map_err(|_| "抓包运行状态已损坏".to_string())?
        .session_id
        .as_deref()
        == Some(session_id.as_str());
    if !capture_still_matches {
        handle.stop().await;
        return Err("抓包已停止，免代理入口未启动".to_string());
    }
    if let Err(error) = state.storage.save_reverse_proxy_settings(&settings) {
        handle.stop().await;
        return Err(error);
    }
    state
        .reverse_proxy
        .lock()
        .map_err(|_| "免代理入口运行状态已损坏".to_string())?
        .replace(ReverseProxyRuntime {
            handle,
            session_id,
            bound_address,
        });
    let status = reverse_proxy_status(&state)?;
    emit(&app, "reverse-proxy://status", &status)?;
    Ok(status)
}

#[tauri::command]
async fn stop_reverse_proxy(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ReverseProxyStatus, String> {
    let runtime = state
        .reverse_proxy
        .lock()
        .map_err(|_| "免代理入口运行状态已损坏".to_string())?
        .take();
    if let Some(runtime) = runtime {
        runtime.handle.stop().await;
    }
    let status = reverse_proxy_status(&state)?;
    emit(&app, "reverse-proxy://status", &status)?;
    Ok(status)
}

#[tauri::command]
fn get_data_storage_settings(state: State<'_, AppState>) -> Result<DataStorageSettings, String> {
    state.storage.get_data_storage_settings()
}

#[tauri::command]
fn save_data_storage_settings(
    settings: DataStorageSettingsInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<DataStorageSettings, String> {
    let settings = state.storage.save_data_storage_settings(settings)?;
    let removed = state.storage.cleanup_expired_sessions()?;
    emit(&app, "settings://data-storage", &settings)?;
    if removed > 0 {
        emit_storage_changed(&app, &state)?;
    }
    Ok(settings)
}

#[tauri::command]
fn get_storage_stats(state: State<'_, AppState>) -> Result<StorageStats, String> {
    state.storage.storage_stats()
}

#[tauri::command]
fn open_data_directory(state: State<'_, AppState>) -> Result<(), String> {
    open_directory(&state.storage.data_directory()?)
}

#[tauri::command]
fn clear_all_session_data(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<StorageStats, String> {
    {
        let capture = state
            .capture
            .lock()
            .map_err(|_| "抓包运行状态已损坏".to_string())?;
        if capture.running {
            return Err("正在抓包，停止后才能清除会话数据".to_string());
        }
    }
    state.storage.set_active_session(None)?;
    state.storage.clear_all_session_data()?;
    emit_storage_changed(&app, &state)
}

#[tauri::command]
fn get_ca_status(state: State<'_, AppState>) -> CertificateAuthorityStatus {
    ca_status(&state)
}

#[tauri::command]
fn export_ca_certificate(
    path: String,
    state: State<'_, AppState>,
) -> Result<FileExportResult, String> {
    let output_path = validate_output_path(path)?;
    let content = state.certificate_authority.certificate_pem();
    std::fs::write(&output_path, content.as_bytes())
        .map_err(|error| format!("导出 Root CA 失败: {error}"))?;
    Ok(FileExportResult {
        path: output_path.to_string_lossy().to_string(),
        format: "ShowNet Root CA".to_string(),
        bytes: content.len(),
    })
}

#[tauri::command]
fn install_ca_certificate(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<CertificateAuthorityStatus, String> {
    install_certificate_into_user_trust(&state.certificate_path)?;
    let installed = certificate_is_installed(state.certificate_authority.fingerprint());
    state.ca_installed.store(installed, Ordering::SeqCst);
    if !installed {
        return Err(certificate_trust_verification_error(std::env::consts::OS));
    }
    let status = ca_status(&state);
    emit(&app, "certificate://status", &status)?;
    Ok(status)
}

#[tauri::command]
async fn get_android_setup_status() -> android_setup::AndroidSetupStatus {
    android_setup::inspect().await
}

#[tauri::command]
async fn prepare_android_device(
    serial: String,
    state: State<'_, AppState>,
) -> Result<android_setup::AndroidSetupResult, String> {
    let status = runtime_status(&state)?;
    if !status.lan_enabled {
        return Err("请先开启局域网设备接入".to_string());
    }
    if !status.proxy_running {
        return Err("请先开始抓包，再配置 Android 设备".to_string());
    }
    let host = status
        .lan_addresses
        .first()
        .ok_or_else(|| "未检测到可供 Android 访问的局域网地址".to_string())?;
    let endpoint = format!("{host}:{}", status.proxy_port);
    let certificate_path = state.certificate_path.with_extension("crt");
    std::fs::write(
        &certificate_path,
        state.certificate_authority.certificate_der().as_ref(),
    )
    .map_err(|error| format!("准备 Android CA 文件失败：{error}"))?;
    android_setup::prepare(&serial, &endpoint, &certificate_path).await
}

#[tauri::command]
async fn reset_android_device_proxy(serial: String) -> Result<(), String> {
    android_setup::reset_proxy(&serial).await
}

#[tauri::command]
fn launch_proxy_terminal(
    session_id: String,
    terminal: String,
    state: State<'_, AppState>,
) -> Result<proxy_terminal::ProxyTerminalLaunchResult, String> {
    let session_id = session_id.trim();
    if session_id.is_empty() {
        return Err("打开代理终端需要当前会话".to_string());
    }
    let port = {
        let capture = state
            .capture
            .lock()
            .map_err(|_| "抓包运行状态已损坏".to_string())?;
        if !capture.running {
            return Err("请先开始当前会话的抓包".to_string());
        }
        if capture.session_id.as_deref() != Some(session_id) {
            return Err("抓包正在另一个会话中运行，请先切回对应会话".to_string());
        }
        capture
            .listen_address
            .map(|address| address.port())
            .unwrap_or(state.proxy_port)
    };
    proxy_terminal::launch(
        terminal.trim(),
        &format!("http://127.0.0.1:{port}"),
        &state.certificate_path,
    )
}

#[tauri::command]
fn list_sessions(state: State<'_, AppState>) -> Result<Vec<SessionRecord>, String> {
    state.storage.list_sessions()
}

#[tauri::command]
fn create_session(
    name: Option<String>,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<SessionRecord, String> {
    let session = state.storage.create_session(name)?;
    emit(&app, "session://created", &session)?;
    Ok(session)
}

#[tauri::command]
fn rename_session(
    session_id: String,
    name: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<SessionRecord, String> {
    let session = state.storage.rename_session(&session_id, &name)?;
    emit(&app, "session://updated", &session)?;
    Ok(session)
}

#[tauri::command]
fn delete_session(
    session_id: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.storage.delete_session(&session_id)?;
    emit(&app, "session://deleted", &session_id)
}

fn begin_request_query(
    app: &tauri::AppHandle,
    requested_query_id: Option<String>,
) -> Result<(String, Arc<AtomicBool>), String> {
    let query_id = requested_query_id
        .filter(|query_id| !query_id.is_empty())
        .unwrap_or_else(|| format!("server-{}", uuid::Uuid::new_v4()));
    let state = app.state::<AppState>();
    let cancellation = state
        .request_queries
        .lock()
        .map_err(|_| "请求查询状态已损坏".to_string())?
        .start(&query_id)?;
    Ok((query_id, cancellation))
}

fn finish_request_query(app: &tauri::AppHandle, query_id: &str, cancellation: &Arc<AtomicBool>) {
    let state = app.state::<AppState>();
    if let Ok(mut queries) = state.request_queries.lock() {
        queries.finish(query_id, cancellation);
    };
}

#[tauri::command]
async fn query_request_list(
    query: RequestQuery,
    query_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<RequestListPage, String> {
    let (query_id, cancellation) = begin_request_query(&app, query_id)?;
    let worker_app = app.clone();
    let worker_cancellation = cancellation.clone();
    let joined = tokio::task::spawn_blocking(move || {
        let state = worker_app.state::<AppState>();
        state
            .storage
            .query_request_list_cancellable(query, worker_cancellation)
    })
    .await;
    finish_request_query(&app, &query_id, &cancellation);
    joined.map_err(|error| format!("请求列表后台任务失败: {error}"))?
}

#[tauri::command]
async fn query_request_window(
    query: RequestWindowQuery,
    query_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<RequestListWindow, String> {
    let (query_id, cancellation) = begin_request_query(&app, query_id)?;
    let worker_app = app.clone();
    let worker_cancellation = cancellation.clone();
    let joined = tokio::task::spawn_blocking(move || {
        let state = worker_app.state::<AppState>();
        state
            .storage
            .query_request_window_cancellable(query, worker_cancellation)
    })
    .await;
    finish_request_query(&app, &query_id, &cancellation);
    joined.map_err(|error| format!("请求窗口后台任务失败: {error}"))?
}

#[tauri::command]
fn cancel_request_query(query_id: String, state: State<'_, AppState>) -> Result<bool, String> {
    state
        .request_queries
        .lock()
        .map_err(|_| "请求查询状态已损坏".to_string())
        .map(|queries| queries.cancel(&query_id))
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestQueryCancellationAck {
    query_id: String,
    accepted: bool,
    settled: bool,
    backend_wait_ms: f64,
}

#[tauri::command]
async fn cancel_request_query_and_wait(
    query_id: String,
    app: tauri::AppHandle,
) -> Result<RequestQueryCancellationAck, String> {
    let started = std::time::Instant::now();
    let accepted = {
        let state = app.state::<AppState>();
        let queries = state
            .request_queries
            .lock()
            .map_err(|_| "请求查询状态已损坏".to_string())?;
        queries.cancel(&query_id)
    };
    let deadline = std::time::Duration::from_secs(2);
    let settled = loop {
        let running = {
            let state = app.state::<AppState>();
            let queries = state
                .request_queries
                .lock()
                .map_err(|_| "请求查询状态已损坏".to_string())?;
            queries.is_running(&query_id)
        };
        if !running {
            break true;
        }
        if started.elapsed() >= deadline {
            break false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    };
    Ok(RequestQueryCancellationAck {
        query_id,
        accepted,
        settled,
        backend_wait_ms: started.elapsed().as_secs_f64() * 1_000.0,
    })
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SoakDiagnosticsStatus {
    enabled: bool,
    session_id: Option<String>,
    request_count: i64,
    samples_recorded: usize,
    target_samples: usize,
    minimum_request_count: i64,
    request_stride: i64,
}

fn soak_diagnostics_status(
    runtime: Option<&SoakDiagnosticsRuntime>,
    request_count: i64,
) -> SoakDiagnosticsStatus {
    SoakDiagnosticsStatus {
        enabled: runtime.is_some(),
        session_id: runtime.and_then(|runtime| runtime.session_id.clone()),
        request_count,
        samples_recorded: runtime.map(|runtime| runtime.samples.len()).unwrap_or(0),
        target_samples: SOAK_CANCELLATION_TARGET_SAMPLES,
        minimum_request_count: SOAK_CANCELLATION_MIN_REQUESTS,
        request_stride: SOAK_CANCELLATION_REQUEST_STRIDE,
    }
}

#[tauri::command]
fn get_soak_diagnostics_status(
    state: State<'_, AppState>,
) -> Result<SoakDiagnosticsStatus, String> {
    let session_id = state
        .soak_diagnostics
        .lock()
        .map_err(|_| "soak 诊断状态已损坏".to_string())?
        .as_ref()
        .and_then(|runtime| runtime.session_id.clone());
    let request_count = session_id
        .as_deref()
        .map(|session_id| state.storage.get_session(session_id))
        .transpose()?
        .map(|session| session.request_count)
        .unwrap_or(0);
    let diagnostics = state
        .soak_diagnostics
        .lock()
        .map_err(|_| "soak 诊断状态已损坏".to_string())?;
    Ok(soak_diagnostics_status(diagnostics.as_ref(), request_count))
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SoakCancellationSampleInput {
    query_id: String,
    click_to_idle_ms: f64,
    backend_wait_ms: f64,
    accepted: bool,
    settled: bool,
}

#[tauri::command]
fn record_soak_cancellation_sample(
    input: SoakCancellationSampleInput,
    state: State<'_, AppState>,
) -> Result<SoakDiagnosticsStatus, String> {
    if input.query_id.is_empty() || input.query_id.len() > 128 {
        return Err("soak 取消样本的查询 ID 无效".to_string());
    }
    for value in [input.click_to_idle_ms, input.backend_wait_ms] {
        if !value.is_finite() || !(0.0..=10_000.0).contains(&value) {
            return Err("soak 取消样本的延迟无效".to_string());
        }
    }
    let session_id = state
        .soak_diagnostics
        .lock()
        .map_err(|_| "soak 诊断状态已损坏".to_string())?
        .as_ref()
        .and_then(|runtime| runtime.session_id.clone())
        .ok_or_else(|| "当前不是可记录取消样本的隔离 soak 会话".to_string())?;
    let request_count = state.storage.get_session(&session_id)?.request_count;
    let mut diagnostics = state
        .soak_diagnostics
        .lock()
        .map_err(|_| "soak 诊断状态已损坏".to_string())?;
    let runtime = diagnostics
        .as_mut()
        .ok_or_else(|| "当前不是可记录取消样本的隔离 soak 会话".to_string())?;
    if runtime.samples.len() < SOAK_CANCELLATION_TARGET_SAMPLES
        && !runtime
            .samples
            .iter()
            .any(|sample| sample.query_id == input.query_id)
    {
        runtime.samples.push(SoakCancellationSample {
            query_id: input.query_id,
            request_count,
            click_to_idle_ms: input.click_to_idle_ms,
            backend_wait_ms: input.backend_wait_ms,
            accepted: input.accepted,
            settled: input.settled,
            measured_at_ms: unix_time_ms(),
        });
        write_soak_cancellation_report(runtime)?;
    }
    Ok(soak_diagnostics_status(Some(runtime), request_count))
}

#[tauri::command]
fn get_request_detail(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<RequestRecord, String> {
    state.storage.get_request_detail(&request_id)
}

#[tauri::command]
fn get_request_list_item(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<RequestListItem, String> {
    state.storage.get_request_list_item(&request_id)
}

#[tauri::command]
fn list_saved_request_views(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<SavedRequestView>, String> {
    state.storage.list_saved_request_views(&session_id)
}

#[tauri::command]
fn save_request_view(
    input: SavedRequestViewInput,
    state: State<'_, AppState>,
) -> Result<SavedRequestView, String> {
    state.storage.save_request_view(input)
}

#[tauri::command]
fn delete_request_view(view_id: String, state: State<'_, AppState>) -> Result<(), String> {
    state.storage.delete_request_view(&view_id)
}

#[tauri::command]
fn get_request_annotation(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<Option<RequestAnnotation>, String> {
    state.storage.get_request_annotation(&request_id)
}

#[tauri::command]
fn save_request_annotation(
    input: RequestAnnotationInput,
    state: State<'_, AppState>,
) -> Result<RequestAnnotation, String> {
    state.storage.save_request_annotation(input)
}

#[tauri::command]
async fn start_replay_batch(
    input: ReplayBatchInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ReplayBatch, String> {
    if input.settings.through_capture {
        let capture = state
            .capture
            .lock()
            .map_err(|_| "抓包运行状态已损坏".to_string())?;
        if !capture.running || capture.session_id.as_deref() != Some(input.session_id.trim()) {
            return Err("“经过 ShowNet”要求当前 Session 正在抓包".to_string());
        }
    }
    let batch = state.storage.create_replay_batch(&input)?;
    let cancellation = Arc::new(AtomicBool::new(false));
    state
        .replay
        .lock()
        .map_err(|_| "重放运行状态已损坏".to_string())?
        .cancellations
        .insert(batch.id.clone(), cancellation.clone());
    let batch_id = batch.id.clone();
    tauri::async_runtime::spawn(async move {
        request_replay::execute_batch(app.clone(), batch_id.clone(), cancellation).await;
        if let Ok(mut runtime) = app.state::<AppState>().replay.lock() {
            runtime.cancellations.remove(&batch_id);
        }
    });
    Ok(batch)
}

/// List a session's past replay batches.
///
/// No caller today, for the same reason as `get_replay_batch`: the UI has no
/// batch history view. The data is already persisted, so the gap is a missing
/// screen rather than a missing capability.
#[tauri::command]
fn list_replay_batches(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ReplayBatch>, String> {
    state.storage.list_replay_batches(&session_id)
}

#[tauri::command]
fn cancel_replay_batch(
    batch_id: String,
    state: State<'_, AppState>,
) -> Result<ReplayBatch, String> {
    let runtime = state
        .replay
        .lock()
        .map_err(|_| "重放运行状态已损坏".to_string())?;
    let cancellation = runtime
        .cancellations
        .get(&batch_id)
        .ok_or_else(|| "该重放批次已结束或不存在".to_string())?;
    cancellation.store(true, Ordering::SeqCst);
    drop(runtime);
    state
        .storage
        .set_replay_batch_status(&batch_id, "cancelled")?;
    state.storage.get_replay_batch(&batch_id)
}

#[tauri::command]
fn create_request_draft_from_capture(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<RequestDraft, String> {
    state.storage.create_request_draft_from_capture(&request_id)
}

#[tauri::command]
fn save_request_draft(
    input: RequestDraftInput,
    state: State<'_, AppState>,
) -> Result<RequestDraft, String> {
    state.storage.save_request_draft(input)
}

#[tauri::command]
fn list_request_drafts(state: State<'_, AppState>) -> Result<Vec<RequestDraft>, String> {
    state.storage.list_request_drafts()
}

#[tauri::command]
fn list_request_collection_workspace(
    state: State<'_, AppState>,
) -> Result<RequestCollectionWorkspace, String> {
    state.storage.list_request_collection_workspace()
}

#[tauri::command]
fn save_request_collection(
    input: RequestCollectionInput,
    state: State<'_, AppState>,
) -> Result<RequestCollection, String> {
    state.storage.save_request_collection(input)
}

#[tauri::command]
fn delete_request_collection(
    collection_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.storage.delete_request_collection(&collection_id)
}

#[tauri::command]
fn save_request_collection_folder(
    input: RequestCollectionFolderInput,
    state: State<'_, AppState>,
) -> Result<RequestCollectionFolder, String> {
    state.storage.save_request_collection_folder(input)
}

#[tauri::command]
fn delete_request_collection_folder(
    folder_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.storage.delete_request_collection_folder(&folder_id)
}

#[tauri::command]
fn move_request_draft(
    input: RequestDraftLocationInput,
    state: State<'_, AppState>,
) -> Result<RequestDraft, String> {
    state.storage.move_request_draft(input)
}

#[tauri::command]
fn update_request_drafts_batch(
    input: RequestDraftBatchUpdateInput,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.storage.update_request_drafts_batch(input)
}

#[tauri::command]
fn preview_request_collection_import(path: String) -> Result<CollectionImportPreview, String> {
    request_collections::preview_import_path(&path)
}

#[tauri::command]
fn commit_request_collection_import(
    input: CollectionImportCommitInput,
    state: State<'_, AppState>,
) -> Result<CollectionImportResult, String> {
    state.storage.import_request_collection(input)
}

#[tauri::command]
fn preview_request_collection_sync(
    collection_id: String,
    path: Option<String>,
    state: State<'_, AppState>,
) -> Result<CollectionSyncPreview, String> {
    let collection = state.storage.get_request_collection(&collection_id)?;
    let path = path
        .or(collection.source_path)
        .ok_or_else(|| "原规范文件不可用，请重新选择 OpenAPI 文件".to_string())?;
    state
        .storage
        .preview_request_collection_sync(&collection_id, &path)
}

#[tauri::command]
fn commit_request_collection_sync(
    input: CollectionSyncCommitInput,
    state: State<'_, AppState>,
) -> Result<CollectionSyncResult, String> {
    state.storage.sync_request_collection(input)
}

#[tauri::command]
fn export_request_collection(
    collection_id: String,
    path: String,
    format: String,
    state: State<'_, AppState>,
) -> Result<CollectionExportResult, String> {
    let workspace = state.storage.list_request_collection_workspace()?;
    let collection = state
        .storage
        .get_request_collection_for_send(&collection_id)?;
    let folders = workspace
        .folders
        .iter()
        .filter(|folder| folder.collection_id == collection_id)
        .cloned()
        .collect::<Vec<_>>();
    let draft_ids = workspace
        .drafts
        .iter()
        .filter(|draft| draft.collection_id.as_deref() == Some(collection_id.as_str()))
        .map(|draft| draft.id.clone())
        .collect::<Vec<_>>();
    let drafts = draft_ids
        .iter()
        .map(|draft_id| state.storage.get_request_draft_for_send(draft_id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut environment_ids = collection
        .default_environment_id
        .iter()
        .cloned()
        .chain(
            drafts
                .iter()
                .filter_map(|draft| draft.environment_id.clone()),
        )
        .collect::<Vec<_>>();
    environment_ids.sort();
    environment_ids.dedup();
    let environments = environment_ids
        .iter()
        .map(|environment_id| state.storage.export_environment_snapshot(environment_id))
        .collect::<Result<Vec<_>, _>>()?;
    let content = request_collections::render_collection_export(
        &format,
        &collection,
        &folders,
        &drafts,
        &environments,
    )?;
    std::fs::write(&path, content).map_err(|error| format!("写入集合文件失败: {error}"))?;
    Ok(CollectionExportResult {
        path,
        format,
        item_count: drafts.len() as i64,
    })
}

#[tauri::command]
fn reveal_request_draft_auth(
    draft_id: String,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    Ok(state.storage.get_request_draft_for_send(&draft_id)?.auth)
}

#[tauri::command]
fn reveal_request_collection_auth(
    collection_id: String,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    Ok(state
        .storage
        .get_request_collection_for_send(&collection_id)?
        .default_auth)
}

#[tauri::command]
async fn send_request_draft(
    draft_id: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<RequestRun, String> {
    let (cancellation, receiver) = tokio::sync::watch::channel(false);
    state
        .replay
        .lock()
        .map_err(|_| "请求发送运行状态已损坏".to_string())?
        .draft_cancellations
        .insert(draft_id.clone(), cancellation);
    let result = request_replay::execute_draft(&app, &draft_id, receiver).await;
    if let Ok(mut runtime) = state.replay.lock() {
        runtime.draft_cancellations.remove(&draft_id);
    }
    result
}

#[tauri::command]
fn cancel_request_draft(draft_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let runtime = state
        .replay
        .lock()
        .map_err(|_| "请求发送运行状态已损坏".to_string())?;
    let cancellation = runtime
        .draft_cancellations
        .get(&draft_id)
        .ok_or_else(|| "该草稿当前没有正在发送的请求".to_string())?;
    cancellation
        .send(true)
        .map_err(|_| "请求已结束".to_string())
}

#[tauri::command]
fn list_request_runs(
    draft_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<RequestRun>, String> {
    state.storage.list_request_runs(&draft_id)
}

fn request_cookie_records(store: &cookie_store::CookieStore) -> Vec<RequestCookieRecord> {
    let mut records = store
        .iter_unexpired()
        .map(|cookie| RequestCookieRecord {
            name: cookie.name().to_string(),
            domain: String::from(&cookie.domain),
            path: cookie.path.as_ref().to_string(),
            secure: cookie.secure().unwrap_or(false),
            http_only: cookie.http_only().unwrap_or(false),
            same_site: cookie.same_site().map(|value| format!("{value:?}")),
            expires_at: match &cookie.expires {
                cookie_store::CookieExpiration::AtUtc(value) => {
                    Some(value.unix_timestamp().saturating_mul(1_000))
                }
                cookie_store::CookieExpiration::SessionEnd => None,
            },
            persistent: cookie.is_persistent(),
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.domain
            .cmp(&right.domain)
            .then(left.path.cmp(&right.path))
            .then(left.name.cmp(&right.name))
    });
    records
}

#[tauri::command]
fn list_request_cookies(state: State<'_, AppState>) -> Result<Vec<RequestCookieRecord>, String> {
    let store = state
        .request_cookie_jar
        .lock()
        .map_err(|_| "Cookie Jar 运行状态已损坏".to_string())?;
    Ok(request_cookie_records(&store))
}

#[tauri::command]
fn delete_request_cookie(
    domain: String,
    path: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<Vec<RequestCookieRecord>, String> {
    let mut store = state
        .request_cookie_jar
        .lock()
        .map_err(|_| "Cookie Jar 运行状态已损坏".to_string())?;
    let previous = store.clone();
    if store
        .remove(domain.trim(), path.trim(), name.trim())
        .is_none()
    {
        return Err("Cookie 不存在或已经失效".to_string());
    }
    if let Err(error) = state.storage.save_request_cookie_store(&store) {
        *store = previous;
        return Err(error);
    }
    Ok(request_cookie_records(&store))
}

#[tauri::command]
fn clear_request_cookies(state: State<'_, AppState>) -> Result<Vec<RequestCookieRecord>, String> {
    let mut store = state
        .request_cookie_jar
        .lock()
        .map_err(|_| "Cookie Jar 运行状态已损坏".to_string())?;
    let previous = store.clone();
    store.clear();
    if let Err(error) = state.storage.save_request_cookie_store(&store) {
        *store = previous;
        return Err(error);
    }
    Ok(Vec::new())
}

#[tauri::command]
fn list_environments(state: State<'_, AppState>) -> Result<Vec<EnvironmentRecord>, String> {
    state.storage.list_environments()
}

#[tauri::command]
fn save_environment(
    input: EnvironmentInput,
    state: State<'_, AppState>,
) -> Result<EnvironmentRecord, String> {
    state.storage.save_environment(input)
}

#[tauri::command]
fn save_environment_variable(
    input: EnvironmentVariableInput,
    state: State<'_, AppState>,
) -> Result<EnvironmentRecord, String> {
    state.storage.save_environment_variable(input)
}

#[tauri::command]
fn reveal_environment_variable(
    variable_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    state.storage.reveal_environment_variable(&variable_id)
}

#[tauri::command]
fn delete_environment_variable(
    variable_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.storage.delete_environment_variable(&variable_id)
}

#[tauri::command]
fn delete_environment(environment_id: String, state: State<'_, AppState>) -> Result<(), String> {
    state.storage.delete_environment(&environment_id)
}

#[tauri::command]
fn list_capture_rules(state: State<'_, AppState>) -> Result<Vec<CaptureRule>, String> {
    state.storage.list_capture_rules()
}

#[tauri::command]
fn list_capture_rule_revisions(
    rule_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<CaptureRuleRevision>, String> {
    state.storage.list_capture_rule_revisions(&rule_id)
}

#[tauri::command]
fn restore_capture_rule_revision(
    rule_id: String,
    revision: i64,
    state: State<'_, AppState>,
) -> Result<CaptureRule, String> {
    state
        .storage
        .restore_capture_rule_revision(&rule_id, revision)
}

#[tauri::command]
fn save_capture_rule_draft(
    input: CaptureRuleInput,
    state: State<'_, AppState>,
) -> Result<CaptureRule, String> {
    state.storage.save_capture_rule(input)
}

#[tauri::command]
fn set_capture_rule_enabled(
    rule_id: String,
    enabled: bool,
    confirmed: bool,
    state: State<'_, AppState>,
) -> Result<CaptureRule, String> {
    let rule = state
        .storage
        .set_capture_rule_enabled(&rule_id, enabled, confirmed)?;
    if !enabled {
        state.breakpoints.cancel_rule(&rule_id, "规则已停用");
    }
    Ok(rule)
}

#[tauri::command]
fn get_breakpoint_queue(state: State<'_, AppState>) -> Result<BreakpointQueueSnapshot, String> {
    state.breakpoints.snapshot()
}

#[tauri::command]
fn resolve_breakpoint(
    input: BreakpointDecisionInput,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.breakpoints.resolve(input)
}

#[tauri::command]
fn preview_capture_rule(
    rule_id: String,
    request_id: String,
    state: State<'_, AppState>,
) -> Result<RulePreviewResult, String> {
    capture_rules::preview_rule(&state.storage, &rule_id, &request_id)
}

#[tauri::command]
fn list_rule_trace_for_request(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<CaptureRuleRun>, String> {
    state.storage.list_rule_trace_for_request(&request_id)
}

#[tauri::command]
async fn run_connection_diagnostics(
    app: tauri::AppHandle,
) -> Result<ConnectionDiagnostics, String> {
    diagnostics::run(&app).await
}

#[tauri::command]
fn get_crypto_code_snippets(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<CryptoCodeSnippet>, String> {
    state.storage.get_crypto_snippets(&request_id)
}

#[tauri::command]
fn get_browser_hook_script() -> String {
    browser_hook::script().to_string()
}

#[tauri::command]
fn record_browser_hook(
    event: BrowserHookInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<BrowserHookEvent, String> {
    let (hook, capture_event) = state.storage.store_browser_hook(event)?;
    emit(&app, "capture://event", &capture_event)?;
    emit(&app, "browser://hook", &hook)?;
    if let Some(request_id) = hook.request_id.as_deref() {
        if let Ok(item) = state.storage.get_request_list_item(request_id) {
            let update = RequestListEvent {
                session_id: hook.session_id.clone(),
                item,
            };
            emit(&app, "capture://request-updated", &update)?;
        }
    }
    Ok(hook)
}

#[tauri::command]
fn list_browser_hooks(
    session_id: String,
    limit: Option<i64>,
    state: State<'_, AppState>,
) -> Result<Vec<BrowserHookEvent>, String> {
    state.storage.list_browser_hooks(&session_id, limit)
}

/// Advanced Console + agent shared: session-scoped TLS fingerprint rows + outbound status.
#[tauri::command]
fn get_tls_fingerprints(session_id: String, state: State<'_, AppState>) -> Result<Value, String> {
    tls_fingerprint::list_session_tls_fingerprints(&state.storage, &session_id)
}

#[tauri::command]
fn export_session_file(
    session_id: String,
    format: String,
    path: String,
    state: State<'_, AppState>,
) -> Result<FileExportResult, String> {
    let output_path = validate_output_path(path)?;
    let export_format = ExportFormat::parse(&format)?;
    let bundle = state.storage.export_session_bundle(&session_id)?;
    let content = render_export(&bundle, export_format)?;
    std::fs::write(&output_path, content.as_bytes())
        .map_err(|error| format!("写入导出文件失败: {error}"))?;
    Ok(FileExportResult {
        path: output_path.to_string_lossy().to_string(),
        format: export_format.label().to_string(),
        bytes: content.len(),
    })
}

#[tauri::command]
fn export_algorithm_replay_package(
    session_id: String,
    language: String,
    report_id: Option<String>,
    output_dir: Option<String>,
    state: State<'_, AppState>,
) -> Result<algorithm_replay::AlgorithmReplayExportResult, String> {
    let directory = match output_dir {
        Some(path) if !path.trim().is_empty() => {
            Some(validate_output_directory(path.trim().to_string())?)
        }
        _ => None,
    };
    let report_id = report_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    algorithm_replay::export_algorithm_replay_for_report(
        &state.storage,
        session_id.trim(),
        language.trim(),
        report_id,
        directory.as_deref(),
    )
}

#[tauri::command]
fn export_evaluation_package(
    session_id: String,
    analysis_id: Option<String>,
    output_dir: Option<String>,
    state: State<'_, AppState>,
) -> Result<evaluation_export::EvaluationExportResult, String> {
    let directory = match output_dir {
        Some(path) if !path.trim().is_empty() => {
            Some(validate_output_directory(path.trim().to_string())?)
        }
        _ => None,
    };
    let analysis_id = analysis_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    evaluation_export::export_evaluation_package(
        &state.storage,
        session_id.trim(),
        analysis_id,
        directory.as_deref(),
    )
}

#[tauri::command]
fn get_outbound_tls_profile() -> Result<Value, String> {
    Ok(tls_outbound::status_json())
}

#[tauri::command]
fn set_outbound_tls_profile(profile: String, state: State<'_, AppState>) -> Result<Value, String> {
    // Accept versioned catalog ids (chrome150) or coarse family names.
    let preset_id = match tls_clienthello_catalog::resolve_preset_id(&profile) {
        Ok(id) => id,
        Err(_) => {
            let parsed = tls_outbound::OutboundTlsProfile::parse(&profile);
            match parsed {
                tls_outbound::OutboundTlsProfile::Default => "default",
                tls_outbound::OutboundTlsProfile::ChromeLike => "chrome150",
                tls_outbound::OutboundTlsProfile::FirefoxLike => "firefox136",
                tls_outbound::OutboundTlsProfile::SafariIosLike => "safari-ios18",
            }
        }
    };
    tls_outbound::set_active_preset(preset_id)?;
    let mut payload = state
        .storage
        .load_app_setting_json("outbound_tls")
        .ok()
        .flatten()
        .unwrap_or_else(|| json!({}));
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("presetId".into(), json!(preset_id));
        obj.insert(
            "profile".into(),
            json!(tls_outbound::global_profile().as_str()),
        );
        obj.insert(
            "autoFromInbound".into(),
            json!(tls_outbound::auto_from_inbound()),
        );
    } else {
        payload = json!({
            "presetId": preset_id,
            "profile": tls_outbound::global_profile().as_str(),
            "autoFromInbound": tls_outbound::auto_from_inbound(),
        });
    }
    state
        .storage
        .save_app_setting_json("outbound_tls", &payload)?;
    Ok(tls_outbound::status_json())
}

#[tauri::command]
fn set_outbound_tls_auto_from_inbound(
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    tls_outbound::set_auto_from_inbound(enabled);
    let mut payload = state
        .storage
        .load_app_setting_json("outbound_tls")
        .ok()
        .flatten()
        .unwrap_or_else(|| json!({ "profile": tls_outbound::global_profile().as_str() }));
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("autoFromInbound".into(), json!(enabled));
    }
    state
        .storage
        .save_app_setting_json("outbound_tls", &payload)?;
    Ok(tls_outbound::status_json())
}

#[tauri::command]
fn get_px_settings() -> Result<Value, String> {
    Ok(px_analysis::settings_json())
}

#[tauri::command]
fn set_px_settings(
    decrypt_enabled: Option<bool>,
    intercept_ec_data: Option<bool>,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    if let Some(v) = decrypt_enabled {
        px_analysis::set_px_decrypt_enabled(v);
    }
    if let Some(v) = intercept_ec_data {
        px_analysis::set_px_intercept_ec_data(v);
    }
    let payload = px_analysis::settings_json();
    state
        .storage
        .save_app_setting_json("px_console", &payload)?;
    Ok(payload)
}

#[tauri::command]
fn list_px_evidence(
    session_id: String,
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<px_analysis::PxEvidenceItem>, String> {
    px_analysis::list_session_evidence(
        &state.storage,
        session_id.trim(),
        limit.unwrap_or(200) as usize,
    )
}

#[tauri::command]
fn decode_px_payload(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<px_analysis::PxDecodeResult, String> {
    px_analysis::decode_request_payload(&state.storage, request_id.trim())
}

/// Run the whole analysis pipeline without a UI driving it.
///
/// No caller today: every in-app path goes through the interactive analysis
/// views. This is the headless entry point — one call from capture to exported
/// code — which is what an automated run or a future CLI would use.
#[tauri::command]
fn run_autonomous_session_analysis(
    session_id: String,
    mode: Option<String>,
    export_language: Option<String>,
    output_dir: Option<String>,
    state: State<'_, AppState>,
) -> Result<analysis_pipeline::AutonomousAnalysisResult, String> {
    let directory = match output_dir {
        Some(path) if !path.trim().is_empty() => {
            Some(validate_output_directory(path.trim().to_string())?)
        }
        _ => None,
    };
    analysis_pipeline::run_autonomous_session_analysis(
        &state.storage,
        session_id.trim(),
        mode.as_deref().unwrap_or("crypto"),
        export_language
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        directory.as_deref(),
    )
}

#[tauri::command]
fn import_session_file(
    path: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<SessionRecord, String> {
    let path = PathBuf::from(path);
    let metadata =
        std::fs::metadata(&path).map_err(|error| format!("无法读取会话文件: {error}"))?;
    if !metadata.is_file() {
        return Err("所选路径不是文件".to_string());
    }
    if metadata.len() > 512 * 1024 * 1024 {
        return Err("会话文件超过 512 MiB 限制".to_string());
    }
    let content =
        std::fs::read_to_string(&path).map_err(|error| format!("读取会话文件失败: {error}"))?;
    let bundle: SessionBundle =
        serde_json::from_str(&content).map_err(|error| format!("解析会话文件失败: {error}"))?;
    let session = state.storage.import_session_bundle(bundle)?;
    emit(&app, "session://created", &session)?;
    Ok(session)
}

#[tauri::command]
fn get_upstream_proxy_settings(
    state: State<'_, AppState>,
) -> Result<UpstreamProxySettings, String> {
    state.storage.get_upstream_proxy_settings()
}

#[tauri::command]
fn get_system_proxy_settings(state: State<'_, AppState>) -> Result<SystemProxySettings, String> {
    system_proxy_status(&state)
}

#[tauri::command]
fn save_system_proxy_settings(
    settings: SystemProxySettingsInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<SystemProxySettings, String> {
    if state
        .system_proxy
        .lock()
        .map_err(|_| "系统代理运行状态已损坏".to_string())?
        .active
    {
        return Err("抓包运行期间不能修改系统代理接管设置".to_string());
    }
    state.storage.save_system_proxy_preferences(settings)?;
    let status = system_proxy_status(&state)?;
    emit(&app, "settings://system-proxy", &status)?;
    Ok(status)
}

#[tauri::command]
fn retry_system_proxy_recovery(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<SystemProxySettings, String> {
    if state
        .capture
        .lock()
        .map_err(|_| "抓包运行状态已损坏".to_string())?
        .running
    {
        return Err("请先停止抓包，再恢复系统代理".to_string());
    }
    restore_system_proxy(&state)?;
    let status = system_proxy_status(&state)?;
    emit(&app, "settings://system-proxy", &status)?;
    Ok(status)
}

#[tauri::command]
fn get_ai_provider_settings(state: State<'_, AppState>) -> Result<AiProviderSettings, String> {
    state.storage.get_ai_provider_settings()
}

#[tauri::command]
fn get_ai_analysis_settings(state: State<'_, AppState>) -> Result<AiAnalysisSettings, String> {
    state.storage.get_ai_analysis_settings()
}

#[tauri::command]
async fn list_ai_models(
    settings: AiModelDiscoveryInput,
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    analysis::list_models(&state, settings).await
}

#[tauri::command]
fn save_ai_provider_settings(
    settings: AiProviderSettingsInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<AiProviderSettings, String> {
    let settings = state.storage.save_ai_provider_settings(settings)?;
    emit(&app, "settings://ai-provider", &settings)?;
    Ok(settings)
}

#[tauri::command]
fn save_ai_analysis_settings(
    settings: AiAnalysisSettings,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<AiAnalysisSettings, String> {
    let settings = state.storage.save_ai_analysis_settings(settings)?;
    emit(&app, "settings://ai-analysis", &settings)?;
    Ok(settings)
}

#[tauri::command]
fn get_mcp_server_status(state: State<'_, AppState>) -> Result<McpServerStatus, String> {
    mcp_server_status(&state)
}

#[tauri::command]
fn list_built_in_skills() -> Vec<SkillDefinition> {
    skills::built_in_skills()
}

#[tauri::command]
fn get_analysis_skill_plan(
    session_id: String,
    mode: String,
    state: State<'_, AppState>,
) -> Result<SkillPlan, String> {
    let requests = state
        .storage
        .list_requests(&session_id, Some(10_000), Some(0))?;
    skills::build_plan(&mode, &requests)
}

#[tauri::command]
fn build_signature_harness(
    session_id: String,
    adapter: Option<String>,
    state: State<'_, AppState>,
) -> Result<signature_adapter::SignatureAdapterHarness, String> {
    signature_adapter::build_signature_harness(
        &state.storage,
        &session_id,
        adapter.as_deref().unwrap_or("auto"),
    )
}

#[tauri::command]
fn list_mcp_tools(state: State<'_, AppState>) -> Result<Vec<agent_tools::ToolDefinition>, String> {
    let settings = state.storage.get_mcp_server_settings()?;
    Ok(mcp::tool_definitions(settings.allow_writes))
}

#[tauri::command]
fn reveal_mcp_access_token(state: State<'_, AppState>) -> Result<String, String> {
    state.storage.reveal_mcp_access_token()
}

#[tauri::command]
fn rotate_mcp_access_token(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let token = state.storage.rotate_mcp_access_token()?;
    let status = mcp_server_status(&state)?;
    emit(&app, "settings://mcp-server", &status)?;
    Ok(token)
}

#[tauri::command]
async fn save_mcp_server_settings(
    settings: McpServerSettingsInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<McpServerStatus, String> {
    state.storage.save_mcp_server_settings(settings)?;
    restart_mcp_server(&app).await
}

#[tauri::command]
fn list_external_mcp_servers(state: State<'_, AppState>) -> Result<Vec<McpClientSettings>, String> {
    state.storage.list_mcp_client_settings()
}

#[tauri::command]
fn save_external_mcp_server(
    settings: McpClientSettingsInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<McpClientSettings, String> {
    let server = state.storage.save_mcp_client_settings(settings)?;
    emit(&app, "settings://mcp-clients", &server)?;
    Ok(server)
}

#[tauri::command]
fn delete_external_mcp_server(
    server_id: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.storage.delete_mcp_client_settings(server_id.trim())?;
    emit(&app, "settings://mcp-clients", &server_id)
}

#[tauri::command]
async fn test_external_mcp_server(
    server_id: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<McpClientTestResult, String> {
    let result = external_mcp::test_server(&state.storage, server_id.trim()).await;
    if let Ok(servers) = state.storage.list_mcp_client_settings() {
        let _ = emit(&app, "settings://mcp-clients", &servers);
    }
    result
}

#[tauri::command]
fn list_analysis_reports(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<AnalysisReport>, String> {
    state.storage.list_analysis_reports(&session_id)
}

#[tauri::command]
fn list_analysis_messages(
    analysis_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<AnalysisChatMessage>, String> {
    state.storage.list_analysis_messages(&analysis_id)
}

#[tauri::command]
fn list_analysis_activities(
    analysis_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<AnalysisActivity>, String> {
    state.storage.list_analysis_activities(&analysis_id)
}

#[tauri::command]
fn list_analysis_skill_runs(
    analysis_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<SkillRunAudit>, String> {
    state.storage.list_analysis_skill_runs(&analysis_id)
}

#[tauri::command]
fn get_analysis_graph_run(
    analysis_id: String,
    state: State<'_, AppState>,
) -> Result<Option<analysis_graph::AnalysisGraphRun>, String> {
    state.storage.get_analysis_graph_run(&analysis_id)
}

#[tauri::command]
fn is_ai_analysis_running(analysis_id: String, state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state
        .analysis
        .lock()
        .map_err(|_| "AI 分析运行状态已损坏".to_string())?
        .executions
        .contains_key(analysis_id.trim()))
}

#[tauri::command]
async fn start_ai_analysis(
    input: StartAnalysisInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<AnalysisReport, String> {
    analysis::start_analysis(&app, &state, input).await
}

#[tauri::command]
fn cancel_ai_analysis(analysis_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let sender = state
        .analysis
        .lock()
        .map_err(|_| "AI 分析运行状态已损坏".to_string())?
        .executions
        .get(analysis_id.trim())
        .map(|execution| execution.cancellation.clone())
        .ok_or_else(|| "这项 AI 分析当前没有在运行".to_string())?;
    sender.send(true).map_err(|_| "AI 分析已经结束".to_string())
}

#[tauri::command]
async fn followup_ai_analysis(
    input: FollowupAnalysisInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<AnalysisChatMessage, String> {
    analysis::followup_analysis(&app, &state, input).await
}

#[tauri::command]
fn save_upstream_proxy_settings(
    settings: UpstreamProxySettingsInput,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<UpstreamProxySettings, String> {
    let settings = state.storage.save_upstream_proxy_settings(settings)?;
    emit(&app, "settings://upstream-proxy", &settings)?;
    Ok(settings)
}

#[tauri::command]
fn detect_env_upstream_proxy() -> Option<DetectedEnvProxy> {
    proxy::detect_env_proxy()
}

/// Probe current form draft when `settings` is provided; otherwise probe saved egress.
#[tauri::command]
async fn probe_upstream_proxy(
    settings: Option<UpstreamProxySettingsInput>,
    state: State<'_, AppState>,
) -> Result<UpstreamProbeResult, String> {
    let effective = if let Some(input) = settings {
        let stored = state.storage.effective_upstream_proxy()?;
        let password = if input.clear_password {
            None
        } else if let Some(password) = input.password.filter(|value| !value.is_empty()) {
            Some(password)
        } else {
            stored.password
        };
        EffectiveUpstreamProxy {
            mode: input.mode,
            host: input.host.trim().to_string(),
            port: input.port,
            username: input.username.trim().to_string(),
            password,
            bypass: input.bypass,
        }
    } else {
        state.storage.effective_upstream_proxy()?
    };
    Ok(proxy::probe_upstream_egress(&effective).await)
}

pub(crate) fn persist_capture_event(
    app: &tauri::AppHandle,
    event: CaptureEventInput,
) -> Result<CaptureEvent, String> {
    let state = app.state::<AppState>();
    let event = state.storage.append_event(event)?;
    emit(&app, "capture://event", &event)?;
    Ok(event)
}

#[tauri::command]
fn list_websocket_frames(
    request_id: String,
    limit: Option<i64>,
    state: State<'_, AppState>,
) -> Result<Vec<CaptureEvent>, String> {
    state.storage.list_websocket_events(&request_id, limit)
}

#[tauri::command]
fn list_sse_events(
    request_id: String,
    limit: Option<i64>,
    state: State<'_, AppState>,
) -> Result<Vec<CaptureEvent>, String> {
    state.storage.list_sse_events(&request_id, limit)
}

async fn start_capture_for_session(
    app: &tauri::AppHandle,
    state: &AppState,
    session_id: String,
    manage_system_proxy: bool,
) -> Result<RuntimeStatus, String> {
    let existing_session_matches = {
        let capture = state
            .capture
            .lock()
            .map_err(|_| "抓包运行状态已损坏".to_string())?;
        capture
            .running
            .then(|| capture.session_id.as_deref() == Some(session_id.as_str()))
    };
    if let Some(matches) = existing_session_matches {
        return if matches {
            runtime_status(state)
        } else {
            Err("代理已在另一个会话中运行，请先停止抓包".to_string())
        };
    }

    state.storage.get_session(&session_id)?;
    let upstream = state.storage.effective_upstream_proxy()?;
    let listener_settings = state.storage.get_capture_listener_settings()?;
    let address = capture_listen_address(listener_settings.lan_enabled, state.proxy_port);
    let client_access =
        ClientAccessPolicy::from_settings(&listener_settings, listener_settings.lan_enabled)?;
    let proxy = ProxyHandle::start(
        address,
        client_access,
        session_id.clone(),
        upstream,
        state.certificate_authority.clone(),
        app.clone(),
    )
    .await?;
    if let Err(error) = state.storage.set_active_session(Some(&session_id)) {
        proxy.stop().await;
        return Err(error);
    }
    if manage_system_proxy {
        if let Err(error) = activate_system_proxy(state) {
            let _ = state.storage.set_active_session(None);
            proxy.stop().await;
            return Err(error);
        }
    }
    let mut capture = state
        .capture
        .lock()
        .map_err(|_| "抓包运行状态已损坏".to_string())?;
    capture.running = true;
    capture.session_id = Some(session_id);
    capture.listen_address = Some(address);
    capture.proxy = Some(proxy);
    drop(capture);
    runtime_status(state)
}

#[tauri::command]
async fn set_capture_running(
    running: bool,
    session_id: Option<String>,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<RuntimeStatus, String> {
    if running {
        let session_id = session_id
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| "开始抓包需要指定会话".to_string())?;
        start_capture_for_session(&app, &state, session_id, true).await?;
    } else {
        // Everything that can bail out happens before the takeover is released.
        // These are std mutexes, so one panic elsewhere poisons them for the
        // process. Returning after the restore would hand the system proxy back
        // and then abort with capture still marked running and nothing emitted;
        // returning here costs at most an already-detached reverse proxy, which
        // shuts itself down when its shutdown sender drops.
        let reverse_proxy = state
            .reverse_proxy
            .lock()
            .map_err(|_| "免代理入口运行状态已损坏".to_string())?
            .take();
        let (proxy, stopped_session_id) = {
            let mut capture = state
                .capture
                .lock()
                .map_err(|_| "抓包运行状态已损坏".to_string())?;
            capture.running = false;
            let stopped_session_id = capture.session_id.take();
            capture.listen_address = None;
            (capture.proxy.take(), stopped_session_id)
        };
        // Released only once the teardown is committed and nothing left can
        // short-circuit. A failure here is reported, not allowed to strand.
        let restore_result = restore_system_proxy(&state);
        if let Some(session_id) = stopped_session_id.as_deref() {
            state.breakpoints.cancel_session(session_id, "抓包已停止");
        }
        let session_cleared = state.storage.set_active_session(None);
        if let Some(proxy) = proxy {
            proxy.stop().await;
        }
        if let Some(reverse_proxy) = reverse_proxy {
            reverse_proxy.handle.stop().await;
        }
        // Teardown is complete, so the frontend hears about it before anything
        // is reported as a failure — returning first left the UI showing 抓包中
        // for a capture that had already stopped, with the takeover switch gated
        // on that same stale flag.
        let emitted = emit_capture_status(&app, &state);
        if emitted.is_err() {
            // Building the full status re-reads the same storage that just
            // failed, so on a locked database the push never happens and the UI
            // is stranded again. This carries the one fact that cannot be got
            // wrong: the capture is down.
            let _ = emit(&app, "capture://stopped", &());
        }
        // The teardown failures come first: they are what the user has to act
        // on, and a push that failed must not stand in for them.
        restore_result?;
        session_cleared?;
        return emitted;
    }

    let status = runtime_status(&state)?;
    emit(&app, "capture://status", &status)?;
    Ok(status)
}

pub(crate) fn persist_captured_request(
    app: &tauri::AppHandle,
    request: CapturedRequestInput,
) -> Result<RequestRecord, String> {
    let state = app.state::<AppState>();
    if request.resource_type == "sse" {
        if let Some(updated) = state.storage.update_streaming_request(request.clone())? {
            let list_item: RequestListItem = state.storage.get_request_list_item(&updated.id)?;
            let list_event = RequestListEvent {
                session_id: request.session_id,
                item: list_item,
            };
            emit(app, "capture://request-updated", &list_event)?;
            return Ok(updated);
        }
    }
    let (request, event) = state.storage.store_request(request)?;
    let list_item: RequestListItem = state.storage.get_request_list_item(&request.id)?;
    let list_event = RequestListEvent {
        session_id: event.session_id.clone(),
        item: list_item,
    };
    emit(app, "capture://event", &event)?;
    // No capture://request beside these two. It carried the very RequestListItem
    // that capture://request-created already ships inside list_event, nothing has
    // ever listened for it, and it is not in the event contract documented in
    // docs/reqable-benchmark-ui-iteration-plan.md. Dropping it also lets the item
    // move into list_event instead of being cloned once per captured request.
    emit(app, "capture://request-created", &list_event)?;
    Ok(request)
}

/// Pushes the current capture and reverse-proxy state to the frontend and
/// returns it.
///
/// Used on the stop path so a teardown that ends in an error still leaves the UI
/// agreeing with the backend about what is running. Returning the status lets
/// the caller emit exactly once and still have something to hand back.
fn emit_capture_status(app: &tauri::AppHandle, state: &AppState) -> Result<RuntimeStatus, String> {
    let status = runtime_status(state)?;
    emit(app, "capture://status", &status)?;
    let reverse_status = reverse_proxy_status(state)?;
    emit(app, "reverse-proxy://status", &reverse_status)?;
    Ok(status)
}

fn runtime_status(state: &AppState) -> Result<RuntimeStatus, String> {
    let capture = state
        .capture
        .lock()
        .map_err(|_| "抓包运行状态已损坏".to_string())?;
    let system_proxy = system_proxy_status(state)?;
    let listener_settings = state.storage.get_capture_listener_settings()?;
    let configured_host =
        capture_listen_address(listener_settings.lan_enabled, state.proxy_port).ip();
    let listen_host = capture
        .listen_address
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|| configured_host.to_string());
    Ok(RuntimeStatus {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        proxy_port: state.proxy_port,
        listen_host,
        lan_enabled: listener_settings.lan_enabled,
        access_mode: listener_settings.access_mode,
        access_rules: listener_settings.access_rules,
        lan_addresses: discover_lan_addresses(),
        proxy_running: capture.running,
        active_session_id: capture.session_id.clone(),
        ca_installed: state.ca_installed.load(Ordering::SeqCst),
        transparent_mode_available: false,
        system_proxy_enabled: system_proxy.enabled,
        system_proxy_active: system_proxy.active,
        system_proxy_recovery_pending: system_proxy.recovery_pending,
    })
}

fn reverse_proxy_status(state: &AppState) -> Result<ReverseProxyStatus, String> {
    let settings = state.storage.get_reverse_proxy_settings()?;
    let runtime = state
        .reverse_proxy
        .lock()
        .map_err(|_| "免代理入口运行状态已损坏".to_string())?;
    let bound_port = runtime.as_ref().map(|runtime| runtime.bound_address.port());
    // Holding a handle only means nobody stopped it; the accept loop can still
    // have died underneath us, and claiming 运行中 then points the user at an
    // entry point that refuses every connection.
    let running = runtime
        .as_ref()
        .is_some_and(|runtime| runtime.handle.is_serving());
    let local_url = bound_port.map(|port| format!("http://127.0.0.1:{port}"));
    let lan_urls = if running && settings.lan_enabled {
        bound_port
            .map(|port| {
                discover_lan_addresses()
                    .into_iter()
                    .map(|address| format!("http://{address}:{port}"))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok(ReverseProxyStatus {
        running,
        target_url: settings.target_url,
        local_port: settings.local_port,
        lan_enabled: settings.lan_enabled,
        preserve_host: settings.preserve_host,
        bound_port,
        local_url,
        lan_urls,
        session_id: runtime.as_ref().map(|runtime| runtime.session_id.clone()),
    })
}

fn capture_listen_address(lan_enabled: bool, port: u16) -> SocketAddr {
    let address = if lan_enabled {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };
    SocketAddr::new(IpAddr::V4(address), port)
}

fn discover_lan_addresses() -> Vec<String> {
    let targets = [
        "1.1.1.1:80",
        "10.255.255.254:80",
        "172.31.255.254:80",
        "192.168.255.254:80",
        "169.254.255.254:80",
    ];
    let mut addresses = Vec::new();
    for target in targets {
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            continue;
        };
        if socket.connect(target).is_err() {
            continue;
        }
        let Ok(SocketAddr::V4(local)) = socket.local_addr() else {
            continue;
        };
        let address = *local.ip();
        if (address.is_private() || address.is_link_local()) && !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses.sort_unstable();
    addresses
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

fn system_proxy_status(state: &AppState) -> Result<SystemProxySettings, String> {
    let preferences = state.storage.get_system_proxy_preferences()?;
    let runtime = state
        .system_proxy
        .lock()
        .map_err(|_| "系统代理运行状态已损坏".to_string())?;
    Ok(SystemProxySettings {
        enabled: preferences.enabled,
        active: runtime.active,
        recovery_pending: system_proxy::recovery_is_pending(
            runtime.active,
            state.storage.has_system_proxy_recovery()?,
        ),
        bypass: preferences.bypass,
        last_error: runtime.last_error.clone(),
    })
}

fn activate_system_proxy(state: &AppState) -> Result<(), String> {
    let preferences = state.storage.get_system_proxy_preferences()?;
    if !preferences.enabled {
        return Ok(());
    }
    // An outstanding record means the machine is still pointing at us from a
    // takeover that never got restored. Snapshotting now would capture ShowNet's
    // own settings and overwrite the only copy of what the user actually had —
    // every later "restore" would then hand them a proxy on a dead port.
    if state.storage.has_system_proxy_recovery()? {
        // Both routes are named on purpose. If the restore fails for a reason
        // that will not clear — a renamed network service, a registry key held
        // by policy — 重试恢复 can never succeed, and pointing only at it sends
        // the user round a loop. Turning the takeover off returns above, so
        // capture still works while they sort the machine out by hand.
        return Err(
            "上一次系统代理接管尚未恢复；请在「设置 → 流量路由」点击「重试恢复」后再开始抓包。若恢复始终失败，可关闭「接管系统代理」照常抓包，并手动检查系统代理设置。"
                .to_string(),
        );
    }
    let snapshot = system_proxy::capture_snapshot()?;
    state.storage.save_system_proxy_recovery(&snapshot)?;
    match system_proxy::apply(
        &snapshot,
        "127.0.0.1",
        state.proxy_port,
        &preferences.bypass,
    ) {
        Ok(()) => {
            let mut runtime = state
                .system_proxy
                .lock()
                .map_err(|_| "系统代理运行状态已损坏".to_string())?;
            runtime.active = true;
            runtime.last_error = None;
            Ok(())
        }
        Err(apply_error) => {
            let restore_result = restore_system_proxy_record(&state.storage);
            let message = match restore_result {
                Ok(()) => format!("接管系统代理失败，原设置已恢复: {apply_error}"),
                Err(restore_error) => {
                    format!("接管系统代理失败，且自动恢复未完成: {apply_error}; {restore_error}")
                }
            };
            if let Ok(mut runtime) = state.system_proxy.lock() {
                runtime.active = false;
                runtime.last_error = Some(message.clone());
            }
            Err(message)
        }
    }
}

fn restore_system_proxy(state: &AppState) -> Result<(), String> {
    match restore_system_proxy_record(&state.storage) {
        Ok(()) => {
            let mut runtime = state
                .system_proxy
                .lock()
                .map_err(|_| "系统代理运行状态已损坏".to_string())?;
            runtime.active = false;
            runtime.last_error = None;
            Ok(())
        }
        Err(error) => {
            if let Ok(mut runtime) = state.system_proxy.lock() {
                // We are no longer holding the takeover on purpose — we tried to
                // give the settings back and could not. Staying `active` would
                // mean the snapshot still in storage reads as "in use rather
                // than owed", which hides the recovery notice and its retry
                // button behind a status that claims everything is fine.
                runtime.active = false;
                runtime.last_error = Some(error.clone());
            }
            Err(error)
        }
    }
}

fn restore_system_proxy_record(storage: &Storage) -> Result<(), String> {
    let Some(snapshot) = storage.get_system_proxy_recovery()? else {
        return Ok(());
    };
    system_proxy::restore(&snapshot)?;
    storage.clear_system_proxy_recovery()
}

fn ca_status(state: &AppState) -> CertificateAuthorityStatus {
    CertificateAuthorityStatus {
        generated: true,
        installed: state.ca_installed.load(Ordering::SeqCst),
        fingerprint: state.certificate_authority.fingerprint().to_string(),
        certificate_path: state.certificate_path.to_string_lossy().to_string(),
        created_at: state.certificate_authority.created_at(),
    }
}

fn mcp_server_status(state: &AppState) -> Result<McpServerStatus, String> {
    let settings = state.storage.get_mcp_server_settings()?;
    let runtime = state
        .mcp
        .lock()
        .map_err(|_| "MCP 运行状态已损坏".to_string())?;
    Ok(McpServerStatus {
        enabled: settings.enabled,
        running: runtime.handle.is_some(),
        starting: runtime.starting,
        host: "127.0.0.1".to_string(),
        port: settings.port,
        endpoint: format!("http://127.0.0.1:{}/mcp", settings.port),
        protocol_version: mcp::PROTOCOL_VERSION.to_string(),
        tool_count: mcp::tool_count(settings.allow_writes),
        allow_writes: settings.allow_writes,
        has_access_token: settings.has_access_token,
        last_error: runtime.last_error.clone(),
        recent_clients: runtime.recent_clients.clone(),
        last_request_at: runtime.last_request_at,
    })
}

pub(crate) fn record_mcp_request_activity(app: &tauri::AppHandle, message: &Value) {
    let method = message.get("method").and_then(Value::as_str);
    let client = mcp::initialize_client_info(message);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default();
    let should_emit = client.is_some() || method == Some("tools/call");
    let state = app.state::<AppState>();
    let Ok(mut runtime) = state.mcp.lock() else {
        return;
    };
    runtime.last_request_at = Some(now);
    if let Some((name, version)) = client {
        runtime
            .recent_clients
            .retain(|entry| entry.name != name || entry.version != version);
        runtime.recent_clients.insert(
            0,
            McpRecentClient {
                name,
                version,
                connected_at: now,
            },
        );
        runtime.recent_clients.truncate(5);
    }
    drop(runtime);
    if should_emit {
        if let Ok(status) = mcp_server_status(&state) {
            let _ = emit(app, "settings://mcp-server", &status);
        }
    }
}

async fn restart_mcp_server(app: &tauri::AppHandle) -> Result<McpServerStatus, String> {
    let previous = {
        let state = app.state::<AppState>();
        let mut runtime = state
            .mcp
            .lock()
            .map_err(|_| "MCP 运行状态已损坏".to_string())?;
        runtime.starting = true;
        runtime.last_error = None;
        runtime.handle.take()
    };
    if let Some(handle) = previous {
        handle.stop().await;
    }

    let settings = app
        .state::<AppState>()
        .storage
        .effective_mcp_server_settings()?;
    let result = if settings.enabled {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), settings.port);
        McpServerHandle::start(address, app.clone()).await.map(Some)
    } else {
        Ok(None)
    };
    let state = app.state::<AppState>();
    {
        let mut runtime = state
            .mcp
            .lock()
            .map_err(|_| "MCP 运行状态已损坏".to_string())?;
        runtime.starting = false;
        match result {
            Ok(handle) => runtime.handle = handle,
            Err(error) => runtime.last_error = Some(error),
        }
    }
    let status = mcp_server_status(&state)?;
    emit(app, "settings://mcp-server", &status)?;
    Ok(status)
}

#[cfg(target_os = "macos")]
fn certificate_is_installed(fingerprint: &str) -> bool {
    use security_framework::policy::SecPolicy;
    use security_framework::trust::{SecTrust, TrustOptions};
    use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};

    let expected = fingerprint.replace(':', "").to_ascii_uppercase();
    [Domain::User, Domain::Admin, Domain::System]
        .into_iter()
        .any(|domain| {
            let trust = TrustSettings::new(domain);
            trust.iter().is_ok_and(|certificates| {
                certificates.into_iter().any(|certificate| {
                    if !certificate_der_matches_fingerprint(&certificate.to_der(), &expected) {
                        return false;
                    }
                    match trust.tls_trust_settings_for_certificate(&certificate) {
                        Ok(Some(
                            TrustSettingsForCertificate::TrustRoot
                            | TrustSettingsForCertificate::TrustAsRoot,
                        )) => true,
                        Ok(None) => {
                            let policy = SecPolicy::create_x509();
                            let Ok(mut evaluation) = SecTrust::create_with_certificates(
                                std::slice::from_ref(&certificate),
                                std::slice::from_ref(&policy),
                            ) else {
                                return false;
                            };
                            if evaluation
                                .set_options(
                                    TrustOptions::LEAF_IS_CA | TrustOptions::USE_TRUST_SETTINGS,
                                )
                                .is_err()
                            {
                                return false;
                            }
                            evaluation.evaluate_with_error().is_ok()
                        }
                        _ => false,
                    }
                })
            })
        })
}

#[cfg(target_os = "windows")]
fn certificate_is_installed(fingerprint: &str) -> bool {
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore,
        CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
    };

    let store_name = "Root\0".encode_utf16().collect::<Vec<_>>();
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            store_name.as_ptr().cast(),
        )
    };
    if store.is_null() {
        return false;
    }

    let mut previous = std::ptr::null_mut();
    let found = loop {
        // CertEnumCertificatesInStore frees the previous context as it advances.
        let current = unsafe { CertEnumCertificatesInStore(store, previous) };
        previous = current;
        if current.is_null() {
            break false;
        }
        let context = unsafe { &*current };
        let der = unsafe {
            std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize)
        };
        if certificate_der_matches_fingerprint(der, fingerprint) {
            unsafe { CertFreeCertificateContext(current) };
            break true;
        }
    };
    unsafe { CertCloseStore(store, 0) };
    found
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn certificate_is_installed(_fingerprint: &str) -> bool {
    false
}

fn certificate_der_matches_fingerprint(der: &[u8], fingerprint: &str) -> bool {
    let expected = fingerprint
        .chars()
        .filter(|character| *character != ':' && !character.is_ascii_whitespace())
        .collect::<String>();
    if expected.len() != 64
        || !expected
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return false;
    }
    let actual = Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    actual.eq_ignore_ascii_case(&expected)
}

fn certificate_trust_verification_error(platform: &str) -> String {
    match platform {
        "macos" => "macOS 已导入证书，但未将它设为受信任的 SSL 根证书",
        "windows" => "Windows 已导入证书，但当前用户 Root 证书库中未找到匹配的 ShowNet CA",
        _ => "已导入证书，但当前平台未确认 ShowNet CA 已受信任",
    }
    .to_string()
}

#[cfg(target_os = "macos")]
fn install_certificate_into_user_trust(path: &std::path::Path) -> Result<(), String> {
    let user_home = std::env::var_os("HOME").ok_or_else(|| "无法定位用户目录".to_string())?;
    let keychain = PathBuf::from(user_home).join("Library/Keychains/login.keychain-db");
    let output = std::process::Command::new("security")
        .args(["add-trusted-cert", "-r", "trustRoot", "-k"])
        .arg(keychain)
        .arg(path)
        .output()
        .map_err(|error| format!("启动 macOS 证书安装失败: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "macOS 未完成证书安装: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(target_os = "windows")]
fn install_certificate_into_user_trust(path: &std::path::Path) -> Result<(), String> {
    let output = std::process::Command::new("certutil")
        .args(["-user", "-addstore", "Root"])
        .arg(path)
        .output()
        .map_err(|error| format!("启动 Windows 证书安装失败: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Windows 未完成证书安装: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn install_certificate_into_user_trust(_path: &std::path::Path) -> Result<(), String> {
    Err("当前平台暂不支持自动安装 Root CA，请导出后手动安装".to_string())
}

fn emit<S: Serialize + Clone>(
    app: &tauri::AppHandle,
    event: &str,
    payload: &S,
) -> Result<(), String> {
    app.emit(event, payload).map_err(|error| error.to_string())
}

fn emit_storage_changed(app: &tauri::AppHandle, state: &AppState) -> Result<StorageStats, String> {
    let stats = state.storage.storage_stats()?;
    emit(app, "storage://changed", &stats)?;
    Ok(stats)
}

#[cfg(target_os = "macos")]
fn open_directory(path: &std::path::Path) -> Result<(), String> {
    std::process::Command::new("open")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("打开数据目录失败: {error}"))
}

#[cfg(target_os = "windows")]
fn open_directory(path: &std::path::Path) -> Result<(), String> {
    std::process::Command::new("explorer")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("打开数据目录失败: {error}"))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn open_directory(path: &std::path::Path) -> Result<(), String> {
    std::process::Command::new("xdg-open")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("打开数据目录失败: {error}"))
}

fn validate_output_path(path: String) -> Result<PathBuf, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("导出路径不能为空".to_string());
    }
    let path = PathBuf::from(trimmed);
    if path.file_name().is_none() {
        return Err("导出路径必须包含文件名".to_string());
    }
    Ok(path)
}

fn validate_output_directory(path: String) -> Result<PathBuf, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("导出目录不能为空".to_string());
    }
    let path = PathBuf::from(trimmed);
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("导出目录不能包含 ..".to_string());
    }
    Ok(path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init());
    #[cfg(desktop)]
    let builder = builder.menu(build_app_menu).on_menu_event(|app, event| {
        let action = match event.id().as_ref() {
            "shownet-edit-undo" => Some("undo"),
            "shownet-edit-redo" => Some("redo"),
            "shownet-edit-cut" => Some("cut"),
            "shownet-edit-copy" => Some("copy"),
            "shownet-edit-paste" => Some("paste"),
            "shownet-edit-select-all" => Some("selectAll"),
            _ => None,
        };
        if let Some(action) = action {
            let _ = app.emit("app://edit-command", action);
        }
    });
    builder
        .setup(|app| {
            let default_data_dir = app.path().app_data_dir()?;
            let current_executable = std::env::current_exe().ok();
            let (data_dir, isolated_data_directory) = resolve_data_directory(
                default_data_dir,
                std::env::var_os(DATA_DIRECTORY_ENV),
                current_executable.as_deref(),
                cfg!(target_os = "windows"),
            )
            .map_err(std::io::Error::other)?;
            let soak_startup = soak_startup_from_values(
                std::env::var_os(SOAK_READY_FILE_ENV),
                std::env::var_os(SOAK_PROXY_PORT_ENV),
                std::env::var_os(SOAK_SESSION_NAME_ENV),
                std::env::var_os(SOAK_UPSTREAM_CA_FILE_ENV),
                isolated_data_directory,
            )
            .map_err(std::io::Error::other)?;
            let proxy_port = soak_startup
                .as_ref()
                .map(|startup| startup.proxy_port)
                .unwrap_or(DEFAULT_CAPTURE_PROXY_PORT);
            std::fs::create_dir_all(&data_dir)?;
            let storage =
                Storage::open(&data_dir.join("shownet.sqlite3")).map_err(std::io::Error::other)?;
            let (certificate_authority, created) = CertificateAuthority::load_or_create(
                storage
                    .get_certificate_authority()
                    .map_err(std::io::Error::other)?,
            )
            .map_err(std::io::Error::other)?;
            if let Some(material) = created {
                storage
                    .save_certificate_authority(&material)
                    .map_err(std::io::Error::other)?;
            }
            let certificate_path = data_dir.join("shownet-root-ca.pem");
            std::fs::write(
                &certificate_path,
                certificate_authority.certificate_pem().as_bytes(),
            )?;
            let ca_installed = certificate_is_installed(certificate_authority.fingerprint());
            storage
                .ensure_mcp_server_settings()
                .map_err(std::io::Error::other)?;
            if let Ok(Some(value)) = storage.load_app_setting_json("outbound_tls") {
                if let Some(preset_id) = value.get("presetId").and_then(|v| v.as_str()) {
                    let _ = tls_outbound::set_active_preset(preset_id);
                } else if let Some(profile) = value.get("profile").and_then(|v| v.as_str()) {
                    if let Ok(id) = tls_clienthello_catalog::resolve_preset_id(profile) {
                        let _ = tls_outbound::set_active_preset(id);
                    } else {
                        tls_outbound::set_global_profile(tls_outbound::OutboundTlsProfile::parse(
                            profile,
                        ));
                    }
                }
                if let Some(auto) = value.get("autoFromInbound").and_then(|v| v.as_bool()) {
                    tls_outbound::set_auto_from_inbound(auto);
                }
                // Never enable fake impersonate engine from persisted flag without a real stack.
                let _ = value.get("impersonate");
                tls_impersonate::set_impersonate_requested(false);
            }
            if let Ok(Some(value)) = storage.load_app_setting_json("px_console") {
                if let Some(v) = value.get("decryptEnabled").and_then(|v| v.as_bool()) {
                    px_analysis::set_px_decrypt_enabled(v);
                }
                if let Some(v) = value.get("interceptEcData").and_then(|v| v.as_bool()) {
                    px_analysis::set_px_intercept_ec_data(v);
                }
            }
            let system_proxy_recovery_error = restore_system_proxy_record(&storage).err();
            storage
                .set_active_session(None)
                .map_err(std::io::Error::other)?;
            storage
                .cleanup_expired_sessions()
                .map_err(std::io::Error::other)?;
            storage
                .ensure_initial_session()
                .map_err(std::io::Error::other)?;
            let request_cookie_jar = Arc::new(reqwest_cookie_store::CookieStoreMutex::new(
                storage
                    .load_request_cookie_store()
                    .map_err(std::io::Error::other)?,
            ));
            let soak_diagnostics = soak_startup.as_ref().map(|startup| SoakDiagnosticsRuntime {
                output_file: startup.cancellation_file.clone(),
                session_id: None,
                samples: Vec::new(),
            });
            let breakpoint_app = app.handle().clone();
            let breakpoints = Arc::new(BreakpointCoordinator::new(Arc::new(move || {
                let _ = breakpoint_app.emit("capture://breakpoints-changed", ());
            })));
            app.manage(AppState {
                analysis: Mutex::new(AnalysisRuntime::default()),
                browser: Mutex::new(None),
                breakpoints,
                capture: Mutex::new(CaptureRuntime::default()),
                mcp: Mutex::new(McpRuntime::default()),
                request_queries: Mutex::new(RequestQueryRuntime::default()),
                soak_diagnostics: Mutex::new(soak_diagnostics),
                replay: Mutex::new(ReplayRuntime::default()),
                reverse_proxy: Mutex::new(None),
                request_cookie_jar,
                system_proxy: Mutex::new(SystemProxyRuntime {
                    active: false,
                    last_error: system_proxy_recovery_error,
                }),
                storage,
                data_directory: data_dir,
                proxy_port,
                certificate_authority: Arc::new(certificate_authority),
                certificate_path,
                ca_installed: AtomicBool::new(ca_installed),
            });
            if let Some(startup) = soak_startup {
                let soak_app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    initialize_soak_capture(soak_app_handle, startup).await;
                });
            }
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let _ = restart_mcp_server(&app_handle).await;
            });
            let cleanup_app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(6 * 60 * 60)).await;
                    let state = cleanup_app_handle.state::<AppState>();
                    if state.storage.cleanup_expired_sessions().unwrap_or_default() > 0 {
                        let _ = emit_storage_changed(&cleanup_app_handle, &state);
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_runtime_status,
            check_for_updates,
            get_tls_interception_settings,
            save_tls_interception_settings,
            save_capture_listener_settings,
            get_reverse_proxy_status,
            start_reverse_proxy,
            stop_reverse_proxy,
            get_data_storage_settings,
            save_data_storage_settings,
            get_storage_stats,
            open_data_directory,
            clear_all_session_data,
            get_ca_status,
            export_ca_certificate,
            install_ca_certificate,
            get_android_setup_status,
            prepare_android_device,
            reset_android_device_proxy,
            launch_proxy_terminal,
            launch_proxy_browser,
            stop_proxy_browser,
            get_proxy_browser_status,
            browser_evaluate,
            browser_click,
            browser_screenshot,
            browser_navigate,
            browser_insert_text,
            browser_dispatch_key,
            browser_install_lab,
            run_web_risk_fixture_probe,
            list_sessions,
            create_session,
            rename_session,
            delete_session,
            query_request_list,
            query_request_window,
            cancel_request_query,
            cancel_request_query_and_wait,
            get_soak_diagnostics_status,
            record_soak_cancellation_sample,
            get_request_detail,
            get_request_list_item,
            list_saved_request_views,
            save_request_view,
            delete_request_view,
            get_request_annotation,
            save_request_annotation,
            start_replay_batch,
            list_replay_batches,
            cancel_replay_batch,
            create_request_draft_from_capture,
            save_request_draft,
            list_request_drafts,
            reveal_request_draft_auth,
            list_request_collection_workspace,
            save_request_collection,
            reveal_request_collection_auth,
            delete_request_collection,
            save_request_collection_folder,
            delete_request_collection_folder,
            move_request_draft,
            update_request_drafts_batch,
            preview_request_collection_import,
            commit_request_collection_import,
            preview_request_collection_sync,
            commit_request_collection_sync,
            export_request_collection,
            send_request_draft,
            cancel_request_draft,
            list_request_runs,
            list_request_cookies,
            delete_request_cookie,
            clear_request_cookies,
            list_environments,
            save_environment,
            save_environment_variable,
            reveal_environment_variable,
            delete_environment_variable,
            delete_environment,
            list_capture_rules,
            list_capture_rule_revisions,
            restore_capture_rule_revision,
            save_capture_rule_draft,
            set_capture_rule_enabled,
            get_breakpoint_queue,
            resolve_breakpoint,
            preview_capture_rule,
            list_rule_trace_for_request,
            run_connection_diagnostics,
            get_crypto_code_snippets,
            get_browser_hook_script,
            record_browser_hook,
            list_browser_hooks,
            get_tls_fingerprints,
            export_session_file,
            import_session_file,
            export_algorithm_replay_package,
            export_evaluation_package,
            get_outbound_tls_profile,
            set_outbound_tls_profile,
            set_outbound_tls_auto_from_inbound,
            get_px_settings,
            set_px_settings,
            list_px_evidence,
            decode_px_payload,
            run_autonomous_session_analysis,
            get_upstream_proxy_settings,
            save_upstream_proxy_settings,
            detect_env_upstream_proxy,
            probe_upstream_proxy,
            get_system_proxy_settings,
            save_system_proxy_settings,
            retry_system_proxy_recovery,
            get_ai_provider_settings,
            get_ai_analysis_settings,
            list_ai_models,
            save_ai_provider_settings,
            save_ai_analysis_settings,
            get_mcp_server_status,
            list_built_in_skills,
            get_analysis_skill_plan,
            build_signature_harness,
            list_mcp_tools,
            save_mcp_server_settings,
            reveal_mcp_access_token,
            rotate_mcp_access_token,
            list_external_mcp_servers,
            save_external_mcp_server,
            delete_external_mcp_server,
            test_external_mcp_server,
            list_analysis_reports,
            list_analysis_messages,
            list_analysis_activities,
            list_analysis_skill_runs,
            get_analysis_graph_run,
            is_ai_analysis_running,
            start_ai_analysis,
            cancel_ai_analysis,
            followup_ai_analysis,
            list_websocket_frames,
            list_sse_events,
            set_capture_running,
        ])
        .build(tauri::generate_context!())
        .expect("error while building ShowNet")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                let state = app.state::<AppState>();
                state.breakpoints.cancel_all("应用已退出");
                let browser = state
                    .browser
                    .lock()
                    .ok()
                    .and_then(|mut browser| browser.take());
                drop(browser);
                let _ = restore_system_proxy(&state);
                let _ = state.storage.set_active_session(None);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_default_data_directory_and_rejects_relative_override() {
        let default = std::env::temp_dir().join("shownet-default-data");
        assert_eq!(
            resolve_data_directory(default.clone(), None, None, false).unwrap(),
            (default, false)
        );
        assert!(resolve_data_directory(
            std::env::temp_dir(),
            Some(OsString::from("relative/soak-data")),
            None,
            false,
        )
        .is_err());
    }

    #[test]
    fn uses_windows_portableapps_data_beside_the_application() {
        let portable_root = std::env::temp_dir().join("ShowNetPortable");
        let executable = portable_root
            .join("App")
            .join("shownet")
            .join("ShowNet.exe");
        let default = std::env::temp_dir().join("shownet-default-data");

        assert_eq!(
            resolve_data_directory(default.clone(), None, Some(&executable), true).unwrap(),
            (portable_root.join("Data").join("ShowNet"), false)
        );
        assert_eq!(
            resolve_data_directory(default.clone(), None, Some(&executable), false).unwrap(),
            (default, false)
        );
    }

    #[test]
    fn explicit_data_directory_wins_over_portable_layout() {
        let portable_executable = std::env::temp_dir()
            .join("ShowNetPortable")
            .join("App")
            .join("ShowNet")
            .join("ShowNet.exe");
        let configured = std::env::temp_dir().join("shownet-explicit-data");

        assert_eq!(
            resolve_data_directory(
                std::env::temp_dir().join("shownet-default-data"),
                Some(configured.clone().into_os_string()),
                Some(&portable_executable),
                true,
            )
            .unwrap(),
            (configured, true)
        );
    }

    #[test]
    fn ignores_similar_non_portable_executable_layouts() {
        let default = std::env::temp_dir().join("shownet-default-data");
        let installed_executable = std::env::temp_dir()
            .join("Program Files")
            .join("ShowNet")
            .join("ShowNet.exe");

        assert_eq!(
            resolve_data_directory(default.clone(), None, Some(&installed_executable), true,)
                .unwrap(),
            (default, false)
        );
    }

    #[test]
    fn requires_an_isolated_directory_for_soak_startup() {
        let ready = std::env::temp_dir().join("shownet-soak-ready.json");
        assert!(soak_startup_from_values(
            Some(ready.clone().into_os_string()),
            None,
            None,
            None,
            false
        )
        .is_err());
        assert!(
            soak_startup_from_values(None, Some(OsString::from("18889")), None, None, true)
                .is_err()
        );
    }

    #[test]
    fn parses_explicit_soak_port_ready_file_and_session_name() {
        let ready = std::env::temp_dir().join("shownet-soak-ready.json");
        let startup = soak_startup_from_values(
            Some(ready.clone().into_os_string()),
            Some(OsString::from("18889")),
            Some(OsString::from("Release smoke")),
            None,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(startup.ready_file, ready);
        assert_eq!(
            startup.cancellation_file,
            std::env::temp_dir().join("cancellation-ipc.json")
        );
        assert_eq!(startup.proxy_port, 18889);
        assert_eq!(startup.session_name, "Release smoke");
        assert!(soak_startup_from_values(
            Some(
                std::env::temp_dir()
                    .join("shownet-invalid-port.json")
                    .into_os_string()
            ),
            Some(OsString::from("0")),
            None,
            None,
            true,
        )
        .is_err());
    }

    #[test]
    fn restricts_soak_upstream_root_to_the_isolated_run_directory() {
        let run_directory =
            std::env::temp_dir().join(format!("shownet-soak-root-{}", uuid::Uuid::new_v4()));
        let fixture_directory = run_directory.join("protocol-fixture");
        std::fs::create_dir_all(&fixture_directory).unwrap();
        let ready = run_directory.join("ready.json");
        let root = fixture_directory.join("root.pem");
        std::fs::write(&root, "test certificate placeholder").unwrap();

        let startup = soak_startup_from_values(
            Some(ready.into_os_string()),
            None,
            None,
            Some(root.clone().into_os_string()),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(startup.upstream_ca_file, Some(root.canonicalize().unwrap()));
        assert!(soak_startup_from_values(
            Some(run_directory.join("other-ready.json").into_os_string()),
            None,
            None,
            Some(OsString::from("relative-root.pem")),
            true,
        )
        .is_err());
        std::fs::remove_dir_all(run_directory).unwrap();
    }

    #[test]
    fn selects_loopback_or_all_ipv4_interfaces_from_listener_scope() {
        assert_eq!(
            capture_listen_address(false, 8888),
            "127.0.0.1:8888".parse().unwrap()
        );
        assert_eq!(
            capture_listen_address(true, 8888),
            "0.0.0.0:8888".parse().unwrap()
        );
    }

    #[test]
    fn matches_certificate_fingerprint_by_der_bytes() {
        let der = b"shownet-test-certificate";
        let fingerprint = Sha256::digest(der)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        assert!(certificate_der_matches_fingerprint(der, &fingerprint));
        assert!(!certificate_der_matches_fingerprint(
            b"different-certificate",
            &fingerprint
        ));
        assert!(!certificate_der_matches_fingerprint(der, "invalid"));
    }

    #[test]
    fn reports_certificate_trust_failure_for_the_active_platform() {
        assert!(certificate_trust_verification_error("macos").starts_with("macOS"));
        assert!(certificate_trust_verification_error("windows").starts_with("Windows"));
        assert!(certificate_trust_verification_error("linux").starts_with("已导入证书"));
    }

    #[test]
    fn request_query_runtime_is_latest_wins_and_explicitly_cancellable() {
        let mut runtime = RequestQueryRuntime::default();
        let first = runtime.start("request-first").unwrap();
        let second = runtime.start("request-second").unwrap();

        assert!(first.load(Ordering::Acquire));
        assert!(!second.load(Ordering::Acquire));
        assert_eq!(runtime.cancellations.len(), 2);
        assert!(runtime.is_running("request-first"));
        assert!(runtime.is_running("request-second"));
        assert!(!runtime.cancel("request-first"));
        assert!(runtime.cancel("request-second"));
        assert!(second.load(Ordering::Acquire));

        runtime.finish("request-second", &second);
        assert!(!runtime.is_running("request-second"));
        assert!(runtime.is_running("request-first"));
        runtime.finish("request-first", &first);
        assert!(runtime.cancellations.is_empty());
    }

    #[test]
    fn stale_request_query_finish_does_not_remove_reused_id() {
        let mut runtime = RequestQueryRuntime::default();
        let stale = runtime.start("request-reused").unwrap();
        let active = runtime.start("request-reused").unwrap();

        assert!(stale.load(Ordering::Acquire));
        runtime.finish("request-reused", &stale);
        assert!(runtime
            .cancellations
            .get("request-reused")
            .is_some_and(|registered| registered
                .iter()
                .any(|instance| Arc::ptr_eq(instance, &active))));

        runtime.finish("request-reused", &active);
        assert!(runtime.cancellations.is_empty());
    }

    #[test]
    fn request_query_runtime_rejects_unsafe_ids() {
        let mut runtime = RequestQueryRuntime::default();
        assert!(runtime.start("").is_err());
        assert!(runtime.start("contains spaces").is_err());
        assert!(runtime.start(&"a".repeat(129)).is_err());
        assert!(runtime.start("request-safe_1:window-2").is_ok());
    }
}
