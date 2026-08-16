use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout, Duration};
use uuid::Uuid;

use crate::browser_bus::BrowserBus;
use crate::models::ProxyBrowserStatus;
use crate::tls_clienthello_catalog::ClientHelloPreset;
use crate::tls_outbound;
use std::sync::Arc;

const LAB_INDEX: &str = include_str!("../../public/lab/index.html");
const LAB_SCRIPT: &str = include_str!("../../public/lab/lab.js");
const LAB_STYLE: &str = include_str!("../../public/lab/lab.css");
const HOOK_RUNTIME: &str = include_str!("../../public/lab/shownet-hook-runtime.js");

pub struct ProxyBrowserHandle {
    status: ProxyBrowserStatus,
    child: Option<Child>,
    profile_dir: Option<PathBuf>,
    lab_shutdown: Option<oneshot::Sender<()>>,
    lab_task: Option<tauri::async_runtime::JoinHandle<()>>,
    bus: Arc<BrowserBus>,
}

/// Chrome features the capture browser runs without, so a captured session is the
/// site's own traffic rather than Google's background chatter.
///
pub(crate) const DISABLED_FEATURES: &str = "AccountConsistency,AutofillServerCommunication,\
CertificateTransparencyComponentUpdater,DiceWebSigninInterception,FedCm,\
FedCmWithoutThirdPartyCookies,InterestFeedContentSuggestions,MediaRouter,\
NetworkTimeServiceQuerying,OptimizationGuideModelDownloading,\
OptimizationHints,OptimizationHintsFetching,OptimizationTargetPrediction,\
PrivacySandboxSettings4,PushMessaging,SafeBrowsingEnhancedProtection,\
SafeBrowsingHashPrefixRealTimeLookups,SafeBrowsingRealTimeLookup,SigninPromo,Translate";

/// The capture window, and the screen it claims to be on.
///
/// The screen is not the window: headless Chrome hardcodes an 800x600 screen
/// regardless of `--window-size`, so a page reading `screen.width` sees a display
/// no real desktop has. `--screen-info` overrides it. The value is a common
/// desktop resolution rather than the host's real one — ShowNet launches the
/// browser without an app handle to query monitors, and any plausible desktop
/// that comfortably contains the window is enough to stop the readout being an
/// outlier.
const WINDOW_WIDTH: u32 = 1440;
const WINDOW_HEIGHT: u32 = 900;
const SCREEN_WIDTH: u32 = 1920;
const SCREEN_HEIGHT: u32 = 1080;

fn normalize_browser_language(language: Option<&str>) -> Result<Option<String>, String> {
    let Some(language) = language.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if language.len() > 35
        || !language.is_ascii()
        || language.starts_with('-')
        || language.ends_with('-')
        || language
            .split('-')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    {
        return Err("浏览器语言格式无效，请使用 en-US、zh-CN 这样的语言标签".to_string());
    }
    let mut parts = language.split('-');
    let primary = parts.next().unwrap_or_default().to_ascii_lowercase();
    if !(2..=8).contains(&primary.len()) || !primary.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return Err("浏览器语言格式无效，请使用 en-US、zh-CN 这样的语言标签".to_string());
    }
    let normalized = std::iter::once(primary)
        .chain(parts.map(|part| {
            if part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                part.to_ascii_uppercase()
            } else if part.len() == 4 && part.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                let mut chars = part.chars();
                let first = chars.next().unwrap().to_ascii_uppercase();
                format!("{first}{}", chars.as_str().to_ascii_lowercase())
            } else {
                part.to_ascii_lowercase()
            }
        }))
        .collect::<Vec<_>>()
        .join("-");
    Ok(Some(normalized))
}

fn accept_language_for(language: &str) -> String {
    let base = language.split('-').next().unwrap_or(language);
    if base.eq_ignore_ascii_case(language) {
        language.to_string()
    } else {
        format!("{language},{base};q=0.9")
    }
}

// Chrome's profile preference stores an ordered language list, not an HTTP
// Accept-Language value. Chrome adds q-values when it builds the request header;
// persisting them here produces malformed values such as `zh;q=0.9;q=0.9`.
fn profile_accept_languages_for(language: &str) -> String {
    let base = language.split('-').next().unwrap_or(language);
    if base.eq_ignore_ascii_case(language) {
        language.to_string()
    } else {
        format!("{language},{base}")
    }
}

/// Chrome's reduced User-Agent: every token but the major version is frozen per
/// platform, which is what makes building the string before launch safe.
fn frozen_user_agent(major: u32) -> String {
    let platform = if cfg!(target_os = "macos") {
        "Macintosh; Intel Mac OS X 10_15_7"
    } else if cfg!(target_os = "windows") {
        "Windows NT 10.0; Win64; x64"
    } else {
        "X11; Linux x86_64"
    };
    format!(
        "Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) \
Chrome/{major}.0.0.0 Safari/537.36"
    )
}

/// Select the browser UA major independently from the installed binary.
///
/// The embedded browser is desktop Chrome, so only a versioned desktop Chrome
/// preset can be represented faithfully. Firefox, Safari, Edge, Android Chrome,
/// generic buckets, and the default preset keep the installed Chrome identity
/// rather than combining a Chrome binary with another browser's UA.
fn browser_user_agent_major(
    installed_major: Option<u32>,
    preset: Option<&ClientHelloPreset>,
) -> Option<u32> {
    match preset {
        Some(preset) if preset.family == "chrome" && preset.major_version > 0 => {
            Some(preset.major_version as u32)
        }
        _ => installed_major,
    }
}

/// Reads the major version straight off the binary that is about to be launched,
/// so the UA below describes the browser that actually runs rather than whatever
/// version this build was written against.
#[cfg(not(target_os = "windows"))]
fn chrome_major_version(chrome: &Path) -> Option<u32> {
    let output = Command::new(chrome).arg("--version").output().ok()?;
    // "Google Chrome 151.0.7922.109", "Chromium 151.0.7922.109",
    // "Google Chrome for Testing 137.0.7151.70" — the version is the first token
    // that starts with a number, whatever precedes it.
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .find_map(|token| token.split('.').next()?.parse::<u32>().ok())
}

#[cfg(target_os = "windows")]
fn chrome_major_version(chrome: &Path) -> Option<u32> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
    };

    let path = chrome
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut ignored_handle = 0;
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &mut ignored_handle) };
    if size == 0 {
        return None;
    }

    let mut data = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, data.as_mut_ptr().cast::<c_void>()) }
        == 0
    {
        return None;
    }

    let root = ['\\' as u16, 0];
    let mut fixed_info = std::ptr::null_mut::<c_void>();
    let mut fixed_info_len = 0;
    if unsafe {
        VerQueryValueW(
            data.as_ptr().cast::<c_void>(),
            root.as_ptr(),
            &mut fixed_info,
            &mut fixed_info_len,
        )
    } == 0
        || fixed_info.is_null()
        || fixed_info_len < std::mem::size_of::<VS_FIXEDFILEINFO>() as u32
    {
        return None;
    }

    let fixed_info = unsafe { &*fixed_info.cast::<VS_FIXEDFILEINFO>() };
    (fixed_info.dwSignature == 0xFEEF_04BD).then_some(fixed_info.dwFileVersionMS >> 16)
}

impl ProxyBrowserHandle {
    pub async fn launch(
        data_dir: &Path,
        proxy_port: u16,
        browser_language: Option<&str>,
    ) -> Result<Self, String> {
        let chrome = chrome_executable()?;
        let installed_chrome_major = chrome_major_version(&chrome);
        let active_preset = tls_outbound::active_preset().ok();
        let user_agent_major = browser_user_agent_major(installed_chrome_major, active_preset);
        let honest_launch_user_agent = user_agent_major.map(frozen_user_agent);
        let browser_language = normalize_browser_language(browser_language)?;
        cleanup_browser_profile(&data_dir.join("browser-profile"));
        let (lab_address, lab_shutdown, lab_task) = start_lab_server().await?;
        let debug_port = match reserve_loopback_port() {
            Ok(port) => port,
            Err(error) => {
                let _ = lab_shutdown.send(());
                lab_task.abort();
                return Err(error);
            }
        };
        let profile_dir = data_dir
            .join("browser-profiles")
            .join(Uuid::new_v4().to_string());
        if let Err(error) = prepare_browser_profile(&profile_dir, browser_language.as_deref()) {
            let _ = lab_shutdown.send(());
            lab_task.abort();
            return Err(error);
        }

        let mut command = chrome_command(
            &chrome,
            &profile_dir,
            debug_port,
            proxy_port,
            honest_launch_user_agent.as_deref(),
            browser_language.as_deref(),
        );
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = lab_shutdown.send(());
                lab_task.abort();
                cleanup_browser_profile(&profile_dir);
                return Err(format!("启动 Chrome 失败: {error}"));
            }
        };
        let source_instance_id = format!("chrome-cdp:{}", child.id());

        let target = match wait_for_page_target(debug_port, &mut child).await {
            Ok(target) => target,
            Err(error) => {
                stop_chrome_child(&mut child);
                let _ = lab_shutdown.send(());
                lab_task.abort();
                cleanup_browser_profile(&profile_dir);
                return Err(error);
            }
        };
        // `/json/version` reports the binary's built-in headless UA and cannot
        // read back `--user-agent`. The launch value is therefore authoritative;
        // only use the endpoint as a fallback when the binary version could not
        // be parsed and no preset supplied a version.
        let honest_user_agent = match honest_launch_user_agent.clone() {
            Some(user_agent) => user_agent,
            None => resolve_honest_user_agent(debug_port).await,
        };
        let status = ProxyBrowserStatus {
            running: true,
            honest_user_agent,
            browser_language: browser_language.clone().unwrap_or_default(),
            accept_language: browser_language
                .as_deref()
                .map(accept_language_for)
                .unwrap_or_default(),
            debug_port,
            target_id: target.id,
            web_socket_debugger_url: target.web_socket_debugger_url.clone(),
            source_instance_id,
            lab_url: format!("http://{lab_address}/lab/index.html?autorun=1"),
            browser_preset_id: active_preset
                .map(|preset| preset.id.to_string())
                .unwrap_or_default(),
            browser_preset_family: active_preset
                .map(|preset| preset.family.to_string())
                .unwrap_or_default(),
            browser_preset_major_version: active_preset
                .map(|preset| preset.major_version)
                .unwrap_or_default(),
            browser_user_agent_major_version: user_agent_major.unwrap_or_default(),
            ..Default::default()
        };
        let bus = Arc::new(BrowserBus::new(target.web_socket_debugger_url));
        Ok(Self {
            status,
            child: Some(child),
            profile_dir: Some(profile_dir),
            lab_shutdown: Some(lab_shutdown),
            lab_task: Some(lab_task),
            bus,
        })
    }

    pub fn status(&mut self) -> ProxyBrowserStatus {
        if self
            .child
            .as_mut()
            .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_some()))
        {
            self.status.running = false;
        }
        self.status.clone()
    }

    pub fn set_owner_session_id(&mut self, session_id: String) {
        self.status.owner_session_id = session_id;
    }

    pub fn bus(&self) -> Arc<BrowserBus> {
        Arc::clone(&self.bus)
    }

    pub async fn stop(mut self) {
        if let Some(mut child) = self.child.take() {
            stop_chrome_child(&mut child);
        }
        if let Some(shutdown) = self.lab_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.lab_task.take() {
            let _ = timeout(Duration::from_secs(2), task).await;
        }
        if let Some(profile_dir) = self.profile_dir.take() {
            cleanup_browser_profile(&profile_dir);
        }
    }
}

fn stop_chrome_child(child: &mut Child) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let pid = child.id().to_string();
        if let Ok(mut taskkill) = Command::new("taskkill.exe")
            .args(["/PID", &pid, "/T", "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if !wait_for_child_exit(&mut taskkill, Duration::from_secs(5)) {
                let _ = taskkill.kill();
                let _ = wait_for_child_exit(&mut taskkill, Duration::from_secs(1));
            }
        }
    }
    let _ = child.kill();
    if !wait_for_child_exit(child, Duration::from_secs(2)) {
        eprintln!(
            "Chrome process {} did not exit before the shutdown deadline",
            child.id()
        );
    }
}

fn wait_for_child_exit(child: &mut Child, deadline_after: Duration) -> bool {
    let deadline = Instant::now() + deadline_after;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(_) => return false,
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn chrome_command(
    chrome: &Path,
    profile_dir: &Path,
    debug_port: u16,
    proxy_port: u16,
    user_agent: Option<&str>,
    browser_language: Option<&str>,
) -> Command {
    let mut command = Command::new(chrome);
    command
        .arg(format!("--user-data-dir={}", profile_dir.to_string_lossy()))
        .arg(format!("--remote-debugging-port={debug_port}"))
        .arg("--remote-debugging-address=127.0.0.1")
        .arg("--remote-allow-origins=tauri://localhost,http://tauri.localhost")
        .arg(format!("--proxy-server=http://127.0.0.1:{proxy_port}"))
        .arg("--proxy-bypass-list=localhost;127.0.0.1;[::1]")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--no-service-autorun")
        // `--headless=new` is ignored by older Chrome builds and can fall
        // through to a visible browser window. Plain `--headless` selects
        // the current implementation on modern Chrome and the supported
        // implementation on older builds, so it never degrades to headed.
        .arg("--headless")
        // Without this Blink advertises `navigator.webdriver = true`, which
        // is the single cheapest automation tell a page can read. Nothing
        // about the capture depends on announcing it.
        .arg("--disable-blink-features=AutomationControlled")
        .arg(format!("--window-size={WINDOW_WIDTH},{WINDOW_HEIGHT}"))
        // Headless reports an 800x600 screen whatever --window-size says, and
        // a desktop browser whose screen is smaller than common phones is a
        // loud tell — bisecting the launch flags against a fingerprint probe,
        // this was the only signal any of them produced once the User-Agent
        // was fixed. Every other flag here (the debugging port, the isolated
        // profile, the disable-* block, the redirected Google endpoints)
        // measured identical to a stock browser.
        .arg(format!("--screen-info={{{SCREEN_WIDTH}x{SCREEN_HEIGHT}}}"))
        .arg("--gcm-checkin-url=http://127.0.0.1:9/disabled")
        .arg("--gcm-mcs-endpoint=127.0.0.1:9")
        .arg("--gcm-registration-url=http://127.0.0.1:9/disabled")
        .arg("--gaia-url=http://127.0.0.1:9")
        .arg("--google-apis-url=http://127.0.0.1:9")
        .arg("--google-base-url=http://127.0.0.1:9")
        .arg("--disable-background-networking")
        .arg("--disable-background-mode")
        .arg("--disable-breakpad")
        .arg("--disable-client-side-phishing-detection")
        .arg("--disable-component-update")
        .arg("--disable-component-extensions-with-background-pages")
        .arg("--disable-default-apps")
        .arg("--disable-domain-reliability")
        .arg("--disable-extensions")
        .arg("--disable-field-trial-config")
        .arg("--disable-search-engine-choice-screen")
        .arg("--disable-sync")
        .arg("--metrics-recording-only")
        .arg("--password-store=basic")
        .arg("--safebrowsing-disable-auto-update")
        .arg("--use-mock-keychain")
        .arg(format!("--disable-features={DISABLED_FEATURES}"));
    // Headless Chrome announces itself in the User-Agent — `HeadlessChrome/151`
    // — which is the loudest automation tell there is, and no amount of TLS
    // fingerprint work survives it. The renderer-level CDP override that used
    // to be the only defense reaches the page it is attached to and nothing
    // else: measured over one real session, the main document went out
    // rewritten while 17,763 subresource and worker requests still announced
    // HeadlessChrome to their origins. A launch flag has no such seam.
    //
    // Chrome derives its client hints from the running build, not from this
    // string, so overriding only the UA leaves Sec-CH-UA agreeing with it —
    // whereas the CDP override had to restate the brand list and drifted from
    // what the browser actually sends. Verified by
    // launch_user_agent_matches_the_browsers_own_client_hints.
    if let Some(user_agent) = user_agent {
        command.arg(format!("--user-agent={user_agent}"));
    }
    if let Some(language) = browser_language {
        command.arg(format!("--lang={language}"));
    }
    command.arg("about:blank");
    command
}

impl Drop for ProxyBrowserHandle {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            stop_chrome_child(child);
        }
        if let Some(shutdown) = self.lab_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.lab_task.take() {
            task.abort();
        }
        if let Some(profile_dir) = self.profile_dir.take() {
            cleanup_browser_profile(&profile_dir);
        }
    }
}

fn prepare_browser_profile(
    profile_dir: &Path,
    browser_language: Option<&str>,
) -> Result<(), String> {
    let default_dir = profile_dir.join("Default");
    std::fs::create_dir_all(&default_dir)
        .map_err(|error| format!("创建 ShowNet 浏览器配置失败: {error}"))?;

    let mut preferences = serde_json::json!({
        "alternate_error_pages": { "enabled": false },
        "autofill": {
            "credit_card_enabled": false,
            "profile_enabled": false
        },
        "browser": { "check_default_browser": false },
        "credentials_enable_service": false,
        "dns_prefetching": { "enabled": false },
        "net": { "network_prediction_options": 2 },
        "profile": { "password_manager_enabled": false },
        "safebrowsing": {
            "enabled": false,
            "enhanced": false
        },
        "search": { "suggest_enabled": false },
        "signin": { "allowed": false },
        "sync": { "suppress_start": true },
        "translate": { "enabled": false }
    });
    if let Some(language) = browser_language {
        preferences["intl"] = serde_json::json!({
            "accept_languages": profile_accept_languages_for(language)
        });
    }
    let local_state = serde_json::json!({
        "background_mode": { "enabled": false },
        "hardware_acceleration_mode": { "enabled": false }
    });

    write_browser_json(&default_dir.join("Preferences"), &preferences)?;
    write_browser_json(&profile_dir.join("Local State"), &local_state)
}

fn write_browser_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let content = serde_json::to_vec(value)
        .map_err(|error| format!("生成 ShowNet 浏览器配置失败: {error}"))?;
    std::fs::write(path, content).map_err(|error| format!("写入 ShowNet 浏览器配置失败: {error}"))
}

fn cleanup_browser_profile(profile_dir: &Path) {
    let mut last_error = None;
    for attempt in 0..10 {
        match std::fs::remove_dir_all(profile_dir) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => last_error = Some(error),
        }
        if attempt < 9 {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    if let Some(error) = last_error {
        eprintln!(
            "failed to remove temporary ShowNet browser profile {}: {error}",
            profile_dir.display()
        );
    }
}

async fn start_lab_server() -> Result<
    (
        SocketAddr,
        oneshot::Sender<()>,
        tauri::async_runtime::JoinHandle<()>,
    ),
    String,
> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .map_err(|error| format!("启动 Crypto Lab 失败: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("读取 Crypto Lab 地址失败: {error}"))?;
    let (shutdown, mut shutdown_rx) = oneshot::channel();
    let task = tauri::async_runtime::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    tauri::async_runtime::spawn(async move {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service_fn(serve_lab_asset))
                            .await;
                    });
                }
            }
        }
    });
    Ok((address, shutdown, task))
}

async fn serve_lab_asset(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (status, content_type, content) = if request.method() != Method::GET {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            "Method not allowed",
        )
    } else {
        match request.uri().path() {
            "/" | "/lab" | "/lab/" | "/lab/index.html" => {
                (StatusCode::OK, "text/html; charset=utf-8", LAB_INDEX)
            }
            "/lab/lab.js" => (StatusCode::OK, "text/javascript; charset=utf-8", LAB_SCRIPT),
            "/lab/lab.css" => (StatusCode::OK, "text/css; charset=utf-8", LAB_STYLE),
            "/lab/shownet-hook-runtime.js" => (
                StatusCode::OK,
                "text/javascript; charset=utf-8",
                HOOK_RUNTIME,
            ),
            _ => (
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                "Not found",
            ),
        }
    };
    let mut response = Response::new(Full::new(Bytes::copy_from_slice(content.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        content_type.parse().expect("valid content type"),
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        "no-store".parse().expect("valid cache control"),
    );
    Ok(response)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChromeTarget {
    id: String,
    #[serde(rename = "type")]
    target_type: String,
    web_socket_debugger_url: String,
}

async fn wait_for_page_target(debug_port: u16, child: &mut Child) -> Result<ChromeTarget, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|error| format!("创建 CDP 客户端失败: {error}"))?;
    let endpoint = format!("http://127.0.0.1:{debug_port}/json/list");
    let mut last_error = "Chrome CDP 尚未就绪".to_string();
    for _ in 0..80 {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("读取 Chrome 进程状态失败: {error}"))?
        {
            return Err(format!(
                "Chrome 在内嵌连接建立前退出（{status}）。请升级 Chrome 后重试"
            ));
        }
        match client.get(&endpoint).send().await {
            Ok(response) => match response.json::<Vec<ChromeTarget>>().await {
                Ok(targets) => {
                    if let Some(target) = targets
                        .into_iter()
                        .find(|target| target.target_type == "page")
                    {
                        return Ok(target);
                    }
                    last_error = "Chrome CDP 未发现页面目标".to_string();
                }
                Err(error) => last_error = format!("解析 Chrome CDP 目标失败: {error}"),
            },
            Err(error) => last_error = error.to_string(),
        }
        sleep(Duration::from_millis(125)).await;
    }
    Err(format!("Chrome CDP 启动超时: {last_error}"))
}

/// Chrome's advertised UA with the automation marker removed, or empty when it
/// carried no marker.
///
/// Read over the CDP HTTP endpoint before the debugger socket is opened, because
/// applying the override afterwards races the first `Page.navigate` — Chrome
/// executes commands in arrival order, so the main document would still go out
/// announcing HeadlessChrome.
///
/// `/json/version` reports the build's own User-Agent, not the one the
/// `--user-agent` launch flag forces on the wire, so this still says `Headless`
/// even when the flag is doing its job. That is why the CDP override in
/// BrowserView remains wired: Chrome offers no way to read the flag back, so the
/// two defenses cannot be made to know about each other. They agree by
/// construction instead — both derive from the same major version, and the
/// override no longer restates the client hints, so there is nothing left to
/// drift. The flag is what covers subresources and workers; this covers the
/// attached page.
async fn resolve_honest_user_agent(debug_port: u16) -> String {
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
    else {
        return String::new();
    };
    let endpoint = format!("http://127.0.0.1:{debug_port}/json/version");
    let Ok(response) = client.get(&endpoint).send().await else {
        return String::new();
    };
    let Ok(value) = response.json::<serde_json::Value>().await else {
        return String::new();
    };
    let reported = value
        .get("User-Agent")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let honest = reported.replace("Headless", "");
    if honest == reported {
        String::new()
    } else {
        honest
    }
}

fn reserve_loopback_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("分配 Chrome CDP 端口失败: {error}"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("读取 Chrome CDP 端口失败: {error}"))
}

#[cfg(target_os = "macos")]
pub(crate) fn chrome_executable() -> Result<PathBuf, String> {
    [
        PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .ok_or_else(|| "未找到 Google Chrome 或 Chromium".to_string())
}

#[cfg(target_os = "windows")]
pub(crate) fn chrome_executable() -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    for variable in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(variable) {
            candidates.push(PathBuf::from(root).join("Google/Chrome/Application/chrome.exe"));
        }
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| "未找到 Google Chrome".to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) fn chrome_executable() -> Result<PathBuf, String> {
    ["google-chrome", "chromium", "chromium-browser"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| "未找到 Chrome/Chromium".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        accept_language_for, browser_user_agent_major, chrome_command, chrome_executable,
        chrome_major_version, frozen_user_agent, normalize_browser_language,
        prepare_browser_profile, profile_accept_languages_for, DISABLED_FEATURES, LAB_SCRIPT,
        SCREEN_HEIGHT, SCREEN_WIDTH, WINDOW_HEIGHT, WINDOW_WIDTH,
    };
    use crate::tls_clienthello_catalog::get_preset;
    use std::path::Path;
    use tokio::time::{sleep, Duration};

    #[test]
    fn embedded_lab_script_falls_back_to_hook_bridge_for_status() {
        assert!(LAB_SCRIPT.contains("__SHOWNET_HOOK_BRIDGE__"));
        assert!(LAB_SCRIPT.contains("shownet-lab-status"));
    }

    /// The list is a hand-maintained comma-joined string spread over continuation
    /// lines, which is exactly the shape where an edit silently drops or doubles an
    /// entry — and dropping this particular one costs JA4 parity with no error.
    #[test]
    fn disabled_feature_list_stays_well_formed() {
        let entries: Vec<&str> = DISABLED_FEATURES.split(',').collect();

        assert!(
            entries.iter().all(|entry| !entry.is_empty()),
            "a stray or doubled comma left an empty feature name: {DISABLED_FEATURES}"
        );
        assert!(
            entries.iter().all(|entry| entry.trim() == *entry),
            "a line continuation leaked whitespace into a feature name: {entries:?}"
        );

        let mut sorted = entries.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            entries.len(),
            "the list repeats a feature: {entries:?}"
        );
        assert_eq!(
            sorted, entries,
            "the list is kept sorted so edits are reviewable; reorder to match"
        );
        assert!(!entries.contains(&"TlsMldsaSignatures"));
    }

    /// The whole point of the flag is that `Headless` never reaches an origin, and
    /// the UA is assembled here rather than copied from the browser, so a typo in
    /// the template would ship a subtly wrong client with nothing to catch it.
    #[test]
    fn launch_user_agent_never_announces_automation() {
        let user_agent = frozen_user_agent(151);

        assert!(
            !user_agent.contains("Headless"),
            "the launch UA still announces headless: {user_agent}"
        );
        assert!(
            user_agent.contains("Chrome/151.0.0.0"),
            "Chrome's reduced UA pins the build to MAJOR.0.0.0: {user_agent}"
        );
        assert!(
            user_agent.starts_with("Mozilla/5.0 (") && user_agent.ends_with(" Safari/537.36"),
            "the UA lost its frozen envelope: {user_agent}"
        );
        // A version that is not substituted is the failure this catches: the
        // template is one format! away from emitting a literal placeholder.
        assert!(
            !user_agent.contains('{') && !user_agent.contains("major"),
            "the template leaked into the UA: {user_agent}"
        );
        assert_ne!(
            frozen_user_agent(151),
            frozen_user_agent(137),
            "the major version has to reach the string"
        );
    }

    #[test]
    fn selected_chrome_preset_controls_the_browser_user_agent_major() {
        let installed = Some(151);
        assert_eq!(
            browser_user_agent_major(installed, Some(get_preset("chrome149").unwrap())),
            Some(149)
        );
        assert_eq!(
            browser_user_agent_major(installed, Some(get_preset("chrome151").unwrap())),
            Some(151)
        );
    }

    #[test]
    fn non_chrome_preset_keeps_the_installed_chrome_user_agent() {
        let installed = Some(151);
        assert_eq!(
            browser_user_agent_major(installed, Some(get_preset("firefox136").unwrap())),
            installed
        );
        assert_eq!(
            browser_user_agent_major(installed, Some(get_preset("default").unwrap())),
            installed
        );
        assert_eq!(browser_user_agent_major(None, None), None);
    }

    #[test]
    fn browser_language_is_canonical_and_keeps_request_and_page_identity_aligned() {
        assert_eq!(
            normalize_browser_language(Some(" zh-hans-cn ")).unwrap(),
            Some("zh-Hans-CN".to_string())
        );
        assert_eq!(
            normalize_browser_language(Some("TH-th")).unwrap(),
            Some("th-TH".to_string())
        );
        assert_eq!(normalize_browser_language(None).unwrap(), None);
        assert_eq!(accept_language_for("th-TH"), "th-TH,th;q=0.9");
        assert_eq!(profile_accept_languages_for("th-TH"), "th-TH,th");
        assert!(normalize_browser_language(Some("zh_CN")).is_err());
        assert!(normalize_browser_language(Some("-en-US")).is_err());
    }

    #[test]
    fn launch_command_never_falls_through_to_a_visible_chrome_window() {
        let command = chrome_command(
            Path::new("chrome"),
            Path::new("browser-profile"),
            9222,
            8080,
            Some("Mozilla/5.0 Chrome/151.0.0.0"),
            Some("th-TH"),
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(args.iter().any(|arg| arg == "--headless"));
        assert!(!args.iter().any(|arg| arg == "--headless=new"));
        assert!(
            !args.iter().any(|arg| arg == "--incognito"),
            "the temporary isolated profile should keep standard SSO/storage semantics"
        );
        assert!(args.iter().any(|arg| arg == "--lang=th-TH"));
        assert!(args
            .iter()
            .any(|arg| arg == "--proxy-server=http://127.0.0.1:8080"));
        assert!(args
            .iter()
            .any(|arg| arg == "--user-agent=Mozilla/5.0 Chrome/151.0.0.0"));
        assert_eq!(args.last().map(String::as_str), Some("about:blank"));
    }

    #[test]
    fn notification_permission_is_not_forced_to_denied() {
        assert!(!DISABLED_FEATURES
            .split(',')
            .any(|feature| feature == "NotificationTriggers"));

        let command = chrome_command(
            Path::new("chrome"),
            Path::new("browser-profile"),
            9222,
            8080,
            None,
            None,
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!args.iter().any(|arg| arg == "--disable-notifications"));

        let profile_dir = std::env::temp_dir().join(format!(
            "shownet-browser-permissions-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        prepare_browser_profile(&profile_dir, None).expect("write browser preferences");
        let preferences = std::fs::read_to_string(profile_dir.join("Default/Preferences"))
            .expect("read browser preferences");
        let preferences: serde_json::Value =
            serde_json::from_str(&preferences).expect("valid browser preferences");
        assert!(preferences
            .pointer("/profile/default_content_setting_values/notifications")
            .is_none());
        let _ = std::fs::remove_dir_all(profile_dir);
    }

    /// The window has to fit on the screen it claims. A screen smaller than the
    /// window is the same class of tell as the 800x600 default it replaces.
    #[test]
    fn the_claimed_screen_can_contain_the_window() {
        assert!(
            SCREEN_WIDTH >= WINDOW_WIDTH && SCREEN_HEIGHT >= WINDOW_HEIGHT,
            "window {WINDOW_WIDTH}x{WINDOW_HEIGHT} does not fit on the claimed \
             screen {SCREEN_WIDTH}x{SCREEN_HEIGHT}"
        );
        // Headless's own default, which is the value this exists to replace.
        assert_ne!(
            (SCREEN_WIDTH, SCREEN_HEIGHT),
            (800, 600),
            "that is the headless default, not an override"
        );
    }

    /// `--version` output is the one input here that comes from outside, and its
    /// wording differs across the builds ShowNet may find.
    #[test]
    fn chrome_version_parsing_reads_the_major_from_every_build_wording() {
        // Exercised through the same expression the real parser uses, so a change
        // to it is caught rather than mirrored.
        let major_of = |line: &str| -> Option<u32> {
            line.split_whitespace()
                .find_map(|token| token.split('.').next()?.parse::<u32>().ok())
        };

        assert_eq!(major_of("Google Chrome 151.0.7922.109"), Some(151));
        assert_eq!(major_of("Chromium 151.0.7922.109"), Some(151));
        // Chrome for Testing puts two extra words before the version.
        assert_eq!(
            major_of("Google Chrome for Testing 137.0.7151.70"),
            Some(137)
        );
        assert_eq!(major_of(""), None);
        assert_eq!(major_of("Google Chrome unknown"), None);
    }

    /// Measures the browser ShowNet will actually launch rather than trusting the
    /// template: the flag is only worth anything if Chrome accepts it and keeps its
    /// client hints agreeing with it, and both are Chrome's behavior, not ours.
    ///
    ///   cargo test launch_user_agent_matches_the_browsers_own_client_hints \
    ///     -- --ignored --nocapture
    #[test]
    #[ignore = "needs a locally installed Chrome; run via npm run test:browser-ua"]
    fn launch_user_agent_matches_the_browsers_own_client_hints() {
        let chrome = chrome_executable().expect("an installed Chrome");
        let major = chrome_major_version(&chrome).expect("a parseable --version");
        let user_agent = frozen_user_agent(major);

        // Chrome derives Sec-CH-UA from the running build, so the brand version it
        // would send has to be the same major this UA claims. If they ever diverge,
        // the launch flag is producing exactly the split-identity the CDP override
        // used to produce, and the flag is no longer the right fix.
        assert!(
            user_agent.contains(&format!("Chrome/{major}.0.0.0")),
            "UA {user_agent} does not describe the installed Chrome {major}"
        );

        // Windows already reads the version from the PE file through the Win32
        // version API. Starting a second Chrome process here can block the
        // shared browser profile on hosted runners, while adding no coverage.
        #[cfg(not(target_os = "windows"))]
        {
            let reported = std::process::Command::new(&chrome)
                .arg("--version")
                .output()
                .expect("run --version");
            let reported = String::from_utf8_lossy(&reported.stdout);
            assert!(
                reported.contains(&major.to_string()),
                "parsed major {major} is not in the browser's own --version output: {reported}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "needs a locally installed Chrome; run via npm run test:browser-launch"]
    async fn a_real_embedded_browser_stays_headless_and_applies_its_language() {
        let data_dir =
            std::env::temp_dir().join(format!("shownet-browser-launch-{}", std::process::id()));
        eprintln!(
            "launching isolated Chrome from {}",
            chrome_executable().unwrap().display()
        );
        let mut browser = super::ProxyBrowserHandle::launch(&data_dir, 9, Some("th-TH"))
            .await
            .expect("launch an isolated headless Chrome");
        eprintln!("Chrome launched; reading page identity");
        let status = browser.status();
        // `about:blank` has an opaque origin and Chrome reports notifications
        // as denied there. Real sites such as bot.sannysoft.com have a normal
        // secure/local origin, so read the permission on the same kind of page
        // the embedded browser actually serves.
        browser
            .bus()
            .navigate(&status.lab_url)
            .await
            .expect("navigate to the embedded Lab");
        sleep(Duration::from_millis(250)).await;
        let identity = browser
            .bus()
            .evaluate("navigator.permissions.query({name: 'notifications'}).then(({state}) => JSON.stringify({language: navigator.language, languages: navigator.languages, ua: navigator.userAgent, notifications: state}))", true)
            .await
            .expect("read browser identity");
        let identity: serde_json::Value = serde_json::from_str(
            identity
                .value
                .as_str()
                .expect("identity expression returns JSON"),
        )
        .expect("valid browser identity JSON");

        assert!(status.running);
        assert_eq!(status.browser_language, "th-TH");
        assert_eq!(status.accept_language, "th-TH,th;q=0.9");
        assert_eq!(identity["language"], "th-TH");
        assert!(identity["languages"]
            .as_array()
            .is_some_and(
                |languages| languages.first().and_then(|value| value.as_str()) == Some("th-TH")
            ));
        assert!(!identity["ua"]
            .as_str()
            .unwrap_or_default()
            .contains("Headless"));
        assert_eq!(identity["notifications"], "prompt");

        eprintln!("page identity verified; stopping Chrome");
        browser.stop().await;
        eprintln!("Chrome stopped; verifying temporary profile cleanup");
        let profiles_dir = data_dir.join("browser-profiles");
        assert!(
            std::fs::read_dir(&profiles_dir)
                .map(|mut profiles| profiles.next().is_none())
                .unwrap_or(true),
            "temporary Chrome profiles should be removed after browser stop"
        );
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    #[ignore = "needs a locally installed Chrome; run manually for preset/UA verification"]
    async fn a_versioned_chrome_preset_reaches_the_real_browser_user_agent() {
        let data_dir =
            std::env::temp_dir().join(format!("shownet-browser-preset-{}", std::process::id()));
        crate::tls_outbound::set_active_preset("chrome149").expect("select chrome149");
        let mut browser = super::ProxyBrowserHandle::launch(&data_dir, 9, None)
            .await
            .expect("launch an isolated headless Chrome");
        let status = browser.status();
        assert_eq!(status.browser_preset_id, "chrome149");
        assert_eq!(status.browser_preset_family, "chrome");
        assert_eq!(status.browser_preset_major_version, 149);
        assert_eq!(status.browser_user_agent_major_version, 149);
        assert!(status.honest_user_agent.contains("Chrome/149.0.0.0"));

        let identity = browser
            .bus()
            .evaluate("navigator.userAgent", false)
            .await
            .expect("read browser user agent");
        assert!(identity
            .value
            .as_str()
            .unwrap_or_default()
            .contains("Chrome/149.0.0.0"));

        browser.stop().await;
        crate::tls_outbound::set_active_preset("chrome150").expect("restore default preset");
        let _ = std::fs::remove_dir_all(data_dir);
    }
}
