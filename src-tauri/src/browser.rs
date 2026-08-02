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
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout, Duration};
use uuid::Uuid;

use crate::browser_bus::BrowserBus;
use crate::models::ProxyBrowserStatus;
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

impl ProxyBrowserHandle {
    pub async fn launch(data_dir: &Path, proxy_port: u16) -> Result<Self, String> {
        let chrome = chrome_executable()?;
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
        if let Err(error) = prepare_browser_profile(&profile_dir) {
            let _ = lab_shutdown.send(());
            lab_task.abort();
            return Err(error);
        }

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
            .arg("--headless=new")
            .arg("--incognito")
            .arg("--window-size=1440,900")
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
            .arg("--disable-notifications")
            .arg("--disable-search-engine-choice-screen")
            .arg("--disable-sync")
            .arg("--metrics-recording-only")
            .arg("--password-store=basic")
            .arg("--safebrowsing-disable-auto-update")
            .arg("--use-mock-keychain")
            .arg("--disable-features=AccountConsistency,AutofillServerCommunication,CertificateTransparencyComponentUpdater,DiceWebSigninInterception,FedCm,FedCmWithoutThirdPartyCookies,InterestFeedContentSuggestions,MediaRouter,NetworkTimeServiceQuerying,NotificationTriggers,OptimizationGuideModelDownloading,OptimizationHints,OptimizationHintsFetching,OptimizationTargetPrediction,PrivacySandboxSettings4,PushMessaging,SafeBrowsingEnhancedProtection,SafeBrowsingHashPrefixRealTimeLookups,SafeBrowsingRealTimeLookup,SigninPromo,Translate")
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
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

        let target = match wait_for_page_target(debug_port).await {
            Ok(target) => target,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = lab_shutdown.send(());
                lab_task.abort();
                cleanup_browser_profile(&profile_dir);
                return Err(error);
            }
        };
        let status = ProxyBrowserStatus {
            running: true,
            debug_port,
            target_id: target.id,
            web_socket_debugger_url: target.web_socket_debugger_url.clone(),
            source_instance_id,
            lab_url: format!("http://{lab_address}/lab/index.html?autorun=1"),
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

    pub fn bus(&self) -> Arc<BrowserBus> {
        Arc::clone(&self.bus)
    }

    pub async fn stop(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
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

impl Drop for ProxyBrowserHandle {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
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

fn prepare_browser_profile(profile_dir: &Path) -> Result<(), String> {
    let default_dir = profile_dir.join("Default");
    std::fs::create_dir_all(&default_dir)
        .map_err(|error| format!("创建 ShowNet 浏览器配置失败: {error}"))?;

    let preferences = serde_json::json!({
        "alternate_error_pages": { "enabled": false },
        "autofill": {
            "credit_card_enabled": false,
            "profile_enabled": false
        },
        "browser": { "check_default_browser": false },
        "credentials_enable_service": false,
        "dns_prefetching": { "enabled": false },
        "net": { "network_prediction_options": 2 },
        "profile": {
            "default_content_setting_values": { "notifications": 2 },
            "password_manager_enabled": false
        },
        "safebrowsing": {
            "enabled": false,
            "enhanced": false
        },
        "search": { "suggest_enabled": false },
        "signin": { "allowed": false },
        "sync": { "suppress_start": true },
        "translate": { "enabled": false }
    });
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
    if let Err(error) = std::fs::remove_dir_all(profile_dir) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "failed to remove temporary ShowNet browser profile {}: {error}",
                profile_dir.display()
            );
        }
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

async fn wait_for_page_target(debug_port: u16) -> Result<ChromeTarget, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|error| format!("创建 CDP 客户端失败: {error}"))?;
    let endpoint = format!("http://127.0.0.1:{debug_port}/json/list");
    let mut last_error = "Chrome CDP 尚未就绪".to_string();
    for _ in 0..80 {
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

fn reserve_loopback_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("分配 Chrome CDP 端口失败: {error}"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("读取 Chrome CDP 端口失败: {error}"))
}

#[cfg(target_os = "macos")]
fn chrome_executable() -> Result<PathBuf, String> {
    [
        PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .ok_or_else(|| "未找到 Google Chrome 或 Chromium".to_string())
}

#[cfg(target_os = "windows")]
fn chrome_executable() -> Result<PathBuf, String> {
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
fn chrome_executable() -> Result<PathBuf, String> {
    ["google-chrome", "chromium", "chromium-browser"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| "未找到 Chrome/Chromium".to_string())
}

#[cfg(test)]
mod tests {
    use super::LAB_SCRIPT;

    #[test]
    fn embedded_lab_script_falls_back_to_hook_bridge_for_status() {
        assert!(LAB_SCRIPT.contains("__SHOWNET_HOOK_BRIDGE__"));
        assert!(LAB_SCRIPT.contains("shownet-lab-status"));
    }
}
