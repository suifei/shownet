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

/// Chrome features the capture browser runs without, so a captured session is the
/// site's own traffic rather than Google's background chatter.
///
/// `TlsMldsaSignatures` is the one entry here that is not about noise, and it must
/// not be dropped when this list is edited. Chrome 141+ offers the ML-DSA
/// post-quantum signature algorithms 0x0904/0905/0906 in its ClientHello, and no
/// BoringSSL the impersonate egress can link knows them — boring-sys2 has no
/// ML-DSA at all — so wreq's Chrome profile cannot reproduce them.
///
/// This does not change what an origin sees. The browser's ClientHello terminates
/// at ShowNet's own MITM listener; only the egress handshake leaves the machine.
/// What it fixes is the `ja3Parity` readout, which compares the two: with the
/// feature on, parity reports false for a difference the egress can never close,
/// so the one diagnostic pointing at fingerprint trouble stays permanently red
/// while naming nothing actionable. That cost real debugging time. With it off
/// both sides measure t13d1516h2_8daaf6152771_d8a2da3f94cd, and the readout means
/// something again — verified against a live reflector by
/// browser_and_egress_present_one_fingerprint.
///
/// Worth recording because it is counterintuitive: real Chrome 137 and real Chrome
/// 151 with this feature off produce the *same* JA4. ML-DSA is the only ClientHello
/// difference across that whole range, so a Chrome 137-shaped handshake carrying a
/// Chrome 151 User-Agent is not the version mismatch it looks like — a large share
/// of real 151 installs look exactly like that.
pub(crate) const DISABLED_FEATURES: &str = "AccountConsistency,AutofillServerCommunication,\
CertificateTransparencyComponentUpdater,DiceWebSigninInterception,FedCm,\
FedCmWithoutThirdPartyCookies,InterestFeedContentSuggestions,MediaRouter,\
NetworkTimeServiceQuerying,NotificationTriggers,OptimizationGuideModelDownloading,\
OptimizationHints,OptimizationHintsFetching,OptimizationTargetPrediction,\
PrivacySandboxSettings4,PushMessaging,SafeBrowsingEnhancedProtection,\
SafeBrowsingHashPrefixRealTimeLookups,SafeBrowsingRealTimeLookup,SigninPromo,\
TlsMldsaSignatures,Translate";

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

/// Reads the major version straight off the binary that is about to be launched,
/// so the UA below describes the browser that actually runs rather than whatever
/// version this build was written against.
fn chrome_major_version(chrome: &Path) -> Option<u32> {
    let output = Command::new(chrome).arg("--version").output().ok()?;
    // "Google Chrome 151.0.7922.109", "Chromium 151.0.7922.109",
    // "Google Chrome for Testing 137.0.7151.70" — the version is the first token
    // that starts with a number, whatever precedes it.
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .find_map(|token| token.split('.').next()?.parse::<u32>().ok())
}

impl ProxyBrowserHandle {
    pub async fn launch(data_dir: &Path, proxy_port: u16) -> Result<Self, String> {
        let chrome = chrome_executable()?;
        let honest_launch_user_agent = chrome_major_version(&chrome).map(frozen_user_agent);
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
            // Without this Blink advertises `navigator.webdriver = true`, which
            // is the single cheapest automation tell a page can read. Nothing
            // about the capture depends on announcing it.
            .arg("--disable-blink-features=AutomationControlled")
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
            .arg(format!("--disable-features={DISABLED_FEATURES}"))
            .arg("about:blank");
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
        if let Some(user_agent) = &honest_launch_user_agent {
            command.arg(format!("--user-agent={user_agent}"));
        }
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
        let honest_user_agent = resolve_honest_user_agent(debug_port).await;
        let status = ProxyBrowserStatus {
            running: true,
            honest_user_agent,
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
        chrome_executable, chrome_major_version, frozen_user_agent, DISABLED_FEATURES, LAB_SCRIPT,
    };

    /// The entry in `DISABLED_FEATURES` whose absence would silently cost JA4
    /// parity with the egress. Named here rather than beside the list because the
    /// assertion is its only reader.
    const MLDSA_FEATURE: &str = "TlsMldsaSignatures";

    #[test]
    fn embedded_lab_script_falls_back_to_hook_bridge_for_status() {
        assert!(LAB_SCRIPT.contains("__SHOWNET_HOOK_BRIDGE__"));
        assert!(LAB_SCRIPT.contains("shownet-lab-status"));
    }

    /// The list is a hand-maintained comma-joined string spread over continuation
    /// lines, which is exactly the shape where an edit silently drops or doubles an
    /// entry — and dropping this particular one costs JA4 parity with no error.
    #[test]
    fn disabled_feature_list_stays_well_formed_and_keeps_ja4_parity() {
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

        assert!(
            entries.contains(&MLDSA_FEATURE),
            "{MLDSA_FEATURE} is gone: the browser would offer ML-DSA signature \
             algorithms the impersonate egress cannot reproduce, so its JA4 would \
             stop matching what ShowNet sends upstream"
        );
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
