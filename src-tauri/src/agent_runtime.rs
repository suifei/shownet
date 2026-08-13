use crate::models::{AgentRuntimeSettings, AgentRuntimeStatus, EffectiveUpstreamProxy};
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;
use tauri::{AppHandle, Manager};
use tokio::process::Command;

const PRIMARY_BASE_URL: &str = "https://x.ai/cli";
const FALLBACK_BASE_URL: &str = "https://storage.googleapis.com/grok-build-public-artifacts/cli";
const UNIX_INSTALLER_URL: &str = "https://x.ai/cli/install.sh";
const WINDOWS_INSTALLER_URL: &str = "https://x.ai/cli/install.ps1";
const MAX_INSTALLER_BYTES: usize = 512 * 1024;
const MAX_INSTALLER_OUTPUT_BYTES: usize = 128 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Debug)]
pub struct ResolvedRuntime {
    pub executable: PathBuf,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedMetadata {
    schema_version: u32,
    provider: String,
    channel: String,
    version: String,
    platform: String,
    executable_path: String,
    installer_url: String,
    version_output: String,
}

pub async fn status(
    app: &AppHandle,
    settings: AgentRuntimeSettings,
    download_upstream: &EffectiveUpstreamProxy,
    check_latest: bool,
) -> AgentRuntimeStatus {
    let platform = managed_platform()
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH));
    let installation = read_installation_metadata(app).ok().flatten();
    let latest_version = if check_latest && managed_platform().is_some() {
        resolve_stable_version(download_upstream).await.ok()
    } else {
        None
    };
    match resolve(app, &settings).await {
        Ok(runtime) => {
            let update_available = latest_version
                .as_ref()
                .is_some_and(|latest| version_is_newer(latest, &runtime.version));
            let official_executable = official_install_directory()
                .ok()
                .map(|directory| directory.join(grok_executable_name()));
            AgentRuntimeStatus {
                settings,
                available: true,
                compatible: true,
                executable_path: Some(runtime.executable.display().to_string()),
                version: Some(runtime.version),
                installed_by_shownet: official_executable
                    .as_ref()
                    .is_some_and(|path| path == &runtime.executable)
                    || installation.as_ref().is_some_and(|metadata| {
                        Path::new(&metadata.executable_path) == runtime.executable
                    }),
                latest_version,
                update_available,
                install_supported: managed_platform().is_some()
                    && official_install_directory().is_ok(),
                platform,
                message: "Grok 已通过版本和命令行兼容性探测".to_string(),
            }
        }
        Err(message) => AgentRuntimeStatus {
            settings,
            available: false,
            compatible: false,
            executable_path: None,
            version: None,
            installed_by_shownet: false,
            latest_version,
            update_available: false,
            install_supported: managed_platform().is_some() && official_install_directory().is_ok(),
            platform,
            message,
        },
    }
}

pub async fn resolve(
    app: &AppHandle,
    settings: &AgentRuntimeSettings,
) -> Result<ResolvedRuntime, String> {
    if settings.provider != "grok" {
        return Err(format!("Agent provider {} 尚未支持", settings.provider));
    }
    let executable = if let Some(selected) = settings.executable_path.as_deref() {
        let selected = PathBuf::from(selected);
        if !selected.is_file() {
            return Err("选定的 Grok 可执行文件已不存在，请重新选择或恢复自动探测".to_string());
        }
        selected
    } else {
        discover_system_binary(app)
            .ok_or_else(|| "系统中未找到 Grok；可一键安装或选择已有可执行文件".to_string())?
    };
    let version_output = probe_version(&executable).await?;
    let version = parse_version_output(&version_output)?;
    probe_cli_compatibility(&executable).await?;
    Ok(ResolvedRuntime {
        executable,
        version,
    })
}

pub async fn install_official(
    app: &AppHandle,
    upstream: &EffectiveUpstreamProxy,
) -> Result<PathBuf, String> {
    let platform = managed_platform().ok_or_else(|| {
        format!(
            "ShowNet 暂不提供 {} {} 的 Grok 一键安装，请选择已有可执行文件",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let installer_url = installer_url();
    let client = download_client(upstream)?;
    let script = download_installer(&client, installer_url).await?;
    validate_installer(&script)?;

    let directory = app
        .path()
        .app_cache_dir()
        .map_err(|error| format!("无法定位 Agent 临时目录: {error}"))?
        .join(format!("grok-installer-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir_all(&directory).map_err(|error| format!("创建 Agent 临时目录失败: {error}"))?;
    let script_path = directory.join(if cfg!(windows) {
        "install.ps1"
    } else {
        "install.sh"
    });
    let install_result = async {
        fs::write(&script_path, script)
            .map_err(|error| format!("保存 x.ai 官方安装器失败: {error}"))?;
        set_private_file(&script_path)?;
        run_official_installer(&script_path, upstream).await?;

        let executable = official_install_directory()?.join(grok_executable_name());
        if !executable.is_file() {
            return Err(format!(
                "x.ai 官方安装器完成后未找到 {}",
                executable.display()
            ));
        }
        let version_output = probe_version(&executable).await?;
        let version = parse_version_output(&version_output)?;
        probe_cli_compatibility(&executable).await?;
        let metadata = ManagedMetadata {
            schema_version: 1,
            provider: "grok".to_string(),
            channel: "stable".to_string(),
            version,
            platform: platform.to_string(),
            executable_path: executable.display().to_string(),
            installer_url: installer_url.to_string(),
            version_output,
        };
        let _ = write_installation_metadata(app, &metadata);
        Ok(executable)
    }
    .await;
    let _ = fs::remove_dir_all(&directory);
    install_result
}

fn installer_url() -> &'static str {
    if cfg!(windows) {
        WINDOWS_INSTALLER_URL
    } else {
        UNIX_INSTALLER_URL
    }
}

async fn download_installer(client: &Client, url: &str) -> Result<Vec<u8>, String> {
    let response = client
        .get(url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|error| format!("下载 x.ai 官方安装器失败: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "下载 x.ai 官方安装器失败: HTTP {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_INSTALLER_BYTES as u64)
    {
        return Err("x.ai 官方安装器超过安全大小上限".to_string());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("读取 x.ai 官方安装器失败: {error}"))?;
    if bytes.len() > MAX_INSTALLER_BYTES {
        return Err("x.ai 官方安装器超过安全大小上限".to_string());
    }
    Ok(bytes.to_vec())
}

fn validate_installer(bytes: &[u8]) -> Result<(), String> {
    let script = std::str::from_utf8(bytes)
        .map_err(|_| "x.ai 官方安装器不是有效的 UTF-8 脚本".to_string())?;
    let expected = if cfg!(windows) {
        [
            "Grok CLI installer for PowerShell",
            "https://x.ai/cli/install.ps1",
        ]
    } else {
        ["Grok CLI installer", "https://x.ai/cli/install.sh"]
    };
    if script.len() < 2_000 || expected.iter().any(|marker| !script.contains(marker)) {
        return Err("x.ai 官方安装器内容与预期不符".to_string());
    }
    Ok(())
}

async fn run_official_installer(
    script: &Path,
    upstream: &EffectiveUpstreamProxy,
) -> Result<(), String> {
    if cfg!(windows) && upstream.mode == "socks5" {
        return Err(
            "x.ai 官方 Windows 安装器不支持 SOCKS5；请直连安装，或改用 ShowNet 的 HTTP/HTTPS 出口代理"
                .to_string(),
        );
    }
    let installer_directory = script
        .parent()
        .ok_or_else(|| "x.ai 官方安装器临时路径无效".to_string())?;
    let wget_config = installer_directory.join("wgetrc");
    fs::write(&wget_config, b"")
        .map_err(|error| format!("创建 Agent 安装器临时配置失败: {error}"))?;
    let mut command = if cfg!(windows) {
        let mut command = Command::new("powershell.exe");
        command.args(["-NoLogo", "-NoProfile", "-NonInteractive"]);
        if upstream.mode == "direct" {
            command.args([
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "[Net.WebRequest]::DefaultWebProxy=$null;& $env:SHOWNET_INSTALL_SCRIPT",
            ]);
        } else {
            command.args([
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                concat!(
                    "$uri=[Uri]$env:SHOWNET_INSTALL_PROXY;",
                    "$proxy=New-Object Net.WebProxy($uri.GetLeftPart([UriPartial]::Authority));",
                    "if($uri.UserInfo){$parts=$uri.UserInfo.Split(':',2);",
                    "$user=[Uri]::UnescapeDataString($parts[0]);",
                    "$pass=if($parts.Length -gt 1){[Uri]::UnescapeDataString($parts[1])}else{''};",
                    "$proxy.Credentials=New-Object Net.NetworkCredential($user,$pass)};",
                    "if($env:SHOWNET_INSTALL_BYPASS){",
                    "$proxy.BypassList=$env:SHOWNET_INSTALL_BYPASS.Split('|')};",
                    "[Net.WebRequest]::DefaultWebProxy=$proxy;",
                    "& $env:SHOWNET_INSTALL_SCRIPT"
                ),
            ]);
        }
        command.env("SHOWNET_INSTALL_SCRIPT", script);
        command
    } else {
        let mut command = Command::new("/bin/bash");
        command.arg(script);
        command
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("GROK_CHANNEL", "stable")
        .env("GROK_BIN_DIR", official_install_directory()?)
        .env("CURL_HOME", installer_directory)
        .env("WGETRC", wget_config)
        .env_remove("GROK_DEPLOYMENT_KEY")
        .env_remove("GROK_PROXY_URL")
        .env_remove("GROK_VERSION");
    configure_installer_proxy(&mut command, upstream)?;
    let output = tokio::time::timeout(INSTALL_TIMEOUT, command.output())
        .await
        .map_err(|_| "x.ai 官方安装器运行超时".to_string())?
        .map_err(|error| format!("无法启动 x.ai 官方安装器: {error}"))?;
    validate_installer_output(output)
}

fn configure_installer_proxy(
    command: &mut Command,
    upstream: &EffectiveUpstreamProxy,
) -> Result<(), String> {
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(name);
    }
    if upstream.mode == "direct" {
        return Ok(());
    }
    let proxy = proxy_url(upstream)?;
    let no_proxy = upstream.bypass.join(",");
    let windows_bypass = windows_proxy_bypass_regexes(&upstream.bypass).join("|");
    command.env("SHOWNET_INSTALL_PROXY", &proxy);
    if !windows_bypass.is_empty() {
        command.env("SHOWNET_INSTALL_BYPASS", windows_bypass);
    }
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(name, &proxy);
    }
    if !no_proxy.is_empty() {
        command.env("NO_PROXY", &no_proxy).env("no_proxy", no_proxy);
    }
    Ok(())
}

fn windows_proxy_bypass_regexes(bypass: &[String]) -> Vec<String> {
    bypass
        .iter()
        .filter_map(|entry| {
            let entry = entry.trim().to_ascii_lowercase();
            if entry.is_empty() {
                return None;
            }
            if entry == "*" {
                return Some(".*".to_string());
            }
            let (subdomains, host) = entry
                .strip_prefix("*.")
                .map(|host| (true, host))
                .unwrap_or((false, entry.as_str()));
            let escaped = host
                .chars()
                .flat_map(|character| {
                    if ".+()[]{}^$|\\?*".contains(character) {
                        vec!['\\', character]
                    } else {
                        vec![character]
                    }
                })
                .collect::<String>();
            let host_pattern = if subdomains {
                format!("(?:[^/]+\\.)?{escaped}")
            } else {
                escaped
            };
            Some(format!("^https?://{host_pattern}(?::[0-9]+)?(?:/|$)"))
        })
        .collect()
}

fn validate_installer_output(output: Output) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Err(format!(
        "x.ai 官方安装器执行失败: {}",
        truncate(&text, MAX_INSTALLER_OUTPUT_BYTES)
    ))
}

fn official_install_directory() -> Result<PathBuf, String> {
    let home = if cfg!(windows) {
        std::env::var_os("USERPROFILE")
    } else {
        std::env::var_os("HOME")
    }
    .map(PathBuf::from)
    .ok_or_else(|| "无法定位用户主目录".to_string())?;
    Ok(home.join(".grok").join("bin"))
}

fn discover_system_binary(app: &AppHandle) -> Option<PathBuf> {
    find_on_path(grok_executable_name())
        .or_else(|| {
            official_install_directory()
                .ok()
                .map(|directory| directory.join(grok_executable_name()))
                .filter(|path| path.is_file())
        })
        .or_else(|| {
            read_installation_metadata(app)
                .ok()
                .flatten()
                .map(|metadata| PathBuf::from(metadata.executable_path))
                .filter(|path| path.is_file())
        })
}

fn metadata_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法定位应用数据目录: {error}"))?
        .join("agent-runtime-install.json"))
}

fn read_installation_metadata(app: &AppHandle) -> Result<Option<ManagedMetadata>, String> {
    let path = metadata_path(app)?;
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|error| format!("读取 Grok 安装记录失败: {error}"))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("Grok 安装记录无效: {error}"))
}

fn write_installation_metadata(app: &AppHandle, metadata: &ManagedMetadata) -> Result<(), String> {
    let path = metadata_path(app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Agent 安装记录路径无效".to_string())?;
    fs::create_dir_all(parent).map_err(|error| format!("创建应用数据目录失败: {error}"))?;
    let temporary = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(metadata).map_err(|error| error.to_string())?;
    fs::write(&temporary, bytes).map_err(|error| format!("保存 Agent 安装记录失败: {error}"))?;
    let result = atomic_replace(&temporary, &path);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

async fn resolve_stable_version(upstream: &EffectiveUpstreamProxy) -> Result<String, String> {
    let client = download_client(upstream)?;
    let mut failures = Vec::new();
    for base in [PRIMARY_BASE_URL, FALLBACK_BASE_URL] {
        let url = format!("{base}/stable");
        match client
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(value) => match validate_version(&value) {
                    Ok(version) => return Ok(version),
                    Err(error) => failures.push(format!("{url}: {error}")),
                },
                Err(error) => failures.push(format!("{url}: {error}")),
            },
            Ok(response) => failures.push(format!("{url}: HTTP {}", response.status())),
            Err(error) => failures.push(format!("{url}: {error}")),
        }
    }
    Err(format!(
        "无法读取 Grok stable 版本: {}",
        failures.join("; ")
    ))
}

fn download_client(upstream: &EffectiveUpstreamProxy) -> Result<Client, String> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::limited(5));
    if upstream.mode != "direct" {
        let bypass = upstream.bypass.clone();
        let proxy_url = reqwest::Url::parse(&proxy_url(upstream)?)
            .map_err(|error| format!("出口代理配置无效: {error}"))?;
        let proxy = Proxy::custom(move |target| {
            (!target_is_bypassed(target, &bypass)).then_some(proxy_url.clone())
        });
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|error| format!("创建下载客户端失败: {error}"))
}

fn proxy_url(upstream: &EffectiveUpstreamProxy) -> Result<String, String> {
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
    Ok(url.to_string())
}

pub async fn probe_version(binary: &Path) -> Result<String, String> {
    let output = tokio::time::timeout(
        PROBE_TIMEOUT,
        Command::new(binary)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "Grok 版本探测超时".to_string())?
    .map_err(|error| format!("无法启动 Grok: {error}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .trim()
    .to_string();
    if !output.status.success() {
        return Err(format!("Grok --version 失败: {text}"));
    }
    parse_version_output(&text)?;
    Ok(text)
}

async fn probe_cli_compatibility(binary: &Path) -> Result<(), String> {
    let output = tokio::time::timeout(
        PROBE_TIMEOUT,
        Command::new(binary)
            .arg("--help")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "Grok 兼容性探测超时".to_string())?
    .map_err(|error| format!("无法探测 Grok 命令行能力: {error}"))?;
    let help = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut required_flags = vec![
        "prompt-file",
        "model",
        "output-format",
        "streaming-json",
        "permission-mode",
        "max-turns",
        "no-auto-update",
        "deny",
        "disable-web-search",
    ];
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        required_flags.push("sandbox");
    }
    if !output.status.success() || required_flags.iter().any(|flag| !help.contains(flag)) {
        return Err("当前 Grok 版本缺少 ShowNet 所需的命令行能力".to_string());
    }
    Ok(())
}

fn parse_version_output(output: &str) -> Result<String, String> {
    output
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .find(|part| {
            let mut pieces = part.split('.');
            pieces.clone().count() == 3
                && pieces
                    .all(|piece| !piece.is_empty() && piece.chars().all(|c| c.is_ascii_digit()))
        })
        .map(str::to_string)
        .ok_or_else(|| format!("无法识别 Grok 版本: {output}"))
}

fn validate_version(value: &str) -> Result<String, String> {
    let version = value.trim();
    let valid = !version.is_empty()
        && version.split('.').count() == 3
        && version
            .split('.')
            .all(|piece| !piece.is_empty() && piece.chars().all(|c| c.is_ascii_digit()));
    valid
        .then(|| version.to_string())
        .ok_or_else(|| format!("无效版本号 {version:?}"))
}

fn version_is_newer(candidate: &str, current: &str) -> bool {
    let parse = |value: &str| {
        value
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .ok()
            .filter(|parts| parts.len() == 3)
    };
    match (parse(candidate), parse(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

fn atomic_replace(temporary: &Path, destination: &Path) -> Result<(), String> {
    let backup = destination.with_extension("previous");
    let _ = fs::remove_file(&backup);
    if destination.exists() {
        fs::rename(destination, &backup)
            .map_err(|error| format!("备份旧 Agent 安装记录失败: {error}"))?;
    }
    if let Err(error) = fs::rename(temporary, destination) {
        if backup.exists() {
            let _ = fs::rename(&backup, destination);
        }
        return Err(format!("保存 Agent 安装记录失败: {error}"));
    }
    let _ = fs::remove_file(backup);
    Ok(())
}

fn target_is_bypassed(url: &reqwest::Url, bypass: &[String]) -> bool {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    bypass.iter().any(|entry| {
        let entry = entry.trim().to_ascii_lowercase();
        entry == host
            || entry == "*"
            || entry
                .strip_prefix("*.")
                .is_some_and(|suffix| host == suffix || host.ends_with(&format!(".{suffix}")))
    })
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn grok_executable_name() -> &'static str {
    if cfg!(windows) {
        "grok.exe"
    } else {
        "grok"
    }
}

fn managed_platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("macos-aarch64"),
        ("windows", "x86_64") => Some("windows-x86_64"),
        _ => None,
    }
}

fn set_private_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("设置 Agent 安装器权限失败: {error}"))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn truncate(value: &str, max_bytes: usize) -> String {
    let value = value.trim();
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [TRUNCATED]", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_versions_are_strict() {
        assert_eq!(validate_version("1.2.3\n").unwrap(), "1.2.3");
        for invalid in ["v1.2.3", "1.2", "1.2.3-beta", "../../bin"] {
            assert!(validate_version(invalid).is_err());
        }
    }

    #[test]
    fn parses_official_version_output() {
        assert_eq!(
            parse_version_output("grok 1.0.3 (abcdef)").unwrap(),
            "1.0.3"
        );
        assert!(parse_version_output("grok unknown").is_err());
    }

    #[test]
    fn update_requires_a_strictly_newer_stable_version() {
        assert!(version_is_newer("1.2.4", "1.2.3"));
        assert!(version_is_newer("2.0.0", "1.99.99"));
        assert!(!version_is_newer("1.2.3", "1.2.3"));
        assert!(!version_is_newer("1.2.2", "1.2.3"));
        assert!(!version_is_newer("latest", "1.2.3"));
    }

    #[test]
    fn validates_only_the_expected_official_installer() {
        let valid = if cfg!(windows) {
            format!(
                "# Grok CLI installer for PowerShell - {}\n{}",
                WINDOWS_INSTALLER_URL,
                "# filler\n".repeat(300)
            )
        } else {
            format!(
                "#!/bin/bash\n# Grok CLI installer - {}\n{}",
                UNIX_INSTALLER_URL,
                "# filler\n".repeat(300)
            )
        };
        assert!(validate_installer(valid.as_bytes()).is_ok());
        assert!(validate_installer(b"echo untrusted").is_err());
    }

    #[test]
    fn proxy_bypass_matches_show_net_rules() {
        let bypass = vec!["*.example.com".to_string(), "localhost".to_string()];
        assert!(target_is_bypassed(
            &reqwest::Url::parse("https://api.example.com/file").unwrap(),
            &bypass,
        ));
        assert!(!target_is_bypassed(
            &reqwest::Url::parse("https://x.ai/cli/stable").unwrap(),
            &bypass,
        ));
    }

    #[test]
    fn windows_proxy_bypass_is_safe_regex() {
        assert_eq!(
            windows_proxy_bypass_regexes(&["localhost".to_string(), "*.example.com".to_string(),]),
            [
                "^https?://localhost(?::[0-9]+)?(?:/|$)",
                "^https?://(?:[^/]+\\.)?example\\.com(?::[0-9]+)?(?:/|$)",
            ]
        );
    }
}
