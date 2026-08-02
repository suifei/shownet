use serde::Serialize;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use url::Url;

#[cfg(target_os = "macos")]
use std::fs::OpenOptions;
#[cfg(target_os = "macos")]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const LOOPBACK_BYPASS: &str = "localhost,127.0.0.1,::1";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyTerminalLaunchResult {
    pub terminal: String,
    pub proxy_url: String,
    pub ca_bundle_configured: bool,
    pub environment_keys: Vec<String>,
}

pub fn launch(
    preference: &str,
    proxy_url: &str,
    certificate_path: &Path,
) -> Result<ProxyTerminalLaunchResult, String> {
    let proxy_url = validate_loopback_proxy(proxy_url)?;
    if !certificate_path.is_file() {
        return Err("ShowNet Root CA 文件不存在，请重新启动应用后再试".to_string());
    }
    let ca_bundle = prepare_ca_bundle(certificate_path)?;
    let environment = proxy_environment(&proxy_url, &ca_bundle);
    let terminal = launch_platform_terminal(preference.trim(), &environment)?;

    Ok(ProxyTerminalLaunchResult {
        terminal,
        proxy_url,
        ca_bundle_configured: true,
        environment_keys: environment.into_iter().map(|(key, _)| key).collect(),
    })
}

fn validate_loopback_proxy(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    let parsed = Url::parse(trimmed).map_err(|_| "代理终端地址无效".to_string())?;
    if parsed.scheme() != "http"
        || parsed.port_or_known_default().is_none()
        || !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
        || parsed.username() != ""
        || parsed.password().is_some()
    {
        return Err("代理终端只允许使用 ShowNet 本机回环代理".to_string());
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn prepare_ca_bundle(certificate_path: &Path) -> Result<PathBuf, String> {
    let certificate = std::fs::read(certificate_path)
        .map_err(|error| format!("读取 ShowNet Root CA 失败：{error}"))?;
    if certificate.is_empty() {
        return Err("ShowNet Root CA 文件为空".to_string());
    }

    let Some(system_path) = system_ca_bundle_path() else {
        return std::fs::canonicalize(certificate_path)
            .map_err(|error| format!("解析 ShowNet Root CA 路径失败：{error}"));
    };
    let Ok(mut combined) = std::fs::read(system_path) else {
        return std::fs::canonicalize(certificate_path)
            .map_err(|error| format!("解析 ShowNet Root CA 路径失败：{error}"));
    };
    if !combined.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(&certificate);

    let output = certificate_path.with_file_name("shownet-proxy-ca-bundle.pem");
    std::fs::write(&output, combined)
        .map_err(|error| format!("准备代理终端 CA 信任包失败：{error}"))?;
    #[cfg(unix)]
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("保护代理终端 CA 信任包失败：{error}"))?;
    std::fs::canonicalize(&output)
        .map_err(|error| format!("解析代理终端 CA 信任包路径失败：{error}"))
}

#[cfg(target_os = "macos")]
fn system_ca_bundle_path() -> Option<&'static Path> {
    ["/etc/ssl/cert.pem"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn system_ca_bundle_path() -> Option<&'static Path> {
    [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ]
    .into_iter()
    .map(Path::new)
    .find(|path| path.is_file())
}

#[cfg(not(unix))]
fn system_ca_bundle_path() -> Option<&'static Path> {
    None
}

fn proxy_environment(proxy_url: &str, ca_bundle: &Path) -> Vec<(String, String)> {
    let ca_bundle = ca_bundle.to_string_lossy().to_string();
    let mut values = Vec::new();
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        values.push((key.to_string(), proxy_url.to_string()));
    }
    for key in ["NO_PROXY", "no_proxy"] {
        values.push((key.to_string(), LOOPBACK_BYPASS.to_string()));
    }
    for key in [
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "SSL_CERT_FILE",
        "GIT_SSL_CAINFO",
        "PIP_CERT",
    ] {
        values.push((key.to_string(), ca_bundle.clone()));
    }
    values.push(("NODE_USE_ENV_PROXY".to_string(), "1".to_string()));
    values
}

fn scrub_sensitive_environment(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        if is_sensitive_environment_name(&name.to_string_lossy()) {
            command.env_remove(name);
        }
    }
}

fn is_sensitive_environment_name(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    name.contains("API_KEY")
        || name.contains("TOKEN")
        || name.contains("PASSWORD")
        || name.contains("SECRET")
        || matches!(
            name.as_str(),
            "AWS_ACCESS_KEY_ID"
                | "GOOGLE_APPLICATION_CREDENTIALS"
                | "AZURE_CLIENT_CERTIFICATE_PATH"
        )
}

fn configured_command(program: impl AsRef<OsStr>, environment: &[(String, String)]) -> Command {
    let mut command = Command::new(program);
    scrub_sensitive_environment(&mut command);
    command.envs(environment.iter().map(|(key, value)| (key, value)));
    command
}

#[cfg(target_os = "macos")]
fn launch_platform_terminal(
    preference: &str,
    environment: &[(String, String)],
) -> Result<String, String> {
    let (application, label) = match preference {
        "" | "auto" | "terminal" => ("Terminal", "Terminal"),
        "iterm2" => ("iTerm", "iTerm2"),
        _ => return Err("当前 macOS 不支持所选终端".to_string()),
    };
    let launcher = write_macos_launcher(environment)?;
    let status = configured_command("open", &[])
        .args(["-a", application])
        .arg(&launcher)
        .status()
        .map_err(|error| format!("打开 {label} 失败：{error}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&launcher);
        return Err(format!("未能打开 {label}，请确认终端应用已经安装"));
    }
    Ok(label.to_string())
}

#[cfg(target_os = "macos")]
fn write_macos_launcher(environment: &[(String, String)]) -> Result<PathBuf, String> {
    let path = std::env::temp_dir().join(format!(
        "shownet-proxy-terminal-{}.command",
        uuid::Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|error| format!("创建代理终端启动器失败：{error}"))?;
    file.write_all(unix_launcher_script(environment).as_bytes())
        .map_err(|error| format!("写入代理终端启动器失败：{error}"))?;
    file.sync_all()
        .map_err(|error| format!("保存代理终端启动器失败：{error}"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("保护代理终端启动器失败：{error}"))?;
    Ok(path)
}

#[cfg(any(target_os = "macos", test))]
fn unix_launcher_script(environment: &[(String, String)]) -> String {
    let mut script = String::from("#!/bin/sh\n");
    for (key, value) in environment {
        script.push_str("export ");
        script.push_str(key);
        script.push('=');
        script.push_str(&unix_shell_quote(value));
        script.push('\n');
    }
    script.push_str("printf '\\n  ShowNet Proxy Terminal\\n'\n");
    script.push_str("printf '  Proxy and HTTPS trust are ready for this shell.\\n\\n'\n");
    script.push_str("rm -f -- \"$0\"\n");
    script.push_str("exec \"${SHELL:-/bin/sh}\" -i\n");
    script
}

#[cfg(any(target_os = "macos", test))]
fn unix_shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(target_os = "windows")]
fn launch_platform_terminal(
    preference: &str,
    environment: &[(String, String)],
) -> Result<String, String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NEW_CONSOLE: u32 = 0x00000010;
    let (program, label, arguments): (&str, &str, Vec<&str>) = match preference {
        "" | "auto" | "powershell" => (
            "powershell.exe",
            "PowerShell",
            vec![
                "-NoLogo",
                "-NoExit",
                "-Command",
                "Write-Host ''; Write-Host 'ShowNet Proxy Terminal' -ForegroundColor Cyan; Write-Host 'Proxy and HTTPS trust are ready.' -ForegroundColor Green; Write-Host ''",
            ],
        ),
        "pwsh" => (
            "pwsh.exe",
            "PowerShell 7",
            vec![
                "-NoLogo",
                "-NoExit",
                "-Command",
                "Write-Host ''; Write-Host 'ShowNet Proxy Terminal' -ForegroundColor Cyan; Write-Host 'Proxy and HTTPS trust are ready.' -ForegroundColor Green; Write-Host ''",
            ],
        ),
        "cmd" => (
            "cmd.exe",
            "CMD",
            vec!["/K", "echo. & echo ShowNet Proxy Terminal & echo Proxy and HTTPS trust are ready. & echo."],
        ),
        _ => return Err("当前 Windows 不支持所选终端".to_string()),
    };
    configured_command(program, environment)
        .args(arguments)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map_err(|error| format!("打开 {label} 失败：{error}"))?;
    Ok(label.to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn launch_platform_terminal(
    preference: &str,
    environment: &[(String, String)],
) -> Result<String, String> {
    let candidates: Vec<(&str, &str, Vec<String>)> = match preference {
        "" | "auto" => vec![
            linux_terminal("gnome-terminal"),
            linux_terminal("konsole"),
            linux_terminal("x-terminal-emulator"),
        ],
        "gnome-terminal" | "konsole" | "x-terminal-emulator" => {
            vec![linux_terminal(preference)]
        }
        _ => return Err("当前 Linux 不支持所选终端".to_string()),
    };
    for (program, label, arguments) in candidates {
        if !command_exists(program) {
            continue;
        }
        configured_command(program, environment)
            .args(arguments)
            .spawn()
            .map_err(|error| format!("打开 {label} 失败：{error}"))?;
        return Ok(label.to_string());
    }
    Err("未找到可用终端，请安装 GNOME Terminal 或 Konsole".to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn linux_terminal(preference: &str) -> (&str, &str, Vec<String>) {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    match preference {
        "gnome-terminal" => (
            "gnome-terminal",
            "GNOME Terminal",
            vec![
                "--title=ShowNet Proxy Terminal".into(),
                "--".into(),
                shell,
                "-i".into(),
            ],
        ),
        "konsole" => (
            "konsole",
            "Konsole",
            vec![
                "-p".into(),
                "tabtitle=ShowNet Proxy Terminal".into(),
                "-e".into(),
                shell,
                "-i".into(),
            ],
        ),
        _ => (
            "x-terminal-emulator",
            "System Terminal",
            vec![
                "-T".into(),
                "ShowNet Proxy Terminal".into(),
                "-e".into(),
                shell,
                "-i".into(),
            ],
        ),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn command_exists(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .map(|path| path.join(program))
                .any(|path| path.is_file())
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_covers_proxy_ca_and_safe_loopback_bypass() {
        let environment = proxy_environment(
            "http://127.0.0.1:8888",
            Path::new("/tmp/ShowNet CA/proxy-bundle.pem"),
        );
        let value = |key: &str| {
            environment
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value("HTTP_PROXY"), Some("http://127.0.0.1:8888"));
        assert_eq!(value("https_proxy"), Some("http://127.0.0.1:8888"));
        assert_eq!(value("NO_PROXY"), Some(LOOPBACK_BYPASS));
        assert_eq!(value("NODE_USE_ENV_PROXY"), Some("1"));
        assert_eq!(
            value("REQUESTS_CA_BUNDLE"),
            Some("/tmp/ShowNet CA/proxy-bundle.pem")
        );
        assert_eq!(value("NODE_TLS_REJECT_UNAUTHORIZED"), None);
    }

    #[test]
    fn launcher_quotes_values_and_exports_no_unrelated_secrets() {
        let environment = vec![
            (
                "HTTP_PROXY".to_string(),
                "http://127.0.0.1:8888".to_string(),
            ),
            (
                "SSL_CERT_FILE".to_string(),
                "/tmp/user's cert.pem".to_string(),
            ),
        ];
        let script = unix_launcher_script(&environment);
        assert!(script.contains("export HTTP_PROXY='http://127.0.0.1:8888'"));
        assert!(script.contains("export SSL_CERT_FILE='/tmp/user'\"'\"'s cert.pem'"));
        assert!(!script.contains("OPENAI_API_KEY"));
        assert!(script.contains("exec \"${SHELL:-/bin/sh}\" -i"));
    }

    #[test]
    fn rejects_remote_or_authenticated_proxy_targets() {
        assert!(validate_loopback_proxy("https://127.0.0.1:8888").is_err());
        assert!(validate_loopback_proxy("http://example.com:8888").is_err());
        assert!(validate_loopback_proxy("http://user:pass@127.0.0.1:8888").is_err());
        assert_eq!(
            validate_loopback_proxy("http://localhost:8888/").unwrap(),
            "http://localhost:8888"
        );
    }

    #[test]
    fn removes_api_credentials_without_removing_normal_shell_state() {
        assert!(is_sensitive_environment_name("OPENAI_API_KEY"));
        assert!(is_sensitive_environment_name("GITHUB_TOKEN"));
        assert!(is_sensitive_environment_name("DATABASE_PASSWORD"));
        assert!(is_sensitive_environment_name("AWS_ACCESS_KEY_ID"));
        assert!(!is_sensitive_environment_name("PATH"));
        assert!(!is_sensitive_environment_name("SSH_AUTH_SOCK"));
        assert!(!is_sensitive_environment_name("HOME"));
    }
}
