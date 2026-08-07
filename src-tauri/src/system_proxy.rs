use serde::{Deserialize, Serialize};
use std::process::{Command, Output};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "platform", content = "state", rename_all = "lowercase")]
pub enum SystemProxySnapshot {
    Macos(Vec<MacServiceProxyState>),
    Windows(WindowsProxySnapshot),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacServiceProxyState {
    pub service: String,
    pub web: NetworkProxyState,
    pub secure_web: NetworkProxyState,
    pub automatic: AutomaticProxyState,
    pub automatic_discovery: bool,
    pub bypass: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProxyState {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
    pub authenticated: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomaticProxyState {
    pub enabled: bool,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProxySnapshot {
    pub proxy_enable: Option<String>,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
    pub auto_config_url: Option<String>,
}

/// Whether a stored snapshot represents a restore somebody still owes.
///
/// A snapshot exists for the whole time the takeover is active — that is how
/// the user's original settings get put back on stop or exit. Reporting the
/// mere presence of one as a pending recovery raised an alarm on every healthy
/// capture, next to a button that would have undone the live takeover.
pub fn recovery_is_pending(active: bool, has_recovery_record: bool) -> bool {
    !active && has_recovery_record
}

pub fn capture_snapshot() -> Result<SystemProxySnapshot, String> {
    #[cfg(target_os = "macos")]
    {
        capture_macos().map(SystemProxySnapshot::Macos)
    }
    #[cfg(target_os = "windows")]
    {
        capture_windows().map(SystemProxySnapshot::Windows)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err("当前平台不支持自动接管系统代理".to_string())
    }
}

pub fn apply(
    snapshot: &SystemProxySnapshot,
    host: &str,
    port: u16,
    bypass: &[String],
) -> Result<(), String> {
    match snapshot {
        #[cfg(target_os = "macos")]
        SystemProxySnapshot::Macos(services) => apply_macos(services, host, port, bypass),
        #[cfg(not(target_os = "macos"))]
        SystemProxySnapshot::Macos(_) => Err("macOS 代理状态无法在当前平台应用".to_string()),
        #[cfg(target_os = "windows")]
        SystemProxySnapshot::Windows(_) => apply_windows(host, port, bypass),
        #[cfg(not(target_os = "windows"))]
        SystemProxySnapshot::Windows(_) => Err("Windows 代理状态无法在当前平台应用".to_string()),
    }
}

pub fn restore(snapshot: &SystemProxySnapshot) -> Result<(), String> {
    match snapshot {
        #[cfg(target_os = "macos")]
        SystemProxySnapshot::Macos(services) => restore_macos(services),
        #[cfg(not(target_os = "macos"))]
        SystemProxySnapshot::Macos(_) => {
            Err("代理恢复记录来自 macOS，无法在当前平台应用".to_string())
        }
        #[cfg(target_os = "windows")]
        SystemProxySnapshot::Windows(settings) => restore_windows(settings),
        #[cfg(not(target_os = "windows"))]
        SystemProxySnapshot::Windows(_) => {
            Err("代理恢复记录来自 Windows，无法在当前平台应用".to_string())
        }
    }
}

#[cfg(target_os = "macos")]
fn capture_macos() -> Result<Vec<MacServiceProxyState>, String> {
    let output = command_output("networksetup", &["-listallnetworkservices"])?;
    let services = parse_network_services(&output);
    if services.is_empty() {
        return Err("未发现可接管的 macOS 网络服务".to_string());
    }

    services
        .into_iter()
        .map(|service| {
            let web = parse_network_proxy(&networksetup(&["-getwebproxy", &service])?)?;
            let secure_web =
                parse_network_proxy(&networksetup(&["-getsecurewebproxy", &service])?)?;
            if web.authenticated || secure_web.authenticated {
                return Err(format!(
                    "网络服务 {service} 使用带认证的系统代理，ShowNet 无法读取并无损恢复其密码；请使用手动代理模式"
                ));
            }
            let automatic =
                parse_automatic_proxy(&networksetup(&["-getautoproxyurl", &service])?)?;
            let automatic_discovery = parse_enabled_only(&networksetup(&[
                "-getproxyautodiscovery",
                &service,
            ])?)?;
            let bypass = parse_bypass_domains(&networksetup(&[
                "-getproxybypassdomains",
                &service,
            ])?);
            Ok(MacServiceProxyState {
                service,
                web,
                secure_web,
                automatic,
                automatic_discovery,
                bypass,
            })
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn apply_macos(
    services: &[MacServiceProxyState],
    host: &str,
    port: u16,
    bypass: &[String],
) -> Result<(), String> {
    for service in services {
        set_network_proxy(&service.service, "web", host, port, true)?;
        set_network_proxy(&service.service, "secureweb", host, port, true)?;
        networksetup(&["-setautoproxystate", &service.service, "off"])?;
        networksetup(&["-setproxyautodiscovery", &service.service, "off"])?;
        set_bypass_domains(&service.service, bypass)?;
    }
    let applied = capture_macos()?;
    for expected in services {
        let actual = applied
            .iter()
            .find(|service| service.service == expected.service)
            .ok_or_else(|| format!("系统代理写入后未找到网络服务 {}", expected.service))?;
        let web_matches = actual.web.enabled
            && actual.web.server == host
            && actual.web.port == port
            && !actual.web.authenticated;
        let secure_matches = actual.secure_web.enabled
            && actual.secure_web.server == host
            && actual.secure_web.port == port
            && !actual.secure_web.authenticated;
        if !web_matches
            || !secure_matches
            || actual.automatic.enabled
            || actual.automatic_discovery
            || actual.bypass != bypass
        {
            return Err(format!(
                "网络服务 {} 的系统代理写入校验失败",
                expected.service
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_macos(services: &[MacServiceProxyState]) -> Result<(), String> {
    for service in services {
        restore_network_proxy(&service.service, "web", &service.web)?;
        restore_network_proxy(&service.service, "secureweb", &service.secure_web)?;
        if !service.automatic.url.is_empty() {
            networksetup(&["-setautoproxyurl", &service.service, &service.automatic.url])?;
        }
        networksetup(&[
            "-setautoproxystate",
            &service.service,
            on_off(service.automatic.enabled),
        ])?;
        networksetup(&[
            "-setproxyautodiscovery",
            &service.service,
            on_off(service.automatic_discovery),
        ])?;
        set_bypass_domains(&service.service, &service.bypass)?;
    }
    let restored = capture_macos()?;
    for expected in services {
        let actual = restored
            .iter()
            .find(|service| service.service == expected.service)
            .ok_or_else(|| format!("系统代理恢复后未找到网络服务 {}", expected.service))?;
        if !macos_effective_state_matches(actual, expected) {
            return Err(format!(
                "网络服务 {} 的系统代理恢复校验失败",
                expected.service
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_effective_state_matches(
    actual: &MacServiceProxyState,
    expected: &MacServiceProxyState,
) -> bool {
    effective_network_proxy_matches(&actual.web, &expected.web)
        && effective_network_proxy_matches(&actual.secure_web, &expected.secure_web)
        && actual.automatic.enabled == expected.automatic.enabled
        && (!expected.automatic.enabled || actual.automatic.url == expected.automatic.url)
        && actual.automatic_discovery == expected.automatic_discovery
        && actual.bypass == expected.bypass
}

#[cfg(target_os = "macos")]
fn effective_network_proxy_matches(
    actual: &NetworkProxyState,
    expected: &NetworkProxyState,
) -> bool {
    actual.enabled == expected.enabled
        && (!expected.enabled
            || (actual.server == expected.server
                && actual.port == expected.port
                && actual.authenticated == expected.authenticated))
}

#[cfg(target_os = "macos")]
fn restore_network_proxy(
    service: &str,
    kind: &str,
    proxy: &NetworkProxyState,
) -> Result<(), String> {
    if !proxy.server.is_empty() && proxy.port > 0 {
        set_network_proxy(service, kind, &proxy.server, proxy.port, proxy.enabled)?;
    } else {
        let state_flag = match kind {
            "web" => "-setwebproxystate",
            "secureweb" => "-setsecurewebproxystate",
            _ => return Err(format!("不支持的 macOS 代理类型: {kind}")),
        };
        networksetup(&[state_flag, service, on_off(proxy.enabled)])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_network_proxy(
    service: &str,
    kind: &str,
    host: &str,
    port: u16,
    enabled: bool,
) -> Result<(), String> {
    let (proxy_flag, state_flag) = match kind {
        "web" => ("-setwebproxy", "-setwebproxystate"),
        "secureweb" => ("-setsecurewebproxy", "-setsecurewebproxystate"),
        _ => return Err(format!("不支持的 macOS 代理类型: {kind}")),
    };
    let port = port.to_string();
    networksetup(&[proxy_flag, service, host, &port])?;
    networksetup(&[state_flag, service, on_off(enabled)])?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_bypass_domains(service: &str, bypass: &[String]) -> Result<(), String> {
    let mut arguments = vec!["-setproxybypassdomains".to_string(), service.to_string()];
    if bypass.is_empty() {
        arguments.push("Empty".to_string());
    } else {
        arguments.extend(bypass.iter().cloned());
    }
    let references = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    networksetup(&references)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn networksetup(arguments: &[&str]) -> Result<String, String> {
    command_output("networksetup", arguments)
}

#[cfg(target_os = "macos")]
fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

#[cfg(target_os = "windows")]
const INTERNET_SETTINGS_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(target_os = "windows")]
fn capture_windows() -> Result<WindowsProxySnapshot, String> {
    let output = command_output("reg.exe", &["query", INTERNET_SETTINGS_KEY])?;
    Ok(parse_windows_registry(&output))
}

#[cfg(target_os = "windows")]
fn apply_windows(host: &str, port: u16, bypass: &[String]) -> Result<(), String> {
    let proxy_server = format!("http={host}:{port};https={host}:{port}");
    let mut proxy_override = bypass.join(";");
    if !bypass
        .iter()
        .any(|value| value.eq_ignore_ascii_case("<local>"))
    {
        if !proxy_override.is_empty() {
            proxy_override.push(';');
        }
        proxy_override.push_str("<local>");
    }
    set_registry_value("ProxyServer", "REG_SZ", &proxy_server)?;
    set_registry_value("ProxyOverride", "REG_SZ", &proxy_override)?;
    set_registry_value("ProxyEnable", "REG_DWORD", "1")?;
    delete_registry_value("AutoConfigURL");
    notify_windows_proxy_change()?;
    let applied = capture_windows()?;
    if !matches!(applied.proxy_enable.as_deref(), Some("0x1") | Some("1"))
        || applied.proxy_server.as_deref() != Some(proxy_server.as_str())
        || applied.proxy_override.as_deref() != Some(proxy_override.as_str())
        || applied.auto_config_url.is_some()
    {
        return Err("Windows 系统代理写入校验失败".to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn restore_windows(snapshot: &WindowsProxySnapshot) -> Result<(), String> {
    restore_registry_value("ProxyEnable", "REG_DWORD", snapshot.proxy_enable.as_deref())?;
    restore_registry_value("ProxyServer", "REG_SZ", snapshot.proxy_server.as_deref())?;
    restore_registry_value(
        "ProxyOverride",
        "REG_SZ",
        snapshot.proxy_override.as_deref(),
    )?;
    restore_registry_value(
        "AutoConfigURL",
        "REG_SZ",
        snapshot.auto_config_url.as_deref(),
    )?;
    notify_windows_proxy_change()?;
    let restored = capture_windows()?;
    if &restored != snapshot {
        return Err("Windows 系统代理恢复校验失败".to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn restore_registry_value(name: &str, kind: &str, value: Option<&str>) -> Result<(), String> {
    match value {
        Some(value) => set_registry_value(name, kind, value),
        None => {
            delete_registry_value(name);
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
fn set_registry_value(name: &str, kind: &str, value: &str) -> Result<(), String> {
    command_output(
        "reg.exe",
        &[
            "add",
            INTERNET_SETTINGS_KEY,
            "/v",
            name,
            "/t",
            kind,
            "/d",
            value,
            "/f",
        ],
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn delete_registry_value(name: &str) {
    // Deleting a value that was never set is a normal outcome here, so the exit
    // status is discarded; `apply_windows` re-reads the key and fails loudly if
    // a value it needed gone is still there.
    let _ = configured_command("reg.exe")
        .args(["delete", INTERNET_SETTINGS_KEY, "/v", name, "/f"])
        .output();
}

#[cfg(target_os = "windows")]
fn notify_windows_proxy_change() -> Result<(), String> {
    use std::ptr::null;
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };

    let changed =
        unsafe { InternetSetOptionW(null(), INTERNET_OPTION_SETTINGS_CHANGED, null(), 0) };
    // INTERNET_OPTION_REFRESH re-reads the settings we just broadcast. It is a
    // best-effort nudge — on a process holding no WinINET handle it can report
    // failure while the broadcast itself landed, and treating that as fatal
    // used to roll the registry back and abort the whole capture start.
    let _ = unsafe { InternetSetOptionW(null(), INTERNET_OPTION_REFRESH, null(), 0) };
    if changed == 0 {
        return Err("Windows 已写入代理设置，但系统刷新通知失败".to_string());
    }
    Ok(())
}

/// Applying the proxy shells out to `reg.exe` four to six times. The app is a
/// GUI subsystem binary, so without this flag every one of those spawns pops a
/// console window on screen.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn configured_command(program: &str) -> Command {
    #[allow(unused_mut)]
    let mut command = Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

fn command_output(program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = configured_command(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("无法运行 {program}: {error}"))?;
    output_text(program, output)
}

fn output_text(program: &str, output: Output) -> Result<String, String> {
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if detail.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        detail
    };
    let detail = detail.chars().take(500).collect::<String>();
    Err(format!("{program} 执行失败: {detail}"))
}

fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with("An asterisk") && !line.starts_with('*')
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_network_proxy(output: &str) -> Result<NetworkProxyState, String> {
    Ok(NetworkProxyState {
        enabled: parse_bool_field(output, "Enabled")?,
        server: field(output, "Server").unwrap_or_default(),
        port: field(output, "Port")
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0),
        authenticated: parse_bool_field(output, "Authenticated Proxy Enabled").unwrap_or(false),
    })
}

fn parse_automatic_proxy(output: &str) -> Result<AutomaticProxyState, String> {
    let url = field(output, "URL").unwrap_or_default();
    Ok(AutomaticProxyState {
        enabled: parse_bool_field(output, "Enabled")?,
        url: if matches!(url.as_str(), "(null)" | "<null>") {
            String::new()
        } else {
            url
        },
    })
}

fn parse_enabled_only(output: &str) -> Result<bool, String> {
    parse_bool_field(output, "Enabled")
        .or_else(|_| parse_bool_field(output, "Auto Proxy Discovery"))
}

fn parse_bool_field(output: &str, name: &str) -> Result<bool, String> {
    let value = field(output, name).ok_or_else(|| format!("代理状态缺少 {name} 字段"))?;
    match value.to_ascii_lowercase().as_str() {
        "yes" | "on" | "true" | "1" => Ok(true),
        "no" | "off" | "false" | "0" => Ok(false),
        _ => Err(format!("无法解析代理状态 {name}: {value}")),
    }
}

fn field(output: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}:");
    output
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .map(ToOwned::to_owned)
}

fn parse_bypass_domains(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("There aren't any")
                && !line.eq_ignore_ascii_case("Empty")
        })
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(target_os = "windows", test))]
fn parse_windows_registry(output: &str) -> WindowsProxySnapshot {
    WindowsProxySnapshot {
        proxy_enable: windows_registry_value(output, "ProxyEnable"),
        proxy_server: windows_registry_value(output, "ProxyServer"),
        proxy_override: windows_registry_value(output, "ProxyOverride"),
        auto_config_url: windows_registry_value(output, "AutoConfigURL"),
    }
}

#[cfg(any(target_os = "windows", test))]
fn windows_registry_value(output: &str, name: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        let index = parts.iter().position(|part| *part == name)?;
        (parts.len() > index + 2).then(|| parts[index + 2..].join(" "))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holding_the_proxy_is_not_an_outstanding_recovery() {
        // The snapshot we are standing on is the takeover working as designed.
        assert!(!recovery_is_pending(true, true));
        // Only a leftover from a run that never restored is owed.
        assert!(recovery_is_pending(false, true));
        assert!(!recovery_is_pending(false, false));
        assert!(!recovery_is_pending(true, false));
    }

    #[test]
    fn parses_macos_proxy_state_without_touching_system_settings() {
        let proxy = parse_network_proxy(
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 8888\nAuthenticated Proxy Enabled: 0",
        )
        .unwrap();
        assert!(proxy.enabled);
        assert_eq!(proxy.server, "127.0.0.1");
        assert_eq!(proxy.port, 8888);
        assert!(!proxy.authenticated);
        assert!(!parse_enabled_only("Auto Proxy Discovery: Off").unwrap());
        assert_eq!(
            parse_automatic_proxy("URL: (null)\nEnabled: No")
                .unwrap()
                .url,
            ""
        );

        assert_eq!(
            parse_network_services(
                "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100/1000 LAN"
            ),
            vec!["Wi-Fi", "USB 10/100/1000 LAN"]
        );
    }

    #[test]
    fn parses_windows_proxy_registry_without_touching_the_registry() {
        let snapshot = parse_windows_registry(
            "    ProxyEnable    REG_DWORD    0x1\n    ProxyServer    REG_SZ    http=127.0.0.1:8888;https=127.0.0.1:8888\n    ProxyOverride    REG_SZ    localhost;*.local;<local>\n",
        );
        assert_eq!(snapshot.proxy_enable.as_deref(), Some("0x1"));
        assert_eq!(
            snapshot.proxy_server.as_deref(),
            Some("http=127.0.0.1:8888;https=127.0.0.1:8888")
        );
        assert_eq!(
            snapshot.proxy_override.as_deref(),
            Some("localhost;*.local;<local>")
        );
        assert!(snapshot.auto_config_url.is_none());
    }
}
