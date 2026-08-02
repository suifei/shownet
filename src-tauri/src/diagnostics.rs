use crate::models::{ConnectionDiagnostics, DiagnosticCheck};
use crate::{ca_status, runtime_status, system_proxy_status, AppState};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tauri::Manager;

pub async fn run(app: &tauri::AppHandle) -> Result<ConnectionDiagnostics, String> {
    let state = app.state::<AppState>();
    let runtime = runtime_status(&state)?;
    let system_proxy = system_proxy_status(&state)?;
    let ca = ca_status(&state);
    let upstream = state.storage.get_upstream_proxy_settings()?;
    let mut checks = Vec::new();

    let listener_status = if runtime.proxy_running {
        (
            "healthy",
            format!("正在监听 {}:{}", runtime.listen_host, runtime.proxy_port),
            "当前 Session 已接收流量".to_string(),
            None,
        )
    } else if std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, runtime.proxy_port))
        .is_ok()
    {
        (
            "idle",
            format!("端口 {} 可用，抓包尚未启动", runtime.proxy_port),
            "开始抓包后监听器会占用此端口".to_string(),
            Some("start-capture"),
        )
    } else {
        (
            "error",
            format!("端口 {} 已被其他进程占用", runtime.proxy_port),
            "关闭冲突代理工具，或修改监听端口后重试".to_string(),
            Some("capture-settings"),
        )
    };
    checks.push(check("listener", "抓包监听端口", listener_status));

    let proxy_status = if system_proxy.recovery_pending {
        (
            "error",
            "系统代理恢复待处理".to_string(),
            system_proxy
                .last_error
                .unwrap_or_else(|| "上次退出后未完成代理恢复".to_string()),
            Some("recover-system-proxy"),
        )
    } else if system_proxy.active {
        (
            "healthy",
            "系统代理已接管".to_string(),
            format!("HTTP(S) 流量指向 127.0.0.1:{}", runtime.proxy_port),
            Some("system-proxy-settings"),
        )
    } else {
        (
            "idle",
            "系统代理未接管".to_string(),
            "应用仍可通过手动代理接入 ShowNet".to_string(),
            Some("system-proxy-settings"),
        )
    };
    checks.push(check("system-proxy", "系统代理", proxy_status));

    checks.push(check(
        "root-ca",
        "Root CA",
        if ca.installed {
            (
                "healthy",
                "Root CA 已生成并信任".to_string(),
                format!("指纹 {}", ca.fingerprint),
                Some("export-ca"),
            )
        } else {
            (
                "warning",
                "Root CA 已生成但尚未信任".to_string(),
                "HTTPS 解密前需要安装到当前用户信任库".to_string(),
                Some("install-ca"),
            )
        },
    ));

    checks.push(check(
        "browser-ca",
        "浏览器证书",
        if runtime.platform == "windows" || runtime.platform == "macos" {
            (
                if ca.installed { "healthy" } else { "warning" },
                if ca.installed {
                    "Chrome / Edge 使用系统信任库".to_string()
                } else {
                    "浏览器尚不能信任 ShowNet".to_string()
                },
                "Firefox 可能使用独立证书库，需要在浏览器内额外导入".to_string(),
                Some("browser-ca-guide"),
            )
        } else {
            (
                "warning",
                "Linux 浏览器信任库需单独确认".to_string(),
                "Chrome 与 Firefox 的证书库可能不同".to_string(),
                Some("browser-ca-guide"),
            )
        },
    ));

    checks.push(check(
        "lan",
        "LAN 访问",
        if !runtime.lan_enabled {
            (
                "idle",
                "局域网设备接入已关闭".to_string(),
                "默认只接受本机流量".to_string(),
                Some("lan-settings"),
            )
        } else if runtime.lan_addresses.is_empty() {
            (
                "error",
                "未检测到可用私网地址".to_string(),
                "检查 Wi-Fi/有线网络，以及手机是否在同一私网".to_string(),
                Some("lan-settings"),
            )
        } else {
            (
                "healthy",
                format!(
                    "可通过 {}:{} 接入",
                    runtime.lan_addresses[0], runtime.proxy_port
                ),
                "仅私网和链路本地来源可连接".to_string(),
                Some("device-guide"),
            )
        },
    ));

    let upstream_check = if upstream.mode == "direct" {
        (
            "healthy",
            "当前使用直连出口".to_string(),
            "重放和抓包不会经过二级代理".to_string(),
            Some("upstream-settings"),
        )
    } else {
        let address = resolve_upstream(&upstream.host, upstream.port).await;
        match address {
            Ok(address) => match tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(address),
            )
            .await
            {
                Ok(Ok(_)) => (
                    "healthy",
                    format!("{} 上游代理可连接", upstream.mode.to_uppercase()),
                    format!("{}:{} TCP 握手成功", upstream.host, upstream.port),
                    Some("upstream-settings"),
                ),
                _ => (
                    "error",
                    "上游代理连接失败".to_string(),
                    format!("无法连接 {}:{}", upstream.host, upstream.port),
                    Some("upstream-settings"),
                ),
            },
            Err(error) => (
                "error",
                "上游代理地址无法解析".to_string(),
                error,
                Some("upstream-settings"),
            ),
        }
    };
    checks.push(check("upstream", "上游代理", upstream_check));

    let mobile_count = runtime
        .active_session_id
        .as_deref()
        .map(|session_id| state.storage.recent_device_request_count(session_id))
        .transpose()?
        .unwrap_or(0);
    checks.push(check(
        "mobile",
        "移动设备",
        if mobile_count > 0 {
            (
                "healthy",
                format!("当前 Session 已收到 {mobile_count} 条移动/IoT 请求"),
                "设备代理路径可用；证书固定应用仍可能无法解密".to_string(),
                Some("device-guide"),
            )
        } else if runtime.lan_enabled {
            (
                "warning",
                "尚未观察到移动设备请求".to_string(),
                "确认设备与电脑在同一私网、代理端口一致且防火墙允许连接".to_string(),
                Some("device-guide"),
            )
        } else {
            (
                "idle",
                "移动设备接入未开启".to_string(),
                "开启 LAN 访问后可显示二维码和证书指引".to_string(),
                Some("lan-settings"),
            )
        },
    ));

    let bypass = system_proxy
        .bypass
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let local_ok = ["localhost", "127.0.0.1", "::1"]
        .iter()
        .all(|required| bypass.iter().any(|entry| entry == required));
    checks.push(check(
        "localhost",
        "localhost 绕过",
        if local_ok {
            (
                "healthy",
                "本机回环地址已绕过".to_string(),
                "避免 ShowNet 自身流量再次进入系统代理".to_string(),
                Some("system-proxy-settings"),
            )
        } else {
            (
                "warning",
                "系统代理绕过列表不完整".to_string(),
                "建议加入 localhost、127.0.0.1 和 ::1，避免代理循环".to_string(),
                Some("system-proxy-settings"),
            )
        },
    ));

    Ok(ConnectionDiagnostics {
        checks,
        generated_at: chrono::Utc::now().timestamp_millis(),
    })
}

fn check(id: &str, label: &str, value: (&str, String, String, Option<&str>)) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.to_string(),
        label: label.to_string(),
        status: value.0.to_string(),
        summary: value.1,
        detail: value.2,
        repair_action: value.3.map(ToString::to_string),
    }
}

async fn resolve_upstream(host: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| format!("DNS 解析失败: {error}"))?
        .next()
        .ok_or_else(|| "DNS 未返回地址".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_preserves_repair_action() {
        let result = check(
            "ca",
            "CA",
            (
                "warning",
                "待安装".into(),
                "detail".into(),
                Some("install-ca"),
            ),
        );
        assert_eq!(result.repair_action.as_deref(), Some("install-ca"));
    }
}
