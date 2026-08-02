use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const ADB_TIMEOUT: Duration = Duration::from_secs(15);
const DEVICE_CERTIFICATE_PATH: &str = "/sdcard/Download/shownet-root-ca.crt";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidDevice {
    pub serial: String,
    pub state: String,
    pub model: String,
    pub product: Option<String>,
    pub device: Option<String>,
    pub transport_id: Option<String>,
    pub ready: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidSetupStatus {
    pub adb_available: bool,
    pub adb_path: Option<String>,
    pub devices: Vec<AndroidDevice>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidSetupResult {
    pub serial: String,
    pub model: String,
    pub proxy_endpoint: String,
    pub certificate_path: String,
    pub installer_opened: bool,
    pub confirmation_required: bool,
}

pub async fn inspect() -> AndroidSetupStatus {
    let Some(adb) = find_adb() else {
        return AndroidSetupStatus {
            adb_available: false,
            adb_path: None,
            devices: Vec::new(),
            message: Some("未找到 ADB。安装 Android Platform Tools 后重新检测。".to_string()),
        };
    };
    let adb_path = Some(adb.to_string_lossy().to_string());
    match run_adb(&adb, &["devices", "-l"]).await {
        Ok(output) => {
            let devices = parse_adb_devices(&output);
            let message = if devices.is_empty() {
                Some("未发现 Android 设备。连接 USB 并开启 USB 调试。".to_string())
            } else if devices.iter().all(|device| !device.ready) {
                Some("设备尚未授权，请在手机上允许这台电脑进行 USB 调试。".to_string())
            } else {
                None
            };
            AndroidSetupStatus {
                adb_available: true,
                adb_path,
                devices,
                message,
            }
        }
        Err(error) => AndroidSetupStatus {
            adb_available: true,
            adb_path,
            devices: Vec::new(),
            message: Some(error),
        },
    }
}

pub async fn prepare(
    serial: &str,
    proxy_endpoint: &str,
    certificate_path: &Path,
) -> Result<AndroidSetupResult, String> {
    let adb =
        find_adb().ok_or_else(|| "未找到 ADB，请先安装 Android Platform Tools".to_string())?;
    let status = inspect().await;
    let device = validated_device(&status.devices, serial)?;
    run_adb_owned(
        &adb,
        vec![
            "-s".to_string(),
            device.serial.clone(),
            "push".to_string(),
            certificate_path.to_string_lossy().to_string(),
            DEVICE_CERTIFICATE_PATH.to_string(),
        ],
    )
    .await?;
    run_adb_owned(
        &adb,
        vec![
            "-s".to_string(),
            device.serial.clone(),
            "shell".to_string(),
            "settings".to_string(),
            "put".to_string(),
            "global".to_string(),
            "http_proxy".to_string(),
            proxy_endpoint.to_string(),
        ],
    )
    .await?;

    let certificate_uri = format!("file://{DEVICE_CERTIFICATE_PATH}");
    let installer = run_adb_owned(
        &adb,
        vec![
            "-s".to_string(),
            device.serial.clone(),
            "shell".to_string(),
            "am".to_string(),
            "start".to_string(),
            "-W".to_string(),
            "-a".to_string(),
            "android.intent.action.VIEW".to_string(),
            "-d".to_string(),
            certificate_uri,
            "-t".to_string(),
            "application/x-x509-ca-cert".to_string(),
            "--grant-read-uri-permission".to_string(),
        ],
    )
    .await;
    let installer_opened = installer.is_ok();
    if !installer_opened {
        run_adb_owned(
            &adb,
            vec![
                "-s".to_string(),
                device.serial.clone(),
                "shell".to_string(),
                "am".to_string(),
                "start".to_string(),
                "-a".to_string(),
                "android.settings.SECURITY_SETTINGS".to_string(),
            ],
        )
        .await
        .map_err(|error| format!("证书已推送且代理已配置，但无法打开系统证书页面：{error}"))?;
    }

    Ok(AndroidSetupResult {
        serial: device.serial,
        model: device.model,
        proxy_endpoint: proxy_endpoint.to_string(),
        certificate_path: DEVICE_CERTIFICATE_PATH.to_string(),
        installer_opened,
        confirmation_required: true,
    })
}

pub async fn reset_proxy(serial: &str) -> Result<(), String> {
    let adb =
        find_adb().ok_or_else(|| "未找到 ADB，请先安装 Android Platform Tools".to_string())?;
    let status = inspect().await;
    let device = validated_device(&status.devices, serial)?;
    run_adb_owned(
        &adb,
        vec![
            "-s".to_string(),
            device.serial,
            "shell".to_string(),
            "settings".to_string(),
            "put".to_string(),
            "global".to_string(),
            "http_proxy".to_string(),
            ":0".to_string(),
        ],
    )
    .await?;
    Ok(())
}

fn find_adb() -> Option<PathBuf> {
    let executable = if cfg!(windows) { "adb.exe" } else { "adb" };
    let mut candidates = Vec::new();
    for variable in ["ANDROID_HOME", "ANDROID_SDK_ROOT"] {
        if let Some(root) = std::env::var_os(variable) {
            candidates.push(PathBuf::from(root).join("platform-tools").join(executable));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        candidates.push(
            home.join("Library/Android/sdk/platform-tools")
                .join(executable),
        );
        candidates.push(home.join("Android/Sdk/platform-tools").join(executable));
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|path| path.join(executable)));
    }
    candidates.into_iter().find(|candidate| candidate.is_file())
}

fn parse_adb_devices(output: &str) -> Vec<AndroidDevice> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("List of devices"))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let serial = fields.next()?.to_string();
            let state = fields.next()?.to_string();
            let metadata = fields
                .filter_map(|field| field.split_once(':'))
                .map(|(key, value)| (key.to_string(), value.replace('_', " ")))
                .collect::<HashMap<_, _>>();
            let model = metadata
                .get("model")
                .cloned()
                .unwrap_or_else(|| serial.clone());
            Some(AndroidDevice {
                serial,
                ready: state == "device",
                state,
                model,
                product: metadata.get("product").cloned(),
                device: metadata.get("device").cloned(),
                transport_id: metadata.get("transport_id").cloned(),
            })
        })
        .collect()
}

fn validated_device(devices: &[AndroidDevice], serial: &str) -> Result<AndroidDevice, String> {
    let serial = serial.trim();
    let device = devices
        .iter()
        .find(|device| device.serial == serial)
        .cloned()
        .ok_or_else(|| "所选 Android 设备已断开，请重新检测".to_string())?;
    if !device.ready {
        return Err(match device.state.as_str() {
            "unauthorized" => "请在手机上允许 USB 调试后重试".to_string(),
            "offline" => "Android 设备当前离线，请重新连接 USB".to_string(),
            state => format!("Android 设备当前不可用：{state}"),
        });
    }
    Ok(device)
}

async fn run_adb(adb: &Path, args: &[&str]) -> Result<String, String> {
    run_adb_owned(adb, args.iter().map(|arg| (*arg).to_string()).collect()).await
}

async fn run_adb_owned(adb: &Path, args: Vec<String>) -> Result<String, String> {
    let output = timeout(ADB_TIMEOUT, Command::new(adb).args(&args).output())
        .await
        .map_err(|_| "ADB 操作超时，请检查设备连接".to_string())?
        .map_err(|error| format!("无法启动 ADB：{error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    let reports_failure = combined.contains("error:")
        || combined.contains("exception")
        || combined.contains("unable to resolve intent")
        || combined.contains("permission denial");
    if output.status.success() && !reports_failure {
        Ok(stdout)
    } else {
        let detail = if stderr.is_empty() { stdout } else { stderr };
        Err(if detail.is_empty() {
            "ADB 操作失败".to_string()
        } else {
            format!("ADB 操作失败：{detail}")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ready_unauthorized_and_offline_devices() {
        let devices = parse_adb_devices(
            "List of devices attached\nR58M123 device product:dm3q model:SM_S9180 device:dm3q transport_id:1\nemulator-5554 unauthorized transport_id:2\nphone-2 offline\n",
        );
        assert_eq!(devices.len(), 3);
        assert_eq!(devices[0].model, "SM S9180");
        assert!(devices[0].ready);
        assert_eq!(devices[1].state, "unauthorized");
        assert!(!devices[2].ready);
    }

    #[test]
    fn only_accepts_a_ready_device_from_the_current_adb_list() {
        let devices = parse_adb_devices(
            "List of devices attached\nready-1 device model:Pixel_8\nlocked-1 unauthorized\n",
        );
        assert!(validated_device(&devices, "ready-1").is_ok());
        assert!(validated_device(&devices, "locked-1")
            .unwrap_err()
            .contains("允许 USB 调试"));
        assert!(validated_device(&devices, "missing").is_err());
    }
}
