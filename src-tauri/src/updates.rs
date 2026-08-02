use crate::analysis::build_egress_client;
use crate::models::{EffectiveUpstreamProxy, UpdateCheckResult};
use futures_util::StreamExt;
use reqwest::header::{ACCEPT, USER_AGENT};
use semver::Version;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

const DEFAULT_MANIFEST_URL: &str = "https://claudegpt.org/shownet/latest.json";
const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_RELEASE_NOTES_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateManifest {
    version: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default, alias = "pub_date", alias = "published_at")]
    published_at: Option<String>,
    #[serde(default, alias = "download_url")]
    download_url: Option<String>,
    #[serde(default)]
    platforms: HashMap<String, UpdateArtifact>,
}

#[derive(Debug, Deserialize)]
struct UpdateArtifact {
    url: String,
}

pub async fn check_for_updates(
    upstream: EffectiveUpstreamProxy,
) -> Result<UpdateCheckResult, String> {
    let manifest_url = update_manifest_url();
    validate_https_url(manifest_url, "更新清单")?;
    let client = build_egress_client(&upstream, manifest_url)?;
    let response = client
        .get(manifest_url)
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, format!("ShowNet/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|error| format!("连接更新服务失败: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("更新服务返回 HTTP {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MANIFEST_BYTES as u64)
    {
        return Err("更新清单超过 128 KB 限制".to_string());
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("读取更新清单失败: {error}"))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_MANIFEST_BYTES {
            return Err("更新清单超过 128 KB 限制".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    parse_update_manifest(&bytes)
}

fn parse_update_manifest(bytes: &[u8]) -> Result<UpdateCheckResult, String> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err("更新清单超过 128 KB 限制".to_string());
    }
    let manifest = serde_json::from_slice::<UpdateManifest>(bytes)
        .map_err(|error| format!("更新清单不是有效 JSON: {error}"))?;
    let current_version = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("当前应用版本无效: {error}"))?;
    let latest_text = manifest.version.trim().trim_start_matches('v');
    let latest_version =
        Version::parse(latest_text).map_err(|error| format!("更新清单版本无效: {error}"))?;
    let available = latest_version > current_version;
    let platform = platform_key();
    let download_url = manifest
        .platforms
        .get(&platform)
        .map(|artifact| artifact.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .or_else(|| {
            manifest
                .download_url
                .map(|url| url.trim().to_string())
                .filter(|url| !url.is_empty())
        });
    if available {
        if let Some(url) = download_url.as_deref() {
            validate_https_url(url, "更新下载地址")?;
        }
    }
    Ok(UpdateCheckResult {
        current_version: current_version.to_string(),
        latest_version: latest_version.to_string(),
        available,
        notes: manifest
            .notes
            .map(|notes| truncate_utf8(notes.trim(), MAX_RELEASE_NOTES_BYTES))
            .filter(|notes| !notes.is_empty()),
        published_at: manifest
            .published_at
            .map(|value| truncate_utf8(value.trim(), 128))
            .filter(|value| !value.is_empty()),
        download_url: available.then_some(download_url).flatten(),
        platform,
    })
}

fn update_manifest_url() -> &'static str {
    option_env!("SHOWNET_UPDATE_MANIFEST_URL").unwrap_or(DEFAULT_MANIFEST_URL)
}

fn validate_https_url(value: &str, label: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(value).map_err(|error| format!("{label}无效: {error}"))?;
    if url.scheme() != "https" {
        return Err(format!("{label}必须使用 HTTPS"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{label}不能包含用户名或密码"));
    }
    Ok(())
}

fn platform_key() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "windows",
        other => other,
    };
    format!("{os}-{}", std::env::consts::ARCH)
}

fn truncate_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_string();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_platform_artifact_and_semver() {
        let platform = platform_key();
        let body = serde_json::json!({
            "version": "v99.1.0",
            "notes": "HTTP/2 and MCP improvements",
            "pub_date": "2026-07-30T00:00:00Z",
            "platforms": {
                platform.clone(): {
                    "url": "https://claudegpt.org/shownet/ShowNet-latest.zip",
                    "signature": "not-used-by-check-only-client"
                }
            }
        });
        let result = parse_update_manifest(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert!(result.available);
        assert_eq!(result.latest_version, "99.1.0");
        assert_eq!(result.platform, platform);
        assert_eq!(
            result.download_url.as_deref(),
            Some("https://claudegpt.org/shownet/ShowNet-latest.zip")
        );
    }

    #[test]
    fn rejects_insecure_downloads_and_oversized_manifests() {
        let body = serde_json::json!({
            "version": "99.1.0",
            "downloadUrl": "http://downloads.example.com/ShowNet.zip"
        });
        assert!(parse_update_manifest(&serde_json::to_vec(&body).unwrap())
            .unwrap_err()
            .contains("必须使用 HTTPS"));
        assert!(parse_update_manifest(&vec![b'x'; MAX_MANIFEST_BYTES + 1])
            .unwrap_err()
            .contains("128 KB"));
    }
}
