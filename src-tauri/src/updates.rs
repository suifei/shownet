//! Update checking, read straight from the GitHub Releases API.
//!
//! There is no separately hosted manifest: the release itself is the source of
//! truth. A hand-built `latest.json` only ever restated what GitHub already
//! knows — the tag, the notes, and download URLs that pointed back at the same
//! release — and it could drift from the release it described or be missed
//! entirely if publishing it failed after the release went out.

use crate::analysis::build_egress_client;
use crate::models::{EffectiveUpstreamProxy, UpdateCheckResult};
use futures_util::StreamExt;
use reqwest::header::{ACCEPT, USER_AGENT};
use semver::Version;
use serde::Deserialize;
use std::time::Duration;

const DEFAULT_MANIFEST_URL: &str = "https://api.github.com/repos/suifei/shownet/releases/latest";
const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_RELEASE_NOTES_BYTES: usize = 16 * 1024;

/// The subset of a GitHub release this needs. Everything else in the payload is
/// ignored rather than modelled, so a new field upstream cannot break parsing.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub async fn check_for_updates(
    upstream: EffectiveUpstreamProxy,
) -> Result<UpdateCheckResult, String> {
    let manifest_url = update_manifest_url();
    validate_https_url(manifest_url, "更新清单")?;
    let client = build_egress_client(&upstream, manifest_url)?;
    let response = client
        .get(manifest_url)
        // GitHub requires a User-Agent and pins its schema behind these headers;
        // without the version header the payload shape can change under us.
        .header(ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(USER_AGENT, format!("ShowNet/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|error| format!("连接更新服务失败: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        // These three are worth naming: unauthenticated GitHub allows 60 checks
        // an hour per address, and a repository with no published release is a
        // normal state, not a fault the user should go hunting for.
        return Err(match status.as_u16() {
            404 => "远端还没有发布任何版本".to_string(),
            403 | 429 => "GitHub 接口请求过于频繁（未登录时每小时 60 次），请稍后再试".to_string(),
            _ => format!("更新服务返回 HTTP {status}"),
        });
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
    let release = serde_json::from_slice::<GithubRelease>(bytes)
        .map_err(|error| format!("更新清单不是有效 JSON: {error}"))?;
    // `/releases/latest` never returns a draft, but the URL is overridable at
    // build time and a draft is not something a user should be offered.
    if release.draft {
        return Err("远端最新版本仍是草稿，尚未发布".to_string());
    }

    let current_version = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("当前应用版本无效: {error}"))?;
    let latest_text = release.tag_name.trim().trim_start_matches('v');
    let latest_version =
        Version::parse(latest_text).map_err(|error| format!("更新清单版本无效: {error}"))?;
    let available = latest_version > current_version;
    let platform = platform_key();

    // Fall back to the release page rather than nothing: a build for this
    // platform may simply not be attached yet, and sending the user to the
    // release beats telling them an update exists with no way to get it.
    let download_url = select_asset(&release.assets, &platform).or_else(|| {
        release
            .html_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(str::to_string)
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
        notes: release
            .body
            .map(|notes| truncate_utf8(notes.trim(), MAX_RELEASE_NOTES_BYTES))
            .filter(|notes| !notes.is_empty()),
        published_at: release
            .published_at
            .map(|value| truncate_utf8(value.trim(), 128))
            .filter(|value| !value.is_empty()),
        download_url: available.then_some(download_url).flatten(),
        platform,
    })
}

/// Pick the installable asset for this platform.
///
/// A release carries more than installers — checksums, verification records and
/// the odd manifest sit beside them, and several share the installer's name with
/// a suffix appended. Requiring both an OS and an architecture signal, and
/// accepting only extensions a user can actually open, keeps `.zip.sha256` from
/// being handed out as the download.
fn select_asset(assets: &[GithubAsset], platform: &str) -> Option<String> {
    let (os_tokens, arch_tokens): (&[&str], &[&str]) = match platform {
        p if p.starts_with("darwin") => (&["darwin", "macos", "mac", "osx", "apple"], &[]),
        p if p.starts_with("windows") => (&["windows", "win"], &[]),
        _ => (&[], &[]),
    };
    let arch_tokens: &[&str] = if !arch_tokens.is_empty() {
        arch_tokens
    } else {
        match platform.rsplit('-').next().unwrap_or_default() {
            "aarch64" => &["aarch64", "arm64"],
            "x86_64" => &["x86_64", "x64", "amd64"],
            _ => &[],
        }
    };
    let installable: &[&str] = if platform.starts_with("darwin") {
        &[".dmg", ".pkg"]
    } else if platform.starts_with("windows") {
        &[".msi", ".exe", ".zip"]
    } else {
        &[".tar.gz", ".appimage", ".deb", ".zip"]
    };

    assets
        .iter()
        .filter(|asset| {
            let name = asset.name.to_ascii_lowercase();
            installable.iter().any(|suffix| name.ends_with(suffix))
        })
        .find(|asset| {
            let name = asset.name.to_ascii_lowercase();
            let os_ok = os_tokens.is_empty()
                || os_tokens.iter().any(|token| name.contains(token))
                // A macOS DMG needs no "macos" in its name to be unambiguous.
                || installable
                    .iter()
                    .take(1)
                    .any(|suffix| *suffix == ".dmg" && name.ends_with(".dmg"));
            let arch_ok =
                arch_tokens.is_empty() || arch_tokens.iter().any(|token| name.contains(token));
            os_ok && arch_ok
        })
        .map(|asset| asset.browser_download_url.trim().to_string())
        .filter(|url| !url.is_empty())
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

    /// Shaped after the repository's real v0.1.0 release, decoys included: the
    /// checksum, the verification record and the summary file all sit beside the
    /// installers and must never be offered as a download.
    fn release_payload(tag: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "tag_name": tag,
            "body": "ShowNet desktop builds (macOS aarch64 DMG + Windows x86_64 portable ZIP).",
            "published_at": "2026-08-04T19:26:43Z",
            "html_url": "https://github.com/suifei/shownet/releases/tag/v0.1.0",
            "draft": false,
            "prerelease": false,
            "assets": [
                {"name": "latest.json", "browser_download_url": "https://github.com/x/latest.json"},
                {"name": "release-verification-macos.json", "browser_download_url": "https://github.com/x/rv.json"},
                {"name": "SHA256SUMS.txt", "browser_download_url": "https://github.com/x/SHA256SUMS.txt"},
                {"name": "ShowNetPortable_0.1.0_windows_x86_64.zip", "browser_download_url": "https://github.com/x/win.zip"},
                {"name": "ShowNetPortable_0.1.0_windows_x86_64.zip.sha256", "browser_download_url": "https://github.com/x/win.zip.sha256"},
                {"name": "ShowNet_0.1.0_aarch64.dmg", "browser_download_url": "https://github.com/x/mac.dmg"},
            ]
        }))
        .unwrap()
    }

    fn assets() -> Vec<GithubAsset> {
        let value: serde_json::Value = serde_json::from_slice(&release_payload("v0.1.0")).unwrap();
        serde_json::from_value(value["assets"].clone()).unwrap()
    }

    #[test]
    fn reads_version_notes_and_date_from_the_release() {
        let result = parse_update_manifest(&release_payload("v99.1.0")).unwrap();
        assert!(result.available);
        assert_eq!(result.latest_version, "99.1.0");
        assert_eq!(result.published_at.as_deref(), Some("2026-08-04T19:26:43Z"));
        assert!(result
            .notes
            .is_some_and(|notes| notes.contains("desktop builds")));
    }

    #[test]
    fn picks_the_installer_for_each_platform() {
        assert_eq!(
            select_asset(&assets(), "darwin-aarch64").as_deref(),
            Some("https://github.com/x/mac.dmg")
        );
        assert_eq!(
            select_asset(&assets(), "windows-x86_64").as_deref(),
            Some("https://github.com/x/win.zip")
        );
    }

    /// The failure that matters: `.zip.sha256` also ends in a plausible-looking
    /// name and sorts next to the real archive. Handing it over would download
    /// 64 bytes of hex and look like a corrupt release.
    #[test]
    fn never_offers_a_checksum_or_metadata_file_as_the_download() {
        for platform in ["darwin-aarch64", "windows-x86_64"] {
            let url = select_asset(&assets(), platform).expect("an installer exists");
            for decoy in [".sha256", ".json", ".txt"] {
                assert!(
                    !url.ends_with(decoy),
                    "{platform} was offered a {decoy} file: {url}"
                );
            }
        }
    }

    /// An architecture the release has no build for must not fall through to the
    /// other architecture's installer.
    #[test]
    fn does_not_substitute_a_build_for_a_different_architecture() {
        assert_eq!(select_asset(&assets(), "windows-aarch64"), None);
        assert_eq!(select_asset(&assets(), "darwin-x86_64"), None);
    }

    /// With no matching asset the user still gets somewhere useful, rather than
    /// being told an update exists with no way to reach it.
    #[test]
    fn falls_back_to_the_release_page_when_this_platform_has_no_build() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&release_payload("v99.1.0")).unwrap();
        value["assets"] = serde_json::json!([]);
        let result = parse_update_manifest(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(result.available);
        assert_eq!(
            result.download_url.as_deref(),
            Some("https://github.com/suifei/shownet/releases/tag/v0.1.0")
        );
    }

    #[test]
    fn an_older_or_equal_release_is_not_an_update() {
        let result = parse_update_manifest(&release_payload("v0.0.1")).unwrap();
        assert!(!result.available);
        assert!(
            result.download_url.is_none(),
            "nothing to download when there is nothing newer"
        );
    }

    #[test]
    fn a_draft_release_is_never_offered() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&release_payload("v99.1.0")).unwrap();
        value["draft"] = serde_json::json!(true);
        assert!(parse_update_manifest(&serde_json::to_vec(&value).unwrap())
            .unwrap_err()
            .contains("草稿"));
    }

    #[test]
    fn rejects_insecure_downloads_and_oversized_payloads() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&release_payload("v99.1.0")).unwrap();
        value["assets"] = serde_json::json!([
            {"name": "ShowNet_99.1.0_aarch64.dmg", "browser_download_url": "http://downloads.example.com/ShowNet.dmg"},
            {"name": "ShowNetPortable_99.1.0_windows_x86_64.zip", "browser_download_url": "http://downloads.example.com/ShowNet.zip"}
        ]);
        assert!(parse_update_manifest(&serde_json::to_vec(&value).unwrap())
            .unwrap_err()
            .contains("必须使用 HTTPS"));
        assert!(parse_update_manifest(&vec![b'x'; MAX_MANIFEST_BYTES + 1])
            .unwrap_err()
            .contains("128 KB"));
    }

    /// The default must be GitHub's API, so a fresh build depends on no
    /// self-hosted service.
    #[test]
    fn the_default_endpoint_is_the_github_releases_api() {
        assert_eq!(
            DEFAULT_MANIFEST_URL,
            "https://api.github.com/repos/suifei/shownet/releases/latest"
        );
        validate_https_url(DEFAULT_MANIFEST_URL, "更新清单").expect("default must be valid HTTPS");
    }

    /// Parse the payload GitHub actually returns for this repository, not a
    /// fixture shaped like it. Guarded by an env var so the suite stays offline
    /// by default; the fixture above is the everyday check.
    #[test]
    fn parses_the_live_release_payload() {
        let Ok(path) = std::env::var("SHOWNET_LIVE_RELEASE_JSON") else {
            return;
        };
        let bytes = std::fs::read(path).expect("live payload");
        let result = parse_update_manifest(&bytes).expect("live payload must parse");
        // Deliberately not pinned to a version: every release would break that,
        // and the version is not what this is checking. What matters is that a
        // real payload parses and resolves to the right file per platform.
        Version::parse(&result.latest_version).expect("live tag must be semver");

        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let assets: Vec<GithubAsset> = serde_json::from_value(value["assets"].clone()).unwrap();
        for (platform, extension, decoys) in [
            ("darwin-aarch64", ".dmg", ["aarch64"].as_slice()),
            ("windows-x86_64", ".zip", ["windows", "x86_64"].as_slice()),
        ] {
            let url = select_asset(&assets, platform).expect("live release has this build");
            assert!(url.ends_with(extension), "{platform} picked {url}");
            for token in decoys {
                assert!(url.contains(token), "{platform} picked {url}");
            }
        }
    }

    /// The user-facing path this whole change exists to serve: an older client
    /// looking at the live release must be told an update exists and be handed a
    /// working download for its own platform.
    #[test]
    fn an_older_client_is_offered_the_live_release() {
        let Ok(path) = std::env::var("SHOWNET_LIVE_RELEASE_JSON") else {
            return;
        };
        let bytes = std::fs::read(path).expect("live payload");
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let published = Version::parse(value["tag_name"].as_str().unwrap().trim_start_matches('v'))
            .expect("live tag is semver");
        let running = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        // Only meaningful while the build under test is not itself the newest.
        if published <= running {
            return;
        }
        let result = parse_update_manifest(&bytes).expect("live payload must parse");
        assert!(result.available, "{result:?}");
        let url = result
            .download_url
            .expect("an update must come with a way to get it");
        assert!(url.starts_with("https://"), "{url}");
    }
}
