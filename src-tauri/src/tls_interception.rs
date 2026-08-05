use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

pub const MAX_TLS_BYPASS_RULES: usize = 128;
pub const MAX_TLS_BYPASS_RULE_BYTES: usize = 253;

/// Built-in static CDN hosts that often return 400 under rustls MITM (e.g. Baidu JSP3).
/// Wildcards cover both apex-style hosts and nested CDNs such as `pss.bdstatic.com`.
/// These domains stay end-to-end TLS when bypassed (no request/response body decryption).
/// Mirrored in the renderer (`src/tlsBypassPresets.ts`); exercised by unit tests.
#[allow(dead_code)]
pub const STATIC_CDN_BYPASS_PRESET: &[&str] = &["*.bdstatic.com", "*.bcebos.com"];

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsInterceptionMode {
    #[default]
    InterceptAll,
    BypassSelected,
    BypassAll,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInterceptionSettings {
    #[serde(default)]
    pub mode: TlsInterceptionMode,
    #[serde(default)]
    pub bypass: Vec<String>,
    #[serde(default = "show_bypassed_connections_by_default")]
    pub show_bypassed_connections: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsInterceptionDecision {
    pub bypass: bool,
    pub matched_rule: Option<String>,
    pub matched_host: Option<String>,
    pub record_successful_tunnel: bool,
}

impl Default for TlsInterceptionSettings {
    fn default() -> Self {
        Self {
            mode: TlsInterceptionMode::InterceptAll,
            bypass: Vec::new(),
            show_bypassed_connections: true,
        }
    }
}

impl TlsInterceptionSettings {
    pub fn decision(
        &self,
        authority_host: &str,
        client_hello_sni: Option<&str>,
    ) -> TlsInterceptionDecision {
        match self.mode {
            TlsInterceptionMode::InterceptAll => TlsInterceptionDecision::default(),
            TlsInterceptionMode::BypassAll => TlsInterceptionDecision {
                bypass: true,
                matched_rule: None,
                matched_host: normalize_match_host(authority_host),
                record_successful_tunnel: self.show_bypassed_connections,
            },
            TlsInterceptionMode::BypassSelected => {
                let mut candidates = Vec::with_capacity(2);
                if let Some(host) = normalize_match_host(authority_host) {
                    candidates.push(host);
                }
                if let Some(sni) = client_hello_sni.and_then(normalize_match_host) {
                    if !candidates.iter().any(|host| host == &sni) {
                        candidates.push(sni);
                    }
                }
                for rule in &self.bypass {
                    if let Some(host) = candidates
                        .iter()
                        .find(|host| wildcard_matches(rule.as_bytes(), host.as_bytes()))
                    {
                        return TlsInterceptionDecision {
                            bypass: true,
                            matched_rule: Some(rule.clone()),
                            matched_host: Some(host.clone()),
                            record_successful_tunnel: self.show_bypassed_connections,
                        };
                    }
                }
                TlsInterceptionDecision::default()
            }
        }
    }
}

fn show_bypassed_connections_by_default() -> bool {
    true
}

/// Merge the static CDN preset into settings, switching to `bypass_selected` when needed.
/// Does not change `bypass_all` (already tunnels every host). Dedupes against existing rules.
/// Used for first-run storage seed and settings one-click apply (UI mirrors list in TS).
pub fn apply_static_cdn_bypass_preset(
    settings: &TlsInterceptionSettings,
) -> Result<TlsInterceptionSettings, String> {
    if settings.mode == TlsInterceptionMode::BypassAll {
        return Ok(settings.clone());
    }
    let mut bypass = settings.bypass.clone();
    for rule in STATIC_CDN_BYPASS_PRESET {
        if !bypass
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(rule))
        {
            bypass.push((*rule).to_string());
        }
    }
    normalize_tls_interception_settings(TlsInterceptionSettings {
        mode: TlsInterceptionMode::BypassSelected,
        bypass,
        show_bypassed_connections: settings.show_bypassed_connections,
    })
}

pub fn normalize_tls_interception_settings(
    mut settings: TlsInterceptionSettings,
) -> Result<TlsInterceptionSettings, String> {
    if settings.bypass.len() > MAX_TLS_BYPASS_RULES {
        return Err(format!("HTTPS 绕行规则最多 {MAX_TLS_BYPASS_RULES} 条"));
    }
    let mut seen = HashSet::new();
    let mut bypass = Vec::with_capacity(settings.bypass.len());
    for (index, rule) in settings.bypass.into_iter().enumerate() {
        let normalized = normalize_rule(&rule)
            .map_err(|error| format!("第 {} 条 HTTPS 绕行规则无效：{error}", index + 1))?;
        if seen.insert(normalized.clone()) {
            bypass.push(normalized);
        }
    }
    if settings.mode == TlsInterceptionMode::BypassSelected && bypass.is_empty() {
        return Err("选择“绕行指定域名”时，至少填写一条域名规则".to_string());
    }
    settings.bypass = bypass;
    Ok(settings)
}

fn normalize_rule(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("规则不能为空".to_string());
    }
    if !trimmed.is_ascii() {
        return Err("请填写 ASCII 域名；中文域名请使用浏览器显示的 Punycode".to_string());
    }
    if trimmed.contains("://")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('@')
        || trimmed.contains('#')
        || trimmed.contains('%')
        || trimmed.chars().any(char::is_whitespace)
    {
        return Err("只填写域名或 IP，不要包含协议、端口、路径或凭据".to_string());
    }

    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing_dot.is_empty() || without_trailing_dot.ends_with('.') {
        return Err("域名格式无效".to_string());
    }
    let unbracketed = without_trailing_dot
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(without_trailing_dot);
    if let Ok(address) = unbracketed.parse::<IpAddr>() {
        return Ok(address.to_string().to_ascii_lowercase());
    }
    if unbracketed.contains(':') {
        return Err("域名规则不能包含端口；IPv6 地址可以使用方括号".to_string());
    }
    if unbracketed.len() > MAX_TLS_BYPASS_RULE_BYTES {
        return Err(format!(
            "单条规则不能超过 {MAX_TLS_BYPASS_RULE_BYTES} 个字符"
        ));
    }
    if unbracketed.bytes().all(|byte| matches!(byte, b'*' | b'?')) {
        return Err("如需绕行全部 HTTPS，请直接选择“全部绕行”".to_string());
    }
    for label in unbracketed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("域名标签不能为空且不能超过 63 个字符".to_string());
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*' | b'?'))
        {
            return Err("域名只能包含字母、数字、点、连字符以及 *、? 通配符".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("域名标签不能以连字符开头或结尾".to_string());
        }
    }
    Ok(unbracketed.to_ascii_lowercase())
}

fn normalize_match_host(input: &str) -> Option<String> {
    let value = input.trim().trim_matches(['[', ']']).trim_end_matches('.');
    (!value.is_empty() && value.len() <= MAX_TLS_BYPASS_RULE_BYTES)
        .then(|| value.to_ascii_lowercase())
}

fn wildcard_matches(pattern: &[u8], value: &[u8]) -> bool {
    let (mut pattern_index, mut value_index) = (0, 0);
    let mut star_index = None;
    let mut retry_value_index = 0;
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            retry_value_index = value_index;
        } else if let Some(star) = star_index {
            retry_value_index += 1;
            value_index = retry_value_index;
            pattern_index = star + 1;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected(rules: &[&str]) -> TlsInterceptionSettings {
        normalize_tls_interception_settings(TlsInterceptionSettings {
            mode: TlsInterceptionMode::BypassSelected,
            bypass: rules.iter().map(|rule| (*rule).to_string()).collect(),
            show_bypassed_connections: true,
        })
        .unwrap()
    }

    #[test]
    fn defaults_to_intercepting_every_host_without_implicit_loopback_bypass() {
        let settings = TlsInterceptionSettings::default();
        assert!(settings.show_bypassed_connections);
        assert!(!settings.decision("api.example.com", None).bypass);
        assert!(!settings.decision("127.0.0.1", None).bypass);
        assert!(!settings.decision("localhost", None).bypass);
    }

    #[test]
    fn normalizes_rules_and_removes_case_insensitive_duplicates() {
        let settings = selected(&[" *.Example.COM. ", "*.example.com", "[::1]"]);
        assert_eq!(settings.bypass, vec!["*.example.com", "::1"]);
    }

    #[test]
    fn matches_complete_hosts_with_star_and_question_wildcards() {
        let settings = selected(&["*.apple.com", "api?.example.test", "internal.test"]);
        assert!(settings.decision("www.apple.com", None).bypass);
        assert!(settings.decision("a.b.apple.com", None).bypass);
        assert!(!settings.decision("apple.com", None).bypass);
        assert!(!settings.decision("notapple.com", None).bypass);
        assert!(settings.decision("API1.EXAMPLE.TEST", None).bypass);
        assert!(!settings.decision("api12.example.test", None).bypass);
        assert!(settings.decision("internal.test", None).bypass);
        assert!(!settings.decision("notinternal.test", None).bypass);
    }

    #[test]
    fn can_match_sni_when_connect_uses_an_ip_address() {
        let decision =
            selected(&["*.secure.example"]).decision("203.0.113.8", Some("login.secure.example"));
        assert!(decision.bypass);
        assert_eq!(decision.matched_rule.as_deref(), Some("*.secure.example"));
        assert_eq!(
            decision.matched_host.as_deref(),
            Some("login.secure.example")
        );
    }

    #[test]
    fn rejects_urls_ports_credentials_empty_selected_modes_and_unbounded_rules() {
        for invalid in [
            "https://api.example.com",
            "api.example.com:443",
            "user@api.example.com",
            "api.example.com/path",
            "foo..example.com",
            "*",
        ] {
            assert!(
                normalize_tls_interception_settings(TlsInterceptionSettings {
                    mode: TlsInterceptionMode::BypassSelected,
                    bypass: vec![invalid.to_string()],
                    show_bypassed_connections: true,
                })
                .is_err(),
                "accepted {invalid}"
            );
        }
        assert!(
            normalize_tls_interception_settings(TlsInterceptionSettings {
                mode: TlsInterceptionMode::BypassSelected,
                bypass: vec![],
                show_bypassed_connections: true,
            })
            .is_err()
        );
        assert!(
            normalize_tls_interception_settings(TlsInterceptionSettings {
                mode: TlsInterceptionMode::InterceptAll,
                bypass: (0..=MAX_TLS_BYPASS_RULES)
                    .map(|index| format!("host-{index}.example"))
                    .collect(),
                show_bypassed_connections: true,
            })
            .is_err()
        );
    }

    #[test]
    fn bypass_all_does_not_require_a_synthetic_wildcard_rule() {
        let settings = normalize_tls_interception_settings(TlsInterceptionSettings {
            mode: TlsInterceptionMode::BypassAll,
            bypass: vec![],
            show_bypassed_connections: true,
        })
        .unwrap();
        let decision = settings.decision("anything.example", None);
        assert!(decision.bypass);
        assert!(decision.matched_rule.is_none());
        assert!(decision.record_successful_tunnel);
    }

    #[test]
    fn old_settings_show_bypassed_connections_and_hidden_mode_only_changes_recording() {
        let legacy: TlsInterceptionSettings =
            serde_json::from_str(r#"{"mode":"bypass_selected","bypass":["api.example.com"]}"#)
                .unwrap();
        assert!(legacy.show_bypassed_connections);
        assert!(
            legacy
                .decision("api.example.com", None)
                .record_successful_tunnel
        );

        let hidden = TlsInterceptionSettings {
            show_bypassed_connections: false,
            ..legacy
        };
        let decision = hidden.decision("api.example.com", None);
        assert!(decision.bypass);
        assert!(!decision.record_successful_tunnel);
    }

    #[test]
    fn static_cdn_preset_bypasses_baidu_cdn_hosts_without_mitm() {
        let settings = apply_static_cdn_bypass_preset(&TlsInterceptionSettings::default()).unwrap();
        assert_eq!(settings.mode, TlsInterceptionMode::BypassSelected);
        assert!(settings.bypass.iter().any(|r| r == "*.bdstatic.com"));
        assert!(settings.bypass.iter().any(|r| r == "*.bcebos.com"));

        // CONNECT / SNI hosts from the Baidu broken-static evidence should tunnel.
        for host in [
            "pss.bdstatic.com",
            "psstatic.cdn.bcebos.com",
            "img.bcebos.com",
            "ss0.bdstatic.com",
        ] {
            let decision = settings.decision(host, None);
            assert!(decision.bypass, "expected bypass for {host}");
            assert!(decision.record_successful_tunnel);
        }
        // Main site HTML still decrypts so search/API remain visible.
        assert!(!settings.decision("www.baidu.com", None).bypass);
        assert!(!settings.decision("www.baidu.com", Some("www.baidu.com")).bypass);
    }

    #[test]
    fn static_cdn_preset_merges_without_duplicates_and_skips_bypass_all() {
        let existing = normalize_tls_interception_settings(TlsInterceptionSettings {
            mode: TlsInterceptionMode::BypassSelected,
            bypass: vec!["*.bdstatic.com".into(), "api.secure.example".into()],
            show_bypassed_connections: true,
        })
        .unwrap();
        let merged = apply_static_cdn_bypass_preset(&existing).unwrap();
        assert_eq!(
            merged
                .bypass
                .iter()
                .filter(|r| r.as_str() == "*.bdstatic.com")
                .count(),
            1
        );
        assert!(merged.bypass.iter().any(|r| r == "*.bcebos.com"));
        assert!(merged.bypass.iter().any(|r| r == "api.secure.example"));

        let all = normalize_tls_interception_settings(TlsInterceptionSettings {
            mode: TlsInterceptionMode::BypassAll,
            bypass: vec![],
            show_bypassed_connections: false,
        })
        .unwrap();
        let unchanged = apply_static_cdn_bypass_preset(&all).unwrap();
        assert_eq!(unchanged.mode, TlsInterceptionMode::BypassAll);
        assert!(unchanged.bypass.is_empty());
    }
}
