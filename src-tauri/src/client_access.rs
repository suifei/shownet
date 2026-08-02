use crate::models::{CaptureListenerSettings, ClientAccessMode};
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;

pub const MAX_CLIENT_ACCESS_RULES: usize = 128;

#[derive(Clone, Debug)]
pub struct ClientAccessPolicy {
    lan_enabled: bool,
    mode: ClientAccessMode,
    rules: Vec<IpNet>,
}

impl ClientAccessPolicy {
    pub fn from_settings(
        settings: &CaptureListenerSettings,
        lan_enabled: bool,
    ) -> Result<Self, String> {
        let settings = normalize_capture_listener_settings(settings.clone())?;
        let rules = settings
            .access_rules
            .iter()
            .map(|rule| parse_access_rule(rule).map(|(_, network)| network))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            lan_enabled,
            mode: settings.access_mode,
            rules,
        })
    }

    #[cfg(test)]
    pub fn private_network(lan_enabled: bool) -> Self {
        Self {
            lan_enabled,
            mode: ClientAccessMode::Private,
            rules: Vec::new(),
        }
    }

    pub fn allows(&self, address: IpAddr) -> bool {
        if address.is_loopback() {
            return true;
        }
        if !self.lan_enabled || !is_private_or_link_local(address) {
            return false;
        }
        let matches_rule = self.rules.iter().any(|rule| rule.contains(&address));
        match self.mode {
            ClientAccessMode::Private => true,
            ClientAccessMode::Allow => matches_rule,
            ClientAccessMode::Deny => !matches_rule,
        }
    }
}

pub fn normalize_capture_listener_settings(
    mut settings: CaptureListenerSettings,
) -> Result<CaptureListenerSettings, String> {
    let source_rules = settings
        .access_rules
        .iter()
        .map(|rule| rule.trim())
        .filter(|rule| !rule.is_empty())
        .collect::<Vec<_>>();
    if source_rules.len() > MAX_CLIENT_ACCESS_RULES {
        return Err(format!(
            "设备访问范围最多支持 {MAX_CLIENT_ACCESS_RULES} 条 IP 或 CIDR"
        ));
    }

    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(source_rules.len());
    for rule in source_rules {
        let (canonical, _) = parse_access_rule(rule)?;
        if seen.insert(canonical.clone()) {
            normalized.push(canonical);
        }
    }
    if settings.access_mode == ClientAccessMode::Allow && normalized.is_empty() {
        return Err("仅受信设备模式至少需要一个私网 IP 或 CIDR".to_string());
    }
    settings.access_rules = normalized;
    Ok(settings)
}

fn parse_access_rule(value: &str) -> Result<(String, IpNet), String> {
    let value = value.trim();
    if let Ok(address) = value.parse::<IpAddr>() {
        if address.is_loopback() {
            return Err("本机回环地址始终允许，无需加入设备范围".to_string());
        }
        if !is_private_or_link_local(address) {
            return Err(format!("“{value}”不是私网或链路本地 IP"));
        }
        return Ok((address.to_string(), IpNet::from(address)));
    }

    let network = value
        .parse::<IpNet>()
        .map_err(|_| format!("“{value}”不是有效的 IP 或 CIDR"))?
        .trunc();
    if !is_private_network(network) {
        return Err(format!("“{value}”必须完整位于私网或链路本地范围"));
    }
    Ok((network.to_string(), network))
}

fn is_private_network(network: IpNet) -> bool {
    is_private_or_link_local(network.network()) && is_private_or_link_local(network.broadcast())
}

fn is_private_or_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(mode: ClientAccessMode, rules: &[&str]) -> CaptureListenerSettings {
        CaptureListenerSettings {
            lan_enabled: true,
            access_mode: mode,
            access_rules: rules.iter().map(|rule| (*rule).to_string()).collect(),
        }
    }

    #[test]
    fn matches_exact_ipv4_and_ipv6_rules() {
        let policy = ClientAccessPolicy::from_settings(
            &settings(ClientAccessMode::Allow, &["192.168.1.23", "fd12:3456::9"]),
            true,
        )
        .unwrap();
        assert!(policy.allows("192.168.1.23".parse().unwrap()));
        assert!(!policy.allows("192.168.1.24".parse().unwrap()));
        assert!(policy.allows("fd12:3456::9".parse().unwrap()));
        assert!(!policy.allows("fd12:3456::a".parse().unwrap()));
    }

    #[test]
    fn matches_ipv4_and_ipv6_cidr_boundaries() {
        let policy = ClientAccessPolicy::from_settings(
            &settings(
                ClientAccessMode::Allow,
                &["10.20.30.0/24", "fd12:3456:789a::/64"],
            ),
            true,
        )
        .unwrap();
        assert!(policy.allows("10.20.30.0".parse().unwrap()));
        assert!(policy.allows("10.20.30.255".parse().unwrap()));
        assert!(!policy.allows("10.20.31.0".parse().unwrap()));
        assert!(policy.allows("fd12:3456:789a::ffff".parse().unwrap()));
        assert!(!policy.allows("fd12:3456:789b::1".parse().unwrap()));
    }

    #[test]
    fn always_allows_loopback_and_never_allows_public_addresses() {
        let disabled = ClientAccessPolicy::private_network(false);
        assert!(disabled.allows("127.0.0.1".parse().unwrap()));
        assert!(disabled.allows("::1".parse().unwrap()));
        assert!(!disabled.allows("192.168.1.10".parse().unwrap()));

        let enabled = ClientAccessPolicy::private_network(true);
        assert!(enabled.allows("192.168.1.10".parse().unwrap()));
        assert!(enabled.allows("fe80::1".parse().unwrap()));
        assert!(!enabled.allows("8.8.8.8".parse().unwrap()));
        assert!(!enabled.allows("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn applies_allow_and_deny_modes_after_private_network_check() {
        let allowed = ClientAccessPolicy::from_settings(
            &settings(ClientAccessMode::Allow, &["192.168.50.0/24"]),
            true,
        )
        .unwrap();
        assert!(allowed.allows("192.168.50.42".parse().unwrap()));
        assert!(!allowed.allows("192.168.51.42".parse().unwrap()));

        let denied = ClientAccessPolicy::from_settings(
            &settings(ClientAccessMode::Deny, &["192.168.50.42"]),
            true,
        )
        .unwrap();
        assert!(!denied.allows("192.168.50.42".parse().unwrap()));
        assert!(denied.allows("192.168.50.43".parse().unwrap()));
    }

    #[test]
    fn normalizes_networks_and_deduplicates_rules() {
        let normalized = normalize_capture_listener_settings(settings(
            ClientAccessMode::Deny,
            &[
                " 192.168.1.42/24 ",
                "192.168.1.0/24",
                "FD12:3456::1",
                "fd12:3456::1",
                "",
            ],
        ))
        .unwrap();
        assert_eq!(
            normalized.access_rules,
            vec!["192.168.1.0/24", "fd12:3456::1"]
        );
    }

    #[test]
    fn rejects_invalid_public_and_unbounded_rules() {
        assert!(
            normalize_capture_listener_settings(settings(ClientAccessMode::Allow, &[])).is_err()
        );
        assert!(normalize_capture_listener_settings(settings(
            ClientAccessMode::Allow,
            &["10.0.0.1/33"]
        ))
        .is_err());
        assert!(normalize_capture_listener_settings(settings(
            ClientAccessMode::Allow,
            &["8.8.8.8"]
        ))
        .is_err());
        assert!(normalize_capture_listener_settings(settings(
            ClientAccessMode::Allow,
            &["10.0.0.0/7"]
        ))
        .is_err());
        let too_many = vec!["192.168.1.1"; MAX_CLIENT_ACCESS_RULES + 1];
        assert!(
            normalize_capture_listener_settings(settings(ClientAccessMode::Deny, &too_many))
                .is_err()
        );
    }

    #[test]
    fn keeps_old_listener_json_compatible() {
        let restored: CaptureListenerSettings =
            serde_json::from_str(r#"{"lanEnabled":true}"#).unwrap();
        assert!(restored.lan_enabled);
        assert_eq!(restored.access_mode, ClientAccessMode::Private);
        assert!(restored.access_rules.is_empty());
    }
}
