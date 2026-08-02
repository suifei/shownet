use crate::models::{CaptureRule, CaptureRuleRun};
use serde_json::{json, Value};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MirrorIdentity {
    Original,
    Target,
}

impl MirrorIdentity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Target => "target",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeMirrorRoute {
    pub rule_id: String,
    pub rule_name: String,
    pub revision: i64,
    pub original_host: String,
    pub original_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub identity: MirrorIdentity,
}

impl RuntimeMirrorRoute {
    pub fn connection_target(&self) -> (&str, u16) {
        (&self.target_host, self.target_port)
    }

    pub fn identity_target(&self) -> (&str, u16) {
        match self.identity {
            MirrorIdentity::Original => (&self.original_host, self.original_port),
            MirrorIdentity::Target => (&self.target_host, self.target_port),
        }
    }

    pub fn trace(&self, request_id: &str, transport: &str) -> CaptureRuleRun {
        let original = format_authority(&self.original_host, self.original_port);
        let target = format_authority(&self.target_host, self.target_port);
        let (identity_host, identity_port) = self.identity_target();
        let identity = format_authority(identity_host, identity_port);
        let mut changes = vec![format!("连接目标 {original} -> {target}")];
        changes.push(match self.identity {
            MirrorIdentity::Original => "兼容模式：保留原 Host、SNI 与证书校验身份".to_string(),
            MirrorIdentity::Target => {
                "测试环境模式：上游 Host、SNI 与证书校验使用镜像地址".to_string()
            }
        });
        if transport == "tls-bypass" && self.identity == MirrorIdentity::Target {
            changes.push("TLS 绕行无法改写 ClientHello，当前连接保留原 SNI".to_string());
        }
        CaptureRuleRun {
            id: format!("rule-run-{}", Uuid::new_v4()),
            request_id: request_id.to_string(),
            rule_id: self.rule_id.clone(),
            rule_name: self.rule_name.clone(),
            revision: self.revision,
            stage: "connection".to_string(),
            result: if transport == "https-mitm-request" {
                "inherited"
            } else {
                "applied"
            }
            .to_string(),
            diff_summary: json!({
                "changes": changes,
                "route": {
                    "originalAuthority": original,
                    "targetAuthority": target,
                    "identityAuthority": identity,
                    "identity": self.identity.as_str(),
                    "transport": transport,
                    "clientCertificateHost": self.original_host,
                },
            }),
            duration_ms: 0,
            error: None,
            created_at: chrono::Utc::now().timestamp_millis(),
        }
    }
}

pub fn route_from_rule(
    rule: &CaptureRule,
    original_host: &str,
    original_port: u16,
) -> Result<RuntimeMirrorRoute, String> {
    let target_host = mirror_target_host(&rule.action)?;
    let target_port = mirror_target_port(&rule.action)?.unwrap_or(original_port);
    let identity = mirror_identity(&rule.action)?;
    Ok(RuntimeMirrorRoute {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        revision: rule.revision,
        original_host: normalize_mirror_host(original_host)?,
        original_port,
        target_host,
        target_port,
        identity,
    })
}

pub fn validate_mirror_action(action: &Value) -> Result<(), String> {
    mirror_target_host(action)?;
    mirror_target_port(action)?;
    mirror_identity(action)?;
    Ok(())
}

fn mirror_target_host(action: &Value) -> Result<String, String> {
    let host = action
        .get("targetHost")
        .and_then(Value::as_str)
        .ok_or_else(|| "镜像规则缺少目标主机".to_string())?;
    normalize_mirror_host(host)
}

fn mirror_target_port(action: &Value) -> Result<Option<u16>, String> {
    let Some(value) = action.get("targetPort") else {
        return Ok(None);
    };
    let port = value
        .as_u64()
        .filter(|value| (1..=u16::MAX as u64).contains(value))
        .ok_or_else(|| "镜像目标端口必须在 1 到 65535 之间".to_string())?;
    Ok(Some(port as u16))
}

fn mirror_identity(action: &Value) -> Result<MirrorIdentity, String> {
    match action
        .get("identity")
        .and_then(Value::as_str)
        .unwrap_or("original")
    {
        "original" => Ok(MirrorIdentity::Original),
        "target" => Ok(MirrorIdentity::Target),
        _ => Err("镜像上游身份必须是 original 或 target".to_string()),
    }
}

pub fn normalize_mirror_host(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 253 {
        return Err("镜像目标主机必须在 1 到 253 字节之间".to_string());
    }
    if value.contains(['/', '\\', '@', '#', '?', '*', '%']) || value.contains("://") {
        return Err("镜像目标只填写主机或 IP，不能包含协议、路径、凭据或通配符".to_string());
    }
    let unwrapped = if value.starts_with('[') && value.ends_with(']') {
        &value[1..value.len() - 1]
    } else if value.contains('[') || value.contains(']') {
        return Err("镜像目标 IPv6 格式无效".to_string());
    } else {
        value
    };
    let normalized = match unwrapped.parse::<IpAddr>() {
        Ok(address) => address.to_string(),
        Err(_) => match url::Host::parse(unwrapped)
            .map_err(|_| "镜像目标主机格式无效".to_string())?
        {
            url::Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
            url::Host::Ipv4(address) => address.to_string(),
            url::Host::Ipv6(address) => address.to_string(),
        },
    };
    if normalized.is_empty() {
        return Err("镜像目标主机格式无效".to_string());
    }
    Ok(normalized)
}

pub fn format_authority(host: &str, port: u16) -> String {
    let host = host.trim_matches(['[', ']']);
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::FilterExpression;

    fn rule(action: Value) -> CaptureRule {
        CaptureRule {
            id: "rule-mirror".to_string(),
            name: "测试环境".to_string(),
            enabled: true,
            priority: 10,
            stage: "connection".to_string(),
            matcher: FilterExpression::Predicate {
                field: "host".to_string(),
                operator: "equals".to_string(),
                value: Some(json!("api.example.test")),
            },
            action,
            created_by: "user".to_string(),
            revision: 2,
            hit_count: 0,
            last_error: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn builds_compatible_and_target_identity_routes() {
        let compatible = route_from_rule(
            &rule(json!({"kind":"mirror","targetHost":"STAGE.example.test"})),
            "api.example.test",
            443,
        )
        .unwrap();
        assert_eq!(compatible.connection_target(), ("stage.example.test", 443));
        assert_eq!(compatible.identity_target(), ("api.example.test", 443));

        let target = route_from_rule(
            &rule(
                json!({"kind":"mirror","targetHost":"[::1]","targetPort":8443,"identity":"target"}),
            ),
            "api.example.test",
            443,
        )
        .unwrap();
        assert_eq!(target.connection_target(), ("::1", 8443));
        assert_eq!(target.identity_target(), ("::1", 8443));
        let trace = target.trace("request-1", "tls-bypass");
        let encoded = serde_json::to_string(&trace).unwrap();
        assert!(encoded.contains("保留原 SNI"));
        assert!(!encoded.contains("authorization"));
    }

    #[test]
    fn rejects_urls_wildcards_credentials_and_invalid_ports() {
        for host in [
            "https://stage.example.test",
            "*.example.test",
            "user@stage.example.test",
            "stage.example.test/path",
            "[::1]:8443",
        ] {
            assert!(
                validate_mirror_action(
                    &json!({"kind":"mirror","targetHost":host,"identity":"original"})
                )
                .is_err(),
                "accepted {host}"
            );
        }
        assert!(validate_mirror_action(
            &json!({"kind":"mirror","targetHost":"stage.example.test","targetPort":0})
        )
        .is_err());
    }
}
