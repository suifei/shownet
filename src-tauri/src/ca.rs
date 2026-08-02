use crate::crypto;
use crate::models::StoredCertificateAuthority;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;

const CA_KEY_AAD: &[u8] = b"shownet/root-ca/v1";

pub struct CertificateAuthority {
    certificate: Certificate,
    private_key: KeyPair,
    certificate_der: CertificateDer<'static>,
    certificate_pem: String,
    fingerprint: String,
    created_at: i64,
    leaf_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertificateAuthority {
    pub fn load_or_create(
        material: Option<StoredCertificateAuthority>,
    ) -> Result<(Self, Option<StoredCertificateAuthority>), String> {
        match material {
            Some(material) => Ok((Self::from_material(&material)?, None)),
            None => {
                let (authority, material) = Self::generate()?;
                Ok((authority, Some(material)))
            }
        }
    }

    fn generate() -> Result<(Self, StoredCertificateAuthority), String> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| format!("创建 Root CA 参数失败: {error}"))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "ShowNet Root CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "ShowNet Local Traffic Analysis");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.not_before = date_time_ymd(2025, 1, 1);
        params.not_after = date_time_ymd(2045, 1, 1);

        let private_key =
            KeyPair::generate().map_err(|error| format!("生成 Root CA 私钥失败: {error}"))?;
        let certificate = params
            .self_signed(&private_key)
            .map_err(|error| format!("签发 Root CA 失败: {error}"))?;
        let certificate_der = certificate.der().to_vec();
        let encrypted_private_key = crypto::encrypt(private_key.serialized_der(), CA_KEY_AAD)?;
        let created_at = chrono::Utc::now().timestamp_millis();
        let material = StoredCertificateAuthority {
            certificate_der: STANDARD.encode(&certificate_der),
            encrypted_private_key,
            created_at,
        };
        let authority = Self::from_parts(certificate, private_key, certificate_der, created_at);
        Ok((authority, material))
    }

    fn from_material(material: &StoredCertificateAuthority) -> Result<Self, String> {
        let certificate_der = STANDARD
            .decode(&material.certificate_der)
            .map_err(|_| "Root CA 证书数据格式无效".to_string())?;
        let private_key_der = crypto::decrypt(&material.encrypted_private_key, CA_KEY_AAD)?;
        let private_key = KeyPair::try_from(private_key_der)
            .map_err(|error| format!("读取 Root CA 私钥失败: {error}"))?;
        let parsed_der = CertificateDer::from(certificate_der.clone());
        let params = CertificateParams::from_ca_cert_der(&parsed_der)
            .map_err(|error| format!("读取 Root CA 证书失败: {error}"))?;
        let certificate = params
            .self_signed(&private_key)
            .map_err(|error| format!("恢复 Root CA 签发器失败: {error}"))?;
        Ok(Self::from_parts(
            certificate,
            private_key,
            certificate_der,
            material.created_at,
        ))
    }

    fn from_parts(
        certificate: Certificate,
        private_key: KeyPair,
        certificate_der: Vec<u8>,
        created_at: i64,
    ) -> Self {
        let fingerprint = sha256_fingerprint(&certificate_der);
        let certificate_pem = der_to_pem(&certificate_der);
        Self {
            certificate,
            private_key,
            certificate_der: CertificateDer::from(certificate_der),
            certificate_pem,
            fingerprint,
            created_at,
            leaf_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if host.is_empty() {
            return Err("无法为缺失的主机名签发证书".to_string());
        }
        if let Some(config) = self
            .leaf_cache
            .lock()
            .map_err(|_| "叶证书缓存已损坏".to_string())?
            .get(&host)
            .cloned()
        {
            return Ok(config);
        }

        let leaf_key =
            KeyPair::generate().map_err(|error| format!("生成 {host} 叶证书私钥失败: {error}"))?;
        let mut params = CertificateParams::new(vec![host.clone()])
            .map_err(|error| format!("创建 {host} 叶证书参数失败: {error}"))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, host.clone());
        let now = SystemTime::now();
        params.not_before = now
            .checked_sub(Duration::from_secs(24 * 60 * 60))
            .unwrap_or(now)
            .into();
        params.not_after = now
            .checked_add(Duration::from_secs(364 * 24 * 60 * 60))
            .unwrap_or(now)
            .into();
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(&leaf_key, &self.certificate, &self.private_key)
            .map_err(|error| format!("签发 {host} 叶证书失败: {error}"))?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone(), self.certificate_der.clone()], key)
            .map_err(|error| format!("创建 {host} TLS 服务配置失败: {error}"))?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        self.leaf_cache
            .lock()
            .map_err(|_| "叶证书缓存已损坏".to_string())?
            .insert(host, config.clone());
        Ok(config)
    }

    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.certificate_der.clone()
    }

    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }
}

fn sha256_fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn der_to_pem(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[test]
    fn persists_the_private_key_encrypted_and_restores_the_same_ca() {
        let (authority, material) = CertificateAuthority::load_or_create(None).unwrap();
        assert!(!material
            .as_ref()
            .unwrap()
            .encrypted_private_key
            .contains("PRIVATE KEY"));
        let fingerprint = authority.fingerprint().to_string();
        let (restored, created) = CertificateAuthority::load_or_create(material).unwrap();
        assert!(created.is_none());
        assert_eq!(restored.fingerprint(), fingerprint);
        assert_eq!(restored.certificate_der(), authority.certificate_der());
    }

    #[tokio::test]
    async fn issues_a_leaf_certificate_trusted_by_the_root() {
        let (authority, _) = CertificateAuthority::load_or_create(None).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(authority.certificate_der()).unwrap();
        let client = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server = authority.server_config("api.example.test").unwrap();
        let (client_io, server_io) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = TlsAcceptor::from(server).accept(server_io).await.unwrap();
            stream.write_all(b"ok").await.unwrap();
        });
        let server_name = ServerName::try_from("api.example.test").unwrap();
        let mut stream = TlsConnector::from(client)
            .connect(server_name, client_io)
            .await
            .unwrap();
        let mut output = [0_u8; 2];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"ok");
        server_task.await.unwrap();
    }
}
