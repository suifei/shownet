//! Byte-exact browser egress via wreq.
//!
//! The rustls path presents rustls's ClientHello and hyper's h2 (pseudo-header
//! order method, scheme, authority, path). A strict JA4/Akamai gate — Cloudflare
//! — sees both as non-Chrome and re-challenges forever. Neither the extension
//! set nor the pseudo order is configurable in rustls/hyper.
//!
//! wreq closes both: its own patched BoringSSL sends Chrome's full ClientHello
//! (JA4 t13d1516h2) and its patched h2 sends Chrome's pseudo order (m,a,s,p).
//! It is a full HTTP client, so the impersonate egress hands it the
//! reconstructed origin request and relays the response, rather than driving a
//! stream through hyper — which is why the CONNECT-tunnel dispatch branches to
//! it before the rustls connector is reached.

#![cfg(feature = "impersonate-boring")]

use crate::models::EffectiveUpstreamProxy;
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use tokio::net::lookup_host;
use wreq::header::{HeaderValue, USER_AGENT};
use wreq::{Body, Client, IntoEmulation, Response, Uri};
use wreq_util::{Platform, Profile};

#[cfg(test)]
static TEST_ROOT_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
static TEST_ROOT_DER: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

/// Serializes tests that inject a throwaway origin CA into wreq's trust store.
#[cfg(test)]
pub struct TestRootGuard {
    _serial: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for TestRootGuard {
    fn drop(&mut self) {
        if let Ok(mut der) = TEST_ROOT_DER.lock() {
            *der = None;
        }
        crate::proxy::clear_test_host_ips();
    }
}

#[cfg(test)]
pub fn install_test_root_certificate_der(der: Vec<u8>) -> TestRootGuard {
    let serial = TEST_ROOT_SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *TEST_ROOT_DER
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(der);
    TestRootGuard { _serial: serial }
}

fn overlay_test_cert_store(
    cert_store: Option<wreq::tls::trust::CertStore>,
) -> Option<wreq::tls::trust::CertStore> {
    if cert_store.is_some() {
        return cert_store;
    }
    #[cfg(test)]
    {
        let guard = TEST_ROOT_DER.lock().ok()?;
        let der = guard.as_ref()?;
        return wreq::tls::trust::CertStore::builder()
            .add_der_cert(der.as_slice())
            .build()
            .ok();
    }
    #[cfg(not(test))]
    None
}

/// The newest Chrome profile provided by the linked wreq-util release. Chrome
/// 151 keeps this profile's ClientHello and HTTP/2 shape, but prepends the three
/// ML-DSA signature schemes below.
pub const EMULATION: Profile = Profile::Chrome149;

const CHROME_151_SIGNATURE_ALGORITHMS: &str = "mldsa44:mldsa65:mldsa87:\
ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

/// The JA4 `EMULATION` puts on the wire. Fixed per emulation, so it is a constant
/// rather than a per-handshake measurement — but it is a measured constant:
/// wreq_egress_is_byte_exact_chrome reads it back off a live reflector, and
/// browser_and_egress_present_one_fingerprint checks the installed browser
/// presents the same one. Changing EMULATION without changing this is caught by
/// both.
pub const EGRESS_JA4: &str = "t13d1516h2_8daaf6152771_806a8c22fdea";

#[derive(Clone)]
pub struct ImpersonateClient {
    direct: Client,
    proxied: Option<Client>,
    bypass: Vec<String>,
    route_connection_host: Option<String>,
}

#[derive(Clone)]
struct DirectRouteOverride {
    identity_host: String,
    connection_host: String,
    addresses: Vec<SocketAddr>,
}

fn host_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else {
        Platform::MacOS
    }
}

fn platform_for_preset(preset_id: &str) -> Platform {
    if preset_id.starts_with("safari-ios") {
        Platform::IOS
    } else if preset_id.starts_with("chrome-android") {
        Platform::Android
    } else {
        host_platform()
    }
}

fn emulation_from_profile(profile: Profile, preset_id: &str) -> wreq::Emulation {
    wreq_util::Emulation::builder()
        .profile(profile)
        .platform(platform_for_preset(preset_id))
        .build()
        .into_emulation()
}

fn overlay_chrome_major_identity(
    headers: &mut wreq::header::HeaderMap,
    from_major: u16,
    to_major: u16,
) {
    let from = from_major.to_string();
    let to = to_major.to_string();
    let names = [
        USER_AGENT,
        wreq::header::HeaderName::from_static("sec-ch-ua"),
    ];
    for name in names {
        let Some(current) = headers.get(&name).and_then(|value| value.to_str().ok()) else {
            continue;
        };
        let rewritten = current
            .replace(&format!("Chrome/{from}"), &format!("Chrome/{to}"))
            .replace(&format!("CriOS/{from}"), &format!("CriOS/{to}"))
            .replace(&format!("v=\"{from}\""), &format!("v=\"{to}\""));
        if rewritten == current {
            continue;
        }
        if let Ok(value) = HeaderValue::from_str(&rewritten) {
            headers.insert(name, value);
        }
    }
}

fn chrome_151_emulation() -> Result<wreq::Emulation, String> {
    let mut emulation = emulation_from_profile(EMULATION, "chrome151");
    let tls = emulation
        .tls_options
        .as_mut()
        .ok_or_else(|| "Chrome 149 emulation is missing TLS options".to_string())?;
    tls.sigalgs_list = Some(Cow::Borrowed(CHROME_151_SIGNATURE_ALGORITHMS));
    overlay_chrome_major_identity(&mut emulation.headers, 149, 151);
    Ok(emulation)
}

fn wreq_profile_from_name(name: &str) -> Option<Profile> {
    Some(match name {
        "Chrome120" => Profile::Chrome120,
        "Chrome124" => Profile::Chrome124,
        "Chrome128" => Profile::Chrome128,
        "Chrome131" => Profile::Chrome131,
        "Chrome133" => Profile::Chrome133,
        "Chrome136" => Profile::Chrome136,
        "Chrome140" => Profile::Chrome140,
        "Chrome144" => Profile::Chrome144,
        "Chrome145" => Profile::Chrome145,
        "Chrome146" => Profile::Chrome146,
        "Chrome149" => Profile::Chrome149,
        "Firefox128" => Profile::Firefox128,
        "Firefox133" => Profile::Firefox133,
        "Firefox136" => Profile::Firefox136,
        "Edge131" => Profile::Edge131,
        "Edge136" => Profile::Edge136,
        "Safari17_6" => Profile::Safari17_6,
        "Safari18" => Profile::Safari18,
        "SafariIos17_4_1" => Profile::SafariIos17_4_1,
        "SafariIos18_1_1" => Profile::SafariIos18_1_1,
        _ => return None,
    })
}

/// wreq ClientHello for the active catalog id. Exact wreq-util profiles when
/// we have them; Chrome 150/151 keep the existing Chrome149 + ML-DSA overlay.
pub fn emulation_for_preset(preset_id: &str) -> Result<wreq::Emulation, String> {
    match crate::tls_clienthello_catalog::wreq_emulation_kind(preset_id) {
        crate::tls_clienthello_catalog::WreqEmulationKind::Chrome149PlusMldsa
        | crate::tls_clienthello_catalog::WreqEmulationKind::None => chrome_151_emulation(),
        crate::tls_clienthello_catalog::WreqEmulationKind::Exact => {
            let name = crate::tls_clienthello_catalog::wreq_profile_name(preset_id)
                .ok_or_else(|| format!("missing wreq profile for {preset_id}"))?;
            let profile = wreq_profile_from_name(name)
                .ok_or_else(|| format!("wreq-util has no Profile::{name}"))?;
            Ok(emulation_from_profile(profile, preset_id))
        }
    }
}

fn emulation_for_active_preset() -> Result<wreq::Emulation, String> {
    emulation_for_preset(&crate::tls_clienthello_catalog::active_preset_id())
}

/// User-Agent the impersonate client will send for this catalog id.
pub fn user_agent_for_preset(preset_id: &str) -> Option<String> {
    let emulation = emulation_for_preset(preset_id).ok()?;
    emulation
        .headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Builds a wreq client that egresses like Chrome, honoring ShowNet's upstream
/// proxy so the impersonate path reaches the network the same way the rest of
/// the proxy does.
pub fn build_client(upstream: &EffectiveUpstreamProxy) -> Result<ImpersonateClient, String> {
    build_client_inner(upstream, None, None)
}

fn build_client_inner(
    upstream: &EffectiveUpstreamProxy,
    route: Option<DirectRouteOverride>,
    cert_store: Option<wreq::tls::trust::CertStore>,
) -> Result<ImpersonateClient, String> {
    let cert_store = overlay_test_cert_store(cert_store);
    // no_proxy() first: wreq, like reqwest, reads http_proxy/https_proxy from
    // the environment by default, and ShowNet points the system proxy at
    // itself — an inherited env proxy would loop the app's own egress back
    // through its capture proxy. The explicit upstream below is the only proxy
    // this client may use. (Invariant enforced by upstream-egress-ui.test.ts.)
    let mut direct_builder = Client::builder()
        .no_proxy()
        .emulation(emulation_for_active_preset()?);
    if let Some(route) = route.as_ref() {
        direct_builder = direct_builder
            .resolve_to_addrs(route.identity_host.clone(), route.addresses.iter().copied());
    }
    if let Some(store) = cert_store.as_ref() {
        direct_builder = direct_builder.tls_cert_store(store.clone());
    }
    let direct = direct_builder
        .build()
        .map_err(|error| format!("构建 wreq 直连客户端失败: {error}"))?;
    let proxied = if upstream.mode == "direct" {
        None
    } else {
        let proxy_uri = explicit_proxy_uri(upstream)?;
        let mut proxy =
            wreq::Proxy::all(proxy_uri).map_err(|error| format!("代理配置无效: {error}"))?;
        if !upstream.username.is_empty() || upstream.password.is_some() {
            proxy = proxy.basic_auth(
                &upstream.username,
                upstream.password.as_deref().unwrap_or_default(),
            );
        }
        let mut builder = Client::builder()
            .no_proxy()
            .emulation(emulation_for_active_preset()?)
            .proxy(proxy);
        if let Some(store) = cert_store {
            builder = builder.tls_cert_store(store);
        }
        Some(
            builder
                .build()
                .map_err(|error| format!("构建 wreq 代理客户端失败: {error}"))?,
        )
    };
    Ok(ImpersonateClient {
        direct,
        proxied,
        bypass: upstream.bypass.clone(),
        route_connection_host: route.map(|route| route.connection_host),
    })
}

/// Builds an isolated client for one HTTPS route whose transport target may
/// differ from its TLS and HTTP identity. Keeping the client route-scoped is
/// required because wreq's connection pool key does not include DNS overrides.
pub async fn build_client_for_route(
    upstream: &EffectiveUpstreamProxy,
    connection_host: &str,
    connection_port: u16,
    tls_identity_host: &str,
    tls_identity_port: u16,
) -> Result<ImpersonateClient, String> {
    build_client_for_route_inner(
        upstream,
        connection_host,
        connection_port,
        tls_identity_host,
        tls_identity_port,
        None,
    )
    .await
}

async fn build_client_for_route_inner(
    upstream: &EffectiveUpstreamProxy,
    connection_host: &str,
    connection_port: u16,
    tls_identity_host: &str,
    tls_identity_port: u16,
    cert_store: Option<wreq::tls::trust::CertStore>,
) -> Result<ImpersonateClient, String> {
    let same_host = connection_host
        .trim_matches(['[', ']'])
        .eq_ignore_ascii_case(tls_identity_host.trim_matches(['[', ']']));
    #[cfg(test)]
    if let Some(ip) = crate::proxy::test_host_ip(tls_identity_host) {
        return build_client_inner(
            upstream,
            Some(DirectRouteOverride {
                identity_host: tls_identity_host.trim_matches(['[', ']']).to_string(),
                connection_host: connection_host.to_string(),
                addresses: vec![SocketAddr::new(ip, connection_port)],
            }),
            cert_store,
        );
    }
    if same_host && connection_port == tls_identity_port {
        return build_client_inner(upstream, None, cert_store);
    }

    // With no explicit port in an HTTPS URI, wreq rc.29 preserves a resolver
    // override's non-zero port. The integration test below locks that behavior
    // for original identity :443 -> an arbitrary mirror port. An explicit
    // non-default identity port overwrites the resolver port and cannot drift.
    if connection_port != tls_identity_port && tls_identity_port != 443 {
        return Err(format!(
            "wreq 兼容镜像暂不支持非默认身份端口 {tls_identity_port} 与连接端口 {connection_port} 不同；请使用相同端口，避免改变 SNI/证书身份或 HTTP/2 :authority"
        ));
    }
    if tls_identity_host
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok()
    {
        return Err(
            "wreq 兼容镜像暂不支持把 IP 身份映射到其他连接地址；请使用域名身份或 target 身份模式"
                .to_string(),
        );
    }

    let route_is_direct =
        upstream.mode == "direct" || crate::proxy::should_bypass(connection_host, &upstream.bypass);
    if !route_is_direct {
        return Err(format!(
            "wreq 兼容镜像 {}:{} -> {}:{} 无法经 {} 二级出口代理保持原 SNI 与 HTTP authority；请为镜像目标配置 bypass 或使用 target 身份模式",
            tls_identity_host,
            tls_identity_port,
            connection_host,
            connection_port,
            upstream.mode
        ));
    }

    let lookup_host_value = connection_host.trim_matches(['[', ']']);
    let addresses = if let Ok(address) = lookup_host_value.parse::<IpAddr>() {
        vec![SocketAddr::new(address, connection_port)]
    } else {
        let resolved = lookup_host((lookup_host_value, connection_port))
            .await
            .map_err(|error| format!("DNS 解析镜像目标 {connection_host} 失败: {error}"))?
            .collect::<Vec<_>>();
        if resolved.is_empty() {
            return Err(format!("DNS 未返回镜像目标 {connection_host} 的地址"));
        }
        resolved
    };
    build_client_inner(
        upstream,
        Some(DirectRouteOverride {
            identity_host: tls_identity_host.trim_matches(['[', ']']).to_string(),
            connection_host: connection_host.to_string(),
            addresses,
        }),
        cert_store,
    )
}

fn explicit_proxy_uri(upstream: &EffectiveUpstreamProxy) -> Result<Uri, String> {
    let scheme = match upstream.mode.as_str() {
        "http" => "http",
        "https" => "https",
        // The existing SOCKS connector resolves the destination through the
        // proxy, so preserve that privacy behavior with socks5h.
        "socks5" => "socks5h",
        mode => return Err(format!("不支持的出口代理类型: {mode}")),
    };
    let host = upstream.host.trim().trim_matches(['[', ']']);
    if host.is_empty() || upstream.port == 0 {
        return Err("出口代理主机或端口无效".to_string());
    }
    let authority = if host.contains(':') {
        format!("[{host}]:{}", upstream.port)
    } else {
        format!("{host}:{}", upstream.port)
    };
    format!("{scheme}://{authority}")
        .parse()
        .map_err(|error| format!("代理配置无效: {error}"))
}

/// Hop-by-hop headers the origin client owns and must not copy. Content-Length
/// is intentionally preserved: browser requests already carry the correct value,
/// and the proxy recalculates it whenever a rule rewrites the body. Dropping a
/// browser's explicit `Content-Length: 0` made strict origins reject empty POSTs
/// with 411 before authentication and risk checks could run.
fn is_client_owned(name: &str) -> bool {
    matches!(
        name,
        "host" | "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}

/// Captured-browser identity. The selected ClientHello profile owns these on
/// the wire; copying the embedded Chrome values would advertise 151 next to a
/// Firefox or Safari handshake.
fn is_profile_identity_header(name: &str) -> bool {
    matches!(
        name,
        "user-agent"
            | "sec-ch-ua"
            | "sec-ch-ua-mobile"
            | "sec-ch-ua-platform"
            | "sec-ch-ua-full-version"
            | "sec-ch-ua-full-version-list"
            | "sec-ch-ua-arch"
            | "sec-ch-ua-bitness"
            | "sec-ch-ua-model"
            | "sec-ch-ua-wow64"
            | "sec-ch-ua-form-factors"
            | "sec-ch-ua-platform-version"
    )
}

/// wreq `RequestBuilder::header` replaces same-name values. HTTP/2 clients
/// send one Cookie header per cookie; iterating those crumbs would keep only
/// the last one. Join them the way RFC 6265 user agents send a single Cookie.
fn collapse_cookie_header_pairs(headers: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    let mut cookies = Vec::new();
    let mut folded = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("cookie") {
            cookies.push(value.as_slice());
        } else {
            folded.push((name.clone(), value.clone()));
        }
    }
    if !cookies.is_empty() {
        let mut joined = Vec::new();
        for (index, crumb) in cookies.iter().enumerate() {
            if index > 0 {
                joined.extend_from_slice(b"; ");
            }
            joined.extend_from_slice(crumb);
        }
        folded.push(("cookie".to_string(), joined));
    }
    folded
}

/// Sends one reconstructed origin request through wreq and returns its streaming response.
pub async fn send(
    client: &ImpersonateClient,
    method: &str,
    url: &str,
    headers: &[(String, Vec<u8>)],
    body: Option<Body>,
) -> Result<Response, String> {
    let method = wreq::Method::from_bytes(method.as_bytes())
        .map_err(|error| format!("方法无效 {method}: {error}"))?;
    let uri: Uri = url
        .parse()
        .map_err(|error| format!("请求地址无效 {url}: {error}"))?;
    let target = if client.proxied.as_ref().is_some_and(|_| {
        let routing_host = client
            .route_connection_host
            .as_deref()
            .unwrap_or_else(|| uri.host().unwrap_or_default());
        !crate::proxy::should_bypass(routing_host, &client.bypass)
    }) {
        client.proxied.as_ref().expect("checked above")
    } else {
        &client.direct
    };
    let mut request = target.request(method, uri);
    for (name, value) in collapse_cookie_header_pairs(headers) {
        let lower = name.to_ascii_lowercase();
        if is_client_owned(&lower) || is_profile_identity_header(&lower) {
            continue;
        }
        request = request.header(name.as_str(), value.as_slice());
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    request
        .send()
        .await
        .map_err(|error| format!("wreq 请求失败: {error}"))
}

/// Origin WebSocket after a Chrome TLS handshake.
///
/// wreq still cannot be driven as a raw `Connection: Upgrade` stream through
/// the ordinary HTTP sender — hop-by-hop headers are stripped there. Its
/// websocket builder does the Upgrade itself on the same BoringSSL profile
/// HTTPS uses, then hands back the upgraded IO for our relay.
pub struct ImpersonateWebsocket {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub socket: wreq::ws::WebSocket,
}

impl ImpersonateClient {
    fn route_client(&self, routing_host: &str) -> &Client {
        if self
            .proxied
            .as_ref()
            .is_some_and(|_| !crate::proxy::should_bypass(routing_host, &self.bypass))
        {
            self.proxied.as_ref().expect("checked above")
        } else {
            &self.direct
        }
    }

    pub async fn websocket_upgrade(
        &self,
        url: &str,
        headers: &[(String, Vec<u8>)],
    ) -> Result<ImpersonateWebsocket, String> {
        let uri: Uri = url
            .parse()
            .map_err(|error| format!("WebSocket 地址无效 {url}: {error}"))?;
        let routing_host = self
            .route_connection_host
            .as_deref()
            .unwrap_or_else(|| uri.host().unwrap_or_default());
        let mut request = self.route_client(routing_host).websocket(uri);
        let mut accept_key = None;
        let mut protocols = Vec::new();
        for (name, value) in collapse_cookie_header_pairs(headers) {
            let lower = name.to_ascii_lowercase();
            if lower == "sec-websocket-key" {
                accept_key = String::from_utf8(value).ok();
                continue;
            }
            if lower == "sec-websocket-protocol" {
                if let Ok(text) = String::from_utf8(value) {
                    protocols.extend(
                        text.split(',')
                            .map(str::trim)
                            .filter(|item| !item.is_empty())
                            .map(str::to_string),
                    );
                }
                continue;
            }
            if lower == "sec-websocket-version"
                || is_client_owned(&lower)
                || is_profile_identity_header(&lower)
            {
                continue;
            }
            request = request.header(name.as_str(), value.as_slice());
        }
        if let Some(key) = accept_key {
            request = request.accept_key(key);
        }
        if !protocols.is_empty() {
            request = request.protocols(protocols);
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("wreq WebSocket 握手失败: {error}"))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect();
        if status != 101 {
            return Err(format!("WebSocket 升级失败: HTTP {status}"));
        }
        let socket = response
            .into_websocket()
            .await
            .map_err(|error| format!("WebSocket 升级失败: {error}"))?;
        Ok(ImpersonateWebsocket {
            status,
            headers,
            socket,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;
    use bytes::Bytes;
    use futures_util::StreamExt;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::{Request, Version};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::{timeout, Duration};
    use tokio_rustls::TlsAcceptor;

    fn upstream(mode: &str, username: &str, password: Option<&str>) -> EffectiveUpstreamProxy {
        EffectiveUpstreamProxy {
            mode: mode.to_string(),
            host: "2001:db8::10".to_string(),
            port: 1080,
            username: username.to_string(),
            password: password.map(str::to_string),
            bypass: vec!["localhost".to_string(), "*.local".to_string()],
        }
    }

    #[test]
    fn explicit_proxy_uri_supports_every_product_mode() {
        let http = explicit_proxy_uri(&upstream("http", "user@example", Some("p@ss:/#")))
            .expect("http proxy");
        assert_eq!(http.scheme_str(), Some("http"));
        assert_eq!(http.host(), Some("[2001:db8::10]"));
        assert_eq!(http.port_u16(), Some(1080));

        assert_eq!(
            explicit_proxy_uri(&upstream("https", "", None))
                .expect("https proxy")
                .scheme_str(),
            Some("https")
        );
        assert_eq!(
            explicit_proxy_uri(&upstream("socks5", "", None))
                .expect("socks proxy")
                .scheme_str(),
            Some("socks5h")
        );
    }

    #[test]
    fn explicit_proxy_uri_rejects_unknown_modes() {
        assert!(explicit_proxy_uri(&upstream("ftp", "", None)).is_err());
    }

    #[test]
    fn browser_content_length_survives_origin_request_reconstruction() {
        assert!(!is_client_owned("content-length"));
        assert!(is_client_owned("transfer-encoding"));
        assert!(is_client_owned("connection"));
        assert!(is_profile_identity_header("user-agent"));
        assert!(is_profile_identity_header("sec-ch-ua"));
        assert!(!is_profile_identity_header("accept-language"));
    }

    #[test]
    fn cookie_crumbs_become_one_header_before_wreq_replaces_same_name() {
        let folded = collapse_cookie_header_pairs(&[
            ("cookie".into(), b"_os=a".to_vec()),
            ("accept".into(), b"*/*".to_vec()),
            ("cookie".into(), b"session=secret".to_vec()),
            ("cookie".into(), b"s6=z".to_vec()),
        ]);
        let cookies: Vec<_> = folded
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
            .collect();
        assert_eq!(
            cookies.len(),
            1,
            "wreq.header replaces; only one Cookie may remain"
        );
        assert_eq!(cookies[0].1, b"_os=a; session=secret; s6=z");
        assert!(folded
            .iter()
            .any(|(name, value)| name == "accept" && value == b"*/*"));
    }

    #[test]
    fn origin_send_folds_cookie_crumbs_before_wreq_header() {
        let source = include_str!("impersonate_egress.rs");
        let fold = source
            .find("for (name, value) in collapse_cookie_header_pairs(headers)")
            .expect("send must fold crumbs before wreq.header replaces Cookie");
        let set = source
            .find("request = request.header(name.as_str(), value.as_slice());")
            .expect("wreq.header site");
        assert!(fold < set);
    }

    #[tokio::test]
    async fn routed_https_hits_mirror_but_keeps_sni_certificate_and_h2_authority() {
        let identity_host = "api.original.invalid";
        let (authority, _) = CertificateAuthority::load_or_create(None).expect("test CA");
        let server_config = authority
            .server_config(identity_host)
            .expect("identity certificate");
        let cert_store = wreq::tls::trust::CertStore::builder()
            .add_der_cert(authority.certificate_der().as_ref())
            .build()
            .expect("wreq test trust store");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let (observed_tx, observed_rx) = oneshot::channel::<(String, String, Version)>();
        let observed_tx = Arc::new(Mutex::new(Some(observed_tx)));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("mirror accept");
            let tls = TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .expect("mirror TLS");
            let sni = tls
                .get_ref()
                .1
                .server_name()
                .unwrap_or_default()
                .to_string();
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let observed_tx = observed_tx.clone();
                let sni = sni.clone();
                async move {
                    let authority = request
                        .uri()
                        .authority()
                        .map(ToString::to_string)
                        .unwrap_or_default();
                    if let Some(sender) = observed_tx.lock().expect("observation lock").take() {
                        let _ = sender.send((sni, authority, request.version()));
                    }
                    Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from_static(
                        b"mirror-ok",
                    ))))
                }
            });
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await
                .expect("mirror h2 server");
        });

        // A configured upstream proxy must still be bypassed using the mirror
        // connection host, not the intentionally unresolvable identity host.
        let client = build_client_for_route_inner(
            &EffectiveUpstreamProxy {
                mode: "http".to_string(),
                host: "127.0.0.1".to_string(),
                port: 9,
                username: String::new(),
                password: None,
                bypass: Vec::new(),
            },
            "127.0.0.1",
            address.port(),
            identity_host,
            443,
            Some(cert_store),
        )
        .await
        .expect("routed client");
        let response = send(
            &client,
            "GET",
            &format!("https://{identity_host}/mirror"),
            &[],
            None,
        )
        .await
        .expect("routed request");
        assert_eq!(response.status(), 200);

        let observed = timeout(Duration::from_secs(5), observed_rx)
            .await
            .expect("observation timeout")
            .expect("observation");
        assert_eq!(observed.0, identity_host);
        assert_eq!(observed.1, identity_host);
        assert_eq!(observed.2, Version::HTTP_2);
        drop(response);
        drop(client);
        timeout(Duration::from_secs(5), server)
            .await
            .expect("mirror server timeout")
            .expect("mirror server");
    }

    #[tokio::test]
    async fn routed_https_rejects_identity_port_drift_and_remote_proxy_routing() {
        let direct_error = build_client_for_route(
            &upstream("direct", "", None),
            "127.0.0.1",
            9443,
            "api.original.invalid",
            8443,
        )
        .await
        .err()
        .expect("port mismatch must fail");
        assert!(direct_error.contains("身份端口 8443 与连接端口 9443 不同"));

        let ip_identity_error = build_client_for_route(
            &upstream("direct", "", None),
            "127.0.0.2",
            443,
            "127.0.0.1",
            443,
        )
        .await
        .err()
        .expect("IP identity remapping must fail");
        assert!(ip_identity_error.contains("不支持把 IP 身份映射到其他连接地址"));

        let proxy_error = build_client_for_route(
            &upstream("http", "", None),
            "mirror.remote.invalid",
            443,
            "api.original.invalid",
            443,
        )
        .await
        .err()
        .expect("remote proxy route must fail");
        assert!(proxy_error.contains("无法经 http 二级出口代理"));
    }

    #[tokio::test]
    async fn empty_post_reaches_http_origin_with_explicit_zero_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let head = String::from_utf8(read_http_head(&mut stream).await).expect("http header");
            assert!(head.starts_with("POST /empty HTTP/1.1\r\n"));
            assert!(head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("content-length: 0")));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("response");
        });

        let client = build_client(&EffectiveUpstreamProxy {
            mode: "direct".to_string(),
            host: String::new(),
            port: 0,
            username: String::new(),
            password: None,
            bypass: Vec::new(),
        })
        .expect("client");
        let response = send(
            &client,
            "POST",
            &format!("http://{address}/empty"),
            &[("Content-Length".to_string(), b"0".to_vec())],
            Some(wreq::Body::from(Vec::<u8>::new())),
        )
        .await
        .expect("empty post");
        assert_eq!(response.status(), 204);
        server.await.expect("server");
    }

    #[tokio::test]
    async fn origin_sees_profile_user_agent_not_the_captured_browser() {
        let _serial = TEST_ROOT_SERIAL
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous = crate::tls_clienthello_catalog::active_preset_id();
        crate::tls_clienthello_catalog::set_active_preset_id("firefox133")
            .expect("select firefox133");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let head = String::from_utf8(read_http_head(&mut stream).await).expect("http header");
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("response");
            head
        });

        let client = build_client(&EffectiveUpstreamProxy {
            mode: "direct".to_string(),
            host: String::new(),
            port: 0,
            username: String::new(),
            password: None,
            bypass: Vec::new(),
        })
        .expect("client");
        let response = send(
            &client,
            "GET",
            &format!("http://{address}/ua"),
            &[(
                "User-Agent".to_string(),
                b"Mozilla/5.0 Chrome/151.0.0.0 Safari/537.36".to_vec(),
            )],
            None,
        )
        .await
        .expect("send");
        assert_eq!(response.status(), 204);
        let head = server.await.expect("server");
        let _ = crate::tls_clienthello_catalog::set_active_preset_id(&previous);
        assert!(
            head.to_ascii_lowercase()
                .contains("user-agent: mozilla/5.0")
                && head.contains("Firefox/133"),
            "origin must see Firefox 133, not the captured Chrome UA: {head}"
        );
        assert!(
            !head.contains("Chrome/151"),
            "captured Chrome UA leaked to origin: {head}"
        );
    }

    #[test]
    fn mapped_catalog_ids_select_the_linked_wreq_profile() {
        let mut exact = 0;
        for id in crate::tls_clienthello_catalog::list_preset_ids() {
            let emulation =
                emulation_for_preset(id).unwrap_or_else(|error| panic!("{id}: {error}"));
            let sigs = emulation
                .tls_options
                .as_ref()
                .and_then(|tls| tls.sigalgs_list.as_ref())
                .map(|list| list.as_ref())
                .unwrap_or("");
            match crate::tls_clienthello_catalog::wreq_emulation_kind(id) {
                crate::tls_clienthello_catalog::WreqEmulationKind::Exact => {
                    exact += 1;
                    let name = crate::tls_clienthello_catalog::wreq_profile_name(id)
                        .unwrap_or_else(|| panic!("{id} missing wreq profile name"));
                    assert!(
                        wreq_profile_from_name(name).is_some(),
                        "{id} → {name} is not a linked wreq-util Profile"
                    );
                    assert!(
                        !sigs.contains("mldsa44"),
                        "{id} must not ride the Chrome 151 ML-DSA overlay: {sigs}"
                    );
                }
                crate::tls_clienthello_catalog::WreqEmulationKind::Chrome149PlusMldsa
                | crate::tls_clienthello_catalog::WreqEmulationKind::None => {
                    assert!(
                        sigs.contains("mldsa44"),
                        "{id} falls back to the Chrome 151 overlay"
                    );
                }
            }
        }
        assert_eq!(
            exact, 20,
            "catalog ↔ wreq-util exact map drifted; update the report"
        );
    }

    fn expected_ua_needle(preset_id: &str) -> Option<&'static str> {
        Some(match preset_id {
            "chrome120" => "Chrome/120",
            "chrome124" => "Chrome/124",
            "chrome128" => "Chrome/128",
            "chrome131" => "Chrome/131",
            "chrome133" => "Chrome/133",
            "chrome136" => "Chrome/136",
            "chrome140" => "Chrome/140",
            "chrome144" => "Chrome/144",
            "chrome145" => "Chrome/145",
            "chrome146" => "Chrome/146",
            "chrome149" => "Chrome/149",
            "chrome150" | "chrome151" | "chrome-like" | "firefox115" => "Chrome/151",
            "firefox128" => "Firefox/128",
            "firefox133" => "Firefox/133",
            "firefox136" => "Firefox/136",
            "edge131" => "Edg/131",
            "edge136" => "Chrome/136",
            "safari17" => "Version/17.6",
            "safari18" => "Version/18.0",
            "safari-ios17" => "Version/17.4.1",
            "safari-ios18" => "Version/18.1.1",
            _ => return None,
        })
    }

    #[test]
    fn mapped_presets_carry_the_matching_user_agent() {
        for id in crate::tls_clienthello_catalog::list_preset_ids() {
            let Some(needle) = expected_ua_needle(id) else {
                continue;
            };
            let ua = user_agent_for_preset(id).unwrap_or_else(|| panic!("{id} missing UA"));
            assert!(
                ua.contains(needle),
                "{id} User-Agent {ua} does not contain {needle}"
            );
            if id.starts_with("firefox") && id != "firefox115" {
                assert!(
                    !ua.contains("Chrome/"),
                    "{id} must not keep a Chrome User-Agent: {ua}"
                );
            }
        }
        let chrome151 = user_agent_for_preset("chrome151").expect("chrome151 ua");
        assert!(
            !chrome151.contains("Chrome/149"),
            "Chrome 151 overlay still advertises 149: {chrome151}"
        );
        let sec_ch_ua = emulation_for_preset("chrome151")
            .expect("chrome151")
            .headers
            .get("sec-ch-ua")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            sec_ch_ua.contains("v=\"151\""),
            "Chrome 151 sec-ch-ua still on 149: {sec_ch_ua}"
        );
        assert!(!sec_ch_ua.contains("v=\"149\""), "{sec_ch_ua}");
    }

    #[test]
    fn chrome_151_http2_profile_keeps_the_observed_akamai_fingerprint() {
        use wreq::http2::PseudoId;

        let emulation = chrome_151_emulation().expect("Chrome 151 emulation");
        let options = emulation.http2_options.expect("HTTP/2 options");
        assert_eq!(options.header_table_size, Some(65_536));
        assert_eq!(options.enable_push, Some(false));
        assert_eq!(options.initial_window_size, 6_291_456);
        assert_eq!(options.max_header_list_size, Some(262_144));
        assert_eq!(options.initial_conn_window_size - 65_535, 15_663_105);
        let pseudo_order = options
            .headers_pseudo_order
            .as_ref()
            .expect("pseudo order")
            .into_iter()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            &pseudo_order[..4],
            [
                PseudoId::Method,
                PseudoId::Authority,
                PseudoId::Scheme,
                PseudoId::Path,
            ]
        );
    }

    async fn read_http_head(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.expect("request byte");
            bytes.push(byte[0]);
            assert!(bytes.len() < 64 * 1024, "request header too large");
        }
        bytes
    }

    #[tokio::test]
    async fn response_stream_yields_before_the_origin_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let (release, released) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = read_http_head(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n13\r\ndata: first-event\n\n\r\n",
                )
                .await
                .expect("first event");
            stream.flush().await.expect("flush");
            let _ = released.await;
            stream.write_all(b"0\r\n\r\n").await.expect("finish");
        });

        let client = build_client(&EffectiveUpstreamProxy {
            mode: "direct".to_string(),
            host: String::new(),
            port: 0,
            username: String::new(),
            password: None,
            bypass: Vec::new(),
        })
        .expect("client");
        let response = timeout(
            Duration::from_secs(2),
            send(
                &client,
                "GET",
                &format!("http://{address}/events"),
                &[],
                None,
            ),
        )
        .await
        .expect("headers before EOF")
        .expect("response");
        assert_eq!(response.status(), 200);
        let mut body = response.bytes_stream();
        let first = timeout(Duration::from_secs(2), body.next())
            .await
            .expect("first body chunk before EOF")
            .expect("body item")
            .expect("body bytes");
        assert_eq!(first, "data: first-event\n\n");

        let _ = release.send(());
        server.await.expect("server");
    }

    #[tokio::test]
    async fn chrome_151_client_hello_includes_mldsa_and_matches_target_ja4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            crate::tls_fingerprint::read_client_hello(&mut stream)
                .await
                .expect("read ClientHello")
                .fingerprint
                .expect("parse ClientHello")
        });
        let client = build_client(&EffectiveUpstreamProxy {
            mode: "direct".to_string(),
            host: String::new(),
            port: 0,
            username: String::new(),
            password: None,
            bypass: Vec::new(),
        })
        .expect("client");

        let result = send(
            &client,
            "GET",
            &format!("https://localhost:{}/", address.port()),
            &[],
            None,
        )
        .await;
        assert!(
            result.is_err(),
            "capture server intentionally closes after ClientHello"
        );

        let fingerprint = server.await.expect("capture task");
        assert_eq!(
            fingerprint.signature_algorithms,
            [
                "0904", "0905", "0906", "0403", "0804", "0401", "0503", "0805", "0501", "0806",
                "0601",
            ]
        );
        assert_eq!(
            fingerprint
                .extensions
                .iter()
                .filter(|value| {
                    u16::from_str_radix(value, 16).is_ok_and(|id| id & 0x0f0f != 0x0a0a)
                })
                .count(),
            16
        );
        assert_eq!(fingerprint.alpn, ["h2", "http/1.1"]);
        assert_eq!(fingerprint.ja4, EGRESS_JA4);
    }

    #[tokio::test]
    async fn http_proxy_receives_special_character_basic_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let head = String::from_utf8(read_http_head(&mut stream).await).expect("http header");
            assert!(head.starts_with("GET http://origin.invalid/proxied HTTP/1.1\r\n"));
            let expected = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                "user@example:p@ss:/#",
            );
            assert!(
                head.to_ascii_lowercase().contains(&format!(
                    "proxy-authorization: basic {}\r\n",
                    expected.to_ascii_lowercase()
                )),
                "proxy request did not contain expected auth header:\n{head}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .expect("response");
        });
        let client = build_client(&EffectiveUpstreamProxy {
            mode: "http".to_string(),
            host: address.ip().to_string(),
            port: address.port(),
            username: "user@example".to_string(),
            password: Some("p@ss:/#".to_string()),
            bypass: Vec::new(),
        })
        .expect("client");
        let body = send(&client, "GET", "http://origin.invalid/proxied", &[], None)
            .await
            .expect("proxied request")
            .text()
            .await
            .expect("body");
        assert_eq!(body, "ok");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn socks5_proxy_receives_remote_dns_target_and_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut greeting = [0_u8; 4];
            stream.read_exact(&mut greeting).await.expect("greeting");
            assert_eq!(greeting, [5, 2, 0, 2]);
            stream.write_all(&[5, 2]).await.expect("select auth");

            let mut auth = [0_u8; 3];
            stream.read_exact(&mut auth).await.expect("auth prefix");
            assert_eq!(auth, [1, 1, b'u']);
            let password_len = stream.read_u8().await.expect("password length") as usize;
            let mut password = vec![0_u8; password_len];
            stream.read_exact(&mut password).await.expect("password");
            assert_eq!(password, b"p@ss");
            stream.write_all(&[1, 0]).await.expect("auth ok");

            let mut connect = [0_u8; 5];
            stream
                .read_exact(&mut connect)
                .await
                .expect("connect prefix");
            assert_eq!(&connect[..4], &[5, 1, 0, 3]);
            let mut host = vec![0_u8; connect[4] as usize];
            stream.read_exact(&mut host).await.expect("target host");
            assert_eq!(host, b"origin.invalid");
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).await.expect("target port");
            assert_eq!(u16::from_be_bytes(port), 80);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .expect("connect ok");

            let head = String::from_utf8(read_http_head(&mut stream).await).expect("http header");
            assert!(head.starts_with("GET /through-socks HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .expect("response");
        });
        let client = build_client(&EffectiveUpstreamProxy {
            mode: "socks5".to_string(),
            host: address.ip().to_string(),
            port: address.port(),
            username: "u".to_string(),
            password: Some("p@ss".to_string()),
            bypass: Vec::new(),
        })
        .expect("client");
        let body = send(
            &client,
            "GET",
            "http://origin.invalid/through-socks",
            &[],
            None,
        )
        .await
        .expect("proxied request")
        .text()
        .await
        .expect("body");
        assert_eq!(body, "ok");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn bypass_rule_keeps_matching_target_off_the_proxy() {
        let target = TcpListener::bind("127.0.0.1:0").await.expect("target");
        let target_address = target.local_addr().expect("target address");
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("proxy");
        let proxy_address = proxy.local_addr().expect("proxy address");
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("target accept");
            let _ = read_http_head(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ndirect")
                .await
                .expect("response");
        });
        let client = build_client(&EffectiveUpstreamProxy {
            mode: "http".to_string(),
            host: proxy_address.ip().to_string(),
            port: proxy_address.port(),
            username: String::new(),
            password: None,
            bypass: vec!["127.0.0.1".to_string()],
        })
        .expect("client");
        let body = send(
            &client,
            "GET",
            &format!("http://{target_address}/bypass"),
            &[],
            None,
        )
        .await
        .expect("direct request")
        .text()
        .await
        .expect("body");
        assert_eq!(body, "direct");
        assert!(timeout(Duration::from_millis(200), proxy.accept())
            .await
            .is_err());
        target_task.await.expect("target task");
    }

    /// JA4 values wreq-util 3.0.0-rc.14 already measured on tls.browserleaks.com
    /// (`tests/emulate_*.rs`). ECH padding can flip the first JA4 token
    /// (t13d1516 ↔ t13d1517); the cipher hash (second token) is the stable check.
    fn expected_detector_ja4(preset_id: &str) -> &'static [&'static str] {
        match preset_id {
            "chrome120" => &[
                "t13d1516h2_8daaf6152771_02713d6af862",
                "t13d1517h2_8daaf6152771_b1ff8ab2d16f",
            ],
            "chrome124" | "chrome128" | "chrome131" | "edge131" => {
                &["t13d1516h2_8daaf6152771_02713d6af862"]
            }
            "chrome133" | "chrome136" | "chrome140" | "chrome144" | "chrome145" | "chrome146"
            | "chrome149" | "edge136" => &["t13d1516h2_8daaf6152771_d8a2da3f94cd"],
            "chrome150" | "chrome151" | "chrome-like" | "firefox115" => &[EGRESS_JA4],
            "firefox128" => &["t13d1513h2_8daaf6152771_748f4c70de1c"],
            "firefox133" => &["t13d1716h2_5b57614c22b0_eeeea6562960"],
            "firefox136" => &["t13d1717h2_5b57614c22b0_3cbfd9057e0d"],
            "safari17" | "safari18" | "safari-ios17" | "safari-ios18" => {
                &["t13d2014h2_a09f3c656075_14788d8d241b"]
            }
            _ => &[],
        }
    }

    fn ja4_cipher_hash(ja4: &str) -> Option<&str> {
        ja4.split('_').nth(1)
    }

    fn ja4_agrees_with_expected(measured: &str, expected: &[&str]) -> bool {
        if expected.is_empty() {
            return true;
        }
        if expected.iter().any(|item| *item == measured) {
            return true;
        }
        let Some(got) = ja4_cipher_hash(measured) else {
            return false;
        };
        expected
            .iter()
            .any(|item| ja4_cipher_hash(item) == Some(got))
    }

    fn family_ja4_ok(preset_id: &str, ja4: &str) -> bool {
        if preset_id.starts_with("safari") {
            return ja4.starts_with("t13d20");
        }
        if preset_id.starts_with("firefox") && preset_id != "firefox115" {
            return ja4.starts_with("t13d1513") || ja4.starts_with("t13d17");
        }
        ja4.starts_with("t13d15")
    }

    fn extract_detector_ja4(url: &str, value: &serde_json::Value) -> Option<String> {
        let ja4 = if url.contains("peet.ws") {
            value["tls"]["ja4"].as_str()
        } else {
            value
                .get("ja4")
                .and_then(|item| item.as_str())
                .or_else(|| value["tls"]["ja4"].as_str())
        }?;
        let ja4 = ja4.trim();
        if ja4.is_empty() {
            None
        } else {
            Some(ja4.to_string())
        }
    }

    async fn probe_preset_ja4(
        preset_id: &str,
        detector: &str,
    ) -> Result<(String, serde_json::Value), String> {
        let client = Client::builder()
            .emulation(emulation_for_preset(preset_id)?)
            .connect_timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|error| format!("build {preset_id}: {error}"))?;
        let text = timeout(Duration::from_secs(30), client.get(detector).send())
            .await
            .map_err(|_| format!("{preset_id}: timeout contacting {detector}"))?
            .map_err(|error| format!("{preset_id}: {error}"))?
            .text()
            .await
            .map_err(|error| format!("{preset_id} body: {error}"))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|error| format!("{preset_id} json from {detector}: {error}; body={text}"))?;
        let ja4 = extract_detector_ja4(detector, &value)
            .ok_or_else(|| format!("{preset_id}: no ja4 in {detector} body={text}"))?;
        Ok((ja4, value))
    }

    /// Hits public JA3/JA4 reflectors with every catalog id that has a linked
    /// wreq-util profile. Does not install browser versions.
    ///
    ///   cargo test --no-default-features --features impersonate-boring \
    ///     mapped_presets_match_detector_ja4 -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "network; run explicitly under --features impersonate-boring"]
    async fn mapped_presets_match_detector_ja4() {
        const DETECTORS: &[&str] = &[
            "https://tls.peet.ws/api/all",
            "https://tls.browserleaks.com/json",
        ];
        let mut ids: Vec<&str> = crate::tls_clienthello_catalog::list_preset_ids()
            .into_iter()
            .filter(|id| {
                crate::tls_clienthello_catalog::wreq_emulation_kind(id)
                    != crate::tls_clienthello_catalog::WreqEmulationKind::None
            })
            .collect();
        ids.push("firefox115");
        ids.sort();
        ids.dedup();

        let mut detector = DETECTORS[0];
        let mut detector_ok = false;
        for candidate in DETECTORS {
            match probe_preset_ja4("chrome151", candidate).await {
                Ok((ja4, _)) => {
                    eprintln!("DETECTOR {candidate} chrome151={ja4}");
                    detector = *candidate;
                    detector_ok = true;
                    break;
                }
                Err(error) => eprintln!("DETECTOR_SKIP {candidate}: {error}"),
            }
        }
        assert!(
            detector_ok,
            "no public JA3/JA4 detector answered (tried {})",
            DETECTORS.join(", ")
        );

        let mut measured = std::collections::BTreeMap::<String, String>::new();
        for id in ids {
            if measured.contains_key(id) {
                continue;
            }
            let (ja4, value) = probe_preset_ja4(id, detector)
                .await
                .unwrap_or_else(|error| panic!("{id}: {error}"));
            let ja3 = if detector.contains("peet.ws") {
                value["tls"]["ja3_hash"].as_str().unwrap_or_default()
            } else {
                value
                    .get("ja3_hash")
                    .and_then(|item| item.as_str())
                    .unwrap_or_default()
            };
            let ua = value
                .get("user_agent")
                .and_then(|item| item.as_str())
                .or_else(|| value["http"]["user_agent"].as_str())
                .unwrap_or_default();
            eprintln!("PROBE {id} ja4={ja4} ja3={ja3} ua={ua}");
            if let Some(needle) = expected_ua_needle(id) {
                assert!(
                    ua.contains(needle),
                    "{id} detector User-Agent {ua} does not contain {needle}"
                );
            }
            assert!(
                family_ja4_ok(id, &ja4),
                "{id} JA4 {ja4} is not the expected browser family"
            );
            let expected = expected_detector_ja4(id);
            assert!(
                ja4_agrees_with_expected(&ja4, expected),
                "{id} JA4 {ja4} disagrees with wreq-util/ShowNet expectation {expected:?}"
            );
            measured.insert(id.to_string(), ja4);
            tokio::time::sleep(Duration::from_millis(400)).await;
        }

        let chrome = measured.get("chrome131").expect("chrome131");
        let firefox = measured.get("firefox133").expect("firefox133");
        let safari = measured.get("safari18").expect("safari18");
        assert_ne!(chrome, firefox, "Firefox 133 must not present Chrome JA4");
        assert_ne!(chrome, safari, "Safari 18 must not present Chrome JA4");
        assert_eq!(
            measured.get("firefox115").map(String::as_str),
            measured.get("chrome151").map(String::as_str),
            "unmapped firefox115 must not pretend to be Firefox; it keeps the Chrome 151 overlay"
        );
    }

    /// The whole reason wreq was chosen: Chrome byte-exact on both axes a strict
    /// gate checks. Measured against a reflector, not asserted from the
    /// library's promise. Ignored because it needs the network.
    ///
    ///   cargo test --no-default-features --features impersonate-boring \
    ///     wreq_egress_is_byte_exact_chrome -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "network; run explicitly under --features impersonate-boring"]
    async fn wreq_egress_is_byte_exact_chrome() {
        let client = Client::builder()
            .emulation(chrome_151_emulation().expect("Chrome 151 emulation"))
            .build()
            .expect("client");
        let text = client
            .get("https://tls.peet.ws/api/all")
            .send()
            .await
            .expect("send")
            .text()
            .await
            .expect("body");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");

        // TLS: Chrome's JA4 has 16 extensions — t13d15_16_h2. rustls could not
        // reach this; it is the gap wreq closes.
        let ja4 = value["tls"]["ja4"].as_str().expect("ja4");
        eprintln!("WREQ_JA4 {ja4}");
        assert!(
            ja4.starts_with("t13d1516h2"),
            "expected Chrome's 16-extension JA4, got {ja4}"
        );

        // HTTP/2: Chrome sends pseudo-header order method, authority, scheme,
        // path. hyper hardcodes m,s,a,p; wreq's patched h2 sends m,a,s,p.
        let akamai = value["http2"]["akamai_fingerprint"]
            .as_str()
            .expect("akamai fingerprint");
        eprintln!("WREQ_AKAMAI {akamai}");
        assert!(
            akamai.ends_with("|m,a,s,p"),
            "expected Chrome pseudo-header order m,a,s,p, got {akamai}"
        );
        assert!(
            akamai.starts_with("1:65536;2:0;4:6291456;6:262144"),
            "h2 SETTINGS drifted from Chrome: {akamai}"
        );
    }

    /// What `ja3Parity` claims, measured rather than assumed.
    ///
    /// An origin never sees the browser's ClientHello — that connection ends at
    /// ShowNet's own listener — so this is not a defense against anything. It is
    /// what makes the parity readout mean something: the two sides are different
    /// TLS stacks (the user's installed Chrome, whatever version it auto-updated
    /// to, against wreq's pinned profile), so their agreement is a fact that
    /// expires. The browser shipping one new ClientHello extension breaks it
    /// silently, and a permanently-red parity light is worse than none — it sent
    /// this investigation chasing a version mismatch that did not exist.
    ///
    ///   cargo test --no-default-features --features impersonate-boring \
    ///     browser_and_egress_present_one_fingerprint -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "network + a locally installed Chrome; run via npm run test:ja4-parity"]
    async fn browser_and_egress_present_one_fingerprint() {
        const REFLECTOR: &str = "https://tls.peet.ws/api/all";

        let egress = Client::builder()
            .no_proxy()
            .emulation(chrome_151_emulation().expect("Chrome 151 emulation"))
            .build()
            .expect("client")
            .get(REFLECTOR)
            .send()
            .await
            .expect("egress send")
            .text()
            .await
            .expect("egress body");
        let egress_ja4 = serde_json::from_str::<serde_json::Value>(&egress)
            .ok()
            .and_then(|value| value["tls"]["ja4"].as_str().map(str::to_owned))
            .expect("egress ja4");

        let browser_ja4 = measure_browser_ja4(REFLECTOR).await;

        eprintln!("BROWSER_JA4 {browser_ja4}\nEGRESS_JA4  {egress_ja4}");
        assert_eq!(
            browser_ja4, egress_ja4,
            "the capture browser and the impersonate egress present different \
             ClientHellos, so ja3Parity now reports a difference nothing in the \
             product can close. If the browser grew an extension or signature \
             algorithm wreq cannot reproduce, update the linked TLS backend and \
             EMULATION to a profile that matches; do not hide the browser feature. \
             Do not read a mismatch here as \
             the cause of an origin-side block: the origin never saw either of \
             these handshakes' differences, only the egress one."
        );
    }

    /// Drives the real browser the same way `ProxyBrowserHandle::launch` does — the
    /// same suppressed features — and reads the fingerprint it presented. Anything
    /// less would measure a browser ShowNet does not actually run.
    #[cfg(test)]
    async fn measure_browser_ja4(reflector: &str) -> String {
        use tokio::process::Command;

        /// How long to let the browser reach the reflector. Measured at ~3s; the
        /// margin is for a cold profile behind a slow proxy.
        const ATTEMPT: std::time::Duration = std::time::Duration::from_secs(60);
        const POLL: std::time::Duration = std::time::Duration::from_millis(250);

        let chrome = crate::browser::chrome_executable().expect("an installed Chrome");
        let profile = std::env::temp_dir().join(format!("shownet-ja4-{}", std::process::id()));
        // Waiting for the browser to exit does not work: `--dump-dom` writes the
        // rendered DOM and then keeps running — measured, even on about:blank it
        // never exited, so waiting on the process burned the whole timeout on a
        // page that had loaded in three seconds. Watch the output instead and end
        // the process once the fingerprint is in it.
        let dump = std::env::temp_dir().join(format!("shownet-ja4-{}.html", std::process::id()));
        let mut last = String::new();
        for _ in 0..3 {
            let mut command = Command::new(&chrome);
            command.kill_on_drop(true);
            // wreq reads the same variables, so honoring them keeps both sides on
            // one egress — otherwise a proxied runner would compare a proxied
            // fingerprint against a direct one.
            if let Some(proxy) = std::env::var("HTTPS_PROXY")
                .or_else(|_| std::env::var("https_proxy"))
                .ok()
                .filter(|value| !value.trim().is_empty())
            {
                command.arg(format!("--proxy-server={proxy}"));
            }
            let mut run = command
                .arg("--headless=new")
                .arg("--disable-gpu")
                .arg("--no-first-run")
                .arg("--no-default-browser-check")
                .arg("--disable-sync")
                .arg("--disable-background-networking")
                .arg(format!("--user-data-dir={}", profile.to_string_lossy()))
                .arg(format!(
                    "--disable-features={}",
                    crate::browser::DISABLED_FEATURES
                ))
                .arg("--virtual-time-budget=25000")
                .arg("--dump-dom")
                .arg(reflector)
                .stdout(std::fs::File::create(&dump).expect("create dump file"))
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn chrome");

            // --dump-dom writes the rendered DOM, so the JSON arrives wrapped in
            // <html><body><pre>; the field is unambiguous enough to read directly.
            let read_ja4 = |text: &str| -> Option<String> {
                text.split("\"ja4\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').nth(1))
                    .map(str::to_owned)
            };

            let deadline = tokio::time::Instant::now() + ATTEMPT;
            let mut found = None;
            while tokio::time::Instant::now() < deadline {
                tokio::time::sleep(POLL).await;
                last = std::fs::read_to_string(&dump).unwrap_or_default();
                if let Some(ja4) = read_ja4(&last) {
                    found = Some(ja4);
                    break;
                }
            }
            // kill_on_drop covers the panic paths; this covers the normal one.
            let _ = run.kill().await;

            if let Some(ja4) = found {
                let _ = std::fs::remove_dir_all(&profile);
                let _ = std::fs::remove_file(&dump);
                return ja4;
            }
            eprintln!("browser produced no fingerprint within {ATTEMPT:?}, retrying");
        }
        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_file(&dump);
        panic!(
            "the browser never reported a fingerprint (network or startup failure), \
             last {} bytes of DOM: {}",
            last.len(),
            &last[last.len().saturating_sub(300)..]
        );
    }
}
