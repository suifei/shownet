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
use wreq::Client;
use wreq_util::Emulation;

/// The Chrome build wreq emulates. One place, so the target the package
/// advertises and the client that produces it cannot drift.
pub const EMULATION: Emulation = Emulation::Chrome131;

/// A gathered response: everything the MITM path needs to relay it back to the
/// calling browser.
pub struct ImpersonateResponse {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// Builds a wreq client that egresses like Chrome, honoring ShowNet's upstream
/// proxy so the impersonate path reaches the network the same way the rest of
/// the proxy does.
pub fn build_client(upstream: &EffectiveUpstreamProxy) -> Result<Client, String> {
    // no_proxy() first: wreq, like reqwest, reads http_proxy/https_proxy from
    // the environment by default, and ShowNet points the system proxy at
    // itself — an inherited env proxy would loop the app's own egress back
    // through its capture proxy. The explicit upstream below is the only proxy
    // this client may use. (Invariant enforced by upstream-egress-ui.test.ts.)
    let mut builder = Client::builder().no_proxy().emulation(EMULATION);
    if upstream.mode == "http" && !upstream.host.trim().is_empty() {
        let auth = if upstream.username.trim().is_empty() {
            String::new()
        } else {
            // The password is decrypted upstream of this call.
            format!(
                "{}:{}@",
                upstream.username,
                upstream.password.as_deref().unwrap_or("")
            )
        };
        let url = format!("http://{auth}{}:{}", upstream.host, upstream.port);
        let proxy = wreq::Proxy::all(&url).map_err(|error| format!("代理配置无效: {error}"))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|error| format!("构建 wreq 客户端失败: {error}"))
}

/// Headers a client owns and must not be copied from the captured request —
/// wreq sets its own, and forwarding these would fight it or corrupt framing.
fn is_client_owned(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Sends one reconstructed origin request through wreq and gathers the response.
pub async fn send(
    client: &Client,
    method: &str,
    url: &str,
    headers: &[(String, Vec<u8>)],
    body: Option<Vec<u8>>,
) -> Result<ImpersonateResponse, String> {
    let method = wreq::Method::from_bytes(method.as_bytes())
        .map_err(|error| format!("方法无效 {method}: {error}"))?;
    let mut request = client.request(method, url);
    for (name, value) in headers {
        if is_client_owned(&name.to_ascii_lowercase()) {
            continue;
        }
        request = request.header(name.as_str(), value.as_slice());
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("wreq 请求失败: {error}"))?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    let body = response
        .bytes()
        .await
        .map_err(|error| format!("wreq 读取响应体失败: {error}"))?
        .to_vec();
    Ok(ImpersonateResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .emulation(EMULATION)
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
}
