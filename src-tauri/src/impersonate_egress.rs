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

/// The Chrome build wreq emulates — the newest wreq-util 2.x offers.
///
/// Trailing the installed browser by a dozen major versions matters far less than
/// it looks, and an earlier revision of this comment was wrong about it. Measured:
/// real Chrome 137 and real Chrome 151 present the *same* ClientHello
/// (t13d1516h2_8daaf6152771_d8a2da3f94cd) once ML-DSA is off, because ML-DSA is
/// the only difference across that range. So the wire says "some Chrome between
/// 137 and 151", which is exactly what the forwarded v=151 UA claims — not the
/// version mismatch it reads as.
///
/// Do not "fix" this by moving to wreq-util 3.x. Its Chrome140+ profiles add
/// extension 0x0029 (17 extensions, t13d1517h2), which no measured Chrome in this
/// range sends, so it is further from the browser rather than closer. Its
/// signature algorithms still omit ML-DSA, and 3.x/wreq 6.x are release
/// candidates that swap the TLS backend from boring2 to btls.
///
/// Verified against a reflector by wreq_egress_is_byte_exact_chrome, and against
/// the actual installed browser by browser_and_egress_present_one_fingerprint.
pub const EMULATION: Emulation = Emulation::Chrome137;

/// The JA4 `EMULATION` puts on the wire. Fixed per emulation, so it is a constant
/// rather than a per-handshake measurement — but it is a measured constant:
/// wreq_egress_is_byte_exact_chrome reads it back off a live reflector, and
/// browser_and_egress_present_one_fingerprint checks the installed browser
/// presents the same one. Changing EMULATION without changing this is caught by
/// both.
pub const EGRESS_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

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
            .emulation(EMULATION)
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
             algorithm wreq cannot reproduce, either suppress it in \
             browser::DISABLED_FEATURES the way TlsMldsaSignatures is, or move \
             EMULATION to a profile that matches. Do not read a mismatch here as \
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
