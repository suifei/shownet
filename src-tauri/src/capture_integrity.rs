//! Controlled Chrome → MITM → wreq HTTP/2 integrity gate (#42).
//!
//! The origin records the reconstructed request; ShowNet persists the decrypted
//! pair to SQLite. Assertions compare those two ends after the storage is
//! reopened. Hook injection is not enabled.

#![cfg(all(test, feature = "impersonate-boring"))]

use crate::ca::CertificateAuthority;
use crate::models::{CapturedRequestInput, EffectiveUpstreamProxy, RequestRecord};
use crate::proxy::ProxyHandle;
use crate::storage::Storage;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, LOCATION, SET_COOKIE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const INTEGRITY_HOST: &str = "capture.shownet.test";

#[derive(Clone, Debug)]
struct OriginSeen {
    method: String,
    path: String,
    version: Version,
    authority: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn direct_upstream() -> EffectiveUpstreamProxy {
    EffectiveUpstreamProxy {
        mode: "direct".to_string(),
        host: String::new(),
        port: 0,
        username: String::new(),
        password: None,
        bypass: vec![],
    }
}

fn sqlite_capture_sink(storage: Arc<Storage>) -> Arc<dyn Fn(CapturedRequestInput) + Send + Sync> {
    Arc::new(move |request| {
        if let Err(error) = storage.store_request(request) {
            panic!("persist captured request: {error}");
        }
    })
}

async fn start_integrity_origin(
    ca: &CertificateAuthority,
) -> (
    u16,
    Arc<Mutex<Vec<OriginSeen>>>,
    tokio::task::JoinHandle<()>,
) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_config = ca.server_config(INTEGRITY_HOST).unwrap();
    let seen_for_server = seen.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => break,
            };
            let server_config = server_config.clone();
            let seen_for_server = seen_for_server.clone();
            tokio::spawn(async move {
                let tls = match TlsAcceptor::from(server_config).accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };
                let service = service_fn(move |request: Request<Incoming>| {
                    let seen_for_server = seen_for_server.clone();
                    async move {
                        let method = request.method().as_str().to_string();
                        let path = request.uri().path().to_string();
                        let version = request.version();
                        let authority = request
                            .uri()
                            .authority()
                            .map(ToString::to_string)
                            .or_else(|| {
                                request
                                    .headers()
                                    .get(HOST)
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_string)
                            })
                            .unwrap_or_default();
                        let headers = request
                            .headers()
                            .iter()
                            .map(|(name, value)| {
                                (
                                    name.as_str().to_string(),
                                    value.to_str().unwrap_or("<binary>").to_string(),
                                )
                            })
                            .collect::<Vec<_>>();
                        let body = request
                            .into_body()
                            .collect()
                            .await
                            .map(|collected| collected.to_bytes().to_vec())
                            .unwrap_or_default();
                        seen_for_server.lock().unwrap().push(OriginSeen {
                            method: method.clone(),
                            path: path.clone(),
                            version,
                            authority,
                            headers,
                            body,
                        });
                        let response = match (method.as_str(), path.as_str()) {
                            ("POST", "/empty") => Response::builder()
                                .status(StatusCode::NO_CONTENT)
                                .header(CONTENT_LENGTH, "0")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                            ("GET", "/set-cookie") => Response::builder()
                                .status(StatusCode::FOUND)
                                .header(SET_COOKIE, "sid=one")
                                .header(SET_COOKIE, "rid=two")
                                .header(LOCATION, "/echo-cookie")
                                .header(CONTENT_LENGTH, "0")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                            ("GET", "/echo-cookie") => {
                                let body = b"cookie-ok";
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(CONTENT_TYPE, "text/plain")
                                    .header(CONTENT_LENGTH, body.len().to_string())
                                    .body(Full::new(Bytes::from_static(body)))
                                    .unwrap()
                            }
                            ("GET", "/") => {
                                let page = br#"<!doctype html><html><body>
<script>
fetch('/empty', {method: 'POST'}).then(() => fetch('/set-cookie', {redirect: 'follow'}));
</script></body></html>"#;
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(CONTENT_TYPE, "text/html; charset=utf-8")
                                    .header(CONTENT_LENGTH, page.len().to_string())
                                    .body(Full::new(Bytes::from_static(page)))
                                    .unwrap()
                            }
                            ("GET", "/303") => Response::builder()
                                .status(StatusCode::SEE_OTHER)
                                .header(LOCATION, "/echo-cookie")
                                .header(CONTENT_LENGTH, "0")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                            ("GET", "/307") => Response::builder()
                                .status(StatusCode::TEMPORARY_REDIRECT)
                                .header(LOCATION, "/echo-cookie")
                                .header(CONTENT_LENGTH, "0")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                            ("GET", "/308") => Response::builder()
                                .status(StatusCode::PERMANENT_REDIRECT)
                                .header(LOCATION, "/echo-cookie")
                                .header(CONTENT_LENGTH, "0")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                            _ => Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .header(CONTENT_LENGTH, "0")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        };
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (port, seen, server)
}

async fn read_http_header(stream: &mut (impl AsyncReadExt + Unpin)) -> String {
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while header.len() < 65_536 {
        stream.read_exact(&mut byte).await.unwrap();
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return String::from_utf8(header).unwrap();
        }
    }
    panic!("HTTP header too large");
}

async fn rustls_mitm_exchange(
    proxy: std::net::SocketAddr,
    ca: &CertificateAuthority,
    port: u16,
    request: &str,
) -> String {
    let mut tunnel = TcpStream::connect(proxy).await.unwrap();
    tunnel
        .write_all(
            format!(
                "CONNECT {INTEGRITY_HOST}:{port} HTTP/1.1\r\nHost: {INTEGRITY_HOST}:{port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let connect = read_http_header(&mut tunnel).await;
    assert!(connect.starts_with("HTTP/1.1 200"), "{connect}");
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate_der()).unwrap();
    let mut tls = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
    .connect(
        ServerName::try_from(INTEGRITY_HOST.to_string()).unwrap(),
        tunnel,
    )
    .await
    .expect("MITM client TLS");
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), tls.read_to_end(&mut raw))
        .await
        .expect("response timeout")
        .unwrap();
    String::from_utf8_lossy(&raw).into_owned()
}

fn reopen_details(db: &std::path::Path, session_id: &str) -> Vec<RequestRecord> {
    let storage = Storage::open(db).expect("reopen sqlite");
    let listed = storage
        .list_requests(session_id, None, None)
        .expect("list after reopen");
    listed
        .into_iter()
        .map(|item| storage.get_request_detail(&item.id).expect("detail"))
        .collect()
}

fn assert_empty_post_on_origin(seen: &[OriginSeen]) {
    let empty = seen
        .iter()
        .find(|item| item.method == "POST" && item.path == "/empty")
        .expect("origin saw POST /empty");
    assert_eq!(empty.body.len(), 0, "empty POST body must stay empty");
    assert_eq!(
        header_value(&empty.headers, "content-length").as_deref(),
        Some("0")
    );
    assert!(
        !empty
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("keep-alive")
                || name.eq_ignore_ascii_case("proxy-connection")
                || name.eq_ignore_ascii_case("transfer-encoding")),
        "hop-by-hop headers leaked to origin: {:?}",
        empty.headers
    );
    assert!(
        empty.authority.contains(INTEGRITY_HOST),
        "authority drifted: {}",
        empty.authority
    );
    assert_eq!(empty.version, Version::HTTP_2);
    if let Some(language) = header_value(&empty.headers, "accept-language") {
        assert!(
            !language.contains("q=0.9;q="),
            "duplicate language weight: {language}"
        );
    }
}

fn assert_sqlite_pair(details: &[RequestRecord], method: &str, path: &str, response_body: &str) {
    let record = details
        .iter()
        .find(|item| item.method == method && item.path == path)
        .unwrap_or_else(|| panic!("sqlite missing {method} {path}: {details:?}"));
    assert!(record.hook.is_none(), "default hook must stay off");
    let metadata = &record.response_body_metadata;
    assert!(metadata.complete, "{method} {path} incomplete");
    assert!(!metadata.truncated, "{method} {path} truncated");
    assert!(
        metadata.error.is_none(),
        "{method} {path} error {:?}",
        metadata.error
    );
    assert!(
        metadata.omitted_reason.is_none(),
        "{method} {path} omitted {:?}",
        metadata.omitted_reason
    );
    if !response_body.is_empty() {
        assert_eq!(record.response_body, response_body);
    }
}

#[tokio::test]
async fn capture_integrity_mitm_wreq_sqlite_roundtrip() {
    let ca = Arc::new(CertificateAuthority::load_or_create(None).unwrap().0);
    let _roots = crate::impersonate_egress::install_test_root_certificate_der(
        ca.certificate_der().as_ref().to_vec(),
    );
    crate::proxy::set_test_host_ip(INTEGRITY_HOST, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let (port, seen, server) = start_integrity_origin(&ca).await;

    let dir = std::env::temp_dir().join(format!("shownet-integrity-sqlite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("shownet.sqlite3");
    let storage = Arc::new(Storage::open(&db).unwrap());
    let session = storage
        .create_session(Some("capture-integrity".to_string()))
        .unwrap();

    let handle = ProxyHandle::start_with_sinks(
        "127.0.0.1:0".parse().unwrap(),
        false,
        session.id.clone(),
        direct_upstream(),
        ca.clone(),
        sqlite_capture_sink(storage.clone()),
        Arc::new(|_| {}),
    )
    .await
    .unwrap();
    let proxy = handle.local_addr();

    let empty = rustls_mitm_exchange(
        proxy,
        &ca,
        port,
        &format!("POST /empty HTTP/1.1\r\nHost: {INTEGRITY_HOST}:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(empty.contains("204") || empty.contains("empty"), "{empty}");

    let redirect = rustls_mitm_exchange(
        proxy,
        &ca,
        port,
        &format!("GET /set-cookie HTTP/1.1\r\nHost: {INTEGRITY_HOST}:{port}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(
        redirect.contains("302") || redirect.contains("Found"),
        "{redirect}"
    );
    assert!(
        redirect.to_ascii_lowercase().contains("set-cookie"),
        "{redirect}"
    );

    let echoed = rustls_mitm_exchange(
        proxy,
        &ca,
        port,
        &format!("GET /echo-cookie HTTP/1.1\r\nHost: {INTEGRITY_HOST}:{port}\r\nCookie: sid=one; rid=two\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(echoed.contains("cookie-ok"), "{echoed}");

    for status_path in ["/303", "/307", "/308"] {
        let redirected = rustls_mitm_exchange(
            proxy,
            &ca,
            port,
            &format!("GET {status_path} HTTP/1.1\r\nHost: {INTEGRITY_HOST}:{port}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(
            redirected.contains("303")
                || redirected.contains("307")
                || redirected.contains("308")
                || redirected.contains("Location"),
            "{status_path}: {redirected}"
        );
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.stop().await;
    server.abort();
    drop(storage);

    let origin = seen.lock().unwrap().clone();
    assert_empty_post_on_origin(&origin);
    let cookie_echo = origin
        .iter()
        .find(|item| item.path == "/echo-cookie")
        .expect("origin saw cookie echo");
    assert_eq!(
        header_value(&cookie_echo.headers, COOKIE.as_str()).as_deref(),
        Some("sid=one; rid=two")
    );

    let details = reopen_details(&db, &session.id);
    assert_sqlite_pair(&details, "POST", "/empty", "");
    assert_sqlite_pair(&details, "GET", "/echo-cookie", "cookie-ok");
    let set_cookie = details
        .iter()
        .find(|item| item.path == "/set-cookie")
        .expect("sqlite set-cookie");
    let cookies = set_cookie
        .response_headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("set-cookie"))
        .map(|header| header.value.as_str())
        .collect::<Vec<_>>();
    assert!(
        cookies.iter().any(|value| *value == "sid=one"),
        "{cookies:?}"
    );
    assert!(
        cookies.iter().any(|value| *value == "rid=two"),
        "{cookies:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn capture_integrity_chrome_mitm_wreq_records_empty_post() {
    crate::browser::chrome_executable().expect("installed Chrome for capture integrity");

    let ca = Arc::new(CertificateAuthority::load_or_create(None).unwrap().0);
    let _roots = crate::impersonate_egress::install_test_root_certificate_der(
        ca.certificate_der().as_ref().to_vec(),
    );
    crate::proxy::set_test_host_ip(INTEGRITY_HOST, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let (port, seen, server) = start_integrity_origin(&ca).await;

    let dir = std::env::temp_dir().join(format!("shownet-integrity-chrome-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("shownet.sqlite3");
    let storage = Arc::new(Storage::open(&db).unwrap());
    let session = storage
        .create_session(Some("capture-integrity-chrome".to_string()))
        .unwrap();

    let handle = ProxyHandle::start_with_sinks(
        "127.0.0.1:0".parse().unwrap(),
        false,
        session.id.clone(),
        direct_upstream(),
        ca.clone(),
        sqlite_capture_sink(storage.clone()),
        Arc::new(|_| {}),
    )
    .await
    .unwrap();
    let proxy_port = handle.local_addr().port();
    let extra = [
        format!("--host-resolver-rules=MAP {INTEGRITY_HOST} 127.0.0.1"),
        "--ignore-certificate-errors".to_string(),
    ];
    let extra_refs = extra.iter().map(String::as_str).collect::<Vec<_>>();
    let mut browser = crate::browser::ProxyBrowserHandle::launch_with_extra_args(
        &dir,
        proxy_port,
        Some("th-TH"),
        &extra_refs,
    )
    .await
    .expect("launch production Chrome");

    let target = format!("https://{INTEGRITY_HOST}:{port}/");
    browser.bus().navigate(&target).await.expect("navigate");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        if seen
            .lock()
            .unwrap()
            .iter()
            .any(|item| item.method == "POST" && item.path == "/empty")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let hook = browser
        .bus()
        .evaluate(
            "JSON.stringify({bridge: typeof window.__SHOWNET_HOOK_BRIDGE__, language: navigator.language})",
            false,
        )
        .await
        .expect("evaluate hook state");
    let hook: serde_json::Value =
        serde_json::from_str(hook.value.as_str().expect("hook expression returns JSON"))
            .expect("hook json");
    assert_eq!(hook["bridge"], "undefined");
    assert_eq!(hook["language"], "th-TH");

    browser.stop().await;
    handle.stop().await;
    server.abort();
    drop(storage);

    let origin = seen.lock().unwrap().clone();
    assert_empty_post_on_origin(&origin);
    if let Some(empty) = origin
        .iter()
        .find(|item| item.method == "POST" && item.path == "/empty")
    {
        if let Some(language) = header_value(&empty.headers, "accept-language") {
            assert_eq!(language, "th-TH,th;q=0.9");
        }
    }

    let details = reopen_details(&db, &session.id);
    assert_sqlite_pair(&details, "POST", "/empty", "");
    assert!(
        details.iter().all(|item| item.hook.is_none()),
        "default hook injection must stay off"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
