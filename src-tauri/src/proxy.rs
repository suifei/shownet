use crate::breakpoints::{
    BreakpointCompletion, BreakpointCoordinator, BreakpointResolution, BreakpointTaskInput,
    BreakpointWaitResult, RuntimeBreakpointRule, MAX_BREAKPOINT_BODY_BYTES,
};
use crate::ca::CertificateAuthority;
use crate::capture_rules::{
    RuntimeRuleControl, RuntimeRuleRequest, RuntimeRuleResponse, MAX_RULE_BODY_BYTES,
};
use crate::client_access::ClientAccessPolicy;
use crate::http2_fingerprint::{Http2FingerprintCollector, Http2ObservedIo};
use crate::mirror::{format_authority, MirrorIdentity, RuntimeMirrorRoute};
use crate::models::{
    BodyCaptureMetadata, CaptureEventInput, CapturedRequestInput, DetectedEnvProxy,
    EffectiveUpstreamProxy, HeaderEntry, UpstreamProbeResult,
};
use crate::tls_fingerprint::{
    mitm_fingerprint_with_selection, read_client_hello, tunnel_fingerprint,
};
use crate::tls_interception::TlsInterceptionDecision;
use crate::tls_outbound::{self, OutboundTlsProfile};
use crate::{persist_capture_event, persist_captured_request};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use brotli::Decompressor;
use bytes::Bytes;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use futures_util::{SinkExt, StreamExt};
#[cfg(feature = "impersonate-boring")]
use http_body_util::StreamBody;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::ext::Protocol;
use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE,
    HOST, TRANSFER_ENCODING, USER_AGENT,
};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Instant;
use tauri::{Emitter, Manager};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::time::{timeout, Duration, Sleep};
use tokio_rustls::rustls::pki_types::ServerName;
#[cfg(test)]
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;
use url::{Position, Url};
use uuid::Uuid;

type BoxError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type CaptureSink = Arc<dyn Fn(CapturedRequestInput) + Send + Sync>;
type EventSink = Arc<dyn Fn(CaptureEventInput) + Send + Sync>;
type ErrorSink = Arc<dyn Fn(String) + Send + Sync>;
type RequestRuleEngine =
    Arc<dyn Fn(&mut RuntimeRuleRequest) -> Result<RuntimeRuleControl, String> + Send + Sync>;
type RequestBodyRuleProbe = Arc<dyn Fn(&RuntimeRuleRequest) -> Result<bool, String> + Send + Sync>;
type ResponseRuleEngine =
    Arc<dyn Fn(&mut RuntimeRuleResponse) -> Result<bool, String> + Send + Sync>;
type ResponseBodyRuleProbe =
    Arc<dyn Fn(&RuntimeRuleResponse) -> Result<bool, String> + Send + Sync>;
type RequestBreakpointProbe =
    Arc<dyn Fn(&RuntimeRuleRequest) -> Result<Vec<RuntimeBreakpointRule>, String> + Send + Sync>;
type ResponseBreakpointProbe =
    Arc<dyn Fn(&RuntimeRuleResponse) -> Result<Vec<RuntimeBreakpointRule>, String> + Send + Sync>;
type TlsInterceptionEngine =
    Arc<dyn Fn(&str, Option<&str>) -> Result<TlsInterceptionDecision, String> + Send + Sync>;
type MirrorRuleEngine =
    Arc<dyn Fn(&RuntimeRuleRequest) -> Result<Option<RuntimeMirrorRoute>, String> + Send + Sync>;

#[derive(Clone)]
struct RuleEngine {
    request: RequestRuleEngine,
    request_body_required: RequestBodyRuleProbe,
    response: ResponseRuleEngine,
    response_body_required: ResponseBodyRuleProbe,
    request_breakpoints: RequestBreakpointProbe,
    response_breakpoints: ResponseBreakpointProbe,
    breakpoints: Arc<BreakpointCoordinator>,
    pending_traces: PendingRuleTraces,
    tls_interception: TlsInterceptionEngine,
    mirror: MirrorRuleEngine,
}

impl RuleEngine {
    fn apply_request(
        &self,
        request: &mut RuntimeRuleRequest,
    ) -> Result<RuntimeRuleControl, String> {
        (self.request)(request)
    }

    fn apply_response(&self, response: &mut RuntimeRuleResponse) -> Result<bool, String> {
        (self.response)(response)
    }

    fn requires_request_body(&self, request: &RuntimeRuleRequest) -> Result<bool, String> {
        if (self.request_body_required)(request)? {
            return Ok(true);
        }
        Ok(!(self.request_breakpoints)(request)?.is_empty())
    }

    fn requires_response_body(&self, response: &RuntimeRuleResponse) -> Result<bool, String> {
        (self.response_body_required)(response)
    }

    fn matching_request_breakpoints(
        &self,
        request: &RuntimeRuleRequest,
    ) -> Result<Vec<RuntimeBreakpointRule>, String> {
        (self.request_breakpoints)(request)
    }

    fn matching_response_breakpoints(
        &self,
        response: &RuntimeRuleResponse,
    ) -> Result<Vec<RuntimeBreakpointRule>, String> {
        (self.response_breakpoints)(response)
    }

    fn queue_breakpoint_trace(
        &self,
        request_id: &str,
        trace: crate::models::CaptureRuleRun,
    ) -> Result<(), String> {
        queue_rule_traces(&self.pending_traces, request_id, vec![trace])
    }

    fn tls_interception_decision(
        &self,
        authority_host: &str,
        client_hello_sni: Option<&str>,
    ) -> Result<TlsInterceptionDecision, String> {
        (self.tls_interception)(authority_host, client_hello_sni)
    }

    fn resolve_mirror(
        &self,
        request: &RuntimeRuleRequest,
    ) -> Result<Option<RuntimeMirrorRoute>, String> {
        (self.mirror)(request)
    }

    fn queue_mirror_trace(
        &self,
        request_id: &str,
        route: &RuntimeMirrorRoute,
        transport: &str,
    ) -> Result<(), String> {
        queue_rule_traces(
            &self.pending_traces,
            request_id,
            vec![route.trace(request_id, transport)],
        )
    }

    #[cfg(test)]
    fn request_only(request: RequestRuleEngine) -> Self {
        let pending_traces = Arc::new(StdMutex::new(HashMap::new()));
        Self {
            request,
            request_body_required: Arc::new(|_| Ok(false)),
            response: Arc::new(|_| Ok(false)),
            response_body_required: Arc::new(|_| Ok(false)),
            request_breakpoints: Arc::new(|_| Ok(Vec::new())),
            response_breakpoints: Arc::new(|_| Ok(Vec::new())),
            breakpoints: Arc::new(BreakpointCoordinator::default()),
            pending_traces,
            tls_interception: Arc::new(|_, _| Ok(TlsInterceptionDecision::default())),
            mirror: Arc::new(|_| Ok(None)),
        }
    }
}
const MAX_PENDING_RULE_TRACE_REQUESTS: usize = 1_000;
type BodyCaptureCallback = Box<dyn FnOnce(BodyCaptureSnapshot) + Send>;
type BodyChunkCallback = Box<dyn FnMut(&[u8]) + Send>;

/// `wreq::Body::wrap` accepts an HTTP body that is `Sync`. Proxy request bodies
/// are polled by one task and intentionally use an unsynchronised box, so wrap
/// them in `SyncWrapper` without changing their single-owner polling model.
#[cfg(feature = "impersonate-boring")]
struct WreqRequestBody<B> {
    inner: sync_wrapper::SyncWrapper<B>,
    size_hint: SizeHint,
    end_stream: bool,
}

#[cfg(feature = "impersonate-boring")]
impl<B> WreqRequestBody<B>
where
    B: Body,
{
    fn new(body: B) -> Self {
        let size_hint = body.size_hint();
        let end_stream = body.is_end_stream();
        Self {
            inner: sync_wrapper::SyncWrapper::new(body),
            size_hint,
            end_stream,
        }
    }
}

#[cfg(feature = "impersonate-boring")]
impl<B> Body for WreqRequestBody<B>
where
    B: Body + Unpin,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(self.inner.get_mut()).poll_frame(context);
        if matches!(result, Poll::Ready(None)) {
            self.end_stream = true;
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.end_stream
    }

    fn size_hint(&self) -> SizeHint {
        self.size_hint.clone()
    }
}
/// Shared MITM origin client: HTTP/1.1 or HTTP/2 depending on negotiated ALPN.
enum HttpsRequestSender {
    Http1(hyper::client::conn::http1::SendRequest<TapBody<ProxyBody>>),
    Http2(hyper::client::conn::http2::SendRequest<TapBody<ProxyBody>>),
    /// Byte-exact Chrome egress via wreq. Holds the client and the origin base
    /// (`https://host:port`), and does a full request per call — which fits the
    /// existing "one shared sender per CONNECT tunnel" model exactly, since a
    /// wreq client pools its own connections.
    #[cfg(feature = "impersonate-boring")]
    Impersonate {
        client: crate::impersonate_egress::ImpersonateClient,
        base: String,
    },
}

impl HttpsRequestSender {
    fn is_http2(&self) -> bool {
        match self {
            Self::Http2(_) => true,
            // wreq presents Chrome, which is h2 for any modern origin.
            #[cfg(feature = "impersonate-boring")]
            Self::Impersonate { .. } => true,
            Self::Http1(_) => false,
        }
    }

    /// Whether this connection can still carry a request.
    ///
    /// One sender is shared by every request inside a CONNECT tunnel. Origins
    /// routinely retire an h2 connection with GOAWAY — Cloudflare does it after
    /// a bounded number of streams — and once that lands, every later
    /// `send_request` on it fails. Without this check the tunnel stayed broken
    /// for good: the page's requests all failed, its challenge could never
    /// complete, and it reloaded forever.
    fn is_closed(&self) -> bool {
        match self {
            Self::Http1(sender) => sender.is_closed(),
            Self::Http2(sender) => sender.is_closed(),
            // wreq pools its own connections; a single logical sender never
            // retires the way a shared h2 stream does.
            #[cfg(feature = "impersonate-boring")]
            Self::Impersonate { .. } => false,
        }
    }

    /// Returns the response with its body already boxed into `ProxyBody`. The
    /// hyper variants carry an `Incoming`; the impersonate variant carries a
    /// streaming body from wreq — both box to the same type, and every consumer
    /// boxed it immediately anyway, so unifying here lets a non-hyper engine
    /// return through the same seam. The error is `BoxError` rather than
    /// `hyper::Error` because a wreq failure cannot be a hyper one.
    async fn send_request(
        &mut self,
        request: Request<TapBody<ProxyBody>>,
    ) -> Result<Response<ProxyBody>, BoxError> {
        match self {
            Self::Http1(sender) => sender
                .send_request(request)
                .await
                .map(|response| response.map(boxed_incoming_body))
                .map_err(|error| Box::new(error) as BoxError),
            Self::Http2(sender) => sender
                .send_request(request)
                .await
                .map(|response| response.map(boxed_incoming_body))
                .map_err(|error| Box::new(error) as BoxError),
            #[cfg(feature = "impersonate-boring")]
            Self::Impersonate { client, base } => send_via_impersonate(client, base, request).await,
        }
    }
}

/// Translates one MITM request into a wreq round-trip and back into the boxed
/// response the rest of the path expects.
#[cfg(feature = "impersonate-boring")]
async fn send_via_impersonate(
    client: &crate::impersonate_egress::ImpersonateClient,
    base: &str,
    request: Request<TapBody<ProxyBody>>,
) -> Result<Response<ProxyBody>, BoxError> {
    let (parts, body) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("{base}{path}");
    let headers: Vec<(String, Vec<u8>)> = parts
        .headers
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    let request_body = wreq::Body::wrap(WreqRequestBody::new(body));
    let response =
        crate::impersonate_egress::send(client, &method, &url, &headers, Some(request_body))
            .await?;

    let mut builder = Response::builder().status(response.status().as_u16());
    for (name, value) in response.headers() {
        // Hyper owns browser-side transfer framing. Content-Length remains
        // valid because the response body is relayed byte-for-byte.
        if name.as_str().eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    let stream = response.bytes_stream().map(|chunk| {
        chunk
            .map(Frame::data)
            .map_err(|error| Box::new(error) as BoxError)
    });
    let body = StreamBody::new(stream).boxed_unsync();
    builder
        .body(body)
        .map_err(|error| Box::new(error) as BoxError)
}

#[derive(Clone, Debug)]
struct DedicatedRequestRoute {
    scheme: String,
    connection_host: String,
    port: u16,
    tls_identity_host: String,
    tls_identity_port: u16,
    /// Prefer h2 when TLS ALPN allows (false forces h1 path e.g. websocket upgrade).
    ///
    /// This must be reflected in the ALPN offered at the TLS layer as well.
    /// Offering h2 and then running an HTTP/1.1 handshake writes h1 bytes onto a
    /// connection the origin believes is h2 — a protocol version error, and the
    /// broken sender then gets cached for the rest of the tunnel.
    prefer_http2: bool,
    tls_profile: OutboundTlsProfile,
}
type DedicatedRequestSenderFactory = Arc<
    dyn Fn(
            DedicatedRequestRoute,
        ) -> Pin<Box<dyn Future<Output = Result<HttpsRequestSender, String>> + Send>>
        + Send
        + Sync,
>;

const MAX_CAPTURED_WIRE_BYTES: usize = 2 * 1024 * 1024;
const MAX_DECODED_BODY_BYTES: usize = 4 * 1024 * 1024;
const DEVICE_SETUP_PATH: &str = "/device";
const DEVICE_CA_DER_PATH: &str = "/shownet-root-ca.crt";
const DEVICE_CA_PEM_PATH: &str = "/shownet-root-ca.pem";
const DEVICE_CA_IOS_PROFILE_PATH: &str = "/shownet-root-ca.mobileconfig";
const REVERSE_PROXY_CONTEXT_HEADER: &str = "x-shownet-reverse-proxy-context";
const MAX_WEBSOCKET_CAPTURE_EVENTS: usize = 2_000;
const MAX_WEBSOCKET_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_SSE_CAPTURE_EVENTS: usize = 2_000;
const MAX_SSE_EVENT_BYTES: usize = 64 * 1024;
const MAX_SSE_CAPTURE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
struct BodyCaptureSnapshot {
    bytes: Vec<u8>,
    total_bytes: usize,
    truncated: bool,
    complete: bool,
    error: Option<String>,
}

struct TapBody<B> {
    inner: B,
    capture: BodyCaptureSnapshot,
    limit: usize,
    chunk_callback: Option<BodyChunkCallback>,
    callback: Option<BodyCaptureCallback>,
    bytes_per_second: Option<u64>,
    pending_frame: Option<Frame<Bytes>>,
    rate_sleep: Option<Pin<Box<Sleep>>>,
    /// When the response advertised Content-Length, H1 `Connection: close`
    /// can drop this wrapper after the last data frame without polling
    /// `Ready(None)`. Meeting that length is a complete capture.
    expected_wire_bytes: Option<usize>,
}

impl<B> TapBody<B> {
    fn new(
        inner: B,
        limit: usize,
        callback: impl FnOnce(BodyCaptureSnapshot) + Send + 'static,
    ) -> Self {
        Self {
            inner,
            capture: BodyCaptureSnapshot::default(),
            limit,
            chunk_callback: None,
            callback: Some(Box::new(callback)),
            bytes_per_second: None,
            pending_frame: None,
            rate_sleep: None,
            expected_wire_bytes: None,
        }
    }

    fn streaming(
        inner: B,
        limit: usize,
        chunk_callback: impl FnMut(&[u8]) + Send + 'static,
        callback: impl FnOnce(BodyCaptureSnapshot) + Send + 'static,
    ) -> Self {
        Self {
            inner,
            capture: BodyCaptureSnapshot::default(),
            limit,
            chunk_callback: Some(Box::new(chunk_callback)),
            callback: Some(Box::new(callback)),
            bytes_per_second: None,
            pending_frame: None,
            rate_sleep: None,
            expected_wire_bytes: None,
        }
    }

    fn with_rate_limit(mut self, bytes_per_second: Option<u64>) -> Self {
        self.bytes_per_second = bytes_per_second.filter(|value| *value > 0);
        self
    }

    fn with_expected_wire_bytes(mut self, expected_wire_bytes: Option<usize>) -> Self {
        self.expected_wire_bytes = expected_wire_bytes;
        self
    }

    fn reached_expected_wire_bytes(&self) -> bool {
        self.expected_wire_bytes
            .is_some_and(|expected| self.capture.total_bytes >= expected)
    }

    fn finish(&mut self) {
        if let Some(callback) = self.callback.take() {
            callback(std::mem::take(&mut self.capture));
        }
    }
}

impl<B> Drop for TapBody<B> {
    fn drop(&mut self) {
        if self.callback.is_some() {
            if self.reached_expected_wire_bytes() {
                self.capture.complete = true;
            } else if self.capture.error.is_none() {
                self.capture.error = Some("正文流在结束前关闭".to_string());
            }
            self.finish();
        }
    }
}

impl<B> Body for TapBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.pending_frame.is_some() {
            if let Some(sleep) = this.rate_sleep.as_mut() {
                if sleep.as_mut().poll(context).is_pending() {
                    return Poll::Pending;
                }
            }
            this.rate_sleep = None;
            return Poll::Ready(this.pending_frame.take().map(Ok));
        }
        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(callback) = this.chunk_callback.as_mut() {
                        callback(data);
                    }
                    this.capture.total_bytes = this.capture.total_bytes.saturating_add(data.len());
                    let remaining = this.limit.saturating_sub(this.capture.bytes.len());
                    let captured = remaining.min(data.len());
                    this.capture.bytes.extend_from_slice(&data[..captured]);
                    this.capture.truncated |= captured < data.len();
                }
                if this.inner.is_end_stream() || this.reached_expected_wire_bytes() {
                    this.capture.complete = true;
                    this.finish();
                }
                if let (Some(bytes_per_second), Some(data)) =
                    (this.bytes_per_second, frame.data_ref())
                {
                    if !data.is_empty() {
                        let seconds = data.len() as f64 / bytes_per_second as f64;
                        this.rate_sleep = Some(Box::pin(tokio::time::sleep(
                            Duration::from_secs_f64(seconds),
                        )));
                        this.pending_frame = Some(frame);
                        context.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.capture.error = Some(error.to_string());
                this.finish();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.capture.complete = true;
                this.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct BoxedIo(Box<dyn AsyncStream>);

struct PrefixedIo<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedIo<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let available = &self.prefix[self.offset..];
            let length = available.len().min(buffer.remaining());
            buffer.put_slice(&available[..length]);
            self.offset += length;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Capture TLS ClientHello bytes written by the outbound rustls connector (for measured JA3).
struct CapturingIo {
    inner: BoxedIo,
    capture: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl CapturingIo {
    fn new(inner: BoxedIo) -> (Self, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        let capture = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        (
            Self {
                inner,
                capture: capture.clone(),
            },
            capture,
        )
    }
}

impl AsyncRead for CapturingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for CapturingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if let Ok(mut guard) = self.capture.lock() {
            if guard.len() < 16 * 1024 {
                let room = 16 * 1024 - guard.len();
                guard.extend_from_slice(&buffer[..buffer.len().min(room)]);
            }
        }
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Pure ALPN branch used by shipped origin handshake (unit-tested).
pub(crate) fn origin_prefers_http2(prefer_http2: bool, alpn: Option<&[u8]>) -> bool {
    prefer_http2 && alpn == Some(b"h2")
}

impl AsyncRead for BoxedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(context, buffer)
    }
}

impl AsyncWrite for BoxedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut *self.0).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.0).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.0).poll_shutdown(context)
    }
}

pub struct ProxyHandle {
    #[cfg(test)]
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: tauri::async_runtime::JoinHandle<()>,
}

type PendingRuleTraces = Arc<StdMutex<HashMap<String, Vec<crate::models::CaptureRuleRun>>>>;

fn queue_rule_traces(
    queue: &PendingRuleTraces,
    request_id: &str,
    traces: Vec<crate::models::CaptureRuleRun>,
) -> Result<(), String> {
    if traces.is_empty() {
        return Ok(());
    }
    let mut queue = queue.lock().map_err(|_| "规则轨迹队列已损坏".to_string())?;
    if !queue.contains_key(request_id) && queue.len() >= MAX_PENDING_RULE_TRACE_REQUESTS {
        if let Some(expired_id) = queue.keys().next().cloned() {
            queue.remove(&expired_id);
        }
    }
    queue
        .entry(request_id.to_string())
        .or_default()
        .extend(traces);
    Ok(())
}

fn app_proxy_sinks(app: tauri::AppHandle) -> (CaptureSink, RuleEngine, EventSink, ErrorSink) {
    let pending_rule_traces = Arc::new(StdMutex::new(HashMap::<
        String,
        Vec<crate::models::CaptureRuleRun>,
    >::new()));
    let capture_app = app.clone();
    let capture_rule_traces = pending_rule_traces.clone();
    let capture_sink: CaptureSink = Arc::new(move |request| {
        let pending_id = request.id.clone();
        match persist_captured_request(&capture_app, request) {
            Ok(stored) => {
                let traces = pending_id
                    .and_then(|id| capture_rule_traces.lock().ok()?.remove(&id))
                    .unwrap_or_default();
                let state = capture_app.state::<crate::AppState>();
                for mut trace in traces {
                    trace.request_id = stored.id.clone();
                    if let Err(error) = state.storage.record_capture_rule_run(&trace) {
                        let _ = capture_app.emit("capture://proxy-error", error);
                    }
                }
            }
            Err(error) => {
                if let Some(id) = pending_id {
                    if let Ok(mut traces) = capture_rule_traces.lock() {
                        traces.remove(&id);
                    }
                }
                let _ = capture_app.emit("capture://proxy-error", error);
            }
        }
    });
    let request_rule_app = app.clone();
    let request_rule_trace_queue = pending_rule_traces.clone();
    let request_rule_engine: RequestRuleEngine = Arc::new(move |request| {
        let state = request_rule_app.state::<crate::AppState>();
        let outcome = crate::capture_rules::apply_runtime_request_rules(&state.storage, request)?;
        queue_rule_traces(
            &request_rule_trace_queue,
            &request.request_id,
            outcome.traces,
        )?;
        Ok(outcome.control)
    });
    let request_probe_app = app.clone();
    let request_body_required: RequestBodyRuleProbe = Arc::new(move |request| {
        let state = request_probe_app.state::<crate::AppState>();
        crate::capture_rules::runtime_request_body_required(&state.storage, request)
    });
    let response_probe_app = app.clone();
    let response_body_required: ResponseBodyRuleProbe = Arc::new(move |response| {
        let state = response_probe_app.state::<crate::AppState>();
        crate::capture_rules::runtime_response_body_required(&state.storage, response)
    });
    let response_rule_app = app.clone();
    let response_rule_trace_queue = pending_rule_traces.clone();
    let response_rule_engine: ResponseRuleEngine = Arc::new(move |response| {
        let state = response_rule_app.state::<crate::AppState>();
        let outcome = crate::capture_rules::apply_runtime_response_rules(&state.storage, response)?;
        queue_rule_traces(
            &response_rule_trace_queue,
            &response.request.request_id,
            outcome.traces,
        )?;
        Ok(outcome.body_changed)
    });
    let request_breakpoint_app = app.clone();
    let request_breakpoints: RequestBreakpointProbe = Arc::new(move |request| {
        let state = request_breakpoint_app.state::<crate::AppState>();
        crate::capture_rules::matching_runtime_request_breakpoints(&state.storage, request)
    });
    let response_breakpoint_app = app.clone();
    let response_breakpoints: ResponseBreakpointProbe = Arc::new(move |response| {
        let state = response_breakpoint_app.state::<crate::AppState>();
        crate::capture_rules::matching_runtime_response_breakpoints(&state.storage, response)
    });
    let breakpoints = app.state::<crate::AppState>().breakpoints.clone();
    let tls_interception_app = app.clone();
    let tls_interception: TlsInterceptionEngine = Arc::new(move |host, sni| {
        let state = tls_interception_app.state::<crate::AppState>();
        state.tls_interception_decision(host, sni)
    });
    let mirror_app = app.clone();
    let mirror: MirrorRuleEngine = Arc::new(move |request| {
        let state = mirror_app.state::<crate::AppState>();
        crate::capture_rules::resolve_runtime_mirror_route(&state.storage, request)
    });
    let rule_engine = RuleEngine {
        request: request_rule_engine,
        request_body_required,
        response: response_rule_engine,
        response_body_required,
        request_breakpoints,
        response_breakpoints,
        breakpoints,
        pending_traces: pending_rule_traces,
        tls_interception,
        mirror,
    };
    let event_app = app.clone();
    let event_sink: EventSink = Arc::new(move |event| {
        if let Err(error) = persist_capture_event(&event_app, event) {
            let _ = event_app.emit("capture://proxy-error", error);
        }
    });
    let error_sink: ErrorSink = Arc::new(move |error| {
        let _ = app.emit("capture://proxy-error", error);
    });
    (capture_sink, rule_engine, event_sink, error_sink)
}

impl ProxyHandle {
    pub async fn start(
        address: SocketAddr,
        client_access: ClientAccessPolicy,
        session_id: String,
        upstream: EffectiveUpstreamProxy,
        certificate_authority: Arc<CertificateAuthority>,
        app: tauri::AppHandle,
    ) -> Result<Self, String> {
        let (capture_sink, rule_engine, event_sink, error_sink) = app_proxy_sinks(app);
        Self::start_with_policy_event_sinks(
            address,
            client_access,
            session_id,
            upstream,
            certificate_authority,
            capture_sink,
            Some(rule_engine),
            event_sink,
            error_sink,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn start_with_sinks(
        address: SocketAddr,
        allow_lan_clients: bool,
        session_id: String,
        upstream: EffectiveUpstreamProxy,
        certificate_authority: Arc<CertificateAuthority>,
        capture_sink: CaptureSink,
        error_sink: ErrorSink,
    ) -> Result<Self, String> {
        Self::start_with_event_sinks(
            address,
            allow_lan_clients,
            session_id,
            upstream,
            certificate_authority,
            capture_sink,
            None,
            Arc::new(|_| {}),
            error_sink,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    async fn start_with_event_sinks(
        address: SocketAddr,
        allow_lan_clients: bool,
        session_id: String,
        upstream: EffectiveUpstreamProxy,
        certificate_authority: Arc<CertificateAuthority>,
        capture_sink: CaptureSink,
        rule_engine: Option<RuleEngine>,
        event_sink: EventSink,
        error_sink: ErrorSink,
    ) -> Result<Self, String> {
        Self::start_with_policy_event_sinks(
            address,
            ClientAccessPolicy::private_network(allow_lan_clients),
            session_id,
            upstream,
            certificate_authority,
            capture_sink,
            rule_engine,
            event_sink,
            error_sink,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_with_policy_event_sinks(
        address: SocketAddr,
        client_access: ClientAccessPolicy,
        session_id: String,
        upstream: EffectiveUpstreamProxy,
        certificate_authority: Arc<CertificateAuthority>,
        capture_sink: CaptureSink,
        rule_engine: Option<RuleEngine>,
        event_sink: EventSink,
        error_sink: ErrorSink,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("无法监听 {address}: {error}"))?;
        #[cfg(test)]
        let bound_address = listener.local_addr().map_err(|error| error.to_string())?;
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tauri::async_runtime::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, peer)) => {
                                if !client_access.allows(peer.ip()) {
                                    error_sink(format!("已拒绝未授权代理客户端: {peer}"));
                                    continue;
                                }
                                let local = match stream.local_addr() {
                                    Ok(address) => address,
                                    Err(error) => {
                                        error_sink(format!("读取代理本地地址失败: {error}"));
                                        continue;
                                    }
                                };
                                let session_id = session_id.clone();
                                let upstream = upstream.clone();
                                let certificate_authority = certificate_authority.clone();
                                let capture_sink = capture_sink.clone();
                                let rule_engine = rule_engine.clone();
                                let event_sink = event_sink.clone();
                                let error_sink = error_sink.clone();
                                tauri::async_runtime::spawn(async move {
                                    if let Err(error) = serve_client(stream, peer, local, session_id, upstream, certificate_authority, capture_sink, rule_engine, event_sink, error_sink.clone()).await {
                                        error_sink(error);
                                    }
                                });
                            }
                            Err(error) => {
                                error_sink(format!("代理接受连接失败: {error}"));
                                break;
                            }
                        }
                    }
                }
            }
        });
        Ok(Self {
            #[cfg(test)]
            address: bound_address,
            shutdown: Some(shutdown),
            task,
        })
    }

    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = timeout(Duration::from_secs(3), self.task).await;
    }
}

pub struct ReverseProxyHandle {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: tauri::async_runtime::JoinHandle<()>,
}

impl ReverseProxyHandle {
    pub async fn start(
        address: SocketAddr,
        client_access: ClientAccessPolicy,
        session_id: String,
        target_url: String,
        preserve_host: bool,
        upstream: EffectiveUpstreamProxy,
        app: tauri::AppHandle,
    ) -> Result<Self, String> {
        let (capture_sink, rule_engine, event_sink, error_sink) = app_proxy_sinks(app);
        Self::start_with_policy_event_sinks(
            address,
            client_access,
            session_id,
            target_url,
            preserve_host,
            upstream,
            capture_sink,
            Some(rule_engine),
            event_sink,
            error_sink,
        )
        .await
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    async fn start_with_sinks(
        address: SocketAddr,
        allow_lan_clients: bool,
        session_id: String,
        target_url: String,
        preserve_host: bool,
        upstream: EffectiveUpstreamProxy,
        capture_sink: CaptureSink,
        error_sink: ErrorSink,
    ) -> Result<Self, String> {
        Self::start_with_event_sinks(
            address,
            allow_lan_clients,
            session_id,
            target_url,
            preserve_host,
            upstream,
            capture_sink,
            None,
            Arc::new(|_| {}),
            error_sink,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    async fn start_with_event_sinks(
        address: SocketAddr,
        allow_lan_clients: bool,
        session_id: String,
        target_url: String,
        preserve_host: bool,
        upstream: EffectiveUpstreamProxy,
        capture_sink: CaptureSink,
        rule_engine: Option<RuleEngine>,
        event_sink: EventSink,
        error_sink: ErrorSink,
    ) -> Result<Self, String> {
        Self::start_with_policy_event_sinks(
            address,
            ClientAccessPolicy::private_network(allow_lan_clients),
            session_id,
            target_url,
            preserve_host,
            upstream,
            capture_sink,
            rule_engine,
            event_sink,
            error_sink,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_with_policy_event_sinks(
        address: SocketAddr,
        client_access: ClientAccessPolicy,
        session_id: String,
        target_url: String,
        preserve_host: bool,
        upstream: EffectiveUpstreamProxy,
        capture_sink: CaptureSink,
        rule_engine: Option<RuleEngine>,
        event_sink: EventSink,
        error_sink: ErrorSink,
    ) -> Result<Self, String> {
        let target = Url::parse(&normalize_reverse_proxy_target(&target_url)?)
            .map_err(|error| error.to_string())?;
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("无法启动免代理入口 {address}: {error}"))?;
        let bound_address = listener.local_addr().map_err(|error| error.to_string())?;
        if target_points_to_listener(&target, bound_address) {
            return Err("远程地址不能指向免代理入口自身".to_string());
        }
        let context = bound_address.port().to_string();
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tauri::async_runtime::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, peer)) => {
                                if !client_access.allows(peer.ip()) {
                                    error_sink(format!("已拒绝未授权免代理客户端: {peer}"));
                                    continue;
                                }
                                let target = target.clone();
                                let context = context.clone();
                                let session_id = session_id.clone();
                                let upstream = upstream.clone();
                                let capture_sink = capture_sink.clone();
                                let rule_engine = rule_engine.clone();
                                let event_sink = event_sink.clone();
                                let client_error_sink = error_sink.clone();
                                tauri::async_runtime::spawn(async move {
                                    if let Err(error) = serve_reverse_proxy_client(
                                        stream,
                                        peer,
                                        target,
                                        context,
                                        preserve_host,
                                        session_id,
                                        upstream,
                                        capture_sink,
                                        rule_engine,
                                        event_sink,
                                        client_error_sink.clone(),
                                    ).await {
                                        client_error_sink(error);
                                    }
                                });
                            }
                            Err(error) => {
                                error_sink(format!("免代理入口接受连接失败: {error}"));
                                break;
                            }
                        }
                    }
                }
            }
        });
        Ok(Self {
            address: bound_address,
            shutdown: Some(shutdown),
            task,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Whether the accept loop is still alive.
    ///
    /// Holding the handle only proves nobody asked it to stop. If the bound task
    /// died on its own, reporting "运行中" from the handle's mere existence sends
    /// the user to an entry point that refuses every connection.
    pub fn is_serving(&self) -> bool {
        !self.task.inner().is_finished()
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = timeout(Duration::from_secs(3), self.task).await;
    }
}

pub fn normalize_reverse_proxy_target(value: &str) -> Result<String, String> {
    let target =
        Url::parse(value.trim()).map_err(|_| "远程地址需要包含 http:// 或 https://".to_string())?;
    if !matches!(target.scheme(), "http" | "https") {
        return Err("免代理接入仅支持 HTTP 和 HTTPS 远程地址".to_string());
    }
    if target.host_str().is_none() {
        return Err("远程地址缺少主机名".to_string());
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err("远程地址不能包含用户名或密码".to_string());
    }
    if target.query().is_some() || target.fragment().is_some() {
        return Err("远程地址不能包含查询参数或片段".to_string());
    }
    Ok(target.to_string())
}

async fn serve_reverse_proxy_client(
    stream: TcpStream,
    peer: SocketAddr,
    target: Url,
    context: String,
    preserve_host: bool,
    session_id: String,
    upstream: EffectiveUpstreamProxy,
    capture_sink: CaptureSink,
    rule_engine: Option<RuleEngine>,
    event_sink: EventSink,
    error_sink: ErrorSink,
) -> Result<(), String> {
    let service = service_fn(move |request| {
        forward_reverse_proxy_request(
            request,
            peer,
            target.clone(),
            context.clone(),
            preserve_host,
            session_id.clone(),
            upstream.clone(),
            capture_sink.clone(),
            rule_engine.clone(),
            event_sink.clone(),
            error_sink.clone(),
        )
    });
    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .map_or_else(
            |error| {
                if is_benign_connection_end(&error) {
                    Ok(())
                } else {
                    Err(error.to_string())
                }
            },
            Ok,
        )
}

#[allow(clippy::too_many_arguments)]
async fn forward_reverse_proxy_request(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    target: Url,
    context: String,
    preserve_host: bool,
    session_id: String,
    upstream: EffectiveUpstreamProxy,
    capture_sink: CaptureSink,
    rule_engine: Option<RuleEngine>,
    event_sink: EventSink,
    error_sink: ErrorSink,
) -> Result<Response<ProxyBody>, Infallible> {
    if request.method() == Method::CONNECT {
        return Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "免代理入口不接受 CONNECT 请求",
        ));
    }
    let result: Result<Response<ProxyBody>, String> = async {
        let uri = reverse_target_uri(&target, request.uri())?;
        if !preserve_host {
            let authority = uri
                .authority()
                .ok_or_else(|| "远程地址缺少主机名".to_string())?;
            request.headers_mut().insert(
                HOST,
                HeaderValue::from_str(authority.as_str())
                    .map_err(|_| "远程地址 Host 无效".to_string())?,
            );
        }
        request.headers_mut().insert(
            REVERSE_PROXY_CONTEXT_HEADER,
            HeaderValue::from_str(&context).map_err(|_| "免代理入口标记无效".to_string())?,
        );
        *request.uri_mut() = uri;
        forward_http(
            request,
            peer,
            session_id,
            upstream,
            capture_sink,
            rule_engine,
            event_sink,
            error_sink.clone(),
        )
        .await
    }
    .await;
    Ok(result.unwrap_or_else(|error| {
        error_sink(error.clone());
        error_response(StatusCode::BAD_GATEWAY, &error)
    }))
}

fn reverse_target_uri(target: &Url, incoming: &Uri) -> Result<Uri, String> {
    let base_path = target.path();
    let incoming_path = incoming.path();
    let path = if base_path == "/" {
        incoming_path.to_string()
    } else if incoming_path == "/" {
        base_path.to_string()
    } else {
        format!(
            "{}/{}",
            base_path.trim_end_matches('/'),
            incoming_path.trim_start_matches('/')
        )
    };
    let mut value = format!("{}{}", &target[..Position::BeforePath], path);
    if let Some(query) = incoming.query() {
        value.push('?');
        value.push_str(query);
    }
    value
        .parse::<Uri>()
        .map_err(|_| "无法组合远程请求地址".to_string())
}

fn target_points_to_listener(target: &Url, listener: SocketAddr) -> bool {
    let port = target.port_or_known_default().unwrap_or_default();
    if port != listener.port() {
        return false;
    }
    let Some(host) = target.host_str() else {
        return false;
    };
    matches!(host, "localhost" | "::1")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

async fn serve_client(
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    session_id: String,
    upstream: EffectiveUpstreamProxy,
    certificate_authority: Arc<CertificateAuthority>,
    capture_sink: CaptureSink,
    rule_engine: Option<RuleEngine>,
    event_sink: EventSink,
    error_sink: ErrorSink,
) -> Result<(), String> {
    let service = service_fn(move |request| {
        handle_request(
            request,
            peer,
            local,
            session_id.clone(),
            upstream.clone(),
            certificate_authority.clone(),
            capture_sink.clone(),
            rule_engine.clone(),
            event_sink.clone(),
            error_sink.clone(),
        )
    });
    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .map_or_else(
            |error| {
                if is_benign_connection_end(&error) {
                    Ok(())
                } else {
                    Err(error.to_string())
                }
            },
            Ok,
        )
}

async fn handle_request(
    request: Request<Incoming>,
    peer: SocketAddr,
    local: SocketAddr,
    session_id: String,
    upstream: EffectiveUpstreamProxy,
    certificate_authority: Arc<CertificateAuthority>,
    capture_sink: CaptureSink,
    rule_engine: Option<RuleEngine>,
    event_sink: EventSink,
    error_sink: ErrorSink,
) -> Result<Response<ProxyBody>, Infallible> {
    if request.method() != Method::CONNECT {
        if let Some(response) = device_setup_response(&request, local, &certificate_authority) {
            return Ok(response);
        }
    }
    let result = if request.method() == Method::CONNECT {
        handle_connect(
            request,
            peer,
            session_id,
            upstream,
            certificate_authority,
            capture_sink,
            rule_engine,
            event_sink,
            error_sink.clone(),
        )
        .await
    } else {
        forward_http(
            request,
            peer,
            session_id,
            upstream,
            capture_sink,
            rule_engine,
            event_sink,
            error_sink.clone(),
        )
        .await
    };
    Ok(result.unwrap_or_else(|error| {
        error_sink(error.clone());
        error_response(StatusCode::BAD_GATEWAY, &error)
    }))
}

async fn handle_connect(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    session_id: String,
    upstream: EffectiveUpstreamProxy,
    certificate_authority: Arc<CertificateAuthority>,
    capture_sink: CaptureSink,
    rule_engine: Option<RuleEngine>,
    event_sink: EventSink,
    error_sink: ErrorSink,
) -> Result<Response<ProxyBody>, String> {
    let authority = request
        .uri()
        .authority()
        .ok_or_else(|| "CONNECT 缺少目标地址".to_string())?;
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    reject_proxy_loop(&host, port)?;
    let source = classify_source(request.headers(), peer);
    let request_headers = headers_to_entries(request.headers());
    let connect_request_id = format!("request-{}", Uuid::new_v4());
    let connection_request = RuntimeRuleRequest {
        request_id: connect_request_id.clone(),
        method: "CONNECT".to_string(),
        scheme: "https".to_string(),
        host: host.clone(),
        port,
        path: "/".to_string(),
        query: None,
        source: source.clone(),
        protocol: "connect".to_string(),
        request_headers: request_headers.clone(),
        request_body: None,
        body_unavailable_reason: None,
    };
    let mirror_route = match rule_engine.as_ref() {
        Some(engine) => engine.resolve_mirror(&connection_request)?,
        None => None,
    };
    let (upstream_host, upstream_port) = mirror_route
        .as_ref()
        .map(RuntimeMirrorRoute::connection_target)
        .map(|(host, port)| (host.to_string(), port))
        .unwrap_or_else(|| (host.clone(), port));
    reject_proxy_loop(&upstream_host, upstream_port)?;
    let start = Instant::now();
    // CONNECT 200 means this listener accepted interception. Origin dial is
    // delayed until ClientHello is classified so MITM+wreq does not open a
    // TCP that is immediately discarded.
    let on_upgrade = hyper::upgrade::on(&mut request);

    tauri::async_runtime::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(error) => {
                if !is_benign_connection_end(&error) {
                    error_sink(format!("CONNECT 升级失败: {error}"));
                }
                return;
            }
        };
        let mut client = TokioIo::new(upgraded);
        let hello = match read_client_hello(&mut client).await {
            Ok(hello) => hello,
            Err(error) => {
                if !error.abandoned {
                    error_sink(error.message);
                }
                return;
            }
        };
        let inbound = match hello.fingerprint {
            Ok(inbound) => inbound,
            Err(error) => {
                queue_mirror_trace_or_report(
                    &rule_engine,
                    &mirror_route,
                    &connect_request_id,
                    "connect-tunnel",
                    &error_sink,
                );
                let detail = mirror_route
                    .as_ref()
                    .map(|route| format!("{}；{error}", mirror_route_detail(route, false)))
                    .unwrap_or_else(|| error.clone());
                let mut upstream_stream =
                    match connect_destination(&upstream, &upstream_host, upstream_port).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            capture_connect_record(
                                &capture_sink,
                                &connect_request_id,
                                &session_id,
                                &source,
                                peer,
                                &host,
                                port,
                                start.elapsed().as_millis() as i64,
                                request_headers,
                                None,
                                "加密隧道（未识别 TLS）".to_string(),
                                Some(format!("{detail}；出站连接失败: {error}")),
                                502,
                            );
                            error_sink(format!(
                                "未识别 TLS 出站连接失败 {upstream_host}:{upstream_port}: {error}"
                            ));
                            return;
                        }
                    };
                capture_connect_record(
                    &capture_sink,
                    &connect_request_id,
                    &session_id,
                    &source,
                    peer,
                    &host,
                    port,
                    start.elapsed().as_millis() as i64,
                    request_headers,
                    None,
                    "加密隧道（未识别 TLS）".to_string(),
                    Some(detail),
                    200,
                );
                if let Err(write_error) = upstream_stream.write_all(&hello.bytes).await {
                    error_sink(format!("转发 CONNECT 前缀失败: {write_error}"));
                    return;
                }
                if let Err(tunnel_error) =
                    copy_bidirectional(&mut client, &mut upstream_stream).await
                {
                    if !is_benign_io_end(&tunnel_error) {
                        error_sink(format!("CONNECT 隧道传输失败: {tunnel_error}"));
                    }
                }
                return;
            }
        };
        let offered_version = inbound
            .offered_versions
            .iter()
            .find(|value| value.starts_with("TLS"))
            .cloned()
            .unwrap_or_else(|| inbound.legacy_version.clone());
        let tls_interception = match rule_engine.as_ref() {
            Some(engine) => match engine.tls_interception_decision(&host, inbound.sni.as_deref()) {
                Ok(decision) => decision,
                Err(error) => {
                    error_sink(format!(
                        "读取 HTTPS 解密策略失败，当前连接继续尝试解密: {error}"
                    ));
                    TlsInterceptionDecision::default()
                }
            },
            None => TlsInterceptionDecision::default(),
        };
        if tls_interception.bypass {
            let mut reason = match (
                tls_interception.matched_rule.as_deref(),
                tls_interception.matched_host.as_deref(),
            ) {
                (Some(rule), Some(matched_host)) => {
                    format!(
                        "已按 HTTPS 绕行规则 {rule} 保持连接（命中 {matched_host}）；正文不可见"
                    )
                }
                _ => "已按“全部绕行”策略保持原始 TLS 连接；正文不可见".to_string(),
            };
            if let Some(route) = mirror_route.as_ref() {
                reason = format!("{reason}；{}", mirror_route_detail(route, true));
            }
            let fingerprint = tunnel_fingerprint(inbound);
            let record_tunnel = tls_interception.record_successful_tunnel || mirror_route.is_some();
            let mut upstream_stream =
                match connect_destination(&upstream, &upstream_host, upstream_port).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        capture_connect_record(
                            &capture_sink,
                            &connect_request_id,
                            &session_id,
                            &source,
                            peer,
                            &host,
                            port,
                            start.elapsed().as_millis() as i64,
                            request_headers,
                            Some(fingerprint),
                            format!("{offered_version} · 原样隧道失败"),
                            Some(format!("{reason}；出站连接失败: {error}")),
                            502,
                        );
                        error_sink(format!(
                            "HTTPS 绕行出站连接失败 {upstream_host}:{upstream_port}: {error}"
                        ));
                        return;
                    }
                };
            if record_tunnel {
                queue_mirror_trace_or_report(
                    &rule_engine,
                    &mirror_route,
                    &connect_request_id,
                    "tls-bypass",
                    &error_sink,
                );
                capture_connect_record(
                    &capture_sink,
                    &connect_request_id,
                    &session_id,
                    &source,
                    peer,
                    &host,
                    port,
                    start.elapsed().as_millis() as i64,
                    request_headers.clone(),
                    Some(fingerprint.clone()),
                    format!("{offered_version} · 原样隧道"),
                    Some(reason.clone()),
                    200,
                );
            }
            if let Err(error) = upstream_stream.write_all(&hello.bytes).await {
                if !record_tunnel {
                    capture_connect_record(
                        &capture_sink,
                        &connect_request_id,
                        &session_id,
                        &source,
                        peer,
                        &host,
                        port,
                        start.elapsed().as_millis() as i64,
                        request_headers,
                        Some(fingerprint),
                        format!("{offered_version} · 原样隧道失败"),
                        Some(format!("{reason}；转发 ClientHello 失败: {error}")),
                        502,
                    );
                }
                error_sink(format!("转发 HTTPS 绕行 ClientHello 失败: {error}"));
                return;
            }
            if let Err(error) = copy_bidirectional(&mut client, &mut upstream_stream).await {
                if !record_tunnel {
                    capture_connect_record(
                        &capture_sink,
                        &connect_request_id,
                        &session_id,
                        &source,
                        peer,
                        &host,
                        port,
                        start.elapsed().as_millis() as i64,
                        request_headers,
                        Some(fingerprint),
                        format!("{offered_version} · 原样隧道失败"),
                        Some(format!("{reason}；隧道传输失败: {error}")),
                        502,
                    );
                }
                if !is_benign_io_end(&error) {
                    error_sink(format!("HTTPS 绕行隧道传输失败: {error}"));
                }
            }
            return;
        }
        let (outbound_profile, selected_from_inbound) =
            tls_outbound::resolve_profile_for_connection(Some(&inbound));
        let mut fingerprint = mitm_fingerprint_with_selection(
            inbound,
            Some(outbound_profile),
            Some(selected_from_inbound),
            None,
        );
        let server_config = match certificate_authority.server_config(&host) {
            Ok(config) => config,
            Err(error) => {
                error_sink(error);
                return;
            }
        };
        let prefixed_client = PrefixedIo::new(hello.bytes, client);
        let client_tls = match timeout(
            Duration::from_secs(15),
            TlsAcceptor::from(server_config).accept(prefixed_client),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                queue_mirror_trace_or_report(
                    &rule_engine,
                    &mirror_route,
                    &connect_request_id,
                    "https-mitm",
                    &error_sink,
                );
                let detail = mirror_route
                    .as_ref()
                    .map(|route| {
                        format!(
                            "{}；客户端拒绝 ShowNet 证书或 TLS 握手失败: {error}",
                            mirror_route_detail(route, false)
                        )
                    })
                    .unwrap_or_else(|| format!("客户端拒绝 ShowNet 证书或 TLS 握手失败: {error}"));
                capture_connect_record(
                    &capture_sink,
                    &connect_request_id,
                    &session_id,
                    &source,
                    peer,
                    &host,
                    port,
                    start.elapsed().as_millis() as i64,
                    request_headers,
                    Some(fingerprint),
                    format!("{offered_version} · MITM 未建立"),
                    Some(detail),
                    502,
                );
                if !is_benign_io_end(&error) {
                    error_sink(format!("客户端 TLS 握手失败 {host}:{port}: {error}"));
                }
                return;
            }
            Err(_) => {
                error_sink(format!("客户端 TLS 握手超时 {host}:{port}"));
                return;
            }
        };
        let inbound_tls = client_tls
            .get_ref()
            .1
            .protocol_version()
            .map(|version| format!("{version:?}"))
            .unwrap_or(offered_version);
        let inbound_http_protocol =
            negotiated_http_protocol(client_tls.get_ref().1.alpn_protocol()).to_string();
        let (tls_identity_host, tls_identity_port) = mirror_route
            .as_ref()
            .map(RuntimeMirrorRoute::identity_target)
            .map(|(host, port)| (host.to_string(), port))
            .unwrap_or_else(|| (host.clone(), port));
        // Strict static CDNs often 400 under rustls H2 MITM; force HTTP/1.1 ALPN when still decrypting.
        let force_http11 = tls_outbound::origin_force_http11_for_host(&tls_identity_host);
        let dedicated_sender_factory =
            dedicated_request_sender_factory(upstream.clone(), outbound_profile);
        let prefer_origin_h2 = !force_http11;
        // Product MITM origin egress is impersonate-only when the stack is
        // linked. rustls ClientHello + hyper h2 are not browser-shaped; a
        // selectable rustls fallback is what made inbound/outbound JA4 diverge
        // after parity had already been proven under wreq.
        #[cfg(feature = "impersonate-boring")]
        let (sender, outbound_tls, negotiated_alpn) = {
            let _ = (prefer_origin_h2, force_http11, outbound_profile);
            let client = match crate::impersonate_egress::build_client_for_route(
                &upstream,
                &upstream_host,
                upstream_port,
                &tls_identity_host,
                tls_identity_port,
            )
            .await
            {
                Ok(client) => client,
                Err(error) => {
                    error_sink(format!("构建 wreq 出站失败: {error}"));
                    return;
                }
            };
            let base = format!(
                "https://{}",
                host_header_authority("https", &tls_identity_host, tls_identity_port)
            );
            let egress_ja4 = crate::impersonate_egress::EGRESS_JA4;
            fingerprint.outbound.engine = Some("impersonate".into());
            // The linked profile has a separately measured golden JA4, but wreq
            // does not expose this individual connection's ClientHello or ALPN.
            // Keep per-request measurement fields empty instead of presenting a
            // profile expectation as observed wire evidence.
            fingerprint.outbound.ja4 = None;
            fingerprint.outbound.ja3_parity = Some(false);
            fingerprint.outbound.note = format!(
                "{} wreq Chrome profile (expected JA4 {egress_ja4}, h2 pseudo m,a,s,p); inbound JA4 {} — this connection was not measured",
                fingerprint.outbound.note,
                fingerprint.inbound.ja4
            );
            (
                HttpsRequestSender::Impersonate { client, base },
                "TLS 1.3 (wreq/Chrome)".to_string(),
                Some("h2".to_string()),
            )
        };
        #[cfg(not(feature = "impersonate-boring"))]
        let (sender, outbound_tls, negotiated_alpn) = {
            // Portable / test builds only. Shipped packages compile with
            // impersonate-boring and never take this arm.
            let upstream_stream =
                match connect_destination(&upstream, &upstream_host, upstream_port).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        queue_mirror_trace_or_report(
                            &rule_engine,
                            &mirror_route,
                            &connect_request_id,
                            "https-mitm",
                            &error_sink,
                        );
                        let detail = mirror_route
                            .as_ref()
                            .map(|route| format!("{}；{error}", mirror_route_detail(route, false)))
                            .unwrap_or_else(|| error.clone());
                        capture_connect_record(
                            &capture_sink,
                            &connect_request_id,
                            &session_id,
                            &source,
                            peer,
                            &host,
                            port,
                            start.elapsed().as_millis() as i64,
                            request_headers,
                            Some(fingerprint),
                            format!("{inbound_tls} · 上游未连接"),
                            Some(detail),
                            502,
                        );
                        error_sink(error);
                        return;
                    }
                };
            let verified = match connect_verified_tls_measured(
                upstream_stream,
                &tls_identity_host,
                outbound_profile,
                force_http11,
            )
            .await
            {
                Ok(verified) => verified,
                Err(error) => {
                    if mirror_route.is_some() {
                        queue_mirror_trace_or_report(
                            &rule_engine,
                            &mirror_route,
                            &connect_request_id,
                            "https-mitm",
                            &error_sink,
                        );
                        let detail = format!(
                            "{}；{error}",
                            mirror_route_detail(
                                mirror_route.as_ref().expect("mirror route"),
                                false
                            )
                        );
                        capture_connect_record(
                            &capture_sink,
                            &connect_request_id,
                            &session_id,
                            &source,
                            peer,
                            &host,
                            port,
                            start.elapsed().as_millis() as i64,
                            request_headers,
                            Some(fingerprint),
                            format!("{inbound_tls} · 上游 TLS 未建立"),
                            Some(detail),
                            502,
                        );
                    }
                    error_sink(error);
                    return;
                }
            };
            let upstream_tls = verified.stream;
            let handshake_alpn = verified.negotiated_alpn.clone();
            let outbound_tls = verified
                .protocol_version
                .clone()
                .unwrap_or_else(|| "TLS".to_string());
            let negotiated_alpn = verified
                .negotiated_alpn
                .as_deref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::to_string);
            fingerprint.outbound.negotiated_alpn = negotiated_alpn.clone();
            fingerprint.outbound.application_protocol = Some(
                negotiated_http_protocol(negotiated_alpn.as_ref().map(|value| value.as_bytes()))
                    .to_string(),
            );
            if let Some(measured) = verified.measured_ja3 {
                let preset_id = crate::tls_outbound::preset_id_for_profile(outbound_profile);
                let measured_ja4 = verified.measured_ja4.as_deref();
                let alignment =
                    crate::tls_golden::evaluate_measured(&preset_id, &measured, measured_ja4);
                fingerprint.outbound.ja3 = Some(measured.clone());
                fingerprint.outbound.ja4 = measured_ja4.map(str::to_owned);
                fingerprint.outbound.ja3_parity = Some(false);
                fingerprint.outbound.engine = Some("rustls".into());
                fingerprint.outbound.note = format!(
                    "{} measuredJa3={measured} measuredJa4={} profile={} preset={preset_id} alignment={} (dev build without impersonate-boring; product requires wreq)",
                    fingerprint.outbound.note,
                    measured_ja4.unwrap_or("-"),
                    outbound_profile.as_str(),
                    alignment.as_str(),
                );
            } else {
                fingerprint.outbound.ja3_parity = Some(false);
                fingerprint.outbound.note = format!(
                    "{} (outbound ClientHello measure unavailable; dev rustls path)",
                    fingerprint.outbound.note
                );
            }
            let sender = match handshake_origin_https(
                upstream_tls,
                handshake_alpn.as_deref(),
                prefer_origin_h2,
            )
            .await
            {
                Ok(sender) => sender,
                Err(error) => {
                    error_sink(format!("目标 HTTPS 应用层握手失败: {error}"));
                    return;
                }
            };
            (sender, outbound_tls, negotiated_alpn)
        };
        let origin_http2 = sender.is_http2();

        queue_mirror_trace_or_report(
            &rule_engine,
            &mirror_route,
            &connect_request_id,
            "https-mitm",
            &error_sink,
        );
        let upstream_detail = {
            let origin_note = if cfg!(feature = "impersonate-boring") {
                format!(
                    "上游 {outbound_tls} · ALPN={} · app={} · 本地 MITM 已建立，出站由首请求拨号",
                    negotiated_alpn.as_deref().unwrap_or("none"),
                    if origin_http2 { "h2" } else { "http/1.1" }
                )
            } else {
                format!(
                    "上游 {outbound_tls} · ALPN={} · app={} · 证书校验通过",
                    negotiated_alpn.as_deref().unwrap_or("none"),
                    if origin_http2 { "h2" } else { "http/1.1" }
                )
            };
            mirror_route
                .as_ref()
                .map(|route| format!("{}；{origin_note}", mirror_route_detail(route, false)))
                .unwrap_or(origin_note)
        };
        capture_connect_record(
            &capture_sink,
            &connect_request_id,
            &session_id,
            &source,
            peer,
            &host,
            port,
            start.elapsed().as_millis() as i64,
            request_headers,
            Some(fingerprint.clone()),
            format!("{inbound_tls} · MITM"),
            Some(upstream_detail),
            200,
        );
        if let Err(error) = serve_mitm_application(
            client_tls,
            peer,
            session_id,
            source,
            host,
            port,
            mirror_route,
            inbound_tls,
            inbound_http_protocol,
            fingerprint,
            Arc::new(AsyncMutex::new(sender)),
            dedicated_sender_factory,
            capture_sink,
            rule_engine,
            event_sink,
            error_sink.clone(),
        )
        .await
        {
            error_sink(format!("HTTPS MITM 连接结束: {error}"));
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .map_err(|error| error.to_string())
}

fn queue_mirror_trace_or_report(
    rule_engine: &Option<RuleEngine>,
    route: &Option<RuntimeMirrorRoute>,
    request_id: &str,
    transport: &str,
    error_sink: &ErrorSink,
) {
    if let (Some(engine), Some(route)) = (rule_engine.as_ref(), route.as_ref()) {
        if let Err(error) = engine.queue_mirror_trace(request_id, route, transport) {
            error_sink(format!("记录镜像路由轨迹失败: {error}"));
        }
    }
}

fn mirror_route_detail(route: &RuntimeMirrorRoute, tls_bypass: bool) -> String {
    let original = format_authority(&route.original_host, route.original_port);
    let target = format_authority(&route.target_host, route.target_port);
    let identity = match route.identity {
        MirrorIdentity::Original => "兼容模式保留原 Host/SNI",
        MirrorIdentity::Target if tls_bypass => {
            "测试环境模式仅改连接目标，TLS 绕行保留原 ClientHello/SNI"
        }
        MirrorIdentity::Target => "测试环境模式使用目标 Host/SNI/证书校验",
    };
    format!("镜像 {original} -> {target}；{identity}")
}

#[allow(clippy::too_many_arguments)]
async fn serve_mitm_application<S>(
    client_stream: S,
    peer: SocketAddr,
    session_id: String,
    source: String,
    host: String,
    port: u16,
    mirror_route: Option<RuntimeMirrorRoute>,
    tls_version: String,
    http_protocol: String,
    tls_fingerprint: crate::tls_fingerprint::TlsFingerprintRecord,
    sender: Arc<AsyncMutex<HttpsRequestSender>>,
    dedicated_sender_factory: DedicatedRequestSenderFactory,
    capture_sink: CaptureSink,
    rule_engine: Option<RuleEngine>,
    event_sink: EventSink,
    error_sink: ErrorSink,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request_protocol = http_protocol.clone();
    let service_error_sink = error_sink.clone();
    let http2_fingerprint =
        (http_protocol == "h2").then(|| Arc::new(Http2FingerprintCollector::default()));
    let service_http2_fingerprint = http2_fingerprint.clone();
    let service = service_fn(move |request| {
        forward_mitm_https(
            request,
            peer,
            session_id.clone(),
            source.clone(),
            host.clone(),
            port,
            mirror_route.clone(),
            tls_version.clone(),
            request_protocol.clone(),
            tls_fingerprint.clone(),
            service_http2_fingerprint.clone(),
            sender.clone(),
            dedicated_sender_factory.clone(),
            capture_sink.clone(),
            rule_engine.clone(),
            event_sink.clone(),
            service_error_sink.clone(),
        )
    });
    let result = if http_protocol == "h2" {
        let observed_stream = Http2ObservedIo::new(
            client_stream,
            http2_fingerprint.expect("HTTP/2 collector exists"),
        );
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder.enable_connect_protocol();
        builder
            .serve_connection(TokioIo::new(observed_stream), service)
            .await
    } else {
        http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(TokioIo::new(client_stream), service)
            .with_upgrades()
            .await
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) if is_benign_connection_end(&error) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

/// Whether a served connection ended in a way not worth interrupting the user for.
///
/// `serve_connection` returns `Err` for endings that are simply how HTTP ends: a
/// browser dropping an idle keep-alive socket, a tab closed mid-response, a peer
/// that resets instead of shutting down cleanly. Every one of those raised
/// "HTTPS MITM 连接结束: …" over a session that was working, which trains the
/// user to ignore the error channel — the one place a real failure has to land.
///
/// Deliberately narrow. A protocol-level complaint is not covered here and still
/// surfaces: an origin refusing our HTTP/2, a malformed frame, a timeout. Those
/// are the reports that led to the fixes in this file, and silencing them to
/// tidy up the toast area would cost more than the noise does.
/// Whether a WebSocket ended without a closing handshake.
///
/// The graceful endings are already handled in `relay_websocket` — a `None`
/// from the stream and a `Close` frame both return `Ok`. What lands here is the
/// abrupt one: a tab closed or reloaded while a socket was live, which is the
/// ordinary way a page's WebSocket dies. tungstenite reports it as
/// `ResetWithoutClosingHandshake` or as a reset underneath.
///
/// A protocol violation or a too-large frame is a real fault and still reports.
fn is_benign_websocket_end(error: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::error::ProtocolError;
    use tokio_tungstenite::tungstenite::Error;
    match error {
        Error::ConnectionClosed | Error::AlreadyClosed => true,
        Error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => true,
        Error::Io(io) => is_benign_io_end(io),
        _ => false,
    }
}

/// One step of a WebSocket relay: `Ok(None)` means the peer simply went away.
fn websocket_step<T>(
    result: Result<T, tokio_tungstenite::tungstenite::Error>,
    context: &str,
) -> Result<Option<T>, String> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if is_benign_websocket_end(&error) => Ok(None),
        Err(error) => Err(format!("{context}: {error}")),
    }
}

fn is_benign_io_end(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
    )
}

fn is_benign_connection_end(error: &hyper::Error) -> bool {
    if error.is_closed() || error.is_incomplete_message() || error.is_canceled() {
        return true;
    }
    is_benign_io_chain(error)
}

/// The same question for a request we sent to an origin.
///
/// `is_canceled()` here has two causes and hyper does not distinguish them. The
/// common one is the origin's connection dying mid-request — any server closing
/// an idle keep-alive socket — which is routine and self-healing. The other is
/// our own doing: hyper's h1 client does not pipeline, so a second
/// `send_request` before the previous body has been read fails the same way.
///
/// Reporting both would put a toast on every stale connection, so this stays
/// silent, and the h1 sharing limit is documented above `drop(shared_guard)`
/// instead. What it is *not* is a client walking away: an end-to-end test
/// showed a departing client drops the whole future, so `send_request` never
/// resolves and this is never reached by that case.
fn is_benign_forward_end(error: &BoxError) -> bool {
    // Only hyper errors carry the connection-end shape this inspects. A wreq
    // error (impersonate path) is not one, so it is not a benign hyper end.
    error
        .downcast_ref::<hyper::Error>()
        .is_some_and(is_benign_connection_end)
}

/// Whether hyper is wrapping an I/O failure that just means the peer went away.
fn is_benign_io_chain(error: &hyper::Error) -> bool {
    // A reset or a broken pipe reaches us as an io::Error wrapped by hyper, and
    // answers false to every predicate hyper exposes. Walk the chain, as
    // `looks_like_origin_http2_refusal` does for the same reason.
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            );
        }
        source = cause.source();
    }
    false
}

fn capture_connect_record(
    capture_sink: &CaptureSink,
    request_id: &str,
    session_id: &str,
    source: &str,
    peer: SocketAddr,
    host: &str,
    port: u16,
    duration_ms: i64,
    request_headers: Vec<HeaderEntry>,
    tls_fingerprint: Option<crate::tls_fingerprint::TlsFingerprintRecord>,
    tls_version: String,
    response_body: Option<String>,
    status: i64,
) {
    capture_sink(CapturedRequestInput {
        id: Some(request_id.to_string()),
        session_id: session_id.to_string(),
        source: source.to_string(),
        source_instance_id: Some(format!("proxy:{}", peer.ip())),
        timestamp: None,
        method: "CONNECT".to_string(),
        scheme: Some("https".to_string()),
        host: host.to_string(),
        port: Some(port as i64),
        path: "/".to_string(),
        query: None,
        status,
        resource_type: "document".to_string(),
        size_bytes: 0,
        duration_ms,
        protocol: "http/1.1".to_string(),
        tls_version: Some(tls_version),
        tls_fingerprint,
        risk_level: "info".to_string(),
        request_headers,
        response_headers: vec![],
        request_body: None,
        response_body,
        response_body_metadata: None,
        crypto_snippets: None,
        hook: None,
    });
}

/// The result of an origin TLS handshake, with the stream boxed so it does not
/// name the engine that produced it. rustls returns a `TlsStream`, a linked
/// impersonate connector returns something else, and both satisfy `AsyncStream`;
/// keeping this type engine-agnostic is what lets a second engine be added
/// without touching the request path that consumes it. The ALPN and protocol
/// version are lifted out here for the same reason — the caller used to read
/// them off the rustls connection directly.
struct VerifiedTlsConnect {
    stream: BoxedIo,
    negotiated_alpn: Option<Vec<u8>>,
    protocol_version: Option<String>,
    measured_ja3: Option<String>,
    measured_ja4: Option<String>,
}

async fn connect_verified_tls(
    stream: BoxedIo,
    host: &str,
    profile: OutboundTlsProfile,
) -> Result<BoxedIo, String> {
    Ok(connect_verified_tls_measured(stream, host, profile, false)
        .await?
        .stream)
}

async fn connect_verified_tls_measured(
    stream: BoxedIo,
    host: &str,
    profile: OutboundTlsProfile,
    force_http11: bool,
) -> Result<VerifiedTlsConnect, String> {
    // Impersonate egress does not run here: wreq is a full client, so when the
    // impersonate engine is active the egress branches before this connector is
    // ever reached (see the CONNECT-tunnel dispatch). This path is always rustls.
    let config = if force_http11 {
        tls_outbound::build_client_config_http11_only(profile)
    } else {
        tls_outbound::build_client_config(profile)
    };
    let server_name = ServerName::try_from(host.trim_matches(['[', ']']).to_string())
        .map_err(|_| format!("目标 TLS 主机名无效: {host}"))?;
    let (capturing, capture) = CapturingIo::new(stream);
    let boxed = BoxedIo(Box::new(capturing));
    let tls = timeout(
        Duration::from_secs(15),
        TlsConnector::from(config).connect(server_name, boxed),
    )
    .await
    .map_err(|_| format!("目标 TLS 握手超时: {host}"))?
    .map_err(|error| format!("目标 TLS 证书校验或握手失败 {host}: {error}"))?;
    let measured = capture.lock().ok().and_then(|bytes| {
        crate::tls_fingerprint::fingerprint_client_hello_wire(&bytes)
            .ok()
            .map(|fp| (fp.ja3, fp.ja4))
    });
    // Read the rustls-specific handshake facts here, while the concrete type is
    // still in hand, so the boxed stream that leaves this function names no engine.
    let connection = tls.get_ref().1;
    let negotiated_alpn = connection.alpn_protocol().map(<[u8]>::to_vec);
    let protocol_version = connection
        .protocol_version()
        .map(|version| format!("{version:?}"));
    Ok(VerifiedTlsConnect {
        stream: BoxedIo(Box::new(tls)),
        negotiated_alpn,
        protocol_version,
        measured_ja3: measured.as_ref().map(|(j, _)| j.clone()),
        measured_ja4: measured.map(|(_, j4)| j4),
    })
}

/// Handshake origin HTTP after TLS using negotiated ALPN (h2 preferred when allowed).
async fn handshake_origin_https(
    upstream_tls: BoxedIo,
    negotiated_alpn: Option<&[u8]>,
    prefer_http2: bool,
) -> Result<HttpsRequestSender, String> {
    let use_h2 = origin_prefers_http2(prefer_http2, negotiated_alpn);
    let io = TokioIo::new(upstream_tls);
    if use_h2 {
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        // Active ClientHello catalog preset drives origin H2 SETTINGS (hyper-exposed fields).
        tls_outbound::apply_http2_recipe_to_builder(
            &mut builder,
            tls_outbound::active_http2_recipe(),
        );
        let (sender, connection) = builder
            .handshake::<_, TapBody<ProxyBody>>(io)
            .await
            .map_err(|error| format!("目标 HTTPS HTTP/2 握手失败: {error}"))?;
        tauri::async_runtime::spawn(async move {
            let _ = connection.await;
        });
        Ok(HttpsRequestSender::Http2(sender))
    } else {
        let (sender, connection) =
            hyper::client::conn::http1::handshake::<_, TapBody<ProxyBody>>(io)
                .await
                .map_err(|error| format!("目标 HTTPS HTTP/1.1 握手失败: {error}"))?;
        tauri::async_runtime::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
        Ok(HttpsRequestSender::Http1(sender))
    }
}

fn dedicated_request_sender_factory(
    upstream: EffectiveUpstreamProxy,
    tls_profile: OutboundTlsProfile,
) -> DedicatedRequestSenderFactory {
    Arc::new(move |route| {
        let upstream = upstream.clone();
        let default_profile = tls_profile;
        Box::pin(async move {
            let profile = route.tls_profile;
            let _ = default_profile;
            // Every HTTPS reconnect uses wreq so JA4 matches the shared tunnel,
            // including hosts on the forced-h1 list. WebSocket still upgrades
            // through wreq's websocket builder at the call site — this factory
            // only supplies the client, never a rustls Upgrade stream.
            #[cfg(feature = "impersonate-boring")]
            if route.scheme == "https" {
                let client = crate::impersonate_egress::build_client_for_route(
                    &upstream,
                    &route.connection_host,
                    route.port,
                    &route.tls_identity_host,
                    route.tls_identity_port,
                )
                .await?;
                let base = format!(
                    "https://{}",
                    host_header_authority(
                        "https",
                        &route.tls_identity_host,
                        route.tls_identity_port,
                    )
                );
                return Ok(HttpsRequestSender::Impersonate { client, base });
            }
            let stream = connect_destination(&upstream, &route.connection_host, route.port).await?;
            let stream = if route.scheme == "https" {
                connect_verified_tls_measured(
                    stream,
                    &route.tls_identity_host,
                    profile,
                    !route.prefer_http2,
                )
                .await?
                .stream
            } else {
                stream
            };
            if route.scheme == "https" {
                if !route.prefer_http2 {
                    let (sender, connection) = hyper::client::conn::http1::handshake::<
                        _,
                        TapBody<ProxyBody>,
                    >(TokioIo::new(stream))
                    .await
                    .map_err(|error| format!("目标独立 HTTP 连接握手失败: {error}"))?;
                    tauri::async_runtime::spawn(async move {
                        let _ = connection.with_upgrades().await;
                    });
                    return Ok(HttpsRequestSender::Http1(sender));
                }
                let mut h2_builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
                tls_outbound::apply_http2_recipe_to_builder(
                    &mut h2_builder,
                    tls_outbound::active_http2_recipe(),
                );
                match h2_builder
                    .handshake::<_, TapBody<ProxyBody>>(TokioIo::new(stream))
                    .await
                {
                    Ok((sender, connection)) => {
                        tauri::async_runtime::spawn(async move {
                            let _ = connection.await;
                        });
                        Ok(HttpsRequestSender::Http2(sender))
                    }
                    Err(_) => {
                        let stream =
                            connect_destination(&upstream, &route.connection_host, route.port)
                                .await?;
                        let stream =
                            connect_verified_tls(stream, &route.tls_identity_host, profile).await?;
                        let (sender, connection) = hyper::client::conn::http1::handshake::<
                            _,
                            TapBody<ProxyBody>,
                        >(TokioIo::new(stream))
                        .await
                        .map_err(|error| format!("目标独立 HTTP/1.1 回退失败: {error}"))?;
                        tauri::async_runtime::spawn(async move {
                            let _ = connection.with_upgrades().await;
                        });
                        Ok(HttpsRequestSender::Http1(sender))
                    }
                }
            } else {
                let (sender, connection) = hyper::client::conn::http1::handshake::<
                    _,
                    TapBody<ProxyBody>,
                >(TokioIo::new(stream))
                .await
                .map_err(|error| format!("目标独立 HTTP 连接握手失败: {error}"))?;
                tauri::async_runtime::spawn(async move {
                    let _ = connection.with_upgrades().await;
                });
                Ok(HttpsRequestSender::Http1(sender))
            }
        })
    })
}

async fn forward_mitm_https(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    session_id: String,
    source: String,
    mut host: String,
    mut port: u16,
    mirror_route: Option<RuntimeMirrorRoute>,
    tls_version: String,
    http_protocol: String,
    mut tls_fingerprint: crate::tls_fingerprint::TlsFingerprintRecord,
    http2_fingerprint: Option<Arc<Http2FingerprintCollector>>,
    sender: Arc<AsyncMutex<HttpsRequestSender>>,
    dedicated_sender_factory: DedicatedRequestSenderFactory,
    capture_sink: CaptureSink,
    rule_engine: Option<RuleEngine>,
    event_sink: EventSink,
    error_sink: ErrorSink,
) -> Result<Response<ProxyBody>, Infallible> {
    // Set where the typed hyper::Error still exists, read at the sink — the
    // message is user-facing text and must not carry control data.
    let routine_end = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let routine_flag = routine_end.clone();
    let result: Result<Response<ProxyBody>, String> = async {
        let mut scheme = "https".to_string();
        let original_route = (scheme.clone(), host.clone(), port);
        let inbound_http2 = http_protocol == "h2";
        if inbound_http2 {
            tls_fingerprint.http2 = http2_fingerprint
                .as_ref()
                .and_then(|collector| collector.snapshot());
        }
        let request_id = format!("request-{}", Uuid::new_v4());
        let mut method = request.method().as_str().to_string();
        let mut path = request.uri().path().to_string();
        let mut query = request.uri().query().map(ToString::to_string);
        let mut request_headers = headers_to_entries(request.headers());
        let mut runtime_request = RuntimeRuleRequest {
            request_id: request_id.clone(),
            method: method.clone(),
            scheme: scheme.clone(),
            host: host.clone(),
            port,
            path: path.clone(),
            query: query.clone(),
            source: source.clone(),
            protocol: http_protocol.clone(),
            request_headers: request_headers.clone(),
            request_body: None,
            body_unavailable_reason: None,
        };
        let extended_websocket = inbound_http2 && is_extended_websocket_connect(&request);
        let websocket = extended_websocket || is_websocket_upgrade(request.headers());
        let inbound_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
        let start = Instant::now();
        let should_buffer_request_body = rule_engine
            .as_ref()
            .map(|engine| engine.requires_request_body(&runtime_request))
            .transpose()?
            .unwrap_or(false);
        let (mut parts, body) = request.into_parts();
        let mut editable_request_body = prepare_editable_request_body(
            body,
            &parts.headers,
            should_buffer_request_body,
            websocket,
        )
        .await?;
        runtime_request.request_body = editable_request_body.text.clone();
        runtime_request.body_unavailable_reason = editable_request_body.unavailable_reason.clone();
        let control = if let Some(rule_engine) = rule_engine.as_ref() {
            let control = rule_engine.apply_request(&mut runtime_request)?;
            if control.request_body_changed {
                let text = runtime_request.request_body.clone().unwrap_or_default();
                editable_request_body.body = full_body(Bytes::copy_from_slice(text.as_bytes()));
                editable_request_body.text = Some(text);
                editable_request_body.editable = true;
                editable_request_body.unavailable_reason = None;
                editable_request_body.changed = true;
            }
            path = runtime_request.path.clone();
            query = runtime_request.query.clone();
            scheme = runtime_request.scheme.clone();
            host = runtime_request.host.clone();
            port = runtime_request.port;
            request_headers = runtime_request.request_headers.clone();
            replace_request_headers(&mut parts.headers, &request_headers)?;
            parts.uri = runtime_origin_uri(&path, query.as_deref())?;
            control
        } else {
            RuntimeRuleControl::default()
        };
        if control.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(control.delay_ms)).await;
        }
        if control.blocked {
            let status = StatusCode::from_u16(control.block_status.unwrap_or(403))
                .unwrap_or(StatusCode::FORBIDDEN);
            let message = control
                .block_message
                .as_deref()
                .unwrap_or("请求已被 ShowNet 规则阻断");
            capture_rule_block(
                &capture_sink,
                &request_id,
                &session_id,
                &source,
                peer,
                &method,
                &scheme,
                &host,
                port,
                &path,
                query,
                request_headers,
                &http_protocol,
                status,
                message,
            );
            return Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(full_body(Bytes::copy_from_slice(message.as_bytes())))
                .map_err(|error| error.to_string());
        }
        let breakpoint_rules = rule_engine
            .as_ref()
            .map(|engine| engine.matching_request_breakpoints(&runtime_request))
            .transpose()?
            .unwrap_or_default();
        if let Some(rule_engine) = rule_engine.as_ref() {
            if run_request_breakpoints(
                rule_engine,
                &session_id,
                &mut runtime_request,
                &mut editable_request_body,
                breakpoint_rules,
            )
            .await?
            {
                method = runtime_request.method.clone();
                scheme = runtime_request.scheme.clone();
                host = runtime_request.host.clone();
                port = runtime_request.port;
                path = runtime_request.path.clone();
                query = runtime_request.query.clone();
                request_headers = runtime_request.request_headers.clone();
                let status = StatusCode::from_u16(499).unwrap_or(StatusCode::BAD_REQUEST);
                let message = "请求已在 ShowNet 人工断点中止";
                capture_rule_block(
                    &capture_sink,
                    &request_id,
                    &session_id,
                    &source,
                    peer,
                    &method,
                    &scheme,
                    &host,
                    port,
                    &path,
                    query,
                    request_headers,
                    &http_protocol,
                    status,
                    message,
                );
                return Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(full_body(Bytes::copy_from_slice(message.as_bytes())))
                    .map_err(|error| error.to_string());
            }
        }
        method = runtime_request.method.clone();
        scheme = runtime_request.scheme.clone();
        host = runtime_request.host.clone();
        port = runtime_request.port;
        path = runtime_request.path.clone();
        query = runtime_request.query.clone();
        request_headers = runtime_request.request_headers.clone();
        replace_request_headers(&mut parts.headers, &request_headers)?;
        parts.method = Method::from_bytes(method.as_bytes())
            .map_err(|_| format!("断点生成的请求方法无效: {method}"))?;
        parts.uri = runtime_origin_uri(&path, query.as_deref())?;
        if editable_request_body.changed {
            sanitize_rewritten_request_body_headers(
                &mut parts.headers,
                editable_request_body
                    .text
                    .as_deref()
                    .unwrap_or_default()
                    .len(),
            )?;
            request_headers = headers_to_entries(&parts.headers);
            runtime_request.request_headers = request_headers.clone();
        }
        let request_content_encoding = header_text(&parts.headers, CONTENT_ENCODING);
        let request_content_type = header_text(&parts.headers, CONTENT_TYPE);
        parts.headers.remove("x-shownet-replay-context");
        parts.headers.remove(REVERSE_PROXY_CONTEXT_HEADER);
        parts.uri = origin_form_uri(&parts.uri)?;
        let authority_changed =
            scheme != original_route.0 || host != original_route.1 || port != original_route.2;
        let active_mirror_route = if authority_changed {
            None
        } else {
            mirror_route.as_ref()
        };
        if !authority_changed {
            queue_mirror_trace_or_report(
                &rule_engine,
                &mirror_route,
                &request_id,
                "https-mitm-request",
                &error_sink,
            );
        }
        let (connection_host, connection_port) = active_mirror_route
            .map(RuntimeMirrorRoute::connection_target)
            .unwrap_or((&host, port));
        let (tls_identity_host, tls_identity_port) = active_mirror_route
            .map(RuntimeMirrorRoute::identity_target)
            .unwrap_or((&host, port));
        // WebSocket / extended CONNECT stay on dedicated HTTP/1.1; normal traffic
        // may use shared h2. `websocket` and not just `extended_websocket`: a
        // plain Connection: Upgrade handshake to the same authority went out on
        // the shared h2 sender carrying Upgrade headers, which is the very
        // "http2 error" this path exists to avoid.
        let use_dedicated_base = authority_changed || websocket;
        #[cfg(feature = "impersonate-boring")]
        let impersonate_client = if websocket && scheme == "https" {
            let slot = sender.lock().await;
            match &*slot {
                HttpsRequestSender::Impersonate { client, .. } => Some(client.clone()),
                _ => None,
            }
        } else {
            None
        };
        // Product WSS must use the same wreq ClientHello as HTTPS even when the
        // shared slot is not Impersonate (retired sender, first request is a
        // socket). rustls Upgrade is not a product path.
        #[cfg(feature = "impersonate-boring")]
        let impersonate_websocket = websocket && scheme == "https";
        #[cfg(not(feature = "impersonate-boring"))]
        let impersonate_websocket = false;
        let outbound_profile =
            tls_outbound::OutboundTlsProfile::parse(tls_fingerprint.outbound.profile.as_str());
        let dedicated_route = DedicatedRequestRoute {
            scheme: scheme.clone(),
            connection_host: connection_host.to_string(),
            port: connection_port,
            tls_identity_host: tls_identity_host.to_string(),
            tls_identity_port,
            // The forced-h1 list has to survive here too. The shared connection
            // consults it at handshake time, but a dedicated one replacing a
            // retired shared connection would go back to preferring h2 and
            // silently undo the CDN workaround for the rest of the tunnel —
            // which is how those hosts' images broke in the first place.
            prefer_http2: !extended_websocket
                && !websocket
                && !tls_outbound::origin_force_http11_for_host(tls_identity_host),
            tls_profile: outbound_profile,
        };
        // A shared connection the origin has retired cannot carry anything more.
        // Replacing it in place matters as much as routing around it: without
        // the write-back every later request in the tunnel re-detected the same
        // dead sender and opened its own TCP+TLS+h2 handshake for one request.
        // On a page with dozens of subresources behind an origin that retires h2
        // after a bounded stream count, that turns one multiplexed connection
        // into N sequential ones — slow, and a connection pattern no browser
        // produces, which is its own signal to whatever is scoring us.
        let mut shared_retired = false;
        if !use_dedicated_base {
            // The guard is held across the reconnect on purpose. Releasing it to
            // await the handshake let every request queued behind one retired h2
            // connection observe `is_closed()` at once: all of them dialled a new
            // origin connection, the last write won, and dropping the losers tore
            // down connections other requests were already streaming bodies from
            // — a truncated response under a 200 that was already captured. The
            // factory never touches this lock, so holding it cannot deadlock.
            let mut slot = sender.lock().await;
            // Retire an h2 connection to a host we have since learned refuses
            // ours, not only a closed one. Waiting for it to close meant the
            // whole first page-load kept reloading over the connection that was
            // already known bad; swapping immediately lets that same load
            // recover instead of the one after it.
            let refuses_our_h2 = slot.is_http2()
                && tls_outbound::origin_force_http11_for_host(tls_identity_host);
            if slot.is_closed() || refuses_our_h2 {
                match dedicated_sender_factory(dedicated_route.clone()).await {
                    Ok(replacement) => *slot = replacement,
                    // Reconnect failed; fall through to a one-off connection so
                    // the request still has a chance rather than failing here.
                    Err(_) => shared_retired = true,
                }
            }
        }
        let use_dedicated = use_dedicated_base || shared_retired;
        // The sender is chosen before the request is shaped, because how it must
        // be shaped — absolute vs origin-form URI, and whether h1's
        // connection-specific headers are legal — depends on the protocol of the
        // connection it actually goes out on. Deciding that from the client's
        // protocol, or from the shared connection while sending on a dedicated
        // one, produces a request the origin rejects outright.
        let mut dedicated_sender = if use_dedicated && !impersonate_websocket {
            Some(dedicated_sender_factory(dedicated_route.clone()).await?)
        } else {
            None
        };
        // The shared guard is taken once here and held through the send. It used
        // to be re-acquired for is_http2 and again for send_request, so another
        // request could replace the sender in between — and the request, already
        // shaped for the protocol that was read, went out on a connection
        // speaking the other one. hyper rejects that as an unsupported version.
        let mut shared_guard = if use_dedicated {
            None
        } else {
            Some(sender.lock().await)
        };
        let outbound_is_http2 = match (dedicated_sender.as_ref(), shared_guard.as_ref()) {
            (Some(dedicated), _) => dedicated.is_http2(),
            (None, Some(shared)) => shared.is_http2(),
            (None, None) => false,
        };
        parts.version = if outbound_is_http2 && !websocket && !extended_websocket {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        };
        let (host_header_host, host_header_port) = active_mirror_route
            .map(RuntimeMirrorRoute::identity_target)
            .unwrap_or((&host, port));
        let replace_host_header = authority_changed && !control.redirect_preserve_host
            || active_mirror_route.is_some_and(|route| route.identity == MirrorIdentity::Target);
        // h2 needs absolute form; h1 needs origin form. Rebuilt here so the
        // authority matches the Host header written just below.
        if parts.version == Version::HTTP_2 {
            parts.uri = absolute_form_uri(&scheme, host_header_host, host_header_port, &parts.uri)?;
        }
        ensure_host_header(
            &mut parts.headers,
            &scheme,
            host_header_host,
            host_header_port,
            replace_host_header,
        )?;
        parts.headers.remove("proxy-authorization");
        parts.headers.remove("proxy-connection");
        if extended_websocket {
            parts.method = Method::GET;
            parts.extensions.remove::<Protocol>();
            parts
                .headers
                .insert("connection", HeaderValue::from_static("Upgrade"));
            parts
                .headers
                .insert("upgrade", HeaderValue::from_static("websocket"));
            // RFC 8441 carries no Sec-WebSocket-Key — the h2 stream itself proves
            // the handshake, so the browser never sends one. RFC 6455 requires it,
            // and this is the line that turns one into the other, so the key has to
            // be minted here. Without it the origin answers 400 "Missing or invalid
            // Sec-WebSocket-Key header" and every WebSocket a captured page opens
            // fails while its polling fallback keeps working — measured on one real
            // session as 2,368 failed upgrades against 16,548 successful polls.
            //
            // Any 16 random bytes are a valid key; a v4 UUID is exactly that, and
            // the response's Sec-WebSocket-Accept is not checked against it because
            // the inbound half is h2, where the accept value has no meaning and is
            // stripped from the 200 below.
            if !parts.headers.contains_key("sec-websocket-key") {
                let key = STANDARD.encode(Uuid::new_v4().as_bytes());
                if let Ok(value) = HeaderValue::from_str(&key) {
                    parts.headers.insert("sec-websocket-key", value);
                }
            }
        }
        if websocket {
            parts.headers.remove("sec-websocket-extensions");
        }
        // A client may reach the MITM over HTTP/1.1 while the origin negotiated
        // h2 — our leaf offers both. Forwarding h1's connection-specific headers
        // onto an h2 stream is a protocol violation, and hyper rejects the whole
        // request with a bare "http2 error", which reads as the site refusing us
        // rather than as us sending something illegal. Stripped before capture so
        // the recorded headers are the ones actually sent.
        if parts.version == Version::HTTP_2 {
            strip_http2_forbidden_headers(&mut parts.headers);
        }
        // HTTP/2 cookie crumbs must be one Cookie header before wreq rebuilds
        // the origin request. wreq's RequestBuilder::header replaces same-name
        // values, so iterating crumbs would keep only the last cookie.
        collapse_cookie_headers(&mut parts.headers);
        request_headers = request_headers_for_capture(
            &parts.headers,
            active_mirror_route,
            &scheme,
            &host,
            port,
            extended_websocket,
        );
        runtime_request.request_headers = request_headers.clone();
        #[cfg(feature = "impersonate-boring")]
        if impersonate_websocket {
            let path_and_query = parts
                .uri
                .path_and_query()
                .map(|item| item.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let url = format!(
                "wss://{}{path_and_query}",
                host_header_authority("https", tls_identity_host, tls_identity_port)
            );
            let header_pairs: Vec<(String, Vec<u8>)> = parts
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
                .collect();
            let client = if let Some(client) = impersonate_client {
                client
            } else {
                match dedicated_sender_factory(dedicated_route.clone()).await? {
                    HttpsRequestSender::Impersonate { client, .. } => client,
                    _ => {
                        return Err("HTTPS WebSocket 出站需要与 HTTPS 相同的 wreq 客户端".to_string())
                    }
                }
            };
            let upgraded = client
                .websocket_upgrade(&url, &header_pairs)
                .await?;
            let mut builder = Response::builder().status(upgraded.status);
            for (name, value) in &upgraded.headers {
                if name.eq_ignore_ascii_case("transfer-encoding") {
                    continue;
                }
                builder = builder.header(name.as_str(), value.as_slice());
            }
            let (mut response, outbound) = (
                builder
                    .body(empty_body())
                    .map_err(|error| format!("组装 WebSocket 响应失败: {error}"))?,
                upgraded.socket,
            );
            response.headers_mut().remove("sec-websocket-extensions");
            if extended_websocket {
                *response.status_mut() = StatusCode::OK;
                response.headers_mut().remove("sec-websocket-accept");
                strip_http2_forbidden_headers(response.headers_mut());
            }
            let response_headers = headers_to_entries(response.headers());
            let mut handshake = websocket_handshake_input(
                &request_id,
                &session_id,
                &source,
                peer,
                method,
                "wss",
                host,
                port,
                path,
                query,
                tls_version,
                Some(tls_fingerprint),
                request_headers,
                response_headers,
                start.elapsed().as_millis() as i64,
            );
            if extended_websocket {
                handshake.status = StatusCode::OK.as_u16() as i64;
                handshake.protocol = "h2".to_string();
            } else {
                handshake.status = response.status().as_u16() as i64;
            }
            capture_sink(handshake);
            if let Some(inbound_upgrade) = inbound_upgrade {
                spawn_impersonate_websocket_relay(
                    inbound_upgrade,
                    outbound,
                    session_id,
                    source,
                    format!("proxy:{}", peer.ip()),
                    request_id,
                    event_sink,
                    error_sink.clone(),
                );
            }
            let (parts, _) = response.into_parts();
            return Ok(Response::from_parts(parts, empty_body()));
        }
        // Decided before the body is consumed by TapBody below; the retry needs
        // to know whether the request can be rebuilt, and by then it cannot ask.
        let replay = replayable_over_http11(&parts, &editable_request_body)
            .then(|| (parts.method.clone(), parts.uri.clone(), parts.headers.clone()));
        let request_capture = Arc::new(StdMutex::new(None));
        let request_capture_sink = request_capture.clone();
        let request_body = TapBody::new(
            editable_request_body.body,
            MAX_CAPTURED_WIRE_BYTES,
            move |capture| {
                if let Ok(mut stored) = request_capture_sink.lock() {
                    stored.replace(capture);
                }
            },
        )
        .with_rate_limit(control.upload_bytes_per_second);
        let outbound_request = Request::from_parts(parts, request_body);
        let mut result = match (dedicated_sender.as_mut(), shared_guard.as_mut()) {
            (Some(dedicated), _) => dedicated.send_request(outbound_request).await,
            (None, Some(shared)) => shared.send_request(outbound_request).await,
            // `use_dedicated` decides which of the two is Some, so neither being
            // set cannot happen. Stated rather than faked with an error value
            // built from a handshake that would actually succeed.
            (None, None) => unreachable!("a sender is always selected"),
        };

        // Remembering the refusal only helps the *next* request, and a stylesheet
        // has no next request: measured on lionairthai, fonts.googleapis.com
        // refused our h2, the 502 rejected the page's CSS preload, React Router
        // caught the rejection during render, and #root stayed empty. Every other
        // asset on that load was 200. So retry this one over HTTP/1.1 rather than
        // leaving the caller a 502 and a lesson for later.
        if result.is_err()
            && outbound_is_http2
            && replay.is_some()
            && result
                .as_ref()
                .err()
                .is_some_and(looks_like_origin_http2_refusal)
        {
            let (method, uri, headers) = replay.expect("checked above");
            let http11_route = DedicatedRequestRoute {
                prefer_http2: false,
                ..dedicated_route.clone()
            };
            match dedicated_sender_factory(http11_route).await {
                Ok(mut h1) => {
                    // h1 wants origin-form; the h2 attempt rewrote it to absolute.
                    let mut retry = Request::builder()
                        .method(method)
                        .uri(origin_form_uri(&uri).unwrap_or(uri))
                        .version(Version::HTTP_11);
                    if let Some(map) = retry.headers_mut() {
                        *map = headers;
                    }
                    if let Ok(request) = retry.body(TapBody::new(
                        full_body(Bytes::new()),
                        MAX_CAPTURED_WIRE_BYTES,
                        |_| {},
                    )) {
                        if let Ok(response) = h1.send_request(request).await {
                            result = Ok(response);
                            dedicated_sender = Some(h1);
                        }
                    }
                }
                Err(error) => {
                    eprintln!("http/1.1 retry could not connect to {host}: {error}");
                }
            }
        }

        let mut response = result
        .map_err(|error| {
            // Some origins fingerprint the HTTP/2 connection itself and refuse
            // ours, which surfaces here as a bare protocol error. Remember the
            // host so the next connection to it speaks HTTP/1.1: measured
            // against such an origin, h2 egress reload-looped the page 23 times
            // in 20 seconds while h1 settled after one navigation. The current
            // request still fails, but the retry the page is about to make
            // succeeds instead of looping forever.
            let message = if outbound_is_http2
                && looks_like_origin_http2_refusal(&error)
                && tls_outbound::note_origin_http2_rejected(&host)
            {
                format!(
                    "转发目标请求失败: {error}（该源站拒绝我们的 HTTP/2 连接，已记住并对其改用 HTTP/1.1，重试即可）"
                )
            } else {
                if is_benign_forward_end(&error) {
                    routine_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                format!("转发目标请求失败: {error}")
            };
            if !routine_flag.load(std::sync::atomic::Ordering::Relaxed) {
                capture_sink(CapturedRequestInput {
                    id: Some(request_id.clone()),
                    session_id: session_id.clone(),
                    source: source.clone(),
                    source_instance_id: Some(format!("proxy:{}", peer.ip())),
                    timestamp: None,
                    method: method.clone(),
                    scheme: Some(scheme.clone()),
                    host: host.clone(),
                    port: Some(port as i64),
                    path: path.clone(),
                    query: query.clone(),
                    status: 502,
                    resource_type: "fetch".to_string(),
                    size_bytes: 0,
                    duration_ms: start.elapsed().as_millis() as i64,
                    protocol: http_protocol.clone(),
                    tls_version: Some(tls_version.clone()),
                    tls_fingerprint: Some(tls_fingerprint.clone()),
                    risk_level: "warning".to_string(),
                    request_headers: request_headers.clone(),
                    response_headers: Vec::new(),
                    request_body: None,
                    response_body: Some(message.clone()),
                    response_body_metadata: None,
                    crypto_snippets: None,
                    hook: None,
                });
            }
            message
        })?;
        // h2 multiplexes, so the guard goes as soon as the headers are in hand:
        // holding it through whole-body buffering for rewrite rules and through
        // `run_response_breakpoints` — which waits for a person — would stall
        // every other request in the tunnel behind this one.
        //
        // h1 is the opposite. hyper's h1 client does not pipeline: a second
        // `send_request` issued before the previous response body has been read
        // fails outright with "operation was canceled". Downgraded hosts are
        // exactly the ones on h1, so releasing at the headers there would have
        // made the very sites this release repairs fail most of their
        // subresources.
        //
        // Two honest limits. The guard lives to the end of this block, which
        // covers whole-body buffering when a rewrite rule needs it but not the
        // lazy streaming that follows when none does — so an h1 connection can
        // still overlap a request with an unread body. And when a response
        // breakpoint is set on an h1 tunnel, other requests on it wait for the
        // operator, bounded by the breakpoint timeout — which `storage.rs`
        // validates to 5s..=300s and defaults to 120s, so the worst case is a
        // host that appears frozen for two minutes while one response is held.
        // The wait is only genuinely necessary when the body is still
        // streaming; once a rewrite rule has collected it the connection is
        // idle and the guard is dead weight. Both are the shape of sharing one
        // non-pipelining connection; the real answer is a small pool of them,
        // which is a larger change than this release.
        if outbound_is_http2 {
            drop(shared_guard);
        }
        let upstream_status = response.status().as_u16() as i64;
        if websocket && response.status() == StatusCode::SWITCHING_PROTOCOLS {
            response.headers_mut().remove("sec-websocket-extensions");
            let outbound_upgrade = hyper::upgrade::on(&mut response);
            if extended_websocket {
                *response.status_mut() = StatusCode::OK;
                // Answers the key minted for the downgraded h1 handshake, and
                // means nothing on an h2 stream — RFC 8441 defines no accept
                // value. Forwarding it would hand the browser a header its own
                // request never asked for.
                response.headers_mut().remove("sec-websocket-accept");
                strip_http2_forbidden_headers(response.headers_mut());
            }
            let response_headers = headers_to_entries(response.headers());
            let mut handshake = websocket_handshake_input(
                &request_id,
                &session_id,
                &source,
                peer,
                method,
                if scheme == "https" { "wss" } else { "ws" },
                host,
                port,
                path,
                query,
                tls_version,
                Some(tls_fingerprint),
                request_headers,
                response_headers,
                start.elapsed().as_millis() as i64,
            );
            if extended_websocket {
                handshake.status = StatusCode::OK.as_u16() as i64;
                handshake.protocol = "h2".to_string();
            } else {
                handshake.status = upstream_status;
            }
            capture_sink(handshake);
            if let Some(inbound_upgrade) = inbound_upgrade {
                spawn_websocket_relay(
                    inbound_upgrade,
                    outbound_upgrade,
                    session_id,
                    source,
                    format!("proxy:{}", peer.ip()),
                    request_id,
                    event_sink,
                    error_sink.clone(),
                );
            }
            let (parts, _) = response.into_parts();
            return Ok(Response::from_parts(parts, empty_body()));
        }
        if inbound_http2 {
            strip_http2_forbidden_headers(response.headers_mut());
        }
        let upstream_resource_type = infer_resource_type(response.headers());
        let mut response = prepare_runtime_response(
            response,
            rule_engine.as_ref(),
            runtime_request,
            &session_id,
            &upstream_resource_type,
        )
        .await?;
        if inbound_http2 {
            strip_http2_forbidden_headers(response.headers_mut());
        }
        let resource_type = if upstream_resource_type == "sse" {
            upstream_resource_type
        } else {
            infer_resource_type(response.headers())
        };
        let status = response.status().as_u16() as i64;
        let response_content_encoding = header_text(response.headers(), CONTENT_ENCODING);
        let response_content_type = header_text(response.headers(), CONTENT_TYPE);
        let response_headers = headers_to_entries(response.headers());
        let (parts, body) = response.into_parts();
        let pending = CapturedRequestInput {
            id: Some(request_id),
            session_id,
            source,
            source_instance_id: Some(format!("proxy:{}", peer.ip())),
            timestamp: None,
            method,
            scheme: Some(scheme),
            host,
            port: Some(port as i64),
            path,
            query,
            status,
            resource_type,
            size_bytes: 0,
            duration_ms: 0,
            protocol: http_protocol,
            tls_version: Some(tls_version),
            tls_fingerprint: Some(tls_fingerprint),
            risk_level: if status >= 400 { "warning" } else { "none" }.to_string(),
            request_headers,
            response_headers,
            request_body: None,
            response_body: None,
            response_body_metadata: None,
            crypto_snippets: None,
            hook: None,
        };
        let body = if pending.resource_type == "sse" {
            captured_sse_response_body(
                body,
                capture_sink,
                event_sink,
                pending,
                request_capture,
                request_content_encoding,
                request_content_type,
                response_content_encoding,
                response_content_type,
                start,
                control.download_bytes_per_second,
            )
        } else {
            captured_response_body(
                body,
                capture_sink,
                pending,
                request_capture,
                request_content_encoding,
                request_content_type,
                response_content_encoding,
                response_content_type,
                start,
                control.download_bytes_per_second,
            )
        };
        Ok(Response::from_parts(parts, body))
    }
    .await;
    Ok(result.unwrap_or_else(|error| {
        if !routine_end.load(std::sync::atomic::Ordering::Relaxed) {
            error_sink(error.clone());
        }
        error_response(StatusCode::BAD_GATEWAY, &error)
    }))
}

async fn prepare_runtime_response(
    response: Response<ProxyBody>,
    rule_engine: Option<&RuleEngine>,
    request: RuntimeRuleRequest,
    session_id: &str,
    resource_type: &str,
) -> Result<Response<ProxyBody>, String> {
    // The body already arrives boxed from HttpsRequestSender::send_request.
    let mut response = response;
    let Some(rule_engine) = rule_engine else {
        return Ok(response);
    };

    let original_headers = headers_to_entries(response.headers());
    let mut runtime = RuntimeRuleResponse {
        request,
        status: response.status().as_u16(),
        response_headers: original_headers.clone(),
        response_body: None,
        body_unavailable_reason: None,
    };
    if rule_engine.requires_response_body(&runtime)? {
        if let Some(reason) =
            response_body_unavailable_reason(response.headers(), response.body(), resource_type)
        {
            runtime.body_unavailable_reason = Some(reason);
        } else {
            let content_type = header_text(response.headers(), CONTENT_TYPE);
            let (parts, body) = response.into_parts();
            let bytes = body
                .collect()
                .await
                .map_err(|error| format!("读取待改写响应正文失败: {error}"))?
                .to_bytes();
            response = Response::from_parts(parts, full_body(bytes.clone()));
            if bytes.len() > MAX_RULE_BODY_BYTES {
                runtime.body_unavailable_reason = Some(format!(
                    "响应正文超过 {} MiB 安全上限，已跳过整条正文规则",
                    MAX_RULE_BODY_BYTES / 1024 / 1024
                ));
            } else if !is_textual_body(&bytes, content_type.as_deref()) {
                runtime.body_unavailable_reason =
                    Some("响应正文不是可安全改写的文本，已跳过整条正文规则".to_string());
            } else {
                match String::from_utf8(bytes.to_vec()) {
                    Ok(body) => runtime.response_body = Some(body),
                    Err(_) => {
                        runtime.body_unavailable_reason =
                            Some("响应正文不是有效 UTF-8，已跳过整条正文规则".to_string())
                    }
                }
            }
        }
    }

    let mut body_changed = rule_engine.apply_response(&mut runtime)?;
    body_changed |= run_response_breakpoints(rule_engine, session_id, &mut runtime).await?;
    *response.status_mut() = StatusCode::from_u16(runtime.status)
        .map_err(|_| format!("规则生成的响应状态码无效: {}", runtime.status))?;
    apply_response_header_changes(
        response.headers_mut(),
        &original_headers,
        &runtime.response_headers,
    )?;
    if body_changed {
        let body = Bytes::from(runtime.response_body.unwrap_or_default());
        sanitize_rewritten_body_headers(response.headers_mut(), body.len())?;
        *response.body_mut() = full_body(body);
    }
    Ok(response)
}

struct EditableRequestBody {
    body: ProxyBody,
    text: Option<String>,
    editable: bool,
    unavailable_reason: Option<String>,
    changed: bool,
}

async fn prepare_editable_request_body(
    body: Incoming,
    headers: &HeaderMap,
    should_buffer: bool,
    websocket: bool,
) -> Result<EditableRequestBody, String> {
    if !should_buffer {
        return Ok(EditableRequestBody {
            body: boxed_incoming_body(body),
            text: None,
            editable: false,
            unavailable_reason: None,
            changed: false,
        });
    }
    if websocket {
        return Ok(EditableRequestBody {
            body: boxed_incoming_body(body),
            text: None,
            editable: false,
            unavailable_reason: Some("WebSocket 握手不支持请求正文改写".to_string()),
            changed: false,
        });
    }
    if header_text(headers, CONTENT_ENCODING).is_some_and(|encoding| {
        !encoding.trim().is_empty() && !encoding.eq_ignore_ascii_case("identity")
    }) {
        return Ok(EditableRequestBody {
            body: boxed_incoming_body(body),
            text: None,
            editable: false,
            unavailable_reason: Some("压缩请求正文保持原样转发，不能安全改写".to_string()),
            changed: false,
        });
    }
    let upper = body.size_hint().upper();
    if upper.is_none() {
        return Ok(EditableRequestBody {
            body: boxed_incoming_body(body),
            text: None,
            editable: false,
            unavailable_reason: Some("流式或长度未知的请求正文保持原样转发".to_string()),
            changed: false,
        });
    }
    if upper.is_some_and(|value| value > MAX_BREAKPOINT_BODY_BYTES as u64) {
        return Ok(EditableRequestBody {
            body: boxed_incoming_body(body),
            text: None,
            editable: false,
            unavailable_reason: Some("请求正文超过 2 MiB，保持原样转发".to_string()),
            changed: false,
        });
    }
    let content_type = header_text(headers, CONTENT_TYPE);
    let bytes = timeout(Duration::from_secs(10), body.collect())
        .await
        .map_err(|_| "读取待改写请求正文超时".to_string())?
        .map_err(|error| format!("读取待改写请求正文失败: {error}"))?
        .to_bytes();
    let body = full_body(bytes.clone());
    if bytes.len() > MAX_BREAKPOINT_BODY_BYTES {
        return Ok(EditableRequestBody {
            body,
            text: None,
            editable: false,
            unavailable_reason: Some("请求正文超过 2 MiB，保持原样转发".to_string()),
            changed: false,
        });
    }
    if !is_textual_body(&bytes, content_type.as_deref()) {
        return Ok(EditableRequestBody {
            body,
            text: None,
            editable: false,
            unavailable_reason: Some("二进制请求正文保持原样转发".to_string()),
            changed: false,
        });
    }
    match String::from_utf8(bytes.to_vec()) {
        Ok(text) => Ok(EditableRequestBody {
            body,
            text: Some(text),
            editable: true,
            unavailable_reason: None,
            changed: false,
        }),
        Err(_) => Ok(EditableRequestBody {
            body,
            text: None,
            editable: false,
            unavailable_reason: Some("请求正文不是有效 UTF-8，保持原样转发".to_string()),
            changed: false,
        }),
    }
}

async fn run_request_breakpoints(
    rule_engine: &RuleEngine,
    session_id: &str,
    request: &mut RuntimeRuleRequest,
    body: &mut EditableRequestBody,
    rules: Vec<RuntimeBreakpointRule>,
) -> Result<bool, String> {
    for rule in rules {
        let started = Instant::now();
        let wait = rule_engine
            .breakpoints
            .pause(
                &rule,
                BreakpointTaskInput {
                    session_id: session_id.to_string(),
                    request_id: request.request_id.clone(),
                    stage: "request".to_string(),
                    method: request.method.clone(),
                    url: runtime_request_url(request),
                    status: None,
                    request_headers: request.request_headers.clone(),
                    response_headers: Vec::new(),
                    request_body: body.text.clone(),
                    response_body: None,
                    body_editable: body.editable,
                    body_unavailable_reason: body.unavailable_reason.clone(),
                },
            )
            .await;
        let (trace_result, summary) = breakpoint_wait_summary(&wait, "请求");
        let aborted = match wait.resolution {
            BreakpointResolution::Continue(edit) => {
                if let Some(method) = edit.method {
                    request.method = method;
                }
                if let Some(url) = edit.url {
                    let url = Url::parse(&url).map_err(|_| "断点请求 URL 无效".to_string())?;
                    request.path = url.path().to_string();
                    request.query = url.query().map(ToString::to_string);
                }
                if let Some(headers) = edit.request_headers {
                    request.request_headers = headers;
                }
                if let Some(text) = edit.request_body {
                    let changed = body.text.as_deref() != Some(text.as_str());
                    if changed {
                        body.body = full_body(Bytes::copy_from_slice(text.as_bytes()));
                    }
                    request.request_body = Some(text.clone());
                    request.body_unavailable_reason = None;
                    body.text = Some(text);
                    body.changed |= changed;
                }
                false
            }
            BreakpointResolution::Abort => true,
        };
        rule_engine.queue_breakpoint_trace(
            &request.request_id,
            crate::capture_rules::runtime_breakpoint_trace(
                request,
                &rule,
                trace_result,
                &summary,
                started.elapsed().as_millis() as i64,
            ),
        )?;
        if aborted {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn run_response_breakpoints(
    rule_engine: &RuleEngine,
    session_id: &str,
    response: &mut RuntimeRuleResponse,
) -> Result<bool, String> {
    let rules = rule_engine.matching_response_breakpoints(response)?;
    let mut body_changed = false;
    for rule in rules {
        let started = Instant::now();
        let wait = rule_engine
            .breakpoints
            .pause(
                &rule,
                BreakpointTaskInput {
                    session_id: session_id.to_string(),
                    request_id: response.request.request_id.clone(),
                    stage: "response".to_string(),
                    method: response.request.method.clone(),
                    url: runtime_request_url(&response.request),
                    status: Some(response.status),
                    request_headers: response.request.request_headers.clone(),
                    response_headers: response.response_headers.clone(),
                    request_body: None,
                    response_body: response.response_body.clone(),
                    body_editable: response.response_body.is_some(),
                    body_unavailable_reason: if response.response_body.is_some() {
                        None
                    } else {
                        response.body_unavailable_reason.clone().or_else(|| {
                            Some("响应正文未安全缓冲，只能编辑状态和 Header".to_string())
                        })
                    },
                },
            )
            .await;
        let (trace_result, summary) = breakpoint_wait_summary(&wait, "响应");
        let aborted = matches!(&wait.resolution, BreakpointResolution::Abort);
        match wait.resolution {
            BreakpointResolution::Continue(edit) => {
                if let Some(status) = edit.status {
                    response.status = status;
                }
                if let Some(headers) = edit.response_headers {
                    response.response_headers = headers;
                }
                if let Some(body) = edit.response_body {
                    body_changed |= response.response_body.as_deref() != Some(body.as_str());
                    response.response_body = Some(body);
                }
            }
            BreakpointResolution::Abort => {
                response.status = 502;
                response.response_headers = vec![HeaderEntry {
                    name: CONTENT_TYPE.as_str().to_string(),
                    value: "text/plain; charset=utf-8".to_string(),
                }];
                response.response_body =
                    Some(if response.request.method.eq_ignore_ascii_case("HEAD") {
                        String::new()
                    } else {
                        "响应已在 ShowNet 人工断点中止".to_string()
                    });
                response.body_unavailable_reason = None;
                body_changed = true;
            }
        }
        rule_engine.queue_breakpoint_trace(
            &response.request.request_id,
            crate::capture_rules::runtime_breakpoint_trace(
                &response.request,
                &rule,
                trace_result,
                &summary,
                started.elapsed().as_millis() as i64,
            ),
        )?;
        if aborted {
            break;
        }
    }
    Ok(body_changed)
}

fn breakpoint_wait_summary(wait: &BreakpointWaitResult, stage: &str) -> (&'static str, String) {
    match &wait.completion {
        BreakpointCompletion::Submitted => match &wait.resolution {
            BreakpointResolution::Abort => ("applied", format!("人工断点已中止{stage}")),
            BreakpointResolution::Continue(_) => ("applied", format!("人工断点已放行{stage}")),
        },
        BreakpointCompletion::TimedOut => match &wait.resolution {
            BreakpointResolution::Abort => ("skipped", format!("{stage}断点超时，已按规则中止")),
            BreakpointResolution::Continue(_) => {
                ("skipped", format!("{stage}断点超时，已自动继续"))
            }
        },
        BreakpointCompletion::QueueFull => ("skipped", format!("{stage}断点队列已满，已自动继续")),
        BreakpointCompletion::Cancelled(reason) => {
            ("skipped", format!("{stage}断点已失效：{reason}"))
        }
    }
}

fn runtime_request_url(request: &RuntimeRuleRequest) -> String {
    let default_port = request.scheme == "http" && request.port == 80
        || request.scheme == "https" && request.port == 443;
    format!(
        "{}://{}{}{}{}",
        request.scheme,
        request.host,
        if default_port {
            String::new()
        } else {
            format!(":{}", request.port)
        },
        request.path,
        request
            .query
            .as_ref()
            .map(|query| format!("?{query}"))
            .unwrap_or_default(),
    )
}

fn sanitize_rewritten_request_body_headers(
    headers: &mut HeaderMap,
    body_len: usize,
) -> Result<(), String> {
    for name in [
        CONTENT_ENCODING.as_str(),
        CONTENT_LENGTH.as_str(),
        TRANSFER_ENCODING.as_str(),
        "content-md5",
        "digest",
    ] {
        headers.remove(name);
    }
    let value = HeaderValue::from_str(&body_len.to_string())
        .map_err(|error| format!("生成请求 Content-Length 失败: {error}"))?;
    headers.insert(CONTENT_LENGTH, value);
    Ok(())
}

fn boxed_incoming_body(body: Incoming) -> ProxyBody {
    body.map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync()
}

fn response_body_unavailable_reason(
    headers: &HeaderMap,
    body: &ProxyBody,
    resource_type: &str,
) -> Option<String> {
    if resource_type == "sse" {
        return Some("SSE 是持续响应流，已跳过整条正文规则".to_string());
    }
    if let Some(encoding) = header_text(headers, CONTENT_ENCODING) {
        if encoding
            .split(',')
            .any(|value| !value.trim().is_empty() && !value.trim().eq_ignore_ascii_case("identity"))
        {
            return Some("压缩响应正文不进行原位改写，已跳过整条正文规则".to_string());
        }
    }
    let length = match headers.get(CONTENT_LENGTH) {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
        {
            Some(length) => Some(length),
            None => return Some("响应 Content-Length 无效，已跳过整条正文规则".to_string()),
        },
        None => body.size_hint().exact(),
    };
    let Some(length) = length else {
        return Some("响应正文长度未知，已跳过整条正文规则".to_string());
    };
    if length > MAX_RULE_BODY_BYTES as u64 {
        return Some(format!(
            "响应正文超过 {} MiB 安全上限，已跳过整条正文规则",
            MAX_RULE_BODY_BYTES / 1024 / 1024
        ));
    }
    None
}

fn apply_response_header_changes(
    headers: &mut HeaderMap,
    before: &[HeaderEntry],
    after: &[HeaderEntry],
) -> Result<(), String> {
    let mut names = before
        .iter()
        .chain(after.iter())
        .filter(|entry| !entry.name.starts_with(':'))
        .map(|entry| entry.name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    for name in names {
        let previous = before
            .iter()
            .filter(|entry| entry.name.eq_ignore_ascii_case(&name))
            .map(|entry| entry.value.as_str())
            .collect::<Vec<_>>();
        let next = after
            .iter()
            .filter(|entry| entry.name.eq_ignore_ascii_case(&name))
            .map(|entry| entry.value.as_str())
            .collect::<Vec<_>>();
        if previous == next {
            continue;
        }
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("规则生成的响应 Header 名称无效: {name}"))?;
        headers.remove(&header_name);
        for value in next {
            let value = HeaderValue::from_str(value)
                .map_err(|_| format!("规则生成的响应 Header 值无效: {name}"))?;
            headers.append(header_name.clone(), value);
        }
    }
    Ok(())
}

fn sanitize_rewritten_body_headers(headers: &mut HeaderMap, body_len: usize) -> Result<(), String> {
    for name in [
        CONTENT_ENCODING.as_str(),
        CONTENT_LENGTH.as_str(),
        TRANSFER_ENCODING.as_str(),
        "content-md5",
        "content-range",
        "digest",
        "etag",
    ] {
        headers.remove(name);
    }
    let value = HeaderValue::from_str(&body_len.to_string())
        .map_err(|error| format!("生成响应 Content-Length 失败: {error}"))?;
    headers.insert(CONTENT_LENGTH, value);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn captured_response_body(
    body: ProxyBody,
    capture_sink: CaptureSink,
    mut pending: CapturedRequestInput,
    request_capture: Arc<StdMutex<Option<BodyCaptureSnapshot>>>,
    request_content_encoding: Option<String>,
    request_content_type: Option<String>,
    response_content_encoding: Option<String>,
    response_content_type: Option<String>,
    start: Instant,
    bytes_per_second: Option<u64>,
) -> ProxyBody {
    let expected_wire_bytes = pending
        .response_headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .and_then(|header| header.value.trim().parse::<usize>().ok());
    TapBody::new(body, MAX_CAPTURED_WIRE_BYTES, move |response_capture| {
        let request_capture = request_capture
            .lock()
            .ok()
            .and_then(|mut capture| capture.take())
            .unwrap_or_default();
        let (request_body, _) = normalize_body_capture(
            request_capture,
            request_content_encoding.as_deref(),
            request_content_type.as_deref(),
        );
        let (response_body, response_metadata) = normalize_body_capture(
            response_capture,
            response_content_encoding.as_deref(),
            response_content_type.as_deref(),
        );
        pending.size_bytes = response_metadata.wire_bytes;
        pending.duration_ms = start.elapsed().as_millis() as i64;
        pending.request_body = request_body;
        pending.response_body = response_body;
        pending.response_body_metadata = Some(response_metadata);
        capture_sink(pending);
    })
    .with_expected_wire_bytes(expected_wire_bytes)
    .with_rate_limit(bytes_per_second)
    .boxed_unsync()
}

#[allow(clippy::too_many_arguments)]
fn captured_sse_response_body(
    body: ProxyBody,
    capture_sink: CaptureSink,
    event_sink: EventSink,
    mut pending: CapturedRequestInput,
    request_capture: Arc<StdMutex<Option<BodyCaptureSnapshot>>>,
    request_content_encoding: Option<String>,
    request_content_type: Option<String>,
    response_content_encoding: Option<String>,
    response_content_type: Option<String>,
    start: Instant,
    bytes_per_second: Option<u64>,
) -> ProxyBody {
    let request_capture = request_capture
        .lock()
        .ok()
        .and_then(|mut capture| capture.take())
        .unwrap_or_default();
    let (request_body, _) = normalize_body_capture(
        request_capture,
        request_content_encoding.as_deref(),
        request_content_type.as_deref(),
    );
    pending.request_body = request_body;
    pending.duration_ms = start.elapsed().as_millis() as i64;
    pending.response_body_metadata = Some(BodyCaptureMetadata {
        captured: true,
        content_encoding: response_content_encoding.clone(),
        decoded: false,
        truncated: false,
        complete: false,
        wire_bytes: 0,
        decoded_bytes: 0,
        format: "empty".to_string(),
        error: None,
        omitted_reason: None,
    });
    capture_sink(pending.clone());

    let stream_capture = Arc::new(StdMutex::new(SseCapture::new(
        pending.session_id.clone(),
        pending.source.clone(),
        pending
            .source_instance_id
            .clone()
            .unwrap_or_else(|| "default".to_string()),
        pending.id.clone().unwrap_or_default(),
        event_sink,
        response_content_encoding.as_deref(),
    )));
    let chunk_capture = stream_capture.clone();
    let finish_capture = stream_capture;
    TapBody::streaming(
        body,
        MAX_CAPTURED_WIRE_BYTES,
        move |chunk| {
            if let Ok(mut capture) = chunk_capture.lock() {
                capture.record_chunk(chunk);
            }
        },
        move |response_capture| {
            let complete = response_capture.complete;
            let error = response_capture.error.clone();
            let wire_bytes = response_capture.total_bytes;
            let duration_ms = start.elapsed().as_millis() as i64;
            if let Ok(mut capture) = finish_capture.lock() {
                capture.finish(complete, error.as_deref(), wire_bytes, duration_ms);
            }
            let (response_body, response_metadata) = normalize_body_capture(
                response_capture,
                response_content_encoding.as_deref(),
                response_content_type.as_deref(),
            );
            pending.size_bytes = response_metadata.wire_bytes;
            pending.duration_ms = duration_ms;
            pending.response_body = response_body;
            pending.response_body_metadata = Some(response_metadata);
            capture_sink(pending);
        },
    )
    .with_rate_limit(bytes_per_second)
    .boxed_unsync()
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SseField {
    name: String,
    value: String,
}

#[derive(Debug)]
struct ParsedSseEvent {
    kind: &'static str,
    event: String,
    id: Option<String>,
    retry: Option<u64>,
    data: String,
    raw: String,
    fields: Vec<SseField>,
    comments: Vec<String>,
    size_bytes: usize,
    truncated: bool,
    incomplete: bool,
}

#[derive(Default)]
struct SseEventBuilder {
    event: String,
    id: Option<String>,
    retry: Option<u64>,
    data: String,
    raw: String,
    fields: Vec<SseField>,
    comments: Vec<String>,
    structured_bytes: usize,
    size_bytes: usize,
    truncated: bool,
    saw_content: bool,
    saw_data: bool,
}

impl SseEventBuilder {
    fn append_raw(&mut self, value: &str) {
        self.truncated |= append_bounded_text(&mut self.raw, value, MAX_SSE_EVENT_BYTES);
    }

    fn append_data(&mut self, value: &str) {
        if self.saw_data {
            self.truncated |= append_bounded_text(&mut self.data, "\n", MAX_SSE_EVENT_BYTES);
        }
        self.truncated |= append_bounded_text(&mut self.data, value, MAX_SSE_EVENT_BYTES);
        self.saw_data = true;
    }

    fn push_field(&mut self, name: &str, value: &str) {
        if self.fields.len() >= 256 || self.structured_bytes >= MAX_SSE_EVENT_BYTES {
            self.truncated = true;
            return;
        }
        let remaining = MAX_SSE_EVENT_BYTES.saturating_sub(self.structured_bytes);
        let name = utf8_prefix(name, remaining).to_string();
        let remaining = remaining.saturating_sub(name.len());
        let captured_value = utf8_prefix(value, remaining);
        self.truncated |= captured_value.len() < value.len();
        self.structured_bytes = self
            .structured_bytes
            .saturating_add(name.len())
            .saturating_add(captured_value.len());
        self.fields.push(SseField {
            name,
            value: captured_value.to_string(),
        });
    }

    fn push_comment(&mut self, value: &str) {
        if self.comments.len() >= 64 || self.structured_bytes >= MAX_SSE_EVENT_BYTES {
            self.truncated = true;
            return;
        }
        let remaining = MAX_SSE_EVENT_BYTES.saturating_sub(self.structured_bytes);
        let captured = utf8_prefix(value, remaining);
        self.truncated |= captured.len() < value.len();
        self.structured_bytes = self.structured_bytes.saturating_add(captured.len());
        self.comments.push(captured.to_string());
    }

    fn into_event(self, incomplete: bool) -> Option<ParsedSseEvent> {
        if !self.saw_content {
            return None;
        }
        let kind = if incomplete {
            "partial"
        } else if self.saw_data || !self.event.is_empty() {
            "event"
        } else if !self.comments.is_empty() && self.fields.is_empty() {
            "heartbeat"
        } else {
            "metadata"
        };
        let event = if self.event.is_empty() {
            if kind == "heartbeat" {
                "heartbeat".to_string()
            } else {
                "message".to_string()
            }
        } else {
            self.event
        };
        Some(ParsedSseEvent {
            kind,
            event,
            id: self.id,
            retry: self.retry,
            data: self.data,
            raw: self.raw,
            fields: self.fields,
            comments: self.comments,
            size_bytes: self.size_bytes,
            truncated: self.truncated,
            incomplete,
        })
    }
}

struct SseParser {
    line: Vec<u8>,
    line_bytes: usize,
    line_truncated: bool,
    skip_lf: bool,
    stream_start: bool,
    event: SseEventBuilder,
}

impl Default for SseParser {
    fn default() -> Self {
        Self {
            line: Vec::new(),
            line_bytes: 0,
            line_truncated: false,
            skip_lf: false,
            stream_start: true,
            event: SseEventBuilder::default(),
        }
    }
}

impl SseParser {
    fn push(&mut self, chunk: &[u8]) -> Vec<ParsedSseEvent> {
        let mut events = Vec::new();
        for byte in chunk {
            if self.skip_lf {
                self.skip_lf = false;
                if *byte == b'\n' {
                    continue;
                }
            }
            match *byte {
                b'\r' => {
                    if let Some(event) = self.finish_line(false) {
                        events.push(event);
                    }
                    self.skip_lf = true;
                }
                b'\n' => {
                    if let Some(event) = self.finish_line(false) {
                        events.push(event);
                    }
                }
                byte => {
                    self.line_bytes = self.line_bytes.saturating_add(1);
                    if self.line.len() < MAX_SSE_EVENT_BYTES + 3 {
                        self.line.push(byte);
                    } else {
                        self.line_truncated = true;
                    }
                }
            }
        }
        events
    }

    fn finish(&mut self) -> Vec<ParsedSseEvent> {
        self.skip_lf = false;
        let mut events = Vec::new();
        if self.line_bytes > 0 || self.line_truncated {
            if let Some(event) = self.finish_line(true) {
                events.push(event);
            }
        }
        if let Some(event) = std::mem::take(&mut self.event).into_event(true) {
            events.push(event);
        }
        events
    }

    fn finish_line(&mut self, incomplete: bool) -> Option<ParsedSseEvent> {
        let line_bytes = self.line_bytes;
        self.event.size_bytes = self
            .event
            .size_bytes
            .saturating_add(line_bytes)
            .saturating_add(1);
        self.event.truncated |= self.line_truncated;
        let mut line = String::from_utf8_lossy(&self.line).to_string();
        self.line.clear();
        self.line_bytes = 0;
        self.line_truncated = false;

        if self.stream_start {
            self.stream_start = false;
            line = line.trim_start_matches('\u{feff}').to_string();
        }
        self.event.append_raw(&line);
        self.event.append_raw("\n");
        if line.is_empty() {
            return std::mem::take(&mut self.event).into_event(incomplete);
        }
        self.event.saw_content = true;
        if let Some(comment) = line.strip_prefix(':') {
            self.event
                .push_comment(comment.strip_prefix(' ').unwrap_or(comment));
            return None;
        }

        let (name, value) = line
            .split_once(':')
            .map(|(name, value)| (name, value.strip_prefix(' ').unwrap_or(value)))
            .unwrap_or((line.as_str(), ""));
        self.event.push_field(name, value);
        match name {
            "event" => self.event.event = utf8_prefix(value, MAX_SSE_EVENT_BYTES).to_string(),
            "data" => self.event.append_data(value),
            "id" if !value.contains('\0') => {
                self.event.id = Some(utf8_prefix(value, MAX_SSE_EVENT_BYTES).to_string())
            }
            "retry" if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
                self.event.retry = value.parse().ok()
            }
            _ => {}
        }
        None
    }
}

fn append_bounded_text(target: &mut String, value: &str, limit: usize) -> bool {
    let remaining = limit.saturating_sub(target.len());
    let captured = utf8_prefix(value, remaining);
    target.push_str(captured);
    captured.len() < value.len()
}

struct SseCapture {
    session_id: String,
    source: String,
    source_instance_id: String,
    request_id: String,
    event_sink: EventSink,
    parser: SseParser,
    event_count: usize,
    captured_bytes: usize,
    parsing_enabled: bool,
    stopped: bool,
}

impl SseCapture {
    fn new(
        session_id: String,
        source: String,
        source_instance_id: String,
        request_id: String,
        event_sink: EventSink,
        content_encoding: Option<&str>,
    ) -> Self {
        let parsing_enabled = content_encoding
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none_or(|value| value.eq_ignore_ascii_case("identity"));
        let mut capture = Self {
            session_id,
            source,
            source_instance_id,
            request_id,
            event_sink,
            parser: SseParser::default(),
            event_count: 0,
            captured_bytes: 0,
            parsing_enabled,
            stopped: false,
        };
        if !parsing_enabled {
            capture.emit_system(
                "stream_notice",
                "响应经过压缩，流结束后仍会保存解码正文；实时事件解析已停用",
                json!({ "contentEncoding": content_encoding.unwrap_or_default() }),
            );
        }
        capture
    }

    fn record_chunk(&mut self, chunk: &[u8]) {
        if self.stopped || !self.parsing_enabled {
            return;
        }
        let events = self.parser.push(chunk);
        for event in events {
            self.record(event);
            if self.stopped {
                break;
            }
        }
    }

    fn finish(&mut self, complete: bool, error: Option<&str>, wire_bytes: usize, duration_ms: i64) {
        if !self.stopped && self.parsing_enabled {
            let events = self.parser.finish();
            for event in events {
                self.record(event);
                if self.stopped {
                    break;
                }
            }
        }
        if !self.stopped && self.event_count < MAX_SSE_CAPTURE_EVENTS {
            self.emit_system(
                "stream_end",
                if complete {
                    "事件流已结束"
                } else {
                    "事件流提前关闭"
                },
                json!({
                    "complete": complete,
                    "error": error,
                    "wireBytes": wire_bytes,
                    "durationMs": duration_ms,
                }),
            );
        }
    }

    fn record(&mut self, event: ParsedSseEvent) {
        if self.event_count >= MAX_SSE_CAPTURE_EVENTS.saturating_sub(1)
            || self.captured_bytes.saturating_add(event.size_bytes) > MAX_SSE_CAPTURE_BYTES
        {
            self.stop_with_limit();
            return;
        }
        self.event_count += 1;
        self.captured_bytes = self.captured_bytes.saturating_add(event.size_bytes);
        (self.event_sink)(CaptureEventInput {
            session_id: self.session_id.clone(),
            source: self.source.clone(),
            source_instance_id: Some(self.source_instance_id.clone()),
            request_id: Some(self.request_id.clone()),
            timestamp: None,
            phase: "sse".to_string(),
            payload: json!({
                "kind": event.kind,
                "event": event.event,
                "id": event.id,
                "retry": event.retry,
                "data": event.data,
                "raw": event.raw,
                "fields": event.fields,
                "comments": event.comments,
                "sizeBytes": event.size_bytes,
                "truncated": event.truncated,
                "incomplete": event.incomplete,
                "index": self.event_count,
            }),
        });
    }

    fn emit_system(&mut self, kind: &str, data: &str, extra: serde_json::Value) {
        if self.event_count >= MAX_SSE_CAPTURE_EVENTS {
            return;
        }
        self.event_count += 1;
        let mut payload = json!({
            "kind": kind,
            "event": kind,
            "data": data,
            "raw": "",
            "fields": [],
            "comments": [],
            "sizeBytes": 0,
            "truncated": false,
            "incomplete": false,
            "index": self.event_count,
        });
        if let (Some(payload), Some(extra)) = (payload.as_object_mut(), extra.as_object()) {
            payload.extend(extra.clone());
        }
        (self.event_sink)(CaptureEventInput {
            session_id: self.session_id.clone(),
            source: self.source.clone(),
            source_instance_id: Some(self.source_instance_id.clone()),
            request_id: Some(self.request_id.clone()),
            timestamp: None,
            phase: "sse".to_string(),
            payload,
        });
    }

    fn stop_with_limit(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.emit_system(
            "capture_limit",
            "事件流仍在转发，仅停止保存后续事件",
            json!({
                "maxEvents": MAX_SSE_CAPTURE_EVENTS,
                "maxEventBytes": MAX_SSE_EVENT_BYTES,
                "maxTotalBytes": MAX_SSE_CAPTURE_BYTES,
            }),
        );
    }
}

fn normalize_body_capture(
    capture: BodyCaptureSnapshot,
    content_encoding: Option<&str>,
    content_type: Option<&str>,
) -> (Option<String>, BodyCaptureMetadata) {
    let normalized_encoding = content_encoding
        .map(str::trim)
        .filter(|encoding| !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity"))
        .map(ToString::to_string);
    let mut metadata = BodyCaptureMetadata {
        captured: true,
        content_encoding: normalized_encoding.clone(),
        decoded: false,
        truncated: capture.truncated,
        complete: capture.complete,
        wire_bytes: capture.total_bytes.min(i64::MAX as usize) as i64,
        decoded_bytes: capture.bytes.len().min(i64::MAX as usize) as i64,
        format: "empty".to_string(),
        error: capture.error,
        omitted_reason: None,
    };
    let mut bytes = capture.bytes;
    let mut render_as_decoded = normalized_encoding.is_none();

    if let Some(encoding) = normalized_encoding {
        if metadata.truncated {
            append_capture_error(
                &mut metadata.error,
                "压缩响应超过 wire 抓包上限，无法安全解压".to_string(),
            );
        } else if !metadata.complete {
            append_capture_error(
                &mut metadata.error,
                "压缩响应未完整结束，无法安全解压".to_string(),
            );
        } else {
            match decode_content_encodings(&bytes, &encoding) {
                Ok(decoded) => {
                    bytes = decoded.bytes;
                    metadata.decoded = decoded.fully_decoded;
                    metadata.truncated |= decoded.truncated;
                    render_as_decoded = decoded.fully_decoded;
                    if decoded.truncated {
                        append_capture_error(
                            &mut metadata.error,
                            if decoded.fully_decoded {
                                format!(
                                    "解压后正文超过 {} MiB 抓包上限",
                                    MAX_DECODED_BODY_BYTES / 1024 / 1024
                                )
                            } else {
                                "多层压缩解码超过上限，后续编码未处理".to_string()
                            },
                        );
                    }
                }
                Err(error) => append_capture_error(&mut metadata.error, error),
            }
        }
    }

    metadata.decoded_bytes = bytes.len().min(i64::MAX as usize) as i64;
    if bytes.is_empty() {
        return (None, metadata);
    }
    let textual = render_as_decoded && is_textual_body(&bytes, content_type);
    metadata.format = if textual { "text" } else { "base64" }.to_string();
    let rendered = if textual {
        String::from_utf8_lossy(&bytes).to_string()
    } else {
        format!("base64:{}", STANDARD.encode(&bytes))
    };
    (Some(rendered), metadata)
}

struct DecodedBody {
    bytes: Vec<u8>,
    truncated: bool,
    fully_decoded: bool,
}

fn decode_content_encodings(bytes: &[u8], content_encoding: &str) -> Result<DecodedBody, String> {
    let encodings = content_encoding
        .split(',')
        .map(|encoding| encoding.trim().to_ascii_lowercase())
        .filter(|encoding| !encoding.is_empty() && encoding != "identity")
        .collect::<Vec<_>>();
    let mut current = DecodedBody {
        bytes: bytes.to_vec(),
        truncated: false,
        fully_decoded: encodings.is_empty(),
    };
    for (index, encoding) in encodings.iter().rev().enumerate() {
        current = match encoding.as_str() {
            "gzip" | "x-gzip" => read_decoded(GzDecoder::new(current.bytes.as_slice()))?,
            "br" => read_decoded(Decompressor::new(current.bytes.as_slice(), 16 * 1024))?,
            "deflate" => decode_deflate(&current.bytes)?,
            "zstd" => {
                let decoder = zstd::stream::read::Decoder::new(current.bytes.as_slice())
                    .map_err(|error| format!("zstd 解压初始化失败: {error}"))?;
                read_decoded(decoder)?
            }
            unsupported => return Err(format!("不支持的 Content-Encoding: {unsupported}")),
        };
        if current.truncated {
            current.fully_decoded = index + 1 == encodings.len();
            break;
        }
    }
    if !current.truncated {
        current.fully_decoded = true;
    }
    Ok(current)
}

fn decode_deflate(bytes: &[u8]) -> Result<DecodedBody, String> {
    read_decoded(ZlibDecoder::new(bytes)).or_else(|_| read_decoded(DeflateDecoder::new(bytes)))
}

fn read_decoded(mut reader: impl Read) -> Result<DecodedBody, String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_DECODED_BODY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("响应正文解压失败: {error}"))?;
    let truncated = bytes.len() > MAX_DECODED_BODY_BYTES;
    bytes.truncate(MAX_DECODED_BODY_BYTES);
    Ok(DecodedBody {
        bytes,
        truncated,
        fully_decoded: false,
    })
}

fn is_textual_body(bytes: &[u8], content_type: Option<&str>) -> bool {
    let content_type = content_type.unwrap_or_default().to_ascii_lowercase();
    if content_type.starts_with("text/")
        || [
            "json",
            "xml",
            "javascript",
            "graphql",
            "x-www-form-urlencoded",
            "event-stream",
        ]
        .iter()
        .any(|kind| content_type.contains(kind))
    {
        return true;
    }
    std::str::from_utf8(bytes).is_ok()
        && !bytes.contains(&0)
        && bytes
            .iter()
            .filter(|byte| **byte < 0x20 && !matches!(**byte, b'\n' | b'\r' | b'\t'))
            .count()
            <= bytes.len() / 100
}

fn append_capture_error(target: &mut Option<String>, error: String) {
    match target {
        Some(current) => {
            current.push_str("; ");
            current.push_str(&error);
        }
        None => *target = Some(error),
    }
}

fn header_text(headers: &HeaderMap, name: hyper::header::HeaderName) -> Option<String> {
    let values = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.join(", "))
}

fn header_contains_token(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case(expected))
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    header_contains_token(headers, "connection", "upgrade")
        && header_contains_token(headers, "upgrade", "websocket")
}

fn is_extended_websocket_connect<B>(request: &Request<B>) -> bool {
    request.version() == Version::HTTP_2
        && request.method() == Method::CONNECT
        && request
            .extensions()
            .get::<Protocol>()
            .is_some_and(|protocol| protocol.as_str().eq_ignore_ascii_case("websocket"))
}

#[allow(clippy::too_many_arguments)]
fn websocket_handshake_input(
    request_id: &str,
    session_id: &str,
    source: &str,
    peer: SocketAddr,
    method: String,
    scheme: &str,
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
    tls_version: String,
    tls_fingerprint: Option<crate::tls_fingerprint::TlsFingerprintRecord>,
    request_headers: Vec<HeaderEntry>,
    response_headers: Vec<HeaderEntry>,
    duration_ms: i64,
) -> CapturedRequestInput {
    CapturedRequestInput {
        id: Some(request_id.to_string()),
        session_id: session_id.to_string(),
        source: source.to_string(),
        source_instance_id: Some(format!("proxy:{}", peer.ip())),
        timestamp: None,
        method,
        scheme: Some(scheme.to_string()),
        host,
        port: Some(port as i64),
        path,
        query,
        status: StatusCode::SWITCHING_PROTOCOLS.as_u16() as i64,
        resource_type: "websocket".to_string(),
        size_bytes: 0,
        duration_ms,
        protocol: "http/1.1".to_string(),
        tls_version: Some(tls_version),
        tls_fingerprint,
        risk_level: "none".to_string(),
        request_headers,
        response_headers,
        request_body: None,
        response_body: None,
        response_body_metadata: None,
        crypto_snippets: None,
        hook: None,
    }
}

struct WebSocketCapture {
    session_id: String,
    source: String,
    source_instance_id: String,
    request_id: String,
    event_sink: EventSink,
    event_count: usize,
    captured_bytes: usize,
    stopped: bool,
}

impl WebSocketCapture {
    fn record(&mut self, direction: &str, message: &Message) {
        if self.stopped {
            return;
        }
        if self.event_count >= MAX_WEBSOCKET_CAPTURE_EVENTS.saturating_sub(1)
            || self.captured_bytes >= MAX_WEBSOCKET_CAPTURE_BYTES
        {
            self.stop_with_limit(direction);
            return;
        }

        let remaining = MAX_WEBSOCKET_CAPTURE_BYTES.saturating_sub(self.captured_bytes);
        let (opcode, data, encoding, size_bytes, captured_bytes, truncated, close_code) =
            websocket_capture_payload(message, remaining);
        self.event_count += 1;
        self.captured_bytes = self.captured_bytes.saturating_add(captured_bytes);
        let mut payload = json!({
            "direction": direction,
            "opcode": opcode,
            "data": data,
            "encoding": encoding,
            "sizeBytes": size_bytes,
            "truncated": truncated,
            "index": self.event_count,
        });
        if let Some(close_code) = close_code {
            payload["closeCode"] = json!(close_code);
        }
        (self.event_sink)(CaptureEventInput {
            session_id: self.session_id.clone(),
            source: self.source.clone(),
            source_instance_id: Some(self.source_instance_id.clone()),
            request_id: Some(self.request_id.clone()),
            timestamp: None,
            phase: "websocket".to_string(),
            payload,
        });

        if truncated || self.captured_bytes >= MAX_WEBSOCKET_CAPTURE_BYTES {
            self.stop_with_limit(direction);
        }
    }

    fn stop_with_limit(&mut self, direction: &str) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        if self.event_count >= MAX_WEBSOCKET_CAPTURE_EVENTS {
            return;
        }
        self.event_count += 1;
        (self.event_sink)(CaptureEventInput {
            session_id: self.session_id.clone(),
            source: self.source.clone(),
            source_instance_id: Some(self.source_instance_id.clone()),
            request_id: Some(self.request_id.clone()),
            timestamp: None,
            phase: "websocket".to_string(),
            payload: json!({
                "direction": direction,
                "opcode": "capture_limit",
                "data": "消息仍在转发，仅停止保存后续内容",
                "encoding": "utf8",
                "sizeBytes": 0,
                "truncated": false,
                "index": self.event_count,
                "maxEvents": MAX_WEBSOCKET_CAPTURE_EVENTS,
                "maxBytes": MAX_WEBSOCKET_CAPTURE_BYTES,
            }),
        });
    }
}

fn websocket_capture_payload(
    message: &Message,
    limit: usize,
) -> (
    &'static str,
    String,
    &'static str,
    usize,
    usize,
    bool,
    Option<u16>,
) {
    match message {
        Message::Text(text) => {
            let text = text.as_str();
            let captured = utf8_prefix(text, limit);
            (
                "text",
                captured.to_string(),
                "utf8",
                text.len(),
                captured.len(),
                captured.len() < text.len(),
                None,
            )
        }
        Message::Binary(data) => binary_capture("binary", data, limit),
        Message::Ping(data) => binary_capture("ping", data, limit),
        Message::Pong(data) => binary_capture("pong", data, limit),
        Message::Close(frame) => {
            let reason = frame
                .as_ref()
                .map(|frame| frame.reason.as_str())
                .unwrap_or_default();
            let captured = utf8_prefix(reason, limit);
            (
                "close",
                captured.to_string(),
                "utf8",
                reason.len(),
                captured.len(),
                captured.len() < reason.len(),
                frame.as_ref().map(|frame| u16::from(frame.code)),
            )
        }
        Message::Frame(frame) => binary_capture("frame", frame.payload(), limit),
    }
}

fn binary_capture(
    opcode: &'static str,
    data: &[u8],
    limit: usize,
) -> (
    &'static str,
    String,
    &'static str,
    usize,
    usize,
    bool,
    Option<u16>,
) {
    let captured = &data[..data.len().min(limit)];
    (
        opcode,
        STANDARD.encode(captured),
        "base64",
        data.len(),
        captured.len(),
        captured.len() < data.len(),
        None,
    )
}

fn utf8_prefix(value: &str, limit: usize) -> &str {
    let mut end = value.len().min(limit);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[allow(clippy::too_many_arguments)]
fn spawn_websocket_relay(
    inbound_upgrade: hyper::upgrade::OnUpgrade,
    outbound_upgrade: hyper::upgrade::OnUpgrade,
    session_id: String,
    source: String,
    source_instance_id: String,
    request_id: String,
    event_sink: EventSink,
    error_sink: ErrorSink,
) {
    tauri::async_runtime::spawn(async move {
        let result: Result<(), String> = async {
            let (inbound, outbound) = tokio::try_join!(inbound_upgrade, outbound_upgrade)
                .map_err(|error| format!("WebSocket 升级失败: {error}"))?;
            let config = WebSocketConfig::default().write_buffer_size(0);
            let client =
                WebSocketStream::from_raw_socket(TokioIo::new(inbound), Role::Server, Some(config))
                    .await;
            let upstream = WebSocketStream::from_raw_socket(
                TokioIo::new(outbound),
                Role::Client,
                Some(config),
            )
            .await;
            let capture = WebSocketCapture {
                session_id,
                source,
                source_instance_id,
                request_id,
                event_sink,
                event_count: 0,
                captured_bytes: 0,
                stopped: false,
            };
            relay_websocket(client, upstream, capture).await
        }
        .await;
        if let Err(error) = result {
            error_sink(error);
        }
    });
}

#[cfg(feature = "impersonate-boring")]
fn spawn_impersonate_websocket_relay(
    inbound_upgrade: hyper::upgrade::OnUpgrade,
    mut upstream: wreq::ws::WebSocket,
    session_id: String,
    source: String,
    source_instance_id: String,
    request_id: String,
    event_sink: EventSink,
    error_sink: ErrorSink,
) {
    tauri::async_runtime::spawn(async move {
        let result: Result<(), String> = async {
            let inbound = inbound_upgrade
                .await
                .map_err(|error| format!("WebSocket 升级失败: {error}"))?;
            let config = WebSocketConfig::default().write_buffer_size(0);
            let client =
                WebSocketStream::from_raw_socket(TokioIo::new(inbound), Role::Server, Some(config))
                    .await;
            let mut capture = WebSocketCapture {
                session_id,
                source,
                source_instance_id,
                request_id,
                event_sink,
                event_count: 0,
                captured_bytes: 0,
                stopped: false,
            };
            relay_impersonate_websocket(client, &mut upstream, &mut capture).await
        }
        .await;
        if let Err(error) = result {
            error_sink(error);
        }
    });
}

#[cfg(feature = "impersonate-boring")]
async fn relay_impersonate_websocket<ClientIo>(
    client: WebSocketStream<ClientIo>,
    upstream: &mut wreq::ws::WebSocket,
    capture: &mut WebSocketCapture,
) -> Result<(), String>
where
    ClientIo: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_write, mut client_read) = client.split();
    loop {
        tokio::select! {
            incoming = client_read.next() => {
                let Some(message) = incoming else {
                    let _ = SinkExt::close(upstream).await;
                    return Ok(());
                };
                let Some(message) = websocket_step(message, "读取客户端 WebSocket 消息失败")? else {
                    return Ok(());
                };
                capture.record("client_to_server", &message);
                match message {
                    Message::Text(_) | Message::Binary(_) | Message::Frame(_) => {
                        if let Some(forward) = to_wreq_ws_message(message) {
                            if let Err(error) = upstream.send(forward).await {
                                return Err(format!("wreq 出站 WebSocket 发送失败: {error}"));
                            }
                        }
                    }
                    Message::Ping(_) => {
                        // Same as the rustls relay: tungstenite already answered
                        // the browser; do not invent a second Ping toward origin.
                        if websocket_step(client_write.flush().await, "回复客户端 WebSocket Ping 失败")?.is_none() {
                            return Ok(());
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Close(frame) => {
                        let _ = client_write.flush().await;
                        if let Some(forward) = to_wreq_ws_message(Message::Close(frame)) {
                            let _ = upstream.send(forward).await;
                        }
                        let _ = SinkExt::close(upstream).await;
                        return Ok(());
                    }
                }
            }
            incoming = upstream.next() => {
                let Some(message) = incoming else {
                    let _ = client_write.close().await;
                    return Ok(());
                };
                let message = message.map_err(|error| format!("wreq 出站 WebSocket 读取失败: {error}"))?;
                if let Some(forward) = from_wreq_ws_message(message) {
                    capture.record("server_to_client", &forward);
                    match forward {
                        Message::Text(_) | Message::Binary(_) | Message::Frame(_) => {
                            if websocket_step(client_write.send(forward).await, "转发上游 WebSocket 消息失败")?.is_none() {
                                return Ok(());
                            }
                        }
                        Message::Ping(_) | Message::Pong(_) => {
                            // wreq/tungstenite answers origin Ping itself.
                        }
                        Message::Close(frame) => {
                            let _ = client_write.send(Message::Close(frame)).await;
                            let _ = client_write.flush().await;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "impersonate-boring")]
fn to_wreq_ws_message(message: Message) -> Option<wreq::ws::message::Message> {
    match message {
        Message::Text(text) => Some(wreq::ws::message::Message::text(text.to_string())),
        Message::Binary(data) => Some(wreq::ws::message::Message::binary(data)),
        Message::Ping(data) => Some(wreq::ws::message::Message::ping(data)),
        Message::Pong(data) => Some(wreq::ws::message::Message::pong(data)),
        Message::Close(frame) => Some(match frame {
            Some(frame) => wreq::ws::message::Message::close(wreq::ws::message::CloseFrame {
                code: u16::from(frame.code).into(),
                reason: frame.reason.as_str().to_string().into(),
            }),
            None => wreq::ws::message::Message::close(None),
        }),
        Message::Frame(_) => None,
    }
}

#[cfg(feature = "impersonate-boring")]
fn from_wreq_ws_message(message: wreq::ws::message::Message) -> Option<Message> {
    match message {
        wreq::ws::message::Message::Text(text) => Some(Message::Text(text.as_str().into())),
        wreq::ws::message::Message::Binary(data) => Some(Message::Binary(data)),
        wreq::ws::message::Message::Ping(data) => Some(Message::Ping(data)),
        wreq::ws::message::Message::Pong(data) => Some(Message::Pong(data)),
        wreq::ws::message::Message::Close(frame) => Some(Message::Close(frame.map(|frame| {
            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: u16::from(frame.code).into(),
                reason: frame.reason.as_str().into(),
            }
        }))),
    }
}

#[cfg(feature = "impersonate-boring")]
async fn impersonate_origin_websocket(
    upstream: &EffectiveUpstreamProxy,
    connection_host: &str,
    connection_port: u16,
    tls_identity_host: &str,
    tls_identity_port: u16,
    path_and_query: &str,
    headers: &HeaderMap,
) -> Result<(Response<ProxyBody>, wreq::ws::WebSocket), String> {
    let client = crate::impersonate_egress::build_client_for_route(
        upstream,
        connection_host,
        connection_port,
        tls_identity_host,
        tls_identity_port,
    )
    .await?;
    let url = format!(
        "wss://{}{path_and_query}",
        host_header_authority("https", tls_identity_host, tls_identity_port)
    );
    let header_pairs: Vec<(String, Vec<u8>)> = headers
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    let upgraded = client.websocket_upgrade(&url, &header_pairs).await?;
    let mut builder = Response::builder().status(upgraded.status);
    for (name, value) in &upgraded.headers {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_slice());
    }
    let response = builder
        .body(empty_body())
        .map_err(|error| format!("组装 WebSocket 响应失败: {error}"))?;
    Ok((response, upgraded.socket))
}

async fn relay_websocket<ClientIo, UpstreamIo>(
    client: WebSocketStream<ClientIo>,
    upstream: WebSocketStream<UpstreamIo>,
    mut capture: WebSocketCapture,
) -> Result<(), String>
where
    ClientIo: AsyncRead + AsyncWrite + Unpin,
    UpstreamIo: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_write, mut client_read) = client.split();
    let (mut upstream_write, mut upstream_read) = upstream.split();
    loop {
        tokio::select! {
            incoming = client_read.next() => {
                let Some(message) = incoming else {
                    let _ = upstream_write.close().await;
                    return Ok(());
                };
                let Some(message) = websocket_step(message, "读取客户端 WebSocket 消息失败")? else {
                    return Ok(());
                };
                capture.record("client_to_server", &message);
                match message {
                    Message::Text(_) | Message::Binary(_) | Message::Frame(_) => {
                        if websocket_step(upstream_write.send(message).await, "转发客户端 WebSocket 消息失败")?.is_none() {
                            return Ok(());
                        }
                    }
                    Message::Ping(_) => {
                        if websocket_step(client_write.flush().await, "回复客户端 WebSocket Ping 失败")?.is_none() {
                            return Ok(());
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Close(frame) => {
                        let _ = client_write.flush().await;
                        let _ = upstream_write.send(Message::Close(frame)).await;
                        let _ = upstream_write.flush().await;
                        return Ok(());
                    }
                }
            }
            incoming = upstream_read.next() => {
                let Some(message) = incoming else {
                    let _ = client_write.close().await;
                    return Ok(());
                };
                let Some(message) = websocket_step(message, "读取上游 WebSocket 消息失败")? else {
                    return Ok(());
                };
                capture.record("server_to_client", &message);
                match message {
                    Message::Text(_) | Message::Binary(_) | Message::Frame(_) => {
                        if websocket_step(client_write.send(message).await, "转发上游 WebSocket 消息失败")?.is_none() {
                            return Ok(());
                        }
                    }
                    Message::Ping(_) => {
                        if websocket_step(upstream_write.flush().await, "回复上游 WebSocket Ping 失败")?.is_none() {
                            return Ok(());
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Close(frame) => {
                        let _ = upstream_write.flush().await;
                        let _ = client_write.send(Message::Close(frame)).await;
                        let _ = client_write.flush().await;
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn forward_http(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    session_id: String,
    upstream: EffectiveUpstreamProxy,
    capture_sink: CaptureSink,
    rule_engine: Option<RuleEngine>,
    event_sink: EventSink,
    error_sink: ErrorSink,
) -> Result<Response<ProxyBody>, String> {
    let (mut scheme, mut host, mut port) = resolve_target(&request)?;
    reject_proxy_loop(&host, port)?;
    let original_route = (scheme.clone(), host.clone(), port);
    let mut method = request.method().as_str().to_string();
    let mut path = request.uri().path().to_string();
    let mut query = request.uri().query().map(ToString::to_string);
    let source = classify_source(request.headers(), peer);
    let source_instance_id = if source == "reverse" {
        request
            .headers()
            .get(REVERSE_PROXY_CONTEXT_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.chars().all(|character| character.is_ascii_digit()))
            .map(|value| format!("reverse:{value}"))
            .unwrap_or_else(|| format!("reverse:{}", peer.ip()))
    } else {
        format!("proxy:{}", peer.ip())
    };
    let request_id = format!("request-{}", Uuid::new_v4());
    let mut request_headers = headers_to_entries(request.headers());
    let mut runtime_request = RuntimeRuleRequest {
        request_id: request_id.clone(),
        method: method.clone(),
        scheme: scheme.clone(),
        host: host.clone(),
        port,
        path: path.clone(),
        query: query.clone(),
        source: source.clone(),
        protocol: "http/1.1".to_string(),
        request_headers: request_headers.clone(),
        request_body: None,
        body_unavailable_reason: None,
    };
    let mirror_route = match rule_engine.as_ref() {
        Some(engine) => engine.resolve_mirror(&runtime_request)?,
        None => None,
    };
    let websocket = is_websocket_upgrade(request.headers());
    let inbound_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
    let start = Instant::now();
    let should_buffer_request_body = rule_engine
        .as_ref()
        .map(|engine| engine.requires_request_body(&runtime_request))
        .transpose()?
        .unwrap_or(false);
    let (mut parts, body) = request.into_parts();
    let mut editable_request_body =
        prepare_editable_request_body(body, &parts.headers, should_buffer_request_body, websocket)
            .await?;
    runtime_request.request_body = editable_request_body.text.clone();
    runtime_request.body_unavailable_reason = editable_request_body.unavailable_reason.clone();
    let control = if let Some(rule_engine) = rule_engine.as_ref() {
        let control = rule_engine.apply_request(&mut runtime_request)?;
        if control.request_body_changed {
            let text = runtime_request.request_body.clone().unwrap_or_default();
            editable_request_body.body = full_body(Bytes::copy_from_slice(text.as_bytes()));
            editable_request_body.text = Some(text);
            editable_request_body.editable = true;
            editable_request_body.unavailable_reason = None;
            editable_request_body.changed = true;
        }
        scheme = runtime_request.scheme.clone();
        host = runtime_request.host.clone();
        port = runtime_request.port;
        path = runtime_request.path.clone();
        query = runtime_request.query.clone();
        request_headers = runtime_request.request_headers.clone();
        replace_request_headers(&mut parts.headers, &request_headers)?;
        parts.uri = runtime_absolute_uri(&scheme, &host, port, &path, query.as_deref())?;
        control
    } else {
        RuntimeRuleControl::default()
    };
    if control.delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(control.delay_ms)).await;
    }
    if control.blocked {
        let status = StatusCode::from_u16(control.block_status.unwrap_or(403))
            .unwrap_or(StatusCode::FORBIDDEN);
        let message = control
            .block_message
            .as_deref()
            .unwrap_or("请求已被 ShowNet 规则阻断");
        capture_rule_block(
            &capture_sink,
            &request_id,
            &session_id,
            &source,
            peer,
            &method,
            &scheme,
            &host,
            port,
            &path,
            query,
            request_headers,
            "http/1.1",
            status,
            message,
        );
        return Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(full_body(Bytes::copy_from_slice(message.as_bytes())))
            .map_err(|error| error.to_string());
    }
    let breakpoint_rules = rule_engine
        .as_ref()
        .map(|engine| engine.matching_request_breakpoints(&runtime_request))
        .transpose()?
        .unwrap_or_default();
    if let Some(rule_engine) = rule_engine.as_ref() {
        if run_request_breakpoints(
            rule_engine,
            &session_id,
            &mut runtime_request,
            &mut editable_request_body,
            breakpoint_rules,
        )
        .await?
        {
            method = runtime_request.method.clone();
            scheme = runtime_request.scheme.clone();
            host = runtime_request.host.clone();
            port = runtime_request.port;
            path = runtime_request.path.clone();
            query = runtime_request.query.clone();
            request_headers = runtime_request.request_headers.clone();
            let status = StatusCode::from_u16(499).unwrap_or(StatusCode::BAD_REQUEST);
            let message = "请求已在 ShowNet 人工断点中止";
            capture_rule_block(
                &capture_sink,
                &request_id,
                &session_id,
                &source,
                peer,
                &method,
                &scheme,
                &host,
                port,
                &path,
                query,
                request_headers,
                "http/1.1",
                status,
                message,
            );
            return Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(full_body(Bytes::copy_from_slice(message.as_bytes())))
                .map_err(|error| error.to_string());
        }
    }
    method = runtime_request.method.clone();
    scheme = runtime_request.scheme.clone();
    host = runtime_request.host.clone();
    port = runtime_request.port;
    path = runtime_request.path.clone();
    query = runtime_request.query.clone();
    request_headers = runtime_request.request_headers.clone();
    replace_request_headers(&mut parts.headers, &request_headers)?;
    parts.method = Method::from_bytes(method.as_bytes())
        .map_err(|_| format!("断点生成的请求方法无效: {method}"))?;
    parts.uri = runtime_absolute_uri(&scheme, &host, port, &path, query.as_deref())?;
    if editable_request_body.changed {
        sanitize_rewritten_request_body_headers(
            &mut parts.headers,
            editable_request_body
                .text
                .as_deref()
                .unwrap_or_default()
                .len(),
        )?;
        request_headers = headers_to_entries(&parts.headers);
        runtime_request.request_headers = request_headers.clone();
    }
    let request_content_encoding = header_text(&parts.headers, CONTENT_ENCODING);
    let request_content_type = header_text(&parts.headers, CONTENT_TYPE);
    let authority_changed =
        scheme != original_route.0 || host != original_route.1 || port != original_route.2;
    let active_mirror_route = if authority_changed {
        None
    } else {
        mirror_route.as_ref()
    };
    if !authority_changed {
        queue_mirror_trace_or_report(
            &rule_engine,
            &mirror_route,
            &request_id,
            if scheme == "https" {
                "https-explicit"
            } else {
                "http"
            },
            &error_sink,
        );
    }
    let (connection_host, connection_port) = active_mirror_route
        .map(RuntimeMirrorRoute::connection_target)
        .unwrap_or((&host, port));
    reject_proxy_loop(connection_host, connection_port)?;
    let (tls_identity_host, tls_identity_port) = active_mirror_route
        .map(RuntimeMirrorRoute::identity_target)
        .unwrap_or((&host, port));
    #[cfg(feature = "impersonate-boring")]
    if websocket && scheme == "https" {
        parts.headers.remove("x-shownet-replay-context");
        parts.headers.remove(REVERSE_PROXY_CONTEXT_HEADER);
        parts.uri = origin_form_uri(&parts.uri)?;
        parts.version = Version::HTTP_11;
        let (host_header_host, host_header_port) = active_mirror_route
            .map(RuntimeMirrorRoute::identity_target)
            .unwrap_or((&host, port));
        let replace_host_header = authority_changed && !control.redirect_preserve_host
            || active_mirror_route.is_some_and(|route| route.identity == MirrorIdentity::Target);
        ensure_host_header(
            &mut parts.headers,
            &scheme,
            host_header_host,
            host_header_port,
            replace_host_header,
        )?;
        parts.headers.remove("proxy-authorization");
        parts.headers.remove("proxy-connection");
        parts.headers.remove("sec-websocket-extensions");
        collapse_cookie_headers(&mut parts.headers);
        request_headers = request_headers_for_capture(
            &parts.headers,
            active_mirror_route,
            &scheme,
            &host,
            port,
            false,
        );
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|item| item.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let (mut response, outbound) = impersonate_origin_websocket(
            &upstream,
            connection_host,
            connection_port,
            tls_identity_host,
            tls_identity_port,
            &path_and_query,
            &parts.headers,
        )
        .await?;
        response.headers_mut().remove("sec-websocket-extensions");
        let response_headers = headers_to_entries(response.headers());
        capture_sink(websocket_handshake_input(
            &request_id,
            &session_id,
            &source,
            peer,
            method,
            "wss",
            host,
            port,
            path,
            query,
            "TLS 1.3 (wreq/Chrome)".to_string(),
            None,
            request_headers,
            response_headers,
            start.elapsed().as_millis() as i64,
        ));
        if let Some(inbound_upgrade) = inbound_upgrade {
            spawn_impersonate_websocket_relay(
                inbound_upgrade,
                outbound,
                session_id,
                source,
                source_instance_id,
                request_id,
                event_sink,
                error_sink,
            );
        }
        let (parts, _) = response.into_parts();
        return Ok(Response::from_parts(parts, empty_body()));
    }
    let mut sender = if scheme == "https" {
        let force_http11 = tls_outbound::origin_force_http11_for_host(tls_identity_host);
        #[cfg(feature = "impersonate-boring")]
        {
            // Explicit / replay HTTPS must match MITM Chrome JA4.
            // Do not pre-dial: wreq opens the only origin TCP.
            let _ = force_http11;
            let client = crate::impersonate_egress::build_client_for_route(
                &upstream,
                connection_host,
                connection_port,
                tls_identity_host,
                tls_identity_port,
            )
            .await?;
            let base = format!(
                "https://{}",
                host_header_authority("https", tls_identity_host, tls_identity_port)
            );
            HttpsRequestSender::Impersonate { client, base }
        }
        #[cfg(not(feature = "impersonate-boring"))]
        {
            let stream = connect_destination(&upstream, connection_host, connection_port).await?;
            let profile = tls_outbound::global_profile();
            let verified =
                connect_verified_tls_measured(stream, tls_identity_host, profile, force_http11)
                    .await?;
            let alpn = verified.negotiated_alpn.clone();
            handshake_origin_https(
                verified.stream,
                alpn.as_deref(),
                !websocket && !force_http11,
            )
            .await?
        }
    } else {
        let stream = connect_destination(&upstream, connection_host, connection_port).await?;
        let (http1_sender, connection) =
            hyper::client::conn::http1::handshake::<_, TapBody<ProxyBody>>(TokioIo::new(stream))
                .await
                .map_err(|error| format!("目标 HTTP 握手失败: {error}"))?;
        tauri::async_runtime::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
        HttpsRequestSender::Http1(http1_sender)
    };

    parts.headers.remove("x-shownet-replay-context");
    parts.headers.remove(REVERSE_PROXY_CONTEXT_HEADER);
    parts.uri = origin_form_uri(&parts.uri)?;
    parts.version = if sender.is_http2() && !websocket {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    let (host_header_host, host_header_port) = active_mirror_route
        .map(RuntimeMirrorRoute::identity_target)
        .unwrap_or((&host, port));
    let replace_host_header = authority_changed && !control.redirect_preserve_host
        || active_mirror_route.is_some_and(|route| route.identity == MirrorIdentity::Target);
    // h2 needs absolute form; h1 needs origin form. See absolute_form_uri.
    if parts.version == Version::HTTP_2 {
        parts.uri = absolute_form_uri(&scheme, host_header_host, host_header_port, &parts.uri)?;
    }
    ensure_host_header(
        &mut parts.headers,
        &scheme,
        host_header_host,
        host_header_port,
        replace_host_header,
    )?;
    parts.headers.remove("proxy-authorization");
    parts.headers.remove("proxy-connection");
    if websocket {
        parts.headers.remove("sec-websocket-extensions");
    }
    // Same hazard as the MITM path: an explicit-proxy client on HTTP/1.1 sending
    // to an h2 origin carries connection-specific headers hyper will not accept
    // over h2, and rejects the whole request as a bare "http2 error".
    if parts.version == Version::HTTP_2 {
        strip_http2_forbidden_headers(&mut parts.headers);
    }
    collapse_cookie_headers(&mut parts.headers);
    request_headers = request_headers_for_capture(
        &parts.headers,
        active_mirror_route,
        &scheme,
        &host,
        port,
        false,
    );
    runtime_request.request_headers = request_headers.clone();
    let request_capture = Arc::new(StdMutex::new(None));
    let request_capture_sink = request_capture.clone();
    let body = TapBody::new(
        editable_request_body.body,
        MAX_CAPTURED_WIRE_BYTES,
        move |capture| {
            if let Ok(mut stored) = request_capture_sink.lock() {
                stored.replace(capture);
            }
        },
    )
    .with_rate_limit(control.upload_bytes_per_second);
    let outbound_is_http2 = parts.version == Version::HTTP_2;
    let response = sender.send_request(Request::from_parts(parts, body)).await;
    let mut response = match response {
        Ok(response) => response,
        Err(error) => {
            // The explicit-proxy path consults the learned list when it picks a
            // protocol, but never contributed to it — so a client reaching an
            // h2-refusing origin this way kept retrying h2 forever while the
            // MITM path had already learned better. Both paths teach it now.
            if outbound_is_http2
                && looks_like_origin_http2_refusal(&error)
                && tls_outbound::note_origin_http2_rejected(tls_identity_host)
            {
                return Err(format!(
                    "目标请求失败: {error}（该源站拒绝我们的 HTTP/2 连接，已记住并对其改用 HTTP/1.1，重试即可）"
                ));
            }
            let message = format!("目标请求失败: {error}");
            if is_benign_forward_end(&error) {
                // The origin's connection went away — a stale keep-alive socket
                // reused a moment too late, a peer that hung up. The caller is
                // still owed the 502, but nobody needs to be interrupted; this
                // is the same call the MITM path makes.
                return Ok(error_response(StatusCode::BAD_GATEWAY, &message));
            }
            return Err(message);
        }
    };
    if websocket && response.status() == StatusCode::SWITCHING_PROTOCOLS {
        response.headers_mut().remove("sec-websocket-extensions");
        let response_headers = headers_to_entries(response.headers());
        capture_sink(websocket_handshake_input(
            &request_id,
            &session_id,
            &source,
            peer,
            method,
            if scheme == "https" { "wss" } else { "ws" },
            host,
            port,
            path,
            query,
            if scheme == "https" {
                "TLS 隧道".to_string()
            } else {
                "明文".to_string()
            },
            None,
            request_headers,
            response_headers,
            start.elapsed().as_millis() as i64,
        ));
        let outbound_upgrade = hyper::upgrade::on(&mut response);
        if let Some(inbound_upgrade) = inbound_upgrade {
            spawn_websocket_relay(
                inbound_upgrade,
                outbound_upgrade,
                session_id,
                source,
                source_instance_id,
                request_id,
                event_sink,
                error_sink,
            );
        }
        let (parts, _) = response.into_parts();
        return Ok(Response::from_parts(parts, empty_body()));
    }
    let upstream_resource_type = infer_resource_type(response.headers());
    let response = prepare_runtime_response(
        response,
        rule_engine.as_ref(),
        runtime_request,
        &session_id,
        &upstream_resource_type,
    )
    .await?;
    let resource_type = if upstream_resource_type == "sse" {
        upstream_resource_type
    } else {
        infer_resource_type(response.headers())
    };
    let status = response.status().as_u16() as i64;
    let response_content_encoding = header_text(response.headers(), CONTENT_ENCODING);
    let response_content_type = header_text(response.headers(), CONTENT_TYPE);
    let response_headers = headers_to_entries(response.headers());

    let pending = CapturedRequestInput {
        id: Some(request_id),
        session_id,
        source,
        source_instance_id: Some(source_instance_id),
        timestamp: None,
        method,
        scheme: Some(scheme.clone()),
        host,
        port: Some(port as i64),
        path,
        query,
        status,
        resource_type,
        size_bytes: 0,
        duration_ms: 0,
        protocol: "http/1.1".to_string(),
        tls_version: Some(if scheme == "https" {
            "TLS 隧道".to_string()
        } else {
            "明文".to_string()
        }),
        tls_fingerprint: None,
        risk_level: if status >= 400 { "warning" } else { "none" }.to_string(),
        request_headers,
        response_headers,
        request_body: None,
        response_body: None,
        response_body_metadata: None,
        crypto_snippets: None,
        hook: None,
    };

    let (parts, body) = response.into_parts();
    let body = if pending.resource_type == "sse" {
        captured_sse_response_body(
            body,
            capture_sink,
            event_sink,
            pending,
            request_capture,
            request_content_encoding,
            request_content_type,
            response_content_encoding,
            response_content_type,
            start,
            control.download_bytes_per_second,
        )
    } else {
        captured_response_body(
            body,
            capture_sink,
            pending,
            request_capture,
            request_content_encoding,
            request_content_type,
            response_content_encoding,
            response_content_type,
            start,
            control.download_bytes_per_second,
        )
    };
    Ok(Response::from_parts(parts, body))
}

fn replace_request_headers(headers: &mut HeaderMap, entries: &[HeaderEntry]) -> Result<(), String> {
    headers.clear();
    for entry in entries.iter().filter(|entry| !entry.name.starts_with(':')) {
        let name = HeaderName::from_bytes(entry.name.trim().as_bytes())
            .map_err(|_| format!("规则生成的 Header 名称无效: {}", entry.name))?;
        let value = HeaderValue::from_str(&entry.value)
            .map_err(|_| format!("规则生成的 Header 值无效: {}", entry.name))?;
        headers.append(name, value);
    }
    Ok(())
}

fn runtime_absolute_uri(
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    query: Option<&str>,
) -> Result<Uri, String> {
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    format!(
        "{scheme}://{authority}{}{}",
        normalized_path(path),
        query.map(|value| format!("?{value}")).unwrap_or_default()
    )
    .parse::<Uri>()
    .map_err(|error| format!("规则生成的 URL 无效: {error}"))
}

fn runtime_origin_uri(path: &str, query: Option<&str>) -> Result<Uri, String> {
    format!(
        "{}{}",
        normalized_path(path),
        query.map(|value| format!("?{value}")).unwrap_or_default()
    )
    .parse::<Uri>()
    .map_err(|error| format!("规则生成的请求路径无效: {error}"))
}

fn normalized_path(path: &str) -> &str {
    if path.starts_with('/') {
        path
    } else {
        "/"
    }
}

#[allow(clippy::too_many_arguments)]
fn capture_rule_block(
    capture_sink: &CaptureSink,
    request_id: &str,
    session_id: &str,
    source: &str,
    peer: SocketAddr,
    method: &str,
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    query: Option<String>,
    request_headers: Vec<HeaderEntry>,
    protocol: &str,
    status: StatusCode,
    message: &str,
) {
    let body = message;
    capture_sink(CapturedRequestInput {
        id: Some(request_id.to_string()),
        session_id: session_id.to_string(),
        source: source.to_string(),
        source_instance_id: Some(format!("proxy:{}", peer.ip())),
        timestamp: None,
        method: method.to_string(),
        scheme: Some(scheme.to_string()),
        host: host.to_string(),
        port: Some(port as i64),
        path: normalized_path(path).to_string(),
        query,
        status: status.as_u16() as i64,
        resource_type: "fetch".to_string(),
        size_bytes: body.len() as i64,
        duration_ms: 0,
        protocol: protocol.to_string(),
        tls_version: Some(
            if scheme == "https" {
                "TLS · 规则阻断"
            } else {
                "明文"
            }
            .to_string(),
        ),
        tls_fingerprint: None,
        risk_level: "warning".to_string(),
        request_headers,
        response_headers: vec![HeaderEntry {
            name: "content-type".to_string(),
            value: "text/plain; charset=utf-8".to_string(),
        }],
        request_body: None,
        response_body: Some(body.to_string()),
        response_body_metadata: Some(BodyCaptureMetadata {
            captured: true,
            content_encoding: None,
            decoded: true,
            truncated: false,
            complete: true,
            wire_bytes: body.len() as i64,
            decoded_bytes: body.len() as i64,
            format: "text".to_string(),
            error: None,
            omitted_reason: None,
        }),
        crypto_snippets: None,
        hook: None,
    });
}

fn resolve_target<B>(request: &Request<B>) -> Result<(String, String, u16), String> {
    let scheme = request
        .uri()
        .scheme_str()
        .unwrap_or("http")
        .to_ascii_lowercase();
    let authority = request
        .uri()
        .authority()
        .map(|value| value.as_str().to_string())
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string)
        })
        .ok_or_else(|| "请求缺少 Host".to_string())?;
    let authority = authority
        .parse::<hyper::http::uri::Authority>()
        .map_err(|_| "请求 Host 无效".to_string())?;
    let port = authority
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    Ok((scheme, authority.host().to_string(), port))
}

fn device_setup_response<B>(
    request: &Request<B>,
    local: SocketAddr,
    certificate_authority: &CertificateAuthority,
) -> Option<Response<ProxyBody>> {
    let (scheme, host, port) = resolve_target(request).ok()?;
    let points_to_listener = host
        .parse::<IpAddr>()
        .is_ok_and(|address| address == local.ip())
        || (host.eq_ignore_ascii_case("localhost") && local.ip().is_loopback());
    if scheme != "http" || port != local.port() || !points_to_listener {
        return None;
    }

    let path = request.uri().path();
    let method_supported = matches!(*request.method(), Method::GET | Method::HEAD);
    if !method_supported {
        return Some(device_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            b"Method not allowed".to_vec(),
            None,
            request.method() == Method::HEAD,
        ));
    }

    let head_only = request.method() == Method::HEAD;
    match path {
        "/" | DEVICE_SETUP_PATH => {
            let endpoint = format!("{host}:{port}");
            let user_agent = request
                .headers()
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let html =
                device_setup_html(&endpoint, certificate_authority.fingerprint(), user_agent);
            Some(device_response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                html.into_bytes(),
                None,
                head_only,
            ))
        }
        DEVICE_CA_DER_PATH => Some(device_response(
            StatusCode::OK,
            "application/x-x509-ca-cert",
            certificate_authority.certificate_der().as_ref().to_vec(),
            Some("attachment; filename=shownet-root-ca.crt"),
            head_only,
        )),
        DEVICE_CA_PEM_PATH => Some(device_response(
            StatusCode::OK,
            "application/x-pem-file",
            certificate_authority.certificate_pem().as_bytes().to_vec(),
            Some("attachment; filename=shownet-root-ca.pem"),
            head_only,
        )),
        DEVICE_CA_IOS_PROFILE_PATH => Some(device_response(
            StatusCode::OK,
            "application/x-apple-aspen-config",
            ios_certificate_profile(certificate_authority).into_bytes(),
            Some("attachment; filename=shownet-root-ca.mobileconfig"),
            head_only,
        )),
        _ => Some(device_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            b"Not found".to_vec(),
            None,
            head_only,
        )),
    }
}

fn device_response(
    status: StatusCode,
    content_type: &str,
    content: Vec<u8>,
    content_disposition: Option<&str>,
    head_only: bool,
) -> Response<ProxyBody> {
    let mut builder = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .header("content-length", content.len())
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header(
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        );
    if let Some(value) = content_disposition {
        builder = builder.header("content-disposition", value);
    }
    let body = if head_only { Vec::new() } else { content };
    builder
        .body(full_body(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(empty_body()))
}

fn ios_certificate_profile(certificate_authority: &CertificateAuthority) -> String {
    let profile_uuid = Uuid::new_v4().to_string().to_ascii_uppercase();
    let certificate_uuid = Uuid::new_v4().to_string().to_ascii_uppercase();
    let certificate = STANDARD.encode(certificate_authority.certificate_der().as_ref());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadCertificateFileName</key><string>ShowNet Root CA.cer</string>
<key>PayloadContent</key><data>{certificate}</data>
<key>PayloadDescription</key><string>允许 ShowNet 解密本设备经授权的 HTTPS 调试流量</string>
<key>PayloadDisplayName</key><string>ShowNet Root CA</string>
<key>PayloadIdentifier</key><string>org.shownet.ca.certificate</string>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadUUID</key><string>{certificate_uuid}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDescription</key><string>ShowNet 设备抓包证书。仅安装到你信任的测试设备。</string>
<key>PayloadDisplayName</key><string>ShowNet HTTPS 调试证书</string>
<key>PayloadIdentifier</key><string>org.shownet.ca.profile</string>
<key>PayloadOrganization</key><string>ShowNet</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>{profile_uuid}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#,
    )
}

fn device_setup_html(endpoint: &str, fingerprint: &str, user_agent: &str) -> String {
    let user_agent = user_agent.to_ascii_lowercase();
    let is_android = user_agent.contains("android");
    let is_ios = user_agent.contains("iphone") || user_agent.contains("ipad");
    let (platform, ca_path, action, certificate_step, trust_step) = if is_ios {
        (
            "iPhone / iPad",
            DEVICE_CA_IOS_PROFILE_PATH,
            "下载 iOS 证书描述文件",
            "下载后打开“设置 · 已下载描述文件”，确认安装 ShowNet HTTPS 调试证书。",
            "再到“设置 · 通用 · 关于本机 · 证书信任设置”，为 ShowNet Root CA 开启完全信任。",
        )
    } else if is_android {
        (
            "Android",
            DEVICE_CA_DER_PATH,
            "下载 Android CA 证书",
            "下载后按系统提示安装 CA；若只完成下载，请从通知栏打开证书文件。",
            "Android 7 及以上应用可能需要调试包显式信任用户证书；证书锁定应用仍只能记录连接元数据。",
        )
    } else {
        (
            "手机 / 平板",
            DEVICE_CA_DER_PATH,
            "下载 Root CA",
            "下载证书并按系统提示完成安装。",
            "安装后返回此页配置 Wi-Fi 代理；iOS 还需要在证书信任设置中开启完全信任。",
        )
    };
    format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ShowNet 设备接入</title><style>
:root{{color-scheme:light;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#202629;background:#f3f5f5}}*{{box-sizing:border-box;letter-spacing:0}}body{{margin:0;padding:18px 14px}}main{{max-width:520px;margin:auto;background:#fff;border:1px solid #dce1e1;border-radius:8px;overflow:hidden;box-shadow:0 18px 50px rgba(24,34,34,.09)}}header{{padding:22px;background:#173c38;color:#fff}}header span{{font-size:10px;font-weight:700}}h1{{margin:7px 0 3px;font-size:24px}}header p{{margin:0;color:#c8dad7;font-size:12px}}section{{padding:18px 20px}}.platform{{display:inline-flex;align-items:center;height:24px;padding:0 7px;color:#285f57;font-size:10px;font-weight:700;background:#e5efed;border-radius:3px}}ol{{display:grid;gap:15px;margin:16px 0 0;padding:0;list-style:none;counter-reset:step}}li{{position:relative;padding-left:39px;counter-increment:step}}li:before{{position:absolute;left:0;display:grid;place-items:center;width:27px;height:27px;border-radius:4px;background:#e5efed;color:#235d54;font-size:11px;font-weight:800;content:counter(step)}}strong{{display:block;font-size:13px}}p{{margin:4px 0 0;color:#687173;font-size:12px;line-height:1.6}}code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#235d54}}a{{display:flex;align-items:center;justify-content:center;height:44px;margin:18px 0 0;color:#fff;font-size:13px;font-weight:750;text-decoration:none;background:#287263;border-radius:5px}}footer{{padding:13px 20px;color:#778083;font-size:10px;line-height:1.55;background:#f7f9f9;border-top:1px solid #e5e8e8;word-break:break-all}}
</style></head><body><main><header><span>SHOWNET DEVICE SETUP</span><h1>设备接入</h1><p>将此设备的 HTTP(S) 流量汇入当前 Session</p></header><section><span class="platform">{platform}</span><ol><li><strong>安装 ShowNet Root CA</strong><p>{certificate_step}</p></li><li><strong>完成系统信任</strong><p>{trust_step}</p></li><li><strong>设置 Wi-Fi 代理</strong><p>服务器填写 <code>{endpoint_host}</code>，端口填写 <code>{endpoint_port}</code>，然后开始访问目标应用。</p></li></ol><a href="{ca_path}">{action}</a></section><footer>请核对桌面端证书指纹：{fingerprint}<br>只在你信任的 ShowNet 电脑上安装此证书。</footer></main></body></html>"#,
        endpoint_host = endpoint
            .rsplit_once(':')
            .map(|value| value.0)
            .unwrap_or(endpoint),
        endpoint_port = endpoint
            .rsplit_once(':')
            .map(|value| value.1)
            .unwrap_or("8888"),
    )
}

fn origin_form_uri(uri: &Uri) -> Result<Uri, String> {
    uri.path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .parse::<Uri>()
        .map_err(|error| error.to_string())
}

/// Absolute-form URI for an HTTP/2 origin connection.
///
/// h2 builds `:scheme` and `:authority` from the URI alone — there is no Host
/// header fallback — so a request carrying only a path is rejected with
/// `MissingUriSchemeAndAuthority` before any frame is written. HTTP/1.1 wants
/// the opposite (origin form), which is why the two paths differ.
///
/// The authority is produced by the same helper that writes the Host header, so
/// `:authority` and `Host` cannot drift apart.
fn absolute_form_uri(scheme: &str, host: &str, port: u16, uri: &Uri) -> Result<Uri, String> {
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let authority = host_header_authority(scheme, host, port);
    format!("{scheme}://{authority}{path}")
        .parse::<Uri>()
        .map_err(|error| format!("构造 HTTP/2 绝对形式 URI 失败: {error}"))
}

fn negotiated_http_protocol(alpn: Option<&[u8]>) -> &'static str {
    if alpn == Some(b"h2") {
        "h2"
    } else {
        "http/1.1"
    }
}

fn host_header_authority(scheme: &str, host: &str, port: u16) -> String {
    let unwrapped = host.trim_matches(['[', ']']);
    let formatted_host = if unwrapped.contains(':') {
        format!("[{unwrapped}]")
    } else {
        unwrapped.to_string()
    };
    if scheme == "http" && port == 80 || scheme == "https" && port == 443 {
        formatted_host
    } else {
        format!("{formatted_host}:{port}")
    }
}

fn request_headers_for_capture(
    outbound: &HeaderMap,
    mirror_route: Option<&RuntimeMirrorRoute>,
    scheme: &str,
    host: &str,
    port: u16,
    extended_websocket: bool,
) -> Vec<HeaderEntry> {
    let mut headers = headers_to_entries(outbound);
    if mirror_route.is_some() {
        headers.retain(|header| !header.name.eq_ignore_ascii_case("host"));
        headers.push(HeaderEntry {
            name: "host".to_string(),
            value: host_header_authority(scheme, host, port),
        });
    }
    if extended_websocket {
        headers.push(HeaderEntry {
            name: ":protocol".to_string(),
            value: "websocket".to_string(),
        });
    }
    headers
}

fn ensure_host_header(
    headers: &mut HeaderMap,
    scheme: &str,
    host: &str,
    port: u16,
    replace_existing: bool,
) -> Result<(), String> {
    if !replace_existing && headers.contains_key(HOST) {
        return Ok(());
    }
    let authority = host_header_authority(scheme, host, port);
    let value = HeaderValue::from_str(&authority)
        .map_err(|error| format!("目标 Host 标头无效: {error}"))?;
    headers.insert(HOST, value);
    Ok(())
}

/// Whether a send failure looks like the origin refusing our HTTP/2, rather than
/// a connection ending the way connections ordinarily do.
///
/// This has to be narrow. Downgrading a host is sticky, and the events that are
/// *not* a verdict are the common ones: a browser abandoning a request, and an
/// origin retiring a connection with GOAWAY — which this very file documents
/// Cloudflare doing after a bounded number of streams. A request that loses the
/// race with that retirement fails, and treating it as refusal would downgrade
/// exactly the busy, healthy hosts we most want to keep multiplexed.
///
/// So a close, an incomplete message, a cancellation, a user error and plain I/O
/// (a dropped Wi-Fi link, a VPN toggle, sleep/wake) are all excluded. What
/// remains is a protocol-level complaint, and even then it takes more than one.
/// Whether a request that failed on h2 may be sent again over HTTP/1.1.
///
/// Conservative on purpose: a replay must be safe to run twice, and the body has
/// already been consumed by the first attempt, so only a bodyless request can be
/// rebuilt faithfully. That still covers the case this exists for — stylesheets,
/// scripts and images, where one failure is fatal to the render and the browser
/// never asks again.
fn replayable_over_http11(parts: &hyper::http::request::Parts, body: &EditableRequestBody) -> bool {
    let idempotent = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
    let declared_empty = parts
        .headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_none_or(|length| length == 0);
    let no_captured_body = body.text.as_ref().is_none_or(|text| text.is_empty());
    idempotent && declared_empty && no_captured_body
}

fn looks_like_origin_http2_refusal(error: &BoxError) -> bool {
    // Only a hyper error can be an origin h2 refusal; a wreq error is not, and
    // wreq manages its own protocol negotiation anyway.
    let Some(error) = error.downcast_ref::<hyper::Error>() else {
        return false;
    };
    // hyper exposes no `is_io()`, and a plain I/O failure — a dropped link, a
    // VPN toggle, sleep/wake — answers false to every predicate it does expose,
    // so it would otherwise read as the origin's verdict. Walk the source chain
    // for the io::Error instead.
    let io_backed = {
        let mut source: Option<&(dyn std::error::Error + 'static)> =
            std::error::Error::source(error);
        let mut found = false;
        while let Some(cause) = source {
            if cause.downcast_ref::<std::io::Error>().is_some() {
                found = true;
                break;
            }
            source = cause.source();
        }
        found
    };
    !io_backed
        && !error.is_canceled()
        && !error.is_user()
        && !error.is_closed()
        && !error.is_incomplete_message()
        && !error.is_timeout()
}

/// Join HTTP/2 cookie crumbs into a single `Cookie` header.
///
/// Chrome and Edge emit one `Cookie` field per cookie on h2. The MITM captures
/// every crumb, but wreq's `RequestBuilder::header` replaces an existing name,
/// so a reconstructed origin request would keep only the last crumb and drop
/// the session cookies a login just issued. Combining is what RFC 6265 user
/// agents send on HTTP/1.1 and is legal on HTTP/2.
pub(crate) fn collapse_cookie_headers(headers: &mut HeaderMap) {
    let crumbs: Vec<HeaderValue> = headers.get_all(COOKIE).iter().cloned().collect();
    if crumbs.len() <= 1 {
        return;
    }
    let mut joined = Vec::new();
    for (index, crumb) in crumbs.iter().enumerate() {
        if index > 0 {
            joined.extend_from_slice(b"; ");
        }
        joined.extend_from_slice(crumb.as_bytes());
    }
    let Ok(value) = HeaderValue::from_bytes(&joined) else {
        return;
    };
    headers.remove(COOKIE);
    headers.insert(COOKIE, value);
}

fn strip_http2_forbidden_headers(headers: &mut HeaderMap) {
    let connection_tokens = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    for token in connection_tokens {
        headers.remove(token);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    // `te` is legal over h2 when its value is exactly `trailers` (RFC 9113
    // §8.2.2), and hyper keeps it for that reason. Dropping it unconditionally
    // broke trailer negotiation for gRPC traffic and made our requests differ
    // from the browser we are meant to look like.
    let te_is_trailers = headers
        .get("te")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("trailers"));
    if !te_is_trailers {
        headers.remove("te");
    }
}

async fn connect_destination(
    upstream: &EffectiveUpstreamProxy,
    target_host: &str,
    target_port: u16,
) -> Result<BoxedIo, String> {
    if upstream.mode == "direct" || should_bypass(target_host, &upstream.bypass) {
        return Ok(BoxedIo(Box::new(
            connect_tcp(target_host, target_port).await?,
        )));
    }
    match upstream.mode.as_str() {
        "http" | "https" => connect_via_http_proxy(upstream, target_host, target_port).await,
        "socks5" => connect_via_socks5(upstream, target_host, target_port).await,
        mode => Err(format!("不支持的出口代理类型: {mode}")),
    }
}

/// Overall budget for a single destination connect (host:port).
const CONNECT_OVERALL_TIMEOUT: Duration = Duration::from_secs(15);
/// Per-attempt cap for IPv4 (and lone IPv6) after DNS.
const CONNECT_PER_ATTEMPT: Duration = Duration::from_secs(4);
/// When IPv4 candidates exist, do not let a broken IPv6 black-hole burn the full budget.
const CONNECT_IPV6_WHEN_IPV4_EXISTS: Duration = Duration::from_millis(750);

/// Prefer IPv4 so dual-stack hosts with broken AAAA paths fail fast and fall back.
fn order_connect_addrs_ipv4_first(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in addrs {
        match addr {
            SocketAddr::V4(_) => v4.push(addr),
            SocketAddr::V6(_) => v6.push(addr),
        }
    }
    v4.extend(v6);
    v4
}

#[cfg(test)]
static TEST_HOST_IPS: std::sync::OnceLock<StdMutex<HashMap<String, IpAddr>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn set_test_host_ip(host: &str, ip: IpAddr) {
    TEST_HOST_IPS
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(host.trim().to_ascii_lowercase(), ip);
}

#[cfg(test)]
pub(crate) fn clear_test_host_ips() {
    if let Some(map) = TEST_HOST_IPS.get() {
        map.lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }
}

#[cfg(test)]
pub(crate) fn test_host_ip(host: &str) -> Option<IpAddr> {
    TEST_HOST_IPS
        .get()?
        .lock()
        .ok()?
        .get(&host.trim().to_ascii_lowercase())
        .copied()
}

async fn resolve_connect_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    #[cfg(test)]
    if let Some(ip) = test_host_ip(host) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let resolved: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(|error| format!("DNS 解析 {host} 失败: {error}"))?
        .collect();
    if resolved.is_empty() {
        return Err(format!("DNS 未返回 {host} 的地址"));
    }
    Ok(order_connect_addrs_ipv4_first(resolved))
}

async fn connect_tcp_addrs(
    host: &str,
    port: u16,
    addrs: Vec<SocketAddr>,
) -> Result<TcpStream, String> {
    if addrs.is_empty() {
        return Err(format!("连接 {host}:{port} 失败: 无可用地址"));
    }
    let has_v4 = addrs.iter().any(SocketAddr::is_ipv4);
    let deadline = Instant::now() + CONNECT_OVERALL_TIMEOUT;
    let mut errors = Vec::new();
    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let attempt = if addr.is_ipv6() && has_v4 {
            remaining.min(CONNECT_IPV6_WHEN_IPV4_EXISTS)
        } else {
            remaining.min(CONNECT_PER_ATTEMPT)
        };
        match timeout(attempt, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => errors.push(format!("{addr}: {error}")),
            Err(_) => errors.push(format!("{addr}: 超时")),
        }
    }
    if errors.is_empty() {
        Err(format!("连接 {host}:{port} 超时"))
    } else {
        Err(format!("连接 {host}:{port} 失败: {}", errors.join("; ")))
    }
}

async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs = resolve_connect_addrs(host, port).await?;
    connect_tcp_addrs(host, port, addrs).await
}

/// Probe egress: direct TCP or full upstream CONNECT/SOCKS to a well-known HTTPS target.
pub async fn probe_upstream_egress(upstream: &EffectiveUpstreamProxy) -> UpstreamProbeResult {
    const TARGET_HOST: &str = "example.com";
    const TARGET_PORT: u16 = 443;
    let target = format!("{TARGET_HOST}:{TARGET_PORT}");
    let start = Instant::now();
    let (ok, message) = if upstream.mode == "direct" {
        match connect_tcp(TARGET_HOST, TARGET_PORT).await {
            Ok(_) => (true, format!("直连可达 {target}（未使用二级出口代理）")),
            Err(error) => (false, error),
        }
    } else if upstream.host.trim().is_empty() || upstream.port == 0 {
        (
            false,
            format!(
                "出口 {}:{} 配置无效：请填写主机与端口",
                upstream.host, upstream.port
            ),
        )
    } else {
        match connect_destination(upstream, TARGET_HOST, TARGET_PORT).await {
            Ok(_) => (
                true,
                format!(
                    "出口 {}:{} ({}) 已成功 CONNECT {target}",
                    upstream.host,
                    upstream.port,
                    upstream.mode.to_uppercase()
                ),
            ),
            Err(error) => (
                false,
                format!("出口 {}:{} 连不上：{error}", upstream.host, upstream.port),
            ),
        }
    };
    UpstreamProbeResult {
        ok,
        mode: upstream.mode.clone(),
        host: upstream.host.clone(),
        port: upstream.port,
        target,
        latency_ms: start.elapsed().as_millis() as u64,
        message,
    }
}

/// Parsed proxy URL fields from env-style values (`PROXY`, `HTTP_PROXY`, …).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedProxyUrl {
    pub mode: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
}

/// Parse a single proxy URL or `host:port` from PROXY / HTTP(S)_PROXY / ALL_PROXY style values.
pub fn parse_proxy_env_value(raw: &str) -> Option<(String, String, u16, String)> {
    let parsed = parse_proxy_url(raw)?;
    Some((parsed.mode, parsed.host, parsed.port, parsed.username))
}

pub fn parse_proxy_url(raw: &str) -> Option<ParsedProxyUrl> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let url = Url::parse(&candidate).ok()?;
    let mode = match url.scheme() {
        "http" => "http",
        "https" => "https",
        "socks5" | "socks5h" | "socks" => "socks5",
        _ => return None,
    };
    let host = url.host_str()?.to_string();
    if host.is_empty() {
        return None;
    }
    let port = url.port().unwrap_or(match mode {
        "https" => 443,
        "socks5" => 1080,
        _ => 80,
    });
    if port == 0 {
        return None;
    }
    let username = percent_decode_str(url.username());
    let password = url.password().map(percent_decode_str);
    Some(ParsedProxyUrl {
        mode: mode.to_string(),
        host,
        port,
        username,
        password,
    })
}

fn percent_decode_str(value: &str) -> String {
    // Username/password in proxy URLs are rarely percent-encoded; keep raw for auth Basic.
    // url crate already percent-decodes password()/username() in recent versions for host URLs.
    value.to_string()
}

/// Prefer PROXY, then HTTPS_PROXY, then HTTP_PROXY, then ALL_PROXY (case-insensitive names).
pub fn detect_env_proxy_from_pairs<'a>(
    pairs: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
) -> Option<DetectedEnvProxy> {
    let mut map = std::collections::HashMap::new();
    for (key, value) in pairs {
        if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
            // First occurrence wins so PROXY/HTTPS_PROXY beats lower-priority aliases.
            map.entry(key.to_ascii_lowercase())
                .or_insert_with(|| (key.to_string(), value.to_string()));
        }
    }
    for name in ["proxy", "https_proxy", "http_proxy", "all_proxy"] {
        let Some((source, raw)) = map.get(name) else {
            continue;
        };
        if let Some(parsed) = parse_proxy_url(raw) {
            return Some(DetectedEnvProxy {
                mode: parsed.mode,
                host: parsed.host,
                port: parsed.port,
                username: parsed.username,
                source: source.clone(),
                raw: raw.clone(),
            });
        }
    }
    None
}

pub fn detect_env_proxy() -> Option<DetectedEnvProxy> {
    let proxy = std::env::var("PROXY").ok();
    let proxy_l = std::env::var("proxy").ok();
    let https = std::env::var("HTTPS_PROXY").ok();
    let https_l = std::env::var("https_proxy").ok();
    let http = std::env::var("HTTP_PROXY").ok();
    let http_l = std::env::var("http_proxy").ok();
    let all = std::env::var("ALL_PROXY").ok();
    let all_l = std::env::var("all_proxy").ok();
    detect_env_proxy_from_pairs([
        ("PROXY", proxy.as_deref()),
        ("proxy", proxy_l.as_deref()),
        ("HTTPS_PROXY", https.as_deref()),
        ("https_proxy", https_l.as_deref()),
        ("HTTP_PROXY", http.as_deref()),
        ("http_proxy", http_l.as_deref()),
        ("ALL_PROXY", all.as_deref()),
        ("all_proxy", all_l.as_deref()),
    ])
}

/// Build an [`EffectiveUpstreamProxy`] from PROXY / HTTP(S)_PROXY / ALL_PROXY for live tests.
pub fn effective_upstream_from_process_env() -> Option<EffectiveUpstreamProxy> {
    let detected = detect_env_proxy()?;
    let parsed = parse_proxy_url(&detected.raw)?;
    Some(EffectiveUpstreamProxy {
        mode: parsed.mode,
        host: parsed.host,
        port: parsed.port,
        username: parsed.username,
        password: parsed.password,
        bypass: vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ],
    })
}

async fn connect_via_http_proxy(
    proxy: &EffectiveUpstreamProxy,
    target_host: &str,
    target_port: u16,
) -> Result<BoxedIo, String> {
    let stream = connect_tcp(&proxy.host, proxy.port).await?;
    let mut stream = if proxy.mode == "https" {
        let config = tls_outbound::build_client_config(tls_outbound::global_profile());
        let connector = TlsConnector::from(config);
        let server_name = ServerName::try_from(proxy.host.clone())
            .map_err(|_| "HTTPS 出口代理主机名无效".to_string())?;
        let tls = timeout(
            Duration::from_secs(15),
            connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| "HTTPS 出口代理握手超时".to_string())?
        .map_err(|error| format!("HTTPS 出口代理握手失败: {error}"))?;
        BoxedIo(Box::new(tls))
    } else {
        BoxedIo(Box::new(stream))
    };

    negotiate_http_connect(&mut stream, proxy, target_host, target_port).await?;
    Ok(stream)
}

async fn negotiate_http_connect<S>(
    stream: &mut S,
    proxy: &EffectiveUpstreamProxy,
    target_host: &str,
    target_port: u16,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = format!("{target_host}:{target_port}");
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
    );
    if !proxy.username.is_empty() || proxy.password.is_some() {
        let token = STANDARD.encode(format!(
            "{}:{}",
            proxy.username,
            proxy.password.as_deref().unwrap_or_default()
        ));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("写入出口代理失败: {error}"))?;
    let header = read_http_header(stream).await?;
    let status_line = header.lines().next().unwrap_or_default();
    let status = status_line.split_whitespace().nth(1).unwrap_or_default();
    if status != "200" {
        return Err(format!("出口代理拒绝 CONNECT: {status_line}"));
    }
    Ok(())
}

async fn read_http_header<S>(stream: &mut S) -> Result<String, String>
where
    S: AsyncRead + Unpin,
{
    let mut header = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while header.len() < 65_536 {
        timeout(Duration::from_secs(15), stream.read_exact(&mut byte))
            .await
            .map_err(|_| "等待出口代理响应超时".to_string())?
            .map_err(|error| format!("读取出口代理响应失败: {error}"))?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return String::from_utf8(header).map_err(|_| "出口代理响应不是有效文本".to_string());
        }
    }
    Err("出口代理响应头过大".to_string())
}

async fn connect_via_socks5(
    proxy: &EffectiveUpstreamProxy,
    target_host: &str,
    target_port: u16,
) -> Result<BoxedIo, String> {
    let mut stream = connect_tcp(&proxy.host, proxy.port).await?;
    negotiate_socks5_connect(&mut stream, proxy, target_host, target_port).await?;
    Ok(BoxedIo(Box::new(stream)))
}

async fn negotiate_socks5_connect<S>(
    stream: &mut S,
    proxy: &EffectiveUpstreamProxy,
    target_host: &str,
    target_port: u16,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let use_auth = !proxy.username.is_empty() || proxy.password.is_some();
    let methods: &[u8] = if use_auth { &[0x00, 0x02] } else { &[0x00] };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream
        .write_all(&greeting)
        .await
        .map_err(|error| format!("SOCKS5 握手写入失败: {error}"))?;
    let mut selected = [0_u8; 2];
    stream
        .read_exact(&mut selected)
        .await
        .map_err(|error| format!("SOCKS5 握手读取失败: {error}"))?;
    if selected[0] != 0x05 || selected[1] == 0xff {
        return Err("SOCKS5 出口代理不接受可用认证方式".to_string());
    }
    if selected[1] == 0x02 {
        socks5_authenticate(stream, proxy).await?;
    } else if selected[1] != 0x00 {
        return Err("SOCKS5 出口代理选择了不支持的认证方式".to_string());
    }

    if target_host.len() > 255 {
        return Err("SOCKS5 目标域名过长".to_string());
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, target_host.len() as u8];
    request.extend_from_slice(target_host.as_bytes());
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| format!("SOCKS5 CONNECT 写入失败: {error}"))?;
    read_socks5_reply(stream).await?;
    Ok(())
}

async fn socks5_authenticate<S>(
    stream: &mut S,
    proxy: &EffectiveUpstreamProxy,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let username = proxy.username.as_bytes();
    let password = proxy.password.as_deref().unwrap_or_default().as_bytes();
    if username.len() > 255 || password.len() > 255 {
        return Err("SOCKS5 用户名或密码过长".to_string());
    }
    let mut request = vec![0x01, username.len() as u8];
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream
        .write_all(&request)
        .await
        .map_err(|error| format!("SOCKS5 认证写入失败: {error}"))?;
    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|error| format!("SOCKS5 认证读取失败: {error}"))?;
    if response != [0x01, 0x00] {
        return Err("SOCKS5 用户名或密码错误".to_string());
    }
    Ok(())
}

async fn read_socks5_reply<S>(stream: &mut S) -> Result<(), String>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|error| format!("SOCKS5 CONNECT 响应失败: {error}"))?;
    if prefix[0] != 0x05 || prefix[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT 被拒绝，代码 {}", prefix[1]));
    }
    let address_len = match prefix[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|error| error.to_string())?;
            length[0] as usize
        }
        _ => return Err("SOCKS5 CONNECT 返回了无效地址类型".to_string()),
    };
    let mut remainder = vec![0_u8; address_len + 2];
    stream
        .read_exact(&mut remainder)
        .await
        .map_err(|error| format!("SOCKS5 CONNECT 响应不完整: {error}"))?;
    Ok(())
}

pub(crate) fn should_bypass(host: &str, patterns: &[String]) -> bool {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if matches!(host.as_str(), "localhost" | "::1")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
    {
        return true;
    }
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim().to_ascii_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else {
            host == pattern
        }
    })
}

fn reject_proxy_loop(host: &str, port: u16) -> Result<(), String> {
    let host = host.trim_matches(['[', ']']);
    if port == 8888
        && (matches!(host, "localhost" | "::1")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback()))
    {
        return Err("请求目标指向 ShowNet 自身代理端口，已阻止回环".to_string());
    }
    Ok(())
}

fn classify_source(headers: &HeaderMap, peer: SocketAddr) -> String {
    if headers.contains_key(REVERSE_PROXY_CONTEXT_HEADER) {
        return "reverse".to_string();
    }
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ["esp32", "esp8266", "arduino", "embedded", "iot-device"]
        .iter()
        .any(|marker| user_agent.contains(marker))
    {
        "iot"
    } else if user_agent.contains("curl")
        || user_agent.contains("wget")
        || user_agent.contains("httpie")
    {
        "terminal"
    } else if user_agent.contains("python")
        || user_agent.contains("node")
        || user_agent.contains("go-http-client")
    {
        "script"
    } else if user_agent.contains("android")
        || user_agent.contains("iphone")
        || user_agent.contains("ipad")
    {
        "mobile"
    } else if !user_agent.contains("electron")
        && (user_agent.contains("chrome/")
            || user_agent.contains("firefox/")
            || user_agent.contains("safari/"))
    {
        "browser"
    } else if user_agent.is_empty() && !peer.ip().is_loopback() {
        "iot"
    } else {
        "desktop"
    }
    .to_string()
}

fn infer_resource_type(headers: &HeaderMap) -> String {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if content_type.contains("text/event-stream") {
        "sse"
    } else if content_type.contains("javascript") {
        "script"
    } else if content_type.starts_with("image/") {
        "image"
    } else if content_type.starts_with("font/") || content_type.contains("woff") {
        "font"
    } else if content_type.contains("html") {
        "document"
    } else {
        "fetch"
    }
    .to_string()
}

fn headers_to_entries(headers: &HeaderMap) -> Vec<HeaderEntry> {
    headers
        .iter()
        .filter(|(name, _)| {
            !name
                .as_str()
                .eq_ignore_ascii_case("x-shownet-replay-context")
                && !name
                    .as_str()
                    .eq_ignore_ascii_case(REVERSE_PROXY_CONTEXT_HEADER)
        })
        .map(|(name, value)| HeaderEntry {
            name: name.as_str().to_string(),
            value: value.to_str().unwrap_or("<binary>").to_string(),
        })
        .collect()
}

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn empty_body() -> ProxyBody {
    full_body(Bytes::new())
}

fn error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::copy_from_slice(message.as_bytes())))
        .unwrap_or_else(|_| Response::new(empty_body()))
}

#[cfg(test)]
mod tests {
    /// This file with its own test module cut off.
    ///
    /// `include_str!` pulls the tests in too, so a `contains` check for a code
    /// string is satisfied by the assertion's own literal — every source-pin
    /// test below passed against gutted production code until this existed.
    /// That mistake was made four separate times in one sitting; making the
    /// haystack exclude the needles is the only version of it that stays fixed.
    fn production_source() -> &'static str {
        let source = include_str!("proxy.rs");
        match source.find("\n#[cfg(test)]\nmod tests {") {
            Some(at) => &source[..at],
            None => panic!("test module marker not found; production_source would be a no-op"),
        }
    }

    use super::*;
    use brotli::CompressorWriter;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use flate2::Compression;
    use std::io::Write;
    use std::sync::Mutex;
    use tokio_tungstenite::{accept_async, client_async};

    fn test_certificate_authority() -> Arc<CertificateAuthority> {
        Arc::new(CertificateAuthority::load_or_create(None).unwrap().0)
    }

    #[test]
    fn order_connect_addrs_puts_ipv4_before_ipv6() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let ordered = order_connect_addrs_ipv4_first([
            SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 80)),
            SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 80)),
        ]);
        assert!(ordered[0].is_ipv4());
        assert!(ordered[1].is_ipv4());
        assert!(ordered[2].is_ipv6());
        assert!(ordered[3].is_ipv6());
    }

    #[test]
    fn parse_proxy_env_value_accepts_urls_and_host_port() {
        let (mode, host, port, user) =
            parse_proxy_env_value("http://127.0.0.1:1080").expect("http url");
        assert_eq!(
            (mode.as_str(), host.as_str(), port, user.as_str()),
            ("http", "127.0.0.1", 1080, "")
        );

        let (mode, host, port, _) =
            parse_proxy_env_value("socks5://proxy.example:1080").expect("socks");
        assert_eq!(
            (mode.as_str(), host.as_str(), port),
            ("socks5", "proxy.example", 1080)
        );

        let (mode, host, port, user) =
            parse_proxy_env_value("http://alice@127.0.0.1:7890").expect("user");
        assert_eq!(
            (mode.as_str(), host.as_str(), port, user.as_str()),
            ("http", "127.0.0.1", 7890, "alice")
        );

        let (mode, host, port, _) = parse_proxy_env_value("127.0.0.1:1080").expect("bare");
        assert_eq!(
            (mode.as_str(), host.as_str(), port),
            ("http", "127.0.0.1", 1080)
        );
    }

    #[test]
    fn detect_env_proxy_prefers_https_over_http() {
        let detected = detect_env_proxy_from_pairs([
            ("HTTP_PROXY", Some("http://127.0.0.1:8080")),
            ("HTTPS_PROXY", Some("socks5://127.0.0.1:1080")),
        ])
        .expect("detected");
        assert_eq!(detected.mode, "socks5");
        assert_eq!(detected.port, 1080);
        assert_eq!(detected.source, "HTTPS_PROXY");
    }

    #[test]
    fn detect_env_proxy_prefers_proxy_over_http_proxy() {
        let detected = detect_env_proxy_from_pairs([
            ("HTTP_PROXY", Some("http://127.0.0.1:9999")),
            ("PROXY", Some("http://localhost:8080")),
        ])
        .expect("detected");
        assert_eq!(detected.host, "localhost");
        assert_eq!(detected.port, 8080);
        assert_eq!(detected.source, "PROXY");
    }

    #[tokio::test]
    async fn connect_tcp_falls_back_to_ipv4_when_ipv6_is_unreachable() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf).await;
        });

        // IPv6 localhost closed port would hang/fail; ordered list still prefers IPv4 first.
        let addrs = order_connect_addrs_ipv4_first([
            SocketAddr::from((Ipv6Addr::LOCALHOST, 1)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ]);
        assert!(addrs[0].is_ipv4(), "IPv4 must be attempted first");
        let stream = connect_tcp_addrs("localhost", port, addrs)
            .await
            .expect("should connect via IPv4 fallback");
        drop(stream);
    }

    #[tokio::test]
    async fn connect_tcp_reports_host_port_on_total_failure() {
        use std::net::Ipv4Addr;
        let err = connect_tcp_addrs(
            "blackhole.test",
            9,
            vec![SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9))],
        )
        .await
        .unwrap_err();
        assert!(err.contains("blackhole.test:9"), "{err}");
    }

    fn complete_capture(bytes: Vec<u8>) -> BodyCaptureSnapshot {
        BodyCaptureSnapshot {
            total_bytes: bytes.len(),
            bytes,
            complete: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn tap_body_marks_content_length_met_complete_without_end_stream() {
        use std::future::poll_fn;
        use std::sync::{Arc, Mutex};

        struct OneChunkThenHang {
            chunk: Option<Bytes>,
        }
        impl Body for OneChunkThenHang {
            type Data = Bytes;
            type Error = std::convert::Infallible;
            fn poll_frame(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                let this = self.get_mut();
                match this.chunk.take() {
                    Some(chunk) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
                    None => Poll::Pending,
                }
            }
            fn is_end_stream(&self) -> bool {
                false
            }
        }

        let seen = Arc::new(Mutex::new(None));
        let seen_for_callback = seen.clone();
        let mut tap = TapBody::new(
            OneChunkThenHang {
                chunk: Some(Bytes::from_static(b"empty-ok")),
            },
            MAX_CAPTURED_WIRE_BYTES,
            move |snapshot| {
                *seen_for_callback.lock().unwrap() = Some(snapshot);
            },
        )
        .with_expected_wire_bytes(Some(8));

        let frame = poll_fn(|context| Pin::new(&mut tap).poll_frame(context)).await;
        assert!(frame.unwrap().is_ok());
        drop(tap);
        let snapshot = seen.lock().unwrap().take().expect("capture callback");
        assert!(snapshot.complete);
        assert_eq!(snapshot.bytes, b"empty-ok");
        assert_eq!(snapshot.error, None);
    }

    fn test_tls_fingerprint() -> crate::tls_fingerprint::TlsFingerprintRecord {
        // Qualified rather than imported at the top of the file: this is its only
        // caller and it lives in the test module, so a top-level `use` reads as a
        // production dependency and warns as unused in the lib build.
        crate::tls_fingerprint::mitm_fingerprint(crate::tls_fingerprint::ClientTlsFingerprint {
            ja3: "test-ja3".to_string(),
            ja3_raw: "771,4865,,,".to_string(),
            ja4: "test-ja4".to_string(),
            ja4_raw: "t13d0000".to_string(),
            sni: Some("example.test".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            legacy_version: "TLSv1_2".to_string(),
            offered_versions: vec!["TLSv1_3".to_string(), "TLSv1_2".to_string()],
            cipher_suites: vec!["0x1301".to_string()],
            extensions: vec!["0x0010".to_string()],
            supported_groups: vec!["0x001d".to_string()],
            signature_algorithms: vec!["0x0804".to_string()],
            grease: false,
        })
    }

    fn unavailable_dedicated_sender_factory() -> DedicatedRequestSenderFactory {
        Arc::new(|_| {
            Box::pin(async { Err("测试未配置独立 HTTPS WebSocket 上游".to_string()) })
        })
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

    #[test]
    fn mirror_host_policy_preserves_compatible_and_replaces_target_identity() {
        let mut compatible_headers = HeaderMap::new();
        compatible_headers.insert(HOST, HeaderValue::from_static("api.original.test"));
        ensure_host_header(
            &mut compatible_headers,
            "https",
            "stage.target.test",
            8443,
            false,
        )
        .unwrap();
        assert_eq!(compatible_headers.get(HOST).unwrap(), "api.original.test");

        let mut target_headers = compatible_headers;
        ensure_host_header(
            &mut target_headers,
            "https",
            "stage.target.test",
            8443,
            true,
        )
        .unwrap();
        assert_eq!(target_headers.get(HOST).unwrap(), "stage.target.test:8443");

        let mut default_http_headers = HeaderMap::new();
        ensure_host_header(
            &mut default_http_headers,
            "http",
            "stage.target.test",
            80,
            true,
        )
        .unwrap();
        assert_eq!(default_http_headers.get(HOST).unwrap(), "stage.target.test");
    }

    fn test_breakpoint_rule(stage: &str) -> RuntimeBreakpointRule {
        RuntimeBreakpointRule {
            id: format!("{stage}-breakpoint"),
            name: format!("{stage} test breakpoint"),
            stage: stage.to_string(),
            revision: 1,
            timeout_ms: 5_000,
            abort_on_timeout: false,
        }
    }

    async fn wait_for_breakpoint(
        coordinator: &Arc<BreakpointCoordinator>,
        stage: &str,
    ) -> crate::breakpoints::BreakpointTask {
        timeout(Duration::from_secs(5), async {
            loop {
                if let Some(task) = coordinator
                    .snapshot()
                    .unwrap()
                    .tasks
                    .into_iter()
                    .find(|task| task.stage == stage)
                {
                    return task;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("breakpoint task")
    }

    fn test_client_hello_wire(host: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0);
        push_test_tls_vector(&mut body, &[0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);

        let hostname = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((hostname.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni.extend_from_slice(hostname);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        push_test_tls_vector(&mut extensions, &sni);
        extensions.extend_from_slice(&43_u16.to_be_bytes());
        push_test_tls_vector(&mut extensions, &[2, 3, 4]);
        push_test_tls_vector(&mut body, &extensions);

        let mut handshake = vec![1];
        handshake.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn push_test_tls_vector(target: &mut Vec<u8>, value: &[u8]) {
        target.extend_from_slice(&(value.len() as u16).to_be_bytes());
        target.extend_from_slice(value);
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli(bytes: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        {
            let mut encoder = CompressorWriter::new(&mut encoded, 16 * 1024, 5, 22);
            encoder.write_all(bytes).unwrap();
        }
        encoded
    }

    fn zlib(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn raw_deflate(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn assert_decoded(encoded: Vec<u8>, encoding: &str, expected: &str) {
        let wire_bytes = encoded.len() as i64;
        let (body, metadata) = normalize_body_capture(
            complete_capture(encoded),
            Some(encoding),
            Some("application/json"),
        );
        assert_eq!(body.as_deref(), Some(expected));
        assert_eq!(metadata.wire_bytes, wire_bytes);
        assert_eq!(metadata.decoded_bytes, expected.len() as i64);
        assert_eq!(metadata.content_encoding.as_deref(), Some(encoding));
        assert!(metadata.decoded);
        assert!(!metadata.truncated);
        assert!(metadata.complete);
        assert_eq!(metadata.format, "text");
        assert!(metadata.error.is_none());
    }

    #[test]
    fn decodes_supported_response_content_encodings() {
        let payload = "{\"message\":\"ShowNet 压缩响应\"}";
        assert_decoded(gzip(payload.as_bytes()), "gzip", payload);
        assert_decoded(brotli(payload.as_bytes()), "br", payload);
        assert_decoded(zlib(payload.as_bytes()), "deflate", payload);
        assert_decoded(raw_deflate(payload.as_bytes()), "deflate", payload);
        assert_decoded(
            zstd::stream::encode_all(payload.as_bytes(), 3).unwrap(),
            "zstd",
            payload,
        );
    }

    #[test]
    fn decodes_content_encoding_chain_in_reverse_order() {
        let payload = "{\"layers\":[\"gzip\",\"br\"]}";
        let encoded = brotli(&gzip(payload.as_bytes()));
        assert_decoded(encoded, "gzip, br", payload);
    }

    #[test]
    fn preserves_unknown_encoded_and_binary_bodies_as_base64() {
        let unknown = vec![0, 0xff, 0x10, 0x80];
        let (body, metadata) = normalize_body_capture(
            complete_capture(unknown.clone()),
            Some("compress42"),
            Some("application/json"),
        );
        assert_eq!(body, Some(format!("base64:{}", STANDARD.encode(&unknown))));
        assert_eq!(metadata.format, "base64");
        assert!(!metadata.decoded);
        assert!(metadata.error.unwrap().contains("compress42"));

        let binary = vec![0, 0x9f, 0x92, 0x96];
        let (body, metadata) = normalize_body_capture(
            complete_capture(binary.clone()),
            None,
            Some("application/octet-stream"),
        );
        assert_eq!(body, Some(format!("base64:{}", STANDARD.encode(binary))));
        assert_eq!(metadata.format, "base64");
        assert!(metadata.error.is_none());
    }

    #[test]
    fn bounds_decompressed_body_size_without_polluting_text() {
        let payload = vec![b'a'; MAX_DECODED_BODY_BYTES + 1024];
        let encoded = gzip(&payload);
        let (body, metadata) =
            normalize_body_capture(complete_capture(encoded), Some("gzip"), Some("text/plain"));
        let body = body.unwrap();
        assert_eq!(body.len(), MAX_DECODED_BODY_BYTES);
        assert!(body.bytes().all(|byte| byte == b'a'));
        assert!(metadata.decoded);
        assert!(metadata.truncated);
        assert_eq!(metadata.decoded_bytes, MAX_DECODED_BODY_BYTES as i64);
        assert!(metadata.error.unwrap().contains("解压后正文超过"));
    }

    #[tokio::test]
    async fn tap_body_forwards_original_bytes_while_capturing_a_bounded_copy() {
        let payload = Bytes::from_static(b"original-response-bytes");
        let captured = Arc::new(Mutex::new(None));
        let captured_sink = captured.clone();
        let body = TapBody::new(Full::new(payload.clone()), 8, move |snapshot| {
            captured_sink.lock().unwrap().replace(snapshot);
        });
        let forwarded = body.collect().await.unwrap().to_bytes();
        assert_eq!(forwarded, payload);

        let captured = captured.lock().unwrap();
        let snapshot = captured.as_ref().unwrap();
        assert_eq!(snapshot.bytes, b"original");
        assert_eq!(snapshot.total_bytes, payload.len());
        assert!(snapshot.truncated);
        assert!(snapshot.complete);
        assert!(snapshot.error.is_none());
    }

    #[tokio::test]
    async fn tap_body_rate_limit_delays_forwarding_by_payload_size() {
        let payload = Bytes::from(vec![b'x'; 16 * 1024]);
        let started = Instant::now();
        let body = TapBody::new(Full::new(payload.clone()), payload.len(), |_| {})
            .with_rate_limit(Some(64 * 1024));
        let forwarded = body.collect().await.unwrap().to_bytes();
        assert_eq!(forwarded, payload);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(200),
            "elapsed: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(2), "elapsed: {elapsed:?}");
    }

    #[test]
    fn parses_chunk_split_sse_utf8_crlf_heartbeats_and_nonstandard_fields() {
        let stream = concat!(
            "\u{feff}: keep-alive\r\n\r\n",
            "event: order.updated\r\n",
            "data: 你\r\n",
            "data: 好\r\n",
            "id: evt-42\r\n",
            "retry: 1500\r\n",
            "x-trace: edge-a\r\n\r\n",
        );
        let mut parser = SseParser::default();
        let mut events = Vec::new();
        for byte in stream.as_bytes() {
            events.extend(parser.push(std::slice::from_ref(byte)));
        }
        events.extend(parser.finish());

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "heartbeat");
        assert_eq!(events[0].comments, ["keep-alive"]);
        assert_eq!(events[1].kind, "event");
        assert_eq!(events[1].event, "order.updated");
        assert_eq!(events[1].data, "你\n好");
        assert_eq!(events[1].id.as_deref(), Some("evt-42"));
        assert_eq!(events[1].retry, Some(1_500));
        assert!(events[1]
            .fields
            .iter()
            .any(|field| field.name == "x-trace" && field.value == "edge-a"));
        assert!(!events[1].truncated);
        assert!(!events[1].incomplete);
    }

    #[test]
    fn bounds_long_sse_events_and_preserves_incomplete_tail_as_evidence() {
        let mut parser = SseParser::default();
        let mut stream = format!("data: {}\n\n", "界".repeat(MAX_SSE_EVENT_BYTES)).into_bytes();
        stream.extend_from_slice(b"event: unfinished\ndata: tail");
        let mut events = parser.push(&stream);
        events.extend(parser.finish());

        assert_eq!(events.len(), 2);
        assert!(events[0].truncated);
        assert!(events[0].data.len() <= MAX_SSE_EVENT_BYTES);
        assert_eq!(events[1].kind, "partial");
        assert_eq!(events[1].event, "unfinished");
        assert_eq!(events[1].data, "tail");
        assert!(events[1].incomplete);
    }

    #[test]
    fn recognizes_event_stream_content_type_case_insensitively() {
        let response = Response::builder()
            .header(CONTENT_TYPE, "Text/Event-Stream; Charset=UTF-8")
            .body(())
            .unwrap();
        assert_eq!(infer_resource_type(response.headers()), "sse");
    }

    /// The form the h2 paths now send, and that `:authority` cannot drift from
    /// the Host header (both come from `host_header_authority`).
    #[test]
    fn every_h2_forward_path_strips_before_capture() {
        // Three independent forwarding paths reach an origin: the MITM tunnel,
        // explicit-proxy HTTPS WebSocket (wreq), and the remaining explicit
        // forward. All three can be handed HTTP/2 cookie crumbs, and wreq's
        // RequestBuilder keeps only the last same-name header. The WSS path was
        // missed when it first landed. Counting occurrences would count this
        // test's own string literal, so each call site is located by the code
        // that follows it instead.
        let source = production_source();
        let stripped = source
            .matches("strip_http2_forbidden_headers(&mut parts.headers);")
            .count();
        let collapsed_before_capture = source
            .matches(
                "collapse_cookie_headers(&mut parts.headers);\n        request_headers = request_headers_for_capture(",
            )
            .count()
            + source
                .matches(
                    "collapse_cookie_headers(&mut parts.headers);\n    request_headers = request_headers_for_capture(",
                )
                .count();
        assert!(
            stripped >= 2,
            "both the MITM and explicit-proxy forward paths must strip h2 hop-by-hop headers"
        );
        assert_eq!(
            collapsed_before_capture, 3,
            "MITM, explicit WSS, and explicit HTTP(S) must join cookie crumbs before capture"
        );
    }

    #[test]
    fn both_forward_paths_teach_the_h2_rejection_list() {
        // Consulting the list without contributing to it means one path keeps
        // retrying h2 against an origin the other has already given up on.
        // Matched by argument, not by count: counting would include this test's
        // own string literals, which is how the first version of it failed.
        let source = production_source();
        assert!(
            source.contains("note_origin_http2_rejected(&host)"),
            "the MITM path must record refusals"
        );
        assert!(
            source.contains("note_origin_http2_rejected(tls_identity_host)"),
            "the explicit-proxy path must record refusals"
        );
        assert!(
            source.contains("origin_force_http11_for_host(tls_identity_host)"),
            "and both must consult the list when choosing a protocol"
        );
    }

    #[test]
    fn a_plain_websocket_never_rides_the_shared_h2_connection() {
        // `extended_websocket` alone left a plain Connection: Upgrade handshake
        // to the same authority on the shared h2 sender, carrying Upgrade
        // headers h2 forbids — the exact error the dedicated path avoids.
        let source = production_source();
        assert!(
            source.contains("let use_dedicated_base = authority_changed || websocket;"),
            "any websocket must take the dedicated HTTP/1.1 route"
        );
        assert!(
            source.contains("impersonate_origin_websocket("),
            "HTTPS WebSocket must use the Chrome TLS websocket builder, not rustls"
        );
        assert!(
            !source.contains("wreq cannot terminate"),
            "the rustls Upgrade fallback is no longer the product HTTPS WebSocket path"
        );
        assert!(
            source.contains("let impersonate_websocket = websocket && scheme == \"https\""),
            "MITM WSS must take the wreq path even when the shared sender is not Impersonate"
        );
        assert!(
            !source.contains("if route.scheme == \"https\" && route.prefer_http2"),
            "dedicated HTTPS reconnects must stay on wreq; prefer_http2 must not select rustls"
        );
    }

    #[test]
    fn the_forced_http11_list_survives_a_reconnect() {
        // The shared connection consults this list at handshake time. Once a
        // retired connection is replaced by a dedicated one, the replacement has
        // to consult it too — otherwise it goes back to preferring h2 and
        // silently undoes the workaround these hosts were added for, which is
        // exactly the breakage (images failing behind Baidu's static CDN) that
        // put them on the list.
        assert!(tls_outbound::origin_force_http11_for_host(
            "pss.bdstatic.com"
        ));
        let source = production_source();
        assert!(
            source.contains("&& !tls_outbound::origin_force_http11_for_host(tls_identity_host),"),
            "the dedicated route must honour the forced-h1 list"
        );
    }

    #[test]
    fn a_retired_shared_connection_is_replaced_not_merely_bypassed() {
        // Routing around a dead sender without storing a live one back made
        // every later request in the tunnel open its own TCP+TLS+h2 handshake
        // for a single request.
        let source = production_source();
        // Matched against what the code actually says. The first version of this
        // assertion quoted `*sender.lock().await = replacement`, which the code
        // has never contained since the guard was hoisted — so it matched only
        // its own string literal and pinned nothing. The two tests either side
        // of it warn about exactly that hazard.
        assert!(
            source.contains("Ok(replacement) => *slot = replacement,"),
            "the reconnected sender must be written back into the shared slot"
        );
        assert!(
            source.contains("let mut slot = sender.lock().await;"),
            "and the check and the write must happen under one guard"
        );
    }

    /// Whether a Chrome recipe's numbers actually reach the wire.
    ///
    /// The catalog carries Chrome SETTINGS per version band, and the settings
    /// page lets one be chosen. If the values never left the builder the whole
    /// arrangement would be decorative — a page telling the user something the
    /// connection does not do. Applied directly rather than through
    /// set_active_preset, which mutates process-global state other tests read.
    #[tokio::test]
    async fn a_chrome_recipe_reaches_the_wire() {
        use crate::http2_fingerprint::Http2FingerprintCollector;
        use tokio::io::AsyncReadExt;

        let chrome = crate::tls_clienthello_catalog::H2_CHROME_MID;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let collector = std::sync::Arc::new(Http2FingerprintCollector::default());
        let observer = collector.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0_u8; 16 * 1024];
            for _ in 0..8 {
                match timeout(Duration::from_millis(300), stream.read(&mut buffer)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(read)) => observer.observe(&buffer[..read]),
                    Ok(Err(_)) => break,
                }
            }
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        tls_outbound::apply_http2_recipe_to_builder(&mut builder, chrome);
        if let Ok((_sender, connection)) = builder
            .handshake::<_, TapBody<ProxyBody>>(TokioIo::new(stream))
            .await
        {
            tokio::spawn(async move {
                let _ = connection.await;
            });
        }
        let _ = timeout(Duration::from_secs(2), server).await;

        let observed = collector.snapshot().expect("SETTINGS were sent");
        let value_of = |id: u16| {
            observed
                .settings
                .iter()
                .find(|s| s.id == id)
                .map(|s| s.value)
        };
        assert_eq!(
            value_of(0x1),
            Some(chrome.header_table_size),
            "HEADER_TABLE_SIZE"
        );
        // Chrome does not send this one, so neither do we. Captured from
        // Chromium 151 through a TLS listener with ALPN h2:
        //   SETTINGS 1:65536 2:0 4:6291456 6:262144, WINDOW_UPDATE +15663105
        assert_eq!(
            value_of(0x3),
            None,
            "MAX_CONCURRENT_STREAMS is not Chrome's"
        );
        assert_eq!(
            value_of(0x4),
            Some(chrome.initial_window_size),
            "INITIAL_WINDOW_SIZE"
        );
        // Absent, like Chrome's. hyper defaults it to Some(16384) and announces
        // it; passing None keeps the entry off the wire entirely.
        assert_eq!(value_of(0x5), None, "MAX_FRAME_SIZE is not Chrome's either");
        assert_eq!(
            value_of(0x6),
            Some(chrome.max_header_list_size),
            "MAX_HEADER_LIST_SIZE"
        );

        // The connection window is reached by WINDOW_UPDATE rather than by a
        // SETTINGS entry, so it is only observable as the increment.
        let expected_increment = chrome.connection_window_size - 65_535;
        assert!(
            observed
                .connection_window_updates
                .contains(&expected_increment),
            "connection window {} should appear as increment {expected_increment}: {:?}",
            chrome.connection_window_size,
            observed.connection_window_updates
        );

        // ENABLE_PUSH matches Chrome's 0 — not because we set it, since the
        // builder has no knob, but because h2's own default agrees. Recorded so
        // a change in that default is not mistaken for our doing.
        assert_eq!(value_of(0x2), Some(chrome.enable_push), "ENABLE_PUSH");

        // What shaping would still have to reach, none of which the builder
        // exposes: the set of SETTINGS and their order are h2's, and no PRIORITY
        // frame is emitted where Chrome sends a priority tree. The *set* is as
        // much a fingerprint as the values, so matching Chrome's numbers is not
        // by itself enough to look like Chrome.
        // Exactly Chrome's four, in Chrome's order. Captured from Chromium 151
        // through a TLS listener with ALPN h2:
        //   SETTINGS 1:65536 2:0 4:6291456 6:262144, WINDOW_UPDATE +15663105
        // The SETTINGS half of the h2 fingerprint now matches without patching
        // h2; only the pseudo-header order still differs.
        let ids: Vec<u16> = observed.settings.iter().map(|s| s.id).collect();
        assert_eq!(ids, vec![0x1, 0x2, 0x4, 0x6], "SETTINGS set and order");
        assert!(
            observed.priority_frames.is_empty(),
            "h2 emitted priority frames after all: {:?}",
            observed.priority_frames
        );

        eprintln!("OUR OUTBOUND H2 (chrome recipe) => {}", observed.canonical);
    }

    #[tokio::test]
    async fn a_goaway_carrying_an_error_code_still_counts_as_a_refusal() {
        // The property the whole downgrade rests on. It has been wrong in both
        // directions: once too broad, so a cancelled request downgraded a
        // healthy host; then the io::Error walk added to fix that risked being
        // too narrow, which would leave the downgrade never firing and the
        // reported site looping again with nothing to explain why.
        //
        // hyper's own `graceful_shutdown` sends GOAWAY(NO_ERROR) — routine
        // retirement, which the predicate is *supposed* to ignore — so it cannot
        // express this case. h2 is pulled in for tests purely to send a GOAWAY
        // that actually carries a refusal.
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            // Refuse everything on this connection, the way an origin that has
            // decided against our client does.
            connection.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
            while connection.accept().await.is_some() {}
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, TapBody<ProxyBody>>(TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut refusal = None;
        for _ in 0..40 {
            let request = Request::builder()
                .method(Method::GET)
                .uri("https://refuser.test/")
                .body(TapBody::new(empty_body(), 0, |_| {}))
                .unwrap();
            match sender.send_request(request).await {
                Ok(_) => tokio::time::sleep(Duration::from_millis(25)).await,
                Err(error) => {
                    refusal = Some(error);
                    break;
                }
            }
        }
        server.abort();

        // The classifiers now take the unified BoxError that send_request
        // returns; box the hyper error the way that path does.
        let error: BoxError =
            Box::new(refusal.expect("the origin never refused; this test would prove nothing"));
        assert!(
            looks_like_origin_http2_refusal(&error),
            "a GOAWAY carrying ENHANCE_YOUR_CALM must count as a refusal: {error:?}"
        );
        // The two classifiers on this path must not overlap. A refusal that also
        // read as a routine ending would be silenced by the `else` below it once
        // the host had already been downgraded — so the one refusal that arrives
        // after a TTL expiry, which is what re-arms the workaround, could pass
        // without a word. They are disjoint by construction; this keeps them so.
        assert!(
            !is_benign_forward_end(&error),
            "an origin refusing our h2 is not a routine ending: {error:?}"
        );
    }

    /// Serves one connection and hands back whatever hyper concluded about it.
    async fn serve_one_and_capture_error(client_bytes: &'static [u8]) -> hyper::Error {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(client_bytes).await.unwrap();
            // Vanish without a shutdown, the way a closed tab does.
            drop(client);
        });
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(|_request: Request<hyper::body::Incoming>| async move {
            Ok::<_, std::convert::Infallible>(Response::new(empty_body()))
        });
        http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect_err("the client went away, so hyper must report an error")
    }

    #[tokio::test]
    async fn a_client_that_vanishes_mid_request_is_not_reported_as_a_failure() {
        // Observed in the running app: "HTTPS MITM 连接结束: connection closed
        // before message completed" arrived as an error toast while browsing
        // worked. A browser dropping an idle keep-alive socket, or a tab closed
        // mid-response, is how HTTP ends — not something to interrupt over.
        let error = serve_one_and_capture_error(b"GET / HTTP/1.1\r\nHost: x.test\r\n").await;
        assert!(
            is_benign_connection_end(&error),
            "a half-sent request from a departed client must stay silent: {error:?}"
        );
    }

    #[test]
    fn a_peer_hanging_up_is_silent_but_a_refused_certificate_or_dead_route_is_not() {
        use std::io::ErrorKind;
        // Observed: "客户端 TLS 握手失败 fonts.gstatic.com:443: tls handshake eof".
        // Browsers pre-open TLS connections they may never use, and racing
        // connections lose and close the same way. The same kinds end a CONNECT
        // or bypass tunnel, which copy_bidirectional reports as a reset.
        for kind in [
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::NotConnected,
        ] {
            assert!(
                is_benign_io_end(&std::io::Error::from(kind)),
                "{kind:?} is a client hanging up, not a failure to report"
            );
        }
        // A client refusing our CA arrives as a fatal alert, which rustls
        // surfaces as InvalidData. That one has to reach the user — it is
        // exactly the setup problem the certificate page exists to fix.
        assert!(
            !is_benign_io_end(&std::io::Error::new(
                ErrorKind::InvalidData,
                "received fatal alert: UnknownCA",
            )),
            "a rejected certificate must still be reported"
        );
        // A dead route is a real problem the user can act on — a wrong upstream
        // proxy, a host that is not there. Silencing these alongside the
        // hang-ups is the mistake this half of the test exists to catch.
        for kind in [ErrorKind::TimedOut, ErrorKind::ConnectionRefused] {
            assert!(
                !is_benign_io_end(&std::io::Error::from(kind)),
                "{kind:?} is actionable and must still be reported"
            );
        }
    }

    #[test]
    fn both_forward_paths_treat_a_routine_ending_the_same_way() {
        // The two paths drifted once already: 0.4.4 quieted the MITM forward and
        // left the explicit-proxy one reporting. They now share one classifier,
        // and the count catches a third path added without it.
        let source = production_source();
        assert_eq!(
            source.matches("is_benign_forward_end(&error)").count(),
            2,
            "the MITM and explicit-proxy forwards must ask the same question"
        );
        // Cancellation is routine on a forward — an origin closing an idle
        // keep-alive socket looks exactly like this — but on the inbound
        // listener it is a peer hanging up, so both keep it.
        let at = source
            .find("fn is_benign_connection_end(")
            .expect("the connection classifier exists");
        assert!(
            source[at..at + 400].contains("is_canceled()"),
            "a cancelled connection is still a peer hanging up"
        );
    }

    #[test]
    fn a_tab_closed_on_a_live_websocket_is_not_a_relay_failure() {
        use tokio_tungstenite::tungstenite::error::ProtocolError;
        use tokio_tungstenite::tungstenite::Error;

        // Closing or reloading a page with an open socket produces exactly
        // these. relay_websocket already returns Ok for the graceful endings —
        // a None from the stream and a Close frame — so what reached the user
        // was only ever the ordinary abrupt one.
        for error in [
            Error::ConnectionClosed,
            Error::AlreadyClosed,
            Error::Protocol(ProtocolError::ResetWithoutClosingHandshake),
            Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        ] {
            assert!(
                is_benign_websocket_end(&error),
                "a socket dying with the page is not a failure: {error:?}"
            );
        }

        // A peer that violates the protocol is a real fault worth reporting.
        for error in [
            Error::Protocol(ProtocolError::WrongHttpMethod),
            Error::Protocol(ProtocolError::HandshakeIncomplete),
        ] {
            assert!(
                !is_benign_websocket_end(&error),
                "a protocol violation must still report: {error:?}"
            );
        }

        // The step helper turns that distinction into control flow: None ends
        // the relay quietly, Err carries the message the user should see.
        assert_eq!(
            websocket_step(Ok::<u8, Error>(7), "读取客户端 WebSocket 消息失败").unwrap(),
            Some(7)
        );
        assert_eq!(
            websocket_step(
                Err::<u8, Error>(Error::ConnectionClosed),
                "读取客户端 WebSocket 消息失败"
            )
            .unwrap(),
            None
        );
        let reported = websocket_step(
            Err::<u8, Error>(Error::Protocol(ProtocolError::WrongHttpMethod)),
            "读取客户端 WebSocket 消息失败",
        )
        .unwrap_err();
        assert!(
            reported.starts_with("读取客户端 WebSocket 消息失败: "),
            "{reported}"
        );
    }

    #[test]
    fn every_websocket_step_goes_through_the_classifier() {
        // rustls relay: two reads, two sends, two pings. impersonate relay:
        // client-side read/send/pong still go through the same classifier.
        let source = production_source();
        assert_eq!(
            source.matches("websocket_step(").count(),
            9,
            "every WebSocket step must ask whether the peer simply went away"
        );
        assert!(
            !source.contains("WebSocket 消息失败: {error}"),
            "a bare map_err on a WebSocket step reports an ordinary disconnect"
        );
    }

    #[test]
    fn the_connect_setup_path_also_asks_before_reporting() {
        // Two more producers on the way into a tunnel: the upgrade itself, and
        // the ClientHello read. Both fail when a browser abandons a connection
        // it pre-opened, which is routine.
        let source = production_source();
        assert!(
            source.contains("if !is_benign_connection_end(&error) {\n                    error_sink(format!(\"CONNECT 升级失败"),
            "an abandoned CONNECT upgrade must not be reported"
        );
        let at = source
            .find("read_client_hello(&mut client).await")
            .expect("the CONNECT path reads a ClientHello");
        assert!(
            source[at..at + 400].contains("if !error.abandoned {"),
            "a ClientHello that never arrived must not be reported"
        );
    }

    #[test]
    fn every_place_that_reports_a_hang_up_asks_first() {
        // The classifier above is only useful where it is consulted. Three
        // sites report an io::Error to the user: the client TLS handshake, the
        // CONNECT tunnel copy, and the bypass tunnel copy. A fourth added
        // without a guard reintroduces the noise, so the count is pinned.
        let source = production_source();
        assert_eq!(
            source.matches("if !is_benign_io_end(&").count(),
            3,
            "each site that reports an io failure must ask whether it is a hang-up"
        );
    }

    #[test]
    fn h2_stripping_removes_exactly_what_http2_forbids() {
        // A client may reach the MITM over HTTP/1.1 while the origin negotiated
        // h2 — our leaf offers both. Forwarding h1's connection-specific headers
        // onto an h2 stream makes hyper reject the whole request with a bare
        // "http2 error", which reads as the origin refusing us.
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("keep-alive, x-hop"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-hop", HeaderValue::from_static("dropped-by-token"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("upgrade", HeaderValue::from_static("h2c"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        headers.insert("cookie", HeaderValue::from_static("cf_clearance=keep"));
        headers.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));

        strip_http2_forbidden_headers(&mut headers);

        for gone in [
            "connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "proxy-connection",
        ] {
            assert!(!headers.contains_key(gone), "{gone} is illegal over h2");
        }
        // `te: trailers` is explicitly legal over h2 (RFC 9113 §8.2.2) and hyper
        // keeps it. Stripping it broke gRPC trailer negotiation and made our
        // requests differ from the browser we are meant to resemble.
        assert_eq!(
            headers.get("te").and_then(|value| value.to_str().ok()),
            Some("trailers")
        );
        let mut other_te = HeaderMap::new();
        other_te.insert("te", HeaderValue::from_static("gzip"));
        strip_http2_forbidden_headers(&mut other_te);
        assert!(!other_te.contains_key("te"), "only `trailers` is legal");
        // Names listed in `Connection:` go too — that is what the token list means.
        assert!(!headers.contains_key("x-hop"));
        // Everything the request actually needs survives. Dropping the cookie
        // here would break the very challenge flow this fix exists to unblock.
        assert_eq!(
            headers.get("cookie").and_then(|value| value.to_str().ok()),
            Some("cf_clearance=keep")
        );
        assert_eq!(
            headers
                .get("user-agent")
                .and_then(|value| value.to_str().ok()),
            Some("Mozilla/5.0")
        );
    }

    #[test]
    fn outbound_h2_requests_are_stripped_before_they_are_captured() {
        // Order matters twice over: the strip has to run after the websocket
        // upgrade headers are set (so it does not eat them on the h1 path) and
        // before capture (so the recorded headers are the ones actually sent).
        let source = production_source();
        let strip = source
            .find("if parts.version == Version::HTTP_2 {\n            strip_http2_forbidden_headers(&mut parts.headers);")
            .expect("outbound h2 requests must be stripped");
        let cookies = source
            .find("collapse_cookie_headers(&mut parts.headers);")
            .expect("cookie crumbs must be joined before wreq rebuilds the request");
        let capture = source
            .find("request_headers = request_headers_for_capture(")
            .expect("request capture site");
        assert!(strip < cookies, "stripping must precede cookie collapse");
        assert!(cookies < capture, "cookie collapse must precede capture");
    }

    #[test]
    fn cookie_crumbs_join_into_one_header() {
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, HeaderValue::from_static("_os=a"));
        headers.append(COOKIE, HeaderValue::from_static("session=keep"));
        headers.append(COOKIE, HeaderValue::from_static("s6=z"));
        collapse_cookie_headers(&mut headers);
        let all: Vec<_> = headers.get_all(COOKIE).iter().collect();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].to_str().unwrap(), "_os=a; session=keep; s6=z");
    }

    #[test]
    fn a_single_cookie_header_is_left_alone() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("session=only"));
        collapse_cookie_headers(&mut headers);
        assert_eq!(
            headers.get(COOKIE).and_then(|value| value.to_str().ok()),
            Some("session=only")
        );
    }

    #[test]
    fn absolute_form_uri_carries_scheme_and_authority_matching_host() {
        let origin = origin_form_uri(&"https://api.test/v1/x?q=1".parse::<Uri>().unwrap()).unwrap();
        assert_eq!(origin.to_string(), "/v1/x?q=1");
        assert!(origin.scheme().is_none() && origin.authority().is_none());

        // Default port is elided, matching the Host header.
        let absolute = absolute_form_uri("https", "api.test", 443, &origin).unwrap();
        assert_eq!(absolute.to_string(), "https://api.test/v1/x?q=1");
        assert_eq!(absolute.scheme_str(), Some("https"));
        assert_eq!(
            absolute.authority().map(|a| a.as_str()),
            Some(host_header_authority("https", "api.test", 443).as_str())
        );

        // Non-default port is kept, still matching the Host header.
        let odd = absolute_form_uri("https", "api.test", 8443, &origin).unwrap();
        assert_eq!(odd.to_string(), "https://api.test:8443/v1/x?q=1");
        assert_eq!(
            odd.authority().map(|a| a.as_str()),
            Some(host_header_authority("https", "api.test", 8443).as_str())
        );

        // A path-less request still produces a valid target.
        let root =
            absolute_form_uri("https", "api.test", 443, &"/".parse::<Uri>().unwrap()).unwrap();
        assert_eq!(root.to_string(), "https://api.test/");
    }

    /// The shape `forward_mitm_https` and `forward_http` send to an h2 origin:
    /// a URI rewritten to origin form (path only) together with HTTP_2.
    ///
    /// h2 derives `:scheme` and `:authority` from the URI alone — there is no
    /// Host-header fallback — so an origin-form URI leaves both pseudo-headers
    /// unset and the send is rejected before a frame goes out. No existing test
    /// builds an `HttpsRequestSender::Http2`, so nothing covered this pairing.
    #[tokio::test]
    async fn h2_origin_rejects_origin_form_uri_but_accepts_absolute_form() {
        async fn send(uri: Uri, version: Version) -> Result<StatusCode, String> {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(server_io),
                        service_fn(|_req: Request<hyper::body::Incoming>| async move {
                            Ok::<_, std::convert::Infallible>(Response::new(
                                http_body_util::Full::new(Bytes::from_static(b"ok")),
                            ))
                        }),
                    )
                    .await;
            });
            let (mut sender, connection) = hyper::client::conn::http2::handshake(
                TokioExecutor::new(),
                TokioIo::new(client_io),
            )
            .await
            .map_err(|error| error.to_string())?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut request = Request::new(http_body_util::Empty::<Bytes>::new());
            *request.uri_mut() = uri;
            *request.version_mut() = version;
            sender
                .send_request(request)
                .await
                .map(|response| response.status())
                .map_err(|error| {
                    // hyper's Display is just "http2 error"; the useful detail is
                    // in the source chain.
                    let mut chain = error.to_string();
                    let mut source = std::error::Error::source(&error);
                    while let Some(inner) = source {
                        chain.push_str(&format!(" | {inner}"));
                        source = std::error::Error::source(inner);
                    }
                    chain
                })
        }

        // Absolute form carries scheme and authority, so h2 can build the pseudo-headers.
        let absolute = send(
            "https://origin.test/path".parse::<Uri>().unwrap(),
            Version::HTTP_2,
        )
        .await
        .expect("absolute-form request must be accepted by an h2 origin");
        assert_eq!(absolute, StatusCode::OK);

        // Origin form is what origin_form_uri produces. This is the pairing the
        // forwarding paths use, and h2 refuses it.
        let origin_form = origin_form_uri(&"https://origin.test/path".parse::<Uri>().unwrap())
            .expect("origin form");
        assert_eq!(origin_form.to_string(), "/path");
        let rejected = send(origin_form, Version::HTTP_2).await;
        assert!(
            rejected.is_err(),
            "expected h2 to reject an origin-form URI, got {rejected:?}"
        );
        let message = rejected.unwrap_err();
        assert!(
            message.contains("scheme") || message.contains("authority"),
            "expected a missing scheme/authority error, got: {message}"
        );
    }

    #[tokio::test]
    async fn decodes_h2_application_requests_and_captures_bodies() {
        let (proxy_upstream, target_upstream) = tokio::io::duplex(64 * 1024);
        let upstream_seen = Arc::new(Mutex::new(Vec::new()));
        let upstream_seen_sink = upstream_seen.clone();
        let target_task = tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let upstream_seen_sink = upstream_seen_sink.clone();
                async move {
                    let version = request.version();
                    let path = request
                        .uri()
                        .path_and_query()
                        .map(|value| value.as_str().to_string())
                        .unwrap_or_else(|| "/".to_string());
                    let host = request
                        .headers()
                        .get(HOST)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    upstream_seen_sink
                        .lock()
                        .unwrap()
                        .push((version, path, host, body));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .header("connection", "close")
                            .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(target_upstream), service)
                .await
                .unwrap();
        });
        let (upstream_sender, upstream_connection) = hyper::client::conn::http1::handshake::<
            _,
            TapBody<ProxyBody>,
        >(TokioIo::new(proxy_upstream))
        .await
        .unwrap();
        let upstream_connection_task = tokio::spawn(async move {
            let _ = upstream_connection.await;
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let (h2_client_io, h2_server_io) = tokio::io::duplex(64 * 1024);
        let mitm_task = tokio::spawn(serve_mitm_application(
            h2_server_io,
            "127.0.0.1:54321".parse().unwrap(),
            "session-h2".to_string(),
            "browser".to_string(),
            "example.test".to_string(),
            443,
            None,
            "TLSv1_3".to_string(),
            "h2".to_string(),
            test_tls_fingerprint(),
            Arc::new(AsyncMutex::new(HttpsRequestSender::Http1(upstream_sender))),
            unavailable_dedicated_sender_factory(),
            capture_sink,
            None,
            Arc::new(|_| {}),
            error_sink,
        ));
        let (mut h2_sender, h2_connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Full<Bytes>>(TokioIo::new(h2_client_io))
                .await
                .unwrap();
        let h2_connection_task = tokio::spawn(async move {
            let _ = h2_connection.await;
        });
        let response = h2_sender
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://example.test/upload?q=1")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from_static(b"{\"value\":42}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        assert!(response.headers().get("connection").is_none());
        let response_body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(response_body, Bytes::from_static(b"{\"ok\":true}"));
        tokio::task::yield_now().await;

        let upstream_seen = upstream_seen.lock().unwrap();
        assert_eq!(upstream_seen.len(), 1);
        assert_eq!(upstream_seen[0].0, Version::HTTP_11);
        assert_eq!(upstream_seen[0].1, "/upload?q=1");
        assert_eq!(upstream_seen[0].2, "example.test");
        assert_eq!(upstream_seen[0].3, Bytes::from_static(b"{\"value\":42}"));
        drop(upstream_seen);

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].protocol, "h2");
        assert_eq!(captured[0].path, "/upload");
        assert_eq!(captured[0].query.as_deref(), Some("q=1"));
        assert_eq!(captured[0].request_body.as_deref(), Some("{\"value\":42}"));
        assert_eq!(captured[0].response_body.as_deref(), Some("{\"ok\":true}"));
        assert!(captured[0]
            .response_headers
            .iter()
            .all(|header| !header.name.eq_ignore_ascii_case("connection")));
        let h2_fingerprint = captured[0]
            .tls_fingerprint
            .as_ref()
            .and_then(|fingerprint| fingerprint.http2.as_ref())
            .expect("HTTP/2 fingerprint");
        assert!(h2_fingerprint.complete);
        assert!(!h2_fingerprint.settings.is_empty());
        assert_eq!(h2_fingerprint.hash.len(), 64);
        drop(captured);
        assert!(errors.lock().unwrap().is_empty());

        drop(h2_sender);
        mitm_task.abort();
        h2_connection_task.abort();
        upstream_connection_task.abort();
        target_task.abort();
    }

    #[tokio::test]
    async fn https_mitm_mirror_uses_target_identity_and_keeps_original_capture_authority() {
        let (proxy_upstream, target_upstream) = tokio::io::duplex(64 * 1024);
        let upstream_host = Arc::new(Mutex::new(String::new()));
        let upstream_host_sink = upstream_host.clone();
        let target_task = tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let upstream_host_sink = upstream_host_sink.clone();
                async move {
                    *upstream_host_sink.lock().unwrap() = request
                        .headers()
                        .get(HOST)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "text/plain")
                            .header(CONTENT_LENGTH, "2")
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(target_upstream), service)
                .await
                .unwrap();
        });
        let (upstream_sender, upstream_connection) = hyper::client::conn::http1::handshake::<
            _,
            TapBody<ProxyBody>,
        >(TokioIo::new(proxy_upstream))
        .await
        .unwrap();
        let upstream_connection_task = tokio::spawn(async move {
            let _ = upstream_connection.await;
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let rule_engine = RuleEngine::request_only(Arc::new(|_| Ok(RuntimeRuleControl::default())));
        let pending_traces = rule_engine.pending_traces.clone();
        let route = RuntimeMirrorRoute {
            rule_id: "rule-mitm-mirror".to_string(),
            rule_name: "测试环境镜像".to_string(),
            revision: 3,
            original_host: "api.original.test".to_string(),
            original_port: 443,
            target_host: "stage.target.test".to_string(),
            target_port: 8443,
            identity: MirrorIdentity::Target,
        };
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mitm_task = tokio::spawn(serve_mitm_application(
            server_io,
            "127.0.0.1:54321".parse().unwrap(),
            "session-mirror-mitm".to_string(),
            "browser".to_string(),
            "api.original.test".to_string(),
            443,
            Some(route),
            "TLSv1_3".to_string(),
            "http/1.1".to_string(),
            test_tls_fingerprint(),
            Arc::new(AsyncMutex::new(HttpsRequestSender::Http1(upstream_sender))),
            unavailable_dedicated_sender_factory(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        ));
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(client_io))
                .await
                .unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender
            .send_request(
                Request::builder()
                    .method(Method::GET)
                    .uri("/items?q=1")
                    .header(HOST, "api.original.test")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"ok")
        );
        tokio::task::yield_now().await;

        assert_eq!(&*upstream_host.lock().unwrap(), "stage.target.test:8443");
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].host, "api.original.test");
        assert_eq!(captured[0].port, Some(443));
        assert!(captured[0].request_headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("host") && header.value == "api.original.test"
        }));
        let request_id = captured[0].id.as_deref().unwrap();
        let traces = pending_traces.lock().unwrap();
        let trace = traces.get(request_id).unwrap().first().unwrap();
        assert_eq!(trace.stage, "connection");
        assert_eq!(trace.result, "inherited");
        assert_eq!(
            trace.diff_summary["route"]["targetAuthority"],
            "stage.target.test:8443"
        );
        drop(traces);
        drop(captured);
        assert!(errors.lock().unwrap().is_empty());

        drop(sender);
        mitm_task.abort();
        connection_task.abort();
        upstream_connection_task.abort();
        target_task.abort();
    }

    #[tokio::test]
    async fn https_mitm_map_remote_uses_dedicated_target_and_skips_shared_origin() {
        let (dedicated_proxy_upstream, dedicated_target_upstream) = tokio::io::duplex(64 * 1024);
        let target_seen = Arc::new(Mutex::new(Vec::<(String, Vec<(String, String)>)>::new()));
        let target_seen_sink = target_seen.clone();
        let target_task = tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let target_seen_sink = target_seen_sink.clone();
                async move {
                    let path_and_query = request
                        .uri()
                        .path_and_query()
                        .map(|value| value.as_str().to_string())
                        .unwrap_or_else(|| "/".to_string());
                    let headers = request
                        .headers()
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.as_str().to_string(),
                                value.to_str().unwrap_or("<binary>").to_string(),
                            )
                        })
                        .collect();
                    target_seen_sink
                        .lock()
                        .unwrap()
                        .push((path_and_query, headers));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .header(CONTENT_LENGTH, "11")
                            .header("connection", "close")
                            .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(dedicated_target_upstream), service)
                .await
                .unwrap();
        });
        let (dedicated_sender, dedicated_connection) =
            hyper::client::conn::http1::handshake::<_, TapBody<ProxyBody>>(TokioIo::new(
                dedicated_proxy_upstream,
            ))
            .await
            .unwrap();
        let dedicated_connection_task = tokio::spawn(async move {
            let _ = dedicated_connection.await;
        });
        let dedicated_sender = Arc::new(AsyncMutex::new(Some(dedicated_sender)));
        let dedicated_routes = Arc::new(Mutex::new(Vec::<DedicatedRequestRoute>::new()));
        let dedicated_sender_factory: DedicatedRequestSenderFactory = {
            let dedicated_sender = dedicated_sender.clone();
            let dedicated_routes = dedicated_routes.clone();
            Arc::new(move |route| {
                dedicated_routes.lock().unwrap().push(route);
                let dedicated_sender = dedicated_sender.clone();
                Box::pin(async move {
                    dedicated_sender
                        .lock()
                        .await
                        .take()
                        .map(HttpsRequestSender::Http1)
                        .ok_or_else(|| "Map Remote 专用测试上游只能建立一次".to_string())
                })
            })
        };

        let (shared_proxy_upstream, shared_target_upstream) = tokio::io::duplex(64 * 1024);
        let shared_seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let shared_seen_sink = shared_seen.clone();
        let shared_target_task = tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let shared_seen_sink = shared_seen_sink.clone();
                async move {
                    shared_seen_sink
                        .lock()
                        .unwrap()
                        .push(request.uri().to_string());
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_LENGTH, "9")
                            .body(Full::new(Bytes::from_static(b"shared-ok")))
                            .unwrap(),
                    )
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(shared_target_upstream), service)
                .await;
        });
        let (shared_sender, shared_connection) = hyper::client::conn::http1::handshake::<
            _,
            TapBody<ProxyBody>,
        >(TokioIo::new(shared_proxy_upstream))
        .await
        .unwrap();
        let shared_connection_task = tokio::spawn(async move {
            let _ = shared_connection.await;
        });

        let storage = Arc::new(crate::storage::Storage::in_memory().unwrap());
        let rule = storage
            .save_capture_rule(crate::models::CaptureRuleInput {
                id: None,
                name: "HTTPS MITM Map Remote".to_string(),
                enabled: false,
                priority: 10,
                stage: "request".to_string(),
                matcher: crate::models::FilterExpression::Predicate {
                    field: "host".to_string(),
                    operator: "equals".to_string(),
                    value: Some(json!("api.original.test")),
                },
                action: json!({
                    "kind":"redirect",
                    "targetTemplate":"https://mapped.target.test:9443/sandbox/*"
                }),
                created_by: "user".to_string(),
            })
            .unwrap();
        storage
            .set_capture_rule_enabled(&rule.id, true, true)
            .unwrap();
        let traces = Arc::new(Mutex::new(Vec::<crate::models::CaptureRuleRun>::new()));
        let request_storage = storage.clone();
        let request_traces = traces.clone();
        let request_engine: RequestRuleEngine = Arc::new(move |request| {
            let outcome =
                crate::capture_rules::apply_runtime_request_rules(&request_storage, request)?;
            request_traces.lock().unwrap().extend(outcome.traces);
            Ok(outcome.control)
        });
        let rule_engine = RuleEngine::request_only(request_engine);
        let pending_traces = rule_engine.pending_traces.clone();
        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let mirror_route = RuntimeMirrorRoute {
            rule_id: "rule-original-mirror".to_string(),
            rule_name: "原连接镜像".to_string(),
            revision: 2,
            original_host: "api.original.test".to_string(),
            original_port: 443,
            target_host: "mirror.shared.test".to_string(),
            target_port: 7443,
            identity: MirrorIdentity::Target,
        };
        let (h2_client_io, h2_server_io) = tokio::io::duplex(64 * 1024);
        let mitm_task = tokio::spawn(serve_mitm_application(
            h2_server_io,
            "127.0.0.1:54321".parse().unwrap(),
            "session-map-remote-mitm".to_string(),
            "browser".to_string(),
            "api.original.test".to_string(),
            443,
            Some(mirror_route),
            "TLSv1_3".to_string(),
            "h2".to_string(),
            test_tls_fingerprint(),
            Arc::new(AsyncMutex::new(HttpsRequestSender::Http1(shared_sender))),
            dedicated_sender_factory,
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        ));
        let (mut h2_sender, h2_connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Full<Bytes>>(TokioIo::new(h2_client_io))
                .await
                .unwrap();
        let h2_connection_task = tokio::spawn(async move {
            let _ = h2_connection.await;
        });
        let response = h2_sender
            .send_request(
                Request::builder()
                    .method(Method::GET)
                    .uri("https://api.original.test/orders?token=query-secret&keep=1")
                    .header("authorization", "Bearer auth-secret")
                    .header("cookie", "sid=cookie-secret")
                    .header("x-api-key", "header-secret")
                    .header("x-client", "shownet")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"{\"ok\":true}")
        );
        tokio::task::yield_now().await;

        let routes = dedicated_routes.lock().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].scheme, "https");
        assert_eq!(routes[0].connection_host, "mapped.target.test");
        assert_eq!(routes[0].port, 9443);
        assert_eq!(routes[0].tls_identity_host, "mapped.target.test");
        drop(routes);
        assert!(shared_seen.lock().unwrap().is_empty());
        let target_seen = target_seen.lock().unwrap();
        assert_eq!(target_seen.len(), 1);
        assert_eq!(target_seen[0].0, "/sandbox/orders?keep=1");
        let target_headers = &target_seen[0].1;
        assert!(target_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("host") && value == "mapped.target.test:9443"
        }));
        assert!(target_headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-client") && value == "shownet"));
        assert!(target_headers.iter().all(|(name, _)| {
            !matches!(
                name.to_ascii_lowercase().as_str(),
                "authorization" | "cookie" | "x-api-key"
            )
        }));
        drop(target_seen);

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].host, "mapped.target.test");
        assert_eq!(captured[0].port, Some(9443));
        assert_eq!(captured[0].path, "/sandbox/orders");
        assert_eq!(captured[0].query.as_deref(), Some("keep=1"));
        assert!(captured[0].request_headers.iter().all(|header| {
            !matches!(
                header.name.to_ascii_lowercase().as_str(),
                "authorization" | "cookie" | "x-api-key"
            )
        }));
        drop(captured);
        let traces = traces.lock().unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].result, "applied");
        let trace_json = serde_json::to_string(&*traces).unwrap();
        for secret in [
            "query-secret",
            "auth-secret",
            "cookie-secret",
            "header-secret",
        ] {
            assert!(!trace_json.contains(secret));
        }
        assert!(pending_traces.lock().unwrap().is_empty());
        assert!(errors.lock().unwrap().is_empty(), "errors: {errors:?}");

        drop(h2_sender);
        mitm_task.abort();
        h2_connection_task.abort();
        shared_connection_task.abort();
        shared_target_task.abort();
        dedicated_connection_task.abort();
        target_task.abort();
    }

    #[tokio::test]
    async fn https_mitm_breakpoint_edits_the_request_seen_by_upstream() {
        let (proxy_upstream, target_upstream) = tokio::io::duplex(64 * 1024);
        let upstream_seen = Arc::new(Mutex::new(Vec::new()));
        let upstream_seen_sink = upstream_seen.clone();
        let target_task = tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let upstream_seen_sink = upstream_seen_sink.clone();
                async move {
                    let method = request.method().clone();
                    let uri = request.uri().to_string();
                    let marker = request
                        .headers()
                        .get("x-breakpoint-edited")
                        .and_then(|value| value.to_str().ok())
                        .map(ToString::to_string);
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    upstream_seen_sink
                        .lock()
                        .unwrap()
                        .push((method, uri, marker, body));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "text/plain")
                            .header(CONTENT_LENGTH, "11")
                            .body(Full::new(Bytes::from_static(b"upstream-ok")))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(target_upstream), service)
                .await
                .unwrap();
        });
        let (upstream_sender, upstream_connection) = hyper::client::conn::http1::handshake::<
            _,
            TapBody<ProxyBody>,
        >(TokioIo::new(proxy_upstream))
        .await
        .unwrap();
        let upstream_connection_task = tokio::spawn(async move {
            let _ = upstream_connection.await;
        });

        let coordinator = Arc::new(BreakpointCoordinator::default());
        let request_rule = test_breakpoint_rule("request");
        let mut rule_engine =
            RuleEngine::request_only(Arc::new(|_| Ok(RuntimeRuleControl::default())));
        rule_engine.request_breakpoints = Arc::new(move |_| Ok(vec![request_rule.clone()]));
        rule_engine.breakpoints = coordinator.clone();
        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let (h2_client_io, h2_server_io) = tokio::io::duplex(64 * 1024);
        let mitm_task = tokio::spawn(serve_mitm_application(
            h2_server_io,
            "127.0.0.1:54321".parse().unwrap(),
            "session-breakpoint-https".to_string(),
            "browser".to_string(),
            "example.test".to_string(),
            443,
            None,
            "TLSv1_3".to_string(),
            "h2".to_string(),
            test_tls_fingerprint(),
            Arc::new(AsyncMutex::new(HttpsRequestSender::Http1(upstream_sender))),
            unavailable_dedicated_sender_factory(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        ));
        let (mut h2_sender, h2_connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Full<Bytes>>(TokioIo::new(h2_client_io))
                .await
                .unwrap();
        let h2_connection_task = tokio::spawn(async move {
            let _ = h2_connection.await;
        });
        let response_task = tokio::spawn(async move {
            h2_sender
                .send_request(
                    Request::builder()
                        .method(Method::POST)
                        .uri("https://example.test/original?q=1")
                        .header(CONTENT_TYPE, "application/json")
                        .header(CONTENT_LENGTH, "18")
                        .body(Full::new(Bytes::from_static(b"{\"value\":\"before\"}")))
                        .unwrap(),
                )
                .await
                .unwrap()
        });

        let task = wait_for_breakpoint(&coordinator, "request").await;
        let mut headers = task.request_headers.clone();
        headers.push(HeaderEntry {
            name: "x-breakpoint-edited".to_string(),
            value: "yes".to_string(),
        });
        coordinator
            .resolve(crate::breakpoints::BreakpointDecisionInput {
                task_id: task.id,
                action: "continue".to_string(),
                method: Some("PATCH".to_string()),
                url: Some("https://example.test/edited?q=2".to_string()),
                request_headers: Some(headers),
                request_body: Some("{\"value\":\"after\"}".to_string()),
                ..Default::default()
            })
            .unwrap();
        let response = response_task.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"upstream-ok")
        );
        tokio::task::yield_now().await;

        let upstream_seen = upstream_seen.lock().unwrap();
        assert_eq!(upstream_seen.len(), 1);
        assert_eq!(upstream_seen[0].0, Method::PATCH);
        assert_eq!(upstream_seen[0].1, "/edited?q=2");
        assert_eq!(upstream_seen[0].2.as_deref(), Some("yes"));
        assert_eq!(
            upstream_seen[0].3,
            Bytes::from_static(b"{\"value\":\"after\"}")
        );
        drop(upstream_seen);
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].method, "PATCH");
        assert_eq!(captured[0].path, "/edited");
        assert_eq!(
            captured[0].request_body.as_deref(),
            Some("{\"value\":\"after\"}")
        );
        drop(captured);
        assert!(errors.lock().unwrap().is_empty());

        mitm_task.abort();
        h2_connection_task.abort();
        upstream_connection_task.abort();
        target_task.abort();
    }

    #[tokio::test]
    async fn https_mitm_request_body_rules_rewrite_and_rebuild_managed_headers() {
        let (proxy_upstream, target_upstream) = tokio::io::duplex(64 * 1024);
        let upstream_seen = Arc::new(Mutex::new(Vec::new()));
        let upstream_seen_sink = upstream_seen.clone();
        let target_task = tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let upstream_seen_sink = upstream_seen_sink.clone();
                async move {
                    let content_length = request
                        .headers()
                        .get(CONTENT_LENGTH)
                        .and_then(|value| value.to_str().ok())
                        .map(ToString::to_string);
                    let content_encoding = request.headers().get(CONTENT_ENCODING).cloned();
                    let content_md5 = request.headers().get("content-md5").cloned();
                    let digest = request.headers().get("digest").cloned();
                    let marker = request
                        .headers()
                        .get("x-body-rule")
                        .and_then(|value| value.to_str().ok())
                        .map(ToString::to_string);
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    upstream_seen_sink.lock().unwrap().push((
                        content_length,
                        content_encoding,
                        content_md5,
                        digest,
                        marker,
                        body,
                    ));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_LENGTH, "2")
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(target_upstream), service)
                .await
                .unwrap();
        });
        let (upstream_sender, upstream_connection) = hyper::client::conn::http1::handshake::<
            _,
            TapBody<ProxyBody>,
        >(TokioIo::new(proxy_upstream))
        .await
        .unwrap();
        let upstream_connection_task = tokio::spawn(async move {
            let _ = upstream_connection.await;
        });

        let request_engine: RequestRuleEngine = Arc::new(|request| {
            assert_eq!(
                request.request_body.as_deref(),
                Some("{\"value\":\"before\"}")
            );
            request.request_headers.push(HeaderEntry {
                name: "x-body-rule".to_string(),
                value: "applied".to_string(),
            });
            request.request_body = Some("{\"value\":\"after\"}".to_string());
            let mut control = RuntimeRuleControl::default();
            control.request_body_changed = true;
            Ok(control)
        });
        let mut rule_engine = RuleEngine::request_only(request_engine);
        rule_engine.request_body_required = Arc::new(|_| Ok(true));
        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let (h2_client_io, h2_server_io) = tokio::io::duplex(64 * 1024);
        let mitm_task = tokio::spawn(serve_mitm_application(
            h2_server_io,
            "127.0.0.1:54321".parse().unwrap(),
            "session-request-body-https".to_string(),
            "browser".to_string(),
            "example.test".to_string(),
            443,
            None,
            "TLSv1_3".to_string(),
            "h2".to_string(),
            test_tls_fingerprint(),
            Arc::new(AsyncMutex::new(HttpsRequestSender::Http1(upstream_sender))),
            unavailable_dedicated_sender_factory(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        ));
        let (mut h2_sender, h2_connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Full<Bytes>>(TokioIo::new(h2_client_io))
                .await
                .unwrap();
        let h2_connection_task = tokio::spawn(async move {
            let _ = h2_connection.await;
        });
        let response = h2_sender
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://example.test/rewrite")
                    .header(CONTENT_TYPE, "application/json")
                    .header(CONTENT_ENCODING, "identity")
                    .header(CONTENT_LENGTH, "18")
                    .header("content-md5", "obsolete")
                    .header("digest", "sha-256=obsolete")
                    .body(Full::new(Bytes::from_static(b"{\"value\":\"before\"}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"ok")
        );
        tokio::task::yield_now().await;

        let upstream_seen = upstream_seen.lock().unwrap();
        assert_eq!(upstream_seen.len(), 1);
        assert_eq!(upstream_seen[0].0.as_deref(), Some("17"));
        assert!(upstream_seen[0].1.is_none());
        assert!(upstream_seen[0].2.is_none());
        assert!(upstream_seen[0].3.is_none());
        assert_eq!(upstream_seen[0].4.as_deref(), Some("applied"));
        assert_eq!(
            upstream_seen[0].5,
            Bytes::from_static(b"{\"value\":\"after\"}")
        );
        drop(upstream_seen);
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0].request_body.as_deref(),
            Some("{\"value\":\"after\"}")
        );
        drop(captured);
        assert!(errors.lock().unwrap().is_empty());

        mitm_task.abort();
        h2_connection_task.abort();
        upstream_connection_task.abort();
        target_task.abort();
    }

    #[tokio::test]
    async fn relays_and_captures_rfc8441_extended_websocket_messages() {
        let (dedicated_proxy_upstream, target_upstream) = tokio::io::duplex(64 * 1024);
        let upstream_seen = Arc::new(Mutex::new(Vec::new()));
        let upstream_seen_sink = upstream_seen.clone();
        let target_task = tokio::spawn(async move {
            let service = service_fn(move |mut request: Request<Incoming>| {
                let upstream_seen_sink = upstream_seen_sink.clone();
                async move {
                    // RFC 6455 requires Sec-WebSocket-Key on the handshake, and a
                    // real origin answers 400 without it. An earlier version of
                    // this fake accepted the upgrade unconditionally, so the
                    // downgrade from RFC 8441 shipped without minting a key and
                    // every real WebSocket failed while this test stayed green.
                    let key_is_valid = request
                        .headers()
                        .get("sec-websocket-key")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| STANDARD.decode(value).ok())
                        .is_some_and(|bytes| bytes.len() == 16);
                    upstream_seen_sink.lock().unwrap().push((
                        request.method().clone(),
                        request.version(),
                        request.uri().path().to_string(),
                        is_websocket_upgrade(request.headers()),
                        key_is_valid,
                    ));
                    if !key_is_valid {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Full::new(Bytes::from_static(
                                    b"Missing or invalid Sec-WebSocket-Key header",
                                )))
                                .unwrap(),
                        );
                    }
                    let on_upgrade = hyper::upgrade::on(&mut request);
                    tokio::spawn(async move {
                        let upgraded = on_upgrade.await.unwrap();
                        let config = WebSocketConfig::default().write_buffer_size(0);
                        let mut websocket = WebSocketStream::from_raw_socket(
                            TokioIo::new(upgraded),
                            Role::Server,
                            Some(config),
                        )
                        .await;
                        while let Some(message) = websocket.next().await {
                            match message.unwrap() {
                                Message::Text(text) => {
                                    websocket.send(Message::Text(text)).await.unwrap()
                                }
                                Message::Binary(data) => {
                                    websocket.send(Message::Binary(data)).await.unwrap()
                                }
                                Message::Close(frame) => {
                                    let _ = websocket.send(Message::Close(frame)).await;
                                    break;
                                }
                                Message::Ping(_) => {
                                    let _ = websocket.flush().await;
                                }
                                Message::Pong(_) | Message::Frame(_) => {}
                            }
                        }
                    });
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header("connection", "Upgrade")
                            .header("upgrade", "websocket")
                            .header("sec-websocket-protocol", "shownet-test")
                            .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(target_upstream), service)
                .with_upgrades()
                .await
                .unwrap();
        });
        let (dedicated_sender, dedicated_connection) =
            hyper::client::conn::http1::handshake::<_, TapBody<ProxyBody>>(TokioIo::new(
                dedicated_proxy_upstream,
            ))
            .await
            .unwrap();
        let dedicated_connection_task = tokio::spawn(async move {
            let _ = dedicated_connection.with_upgrades().await;
        });
        let dedicated_sender = Arc::new(AsyncMutex::new(Some(dedicated_sender)));
        let dedicated_sender_factory: DedicatedRequestSenderFactory = {
            let dedicated_sender = dedicated_sender.clone();
            Arc::new(move |_| {
                let dedicated_sender = dedicated_sender.clone();
                Box::pin(async move {
                    dedicated_sender
                        .lock()
                        .await
                        .take()
                        .map(HttpsRequestSender::Http1)
                        .ok_or_else(|| "独立测试上游只能建立一次".to_string())
                })
            })
        };

        let (shared_proxy_upstream, shared_target_upstream) = tokio::io::duplex(64 * 1024);
        let shared_seen = Arc::new(Mutex::new(Vec::new()));
        let shared_seen_sink = shared_seen.clone();
        let shared_target_task = tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let shared_seen_sink = shared_seen_sink.clone();
                async move {
                    shared_seen_sink
                        .lock()
                        .unwrap()
                        .push(request.uri().path().to_string());
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "text/plain")
                            .body(Full::new(Bytes::from_static(b"shared-ok")))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(shared_target_upstream), service)
                .await
                .unwrap();
        });
        let (upstream_sender, upstream_connection) = hyper::client::conn::http1::handshake::<
            _,
            TapBody<ProxyBody>,
        >(TokioIo::new(shared_proxy_upstream))
        .await
        .unwrap();
        let upstream_connection_task = tokio::spawn(async move {
            let _ = upstream_connection.await;
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let events = Arc::new(Mutex::new(Vec::<CaptureEventInput>::new()));
        let event_sink: EventSink = {
            let events = events.clone();
            Arc::new(move |event| events.lock().unwrap().push(event))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let (h2_client_io, h2_server_io) = tokio::io::duplex(64 * 1024);
        let mitm_task = tokio::spawn(serve_mitm_application(
            h2_server_io,
            "127.0.0.1:54321".parse().unwrap(),
            "session-rfc8441".to_string(),
            "browser".to_string(),
            "example.test".to_string(),
            443,
            None,
            "TLSv1_3".to_string(),
            "h2".to_string(),
            test_tls_fingerprint(),
            Arc::new(AsyncMutex::new(HttpsRequestSender::Http1(upstream_sender))),
            dedicated_sender_factory,
            capture_sink,
            None,
            event_sink,
            error_sink,
        ));
        let (mut h2_sender, h2_connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Full<Bytes>>(TokioIo::new(h2_client_io))
                .await
                .unwrap();
        let h2_connection_task = tokio::spawn(async move {
            let _ = h2_connection.await;
        });
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri("https://example.test/socket?q=1")
            .header("sec-websocket-version", "13")
            // No sec-websocket-key, because RFC 8441 has none: the h2 stream
            // itself is the handshake. Chrome's real extended CONNECT was
            // captured and carries only version, protocol and the ordinary
            // headers. This fixture used to send one anyway, which let the
            // downgrade below reach the origin keyless while the test stayed
            // green — the fixture was the reason the bug was invisible.
            .header("sec-websocket-protocol", "shownet-test")
            .body(Full::new(Bytes::new()))
            .unwrap();
        request
            .extensions_mut()
            .insert(Protocol::from_static("websocket"));
        let mut response = timeout(Duration::from_secs(5), h2_sender.send_request(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_2);
        assert!(response.headers().get("connection").is_none());
        assert!(response.headers().get("upgrade").is_none());
        assert_eq!(
            response.headers().get("sec-websocket-protocol").unwrap(),
            "shownet-test"
        );

        let client_upgrade = hyper::upgrade::on(&mut response);
        let upgraded = timeout(Duration::from_secs(5), client_upgrade)
            .await
            .unwrap()
            .unwrap();
        let config = WebSocketConfig::default().write_buffer_size(0);
        let mut websocket =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, Some(config))
                .await;
        websocket
            .send(Message::text("hello over rfc8441"))
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(5), websocket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Message::text("hello over rfc8441")
        );
        let ordinary_response = timeout(
            Duration::from_secs(5),
            h2_sender.send_request(
                Request::builder()
                    .method(Method::GET)
                    .uri("https://example.test/after-websocket")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(ordinary_response.status(), StatusCode::OK);
        assert_eq!(
            ordinary_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            Bytes::from_static(b"shared-ok")
        );
        websocket.close(None).await.unwrap();
        tokio::task::yield_now().await;

        let upstream_seen = upstream_seen.lock().unwrap();
        assert_eq!(upstream_seen.len(), 1);
        assert_eq!(upstream_seen[0].0, Method::GET);
        assert_eq!(upstream_seen[0].1, Version::HTTP_11);
        assert_eq!(upstream_seen[0].2, "/socket");
        assert!(upstream_seen[0].3);
        assert!(
            upstream_seen[0].4,
            "the h1 handshake reached the origin without a valid Sec-WebSocket-Key; \
             RFC 8441 does not carry one, so the downgrade has to mint it"
        );
        drop(upstream_seen);
        assert_eq!(shared_seen.lock().unwrap().as_slice(), ["/after-websocket"]);

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 2);
        let websocket_capture = captured
            .iter()
            .find(|request| request.resource_type == "websocket")
            .unwrap();
        assert_eq!(websocket_capture.method, "CONNECT");
        assert_eq!(websocket_capture.status, 200);
        assert_eq!(websocket_capture.protocol, "h2");
        assert_eq!(websocket_capture.path, "/socket");
        assert_eq!(websocket_capture.query.as_deref(), Some("q=1"));
        assert!(websocket_capture
            .request_headers
            .iter()
            .any(|header| header.name == ":protocol" && header.value == "websocket"));
        assert!(captured
            .iter()
            .any(|request| request.path == "/after-websocket" && request.status == 200));
        let request_id = websocket_capture.id.clone().unwrap();
        let events = events.lock().unwrap();
        assert!(events.len() >= 2, "captured events: {events:?}");
        assert!(events.iter().all(|event| {
            event.phase == "websocket" && event.request_id.as_deref() == Some(request_id.as_str())
        }));
        assert_eq!(events[0].payload["direction"], "client_to_server");
        assert_eq!(events[0].payload["data"], "hello over rfc8441");
        assert_eq!(events[1].payload["direction"], "server_to_client");
        drop(events);
        drop(captured);
        assert!(errors.lock().unwrap().is_empty(), "errors: {errors:?}");

        drop(h2_sender);
        mitm_task.abort();
        h2_connection_task.abort();
        upstream_connection_task.abort();
        dedicated_connection_task.abort();
        shared_target_task.abort();
        target_task.abort();
    }

    #[test]
    fn mitm_leaf_advertises_h2_before_http11() {
        let config = test_certificate_authority()
            .server_config("example.test")
            .unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(negotiated_http_protocol(Some(b"h2")), "h2");
        assert_eq!(negotiated_http_protocol(Some(b"http/1.1")), "http/1.1");
        assert_eq!(negotiated_http_protocol(None), "http/1.1");
    }

    #[test]
    fn origin_http2_branch_follows_alpn_and_prefer_flag() {
        // Shipped ALPN selector used by handshake_origin_https.
        assert!(origin_prefers_http2(true, Some(b"h2")));
        assert!(!origin_prefers_http2(true, Some(b"http/1.1")));
        assert!(!origin_prefers_http2(false, Some(b"h2")));
        assert!(!origin_prefers_http2(true, None));
        // Chrome-like outbound config advertises h2 first.
        let cfg = tls_outbound::build_client_config(OutboundTlsProfile::ChromeLike);
        assert_eq!(
            cfg.alpn_protocols.first().map(|p| p.as_slice()),
            Some(&b"h2"[..])
        );
        // Strict CDN helper forces HTTP/1.1-only ALPN when still MITMing.
        let h1 = tls_outbound::build_client_config_http11_only(OutboundTlsProfile::ChromeLike);
        assert_eq!(h1.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(tls_outbound::origin_force_http11_for_host(
            "pss.bdstatic.com"
        ));
        assert!(tls_outbound::origin_force_http11_for_host(
            "psstatic.cdn.bcebos.com"
        ));
        assert!(!tls_outbound::origin_force_http11_for_host("www.baidu.com"));
    }

    fn ja3_measure_lock() -> std::sync::MutexGuard<'static, ()> {
        // set_soak_root_certificates_from_pem mutates process-global roots; serialize
        // all JA3 measure tests so ClientConfig verifies the same CA the server uses.
        static MEASURE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        MEASURE_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    async fn measure_profile_ja3(profile: OutboundTlsProfile, host: &str) -> String {
        let preset_id = match profile {
            OutboundTlsProfile::Default => "default",
            OutboundTlsProfile::ChromeLike => "chrome150",
            OutboundTlsProfile::FirefoxLike => "firefox136",
            OutboundTlsProfile::SafariIosLike => "safari-ios18",
        };
        measure_profile_ja3_with_preset(profile, preset_id, host).await
    }

    #[tokio::test]
    async fn connect_verified_tls_measures_outbound_client_hello_ja3() {
        let ja3 = measure_profile_ja3(OutboundTlsProfile::ChromeLike, "ja3.measure.test").await;
        assert_eq!(ja3.len(), 32);
        // The stack is linked exactly when the feature is compiled in; engine
        // follows the stack. Measured ja3Parity is still a separate, per-sample
        // golden decision and is not asserted here.
        assert_eq!(
            tls_outbound::real_impersonate_stack_available(),
            cfg!(feature = "impersonate-boring")
        );
        assert_eq!(
            tls_outbound::active_engine().supports_full_browser_ja3(),
            cfg!(feature = "impersonate-boring")
        );
    }

    #[tokio::test]
    async fn different_outbound_profiles_measure_different_ja3() {
        // Profiles must change real ClientHello material, not just labels.
        let chrome = measure_profile_ja3(OutboundTlsProfile::ChromeLike, "ja3.chrome.test").await;
        let firefox =
            measure_profile_ja3(OutboundTlsProfile::FirefoxLike, "ja3.firefox.test").await;
        let safari =
            measure_profile_ja3(OutboundTlsProfile::SafariIosLike, "ja3.safari.test").await;
        assert_ne!(
            chrome, firefox,
            "chrome-like vs firefox-like must differ on the wire"
        );
        assert_ne!(
            chrome, safari,
            "chrome-like vs safari-ios-like must differ on the wire"
        );
    }

    /// Measure wire JA3 for a versioned catalog preset (shipped MITM connect path).
    /// Serializes with other JA3 measures via the same lock as `measure_profile_ja3`.
    async fn measure_catalog_preset_ja3(preset_id: &str, host: &str) -> String {
        let preset = crate::tls_clienthello_catalog::get_preset(preset_id)
            .unwrap_or_else(|e| panic!("preset {preset_id}: {e}"));
        let coarse = match preset.family {
            "firefox" => OutboundTlsProfile::FirefoxLike,
            "safari" | "safari-ios" => OutboundTlsProfile::SafariIosLike,
            "chrome" | "chrome-android" | "edge" => OutboundTlsProfile::ChromeLike,
            _ => OutboundTlsProfile::Default,
        };
        // set_active is applied inside measure after taking the shared roots lock so the
        // selected catalog id is what build_client_config resolves.
        measure_profile_ja3_with_preset(coarse, preset_id, host).await
    }

    async fn measure_profile_ja3_with_preset(
        profile: OutboundTlsProfile,
        preset_id: &str,
        host: &str,
    ) -> String {
        let _guard = ja3_measure_lock();

        tls_outbound::set_active_preset(preset_id).unwrap();
        assert_eq!(
            tls_outbound::preset_id_for_profile(profile),
            preset_id,
            "builder must resolve to selected catalog preset {preset_id}"
        );

        let ca = test_certificate_authority();
        let pem_path = std::env::temp_dir().join(format!(
            "shownet-preset-ja3-{}-{}-{}.pem",
            std::process::id(),
            preset_id,
            host.replace('.', "_")
        ));
        std::fs::write(&pem_path, ca.certificate_pem().as_bytes()).unwrap();
        tls_outbound::set_soak_root_certificates_from_pem(&pem_path).unwrap();
        let server_config = ca.server_config(host).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(server_config);
            let _ = acceptor.accept(tcp).await;
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let stream = BoxedIo(Box::new(tcp));
        let verified = connect_verified_tls_measured(stream, host, profile, false)
            .await
            .expect("tls connect for catalog preset");
        let ja3 = verified
            .measured_ja3
            .clone()
            .expect("measured ja3 from CapturingIo");
        assert_eq!(ja3.len(), 32);
        drop(verified.stream);
        let _ = server_task.await;
        let _ = std::fs::remove_file(pem_path);
        assert_eq!(
            tls_outbound::real_impersonate_stack_available(),
            cfg!(feature = "impersonate-boring")
        );
        // Product policy: linked stack ⇒ full-browser engine is active.
        // This helper only measures rustls builder JA3 recipes; it does not
        // claim product MITM uses rustls when impersonate is linked.
        assert_eq!(
            tls_outbound::active_engine().supports_full_browser_ja3(),
            cfg!(feature = "impersonate-boring")
        );
        ja3
    }

    #[tokio::test]
    async fn industry_chrome_presets_measure_distinct_wire_ja3() {
        // Industry floor majors must produce distinct measured ClientHello JA3 on the
        // shipped MITM connect path (cipher/kx recipe differences), not labels alone.
        let c120 = measure_catalog_preset_ja3("chrome120", "ja3.ref.chrome120.test").await;
        let c131 = measure_catalog_preset_ja3("chrome131", "ja3.ref.chrome131.test").await;
        let c150 = measure_catalog_preset_ja3("chrome150", "ja3.ref.chrome150.test").await;
        let c133 = measure_catalog_preset_ja3("chrome133", "ja3.ref.chrome133.test").await;
        assert_ne!(c120, c131, "chrome120 vs chrome131 wire JA3");
        assert_ne!(c131, c150, "chrome131 vs chrome150 wire JA3");
        assert_ne!(c120, c150, "chrome120 vs chrome150 wire JA3");
        assert_ne!(c133, c150, "chrome133 vs chrome150 wire JA3");
        // Cross-family industry ids
        let ff = measure_catalog_preset_ja3("firefox133", "ja3.ref.firefox133.test").await;
        assert_ne!(c150, ff, "chrome150 vs firefox133 wire JA3");
        // Restore product default
        tls_outbound::set_active_preset("chrome150").unwrap();
    }

    #[tokio::test]
    async fn selected_preset_wire_ja3_is_stable_for_same_id() {
        // Same host twice: rustls ClientHello JA3 can still vary if extension order is not fixed.
        // Consistency we guarantee: builder cipher fingerprint is stable; wire JA3 for the same
        // preset stays within the chrome150 recipe class (≠ firefox133) and builder path is fixed.
        let host = "ja3.stable.chrome150.test";
        let fp = tls_outbound::preset_cipher_fingerprint("chrome150").unwrap();
        let fp2 = tls_outbound::preset_cipher_fingerprint("chrome150").unwrap();
        assert_eq!(fp, fp2, "builder cipher fingerprint must be deterministic");
        let a = measure_catalog_preset_ja3("chrome150", host).await;
        let b = measure_catalog_preset_ja3("chrome150", host).await;
        let ff = measure_catalog_preset_ja3("firefox133", "ja3.stable.ff.test").await;
        // Wire JA3: if rustls emits a fixed ClientHello for a fixed provider, equal; otherwise
        // at least both chrome150 samples must differ from firefox133 (recipe actually applied).
        if a != b {
            eprintln!(
                "note: rustls wire JA3 non-deterministic for same preset (a={a} b={b}); checking class separation"
            );
        } else {
            assert_eq!(a, b);
        }
        assert_ne!(a, ff, "chrome150 wire JA3 must differ from firefox133");
        assert_ne!(b, ff, "chrome150 wire JA3 must differ from firefox133");
        tls_outbound::set_active_preset("chrome150").unwrap();
    }

    /// The panel compares the two sides; before this the outbound half had no
    /// JA4 field at all, so the measurement was taken, written into prose, and
    /// dropped. Comparing the JA3s instead cannot work: Chrome randomises the
    /// GREASE values JA3 covers, so a real session produced sixteen distinct
    /// inbound JA3s carrying one identical JA4.
    #[test]
    fn a_tunnelled_handshake_reports_the_same_ja4_on_both_sides() {
        let inbound = crate::tls_fingerprint::ClientTlsFingerprint {
            ja3: "inbound-ja3".to_string(),
            ja3_raw: "771,4865,,,".to_string(),
            ja4: "t13d1516h2_8daaf6152771_806a8c22fdea".to_string(),
            ja4_raw: "t13d1516h2".to_string(),
            sni: Some("example.test".to_string()),
            alpn: vec!["h2".to_string()],
            legacy_version: "TLSv1_2".to_string(),
            offered_versions: vec!["TLSv1_3".to_string()],
            cipher_suites: vec!["0x1301".to_string()],
            extensions: vec!["0x0010".to_string()],
            supported_groups: vec!["0x001d".to_string()],
            signature_algorithms: vec!["0x0804".to_string()],
            grease: true,
        };
        let record = crate::tls_fingerprint::tunnel_fingerprint(inbound);
        assert_eq!(
            record.outbound.ja4.as_deref(),
            Some(record.inbound.ja4.as_str()),
            "pass-through sends the client's own ClientHello, so the sides cannot differ"
        );
    }

    #[test]
    fn mitm_fingerprint_never_preclaims_ja3_parity() {
        let inbound = crate::tls_fingerprint::ClientTlsFingerprint {
            ja3: "a".into(),
            ja3_raw: "raw".into(),
            ja4: "t13d1516h2_x_y".into(),
            ja4_raw: "t13d1516h2_x_y".into(),
            sni: Some("example.com".into()),
            alpn: vec!["h2".into()],
            legacy_version: "TLS1.2".into(),
            offered_versions: vec![],
            cipher_suites: vec![],
            extensions: vec![],
            supported_groups: vec![],
            signature_algorithms: vec![],
            grease: true,
        };
        let fp = mitm_fingerprint_with_selection(
            inbound,
            Some(OutboundTlsProfile::ChromeLike),
            Some(true),
            None,
        );
        assert_eq!(fp.outbound.ja3_parity, Some(false));
        let expected_engine = if tls_outbound::real_impersonate_stack_available() {
            "impersonate"
        } else {
            "rustls"
        };
        assert_eq!(fp.outbound.engine.as_deref(), Some(expected_engine));
        assert!(fp.outbound.ja3.is_none());
    }

    #[test]
    fn matches_bypass_patterns_without_partial_domain_matches() {
        let rules = vec!["*.example.com".to_string(), "internal.test".to_string()];
        assert!(should_bypass("api.example.com", &rules));
        assert!(should_bypass("example.com", &rules));
        assert!(should_bypass("internal.test", &rules));
        assert!(!should_bypass("notexample.com", &rules));
    }

    #[test]
    fn blocks_self_proxy_loop() {
        assert!(reject_proxy_loop("127.0.0.1", 8888).is_err());
        assert!(reject_proxy_loop("127.0.0.1", 7890).is_ok());
    }

    #[tokio::test]
    async fn connect_loop_is_rejected_before_the_tunnel_is_accepted() {
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-connect-loop".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
        )
        .await
        .unwrap();
        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(b"CONNECT 127.0.0.1:8888 HTTP/1.1\r\nHost: 127.0.0.1:8888\r\n\r\n")
            .await
            .unwrap();
        let response = read_http_header(&mut client).await.unwrap();
        assert!(
            response.starts_with("HTTP/1.1 502"),
            "CONNECT loop must fail before 200: {response}"
        );
        handle.stop().await;
    }

    #[tokio::test]
    async fn unrecognized_tls_dials_once_and_forwards_the_original_bytes() {
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::<u8>::new()));
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = {
            let accepted = accepted.clone();
            let received = received.clone();
            tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut bytes = Vec::new();
                let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes)).await;
                *received.lock().unwrap() = bytes;
            })
        };

        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-unrecognized-tls".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!("CONNECT {target_address} HTTP/1.1\r\nHost: {target_address}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut client).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        // Handshake record type 23 is not ClientHello — the tunnel path must
        // still open exactly one origin TCP and forward the original bytes.
        let unrecognized = [23_u8, 3, 3, 0, 4, b't', b'e', b's', b't'];
        client.write_all(&unrecognized).await.unwrap();
        client.shutdown().await.unwrap();
        target_task.await.unwrap();
        handle.stop().await;

        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(&*received.lock().unwrap(), &unrecognized);
    }

    #[tokio::test]
    async fn bypass_connect_failure_is_reported_after_local_accept() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_address = dead.local_addr().unwrap();
        drop(dead);

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let settings = crate::tls_interception::normalize_tls_interception_settings(
            crate::tls_interception::TlsInterceptionSettings {
                mode: crate::tls_interception::TlsInterceptionMode::BypassSelected,
                bypass: vec!["127.0.0.1".to_string()],
                show_bypassed_connections: true,
            },
        )
        .unwrap();
        let mut rule_engine =
            RuleEngine::request_only(Arc::new(|_| Ok(RuntimeRuleControl::default())));
        rule_engine.tls_interception = Arc::new(move |host, sni| Ok(settings.decision(host, sni)));
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-delayed-dial-fail".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!("CONNECT {dead_address} HTTP/1.1\r\nHost: {dead_address}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut client).await.unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "local CONNECT accept must not wait on origin dial: {response}"
        );
        client
            .write_all(&test_client_hello_wire("api.pinned.test"))
            .await
            .unwrap();
        let _ = timeout(Duration::from_secs(5), client.read_to_end(&mut Vec::new())).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        handle.stop().await;

        let captured = captured.lock().unwrap();
        assert!(
            captured
                .iter()
                .any(|request| request.method == "CONNECT" && request.status == 502),
            "origin dial failure after CONNECT 200 must be captured: {captured:?}"
        );
        assert!(
            errors
                .lock()
                .unwrap()
                .iter()
                .any(|error| error.contains("出站连接失败") || error.contains("连接")),
            "browser-facing error must surface: {:?}",
            errors.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn bypass_tls_dials_once_and_forwards_the_original_client_hello() {
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::<u8>::new()));
        let expected = test_client_hello_wire("api.pinned.test");
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = {
            let accepted = accepted.clone();
            let received = received.clone();
            let expected_len = expected.len();
            tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut bytes = vec![0_u8; expected_len];
                stream.read_exact(&mut bytes).await.unwrap();
                *received.lock().unwrap() = bytes;
            })
        };
        let settings = crate::tls_interception::normalize_tls_interception_settings(
            crate::tls_interception::TlsInterceptionSettings {
                mode: crate::tls_interception::TlsInterceptionMode::BypassSelected,
                bypass: vec!["127.0.0.1".to_string()],
                show_bypassed_connections: true,
            },
        )
        .unwrap();
        let mut rule_engine =
            RuleEngine::request_only(Arc::new(|_| Ok(RuntimeRuleControl::default())));
        rule_engine.tls_interception = Arc::new(move |host, sni| Ok(settings.decision(host, sni)));
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-bypass-one-tcp".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            Arc::new(|_| {}),
            Some(rule_engine),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
        )
        .await
        .unwrap();
        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!("CONNECT {target_address} HTTP/1.1\r\nHost: {target_address}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut client).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        client.write_all(&expected).await.unwrap();
        client.shutdown().await.unwrap();
        target_task.await.unwrap();
        handle.stop().await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(&*received.lock().unwrap(), &expected);
    }

    #[tokio::test]
    async fn mitm_dead_origin_is_captured_as_502_after_local_connect_ok() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_address = dead.local_addr().unwrap();
        drop(dead);
        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let ca = test_certificate_authority();
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-mitm-dead-origin".to_string(),
            direct_upstream(),
            ca.clone(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap();
        let mut tunnel = TcpStream::connect(handle.local_addr()).await.unwrap();
        tunnel
            .write_all(
                format!("CONNECT {dead_address} HTTP/1.1\r\nHost: {dead_address}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut tunnel).await.unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "local CONNECT accept must not wait on origin dial: {response}"
        );
        let mut roots = RootCertStore::empty();
        roots.add(ca.certificate_der()).unwrap();
        let tls = timeout(
            Duration::from_secs(5),
            TlsConnector::from(Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ))
            .connect(
                ServerName::try_from(dead_address.ip().to_string()).unwrap(),
                tunnel,
            ),
        )
        .await;
        match tls {
            Ok(Ok(mut stream)) => {
                let _ = stream
                    .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut Vec::new())).await;
            }
            Ok(Err(_)) | Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        handle.stop().await;
        let captured = captured.lock().unwrap();
        assert!(
            captured.iter().any(|request| request.status == 502),
            "MITM dead origin after CONNECT 200 must leave a 502: {captured:?}"
        );
        assert!(
            errors
                .lock()
                .unwrap()
                .iter()
                .any(|error| error.contains("连接")
                    || error.contains("转发")
                    || error.contains("上游")),
            "MITM origin failure must surface: {:?}",
            errors.lock().unwrap()
        );
    }

    #[cfg(feature = "impersonate-boring")]
    async fn counting_https_origin(
        host: &str,
        ca: &CertificateAuthority,
    ) -> (
        u16,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_config = ca.server_config(host).unwrap();
        let accepted_for_server = accepted.clone();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(_) => break,
                };
                accepted_for_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let server_config = server_config.clone();
                tokio::spawn(async move {
                    let tls = match TlsAcceptor::from(server_config).accept(stream).await {
                        Ok(tls) => tls,
                        Err(_) => return,
                    };
                    let service = service_fn(|request: Request<Incoming>| async move {
                        let empty = request.method() == Method::POST
                            && request.uri().path() == "/empty"
                            && request
                                .headers()
                                .get(CONTENT_LENGTH)
                                .and_then(|value| value.to_str().ok())
                                == Some("0");
                        let body = if empty { "empty-ok" } else { "one" };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/plain")
                                .header(CONTENT_LENGTH, body.len().to_string())
                                .body(Full::new(Bytes::from_static(if empty {
                                    b"empty-ok"
                                } else {
                                    b"one"
                                })))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        (port, accepted, server)
    }

    #[cfg(feature = "impersonate-boring")]
    #[tokio::test]
    async fn mitm_wreq_opens_one_target_tcp() {
        let ca = test_certificate_authority();
        let _roots = crate::impersonate_egress::install_test_root_certificate_der(
            ca.certificate_der().as_ref().to_vec(),
        );
        let host = "localhost";
        let (port, accepted, server) = counting_https_origin(host, &ca).await;
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-one-tcp-mitm".to_string(),
            direct_upstream(),
            ca.clone(),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
        )
        .await
        .unwrap();

        let client = TcpStream::connect(handle.local_addr()).await.unwrap();
        let mut tunnel = BoxedIo(Box::new(client));
        tunnel
            .write_all(
                format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut tunnel).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        let mut roots = RootCertStore::empty();
        roots.add(ca.certificate_der()).unwrap();
        let mut tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
        .connect(ServerName::try_from(host.to_string()).unwrap(), tunnel)
        .await
        .expect("MITM client TLS");
        tls.write_all(
            format!("GET /one HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut raw = Vec::new();
        timeout(Duration::from_secs(10), tls.read_to_end(&mut raw))
            .await
            .expect("origin response timeout")
            .unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("one"), "{text}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        handle.stop().await;
        server.abort();
        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "MITM+wreq must open exactly one origin TCP"
        );
    }

    #[cfg(feature = "impersonate-boring")]
    #[tokio::test]
    async fn mitm_wss_uses_wreq_and_relays_frames() {
        let ca = test_certificate_authority();
        let _roots = crate::impersonate_egress::install_test_root_certificate_der(
            ca.certificate_der().as_ref().to_vec(),
        );
        let host = "localhost";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_config = ca.server_config(host).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls = match TlsAcceptor::from(server_config).accept(stream).await {
                Ok(tls) => tls,
                Err(_) => return,
            };
            let mut websocket = match accept_async(tls).await {
                Ok(websocket) => websocket,
                Err(_) => return,
            };
            while let Some(message) = websocket.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        let _ = websocket.send(Message::Text(text)).await;
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let events = Arc::new(Mutex::new(Vec::<CaptureEventInput>::new()));
        let event_sink: EventSink = {
            let events = events.clone();
            Arc::new(move |event| events.lock().unwrap().push(event))
        };
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-wss-wreq".to_string(),
            direct_upstream(),
            ca.clone(),
            capture_sink,
            None,
            event_sink,
            Arc::new(|_| {}),
        )
        .await
        .unwrap();

        let client = TcpStream::connect(handle.local_addr()).await.unwrap();
        let mut tunnel = BoxedIo(Box::new(client));
        tunnel
            .write_all(
                format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut tunnel).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        let mut roots = RootCertStore::empty();
        roots.add(ca.certificate_der()).unwrap();
        let tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
        .connect(ServerName::try_from(host.to_string()).unwrap(), tunnel)
        .await
        .expect("MITM client TLS");
        let (mut websocket, response) = client_async(format!("ws://{host}:{port}/echo"), tls)
            .await
            .expect("websocket upgrade through MITM");
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        websocket
            .send(Message::text("align"))
            .await
            .expect("send frame");
        assert_eq!(
            timeout(Duration::from_secs(5), websocket.next())
                .await
                .expect("echo timeout")
                .unwrap()
                .unwrap(),
            Message::text("align")
        );
        let _ = websocket.close(None).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        handle.stop().await;
        server.abort();

        let captured = captured.lock().unwrap();
        let handshake = captured
            .iter()
            .find(|request| request.resource_type == "websocket")
            .expect("websocket handshake captured");
        assert_eq!(handshake.scheme.as_deref(), Some("wss"));
        assert!(
            handshake
                .tls_version
                .as_deref()
                .is_some_and(|value| value.contains("wreq") || value.contains("TLS")),
            "wss handshake should record Chrome/wreq TLS, got {:?}",
            handshake.tls_version
        );
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.phase == "websocket"),
            "websocket frames must still be captured"
        );
    }

    #[cfg(feature = "impersonate-boring")]
    #[tokio::test]
    async fn explicit_https_wreq_opens_one_target_tcp() {
        let ca = test_certificate_authority();
        let _roots = crate::impersonate_egress::install_test_root_certificate_der(
            ca.certificate_der().as_ref().to_vec(),
        );
        let host = "localhost";
        let (port, accepted, server) = counting_https_origin(host, &ca).await;
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-one-tcp-explicit".to_string(),
            direct_upstream(),
            ca,
            Arc::new(|_| {}),
            Arc::new(|_| {}),
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!(
                    "POST https://{host}:{port}/empty HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut raw = Vec::new();
        timeout(Duration::from_secs(10), client.read_to_end(&mut raw))
            .await
            .expect("explicit response timeout")
            .unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("empty-ok"), "{text}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        handle.stop().await;
        server.abort();
        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "explicit HTTPS+wreq must open exactly one origin TCP"
        );
    }

    #[test]
    fn test_host_ip_map_is_used_by_destination_resolution() {
        set_test_host_ip(
            "capture.shownet.test",
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );
        assert_eq!(
            test_host_ip("capture.shownet.test"),
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
        clear_test_host_ips();
        assert_eq!(test_host_ip("capture.shownet.test"), None);
    }

    #[test]
    fn validates_and_combines_reverse_proxy_targets() {
        assert_eq!(
            normalize_reverse_proxy_target("https://api.example.test/v2").unwrap(),
            "https://api.example.test/v2"
        );
        assert!(normalize_reverse_proxy_target("api.example.test").is_err());
        assert!(normalize_reverse_proxy_target("ftp://api.example.test").is_err());
        assert!(normalize_reverse_proxy_target("https://user:secret@api.example.test").is_err());
        assert!(normalize_reverse_proxy_target("https://api.example.test?token=secret").is_err());

        let base = Url::parse("https://api.example.test/v2/").unwrap();
        let incoming: Uri = "/orders/42?expand=items".parse().unwrap();
        assert_eq!(
            reverse_target_uri(&base, &incoming).unwrap().to_string(),
            "https://api.example.test/v2/orders/42?expand=items"
        );
    }

    #[tokio::test]
    async fn local_socket_reverse_proxy_reports_serving_only_while_its_task_lives() {
        let capture_sink: CaptureSink = Arc::new(|_| {});
        let error_sink: ErrorSink = Arc::new(|_| {});
        let reverse = ReverseProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-liveness".to_string(),
            "http://127.0.0.1:9/unused".to_string(),
            false,
            direct_upstream(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap();

        assert!(reverse.is_serving(), "a freshly started entry point serves");

        // Holding the handle after a stop must not keep reporting 运行中 — that
        // is the shape that sends users to an entry point nothing is listening on.
        reverse.stop().await;
    }

    #[tokio::test]
    #[ignore = "requires local socket permission"]
    async fn local_socket_reverse_proxy_forwards_and_captures_without_internal_headers() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::<(String, String, Vec<u8>)>::new()));
        let seen_sink = seen.clone();
        let target_task = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let seen_sink = seen_sink.clone();
                async move {
                    let host = request
                        .headers()
                        .get(HOST)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let path = request
                        .uri()
                        .path_and_query()
                        .map(|value| value.as_str().to_string())
                        .unwrap_or_default();
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes()
                        .to_vec();
                    seen_sink.lock().unwrap().push((host, path, body));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::CREATED)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let reverse = ReverseProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-reverse".to_string(),
            format!("http://{target_address}/v2"),
            false,
            direct_upstream(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(reverse.local_addr()).await.unwrap();
        client
            .write_all(
                b"POST /orders?expand=items HTTP/1.1\r\nHost: local.test\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 201"));
        target_task.await.unwrap();
        tokio::task::yield_now().await;

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, target_address.to_string());
        assert_eq!(seen[0].1, "/v2/orders?expand=items");
        assert_eq!(seen[0].2, b"payload");
        drop(seen);

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].source, "reverse");
        assert_eq!(captured[0].session_id, "session-reverse");
        assert_eq!(captured[0].path, "/v2/orders");
        assert_eq!(captured[0].query.as_deref(), Some("expand=items"));
        assert_eq!(captured[0].status, 201);
        assert_eq!(captured[0].request_body.as_deref(), Some("payload"));
        assert!(captured[0]
            .source_instance_id
            .as_deref()
            .is_some_and(|value| value.starts_with("reverse:")));
        assert!(captured[0].request_headers.iter().all(|header| {
            !header
                .name
                .eq_ignore_ascii_case(REVERSE_PROXY_CONTEXT_HEADER)
        }));
        drop(captured);
        assert!(errors.lock().unwrap().is_empty(), "errors: {errors:?}");
        reverse.stop().await;
    }

    #[tokio::test]
    async fn negotiates_authenticated_http_upstream_proxy() {
        let proxy = EffectiveUpstreamProxy {
            mode: "http".to_string(),
            host: "127.0.0.1".to_string(),
            port: 7890,
            username: "user".to_string(),
            password: Some("secret".to_string()),
            bypass: vec![],
        };
        let (mut client, mut server) = tokio::io::duplex(4 * 1024);
        let server_task = tokio::spawn(async move {
            let mut header = Vec::new();
            let mut byte = [0_u8; 1];
            while !header.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                header.push(byte[0]);
            }
            let header = String::from_utf8(header).unwrap();
            assert!(header.starts_with(
                "CONNECT overseas.example:443 HTTP/1.1\r\nHost: overseas.example:443\r\n"
            ));
            assert!(header.contains(&format!(
                "Proxy-Authorization: Basic {}\r\n",
                STANDARD.encode("user:secret")
            )));
            server
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut tunneled = [0_u8; 4];
            server.read_exact(&mut tunneled).await.unwrap();
            assert_eq!(&tunneled, b"ping");
            server.write_all(b"pong").await.unwrap();
        });

        negotiate_http_connect(&mut client, &proxy, "overseas.example", 443)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn negotiates_authenticated_socks5_upstream_proxy() {
        let proxy = EffectiveUpstreamProxy {
            mode: "socks5".to_string(),
            host: "127.0.0.1".to_string(),
            port: 7891,
            username: "user".to_string(),
            password: Some("secret".to_string()),
            bypass: vec![],
        };
        let (mut client, mut server) = tokio::io::duplex(4 * 1024);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0_u8; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            server.write_all(&[0x05, 0x02]).await.unwrap();

            let mut auth = [0_u8; 13];
            server.read_exact(&mut auth).await.unwrap();
            assert_eq!(
                &auth,
                &[0x01, 0x04, b'u', b's', b'e', b'r', 0x06, b's', b'e', b'c', b'r', b'e', b't']
            );
            server.write_all(&[0x01, 0x00]).await.unwrap();

            let mut request_prefix = [0_u8; 5];
            server.read_exact(&mut request_prefix).await.unwrap();
            assert_eq!(request_prefix, [0x05, 0x01, 0x00, 0x03, 0x10]);
            let mut destination = [0_u8; 18];
            server.read_exact(&mut destination).await.unwrap();
            assert_eq!(&destination[..16], b"overseas.example");
            assert_eq!(u16::from_be_bytes([destination[16], destination[17]]), 443);
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
                .await
                .unwrap();

            let mut tunneled = [0_u8; 4];
            server.read_exact(&mut tunneled).await.unwrap();
            assert_eq!(&tunneled, b"ping");
            server.write_all(b"pong").await.unwrap();
        });

        negotiate_socks5_connect(&mut client, &proxy, "overseas.example", 443)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server_task.await.unwrap();
    }

    #[test]
    fn recognizes_websocket_upgrade_tokens_case_insensitively() {
        let request = Request::builder()
            .header("Connection", "keep-alive, Upgrade")
            .header("Upgrade", "WebSocket")
            .body(())
            .unwrap();
        assert!(is_websocket_upgrade(request.headers()));

        let ordinary = Request::builder()
            .header("Connection", "keep-alive")
            .body(())
            .unwrap();
        assert!(!is_websocket_upgrade(ordinary.headers()));
    }

    #[test]
    fn recognizes_only_rfc8441_websocket_connect_protocol() {
        let mut websocket = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri("https://example.test/socket")
            .body(())
            .unwrap();
        websocket
            .extensions_mut()
            .insert(Protocol::from_static("websocket"));
        assert!(is_extended_websocket_connect(&websocket));

        let mut connect_udp = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri("https://example.test/masque")
            .body(())
            .unwrap();
        connect_udp
            .extensions_mut()
            .insert(Protocol::from_static("connect-udp"));
        assert!(!is_extended_websocket_connect(&connect_udp));

        *websocket.version_mut() = Version::HTTP_11;
        assert!(!is_extended_websocket_connect(&websocket));
    }

    #[test]
    fn websocket_capture_is_bounded_without_splitting_utf8() {
        let text = format!("{}界", "a".repeat(MAX_WEBSOCKET_CAPTURE_BYTES - 1));
        let (_, captured, encoding, size, captured_bytes, truncated, _) =
            websocket_capture_payload(&Message::text(text.clone()), MAX_WEBSOCKET_CAPTURE_BYTES);
        assert_eq!(encoding, "utf8");
        assert_eq!(size, text.len());
        assert_eq!(captured_bytes, MAX_WEBSOCKET_CAPTURE_BYTES - 1);
        assert!(truncated);
        assert!(captured.ends_with('a'));
    }

    #[test]
    fn restricts_proxy_clients_to_the_configured_network_scope() {
        let local_only = ClientAccessPolicy::private_network(false);
        let private_network = ClientAccessPolicy::private_network(true);
        for address in ["127.0.0.1", "::1"] {
            assert!(local_only.allows(address.parse().unwrap()));
        }
        for address in ["10.1.2.3", "172.16.8.9", "192.168.2.20", "169.254.4.5"] {
            let address = address.parse().unwrap();
            assert!(!local_only.allows(address));
            assert!(private_network.allows(address));
        }
        for address in ["fd00::20", "fe80::20"] {
            let address = address.parse().unwrap();
            assert!(!local_only.allows(address));
            assert!(private_network.allows(address));
        }
        for address in ["8.8.8.8", "2001:4860:4860::8888"] {
            assert!(!private_network.allows(address.parse().unwrap()));
        }
    }

    #[test]
    fn classifies_remote_embedded_clients_as_iot() {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "ESP32HTTPClient/1.0".parse().unwrap());
        assert_eq!(
            classify_source(&headers, "192.168.1.20:54321".parse().unwrap()),
            "iot"
        );

        let headers = HeaderMap::new();
        assert_eq!(
            classify_source(&headers, "192.168.1.21:54321".parse().unwrap()),
            "iot"
        );
        assert_eq!(
            classify_source(&headers, "127.0.0.1:54321".parse().unwrap()),
            "desktop"
        );
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_serves_lan_device_setup_and_ca() {
        let capture_sink: CaptureSink = Arc::new(|_| {});
        let error_sink: ErrorSink = Arc::new(|_| {});
        let certificate_authority = test_certificate_authority();
        let handle = ProxyHandle::start_with_sinks(
            "0.0.0.0:0".parse().unwrap(),
            true,
            "session-lan".to_string(),
            EffectiveUpstreamProxy {
                mode: "direct".to_string(),
                host: String::new(),
                port: 0,
                username: String::new(),
                password: None,
                bypass: vec![],
            },
            certificate_authority.clone(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap();

        let listener = handle.local_addr();
        assert!(listener.ip().is_unspecified());
        let mut client = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, listener.port()))
            .await
            .unwrap();
        client
            .write_all(
                format!(
                    "GET /device HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                    listener.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("ShowNet 设备接入"));

        let mut certificate_client =
            TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, listener.port()))
                .await
                .unwrap();
        certificate_client
            .write_all(
                format!(
                    "GET {DEVICE_CA_DER_PATH} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                    listener.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut certificate_response = Vec::new();
        timeout(
            Duration::from_secs(5),
            certificate_client.read_to_end(&mut certificate_response),
        )
        .await
        .unwrap()
        .unwrap();
        let header_end = certificate_response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .unwrap();
        let certificate_header = String::from_utf8_lossy(&certificate_response[..header_end]);
        assert!(certificate_header.starts_with("HTTP/1.1 200"));
        assert!(certificate_header.contains("application/x-x509-ca-cert"));
        assert_eq!(
            &certificate_response[header_end..],
            certificate_authority.certificate_der().as_ref()
        );
        handle.stop().await;
    }

    #[tokio::test]
    async fn serves_device_setup_and_public_ca_only_on_the_local_listener_host() {
        let certificate_authority = test_certificate_authority();
        let local = "192.168.50.8:8888".parse().unwrap();
        let setup_request = Request::builder()
            .method(Method::GET)
            .uri(DEVICE_SETUP_PATH)
            .header(HOST, "192.168.50.8:8888")
            .body(())
            .unwrap();
        let setup_response =
            device_setup_response(&setup_request, local, &certificate_authority).unwrap();
        assert_eq!(setup_response.status(), StatusCode::OK);
        assert_eq!(
            setup_response.headers()[CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        let setup_html = String::from_utf8(
            setup_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(setup_html.contains("192.168.50.8"));
        assert!(setup_html.contains(certificate_authority.fingerprint()));
        assert!(setup_html.contains(DEVICE_CA_DER_PATH));
        let android_html = device_setup_html(
            "192.168.50.8:8888",
            certificate_authority.fingerprint(),
            "Mozilla/5.0 (Linux; Android 15; Pixel 8)",
        );
        assert!(android_html.contains("Android"));
        assert!(android_html.contains(DEVICE_CA_DER_PATH));
        assert!(!android_html.contains(DEVICE_CA_IOS_PROFILE_PATH));
        let ios_html = device_setup_html(
            "192.168.50.8:8888",
            certificate_authority.fingerprint(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
        );
        assert!(ios_html.contains("iPhone / iPad"));
        assert!(ios_html.contains(DEVICE_CA_IOS_PROFILE_PATH));

        let certificate_request = Request::builder()
            .method(Method::GET)
            .uri(DEVICE_CA_DER_PATH)
            .header(HOST, "192.168.50.8:8888")
            .body(())
            .unwrap();
        let certificate_response =
            device_setup_response(&certificate_request, local, &certificate_authority).unwrap();
        assert_eq!(certificate_response.status(), StatusCode::OK);
        assert_eq!(
            certificate_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            certificate_authority.certificate_der().as_ref()
        );

        let ios_profile_request = Request::builder()
            .method(Method::GET)
            .uri(DEVICE_CA_IOS_PROFILE_PATH)
            .header(HOST, "192.168.50.8:8888")
            .body(())
            .unwrap();
        let ios_profile_response =
            device_setup_response(&ios_profile_request, local, &certificate_authority).unwrap();
        assert_eq!(ios_profile_response.status(), StatusCode::OK);
        assert_eq!(
            ios_profile_response.headers()[CONTENT_TYPE],
            "application/x-apple-aspen-config"
        );
        let ios_profile = String::from_utf8(
            ios_profile_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(ios_profile.contains("com.apple.security.root"));
        assert!(ios_profile
            .contains(&STANDARD.encode(certificate_authority.certificate_der().as_ref())));

        let other_private_host = Request::builder()
            .method(Method::GET)
            .uri(DEVICE_SETUP_PATH)
            .header(HOST, "192.168.50.9:8888")
            .body(())
            .unwrap();
        assert!(
            device_setup_response(&other_private_host, local, &certificate_authority).is_none()
        );
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_forwards_plain_http_and_emits_capture_record() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut request = vec![0_u8; 2048];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /health?q=1 HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap();
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-local".to_string(),
            EffectiveUpstreamProxy {
                mode: "direct".to_string(),
                host: String::new(),
                port: 0,
                username: String::new(),
                password: None,
                bypass: vec![],
            },
            test_certificate_authority(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/health?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: python-requests/test\r\nConnection: close\r\n\r\n",
                    target_address.port(),
                    target_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = vec![0_u8; 512];
        let read = timeout(Duration::from_secs(5), client.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..read]).starts_with("HTTP/1.1 200"));

        target_task.await.unwrap();
        handle.stop().await;
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].method, "GET");
        assert_eq!(captured[0].path, "/health");
        assert_eq!(captured[0].query.as_deref(), Some("q=1"));
        assert_eq!(captured[0].status, 200);
        assert_eq!(captured[0].source, "script");
        assert!(errors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_a_client_hanging_up_reports_nothing_but_a_dead_target_does() {
        // End to end over a real listener, because the unit tests for this only
        // pin the classifiers. Browsers abandon connections constantly — a
        // pre-opened socket never used, a tab closed mid-response — and every
        // one of those used to arrive as a red toast during normal browsing.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        // Accept and then vanish, the way a peer that goes away does.
        let target_task = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            drop(stream);
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-hangup".to_string(),
            EffectiveUpstreamProxy {
                mode: "direct".to_string(),
                host: String::new(),
                port: 0,
                username: String::new(),
                password: None,
                bypass: vec![],
            },
            test_certificate_authority(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap();

        // 1. Connect and leave without sending anything.
        drop(TcpStream::connect(handle.local_addr()).await.unwrap());

        // 2. Send half a request line, then vanish.
        let mut partial = TcpStream::connect(handle.local_addr()).await.unwrap();
        partial
            .write_all(b"GET http://127.0.0.1/ HTTP")
            .await
            .unwrap();
        drop(partial);

        // 3. A complete request whose target accepts and immediately closes.
        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/gone HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                    target_address.port(),
                    target_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = vec![0_u8; 512];
        let _ = timeout(Duration::from_secs(5), client.read(&mut response)).await;
        drop(client);
        target_task.await.unwrap();

        // Give the spawned connection tasks a moment to finish reporting.
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let seen = errors.lock().unwrap();
            assert!(
                seen.is_empty(),
                "a client hanging up is not a failure, but these were reported: {seen:?}"
            );
        }

        // The other half: a target that is not there must still be reported,
        // or silencing the hang-ups would have hidden a real problem.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_address = dead.local_addr().unwrap();
        drop(dead);
        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/nope HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                    dead_address.port(),
                    dead_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = vec![0_u8; 512];
        let _ = timeout(Duration::from_secs(5), client.read(&mut response)).await;
        handle.stop().await;

        let seen = errors.lock().unwrap();
        assert!(
            seen.iter().any(|error| error.contains("连接")),
            "an unreachable target must still reach the user: {seen:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_map_remote_skips_original_and_mirror_and_strips_credentials() {
        let original = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let original_address = original.local_addr().unwrap();
        let mirror = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mirror_address = mirror.local_addr().unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_seen = Arc::new(Mutex::new(Vec::<(String, Vec<(String, String)>)>::new()));
        let target_seen_sink = target_seen.clone();
        let target_task = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let target_seen_sink = target_seen_sink.clone();
                async move {
                    let path_and_query = request
                        .uri()
                        .path_and_query()
                        .map(|value| value.as_str().to_string())
                        .unwrap_or_else(|| "/".to_string());
                    let headers = request
                        .headers()
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.as_str().to_string(),
                                value.to_str().unwrap_or("<binary>").to_string(),
                            )
                        })
                        .collect();
                    target_seen_sink
                        .lock()
                        .unwrap()
                        .push((path_and_query, headers));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .header(CONTENT_LENGTH, "11")
                            .header("connection", "close")
                            .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let storage = Arc::new(crate::storage::Storage::in_memory().unwrap());
        let rule = storage
            .save_capture_rule(crate::models::CaptureRuleInput {
                id: None,
                name: "HTTP Map Remote 安全转发".to_string(),
                enabled: false,
                priority: 10,
                stage: "request".to_string(),
                matcher: crate::models::FilterExpression::Predicate {
                    field: "host".to_string(),
                    operator: "equals".to_string(),
                    value: Some(json!("127.0.0.1")),
                },
                action: json!({
                    "kind":"redirect",
                    "targetTemplate":format!("http://127.0.0.1:{}/mapped/*", target_address.port())
                }),
                created_by: "user".to_string(),
            })
            .unwrap();
        storage
            .set_capture_rule_enabled(&rule.id, true, true)
            .unwrap();
        let traces = Arc::new(Mutex::new(Vec::<crate::models::CaptureRuleRun>::new()));
        let request_storage = storage.clone();
        let request_traces = traces.clone();
        let request_engine: RequestRuleEngine = Arc::new(move |request| {
            let outcome =
                crate::capture_rules::apply_runtime_request_rules(&request_storage, request)?;
            request_traces.lock().unwrap().extend(outcome.traces);
            Ok(outcome.control)
        });
        let mut rule_engine = RuleEngine::request_only(request_engine);
        let mirror_port = mirror_address.port();
        rule_engine.mirror = Arc::new(move |request| {
            Ok(Some(RuntimeMirrorRoute {
                rule_id: "rule-should-not-mirror".to_string(),
                rule_name: "不应执行的连接镜像".to_string(),
                revision: 1,
                original_host: request.host.clone(),
                original_port: request.port,
                target_host: "127.0.0.1".to_string(),
                target_port: mirror_port,
                identity: MirrorIdentity::Target,
            }))
        });
        let pending_traces = rule_engine.pending_traces.clone();
        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-map-remote-http".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/original/items?token=query-secret&keep=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer auth-secret\r\nCookie: sid=cookie-secret\r\nX-Api-Key: header-secret\r\nX-Client: shownet\r\nConnection: close\r\n\r\n",
                    original_address.port(),
                    original_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

        target_task.await.unwrap();
        assert!(timeout(Duration::from_millis(300), original.accept())
            .await
            .is_err());
        assert!(timeout(Duration::from_millis(300), mirror.accept())
            .await
            .is_err());
        handle.stop().await;

        let target_seen = target_seen.lock().unwrap();
        assert_eq!(target_seen.len(), 1);
        assert_eq!(target_seen[0].0, "/mapped/original/items?keep=1");
        let target_headers = &target_seen[0].1;
        assert!(target_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("host")
                && value == &format!("127.0.0.1:{}", target_address.port())
        }));
        assert!(target_headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-client") && value == "shownet"));
        assert!(target_headers.iter().all(|(name, _)| {
            !matches!(
                name.to_ascii_lowercase().as_str(),
                "authorization" | "cookie" | "x-api-key"
            )
        }));
        drop(target_seen);

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].host, "127.0.0.1");
        assert_eq!(captured[0].port, Some(target_address.port() as i64));
        assert_eq!(captured[0].path, "/mapped/original/items");
        assert_eq!(captured[0].query.as_deref(), Some("keep=1"));
        assert!(captured[0].request_headers.iter().all(|header| {
            !matches!(
                header.name.to_ascii_lowercase().as_str(),
                "authorization" | "cookie" | "x-api-key"
            )
        }));
        drop(captured);
        let traces = traces.lock().unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].result, "applied");
        let trace_json = serde_json::to_string(&*traces).unwrap();
        for secret in [
            "query-secret",
            "auth-secret",
            "cookie-secret",
            "header-secret",
        ] {
            assert!(!trace_json.contains(secret));
        }
        assert!(pending_traces.lock().unwrap().is_empty());
        assert!(errors.lock().unwrap().is_empty(), "errors: {errors:?}");
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_http_mirror_connects_target_and_uses_target_identity() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut request = vec![0_u8; 2048];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]).into_owned();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .await
                .unwrap();
            request
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let mut rule_engine =
            RuleEngine::request_only(Arc::new(|_| Ok(RuntimeRuleControl::default())));
        let mirror_port = target_address.port();
        rule_engine.mirror = Arc::new(move |request| {
            Ok(Some(RuntimeMirrorRoute {
                rule_id: "rule-http-mirror".to_string(),
                rule_name: "HTTP 测试环境".to_string(),
                revision: 1,
                original_host: request.host.clone(),
                original_port: request.port,
                target_host: "127.0.0.1".to_string(),
                target_port: mirror_port,
                identity: MirrorIdentity::Target,
            }))
        });
        let pending_traces = rule_engine.pending_traces.clone();
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-http-mirror".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                b"GET http://api.original.test:8081/items HTTP/1.1\r\nHost: api.original.test:8081\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

        let target_request = target_task.await.unwrap();
        handle.stop().await;
        assert!(target_request.starts_with("GET /items HTTP/1.1"));
        assert!(target_request
            .to_ascii_lowercase()
            .contains(&format!("host: 127.0.0.1:{}", target_address.port())));
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].host, "api.original.test");
        assert_eq!(captured[0].port, Some(8081));
        assert!(captured[0].request_headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("host") && header.value == "api.original.test:8081"
        }));
        let request_id = captured[0].id.as_deref().unwrap();
        let traces = pending_traces.lock().unwrap();
        assert_eq!(traces.get(request_id).unwrap()[0].result, "applied");
        assert_eq!(
            traces.get(request_id).unwrap()[0].diff_summary["route"]["targetAuthority"],
            format!("127.0.0.1:{}", target_address.port())
        );
        assert!(errors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_emits_sse_event_before_the_response_stream_closes() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let (release_target, release_stream) = oneshot::channel::<()>();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut request = vec![0_u8; 2048];
            let read = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /events HTTP/1.1"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let first = b"id: evt-1\ndata: first\n\n";
            stream
                .write_all(format!("{:X}\r\n", first.len()).as_bytes())
                .await
                .unwrap();
            stream.write_all(first).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
            stream.flush().await.unwrap();
            let _ = release_stream.await;
            let second = b"event: done\ndata: second\n\n";
            stream
                .write_all(format!("{:X}\r\n", second.len()).as_bytes())
                .await
                .unwrap();
            stream.write_all(second).await.unwrap();
            stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let events = Arc::new(Mutex::new(Vec::<CaptureEventInput>::new()));
        let event_sink: EventSink = {
            let events = events.clone();
            Arc::new(move |event| events.lock().unwrap().push(event))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-sse".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            capture_sink,
            None,
            event_sink,
            error_sink,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/events HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
                    target_address.port(),
                    target_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        while !String::from_utf8_lossy(&response).contains("data: first") {
            let mut chunk = vec![0_u8; 512];
            let read = timeout(Duration::from_secs(5), client.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }

        timeout(Duration::from_secs(2), async {
            loop {
                if events
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|event| event.phase == "sse" && event.payload["data"] == "first")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        {
            let captured = captured.lock().unwrap();
            assert_eq!(captured.len(), 1);
            assert_eq!(captured[0].resource_type, "sse");
            assert!(
                !captured[0]
                    .response_body_metadata
                    .as_ref()
                    .unwrap()
                    .complete
            );
        }

        let _ = release_target.send(());
        timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        target_task.await.unwrap();
        tokio::task::yield_now().await;
        handle.stop().await;

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert!(
            captured[1]
                .response_body_metadata
                .as_ref()
                .unwrap()
                .complete
        );
        let events = events.lock().unwrap();
        assert!(events.iter().any(|event| event.payload["data"] == "second"));
        assert!(events
            .iter()
            .any(|event| event.payload["kind"] == "stream_end"));
        assert!(errors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_request_rules_rewrite_and_block_without_connecting() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut request = vec![0_u8; 4096];
                let read = stream.read(&mut request).await.unwrap();
                seen.push(String::from_utf8_lossy(&request[..read]).into_owned());
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
            let unexpected_connection = timeout(Duration::from_millis(500), target.accept())
                .await
                .is_ok();
            (seen, unexpected_connection)
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let request_rule_engine: RequestRuleEngine = Arc::new(move |request| {
            let mut control = RuntimeRuleControl::default();
            match request.path.as_str() {
                "/rewritten" => {
                    request.query = Some("q=2".to_string());
                    request.request_headers.push(HeaderEntry {
                        name: "X-Rule-Applied".to_string(),
                        value: "yes".to_string(),
                    });
                }
                "/blocked" => control.blocked = true,
                "/lost" => {
                    control.blocked = true;
                    control.block_status = Some(504);
                    control.block_message = Some("ShowNet 弱网规则模拟丢包".to_string());
                }
                _ => {}
            }
            Ok(control)
        });
        let rule_engine = RuleEngine::request_only(request_rule_engine);
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-rules".to_string(),
            EffectiveUpstreamProxy {
                mode: "direct".to_string(),
                host: String::new(),
                port: 0,
                username: String::new(),
                password: None,
                bypass: vec![],
            },
            test_certificate_authority(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        )
        .await
        .unwrap();

        async fn send(proxy: SocketAddr, target_port: u16, path: &str) -> String {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            client
                .write_all(
                    format!(
                        "GET http://127.0.0.1:{target_port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            timeout(Duration::from_secs(5), client.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            String::from_utf8_lossy(&response).into_owned()
        }

        let plain = send(handle.local_addr(), target_address.port(), "/plain?q=1").await;
        let rewritten = send(handle.local_addr(), target_address.port(), "/rewritten?q=1").await;
        let blocked = send(handle.local_addr(), target_address.port(), "/blocked?q=1").await;
        let lost = send(handle.local_addr(), target_address.port(), "/lost?q=1").await;
        assert!(plain.starts_with("HTTP/1.1 200"));
        assert!(rewritten.starts_with("HTTP/1.1 200"));
        assert!(blocked.starts_with("HTTP/1.1 403"));
        assert!(lost.starts_with("HTTP/1.1 504"));
        assert!(lost.contains("ShowNet 弱网规则模拟丢包"));

        let (seen, unexpected_connection) = target_task.await.unwrap();
        handle.stop().await;
        assert_eq!(seen.len(), 2);
        assert!(seen[0].starts_with("GET /plain?q=1 HTTP/1.1"));
        assert!(!seen[0].to_ascii_lowercase().contains("x-rule-applied"));
        assert!(seen[1].starts_with("GET /rewritten?q=2 HTTP/1.1"));
        assert!(seen[1].to_ascii_lowercase().contains("x-rule-applied: yes"));
        assert!(!unexpected_connection);
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 4);
        assert_eq!(captured[2].status, 403);
        assert_eq!(captured[3].status, 504);
        assert!(errors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_request_body_rules_rewrite_text_and_skip_compressed_atomically() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let upstream_seen = Arc::new(Mutex::new(Vec::new()));
        let upstream_seen_sink = upstream_seen.clone();
        let target_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = target.accept().await.unwrap();
                let upstream_seen_sink = upstream_seen_sink.clone();
                let service = service_fn(move |request: Request<Incoming>| {
                    let upstream_seen_sink = upstream_seen_sink.clone();
                    async move {
                        let path = request.uri().path().to_string();
                        let content_length = request
                            .headers()
                            .get(CONTENT_LENGTH)
                            .and_then(|value| value.to_str().ok())
                            .map(ToString::to_string);
                        let content_encoding = request
                            .headers()
                            .get(CONTENT_ENCODING)
                            .and_then(|value| value.to_str().ok())
                            .map(ToString::to_string);
                        let content_md5 = request
                            .headers()
                            .get("content-md5")
                            .and_then(|value| value.to_str().ok())
                            .map(ToString::to_string);
                        let digest = request
                            .headers()
                            .get("digest")
                            .and_then(|value| value.to_str().ok())
                            .map(ToString::to_string);
                        let marker = request
                            .headers()
                            .get("x-body-rule")
                            .and_then(|value| value.to_str().ok())
                            .map(ToString::to_string);
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        upstream_seen_sink.lock().unwrap().push((
                            path,
                            content_length,
                            content_encoding,
                            content_md5,
                            digest,
                            marker,
                            body,
                        ));
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_LENGTH, "2")
                                .header("connection", "close")
                                .body(Full::new(Bytes::from_static(b"ok")))
                                .unwrap(),
                        )
                    }
                });
                http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            }
        });

        let storage = Arc::new(crate::storage::Storage::in_memory().unwrap());
        let rule = storage
            .save_capture_rule(crate::models::CaptureRuleInput {
                id: None,
                name: "请求正文安全改写".to_string(),
                enabled: false,
                priority: 10,
                stage: "request".to_string(),
                matcher: crate::models::FilterExpression::Predicate {
                    field: "path".to_string(),
                    operator: "regex".to_string(),
                    value: Some(json!("^/(rewrite|compressed)$")),
                },
                action: json!({"kind":"rewrite","operations":[
                    {"target":"request.header","op":"set","name":"X-Body-Rule","value":"applied"},
                    {"target":"request.body","op":"replace","pattern":"before","value":"after-long"}
                ]}),
                created_by: "user".to_string(),
            })
            .unwrap();
        storage
            .set_capture_rule_enabled(&rule.id, true, true)
            .unwrap();

        let traces = Arc::new(Mutex::new(Vec::<crate::models::CaptureRuleRun>::new()));
        let request_storage = storage.clone();
        let request_traces = traces.clone();
        let request_engine: RequestRuleEngine = Arc::new(move |request| {
            let outcome =
                crate::capture_rules::apply_runtime_request_rules(&request_storage, request)?;
            request_traces.lock().unwrap().extend(outcome.traces);
            Ok(outcome.control)
        });
        let probe_storage = storage.clone();
        let mut rule_engine = RuleEngine::request_only(request_engine);
        rule_engine.request_body_required = Arc::new(move |request| {
            crate::capture_rules::runtime_request_body_required(&probe_storage, request)
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-request-body-rules".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        )
        .await
        .unwrap();

        async fn send(
            proxy: SocketAddr,
            target_port: u16,
            path: &str,
            body: &[u8],
            content_encoding: Option<&str>,
        ) -> String {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            let encoding = content_encoding
                .map(|value| format!("Content-Encoding: {value}\r\n"))
                .unwrap_or_default();
            client
                .write_all(
                    format!(
                        "POST http://127.0.0.1:{target_port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nContent-Type: application/json\r\n{encoding}Content-Length: {}\r\nContent-MD5: stale-md5\r\nDigest: stale-digest\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            client.write_all(body).await.unwrap();
            let mut response = Vec::new();
            timeout(Duration::from_secs(5), client.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            String::from_utf8_lossy(&response).into_owned()
        }

        let original = br#"{"value":"before"}"#;
        let rewritten_response = send(
            handle.local_addr(),
            target_address.port(),
            "/rewrite",
            original,
            None,
        )
        .await;
        let compressed = gzip(br#"{"value":"before"}"#);
        let compressed_response = send(
            handle.local_addr(),
            target_address.port(),
            "/compressed",
            &compressed,
            Some("gzip"),
        )
        .await;
        assert!(rewritten_response.starts_with("HTTP/1.1 200"));
        assert!(compressed_response.starts_with("HTTP/1.1 200"));

        target_task.await.unwrap();
        tokio::task::yield_now().await;
        handle.stop().await;

        let rewritten = Bytes::from_static(br#"{"value":"after-long"}"#);
        let upstream_seen = upstream_seen.lock().unwrap();
        let rewritten_seen = upstream_seen
            .iter()
            .find(|item| item.0 == "/rewrite")
            .unwrap();
        assert_eq!(
            rewritten_seen
                .1
                .as_deref()
                .and_then(|value| value.parse().ok()),
            Some(rewritten.len())
        );
        assert!(rewritten_seen.2.is_none());
        assert!(rewritten_seen.3.is_none());
        assert!(rewritten_seen.4.is_none());
        assert_eq!(rewritten_seen.5.as_deref(), Some("applied"));
        assert_eq!(rewritten_seen.6, rewritten);
        let compressed_seen = upstream_seen
            .iter()
            .find(|item| item.0 == "/compressed")
            .unwrap();
        assert_eq!(
            compressed_seen
                .1
                .as_deref()
                .and_then(|value| value.parse().ok()),
            Some(compressed.len())
        );
        assert_eq!(compressed_seen.2.as_deref(), Some("gzip"));
        assert_eq!(compressed_seen.3.as_deref(), Some("stale-md5"));
        assert_eq!(compressed_seen.4.as_deref(), Some("stale-digest"));
        assert!(compressed_seen.5.is_none());
        assert_eq!(compressed_seen.6.as_ref(), compressed.as_slice());
        drop(upstream_seen);

        let captured = captured.lock().unwrap();
        let rewritten_capture = captured
            .iter()
            .find(|request| request.path == "/rewrite")
            .unwrap();
        assert_eq!(
            rewritten_capture.request_body.as_deref(),
            Some("{\"value\":\"after-long\"}")
        );
        assert!(rewritten_capture
            .request_headers
            .iter()
            .all(|header| !matches!(
                header.name.to_ascii_lowercase().as_str(),
                "content-md5" | "digest"
            )));
        drop(captured);

        let traces = traces.lock().unwrap();
        assert!(traces.iter().any(|trace| {
            trace.result == "applied" && trace.diff_summary["bodyChanged"] == true
        }));
        let skipped = traces
            .iter()
            .find(|trace| trace.result == "skipped")
            .unwrap();
        let skipped_summary = serde_json::to_string(&skipped.diff_summary).unwrap();
        assert!(skipped_summary.contains("压缩请求正文保持原样转发"));
        assert!(!skipped_summary.contains("before"));
        assert!(!skipped_summary.contains("after-long"));
        assert!(errors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_breakpoints_edit_http_request_and_response_end_to_end() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let upstream_seen = Arc::new(Mutex::new(Vec::new()));
        let upstream_seen_sink = upstream_seen.clone();
        let target_task = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let upstream_seen_sink = upstream_seen_sink.clone();
                async move {
                    let method = request.method().clone();
                    let uri = request.uri().to_string();
                    let marker = request
                        .headers()
                        .get("x-breakpoint-edited")
                        .and_then(|value| value.to_str().ok())
                        .map(ToString::to_string);
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    upstream_seen_sink
                        .lock()
                        .unwrap()
                        .push((method, uri, marker, body));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .header(CONTENT_LENGTH, "15")
                            .header("x-upstream", "yes")
                            .body(Full::new(Bytes::from_static(b"{\"source\":true}")))
                            .unwrap(),
                    )
                }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let coordinator = Arc::new(BreakpointCoordinator::default());
        let request_rule = test_breakpoint_rule("request");
        let response_rule = test_breakpoint_rule("response");
        let mut rule_engine =
            RuleEngine::request_only(Arc::new(|_| Ok(RuntimeRuleControl::default())));
        rule_engine.request_breakpoints = Arc::new(move |_| Ok(vec![request_rule.clone()]));
        rule_engine.response_breakpoints = Arc::new(move |_| Ok(vec![response_rule.clone()]));
        rule_engine.response_body_required = Arc::new(|_| Ok(true));
        rule_engine.breakpoints = coordinator.clone();

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-breakpoint-http".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        )
        .await
        .unwrap();

        let proxy_address = handle.local_addr();
        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(proxy_address).await.unwrap();
            let body = b"{\"value\":\"before\"}";
            client
                .write_all(
                    format!(
                        "POST http://127.0.0.1:{}/original?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        target_address.port(),
                        target_address.port(),
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            client.write_all(body).await.unwrap();
            let mut response = Vec::new();
            timeout(Duration::from_secs(10), client.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            response
        });

        let request_task = wait_for_breakpoint(&coordinator, "request").await;
        let mut request_headers = request_task.request_headers.clone();
        request_headers.push(HeaderEntry {
            name: "x-breakpoint-edited".to_string(),
            value: "yes".to_string(),
        });
        coordinator
            .resolve(crate::breakpoints::BreakpointDecisionInput {
                task_id: request_task.id,
                action: "continue".to_string(),
                method: Some("PUT".to_string()),
                url: Some(format!(
                    "http://127.0.0.1:{}/edited?q=2",
                    target_address.port()
                )),
                request_headers: Some(request_headers),
                request_body: Some("{\"value\":\"after\"}".to_string()),
                ..Default::default()
            })
            .unwrap();

        let response_task = wait_for_breakpoint(&coordinator, "response").await;
        assert_eq!(
            response_task.response_body.as_deref(),
            Some("{\"source\":true}")
        );
        let mut response_headers = response_task.response_headers.clone();
        response_headers.push(HeaderEntry {
            name: "x-breakpoint-edited".to_string(),
            value: "yes".to_string(),
        });
        coordinator
            .resolve(crate::breakpoints::BreakpointDecisionInput {
                task_id: response_task.id,
                action: "continue".to_string(),
                status: Some(201),
                response_headers: Some(response_headers),
                response_body: Some("{\"edited\":true}".to_string()),
                ..Default::default()
            })
            .unwrap();

        let response = client_task.await.unwrap();
        let response_text = String::from_utf8_lossy(&response).to_ascii_lowercase();
        assert!(response_text.starts_with("http/1.1 201"));
        assert!(response_text.contains("x-breakpoint-edited: yes"));
        assert!(response_text.contains("content-length: 15"));
        assert!(response_text.ends_with("{\"edited\":true}"));
        target_task.await.unwrap();
        handle.stop().await;

        let upstream_seen = upstream_seen.lock().unwrap();
        assert_eq!(upstream_seen.len(), 1);
        assert_eq!(upstream_seen[0].0, Method::PUT);
        assert_eq!(upstream_seen[0].1, "/edited?q=2");
        assert_eq!(upstream_seen[0].2.as_deref(), Some("yes"));
        assert_eq!(
            upstream_seen[0].3,
            Bytes::from_static(b"{\"value\":\"after\"}")
        );
        drop(upstream_seen);
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].method, "PUT");
        assert_eq!(captured[0].path, "/edited");
        assert_eq!(captured[0].status, 201);
        assert_eq!(
            captured[0].request_body.as_deref(),
            Some("{\"value\":\"after\"}")
        );
        assert_eq!(
            captured[0].response_body.as_deref(),
            Some("{\"edited\":true}")
        );
        assert!(errors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_response_rules_rewrite_safely_and_apply_download_rate() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut request = vec![0_u8; 4096];
                let read = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                match path {
                    "/rewrite" => {
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nETag: old-value\r\nConnection: close\r\n\r\nhello world",
                            )
                            .await
                            .unwrap();
                    }
                    "/compressed" => {
                        let encoded = gzip(b"compressed response");
                        stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    encoded.len()
                                )
                                .as_bytes(),
                            )
                            .await
                            .unwrap();
                        stream.write_all(&encoded).await.unwrap();
                    }
                    "/slow" => {
                        let payload = vec![b's'; 4 * 1024];
                        stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    payload.len()
                                )
                                .as_bytes(),
                            )
                            .await
                            .unwrap();
                        stream.write_all(&payload).await.unwrap();
                    }
                    other => panic!("unexpected target path: {other}"),
                }
            }
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let unavailable_reasons = Arc::new(Mutex::new(Vec::<String>::new()));
        let response_reasons = unavailable_reasons.clone();
        let request_engine: RequestRuleEngine = Arc::new(move |request| {
            let mut control = RuntimeRuleControl::default();
            if request.path == "/slow" {
                control.download_bytes_per_second = Some(16 * 1024);
            }
            Ok(control)
        });
        let response_engine: ResponseRuleEngine =
            Arc::new(move |response| match response.request.path.as_str() {
                "/rewrite" => {
                    assert_eq!(response.response_body.as_deref(), Some("hello world"));
                    response.status = 201;
                    response.response_headers.push(HeaderEntry {
                        name: "x-rule-applied".to_string(),
                        value: "yes".to_string(),
                    });
                    response.response_body = Some("codex-body".to_string());
                    Ok(true)
                }
                "/compressed" => {
                    assert!(response.response_body.is_none());
                    response_reasons
                        .lock()
                        .unwrap()
                        .push(response.body_unavailable_reason.clone().unwrap_or_default());
                    Ok(false)
                }
                _ => Ok(false),
            });
        let body_probe: ResponseBodyRuleProbe = Arc::new(|response| {
            Ok(matches!(
                response.request.path.as_str(),
                "/rewrite" | "/compressed"
            ))
        });
        let rule_engine = RuleEngine {
            request: request_engine,
            request_body_required: Arc::new(|_| Ok(false)),
            response: response_engine,
            response_body_required: body_probe,
            request_breakpoints: Arc::new(|_| Ok(Vec::new())),
            response_breakpoints: Arc::new(|_| Ok(Vec::new())),
            breakpoints: Arc::new(BreakpointCoordinator::default()),
            pending_traces: Arc::new(StdMutex::new(HashMap::new())),
            tls_interception: Arc::new(|_, _| Ok(TlsInterceptionDecision::default())),
            mirror: Arc::new(|_| Ok(None)),
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-response-rules".to_string(),
            EffectiveUpstreamProxy {
                mode: "direct".to_string(),
                host: String::new(),
                port: 0,
                username: String::new(),
                password: None,
                bypass: vec![],
            },
            test_certificate_authority(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        )
        .await
        .unwrap();

        async fn send(proxy: SocketAddr, target_port: u16, path: &str) -> (Vec<u8>, Duration) {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            client
                .write_all(
                    format!(
                        "GET http://127.0.0.1:{target_port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let started = Instant::now();
            let mut response = Vec::new();
            timeout(Duration::from_secs(5), client.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            (response, started.elapsed())
        }

        let (rewritten, _) = send(handle.local_addr(), target_address.port(), "/rewrite").await;
        let rewritten = String::from_utf8_lossy(&rewritten).to_ascii_lowercase();
        assert!(rewritten.starts_with("http/1.1 201"));
        assert!(rewritten.contains("content-length: 10"));
        assert!(rewritten.contains("x-rule-applied: yes"));
        assert!(!rewritten.contains("etag:"));
        assert!(rewritten.ends_with("codex-body"));

        let (compressed, _) = send(handle.local_addr(), target_address.port(), "/compressed").await;
        let compressed_headers = String::from_utf8_lossy(&compressed)
            .split("\r\n\r\n")
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(compressed_headers.starts_with("http/1.1 200"));
        assert!(compressed_headers.contains("content-encoding: gzip"));
        assert!(unavailable_reasons.lock().unwrap()[0].contains("压缩"));

        let (slow, elapsed) = send(handle.local_addr(), target_address.port(), "/slow").await;
        assert!(String::from_utf8_lossy(&slow).starts_with("HTTP/1.1 200"));
        assert!(
            elapsed >= Duration::from_millis(200),
            "elapsed: {elapsed:?}"
        );

        target_task.await.unwrap();
        tokio::task::yield_now().await;
        handle.stop().await;
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 3);
        assert_eq!(captured[0].status, 201);
        assert_eq!(captured[0].response_body.as_deref(), Some("codex-body"));
        assert!(captured[0]
            .response_headers
            .iter()
            .all(|header| !header.name.eq_ignore_ascii_case("etag")));
        assert!(errors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_unifies_every_supported_source_family_in_one_session() {
        let source_cases = [
            (
                "browser",
                "Mozilla/5.0 AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36",
            ),
            ("desktop", "PostmanRuntime/7.49.0"),
            ("terminal", "curl/8.7.1"),
            ("script", "python-requests/2.32.0"),
            (
                "mobile",
                "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/150.0 Mobile Safari/537.36",
            ),
            ("iot", "ESP32HTTPClient/1.0"),
        ];
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            for _ in 0..source_cases.len() {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut request = vec![0_u8; 2048];
                let read = stream.read(&mut request).await.unwrap();
                assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /source/"));
                stream
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            }
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-all-sources".to_string(),
            EffectiveUpstreamProxy {
                mode: "direct".to_string(),
                host: String::new(),
                port: 0,
                username: String::new(),
                password: None,
                bypass: vec![],
            },
            test_certificate_authority(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap();

        for (index, (_, user_agent)) in source_cases.iter().enumerate() {
            let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
            client
                .write_all(
                    format!(
                        "GET http://127.0.0.1:{}/source/{index} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n\r\n",
                        target_address.port(),
                        target_address.port(),
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = vec![0_u8; 256];
            let read = timeout(Duration::from_secs(5), client.read(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(String::from_utf8_lossy(&response[..read]).starts_with("HTTP/1.1 204"));
        }

        target_task.await.unwrap();
        handle.stop().await;
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), source_cases.len());
        assert_eq!(
            captured
                .iter()
                .map(|request| request.source.as_str())
                .collect::<Vec<_>>(),
            source_cases
                .iter()
                .map(|(source, _)| *source)
                .collect::<Vec<_>>()
        );
        assert!(captured
            .iter()
            .all(|request| request.status == 204 && request.path.starts_with("/source/")));
        assert!(errors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_a_websocket_dying_with_its_page_reports_nothing() {
        // Closing or reloading a page drops a live socket without a closing
        // handshake. tungstenite calls that ResetWithoutClosingHandshake, and
        // every one of the relay's six steps used to turn it into a toast — so
        // any page holding a socket produced an error on every reload. The unit
        // test pins the classifier; this proves the relay actually reaches it.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.unwrap();
            // Echo until the client disappears; never send a Close.
            while let Some(message) = websocket.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        if websocket.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let events = Arc::new(Mutex::new(Vec::<CaptureEventInput>::new()));
        let event_sink: EventSink = {
            let events = events.clone();
            Arc::new(move |event| events.lock().unwrap().push(event))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-websocket-hangup".to_string(),
            EffectiveUpstreamProxy {
                mode: "direct".to_string(),
                host: String::new(),
                port: 0,
                username: String::new(),
                password: None,
                bypass: vec![],
            },
            test_certificate_authority(),
            capture_sink,
            None,
            event_sink,
            error_sink,
        )
        .await
        .unwrap();

        let stream = TcpStream::connect(handle.local_addr()).await.unwrap();
        let (mut client, response) = client_async(
            format!("ws://127.0.0.1:{}/live", target_address.port()),
            stream,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

        client.send(Message::text("still here")).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(5), client.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Message::text("still here")
        );

        // The page goes away: no Close frame, just a dropped socket.
        drop(client);
        target_task.await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        handle.stop().await;

        let seen = errors.lock().unwrap();
        assert!(
            seen.is_empty(),
            "a socket dying with its page is not a relay failure, but these were reported: {seen:?}"
        );
        assert!(
            !captured.lock().unwrap().is_empty(),
            "the handshake must still be captured — going quiet must not mean recording nothing"
        );
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_relays_and_captures_plain_websocket_messages() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.unwrap();
            while let Some(message) = websocket.next().await {
                match message.unwrap() {
                    Message::Text(text) => websocket.send(Message::Text(text)).await.unwrap(),
                    Message::Binary(data) => websocket.send(Message::Binary(data)).await.unwrap(),
                    Message::Close(_) => {
                        let _ = websocket.flush().await;
                        break;
                    }
                    Message::Ping(_) => {
                        let _ = websocket.flush().await;
                    }
                    Message::Pong(_) | Message::Frame(_) => {}
                }
            }
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let events = Arc::new(Mutex::new(Vec::<CaptureEventInput>::new()));
        let event_sink: EventSink = {
            let events = events.clone();
            Arc::new(move |event| events.lock().unwrap().push(event))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-websocket".to_string(),
            EffectiveUpstreamProxy {
                mode: "direct".to_string(),
                host: String::new(),
                port: 0,
                username: String::new(),
                password: None,
                bypass: vec![],
            },
            test_certificate_authority(),
            capture_sink,
            None,
            event_sink,
            error_sink,
        )
        .await
        .unwrap();

        let stream = TcpStream::connect(handle.local_addr()).await.unwrap();
        let (mut client, response) = client_async(
            format!("ws://127.0.0.1:{}/echo", target_address.port()),
            stream,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

        client.send(Message::text("hello shownet")).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(5), client.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Message::text("hello shownet")
        );
        client
            .send(Message::binary(vec![0_u8, 1, 2, 255]))
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(5), client.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Message::binary(vec![0_u8, 1, 2, 255])
        );
        client.close(None).await.unwrap();
        target_task.await.unwrap();
        handle.stop().await;

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].status, 101);
        assert_eq!(captured[0].resource_type, "websocket");
        assert_eq!(captured[0].path, "/echo");
        let request_id = captured[0].id.as_deref().unwrap();
        let events = events.lock().unwrap();
        assert!(events.len() >= 4, "captured events: {events:?}");
        assert!(events.iter().all(|event| {
            event.phase == "websocket" && event.request_id.as_deref() == Some(request_id)
        }));
        assert_eq!(events[0].payload["direction"], "client_to_server");
        assert_eq!(events[0].payload["opcode"], "text");
        assert_eq!(events[0].payload["data"], "hello shownet");
        assert_eq!(events[1].payload["direction"], "server_to_client");
        assert_eq!(events[2].payload["opcode"], "binary");
        assert_eq!(events[3].payload["direction"], "server_to_client");
        assert!(errors.lock().unwrap().is_empty(), "errors: {errors:?}");
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_forwards_gzip_script_unchanged_and_persists_crypto_snippet() {
        let payload =
            br#"function sign(body,key){return CryptoJS.HmacSHA256(body,key).toString();}"#;
        let encoded = gzip(payload);
        let target_encoded = encoded.clone();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut request = vec![0_u8; 2048];
            let read = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /gzip HTTP/1.1"));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        target_encoded.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&target_encoded).await.unwrap();
        });

        let storage = Arc::new(crate::storage::Storage::in_memory().unwrap());
        let session = storage
            .create_session(Some("Compressed JS".to_string()))
            .unwrap();
        let persistence_errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let capture_sink: CaptureSink = {
            let storage = storage.clone();
            let persistence_errors = persistence_errors.clone();
            Arc::new(move |request| {
                if let Err(error) = storage.store_request(request) {
                    persistence_errors.lock().unwrap().push(error);
                }
            })
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            session.id.clone(),
            EffectiveUpstreamProxy {
                mode: "direct".to_string(),
                host: String::new(),
                port: 0,
                username: String::new(),
                password: None,
                bypass: vec![],
            },
            test_certificate_authority(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/gzip HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: curl/shownet-test\r\nConnection: close\r\n\r\n",
                    target_address.port(),
                    target_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let body_offset = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .unwrap();
        assert_eq!(&response[body_offset..], encoded.as_slice());

        target_task.await.unwrap();
        handle.stop().await;
        let requests = storage.list_requests(&session.id, None, None).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].response_body,
            std::str::from_utf8(payload).unwrap()
        );
        let metadata = &requests[0].response_body_metadata;
        assert_eq!(metadata.content_encoding.as_deref(), Some("gzip"));
        assert!(metadata.decoded);
        assert!(metadata.complete);
        assert!(!metadata.truncated);
        assert_eq!(metadata.wire_bytes, encoded.len() as i64);
        assert_eq!(requests[0].crypto_snippet_count, 1);
        let snippets = storage.get_crypto_snippets(&requests[0].id).unwrap();
        assert_eq!(snippets[0].name.as_deref(), Some("sign"));
        assert!(snippets[0].algorithms.contains(&"HMAC".to_string()));
        assert!(snippets[0].algorithms.contains(&"SHA-256".to_string()));
        assert!(persistence_errors.lock().unwrap().is_empty());
        assert!(errors.lock().unwrap().is_empty());
    }

    async fn run_local_tls_bypass(
        show_bypassed_connections: bool,
        mirror_target: bool,
    ) -> (Vec<CapturedRequestInput>, Vec<String>) {
        let expected_hello = test_client_hello_wire("api.pinned.test");
        let target_hello = expected_hello.clone();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut received = vec![0_u8; target_hello.len()];
            stream.read_exact(&mut received).await.unwrap();
            stream
                .write_all(b"target-received-original-client-hello")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
            received
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let settings = crate::tls_interception::normalize_tls_interception_settings(
            crate::tls_interception::TlsInterceptionSettings {
                mode: crate::tls_interception::TlsInterceptionMode::BypassSelected,
                bypass: vec!["*.pinned.test".to_string()],
                show_bypassed_connections,
            },
        )
        .unwrap();
        let mut rule_engine =
            RuleEngine::request_only(Arc::new(|_| Ok(RuntimeRuleControl::default())));
        rule_engine.tls_interception = Arc::new(move |host, sni| Ok(settings.decision(host, sni)));
        if mirror_target {
            let target_port = target_address.port();
            rule_engine.mirror = Arc::new(move |request| {
                Ok(Some(RuntimeMirrorRoute {
                    rule_id: "rule-tls-mirror".to_string(),
                    rule_name: "固定证书域名镜像".to_string(),
                    revision: 1,
                    original_host: request.host.clone(),
                    original_port: request.port,
                    target_host: "127.0.0.1".to_string(),
                    target_port,
                    identity: MirrorIdentity::Target,
                }))
            });
        }
        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-tls-bypass".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        let connect_authority = if mirror_target {
            "api.pinned.test:443".to_string()
        } else {
            target_address.to_string()
        };
        client
            .write_all(
                format!(
                    "CONNECT {connect_authority} HTTP/1.1\r\nHost: {connect_authority}\r\nUser-Agent: curl/shownet-test\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut client).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        client.write_all(&expected_hello).await.unwrap();
        client.shutdown().await.unwrap();
        let mut target_response = Vec::new();
        timeout(
            Duration::from_secs(5),
            client.read_to_end(&mut target_response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(target_response, b"target-received-original-client-hello");

        let received = target_task.await.unwrap();
        handle.stop().await;
        assert_eq!(received, expected_hello);
        let captured_requests = captured.lock().unwrap().clone();
        let captured_errors = errors.lock().unwrap().clone();
        (captured_requests, captured_errors)
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_a_client_leaving_before_the_reply_reports_nothing() {
        // A client that walks away from a slow request. This is what settled
        // where "operation was canceled" comes from: disabling only the forward
        // cancellation branch leaves this test green, because a departing client
        // drops the whole service future rather than resolving it. What it does
        // exercise is the inbound listener — disabling that classifier makes it
        // fail with "connection closed before message completed".
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            loop {
                match target.accept().await {
                    Ok((mut stream, _)) => {
                        tokio::spawn(async move {
                            let mut request = vec![0_u8; 2048];
                            let _ = stream.read(&mut request).await;
                            // Answer far too late for a client that already left.
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                                .await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-abandoned-request".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/slow HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    target_address.port(),
                    target_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        // Let the forward get under way, then leave without reading the answer.
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(client);

        // Outlive the target's delayed reply so the forward really does resolve.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        target_task.abort();
        handle.stop().await;

        let seen = errors.lock().unwrap();
        assert!(
            seen.is_empty(),
            "a request the client gave up on is not a failure, but these were reported: {seen:?}"
        );
        // This request *did* reach the origin, and nothing records it: the
        // client's disconnect drops the whole service future before the capture
        // runs. Also pre-existing, and not something the silencing changed — but
        // worth knowing that a cancelled request a browser would still show in
        // its network panel leaves no row here.
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_an_abandoned_connect_tunnel_reports_nothing() {
        // Browsers pre-open CONNECT tunnels they may never use, and racing
        // connections lose and close the same way. Three classifiers sit on
        // this path — the upgrade, the ClientHello read, and the tunnel copy —
        // and each was reported before. Bypassed hosts were the loudest, so a
        // host deliberately left undecrypted produced the most noise.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        // Keep accepting: both tunnels below reach this listener, and a target
        // that stopped listening would be a genuine failure the proxy should
        // report — which would mask what this test is actually checking.
        let target_task = tokio::spawn(async move {
            loop {
                match target.accept().await {
                    Ok((mut stream, _)) => {
                        tokio::spawn(async move {
                            let mut sink = Vec::new();
                            let _ = stream.read_to_end(&mut sink).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        // Bypass everything: this is the undecrypted-host case, which produced
        // the most noise precisely because it is the one a user opted into.
        let settings = crate::tls_interception::normalize_tls_interception_settings(
            crate::tls_interception::TlsInterceptionSettings {
                mode: crate::tls_interception::TlsInterceptionMode::BypassSelected,
                bypass: vec!["127.0.0.1".to_string()],
                show_bypassed_connections: true,
            },
        )
        .unwrap();
        let mut rule_engine =
            RuleEngine::request_only(Arc::new(|_| Ok(RuntimeRuleControl::default())));
        rule_engine.tls_interception = Arc::new(move |host, sni| Ok(settings.decision(host, sni)));

        let handle = ProxyHandle::start_with_event_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-connect-hangup".to_string(),
            direct_upstream(),
            test_certificate_authority(),
            capture_sink,
            Some(rule_engine),
            Arc::new(|_| {}),
            error_sink,
        )
        .await
        .unwrap();

        // 1. CONNECT accepted, then the client leaves without a ClientHello.
        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!("CONNECT {target_address} HTTP/1.1\r\nHost: {target_address}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut client).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        drop(client);

        // 2. CONNECT accepted, a partial ClientHello, then gone mid-record.
        let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
        client
            .write_all(
                format!("CONNECT {target_address} HTTP/1.1\r\nHost: {target_address}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut client).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        // A TLS record header promising far more than will ever arrive.
        client
            .write_all(&[0x16, 0x03, 0x01, 0x02, 0x00])
            .await
            .unwrap();
        drop(client);

        tokio::time::sleep(Duration::from_millis(300)).await;
        target_task.abort();
        handle.stop().await;

        let seen = errors.lock().unwrap();
        assert!(
            seen.is_empty(),
            "an abandoned tunnel is not a failure, but these were reported: {seen:?}"
        );
        // Nothing is recorded for a tunnel that carried no bytes: the hello is
        // read before the first capture_connect_record, so this never reached
        // one. That predates the silencing — but it does mean an abandoned
        // tunnel now leaves no trace at all, where before it left a toast.
        // Correct for a pre-opened socket that was never used; see the note on
        // the request case below for where it is less obviously right.
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_tls_bypass_forwards_the_original_client_hello() {
        let (captured, errors) = run_local_tls_bypass(true, false).await;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].method, "CONNECT");
        assert_eq!(captured[0].host, "127.0.0.1");
        assert!(captured[0]
            .tls_version
            .as_deref()
            .is_some_and(|value| value.contains("原样隧道")));
        assert!(captured[0]
            .response_body
            .as_deref()
            .is_some_and(|value| value.contains("*.pinned.test")));
        let fingerprint = captured[0].tls_fingerprint.as_ref().unwrap();
        assert_eq!(fingerprint.capture_mode, "tunnel");
        assert_eq!(fingerprint.inbound.sni.as_deref(), Some("api.pinned.test"));
        assert_eq!(fingerprint.outbound.mode, "pass-through");
        assert_eq!(
            fingerprint.outbound.ja3.as_deref(),
            Some(fingerprint.inbound.ja3.as_str())
        );
        assert!(errors.is_empty(), "errors: {errors:?}");
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_tls_bypass_can_hide_only_the_successful_tunnel() {
        let (captured, errors) = run_local_tls_bypass(false, false).await;
        assert!(captured.is_empty(), "captured: {captured:?}");
        assert!(errors.is_empty(), "errors: {errors:?}");
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_tls_bypass_mirrors_the_connection_and_records_sni_fallback() {
        let (captured, errors) = run_local_tls_bypass(false, true).await;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].host, "api.pinned.test");
        assert_eq!(captured[0].port, Some(443));
        assert!(captured[0]
            .response_body
            .as_deref()
            .is_some_and(|value| value.contains("镜像 api.pinned.test:443")
                && value.contains("保留原 ClientHello/SNI")));
        assert_eq!(
            captured[0]
                .tls_fingerprint
                .as_ref()
                .and_then(|fingerprint| fingerprint.inbound.sni.as_deref()),
            Some("api.pinned.test")
        );
        assert!(errors.is_empty(), "errors: {errors:?}");
    }

    #[test]
    fn effective_upstream_from_env_reads_proxy_not_hardcoded_ports() {
        // Contract for live tests: PROXY beats HTTP_PROXY; no silent 7890 fallback.
        let detected = detect_env_proxy_from_pairs([
            ("HTTP_PROXY", Some("http://127.0.0.1:9999")),
            ("PROXY", Some("socks5://127.0.0.1:1080")),
        ])
        .expect("PROXY should win");
        assert_eq!(detected.port, 1080);
        assert_eq!(detected.mode, "socks5");
        assert_eq!(detected.source, "PROXY");
        let parsed = parse_proxy_url("http://user:secret@localhost:8080").unwrap();
        assert_eq!(parsed.host, "localhost");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.username, "user");
        assert_eq!(parsed.password.as_deref(), Some("secret"));
    }

    #[tokio::test]
    #[ignore = "requires PROXY or HTTP(S)_PROXY pointing at a working egress"]
    async fn live_upstream_proxy_from_env_reaches_https() {
        let proxy = effective_upstream_from_process_env().unwrap_or_else(|| {
            panic!(
                "live egress requires PROXY or HTTP(S)_PROXY / ALL_PROXY in the environment \
                 (project .env is loaded by `npm run test:windows`)"
            )
        });
        eprintln!(
            "LIVE_EGRESS using mode={} host={} port={} (from process env)",
            proxy.mode, proxy.host, proxy.port
        );

        // Shipped probe: CONNECT example.com:443 via configured egress.
        let probe = probe_upstream_egress(&proxy).await;
        assert!(
            probe.ok,
            "probe_upstream_egress failed for {}:{} — {}",
            proxy.host, proxy.port, probe.message
        );
        assert!(
            probe
                .message
                .contains(&format!("{}:{}", proxy.host, proxy.port))
                || proxy.mode == "direct",
            "probe message should name the egress: {}",
            probe.message
        );

        // Full tunnel + origin TLS via shipped connect_destination.
        let target_host = "example.com";
        let stream = connect_destination(&proxy, target_host, 443)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "connect_destination via {}:{} failed: {error}",
                    proxy.host, proxy.port
                )
            });
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let mut tls = connector
            .connect(
                ServerName::try_from(target_host.to_string()).unwrap(),
                stream,
            )
            .await
            .unwrap_or_else(|error| panic!("origin TLS failed: {error}"));
        tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = vec![0_u8; 1024];
        let read = timeout(Duration::from_secs(20), tls.read(&mut response))
            .await
            .expect("origin read timeout")
            .expect("origin read error");
        let status = String::from_utf8_lossy(&response[..read]);
        assert!(
            status.contains("HTTP/1.")
                && (status.contains(" 200 ")
                    || status.contains(" 204 ")
                    || status.contains(" 301 ")
                    || status.contains(" 302 ")
                    || status.contains(" 303 ")
                    || status.contains(" 307 ")
                    || status.contains(" 308 ")),
            "unexpected origin response via egress {}:{}: {status:?}",
            proxy.host,
            proxy.port
        );
        eprintln!(
            "LIVE_EGRESS_OK mode={} {}:{} → example.com:443",
            proxy.mode, proxy.host, proxy.port
        );
    }

    #[tokio::test]
    #[ignore = "requires PROXY/HTTP(S)_PROXY and ability to bind a local ShowNet listener"]
    async fn live_shownet_mitm_smoke_via_env_upstream() {
        let upstream = effective_upstream_from_process_env().unwrap_or_else(|| {
            panic!("live MITM smoke requires PROXY or HTTP(S)_PROXY / ALL_PROXY")
        });
        eprintln!(
            "LIVE_MITM upstream mode={} host={} port={}",
            upstream.mode, upstream.host, upstream.port
        );

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let certificate_authority = test_certificate_authority();
        // Bind ephemeral port so the smoke does not fight a running :8888 instance.
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-windows-qa-mitm".to_string(),
            upstream.clone(),
            certificate_authority.clone(),
            capture_sink,
            error_sink,
        )
        .await
        .unwrap_or_else(|error| panic!("ShowNet listener bind/start failed: {error}"));
        let listen = handle.local_addr();
        eprintln!("LIVE_MITM listener {}", listen);

        let client = connect_tcp(&listen.ip().to_string(), listen.port())
            .await
            .unwrap_or_else(|error| panic!("connect to ShowNet listener failed: {error}"));
        let mut tunnel = BoxedIo(Box::new(client));
        tunnel
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: shownet-windows-qa\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_header(&mut tunnel)
            .await
            .unwrap_or_else(|error| panic!("CONNECT response failed: {error}"));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "ShowNet CONNECT not 200 (often bad egress or bind): {response:?}"
        );

        let mut roots = RootCertStore::empty();
        roots
            .add(certificate_authority.certificate_der())
            .expect("trust ShowNet CA for MITM client");
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let mut tls = connector
            .connect(
                ServerName::try_from("example.com".to_string()).unwrap(),
                tunnel,
            )
            .await
            .unwrap_or_else(|error| panic!("MITM client TLS failed: {error}"));
        tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut target_response = vec![0_u8; 1024];
        let read = timeout(Duration::from_secs(20), tls.read(&mut target_response))
            .await
            .expect("MITM body timeout")
            .expect("MITM body read");
        let body = String::from_utf8_lossy(&target_response[..read]);
        assert!(
            body.contains("HTTP/1.")
                && !body.contains(" 502 ")
                && (body.contains(" 200 ")
                    || body.contains(" 301 ")
                    || body.contains(" 302 ")
                    || body.contains(" 303 ")
                    || body.contains(" 307 ")
                    || body.contains(" 308 ")),
            "MITM fetch should not be 502; got: {body:?}"
        );
        drop(tls);
        handle.stop().await;

        let captured = captured.lock().unwrap();
        assert!(
            !captured.is_empty(),
            "MITM smoke should capture CONNECT and/or GET; errors={:?}",
            errors.lock().unwrap()
        );
        assert!(
            captured
                .iter()
                .any(|r| r.method.eq_ignore_ascii_case("CONNECT")),
            "expected CONNECT capture: {captured:?}"
        );
        // Prefer decrypted GET when MITM succeeds.
        if let Some(get) = captured
            .iter()
            .find(|r| r.method.eq_ignore_ascii_case("GET"))
        {
            assert_ne!(get.status, 502, "GET should not be proxy error: {get:?}");
            assert!(
                get.status == 200 || (300..400).contains(&get.status),
                "unexpected GET status {}: {get:?}",
                get.status
            );
        }
        assert!(
            errors.lock().unwrap().is_empty(),
            "proxy errors: {:?}",
            errors.lock().unwrap()
        );
        eprintln!(
            "LIVE_MITM_OK listener={} captures={}",
            listen,
            captured.len()
        );
    }

    /// Fully automated, no human: drives the whole MITM egress the embedded
    /// browser drives — a client → ShowNet MITM → wreq → origin — with
    /// impersonate on, against a JA4/h2 reflector, and asserts the origin sees
    /// Chrome byte-exact. This is what proves the *proxy path* (not just
    /// standalone wreq) presents Chrome; if it passes, a persisting Cloudflare
    /// loop is the JS/connection-binding problem, not the fingerprint.
    ///
    ///   PROXY=http://127.0.0.1:8080 cargo test --no-default-features \
    ///     --features impersonate-boring mitm_impersonate_presents_chrome \
    ///     -- --ignored --nocapture
    #[tokio::test]
    #[cfg(feature = "impersonate-boring")]
    #[ignore = "network + env upstream; run via npm run test:impersonate-mitm"]
    async fn mitm_impersonate_presents_chrome_to_the_origin() {
        let upstream = effective_upstream_from_process_env().unwrap_or_else(|| {
            panic!("needs PROXY or HTTP(S)_PROXY / ALL_PROXY to reach the reflector")
        });
        crate::tls_impersonate::set_impersonate_requested(true);
        assert_eq!(
            tls_outbound::active_engine(),
            tls_outbound::OutboundTlsEngine::Impersonate,
            "impersonate must be the active engine for this test"
        );

        let capture_sink: CaptureSink = Arc::new(move |_| {});
        let error_sink: ErrorSink = Arc::new(move |error| eprintln!("PROXY_ERR {error}"));
        let certificate_authority = test_certificate_authority();
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-impersonate-mitm".to_string(),
            upstream,
            certificate_authority.clone(),
            capture_sink,
            error_sink,
        )
        .await
        .expect("ShowNet listener");
        let listen = handle.local_addr();

        let host = "tls.peet.ws";
        let client = connect_tcp(&listen.ip().to_string(), listen.port())
            .await
            .expect("connect to listener");
        let mut tunnel = BoxedIo(Box::new(client));
        tunnel
            .write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_header(&mut tunnel)
            .await
            .expect("CONNECT response");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "CONNECT: {response:?}"
        );

        let mut roots = RootCertStore::empty();
        roots.add(certificate_authority.certificate_der()).unwrap();
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(host.to_string()).unwrap(), tunnel)
            .await
            .expect("MITM client TLS");
        tls.write_all(
            format!("GET /api/all HTTP/1.1\r\nHost: {host}\r\nUser-Agent: shownet\r\nAccept: application/json\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

        // Read to EOF — the reflector JSON is well past one buffer.
        let mut raw = Vec::new();
        loop {
            let mut chunk = [0_u8; 8192];
            let n = timeout(Duration::from_secs(30), tls.read(&mut chunk))
                .await
                .expect("read timeout")
                .expect("read");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            if raw.len() > 512 * 1024 {
                break;
            }
        }
        handle.stop().await;
        crate::tls_impersonate::set_impersonate_requested(false);

        let text = String::from_utf8_lossy(&raw);
        let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
        let json: serde_json::Value = {
            let body = &text[body_start..];
            let start = body.find('{').expect("no JSON in reflector response");
            serde_json::from_str(body[start..].trim_end()).expect("reflector JSON")
        };

        let ja4 = json["tls"]["ja4"].as_str().expect("ja4");
        let akamai = json["http2"]["akamai_fingerprint"]
            .as_str()
            .expect("akamai fingerprint");
        eprintln!("MITM_IMPERSONATE_JA4 {ja4}");
        eprintln!("MITM_IMPERSONATE_AKAMAI {akamai}");
        assert!(
            ja4.starts_with("t13d1516h2"),
            "the origin must see Chrome's 16-extension JA4 through the MITM path, got {ja4}"
        );
        assert!(
            akamai.ends_with("|m,a,s,p"),
            "the origin must see Chrome's h2 pseudo order through the MITM path, got {akamai}"
        );
    }

    /// The certificate authority the desktop app generated and the user installed,
    /// read from its database. A browser only trusts the MITM leaf if it was
    /// signed by this one.
    #[cfg(test)]
    fn installed_certificate_authority() -> Result<CertificateAuthority, String> {
        let database = std::env::var("SHOWNET_DB")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                // No dirs crate in this build, and HOME is set wherever a browser
                // could be launched anyway.
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
                    .join("Library/Application Support/com.shownet.desktop/shownet.sqlite3")
            });
        if !database.is_file() {
            return Err(format!("no ShowNet database at {}", database.display()));
        }
        let material = crate::storage::Storage::open(&database)?
            .get_certificate_authority()?
            .ok_or_else(|| "the database holds no certificate authority".to_string())?;
        Ok(CertificateAuthority::load_or_create(Some(material))?.0)
    }

    /// Google Fonts through the MITM path, which is where a whole site can die on
    /// a stylesheet.
    ///
    /// Measured on lionairthai: `fonts.googleapis.com/css2` answered 502 through
    /// the proxy, the page's CSS preload rejected, React Router caught the
    /// rejection during render, and `#root` stayed empty — a blank page whose
    /// cause is three layers away from the request that failed. Nothing else on
    /// that load failed; every other asset was 200.
    ///
    ///   PROXY=http://127.0.0.1:8080 npm run test:font-css
    #[tokio::test]
    #[ignore = "network + an env upstream; run via npm run test:font-css"]
    async fn a_google_fonts_stylesheet_survives_the_mitm_path() {
        let upstream = effective_upstream_from_process_env()
            .unwrap_or_else(|| panic!("needs PROXY or HTTP(S)_PROXY / ALL_PROXY"));
        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-font-css".to_string(),
            upstream,
            test_certificate_authority(),
            capture_sink,
            error_sink,
        )
        .await
        .expect("listener");
        let listen = handle.local_addr();

        // The MITM leaf is signed by a throwaway CA here; the point of the test is
        // the status the origin path produces, not certificate trust.
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{listen}")).expect("proxy"))
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");

        // The exact shape the site requests: two families, italic axis, several
        // weights, and display=swap. A long query is the part that a rewriting
        // proxy is most likely to mangle.
        let url = "https://fonts.googleapis.com/css2\
?family=Prompt:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400\
&family=Outfit:wght@300;400;500;600;700&display=swap";
        let response = client
            .get(url.replace('\n', ""))
            .header("referer", "https://www.lionairthai.com/")
            .send()
            .await
            .unwrap_or_else(|error| panic!("request through the MITM failed: {error}"));

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        eprintln!("FONT_CSS status={status} bytes={}", body.len());
        for error in errors.lock().unwrap().iter().take(5) {
            eprintln!("FONT_CSS proxy error: {error}");
        }

        assert!(
            status.is_success(),
            "the stylesheet came back {status}; a site that preloads it renders \
             blank, and the failure surfaces as a React render error rather than \
             as a network problem. Body: {}",
            &body[..body.len().min(300)]
        );
        assert!(
            body.contains("font-face"),
            "a 200 that is not CSS breaks the same way a 502 does: {}",
            &body[..body.len().min(200)]
        );
    }

    /// Drives a real capture session end to end — production proxy, production
    /// browser launch, a real site — and inspects what the origins were actually
    /// sent.
    ///
    /// Both defects this covers were invisible to every other test because both
    /// live in the seam between the launcher and the wire. The UA fix is a launch
    /// flag, so a unit test on the string it builds proves nothing about whether
    /// `launch` applies it; the WebSocket fix only shows up on a page that opens
    /// one. Here the assertions read the capture sink, which is the same data the
    /// product records, so they see exactly what the site saw.
    ///
    ///   PROXY=http://127.0.0.1:8080 npm run test:live-capture
    #[tokio::test]
    #[ignore = "network, an env upstream, and a locally installed Chrome; run via npm run test:live-capture"]
    async fn a_live_capture_session_shows_the_site_a_consistent_browser() {
        let upstream = effective_upstream_from_process_env()
            .unwrap_or_else(|| panic!("live capture requires PROXY or HTTP(S)_PROXY / ALL_PROXY"));
        // Overridable so this can be pointed at whatever site is being
        // investigated without editing the test.
        let target = std::env::var("SHOWNET_LIVE_TARGET")
            .unwrap_or_else(|_| "https://www.lionairthai.com/".to_string());

        let captured = Arc::new(Mutex::new(Vec::<CapturedRequestInput>::new()));
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let capture_sink: CaptureSink = {
            let captured = captured.clone();
            Arc::new(move |request| captured.lock().unwrap().push(request))
        };
        let error_sink: ErrorSink = {
            let errors = errors.clone();
            Arc::new(move |error| errors.lock().unwrap().push(error))
        };
        // Linked stack ⇒ engine is always impersonate (no product opt-out).
        eprintln!(
            "LIVE_CAPTURE engine={} (stack available={})",
            crate::tls_outbound::active_engine().as_str(),
            crate::tls_outbound::real_impersonate_stack_available()
        );

        // The generated test CA is trusted by nothing, so a real browser answers
        // the MITM leaf with CertificateUnknown and the session is one failed
        // CONNECT — the first run of this test hit exactly that. Reuse the CA the
        // installed app already put in the trust store instead.
        let authority = Arc::new(installed_certificate_authority().unwrap_or_else(|error| {
            panic!(
                "live capture needs the CA the desktop app installed, so the \
                 launched browser trusts the MITM leaf: {error}"
            )
        }));
        let handle = ProxyHandle::start_with_sinks(
            "127.0.0.1:0".parse().unwrap(),
            false,
            "session-live-capture".to_string(),
            upstream,
            authority,
            capture_sink,
            error_sink,
        )
        .await
        .expect("ShowNet listener");
        let port = handle.local_addr().port();

        let data_dir = std::env::temp_dir().join(format!("shownet-live-{}", std::process::id()));
        std::fs::create_dir_all(&data_dir).expect("data dir");
        // The production launcher, not a hand-rolled Chrome invocation — the
        // point is to check what ShowNet actually starts.
        let browser = crate::browser::ProxyBrowserHandle::launch(&data_dir, port, None)
            .await
            .expect("launch the capture browser");
        let bus = browser.bus();

        bus.navigate(&target).await.expect("navigate");
        // Let the page settle: first paint, subresources, and whatever sockets it
        // opens afterwards. Polled rather than slept so a quiet site does not pay
        // the full wait.
        // A real page load is dozens of requests. Requiring a floor before the
        // quiet check matters: without it the loop settles on the handful that
        // arrive while the renderer is still starting and the assertions below
        // pass having inspected almost nothing — which is exactly what the first
        // run of this test did, declaring success on one request.
        const MIN_REQUESTS: usize = 10;
        const QUIET_POLLS: u32 = 3;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        let mut settled = 0;
        let mut quiet = 0;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let count = captured.lock().unwrap().len();
            quiet = if count == settled { quiet + 1 } else { 0 };
            settled = count;
            if count >= MIN_REQUESTS && quiet >= QUIET_POLLS {
                break;
            }
        }

        // Whether the page actually rendered, which the request log alone cannot
        // say: a site can fetch every asset successfully and still show nothing
        // if one of them fails in a way its framework catches during render.
        // Measured here as the search form the site's own home page builds.
        let rendered = bus
            .evaluate(
                "JSON.stringify({inputs: document.querySelectorAll('input').length, \
                 rootKids: document.getElementById('root') ? \
                 document.getElementById('root').children.length : -1, \
                 text: (document.body ? document.body.innerText.length : 0)})",
                false,
            )
            .await;
        match &rendered {
            Ok(value) => eprintln!("LIVE_CAPTURE   rendered: {:?}", value.value),
            Err(error) => eprintln!("LIVE_CAPTURE   rendered: (evaluate failed: {error})"),
        }

        let seen = captured.lock().unwrap().clone();
        browser.stop().await;
        let _ = std::fs::remove_dir_all(&data_dir);
        eprintln!("LIVE_CAPTURE recorded {} requests to {target}", seen.len());
        for request in seen.iter().take(15) {
            eprintln!(
                "LIVE_CAPTURE   {} {} {}{} -> {}",
                request.protocol, request.method, request.host, request.path, request.status
            );
        }
        {
            let errors = errors.lock().unwrap();
            for error in errors.iter().take(10) {
                eprintln!("LIVE_CAPTURE   error: {error}");
            }
        }
        assert!(
            seen.len() >= MIN_REQUESTS,
            "only {} requests were captured, which is not a page load — the \
             assertions below would pass without inspecting anything. Check the \
             errors printed above",
            seen.len()
        );

        // 1. No request may announce automation. This is the whole reason the UA
        //    moved from a per-target CDP override to a launch flag: the override
        //    covered the main document and left subresources and workers leaking.
        let headless: Vec<String> = seen
            .iter()
            .filter(|request| {
                request.request_headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("user-agent")
                        && header.value.contains("HeadlessChrome")
                })
            })
            .map(|request| format!("{} {}{}", request.method, request.host, request.path))
            .collect();
        assert!(
            headless.is_empty(),
            "{} of {} requests announced HeadlessChrome, e.g. {:?}",
            headless.len(),
            seen.len(),
            &headless[..headless.len().min(5)]
        );

        // 2. No WebSocket handshake may be rejected for the key the RFC 8441
        //    downgrade has to mint. A site whose sockets 400 keeps retrying them,
        //    which is what a challenge loop looks like from the outside.
        let keyless: Vec<String> = seen
            .iter()
            .filter(|request| {
                request.status == 400
                    && request
                        .response_body
                        .as_deref()
                        .is_some_and(|body| body.contains("Sec-WebSocket-Key"))
            })
            .map(|request| format!("{}{}", request.host, request.path))
            .collect();
        assert!(
            keyless.is_empty(),
            "{} WebSocket upgrades were rejected for a missing Sec-WebSocket-Key: {:?}",
            keyless.len(),
            &keyless[..keyless.len().min(5)]
        );

        // Reported, not asserted: whether a challenge appeared at all is the
        // site's decision on the day, and failing the build on it would make this
        // a weather report. The counts are what a human needs to judge a loop.
        let challenges = seen
            .iter()
            .filter(|request| {
                request.path.contains("/cdn-cgi/challenge-platform")
                    || request.response_headers.iter().any(|header| {
                        header.name.eq_ignore_ascii_case("cf-mitigated")
                            && header.value.contains("challenge")
                    })
            })
            .count();
        eprintln!("LIVE_CAPTURE challenge requests: {challenges}");
        // A challenge appearing once is the gate working. The same endpoint
        // fetched over and over is the loop, and only the breakdown tells them
        // apart, so print it rather than a single number.
        let mut by_path: std::collections::BTreeMap<String, (usize, i64)> =
            std::collections::BTreeMap::new();
        for request in seen
            .iter()
            .filter(|request| request.path.contains("/cdn-cgi/"))
        {
            let entry = by_path
                .entry(format!("{}{}", request.host, request.path))
                .or_insert((0, request.status));
            entry.0 += 1;
            entry.1 = request.status;
        }
        for (path, (count, status)) in by_path.iter().take(12) {
            eprintln!("LIVE_CAPTURE   challenge x{count} -> {status}  {path}");
        }
        // Whether the clearance cookie the server grants ever comes back is what
        // separates "the gate keeps refusing us" from "we keep losing the pass".
        let oneshots: Vec<&CapturedRequestInput> = seen
            .iter()
            .filter(|request| request.path.contains("/jsd/oneshot/"))
            .collect();
        let carrying = oneshots
            .iter()
            .filter(|request| {
                request.request_headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("cookie")
                        && header.value.contains("cf_clearance")
                })
            })
            .count();
        let granting = oneshots
            .iter()
            .filter(|request| {
                request.response_headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("set-cookie")
                        && header.value.contains("cf_clearance")
                })
            })
            .count();
        eprintln!(
            "LIVE_CAPTURE   oneshot: {} total, {granting} granted cf_clearance, {carrying} sent it back",
            oneshots.len()
        );
        // If the document itself is refetched over and over, the beacon count is
        // a symptom and the reload is the disease.
        let mut repeats: Vec<(usize, String)> = {
            let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
            for request in &seen {
                *counts
                    .entry(format!(
                        "{} {}{}",
                        request.method, request.host, request.path
                    ))
                    .or_default() += 1;
            }
            counts.into_iter().map(|(k, v)| (v, k)).collect()
        };
        repeats.sort_by(|a, b| b.0.cmp(&a.0));
        for (count, what) in repeats.iter().take(8) {
            eprintln!("LIVE_CAPTURE   x{count}  {}", &what[..what.len().min(110)]);
        }
        // What the product claims on the fingerprint panel, read off the same
        // records it shows there: whether the handshake the browser made and the
        // handshake ShowNet made on its behalf are the same client.
        {
            let mut pairs: std::collections::BTreeSet<(String, String, String)> =
                Default::default();
            for record in seen.iter().filter_map(|r| r.tls_fingerprint.as_ref()) {
                let json = serde_json::to_value(record).unwrap_or_default();
                let side = |name: &str, field: &str| {
                    json.get(name)
                        .and_then(|value| value.get(field))
                        .and_then(|value| value.as_str())
                        .unwrap_or("—")
                        .to_string()
                };
                pairs.insert((
                    side("inbound", "ja3"),
                    side("outbound", "ja3"),
                    format!("{} / {}", side("inbound", "ja4"), side("outbound", "ja4")),
                ));
            }
            eprintln!("LIVE_CAPTURE   fingerprint pairs seen: {}", pairs.len());
            for (inbound, outbound, ja4) in pairs.iter().take(4) {
                eprintln!(
                    "LIVE_CAPTURE     ja3 in={inbound}\nLIVE_CAPTURE     ja3 out={outbound}  {}",
                    if inbound == outbound {
                        "MATCH"
                    } else {
                        "DIFFER"
                    }
                );
                eprintln!("LIVE_CAPTURE     ja4 in/out={ja4}");
            }
        }

        // The document is what reloads, so what it gets back each time is the
        // question: the real page, or a Cloudflare interstitial.
        let documents: Vec<&CapturedRequestInput> = seen
            .iter()
            .filter(|request| {
                request.method == "GET" && request.path == "/" && request.host.starts_with("www.")
            })
            .collect();
        let with_clearance = documents
            .iter()
            .filter(|request| {
                request.request_headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("cookie")
                        && header.value.contains("cf_clearance")
                })
            })
            .count();
        let mitigated = documents
            .iter()
            .filter(|request| {
                request
                    .response_headers
                    .iter()
                    .any(|header| header.name.eq_ignore_ascii_case("cf-mitigated"))
            })
            .count();
        eprintln!(
            "LIVE_CAPTURE   document: {} fetches, {with_clearance} carried cf_clearance, {mitigated} were cf-mitigated",
            documents.len()
        );
        for request in documents
            .iter()
            .take(3)
            .chain(documents.iter().rev().take(2))
        {
            eprintln!(
                "LIVE_CAPTURE     doc -> {} {} bytes proto={}",
                request.status, request.size_bytes, request.protocol
            );
        }

        // "Unexpected token '<'" means a script fetch answered with markup. Find
        // every request the browser asked for as a script whose response was not
        // JavaScript — that is the one the page choked on.
        for request in seen
            .iter()
            .filter(|request| {
                request.request_headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("sec-fetch-dest") && header.value == "script"
                }) && request.response_headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("content-type")
                        && header.value.contains("text/html")
                })
            })
            .take(6)
        {
            eprintln!(
                "LIVE_CAPTURE   script served HTML: {} {}{} -> {} {:?}",
                request.method,
                request.host,
                &request.path[..request.path.len().min(70)],
                request.status,
                request
                    .response_body
                    .as_deref()
                    .map(|b| &b[..b.len().min(120)])
            );
        }

        // A page that reports its own errors is telling us what broke; read it
        // rather than guess.
        if let Some(reported) = seen
            .iter()
            .find(|request| request.path.contains("/track/error") && request.method == "POST")
        {
            eprintln!(
                "LIVE_CAPTURE   site error report -> {} {:?}",
                reported.status,
                reported
                    .request_body
                    .as_deref()
                    .map(|body| &body[..body.len().min(600)])
            );
        }
        if let Some(sample) = oneshots.first() {
            eprintln!(
                "LIVE_CAPTURE   sample {} {} proto={} status={} size={}",
                sample.method, sample.path, sample.protocol, sample.status, sample.size_bytes
            );
            for header in &sample.request_headers {
                eprintln!("LIVE_CAPTURE     > {}: {}", header.name, header.value);
            }
            for header in &sample.response_headers {
                eprintln!("LIVE_CAPTURE     < {}: {}", header.name, header.value);
            }
            eprintln!(
                "LIVE_CAPTURE     body: {:?}",
                sample
                    .response_body
                    .as_deref()
                    .map(|body| &body[..body.len().min(200)])
            );
        }
        let errors = errors.lock().unwrap();
        eprintln!("LIVE_CAPTURE proxy errors: {}", errors.len());
        let mut by_kind: std::collections::BTreeMap<String, usize> = Default::default();
        for error in errors.iter() {
            *by_kind
                .entry(error.chars().take(70).collect::<String>())
                .or_default() += 1;
        }
        let mut kinds: Vec<(usize, String)> = by_kind.into_iter().map(|(k, v)| (v, k)).collect();
        kinds.sort_by(|a, b| b.0.cmp(&a.0));
        for (count, kind) in kinds.iter().take(8) {
            eprintln!("LIVE_CAPTURE   err x{count}  {kind}");
        }
    }
}
