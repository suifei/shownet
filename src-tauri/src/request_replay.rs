use crate::models::{
    BodyCaptureMetadata, CapturedRequestInput, HeaderEntry, ReplayBatchItem, ReplaySettings,
    RequestCollection, RequestDraft, RequestRun,
};
use crate::{emit, AppState};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures_util::{stream, StreamExt};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest_cookie_store::CookieStoreMutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const REPLAY_CONTEXT_HEADER: &str = "x-shownet-replay-context";

pub async fn execute_batch(app: tauri::AppHandle, batch_id: String, cancellation: Arc<AtomicBool>) {
    let state = app.state::<AppState>();
    let Ok(batch) = state.storage.get_replay_batch(&batch_id) else {
        return;
    };
    let settings = batch.settings.clone();
    let _ = state.storage.set_replay_batch_status(&batch_id, "running");
    let _ = emit_replay_batch(&app, &batch_id);
    if settings.start_delay_ms > 0 {
        if sleep_or_cancel(
            Duration::from_millis(settings.start_delay_ms as u64),
            &cancellation,
        )
        .await
        {
            let _ = state.storage.cancel_queued_replay_items(&batch_id);
            let _ = state
                .storage
                .set_replay_batch_status(&batch_id, "cancelled");
            let _ = emit_replay_batch(&app, &batch_id);
            return;
        }
    }

    let concurrency = settings.max_concurrency.clamp(1, 8) as usize;
    let futures = batch.items.into_iter().enumerate().map(|(index, item)| {
        let app = app.clone();
        let settings = settings.clone();
        let cancellation = cancellation.clone();
        async move {
            if settings.interval_ms > 0 && index > 0 {
                if sleep_or_cancel(
                    Duration::from_millis(settings.interval_ms as u64 * index as u64),
                    &cancellation,
                )
                .await
                {
                    return;
                }
            }
            if cancellation.load(Ordering::SeqCst) {
                return;
            }
            execute_replay_item(&app, &item, &settings, cancellation).await;
        }
    });
    stream::iter(futures)
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

    let state = app.state::<AppState>();
    let cancelled = cancellation.load(Ordering::SeqCst);
    if cancelled {
        let _ = state.storage.cancel_queued_replay_items(&batch_id);
        let _ = state
            .storage
            .set_replay_batch_status(&batch_id, "cancelled");
    } else {
        let status = state
            .storage
            .get_replay_batch(&batch_id)
            .map(|batch| {
                if batch.failed > 0 && batch.succeeded == 0 {
                    "failed"
                } else {
                    "complete"
                }
            })
            .unwrap_or("failed");
        let _ = state.storage.set_replay_batch_status(&batch_id, status);
    }
    let _ = emit_replay_batch(&app, &batch_id);
}

async fn execute_replay_item(
    app: &tauri::AppHandle,
    item: &ReplayBatchItem,
    settings: &ReplaySettings,
    cancellation: Arc<AtomicBool>,
) {
    let state = app.state::<AppState>();
    if state.storage.set_replay_item_running(&item.id).is_err() {
        return;
    }
    let _ = emit_replay_batch_item(app, &item.id, "running");
    let started = Instant::now();
    let network = async {
        let source = state.storage.get_bundle_request(&item.source_request_id)?;
        let url = request_url(
            &source.scheme,
            &source.host,
            source.port,
            &source.path,
            source.query.as_deref(),
        )?;
        let body = source.request_body.unwrap_or_default();
        let headers = sanitize_headers(
            &source.request_headers,
            settings.include_cookie,
            settings.include_authorization,
            body.len(),
        );
        let client = build_client(&state, settings, &url, None)?;
        let method = reqwest::Method::from_bytes(source.method.as_bytes())
            .map_err(|_| "来源请求方法无效".to_string())?;
        let mut request = client.request(method, &url);
        for header in &headers {
            let name = HeaderName::from_str(header.name.trim())
                .map_err(|_| format!("Header 名称无效: {}", header.name))?;
            let value = HeaderValue::from_str(&header.value)
                .map_err(|_| format!("Header 值无效: {}", header.name))?;
            request = request.header(name, value);
        }
        if settings.through_capture {
            request = request.header(
                REPLAY_CONTEXT_HEADER,
                format!("{}:{}", item.id, item.source_request_id),
            );
        }
        if !body.is_empty() {
            request = request.body(body.clone());
        }
        let response = request
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .map_err(|error| format!("重放请求失败: {error}"))?;
        let status = response.status().as_u16() as i64;
        let protocol = match response.version() {
            reqwest::Version::HTTP_2 => "h2",
            reqwest::Version::HTTP_3 => "h3",
            _ => "http/1.1",
        }
        .to_string();
        let response_headers = response
            .headers()
            .iter()
            .map(|(name, value)| HeaderEntry {
                name: name.to_string(),
                value: value.to_str().unwrap_or("<binary>").to_string(),
            })
            .collect::<Vec<_>>();
        let (response_body, metadata) = read_response(response).await?;
        if !settings.through_capture {
            let parsed = reqwest::Url::parse(&url).map_err(|error| error.to_string())?;
            let mut captured_headers = headers.clone();
            captured_headers.push(HeaderEntry {
                name: REPLAY_CONTEXT_HEADER.to_string(),
                value: format!("{}:{}", item.id, item.source_request_id),
            });
            state.storage.store_request(CapturedRequestInput {
                id: None,
                session_id: state
                    .storage
                    .request_session_id_for_replay(&item.source_request_id)?,
                source: "script".to_string(),
                source_instance_id: Some("request-replay:direct".to_string()),
                timestamp: None,
                method: source.method,
                scheme: Some(parsed.scheme().to_string()),
                host: parsed.host_str().unwrap_or_default().to_string(),
                port: parsed.port().map(i64::from),
                path: parsed.path().to_string(),
                query: parsed.query().map(ToString::to_string),
                status,
                resource_type: "fetch".to_string(),
                size_bytes: metadata.wire_bytes,
                duration_ms: started.elapsed().as_millis() as i64,
                protocol,
                tls_version: Some(
                    if parsed.scheme() == "https" {
                        "TLS"
                    } else {
                        "明文"
                    }
                    .to_string(),
                ),
                tls_fingerprint: None,
                risk_level: if status >= 400 { "warning" } else { "none" }.to_string(),
                request_headers: captured_headers,
                response_headers,
                request_body: (!body.is_empty()).then_some(body),
                response_body: Some(response_body),
                response_body_metadata: Some(metadata),
                crypto_snippets: None,
                hook: None,
            })?;
        }
        Ok::<i64, String>(status)
    };
    let result = tokio::select! {
        biased;
        _ = wait_for_batch_cancellation(&cancellation) => None,
        result = network => Some(result),
    };
    let duration = started.elapsed().as_millis() as i64;
    match result {
        Some(Ok(status_code)) => {
            let _ = state.storage.finish_replay_item(
                &item.id,
                "complete",
                Some(status_code),
                duration,
                None,
            );
        }
        Some(Err(error)) => {
            let _ =
                state
                    .storage
                    .finish_replay_item(&item.id, "failed", None, duration, Some(&error));
        }
        None => {
            let _ = state.storage.finish_replay_item(
                &item.id,
                "cancelled",
                None,
                duration,
                Some("用户取消批次"),
            );
        }
    }
    let _ = emit_replay_batch_item(app, &item.id, "finished");
}

async fn wait_for_batch_cancellation(cancellation: &AtomicBool) {
    while !cancellation.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn sleep_or_cancel(duration: Duration, cancellation: &AtomicBool) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = wait_for_batch_cancellation(cancellation) => true,
    }
}

pub async fn execute_draft(
    app: &tauri::AppHandle,
    draft_id: &str,
    mut cancellation: tokio::sync::watch::Receiver<bool>,
) -> Result<RequestRun, String> {
    let state = app.state::<AppState>();
    let draft = state.storage.get_request_draft_for_send(draft_id)?;
    let collection = if collection_inheritance_enabled(&draft) {
        match draft.collection_id.as_deref() {
            Some(collection_id) => Some(
                state
                    .storage
                    .get_request_collection_for_send(collection_id)?,
            ),
            None => None,
        }
    } else {
        None
    };
    let (mut effective_draft, inheritance) = apply_collection_defaults(&draft, collection.as_ref());
    effective_draft.environment_id = state
        .storage
        .resolve_effective_environment_id(effective_draft.environment_id.as_deref())?;
    let variables = state
        .storage
        .effective_environment_values(effective_draft.environment_id.as_deref())?;
    let mut prepared = prepare_draft(&effective_draft, &variables)?;
    if let Some(inheritance) = inheritance {
        prepared.snapshot["inheritance"] = inheritance;
    }
    let cookie_jar_enabled = draft
        .settings
        .get("cookieJar")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let run = state
        .storage
        .create_request_run(draft_id, &prepared.snapshot)?;
    let started = Instant::now();
    let network = async {
        let mut settings = ReplaySettings::default();
        settings.follow_redirects = draft
            .settings
            .get("followRedirects")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        settings.verify_tls = draft
            .settings
            .get("verifyTls")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        settings.use_upstream_proxy = draft
            .settings
            .get("useUpstreamProxy")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let cookie_jar = cookie_jar_enabled.then(|| Arc::clone(&state.request_cookie_jar));
        let client = build_client(&state, &settings, &prepared.url, cookie_jar)?;
        let method = reqwest::Method::from_bytes(draft.method.as_bytes())
            .map_err(|_| "草稿请求方法无效".to_string())?;
        let mut request = client.request(method, &prepared.url);
        for header in &prepared.headers {
            request = request.header(
                HeaderName::from_str(&header.name)
                    .map_err(|_| format!("Header 名称无效: {}", header.name))?,
                HeaderValue::from_str(&header.value)
                    .map_err(|_| format!("Header 值无效: {}", header.name))?,
            );
        }
        if !prepared.body.is_empty() {
            request = request.body(prepared.body.clone());
        }
        let response = request
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .map_err(|error| format!("发送草稿失败: {error}"))?;
        let status = response.status().as_u16();
        let headers = response_snapshot_headers(response.headers());
        let (body, metadata) = read_response(response).await?;
        Ok::<Value, String>(
            json!({"status":status,"headers":headers,"body":body,"bodyMetadata":metadata,"durationMs":started.elapsed().as_millis()}),
        )
    };
    let result = tokio::select! {
        result = network => Some(result),
        _ = wait_for_cancellation(&mut cancellation) => None,
    };
    if cookie_jar_enabled {
        let store = state
            .request_cookie_jar
            .lock()
            .map_err(|_| "Cookie Jar 运行状态已损坏".to_string())?;
        state.storage.save_request_cookie_store(&store)?;
    }
    match result {
        Some(Ok(response)) => state
            .storage
            .finish_request_run(&run.id, "complete", &response, None),
        Some(Err(error)) => state.storage.finish_request_run(
            &run.id,
            "failed",
            &json!({"durationMs":started.elapsed().as_millis()}),
            Some(&error),
        ),
        None => state.storage.finish_request_run(
            &run.id,
            "cancelled",
            &json!({"durationMs":started.elapsed().as_millis()}),
            Some("用户取消发送"),
        ),
    }
}

async fn wait_for_cancellation(cancellation: &mut tokio::sync::watch::Receiver<bool>) {
    if *cancellation.borrow() {
        return;
    }
    while cancellation.changed().await.is_ok() {
        if *cancellation.borrow() {
            return;
        }
    }
}

struct PreparedDraft {
    url: String,
    headers: Vec<HeaderEntry>,
    body: Vec<u8>,
    snapshot: Value,
}

struct PreparedDraftBody {
    bytes: Vec<u8>,
    content_type: Option<String>,
    force_content_type: bool,
    snapshot: Value,
}

fn collection_inheritance_enabled(draft: &RequestDraft) -> bool {
    draft.collection_id.is_some()
        && draft
            .settings
            .get("inheritCollection")
            .and_then(Value::as_bool)
            .unwrap_or(true)
}

fn apply_collection_defaults(
    draft: &RequestDraft,
    collection: Option<&RequestCollection>,
) -> (RequestDraft, Option<Value>) {
    let Some(collection) = collection else {
        return (draft.clone(), None);
    };
    let mut effective = draft.clone();
    let request_header_names = draft
        .headers
        .iter()
        .map(|header| header.name.trim().to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let inherited_headers = collection
        .default_headers
        .iter()
        .filter(|header| !request_header_names.contains(&header.name.trim().to_ascii_lowercase()))
        .cloned()
        .collect::<Vec<_>>();
    effective.headers = inherited_headers
        .iter()
        .cloned()
        .chain(draft.headers.iter().cloned())
        .collect();

    let request_auth_kind = draft
        .auth
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let collection_auth_kind = collection
        .default_auth
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let inherited_auth = request_auth_kind == "none" && collection_auth_kind != "none";
    if inherited_auth {
        effective.auth = collection.default_auth.clone();
    }

    let inherited_environment =
        effective.environment_id.is_none() && collection.default_environment_id.is_some();
    if inherited_environment {
        effective.environment_id = collection.default_environment_id.clone();
    }
    let summary = json!({
        "collectionId": collection.id,
        "collectionName": collection.name,
        "headerCount": inherited_headers.len(),
        "auth": inherited_auth,
        "environment": inherited_environment,
    });
    (effective, Some(summary))
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DraftBodyField {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
    #[serde(default = "default_body_field_kind")]
    kind: String,
    #[serde(default)]
    file_path: Option<String>,
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DraftFileBody {
    file_path: String,
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
}

fn default_body_field_kind() -> String {
    "text".to_string()
}

fn default_true() -> bool {
    true
}

fn prepare_draft(
    draft: &RequestDraft,
    variables: &[(String, String, bool)],
) -> Result<PreparedDraft, String> {
    let now = chrono::Utc::now();
    let mut map = HashMap::from([
        (
            "timestamp".to_string(),
            (now.timestamp().to_string(), false),
        ),
        (
            "timestamp_ms".to_string(),
            (now.timestamp_millis().to_string(), false),
        ),
        (
            "iso_datetime".to_string(),
            (
                now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                false,
            ),
        ),
        (
            "uuid".to_string(),
            (uuid::Uuid::new_v4().to_string(), false),
        ),
    ]);
    for (name, value, secret) in variables {
        map.insert(name.clone(), (value.clone(), *secret));
    }
    let mut unresolved = HashSet::new();
    let resolve =
        |input: &str, unresolved: &mut HashSet<String>| replace_variables(input, &map, unresolved);
    let mut url = resolve(&draft.url, &mut unresolved);
    let mut headers = draft
        .headers
        .iter()
        .map(|header| HeaderEntry {
            name: resolve(&header.name, &mut unresolved),
            value: resolve(&header.value, &mut unresolved),
        })
        .collect::<Vec<_>>();
    let auth = resolve_draft_auth(&draft.auth, &map, &mut unresolved);
    apply_draft_auth(&auth, &mut url, &mut headers)?;
    let prepared_body = prepare_draft_body(draft, &map, &mut unresolved)?;
    if !unresolved.is_empty() {
        return Err(format!(
            "存在未定义变量: {}",
            unresolved.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(content_type) = &prepared_body.content_type {
        let has_content_type = headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-type"));
        if prepared_body.force_content_type || !has_content_type {
            headers.retain(|header| !header.name.eq_ignore_ascii_case("content-type"));
            headers.push(HeaderEntry {
                name: "Content-Type".to_string(),
                value: content_type.clone(),
            });
        }
    }
    let body_len = prepared_body.bytes.len();
    let headers = sanitize_headers(&headers, true, true, body_len);
    let mut snapshot = json!({"method":draft.method,"url":url.clone(),"headers":headers.clone(),"body":prepared_body.snapshot.clone(),"bodyType":draft.body_type,"bodyBytes":body_len,"environmentId":draft.environment_id,"collectionId":draft.collection_id});
    if matches!(draft.body_type.as_str(), "form-data" | "file") && !prepared_body.bytes.is_empty() {
        snapshot["wireBodyBase64"] = json!(STANDARD.encode(&prepared_body.bytes));
    }
    Ok(PreparedDraft {
        url,
        headers,
        body: prepared_body.bytes,
        snapshot,
    })
}

fn prepare_draft_body(
    draft: &RequestDraft,
    variables: &HashMap<String, (String, bool)>,
    unresolved: &mut HashSet<String>,
) -> Result<PreparedDraftBody, String> {
    let resolve = |input: &str, unresolved: &mut HashSet<String>| {
        replace_variables(input, variables, unresolved)
    };
    match draft.body_type.as_str() {
        "none" => Ok(PreparedDraftBody {
            bytes: Vec::new(),
            content_type: None,
            force_content_type: false,
            snapshot: Value::String(String::new()),
        }),
        "json" | "text" | "xml" | "raw" => {
            let body = resolve(&draft.body, unresolved);
            if draft.body_type == "json" {
                serde_json::from_str::<Value>(&body)
                    .map_err(|error| format!("JSON 正文无效: {error}"))?;
            }
            let content_type = match draft.body_type.as_str() {
                "json" => Some("application/json".to_string()),
                "text" => Some("text/plain; charset=utf-8".to_string()),
                "xml" => Some("application/xml".to_string()),
                _ => None,
            };
            checked_request_body(PreparedDraftBody {
                bytes: body.as_bytes().to_vec(),
                content_type,
                force_content_type: false,
                snapshot: Value::String(body),
            })
        }
        "urlencoded" => {
            let fields = parse_draft_body_fields(&draft.body)?;
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            for field in fields.into_iter().filter(|field| field.enabled) {
                if field.kind != "text" {
                    return Err("Urlencode 正文只支持文本字段".to_string());
                }
                let name = resolve(&field.name, unresolved);
                let value = resolve(&field.value, unresolved);
                encoded.append_pair(&name, &value);
            }
            let encoded = encoded.finish();
            checked_request_body(PreparedDraftBody {
                bytes: encoded.as_bytes().to_vec(),
                content_type: Some("application/x-www-form-urlencoded".to_string()),
                force_content_type: false,
                snapshot: Value::String(encoded),
            })
        }
        "form-data" => {
            let fields = parse_draft_body_fields(&draft.body)?;
            if fields.iter().filter(|field| field.enabled).count() > 100 {
                return Err("Form-data 最多包含 100 个启用字段".to_string());
            }
            let boundary = format!("shownet-{}", uuid::Uuid::new_v4().simple());
            let mut resolved = Vec::new();
            let mut snapshot = Vec::new();
            for field in fields.into_iter().filter(|field| field.enabled) {
                let name = resolve(&field.name, unresolved);
                if name.is_empty() {
                    return Err("Form-data 字段名称不能为空".to_string());
                }
                if field.kind == "file" {
                    let path = resolve(field.file_path.as_deref().unwrap_or_default(), unresolved);
                    let file_name = field.file_name.unwrap_or_else(|| {
                        std::path::Path::new(&path)
                            .file_name()
                            .and_then(|value| value.to_str())
                            .unwrap_or("file")
                            .to_string()
                    });
                    let content_type = field
                        .content_type
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or_else(|| "application/octet-stream".to_string());
                    resolved.push((
                        name.clone(),
                        Some((path.clone(), file_name.clone(), content_type.clone())),
                        String::new(),
                    ));
                    snapshot.push(json!({"name":name,"kind":"file","filePath":path,"fileName":file_name,"contentType":content_type}));
                } else if field.kind == "text" {
                    let value = resolve(&field.value, unresolved);
                    resolved.push((name.clone(), None, value.clone()));
                    snapshot.push(json!({"name":name,"kind":"text","value":value}));
                } else {
                    return Err(format!("Form-data 字段类型无效: {}", field.kind));
                }
            }
            reject_unresolved(unresolved)?;
            let mut bytes = Vec::new();
            for (name, file, value) in resolved {
                append_multipart_boundary(&mut bytes, &boundary);
                if let Some((path, file_name, content_type)) = file {
                    let file_bytes = read_request_body_file(&path)?;
                    bytes.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
                            escape_multipart_parameter(&name),
                            escape_multipart_parameter(&file_name),
                            content_type
                        )
                        .as_bytes(),
                    );
                    bytes.extend_from_slice(&file_bytes);
                    bytes.extend_from_slice(b"\r\n");
                } else {
                    bytes.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"{}\"\r\n\r\n{}\r\n",
                            escape_multipart_parameter(&name),
                            value
                        )
                        .as_bytes(),
                    );
                }
                if bytes.len() > MAX_REQUEST_BODY_BYTES {
                    return Err("请求正文超过 2 MiB 上限".to_string());
                }
            }
            bytes.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
            checked_request_body(PreparedDraftBody {
                bytes,
                content_type: Some(format!("multipart/form-data; boundary={boundary}")),
                force_content_type: true,
                snapshot: Value::Array(snapshot),
            })
        }
        "file" => {
            let file: DraftFileBody = serde_json::from_str(&draft.body)
                .map_err(|error| format!("文件正文配置无效: {error}"))?;
            let path = resolve(&file.file_path, unresolved);
            reject_unresolved(unresolved)?;
            let bytes = read_request_body_file(&path)?;
            let file_name = file.file_name.unwrap_or_else(|| {
                std::path::Path::new(&path)
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("file")
                    .to_string()
            });
            let content_type = file
                .content_type
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "application/octet-stream".to_string());
            checked_request_body(PreparedDraftBody {
                bytes,
                content_type: Some(content_type.clone()),
                force_content_type: false,
                snapshot: json!({"kind":"file","filePath":path,"fileName":file_name,"contentType":content_type}),
            })
        }
        other => Err(format!("请求正文类型无效: {other}")),
    }
}

fn parse_draft_body_fields(body: &str) -> Result<Vec<DraftBodyField>, String> {
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    if body.trim_start().starts_with('[') {
        return serde_json::from_str(body).map_err(|error| format!("结构化正文无效: {error}"));
    }
    Ok(body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (name, value) = line.split_once('=').unwrap_or((line, ""));
            DraftBodyField {
                name: name.trim().to_string(),
                value: value.to_string(),
                kind: "text".to_string(),
                file_path: None,
                file_name: None,
                content_type: None,
                enabled: true,
            }
        })
        .collect())
}

fn reject_unresolved(unresolved: &HashSet<String>) -> Result<(), String> {
    if unresolved.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "存在未定义变量: {}",
            unresolved.iter().cloned().collect::<Vec<_>>().join(", ")
        ))
    }
}

fn read_request_body_file(path: &str) -> Result<Vec<u8>, String> {
    let metadata = std::fs::metadata(path).map_err(|error| format!("无法读取正文文件: {error}"))?;
    if !metadata.is_file() {
        return Err("正文文件路径不是普通文件".to_string());
    }
    if metadata.len() > MAX_REQUEST_BODY_BYTES as u64 {
        return Err("正文文件超过 2 MiB 上限".to_string());
    }
    std::fs::read(path).map_err(|error| format!("无法读取正文文件: {error}"))
}

fn checked_request_body(body: PreparedDraftBody) -> Result<PreparedDraftBody, String> {
    if body.bytes.len() > MAX_REQUEST_BODY_BYTES {
        Err("请求正文超过 2 MiB 上限".to_string())
    } else {
        Ok(body)
    }
}

fn append_multipart_boundary(bytes: &mut Vec<u8>, boundary: &str) {
    bytes.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
}

fn escape_multipart_parameter(value: &str) -> String {
    value
        .replace(['\r', '\n'], "")
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn resolve_draft_auth(
    value: &Value,
    variables: &HashMap<String, (String, bool)>,
    unresolved: &mut HashSet<String>,
) -> Value {
    match value {
        Value::String(value) => Value::String(replace_variables(value, variables, unresolved)),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| resolve_draft_auth(value, variables, unresolved))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        resolve_draft_auth(value, variables, unresolved),
                    )
                })
                .collect(),
        ),
        value => value.clone(),
    }
}

fn apply_draft_auth(
    auth: &Value,
    url: &mut String,
    headers: &mut Vec<HeaderEntry>,
) -> Result<(), String> {
    match auth.get("kind").and_then(Value::as_str).unwrap_or("none") {
        "none" => Ok(()),
        "basic" => {
            let username = auth
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let password = auth
                .get("password")
                .and_then(Value::as_str)
                .ok_or_else(|| "Basic Auth 密码缺失".to_string())?;
            headers.retain(|header| !header.name.eq_ignore_ascii_case("authorization"));
            headers.push(HeaderEntry {
                name: "Authorization".to_string(),
                value: format!(
                    "Basic {}",
                    STANDARD.encode(format!("{username}:{password}"))
                ),
            });
            Ok(())
        }
        "bearer" => {
            let token = auth
                .get("token")
                .and_then(Value::as_str)
                .ok_or_else(|| "Bearer Token 缺失".to_string())?;
            headers.retain(|header| !header.name.eq_ignore_ascii_case("authorization"));
            headers.push(HeaderEntry {
                name: "Authorization".to_string(),
                value: format!("Bearer {token}"),
            });
            Ok(())
        }
        "api-key" => {
            let name = auth
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("X-API-Key");
            let value = auth
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| "API Key 值缺失".to_string())?;
            let location = auth
                .get("location")
                .and_then(Value::as_str)
                .unwrap_or("header");
            if location == "query" {
                *url = set_query_parameter(url, name, value)?;
                return Ok(());
            }
            if location != "header" {
                return Err("API Key 位置仅支持 Header 或 Query".to_string());
            }
            headers.retain(|header| !header.name.eq_ignore_ascii_case(name));
            headers.push(HeaderEntry {
                name: name.to_string(),
                value: value.to_string(),
            });
            Ok(())
        }
        kind => Err(format!("Request Lab Auth 类型无效: {kind}")),
    }
}

fn set_query_parameter(input: &str, name: &str, value: &str) -> Result<String, String> {
    if name.trim().is_empty() {
        return Err("API Key 名称不能为空".to_string());
    }
    let mut url = url::Url::parse(input).map_err(|_| "API Key 需要有效的请求 URL".to_string())?;
    let retained = url
        .query_pairs()
        .filter(|(existing, _)| !existing.eq_ignore_ascii_case(name))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in retained {
            query.append_pair(&key, &value);
        }
        query.append_pair(name, value);
    }
    Ok(url.into())
}

fn replace_variables(
    input: &str,
    variables: &HashMap<String, (String, bool)>,
    unresolved: &mut HashSet<String>,
) -> String {
    let expression =
        regex::Regex::new(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\}\}").expect("static regex");
    expression
        .replace_all(input, |captures: &regex::Captures<'_>| {
            let name = &captures[1];
            match variables.get(name) {
                Some((value, _secret)) => value.clone(),
                None => {
                    unresolved.insert(name.to_string());
                    captures[0].to_string()
                }
            }
        })
        .into_owned()
}

fn build_client(
    state: &AppState,
    settings: &ReplaySettings,
    target: &str,
    cookie_jar: Option<Arc<CookieStoreMutex>>,
) -> Result<reqwest::Client, String> {
    let redirect = if settings.follow_redirects {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .redirect(redirect)
        .danger_accept_invalid_certs(!settings.verify_tls);
    if let Some(cookie_jar) = cookie_jar {
        builder = builder.cookie_provider(cookie_jar);
    }
    if settings.through_capture {
        let capture = state
            .capture
            .lock()
            .map_err(|_| "抓包运行状态已损坏".to_string())?;
        let address = capture
            .listen_address
            .ok_or_else(|| "当前抓包监听未启动".to_string())?;
        builder = builder.proxy(
            reqwest::Proxy::all(format!("http://127.0.0.1:{}", address.port()))
                .map_err(|error| error.to_string())?,
        );
    } else if settings.use_upstream_proxy {
        let upstream = state.storage.effective_upstream_proxy()?;
        if upstream.mode != "direct" {
            let scheme = if upstream.mode == "socks5" {
                "socks5h"
            } else {
                upstream.mode.as_str()
            };
            let mut proxy =
                reqwest::Proxy::all(format!("{scheme}://{}:{}", upstream.host, upstream.port))
                    .map_err(|error| format!("出口代理配置无效: {error}"))?;
            if !upstream.username.is_empty() {
                proxy = proxy.basic_auth(
                    &upstream.username,
                    upstream.password.as_deref().unwrap_or_default(),
                );
            }
            builder = builder.proxy(proxy);
        }
    }
    let _ = target;
    builder
        .build()
        .map_err(|error| format!("创建重放网络客户端失败: {error}"))
}

pub fn sanitize_headers(
    headers: &[HeaderEntry],
    include_cookie: bool,
    include_authorization: bool,
    body_len: usize,
) -> Vec<HeaderEntry> {
    let mut blocked = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect::<HashSet<_>>();
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
    {
        blocked.extend(
            header
                .value
                .split(',')
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty()),
        );
    }
    let mut result = headers
        .iter()
        .filter(|header| {
            let name = header.name.trim().to_ascii_lowercase();
            !name.is_empty()
                && !blocked.contains(&name)
                && name != "content-length"
                && name != "host"
                && (include_cookie || name != "cookie")
                && (include_authorization || name != "authorization")
                && name != REPLAY_CONTEXT_HEADER
        })
        .cloned()
        .collect::<Vec<_>>();
    if body_len > 0 {
        result.push(HeaderEntry {
            name: "Content-Length".to_string(),
            value: body_len.to_string(),
        });
    }
    result
}

async fn read_response(
    response: reqwest::Response,
) -> Result<(String, BodyCaptureMetadata), String> {
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    let mut wire_bytes = 0usize;
    let mut truncated = false;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("读取重放响应失败: {error}"))?;
        wire_bytes = wire_bytes.saturating_add(chunk.len());
        let remaining = MAX_RESPONSE_BYTES.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining {
            truncated = true;
        }
    }
    let textual = content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("xml")
        || content_type.contains("javascript")
        || content_type.is_empty();
    let (body, format) = if textual {
        (String::from_utf8_lossy(&bytes).into_owned(), "text")
    } else {
        (STANDARD.encode(&bytes), "base64")
    };
    Ok((
        body,
        BodyCaptureMetadata {
            captured: true,
            content_encoding: None,
            decoded: true,
            truncated,
            complete: !truncated,
            wire_bytes: wire_bytes as i64,
            decoded_bytes: bytes.len() as i64,
            format: format.to_string(),
            error: None,
            omitted_reason: None,
        },
    ))
}

fn request_url(
    scheme: &str,
    host: &str,
    port: Option<i64>,
    path: &str,
    query: Option<&str>,
) -> Result<String, String> {
    let default_port =
        (scheme == "http" && port == Some(80)) || (scheme == "https" && port == Some(443));
    let authority = match port.filter(|_| !default_port) {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let url = format!(
        "{scheme}://{authority}{path}{}",
        query.map(|value| format!("?{value}")).unwrap_or_default()
    );
    reqwest::Url::parse(&url).map_err(|error| format!("来源请求 URL 无效: {error}"))?;
    Ok(url)
}

fn response_snapshot_headers(headers: &reqwest::header::HeaderMap) -> Vec<Value> {
    headers
        .iter()
        .map(|(name, value)| {
            json!({
                "name": name.as_str(),
                "value": value.to_str().unwrap_or("<binary>")
            })
        })
        .collect()
}

fn emit_replay_batch(app: &tauri::AppHandle, batch_id: &str) -> Result<(), String> {
    let state = app.state::<AppState>();
    let batch = state.storage.get_replay_batch(batch_id)?;
    emit(app, "replay://batch-updated", &batch)
}

fn emit_replay_batch_item(
    app: &tauri::AppHandle,
    item_id: &str,
    phase: &str,
) -> Result<(), String> {
    app.emit("replay://item", json!({"itemId":item_id,"phase":phase}))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn draft(url: &str) -> RequestDraft {
        RequestDraft {
            id: "draft-test".to_string(),
            session_id: None,
            source_request_id: None,
            spec_operation_key: None,
            spec_fingerprint: None,
            name: "Dynamic variables".to_string(),
            method: "POST".to_string(),
            url: url.to_string(),
            headers: vec![HeaderEntry {
                name: "X-Request-Id".to_string(),
                value: "{{uuid}}".to_string(),
            }],
            body: r#"{"at":"{{iso_datetime}}","token":"{{token}}"}"#.to_string(),
            body_type: "json".to_string(),
            auth: json!({"kind":"none"}),
            settings: json!({}),
            environment_id: None,
            collection_id: None,
            folder_id: None,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn removes_hop_by_hop_sensitive_and_internal_headers() {
        let headers = vec![
            HeaderEntry {
                name: "Connection".into(),
                value: "keep-alive, X-Debug".into(),
            },
            HeaderEntry {
                name: "X-Debug".into(),
                value: "remove".into(),
            },
            HeaderEntry {
                name: "Cookie".into(),
                value: "sid=secret".into(),
            },
            HeaderEntry {
                name: "Authorization".into(),
                value: "Bearer secret".into(),
            },
            HeaderEntry {
                name: REPLAY_CONTEXT_HEADER.into(),
                value: "internal".into(),
            },
            HeaderEntry {
                name: "Accept".into(),
                value: "application/json".into(),
            },
        ];
        assert_eq!(
            sanitize_headers(&headers, false, false, 4),
            vec![
                HeaderEntry {
                    name: "Accept".into(),
                    value: "application/json".into()
                },
                HeaderEntry {
                    name: "Content-Length".into(),
                    value: "4".into()
                }
            ]
        );
    }

    #[test]
    fn collection_defaults_are_merged_with_request_level_precedence() {
        let collection = RequestCollection {
            id: "collection-shop".into(),
            name: "Shop API".into(),
            description: String::new(),
            default_headers: vec![
                HeaderEntry {
                    name: "X-Tenant".into(),
                    value: "{{tenant}}".into(),
                },
                HeaderEntry {
                    name: "X-Trace".into(),
                    value: "collection".into(),
                },
            ],
            default_auth: json!({"kind":"bearer","token":"collection-secret"}),
            default_environment_id: Some("environment-staging".into()),
            source_format: None,
            source_path: None,
            source_fingerprint: None,
            source_synced_at: None,
            sort_order: 0,
            draft_count: 1,
            folder_count: 0,
            created_at: 0,
            updated_at: 0,
        };
        let mut input = draft("https://api.example.test/orders");
        input.collection_id = Some(collection.id.clone());
        input.headers = vec![HeaderEntry {
            name: "x-trace".into(),
            value: "request".into(),
        }];

        assert!(collection_inheritance_enabled(&input));
        let (effective, summary) = apply_collection_defaults(&input, Some(&collection));
        assert_eq!(effective.headers.len(), 2);
        assert_eq!(effective.headers[0].name, "X-Tenant");
        assert_eq!(effective.headers[1].value, "request");
        assert_eq!(effective.auth["token"], "collection-secret");
        assert_eq!(
            effective.environment_id.as_deref(),
            Some("environment-staging")
        );
        assert_eq!(summary.unwrap()["headerCount"], 1);

        input.auth = json!({"kind":"api-key","name":"X-Key","value":"request-secret"});
        input.environment_id = Some("environment-local".into());
        let (effective, _) = apply_collection_defaults(&input, Some(&collection));
        assert_eq!(effective.auth["kind"], "api-key");
        assert_eq!(
            effective.environment_id.as_deref(),
            Some("environment-local")
        );

        input.settings = json!({"inheritCollection":false});
        assert!(!collection_inheritance_enabled(&input));
    }

    #[test]
    fn variable_resolution_preserves_secrets_and_reports_missing_values() {
        let variables = HashMap::from([
            ("host".to_string(), ("api.example".to_string(), false)),
            ("token".to_string(), ("secret".to_string(), true)),
        ]);
        let mut unresolved = HashSet::new();
        assert_eq!(
            replace_variables(
                "{{host}}/{{token}}/{{missing}}",
                &variables,
                &mut unresolved
            ),
            "api.example/secret/{{missing}}"
        );
        assert!(unresolved.contains("missing"));
    }

    #[test]
    fn prepares_dynamic_variables_once_and_preserves_resolved_values_in_history() {
        let prepared = prepare_draft(
            &draft("https://api.example.test/{{timestamp}}?ms={{timestamp_ms}}&iso={{iso_datetime}}&uuid={{uuid}}"),
            &[("token".to_string(), "environment-secret".to_string(), true)],
        )
        .unwrap();
        let url = reqwest::Url::parse(&prepared.url).unwrap();
        let timestamp = url.path().trim_start_matches('/').parse::<i64>().unwrap();
        let query = url.query_pairs().into_owned().collect::<HashMap<_, _>>();
        let timestamp_ms = query["ms"].parse::<i64>().unwrap();
        let iso = chrono::DateTime::parse_from_rfc3339(&query["iso"]).unwrap();
        let uuid = uuid::Uuid::parse_str(&query["uuid"]).unwrap();

        assert!((timestamp_ms / 1_000 - timestamp).abs() <= 1);
        assert_eq!(iso.timestamp(), timestamp);
        assert_eq!(prepared.headers[0].value, uuid.to_string());
        let body = String::from_utf8(prepared.body).unwrap();
        assert!(body.contains(&query["iso"]));
        assert!(body.contains("environment-secret"));
        let snapshot = serde_json::to_string(&prepared.snapshot).unwrap();
        assert!(snapshot.contains("environment-secret"));
    }

    #[test]
    fn resolves_auth_and_header_name_variables_into_complete_history() {
        let mut input = draft("https://api.example.test/account");
        input.headers = vec![HeaderEntry {
            name: "{{trace_header}}".into(),
            value: "{{trace_id}}".into(),
        }];
        input.auth = json!({"kind":"bearer","token":"{{token}}"});
        let prepared = prepare_draft(
            &input,
            &[
                ("trace_header".into(), "X-Trace-Id".into(), false),
                ("trace_id".into(), "trace-123".into(), false),
                ("token".into(), "private-bearer-token".into(), true),
            ],
        )
        .unwrap();
        assert!(prepared
            .headers
            .iter()
            .any(|header| { header.name == "X-Trace-Id" && header.value == "trace-123" }));
        assert!(prepared.headers.iter().any(|header| {
            header.name == "Authorization" && header.value == "Bearer private-bearer-token"
        }));
        let snapshot = serde_json::to_string(&prepared.snapshot).unwrap();
        assert!(snapshot.contains("Bearer private-bearer-token"));
    }

    #[test]
    fn applies_query_api_key_once_and_preserves_it_in_history() {
        let mut input = draft("https://api.example.test/items?stable=1&api_key=old");
        input.body = "{}".to_string();
        input.auth = json!({
            "kind":"api-key",
            "name":"api_key",
            "value":"{{api_key}}",
            "location":"query"
        });
        let prepared = prepare_draft(
            &input,
            &[("api_key".into(), "query-secret-value".into(), true)],
        )
        .unwrap();
        let query = url::Url::parse(&prepared.url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect::<Vec<_>>();
        assert_eq!(
            query.iter().filter(|(name, _)| name == "api_key").count(),
            1
        );
        assert!(query.contains(&("stable".into(), "1".into())));
        assert!(query.contains(&("api_key".into(), "query-secret-value".into())));
        let snapshot = serde_json::to_string(&prepared.snapshot).unwrap();
        assert!(snapshot.contains("query-secret-value"));
        assert!(snapshot.contains("api_key"));
    }

    #[test]
    fn preserves_response_headers_before_history_storage() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=private-cookie-value; Path=/; HttpOnly"),
        );
        headers.insert("x-trace-id", HeaderValue::from_static("trace-123"));

        let snapshot = serde_json::to_string(&response_snapshot_headers(&headers)).unwrap();
        assert!(snapshot.contains("private-cookie-value"));
        assert!(snapshot.contains("trace-123"));
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_collection_defaults_reach_target_after_variable_resolution() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        });

        let collection = RequestCollection {
            id: "collection-shop".into(),
            name: "Shop API".into(),
            description: String::new(),
            default_headers: vec![HeaderEntry {
                name: "X-Tenant".into(),
                value: "{{tenant}}".into(),
            }],
            default_auth: json!({"kind":"bearer","token":"{{token}}"}),
            default_environment_id: Some("environment-staging".into()),
            source_format: None,
            source_path: None,
            source_fingerprint: None,
            source_synced_at: None,
            sort_order: 0,
            draft_count: 1,
            folder_count: 0,
            created_at: 0,
            updated_at: 0,
        };
        let mut input = draft(&format!("http://{address}/orders"));
        input.method = "GET".into();
        input.body.clear();
        input.body_type = "none".into();
        input.headers.clear();
        input.collection_id = Some(collection.id.clone());

        let (effective, inheritance) = apply_collection_defaults(&input, Some(&collection));
        assert_eq!(
            effective.environment_id.as_deref(),
            Some("environment-staging")
        );
        let mut prepared = prepare_draft(
            &effective,
            &[
                ("tenant".into(), "north".into(), false),
                ("token".into(), "collection-auth-secret".into(), true),
            ],
        )
        .unwrap();
        prepared.snapshot["inheritance"] = inheritance.unwrap();

        let client = reqwest::Client::new();
        let mut request = client.get(&prepared.url);
        for header in &prepared.headers {
            request = request.header(&header.name, &header.value);
        }
        assert_eq!(
            request.send().await.unwrap().status(),
            reqwest::StatusCode::NO_CONTENT
        );

        let received = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request_header(&received, "x-tenant"), Some("north"));
        assert_eq!(
            request_header(&received, "authorization"),
            Some("Bearer collection-auth-secret")
        );
        let history = serde_json::to_string(&prepared.snapshot).unwrap();
        assert!(history.contains("collection-auth-secret"));
        assert!(history.contains("collection-shop"));
    }

    #[tokio::test]
    #[ignore = "requires local socket permissions"]
    async fn local_socket_cookie_jar_round_trip_respects_disable_and_explicit_override() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for index in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let read = socket.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..read]);
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                requests.push(String::from_utf8_lossy(&bytes).into_owned());
                let set_cookie = if index == 0 {
                    "Set-Cookie: session=stored; Path=/; HttpOnly\r\n"
                } else {
                    ""
                };
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n{set_cookie}\r\nok"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
            requests
        });

        let url = format!("http://{address}/cookie-check");
        let jar = Arc::new(CookieStoreMutex::new(cookie_store::CookieStore::default()));
        let jar_client = reqwest::Client::builder()
            .cookie_provider(Arc::clone(&jar))
            .build()
            .unwrap();
        jar_client
            .get(&url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        jar_client
            .get(&url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        jar_client
            .get(&url)
            .header(reqwest::header::COOKIE, "session=manual")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        let requests = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request_header(&requests[0], "cookie"), None);
        assert_eq!(
            request_header(&requests[1], "cookie"),
            Some("session=stored")
        );
        assert_eq!(request_header(&requests[2], "cookie"), None);
        assert_eq!(
            request_header(&requests[3], "cookie"),
            Some("session=manual")
        );
    }

    #[test]
    fn encodes_urlencoded_fields_and_sets_content_headers() {
        let mut input = draft("https://api.example.test/submit");
        input.body_type = "urlencoded".to_string();
        input.body = serde_json::json!([
            {"name":"tag","value":"one","kind":"text","enabled":true},
            {"name":"tag","value":"two words","kind":"text","enabled":true},
            {"name":"skip","value":"no","kind":"text","enabled":false}
        ])
        .to_string();
        let prepared = prepare_draft(&input, &[]).unwrap();
        assert_eq!(
            String::from_utf8(prepared.body.clone()).unwrap(),
            "tag=one&tag=two+words"
        );
        assert!(prepared.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type")
                && header.value == "application/x-www-form-urlencoded"
        }));
        assert!(prepared.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-length")
                && header.value == prepared.body.len().to_string()
        }));
    }

    #[test]
    fn encodes_multipart_text_and_file_parts_without_leaking_paths_to_history() {
        let path = std::env::temp_dir().join(format!("shownet-body-{}.bin", uuid::Uuid::new_v4()));
        std::fs::write(&path, [0_u8, 1, 2, 255]).unwrap();
        let mut input = draft("https://api.example.test/upload");
        input.body_type = "form-data".to_string();
        input.body = serde_json::json!([
            {"name":"message","value":"{{token}}","kind":"text","enabled":true},
            {"name":"asset","kind":"file","filePath":path.to_string_lossy(),"fileName":"sample.bin","contentType":"application/octet-stream","enabled":true}
        ])
        .to_string();
        let prepared = prepare_draft(
            &input,
            &[("token".to_string(), "multipart-secret".to_string(), true)],
        )
        .unwrap();
        let content_type = prepared
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .map(|header| header.value.clone())
            .unwrap();
        assert!(content_type.starts_with("multipart/form-data; boundary=shownet-"));
        assert!(prepared
            .body
            .windows("multipart-secret".len())
            .any(|window| window == b"multipart-secret"));
        assert!(prepared
            .body
            .windows("sample.bin".len())
            .any(|window| window == b"sample.bin"));
        assert!(prepared
            .body
            .windows(4)
            .any(|window| window == [0, 1, 2, 255]));
        let snapshot = serde_json::to_string(&prepared.snapshot).unwrap();
        assert!(snapshot.contains("multipart-secret"));
        assert!(snapshot.contains(path.to_string_lossy().as_ref()));
        assert!(snapshot.contains("sample.bin"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reads_file_body_as_bytes_and_preserves_file_history() {
        let path = std::env::temp_dir().join(format!("shownet-raw-{}.bin", uuid::Uuid::new_v4()));
        std::fs::write(&path, [9_u8, 8, 7, 6]).unwrap();
        let mut input = draft("https://api.example.test/file");
        input.body_type = "file".to_string();
        input.body = serde_json::json!({
            "filePath":path.to_string_lossy(),
            "fileName":"payload.bin",
            "contentType":"application/custom"
        })
        .to_string();
        let prepared = prepare_draft(&input, &[]).unwrap();
        assert_eq!(prepared.body, vec![9, 8, 7, 6]);
        assert!(prepared.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type") && header.value == "application/custom"
        }));
        let snapshot = serde_json::to_string(&prepared.snapshot).unwrap();
        assert!(snapshot.contains(path.to_string_lossy().as_ref()));
        assert!(snapshot.contains("payload.bin"));
        assert!(snapshot.contains("CQgHBg=="));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn cancellation_signal_interrupts_a_pending_operation() {
        let (sender, mut receiver) = tokio::sync::watch::channel(false);
        let pending = tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(30)) => false,
                _ = wait_for_cancellation(&mut receiver) => true,
            }
        });
        sender.send(true).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap());
    }

    #[tokio::test]
    async fn batch_cancellation_interrupts_delays_and_running_network_waits() {
        let cancellation = Arc::new(AtomicBool::new(false));
        let pending = {
            let cancellation = cancellation.clone();
            tokio::spawn(
                async move { sleep_or_cancel(Duration::from_secs(30), &cancellation).await },
            )
        };
        cancellation.store(true, Ordering::SeqCst);
        assert!(tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap());
    }

    fn request_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        request.lines().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}
