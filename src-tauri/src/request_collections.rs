use crate::models::{
    CollectionImportEnvironment, CollectionImportEnvironmentVariable, CollectionImportItem,
    CollectionImportMetadata, CollectionImportPreview, HeaderEntry, RequestCollection,
    RequestCollectionFolder, RequestDraft,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use url::Url;

const MAX_IMPORT_BYTES: u64 = 10 * 1024 * 1024;
const MAX_IMPORT_ITEMS: usize = 1_000;
const MAX_IMPORT_ENVIRONMENTS: usize = 50;
const MAX_IMPORT_ENVIRONMENT_VARIABLES: usize = 1_000;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_SOURCE_KEY_CHARS: usize = 1_000;
const IMPORT_SOURCE_AUTH_KEY: &str = "_shownetImportedAuth";
const IMPORT_SOURCE_COMPONENTS_KEY: &str = "_shownetImportedComponents";

struct ImportBuilder {
    items: Vec<CollectionImportItem>,
    collection: Option<CollectionImportMetadata>,
    environments: Vec<CollectionImportEnvironment>,
    warnings: Vec<String>,
}

impl ImportBuilder {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            collection: None,
            environments: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    fn push(&mut self, item: CollectionImportItem) {
        if self.items.len() >= MAX_IMPORT_ITEMS {
            self.warn(format!("导入上限为 {MAX_IMPORT_ITEMS} 条，其余请求已跳过"));
            return;
        }
        match normalize_import_item(item) {
            Ok(item) => self.items.push(item),
            Err(error) => self.warn(error),
        }
    }

    fn set_environments(&mut self, environments: Vec<CollectionImportEnvironment>) {
        self.environments = environments;
    }

    fn set_collection(&mut self, collection: CollectionImportMetadata) {
        self.collection = Some(collection);
    }

    fn finish(mut self, source_format: &str, suggested_name: String) -> CollectionImportPreview {
        let mut seen = HashSet::new();
        self.warnings.retain(|warning| seen.insert(warning.clone()));
        CollectionImportPreview {
            source_format: source_format.to_string(),
            suggested_name,
            items: self.items,
            collection: self.collection,
            environments: self.environments,
            warnings: self.warnings,
            source_path: None,
            source_fingerprint: None,
        }
    }
}

pub fn preview_import_path(path: &str) -> Result<CollectionImportPreview, String> {
    let path = Path::new(path);
    let metadata = fs::metadata(path).map_err(|error| format!("读取集合文件失败: {error}"))?;
    if !metadata.is_file() {
        return Err("请选择集合文件".to_string());
    }
    if metadata.len() > MAX_IMPORT_BYTES {
        return Err("集合文件不能超过 10 MiB".to_string());
    }
    let content = fs::read_to_string(path).map_err(|error| format!("读取集合文件失败: {error}"))?;
    let value = serde_json::from_str::<Value>(&content)
        .or_else(|_| serde_yaml::from_str::<Value>(&content))
        .map_err(|error| format!("集合文件不是有效的 JSON 或 YAML: {error}"))?;
    let fallback_name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("导入的请求")
        .trim()
        .to_string();

    if value
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .is_some()
    {
        return parse_har(&value, fallback_name);
    }
    if value.get("format").and_then(Value::as_str) == Some("shownet-request-collection")
        && value.get("requests").and_then(Value::as_array).is_some()
    {
        return parse_shownet(&value, fallback_name);
    }
    if value.get("resources").and_then(Value::as_array).is_some()
        && (value.get("_type").and_then(Value::as_str) == Some("export")
            || value.get("__export_format").is_some())
    {
        return parse_insomnia(&value, fallback_name);
    }
    if value.get("openapi").is_some() || value.get("swagger").is_some() {
        let mut preview = parse_openapi(&value, fallback_name)?;
        preview.source_path = Some(path.to_string_lossy().to_string());
        preview.source_fingerprint = Some(json_fingerprint(&value));
        return Ok(preview);
    }
    if value.get("item").and_then(Value::as_array).is_some() {
        return parse_postman(&value, fallback_name);
    }
    Err(
        "暂不识别该集合格式；支持浏览器 HAR、Postman 2.x、Insomnia、OpenAPI/Swagger 和 ShowNet JSON"
            .to_string(),
    )
}

pub fn normalize_import_item(
    mut item: CollectionImportItem,
) -> Result<CollectionImportItem, String> {
    item.name = clean_name(&item.name, "未命名请求", 120);
    item.method = item.method.trim().to_uppercase();
    if item.method.is_empty()
        || item.method.len() > 20
        || !item
            .method
            .chars()
            .all(|character| character.is_ascii_alphabetic() || character == '-')
    {
        return Err(format!("“{}”请求方法无效，已跳过", item.name));
    }
    if item.headers.len() > 200 {
        item.headers.truncate(200);
    }
    item.url = validate_import_url(&item.url)?;
    if item.body.len() > MAX_BODY_BYTES {
        return Err(format!("“{}”正文超过 2 MiB，已跳过", item.name));
    }
    if !matches!(
        item.body_type.as_str(),
        "none" | "json" | "text" | "xml" | "raw" | "form-data" | "urlencoded" | "file"
    ) {
        item.body_type = "raw".to_string();
    }
    if !item.auth.is_object() {
        item.auth = json!({"kind":"none"});
    }
    if item.settings.is_null() {
        item.settings = default_request_settings();
    }
    item.environment_id = item
        .environment_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let mut seen_tags = HashSet::new();
    item.tags = item
        .tags
        .into_iter()
        .map(|tag| clean_name(&tag, "", 40))
        .filter(|tag| !tag.is_empty() && seen_tags.insert(tag.to_ascii_lowercase()))
        .take(20)
        .collect();
    item.folder_path = item
        .folder_path
        .into_iter()
        .map(|name| clean_name(&name, "文件夹", 80))
        .filter(|name| !name.is_empty())
        .take(4)
        .collect();
    if let Some(source_key) = item.source_key.as_mut() {
        *source_key = source_key.trim().to_string();
        if source_key.is_empty() || source_key.chars().count() > MAX_SOURCE_KEY_CHARS {
            return Err(format!("“{}”的规范 operation key 无效，已跳过", item.name));
        }
        item.source_fingerprint = Some(import_item_fingerprint(&item));
    } else {
        item.source_fingerprint = None;
    }
    Ok(item)
}

pub fn import_item_fingerprint(item: &CollectionImportItem) -> String {
    let mut headers = item.headers.clone();
    headers.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
            .then_with(|| left.value.cmp(&right.value))
    });
    let body = canonical_import_body(&item.body, &item.body_type);
    let canonical = json!({
        "name": item.name.trim(),
        "method": item.method.trim().to_uppercase(),
        "url": item.url.trim(),
        "headers": headers,
        "body": body,
        "bodyType": item.body_type,
        "auth": item.auth,
        "settings": item.settings,
        "environmentId": item.environment_id,
        "tags": item.tags,
        "folderPath": item.folder_path,
    });
    json_fingerprint(&canonical)
}

fn default_request_settings() -> Value {
    json!({"cookieJar":false,"followRedirects":true,"verifyTls":true})
}

fn imported_settings(
    settings: Option<&Value>,
    source_format: &str,
    source_auth: Option<&Value>,
    source_components: Option<Value>,
) -> Value {
    let mut value = settings.cloned().unwrap_or_else(default_request_settings);
    if source_auth.is_none() && source_components.is_none() {
        return value;
    }
    if !value.is_object() {
        value = json!({"_shownetOriginalSettings":value});
    }
    let settings = value.as_object_mut().expect("settings object");
    if let Some(source_auth) = source_auth {
        settings.insert(
            IMPORT_SOURCE_AUTH_KEY.to_string(),
            json!({"format":source_format,"value":source_auth}),
        );
    }
    if let Some(source_components) = source_components {
        settings.insert(IMPORT_SOURCE_COMPONENTS_KEY.to_string(), source_components);
    }
    value
}

fn imported_disabled_components<F>(
    source_format: &str,
    headers: Option<&Value>,
    query: Option<&Value>,
    mut resolve: F,
) -> Option<Value>
where
    F: FnMut(&str) -> String,
{
    let mut disabled_entries = |value: Option<&Value>| {
        value
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| entry.get("disabled").and_then(Value::as_bool) == Some(true))
            .filter_map(|entry| {
                let name = entry
                    .get("key")
                    .or_else(|| entry.get("name"))
                    .and_then(Value::as_str)?
                    .trim();
                if name.is_empty() {
                    return None;
                }
                let raw_value = entry.get("value").map(value_to_string).unwrap_or_default();
                Some(json!({"name":name,"value":resolve(&raw_value)}))
            })
            .collect::<Vec<_>>()
    };
    let disabled_headers = disabled_entries(headers);
    let disabled_query = disabled_entries(query);
    (!disabled_headers.is_empty() || !disabled_query.is_empty()).then(|| {
        json!({
            "format": source_format,
            "disabledHeaders": disabled_headers,
            "disabledQuery": disabled_query
        })
    })
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn parse_portable_environments(
    value: Option<&Value>,
    builder: &mut ImportBuilder,
) -> Vec<CollectionImportEnvironment> {
    let mut environments = Vec::new();
    let mut source_ids = HashSet::new();
    for environment in value.and_then(Value::as_array).into_iter().flatten() {
        if environments.len() >= MAX_IMPORT_ENVIRONMENTS {
            builder.warn(format!(
                "环境导入上限为 {MAX_IMPORT_ENVIRONMENTS} 个，其余环境已跳过"
            ));
            break;
        }
        let source_id = environment
            .get("sourceId")
            .or_else(|| environment.get("id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        if source_id.is_empty() || !source_ids.insert(source_id.to_string()) {
            builder.warn("集合中存在空白或重复的环境 ID，该环境已跳过");
            continue;
        }
        let name = clean_name(
            environment
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("导入环境"),
            "导入环境",
            120,
        );
        let mut variables = Vec::new();
        let mut variable_names = HashSet::new();
        for variable in environment
            .get("variables")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if variables.len() >= MAX_IMPORT_ENVIRONMENT_VARIABLES {
                builder.warn(format!(
                    "环境“{name}”最多导入 {MAX_IMPORT_ENVIRONMENT_VARIABLES} 个变量，其余变量已跳过"
                ));
                break;
            }
            let variable_name = variable
                .get("name")
                .or_else(|| variable.get("key"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if variable_name.is_empty() || !variable_names.insert(variable_name.to_string()) {
                builder.warn(format!("环境“{name}”包含空白或重复变量名，已跳过该变量"));
                continue;
            }
            variables.push(CollectionImportEnvironmentVariable {
                name: variable_name.to_string(),
                value: variable
                    .get("value")
                    .map(value_to_string)
                    .unwrap_or_default(),
                secret: variable.get("secret").and_then(Value::as_bool) == Some(true)
                    || variable.get("type").and_then(Value::as_str) == Some("secret"),
                enabled: variable.get("enabled").and_then(Value::as_bool) != Some(false)
                    && variable.get("disabled").and_then(Value::as_bool) != Some(true),
            });
        }
        environments.push(CollectionImportEnvironment {
            source_id: source_id.to_string(),
            name,
            variables,
        });
    }
    environments
}

fn collection_import_metadata(
    description: String,
    default_headers: Vec<HeaderEntry>,
    default_auth: Value,
    default_environment_id: Option<String>,
    source: Option<&Value>,
) -> CollectionImportMetadata {
    CollectionImportMetadata {
        description,
        default_headers,
        default_auth,
        default_environment_id,
        source_format: source
            .and_then(|value| value.get("format"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        source_path: source
            .and_then(|value| value.get("path"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        source_fingerprint: source
            .and_then(|value| value.get("fingerprint"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        source_synced_at: source
            .and_then(|value| value.get("syncedAt"))
            .and_then(Value::as_i64),
    }
}

/// Splits a raw `a=1&b=2` body into the field shape an imported form uses.
///
/// Mirrors the objects the HAR `params` path builds, so a form arrives the same
/// way whichever variant the browser recorded.
fn urlencoded_body_fields(body: &str) -> Vec<Value> {
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(name, value)| {
            json!({
                "id": format!("import-field-{}", uuid::Uuid::new_v4()),
                "name": name.as_ref(),
                "value": value.as_ref(),
                "kind": "text",
                "filePath": "",
                "fileName": "",
                // Unused for a text field, but matching the sibling builders
                // keeps the two form paths byte-identical rather than merely
                // equivalent.
                "contentType": "application/octet-stream",
                "enabled": true
            })
        })
        .collect()
}

fn canonical_import_body(body: &str, body_type: &str) -> Value {
    if matches!(body_type, "json" | "urlencoded" | "form-data") {
        if let Ok(mut value) = serde_json::from_str::<Value>(body) {
            if matches!(body_type, "urlencoded" | "form-data") {
                remove_transient_field_ids(&mut value);
            }
            return value;
        }
    }
    Value::String(body.to_string())
}

fn remove_transient_field_ids(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("id");
            for value in object.values_mut() {
                remove_transient_field_ids(value);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(remove_transient_field_ids),
        _ => {}
    }
}

fn json_fingerprint(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

fn parse_postman(value: &Value, fallback_name: String) -> Result<CollectionImportPreview, String> {
    let suggested_name = value
        .pointer("/info/name")
        .and_then(Value::as_str)
        .map(|name| clean_name(name, &fallback_name, 120))
        .unwrap_or(fallback_name);
    let variables = value
        .get("variable")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let key = item.get("key")?.as_str()?.trim();
                    let value = value_to_string(item.get("value")?);
                    (!key.is_empty()).then(|| (key.to_string(), value))
                })
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    let mut builder = ImportBuilder::new();
    let mut environments =
        parse_portable_environments(value.pointer("/_shownet/environments"), &mut builder);
    let native_environment_id = if environments.is_empty() {
        postman_collection_environment(value, &suggested_name).map(|environment| {
            let source_id = environment.source_id.clone();
            environments.push(environment);
            source_id
        })
    } else {
        None
    };
    builder.set_environments(environments);
    let collection_auth = parse_postman_auth(value.get("auth"), &variables, &mut builder);
    let collection_source_auth = explicit_postman_auth(value.get("auth"));
    let collection_headers =
        parse_header_array(value.pointer("/_shownet/collectionDefaults/headers"));
    let collection_environment_id = value
        .pointer("/_shownet/collectionDefaults/environmentId")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or(native_environment_id);
    builder.set_collection(collection_import_metadata(
        value
            .pointer("/info/description")
            .map(value_to_string)
            .unwrap_or_default(),
        collection_headers.clone(),
        collection_auth.clone().unwrap_or_else(no_auth),
        collection_environment_id.clone(),
        value.pointer("/_shownet/source"),
    ));
    walk_postman_items(
        value
            .get("item")
            .and_then(Value::as_array)
            .unwrap_or(&Vec::new()),
        &[],
        &variables,
        collection_auth.as_ref(),
        collection_source_auth,
        &collection_headers,
        collection_environment_id.as_deref(),
        &mut builder,
    );
    if builder.items.is_empty() {
        return Err("Postman 集合中没有可导入的 HTTP 请求".to_string());
    }
    Ok(builder.finish("postman", suggested_name))
}

fn postman_collection_environment(
    value: &Value,
    suggested_name: &str,
) -> Option<CollectionImportEnvironment> {
    let mut variable_names = HashSet::new();
    let variables = value
        .get("variable")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|variable| {
            let name = variable
                .get("key")
                .or_else(|| variable.get("name"))
                .and_then(Value::as_str)?
                .trim();
            if name.is_empty() {
                return None;
            }
            if !variable_names.insert(name.to_string()) {
                return None;
            }
            Some(CollectionImportEnvironmentVariable {
                name: name.to_string(),
                value: variable
                    .get("value")
                    .map(value_to_string)
                    .unwrap_or_default(),
                secret: variable.get("secret").and_then(Value::as_bool) == Some(true)
                    || variable.get("type").and_then(Value::as_str) == Some("secret"),
                enabled: variable.get("disabled").and_then(Value::as_bool) != Some(true),
            })
        })
        .take(MAX_IMPORT_ENVIRONMENT_VARIABLES)
        .collect::<Vec<_>>();
    (!variables.is_empty()).then(|| CollectionImportEnvironment {
        source_id: "postman-collection-environment".to_string(),
        name: clean_name(&format!("{suggested_name} 变量"), "Postman 变量", 120),
        variables,
    })
}

fn walk_postman_items(
    items: &[Value],
    folder_path: &[String],
    variables: &HashMap<String, String>,
    inherited_auth: Option<&Value>,
    inherited_source_auth: Option<&Value>,
    collection_headers: &[HeaderEntry],
    collection_environment_id: Option<&str>,
    builder: &mut ImportBuilder,
) {
    for item in items {
        if let Some(children) = item.get("item").and_then(Value::as_array) {
            let mut next = folder_path.to_vec();
            if next.len() < 4 {
                next.push(clean_name(
                    item.get("name").and_then(Value::as_str).unwrap_or("文件夹"),
                    "文件夹",
                    80,
                ));
            } else {
                builder.warn("Postman 文件夹超过四级，较深层级已合并到第四级");
            }
            let folder_auth = parse_postman_auth(item.get("auth"), variables, builder);
            let folder_source_auth = explicit_postman_auth(item.get("auth"));
            walk_postman_items(
                children,
                &next,
                variables,
                folder_auth.as_ref().or(inherited_auth),
                folder_source_auth.or(inherited_source_auth),
                collection_headers,
                collection_environment_id,
                builder,
            );
            continue;
        }
        let Some(request) = item.get("request") else {
            continue;
        };
        let request_auth = parse_postman_auth(request.get("auth"), variables, builder);
        let request_source_auth = explicit_postman_auth(request.get("auth"));
        let auth = request_auth
            .as_ref()
            .or(inherited_auth)
            .cloned()
            .unwrap_or_else(no_auth);
        let raw_url = postman_url(request.get("url")).unwrap_or_default();
        let resolved_url = resolve_postman_url(&raw_url, variables);
        let source_components = imported_disabled_components(
            "postman",
            request.get("header"),
            request.pointer("/url/query"),
            |value| resolve_postman_value(value, variables),
        );
        let mut headers = parse_header_array(request.get("header"));
        for header in &mut headers {
            header.value = resolve_postman_value(&header.value, variables);
        }
        merge_default_headers(&mut headers, collection_headers);
        let (body, body_type) = parse_postman_body(request.get("body"), builder);
        let body = resolve_postman_value(&body, variables);
        builder.push(CollectionImportItem {
            name: item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("未命名请求")
                .to_string(),
            method: request
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("GET")
                .to_string(),
            url: resolved_url,
            headers,
            body,
            body_type,
            auth,
            settings: imported_settings(
                item.pointer("/_shownet/settings"),
                "postman",
                request_source_auth.or(inherited_source_auth),
                source_components,
            ),
            environment_id: item
                .pointer("/_shownet/environmentId")
                .and_then(Value::as_str)
                .or(collection_environment_id)
                .map(ToString::to_string),
            tags: string_array(item.pointer("/_shownet/tags")),
            folder_path: folder_path.to_vec(),
            source_key: None,
            source_fingerprint: None,
        });
    }
}

fn explicit_postman_auth(auth: Option<&Value>) -> Option<&Value> {
    let auth = auth?;
    let kind = auth.get("type").and_then(Value::as_str).unwrap_or_default();
    (!matches!(kind, "" | "inherit") && auth.is_object()).then_some(auth)
}

fn postman_url(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(url) => Some(url.clone()),
        Value::Object(object) => {
            if let Some(raw) = object
                .get("raw")
                .and_then(Value::as_str)
                .filter(|raw| !raw.trim().is_empty())
            {
                return Some(raw.to_string());
            }
            let host = match object.get("host")? {
                Value::String(host) => host.clone(),
                Value::Array(parts) => parts
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("."),
                _ => return None,
            };
            if host.trim().is_empty() {
                return None;
            }
            let protocol = object
                .get("protocol")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|protocol| !protocol.is_empty())
                .unwrap_or("https")
                .trim_end_matches("://")
                .trim_end_matches(':');
            let mut url = if host.contains("://") {
                host
            } else {
                format!("{protocol}://{host}")
            };
            if let Some(port) = object
                .get("port")
                .map(value_to_string)
                .filter(|port| !port.trim().is_empty())
            {
                url.push(':');
                url.push_str(port.trim());
            }
            let path = match object.get("path") {
                Some(Value::String(path)) => path.clone(),
                Some(Value::Array(parts)) => parts
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("/"),
                _ => String::new(),
            };
            if !path.is_empty() {
                url.push('/');
                url.push_str(path.trim_start_matches('/'));
            }
            let query = object
                .get("query")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|entry| entry.get("disabled").and_then(Value::as_bool) != Some(true))
                .filter_map(|entry| {
                    let name = entry.get("key")?.as_str()?.trim();
                    if name.is_empty() {
                        return None;
                    }
                    let value = entry.get("value").map(value_to_string).unwrap_or_default();
                    Some(format!(
                        "{}={}",
                        percent_encode_query(name),
                        percent_encode_query_value(&value)
                    ))
                })
                .collect::<Vec<_>>();
            if !query.is_empty() {
                url.push('?');
                url.push_str(&query.join("&"));
            }
            Some(url)
        }
        _ => None,
    }
}

fn resolve_postman_url(raw: &str, variables: &HashMap<String, String>) -> String {
    let resolved = resolve_postman_value(raw, variables);
    if Url::parse(&resolved).is_ok() {
        return resolved;
    }
    if resolved.starts_with("{{") {
        if let Some(path_index) = resolved.find('/') {
            return format!("https://api.example.com{}", &resolved[path_index..]);
        }
    }
    resolved
}

fn resolve_postman_value(raw: &str, variables: &HashMap<String, String>) -> String {
    let mut resolved = raw.to_string();
    for (name, value) in variables {
        resolved = resolved.replace(&format!("{{{{{name}}}}}"), value);
    }
    resolved
}

fn parse_postman_auth(
    auth: Option<&Value>,
    variables: &HashMap<String, String>,
    builder: &mut ImportBuilder,
) -> Option<Value> {
    let auth = auth?;
    if auth.is_null() {
        return None;
    }
    let kind = auth.get("type").and_then(Value::as_str).unwrap_or("none");
    if matches!(kind, "inherit" | "") {
        return None;
    }
    if matches!(kind, "none" | "noauth") {
        return Some(no_auth());
    }
    let entries = auth
        .get(kind)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let key = entry.get("key")?.as_str()?.to_string();
            let value = resolve_postman_value(&value_to_string(entry.get("value")?), variables);
            Some((key, value))
        })
        .collect::<HashMap<_, _>>();
    let parsed = match kind {
        "basic" => json!({
            "kind":"basic",
            "username":entries.get("username").cloned().unwrap_or_default(),
            "password":entries.get("password").cloned().unwrap_or_default()
        }),
        "bearer" => json!({
            "kind":"bearer",
            "token":entries.get("token").cloned().unwrap_or_default()
        }),
        "apikey" => json!({
            "kind":"api-key",
            "name":entries.get("key").cloned().unwrap_or_else(|| "X-API-Key".to_string()),
            "value":entries.get("value").cloned().unwrap_or_default(),
            "location":entries.get("in").map(|value| if value.eq_ignore_ascii_case("query") { "query" } else { "header" }).unwrap_or("header")
        }),
        "oauth2" if entries.get("accessToken").is_some() || entries.get("token").is_some() => {
            json!({
                "kind":"bearer",
                "token":entries.get("accessToken").or_else(|| entries.get("token")).cloned().unwrap_or_default()
            })
        }
        _ => {
            builder.warn(format!("Postman Auth 类型 {kind} 已保留其现有 Authorization/Header，但 ShowNet 暂不自动生成该认证握手"));
            return Some(no_auth());
        }
    };
    Some(parsed)
}

fn no_auth() -> Value {
    json!({"kind":"none"})
}

fn parse_shownet(value: &Value, fallback_name: String) -> Result<CollectionImportPreview, String> {
    let suggested_name = value
        .pointer("/collection/name")
        .and_then(Value::as_str)
        .map(|name| clean_name(name, &fallback_name, 120))
        .unwrap_or(fallback_name);
    let folders = value
        .get("folders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|folder| {
            let id = folder.get("id")?.as_str()?.to_string();
            let name = folder
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("文件夹")
                .to_string();
            let parent_id = folder
                .get("parentId")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            Some((id, (name, parent_id)))
        })
        .collect::<HashMap<_, _>>();
    let mut builder = ImportBuilder::new();
    let environments = parse_portable_environments(value.get("environments"), &mut builder);
    builder.set_environments(environments);
    let default_headers = parse_header_array(value.pointer("/collection/defaults/headers"));
    let default_auth = value
        .pointer("/collection/defaults/auth")
        .cloned()
        .unwrap_or_else(no_auth);
    let default_environment_id = value
        .pointer("/collection/defaults/environmentId")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    builder.set_collection(collection_import_metadata(
        value
            .pointer("/collection/description")
            .map(value_to_string)
            .unwrap_or_default(),
        default_headers.clone(),
        default_auth.clone(),
        default_environment_id.clone(),
        value.pointer("/collection/source"),
    ));
    let empty_requests = Vec::new();
    for request in value
        .get("requests")
        .and_then(Value::as_array)
        .unwrap_or(&empty_requests)
    {
        let mut headers = parse_header_array(request.get("headers"));
        merge_default_headers(&mut headers, &default_headers);
        let request_auth = request.get("auth").cloned().unwrap_or_else(no_auth);
        let auth = if request_auth.get("kind").and_then(Value::as_str) == Some("none") {
            default_auth.clone()
        } else {
            request_auth
        };
        builder.push(CollectionImportItem {
            name: request
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("未命名请求")
                .to_string(),
            method: request
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("GET")
                .to_string(),
            url: request
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            headers,
            body: request
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            body_type: request
                .get("bodyType")
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_string(),
            auth,
            settings: request
                .get("settings")
                .cloned()
                .unwrap_or_else(default_request_settings),
            environment_id: request
                .get("environmentId")
                .and_then(Value::as_str)
                .or(default_environment_id.as_deref())
                .map(ToString::to_string),
            tags: string_array(request.get("tags")),
            folder_path: resolve_import_folder_path(
                request.get("folderId").and_then(Value::as_str),
                &folders,
            ),
            source_key: None,
            source_fingerprint: None,
        });
    }
    if builder.items.is_empty() {
        return Err("ShowNet 集合中没有可导入的 HTTP 请求".to_string());
    }
    Ok(builder.finish("shownet", suggested_name))
}

fn parse_insomnia(value: &Value, fallback_name: String) -> Result<CollectionImportPreview, String> {
    let resources = value
        .get("resources")
        .and_then(Value::as_array)
        .ok_or_else(|| "Insomnia 导出缺少 resources".to_string())?;
    let suggested_name = resources
        .iter()
        .find(|resource| resource.get("_type").and_then(Value::as_str) == Some("workspace"))
        .and_then(|workspace| workspace.get("name"))
        .and_then(Value::as_str)
        .map(|name| clean_name(name, &fallback_name, 120))
        .unwrap_or(fallback_name);
    let folders = resources
        .iter()
        .filter(|resource| resource.get("_type").and_then(Value::as_str) == Some("request_group"))
        .filter_map(|folder| {
            let id = folder.get("_id")?.as_str()?.to_string();
            let name = folder
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("文件夹")
                .to_string();
            let parent_id = folder
                .get("parentId")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            Some((id, (name, parent_id)))
        })
        .collect::<HashMap<_, _>>();
    let variables = insomnia_environment_variables(resources);
    let mut builder = ImportBuilder::new();
    let environments = insomnia_import_environments(resources, &mut builder);
    let request_environment_id = environments
        .first()
        .map(|environment| environment.source_id.clone());
    builder.set_environments(environments);
    let workspace_description = resources
        .iter()
        .find(|resource| resource.get("_type").and_then(Value::as_str) == Some("workspace"))
        .and_then(|workspace| workspace.get("description"))
        .map(value_to_string)
        .unwrap_or_default();
    builder.set_collection(collection_import_metadata(
        workspace_description,
        Vec::new(),
        no_auth(),
        request_environment_id.clone(),
        None,
    ));
    let unsupported = resources.iter().any(|resource| {
        matches!(
            resource.get("_type").and_then(Value::as_str),
            Some("websocket_request" | "grpc_request")
        )
    });
    if unsupported {
        builder.warn("Insomnia 中的 WebSocket/gRPC 请求未导入，本次仅导入 HTTP(S) 请求");
    }
    for request in resources
        .iter()
        .filter(|resource| resource.get("_type").and_then(Value::as_str) == Some("request"))
    {
        let auth = parse_insomnia_auth(request.get("authentication"), &variables, &mut builder);
        let source_auth = request.get("authentication");
        let raw_url = request
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let url = insomnia_url(
            raw_url,
            request.get("parameters").and_then(Value::as_array),
            &variables,
            &mut builder,
        );
        let (body, body_type) = parse_insomnia_body(request.get("body"), &mut builder);
        let body = resolve_insomnia_value(&body, &variables);
        let source_components = imported_disabled_components(
            "insomnia",
            request.get("headers"),
            request.get("parameters"),
            |value| resolve_insomnia_value(value, &variables),
        );
        let mut headers = parse_header_array(request.get("headers"));
        for header in &mut headers {
            header.value = resolve_insomnia_value(&header.value, &variables);
        }
        builder.push(CollectionImportItem {
            name: request
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("未命名请求")
                .to_string(),
            method: request
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("GET")
                .to_string(),
            url,
            headers,
            body,
            body_type,
            auth,
            settings: imported_settings(None, "insomnia", source_auth, source_components),
            environment_id: request_environment_id.clone(),
            tags: string_array(request.get("tags")),
            folder_path: resolve_import_folder_path(
                request.get("parentId").and_then(Value::as_str),
                &folders,
            ),
            source_key: None,
            source_fingerprint: None,
        });
    }
    if builder.items.is_empty() {
        return Err("Insomnia 导出中没有可导入的 HTTP 请求".to_string());
    }
    Ok(builder.finish("insomnia", suggested_name))
}

fn insomnia_environment_variables(resources: &[Value]) -> HashMap<String, String> {
    let mut variables = HashMap::new();
    for environment in resources
        .iter()
        .filter(|resource| resource.get("_type").and_then(Value::as_str) == Some("environment"))
    {
        let Some(data) = environment.get("data").and_then(Value::as_object) else {
            continue;
        };
        for (name, value) in data {
            variables
                .entry(name.clone())
                .or_insert_with(|| value_to_string(value));
        }
    }
    variables
}

fn insomnia_import_environments(
    resources: &[Value],
    builder: &mut ImportBuilder,
) -> Vec<CollectionImportEnvironment> {
    let mut environments = Vec::new();
    for (index, environment) in resources
        .iter()
        .filter(|resource| resource.get("_type").and_then(Value::as_str) == Some("environment"))
        .enumerate()
    {
        if environments.len() >= MAX_IMPORT_ENVIRONMENTS {
            builder.warn(format!(
                "环境导入上限为 {MAX_IMPORT_ENVIRONMENTS} 个，其余 Insomnia 环境已跳过"
            ));
            break;
        }
        let Some(data) = environment.get("data").and_then(Value::as_object) else {
            continue;
        };
        let mut variable_names = HashSet::new();
        let variables = data
            .iter()
            .filter_map(|(name, value)| {
                let name = name.trim();
                if name.is_empty() || !variable_names.insert(name.to_string()) {
                    return None;
                }
                Some(CollectionImportEnvironmentVariable {
                    name: name.to_string(),
                    value: value_to_string(value),
                    secret: false,
                    enabled: true,
                })
            })
            .take(MAX_IMPORT_ENVIRONMENT_VARIABLES)
            .collect::<Vec<_>>();
        if variables.is_empty() {
            continue;
        }
        environments.push(CollectionImportEnvironment {
            source_id: environment
                .get("_id")
                .and_then(Value::as_str)
                .filter(|id| !id.trim().is_empty())
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("insomnia-environment-{index}")),
            name: clean_name(
                environment
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("Insomnia 环境"),
                "Insomnia 环境",
                120,
            ),
            variables,
        });
    }
    environments
}

fn insomnia_url(
    raw: &str,
    parameters: Option<&Vec<Value>>,
    variables: &HashMap<String, String>,
    builder: &mut ImportBuilder,
) -> String {
    let mut resolved = resolve_insomnia_value(raw, variables);
    if Url::parse(&resolved).is_err() && resolved.trim_start().starts_with("{{") {
        if let Some(end) = resolved.find("}}") {
            let path = resolved[end + 2..].trim_start();
            resolved = format!("https://api.example.com/{}", path.trim_start_matches('/'));
            builder.warn(
                "Insomnia 基础地址变量未能解析，已使用 api.example.com 占位，请在导入后确认 URL",
            );
        }
    }
    let Some(parameters) = parameters else {
        return resolved;
    };
    let Ok(mut url) = Url::parse(&resolved) else {
        return resolved;
    };
    for parameter in parameters {
        if parameter.get("disabled").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let name = parameter
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        if name.is_empty() {
            continue;
        }
        // A spec parameter is routinely a number — page=1, limit=50, an id.
        // `as_str()` returns None for those and the empty default silently
        // turned them into `?page=`, importing a request that asks for
        // something different from the one the spec describes.
        let raw = parameter
            .get("value")
            .map(value_to_string)
            .unwrap_or_default();
        let value = resolve_insomnia_value(&raw, variables);
        url.query_pairs_mut().append_pair(name, &value);
    }
    url.to_string()
}

fn resolve_insomnia_value(raw: &str, variables: &HashMap<String, String>) -> String {
    let mut resolved = raw.to_string();
    for (name, value) in variables {
        for template in [
            format!("{{{{ _.{name} }}}}"),
            format!("{{{{_.{name}}}}}"),
            format!("{{{{ {name} }}}}"),
            format!("{{{{{name}}}}}"),
        ] {
            resolved = resolved.replace(&template, value);
        }
    }
    resolved
}

fn parse_insomnia_auth(
    auth: Option<&Value>,
    variables: &HashMap<String, String>,
    builder: &mut ImportBuilder,
) -> Value {
    let Some(auth) = auth else {
        return no_auth();
    };
    let kind = auth.get("type").and_then(Value::as_str).unwrap_or("none");
    let value = |name: &str| {
        resolve_insomnia_value(
            auth.get(name)
                .map(value_to_string)
                .unwrap_or_default()
                .as_str(),
            variables,
        )
    };
    match kind {
        "" | "none" | "noauth" => no_auth(),
        "basic" => {
            json!({"kind":"basic","username":value("username"),"password":value("password")})
        }
        "bearer" => json!({"kind":"bearer","token":value("token")}),
        "oauth2" if auth.get("accessToken").is_some() => {
            json!({"kind":"bearer","token":value("accessToken")})
        }
        "apikey" | "api-key" => json!({
            "kind":"api-key",
            "name":if value("key").is_empty() { "X-API-Key".to_string() } else { value("key") },
            "value":value("value"),
            "location":if matches!(auth.get("addTo").and_then(Value::as_str), Some("queryParams" | "query")) { "query" } else { "header" }
        }),
        _ => {
            builder.warn(format!("Insomnia Auth 类型 {kind} 已保留其现有 Authorization/Header，但 ShowNet 暂不自动生成该认证握手"));
            no_auth()
        }
    }
}

fn parse_insomnia_body(body: Option<&Value>, builder: &mut ImportBuilder) -> (String, String) {
    let Some(body) = body else {
        return (String::new(), "none".to_string());
    };
    let mime = body
        .get("mimeType")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if matches!(
        mime,
        "application/x-www-form-urlencoded" | "multipart/form-data"
    ) {
        let fields = body
            .get("params")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|field| {
                let name = field.get("name").and_then(Value::as_str)?.trim();
                if name.is_empty() {
                    return None;
                }
                let kind = if field.get("type").and_then(Value::as_str) == Some("file") {
                    "file"
                } else {
                    "text"
                };
                let file_path = field
                    .get("fileName")
                    .or_else(|| field.get("filePath"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if kind == "file" && file_path.is_empty() {
                    builder.warn("Insomnia 表单文件字段缺少源路径，发送前需要选择文件");
                }
                Some(json!({
                    "id": format!("import-field-{}", uuid::Uuid::new_v4()),
                    "name": name,
                    "value": field.get("value").and_then(Value::as_str).unwrap_or_default(),
                    "kind": kind,
                    "filePath": file_path,
                    "fileName": Path::new(file_path).file_name().and_then(|name| name.to_str()).unwrap_or(""),
                    "contentType": field.get("contentType").and_then(Value::as_str).unwrap_or("application/octet-stream"),
                    "enabled": field.get("disabled").and_then(Value::as_bool) != Some(true)
                        && (kind != "file" || !file_path.is_empty())
                }))
            })
            .collect::<Vec<_>>();
        return (
            serde_json::to_string(&fields).unwrap_or_else(|_| "[]".to_string()),
            if mime == "multipart/form-data" {
                "form-data"
            } else {
                "urlencoded"
            }
            .to_string(),
        );
    }
    if let Some(path) = body
        .get("fileName")
        .or_else(|| body.get("filePath"))
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    {
        return (
            json!({
                "filePath":path,
                "fileName":Path::new(path).file_name().and_then(|name| name.to_str()).unwrap_or_default(),
                "contentType":if mime.is_empty() { "application/octet-stream" } else { mime }
            })
            .to_string(),
            "file".to_string(),
        );
    }
    let text = body
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if text.is_empty() {
        return (String::new(), "none".to_string());
    }
    let body_type = if mime.contains("json") {
        "json"
    } else if mime.contains("xml") {
        "xml"
    } else if mime.starts_with("text/") {
        "text"
    } else {
        "raw"
    };
    (text, body_type.to_string())
}

fn resolve_import_folder_path(
    parent_id: Option<&str>,
    folders: &HashMap<String, (String, Option<String>)>,
) -> Vec<String> {
    let mut reversed = Vec::new();
    let mut current = parent_id.map(ToString::to_string);
    let mut seen = HashSet::new();
    while let Some(id) = current {
        if !seen.insert(id.clone()) {
            break;
        }
        let Some((name, parent)) = folders.get(&id) else {
            break;
        };
        reversed.push(clean_name(name, "文件夹", 80));
        current = parent.clone();
    }
    reversed.reverse();
    reversed.truncate(4);
    reversed
}

fn merge_default_headers(headers: &mut Vec<HeaderEntry>, defaults: &[HeaderEntry]) {
    for header in defaults {
        if headers
            .iter()
            .any(|current| current.name.eq_ignore_ascii_case(&header.name))
        {
            continue;
        }
        headers.push(header.clone());
    }
}

fn parse_postman_body(body: Option<&Value>, builder: &mut ImportBuilder) -> (String, String) {
    let Some(body) = body else {
        return (String::new(), "none".to_string());
    };
    match body.get("mode").and_then(Value::as_str).unwrap_or("raw") {
        "raw" => {
            let content = body
                .get("raw")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let language = body
                .pointer("/options/raw/language")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let body_type = match language {
                "json" => "json",
                "xml" => "xml",
                "text" => "text",
                _ => "raw",
            };
            (content, body_type.to_string())
        }
        "urlencoded" => {
            let fields = postman_body_fields(body.get("urlencoded"), false, builder);
            (
                serde_json::to_string(&fields).unwrap_or_else(|_| "[]".to_string()),
                "urlencoded".to_string(),
            )
        }
        "formdata" => {
            let fields = postman_body_fields(body.get("formdata"), true, builder);
            (
                serde_json::to_string(&fields).unwrap_or_else(|_| "[]".to_string()),
                "form-data".to_string(),
            )
        }
        "file" => {
            let path = body
                .pointer("/file/src")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let file_name = Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            (
                json!({"filePath":path,"fileName":file_name,"contentType":"application/octet-stream"}).to_string(),
                "file".to_string(),
            )
        }
        "graphql" => {
            let graphql = body.get("graphql").cloned().unwrap_or(Value::Null);
            let query = graphql
                .get("query")
                .map(value_to_string)
                .unwrap_or_default();
            let variables = graphql
                .get("variables")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let variables = variables
                .as_str()
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .unwrap_or(variables);
            (
                json!({"query":query,"variables":variables}).to_string(),
                "json".to_string(),
            )
        }
        mode => {
            let original = body.get(mode).cloned().unwrap_or_else(|| body.clone());
            let preserved = match original {
                Value::String(value) => value,
                value => serde_json::to_string(&value).unwrap_or_default(),
            };
            builder.warn(format!(
                "Postman 正文模式 {mode} 暂不直接执行，原始负载已作为 Raw 正文保留"
            ));
            (preserved, "raw".to_string())
        }
    }
}

fn postman_body_fields(
    value: Option<&Value>,
    allow_file_marker: bool,
    builder: &mut ImportBuilder,
) -> Vec<Value> {
    let mut result = Vec::new();
    for field in value.and_then(Value::as_array).into_iter().flatten() {
        let enabled = field.get("disabled").and_then(Value::as_bool) != Some(true);
        let Some(name) = field
            .get("key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        if allow_file_marker && field.get("type").and_then(Value::as_str) == Some("file") {
            let mut paths = match field.get("src") {
                Some(Value::String(path)) => vec![path.as_str()],
                Some(Value::Array(paths)) => paths.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            if paths.is_empty() {
                builder.warn("Postman 表单文件字段缺少源路径，发送前需要选择文件");
                paths.push("");
            }
            for path in paths {
                result.push(json!({
                    "id": format!("import-field-{}", uuid::Uuid::new_v4()),
                    "name": name,
                    "value": "",
                    "kind": "file",
                    "filePath": path,
                    "fileName": Path::new(path).file_name().and_then(|name| name.to_str()).unwrap_or(""),
                    "contentType": field.get("contentType").and_then(Value::as_str).unwrap_or("application/octet-stream"),
                    "enabled": enabled && !path.is_empty()
                }));
            }
            continue;
        }
        result.push(json!({
            "id": format!("import-field-{}", uuid::Uuid::new_v4()),
            "name": name,
            "value": field.get("value").map(value_to_string).unwrap_or_default(),
            "kind": "text",
            "enabled": enabled
        }));
    }
    result
}

fn parse_openapi(value: &Value, fallback_name: String) -> Result<CollectionImportPreview, String> {
    let suggested_name = value
        .pointer("/info/title")
        .and_then(Value::as_str)
        .map(|name| clean_name(name, &fallback_name, 120))
        .unwrap_or(fallback_name);
    let base_url = openapi_base_url(value);
    let mut builder = ImportBuilder::new();
    builder.set_collection(collection_import_metadata(
        value
            .pointer("/info/description")
            .map(value_to_string)
            .unwrap_or_default(),
        Vec::new(),
        no_auth(),
        None,
        None,
    ));
    if value.get("security").is_some() || value.pointer("/components/securitySchemes").is_some() {
        builder.warn("OpenAPI 安全方案已识别；规范通常只描述认证方式，不包含实际凭据");
    }
    let Some(paths) = value.get("paths").and_then(Value::as_object) else {
        return Err("OpenAPI 文件缺少 paths".to_string());
    };
    const METHODS: &[&str] = &[
        "get", "post", "put", "patch", "delete", "options", "head", "trace",
    ];
    for (path, path_item) in paths {
        for method in METHODS {
            let Some(operation) = path_item.get(*method).and_then(Value::as_object) else {
                continue;
            };
            let folder = operation
                .get("tags")
                .and_then(Value::as_array)
                .and_then(|tags| tags.first())
                .and_then(Value::as_str)
                .unwrap_or("接口");
            let mut url = format!("{}{}", base_url.trim_end_matches('/'), openapi_path(path));
            let parameters =
                merge_openapi_parameters(path_item.get("parameters"), operation.get("parameters"));
            let mut query = Vec::new();
            let mut headers = Vec::new();
            for parameter in parameters {
                let name = parameter
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let location = parameter
                    .get("in")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let sample =
                    parameter_example(parameter).unwrap_or_else(|| format!("{{{{{name}}}}}"));
                if location == "query" && !name.is_empty() {
                    query.push((name.to_string(), sample));
                } else if location == "header" && !name.is_empty() {
                    headers.push(HeaderEntry {
                        name: name.to_string(),
                        value: sample,
                    });
                }
            }
            if !query.is_empty() {
                let encoded = query
                    .into_iter()
                    .map(|(name, value)| {
                        format!(
                            "{}={}",
                            percent_encode_query(&name),
                            percent_encode_query_value(&value)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                url.push('?');
                url.push_str(&encoded);
            }
            let (body, body_type, content_type) = openapi_body(value, operation);
            if let Some(content_type) = content_type {
                headers.push(HeaderEntry {
                    name: "Content-Type".to_string(),
                    value: content_type,
                });
            }
            builder.push(CollectionImportItem {
                name: operation
                    .get("summary")
                    .or_else(|| operation.get("operationId"))
                    .and_then(Value::as_str)
                    .unwrap_or(&format!("{} {}", method.to_uppercase(), path))
                    .to_string(),
                method: method.to_uppercase(),
                url,
                headers,
                body,
                body_type,
                auth: no_auth(),
                settings: default_request_settings(),
                environment_id: None,
                tags: string_array(operation.get("tags")),
                folder_path: vec![folder.to_string()],
                source_key: Some(format!("{} {}", method.to_uppercase(), path.trim())),
                source_fingerprint: None,
            });
        }
    }
    if builder.items.is_empty() {
        return Err("OpenAPI 文件中没有可导入的 HTTP 操作".to_string());
    }
    Ok(builder.finish("openapi", suggested_name))
}

fn openapi_base_url(value: &Value) -> String {
    if let Some(server) = value
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|servers| servers.first())
        .and_then(|server| server.get("url"))
        .and_then(Value::as_str)
    {
        if server.starts_with("http://") || server.starts_with("https://") {
            return server.to_string();
        }
    }
    let scheme = value
        .get("schemes")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .unwrap_or("https");
    let host = value
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("api.example.com");
    let base_path = value.get("basePath").and_then(Value::as_str).unwrap_or("");
    format!("{scheme}://{host}{base_path}")
}

fn openapi_path(path: &str) -> String {
    let mut result = String::new();
    let mut name = String::new();
    let mut in_parameter = false;
    for character in path.chars() {
        match character {
            '{' if !in_parameter => {
                in_parameter = true;
                name.clear();
            }
            '}' if in_parameter => {
                in_parameter = false;
                result.push_str("{{");
                result.push_str(&name);
                result.push_str("}}");
            }
            _ if in_parameter => name.push(character),
            _ => result.push(character),
        }
    }
    if in_parameter {
        result.push('{');
        result.push_str(&name);
    }
    result
}

fn merge_openapi_parameters<'a>(
    left: Option<&'a Value>,
    right: Option<&'a Value>,
) -> Vec<&'a Value> {
    left.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(right.and_then(Value::as_array).into_iter().flatten())
        .collect()
}

fn parameter_example(parameter: &Value) -> Option<String> {
    parameter
        .get("example")
        .or_else(|| parameter.pointer("/schema/example"))
        .or_else(|| parameter.pointer("/schema/default"))
        .map(value_to_string)
}

fn openapi_body(_root: &Value, operation: &Map<String, Value>) -> (String, String, Option<String>) {
    if let Some(content) = operation
        .get("requestBody")
        .and_then(|body| body.get("content"))
        .and_then(Value::as_object)
    {
        let preferred = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
            "application/xml",
        ];
        let selected = preferred
            .iter()
            .find_map(|kind| content.get(*kind).map(|entry| ((*kind).to_string(), entry)))
            .or_else(|| {
                content
                    .iter()
                    .next()
                    .map(|(kind, entry)| (kind.clone(), entry))
            });
        if let Some((content_type, entry)) = selected {
            let example = entry
                .get("example")
                .cloned()
                .or_else(|| entry.get("schema").map(schema_example))
                .unwrap_or(Value::Null);
            let body_type = if content_type.contains("json") {
                "json"
            } else if content_type.contains("xml") {
                "xml"
            } else if content_type == "application/x-www-form-urlencoded" {
                "urlencoded"
            } else if content_type == "multipart/form-data" {
                "form-data"
            } else {
                "text"
            };
            let body = if matches!(body_type, "urlencoded" | "form-data") {
                structured_fields_from_example(&example)
            } else if example.is_string() {
                example.as_str().unwrap_or_default().to_string()
            } else if example.is_null() {
                String::new()
            } else {
                serde_json::to_string_pretty(&example).unwrap_or_default()
            };
            return (body, body_type.to_string(), Some(content_type));
        }
    }
    (String::new(), "none".to_string(), None)
}

fn schema_example(schema: &Value) -> Value {
    if let Some(example) = schema.get("example") {
        return example.clone();
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("object") | None if schema.get("properties").is_some() => {
            let mut object = Map::new();
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                for (name, value) in properties.iter().take(50) {
                    object.insert(name.clone(), schema_example(value));
                }
            }
            Value::Object(object)
        }
        Some("array") => Value::Array(vec![schema_example(
            schema.get("items").unwrap_or(&Value::Null),
        )]),
        Some("integer") | Some("number") => schema.get("default").cloned().unwrap_or(json!(0)),
        Some("boolean") => schema.get("default").cloned().unwrap_or(json!(false)),
        _ => schema
            .get("default")
            .cloned()
            .unwrap_or(Value::String("string".to_string())),
    }
}

fn structured_fields_from_example(example: &Value) -> String {
    // A spec may write the example as a string — `example: "user=ada&pass=x"`
    // is ordinary for form content. `as_object()` returns None for it and the
    // default below is an empty list, so the body was dropped outright rather
    // than merely mislabelled. Parsed the same way the HAR path parses a raw
    // form, so the two importers agree.
    if let Some(text) = example.as_str() {
        let fields = urlencoded_body_fields(text);
        return serde_json::to_string(&fields).unwrap_or_else(|_| "[]".to_string());
    }
    let fields = example
        .as_object()
        .map(|object| {
            object
                .iter()
                .map(|(name, value)| {
                    json!({
                        "id": format!("import-field-{}", uuid::Uuid::new_v4()),
                        "name": name,
                        "value": value_to_string(value),
                        "kind": "text",
                        "enabled": true
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    serde_json::to_string(&fields).unwrap_or_else(|_| "[]".to_string())
}

fn parse_har(value: &Value, fallback_name: String) -> Result<CollectionImportPreview, String> {
    let mut builder = ImportBuilder::new();
    let empty_entries = Vec::new();
    let entries = value
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .unwrap_or(&empty_entries);
    for entry in entries {
        let Some(request) = entry.get("request") else {
            continue;
        };
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let path = Url::parse(url)
            .ok()
            .map(|url| url.path().to_string())
            .unwrap_or_else(|| "/".to_string());
        let host = Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(ToString::to_string))
            .unwrap_or_else(|| "HAR".to_string());
        let mut headers = parse_header_array(request.get("headers"));
        if !headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("cookie"))
        {
            let cookie = request
                .get("cookies")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|cookie| {
                    let name = cookie.get("name")?.as_str()?;
                    let value = cookie
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    Some(format!("{name}={value}"))
                })
                .collect::<Vec<_>>()
                .join("; ");
            if !cookie.is_empty() {
                headers.push(HeaderEntry {
                    name: "Cookie".to_string(),
                    value: cookie,
                });
            }
        }
        let post_data = request.get("postData");
        let mut body = post_data
            .and_then(|data| data.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let mime = post_data
            .and_then(|data| data.get("mimeType"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut body_type = if body.is_empty() {
            "none"
        } else if mime.contains("json") {
            "json"
        } else if mime.contains("xml") {
            "xml"
        } else if mime.contains("x-www-form-urlencoded") {
            "urlencoded"
        } else {
            "raw"
        };
        // A HAR may record a form either way: as parsed `params`, handled below,
        // or as raw `text`. Chrome writes the text. Both describe the same
        // request, so both have to arrive as fields — "urlencoded" means a JSON
        // field array to canonical_import_body, and handing it `a=1&b=2` left
        // the workbench with a string where it expects fields. Importing the
        // same form two different ways depending on which browser wrote the HAR
        // is the actual defect here.
        if body_type == "urlencoded" && !body.is_empty() {
            body = serde_json::to_string(&urlencoded_body_fields(&body))
                .unwrap_or_else(|_| "[]".to_string());
        }
        if body.is_empty() {
            let fields = post_data
                .and_then(|data| data.get("params"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|field| {
                    let name = field.get("name").and_then(Value::as_str)?;
                    let file_path = field
                        .get("fileName")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let kind = if file_path.is_empty() { "text" } else { "file" };
                    Some(json!({
                        "id":format!("import-field-{}", uuid::Uuid::new_v4()),
                        "name":name,
                        "value":field.get("value").and_then(Value::as_str).unwrap_or_default(),
                        "kind":kind,
                        "filePath":file_path,
                        "fileName":Path::new(file_path).file_name().and_then(|name| name.to_str()).unwrap_or_default(),
                        "contentType":field.get("contentType").and_then(Value::as_str).unwrap_or("application/octet-stream"),
                        "enabled":true
                    }))
                })
                .collect::<Vec<_>>();
            if !fields.is_empty() {
                body = serde_json::to_string(&fields).unwrap_or_else(|_| "[]".to_string());
                body_type = if mime.contains("multipart/form-data") {
                    "form-data"
                } else {
                    "urlencoded"
                };
            }
        }
        builder.push(CollectionImportItem {
            name: format!(
                "{} {}",
                request
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("GET"),
                path
            ),
            method: request
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("GET")
                .to_string(),
            url: url.to_string(),
            headers,
            body,
            body_type: body_type.to_string(),
            auth: no_auth(),
            settings: default_request_settings(),
            environment_id: None,
            tags: Vec::new(),
            folder_path: vec![host],
            source_key: None,
            source_fingerprint: None,
        });
    }
    if builder.items.is_empty() {
        return Err("HAR 中没有可导入的 HTTP 请求".to_string());
    }
    Ok(builder.finish("har", fallback_name))
}

fn parse_header_array(value: Option<&Value>) -> Vec<HeaderEntry> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|header| header.get("disabled").and_then(Value::as_bool) != Some(true))
        .filter_map(|header| {
            let name = header
                .get("key")
                .or_else(|| header.get("name"))
                .and_then(Value::as_str)?
                .trim();
            if name.is_empty() {
                return None;
            }
            Some(HeaderEntry {
                name: name.to_string(),
                value: header
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .take(200)
        .collect()
}

fn validate_import_url(value: &str) -> Result<String, String> {
    let url = Url::parse(value.trim())
        .map_err(|_| format!("URL 无效，已跳过: {}", truncate(value, 100)))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(format!(
            "仅支持 HTTP(S) 请求，已跳过: {}",
            truncate(value, 100)
        ));
    }
    Ok(url.to_string())
}

fn clean_name(value: &str, fallback: &str, max: usize) -> String {
    let value = value.trim();
    let value = if value.is_empty() { fallback } else { value };
    value.chars().take(max).collect()
}

fn truncate(value: &str, max: usize) -> String {
    let mut result = value.chars().take(max).collect::<String>();
    if value.chars().count() > max {
        result.push_str("...");
    }
    result
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => String::new(),
        _ => value.to_string(),
    }
}

fn percent_encode_query(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn percent_encode_query_value(value: &str) -> String {
    if value.starts_with("{{") && value.ends_with("}}") {
        value.to_string()
    } else {
        percent_encode_query(value)
    }
}

pub fn render_collection_export(
    format: &str,
    collection: &RequestCollection,
    folders: &[RequestCollectionFolder],
    drafts: &[RequestDraft],
    environments: &[CollectionImportEnvironment],
) -> Result<String, String> {
    let defaults = collection_defaults(collection);
    let source = collection_source(collection);
    let value = match format {
        "shownet" => {
            let items = drafts.iter().map(export_draft).collect::<Vec<_>>();
            json!({
                "format": "shownet-request-collection",
                "version": 1,
                "collection": { "name": collection.name, "description": collection.description, "defaults": defaults, "source": source },
                "folders": folders.iter().map(|folder| json!({"id":folder.id,"parentId":folder.parent_id,"name":folder.name,"depth":folder.depth})).collect::<Vec<_>>(),
                "requests": items,
                "environments": environments
            })
        }
        "postman" => {
            let mut collection_value = json!({
                "info": {
                "name": collection.name,
                "description": collection.description,
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                },
                "item": postman_items(None, folders, drafts),
                "variable": postman_environment_variables(collection, environments),
                "_shownet": { "collectionDefaults": defaults, "environments": environments, "source": source }
            });
            if let Some(auth) = postman_auth(&collection.default_auth) {
                collection_value["auth"] = auth;
            }
            collection_value
        }
        _ => return Err("集合导出格式无效".to_string()),
    };
    serde_json::to_string_pretty(&value).map_err(|error| format!("序列化集合失败: {error}"))
}

fn collection_source(collection: &RequestCollection) -> Value {
    json!({
        "format": collection.source_format,
        "path": collection.source_path,
        "fingerprint": collection.source_fingerprint,
        "syncedAt": collection.source_synced_at
    })
}

fn postman_environment_variables(
    collection: &RequestCollection,
    environments: &[CollectionImportEnvironment],
) -> Vec<Value> {
    let selected = collection
        .default_environment_id
        .as_deref()
        .and_then(|environment_id| {
            environments
                .iter()
                .find(|environment| environment.source_id == environment_id)
        })
        .or_else(|| (environments.len() == 1).then(|| &environments[0]));
    selected
        .into_iter()
        .flat_map(|environment| &environment.variables)
        .map(|variable| {
            json!({
                "key": variable.name,
                "value": variable.value,
                "type": if variable.secret { "secret" } else { "string" },
                "disabled": !variable.enabled
            })
        })
        .collect()
}

fn collection_defaults(collection: &RequestCollection) -> Value {
    json!({
        "headers": collection.default_headers,
        "auth": collection.default_auth,
        "environmentId": collection.default_environment_id
    })
}

fn export_draft(draft: &RequestDraft) -> Value {
    json!({
        "id": draft.id,
        "folderId": draft.folder_id,
        "name": draft.name,
        "method": draft.method,
        "url": draft.url,
        "headers": draft.headers,
        "body": draft.body,
        "bodyType": draft.body_type,
        "auth": draft.auth,
        "settings": draft.settings,
        "environmentId": draft.environment_id,
        "tags": draft.tags
    })
}

fn postman_items(
    parent_id: Option<&str>,
    folders: &[RequestCollectionFolder],
    drafts: &[RequestDraft],
) -> Vec<Value> {
    let mut items = drafts
        .iter()
        .filter(|draft| draft.folder_id.as_deref() == parent_id)
        .map(|draft| {
            let mut headers = draft.headers
                .iter()
                .cloned()
                .into_iter()
                .map(|header| json!({"key":header.name,"value":header.value,"type":"text"}))
                .collect::<Vec<_>>();
            headers.extend(postman_disabled_entries(&draft.settings, "disabledHeaders"));
            let disabled_query = postman_disabled_entries(&draft.settings, "disabledQuery");
            let url = if disabled_query.is_empty() {
                Value::String(draft.url.clone())
            } else {
                json!({"raw":draft.url,"query":disabled_query})
            };
            let mut request = json!({"method":draft.method,"header":headers,"url":url});
            if let Some(body) = postman_body(draft) {
                request["body"] = body;
            }
            if let Some(auth) = postman_auth(&draft.auth) {
                request["auth"] = auth;
            } else if let Some(auth) = imported_source_auth(&draft.settings, "postman") {
                request["auth"] = auth.clone();
            }
            json!({"name":draft.name,"request":request,"_shownet":{"tags":draft.tags,"settings":draft.settings,"environmentId":draft.environment_id}})
        })
        .collect::<Vec<_>>();
    for folder in folders
        .iter()
        .filter(|folder| folder.parent_id.as_deref() == parent_id)
    {
        items.push(json!({
            "name": folder.name,
            "item": postman_items(Some(&folder.id), folders, drafts)
        }));
    }
    items
}

fn imported_source_auth<'a>(settings: &'a Value, format: &str) -> Option<&'a Value> {
    let imported = settings.get(IMPORT_SOURCE_AUTH_KEY)?;
    (imported.get("format").and_then(Value::as_str) == Some(format))
        .then(|| imported.get("value"))
        .flatten()
}

fn postman_disabled_entries(settings: &Value, key: &str) -> Vec<Value> {
    settings
        .get(IMPORT_SOURCE_COMPONENTS_KEY)
        .and_then(|components| components.get(key))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let name = entry.get("name").and_then(Value::as_str)?.trim();
            if name.is_empty() {
                return None;
            }
            Some(json!({
                "key": name,
                "value": entry.get("value").map(value_to_string).unwrap_or_default(),
                "type": "text",
                "disabled": true
            }))
        })
        .collect()
}

fn postman_auth(auth: &Value) -> Option<Value> {
    match auth.get("kind").and_then(Value::as_str).unwrap_or("none") {
        "basic" => Some(json!({"type":"basic","basic":[
            {"key":"username","value":auth.get("username").map(value_to_string).unwrap_or_default(),"type":"string"},
            {"key":"password","value":auth.get("password").map(value_to_string).unwrap_or_default(),"type":"string"}
        ]})),
        "bearer" => Some(json!({"type":"bearer","bearer":[
            {"key":"token","value":auth.get("token").map(value_to_string).unwrap_or_default(),"type":"string"}
        ]})),
        "api-key" => Some(json!({"type":"apikey","apikey":[
            {"key":"key","value":auth.get("name").map(value_to_string).unwrap_or_else(|| "X-API-Key".to_string()),"type":"string"},
            {"key":"value","value":auth.get("value").map(value_to_string).unwrap_or_default(),"type":"string"},
            {"key":"in","value":auth.get("location").map(value_to_string).unwrap_or_else(|| "header".to_string()),"type":"string"}
        ]})),
        _ => None,
    }
}

fn postman_body(draft: &RequestDraft) -> Option<Value> {
    if draft.body.is_empty() || draft.body_type == "none" {
        return None;
    }
    if matches!(draft.body_type.as_str(), "urlencoded" | "form-data") {
        let fields = serde_json::from_str::<Vec<Value>>(&draft.body).unwrap_or_default();
        let key = if draft.body_type == "form-data" {
            "formdata"
        } else {
            "urlencoded"
        };
        let values = fields
            .into_iter()
            .map(|field| {
                let mut value = json!({
                    "key":field.get("name").map(value_to_string).unwrap_or_default(),
                    "value":field.get("value").map(value_to_string).unwrap_or_default(),
                    "type":field.get("kind").and_then(Value::as_str).unwrap_or("text"),
                    "disabled":field.get("enabled").and_then(Value::as_bool) == Some(false)
                });
                if field.get("kind").and_then(Value::as_str) == Some("file") {
                    value["src"] = field
                        .get("filePath")
                        .or_else(|| field.get("fileName"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    if let Some(content_type) = field.get("contentType") {
                        value["contentType"] = content_type.clone();
                    }
                }
                value
            })
            .collect::<Vec<_>>();
        let mut body = json!({"mode":key});
        body[key] = Value::Array(values);
        return Some(body);
    }
    if draft.body_type == "file" {
        let file = serde_json::from_str::<Value>(&draft.body).unwrap_or(Value::Null);
        return Some(
            json!({"mode":"file","file":{"src":file.get("filePath").and_then(Value::as_str).unwrap_or(&draft.body)}}),
        );
    }
    let language = match draft.body_type.as_str() {
        "json" => "json",
        "xml" => "xml",
        "text" => "text",
        _ => "",
    };
    Some(json!({"mode":"raw","raw":draft.body,"options":{"raw":{"language":language}}}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_importing_the_same_form_does_not_look_like_a_new_request() {
        // The parsed field objects carry a fresh uuid each time, and the
        // fingerprint drives duplicate detection. If those ids reached it,
        // importing the same HAR twice would create a second copy every time —
        // a duplicate storm caused by the import fix rather than by the file.
        let har = json!({
            "log":{"entries":[{"request":{
                "method":"POST","url":"https://api.example.test/login",
                "headers":[],
                "postData":{"mimeType":"application/x-www-form-urlencoded","text":"user=ada&pass=x"}
            }}]}
        });
        let first = parse_har(&har, "fallback".to_string()).unwrap();
        let second = parse_har(&har, "fallback".to_string()).unwrap();
        assert_ne!(
            first.items[0].body, second.items[0].body,
            "the ids really do differ, so the fingerprint has to strip them"
        );
        assert_eq!(
            import_item_fingerprint(&first.items[0]),
            import_item_fingerprint(&second.items[0]),
            "the same file must fingerprint the same way twice"
        );

        // And a genuinely different form still fingerprints differently.
        let other = json!({
            "log":{"entries":[{"request":{
                "method":"POST","url":"https://api.example.test/login",
                "headers":[],
                "postData":{"mimeType":"application/x-www-form-urlencoded","text":"user=bob&pass=x"}
            }}]}
        });
        let other = parse_har(&other, "fallback".to_string()).unwrap();
        assert_ne!(
            import_item_fingerprint(&first.items[0]),
            import_item_fingerprint(&other.items[0])
        );
    }

    #[test]
    fn a_har_form_survives_the_round_trip_to_postman() {
        // The import fix is only worth anything if the shape it produces is the
        // one export expects. Before it, a Chrome HAR form imported as "raw",
        // so this exported a raw string where Postman describes urlencoded
        // entries — and re-importing it elsewhere would have lost the fields
        // again.
        let har = json!({
            "log":{"entries":[{"request":{
                "method":"POST","url":"https://api.example.test/login",
                "headers":[],
                "postData":{"mimeType":"application/x-www-form-urlencoded","text":"user=ada&pass=a%20b%26c"}
            }}]}
        });
        let imported = parse_har(&har, "fallback".to_string()).unwrap();
        let item = &imported.items[0];
        assert_eq!(item.body_type, "urlencoded");

        let collection = collection("HAR form");
        let draft = draft_from_import_item(item, "draft-har-form", &collection.id);
        let exported =
            render_collection_export("postman", &collection, &[], &[draft], &[]).unwrap();
        let value: Value = serde_json::from_str(&exported).unwrap();

        let body = value
            .pointer("/item/0/request/body")
            .expect("the exported request carries a body");
        assert_eq!(body["mode"], "urlencoded", "{body}");
        let entries = body["urlencoded"]
            .as_array()
            .expect("urlencoded entries are a list");
        assert_eq!(entries.len(), 2, "{body}");
        assert_eq!(entries[0]["key"], "user");
        assert_eq!(entries[0]["value"], "ada");
        // Decoded once on import and not re-encoded on the way out.
        assert_eq!(entries[1]["key"], "pass");
        assert_eq!(entries[1]["value"], "a b&c");
        assert_eq!(entries[0]["disabled"], false);
    }

    #[test]
    fn a_numeric_spec_parameter_keeps_its_value() {
        // page=1 and limit=50 are how specs actually write these, and as_str()
        // returns None for a JSON number — so the query arrived as `?page=`
        // and the imported request asked for something else entirely.
        let mut builder = ImportBuilder::new();
        let parameters = vec![
            json!({"name":"page","value":1}),
            json!({"name":"limit","value":50}),
            json!({"name":"active","value":true}),
            json!({"name":"q","value":"tea & coffee"}),
            json!({"name":"skipped","value":null}),
        ];
        let url = insomnia_url(
            "https://api.example.test/items",
            Some(&parameters),
            &HashMap::new(),
            &mut builder,
        );
        assert!(url.contains("page=1"), "{url}");
        assert!(url.contains("limit=50"), "{url}");
        assert!(url.contains("active=true"), "{url}");
        // Strings still work, and encoding is unchanged.
        assert!(
            url.contains("q=tea+%26+coffee") || url.contains("q=tea%20%26%20coffee"),
            "{url}"
        );
        // A null value stays empty rather than becoming the text "null".
        assert!(
            url.contains("skipped=&") || url.ends_with("skipped="),
            "{url}"
        );
    }

    #[test]
    fn a_form_example_written_as_a_string_is_not_dropped() {
        // structured_fields_from_example took `as_object().unwrap_or_default()`,
        // so a spec writing `example: "a=1&b=2"` — ordinary for form content —
        // imported as an empty field list. The label said urlencoded and the
        // body was gone, which is worse than the wrong label the HAR path had.
        assert_eq!(structured_fields_from_example(&json!(null)), "[]");

        let fields: Value = serde_json::from_str(&structured_fields_from_example(&json!(
            "user=ada&pass=a%20b"
        )))
        .unwrap();
        let fields = fields.as_array().expect("a field array");
        assert_eq!(fields.len(), 2, "the body must survive the import");
        assert_eq!(fields[0]["name"], "user");
        assert_eq!(fields[0]["value"], "ada");
        assert_eq!(fields[1]["value"], "a b");

        // An object example keeps working exactly as before.
        let fields: Value = serde_json::from_str(&structured_fields_from_example(
            &json!({"user":"ada","count":3}),
        ))
        .unwrap();
        let fields = fields.as_array().unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields
            .iter()
            .any(|f| f["name"] == "user" && f["value"] == "ada"));
        assert!(fields
            .iter()
            .any(|f| f["name"] == "count" && f["value"] == "3"));
    }

    #[test]
    fn a_har_form_imports_as_fields_whichever_way_the_browser_recorded_it() {
        // Chrome writes postData.text for a urlencoded form; others write
        // postData.params. Both describe the same request, and both must reach
        // the workbench as editable fields — the text variant used to arrive as
        // body_type "raw", losing the field editor for exactly the forms most
        // likely to be captured from a browser.
        let as_text = json!({
            "log":{"entries":[{"request":{
                "method":"POST","url":"https://api.example.test/login",
                "headers":[],
                "postData":{"mimeType":"application/x-www-form-urlencoded","text":"user=ada&pass=a%20b%26c"}
            }}]}
        });
        let preview = parse_har(&as_text, "fallback".to_string()).unwrap();
        assert_eq!(preview.items.len(), 1);
        assert_eq!(preview.items[0].body_type, "urlencoded");
        let fields: Value = serde_json::from_str(&preview.items[0].body).unwrap();
        let fields = fields
            .as_array()
            .expect("a urlencoded body is a field array");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0]["name"], "user");
        assert_eq!(fields[0]["value"], "ada");
        assert_eq!(fields[0]["kind"], "text");
        assert!(fields[0]["enabled"].as_bool().unwrap());
        // Percent-encoding is decoded, so the editor shows what was sent.
        assert_eq!(fields[1]["name"], "pass");
        assert_eq!(fields[1]["value"], "a b&c");

        // The params variant already worked; it must keep working and agree.
        let as_params = json!({
            "log":{"entries":[{"request":{
                "method":"POST","url":"https://api.example.test/login",
                "headers":[],
                "postData":{"mimeType":"application/x-www-form-urlencoded",
                    "params":[{"name":"user","value":"ada"},{"name":"pass","value":"a b&c"}]}
            }}]}
        });
        let preview = parse_har(&as_params, "fallback".to_string()).unwrap();
        assert_eq!(preview.items[0].body_type, "urlencoded");
        let params_fields: Value = serde_json::from_str(&preview.items[0].body).unwrap();
        let params_fields = params_fields.as_array().unwrap();
        assert_eq!(params_fields.len(), 2);
        assert_eq!(params_fields[1]["value"], "a b&c");

        // A body that is not a form is untouched.
        let raw = json!({
            "log":{"entries":[{"request":{
                "method":"POST","url":"https://api.example.test/raw",
                "headers":[],
                "postData":{"mimeType":"text/plain","text":"hello"}
            }}]}
        });
        let preview = parse_har(&raw, "fallback".to_string()).unwrap();
        assert_eq!(preview.items[0].body_type, "raw");
        assert_eq!(preview.items[0].body, "hello");
    }

    #[test]
    fn parses_postman_tree_and_preserves_credentials() {
        let value = json!({
            "info":{"name":"Demo"},
            "item":[{"name":"Users","item":[{"name":"Get user","request":{
                "method":"GET","url":"https://api.example.test/users/1?token=secret","auth":{"type":"bearer","bearer":[{"key":"token","value":"postman-token"}]},
                "header":[{"key":"Authorization","value":"Bearer secret"},{"key":"Accept","value":"application/json"}]
            }}]}]
        });
        let preview = parse_postman(&value, "fallback".to_string()).unwrap();
        assert_eq!(preview.items.len(), 1);
        assert_eq!(preview.items[0].folder_path, vec!["Users"]);
        assert_eq!(preview.items[0].headers.len(), 2);
        assert!(preview.items[0].url.contains("token=secret"));
        assert_eq!(preview.items[0].auth["token"], "postman-token");
        assert_eq!(preview.items[0].headers[0].value, "Bearer secret");
    }

    #[test]
    fn imports_shownet_exports_with_folders_and_collection_headers() {
        let value = json!({
            "format":"shownet-request-collection",
            "version":1,
            "collection":{
                "name":"Round trip",
                "description":"Private collection description",
                "defaults":{
                    "headers":[{"name":"X-Tenant","value":"demo"}],
                    "auth":{"kind":"bearer","token":"collection-token"},
                    "environmentId":"environment-secret-id"
                },
                "source":{"format":"openapi","path":"/private/specs/source.yaml","fingerprint":"source-fingerprint-secret","syncedAt":1234}
            },
            "folders":[
                {"id":"parent","name":"Users","depth":1},
                {"id":"child","parentId":"parent","name":"Profile","depth":2}
            ],
            "requests":[{
                "name":"Read profile",
                "method":"GET",
                "url":"https://api.example.test/profile",
                "headers":[{"name":"Accept","value":"application/json"}],
                "body":"",
                "bodyType":"none",
                "folderId":"child",
                "auth":{"kind":"none"},
                "settings":{"cookieJar":true,"customToken":"settings-secret"},
                "environmentId":"environment-secret-id",
                "tags":["auth","smoke"]
            }]
        });
        let preview = parse_shownet(&value, "fallback".to_string()).unwrap();
        assert_eq!(preview.source_format, "shownet");
        assert_eq!(preview.suggested_name, "Round trip");
        let metadata = preview.collection.as_ref().unwrap();
        assert_eq!(metadata.description, "Private collection description");
        assert_eq!(metadata.default_headers[0].value, "demo");
        assert_eq!(metadata.default_auth["token"], "collection-token");
        assert_eq!(
            metadata.default_environment_id.as_deref(),
            Some("environment-secret-id")
        );
        assert_eq!(metadata.source_format.as_deref(), Some("openapi"));
        assert_eq!(
            metadata.source_path.as_deref(),
            Some("/private/specs/source.yaml")
        );
        assert_eq!(
            metadata.source_fingerprint.as_deref(),
            Some("source-fingerprint-secret")
        );
        assert_eq!(metadata.source_synced_at, Some(1234));
        assert_eq!(preview.items[0].folder_path, vec!["Users", "Profile"]);
        assert_eq!(preview.items[0].headers.len(), 2);
        assert_eq!(preview.items[0].auth["token"], "collection-token");
        assert_eq!(preview.items[0].settings["customToken"], "settings-secret");
        assert_eq!(
            preview.items[0].environment_id.as_deref(),
            Some("environment-secret-id")
        );
        assert_eq!(preview.items[0].tags, vec!["auth", "smoke"]);
    }

    #[test]
    fn preserves_unmapped_postman_auth_for_lossless_reexport() {
        let value = json!({
            "info":{"name":"Auth metadata"},
            "item":[{"name":"Digest login","request":{
                "method":"GET",
                "url":"https://api.example.test/private",
                "auth":{"type":"digest","digest":[
                    {"key":"username","value":"developer"},
                    {"key":"password","value":"digest-password-secret"},
                    {"key":"clientSecret","value":"oauth-client-secret"}
                ]}
            }}]
        });
        let preview = parse_postman(&value, "fallback".to_string()).unwrap();
        assert_eq!(preview.items[0].auth["kind"], "none");
        assert_eq!(
            preview.items[0].settings[IMPORT_SOURCE_AUTH_KEY]["value"]["digest"][1]["value"],
            "digest-password-secret"
        );

        let collection = collection("Auth metadata");
        let draft = RequestDraft {
            id: "draft-digest".into(),
            session_id: None,
            source_request_id: None,
            name: preview.items[0].name.clone(),
            method: preview.items[0].method.clone(),
            url: preview.items[0].url.clone(),
            headers: preview.items[0].headers.clone(),
            body: preview.items[0].body.clone(),
            body_type: preview.items[0].body_type.clone(),
            auth: preview.items[0].auth.clone(),
            settings: preview.items[0].settings.clone(),
            environment_id: None,
            collection_id: Some(collection.id.clone()),
            folder_id: None,
            tags: vec![],
            spec_operation_key: None,
            spec_fingerprint: None,
            created_at: 0,
            updated_at: 0,
        };
        let exported =
            render_collection_export("postman", &collection, &[], &[draft], &[]).unwrap();
        assert!(exported.contains("digest-password-secret"));
        assert!(exported.contains("oauth-client-secret"));
        assert_eq!(
            serde_json::from_str::<Value>(&exported).unwrap()["item"][0]["request"]["auth"]["type"],
            "digest"
        );
    }

    #[test]
    fn disabled_postman_credentials_and_file_fields_survive_both_exports() {
        let source = json!({
            "info":{"name":"Disabled credentials"},
            "variable":[{"key":"disabled_header","value":"resolved-disabled-header-secret","type":"secret"}],
            "item":[{"name":"Disabled login","request":{
                "method":"POST",
                "url":{
                    "raw":"https://api.example.test/login?active=1",
                    "query":[
                        {"key":"active","value":"1"},
                        {"key":"disabled_token","value":"disabled-query-secret","disabled":true}
                    ]
                },
                "header":[
                    {"key":"Authorization","value":"Bearer active-secret"},
                    {"key":"X-Disabled-Token","value":"{{disabled_header}}","disabled":true}
                ],
                "body":{"mode":"formdata","formdata":[
                    {"key":"username","value":"developer","type":"text"},
                    {"key":"password","value":"disabled-body-secret","type":"text","disabled":true},
                    {"key":"certificate","src":"/private/tmp/disabled-client-secret.pem","type":"file","disabled":true}
                ]}
            }}]
        });
        let imported = parse_postman(&source, "fallback".to_string()).unwrap();
        let item = &imported.items[0];
        assert_eq!(item.headers.len(), 1);
        assert_eq!(
            item.settings[IMPORT_SOURCE_COMPONENTS_KEY]["disabledHeaders"][0]["value"],
            "resolved-disabled-header-secret"
        );
        assert_eq!(
            item.settings[IMPORT_SOURCE_COMPONENTS_KEY]["disabledQuery"][0]["value"],
            "disabled-query-secret"
        );
        let fields = serde_json::from_str::<Vec<Value>>(&item.body).unwrap();
        assert!(fields.iter().any(|field| {
            field["name"] == "password"
                && field["value"] == "disabled-body-secret"
                && field["enabled"] == false
        }));
        assert!(fields.iter().any(|field| {
            field["name"] == "certificate"
                && field["filePath"] == "/private/tmp/disabled-client-secret.pem"
                && field["enabled"] == false
        }));

        let collection = collection("Disabled credentials");
        let draft = draft_from_import_item(item, "draft-disabled-postman", &collection.id);
        let shownet = render_collection_export(
            "shownet",
            &collection,
            &[],
            &[draft.clone()],
            &imported.environments,
        )
        .unwrap();
        for expected in [
            "resolved-disabled-header-secret",
            "disabled-query-secret",
            "disabled-body-secret",
            "/private/tmp/disabled-client-secret.pem",
        ] {
            assert!(shownet.contains(expected), "missing {expected}");
        }

        let postman = render_collection_export(
            "postman",
            &collection,
            &[],
            &[draft],
            &imported.environments,
        )
        .unwrap();
        let value = serde_json::from_str::<Value>(&postman).unwrap();
        let request = &value["item"][0]["request"];
        assert!(request["header"].as_array().unwrap().iter().any(|header| {
            header["key"] == "X-Disabled-Token"
                && header["value"] == "resolved-disabled-header-secret"
                && header["disabled"] == true
        }));
        assert!(request["url"]["query"]
            .as_array()
            .unwrap()
            .iter()
            .any(|query| {
                query["key"] == "disabled_token"
                    && query["value"] == "disabled-query-secret"
                    && query["disabled"] == true
            }));
        assert!(request["body"]["formdata"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| {
                field["key"] == "password"
                    && field["value"] == "disabled-body-secret"
                    && field["disabled"] == true
            }));

        let reparsed = parse_postman(&value, "fallback".to_string()).unwrap();
        assert!(reparsed.items[0]
            .settings
            .to_string()
            .contains("resolved-disabled-header-secret"));
        assert!(reparsed.items[0]
            .settings
            .to_string()
            .contains("disabled-query-secret"));
        assert!(reparsed.items[0].body.contains("disabled-body-secret"));
        assert!(reparsed.items[0]
            .body
            .contains("/private/tmp/disabled-client-secret.pem"));
    }

    #[test]
    fn graphql_and_unknown_postman_body_values_are_never_replaced_with_empty_content() {
        let source = json!({
            "info":{"name":"Body modes"},
            "item":[
                {"name":"GraphQL login","request":{
                    "method":"POST",
                    "url":"https://api.example.test/graphql",
                    "body":{"mode":"graphql","graphql":{
                        "query":"mutation Login($password: String!) { login(password: $password) { token } }",
                        "variables":"{\"password\":\"graphql-password-secret\",\"token\":\"graphql-token-secret\"}"
                    }}
                }},
                {"name":"Future body mode","request":{
                    "method":"POST",
                    "url":"https://api.example.test/future",
                    "body":{"mode":"future-mode","future-mode":{
                        "password":"future-password-secret",
                        "token":"future-token-secret"
                    }}
                }}
            ]
        });
        let imported = parse_postman(&source, "fallback".to_string()).unwrap();
        assert_eq!(imported.items.len(), 2);
        let graphql = imported
            .items
            .iter()
            .find(|item| item.name == "GraphQL login")
            .unwrap();
        assert_eq!(graphql.body_type, "json");
        assert!(graphql.body.contains("graphql-password-secret"));
        assert!(graphql.body.contains("graphql-token-secret"));
        assert!(graphql.body.contains("mutation Login"));
        let future = imported
            .items
            .iter()
            .find(|item| item.name == "Future body mode")
            .unwrap();
        assert_eq!(future.body_type, "raw");
        assert!(future.body.contains("future-password-secret"));
        assert!(future.body.contains("future-token-secret"));
        assert!(imported
            .warnings
            .iter()
            .any(|warning| warning.contains("原始负载已作为 Raw 正文保留")));

        let collection = collection("Body modes");
        let drafts = imported
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                draft_from_import_item(item, &format!("draft-body-{index}"), &collection.id)
            })
            .collect::<Vec<_>>();
        for format in ["shownet", "postman"] {
            let exported =
                render_collection_export(format, &collection, &[], &drafts, &imported.environments)
                    .unwrap();
            for expected in [
                "graphql-password-secret",
                "graphql-token-secret",
                "future-password-secret",
                "future-token-secret",
            ] {
                assert!(exported.contains(expected), "{format} missing {expected}");
            }
        }
    }

    #[test]
    fn structured_postman_urls_and_multi_file_paths_import_without_loss() {
        let source = json!({
            "info":{"name":"Structured request"},
            "item":[{"name":"Upload certificates","request":{
                "method":"POST",
                "url":{
                    "protocol":"https",
                    "host":"developer:url-password-secret@api.example.test",
                    "port":"8443",
                    "path":["v1","upload"],
                    "query":[
                        {"key":"api_token","value":"structured-query-secret"},
                        {"key":"disabled_token","value":"structured-disabled-secret","disabled":true}
                    ]
                },
                "body":{"mode":"formdata","formdata":[
                    {"key":"certificates","src":["/private/tmp/client-a-secret.pem","/private/tmp/client-b-secret.pem"],"type":"file"},
                    {"key":"pin","value":123456,"type":"text"}
                ]}
            }}]
        });
        let imported = parse_postman(&source, "fallback".to_string()).unwrap();
        let item = &imported.items[0];
        assert_eq!(
            item.url,
            "https://developer:url-password-secret@api.example.test:8443/v1/upload?api_token=structured-query-secret"
        );
        assert_eq!(
            item.settings[IMPORT_SOURCE_COMPONENTS_KEY]["disabledQuery"][0]["value"],
            "structured-disabled-secret"
        );
        let fields = serde_json::from_str::<Vec<Value>>(&item.body).unwrap();
        assert_eq!(
            fields
                .iter()
                .filter(|field| field["name"] == "certificates")
                .count(),
            2
        );
        assert!(fields
            .iter()
            .any(|field| field["filePath"] == "/private/tmp/client-a-secret.pem"));
        assert!(fields
            .iter()
            .any(|field| field["filePath"] == "/private/tmp/client-b-secret.pem"));
        assert!(fields
            .iter()
            .any(|field| field["name"] == "pin" && field["value"] == "123456"));

        let collection = collection("Structured request");
        let draft = draft_from_import_item(item, "draft-structured", &collection.id);
        for format in ["shownet", "postman"] {
            let exported = render_collection_export(
                format,
                &collection,
                &[],
                &[draft.clone()],
                &imported.environments,
            )
            .unwrap();
            for expected in [
                "url-password-secret",
                "structured-query-secret",
                "structured-disabled-secret",
                "/private/tmp/client-a-secret.pem",
                "/private/tmp/client-b-secret.pem",
                "123456",
            ] {
                assert!(exported.contains(expected), "{format} missing {expected}");
            }
        }
    }

    #[test]
    fn disabled_insomnia_credentials_survive_postman_conversion() {
        let source = json!({
            "_type":"export",
            "resources":[
                {"_id":"workspace-disabled","_type":"workspace","name":"Disabled Insomnia"},
                {"_id":"environment-disabled","_type":"environment","parentId":"workspace-disabled","name":"Private","data":{"disabled_header":"insomnia-disabled-header-secret"}},
                {"_id":"request-disabled","_type":"request","parentId":"workspace-disabled","name":"Disabled request","method":"POST","url":"https://api.example.test/login","parameters":[
                    {"name":"disabled_token","value":"insomnia-disabled-query-secret","disabled":true}
                ],"headers":[
                    {"name":"Authorization","value":"Bearer active-secret"},
                    {"name":"X-Disabled-Token","value":"{{ _.disabled_header }}","disabled":true}
                ],"body":{"mimeType":"multipart/form-data","params":[
                    {"name":"password","value":"insomnia-disabled-body-secret","type":"text","disabled":true},
                    {"name":"certificate","fileName":"/private/tmp/insomnia-disabled-secret.pem","type":"file","disabled":true}
                ]}}
            ]
        });
        let imported = parse_insomnia(&source, "fallback".to_string()).unwrap();
        let item = &imported.items[0];
        assert_eq!(item.headers.len(), 1);
        assert!(item
            .settings
            .to_string()
            .contains("insomnia-disabled-header-secret"));
        assert!(item
            .settings
            .to_string()
            .contains("insomnia-disabled-query-secret"));
        assert!(item.body.contains("insomnia-disabled-body-secret"));
        assert!(item
            .body
            .contains("/private/tmp/insomnia-disabled-secret.pem"));

        let collection = collection("Disabled Insomnia");
        let draft = draft_from_import_item(item, "draft-disabled-insomnia", &collection.id);
        let postman = render_collection_export(
            "postman",
            &collection,
            &[],
            &[draft],
            &imported.environments,
        )
        .unwrap();
        let value = serde_json::from_str::<Value>(&postman).unwrap();
        let request = &value["item"][0]["request"];
        assert!(request["header"].as_array().unwrap().iter().any(|header| {
            header["value"] == "insomnia-disabled-header-secret" && header["disabled"] == true
        }));
        assert!(request["url"]["query"]
            .as_array()
            .unwrap()
            .iter()
            .any(|query| {
                query["value"] == "insomnia-disabled-query-secret" && query["disabled"] == true
            }));
        assert!(request["body"]["formdata"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| {
                field["value"] == "insomnia-disabled-body-secret" && field["disabled"] == true
            }));
        assert!(postman.contains("/private/tmp/insomnia-disabled-secret.pem"));
    }

    #[test]
    fn imports_insomnia_http_requests_and_preserves_credentials() {
        let value = json!({
            "_type":"export",
            "__export_format":4,
            "resources":[
                {"_id":"wrk_demo","_type":"workspace","name":"Insomnia Demo"},
                {"_id":"env_demo","_type":"environment","parentId":"wrk_demo","data":{"base_url":"https://api.example.test","token":"secret"}},
                {"_id":"fld_users","_type":"request_group","parentId":"wrk_demo","name":"Users"},
                {"_id":"req_user","_type":"request","parentId":"fld_users","name":"Create user","method":"POST","url":"{{ _.base_url }}/users",
                 "parameters":[{"name":"access_token","value":"secret"}],
                 "headers":[{"name":"Authorization","value":"Bearer secret"},{"name":"Accept","value":"application/json"}],
                 "authentication":{"type":"bearer","token":"secret"},
                 "body":{"mimeType":"application/json","text":"{\"name\":\"Ada\"}"}},
                {"_id":"ws_demo","_type":"websocket_request","parentId":"wrk_demo","name":"Events"}
            ]
        });
        let preview = parse_insomnia(&value, "fallback".to_string()).unwrap();
        assert_eq!(preview.source_format, "insomnia");
        assert_eq!(preview.suggested_name, "Insomnia Demo");
        assert_eq!(preview.items.len(), 1);
        assert_eq!(preview.items[0].folder_path, vec!["Users"]);
        assert_eq!(preview.items[0].body_type, "json");
        assert!(preview.items[0]
            .url
            .starts_with("https://api.example.test/users?"));
        assert!(preview.items[0].url.contains("access_token=secret"));
        assert_eq!(preview.items[0].headers.len(), 2);
        assert_eq!(preview.items[0].headers[0].value, "Bearer secret");
        assert_eq!(preview.items[0].auth["token"], "secret");
        assert!(preview
            .warnings
            .iter()
            .any(|warning| warning.contains("WebSocket/gRPC")));
    }

    #[test]
    fn parses_openapi_yaml_with_examples() {
        let value = serde_yaml::from_str::<Value>(
            r#"
openapi: 3.0.3
info: { title: Example API }
servers: [{ url: https://api.example.test }]
paths:
  /users/{id}:
    get:
      tags: [Users]
      summary: Read user
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
        - { in: query, name: page, schema: { type: integer, default: 1 } }
"#,
        )
        .unwrap();
        let preview = parse_openapi(&value, "fallback".to_string()).unwrap();
        assert_eq!(preview.suggested_name, "Example API");
        assert_eq!(preview.items[0].method, "GET");
        assert!(preview.items[0]
            .url
            .contains("/users/%7B%7Bid%7D%7D?page=1"));
    }

    #[test]
    fn openapi_operation_keys_and_fingerprints_ignore_json_yaml_formatting() {
        let json_value = serde_json::from_str::<Value>(
            r#"{
              "openapi": "3.0.3",
              "info": { "title": "Stable API" },
              "servers": [{ "url": "https://api.example.test" }],
              "paths": {
                "/widgets/{id}": {
                  "get": {
                    "summary": "Read widget",
                    "tags": ["Widgets"],
                    "parameters": [
                      { "name": "expand", "in": "query", "schema": { "type": "string", "default": "full" } },
                      { "name": "X-Trace", "in": "header", "example": "demo" }
                    ]
                  }
                }
              }
            }"#,
        )
        .unwrap();
        let yaml_value = serde_yaml::from_str::<Value>(
            r#"
openapi: 3.0.3
info:
  title: Stable API
servers:
  - url: https://api.example.test
paths:
  /widgets/{id}:
    get:
      summary: Read widget
      tags:
        - Widgets
      parameters:
        - name: expand
          in: query
          schema:
            type: string
            default: full
        - name: X-Trace
          in: header
          example: demo
"#,
        )
        .unwrap();

        assert_eq!(json_fingerprint(&json_value), json_fingerprint(&yaml_value));
        let json_preview = parse_openapi(&json_value, "json".to_string()).unwrap();
        let yaml_preview = parse_openapi(&yaml_value, "yaml".to_string()).unwrap();
        assert_eq!(json_preview.items.len(), 1);
        assert_eq!(
            json_preview.items[0].source_key.as_deref(),
            Some("GET /widgets/{id}")
        );
        assert_eq!(
            json_preview.items[0].source_key,
            yaml_preview.items[0].source_key
        );
        assert_eq!(
            json_preview.items[0].source_fingerprint,
            yaml_preview.items[0].source_fingerprint
        );
    }

    #[test]
    fn parses_har_and_groups_by_host() {
        let value = json!({"log":{"entries":[{"request":{
            "method":"POST","url":"https://api.example.test/login","headers":[{"name":"Cookie","value":"sid=secret"}],
            "postData":{"mimeType":"application/json","text":"{\"username\":\"demo\"}"}
        }}]}});
        let preview = parse_har(&value, "capture".to_string()).unwrap();
        assert_eq!(preview.items[0].folder_path, vec!["api.example.test"]);
        assert_eq!(preview.items[0].body_type, "json");
        assert_eq!(preview.items[0].headers[0].name, "Cookie");
        assert_eq!(preview.items[0].headers[0].value, "sid=secret");
    }

    #[test]
    fn exports_collection_defaults_with_auth_headers_and_environment_reference() {
        let collection = RequestCollection {
            id: "collection-shop".into(),
            name: "Shop API".into(),
            description: "Shared defaults".into(),
            default_headers: vec![
                HeaderEntry {
                    name: "X-Tenant".into(),
                    value: "{{tenant}}".into(),
                },
                HeaderEntry {
                    name: "Authorization".into(),
                    value: "Bearer header-secret".into(),
                },
            ],
            default_auth: json!({"kind":"bearer","token":"auth-secret"}),
            default_environment_id: Some("environment-private-id".into()),
            source_format: Some("openapi".into()),
            source_path: Some("/Users/private/specs/shop.openapi.yaml".into()),
            source_fingerprint: Some("f".repeat(64)),
            source_synced_at: Some(123),
            sort_order: 0,
            draft_count: 0,
            folder_count: 0,
            created_at: 0,
            updated_at: 0,
        };

        for format in ["shownet", "postman"] {
            let content = render_collection_export(format, &collection, &[], &[], &[]).unwrap();
            let value: Value = serde_json::from_str(&content).unwrap();
            let defaults = if format == "shownet" {
                value.pointer("/collection/defaults").unwrap()
            } else {
                value.pointer("/_shownet/collectionDefaults").unwrap()
            };
            let source = if format == "shownet" {
                value.pointer("/collection/source").unwrap()
            } else {
                value.pointer("/_shownet/source").unwrap()
            };
            assert_eq!(defaults["headers"][0]["name"], "X-Tenant");
            assert_eq!(
                defaults["auth"],
                json!({"kind":"bearer","token":"auth-secret"})
            );
            assert_eq!(defaults["environmentId"], "environment-private-id");
            assert!(content.contains("header-secret"));
            assert!(content.contains("auth-secret"));
            assert!(content.contains("environment-private-id"));
            assert_eq!(source["format"], "openapi");
            assert_eq!(source["path"], "/Users/private/specs/shop.openapi.yaml");
            assert_eq!(source["fingerprint"], "f".repeat(64));
            assert_eq!(source["syncedAt"], 123);
        }
    }

    #[test]
    fn exports_request_tags_in_shownet_and_postman_extensions() {
        let collection = collection("Shop API");
        let draft = RequestDraft {
            id: "draft-login".into(),
            session_id: None,
            source_request_id: None,
            name: "Login".into(),
            method: "POST".into(),
            url: "https://api.example.test/login".into(),
            headers: vec![],
            body: String::new(),
            body_type: "none".into(),
            auth: json!({"kind":"none"}),
            settings: json!({"cookieJar":true,"privateSetting":"setting-secret"}),
            environment_id: Some("environment-private-id".into()),
            collection_id: Some(collection.id.clone()),
            folder_id: None,
            tags: vec!["auth".into(), "smoke".into()],
            spec_operation_key: None,
            spec_fingerprint: None,
            created_at: 0,
            updated_at: 0,
        };

        let shownet: Value = serde_json::from_str(
            &render_collection_export("shownet", &collection, &[], &[draft.clone()], &[]).unwrap(),
        )
        .unwrap();
        let postman: Value = serde_json::from_str(
            &render_collection_export("postman", &collection, &[], &[draft], &[]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            shownet.pointer("/requests/0/tags").unwrap(),
            &json!(["auth", "smoke"])
        );
        assert_eq!(
            postman.pointer("/item/0/_shownet/tags").unwrap(),
            &json!(["auth", "smoke"])
        );
        let imported = parse_shownet(&shownet, "fallback".to_string()).unwrap();
        assert_eq!(imported.items[0].tags, vec!["auth", "smoke"]);
        assert_eq!(
            imported.items[0].settings["privateSetting"],
            "setting-secret"
        );
        assert_eq!(
            imported.items[0].environment_id.as_deref(),
            Some("environment-private-id")
        );
    }

    #[test]
    fn postman_file_and_multipart_paths_survive_import_export_round_trip() {
        let source = json!({
            "info":{"name":"File requests"},
            "item":[
                {"name":"Upload archive","request":{
                    "method":"POST",
                    "url":"https://api.example.test/archive",
                    "body":{"mode":"file","file":{"src":"/private/tmp/archive-secret.zip"}}
                }},
                {"name":"Upload certificate","request":{
                    "method":"POST",
                    "url":"https://api.example.test/certificate",
                    "body":{"mode":"formdata","formdata":[
                        {"key":"password","value":"multipart-password-secret","type":"text"},
                        {"key":"certificate","src":"/private/tmp/client-secret.pem","type":"file","contentType":"application/x-pem-file"}
                    ]}
                }}
            ]
        });
        let imported = parse_postman(&source, "fallback".to_string()).unwrap();
        assert_eq!(imported.items.len(), 2);
        assert!(imported.items[0]
            .body
            .contains("/private/tmp/archive-secret.zip"));
        assert!(imported.items[1].body.contains("multipart-password-secret"));
        assert!(imported.items[1]
            .body
            .contains("/private/tmp/client-secret.pem"));

        let collection = collection("File requests");
        let drafts = imported
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| RequestDraft {
                id: format!("draft-file-{index}"),
                session_id: None,
                source_request_id: None,
                name: item.name.clone(),
                method: item.method.clone(),
                url: item.url.clone(),
                headers: item.headers.clone(),
                body: item.body.clone(),
                body_type: item.body_type.clone(),
                auth: item.auth.clone(),
                settings: item.settings.clone(),
                environment_id: item.environment_id.clone(),
                collection_id: Some(collection.id.clone()),
                folder_id: None,
                tags: item.tags.clone(),
                spec_operation_key: None,
                spec_fingerprint: None,
                created_at: 0,
                updated_at: 0,
            })
            .collect::<Vec<_>>();
        let exported = render_collection_export("postman", &collection, &[], &drafts, &[]).unwrap();
        let reparsed = parse_postman(
            &serde_json::from_str::<Value>(&exported).unwrap(),
            "fallback".to_string(),
        )
        .unwrap();
        let archive = reparsed
            .items
            .iter()
            .find(|item| item.name == "Upload archive")
            .unwrap();
        let certificate = reparsed
            .items
            .iter()
            .find(|item| item.name == "Upload certificate")
            .unwrap();
        assert!(archive.body.contains("/private/tmp/archive-secret.zip"));
        assert!(certificate.body.contains("multipart-password-secret"));
        assert!(certificate.body.contains("/private/tmp/client-secret.pem"));
    }

    #[test]
    fn insomnia_file_and_multipart_paths_survive_shownet_round_trip() {
        let source = json!({
            "_type":"export",
            "__export_format":4,
            "resources":[
                {"_id":"workspace-files","_type":"workspace","name":"Insomnia files"},
                {"_id":"request-file","_type":"request","parentId":"workspace-files","name":"Binary upload","method":"POST","url":"https://api.example.test/binary","body":{"mimeType":"application/octet-stream","fileName":"/private/tmp/insomnia-secret.bin"}},
                {"_id":"request-form","_type":"request","parentId":"workspace-files","name":"Form upload","method":"POST","url":"https://api.example.test/form","body":{"mimeType":"multipart/form-data","params":[
                    {"name":"password","value":"insomnia-password-secret","type":"text"},
                    {"name":"document","fileName":"/private/tmp/insomnia-secret.pdf","type":"file","contentType":"application/pdf"}
                ]}}
            ]
        });
        let imported = parse_insomnia(&source, "fallback".to_string()).unwrap();
        assert!(imported.items[0]
            .body
            .contains("/private/tmp/insomnia-secret.bin"));
        assert!(imported.items[1].body.contains("insomnia-password-secret"));
        assert!(imported.items[1]
            .body
            .contains("/private/tmp/insomnia-secret.pdf"));

        let collection = collection("Insomnia files");
        let drafts = imported
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| RequestDraft {
                id: format!("draft-insomnia-{index}"),
                session_id: None,
                source_request_id: None,
                name: item.name.clone(),
                method: item.method.clone(),
                url: item.url.clone(),
                headers: item.headers.clone(),
                body: item.body.clone(),
                body_type: item.body_type.clone(),
                auth: item.auth.clone(),
                settings: item.settings.clone(),
                environment_id: item.environment_id.clone(),
                collection_id: Some(collection.id.clone()),
                folder_id: None,
                tags: item.tags.clone(),
                spec_operation_key: None,
                spec_fingerprint: None,
                created_at: 0,
                updated_at: 0,
            })
            .collect::<Vec<_>>();
        let exported = render_collection_export("shownet", &collection, &[], &drafts, &[]).unwrap();
        let reparsed = parse_shownet(
            &serde_json::from_str::<Value>(&exported).unwrap(),
            "fallback".to_string(),
        )
        .unwrap();
        assert!(reparsed.items[0]
            .body
            .contains("/private/tmp/insomnia-secret.bin"));
        assert!(reparsed.items[1].body.contains("insomnia-password-secret"));
        assert!(reparsed.items[1]
            .body
            .contains("/private/tmp/insomnia-secret.pdf"));
    }

    #[test]
    fn portable_environment_values_and_secrets_survive_both_export_formats() {
        let mut collection = collection("Environment API");
        collection.description = "Portable collection metadata".into();
        collection.default_environment_id = Some("environment-production".into());
        collection.source_format = Some("openapi".into());
        collection.source_path = Some("/private/specs/environment-api.yaml".into());
        collection.source_fingerprint = Some("portable-source-fingerprint".into());
        collection.source_synced_at = Some(9_876);
        let draft = RequestDraft {
            id: "draft-environment".into(),
            session_id: None,
            source_request_id: None,
            name: "Authenticated request".into(),
            method: "GET".into(),
            url: "https://api.example.test/items?token={{token}}".into(),
            headers: vec![HeaderEntry {
                name: "X-Tenant".into(),
                value: "{{tenant}}".into(),
            }],
            body: String::new(),
            body_type: "none".into(),
            auth: no_auth(),
            settings: default_request_settings(),
            environment_id: Some("environment-production".into()),
            collection_id: Some(collection.id.clone()),
            folder_id: None,
            tags: vec![],
            spec_operation_key: None,
            spec_fingerprint: None,
            created_at: 0,
            updated_at: 0,
        };
        let environments = vec![CollectionImportEnvironment {
            source_id: "environment-production".into(),
            name: "Production".into(),
            variables: vec![
                CollectionImportEnvironmentVariable {
                    name: "tenant".into(),
                    value: "north".into(),
                    secret: false,
                    enabled: true,
                },
                CollectionImportEnvironmentVariable {
                    name: "token".into(),
                    value: "portable-environment-secret".into(),
                    secret: true,
                    enabled: true,
                },
            ],
        }];

        for format in ["shownet", "postman"] {
            let exported =
                render_collection_export(format, &collection, &[], &[draft.clone()], &environments)
                    .unwrap();
            assert!(exported.contains("portable-environment-secret"));
            let value = serde_json::from_str::<Value>(&exported).unwrap();
            if format == "postman" {
                assert_eq!(value["variable"][1]["type"], "secret");
                assert_eq!(value["variable"][1]["value"], "portable-environment-secret");
            }
            let preview = if format == "shownet" {
                parse_shownet(&value, "fallback".to_string()).unwrap()
            } else {
                parse_postman(&value, "fallback".to_string()).unwrap()
            };
            let metadata = preview.collection.as_ref().unwrap();
            assert_eq!(metadata.description, "Portable collection metadata");
            assert_eq!(metadata.source_format.as_deref(), Some("openapi"));
            assert_eq!(
                metadata.source_path.as_deref(),
                Some("/private/specs/environment-api.yaml")
            );
            assert_eq!(
                metadata.source_fingerprint.as_deref(),
                Some("portable-source-fingerprint")
            );
            assert_eq!(metadata.source_synced_at, Some(9_876));
            assert_eq!(preview.environments.len(), 1);
            assert_eq!(preview.environments[0].source_id, "environment-production");
            assert!(preview.environments[0].variables.iter().any(|variable| {
                variable.name == "token"
                    && variable.value == "portable-environment-secret"
                    && variable.secret
            }));
            assert_eq!(
                preview.items[0].environment_id.as_deref(),
                Some("environment-production")
            );
        }
    }

    fn collection(name: &str) -> RequestCollection {
        RequestCollection {
            id: "collection-shop".into(),
            name: name.into(),
            description: String::new(),
            default_headers: vec![],
            default_auth: json!({"kind":"none"}),
            default_environment_id: None,
            source_format: None,
            source_path: None,
            source_fingerprint: None,
            source_synced_at: None,
            sort_order: 0,
            draft_count: 1,
            folder_count: 0,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn draft_from_import_item(
        item: &CollectionImportItem,
        id: &str,
        collection_id: &str,
    ) -> RequestDraft {
        RequestDraft {
            id: id.into(),
            session_id: None,
            source_request_id: None,
            name: item.name.clone(),
            method: item.method.clone(),
            url: item.url.clone(),
            headers: item.headers.clone(),
            body: item.body.clone(),
            body_type: item.body_type.clone(),
            auth: item.auth.clone(),
            settings: item.settings.clone(),
            environment_id: item.environment_id.clone(),
            collection_id: Some(collection_id.into()),
            folder_id: None,
            tags: item.tags.clone(),
            spec_operation_key: None,
            spec_fingerprint: None,
            created_at: 0,
            updated_at: 0,
        }
    }
}
