use crate::analysis_graph::AnalysisGraphRun;
use crate::browser_hook;
use crate::client_access::normalize_capture_listener_settings;
use crate::crypto;
use crate::crypto_code;
use crate::interchange::{
    validate_bundle, BundleEvent, BundleRequest, BundleSession, SessionBundle, BUNDLE_FORMAT,
    BUNDLE_VERSION,
};
use crate::mirror::validate_mirror_action;
#[cfg(test)]
use crate::models::ClientAccessMode;
use crate::models::{
    AiAnalysisSettings, AiProviderSettings, AiProviderSettingsInput, AnalysisActivity,
    AnalysisChatMessage, AnalysisReport, BodyCaptureMetadata, BrowserHookEvent, BrowserHookInput,
    CaptureEvent, CaptureEventInput, CaptureListenerSettings, CaptureRule, CaptureRuleInput,
    CaptureRuleRevision, CaptureRuleRun, CapturedRequestInput, CollectionImportCommitInput,
    CollectionImportEnvironment, CollectionImportEnvironmentVariable, CollectionImportItem,
    CollectionImportMetadata, CollectionImportResult, CollectionSyncChange,
    CollectionSyncCommitInput, CollectionSyncPreview, CollectionSyncResult,
    CollectionSyncSelection, CryptoCodeSnippet, DataStorageSettings, DataStorageSettingsInput,
    EffectiveAiProviderSettings, EffectiveMcpClientSettings, EffectiveMcpServerSettings,
    EffectiveUpstreamProxy, EnvironmentInput, EnvironmentRecord, EnvironmentVariable,
    EnvironmentVariableInput, FacetCount, FilterExpression, HookRecord, McpClientSettings,
    McpClientSettingsInput, McpServerSettings, McpServerSettingsInput, ReplayBatch,
    ReplayBatchInput, ReplayBatchItem, RequestAnnotation, RequestAnnotationInput,
    RequestAnnotationSummary, RequestCollection, RequestCollectionFolder,
    RequestCollectionFolderInput, RequestCollectionInput, RequestCollectionWorkspace, RequestDraft,
    RequestDraftBatchUpdateInput, RequestDraftInput, RequestDraftLocationInput, RequestFacets,
    RequestListItem, RequestListPage, RequestListWindow, RequestQuery, RequestRecord, RequestRun,
    RequestWindowQuery, ReverseProxySettings, SavedRequestView, SavedRequestViewInput,
    SessionRecord, SkillRunAudit, SkillToolCallAudit, StorageStats, StoredAiProviderSettings,
    StoredCertificateAuthority, StoredMcpClientSettings, StoredMcpServerSettings,
    StoredSystemProxySettings, SystemProxySettingsInput, UpstreamProxySettings,
    UpstreamProxySettingsInput,
};
use crate::system_proxy::SystemProxySnapshot;
use crate::tls_interception::{normalize_tls_interception_settings, TlsInterceptionSettings};
use chrono::{DateTime, Local, SecondsFormat, Utc};
use cookie_store::CookieStore;
use regex::Regex;
use rusqlite::functions::FunctionFlags;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Transaction};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'idle' CHECK (status IN ('idle', 'active')),
  request_count INTEGER NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0,
  last_sequence INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS capture_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL,
  timestamp INTEGER NOT NULL,
  source TEXT NOT NULL,
  source_instance_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  phase TEXT NOT NULL CHECK (phase IN ('request', 'response', 'websocket', 'sse', 'hook', 'interaction', 'storage', 'connection')),
  payload_json TEXT NOT NULL,
  UNIQUE(session_id, sequence)
);

CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL,
  source TEXT NOT NULL,
  source_instance_id TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  method TEXT NOT NULL,
  scheme TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER,
  path TEXT NOT NULL,
  query TEXT,
  status INTEGER NOT NULL DEFAULT 0,
  resource_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  protocol TEXT NOT NULL,
  tls_version TEXT,
  risk_level TEXT NOT NULL DEFAULT 'none',
  request_headers_json TEXT NOT NULL DEFAULT '[]',
  response_headers_json TEXT NOT NULL DEFAULT '[]',
  request_body TEXT,
  response_body TEXT,
  response_body_meta_json TEXT NOT NULL DEFAULT '{}',
  crypto_snippets_json TEXT NOT NULL DEFAULT '[]',
  hook_json TEXT,
  UNIQUE(session_id, sequence)
);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_capture_events_session_sequence
  ON capture_events(session_id, sequence);
CREATE INDEX IF NOT EXISTS idx_requests_session_sequence
  ON requests(session_id, sequence);
CREATE INDEX IF NOT EXISTS idx_requests_session_host
  ON requests(session_id, host);
CREATE INDEX IF NOT EXISTS idx_requests_session_status
  ON requests(session_id, status);

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES (1, unixepoch('now') * 1000);
"#;

const UPSTREAM_PROXY_KEY: &str = "upstream_proxy";
const CERTIFICATE_AUTHORITY_KEY: &str = "certificate_authority";
const AI_PROVIDER_KEY: &str = "ai_provider";
const AI_ANALYSIS_KEY: &str = "ai_analysis";
const MCP_SERVER_KEY: &str = "mcp_server";
const MCP_CLIENTS_KEY: &str = "mcp_clients";
const SYSTEM_PROXY_KEY: &str = "system_proxy";
const CAPTURE_LISTENER_KEY: &str = "capture_listener";
const TLS_INTERCEPTION_KEY: &str = "tls_interception";
const REVERSE_PROXY_KEY: &str = "reverse_proxy";
const DATA_STORAGE_KEY: &str = "data_storage";
const SYSTEM_PROXY_RECOVERY_KEY: &str = "system_proxy_recovery";
const REQUEST_COOKIE_JAR_KEY: &str = "request_cookie_jar";
const CREDENTIAL_AAD: &[u8] = b"shownet/upstream-proxy/v1";
const AI_CREDENTIAL_AAD: &[u8] = b"shownet/ai-provider/v1";
const MCP_CREDENTIAL_AAD: &[u8] = b"shownet/mcp-server/v1";
const MCP_CLIENT_CREDENTIAL_AAD: &[u8] = b"shownet/mcp-client/v1/";
const SYSTEM_PROXY_RECOVERY_AAD: &[u8] = b"shownet/system-proxy-recovery/v1";
const REQUEST_COOKIE_JAR_AAD: &[u8] = b"shownet/request-cookie-jar/v1";
const ENVIRONMENT_SECRET_AAD_PREFIX: &[u8] = b"shownet/environment-secret/v1/";
const REQUEST_DRAFT_AUTH_AAD_PREFIX: &[u8] = b"shownet/request-draft-auth/v1/";
const REQUEST_COLLECTION_AUTH_AAD_PREFIX: &[u8] = b"shownet/request-collection-auth/v1/";
const REPLAY_CONTEXT_HEADER: &str = "x-shownet-replay-context";
const MAX_REQUEST_DRAFT_TAGS: usize = 20;
const MAX_REQUEST_DRAFT_TAG_CHARS: usize = 40;
const MAX_REQUEST_DRAFT_BATCH: usize = 500;
pub(crate) const REQUEST_QUERY_CANCELLED: &str = "REQUEST_QUERY_CANCELLED";

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredUpstreamProxySettings {
    mode: String,
    host: String,
    port: u16,
    username: String,
    encrypted_password: Option<String>,
    bypass: Vec<String>,
}

pub struct Storage {
    connection: Mutex<Connection>,
    database_path: Option<PathBuf>,
    data_storage_settings: RwLock<DataStorageSettings>,
    tls_interception_settings: RwLock<TlsInterceptionSettings>,
}

struct PreparedCollectionImportEnvironment {
    id: String,
    name: String,
    variables: Vec<PreparedCollectionImportEnvironmentVariable>,
}

struct PreparedCollectionImportEnvironmentVariable {
    id: String,
    name: String,
    value: Option<String>,
    encrypted_value: Option<String>,
    secret: bool,
    enabled: bool,
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| error.to_string())?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        Self::from_connection_with_path(connection, Some(path.to_path_buf()))
    }

    #[cfg(test)]
    fn from_connection(connection: Connection) -> Result<Self, String> {
        Self::from_connection_with_path(connection, None)
    }

    fn from_connection_with_path(
        connection: Connection,
        database_path: Option<PathBuf>,
    ) -> Result<Self, String> {
        register_sql_functions(&connection)?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|error| error.to_string())?;
        apply_migrations(&connection)?;
        let data_storage_settings =
            read_json_setting(&connection, DATA_STORAGE_KEY)?.unwrap_or_default();
        let tls_interception_settings =
            read_json_setting::<TlsInterceptionSettings>(&connection, TLS_INTERCEPTION_KEY)?
                .map(normalize_tls_interception_settings)
                .transpose()?
                .unwrap_or_default();
        Ok(Self {
            connection: Mutex::new(connection),
            database_path,
            data_storage_settings: RwLock::new(data_storage_settings),
            tls_interception_settings: RwLock::new(tls_interception_settings),
        })
    }

    pub(crate) fn in_memory() -> Result<Self, String> {
        Self::from_connection_with_path(
            Connection::open_in_memory().map_err(|error| error.to_string())?,
            None,
        )
    }

    pub fn ensure_initial_session(&self) -> Result<(), String> {
        let count: i64 = self.with_connection(|connection| {
            connection.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
        })?;
        if count == 0 {
            self.create_session(Some("首次抓包".to_string()))?;
        }
        Ok(())
    }

    pub fn get_data_storage_settings(&self) -> Result<DataStorageSettings, String> {
        self.data_storage_settings
            .read()
            .map(|settings| settings.clone())
            .map_err(|_| "数据存储设置状态已损坏".to_string())
    }

    pub fn get_tls_interception_settings(&self) -> Result<TlsInterceptionSettings, String> {
        self.tls_interception_settings
            .read()
            .map(|settings| settings.clone())
            .map_err(|_| "HTTPS 解密策略状态已损坏".to_string())
    }

    pub fn save_tls_interception_settings(
        &self,
        settings: TlsInterceptionSettings,
    ) -> Result<TlsInterceptionSettings, String> {
        let settings = normalize_tls_interception_settings(settings)?;
        let value = serde_json::to_string(&settings).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![TLS_INTERCEPTION_KEY, value, now_ms()],
            )?;
            Ok(())
        })?;
        *self
            .tls_interception_settings
            .write()
            .map_err(|_| "HTTPS 解密策略状态已损坏".to_string())? = settings.clone();
        Ok(settings)
    }

    pub fn save_data_storage_settings(
        &self,
        input: DataStorageSettingsInput,
    ) -> Result<DataStorageSettings, String> {
        if !(1..=3_650).contains(&input.retention_days) {
            return Err("会话保留天数必须在 1 到 3650 天之间".to_string());
        }
        let settings = DataStorageSettings {
            auto_cleanup_enabled: input.auto_cleanup_enabled,
            retention_days: input.retention_days,
            save_binary_responses: input.save_binary_responses,
        };
        let value = serde_json::to_string(&settings).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![DATA_STORAGE_KEY, value, now_ms()],
            )?;
            Ok(())
        })?;
        *self
            .data_storage_settings
            .write()
            .map_err(|_| "数据存储设置状态已损坏".to_string())? = settings.clone();
        Ok(settings)
    }

    pub fn storage_stats(&self) -> Result<StorageStats, String> {
        let (session_count, request_count, response_body_bytes, logical_database_bytes) = self
            .with_connection(|connection| {
                let session_count =
                    connection.query_row("SELECT COUNT(*) FROM sessions", [], |row| {
                        row.get::<_, i64>(0)
                    })?;
                let request_count =
                    connection.query_row("SELECT COUNT(*) FROM requests", [], |row| {
                        row.get::<_, i64>(0)
                    })?;
                let response_body_bytes = connection.query_row(
                    "SELECT COALESCE(SUM(LENGTH(CAST(response_body AS BLOB))), 0) FROM requests",
                    [],
                    |row| row.get::<_, i64>(0),
                )?;
                let page_count = connection
                    .pragma_query_value(None, "page_count", |row| row.get::<_, i64>(0))?;
                let page_size =
                    connection.pragma_query_value(None, "page_size", |row| row.get::<_, i64>(0))?;
                Ok((
                    session_count,
                    request_count,
                    response_body_bytes,
                    page_count.saturating_mul(page_size),
                ))
            })?;
        let database_bytes = self
            .database_path
            .as_deref()
            .map(sqlite_physical_bytes)
            .filter(|bytes| *bytes > 0)
            .unwrap_or(logical_database_bytes);
        let database_path = self
            .database_path
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| ":memory:".to_string());
        let data_directory = self
            .database_path
            .as_deref()
            .and_then(Path::parent)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| ":memory:".to_string());
        Ok(StorageStats {
            database_bytes,
            response_body_bytes,
            session_count,
            request_count,
            database_path,
            data_directory,
        })
    }

    pub fn save_app_setting_json(
        &self,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<(), String> {
        let encoded = serde_json::to_string(value).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![key, encoded, now_ms()],
            )?;
            Ok(())
        })
    }

    pub fn load_app_setting_json(&self, key: &str) -> Result<Option<serde_json::Value>, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [key],
                    |row| row.get(0),
                )
                .optional()
        })?;
        value
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn load_request_cookie_store(&self) -> Result<CookieStore, String> {
        let Some(value) = self.load_app_setting_json(REQUEST_COOKIE_JAR_KEY)? else {
            return Ok(CookieStore::default());
        };
        let encrypted = value
            .as_str()
            .ok_or_else(|| "Cookie Jar 存储格式无效".to_string())?;
        let plaintext = crypto::decrypt(encrypted, REQUEST_COOKIE_JAR_AAD)?;
        cookie_store::serde::json::load_all(Cursor::new(plaintext))
            .map_err(|error| format!("Cookie Jar 数据损坏: {error}"))
    }

    pub fn save_request_cookie_store(&self, store: &CookieStore) -> Result<(), String> {
        let mut plaintext = Vec::new();
        cookie_store::serde::json::save_incl_expired_and_nonpersistent(store, &mut plaintext)
            .map_err(|error| format!("序列化 Cookie Jar 失败: {error}"))?;
        let encrypted = crypto::encrypt(&plaintext, REQUEST_COOKIE_JAR_AAD)?;
        self.save_app_setting_json(REQUEST_COOKIE_JAR_KEY, &Value::String(encrypted))
    }

    pub fn data_directory(&self) -> Result<PathBuf, String> {
        self.database_path
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .ok_or_else(|| "当前数据库没有可打开的数据目录".to_string())
    }

    pub fn cleanup_expired_sessions(&self) -> Result<usize, String> {
        let settings = self.get_data_storage_settings()?;
        if !settings.auto_cleanup_enabled {
            return Ok(0);
        }
        let retention_ms = settings.retention_days.saturating_mul(24 * 60 * 60 * 1_000);
        let cutoff = now_ms().saturating_sub(retention_ms);
        let removed = self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM sessions WHERE status != 'active' AND updated_at < ?1",
                [cutoff],
            )
        })?;
        self.ensure_initial_session()?;
        Ok(removed)
    }

    pub fn clear_all_session_data(&self) -> Result<SessionRecord, String> {
        let active_count = self.with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM sessions WHERE status = 'active'",
                [],
                |row| row.get::<_, i64>(0),
            )
        })?;
        if active_count > 0 {
            return Err("活动会话不能清除，请先停止抓包".to_string());
        }
        let (id, name, now) = (
            format!("session-{}", Uuid::new_v4()),
            "首次抓包".to_string(),
            now_ms(),
        );
        self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            transaction.execute("DELETE FROM sessions", [])?;
            transaction.execute(
                "INSERT INTO sessions(id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
                params![id, name, now],
            )?;
            transaction.commit()?;
            connection.execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")?;
            Ok(())
        })?;
        self.get_session(&id)
    }

    pub fn get_upstream_proxy_settings(&self) -> Result<UpstreamProxySettings, String> {
        let Some(stored) = self.read_upstream_proxy_settings()? else {
            return Ok(UpstreamProxySettings::default());
        };
        Ok(UpstreamProxySettings {
            mode: stored.mode,
            host: stored.host,
            port: stored.port,
            username: stored.username,
            has_password: stored.encrypted_password.is_some(),
            bypass: stored.bypass,
        })
    }

    pub fn get_capture_listener_settings(&self) -> Result<CaptureListenerSettings, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [CAPTURE_LISTENER_KEY],
                    |row| row.get(0),
                )
                .optional()
        })?;
        let settings = value
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
            .map(|settings| settings.unwrap_or_default())?;
        normalize_capture_listener_settings(settings)
    }

    pub fn save_capture_listener_settings(
        &self,
        settings: CaptureListenerSettings,
    ) -> Result<CaptureListenerSettings, String> {
        let settings = normalize_capture_listener_settings(settings)?;
        let value = serde_json::to_string(&settings).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![CAPTURE_LISTENER_KEY, value, now_ms()],
            )?;
            Ok(())
        })?;
        Ok(settings)
    }

    pub fn get_reverse_proxy_settings(&self) -> Result<ReverseProxySettings, String> {
        let Some(value) = self.load_app_setting_json(REVERSE_PROXY_KEY)? else {
            return Ok(ReverseProxySettings::default());
        };
        serde_json::from_value(value).map_err(|error| error.to_string())
    }

    pub fn save_reverse_proxy_settings(
        &self,
        settings: &ReverseProxySettings,
    ) -> Result<(), String> {
        let value = serde_json::to_value(settings).map_err(|error| error.to_string())?;
        self.save_app_setting_json(REVERSE_PROXY_KEY, &value)
    }

    pub fn get_system_proxy_preferences(&self) -> Result<StoredSystemProxySettings, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [SYSTEM_PROXY_KEY],
                    |row| row.get(0),
                )
                .optional()
        })?;
        value
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
            .map(|settings| settings.unwrap_or_default())
    }

    pub fn save_system_proxy_preferences(
        &self,
        input: SystemProxySettingsInput,
    ) -> Result<StoredSystemProxySettings, String> {
        let settings = StoredSystemProxySettings {
            enabled: input.enabled,
            bypass: normalize_system_bypass(input.bypass),
        };
        let value = serde_json::to_string(&settings).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![SYSTEM_PROXY_KEY, value, now_ms()],
            )?;
            Ok(())
        })?;
        Ok(settings)
    }

    pub fn save_system_proxy_recovery(&self, snapshot: &SystemProxySnapshot) -> Result<(), String> {
        let plaintext = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
        let encrypted = crypto::encrypt(&plaintext, SYSTEM_PROXY_RECOVERY_AAD)?;
        let value = serde_json::to_string(&encrypted).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![SYSTEM_PROXY_RECOVERY_KEY, value, now_ms()],
            )?;
            Ok(())
        })
    }

    pub fn get_system_proxy_recovery(&self) -> Result<Option<SystemProxySnapshot>, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [SYSTEM_PROXY_RECOVERY_KEY],
                    |row| row.get(0),
                )
                .optional()
        })?;
        let Some(value) = value else {
            return Ok(None);
        };
        let encrypted =
            serde_json::from_str::<String>(&value).map_err(|error| error.to_string())?;
        let plaintext = crypto::decrypt(&encrypted, SYSTEM_PROXY_RECOVERY_AAD)?;
        serde_json::from_slice(&plaintext)
            .map(Some)
            .map_err(|error| format!("系统代理恢复记录损坏: {error}"))
    }

    pub fn clear_system_proxy_recovery(&self) -> Result<(), String> {
        self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM app_settings WHERE key = ?1",
                [SYSTEM_PROXY_RECOVERY_KEY],
            )?;
            Ok(())
        })
    }

    pub fn has_system_proxy_recovery(&self) -> Result<bool, String> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM app_settings WHERE key = ?1)",
                [SYSTEM_PROXY_RECOVERY_KEY],
                |row| row.get(0),
            )
        })
    }

    pub fn get_certificate_authority(&self) -> Result<Option<StoredCertificateAuthority>, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [CERTIFICATE_AUTHORITY_KEY],
                    |row| row.get(0),
                )
                .optional()
        })?;
        value
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn save_certificate_authority(
        &self,
        material: &StoredCertificateAuthority,
    ) -> Result<(), String> {
        let value = serde_json::to_string(material).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![CERTIFICATE_AUTHORITY_KEY, value, now_ms()],
            )?;
            Ok(())
        })
    }

    pub fn get_ai_provider_settings(&self) -> Result<AiProviderSettings, String> {
        let Some(stored) = self.read_ai_provider_settings()? else {
            return Ok(AiProviderSettings::default());
        };
        Ok(AiProviderSettings {
            provider: stored.provider,
            base_url: stored.base_url,
            model: stored.model,
            has_api_key: stored.encrypted_api_key.is_some(),
        })
    }

    pub fn get_ai_analysis_settings(&self) -> Result<AiAnalysisSettings, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [AI_ANALYSIS_KEY],
                    |row| row.get(0),
                )
                .optional()
        })?;
        value
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
            .map(|settings| settings.unwrap_or_default())
    }

    pub fn save_ai_analysis_settings(
        &self,
        mut settings: AiAnalysisSettings,
    ) -> Result<AiAnalysisSettings, String> {
        settings.max_agent_turns = settings.max_agent_turns.max(1);
        let value = serde_json::to_string(&settings).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![AI_ANALYSIS_KEY, value, now_ms()],
            )?;
            Ok(())
        })?;
        self.get_ai_analysis_settings()
    }

    pub fn save_ai_provider_settings(
        &self,
        input: AiProviderSettingsInput,
    ) -> Result<AiProviderSettings, String> {
        validate_ai_provider(&input)?;
        let normalized_base_url = input.base_url.trim().trim_end_matches('/').to_string();
        let current = self.read_ai_provider_settings()?;
        let encrypted_api_key = if input.clear_api_key {
            None
        } else if let Some(api_key) = input.api_key.filter(|value| !value.is_empty()) {
            Some(crypto::encrypt(api_key.as_bytes(), AI_CREDENTIAL_AAD)?)
        } else {
            current.and_then(|settings| {
                (settings.base_url.trim().trim_end_matches('/') == normalized_base_url)
                    .then_some(settings.encrypted_api_key)
                    .flatten()
            })
        };
        let stored = StoredAiProviderSettings {
            provider: input.provider,
            base_url: normalized_base_url,
            model: input.model.trim().to_string(),
            encrypted_api_key,
        };
        let value = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![AI_PROVIDER_KEY, value, now_ms()],
            )?;
            Ok(())
        })?;
        self.get_ai_provider_settings()
    }

    pub fn effective_ai_provider_settings(&self) -> Result<EffectiveAiProviderSettings, String> {
        let Some(stored) = self.read_ai_provider_settings()? else {
            let default = AiProviderSettings::default();
            return Ok(EffectiveAiProviderSettings {
                provider: default.provider,
                base_url: default.base_url,
                model: default.model,
                api_key: None,
            });
        };
        let api_key = stored
            .encrypted_api_key
            .as_deref()
            .map(|value| crypto::decrypt(value, AI_CREDENTIAL_AAD))
            .transpose()?
            .map(|value| {
                String::from_utf8(value).map_err(|_| "AI API Key 不是有效 UTF-8".to_string())
            })
            .transpose()?;
        Ok(EffectiveAiProviderSettings {
            provider: stored.provider,
            base_url: stored.base_url,
            model: stored.model,
            api_key,
        })
    }

    fn read_ai_provider_settings(&self) -> Result<Option<StoredAiProviderSettings>, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [AI_PROVIDER_KEY],
                    |row| row.get(0),
                )
                .optional()
        })?;
        value
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn ensure_mcp_server_settings(&self) -> Result<McpServerSettings, String> {
        if self.read_mcp_server_settings()?.is_none() {
            let defaults = McpServerSettings::default();
            self.write_mcp_server_settings(StoredMcpServerSettings {
                enabled: defaults.enabled,
                port: defaults.port,
                allow_writes: defaults.allow_writes,
                encrypted_access_token: crypto::encrypt(
                    generate_mcp_access_token().as_bytes(),
                    MCP_CREDENTIAL_AAD,
                )?,
            })?;
        }
        self.get_mcp_server_settings()
    }

    pub fn get_mcp_server_settings(&self) -> Result<McpServerSettings, String> {
        let Some(stored) = self.read_mcp_server_settings()? else {
            return Ok(McpServerSettings::default());
        };
        Ok(McpServerSettings {
            enabled: stored.enabled,
            port: stored.port,
            allow_writes: stored.allow_writes,
            has_access_token: !stored.encrypted_access_token.is_empty(),
        })
    }

    pub fn save_mcp_server_settings(
        &self,
        input: McpServerSettingsInput,
    ) -> Result<McpServerSettings, String> {
        validate_mcp_server_settings(&input)?;
        let token = self
            .read_mcp_server_settings()?
            .map(|settings| settings.encrypted_access_token)
            .filter(|value| !value.is_empty())
            .unwrap_or(crypto::encrypt(
                generate_mcp_access_token().as_bytes(),
                MCP_CREDENTIAL_AAD,
            )?);
        self.write_mcp_server_settings(StoredMcpServerSettings {
            enabled: input.enabled,
            port: input.port,
            allow_writes: input.allow_writes,
            encrypted_access_token: token,
        })?;
        self.get_mcp_server_settings()
    }

    pub fn reveal_mcp_access_token(&self) -> Result<String, String> {
        Ok(self.effective_mcp_server_settings()?.access_token)
    }

    pub fn rotate_mcp_access_token(&self) -> Result<String, String> {
        let current = self
            .read_mcp_server_settings()?
            .unwrap_or_else(|| StoredMcpServerSettings {
                enabled: true,
                port: 8899,
                allow_writes: false,
                encrypted_access_token: String::new(),
            });
        let token = generate_mcp_access_token();
        self.write_mcp_server_settings(StoredMcpServerSettings {
            encrypted_access_token: crypto::encrypt(token.as_bytes(), MCP_CREDENTIAL_AAD)?,
            ..current
        })?;
        Ok(token)
    }

    pub fn effective_mcp_server_settings(&self) -> Result<EffectiveMcpServerSettings, String> {
        let stored = self
            .read_mcp_server_settings()?
            .ok_or_else(|| "MCP 服务尚未初始化".to_string())?;
        let access_token = String::from_utf8(crypto::decrypt(
            &stored.encrypted_access_token,
            MCP_CREDENTIAL_AAD,
        )?)
        .map_err(|_| "MCP 访问令牌不是有效文本".to_string())?;
        Ok(EffectiveMcpServerSettings {
            enabled: stored.enabled,
            port: stored.port,
            allow_writes: stored.allow_writes,
            access_token,
        })
    }

    fn read_mcp_server_settings(&self) -> Result<Option<StoredMcpServerSettings>, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [MCP_SERVER_KEY],
                    |row| row.get(0),
                )
                .optional()
        })?;
        value
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    fn write_mcp_server_settings(&self, stored: StoredMcpServerSettings) -> Result<(), String> {
        let value = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![MCP_SERVER_KEY, value, now_ms()],
            )?;
            Ok(())
        })
    }

    pub fn list_mcp_client_settings(&self) -> Result<Vec<McpClientSettings>, String> {
        Ok(self
            .read_mcp_clients()?
            .into_iter()
            .map(public_mcp_client_settings)
            .collect())
    }

    pub fn effective_mcp_clients(&self) -> Result<Vec<EffectiveMcpClientSettings>, String> {
        self.read_mcp_clients()?
            .into_iter()
            .filter(|server| server.enabled)
            .map(|server| {
                let access_token = server
                    .encrypted_access_token
                    .as_deref()
                    .map(|encrypted| {
                        let plaintext = crypto::decrypt(encrypted, &mcp_client_aad(&server.id))?;
                        String::from_utf8(plaintext)
                            .map_err(|_| "外部 MCP 访问令牌不是有效文本".to_string())
                    })
                    .transpose()?;
                Ok(EffectiveMcpClientSettings {
                    id: server.id,
                    name: server.name,
                    endpoint: server.endpoint,
                    access_token,
                })
            })
            .collect()
    }

    pub fn effective_mcp_client(&self, id: &str) -> Result<EffectiveMcpClientSettings, String> {
        self.read_mcp_clients()?
            .into_iter()
            .find(|server| server.id == id)
            .ok_or_else(|| "外部 MCP Server 不存在".to_string())
            .and_then(|server| {
                let access_token = server
                    .encrypted_access_token
                    .as_deref()
                    .map(|encrypted| {
                        let plaintext = crypto::decrypt(encrypted, &mcp_client_aad(&server.id))?;
                        String::from_utf8(plaintext)
                            .map_err(|_| "外部 MCP 访问令牌不是有效文本".to_string())
                    })
                    .transpose()?;
                Ok(EffectiveMcpClientSettings {
                    id: server.id,
                    name: server.name,
                    endpoint: server.endpoint,
                    access_token,
                })
            })
    }

    pub fn save_mcp_client_settings(
        &self,
        input: McpClientSettingsInput,
    ) -> Result<McpClientSettings, String> {
        validate_mcp_client_settings(&input)?;
        let mut servers = self.read_mcp_clients()?;
        let id = input
            .id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("mcp-client-{}", Uuid::new_v4()));
        let current = servers.iter().find(|server| server.id == id).cloned();
        if current.is_none() && servers.len() >= 16 {
            return Err("最多可配置 16 个外部 MCP Server".to_string());
        }
        let endpoint = input.endpoint.trim().trim_end_matches('/').to_string();
        if servers
            .iter()
            .any(|server| server.id != id && server.endpoint.eq_ignore_ascii_case(&endpoint))
        {
            return Err("该 MCP Server 地址已存在".to_string());
        }
        if mcp_endpoint_is_self(&endpoint, self.get_mcp_server_settings()?.port) {
            return Err("不能把 ShowNet 自己的 MCP Server 配置为外部 Server".to_string());
        }
        let encrypted_access_token = if input.clear_access_token {
            None
        } else if let Some(token) = input
            .access_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(crypto::encrypt(token.as_bytes(), &mcp_client_aad(&id))?)
        } else {
            current.as_ref().and_then(|server| {
                server
                    .endpoint
                    .eq_ignore_ascii_case(&endpoint)
                    .then(|| server.encrypted_access_token.clone())
                    .flatten()
            })
        };
        let stored = StoredMcpClientSettings {
            id: id.clone(),
            name: input.name.trim().to_string(),
            endpoint,
            enabled: input.enabled,
            encrypted_access_token,
            tool_count: current.as_ref().map_or(0, |server| server.tool_count),
            last_connected_at: current.as_ref().and_then(|server| server.last_connected_at),
            last_error: None,
        };
        if let Some(index) = servers.iter().position(|server| server.id == id) {
            servers[index] = stored.clone();
        } else {
            servers.push(stored.clone());
        }
        self.write_mcp_clients(&servers)?;
        Ok(public_mcp_client_settings(stored))
    }

    pub fn delete_mcp_client_settings(&self, id: &str) -> Result<(), String> {
        let mut servers = self.read_mcp_clients()?;
        let before = servers.len();
        servers.retain(|server| server.id != id);
        if servers.len() == before {
            return Err("外部 MCP Server 不存在".to_string());
        }
        self.write_mcp_clients(&servers)
    }

    pub fn update_mcp_client_status(
        &self,
        id: &str,
        tool_count: usize,
        error: Option<&str>,
    ) -> Result<McpClientSettings, String> {
        let mut servers = self.read_mcp_clients()?;
        let server = servers
            .iter_mut()
            .find(|server| server.id == id)
            .ok_or_else(|| "外部 MCP Server 不存在".to_string())?;
        server.tool_count = tool_count;
        server.last_error = error.map(|value| truncate_setting(value, 1_024));
        if error.is_none() {
            server.last_connected_at = Some(now_ms());
        }
        let public = public_mcp_client_settings(server.clone());
        self.write_mcp_clients(&servers)?;
        Ok(public)
    }

    pub fn begin_mcp_client_log(&self, server_id: &str, tool_name: &str) -> Result<String, String> {
        let id = format!("mcp-call-{}", Uuid::new_v4());
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO mcp_client_logs(id, server_id, tool_name, status, error, started_at, finished_at)
                 VALUES (?1, ?2, ?3, 'running', NULL, ?4, NULL)",
                params![id, server_id, truncate_setting(tool_name, 256), now_ms()],
            )?;
            Ok(())
        })?;
        Ok(id)
    }

    pub fn finish_mcp_client_log(
        &self,
        id: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), String> {
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE mcp_client_logs SET status = ?2, error = ?3, finished_at = ?4 WHERE id = ?1",
                params![id, status, error.map(|value| truncate_setting(value, 2_048)), now_ms()],
            )?;
            Ok(())
        })
    }

    fn read_mcp_clients(&self) -> Result<Vec<StoredMcpClientSettings>, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [MCP_CLIENTS_KEY],
                    |row| row.get(0),
                )
                .optional()
        })?;
        value
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
            .map(|value| value.unwrap_or_default())
    }

    fn write_mcp_clients(&self, servers: &[StoredMcpClientSettings]) -> Result<(), String> {
        let value = serde_json::to_string(servers).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![MCP_CLIENTS_KEY, value, now_ms()],
            )?;
            Ok(())
        })
    }

    pub fn save_upstream_proxy_settings(
        &self,
        input: UpstreamProxySettingsInput,
    ) -> Result<UpstreamProxySettings, String> {
        validate_upstream_proxy(&input)?;
        let current_password = self
            .read_upstream_proxy_settings()?
            .and_then(|settings| settings.encrypted_password);
        let encrypted_password = if input.clear_password {
            None
        } else if let Some(password) = input.password.filter(|value| !value.is_empty()) {
            let encrypted = encrypt_credential(&password)?;
            if decrypt_credential(&encrypted)? != password {
                return Err("出口代理密码加密校验失败".to_string());
            }
            Some(encrypted)
        } else {
            current_password
        };
        let stored = StoredUpstreamProxySettings {
            mode: input.mode,
            host: input.host.trim().to_string(),
            port: input.port,
            username: input.username.trim().to_string(),
            encrypted_password,
            bypass: normalize_bypass(input.bypass),
        };
        let value = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO app_settings(key, value_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                                updated_at = excluded.updated_at",
                params![UPSTREAM_PROXY_KEY, value, now_ms()],
            )?;
            Ok(())
        })?;
        self.get_upstream_proxy_settings()
    }

    pub fn effective_upstream_proxy(&self) -> Result<EffectiveUpstreamProxy, String> {
        let Some(settings) = self.read_upstream_proxy_settings()? else {
            let settings = UpstreamProxySettings::default();
            return Ok(EffectiveUpstreamProxy {
                mode: settings.mode,
                host: settings.host,
                port: settings.port,
                username: settings.username,
                password: None,
                bypass: settings.bypass,
            });
        };
        let password = settings
            .encrypted_password
            .as_deref()
            .map(decrypt_credential)
            .transpose()?;
        Ok(EffectiveUpstreamProxy {
            mode: settings.mode,
            host: settings.host,
            port: settings.port,
            username: settings.username,
            password,
            bypass: settings.bypass,
        })
    }

    #[cfg(test)]
    fn upstream_proxy_password(&self) -> Result<Option<String>, String> {
        Ok(self.effective_upstream_proxy()?.password)
    }

    fn read_upstream_proxy_settings(&self) -> Result<Option<StoredUpstreamProxySettings>, String> {
        let value: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [UPSTREAM_PROXY_KEY],
                    |row| row.get(0),
                )
                .optional()
        })?;
        value
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn create_session(&self, name: Option<String>) -> Result<SessionRecord, String> {
        let id = format!("session-{}", Uuid::new_v4());
        let now = now_ms();
        let name = name
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "未命名会话".to_string());

        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO sessions(id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
                params![id, name, now],
            )?;
            Ok(())
        })?;
        self.get_session(&id)
    }

    pub fn get_session(&self, id: &str) -> Result<SessionRecord, String> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT s.id, s.name, s.created_at, s.request_count, s.error_count, s.status,
                        (SELECT COUNT(*) FROM analysis_reports ar WHERE ar.session_id = s.id),
                        (SELECT ar.status FROM analysis_reports ar WHERE ar.session_id = s.id
                         ORDER BY ar.updated_at DESC LIMIT 1),
                        (SELECT ar.updated_at FROM analysis_reports ar WHERE ar.session_id = s.id
                         ORDER BY ar.updated_at DESC LIMIT 1)
                 FROM sessions s WHERE s.id = ?1",
            )?;
            let base = statement
                .query_row([id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                    ))
                })
                .optional()?
                .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
            let sources = session_sources(connection, id)?;
            Ok(to_session(base, sources))
        })
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionRecord>, String> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT s.id, s.name, s.created_at, s.request_count, s.error_count, s.status,
                        (SELECT COUNT(*) FROM analysis_reports ar WHERE ar.session_id = s.id),
                        (SELECT ar.status FROM analysis_reports ar WHERE ar.session_id = s.id
                         ORDER BY ar.updated_at DESC LIMIT 1),
                        (SELECT ar.updated_at FROM analysis_reports ar WHERE ar.session_id = s.id
                         ORDER BY ar.updated_at DESC LIMIT 1)
                 FROM sessions s ORDER BY s.updated_at DESC, s.created_at DESC",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            })?;
            let mut sessions = Vec::new();
            for row in rows {
                let base = row?;
                let sources = session_sources(connection, &base.0)?;
                sessions.push(to_session(base, sources));
            }
            Ok(sessions)
        })
    }

    pub fn rename_session(&self, id: &str, name: &str) -> Result<SessionRecord, String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err("会话名称不能为空".to_string());
        }
        if trimmed.chars().count() > 60 {
            return Err("会话名称不能超过 60 个字符".to_string());
        }
        let changed = self.with_connection(|connection| {
            connection.execute(
                "UPDATE sessions SET name = ?1, updated_at = ?2 WHERE id = ?3",
                params![trimmed, now_ms(), id],
            )
        })?;
        if changed == 0 {
            return Err("会话不存在".to_string());
        }
        self.get_session(id)
    }

    pub fn delete_session(&self, id: &str) -> Result<(), String> {
        let changed = self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM sessions WHERE id = ?1 AND status != 'active'",
                [id],
            )
        })?;
        if changed == 0 {
            return Err("活动会话不能删除，或会话不存在".to_string());
        }
        Ok(())
    }

    pub fn set_active_session(&self, session_id: Option<&str>) -> Result<(), String> {
        self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "UPDATE sessions SET status = 'idle' WHERE status = 'active'",
                [],
            )?;
            if let Some(id) = session_id {
                let changed = transaction.execute(
                    "UPDATE sessions SET status = 'active', updated_at = ?1 WHERE id = ?2",
                    params![now_ms(), id],
                )?;
                if changed == 0 {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
            }
            transaction.commit()
        })
    }

    pub fn append_event(&self, input: CaptureEventInput) -> Result<CaptureEvent, String> {
        validate_source(&input.source)?;
        validate_phase(&input.phase)?;
        self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            let sequence = next_sequence(&transaction, &input.session_id)?;
            let event = CaptureEvent {
                session_id: input.session_id,
                source: input.source,
                source_instance_id: input
                    .source_instance_id
                    .unwrap_or_else(|| "default".to_string()),
                request_id: input.request_id.unwrap_or_default(),
                sequence,
                timestamp: input.timestamp.unwrap_or_else(now_ms),
                phase: input.phase,
                payload: input.payload,
            };
            transaction.execute(
                "INSERT INTO capture_events(
                   session_id, sequence, timestamp, source, source_instance_id,
                   request_id, phase, payload_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.session_id,
                    event.sequence,
                    event.timestamp,
                    event.source,
                    event.source_instance_id,
                    event.request_id,
                    event.phase,
                    serde_json::to_string(&event.payload).unwrap_or_else(|_| "null".to_string()),
                ],
            )?;
            transaction.execute(
                "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
                params![event.timestamp, event.session_id],
            )?;
            transaction.commit()?;
            Ok(event)
        })
    }

    pub fn list_websocket_events(
        &self,
        request_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<CaptureEvent>, String> {
        let request_id = request_id.trim();
        if request_id.is_empty() {
            return Err("请求 ID 不能为空".to_string());
        }
        let limit = limit.unwrap_or(500).clamp(1, 2_000);
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT session_id, source, source_instance_id, request_id,
                        sequence, timestamp, phase, payload_json
                 FROM capture_events
                 WHERE request_id = ?1 AND phase = 'websocket'
                 ORDER BY sequence ASC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![request_id, limit], |row| {
                let payload: String = row.get(7)?;
                Ok(CaptureEvent {
                    session_id: row.get(0)?,
                    source: row.get(1)?,
                    source_instance_id: row.get(2)?,
                    request_id: row.get(3)?,
                    sequence: row.get(4)?,
                    timestamp: row.get(5)?,
                    phase: row.get(6)?,
                    payload: serde_json::from_str(&payload).unwrap_or(Value::Null),
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn list_sse_events(
        &self,
        request_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<CaptureEvent>, String> {
        let request_id = request_id.trim();
        if request_id.is_empty() {
            return Err("请求 ID 不能为空".to_string());
        }
        let limit = limit.unwrap_or(500).clamp(1, 2_000);
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT session_id, source, source_instance_id, request_id,
                        sequence, timestamp, phase, payload_json
                 FROM capture_events
                 WHERE request_id = ?1 AND phase = 'sse'
                 ORDER BY sequence ASC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![request_id, limit], |row| {
                let payload: String = row.get(7)?;
                Ok(CaptureEvent {
                    session_id: row.get(0)?,
                    source: row.get(1)?,
                    source_instance_id: row.get(2)?,
                    request_id: row.get(3)?,
                    sequence: row.get(4)?,
                    timestamp: row.get(5)?,
                    phase: row.get(6)?,
                    payload: serde_json::from_str(&payload).unwrap_or(Value::Null),
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn store_browser_hook(
        &self,
        input: BrowserHookInput,
    ) -> Result<(BrowserHookEvent, CaptureEvent), String> {
        let input = browser_hook::normalize_input(input)?;
        self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            let timestamp = input
                .timestamp
                .filter(|value| *value > 0 && *value <= now_ms() + 300_000)
                .unwrap_or_else(now_ms);
            let sequence = next_sequence(&transaction, &input.session_id)?;
            let source_instance_id = input
                .source_instance_id
                .clone()
                .unwrap_or_else(|| "embedded-browser".to_string());
            let (request_id, correlation) =
                correlate_browser_hook(&transaction, &input, timestamp)?;
            let event = BrowserHookEvent {
                id: format!("hook-{}", Uuid::new_v4()),
                session_id: input.session_id.clone(),
                source_instance_id: source_instance_id.clone(),
                request_id: request_id.clone(),
                sequence,
                timestamp,
                kind: input.kind,
                name: input.name,
                url: input.url,
                method: input.method,
                input: input.input,
                output: input.output,
                stack: input.stack,
                duration_ms: input.duration_ms,
                correlation,
            };
            let payload = serde_json::to_value(&event).unwrap_or(serde_json::Value::Null);
            transaction.execute(
                "INSERT INTO capture_events(
                   session_id, sequence, timestamp, source, source_instance_id,
                   request_id, phase, payload_json
                 ) VALUES (?1, ?2, ?3, 'browser', ?4, ?5, 'hook', ?6)",
                params![
                    event.session_id,
                    event.sequence,
                    event.timestamp,
                    event.source_instance_id,
                    event.request_id.as_deref().unwrap_or_default(),
                    payload.to_string(),
                ],
            )?;
            if event.kind == "network" {
                if let Some(request_id) = event.request_id.as_deref() {
                    correlate_pending_crypto_hooks_to_request(
                        &transaction,
                        &event.session_id,
                        &event.source_instance_id,
                        request_id,
                        event.timestamp,
                    )?;
                }
            }
            if event.kind == "crypto" || event.kind == "encoding" {
                if let Some(request_id) = event.request_id.as_deref() {
                    let legacy = HookRecord {
                        algorithm: event.name.clone(),
                        input: serde_json::to_string(&event.input)
                            .unwrap_or_else(|_| "null".to_string()),
                        output: serde_json::to_string(&event.output)
                            .unwrap_or_else(|_| "null".to_string()),
                    };
                    transaction.execute(
                        "UPDATE requests SET hook_json = COALESCE(hook_json, ?1)
                         WHERE id = ?2 AND session_id = ?3",
                        params![to_json(&legacy)?, request_id, event.session_id],
                    )?;
                }
            }
            transaction.execute(
                "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
                params![event.timestamp, event.session_id],
            )?;
            transaction.commit()?;
            let capture_event = CaptureEvent {
                session_id: event.session_id.clone(),
                source: "browser".to_string(),
                source_instance_id,
                request_id: request_id.unwrap_or_default(),
                sequence,
                timestamp,
                phase: "hook".to_string(),
                payload,
            };
            Ok((event, capture_event))
        })
    }

    pub fn list_browser_hooks(
        &self,
        session_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<BrowserHookEvent>, String> {
        let limit = limit.unwrap_or(500).clamp(1, 2_000);
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT sequence, timestamp, source_instance_id, request_id, payload_json
                 FROM capture_events
                 WHERE session_id = ?1 AND phase = 'hook'
                 ORDER BY sequence DESC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![session_id, limit], browser_hook_from_row)?;
            Ok(rows
                .filter_map(Result::transpose)
                .collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn list_request_browser_hooks(
        &self,
        request_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<BrowserHookEvent>, String> {
        let limit = limit.unwrap_or(100).clamp(1, 500);
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT sequence, timestamp, source_instance_id, request_id, payload_json
                 FROM capture_events
                 WHERE request_id = ?1 AND phase = 'hook'
                 ORDER BY sequence ASC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![request_id, limit], browser_hook_from_row)?;
            Ok(rows
                .filter_map(Result::transpose)
                .collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn store_request(
        &self,
        mut input: CapturedRequestInput,
    ) -> Result<(RequestRecord, CaptureEvent), String> {
        validate_source(&input.source)?;
        if input.host.trim().is_empty() || input.path.trim().is_empty() {
            return Err("请求 host 和 path 不能为空".to_string());
        }
        let replay_context = take_replay_context(&mut input.request_headers);
        let save_binary_responses = self.get_data_storage_settings()?.save_binary_responses;

        self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            let sequence = next_sequence(&transaction, &input.session_id)?;
            let id = input
                .id
                .unwrap_or_else(|| format!("request-{}", Uuid::new_v4()));
            let timestamp = input.timestamp.unwrap_or_else(now_ms);
            let source_instance_id = input
                .source_instance_id
                .unwrap_or_else(|| "default".to_string());
            let method = input.method.to_uppercase();
            let request_headers_json = to_json(&input.request_headers)?;
            let response_headers_json = to_json(&input.response_headers)?;
            let hook_json = input.hook.as_ref().map(to_json).transpose()?;
            let tls_fingerprint_json = input.tls_fingerprint.as_ref().map(to_json).transpose()?;
            let mut response_body = input.response_body.unwrap_or_default();
            let mut response_body_metadata = input.response_body_metadata.unwrap_or_default();
            if response_body_metadata.format == "base64" && !save_binary_responses {
                response_body.clear();
                response_body_metadata.captured = false;
                response_body_metadata.format = "omitted".to_string();
                response_body_metadata.omitted_reason =
                    Some("binary-response-storage-disabled".to_string());
            }
            let crypto_snippets = input.crypto_snippets.unwrap_or_else(|| {
                extract_crypto_snippets_for_response(
                    &input.resource_type,
                    &input.response_headers,
                    &response_body,
                    &response_body_metadata,
                )
            });
            let response_body_metadata_json = to_json(&response_body_metadata)?;
            let crypto_snippets_json = to_json(&crypto_snippets)?;
            let tls_version = input.tls_version.unwrap_or_else(|| {
                if input.scheme.as_deref() == Some("https") {
                    "TLS".to_string()
                } else {
                    "明文".to_string()
                }
            });

            transaction.execute(
                "INSERT INTO requests(
                   id, session_id, sequence, source, source_instance_id, started_at,
                   method, scheme, host, port, path, query, status, resource_type,
                   size_bytes, duration_ms, protocol, tls_version, risk_level,
                   request_headers_json, response_headers_json, request_body,
                   response_body, response_body_meta_json, crypto_snippets_json,
                   hook_json, tls_fingerprint_json
                 ) VALUES (
                   ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
                   ?25, ?26, ?27
                 )",
                params![
                    id,
                    input.session_id,
                    sequence,
                    input.source,
                    source_instance_id,
                    timestamp,
                    method,
                    input.scheme.unwrap_or_else(|| "http".to_string()),
                    input.host,
                    input.port,
                    input.path,
                    input.query,
                    input.status,
                    input.resource_type,
                    input.size_bytes.max(0),
                    input.duration_ms.max(0),
                    input.protocol,
                    tls_version,
                    input.risk_level,
                    request_headers_json,
                    response_headers_json,
                    input.request_body,
                    response_body,
                    response_body_metadata_json,
                    crypto_snippets_json,
                    hook_json,
                    tls_fingerprint_json,
                ],
            )?;

            if let Some((item_id, source_request_id)) = replay_context.as_ref() {
                transaction.execute(
                    "UPDATE requests SET replayed_from_request_id = ?1 WHERE id = ?2",
                    params![source_request_id, id],
                )?;
                transaction.execute(
                    "UPDATE replay_batch_items SET captured_request_id = ?1 WHERE id = ?2",
                    params![id, item_id],
                )?;
            }

            correlate_pending_browser_hooks(
                &transaction,
                &input.session_id,
                &id,
                timestamp,
                &method,
                &input.host,
                &input.path,
            )?;

            let payload = serde_json::json!({ "requestId": id });
            transaction.execute(
                "INSERT INTO capture_events(
                   session_id, sequence, timestamp, source, source_instance_id,
                   request_id, phase, payload_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'response', ?7)",
                params![
                    input.session_id,
                    sequence,
                    timestamp,
                    input.source,
                    source_instance_id,
                    id,
                    payload.to_string(),
                ],
            )?;
            transaction.execute(
                "UPDATE sessions SET
                   updated_at = ?1,
                   request_count = request_count + 1,
                   error_count = error_count + CASE WHEN ?2 >= 400 THEN 1 ELSE 0 END
                 WHERE id = ?3",
                params![timestamp, input.status, input.session_id],
            )?;
            transaction.commit()?;

            let request = self.get_request_with_connection(connection, &id)?;
            let event = CaptureEvent {
                session_id: input.session_id,
                source: input.source,
                source_instance_id,
                request_id: id,
                sequence,
                timestamp,
                phase: "response".to_string(),
                payload,
            };
            Ok((request, event))
        })
    }

    pub fn update_streaming_request(
        &self,
        mut input: CapturedRequestInput,
    ) -> Result<Option<RequestRecord>, String> {
        let Some(id) = input.id.take() else {
            return Ok(None);
        };
        if input.resource_type != "sse" {
            return Ok(None);
        }
        let save_binary_responses = self.get_data_storage_settings()?.save_binary_responses;
        self.with_connection(|connection| {
            let existing = connection
                .query_row(
                    "SELECT session_id, resource_type FROM requests WHERE id = ?1",
                    [&id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let Some((session_id, resource_type)) = existing else {
                return Ok(None);
            };
            if session_id != input.session_id || resource_type != "sse" {
                return Err(rusqlite::Error::InvalidQuery);
            }

            let mut response_body = input.response_body.unwrap_or_default();
            let mut response_body_metadata = input.response_body_metadata.unwrap_or_default();
            if response_body_metadata.format == "base64" && !save_binary_responses {
                response_body.clear();
                response_body_metadata.captured = false;
                response_body_metadata.format = "omitted".to_string();
                response_body_metadata.omitted_reason =
                    Some("binary-response-storage-disabled".to_string());
            }
            let response_headers_json = to_json(&input.response_headers)?;
            let response_body_metadata_json = to_json(&response_body_metadata)?;
            let updated_at = now_ms();
            connection.execute(
                "UPDATE requests SET
                   status = ?1,
                   size_bytes = ?2,
                   duration_ms = ?3,
                   risk_level = ?4,
                   response_headers_json = ?5,
                   request_body = COALESCE(?6, request_body),
                   response_body = ?7,
                   response_body_meta_json = ?8
                 WHERE id = ?9 AND session_id = ?10 AND resource_type = 'sse'",
                params![
                    input.status,
                    input.size_bytes.max(0),
                    input.duration_ms.max(0),
                    input.risk_level,
                    response_headers_json,
                    input.request_body,
                    response_body,
                    response_body_metadata_json,
                    id,
                    input.session_id,
                ],
            )?;
            connection.execute(
                "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
                params![updated_at, session_id],
            )?;
            Ok(Some(self.get_request_with_connection(connection, &id)?))
        })
        .map_err(|error| {
            if error == "Query is not read-only" || error == "Invalid query" {
                "SSE 流更新与已保存请求不匹配".to_string()
            } else {
                error
            }
        })
    }

    pub fn list_requests(
        &self,
        session_id: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<RequestRecord>, String> {
        let limit = limit.unwrap_or(2_000).clamp(1, 10_000);
        let offset = offset.unwrap_or(0).max(0);
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id FROM requests WHERE session_id = ?1
                 ORDER BY sequence ASC LIMIT ?2 OFFSET ?3",
            )?;
            let ids = statement
                .query_map(params![session_id, limit, offset], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            ids.into_iter()
                .map(|id| self.get_request_with_connection(connection, &id))
                .collect()
        })
    }

    pub fn query_request_list(&self, query: RequestQuery) -> Result<RequestListPage, String> {
        self.query_request_list_inner(query, None)
    }

    pub fn query_request_list_cancellable(
        &self,
        query: RequestQuery,
        cancellation: Arc<AtomicBool>,
    ) -> Result<RequestListPage, String> {
        self.query_request_list_inner(query, Some(cancellation))
    }

    fn query_request_list_inner(
        &self,
        query: RequestQuery,
        cancellation: Option<Arc<AtomicBool>>,
    ) -> Result<RequestListPage, String> {
        let limit = query.limit.clamp(100, 500);
        let offset = decode_request_cursor(query.cursor.as_deref())?;
        let (where_clause, order_clause, filter_params) =
            compile_request_list_query(&query.session_id, query.filter.as_ref(), &query.sort)?;

        let operation = |connection: &mut Connection| {
            let total_count = connection.query_row(
                "SELECT COUNT(*) FROM requests WHERE session_id = ?1",
                [&query.session_id],
                |row| row.get::<_, i64>(0),
            )?;
            let filtered_count = connection.query_row(
                &format!("SELECT COUNT(*) FROM requests r WHERE {where_clause}"),
                params_from_iter(filter_params.iter()),
                |row| row.get::<_, i64>(0),
            )?;
            let hook_count = connection.query_row(
                &format!(
                    "SELECT COUNT(*) FROM requests r WHERE {where_clause} AND r.hook_json IS NOT NULL"
                ),
                params_from_iter(filter_params.iter()),
                |row| row.get::<_, i64>(0),
            )?;
            let bookmarked_count = connection.query_row(
                &format!(
                    "SELECT COUNT(*) FROM requests r JOIN request_annotations a ON a.request_id = r.id WHERE {where_clause} AND a.bookmarked = 1"
                ),
                params_from_iter(filter_params.iter()),
                |row| row.get::<_, i64>(0),
            )?;

            let mut page_params = filter_params.clone();
            page_params.push(SqlValue::Integer(limit));
            page_params.push(SqlValue::Integer(offset));
            let sql = format!(
                "{REQUEST_LIST_SELECT} WHERE {where_clause} ORDER BY {order_clause} LIMIT ? OFFSET ?"
            );
            let mut statement = connection.prepare(&sql)?;
            let items = statement
                .query_map(
                    params_from_iter(page_params.iter()),
                    request_list_item_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            let next_offset = offset.saturating_add(items.len() as i64);
            let next_cursor =
                (next_offset < filtered_count).then(|| encode_request_cursor(next_offset));
            let facets = if offset == 0 {
                RequestFacets {
                    hosts: request_facet_counts(
                        connection,
                        "r.host",
                        &where_clause,
                        &filter_params,
                        100,
                    )?,
                    methods: request_facet_counts(
                        connection,
                        "r.method",
                        &where_clause,
                        &filter_params,
                        16,
                    )?,
                    sources: request_facet_counts(
                        connection,
                        "r.source",
                        &where_clause,
                        &filter_params,
                        16,
                    )?,
                    protocols: request_facet_counts(
                        connection,
                        "r.protocol",
                        &where_clause,
                        &filter_params,
                        16,
                    )?,
                    statuses: request_facet_counts(
                        connection,
                        "CASE WHEN r.status = 0 THEN 'pending' ELSE CAST(r.status AS TEXT) END",
                        &where_clause,
                        &filter_params,
                        64,
                    )?,
                    types: request_facet_counts(
                        connection,
                        "r.resource_type",
                        &where_clause,
                        &filter_params,
                        32,
                    )?,
                    risks: request_facet_counts(
                        connection,
                        "r.risk_level",
                        &where_clause,
                        &filter_params,
                        16,
                    )?,
                }
            } else {
                RequestFacets::default()
            };
            Ok(RequestListPage {
                items,
                next_cursor,
                total_count,
                filtered_count,
                hook_count,
                bookmarked_count,
                facets,
            })
        };
        match cancellation {
            Some(cancellation) => self.with_cancellable_connection(cancellation, operation),
            None => self.with_connection(operation),
        }
    }

    pub fn query_request_window(
        &self,
        query: RequestWindowQuery,
    ) -> Result<RequestListWindow, String> {
        self.query_request_window_inner(query, None)
    }

    pub fn query_request_window_cancellable(
        &self,
        query: RequestWindowQuery,
        cancellation: Arc<AtomicBool>,
    ) -> Result<RequestListWindow, String> {
        self.query_request_window_inner(query, Some(cancellation))
    }

    fn query_request_window_inner(
        &self,
        query: RequestWindowQuery,
        cancellation: Option<Arc<AtomicBool>>,
    ) -> Result<RequestListWindow, String> {
        if !(0..=10_000_000).contains(&query.offset) {
            return Err("offset 必须在 0 到 10000000 之间".to_string());
        }
        let limit = query.limit.clamp(100, 500);
        let (where_clause, order_clause, mut query_params) =
            compile_request_list_query(&query.session_id, query.filter.as_ref(), &query.sort)?;
        query_params.push(SqlValue::Integer(limit));
        query_params.push(SqlValue::Integer(query.offset));
        let sql = format!(
            "{REQUEST_LIST_SELECT} WHERE {where_clause} ORDER BY {order_clause} LIMIT ? OFFSET ?"
        );
        let operation = |connection: &mut Connection| {
            let mut statement = connection.prepare(&sql)?;
            let items = statement
                .query_map(
                    params_from_iter(query_params.iter()),
                    request_list_item_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RequestListWindow {
                items,
                offset: query.offset,
            })
        };
        match cancellation {
            Some(cancellation) => self.with_cancellable_connection(cancellation, operation),
            None => self.with_connection(operation),
        }
    }

    pub fn get_request_list_item(&self, request_id: &str) -> Result<RequestListItem, String> {
        self.with_connection(|connection| {
            connection.query_row(
                &format!("{REQUEST_LIST_SELECT} WHERE r.id = ?1"),
                [request_id],
                request_list_item_from_row,
            )
        })
    }

    pub fn get_request_detail(&self, request_id: &str) -> Result<RequestRecord, String> {
        self.with_connection(|connection| self.get_request_with_connection(connection, request_id))
    }

    pub fn list_saved_request_views(
        &self,
        session_id: &str,
    ) -> Result<Vec<SavedRequestView>, String> {
        let rows = self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, name, session_id, filter_json, sort_json, columns_json, created_at, updated_at
                   FROM saved_request_views
                  WHERE session_id IS NULL OR session_id = ?1
                  ORDER BY updated_at DESC, name COLLATE NOCASE ASC",
            )?;
            let rows = statement
                .query_map([session_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })?;
        rows.into_iter()
            .map(
                |(
                    id,
                    name,
                    session_id,
                    filter_json,
                    sort_json,
                    columns_json,
                    created_at,
                    updated_at,
                )| {
                    Ok(SavedRequestView {
                        id,
                        name,
                        session_id,
                        filter: serde_json::from_str(&filter_json)
                            .map_err(|error| format!("保存视图筛选条件损坏: {error}"))?,
                        sort: serde_json::from_str(&sort_json)
                            .map_err(|error| format!("保存视图排序条件损坏: {error}"))?,
                        columns: serde_json::from_str(&columns_json)
                            .map_err(|error| format!("保存视图列配置损坏: {error}"))?,
                        created_at,
                        updated_at,
                    })
                },
            )
            .collect()
    }

    pub fn save_request_view(
        &self,
        input: SavedRequestViewInput,
    ) -> Result<SavedRequestView, String> {
        let SavedRequestViewInput {
            id: input_id,
            name,
            session_id,
            filter,
            sort,
            columns,
        } = input;
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 80 {
            return Err("保存视图名称需为 1 到 80 个字符".to_string());
        }
        compile_request_sort(&sort)?;
        if let Some(expression) = filter.as_ref() {
            let mut params = Vec::new();
            let mut predicate_count = 0;
            compile_request_filter(expression, &mut params, 0, &mut predicate_count)?;
        }
        let id = input_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = Utc::now().timestamp_millis();
        let filter_json = serde_json::to_string(&filter).map_err(|error| error.to_string())?;
        let sort_json = serde_json::to_string(&sort).map_err(|error| error.to_string())?;
        if !columns.is_null() && !columns.is_object() {
            return Err("保存视图列配置必须是对象".to_string());
        }
        let columns_json = serde_json::to_string(&columns).map_err(|error| error.to_string())?;
        if columns_json.len() > 32 * 1024 {
            return Err("保存视图列配置超过 32 KiB 上限".to_string());
        }
        let created_at = self.with_connection(|connection| {
            let existing = connection
                .query_row(
                    "SELECT created_at FROM saved_request_views WHERE id = ?1",
                    [&id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            let created_at = existing.unwrap_or(now);
            connection.execute(
                "INSERT INTO saved_request_views
                   (id, name, session_id, filter_json, sort_json, columns_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                   name = excluded.name,
                   session_id = excluded.session_id,
                   filter_json = excluded.filter_json,
                   sort_json = excluded.sort_json,
                   columns_json = excluded.columns_json,
                   updated_at = excluded.updated_at",
                params![&id, &name, &session_id, &filter_json, &sort_json, &columns_json, created_at, now],
            )?;
            Ok(created_at)
        })?;
        Ok(SavedRequestView {
            id,
            name,
            session_id,
            filter,
            sort,
            columns,
            created_at,
            updated_at: now,
        })
    }

    pub fn delete_request_view(&self, view_id: &str) -> Result<(), String> {
        if view_id.trim().is_empty() {
            return Err("viewId 不能为空".to_string());
        }
        self.with_connection(|connection| {
            connection.execute("DELETE FROM saved_request_views WHERE id = ?1", [view_id])?;
            Ok(())
        })
    }

    pub fn get_request_annotation(
        &self,
        request_id: &str,
    ) -> Result<Option<RequestAnnotation>, String> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT request_id, bookmarked, color, struck_through, note,
                            tags_json, created_at, updated_at
                       FROM request_annotations WHERE request_id = ?1",
                    [request_id],
                    request_annotation_from_row,
                )
                .optional()
        })
    }

    pub fn save_request_annotation(
        &self,
        input: RequestAnnotationInput,
    ) -> Result<RequestAnnotation, String> {
        let request_id = input.request_id.trim().to_string();
        if request_id.is_empty() {
            return Err("requestId 不能为空".to_string());
        }
        if input.note.chars().count() > 20_000 {
            return Err("备注不能超过 20000 个字符".to_string());
        }
        if input.tags.len() > 20
            || input
                .tags
                .iter()
                .any(|tag| tag.trim().is_empty() || tag.chars().count() > 40)
        {
            return Err("标签最多 20 个，每个标签需为 1 到 40 个字符".to_string());
        }
        if let Some(color) = input.color.as_deref() {
            if !matches!(color, "red" | "yellow" | "green" | "blue" | "gray") {
                return Err("不支持的标注颜色".to_string());
            }
        }
        let tags = input
            .tags
            .into_iter()
            .map(|tag| tag.trim().to_string())
            .collect::<Vec<_>>();
        let tags_json = serde_json::to_string(&tags).map_err(|error| error.to_string())?;
        let now = now_ms();
        let created_at = self.with_connection(|connection| {
            let existing = connection
                .query_row(
                    "SELECT created_at FROM request_annotations WHERE request_id = ?1",
                    [&request_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            let created_at = existing.unwrap_or(now);
            connection.execute(
                "INSERT INTO request_annotations(
                   request_id, bookmarked, color, struck_through, note,
                   tags_json, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(request_id) DO UPDATE SET
                   bookmarked = excluded.bookmarked,
                   color = excluded.color,
                   struck_through = excluded.struck_through,
                   note = excluded.note,
                   tags_json = excluded.tags_json,
                   updated_at = excluded.updated_at",
                params![
                    &request_id,
                    input.bookmarked,
                    input.color,
                    input.struck_through,
                    input.note,
                    tags_json,
                    created_at,
                    now,
                ],
            )?;
            Ok(created_at)
        })?;
        Ok(RequestAnnotation {
            request_id,
            bookmarked: input.bookmarked,
            color: input.color,
            struck_through: input.struck_through,
            note: input.note,
            tags,
            created_at,
            updated_at: now,
        })
    }

    pub fn get_crypto_snippets(&self, request_id: &str) -> Result<Vec<CryptoCodeSnippet>, String> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT crypto_snippets_json FROM requests WHERE id = ?1",
                [request_id],
                |row| Ok(from_json(row.get::<_, String>(0)?)),
            )
        })
    }

    pub fn create_analysis_report(
        &self,
        session_id: &str,
        mode: &str,
        request_count: i64,
        provider: &str,
        model: &str,
    ) -> Result<AnalysisReport, String> {
        self.get_session(session_id)?;
        let id = format!("analysis-{}", Uuid::new_v4());
        let now = now_ms();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO analysis_reports(
                   id, session_id, mode, status, request_count, key_request_count,
                   selected_request_ids_json, content, provider, model, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'filtering', ?4, 0, '[]', '', ?5, ?6, ?7, ?7)",
                params![id, session_id, mode, request_count, provider, model, now],
            )?;
            Ok(())
        })?;
        self.get_analysis_report(&id)
    }

    pub fn update_analysis_selection(
        &self,
        analysis_id: &str,
        request_ids: &[String],
    ) -> Result<(), String> {
        let request_ids_json =
            serde_json::to_string(&request_ids).map_err(|error| error.to_string())?;
        let changed = self.with_connection(|connection| {
            connection.execute(
                "UPDATE analysis_reports
                 SET status = 'analyzing', key_request_count = ?1,
                     selected_request_ids_json = ?2, updated_at = ?3
                 WHERE id = ?4",
                params![
                    request_ids.len() as i64,
                    request_ids_json,
                    now_ms(),
                    analysis_id
                ],
            )
        })?;
        if changed == 0 {
            return Err("分析报告不存在".to_string());
        }
        Ok(())
    }

    pub fn save_analysis_progress(&self, analysis_id: &str, content: &str) -> Result<(), String> {
        let changed = self.with_connection(|connection| {
            connection.execute(
                "UPDATE analysis_reports SET content = ?1, updated_at = ?2 WHERE id = ?3",
                params![content, now_ms(), analysis_id],
            )
        })?;
        if changed == 0 {
            return Err("分析报告不存在".to_string());
        }
        Ok(())
    }

    pub fn finish_analysis_report(
        &self,
        analysis_id: &str,
        content: &str,
    ) -> Result<AnalysisReport, String> {
        let updated_at = now_ms();
        let changed = self.with_connection(|connection| {
            let changed = connection.execute(
                "UPDATE analysis_reports
                 SET status = 'complete', content = ?1, error = NULL, updated_at = ?2
                 WHERE id = ?3",
                params![content, updated_at, analysis_id],
            )?;
            if changed > 0 {
                let context = connection
                    .query_row(
                        "SELECT ar.session_id, ar.mode, s.name
                         FROM analysis_reports ar
                         JOIN sessions s ON s.id = ar.session_id
                         WHERE ar.id = ?1",
                        [analysis_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    )
                    .optional()?;
                if let Some((session_id, mode, current_name)) = context {
                    if is_generated_session_name(&current_name) {
                        let primary_host = connection
                            .query_row(
                                "SELECT host FROM requests
                                 WHERE session_id = ?1 AND TRIM(host) != ''
                                 GROUP BY host
                                 ORDER BY COUNT(*) DESC, host ASC
                                 LIMIT 1",
                                [&session_id],
                                |row| row.get::<_, String>(0),
                            )
                            .optional()?;
                        let generated =
                            analysis_session_name(content, &mode, primary_host.as_deref());
                        connection.execute(
                            "UPDATE sessions SET name = ?1, updated_at = ?2 WHERE id = ?3",
                            params![generated, updated_at, session_id],
                        )?;
                    }
                }
            }
            Ok(changed)
        })?;
        if changed == 0 {
            return Err("分析报告不存在".to_string());
        }
        self.get_analysis_report(analysis_id)
    }

    pub fn fail_analysis_report(
        &self,
        analysis_id: &str,
        content: &str,
        error: &str,
    ) -> Result<AnalysisReport, String> {
        let changed = self.with_connection(|connection| {
            connection.execute(
                "UPDATE analysis_reports
                 SET status = 'failed', content = ?1, error = ?2, updated_at = ?3
                 WHERE id = ?4",
                params![content, error, now_ms(), analysis_id],
            )
        })?;
        if changed == 0 {
            return Err("分析报告不存在".to_string());
        }
        self.get_analysis_report(analysis_id)
    }

    pub fn get_analysis_report(&self, analysis_id: &str) -> Result<AnalysisReport, String> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT id, session_id, mode, status, request_count, key_request_count,
                        selected_request_ids_json, content, provider, model, error,
                        created_at, updated_at
                 FROM analysis_reports WHERE id = ?1",
                [analysis_id],
                analysis_report_from_row,
            )
        })
    }

    pub fn latest_analysis_report(
        &self,
        session_id: &str,
    ) -> Result<Option<AnalysisReport>, String> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT id, session_id, mode, status, request_count, key_request_count,
                            selected_request_ids_json, content, provider, model, error,
                            created_at, updated_at
                     FROM analysis_reports WHERE session_id = ?1
                     ORDER BY updated_at DESC LIMIT 1",
                    [session_id],
                    analysis_report_from_row,
                )
                .optional()
        })
    }

    pub fn list_analysis_reports(&self, session_id: &str) -> Result<Vec<AnalysisReport>, String> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, session_id, mode, status, request_count, key_request_count,
                        selected_request_ids_json, content, provider, model, error,
                        created_at, updated_at
                 FROM analysis_reports WHERE session_id = ?1
                 ORDER BY updated_at DESC, rowid DESC LIMIT 100",
            )?;
            let reports = statement
                .query_map([session_id], analysis_report_from_row)?
                .collect();
            reports
        })
    }

    pub fn append_analysis_activity(
        &self,
        analysis_id: &str,
        phase: &str,
        message: Option<&str>,
    ) -> Result<AnalysisActivity, String> {
        if !matches!(
            phase,
            "filtering"
                | "analyzing"
                | "runtime"
                | "reasoning"
                | "tool"
                | "tool-complete"
                | "tool-error"
                | "graph-node"
                | "graph-retry"
                | "artifact-valid"
                | "artifact-invalid"
                | "graph-complete"
                | "generating"
                | "complete"
                | "error"
        ) {
            return Err(format!("不支持的 Agent 执行阶段: {phase}"));
        }
        let created_at = now_ms();
        let message = message.unwrap_or_default();
        let id = self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO analysis_activities(analysis_id, phase, message, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![analysis_id, phase, message, created_at],
            )?;
            Ok(connection.last_insert_rowid())
        })?;
        Ok(AnalysisActivity {
            id,
            analysis_id: analysis_id.to_string(),
            phase: phase.to_string(),
            message: message.to_string(),
            created_at,
        })
    }

    pub fn list_analysis_activities(
        &self,
        analysis_id: &str,
    ) -> Result<Vec<AnalysisActivity>, String> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, analysis_id, phase, message, created_at
                 FROM (
                   SELECT id, analysis_id, phase, message, created_at
                   FROM analysis_activities
                   WHERE analysis_id = ?1
                   ORDER BY id DESC
                   LIMIT 200
                 )
                 ORDER BY id ASC",
            )?;
            let activities = statement
                .query_map([analysis_id], |row| {
                    Ok(AnalysisActivity {
                        id: row.get(0)?,
                        analysis_id: row.get(1)?,
                        phase: row.get(2)?,
                        message: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                })?
                .collect();
            activities
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_skill_run(
        &self,
        analysis_id: &str,
        skill_id: &str,
        skill_name: &str,
        skill_version: &str,
        mode: &str,
        permissions: &[String],
        planned_tools: &[String],
        input_summary: &Value,
    ) -> Result<String, String> {
        let id = format!("skill-run-{}", Uuid::new_v4());
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO skill_runs(
                   id, analysis_id, skill_id, skill_name, skill_version, mode, status,
                   permissions_json, planned_tools_json, input_summary_json,
                   output_summary_json, started_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'running', ?7, ?8, ?9, '{}', ?10)",
                params![
                    id,
                    analysis_id,
                    skill_id,
                    skill_name,
                    skill_version,
                    mode,
                    to_json(permissions)?,
                    to_json(planned_tools)?,
                    to_json(input_summary)?,
                    now_ms(),
                ],
            )?;
            Ok(())
        })?;
        Ok(id)
    }

    pub fn finish_skill_runs(
        &self,
        analysis_id: &str,
        status: &str,
        output_summary: &Value,
        error: Option<&str>,
    ) -> Result<(), String> {
        if !matches!(status, "complete" | "failed") {
            return Err(format!("不支持的 Skill 运行状态: {status}"));
        }
        self.with_connection(|connection| {
            let finished_at = now_ms();
            connection.execute(
                "UPDATE skill_runs
                 SET status = ?1, output_summary_json = ?2, error = ?3, finished_at = ?4
                 WHERE analysis_id = ?5 AND status = 'running'",
                params![
                    status,
                    to_json(output_summary)?,
                    error,
                    finished_at,
                    analysis_id
                ],
            )?;
            connection.execute(
                "UPDATE skill_tool_calls
                 SET status = 'failed', finished_at = ?1
                 WHERE analysis_id = ?2 AND status = 'running'",
                params![finished_at, analysis_id],
            )?;
            Ok(())
        })
    }

    pub fn finish_skill_run(
        &self,
        analysis_id: &str,
        skill_id: &str,
        status: &str,
        output_summary: &Value,
        error: Option<&str>,
    ) -> Result<(), String> {
        if !matches!(status, "complete" | "failed") {
            return Err(format!("不支持的 Skill 运行状态: {status}"));
        }
        self.with_connection(|connection| {
            let finished_at = now_ms();
            connection.execute(
                "UPDATE skill_runs
                 SET status = ?1, output_summary_json = ?2, error = ?3, finished_at = ?4
                 WHERE analysis_id = ?5 AND skill_id = ?6 AND status = 'running'",
                params![
                    status,
                    to_json(output_summary)?,
                    error,
                    finished_at,
                    analysis_id,
                    skill_id,
                ],
            )?;
            Ok(())
        })
    }

    pub fn begin_skill_tool_call(&self, analysis_id: &str, tool_name: &str) -> Result<i64, String> {
        let started_at = now_ms();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO skill_tool_calls(analysis_id, tool_name, status, started_at)
                 VALUES (?1, ?2, 'running', ?3)",
                params![analysis_id, tool_name, started_at],
            )?;
            Ok(connection.last_insert_rowid())
        })
    }

    pub fn finish_skill_tool_call(
        &self,
        analysis_id: &str,
        tool_name: &str,
        status: &str,
    ) -> Result<(), String> {
        if !matches!(status, "complete" | "failed") {
            return Err(format!("不支持的 Skill 工具状态: {status}"));
        }
        let finished_at = now_ms();
        self.with_connection(|connection| {
            let changed = connection.execute(
                "UPDATE skill_tool_calls
                 SET status = ?1, finished_at = ?2
                 WHERE id = (
                   SELECT id FROM skill_tool_calls
                   WHERE analysis_id = ?3 AND tool_name = ?4 AND status = 'running'
                   ORDER BY id DESC LIMIT 1
                 )",
                params![status, finished_at, analysis_id, tool_name],
            )?;
            if changed == 0 {
                connection.execute(
                    "INSERT INTO skill_tool_calls(
                       analysis_id, tool_name, status, started_at, finished_at
                     ) VALUES (?1, ?2, ?3, ?4, ?4)",
                    params![analysis_id, tool_name, status, finished_at],
                )?;
            }
            Ok(())
        })
    }

    pub fn list_analysis_skill_runs(
        &self,
        analysis_id: &str,
    ) -> Result<Vec<SkillRunAudit>, String> {
        self.with_connection(|connection| {
            let mut run_statement = connection.prepare(
                "SELECT id, analysis_id, skill_id, skill_name, skill_version, mode, status,
                        permissions_json, planned_tools_json, input_summary_json,
                        output_summary_json, error, started_at, finished_at
                 FROM skill_runs WHERE analysis_id = ?1 ORDER BY started_at ASC, rowid ASC",
            )?;
            let mut runs = run_statement
                .query_map([analysis_id], |row| {
                    let started_at: i64 = row.get(12)?;
                    let finished_at: Option<i64> = row.get(13)?;
                    Ok(SkillRunAudit {
                        id: row.get(0)?,
                        analysis_id: row.get(1)?,
                        skill_id: row.get(2)?,
                        skill_name: row.get(3)?,
                        skill_version: row.get(4)?,
                        mode: row.get(5)?,
                        status: row.get(6)?,
                        permissions: from_json(row.get(7)?),
                        planned_tools: from_json(row.get(8)?),
                        actual_tool_calls: Vec::new(),
                        input_summary: from_json(row.get(9)?),
                        output_summary: from_json(row.get(10)?),
                        error: row.get(11)?,
                        started_at,
                        finished_at,
                        duration_ms: finished_at
                            .map(|finished| finished.saturating_sub(started_at)),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            let mut tool_statement = connection.prepare(
                "SELECT id, analysis_id, tool_name, status, started_at, finished_at
                 FROM skill_tool_calls WHERE analysis_id = ?1 ORDER BY id ASC",
            )?;
            let calls = tool_statement
                .query_map([analysis_id], |row| {
                    let started_at: i64 = row.get(4)?;
                    let finished_at: Option<i64> = row.get(5)?;
                    Ok(SkillToolCallAudit {
                        id: row.get(0)?,
                        analysis_id: row.get(1)?,
                        tool_name: row.get(2)?,
                        status: row.get(3)?,
                        started_at,
                        finished_at,
                        duration_ms: finished_at
                            .map(|finished| finished.saturating_sub(started_at)),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for run in &mut runs {
                run.actual_tool_calls = calls
                    .iter()
                    .filter(|call| run.planned_tools.contains(&call.tool_name))
                    .cloned()
                    .collect();
            }
            Ok(runs)
        })
    }

    pub fn create_analysis_graph_run(&self, run: &AnalysisGraphRun) -> Result<(), String> {
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO analysis_graph_runs(
                   analysis_id, status, current_node_id, run_json, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    run.analysis_id,
                    graph_run_status(run),
                    run.current_node_id,
                    to_json(run)?,
                    run.created_at,
                    run.updated_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn save_analysis_graph_run(&self, run: &AnalysisGraphRun) -> Result<(), String> {
        self.with_connection(|connection| {
            let changed = connection.execute(
                "UPDATE analysis_graph_runs
                 SET status = ?1, current_node_id = ?2, run_json = ?3, updated_at = ?4
                 WHERE analysis_id = ?5",
                params![
                    graph_run_status(run),
                    run.current_node_id,
                    to_json(run)?,
                    run.updated_at,
                    run.analysis_id,
                ],
            )?;
            if changed == 0 {
                connection.execute(
                    "INSERT INTO analysis_graph_runs(
                       analysis_id, status, current_node_id, run_json, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        run.analysis_id,
                        graph_run_status(run),
                        run.current_node_id,
                        to_json(run)?,
                        run.created_at,
                        run.updated_at,
                    ],
                )?;
            }
            Ok(())
        })
    }

    pub fn get_analysis_graph_run(
        &self,
        analysis_id: &str,
    ) -> Result<Option<AnalysisGraphRun>, String> {
        let encoded = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT run_json FROM analysis_graph_runs WHERE analysis_id = ?1",
                    [analysis_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })?;
        encoded
            .map(|encoded| {
                serde_json::from_str(&encoded)
                    .map_err(|error| format!("分析 Graph 运行记录损坏: {error}"))
            })
            .transpose()
    }

    pub fn add_analysis_message(
        &self,
        analysis_id: &str,
        role: &str,
        content: &str,
    ) -> Result<AnalysisChatMessage, String> {
        if !matches!(role, "user" | "assistant") {
            return Err("不支持的分析消息角色".to_string());
        }
        let now = now_ms();
        let id = self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO analysis_messages(analysis_id, role, content, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![analysis_id, role, content, now],
            )?;
            Ok(connection.last_insert_rowid())
        })?;
        Ok(AnalysisChatMessage {
            id,
            analysis_id: analysis_id.to_string(),
            role: role.to_string(),
            content: content.to_string(),
            created_at: now,
        })
    }

    pub fn list_analysis_messages(
        &self,
        analysis_id: &str,
    ) -> Result<Vec<AnalysisChatMessage>, String> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, analysis_id, role, content, created_at
                 FROM analysis_messages WHERE analysis_id = ?1 ORDER BY id ASC",
            )?;
            let messages = statement
                .query_map([analysis_id], |row| {
                    Ok(AnalysisChatMessage {
                        id: row.get(0)?,
                        analysis_id: row.get(1)?,
                        role: row.get(2)?,
                        content: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                })?
                .collect();
            messages
        })
    }

    pub fn begin_ai_request_log(
        &self,
        analysis_id: &str,
        request_kind: &str,
        provider: &str,
        model: &str,
        endpoint: &str,
    ) -> Result<String, String> {
        let id = format!("ai-log-{}", Uuid::new_v4());
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO ai_request_logs(
                   id, analysis_id, request_kind, provider, model, endpoint,
                   status, started_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'running', ?7)",
                params![
                    id,
                    analysis_id,
                    request_kind,
                    provider,
                    model,
                    endpoint,
                    now_ms()
                ],
            )?;
            Ok(())
        })?;
        Ok(id)
    }

    pub fn finish_ai_request_log(
        &self,
        log_id: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), String> {
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE ai_request_logs
                 SET status = ?1, error = ?2, finished_at = ?3 WHERE id = ?4",
                params![status, error, now_ms(), log_id],
            )?;
            Ok(())
        })
    }

    pub fn export_session_bundle(&self, session_id: &str) -> Result<SessionBundle, String> {
        self.with_connection(|connection| {
            let session = connection.query_row(
                "SELECT name, created_at FROM sessions WHERE id = ?1",
                [session_id],
                |row| {
                    Ok(BundleSession {
                        name: row.get(0)?,
                        created_at: row.get(1)?,
                    })
                },
            )?;
            let mut request_statement = connection.prepare(BUNDLE_REQUEST_SELECT)?;
            let requests = request_statement
                .query_map([session_id], bundle_request_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            let mut event_statement = connection.prepare(
                "SELECT sequence, timestamp, source, source_instance_id, request_id,
                        phase, payload_json
                 FROM capture_events WHERE session_id = ?1 ORDER BY sequence ASC",
            )?;
            let events = event_statement
                .query_map([session_id], |row| {
                    Ok(BundleEvent {
                        sequence: row.get(0)?,
                        timestamp: row.get(1)?,
                        source: row.get(2)?,
                        source_instance_id: row.get(3)?,
                        request_id: row.get(4)?,
                        phase: row.get(5)?,
                        payload: from_json(row.get::<_, String>(6)?),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let mut annotation_statement = connection.prepare(
                "SELECT a.request_id, a.bookmarked, a.color, a.struck_through,
                        a.note, a.tags_json, a.created_at, a.updated_at
                   FROM request_annotations a
                   JOIN requests r ON r.id = a.request_id
                  WHERE r.session_id = ?1 ORDER BY r.sequence ASC",
            )?;
            let annotations = annotation_statement
                .query_map([session_id], request_annotation_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            let mut rule_statement = connection.prepare(
                "SELECT DISTINCT cr.id,cr.name,cr.enabled,cr.priority,cr.stage,cr.matcher_json,cr.action_json,cr.created_by,cr.revision,cr.hit_count,cr.last_error,cr.created_at,cr.updated_at
                   FROM capture_rules cr JOIN capture_rule_runs rr ON rr.rule_id=cr.id JOIN requests r ON r.id=rr.request_id
                  WHERE r.session_id=?1 ORDER BY cr.priority ASC, cr.updated_at DESC",
            )?;
            let rules = rule_statement.query_map([session_id], capture_rule_from_row)?.collect::<Result<Vec<_>, _>>()?;
            let mut trace_statement = connection.prepare(
                "SELECT rr.id,rr.request_id,rr.rule_id,rr.rule_name,rr.revision,rr.stage,rr.result,rr.diff_summary_json,rr.duration_ms,rr.error,rr.created_at
                   FROM capture_rule_runs rr JOIN requests r ON r.id=rr.request_id
                  WHERE r.session_id=?1 ORDER BY rr.created_at ASC",
            )?;
            let rule_traces = trace_statement.query_map([session_id], |row| Ok(CaptureRuleRun { id:row.get(0)?,request_id:row.get(1)?,rule_id:row.get(2)?,rule_name:row.get(3)?,revision:row.get(4)?,stage:row.get(5)?,result:row.get(6)?,diff_summary:from_json(row.get::<_,String>(7)?),duration_ms:row.get(8)?,error:row.get(9)?,created_at:row.get(10)? }))?.collect::<Result<Vec<_>, _>>()?;
            Ok(SessionBundle {
                format: BUNDLE_FORMAT.to_string(),
                version: BUNDLE_VERSION,
                exported_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                session,
                requests,
                events,
                annotations,
                rules,
                rule_traces,
            })
        })
    }

    pub fn get_bundle_request(&self, request_id: &str) -> Result<BundleRequest, String> {
        self.with_connection(|connection| {
            connection.query_row(
                &BUNDLE_REQUEST_SELECT.replace(
                    "WHERE session_id = ?1 ORDER BY sequence ASC",
                    "WHERE id = ?1",
                ),
                [request_id],
                bundle_request_from_row,
            )
        })
    }

    pub fn import_session_bundle(&self, bundle: SessionBundle) -> Result<SessionRecord, String> {
        validate_bundle(&bundle)?;
        for request in &bundle.requests {
            validate_source(&request.source)?;
        }
        for event in &bundle.events {
            validate_source(&event.source)?;
            validate_phase(&event.phase)?;
        }

        let new_session_id = format!("session-{}", Uuid::new_v4());
        let imported_name = format!("{}（导入）", bundle.session.name.trim());
        let now = now_ms();
        let created_at = if bundle.session.created_at > 0 {
            bundle.session.created_at
        } else {
            now
        };
        let request_count = bundle.requests.len() as i64;
        let error_count = bundle
            .requests
            .iter()
            .filter(|request| request.status >= 400)
            .count() as i64;
        let last_sequence = bundle
            .requests
            .iter()
            .map(|request| request.sequence)
            .chain(bundle.events.iter().map(|event| event.sequence))
            .max()
            .unwrap_or(0);

        self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO sessions(
                   id, name, created_at, updated_at, status,
                   request_count, error_count, last_sequence
                 ) VALUES (?1, ?2, ?3, ?4, 'idle', ?5, ?6, ?7)",
                params![
                    new_session_id,
                    imported_name,
                    created_at,
                    now,
                    request_count,
                    error_count,
                    last_sequence,
                ],
            )?;

            let request_ids = bundle.requests.iter().map(|request| (request.id.clone(), format!("request-{}", Uuid::new_v4()))).collect::<HashMap<_, _>>();
            for request in &bundle.requests {
                let new_request_id = request_ids.get(&request.id).expect("validated request id");
                let replayed_from_request_id = request.replayed_from_request_id.as_ref().and_then(|id| request_ids.get(id));
                transaction.execute(
                    "INSERT INTO requests(
                       id, session_id, sequence, source, source_instance_id, started_at,
                       method, scheme, host, port, path, query, status, resource_type,
                       size_bytes, duration_ms, protocol, tls_version, risk_level,
                       request_headers_json, response_headers_json, request_body,
                       response_body, response_body_meta_json, crypto_snippets_json,
                       hook_json, tls_fingerprint_json, replayed_from_request_id
                     ) VALUES (
                       ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                       ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25,
                       ?26, ?27, ?28
                     )",
                    params![
                        new_request_id,
                        new_session_id,
                        request.sequence,
                        request.source,
                        request.source_instance_id,
                        request.started_at,
                        request.method,
                        request.scheme,
                        request.host,
                        request.port,
                        request.path,
                        request.query,
                        request.status,
                        request.resource_type,
                        request.size_bytes,
                        request.duration_ms,
                        request.protocol,
                        request.tls_version,
                        request.risk_level,
                        to_json(&request.request_headers)?,
                        to_json(&request.response_headers)?,
                        request.request_body,
                        request.response_body,
                        to_json(&request.response_body_metadata)?,
                        to_json(&if request.crypto_snippets.is_empty() {
                            extract_crypto_snippets_for_response(
                                &request.resource_type,
                                &request.response_headers,
                                &request.response_body,
                                &request.response_body_metadata,
                            )
                        } else {
                            request.crypto_snippets.clone()
                        })?,
                        request.hook.as_ref().map(to_json).transpose()?,
                        request.tls_fingerprint.as_ref().map(to_json).transpose()?,
                        replayed_from_request_id,
                    ],
                )?;
            }

            let mut rule_ids = HashMap::new();
            for rule in &bundle.rules {
                let new_rule_id = format!("rule-{}", Uuid::new_v4());
                rule_ids.insert(rule.id.clone(), new_rule_id.clone());
                transaction.execute(
                    "INSERT INTO capture_rules(id,name,enabled,priority,stage,matcher_json,action_json,created_by,revision,hit_count,last_error,created_at,updated_at) VALUES (?1,?2,0,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                    params![new_rule_id,rule.name,rule.priority,rule.stage,to_json(&rule.matcher)?,to_json(&rule.action)?,rule.created_by,rule.revision,rule.hit_count,rule.last_error,rule.created_at,rule.updated_at],
                )?;
                transaction.execute(
                    "INSERT INTO capture_rule_revisions(id,rule_id,revision,snapshot_json,created_at) VALUES (?1,?2,?3,?4,?5)",
                    params![format!("rule-revision-{}",Uuid::new_v4()),new_rule_id,rule.revision,to_json(&serde_json::json!({"name":rule.name,"enabled":false,"priority":rule.priority,"stage":rule.stage,"matcher":rule.matcher,"action":rule.action,"createdBy":rule.created_by}))?,rule.created_at],
                )?;
            }

            for trace in &bundle.rule_traces {
                let (Some(request_id), Some(rule_id)) = (request_ids.get(&trace.request_id), rule_ids.get(&trace.rule_id)) else { continue };
                transaction.execute(
                    "INSERT INTO capture_rule_runs(id,request_id,rule_id,rule_name,revision,stage,result,diff_summary_json,duration_ms,error,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![format!("rule-run-{}",Uuid::new_v4()),request_id,rule_id,trace.rule_name,trace.revision,trace.stage,trace.result,to_json(&trace.diff_summary)?,trace.duration_ms,trace.error,trace.created_at],
                )?;
            }

            for annotation in &bundle.annotations {
                let Some(request_id) = request_ids.get(&annotation.request_id) else {
                    continue;
                };
                transaction.execute(
                    "INSERT INTO request_annotations(
                       request_id, bookmarked, color, struck_through, note,
                       tags_json, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        request_id,
                        annotation.bookmarked,
                        annotation.color,
                        annotation.struck_through,
                        annotation.note,
                        to_json(&annotation.tags)?,
                        annotation.created_at,
                        annotation.updated_at,
                    ],
                )?;
            }

            for event in &bundle.events {
                let request_id = request_ids
                    .get(&event.request_id)
                    .cloned()
                    .unwrap_or_else(|| event.request_id.clone());
                let payload = remap_event_payload(event.payload.clone(), &request_ids);
                transaction.execute(
                    "INSERT INTO capture_events(
                       session_id, sequence, timestamp, source, source_instance_id,
                       request_id, phase, payload_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        new_session_id,
                        event.sequence,
                        event.timestamp,
                        event.source,
                        event.source_instance_id,
                        request_id,
                        event.phase,
                        payload.to_string(),
                    ],
                )?;
            }
            transaction.commit()
        })?;
        self.get_session(&new_session_id)
    }

    pub fn create_replay_batch(&self, input: &ReplayBatchInput) -> Result<ReplayBatch, String> {
        if input.session_id.trim().is_empty() || input.request_ids.is_empty() {
            return Err("请选择至少一条可重放请求".to_string());
        }
        if input.request_ids.len() > 20 {
            return Err("单个批次最多选择 20 条来源请求".to_string());
        }
        if !(1..=100).contains(&input.settings.repeat_count) {
            return Err("重放次数必须在 1 到 100 之间".to_string());
        }
        if !(1..=8).contains(&input.settings.max_concurrency) {
            return Err("最大并发必须在 1 到 8 之间".to_string());
        }
        if !(0..=60_000).contains(&input.settings.start_delay_ms)
            || !(0..=60_000).contains(&input.settings.interval_ms)
        {
            return Err("开始延迟和请求间隔必须在 0 到 60000ms 之间".to_string());
        }
        let total = input.request_ids.len() as i64 * input.settings.repeat_count;
        if total > 100 {
            return Err("单个重放批次硬上限为 100 次请求".to_string());
        }
        if total > 20 && !input.confirmed_large_batch {
            return Err("超过默认 20 次前需要再次确认影响范围".to_string());
        }
        let batch_id = format!("replay-{}", Uuid::new_v4());
        let now = now_ms();
        let settings_json =
            serde_json::to_string(&input.settings).map_err(|error| error.to_string())?;
        self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            for request_id in &input.request_ids {
                let exists: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM requests WHERE id = ?1 AND session_id = ?2",
                    params![request_id, input.session_id],
                    |row| row.get(0),
                )?;
                if exists == 0 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            transaction.execute(
                "INSERT INTO replay_batches(id, session_id, status, settings_json, total, created_at, updated_at)
                 VALUES (?1, ?2, 'queued', ?3, ?4, ?5, ?5)",
                params![batch_id, input.session_id, settings_json, total, now],
            )?;
            for request_id in &input.request_ids {
                for run_index in 0..input.settings.repeat_count {
                    transaction.execute(
                        "INSERT INTO replay_batch_items(id, batch_id, source_request_id, run_index, status)
                         VALUES (?1, ?2, ?3, ?4, 'queued')",
                        params![format!("replay-item-{}", Uuid::new_v4()), batch_id, request_id, run_index],
                    )?;
                }
            }
            transaction.commit()?;
            Ok(())
        })?;
        self.get_replay_batch(&batch_id)
    }

    pub fn get_replay_batch(&self, batch_id: &str) -> Result<ReplayBatch, String> {
        self.with_connection(|connection| {
            let (session_id, status, settings_json, total, created_at, updated_at): (
                String,
                String,
                String,
                i64,
                i64,
                i64,
            ) = connection.query_row(
                "SELECT session_id, status, settings_json, total, created_at, updated_at
                 FROM replay_batches WHERE id = ?1",
                [batch_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )?;
            let mut statement = connection.prepare(
                "SELECT id, source_request_id, run_index, status, captured_request_id,
                        status_code, duration_ms, error, started_at, finished_at
                 FROM replay_batch_items WHERE batch_id = ?1
                 ORDER BY source_request_id, run_index",
            )?;
            let items = statement
                .query_map([batch_id], |row| {
                    Ok(ReplayBatchItem {
                        id: row.get(0)?,
                        source_request_id: row.get(1)?,
                        run_index: row.get(2)?,
                        status: row.get(3)?,
                        captured_request_id: row.get(4)?,
                        status_code: row.get(5)?,
                        duration_ms: row.get(6)?,
                        error: row.get(7)?,
                        started_at: row.get(8)?,
                        finished_at: row.get(9)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let completed = items
                .iter()
                .filter(|item| matches!(item.status.as_str(), "complete" | "failed" | "cancelled"))
                .count() as i64;
            let succeeded = items
                .iter()
                .filter(|item| item.status == "complete")
                .count() as i64;
            let failed = items.iter().filter(|item| item.status == "failed").count() as i64;
            Ok(ReplayBatch {
                id: batch_id.to_string(),
                session_id,
                status,
                settings: from_json(settings_json),
                total,
                completed,
                succeeded,
                failed,
                items,
                created_at,
                updated_at,
            })
        })
    }

    pub fn list_replay_batches(&self, session_id: &str) -> Result<Vec<ReplayBatch>, String> {
        let ids = self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT id FROM replay_batches WHERE session_id = ?1 ORDER BY created_at DESC LIMIT 20")?;
            let rows = statement.query_map([session_id], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })?;
        ids.into_iter()
            .map(|id| self.get_replay_batch(&id))
            .collect()
    }

    pub fn set_replay_batch_status(&self, batch_id: &str, status: &str) -> Result<(), String> {
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE replay_batches SET status = ?1, updated_at = ?2 WHERE id = ?3",
                params![status, now_ms(), batch_id],
            )?;
            Ok(())
        })
    }

    pub fn set_replay_item_running(&self, item_id: &str) -> Result<(), String> {
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE replay_batch_items SET status = 'running', started_at = ?1 WHERE id = ?2",
                params![now_ms(), item_id],
            )?;
            Ok(())
        })
    }

    pub fn finish_replay_item(
        &self,
        item_id: &str,
        status: &str,
        status_code: Option<i64>,
        duration_ms: i64,
        error: Option<&str>,
    ) -> Result<(), String> {
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE replay_batch_items SET status = ?1, status_code = ?2, duration_ms = ?3, error = ?4, finished_at = ?5 WHERE id = ?6",
                params![status, status_code, duration_ms, error, now_ms(), item_id],
            )?;
            Ok(())
        })
    }

    pub fn cancel_queued_replay_items(&self, batch_id: &str) -> Result<(), String> {
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE replay_batch_items SET status = 'cancelled', finished_at = ?1
                 WHERE batch_id = ?2 AND status IN ('queued', 'running')",
                params![now_ms(), batch_id],
            )?;
            Ok(())
        })
    }

    pub fn save_request_draft(&self, input: RequestDraftInput) -> Result<RequestDraft, String> {
        validate_request_draft(&input)?;
        let tags = normalize_draft_tags(input.tags.clone())?;
        self.validate_request_draft_location(
            input.collection_id.as_deref(),
            input.folder_id.as_deref(),
        )?;
        let id = input
            .id
            .unwrap_or_else(|| format!("draft-{}", Uuid::new_v4()));
        let now = now_ms();
        let existing_auth = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT auth_json FROM request_drafts WHERE id=?1",
                    [&id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })?;
        let auth_json = encode_draft_auth(&id, &input.auth, existing_auth.as_deref())?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO request_drafts(id, session_id, source_request_id, name, method, url, headers_json, body, body_type, auth_json, settings_json, environment_id, collection_id, folder_id, tags_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16)
                 ON CONFLICT(id) DO UPDATE SET session_id=excluded.session_id, source_request_id=excluded.source_request_id,
                   name=excluded.name, method=excluded.method, url=excluded.url, headers_json=excluded.headers_json,
                   body=excluded.body, body_type=excluded.body_type, auth_json=excluded.auth_json,
                   settings_json=excluded.settings_json, environment_id=excluded.environment_id,
                   collection_id=excluded.collection_id, folder_id=excluded.folder_id,
                   tags_json=excluded.tags_json, updated_at=excluded.updated_at",
                params![id, input.session_id, input.source_request_id, input.name.trim(), input.method.to_uppercase(), input.url.trim(), to_json(&input.headers)?, input.body, input.body_type, auth_json, to_json(&input.settings)?, input.environment_id, input.collection_id, input.folder_id, to_json(&tags)?, now],
            )?;
            Ok(())
        })?;
        self.get_request_draft(&id)
    }

    pub fn create_request_draft_from_capture(
        &self,
        request_id: &str,
    ) -> Result<RequestDraft, String> {
        let request = self.get_bundle_request(request_id)?;
        let default_port = (request.scheme == "http" && request.port == Some(80))
            || (request.scheme == "https" && request.port == Some(443));
        let authority = match request.port.filter(|_| !default_port) {
            Some(port) => format!("{}:{port}", request.host),
            None => request.host.clone(),
        };
        let url = format!(
            "{}://{}{}{}",
            request.scheme,
            authority,
            request.path,
            request
                .query
                .as_ref()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        );
        self.save_request_draft(RequestDraftInput {
            id: None, session_id: Some(self.request_session_id(request_id)?), source_request_id: Some(request.id),
            name: format!("{} {}", request.method, request.path), method: request.method, url,
            headers: request.request_headers, body: request.request_body.unwrap_or_default(), body_type: "raw".to_string(),
            auth: serde_json::json!({"kind":"none"}), settings: serde_json::json!({"cookieJar":false,"followRedirects":true,"verifyTls":true}), environment_id: None, collection_id: None, folder_id: None, tags: vec![],
        })
    }

    pub fn get_request_draft(&self, draft_id: &str) -> Result<RequestDraft, String> {
        let mut draft = self.with_connection(|connection| connection.query_row(
            "SELECT id, session_id, source_request_id, name, method, url, headers_json, body, body_type, auth_json, settings_json, environment_id, created_at, updated_at, collection_id, folder_id, tags_json, spec_operation_key, spec_fingerprint FROM request_drafts WHERE id = ?1",
            [draft_id], request_draft_from_row,
        ))?;
        draft.auth = decode_draft_auth(&draft.id, &draft.auth, true)?;
        Ok(draft)
    }

    pub(crate) fn get_request_draft_for_send(
        &self,
        draft_id: &str,
    ) -> Result<RequestDraft, String> {
        let mut draft = self.with_connection(|connection| connection.query_row(
            "SELECT id, session_id, source_request_id, name, method, url, headers_json, body, body_type, auth_json, settings_json, environment_id, created_at, updated_at, collection_id, folder_id, tags_json, spec_operation_key, spec_fingerprint FROM request_drafts WHERE id = ?1",
            [draft_id], request_draft_from_row,
        ))?;
        draft.auth = decode_draft_auth(&draft.id, &draft.auth, false)?;
        Ok(draft)
    }

    pub fn list_request_drafts(&self) -> Result<Vec<RequestDraft>, String> {
        let rows = self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT id, session_id, source_request_id, name, method, url, headers_json, body, body_type, auth_json, settings_json, environment_id, created_at, updated_at, collection_id, folder_id, tags_json, spec_operation_key, spec_fingerprint FROM request_drafts ORDER BY updated_at DESC LIMIT 100")?;
            let rows = statement.query_map([], request_draft_from_row)?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })?;
        rows.into_iter()
            .map(|mut draft| {
                draft.auth = decode_draft_auth(&draft.id, &draft.auth, true)?;
                Ok(draft)
            })
            .collect()
    }

    pub fn list_request_collection_workspace(&self) -> Result<RequestCollectionWorkspace, String> {
        let collections = self.list_request_collections()?;
        let folders = self.list_request_collection_folders()?;
        let rows = self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, session_id, source_request_id, name, method, url, headers_json, body, body_type, auth_json, settings_json, environment_id, created_at, updated_at, collection_id, folder_id, tags_json, spec_operation_key, spec_fingerprint
                 FROM request_drafts ORDER BY updated_at DESC LIMIT 2000",
            )?;
            let rows = statement
                .query_map([], request_draft_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })?;
        let drafts = rows
            .into_iter()
            .map(|mut draft| {
                draft.auth = decode_draft_auth(&draft.id, &draft.auth, true)?;
                Ok(draft)
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(RequestCollectionWorkspace {
            collections,
            folders,
            drafts,
        })
    }

    pub fn save_request_collection(
        &self,
        input: RequestCollectionInput,
    ) -> Result<RequestCollection, String> {
        let name = input.name.trim();
        if name.is_empty() || name.chars().count() > 120 {
            return Err("集合名称必须在 1 到 120 个字符之间".to_string());
        }
        if input.description.chars().count() > 2_000 {
            return Err("集合说明不能超过 2000 个字符".to_string());
        }
        validate_collection_default_headers(&input.default_headers)?;
        if let Some(environment_id) = input.default_environment_id.as_deref() {
            let environment = self.get_environment(environment_id)?;
            if environment.kind != "named" {
                return Err("集合默认环境必须是命名环境".to_string());
            }
        }
        let duplicate = self.with_connection(|connection| {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM request_collections WHERE name=?1 COLLATE NOCASE AND id<>COALESCE(?2,''))",
                params![name, input.id],
                |row| row.get::<_, bool>(0),
            )
        })?;
        if duplicate {
            return Err("已有同名请求集合".to_string());
        }
        let id = input
            .id
            .unwrap_or_else(|| format!("collection-{}", Uuid::new_v4()));
        let now = now_ms();
        let existing_auth = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT default_auth_json FROM request_collections WHERE id=?1",
                    [&id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })?;
        let default_auth_json =
            encode_collection_auth(&id, &input.default_auth, existing_auth.as_deref())?;
        self.with_connection(|connection| {
            let sort_order = connection.query_row(
                "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM request_collections",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            connection.execute(
                "INSERT INTO request_collections(id,name,description,sort_order,created_at,updated_at,default_headers_json,default_auth_json,default_environment_id)
                 VALUES (?1,?2,?3,?4,?5,?5,?6,?7,?8)
                 ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description,
                   default_headers_json=excluded.default_headers_json,
                   default_auth_json=excluded.default_auth_json,
                   default_environment_id=excluded.default_environment_id,
                   updated_at=excluded.updated_at",
                params![id, name, input.description.trim(), sort_order, now, to_json(&input.default_headers)?, default_auth_json, input.default_environment_id],
            )?;
            Ok(())
        })?;
        self.get_request_collection(&id)
    }

    pub fn get_request_collection(&self, collection_id: &str) -> Result<RequestCollection, String> {
        let mut collection = self.with_connection(|connection| {
            connection.query_row(
                "SELECT c.id,c.name,c.description,c.sort_order,
                        (SELECT COUNT(*) FROM request_drafts d WHERE d.collection_id=c.id),
                        (SELECT COUNT(*) FROM request_collection_folders f WHERE f.collection_id=c.id),
                        c.created_at,c.updated_at,c.default_headers_json,c.default_auth_json,c.default_environment_id,
                        c.source_format,c.source_path,c.source_fingerprint,c.source_synced_at
                 FROM request_collections c WHERE c.id=?1",
                [collection_id],
                request_collection_from_row,
            )
        })?;
        collection.default_auth =
            decode_collection_auth(&collection.id, &collection.default_auth, true)?;
        Ok(collection)
    }

    pub(crate) fn get_request_collection_for_send(
        &self,
        collection_id: &str,
    ) -> Result<RequestCollection, String> {
        let mut collection = self.with_connection(|connection| {
            connection.query_row(
                "SELECT c.id,c.name,c.description,c.sort_order,
                        (SELECT COUNT(*) FROM request_drafts d WHERE d.collection_id=c.id),
                        (SELECT COUNT(*) FROM request_collection_folders f WHERE f.collection_id=c.id),
                        c.created_at,c.updated_at,c.default_headers_json,c.default_auth_json,c.default_environment_id,
                        c.source_format,c.source_path,c.source_fingerprint,c.source_synced_at
                 FROM request_collections c WHERE c.id=?1",
                [collection_id],
                request_collection_from_row,
            )
        })?;
        collection.default_auth =
            decode_collection_auth(&collection.id, &collection.default_auth, false)?;
        Ok(collection)
    }

    pub fn list_request_collections(&self) -> Result<Vec<RequestCollection>, String> {
        let rows = self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT c.id,c.name,c.description,c.sort_order,
                        (SELECT COUNT(*) FROM request_drafts d WHERE d.collection_id=c.id),
                        (SELECT COUNT(*) FROM request_collection_folders f WHERE f.collection_id=c.id),
                        c.created_at,c.updated_at,c.default_headers_json,c.default_auth_json,c.default_environment_id,
                        c.source_format,c.source_path,c.source_fingerprint,c.source_synced_at
                 FROM request_collections c ORDER BY c.sort_order ASC,c.name COLLATE NOCASE ASC",
            )?;
            let rows = statement
                .query_map([], request_collection_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })?;
        rows.into_iter()
            .map(|mut collection| {
                collection.default_auth =
                    decode_collection_auth(&collection.id, &collection.default_auth, true)?;
                Ok(collection)
            })
            .collect()
    }

    pub fn delete_request_collection(&self, collection_id: &str) -> Result<(), String> {
        let changed = self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM request_collections WHERE id=?1",
                [collection_id],
            )
        })?;
        if changed == 0 {
            return Err("请求集合不存在".to_string());
        }
        Ok(())
    }

    pub fn save_request_collection_folder(
        &self,
        input: RequestCollectionFolderInput,
    ) -> Result<RequestCollectionFolder, String> {
        let name = input.name.trim();
        if name.is_empty() || name.chars().count() > 80 {
            return Err("文件夹名称必须在 1 到 80 个字符之间".to_string());
        }
        self.get_request_collection(&input.collection_id)?;
        let id = input
            .id
            .unwrap_or_else(|| format!("folder-{}", Uuid::new_v4()));
        let target_depth = self.request_collection_folder_target_depth(
            &input.collection_id,
            input.parent_id.as_deref(),
            Some(&id),
        )?;
        let existing = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT parent_id,depth FROM request_collection_folders WHERE id=?1",
                    [&id],
                    |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()
        })?;
        if let Some((_, current_depth)) = &existing {
            let relative_depth = self.with_connection(|connection| {
                connection.query_row(
                    "WITH RECURSIVE descendants(id,relative_depth) AS (
                       SELECT id,0 FROM request_collection_folders WHERE id=?1
                       UNION ALL
                       SELECT f.id,d.relative_depth+1 FROM request_collection_folders f JOIN descendants d ON f.parent_id=d.id
                     ) SELECT COALESCE(MAX(relative_depth),0) FROM descendants",
                    [&id],
                    |row| row.get::<_, i64>(0),
                )
            })?;
            if target_depth + relative_depth > 4 {
                return Err("移动后文件夹树会超过四级".to_string());
            }
            let duplicate = self.request_collection_folder_name_exists(
                &input.collection_id,
                input.parent_id.as_deref(),
                name,
                Some(&id),
            )?;
            if duplicate {
                return Err("当前位置已有同名文件夹".to_string());
            }
            let delta = target_depth - *current_depth;
            self.with_connection(|connection| {
                connection.execute(
                    "UPDATE request_collection_folders SET parent_id=?1,name=?2,depth=?3,updated_at=?4 WHERE id=?5",
                    params![input.parent_id, name, target_depth, now_ms(), id],
                )?;
                if delta != 0 {
                    connection.execute(
                        "WITH RECURSIVE descendants(id) AS (
                           SELECT id FROM request_collection_folders WHERE parent_id=?1
                           UNION ALL SELECT f.id FROM request_collection_folders f JOIN descendants d ON f.parent_id=d.id
                         ) UPDATE request_collection_folders SET depth=depth+?2,updated_at=?3 WHERE id IN (SELECT id FROM descendants)",
                        params![id, delta, now_ms()],
                    )?;
                }
                Ok(())
            })?;
        } else {
            if self.request_collection_folder_name_exists(
                &input.collection_id,
                input.parent_id.as_deref(),
                name,
                None,
            )? {
                return Err("当前位置已有同名文件夹".to_string());
            }
            self.with_connection(|connection| {
                let sort_order = connection.query_row(
                    "SELECT COALESCE(MAX(sort_order),-1)+1 FROM request_collection_folders WHERE collection_id=?1 AND parent_id IS ?2",
                    params![input.collection_id, input.parent_id],
                    |row| row.get::<_, i64>(0),
                )?;
                let now = now_ms();
                connection.execute(
                    "INSERT INTO request_collection_folders(id,collection_id,parent_id,name,depth,sort_order,created_at,updated_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?7)",
                    params![id, input.collection_id, input.parent_id, name, target_depth, sort_order, now],
                )?;
                Ok(())
            })?;
        }
        self.get_request_collection_folder(&id)
    }

    pub fn get_request_collection_folder(
        &self,
        folder_id: &str,
    ) -> Result<RequestCollectionFolder, String> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT f.id,f.collection_id,f.parent_id,f.name,f.depth,f.sort_order,
                        (SELECT COUNT(*) FROM request_drafts d WHERE d.folder_id=f.id),
                        f.created_at,f.updated_at
                 FROM request_collection_folders f WHERE f.id=?1",
                [folder_id],
                request_collection_folder_from_row,
            )
        })
    }

    pub fn list_request_collection_folders(&self) -> Result<Vec<RequestCollectionFolder>, String> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT f.id,f.collection_id,f.parent_id,f.name,f.depth,f.sort_order,
                        (SELECT COUNT(*) FROM request_drafts d WHERE d.folder_id=f.id),
                        f.created_at,f.updated_at
                 FROM request_collection_folders f ORDER BY f.collection_id,f.depth,f.sort_order,f.name COLLATE NOCASE",
            )?;
            let rows = statement
                .query_map([], request_collection_folder_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
    }

    pub fn delete_request_collection_folder(&self, folder_id: &str) -> Result<(), String> {
        let changed = self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM request_collection_folders WHERE id=?1",
                [folder_id],
            )
        })?;
        if changed == 0 {
            return Err("请求文件夹不存在".to_string());
        }
        Ok(())
    }

    pub fn move_request_draft(
        &self,
        input: RequestDraftLocationInput,
    ) -> Result<RequestDraft, String> {
        self.validate_request_draft_location(
            input.collection_id.as_deref(),
            input.folder_id.as_deref(),
        )?;
        let changed =
            self.with_connection(|connection| {
                connection.execute(
                "UPDATE request_drafts SET collection_id=?1,folder_id=?2,updated_at=?3 WHERE id=?4",
                params![input.collection_id, input.folder_id, now_ms(), input.draft_id],
            )
            })?;
        if changed == 0 {
            return Err("请求草稿不存在".to_string());
        }
        self.get_request_draft(&input.draft_id)
    }

    pub fn update_request_drafts_batch(
        &self,
        input: RequestDraftBatchUpdateInput,
    ) -> Result<(), String> {
        if input.draft_ids.is_empty() || input.draft_ids.len() > MAX_REQUEST_DRAFT_BATCH {
            return Err(format!(
                "每次请选择 1 到 {MAX_REQUEST_DRAFT_BATCH} 条请求草稿"
            ));
        }
        let mut seen = HashSet::new();
        let draft_ids = input
            .draft_ids
            .into_iter()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty() && seen.insert(id.clone()))
            .collect::<Vec<_>>();
        if draft_ids.is_empty() {
            return Err("请求草稿 ID 不能为空".to_string());
        }
        let add_tags = normalize_draft_tags(input.add_tags)?;
        let remove_tags = normalize_draft_tags(input.remove_tags)?;
        if input.location.is_none() && add_tags.is_empty() && remove_tags.is_empty() {
            return Err("批量操作没有包含位置或标签变更".to_string());
        }

        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "数据库状态已损坏".to_string())?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if let Some(location) = input.location.as_ref() {
            validate_request_draft_location_in_transaction(
                &transaction,
                location.collection_id.as_deref(),
                location.folder_id.as_deref(),
            )?;
        }

        let remove_keys = remove_tags
            .iter()
            .map(|tag| tag.to_lowercase())
            .collect::<HashSet<_>>();
        let now = now_ms();
        for draft_id in &draft_ids {
            let tags_json = transaction
                .query_row(
                    "SELECT tags_json FROM request_drafts WHERE id=?1",
                    [draft_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("请求草稿不存在: {draft_id}"))?;
            let mut tags = serde_json::from_str::<Vec<String>>(&tags_json).unwrap_or_default();
            tags.retain(|tag| !remove_keys.contains(&tag.to_lowercase()));
            let mut tag_keys = tags
                .iter()
                .map(|tag| tag.to_lowercase())
                .collect::<HashSet<_>>();
            for tag in &add_tags {
                if tag_keys.insert(tag.to_lowercase()) {
                    tags.push(tag.clone());
                }
            }
            let tags = normalize_draft_tags(tags)?;
            let tags_json = serde_json::to_string(&tags).map_err(|error| error.to_string())?;
            if let Some(location) = input.location.as_ref() {
                transaction
                    .execute(
                        "UPDATE request_drafts SET collection_id=?1,folder_id=?2,tags_json=?3,updated_at=?4 WHERE id=?5",
                        params![location.collection_id, location.folder_id, tags_json, now, draft_id],
                    )
                    .map_err(|error| error.to_string())?;
            } else {
                transaction
                    .execute(
                        "UPDATE request_drafts SET tags_json=?1,updated_at=?2 WHERE id=?3",
                        params![tags_json, now, draft_id],
                    )
                    .map_err(|error| error.to_string())?;
            }
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn import_request_collection(
        &self,
        input: CollectionImportCommitInput,
    ) -> Result<CollectionImportResult, String> {
        let CollectionImportCommitInput {
            collection_id: requested_collection_id,
            collection_name,
            items: raw_items,
            collection: raw_collection,
            environments: raw_environments,
            source_format,
            source_path,
            source_fingerprint,
        } = input;
        if raw_items.is_empty() || raw_items.len() > 1_000 {
            return Err("请选择 1 到 1000 条请求导入".to_string());
        }
        let openapi_source = source_format.as_deref() == Some("openapi");
        let (source_path, source_fingerprint) = if openapi_source {
            (
                Some(validate_collection_source_path(source_path.as_deref())?),
                Some(validate_sha256_fingerprint(source_fingerprint.as_deref())?),
            )
        } else {
            (None, None)
        };
        let mut collection_metadata =
            normalize_collection_import_metadata(raw_collection.unwrap_or_else(|| {
                CollectionImportMetadata {
                    description: String::new(),
                    default_headers: Vec::new(),
                    default_auth: serde_json::json!({"kind":"none"}),
                    default_environment_id: None,
                    source_format: None,
                    source_path: None,
                    source_fingerprint: None,
                    source_synced_at: None,
                }
            }))?;
        let mut items = Vec::with_capacity(raw_items.len());
        let mut operation_keys = std::collections::HashSet::new();
        for mut item in raw_items {
            if !openapi_source {
                item.source_key = None;
                item.source_fingerprint = None;
            }
            let item = crate::request_collections::normalize_import_item(item)?;
            if openapi_source {
                let key = item
                    .source_key
                    .as_deref()
                    .ok_or_else(|| "OpenAPI 请求缺少 operation key，请重新预览导入".to_string())?;
                if !operation_keys.insert(key.to_string()) {
                    return Err(format!("OpenAPI 中存在重复操作：{key}"));
                }
            }
            items.push(item);
        }
        let mut referenced_environment_ids = items
            .iter()
            .filter_map(|item| item.environment_id.clone())
            .collect::<HashSet<_>>();
        if let Some(environment_id) = collection_metadata.default_environment_id.clone() {
            referenced_environment_ids.insert(environment_id);
        }
        let (prepared_environments, environment_id_map) =
            prepare_collection_import_environments(raw_environments, referenced_environment_ids)?;
        for item in &mut items {
            if let Some(source_id) = item.environment_id.as_deref() {
                item.environment_id = environment_id_map.get(source_id).cloned();
            }
        }
        collection_metadata.default_environment_id = collection_metadata
            .default_environment_id
            .as_deref()
            .and_then(|source_id| environment_id_map.get(source_id).cloned());
        let imported_environment_count = prepared_environments.len() as i64;
        let prepared_items = items
            .into_iter()
            .map(|item| {
                let draft_id = format!("draft-{}", Uuid::new_v4());
                let auth_json = encode_draft_auth(&draft_id, &item.auth, None)?;
                Ok((draft_id, auth_json, item))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let collection_name = collection_name.trim().to_string();
        if requested_collection_id.is_none()
            && (collection_name.is_empty() || collection_name.chars().count() > 120)
        {
            return Err("集合名称必须在 1 到 120 个字符之间".to_string());
        }
        if let Some(collection_id) = requested_collection_id.as_deref() {
            let collection = self.get_request_collection(collection_id)?;
            if openapi_source && collection.source_format.is_some() {
                return Err("该集合已关联规范，请使用“同步规范”更新，避免重复导入".to_string());
            }
        }
        let creating_collection = requested_collection_id.is_none();
        let target_collection_id = requested_collection_id
            .clone()
            .unwrap_or_else(|| format!("collection-{}", Uuid::new_v4()));
        let imported_default_auth_json = creating_collection
            .then(|| {
                encode_collection_auth(
                    &target_collection_id,
                    &collection_metadata.default_auth,
                    None,
                )
            })
            .transpose()?;
        let imported_source_format = if openapi_source {
            Some("openapi".to_string())
        } else {
            collection_metadata.source_format.clone()
        };
        let imported_source_path = if openapi_source {
            source_path.clone()
        } else {
            collection_metadata.source_path.clone()
        };
        let imported_source_fingerprint = if openapi_source {
            source_fingerprint.clone()
        } else {
            collection_metadata.source_fingerprint.clone()
        };
        let (collection_id, created_folder_count, imported_count) = self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            let environment_now = now_ms();
            for environment in &prepared_environments {
                transaction.execute(
                    "INSERT INTO environments(id,name,kind,active,created_at,updated_at) VALUES (?1,?2,'named',0,?3,?3)",
                    params![environment.id, environment.name, environment_now],
                )?;
                for variable in &environment.variables {
                    transaction.execute(
                        "INSERT INTO environment_variables(id,environment_id,name,value,encrypted_value,secret,enabled,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                        params![variable.id, environment.id, variable.name, variable.value, variable.encrypted_value, variable.secret as i64, variable.enabled as i64, environment_now],
                    )?;
                }
            }
            let collection_id = if creating_collection {
                let id = target_collection_id.clone();
                let sort_order = transaction.query_row(
                    "SELECT COALESCE(MAX(sort_order),-1)+1 FROM request_collections",
                    [],
                    |row| row.get::<_, i64>(0),
                )?;
                let now = now_ms();
                transaction.execute(
                    "INSERT INTO request_collections(id,name,description,sort_order,created_at,updated_at,source_format,source_path,source_fingerprint,source_synced_at,default_headers_json,default_auth_json,default_environment_id)
                     VALUES (?1,?2,?3,?4,?5,?5,?6,?7,?8,?9,?10,?11,?12)",
                    params![id, collection_name, collection_metadata.description, sort_order, now, imported_source_format, imported_source_path, imported_source_fingerprint, if openapi_source { Some(now) } else { collection_metadata.source_synced_at }, to_json(&collection_metadata.default_headers)?, imported_default_auth_json.as_deref().unwrap_or("{\"kind\":\"none\"}"), collection_metadata.default_environment_id],
                )?;
                id
            } else {
                target_collection_id.clone()
            };
            let mut created_folder_count = 0_i64;
            let mut imported_count = 0_i64;
            for (draft_id, auth_json, item) in prepared_items {
                let mut parent_id: Option<String> = None;
                for (depth_index, folder_name) in item.folder_path.iter().take(4).enumerate() {
                    let existing = transaction
                        .query_row(
                            "SELECT id FROM request_collection_folders WHERE collection_id=?1 AND parent_id IS ?2 AND name=?3 COLLATE NOCASE",
                            params![collection_id, parent_id, folder_name],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?;
                    parent_id = Some(if let Some(existing) = existing {
                        existing
                    } else {
                        let id = format!("folder-{}", Uuid::new_v4());
                        let sort_order = transaction.query_row(
                            "SELECT COALESCE(MAX(sort_order),-1)+1 FROM request_collection_folders WHERE collection_id=?1 AND parent_id IS ?2",
                            params![collection_id, parent_id],
                            |row| row.get::<_, i64>(0),
                        )?;
                        let now = now_ms();
                        transaction.execute(
                            "INSERT INTO request_collection_folders(id,collection_id,parent_id,name,depth,sort_order,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?7)",
                            params![id, collection_id, parent_id, folder_name, depth_index as i64 + 1, sort_order, now],
                        )?;
                        created_folder_count += 1;
                        id
                    });
                }
                let now = now_ms();
                transaction.execute(
                    "INSERT INTO request_drafts(id,name,method,url,headers_json,body,body_type,auth_json,settings_json,environment_id,collection_id,folder_id,tags_json,spec_operation_key,spec_fingerprint,created_at,updated_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?16)",
                    params![draft_id, item.name, item.method, item.url, to_json(&item.headers)?, item.body, item.body_type, auth_json, to_json(&item.settings)?, item.environment_id, collection_id, parent_id, to_json(&item.tags)?, item.source_key, item.source_fingerprint, now],
                )?;
                imported_count += 1;
            }
            let updated_at = now_ms();
            if openapi_source {
                transaction.execute(
                    "UPDATE request_collections
                     SET source_format='openapi',source_path=?1,source_fingerprint=?2,source_synced_at=?3,updated_at=?3
                     WHERE id=?4",
                    params![source_path.as_deref(), source_fingerprint.as_deref(), updated_at, collection_id],
                )?;
            } else {
                transaction.execute(
                    "UPDATE request_collections SET updated_at=?1 WHERE id=?2",
                    params![updated_at, collection_id],
                )?;
            }
            transaction.commit()?;
            Ok((collection_id, created_folder_count, imported_count))
        })?;
        Ok(CollectionImportResult {
            collection: self.get_request_collection(&collection_id)?,
            imported_count,
            created_folder_count,
            imported_environment_count,
        })
    }

    pub fn preview_request_collection_sync(
        &self,
        collection_id: &str,
        path: &str,
    ) -> Result<CollectionSyncPreview, String> {
        let collection = self.get_request_collection(collection_id)?;
        if collection.source_format.as_deref() != Some("openapi") {
            return Err("该集合没有关联 OpenAPI 规范，请先通过 OpenAPI 文件导入".to_string());
        }
        let imported = crate::request_collections::preview_import_path(path)?;
        if imported.source_format != "openapi" {
            return Err("同步文件必须是 OpenAPI 或 Swagger JSON/YAML".to_string());
        }
        let source_path = validate_collection_source_path(imported.source_path.as_deref())?;
        let source_fingerprint =
            validate_sha256_fingerprint(imported.source_fingerprint.as_deref())?;
        let workspace = self.list_request_collection_workspace()?;
        let mut existing_by_key = workspace
            .drafts
            .iter()
            .filter(|draft| draft.collection_id.as_deref() == Some(collection_id))
            .filter_map(|draft| {
                draft
                    .spec_operation_key
                    .as_ref()
                    .map(|key| (key.clone(), draft.clone()))
            })
            .collect::<HashMap<_, _>>();
        let mut incoming_keys = HashSet::new();
        let mut changes = Vec::new();
        let mut unchanged_count = 0_i64;
        for item in imported.items {
            let operation_key = item
                .source_key
                .clone()
                .ok_or_else(|| "OpenAPI 请求缺少 operation key，请重新选择规范文件".to_string())?;
            if !incoming_keys.insert(operation_key.clone()) {
                return Err(format!("OpenAPI 中存在重复操作：{operation_key}"));
            }
            if let Some(draft) = existing_by_key.remove(&operation_key) {
                if draft.spec_fingerprint == item.source_fingerprint {
                    unchanged_count += 1;
                    continue;
                }
                let current_folder_path = request_draft_folder_path(&draft, &workspace.folders);
                let current_item = CollectionImportItem {
                    name: draft.name.clone(),
                    method: draft.method.clone(),
                    url: draft.url.clone(),
                    headers: draft.headers.clone(),
                    body: draft.body.clone(),
                    body_type: draft.body_type.clone(),
                    auth: draft.auth.clone(),
                    settings: draft.settings.clone(),
                    environment_id: draft.environment_id.clone(),
                    tags: draft.tags.clone(),
                    folder_path: current_folder_path.clone(),
                    source_key: Some(operation_key.clone()),
                    source_fingerprint: None,
                };
                let local_override = draft.spec_fingerprint.as_deref()
                    != Some(
                        crate::request_collections::import_item_fingerprint(&current_item).as_str(),
                    );
                changes.push(CollectionSyncChange {
                    kind: "modify".to_string(),
                    operation_key,
                    changed_fields: collection_sync_changed_fields(
                        &current_item,
                        &item,
                        &current_folder_path,
                    ),
                    item: Some(item),
                    draft_id: Some(draft.id),
                    current_name: Some(draft.name),
                    current_method: Some(draft.method),
                    current_url: Some(draft.url),
                    local_override,
                });
            } else {
                changes.push(CollectionSyncChange {
                    kind: "add".to_string(),
                    operation_key,
                    item: Some(item),
                    draft_id: None,
                    current_name: None,
                    current_method: None,
                    current_url: None,
                    changed_fields: vec!["operation".to_string()],
                    local_override: false,
                });
            }
        }
        let mut removed = existing_by_key.into_iter().collect::<Vec<_>>();
        removed.sort_by(|left, right| left.0.cmp(&right.0));
        for (operation_key, draft) in removed {
            changes.push(CollectionSyncChange {
                kind: "remove".to_string(),
                operation_key,
                item: None,
                draft_id: Some(draft.id),
                current_name: Some(draft.name),
                current_method: Some(draft.method),
                current_url: Some(draft.url),
                changed_fields: vec!["operation".to_string()],
                local_override: true,
            });
        }
        Ok(CollectionSyncPreview {
            collection_id: collection.id,
            collection_name: collection.name,
            source_path,
            source_fingerprint,
            changes,
            unchanged_count,
            warnings: imported.warnings,
        })
    }

    pub fn sync_request_collection(
        &self,
        input: CollectionSyncCommitInput,
    ) -> Result<CollectionSyncResult, String> {
        let collection = self.get_request_collection(&input.collection_id)?;
        if collection.source_format.as_deref() != Some("openapi") {
            return Err("该集合没有关联 OpenAPI 规范".to_string());
        }
        if input.selections.len() > 1_000 {
            return Err("单次最多同步 1000 条规范变更".to_string());
        }
        let source_path = validate_collection_source_path(Some(&input.source_path))?;
        let source_fingerprint = validate_sha256_fingerprint(Some(&input.source_fingerprint))?;
        let mut seen = HashSet::new();
        let mut selections = Vec::with_capacity(input.selections.len());
        for selection in input.selections {
            let kind = selection.kind.trim().to_lowercase();
            if !matches!(kind.as_str(), "add" | "modify" | "remove") {
                return Err("规范同步包含未知变更类型".to_string());
            }
            let operation_key = selection.operation_key.trim().to_string();
            if operation_key.is_empty() || !seen.insert(operation_key.clone()) {
                return Err("规范同步包含空白或重复 operation key".to_string());
            }
            let item = if matches!(kind.as_str(), "add" | "modify") {
                let item = selection
                    .item
                    .ok_or_else(|| format!("{operation_key} 缺少同步内容"))?;
                let item = crate::request_collections::normalize_import_item(item)?;
                if item.source_key.as_deref() != Some(operation_key.as_str()) {
                    return Err(format!("{operation_key} 的同步身份不一致"));
                }
                Some(item)
            } else {
                None
            };
            selections.push(CollectionSyncSelection {
                kind,
                operation_key,
                item,
                draft_id: selection.draft_id,
            });
        }

        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "数据库状态已损坏".to_string())?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let mut added_count = 0_i64;
        let mut updated_count = 0_i64;
        let mut detached_count = 0_i64;
        let mut created_folder_count = 0_i64;
        let now = now_ms();
        for selection in selections {
            match selection.kind.as_str() {
                "add" => {
                    let item = selection.item.expect("validated add item");
                    let duplicate = transaction
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM request_drafts WHERE collection_id=?1 AND spec_operation_key=?2)",
                            params![input.collection_id, selection.operation_key],
                            |row| row.get::<_, bool>(0),
                        )
                        .map_err(|error| error.to_string())?;
                    if duplicate {
                        return Err(format!(
                            "{} 已存在，请重新预览同步",
                            selection.operation_key
                        ));
                    }
                    let folder_id = ensure_import_folder_path(
                        &transaction,
                        &input.collection_id,
                        &item.folder_path,
                        &mut created_folder_count,
                    )?;
                    let headers_json = to_json(&item.headers).map_err(|error| error.to_string())?;
                    let settings_json =
                        to_json(&item.settings).map_err(|error| error.to_string())?;
                    let tags_json = to_json(&item.tags).map_err(|error| error.to_string())?;
                    let draft_id = format!("draft-{}", Uuid::new_v4());
                    let auth_json = encode_draft_auth(&draft_id, &item.auth, None)?;
                    transaction
                        .execute(
                            "INSERT INTO request_drafts(id,name,method,url,headers_json,body,body_type,auth_json,settings_json,environment_id,collection_id,folder_id,tags_json,spec_operation_key,spec_fingerprint,created_at,updated_at)
                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?16)",
                            params![draft_id, item.name, item.method, item.url, headers_json, item.body, item.body_type, auth_json, settings_json, item.environment_id, input.collection_id, folder_id, tags_json, selection.operation_key, item.source_fingerprint, now],
                        )
                        .map_err(|error| error.to_string())?;
                    added_count += 1;
                }
                "modify" => {
                    let item = selection.item.expect("validated modify item");
                    let draft_id = selection
                        .draft_id
                        .as_deref()
                        .ok_or_else(|| format!("{} 缺少草稿 ID", selection.operation_key))?;
                    let headers_json = to_json(&item.headers).map_err(|error| error.to_string())?;
                    let changed = transaction
                        .execute(
                            "UPDATE request_drafts
                             SET method=?1,url=?2,headers_json=?3,body=?4,body_type=?5,spec_fingerprint=?6,updated_at=?7
                             WHERE id=?8 AND collection_id=?9 AND spec_operation_key=?10",
                            params![item.method, item.url, headers_json, item.body, item.body_type, item.source_fingerprint, now, draft_id, input.collection_id, selection.operation_key],
                        )
                        .map_err(|error| error.to_string())?;
                    if changed != 1 {
                        return Err(format!(
                            "{} 已变化，请重新预览同步",
                            selection.operation_key
                        ));
                    }
                    updated_count += 1;
                }
                "remove" => {
                    let draft_id = selection
                        .draft_id
                        .as_deref()
                        .ok_or_else(|| format!("{} 缺少草稿 ID", selection.operation_key))?;
                    let changed = transaction
                        .execute(
                            "UPDATE request_drafts
                             SET spec_operation_key=NULL,spec_fingerprint=NULL,updated_at=?1
                             WHERE id=?2 AND collection_id=?3 AND spec_operation_key=?4",
                            params![now, draft_id, input.collection_id, selection.operation_key],
                        )
                        .map_err(|error| error.to_string())?;
                    if changed != 1 {
                        return Err(format!(
                            "{} 已变化，请重新预览同步",
                            selection.operation_key
                        ));
                    }
                    detached_count += 1;
                }
                _ => unreachable!(),
            }
        }
        transaction
            .execute(
                "UPDATE request_collections
                 SET source_path=?1,source_fingerprint=?2,source_synced_at=?3,updated_at=?3
                 WHERE id=?4 AND source_format='openapi'",
                params![source_path, source_fingerprint, now, input.collection_id],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        drop(connection);
        Ok(CollectionSyncResult {
            collection: self.get_request_collection(&input.collection_id)?,
            added_count,
            updated_count,
            detached_count,
        })
    }

    fn validate_request_draft_location(
        &self,
        collection_id: Option<&str>,
        folder_id: Option<&str>,
    ) -> Result<(), String> {
        let Some(collection_id) = collection_id else {
            if folder_id.is_some() {
                return Err("文件夹必须属于请求集合".to_string());
            }
            return Ok(());
        };
        self.get_request_collection(collection_id)?;
        if let Some(folder_id) = folder_id {
            let folder = self.get_request_collection_folder(folder_id)?;
            if folder.collection_id != collection_id {
                return Err("请求集合与文件夹不匹配".to_string());
            }
        }
        Ok(())
    }

    fn request_collection_folder_target_depth(
        &self,
        collection_id: &str,
        parent_id: Option<&str>,
        current_id: Option<&str>,
    ) -> Result<i64, String> {
        let mut depth = 1_i64;
        let mut cursor = parent_id.map(ToString::to_string);
        let mut seen = HashSet::new();
        while let Some(folder_id) = cursor {
            if current_id == Some(folder_id.as_str()) || !seen.insert(folder_id.clone()) {
                return Err("文件夹不能移动到自身或子文件夹".to_string());
            }
            let folder = self.get_request_collection_folder(&folder_id)?;
            if folder.collection_id != collection_id {
                return Err("父文件夹不属于当前集合".to_string());
            }
            depth += 1;
            if depth > 4 {
                return Err("请求集合最多支持四级文件夹".to_string());
            }
            cursor = folder.parent_id;
        }
        Ok(depth)
    }

    fn request_collection_folder_name_exists(
        &self,
        collection_id: &str,
        parent_id: Option<&str>,
        name: &str,
        excluding_id: Option<&str>,
    ) -> Result<bool, String> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM request_collection_folders WHERE collection_id=?1 AND parent_id IS ?2 AND name=?3 COLLATE NOCASE AND id<>COALESCE(?4,''))",
                params![collection_id, parent_id, name, excluding_id],
                |row| row.get::<_, bool>(0),
            )
        })
    }

    pub fn create_request_run(
        &self,
        draft_id: &str,
        request_snapshot: &Value,
    ) -> Result<RequestRun, String> {
        let id = format!("run-{}", Uuid::new_v4());
        let started_at = now_ms();
        self.with_connection(|connection| {
            connection.execute("INSERT INTO request_runs(id, draft_id, status, request_snapshot_json, started_at) VALUES (?1, ?2, 'running', ?3, ?4)", params![id, draft_id, to_json(request_snapshot)?, started_at])?;
            Ok(())
        })?;
        self.get_request_run(&id)
    }

    pub fn finish_request_run(
        &self,
        run_id: &str,
        status: &str,
        response: &Value,
        error: Option<&str>,
    ) -> Result<RequestRun, String> {
        self.with_connection(|connection| {
            connection.execute("UPDATE request_runs SET status=?1, response_snapshot_json=?2, error=?3, finished_at=?4 WHERE id=?5", params![status, to_json(response)?, error, now_ms(), run_id])?;
            Ok(())
        })?;
        self.get_request_run(run_id)
    }

    pub fn get_request_run(&self, run_id: &str) -> Result<RequestRun, String> {
        self.with_connection(|connection| connection.query_row(
            "SELECT id, draft_id, status, request_snapshot_json, response_snapshot_json, error, started_at, finished_at FROM request_runs WHERE id=?1",
            [run_id], |row| Ok(RequestRun { id: row.get(0)?, draft_id: row.get(1)?, status: row.get(2)?, request_snapshot: from_json(row.get::<_, String>(3)?), response_snapshot: from_json(row.get::<_, String>(4)?), error: row.get(5)?, started_at: row.get(6)?, finished_at: row.get(7)? }),
        ))
    }

    pub fn list_request_runs(&self, draft_id: &str) -> Result<Vec<RequestRun>, String> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT id, draft_id, status, request_snapshot_json, response_snapshot_json, error, started_at, finished_at FROM request_runs WHERE draft_id=?1 ORDER BY started_at DESC LIMIT 100")?;
            let rows = statement.query_map([draft_id], |row| Ok(RequestRun { id: row.get(0)?, draft_id: row.get(1)?, status: row.get(2)?, request_snapshot: from_json(row.get::<_, String>(3)?), response_snapshot: from_json(row.get::<_, String>(4)?), error: row.get(5)?, started_at: row.get(6)?, finished_at: row.get(7)? }))?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
    }

    pub fn save_environment(&self, input: EnvironmentInput) -> Result<EnvironmentRecord, String> {
        let name = input.name.trim();
        if name.is_empty()
            || name.chars().count() > 80
            || !matches!(input.kind.as_str(), "global" | "named")
        {
            return Err("环境名称或类型无效".to_string());
        }
        let id = input
            .id
            .unwrap_or_else(|| format!("environment-{}", Uuid::new_v4()));
        let now = now_ms();
        self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            if input.active && input.kind == "named" {
                transaction.execute("UPDATE environments SET active=0 WHERE kind='named'", [])?;
            }
            transaction.execute(
                "INSERT INTO environments(id,name,kind,active,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?5)
                 ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind, active=excluded.active, updated_at=excluded.updated_at",
                params![id, name, input.kind, input.active as i64, now],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        self.get_environment(&id)
    }

    pub fn save_environment_variable(
        &self,
        input: EnvironmentVariableInput,
    ) -> Result<EnvironmentRecord, String> {
        let name = input.name.trim();
        if name.is_empty()
            || name.chars().count() > 80
            || !name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
            })
        {
            return Err("变量名只能包含字母、数字、点、短横线和下划线".to_string());
        }
        let id = input
            .id
            .unwrap_or_else(|| format!("variable-{}", Uuid::new_v4()));
        let existing = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT value, encrypted_value FROM environment_variables WHERE id=?1",
                    [&id],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                        ))
                    },
                )
                .optional()
        })?;
        let (value, encrypted_value) = if input.clear_value {
            (None, None)
        } else if let Some(new_value) = input.value {
            if input.secret {
                let mut aad = ENVIRONMENT_SECRET_AAD_PREFIX.to_vec();
                aad.extend_from_slice(id.as_bytes());
                (None, Some(crypto::encrypt(new_value.as_bytes(), &aad)?))
            } else {
                (Some(new_value), None)
            }
        } else {
            existing.unwrap_or((None, None))
        };
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO environment_variables(id,environment_id,name,value,encrypted_value,secret,enabled,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(id) DO UPDATE SET environment_id=excluded.environment_id,name=excluded.name,value=excluded.value,encrypted_value=excluded.encrypted_value,secret=excluded.secret,enabled=excluded.enabled,updated_at=excluded.updated_at",
                params![id, input.environment_id, name, value, encrypted_value, input.secret as i64, input.enabled as i64, now_ms()],
            )?;
            Ok(())
        })?;
        self.get_environment(&input.environment_id)
    }

    pub fn reveal_environment_variable(&self, variable_id: &str) -> Result<String, String> {
        let (value, encrypted_value, secret) = self.with_connection(|connection| {
            connection.query_row(
                "SELECT value,encrypted_value,secret FROM environment_variables WHERE id=?1",
                [variable_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
        })?;
        if !secret {
            return Ok(value.unwrap_or_default());
        }
        let Some(encrypted_value) = encrypted_value else {
            return Ok(String::new());
        };
        let mut aad = ENVIRONMENT_SECRET_AAD_PREFIX.to_vec();
        aad.extend_from_slice(variable_id.as_bytes());
        String::from_utf8(crypto::decrypt(&encrypted_value, &aad)?)
            .map_err(|_| "环境 Secret 不是有效 UTF-8".to_string())
    }

    pub fn delete_environment_variable(&self, variable_id: &str) -> Result<(), String> {
        self.with_connection(|connection| {
            if connection.execute(
                "DELETE FROM environment_variables WHERE id=?1",
                [variable_id],
            )? == 0
            {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            Ok(())
        })
        .map_err(|error| {
            if error.contains("Query returned no rows") {
                "环境变量不存在".to_string()
            } else {
                error
            }
        })
    }

    pub fn delete_environment(&self, environment_id: &str) -> Result<(), String> {
        self.with_connection(|connection| {
            if connection.execute("DELETE FROM environments WHERE id=?1", [environment_id])? == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            Ok(())
        })
        .map_err(|error| {
            if error.contains("Query returned no rows") {
                "环境不存在".to_string()
            } else {
                error
            }
        })
    }

    pub fn list_environments(&self) -> Result<Vec<EnvironmentRecord>, String> {
        let ids = self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT id FROM environments ORDER BY CASE kind WHEN 'global' THEN 0 ELSE 1 END, active DESC, name COLLATE NOCASE")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })?;
        ids.into_iter()
            .map(|id| self.get_environment(&id))
            .collect()
    }

    pub fn get_environment(&self, environment_id: &str) -> Result<EnvironmentRecord, String> {
        self.with_connection(|connection| {
            let (name, kind, active, created_at, updated_at): (String, String, bool, i64, i64) = connection.query_row("SELECT name,kind,active,created_at,updated_at FROM environments WHERE id=?1", [environment_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
            let mut statement = connection.prepare("SELECT id,name,value,encrypted_value,secret,enabled,updated_at FROM environment_variables WHERE environment_id=?1 ORDER BY name COLLATE NOCASE")?;
            let variables = statement.query_map([environment_id], |row| {
                let secret: bool = row.get(4)?;
                let value: Option<String> = row.get(2)?;
                let encrypted: Option<String> = row.get(3)?;
                Ok(EnvironmentVariable { id: row.get(0)?, name: row.get(1)?, value: if secret && encrypted.is_some() { "••••••••".to_string() } else { value.clone().unwrap_or_default() }, secret, has_value: value.is_some() || encrypted.is_some(), enabled: row.get(5)?, updated_at: row.get(6)? })
            })?.collect::<Result<Vec<_>, _>>()?;
            Ok(EnvironmentRecord { id: environment_id.to_string(), name, kind, active, variables, created_at, updated_at })
        })
    }

    pub fn effective_environment_values(
        &self,
        environment_id: Option<&str>,
    ) -> Result<Vec<(String, String, bool)>, String> {
        let environment_id = self.resolve_effective_environment_id(environment_id)?;
        let rows = self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT v.id,v.name,v.value,v.encrypted_value,v.secret FROM environment_variables v JOIN environments e ON e.id=v.environment_id
                 WHERE v.enabled=1 AND (e.kind='global' OR e.id=?1) ORDER BY CASE e.kind WHEN 'global' THEN 0 ELSE 1 END",
            )?;
            let rows = statement.query_map([environment_id.as_deref()], |row| Ok((row.get::<_, String>(0)?,row.get::<_, String>(1)?,row.get::<_, Option<String>>(2)?,row.get::<_, Option<String>>(3)?,row.get::<_, bool>(4)?)))?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })?;
        let mut result = HashMap::<String, (String, bool)>::new();
        for (id, name, value, encrypted, secret) in rows {
            let resolved = if secret {
                if let Some(encrypted) = encrypted {
                    let mut aad = ENVIRONMENT_SECRET_AAD_PREFIX.to_vec();
                    aad.extend_from_slice(id.as_bytes());
                    String::from_utf8(crypto::decrypt(&encrypted, &aad)?)
                        .map_err(|_| "环境 Secret 不是有效 UTF-8".to_string())?
                } else {
                    String::new()
                }
            } else {
                value.unwrap_or_default()
            };
            result.insert(name, (resolved, secret));
        }
        Ok(result
            .into_iter()
            .map(|(name, (value, secret))| (name, value, secret))
            .collect())
    }

    pub(crate) fn export_environment_snapshot(
        &self,
        environment_id: &str,
    ) -> Result<CollectionImportEnvironment, String> {
        let environment = self.get_environment(environment_id)?;
        let mut values = self.effective_environment_values(Some(environment_id))?;
        values.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(CollectionImportEnvironment {
            source_id: environment.id,
            name: environment.name,
            variables: values
                .into_iter()
                .map(
                    |(name, value, secret)| CollectionImportEnvironmentVariable {
                        name,
                        value,
                        secret,
                        enabled: true,
                    },
                )
                .collect(),
        })
    }

    pub(crate) fn resolve_effective_environment_id(
        &self,
        environment_id: Option<&str>,
    ) -> Result<Option<String>, String> {
        if let Some(environment_id) = environment_id.filter(|value| !value.trim().is_empty()) {
            let environment = self.get_environment(environment_id)?;
            if environment.kind != "named" {
                return Err("请求环境必须是命名环境".to_string());
            }
            return Ok(Some(environment.id));
        }
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT id FROM environments WHERE kind='named' AND active=1 LIMIT 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })
    }

    pub fn save_capture_rule(&self, input: CaptureRuleInput) -> Result<CaptureRule, String> {
        validate_capture_rule_input(&input)?;
        let id = input
            .id
            .unwrap_or_else(|| format!("rule-{}", Uuid::new_v4()));
        let now = now_ms();
        self.with_connection(|connection| {
            let transaction = connection.transaction()?;
            let existing_revision = transaction.query_row("SELECT revision FROM capture_rules WHERE id=?1", [&id], |row| row.get::<_, i64>(0)).optional()?.unwrap_or(0);
            let revision = existing_revision + 1;
            // Draft saves never activate traffic-changing behavior. Enabling is a separate,
            // explicitly confirmed command.
            let enabled = false;
            transaction.execute(
                "INSERT INTO capture_rules(id,name,enabled,priority,stage,matcher_json,action_json,created_by,revision,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)
                 ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,priority=excluded.priority,stage=excluded.stage,matcher_json=excluded.matcher_json,action_json=excluded.action_json,created_by=excluded.created_by,revision=excluded.revision,updated_at=excluded.updated_at",
                params![id,input.name.trim(),enabled as i64,input.priority,input.stage,to_json(&input.matcher)?,to_json(&input.action)?,input.created_by,revision,now],
            )?;
            let snapshot = serde_json::json!({"name":input.name,"enabled":enabled,"priority":input.priority,"stage":input.stage,"matcher":input.matcher,"action":input.action,"createdBy":input.created_by});
            transaction.execute("INSERT INTO capture_rule_revisions(id,rule_id,revision,snapshot_json,created_at) VALUES (?1,?2,?3,?4,?5)", params![format!("rule-revision-{}",Uuid::new_v4()),id,revision,to_json(&snapshot)?,now])?;
            transaction.commit()?;
            Ok(())
        })?;
        self.get_capture_rule(&id)
    }

    pub fn get_capture_rule(&self, rule_id: &str) -> Result<CaptureRule, String> {
        self.with_connection(|connection| connection.query_row("SELECT id,name,enabled,priority,stage,matcher_json,action_json,created_by,revision,hit_count,last_error,created_at,updated_at FROM capture_rules WHERE id=?1", [rule_id], capture_rule_from_row))
    }

    pub fn list_capture_rules(&self) -> Result<Vec<CaptureRule>, String> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT id,name,enabled,priority,stage,matcher_json,action_json,created_by,revision,hit_count,last_error,created_at,updated_at FROM capture_rules ORDER BY priority ASC, updated_at DESC")?;
            let rows = statement.query_map([], capture_rule_from_row)?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
    }

    pub fn list_capture_rule_revisions(
        &self,
        rule_id: &str,
    ) -> Result<Vec<CaptureRuleRevision>, String> {
        self.get_capture_rule(rule_id)?;
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id,rule_id,revision,snapshot_json,created_at
                   FROM capture_rule_revisions
                  WHERE rule_id=?1 ORDER BY revision DESC",
            )?;
            let rows = statement
                .query_map([rule_id], |row| {
                    Ok(CaptureRuleRevision {
                        id: row.get(0)?,
                        rule_id: row.get(1)?,
                        revision: row.get(2)?,
                        snapshot: from_json(row.get::<_, String>(3)?),
                        created_at: row.get(4)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
    }

    pub fn restore_capture_rule_revision(
        &self,
        rule_id: &str,
        revision: i64,
    ) -> Result<CaptureRule, String> {
        let snapshot = self.with_connection(|connection| {
            connection.query_row(
                "SELECT snapshot_json FROM capture_rule_revisions
                  WHERE rule_id=?1 AND revision=?2",
                params![rule_id, revision],
                |row| row.get::<_, String>(0),
            )
        })?;
        let mut input: CaptureRuleInput = serde_json::from_str(&snapshot)
            .map_err(|error| format!("规则版本快照无效: {error}"))?;
        input.id = Some(rule_id.to_string());
        input.enabled = false;
        self.save_capture_rule(input)
    }

    pub fn set_capture_rule_enabled(
        &self,
        rule_id: &str,
        enabled: bool,
        confirmed: bool,
    ) -> Result<CaptureRule, String> {
        if enabled && !confirmed {
            return Err("启用规则前必须在桌面界面确认影响范围".to_string());
        }
        if enabled {
            let rule = self.get_capture_rule(rule_id)?;
            validate_capture_rule_input(&CaptureRuleInput {
                id: Some(rule.id),
                name: rule.name,
                enabled: rule.enabled,
                priority: rule.priority,
                stage: rule.stage,
                matcher: rule.matcher,
                action: rule.action,
                created_by: rule.created_by,
            })?;
        }
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE capture_rules SET enabled=?1,updated_at=?2 WHERE id=?3",
                params![enabled as i64, now_ms(), rule_id],
            )?;
            Ok(())
        })?;
        self.get_capture_rule(rule_id)
    }

    pub fn record_capture_rule_run(&self, run: &CaptureRuleRun) -> Result<(), String> {
        self.with_connection(|connection| {
            connection.execute("INSERT INTO capture_rule_runs(id,request_id,rule_id,rule_name,revision,stage,result,diff_summary_json,duration_ms,error,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![run.id,run.request_id,run.rule_id,run.rule_name,run.revision,run.stage,run.result,to_json(&run.diff_summary)?,run.duration_ms,run.error,run.created_at])?;
            connection.execute("UPDATE capture_rules SET hit_count=hit_count+CASE WHEN ?1='applied' THEN 1 ELSE 0 END,last_error=?2 WHERE id=?3",params![run.result,run.error,run.rule_id])?;
            Ok(())
        })
    }

    pub fn list_rule_trace_for_request(
        &self,
        request_id: &str,
    ) -> Result<Vec<CaptureRuleRun>, String> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT id,request_id,rule_id,rule_name,revision,stage,result,diff_summary_json,duration_ms,error,created_at FROM capture_rule_runs WHERE request_id=?1 ORDER BY created_at ASC")?;
            let rows = statement.query_map([request_id], |row| Ok(CaptureRuleRun { id:row.get(0)?,request_id:row.get(1)?,rule_id:row.get(2)?,rule_name:row.get(3)?,revision:row.get(4)?,stage:row.get(5)?,result:row.get(6)?,diff_summary:from_json(row.get::<_,String>(7)?),duration_ms:row.get(8)?,error:row.get(9)?,created_at:row.get(10)? }))?.collect::<Result<Vec<_>,_>>()?;
            Ok(rows)
        })
    }

    fn request_session_id(&self, request_id: &str) -> Result<String, String> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT session_id FROM requests WHERE id=?1",
                [request_id],
                |row| row.get(0),
            )
        })
    }

    pub(crate) fn request_session_id_for_replay(&self, request_id: &str) -> Result<String, String> {
        self.request_session_id(request_id)
    }

    pub fn recent_device_request_count(&self, session_id: &str) -> Result<i64, String> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM requests WHERE session_id=?1 AND source IN ('mobile','iot')",
                [session_id],
                |row| row.get(0),
            )
        })
    }

    fn get_request_with_connection(
        &self,
        connection: &Connection,
        id: &str,
    ) -> rusqlite::Result<RequestRecord> {
        connection.query_row(
            "SELECT id, sequence, started_at, method, host, path, query, status,
                    resource_type, size_bytes, duration_ms, source, protocol,
                    tls_version, risk_level, request_headers_json,
                    response_headers_json, request_body, response_body,
                    response_body_meta_json, json_array_length(crypto_snippets_json),
                    hook_json, tls_fingerprint_json
             FROM requests WHERE id = ?1",
            [id],
            |row| {
                Ok(RequestRecord {
                    id: row.get(0)?,
                    order: row.get(1)?,
                    time: format_time(row.get(2)?),
                    method: row.get(3)?,
                    host: row.get(4)?,
                    path: row.get(5)?,
                    query: row.get(6)?,
                    status: row.get(7)?,
                    resource_type: row.get(8)?,
                    size: format_bytes(row.get(9)?),
                    duration: row.get(10)?,
                    source: row.get(11)?,
                    protocol: row.get(12)?,
                    tls: row.get(13)?,
                    tls_fingerprint: row
                        .get::<_, Option<String>>(22)?
                        .and_then(|value| serde_json::from_str(&value).ok()),
                    risk: row.get(14)?,
                    request_headers: from_json(row.get::<_, String>(15)?),
                    response_headers: from_json(row.get::<_, String>(16)?),
                    request_body: row.get(17)?,
                    response_body: row.get::<_, Option<String>>(18)?.unwrap_or_default(),
                    response_body_metadata: from_json(
                        row.get::<_, String>(19)
                            .unwrap_or_else(|_| "{}".to_string()),
                    ),
                    crypto_snippet_count: row.get::<_, Option<i64>>(20)?.unwrap_or_default(),
                    hook: row
                        .get::<_, Option<String>>(21)?
                        .and_then(|value| serde_json::from_str::<HookRecord>(&value).ok()),
                })
            },
        )
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> rusqlite::Result<T>,
    ) -> Result<T, String> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "数据库状态已损坏".to_string())?;
        operation(&mut connection).map_err(|error| error.to_string())
    }

    fn with_cancellable_connection<T>(
        &self,
        cancellation: Arc<AtomicBool>,
        operation: impl FnOnce(&mut Connection) -> rusqlite::Result<T>,
    ) -> Result<T, String> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "数据库状态已损坏".to_string())?;
        if cancellation.load(Ordering::Acquire) {
            return Err(REQUEST_QUERY_CANCELLED.to_string());
        }

        let progress_cancellation = cancellation.clone();
        connection
            .progress_handler(
                1_000,
                Some(move || progress_cancellation.load(Ordering::Acquire)),
            )
            .map_err(|error| error.to_string())?;
        let result = operation(&mut connection);
        let clear_result = connection.progress_handler(0, None::<fn() -> bool>);
        if let Err(error) = clear_result {
            return Err(error.to_string());
        }
        if cancellation.load(Ordering::Acquire) {
            return Err(REQUEST_QUERY_CANCELLED.to_string());
        }
        result.map_err(|error| error.to_string())
    }
}

fn take_replay_context(headers: &mut Vec<crate::models::HeaderEntry>) -> Option<(String, String)> {
    let index = headers
        .iter()
        .position(|header| header.name.eq_ignore_ascii_case(REPLAY_CONTEXT_HEADER))?;
    let value = headers.remove(index).value;
    let (item_id, source_request_id) = value.split_once(':')?;
    if item_id.starts_with("replay-item-") && source_request_id.starts_with("request-") {
        Some((item_id.to_string(), source_request_id.to_string()))
    } else {
        None
    }
}

fn normalize_draft_tags(tags: Vec<String>) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for tag in tags {
        let tag = tag.split_whitespace().collect::<Vec<_>>().join(" ");
        if tag.is_empty() {
            continue;
        }
        if tag.chars().count() > MAX_REQUEST_DRAFT_TAG_CHARS {
            return Err(format!(
                "每个标签不能超过 {MAX_REQUEST_DRAFT_TAG_CHARS} 个字符"
            ));
        }
        if seen.insert(tag.to_lowercase()) {
            normalized.push(tag);
        }
    }
    if normalized.len() > MAX_REQUEST_DRAFT_TAGS {
        return Err(format!("每条请求最多 {MAX_REQUEST_DRAFT_TAGS} 个标签"));
    }
    Ok(normalized)
}

fn normalize_collection_import_metadata(
    mut metadata: CollectionImportMetadata,
) -> Result<CollectionImportMetadata, String> {
    metadata.description = metadata.description.trim().to_string();
    if metadata.description.chars().count() > 2_000 {
        return Err("集合说明不能超过 2000 个字符".to_string());
    }
    validate_collection_default_headers(&metadata.default_headers)?;
    if metadata.default_auth.is_null() {
        metadata.default_auth = serde_json::json!({"kind":"none"});
    }
    if !metadata.default_auth.is_object() {
        return Err("集合默认 Auth 配置无效".to_string());
    }
    metadata.default_environment_id = metadata
        .default_environment_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if metadata
        .default_environment_id
        .as_ref()
        .is_some_and(|value| value.chars().count() > 256)
    {
        return Err("集合默认环境 ID 不能超过 256 个字符".to_string());
    }
    metadata.source_format = bounded_optional_metadata(metadata.source_format, 40, "来源格式")?;
    metadata.source_path = bounded_optional_metadata(metadata.source_path, 4_096, "来源路径")?;
    metadata.source_fingerprint =
        bounded_optional_metadata(metadata.source_fingerprint, 1_024, "来源指纹")?;
    Ok(metadata)
}

fn bounded_optional_metadata(
    value: Option<String>,
    maximum: usize,
    label: &str,
) -> Result<Option<String>, String> {
    let value = value.map(|value| value.trim().to_string());
    if value
        .as_ref()
        .is_some_and(|value| value.chars().count() > maximum)
    {
        return Err(format!("集合{label}不能超过 {maximum} 个字符"));
    }
    Ok(value.filter(|value| !value.is_empty()))
}

fn prepare_collection_import_environments(
    mut environments: Vec<CollectionImportEnvironment>,
    referenced_source_ids: HashSet<String>,
) -> Result<
    (
        Vec<PreparedCollectionImportEnvironment>,
        HashMap<String, String>,
    ),
    String,
> {
    let supplied_ids = environments
        .iter()
        .map(|environment| environment.source_id.trim().to_string())
        .collect::<HashSet<_>>();
    let mut missing_ids = referenced_source_ids
        .into_iter()
        .filter(|source_id| !supplied_ids.contains(source_id))
        .collect::<Vec<_>>();
    missing_ids.sort();
    environments.extend(
        missing_ids
            .into_iter()
            .map(|source_id| CollectionImportEnvironment {
                name: format!("导入环境 {source_id}").chars().take(120).collect(),
                source_id,
                variables: Vec::new(),
            }),
    );
    if environments.len() > 50 {
        return Err("单次最多导入 50 个环境".to_string());
    }

    let mut source_ids = HashSet::new();
    let mut environment_id_map = HashMap::new();
    let mut prepared = Vec::with_capacity(environments.len());
    for environment in environments {
        let source_id = environment.source_id.trim();
        if source_id.is_empty()
            || source_id.chars().count() > 256
            || !source_ids.insert(source_id.to_string())
        {
            return Err("导入环境包含空白、过长或重复的源 ID".to_string());
        }
        let name = environment.name.trim();
        if name.is_empty() || name.chars().count() > 120 {
            return Err(format!("环境 {source_id} 的名称必须在 1 到 120 个字符之间"));
        }
        if environment.variables.len() > 1_000 {
            return Err(format!("环境“{name}”最多导入 1000 个变量"));
        }
        let target_id = format!("environment-{}", Uuid::new_v4());
        let mut variable_names = HashSet::new();
        let mut variables = Vec::with_capacity(environment.variables.len());
        for variable in environment.variables {
            let variable_name = variable.name.trim();
            if variable_name.is_empty()
                || variable_name.chars().count() > 80
                || !variable_name.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
                })
                || !variable_names.insert(variable_name.to_string())
            {
                return Err(format!("环境“{name}”包含无效或重复的变量名"));
            }
            let variable_id = format!("variable-{}", Uuid::new_v4());
            let (value, encrypted_value) = if variable.secret {
                let mut aad = ENVIRONMENT_SECRET_AAD_PREFIX.to_vec();
                aad.extend_from_slice(variable_id.as_bytes());
                (
                    None,
                    Some(crypto::encrypt(variable.value.as_bytes(), &aad)?),
                )
            } else {
                (Some(variable.value), None)
            };
            variables.push(PreparedCollectionImportEnvironmentVariable {
                id: variable_id,
                name: variable_name.to_string(),
                value,
                encrypted_value,
                secret: variable.secret,
                enabled: variable.enabled,
            });
        }
        environment_id_map.insert(source_id.to_string(), target_id.clone());
        prepared.push(PreparedCollectionImportEnvironment {
            id: target_id,
            name: name.to_string(),
            variables,
        });
    }
    Ok((prepared, environment_id_map))
}

fn validate_collection_source_path(path: Option<&str>) -> Result<String, String> {
    let path = path.unwrap_or_default().trim();
    if path.is_empty() || path.chars().count() > 4_096 || !Path::new(path).is_absolute() {
        return Err("规范来源必须是有效的本机绝对路径".to_string());
    }
    Ok(path.to_string())
}

fn validate_sha256_fingerprint(fingerprint: Option<&str>) -> Result<String, String> {
    let fingerprint = fingerprint.unwrap_or_default().trim().to_ascii_lowercase();
    if fingerprint.len() != 64
        || !fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("规范指纹无效，请重新预览文件".to_string());
    }
    Ok(fingerprint)
}

fn request_draft_folder_path(
    draft: &RequestDraft,
    folders: &[RequestCollectionFolder],
) -> Vec<String> {
    let Some(collection_id) = draft.collection_id.as_deref() else {
        return Vec::new();
    };
    let mut path = Vec::new();
    let mut visited = HashSet::new();
    let mut folder = draft
        .folder_id
        .as_ref()
        .and_then(|id| folders.iter().find(|folder| folder.id == *id));
    while let Some(current) = folder {
        if current.collection_id != collection_id || !visited.insert(current.id.clone()) {
            break;
        }
        path.push(current.name.clone());
        folder = current
            .parent_id
            .as_ref()
            .and_then(|id| folders.iter().find(|candidate| candidate.id == *id));
    }
    path.reverse();
    path
}

fn collection_sync_changed_fields(
    current: &CollectionImportItem,
    incoming: &CollectionImportItem,
    current_folder_path: &[String],
) -> Vec<String> {
    let mut fields = Vec::new();
    if current.name != incoming.name {
        fields.push("name".to_string());
    }
    if current.method != incoming.method {
        fields.push("method".to_string());
    }
    if current.url != incoming.url {
        fields.push("url".to_string());
    }
    if current.headers != incoming.headers {
        fields.push("headers".to_string());
    }
    if current.body_type != incoming.body_type || current.body != incoming.body {
        fields.push("body".to_string());
    }
    if current.auth != incoming.auth {
        fields.push("auth".to_string());
    }
    if current.settings != incoming.settings {
        fields.push("settings".to_string());
    }
    if current.environment_id != incoming.environment_id {
        fields.push("environment".to_string());
    }
    if current.tags != incoming.tags {
        fields.push("tags".to_string());
    }
    if current_folder_path != incoming.folder_path {
        fields.push("folder".to_string());
    }
    if fields.is_empty() {
        fields.push("request".to_string());
    }
    fields
}

fn ensure_import_folder_path(
    transaction: &Transaction<'_>,
    collection_id: &str,
    folder_path: &[String],
    created_folder_count: &mut i64,
) -> Result<Option<String>, String> {
    let mut parent_id: Option<String> = None;
    for (depth_index, folder_name) in folder_path.iter().take(4).enumerate() {
        let existing = transaction
            .query_row(
                "SELECT id FROM request_collection_folders
                 WHERE collection_id=?1 AND parent_id IS ?2 AND name=?3 COLLATE NOCASE",
                params![collection_id, parent_id, folder_name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        parent_id = Some(if let Some(existing) = existing {
            existing
        } else {
            let id = format!("folder-{}", Uuid::new_v4());
            let sort_order = transaction
                .query_row(
                    "SELECT COALESCE(MAX(sort_order),-1)+1 FROM request_collection_folders
                     WHERE collection_id=?1 AND parent_id IS ?2",
                    params![collection_id, parent_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO request_collection_folders(id,collection_id,parent_id,name,depth,sort_order,created_at,updated_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?7)",
                    params![id, collection_id, parent_id, folder_name, depth_index as i64 + 1, sort_order, now_ms()],
                )
                .map_err(|error| error.to_string())?;
            *created_folder_count += 1;
            id
        });
    }
    Ok(parent_id)
}

fn validate_request_draft_location_in_transaction(
    transaction: &Transaction<'_>,
    collection_id: Option<&str>,
    folder_id: Option<&str>,
) -> Result<(), String> {
    let Some(collection_id) = collection_id else {
        return if folder_id.is_some() {
            Err("文件夹必须属于请求集合".to_string())
        } else {
            Ok(())
        };
    };
    let collection_exists = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM request_collections WHERE id=?1)",
            [collection_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| error.to_string())?;
    if !collection_exists {
        return Err("请求集合不存在".to_string());
    }
    if let Some(folder_id) = folder_id {
        let folder_collection = transaction
            .query_row(
                "SELECT collection_id FROM request_collection_folders WHERE id=?1",
                [folder_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "请求文件夹不存在".to_string())?;
        if folder_collection != collection_id {
            return Err("请求集合与文件夹不匹配".to_string());
        }
    }
    Ok(())
}

fn validate_request_draft(input: &RequestDraftInput) -> Result<(), String> {
    if input.name.trim().is_empty() || input.name.chars().count() > 120 {
        return Err("草稿名称必须在 1 到 120 个字符之间".to_string());
    }
    if input.method.trim().is_empty()
        || input.method.len() > 20
        || !input
            .method
            .chars()
            .all(|character| character.is_ascii_alphabetic() || character == '-')
    {
        return Err("请求方法无效".to_string());
    }
    let url = reqwest::Url::parse(input.url.trim()).map_err(|_| "请求 URL 无效".to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("Request Lab 仅支持 HTTP(S) URL".to_string());
    }
    if input.headers.len() > 200 || input.body.len() > 2 * 1024 * 1024 {
        return Err("Header 或正文超过 Request Lab 上限".to_string());
    }
    if !matches!(
        input.body_type.as_str(),
        "none" | "json" | "text" | "xml" | "raw" | "form-data" | "urlencoded" | "file"
    ) {
        return Err("请求正文类型无效".to_string());
    }
    Ok(())
}

fn validate_collection_default_headers(
    headers: &[crate::models::HeaderEntry],
) -> Result<(), String> {
    if headers.len() > 100 {
        return Err("集合公共 Header 最多 100 条".to_string());
    }
    let mut names = HashSet::new();
    for header in headers {
        let name = header.name.trim();
        if name.is_empty() || name.len() > 256 {
            return Err("集合公共 Header 名称必须在 1 到 256 字节之间".to_string());
        }
        reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("集合公共 Header 名称无效: {name}"))?;
        if header.value.len() > 16 * 1024 || header.value.contains(['\r', '\n']) {
            return Err(format!("集合公共 Header 值无效: {name}"));
        }
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(format!("集合公共 Header 重复: {name}"));
        }
    }
    Ok(())
}

fn draft_auth_aad(draft_id: &str) -> Vec<u8> {
    let mut aad = REQUEST_DRAFT_AUTH_AAD_PREFIX.to_vec();
    aad.extend_from_slice(draft_id.as_bytes());
    aad
}

fn collection_auth_aad(collection_id: &str) -> Vec<u8> {
    let mut aad = REQUEST_COLLECTION_AUTH_AAD_PREFIX.to_vec();
    aad.extend_from_slice(collection_id.as_bytes());
    aad
}

fn encode_draft_auth(
    draft_id: &str,
    auth: &Value,
    existing: Option<&str>,
) -> Result<String, String> {
    encode_auth_value(
        auth,
        existing,
        &draft_auth_aad(draft_id),
        "Request Lab Auth",
    )
}

fn encode_collection_auth(
    collection_id: &str,
    auth: &Value,
    existing: Option<&str>,
) -> Result<String, String> {
    encode_auth_value(
        auth,
        existing,
        &collection_auth_aad(collection_id),
        "集合 Auth",
    )
}

fn encode_auth_value(
    auth: &Value,
    existing: Option<&str>,
    aad: &[u8],
    context: &str,
) -> Result<String, String> {
    let kind = auth.get("kind").and_then(Value::as_str).unwrap_or("none");
    if kind == "none" {
        return serde_json::to_string(&serde_json::json!({"kind":"none"}))
            .map_err(|error| error.to_string());
    }
    let secret_field = match kind {
        "basic" => "password",
        "bearer" => "token",
        "api-key" => "value",
        _ => return Err(format!("{context} 类型无效")),
    };
    let mut normalized = auth.clone();
    let has_new_secret = normalized
        .get(secret_field)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    if !has_new_secret
        && normalized
            .get("hasSecret")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        if let Some(existing) = existing {
            let stored = serde_json::from_str::<Value>(existing)
                .map_err(|error| format!("{context} 密文索引损坏: {error}"))?;
            let previous = decode_auth_value(&stored, false, aad, context)?;
            if previous.get("kind").and_then(Value::as_str) == Some(kind) {
                if let Some(secret) = previous.get(secret_field).cloned() {
                    normalized
                        .as_object_mut()
                        .ok_or_else(|| format!("{context} 配置无效"))?
                        .insert(secret_field.to_string(), secret);
                }
            }
        }
    }
    if !normalized
        .get(secret_field)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        return Err(format!("{context} 敏感值不能为空"));
    }
    if let Some(object) = normalized.as_object_mut() {
        object.remove("hasSecret");
    }
    let plaintext = serde_json::to_vec(&normalized).map_err(|error| error.to_string())?;
    let encrypted = crypto::encrypt(&plaintext, aad)?;
    serde_json::to_string(&serde_json::json!({"kind":kind,"encrypted":encrypted}))
        .map_err(|error| error.to_string())
}

fn decode_draft_auth(draft_id: &str, stored: &Value, masked: bool) -> Result<Value, String> {
    decode_auth_value(
        stored,
        masked,
        &draft_auth_aad(draft_id),
        "Request Lab Auth",
    )
}

fn decode_collection_auth(
    collection_id: &str,
    stored: &Value,
    masked: bool,
) -> Result<Value, String> {
    decode_auth_value(
        stored,
        masked,
        &collection_auth_aad(collection_id),
        "集合 Auth",
    )
}

fn decode_auth_value(
    stored: &Value,
    masked: bool,
    aad: &[u8],
    context: &str,
) -> Result<Value, String> {
    let Some(encrypted) = stored.get("encrypted").and_then(Value::as_str) else {
        return Ok(stored.clone());
    };
    let plaintext = crypto::decrypt(encrypted, aad)?;
    let auth: Value = serde_json::from_slice(&plaintext)
        .map_err(|error| format!("{context} 密文内容损坏: {error}"))?;
    if !masked {
        return Ok(auth);
    }
    let kind = auth.get("kind").and_then(Value::as_str).unwrap_or("none");
    Ok(match kind {
        "basic" => {
            serde_json::json!({"kind":"basic","username":auth.get("username").and_then(Value::as_str).unwrap_or_default(),"hasSecret":true})
        }
        "api-key" => {
            serde_json::json!({"kind":"api-key","name":auth.get("name").and_then(Value::as_str).unwrap_or("X-API-Key"),"location":auth.get("location").and_then(Value::as_str).unwrap_or("header"),"hasSecret":true})
        }
        _ => serde_json::json!({"kind":kind,"hasSecret":true}),
    })
}

fn request_draft_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RequestDraft> {
    Ok(RequestDraft {
        id: row.get(0)?,
        session_id: row.get(1)?,
        source_request_id: row.get(2)?,
        name: row.get(3)?,
        method: row.get(4)?,
        url: row.get(5)?,
        headers: from_json(row.get::<_, String>(6)?),
        body: row.get(7)?,
        body_type: row.get(8)?,
        auth: from_json(row.get::<_, String>(9)?),
        settings: from_json(row.get::<_, String>(10)?),
        environment_id: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
        collection_id: row.get(14)?,
        folder_id: row.get(15)?,
        tags: from_json(row.get::<_, String>(16)?),
        spec_operation_key: row.get(17)?,
        spec_fingerprint: row.get(18)?,
    })
}

fn request_collection_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RequestCollection> {
    Ok(RequestCollection {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        sort_order: row.get(3)?,
        draft_count: row.get(4)?,
        folder_count: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        default_headers: from_json(row.get::<_, String>(8)?),
        default_auth: from_json(row.get::<_, String>(9)?),
        default_environment_id: row.get(10)?,
        source_format: row.get(11)?,
        source_path: row.get(12)?,
        source_fingerprint: row.get(13)?,
        source_synced_at: row.get(14)?,
    })
}

fn request_collection_folder_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RequestCollectionFolder> {
    Ok(RequestCollectionFolder {
        id: row.get(0)?,
        collection_id: row.get(1)?,
        parent_id: row.get(2)?,
        name: row.get(3)?,
        depth: row.get(4)?,
        sort_order: row.get(5)?,
        draft_count: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn validate_capture_rule_input(input: &CaptureRuleInput) -> Result<(), String> {
    if input.name.trim().is_empty() || input.name.chars().count() > 120 {
        return Err("规则名称必须在 1 到 120 个字符之间".to_string());
    }
    if !matches!(input.stage.as_str(), "connection" | "request" | "response") {
        return Err("规则阶段必须是连接、请求或响应".to_string());
    }
    if !matches!(input.created_by.as_str(), "user" | "agent-draft") {
        return Err("规则创建来源无效".to_string());
    }
    if !(-10_000..=10_000).contains(&input.priority) {
        return Err("规则优先级超出范围".to_string());
    }
    let mut predicate_count = 0;
    validate_runtime_rule_matcher(&input.matcher, &input.stage, 0, &mut predicate_count)?;
    let kind = input
        .action
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    validate_runtime_rule_action(&input.stage, kind, &input.action)?;
    let encoded = serde_json::to_vec(&input.action).map_err(|error| error.to_string())?;
    if encoded.len() > 64 * 1024 {
        return Err("规则动作超过 64 KiB 上限".to_string());
    }
    Ok(())
}

fn validate_runtime_rule_matcher(
    matcher: &FilterExpression,
    stage: &str,
    depth: usize,
    predicates: &mut usize,
) -> Result<(), String> {
    if depth > 8 {
        return Err("规则匹配条件最多嵌套 8 层".to_string());
    }
    match matcher {
        FilterExpression::Group { operator, children } => {
            if !matches!(operator.as_str(), "and" | "or") || children.is_empty() {
                return Err("规则匹配组必须使用 and/or 且不能为空".to_string());
            }
            for child in children {
                validate_runtime_rule_matcher(child, stage, depth + 1, predicates)?;
            }
        }
        FilterExpression::Predicate {
            field,
            operator,
            value,
        } => {
            *predicates += 1;
            if *predicates > 100 {
                return Err("单条规则最多 100 个匹配条件".to_string());
            }
            let common = if stage == "connection" {
                matches!(field.as_str(), "scheme" | "host" | "source" | "protocol")
            } else {
                matches!(
                    field.as_str(),
                    "method"
                        | "scheme"
                        | "host"
                        | "path"
                        | "url"
                        | "source"
                        | "protocol"
                        | "requestHeader"
                )
            };
            let response_only =
                stage == "response" && matches!(field.as_str(), "status" | "responseHeader");
            if !common && !response_only {
                return Err(format!("{stage} 阶段不支持匹配字段: {field}"));
            }
            let text_operator = matches!(
                operator.as_str(),
                "exists"
                    | "equals"
                    | "not_equals"
                    | "contains"
                    | "not_contains"
                    | "starts_with"
                    | "ends_with"
                    | "wildcard"
                    | "regex"
            );
            let numeric_operator =
                field == "status" && matches!(operator.as_str(), "gt" | "gte" | "lt" | "lte");
            if !text_operator && !numeric_operator {
                return Err(format!("{stage} 阶段不支持匹配操作符: {operator}"));
            }
            if operator != "exists" && value.is_none() {
                return Err("规则匹配条件缺少比较值".to_string());
            }
            if operator == "regex" {
                let pattern = value.as_ref().and_then(Value::as_str).unwrap_or_default();
                if pattern.len() > 256 {
                    return Err("规则正则最长 256 字符".to_string());
                }
                Regex::new(pattern).map_err(|error| format!("规则正则无效: {error}"))?;
            }
        }
    }
    Ok(())
}

fn validate_runtime_rule_action(stage: &str, kind: &str, action: &Value) -> Result<(), String> {
    match kind {
        "rewrite" => {
            let operations = action
                .get("operations")
                .and_then(Value::as_array)
                .ok_or_else(|| "重写规则缺少 operations".to_string())?;
            if operations.is_empty() || operations.len() > 50 {
                return Err("单条规则必须包含 1 到 50 个重写操作".to_string());
            }
            for operation in operations {
                let target = operation
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let request_target = stage == "request"
                    && matches!(target, "request.header" | "query" | "request.body");
                let response_target = stage == "response"
                    && matches!(
                        target,
                        "response.header" | "response.status" | "response.body"
                    );
                if !request_target && !response_target {
                    return Err(format!("{stage} 阶段不支持重写目标: {target}"));
                }
                let op = operation.get("op").and_then(Value::as_str).unwrap_or("set");
                let valid_op = match target {
                    "request.header" | "query" | "response.header" => {
                        matches!(op, "set" | "delete")
                    }
                    "response.status" => op == "set",
                    "request.body" | "response.body" => matches!(op, "set" | "replace"),
                    _ => false,
                };
                if !valid_op {
                    return Err(format!("{target} 重写操作无效: {op}"));
                }
                let name = operation
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if matches!(target, "request.header" | "query" | "response.header")
                    && (name.is_empty() || name.len() > 1024)
                {
                    return Err("Header 或 Query 名称必须在 1 到 1024 字节之间".to_string());
                }
                if matches!(target, "request.header" | "response.header") {
                    reqwest::header::HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| format!("Header 名称无效: {name}"))?;
                    if is_runtime_managed_rule_header(stage, name) {
                        return Err(format!("{name} 由代理自动维护，规则不能直接改写"));
                    }
                }
                if target == "response.status" {
                    let status = operation.get("value").and_then(|value| {
                        value
                            .as_u64()
                            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
                    });
                    if !status.is_some_and(|status| (100..=599).contains(&status)) {
                        return Err("响应状态码必须在 100 到 599 之间".to_string());
                    }
                }
                if matches!(target, "request.body" | "response.body") && op == "replace" {
                    let pattern = operation
                        .get("pattern")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if pattern.is_empty() || pattern.len() > 256 {
                        return Err("正文正则必须在 1 到 256 字节之间".to_string());
                    }
                    Regex::new(pattern).map_err(|error| format!("正文正则无效: {error}"))?;
                }
            }
        }
        "redirect" => {
            if stage != "request" {
                return Err("请求转发仅支持请求阶段".to_string());
            }
            let template = action
                .get("targetTemplate")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if template.is_empty() || template.len() > 4096 {
                return Err("请求转发目标必须在 1 到 4096 字节之间".to_string());
            }
            validate_redirect_target_template(template)?;
            if let Some(exclude) = action.get("excludePattern") {
                let exclude = exclude
                    .as_str()
                    .ok_or_else(|| "转发排除 URL 必须是文本".to_string())?;
                if exclude.len() > 4096 {
                    return Err("转发排除 URL 不能超过 4096 字节".to_string());
                }
            }
            for key in [
                "preserveHost",
                "preserveCredentials",
                "allowInsecureDowngrade",
            ] {
                if action.get(key).is_some_and(|value| !value.is_boolean()) {
                    return Err(format!("请求转发选项 {key} 必须是布尔值"));
                }
            }
        }
        "delay" => {
            if stage != "request" {
                return Err("延迟与抖动仅支持请求阶段".to_string());
            }
            let latency = action.get("latencyMs").and_then(Value::as_i64);
            if !latency.is_some_and(|value| (0..=30_000).contains(&value)) {
                return Err("固定延迟必须在 0 到 30000 毫秒之间".to_string());
            }
            let jitter = action.get("jitterMs").and_then(Value::as_i64).unwrap_or(0);
            if !(0..=30_000).contains(&jitter)
                || latency.unwrap_or_default().saturating_add(jitter) > 30_000
            {
                return Err("延迟与抖动之和不能超过 30000 毫秒".to_string());
            }
        }
        "block" => {
            if stage != "request" {
                return Err("出站阻断仅支持请求阶段".to_string());
            }
            if action
                .get("direction")
                .and_then(Value::as_str)
                .unwrap_or("outbound")
                != "outbound"
            {
                return Err("请求阶段只支持 outbound 阻断".to_string());
            }
        }
        "throttle" => {
            if stage != "request" {
                return Err("受控弱网仅支持请求阶段".to_string());
            }
            let latency = action.get("latencyMs").and_then(Value::as_i64).unwrap_or(0);
            let jitter = action.get("jitterMs").and_then(Value::as_i64).unwrap_or(0);
            if latency < 0 || jitter < 0 || latency.saturating_add(jitter) > 30_000 {
                return Err("弱网延迟与抖动之和不能超过 30000 毫秒".to_string());
            }
            for key in ["uploadKbps", "downloadKbps"] {
                let rate = action.get(key).and_then(Value::as_i64).unwrap_or(0);
                if rate != 0 && !(8..=1_000_000).contains(&rate) {
                    return Err(format!("{key} 必须为 0 或 8 到 1000000 Kbps"));
                }
            }
            let loss = action
                .get("packetLossPercent")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if !(0.0..=100.0).contains(&loss) {
                return Err("丢包率必须在 0 到 100 之间".to_string());
            }
            if latency == 0
                && jitter == 0
                && action
                    .get("uploadKbps")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    == 0
                && action
                    .get("downloadKbps")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    == 0
                && loss == 0.0
            {
                return Err("弱网规则至少需要一项有效限制".to_string());
            }
        }
        "breakpoint" => {
            if stage != "request" && stage != "response" {
                return Err("人工断点仅支持请求或响应阶段".to_string());
            }
            let timeout_ms = action
                .get("timeoutMs")
                .and_then(Value::as_i64)
                .unwrap_or(120_000);
            if !(5_000..=300_000).contains(&timeout_ms) {
                return Err("人工断点等待时间必须在 5 到 300 秒之间".to_string());
            }
            if !matches!(
                action
                    .get("onTimeout")
                    .and_then(Value::as_str)
                    .unwrap_or("continue"),
                "continue" | "abort"
            ) {
                return Err("人工断点超时策略必须是 continue 或 abort".to_string());
            }
        }
        "mirror" => {
            if stage != "connection" {
                return Err("镜像只支持连接阶段".to_string());
            }
            validate_mirror_action(action)?;
        }
        _ => {
            return Err(
                "当前版本只支持镜像、人工断点、请求/响应重写、请求转发、延迟、受控弱网和出站阻断"
                    .to_string(),
            )
        }
    }
    Ok(())
}

fn validate_redirect_target_template(template: &str) -> Result<(), String> {
    let template = template.trim();
    if template.contains('\\') {
        return Err("请求转发目标不能包含反斜杠".to_string());
    }
    let rendered = template
        .replace("{{scheme}}", "https")
        .replace("{{host}}", "api.example.test")
        .replace("{{port}}", "443")
        .replace("{{path}}", "/v1/items")
        .replace("{{query}}", "page=1");
    let target = if rendered.starts_with('/') {
        url::Url::parse("https://api.example.test/").and_then(|base| base.join(&rendered))
    } else {
        url::Url::parse(&rendered)
    }
    .map_err(|error| format!("请求转发目标无效: {error}"))?;
    if !matches!(target.scheme(), "http" | "https") || target.host_str().is_none() {
        return Err("请求转发目标只支持包含有效 Host 的 HTTP(S) URL".to_string());
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err("请求转发目标不能包含用户名或密码".to_string());
    }
    if target.fragment().is_some() {
        return Err("请求转发目标不能包含 URL 片段".to_string());
    }
    Ok(())
}

fn is_runtime_managed_rule_header(stage: &str, name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    matches!(
        name.as_str(),
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || (stage == "request" && name == "host")
        || (stage == "response" && name == "content-encoding")
}

fn capture_rule_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CaptureRule> {
    let matcher_json: String = row.get(5)?;
    let matcher = serde_json::from_str(&matcher_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(CaptureRule {
        id: row.get(0)?,
        name: row.get(1)?,
        enabled: row.get(2)?,
        priority: row.get(3)?,
        stage: row.get(4)?,
        matcher,
        action: from_json(row.get::<_, String>(6)?),
        created_by: row.get(7)?,
        revision: row.get(8)?,
        hit_count: row.get(9)?,
        last_error: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

const BUNDLE_REQUEST_SELECT: &str =
    "SELECT id, sequence, source, source_instance_id, started_at, method, scheme,
            host, port, path, query, status, resource_type, size_bytes, duration_ms,
            protocol, tls_version, risk_level, request_headers_json,
            response_headers_json, request_body, response_body, response_body_meta_json,
            crypto_snippets_json, hook_json, tls_fingerprint_json, replayed_from_request_id
     FROM requests WHERE session_id = ?1 ORDER BY sequence ASC";

fn bundle_request_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BundleRequest> {
    Ok(BundleRequest {
        id: row.get(0)?,
        sequence: row.get(1)?,
        source: row.get(2)?,
        source_instance_id: row.get(3)?,
        started_at: row.get(4)?,
        method: row.get(5)?,
        scheme: row.get(6)?,
        host: row.get(7)?,
        port: row.get(8)?,
        path: row.get(9)?,
        query: row.get(10)?,
        status: row.get(11)?,
        resource_type: row.get(12)?,
        size_bytes: row.get(13)?,
        duration_ms: row.get(14)?,
        protocol: row.get(15)?,
        tls_version: row
            .get::<_, Option<String>>(16)?
            .unwrap_or_else(|| "TLS".to_string()),
        risk_level: row.get(17)?,
        request_headers: from_json(row.get::<_, String>(18)?),
        response_headers: from_json(row.get::<_, String>(19)?),
        request_body: row.get(20)?,
        response_body: row.get::<_, Option<String>>(21)?.unwrap_or_default(),
        response_body_metadata: from_json(
            row.get::<_, String>(22)
                .unwrap_or_else(|_| "{}".to_string()),
        ),
        crypto_snippets: from_json(
            row.get::<_, String>(23)
                .unwrap_or_else(|_| "[]".to_string()),
        ),
        hook: row
            .get::<_, Option<String>>(24)?
            .and_then(|value| serde_json::from_str(&value).ok()),
        tls_fingerprint: row
            .get::<_, Option<String>>(25)?
            .and_then(|value| serde_json::from_str(&value).ok()),
        replayed_from_request_id: row.get(26)?,
    })
}

fn remap_event_payload(
    mut payload: serde_json::Value,
    request_ids: &HashMap<String, String>,
) -> serde_json::Value {
    if let Some(object) = payload.as_object_mut() {
        if let Some(old_id) = object.get("requestId").and_then(|value| value.as_str()) {
            if let Some(new_id) = request_ids.get(old_id) {
                object.insert(
                    "requestId".to_string(),
                    serde_json::Value::String(new_id.clone()),
                );
            }
        }
    }
    payload
}

fn apply_migrations(connection: &Connection) -> Result<(), String> {
    let has_fingerprint_column = {
        let mut statement = connection
            .prepare("PRAGMA table_info(requests)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns
            .iter()
            .any(|column| column == "tls_fingerprint_json")
    };
    if !has_fingerprint_column {
        connection
            .execute(
                "ALTER TABLE requests ADD COLUMN tls_fingerprint_json TEXT",
                [],
            )
            .map_err(|error| format!("数据库迁移 v2 失败: {error}"))?;
    }
    connection
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (2, unixepoch('now') * 1000)",
            [],
        )
        .map_err(|error| format!("记录数据库迁移 v2 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS analysis_reports (
               id TEXT PRIMARY KEY,
               session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
               mode TEXT NOT NULL,
               status TEXT NOT NULL CHECK (status IN ('filtering', 'analyzing', 'complete', 'failed')),
               request_count INTEGER NOT NULL,
               key_request_count INTEGER NOT NULL DEFAULT 0,
               selected_request_ids_json TEXT NOT NULL DEFAULT '[]',
               content TEXT NOT NULL DEFAULT '',
               provider TEXT NOT NULL,
               model TEXT NOT NULL,
               error TEXT,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS analysis_messages (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               analysis_id TEXT NOT NULL REFERENCES analysis_reports(id) ON DELETE CASCADE,
               role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
               content TEXT NOT NULL,
               created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS ai_request_logs (
               id TEXT PRIMARY KEY,
               analysis_id TEXT NOT NULL REFERENCES analysis_reports(id) ON DELETE CASCADE,
               request_kind TEXT NOT NULL,
               provider TEXT NOT NULL,
               model TEXT NOT NULL,
               endpoint TEXT NOT NULL,
               status TEXT NOT NULL,
               error TEXT,
               started_at INTEGER NOT NULL,
               finished_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_analysis_reports_session_updated
               ON analysis_reports(session_id, updated_at DESC);
             CREATE INDEX IF NOT EXISTS idx_analysis_messages_report
               ON analysis_messages(analysis_id, id);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (3, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v3 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_capture_events_session_phase_sequence
               ON capture_events(session_id, phase, sequence DESC);
             CREATE INDEX IF NOT EXISTS idx_capture_events_request_phase
               ON capture_events(request_id, phase, sequence);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (4, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v4 失败: {error}"))?;
    let has_response_body_meta_column = {
        let mut statement = connection
            .prepare("PRAGMA table_info(requests)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns
            .iter()
            .any(|column| column == "response_body_meta_json")
    };
    if !has_response_body_meta_column {
        connection
            .execute(
                "ALTER TABLE requests ADD COLUMN response_body_meta_json TEXT NOT NULL DEFAULT '{}'",
                [],
            )
            .map_err(|error| format!("数据库迁移 v5 失败: {error}"))?;
    }
    connection
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (5, unixepoch('now') * 1000)",
            [],
        )
        .map_err(|error| format!("记录数据库迁移 v5 失败: {error}"))?;
    let has_crypto_snippets_column = {
        let mut statement = connection
            .prepare("PRAGMA table_info(requests)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns
            .iter()
            .any(|column| column == "crypto_snippets_json")
    };
    if !has_crypto_snippets_column {
        connection
            .execute(
                "ALTER TABLE requests ADD COLUMN crypto_snippets_json TEXT NOT NULL DEFAULT '[]'",
                [],
            )
            .map_err(|error| format!("数据库迁移 v6 失败: {error}"))?;
    }
    connection
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (6, unixepoch('now') * 1000)",
            [],
        )
        .map_err(|error| format!("记录数据库迁移 v6 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS mcp_client_logs (
               id TEXT PRIMARY KEY,
               server_id TEXT NOT NULL,
               tool_name TEXT NOT NULL,
               status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed')),
               error TEXT,
               started_at INTEGER NOT NULL,
               finished_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_mcp_client_logs_server_started
               ON mcp_client_logs(server_id, started_at DESC);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (7, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v7 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS analysis_activities (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               analysis_id TEXT NOT NULL REFERENCES analysis_reports(id) ON DELETE CASCADE,
               phase TEXT NOT NULL,
               message TEXT NOT NULL DEFAULT '',
               created_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_analysis_activities_report
               ON analysis_activities(analysis_id, id);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (8, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v8 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS skill_runs (
               id TEXT PRIMARY KEY,
               analysis_id TEXT NOT NULL REFERENCES analysis_reports(id) ON DELETE CASCADE,
               skill_id TEXT NOT NULL,
               skill_name TEXT NOT NULL,
               skill_version TEXT NOT NULL,
               mode TEXT NOT NULL,
               status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed')),
               permissions_json TEXT NOT NULL DEFAULT '[]',
               planned_tools_json TEXT NOT NULL DEFAULT '[]',
               input_summary_json TEXT NOT NULL DEFAULT '{}',
               output_summary_json TEXT NOT NULL DEFAULT '{}',
               error TEXT,
               started_at INTEGER NOT NULL,
               finished_at INTEGER,
               UNIQUE(analysis_id, skill_id)
             );
             CREATE TABLE IF NOT EXISTS skill_tool_calls (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               analysis_id TEXT NOT NULL REFERENCES analysis_reports(id) ON DELETE CASCADE,
               tool_name TEXT NOT NULL,
               status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed')),
               started_at INTEGER NOT NULL,
               finished_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_skill_runs_analysis
               ON skill_runs(analysis_id, started_at);
             CREATE INDEX IF NOT EXISTS idx_skill_tool_calls_analysis
               ON skill_tool_calls(analysis_id, id);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (9, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v9 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_requests_session_source_sequence
               ON requests(session_id, source, sequence);
             CREATE INDEX IF NOT EXISTS idx_requests_session_type_sequence
               ON requests(session_id, resource_type, sequence);
             CREATE INDEX IF NOT EXISTS idx_requests_session_protocol_sequence
               ON requests(session_id, protocol, sequence);
             CREATE INDEX IF NOT EXISTS idx_requests_session_risk_sequence
               ON requests(session_id, risk_level, sequence);
             CREATE INDEX IF NOT EXISTS idx_requests_session_started
               ON requests(session_id, started_at, id);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (10, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v10 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS saved_request_views (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
               filter_json TEXT NOT NULL DEFAULT 'null',
               sort_json TEXT NOT NULL DEFAULT '[]',
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_saved_request_views_session_updated
               ON saved_request_views(session_id, updated_at DESC);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (11, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v11 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS request_annotations (
               request_id TEXT PRIMARY KEY REFERENCES requests(id) ON DELETE CASCADE,
               bookmarked INTEGER NOT NULL DEFAULT 0,
               color TEXT,
               struck_through INTEGER NOT NULL DEFAULT 0,
               note TEXT NOT NULL DEFAULT '',
               tags_json TEXT NOT NULL DEFAULT '[]',
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_request_annotations_bookmarked_updated
               ON request_annotations(bookmarked, updated_at DESC);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (12, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v12 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS replay_batches (
               id TEXT PRIMARY KEY,
               session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
               status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'complete', 'cancelled', 'failed')),
               settings_json TEXT NOT NULL,
               total INTEGER NOT NULL,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS replay_batch_items (
               id TEXT PRIMARY KEY,
               batch_id TEXT NOT NULL REFERENCES replay_batches(id) ON DELETE CASCADE,
               source_request_id TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
               run_index INTEGER NOT NULL,
               status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancelled')),
               captured_request_id TEXT,
               status_code INTEGER,
               duration_ms INTEGER,
               error TEXT,
               started_at INTEGER,
               finished_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS request_drafts (
               id TEXT PRIMARY KEY,
               session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
               source_request_id TEXT REFERENCES requests(id) ON DELETE SET NULL,
               name TEXT NOT NULL,
               method TEXT NOT NULL,
               url TEXT NOT NULL,
               headers_json TEXT NOT NULL DEFAULT '[]',
               body TEXT NOT NULL DEFAULT '',
               body_type TEXT NOT NULL DEFAULT 'raw',
               auth_json TEXT NOT NULL DEFAULT '{}',
               settings_json TEXT NOT NULL DEFAULT '{}',
               environment_id TEXT,
               spec_operation_key TEXT,
               spec_fingerprint TEXT,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS request_runs (
               id TEXT PRIMARY KEY,
               draft_id TEXT NOT NULL REFERENCES request_drafts(id) ON DELETE CASCADE,
               status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed', 'cancelled')),
               request_snapshot_json TEXT NOT NULL,
               response_snapshot_json TEXT NOT NULL DEFAULT '{}',
               error TEXT,
               started_at INTEGER NOT NULL,
               finished_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS environments (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               kind TEXT NOT NULL CHECK (kind IN ('global', 'named')),
               active INTEGER NOT NULL DEFAULT 0,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_environments_one_global
               ON environments(kind) WHERE kind = 'global';
             CREATE UNIQUE INDEX IF NOT EXISTS idx_environments_one_active_named
               ON environments(active) WHERE kind = 'named' AND active = 1;
             CREATE TABLE IF NOT EXISTS environment_variables (
               id TEXT PRIMARY KEY,
               environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
               name TEXT NOT NULL,
               value TEXT,
               encrypted_value TEXT,
               secret INTEGER NOT NULL DEFAULT 0,
               enabled INTEGER NOT NULL DEFAULT 1,
               updated_at INTEGER NOT NULL,
               UNIQUE(environment_id, name)
             );
             CREATE INDEX IF NOT EXISTS idx_replay_batches_session_created
               ON replay_batches(session_id, created_at DESC);
             CREATE INDEX IF NOT EXISTS idx_replay_items_batch_status
               ON replay_batch_items(batch_id, status, run_index);
             CREATE INDEX IF NOT EXISTS idx_request_drafts_updated
               ON request_drafts(updated_at DESC);
             CREATE INDEX IF NOT EXISTS idx_request_runs_draft_started
               ON request_runs(draft_id, started_at DESC);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (13, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v13 失败: {error}"))?;
    let has_replayed_from_column = {
        let mut statement = connection
            .prepare("PRAGMA table_info(requests)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns
            .iter()
            .any(|column| column == "replayed_from_request_id")
    };
    if !has_replayed_from_column {
        connection
            .execute(
                "ALTER TABLE requests ADD COLUMN replayed_from_request_id TEXT",
                [],
            )
            .map_err(|error| format!("数据库迁移 v14 失败: {error}"))?;
    }
    connection
        .execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_requests_replayed_from
               ON requests(replayed_from_request_id);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (14, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("记录数据库迁移 v14 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS capture_rules (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               enabled INTEGER NOT NULL DEFAULT 0,
               priority INTEGER NOT NULL,
               stage TEXT NOT NULL CHECK (stage IN ('connection', 'request', 'response')),
               matcher_json TEXT NOT NULL,
               action_json TEXT NOT NULL,
               created_by TEXT NOT NULL CHECK (created_by IN ('user', 'agent-draft')),
               revision INTEGER NOT NULL DEFAULT 1,
               hit_count INTEGER NOT NULL DEFAULT 0,
               last_error TEXT,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS capture_rule_revisions (
               id TEXT PRIMARY KEY,
               rule_id TEXT NOT NULL REFERENCES capture_rules(id) ON DELETE CASCADE,
               revision INTEGER NOT NULL,
               snapshot_json TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               UNIQUE(rule_id, revision)
             );
             CREATE TABLE IF NOT EXISTS capture_rule_runs (
               id TEXT PRIMARY KEY,
               request_id TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
               rule_id TEXT NOT NULL REFERENCES capture_rules(id) ON DELETE CASCADE,
               rule_name TEXT NOT NULL,
               revision INTEGER NOT NULL,
               stage TEXT NOT NULL,
               result TEXT NOT NULL,
               diff_summary_json TEXT NOT NULL DEFAULT '{}',
               duration_ms INTEGER NOT NULL DEFAULT 0,
               error TEXT,
               created_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_capture_rules_order
               ON capture_rules(enabled DESC, priority ASC, updated_at DESC);
             CREATE INDEX IF NOT EXISTS idx_capture_rule_runs_request
               ON capture_rule_runs(request_id, created_at ASC);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (15, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v15 失败: {error}"))?;
    let has_saved_view_columns = {
        let mut statement = connection
            .prepare("PRAGMA table_info(saved_request_views)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns.iter().any(|column| column == "columns_json")
    };
    if !has_saved_view_columns {
        connection
            .execute(
                "ALTER TABLE saved_request_views ADD COLUMN columns_json TEXT NOT NULL DEFAULT '{}'",
                [],
            )
            .map_err(|error| format!("数据库迁移 v16 失败: {error}"))?;
    }
    connection
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (16, unixepoch('now') * 1000)",
            [],
        )
        .map_err(|error| format!("记录数据库迁移 v16 失败: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS request_collections (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               description TEXT NOT NULL DEFAULT '',
               source_format TEXT,
               source_path TEXT,
               source_fingerprint TEXT,
               source_synced_at INTEGER,
               sort_order INTEGER NOT NULL DEFAULT 0,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_request_collections_name
               ON request_collections(name COLLATE NOCASE);
             CREATE TABLE IF NOT EXISTS request_collection_folders (
               id TEXT PRIMARY KEY,
               collection_id TEXT NOT NULL REFERENCES request_collections(id) ON DELETE CASCADE,
               parent_id TEXT REFERENCES request_collection_folders(id) ON DELETE CASCADE,
               name TEXT NOT NULL,
               depth INTEGER NOT NULL CHECK (depth BETWEEN 1 AND 4),
               sort_order INTEGER NOT NULL DEFAULT 0,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_request_collection_folder_name
               ON request_collection_folders(collection_id, COALESCE(parent_id, ''), name COLLATE NOCASE);
             CREATE INDEX IF NOT EXISTS idx_request_collection_folders_tree
               ON request_collection_folders(collection_id, parent_id, sort_order);",
        )
        .map_err(|error| format!("数据库迁移 v17 创建集合表失败: {error}"))?;
    let request_draft_columns = {
        let mut statement = connection
            .prepare("PRAGMA table_info(request_drafts)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns
    };
    if !request_draft_columns
        .iter()
        .any(|column| column == "collection_id")
    {
        connection
            .execute(
                "ALTER TABLE request_drafts ADD COLUMN collection_id TEXT REFERENCES request_collections(id) ON DELETE SET NULL",
                [],
            )
            .map_err(|error| format!("数据库迁移 v17 增加 collection_id 失败: {error}"))?;
    }
    if !request_draft_columns
        .iter()
        .any(|column| column == "folder_id")
    {
        connection
            .execute(
                "ALTER TABLE request_drafts ADD COLUMN folder_id TEXT REFERENCES request_collection_folders(id) ON DELETE SET NULL",
                [],
            )
            .map_err(|error| format!("数据库迁移 v17 增加 folder_id 失败: {error}"))?;
    }
    connection
        .execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_request_drafts_collection_updated
               ON request_drafts(collection_id, updated_at DESC);
             CREATE INDEX IF NOT EXISTS idx_request_drafts_folder_updated
               ON request_drafts(folder_id, updated_at DESC);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (17, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("记录数据库迁移 v17 失败: {error}"))?;
    let request_collection_columns = {
        let mut statement = connection
            .prepare("PRAGMA table_info(request_collections)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns
    };
    if !request_collection_columns
        .iter()
        .any(|column| column == "default_headers_json")
    {
        connection
            .execute(
                "ALTER TABLE request_collections ADD COLUMN default_headers_json TEXT NOT NULL DEFAULT '[]'",
                [],
            )
            .map_err(|error| format!("数据库迁移 v18 增加 default_headers_json 失败: {error}"))?;
    }
    if !request_collection_columns
        .iter()
        .any(|column| column == "default_auth_json")
    {
        connection
            .execute(
                "ALTER TABLE request_collections ADD COLUMN default_auth_json TEXT NOT NULL DEFAULT '{\"kind\":\"none\"}'",
                [],
            )
            .map_err(|error| format!("数据库迁移 v18 增加 default_auth_json 失败: {error}"))?;
    }
    if !request_collection_columns
        .iter()
        .any(|column| column == "default_environment_id")
    {
        connection
            .execute(
                "ALTER TABLE request_collections ADD COLUMN default_environment_id TEXT REFERENCES environments(id) ON DELETE SET NULL",
                [],
            )
            .map_err(|error| format!("数据库迁移 v18 增加 default_environment_id 失败: {error}"))?;
    }
    connection
        .execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_request_collections_default_environment
               ON request_collections(default_environment_id);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (18, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("记录数据库迁移 v18 失败: {error}"))?;
    let has_request_draft_tags = {
        let mut statement = connection
            .prepare("PRAGMA table_info(request_drafts)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns.iter().any(|column| column == "tags_json")
    };
    if !has_request_draft_tags {
        connection
            .execute(
                "ALTER TABLE request_drafts ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'",
                [],
            )
            .map_err(|error| format!("数据库迁移 v19 增加 tags_json 失败: {error}"))?;
    }
    connection
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
             VALUES (19, unixepoch('now') * 1000)",
            [],
        )
        .map_err(|error| format!("记录数据库迁移 v19 失败: {error}"))?;
    let request_collection_source_columns = {
        let mut statement = connection
            .prepare("PRAGMA table_info(request_collections)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns
    };
    for (column, sql) in [
        (
            "source_format",
            "ALTER TABLE request_collections ADD COLUMN source_format TEXT",
        ),
        (
            "source_path",
            "ALTER TABLE request_collections ADD COLUMN source_path TEXT",
        ),
        (
            "source_fingerprint",
            "ALTER TABLE request_collections ADD COLUMN source_fingerprint TEXT",
        ),
        (
            "source_synced_at",
            "ALTER TABLE request_collections ADD COLUMN source_synced_at INTEGER",
        ),
    ] {
        if !request_collection_source_columns
            .iter()
            .any(|candidate| candidate == column)
        {
            connection
                .execute(sql, [])
                .map_err(|error| format!("数据库迁移 v20 增加 {column} 失败: {error}"))?;
        }
    }
    let request_draft_spec_columns = {
        let mut statement = connection
            .prepare("PRAGMA table_info(request_drafts)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        columns
    };
    for (column, sql) in [
        (
            "spec_operation_key",
            "ALTER TABLE request_drafts ADD COLUMN spec_operation_key TEXT",
        ),
        (
            "spec_fingerprint",
            "ALTER TABLE request_drafts ADD COLUMN spec_fingerprint TEXT",
        ),
    ] {
        if !request_draft_spec_columns
            .iter()
            .any(|candidate| candidate == column)
        {
            connection
                .execute(sql, [])
                .map_err(|error| format!("数据库迁移 v20 增加 {column} 失败: {error}"))?;
        }
    }
    connection
        .execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_request_drafts_spec_operation
               ON request_drafts(collection_id, spec_operation_key)
               WHERE collection_id IS NOT NULL AND spec_operation_key IS NOT NULL;
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (20, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("记录数据库迁移 v20 失败: {error}"))?;

    let capture_events_supports_sse = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'capture_events'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map(|sql| sql.contains("'sse'"))
        .unwrap_or(false);
    if !capture_events_supports_sse {
        connection
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .map_err(|error| format!("数据库迁移 v21 准备失败: {error}"))?;
        let migration = connection.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE capture_events RENAME TO capture_events_v20;
             CREATE TABLE capture_events (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
               sequence INTEGER NOT NULL,
               timestamp INTEGER NOT NULL,
               source TEXT NOT NULL,
               source_instance_id TEXT NOT NULL,
               request_id TEXT NOT NULL,
               phase TEXT NOT NULL CHECK (phase IN ('request', 'response', 'websocket', 'sse', 'hook', 'interaction', 'storage', 'connection')),
               payload_json TEXT NOT NULL,
               UNIQUE(session_id, sequence)
             );
             INSERT INTO capture_events(
               id, session_id, sequence, timestamp, source, source_instance_id,
               request_id, phase, payload_json
             )
             SELECT id, session_id, sequence, timestamp, source, source_instance_id,
                    request_id, phase, payload_json
               FROM capture_events_v20;
             DROP TABLE capture_events_v20;
             CREATE INDEX idx_capture_events_session_sequence
               ON capture_events(session_id, sequence);
             CREATE INDEX idx_capture_events_session_phase_sequence
               ON capture_events(session_id, phase, sequence DESC);
             CREATE INDEX idx_capture_events_request_phase
               ON capture_events(request_id, phase, sequence);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (21, unixepoch('now') * 1000);
             COMMIT;",
        );
        let foreign_keys = connection.execute_batch("PRAGMA foreign_keys = ON;");
        migration.map_err(|error| format!("数据库迁移 v21 失败: {error}"))?;
        foreign_keys.map_err(|error| format!("数据库迁移 v21 恢复外键失败: {error}"))?;
    } else {
        connection
            .execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                 VALUES (21, unixepoch('now') * 1000)",
                [],
            )
            .map_err(|error| format!("记录数据库迁移 v21 失败: {error}"))?;
    }
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS analysis_graph_runs (
               analysis_id TEXT PRIMARY KEY REFERENCES analysis_reports(id) ON DELETE CASCADE,
               status TEXT NOT NULL,
               current_node_id TEXT,
               run_json TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_analysis_graph_runs_status_updated
               ON analysis_graph_runs(status, updated_at DESC);
             INSERT OR IGNORE INTO schema_migrations(version, applied_at)
               VALUES (22, unixepoch('now') * 1000);",
        )
        .map_err(|error| format!("数据库迁移 v22 失败: {error}"))?;
    Ok(())
}

fn register_sql_functions(connection: &Connection) -> Result<(), String> {
    let cache = Mutex::new(None::<(String, regex::Regex)>);
    connection
        .create_scalar_function(
            "shownet_regex",
            2,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            move |context| {
                let pattern = context.get::<String>(0)?;
                let text = context.get::<String>(1)?;
                let mut cache = cache.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
                let needs_compile = cache
                    .as_ref()
                    .map(|(cached, _)| cached != &pattern)
                    .unwrap_or(true);
                if needs_compile {
                    let compiled = regex::Regex::new(&pattern)
                        .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
                    *cache = Some((pattern, compiled));
                }
                Ok(cache
                    .as_ref()
                    .is_some_and(|(_, compiled)| compiled.is_match(&text)))
            },
        )
        .map_err(|error| format!("注册正则筛选函数失败: {error}"))
}

const REQUEST_LIST_SELECT: &str = "SELECT r.id, r.sequence, r.started_at,
            CASE WHEN r.resource_type = 'sse' AND COALESCE(json_extract(r.response_body_meta_json, '$.complete'), 0) = 0 THEN NULL
                 WHEN r.status = 0 AND r.duration_ms = 0 THEN NULL
                 ELSE r.started_at + r.duration_ms END,
            CASE WHEN UPPER(r.method) = 'CONNECT' THEN 'tunnel'
                 WHEN r.resource_type = 'sse' AND COALESCE(json_extract(r.response_body_meta_json, '$.complete'), 0) = 0 THEN 'streaming'
                 WHEN r.status = 0 AND r.duration_ms = 0 THEN 'pending'
                 WHEN r.status = 0 THEN 'failed'
                 ELSE 'complete' END,
            r.method, r.scheme, r.host, r.port, r.path, r.query,
            NULLIF(r.status, 0), r.resource_type, r.source, r.source_instance_id,
            r.protocol, r.size_bytes,
            CASE WHEN r.status = 0 AND r.duration_ms = 0 THEN NULL ELSE r.duration_ms END,
            r.risk_level, CASE WHEN r.hook_json IS NULL THEN 0 ELSE 1 END,
            COALESCE(json_array_length(r.crypto_snippets_json), 0),
            CASE WHEN COALESCE(json_extract(r.tls_fingerprint_json, '$.captureMode'), '') != ''
                 THEN CASE WHEN json_extract(r.tls_fingerprint_json, '$.captureMode') = 'mitm' THEN 1 ELSE 0 END
                 WHEN UPPER(r.method) != 'CONNECT' AND r.scheme = 'https' AND COALESCE(r.tls_version, '') != ''
                 THEN 1 ELSE 0 END,
            r.tls_version,
            a.bookmarked, a.color, a.struck_through,
            CASE WHEN a.note = '' THEN NULL ELSE substr(a.note, 1, 120) END,
            a.tags_json
       FROM requests r
       LEFT JOIN request_annotations a ON a.request_id = r.id";

fn request_list_item_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RequestListItem> {
    Ok(RequestListItem {
        id: row.get(0)?,
        order: row.get(1)?,
        started_at: row.get(2)?,
        completed_at: row.get(3)?,
        state: row.get(4)?,
        method: row.get(5)?,
        scheme: row.get(6)?,
        host: row.get(7)?,
        port: row.get(8)?,
        path: row.get(9)?,
        query: row.get(10)?,
        status: row.get(11)?,
        resource_type: row.get(12)?,
        source: row.get(13)?,
        source_instance_id: row.get(14)?,
        protocol: row.get(15)?,
        size_bytes: row.get::<_, i64>(16)?.max(0),
        duration_ms: row.get(17)?,
        risk: row.get(18)?,
        has_hook: row.get::<_, i64>(19)? != 0,
        crypto_snippet_count: row.get::<_, i64>(20)?.max(0),
        tls_intercepted: row.get::<_, i64>(21)? != 0,
        tls_version: row.get(22)?,
        annotation: row
            .get::<_, Option<i64>>(23)?
            .map(|bookmarked| RequestAnnotationSummary {
                bookmarked: bookmarked != 0,
                color: row.get(24).unwrap_or_default(),
                struck_through: row.get::<_, i64>(25).unwrap_or_default() != 0,
                note_preview: row.get(26).unwrap_or_default(),
                tags: row
                    .get::<_, Option<String>>(27)
                    .ok()
                    .flatten()
                    .map(from_json)
                    .unwrap_or_default(),
            }),
    })
}

fn request_annotation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RequestAnnotation> {
    Ok(RequestAnnotation {
        request_id: row.get(0)?,
        bookmarked: row.get::<_, i64>(1)? != 0,
        color: row.get(2)?,
        struck_through: row.get::<_, i64>(3)? != 0,
        note: row.get(4)?,
        tags: from_json(row.get::<_, String>(5)?),
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

fn encode_request_cursor(offset: i64) -> String {
    format!("o:{}", offset.max(0))
}

fn decode_request_cursor(cursor: Option<&str>) -> Result<i64, String> {
    let Some(cursor) = cursor.filter(|value| !value.is_empty()) else {
        return Ok(0);
    };
    cursor
        .strip_prefix("o:")
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 0)
        .ok_or_else(|| "请求列表游标无效".to_string())
}

fn compile_request_list_query(
    session_id: &str,
    filter: Option<&FilterExpression>,
    sort: &[crate::models::RequestSort],
) -> Result<(String, String, Vec<SqlValue>), String> {
    if session_id.trim().is_empty() {
        return Err("sessionId 不能为空".to_string());
    }
    let mut filter_params = vec![SqlValue::Text(session_id.to_string())];
    let mut predicate_count = 0usize;
    let filter_clause = filter
        .map(|expression| {
            compile_request_filter(expression, &mut filter_params, 0, &mut predicate_count)
        })
        .transpose()?
        .filter(|clause| !clause.is_empty());
    let where_clause = match filter_clause {
        Some(filter) => format!("r.session_id = ? AND ({filter})"),
        None => "r.session_id = ?".to_string(),
    };
    Ok((where_clause, compile_request_sort(sort)?, filter_params))
}

fn compile_request_sort(sort: &[crate::models::RequestSort]) -> Result<String, String> {
    if sort.len() > 3 {
        return Err("请求列表最多支持 3 个排序字段".to_string());
    }
    let mut clauses = Vec::new();
    for item in sort {
        let expression = request_sort_expression(&item.field)?;
        let direction = match item.direction.to_ascii_lowercase().as_str() {
            "asc" => "ASC",
            "desc" => "DESC",
            _ => return Err(format!("不支持的排序方向: {}", item.direction)),
        };
        clauses.push(format!("{expression} {direction}"));
    }
    if clauses.is_empty() {
        clauses.push("r.sequence ASC".to_string());
    }
    clauses.push("r.id ASC".to_string());
    Ok(clauses.join(", "))
}

fn request_sort_expression(field: &str) -> Result<&'static str, String> {
    match field {
        "order" => Ok("r.sequence"),
        "startedAt" => Ok("r.started_at"),
        "state" => Ok("CASE WHEN UPPER(r.method) = 'CONNECT' THEN 4 WHEN r.resource_type = 'sse' AND COALESCE(json_extract(r.response_body_meta_json, '$.complete'), 0) = 0 THEN 1 WHEN r.status = 0 AND r.duration_ms = 0 THEN 0 WHEN r.status = 0 THEN 3 ELSE 2 END"),
        "method" => Ok("r.method COLLATE NOCASE"),
        "scheme" => Ok("r.scheme COLLATE NOCASE"),
        "host" => Ok("r.host COLLATE NOCASE"),
        "path" | "url" => Ok("r.path COLLATE NOCASE"),
        "status" => Ok("r.status"),
        "type" => Ok("r.resource_type COLLATE NOCASE"),
        "source" => Ok("r.source COLLATE NOCASE"),
        "sourceInstanceId" => Ok("r.source_instance_id COLLATE NOCASE"),
        "protocol" => Ok("r.protocol COLLATE NOCASE"),
        "sizeBytes" => Ok("r.size_bytes"),
        "durationMs" => Ok("r.duration_ms"),
        "risk" => Ok("CASE r.risk_level WHEN 'critical' THEN 3 WHEN 'warning' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"),
        "hasHook" => Ok("r.hook_json IS NOT NULL"),
        "cryptoSnippetCount" => Ok("COALESCE(json_array_length(r.crypto_snippets_json), 0)"),
        "tlsIntercepted" => Ok("CASE WHEN COALESCE(json_extract(r.tls_fingerprint_json, '$.captureMode'), '') != '' THEN CASE WHEN json_extract(r.tls_fingerprint_json, '$.captureMode') = 'mitm' THEN 1 ELSE 0 END WHEN UPPER(r.method) != 'CONNECT' AND r.scheme = 'https' AND COALESCE(r.tls_version, '') != '' THEN 1 ELSE 0 END"),
        _ => Err(format!("不支持的请求排序字段: {field}")),
    }
}

fn compile_request_filter(
    expression: &FilterExpression,
    params: &mut Vec<SqlValue>,
    depth: usize,
    predicate_count: &mut usize,
) -> Result<String, String> {
    if depth > 12 {
        return Err("请求筛选嵌套过深".to_string());
    }
    match expression {
        FilterExpression::Group { operator, children } => {
            let joiner = match operator.to_ascii_lowercase().as_str() {
                "and" => " AND ",
                "or" => " OR ",
                _ => return Err(format!("不支持的筛选组关系: {operator}")),
            };
            if children.is_empty() {
                return Ok(if joiner == " AND " { "1 = 1" } else { "1 = 0" }.to_string());
            }
            let clauses = children
                .iter()
                .map(|child| compile_request_filter(child, params, depth + 1, predicate_count))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("({})", clauses.join(joiner)))
        }
        FilterExpression::Predicate {
            field,
            operator,
            value,
        } => {
            *predicate_count += 1;
            if *predicate_count > 64 {
                return Err("请求筛选条件不能超过 64 个".to_string());
            }
            let field_sql = request_filter_expression(field)?;
            compile_request_predicate(field_sql, operator, value.as_ref(), params)
        }
    }
}

fn request_filter_expression(field: &str) -> Result<&'static str, String> {
    match field {
        "order" => Ok("r.sequence"),
        "startedAt" => Ok("r.started_at"),
        "state" => Ok("CASE WHEN UPPER(r.method) = 'CONNECT' THEN 'tunnel' WHEN r.resource_type = 'sse' AND COALESCE(json_extract(r.response_body_meta_json, '$.complete'), 0) = 0 THEN 'streaming' WHEN r.status = 0 AND r.duration_ms = 0 THEN 'pending' WHEN r.status = 0 THEN 'failed' ELSE 'complete' END"),
        "method" => Ok("r.method"),
        "scheme" => Ok("r.scheme"),
        "host" => Ok("r.host"),
        "path" => Ok("r.path"),
        "url" => Ok("r.scheme || '://' || r.host || r.path || CASE WHEN r.query IS NULL OR r.query = '' THEN '' ELSE '?' || r.query END"),
        "status" => Ok("r.status"),
        "type" => Ok("r.resource_type"),
        "source" => Ok("r.source"),
        "sourceInstanceId" => Ok("r.source_instance_id"),
        "protocol" => Ok("r.protocol"),
        "sizeBytes" => Ok("r.size_bytes"),
        "durationMs" => Ok("r.duration_ms"),
        "risk" => Ok("r.risk_level"),
        "hasHook" => Ok("r.hook_json IS NOT NULL"),
        "cryptoSnippetCount" => Ok("COALESCE(json_array_length(r.crypto_snippets_json), 0)"),
        "tlsIntercepted" => Ok("CASE WHEN COALESCE(json_extract(r.tls_fingerprint_json, '$.captureMode'), '') != '' THEN CASE WHEN json_extract(r.tls_fingerprint_json, '$.captureMode') = 'mitm' THEN 1 ELSE 0 END WHEN UPPER(r.method) != 'CONNECT' AND r.scheme = 'https' AND COALESCE(r.tls_version, '') != '' THEN 1 ELSE 0 END"),
        "requestHeader" => Ok("r.request_headers_json"),
        "responseHeader" => Ok("r.response_headers_json"),
        "requestBody" => Ok("COALESCE(r.request_body, '')"),
        "responseBody" => Ok("COALESCE(r.response_body, '')"),
        "hook" => Ok("COALESCE(r.hook_json, '')"),
        _ => Err(format!("不支持的请求筛选字段: {field}")),
    }
}

fn compile_request_predicate(
    field_sql: &str,
    operator: &str,
    value: Option<&Value>,
    params: &mut Vec<SqlValue>,
) -> Result<String, String> {
    if operator == "exists" {
        let expected = value.and_then(Value::as_bool).unwrap_or(true);
        return Ok(if expected {
            format!("({field_sql}) IS NOT NULL AND CAST(({field_sql}) AS TEXT) != ''")
        } else {
            format!("({field_sql}) IS NULL OR CAST(({field_sql}) AS TEXT) = ''")
        });
    }
    let value = value.ok_or_else(|| format!("筛选操作 {operator} 需要 value"))?;
    match operator {
        "equals" | "not_equals" => {
            params.push(json_value_to_sql(value)?);
            let comparison = if operator == "equals" { "=" } else { "!=" };
            Ok(format!(
                "CAST(({field_sql}) AS TEXT) COLLATE NOCASE {comparison} CAST(? AS TEXT)"
            ))
        }
        "contains" | "not_contains" | "starts_with" | "ends_with" | "wildcard" => {
            let text = json_value_as_text(value)?.to_ascii_lowercase();
            let pattern = match operator {
                "contains" | "not_contains" => format!("%{}%", escape_like(&text)),
                "starts_with" => format!("{}%", escape_like(&text)),
                "ends_with" => format!("%{}", escape_like(&text)),
                "wildcard" => wildcard_to_like(&text),
                _ => unreachable!(),
            };
            params.push(SqlValue::Text(pattern));
            let not = if operator == "not_contains" {
                "NOT "
            } else {
                ""
            };
            Ok(format!(
                "LOWER(CAST(({field_sql}) AS TEXT)) {not}LIKE ? ESCAPE '\\'"
            ))
        }
        "gt" | "gte" | "lt" | "lte" => {
            params.push(json_value_to_sql(value)?);
            let comparison = match operator {
                "gt" => ">",
                "gte" => ">=",
                "lt" => "<",
                "lte" => "<=",
                _ => unreachable!(),
            };
            Ok(format!("({field_sql}) {comparison} ?"))
        }
        "regex" => {
            let pattern = json_value_as_text(value)?;
            if pattern.chars().count() > 256 {
                return Err("正则表达式不能超过 256 个字符".to_string());
            }
            regex::Regex::new(&pattern).map_err(|error| format!("正则表达式无效: {error}"))?;
            params.push(SqlValue::Text(pattern));
            Ok(format!("shownet_regex(?, CAST(({field_sql}) AS TEXT)) = 1"))
        }
        _ => Err(format!("不支持的请求筛选操作: {operator}")),
    }
}

fn json_value_to_sql(value: &Value) -> Result<SqlValue, String> {
    match value {
        Value::String(value) => Ok(SqlValue::Text(value.clone())),
        Value::Number(value) => value
            .as_i64()
            .map(SqlValue::Integer)
            .or_else(|| value.as_f64().map(SqlValue::Real))
            .ok_or_else(|| "筛选数值无效".to_string()),
        Value::Bool(value) => Ok(SqlValue::Integer(i64::from(*value))),
        Value::Null => Ok(SqlValue::Null),
        _ => Err("筛选值只能是字符串、数字或布尔值".to_string()),
    }
}

fn json_value_as_text(value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err("文本筛选值无效".to_string()),
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn wildcard_to_like(value: &str) -> String {
    let escaped = escape_like(value);
    escaped.replace('*', "%").replace('?', "_")
}

fn request_facet_counts(
    connection: &Connection,
    expression: &str,
    where_clause: &str,
    params: &[SqlValue],
    limit: i64,
) -> rusqlite::Result<Vec<FacetCount>> {
    let sql = format!(
        "SELECT CAST(({expression}) AS TEXT), COUNT(*) AS item_count
           FROM requests r WHERE {where_clause}
          GROUP BY ({expression}) ORDER BY item_count DESC, 1 ASC LIMIT {limit}"
    );
    let mut statement = connection.prepare(&sql)?;
    let counts = statement
        .query_map(params_from_iter(params.iter()), |row| {
            Ok(FacetCount {
                value: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                count: row.get(1)?,
            })
        })?
        .collect();
    counts
}

fn browser_hook_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<BrowserHookEvent>> {
    let sequence: i64 = row.get(0)?;
    let timestamp: i64 = row.get(1)?;
    let source_instance_id: String = row.get(2)?;
    let request_id: String = row.get(3)?;
    let payload: String = row.get(4)?;
    let Ok(mut event) = serde_json::from_str::<BrowserHookEvent>(&payload) else {
        return Ok(None);
    };
    event.sequence = sequence;
    event.timestamp = timestamp;
    event.source_instance_id = source_instance_id;
    event.request_id = (!request_id.is_empty()).then_some(request_id);
    Ok(Some(event))
}

fn correlate_browser_hook(
    transaction: &Transaction<'_>,
    input: &BrowserHookInput,
    timestamp: i64,
) -> rusqlite::Result<(Option<String>, String)> {
    if let Some(request_id) = input.request_id.as_deref() {
        let matched = transaction
            .query_row(
                "SELECT id FROM requests WHERE id = ?1 AND session_id = ?2",
                params![request_id, input.session_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if matched.is_some() {
            return Ok((matched, "explicit".to_string()));
        }
    }

    if let Some(url) = input
        .url
        .as_deref()
        .and_then(|value| reqwest::Url::parse(value).ok())
    {
        let host = url.host_str().unwrap_or_default();
        let path = url.path();
        if !host.is_empty() && !path.is_empty() {
            let method = input.method.as_deref().unwrap_or_default();
            let matched = transaction
                .query_row(
                    "SELECT id FROM requests
                     WHERE session_id = ?1 AND host = ?2 AND path = ?3
                       AND (?4 = '' OR method = ?4)
                       AND started_at BETWEEN ?5 AND ?6
                     ORDER BY ABS(started_at - ?7) ASC LIMIT 1",
                    params![
                        input.session_id,
                        host,
                        path,
                        method,
                        timestamp - 10_000,
                        timestamp + 2_000,
                        timestamp,
                    ],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if matched.is_some() {
                return Ok((matched, "url-time".to_string()));
            }
        }
    }

    if input.kind == "crypto" || input.kind == "encoding" {
        let matched = transaction
            .query_row(
                "SELECT request_id FROM capture_events
                 WHERE session_id = ?1 AND source_instance_id = ?2
                   AND phase = 'hook' AND request_id != ''
                   AND json_extract(payload_json, '$.kind') = 'network'
                   AND timestamp BETWEEN ?3 AND ?4
                 ORDER BY ABS(timestamp - ?5) ASC LIMIT 1",
                params![
                    input.session_id,
                    input
                        .source_instance_id
                        .as_deref()
                        .unwrap_or("embedded-browser"),
                    timestamp - 5_000,
                    timestamp + 5_000,
                    timestamp
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if matched.is_some() {
            return Ok((matched, "time-window".to_string()));
        }
    }
    Ok((None, "unmatched".to_string()))
}

fn correlate_pending_browser_hooks(
    transaction: &Transaction<'_>,
    session_id: &str,
    request_id: &str,
    started_at: i64,
    method: &str,
    host: &str,
    path: &str,
) -> rusqlite::Result<()> {
    let candidates = {
        let mut statement = transaction.prepare(
            "SELECT id, timestamp, payload_json FROM capture_events
             WHERE session_id = ?1 AND phase = 'hook' AND request_id = ''
               AND timestamp BETWEEN ?2 AND ?3
             ORDER BY sequence ASC",
        )?;
        let rows = statement
            .query_map(
                params![session_id, started_at - 2_000, started_at + 10_000],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };

    let candidates = candidates
        .into_iter()
        .filter_map(|(event_id, timestamp, payload)| {
            serde_json::from_str::<BrowserHookEvent>(&payload)
                .ok()
                .map(|event| (event_id, timestamp, event))
        })
        .collect::<Vec<_>>();
    let has_matching_network_hook = candidates.iter().any(|(_, _, event)| {
        event.kind == "network" && browser_hook_matches_request(event, method, host, path)
    });
    let mut legacy_hook = None;
    for (event_id, timestamp, mut event) in candidates {
        let correlation = if event.kind == "network"
            && browser_hook_matches_request(&event, method, host, path)
        {
            Some("url-time")
        } else if has_matching_network_hook
            && matches!(event.kind.as_str(), "crypto" | "encoding")
            && (timestamp - started_at).abs() <= 2_000
        {
            Some("time-window")
        } else {
            None
        };
        let Some(correlation) = correlation else {
            continue;
        };
        event.request_id = Some(request_id.to_string());
        event.correlation = correlation.to_string();
        transaction.execute(
            "UPDATE capture_events SET request_id = ?1, payload_json = ?2 WHERE id = ?3",
            params![request_id, to_json(&event)?, event_id],
        )?;
        if legacy_hook.is_none() && matches!(event.kind.as_str(), "crypto" | "encoding") {
            legacy_hook = Some(HookRecord {
                algorithm: event.name,
                input: serde_json::to_string(&event.input).unwrap_or_else(|_| "null".to_string()),
                output: serde_json::to_string(&event.output).unwrap_or_else(|_| "null".to_string()),
            });
        }
    }
    if let Some(legacy_hook) = legacy_hook {
        transaction.execute(
            "UPDATE requests SET hook_json = COALESCE(hook_json, ?1)
             WHERE id = ?2 AND session_id = ?3",
            params![to_json(&legacy_hook)?, request_id, session_id],
        )?;
    }
    Ok(())
}

fn correlate_pending_crypto_hooks_to_request(
    transaction: &Transaction<'_>,
    session_id: &str,
    source_instance_id: &str,
    request_id: &str,
    network_timestamp: i64,
) -> rusqlite::Result<()> {
    let candidates = {
        let mut statement = transaction.prepare(
            "SELECT id, payload_json FROM capture_events
             WHERE session_id = ?1 AND source_instance_id = ?2
               AND phase = 'hook' AND request_id = ''
               AND timestamp BETWEEN ?3 AND ?4
             ORDER BY sequence ASC",
        )?;
        let rows = statement
            .query_map(
                params![
                    session_id,
                    source_instance_id,
                    network_timestamp - 5_000,
                    network_timestamp + 2_000
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let mut legacy_hook = None;
    for (event_id, payload) in candidates {
        let Ok(mut event) = serde_json::from_str::<BrowserHookEvent>(&payload) else {
            continue;
        };
        if !matches!(event.kind.as_str(), "crypto" | "encoding") {
            continue;
        }
        event.request_id = Some(request_id.to_string());
        event.correlation = "time-window".to_string();
        transaction.execute(
            "UPDATE capture_events SET request_id = ?1, payload_json = ?2 WHERE id = ?3",
            params![request_id, to_json(&event)?, event_id],
        )?;
        if legacy_hook.is_none() {
            legacy_hook = Some(HookRecord {
                algorithm: event.name,
                input: serde_json::to_string(&event.input).unwrap_or_else(|_| "null".to_string()),
                output: serde_json::to_string(&event.output).unwrap_or_else(|_| "null".to_string()),
            });
        }
    }
    if let Some(legacy_hook) = legacy_hook {
        transaction.execute(
            "UPDATE requests SET hook_json = COALESCE(hook_json, ?1)
             WHERE id = ?2 AND session_id = ?3",
            params![to_json(&legacy_hook)?, request_id, session_id],
        )?;
    }
    Ok(())
}

fn browser_hook_matches_request(
    event: &BrowserHookEvent,
    method: &str,
    host: &str,
    path: &str,
) -> bool {
    let Some(url) = event
        .url
        .as_deref()
        .and_then(|value| reqwest::Url::parse(value).ok())
    else {
        return false;
    };
    url.host_str() == Some(host)
        && url.path() == path
        && event
            .method
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case(method))
}

fn analysis_report_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AnalysisReport> {
    Ok(AnalysisReport {
        id: row.get(0)?,
        session_id: row.get(1)?,
        mode: row.get(2)?,
        status: row.get(3)?,
        request_count: row.get(4)?,
        key_request_count: row.get(5)?,
        selected_request_ids: from_json(row.get::<_, String>(6)?),
        content: row.get(7)?,
        provider: row.get(8)?,
        model: row.get(9)?,
        error: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

type SessionBase = (
    String,
    String,
    i64,
    i64,
    i64,
    String,
    i64,
    Option<String>,
    Option<i64>,
);

fn to_session(base: SessionBase, sources: Vec<String>) -> SessionRecord {
    SessionRecord {
        id: base.0,
        name: base.1,
        created_at: format_timestamp(base.2),
        request_count: base.3,
        error_count: base.4,
        active: base.5 == "active",
        sources,
        analysis_report_count: base.6,
        latest_analysis_status: base.7,
        latest_analysis_updated_at: base.8,
    }
}

fn session_sources(connection: &Connection, session_id: &str) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(
        "SELECT source FROM (
           SELECT source FROM requests WHERE session_id = ?1
           UNION
           SELECT source FROM capture_events WHERE session_id = ?1
         ) ORDER BY source",
    )?;
    let sources = statement
        .query_map([session_id], |row| row.get::<_, String>(0))?
        .collect();
    sources
}

fn next_sequence(transaction: &Transaction<'_>, session_id: &str) -> rusqlite::Result<i64> {
    let current = transaction
        .query_row(
            "SELECT last_sequence FROM sessions WHERE id = ?1",
            [session_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    let next = current + 1;
    transaction.execute(
        "UPDATE sessions SET last_sequence = ?1 WHERE id = ?2",
        params![next, session_id],
    )?;
    Ok(next)
}

fn validate_source(source: &str) -> Result<(), String> {
    match source {
        "browser" | "desktop" | "terminal" | "script" | "mobile" | "iot" | "reverse" => Ok(()),
        _ => Err(format!("不支持的流量来源: {source}")),
    }
}

fn extract_crypto_snippets_for_response(
    resource_type: &str,
    response_headers: &[crate::models::HeaderEntry],
    response_body: &str,
    metadata: &BodyCaptureMetadata,
) -> Vec<CryptoCodeSnippet> {
    let javascript_content_type = response_headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("content-type")
            && (header.value.to_ascii_lowercase().contains("javascript")
                || header.value.to_ascii_lowercase().contains("ecmascript"))
    });
    if (resource_type != "script" && !javascript_content_type)
        || response_body.is_empty()
        || response_body.starts_with("base64:")
        || metadata.format == "base64"
    {
        return Vec::new();
    }
    crypto_code::extract_crypto_snippets(response_body, metadata.truncated || !metadata.complete)
        .unwrap_or_default()
}

fn validate_phase(phase: &str) -> Result<(), String> {
    match phase {
        "request" | "response" | "websocket" | "sse" | "hook" | "interaction" | "storage"
        | "connection" => Ok(()),
        _ => Err(format!("不支持的事件阶段: {phase}")),
    }
}

fn validate_upstream_proxy(input: &UpstreamProxySettingsInput) -> Result<(), String> {
    match input.mode.as_str() {
        "direct" => return Ok(()),
        "http" | "https" | "socks5" => {}
        _ => return Err(format!("不支持的出口代理类型: {}", input.mode)),
    }
    let host = input.host.trim();
    if host.is_empty() {
        return Err("启用出口代理时必须填写主机".to_string());
    }
    if input.port == 0 {
        return Err("出口代理端口必须在 1 到 65535 之间".to_string());
    }
    if input.port == 8888 && matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return Err("出口代理不能指向 ShowNet 自身的 8888 端口".to_string());
    }
    Ok(())
}

fn validate_ai_provider(input: &AiProviderSettingsInput) -> Result<(), String> {
    match input.provider.as_str() {
        "claudegpt" | "compatible" | "local" => {}
        provider => return Err(format!("不支持的 AI 提供商: {provider}")),
    }
    let base_url = input.base_url.trim();
    if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
        return Err("AI Base URL 必须使用 http:// 或 https://".to_string());
    }
    if base_url.chars().any(char::is_whitespace) {
        return Err("AI Base URL 不能包含空白字符".to_string());
    }
    if input.provider != "local" && !base_url.starts_with("https://") {
        return Err("远程 AI 服务必须使用 HTTPS".to_string());
    }
    if input.model.trim().is_empty() {
        return Err("AI 模型不能为空".to_string());
    }
    Ok(())
}

fn validate_mcp_server_settings(input: &McpServerSettingsInput) -> Result<(), String> {
    if input.port < 1024 {
        return Err("MCP 服务端口必须在 1024 到 65535 之间".to_string());
    }
    if matches!(input.port, 1420 | 8888) {
        return Err("MCP 服务端口不能与 ShowNet 前端或抓包代理端口冲突".to_string());
    }
    Ok(())
}

fn validate_mcp_client_settings(input: &McpClientSettingsInput) -> Result<(), String> {
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err("MCP Server 名称必须为 1 到 64 个字符".to_string());
    }
    let endpoint = input.endpoint.trim();
    if endpoint.is_empty() || endpoint.len() > 2_048 {
        return Err("MCP Server 地址不能为空且不能超过 2048 字节".to_string());
    }
    let url = reqwest::Url::parse(endpoint).map_err(|_| "MCP Server 地址无效".to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("MCP Server 仅支持 HTTP 或 HTTPS Streamable HTTP 地址".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("MCP Server 地址不能包含内嵌凭据或片段".to_string());
    }
    let host = url.host_str().unwrap_or_default();
    let local = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if !local && url.scheme() != "https" {
        return Err("远程 MCP Server 必须使用 HTTPS".to_string());
    }
    if input
        .access_token
        .as_deref()
        .is_some_and(|token| token.len() > 8_192)
    {
        return Err("MCP 访问令牌不能超过 8192 字节".to_string());
    }
    Ok(())
}

fn public_mcp_client_settings(stored: StoredMcpClientSettings) -> McpClientSettings {
    McpClientSettings {
        id: stored.id,
        name: stored.name,
        endpoint: stored.endpoint,
        enabled: stored.enabled,
        has_access_token: stored
            .encrypted_access_token
            .as_deref()
            .is_some_and(|value| !value.is_empty()),
        tool_count: stored.tool_count,
        last_connected_at: stored.last_connected_at,
        last_error: stored.last_error,
    }
}

fn mcp_client_aad(id: &str) -> Vec<u8> {
    let mut aad = MCP_CLIENT_CREDENTIAL_AAD.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn mcp_endpoint_is_self(endpoint: &str, own_port: u16) -> bool {
    reqwest::Url::parse(endpoint).is_ok_and(|url| {
        matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
            && url.port_or_known_default() == Some(own_port)
            && url.path().trim_end_matches('/') == "/mcp"
    })
}

fn truncate_setting(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_string();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn is_generated_session_name(name: &str) -> bool {
    let value = name.trim();
    if value == "未命名会话" {
        return true;
    }
    if let Some(number) = value.strip_prefix("未命名会话 ") {
        return !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit());
    }
    let Some(timestamp) = value.strip_prefix("抓包 ") else {
        return false;
    };
    timestamp.len() == 11
        && timestamp
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                2 => byte == b'-',
                5 => byte == b' ',
                8 => byte == b':',
                _ => byte.is_ascii_digit(),
            })
}

fn analysis_session_name(content: &str, mode: &str, primary_host: Option<&str>) -> String {
    if let Some(title) = report_session_title(content) {
        return title;
    }
    let mode_name = match mode {
        "api" => "API 协议",
        "security" => "安全审计",
        "performance" => "性能分析",
        "crypto" => "加密逆向",
        _ => "自动分析",
    };
    match primary_host.map(str::trim).filter(|host| !host.is_empty()) {
        Some(host) => truncate_session_name(&format!("{host} · {mode_name}")),
        None => mode_name.to_string(),
    }
}

fn report_session_title(content: &str) -> Option<String> {
    for line in content.lines().take(80) {
        let trimmed = line.trim();
        let heading_depth = trimmed.bytes().take_while(|byte| *byte == b'#').count();
        if !(1..=6).contains(&heading_depth) {
            continue;
        }
        let compact = trimmed[heading_depth..]
            .trim()
            .trim_matches(|character| matches!(character, '*' | '_' | '`' | '[' | ']'))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let candidate = compact.strip_suffix("报告").unwrap_or(&compact).trim();
        let normalized = candidate.replace(' ', "").to_ascii_lowercase();
        if candidate.is_empty()
            || matches!(
                normalized.as_str(),
                "分析"
                    | "ai分析"
                    | "shownetai分析"
                    | "自动识别"
                    | "report"
                    | "analysisreport"
                    | "aireport"
            )
        {
            continue;
        }
        return Some(truncate_session_name(candidate));
    }
    None
}

fn truncate_session_name(value: &str) -> String {
    value
        .chars()
        .take(36)
        .collect::<String>()
        .trim()
        .to_string()
}

fn generate_mcp_access_token() -> String {
    format!("shownet_mcp_{}", Uuid::new_v4().simple())
}

fn normalize_bypass(entries: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for entry in entries.into_iter().take(200) {
        let value = entry.trim().to_lowercase();
        if !value.is_empty() && !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    normalized
}

fn normalize_system_bypass(entries: Vec<String>) -> Vec<String> {
    let mut normalized = normalize_bypass(entries);
    for required in ["localhost", "127.0.0.1", "::1", "*.local"] {
        if !normalized.iter().any(|value| value == required) {
            normalized.push(required.to_string());
        }
    }
    normalized
}

fn encrypt_credential(plaintext: &str) -> Result<String, String> {
    crypto::encrypt(plaintext.as_bytes(), CREDENTIAL_AAD)
}

fn decrypt_credential(encoded: &str) -> Result<String, String> {
    let plaintext = crypto::decrypt(encoded, CREDENTIAL_AAD)?;
    String::from_utf8(plaintext).map_err(|_| "出口代理密码不是有效文本".to_string())
}

fn read_json_setting<T: DeserializeOwned>(
    connection: &Connection,
    key: &str,
) -> Result<Option<T>, String> {
    let value = connection
        .query_row(
            "SELECT value_json FROM app_settings WHERE key = ?1",
            [key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    value
        .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
        .transpose()
}

fn sqlite_physical_bytes(path: &Path) -> i64 {
    let mut paths = vec![path.to_path_buf()];
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        paths.push(PathBuf::from(sidecar));
    }
    paths
        .into_iter()
        .filter_map(|candidate| std::fs::metadata(candidate).ok())
        .fold(0_i64, |total, metadata| {
            total.saturating_add(metadata.len().min(i64::MAX as u64) as i64)
        })
}

fn to_json<T: serde::Serialize + ?Sized>(value: &T) -> rusqlite::Result<String> {
    serde_json::to_string(value)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}

fn graph_run_status(run: &AnalysisGraphRun) -> &'static str {
    use crate::analysis_graph::GraphRunStatus;
    match run.status {
        GraphRunStatus::Running => "running",
        GraphRunStatus::Completed => "completed",
        GraphRunStatus::CompletedWithGaps => "completedWithGaps",
        GraphRunStatus::Failed => "failed",
        GraphRunStatus::Cancelled => "cancelled",
    }
}

fn from_json<T: DeserializeOwned + Default>(value: String) -> T {
    serde_json::from_str(&value).unwrap_or_default()
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn format_timestamp(timestamp: i64) -> String {
    DateTime::from_timestamp_millis(timestamp)
        .unwrap_or_else(Utc::now)
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn format_time(timestamp: i64) -> String {
    DateTime::from_timestamp_millis(timestamp)
        .map(|value| value.with_timezone(&Local).format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "--:--:--".to_string())
}

fn format_bytes(bytes: i64) -> String {
    if bytes < 1_024 {
        format!("{bytes} B")
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http2_fingerprint::{Http2Fingerprint, Http2Setting};
    use crate::models::{BodyCaptureMetadata, CollectionImportItem, HeaderEntry};
    use crate::tls_fingerprint::{
        mitm_fingerprint, tunnel_fingerprint, ClientTlsFingerprint, OutboundTlsFingerprint,
        TlsFingerprintRecord,
    };
    use crate::tls_interception::TlsInterceptionMode;
    use serde_json::Value;
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        thread,
        time::{Duration, Instant},
    };

    fn storage() -> Storage {
        Storage::from_connection(Connection::open_in_memory().unwrap()).unwrap()
    }

    fn write_openapi_fixture(extension: &str, content: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "shownet-openapi-sync-{}.{}",
            Uuid::new_v4(),
            extension
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    fn import_openapi_fixture(
        storage: &Storage,
        path: &Path,
        collection_name: &str,
    ) -> CollectionImportResult {
        let preview =
            crate::request_collections::preview_import_path(path.to_str().unwrap()).unwrap();
        storage
            .import_request_collection(CollectionImportCommitInput {
                collection_id: None,
                collection_name: collection_name.to_string(),
                items: preview.items,
                collection: preview.collection,
                environments: preview.environments,
                source_format: Some(preview.source_format),
                source_path: preview.source_path,
                source_fingerprint: preview.source_fingerprint,
            })
            .unwrap()
    }

    const OPENAPI_SYNC_V1: &str = r#"{
      "openapi": "3.0.3",
      "info": { "title": "Sync API" },
      "servers": [{ "url": "https://api.example.test" }],
      "paths": {
        "/same": {
          "get": { "summary": "Unchanged", "tags": ["Stable"] }
        },
        "/change": {
          "post": {
            "summary": "Remote name v1",
            "tags": ["Remote"],
            "requestBody": {
              "content": {
                "application/json": { "example": { "version": 1 } }
              }
            }
          }
        },
        "/removed": {
          "delete": { "summary": "Remove remotely", "tags": ["Remote"] }
        }
      }
    }"#;

    const OPENAPI_SYNC_V2: &str = r#"{
      "openapi": "3.0.3",
      "info": { "title": "Sync API" },
      "servers": [{ "url": "https://api.example.test" }],
      "paths": {
        "/same": {
          "get": { "summary": "Unchanged", "tags": ["Stable"] }
        },
        "/change": {
          "post": {
            "summary": "Remote name v2",
            "tags": ["Moved remotely"],
            "parameters": [
              { "name": "revision", "in": "query", "schema": { "type": "integer", "default": 2 } }
            ],
            "requestBody": {
              "content": {
                "application/json": { "example": { "version": 2 } }
              }
            }
          }
        },
        "/added": {
          "put": { "summary": "Added remotely", "tags": ["New"] }
        }
      }
    }"#;

    #[test]
    fn migrates_existing_database_to_response_body_metadata_v5() {
        let connection = Connection::open_in_memory().unwrap();
        let old_schema = SCHEMA.replace(
            "  response_body_meta_json TEXT NOT NULL DEFAULT '{}',\n",
            "",
        );
        connection.execute_batch(&old_schema).unwrap();
        let storage = Storage::from_connection(connection).unwrap();
        let (column_count, migration_count): (i64, i64) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COUNT(*) FROM pragma_table_info('requests') WHERE name = 'response_body_meta_json'",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version = 5",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(column_count, 1);
        assert_eq!(migration_count, 1);
    }

    #[test]
    fn migrates_existing_request_drafts_to_tags_v19() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE request_drafts (
                   id TEXT PRIMARY KEY,
                   session_id TEXT,
                   source_request_id TEXT,
                   name TEXT NOT NULL,
                   method TEXT NOT NULL,
                   url TEXT NOT NULL,
                   headers_json TEXT NOT NULL DEFAULT '[]',
                   body TEXT NOT NULL DEFAULT '',
                   body_type TEXT NOT NULL DEFAULT 'raw',
                   auth_json TEXT NOT NULL DEFAULT '{}',
                   settings_json TEXT NOT NULL DEFAULT '{}',
                   environment_id TEXT,
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL
                 );",
            )
            .unwrap();
        let storage = Storage::from_connection(connection).unwrap();
        let (column_count, migration_count): (i64, i64) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COUNT(*) FROM pragma_table_info('request_drafts') WHERE name='tags_json' AND [notnull]=1",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version=19",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!((column_count, migration_count), (1, 1));
    }

    #[test]
    fn migrates_existing_collections_and_drafts_to_openapi_sync_v20() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE request_collections (
                   id TEXT PRIMARY KEY,
                   name TEXT NOT NULL,
                   description TEXT NOT NULL DEFAULT '',
                   sort_order INTEGER NOT NULL DEFAULT 0,
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL,
                   default_headers_json TEXT NOT NULL DEFAULT '[]',
                   default_auth_json TEXT NOT NULL DEFAULT '{\"kind\":\"none\"}',
                   default_environment_id TEXT
                 );
                 CREATE TABLE request_drafts (
                   id TEXT PRIMARY KEY,
                   session_id TEXT,
                   source_request_id TEXT,
                   name TEXT NOT NULL,
                   method TEXT NOT NULL,
                   url TEXT NOT NULL,
                   headers_json TEXT NOT NULL DEFAULT '[]',
                   body TEXT NOT NULL DEFAULT '',
                   body_type TEXT NOT NULL DEFAULT 'raw',
                   auth_json TEXT NOT NULL DEFAULT '{}',
                   settings_json TEXT NOT NULL DEFAULT '{}',
                   environment_id TEXT,
                   collection_id TEXT,
                   folder_id TEXT,
                   tags_json TEXT NOT NULL DEFAULT '[]',
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL
                 );
                 INSERT INTO request_collections(id,name,created_at,updated_at)
                   VALUES ('collection-old','Old API',1,1);
                 INSERT INTO request_drafts(id,name,method,url,collection_id,created_at,updated_at)
                   VALUES ('draft-old','Old request','GET','https://api.example.test/old','collection-old',1,1);",
            )
            .unwrap();

        let storage = Storage::from_connection(connection).unwrap();
        let migration_state: (i64, i64, i64, i64) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COUNT(*) FROM pragma_table_info('request_collections')
                         WHERE name IN ('source_format','source_path','source_fingerprint','source_synced_at')",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM pragma_table_info('request_drafts')
                         WHERE name IN ('spec_operation_key','spec_fingerprint')",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version=20",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM pragma_index_list('request_drafts')
                         WHERE name='idx_request_drafts_spec_operation' AND [unique]=1",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(migration_state, (4, 2, 1, 1));
        let old_collection = storage.get_request_collection("collection-old").unwrap();
        let old_draft = storage.get_request_draft("draft-old").unwrap();
        assert!(old_collection.source_format.is_none());
        assert!(old_draft.spec_operation_key.is_none());
        assert!(old_draft.spec_fingerprint.is_none());
    }

    #[test]
    fn migrates_capture_events_to_first_class_sse_phase_v21() {
        let connection = Connection::open_in_memory().unwrap();
        let old_schema = SCHEMA.replace(
            "'request', 'response', 'websocket', 'sse', 'hook'",
            "'request', 'response', 'websocket', 'hook'",
        );
        connection.execute_batch(&old_schema).unwrap();
        connection
            .execute_batch(
                "INSERT INTO sessions(
                   id, name, created_at, updated_at, status,
                   request_count, error_count, last_sequence
                 ) VALUES ('session-v21', 'Legacy', 1, 1, 'idle', 0, 0, 1);
                 INSERT INTO capture_events(
                   session_id, sequence, timestamp, source, source_instance_id,
                   request_id, phase, payload_json
                 ) VALUES ('session-v21', 1, 1, 'desktop', 'legacy',
                           'request-old', 'websocket', '{}');",
            )
            .unwrap();

        let storage = Storage::from_connection(connection).unwrap();
        let state: (i64, i64, String) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version = 21",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM capture_events WHERE request_id = 'request-old'",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT sql FROM sqlite_master WHERE type='table' AND name='capture_events'",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(state.0, 1);
        assert_eq!(state.1, 1);
        assert!(state.2.contains("'sse'"));

        let event = storage
            .append_event(CaptureEventInput {
                session_id: "session-v21".to_string(),
                source: "desktop".to_string(),
                source_instance_id: Some("proxy:127.0.0.1".to_string()),
                request_id: Some("request-sse".to_string()),
                timestamp: Some(2),
                phase: "sse".to_string(),
                payload: serde_json::json!({ "data": "ready" }),
            })
            .unwrap();
        assert_eq!(event.sequence, 2);
    }

    #[test]
    fn migrates_existing_database_to_crypto_snippets_v6() {
        let connection = Connection::open_in_memory().unwrap();
        let old_schema = SCHEMA.replace("  crypto_snippets_json TEXT NOT NULL DEFAULT '[]',\n", "");
        connection.execute_batch(&old_schema).unwrap();
        let storage = Storage::from_connection(connection).unwrap();
        let (column_count, migration_count): (i64, i64) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COUNT(*) FROM pragma_table_info('requests') WHERE name = 'crypto_snippets_json'",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version = 6",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(column_count, 1);
        assert_eq!(migration_count, 1);
    }

    fn request(session_id: String, status: i64) -> CapturedRequestInput {
        CapturedRequestInput {
            id: None,
            session_id,
            source: "terminal".to_string(),
            source_instance_id: Some("curl".to_string()),
            timestamp: Some(1_785_393_200_000),
            method: "GET".to_string(),
            scheme: Some("https".to_string()),
            host: "api.example.test".to_string(),
            port: Some(443),
            path: "/v1/items".to_string(),
            query: None,
            status,
            resource_type: "fetch".to_string(),
            size_bytes: 2_048,
            duration_ms: 123,
            protocol: "h2".to_string(),
            tls_version: Some("TLS 1.3".to_string()),
            tls_fingerprint: None,
            risk_level: "none".to_string(),
            request_headers: vec![HeaderEntry {
                name: "accept".to_string(),
                value: "application/json".to_string(),
            }],
            response_headers: vec![],
            request_body: None,
            response_body: Some("{\"ok\":true}".to_string()),
            response_body_metadata: None,
            crypto_snippets: None,
            hook: None,
        }
    }

    fn test_client_tls_fingerprint(host: &str) -> ClientTlsFingerprint {
        ClientTlsFingerprint {
            ja3: "ja3-hash".to_string(),
            ja3_raw: "771,4865,0,29,0".to_string(),
            ja4: "ja4-hash".to_string(),
            ja4_raw: "ja4-raw".to_string(),
            sni: Some(host.to_string()),
            alpn: vec!["h2".to_string()],
            legacy_version: "TLS 1.2".to_string(),
            offered_versions: vec!["TLS 1.3".to_string()],
            cipher_suites: vec!["1301".to_string()],
            extensions: vec!["0000".to_string()],
            supported_groups: vec!["001d".to_string()],
            signature_algorithms: vec!["0403".to_string()],
            grease: false,
        }
    }

    fn seed_request_list_fixture_with_payload(
        storage: &Storage,
        count: usize,
        compact_payload: bool,
    ) -> String {
        let session = storage
            .create_session(Some(format!("request-list-{count}")))
            .unwrap();
        let headers = serde_json::to_string(&vec![HeaderEntry {
            name: "x-fixture-header".to_string(),
            value: "h".repeat(if compact_payload { 32 } else { 512 }),
        }])
        .unwrap();
        let response_body = "r".repeat(if compact_payload { 128 } else { 2_048 });
        let request_body = "q".repeat(if compact_payload { 32 } else { 512 });
        storage
            .with_connection(|connection| {
                let transaction = connection.transaction()?;
                {
                    let mut statement = transaction.prepare(
                        "INSERT INTO requests(
                           id, session_id, sequence, source, source_instance_id, started_at,
                           method, scheme, host, port, path, query, status, resource_type,
                           size_bytes, duration_ms, protocol, tls_version, risk_level,
                           request_headers_json, response_headers_json, request_body,
                           response_body, response_body_meta_json, crypto_snippets_json, hook_json
                         ) VALUES (
                           ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'https', ?8, 443, ?9, ?10, ?11,
                           ?12, ?13, ?14, ?15, 'TLS 1.3', ?16, ?17, '[]', ?18, ?19,
                           '{\"captured\":true,\"decoded\":true,\"truncated\":false,\"complete\":true,\"wireBytes\":2048,\"decodedBytes\":2048,\"format\":\"text\"}',
                           ?20, ?21
                         )",
                    )?;
                    for index in 0..count {
                        let sequence = index as i64 + 1;
                        let source = match index % 6 {
                            0 => "browser",
                            1 => "desktop",
                            2 => "terminal",
                            3 => "script",
                            4 => "mobile",
                            _ => "iot",
                        };
                        let method = if index % 5 == 0 { "POST" } else { "GET" };
                        let status = if index % 17 == 0 { 500 } else { 200 };
                        let resource_type = if index % 7 == 0 { "script" } else { "fetch" };
                        let risk = if index % 19 == 0 { "warning" } else { "none" };
                        let snippets = if index % 11 == 0 { "[{}]" } else { "[]" };
                        let hook = (index % 13 == 0).then_some(
                            "{\"algorithm\":\"SHA-256\",\"input\":\"fixture\",\"output\":\"fixture\"}",
                        );
                        statement.execute(params![
                            format!("fixture-{count}-{index}"),
                            session.id,
                            sequence,
                            source,
                            format!("{source}-{index_mod}", index_mod = index % 4),
                            1_785_393_200_000i64 + sequence,
                            method,
                            format!("api-{}.example.test", index % 24),
                            format!("/v1/items/{}", index % 200),
                            format!("page={}&token=fixture", index % 50),
                            status,
                            resource_type,
                            2_048 + index as i64,
                            20 + (index % 2_000) as i64,
                            if index % 8 == 0 { "http/1.1" } else { "h2" },
                            risk,
                            headers,
                            request_body,
                            response_body,
                            snippets,
                            hook,
                        ])?;
                    }
                }
                transaction.execute(
                    "UPDATE sessions SET request_count = ?1, error_count = ?2, last_sequence = ?1 WHERE id = ?3",
                    params![count as i64, (0..count).filter(|index| index % 17 == 0).count() as i64, session.id],
                )?;
                transaction.commit()
            })
            .unwrap();
        session.id
    }

    fn seed_request_list_fixture(storage: &Storage, count: usize) -> String {
        seed_request_list_fixture_with_payload(storage, count, false)
    }

    fn default_request_query(session_id: String) -> RequestQuery {
        RequestQuery {
            session_id,
            filter: None,
            sort: vec![crate::models::RequestSort {
                field: "order".to_string(),
                direction: "asc".to_string(),
            }],
            cursor: None,
            limit: 100,
        }
    }

    #[test]
    fn request_list_query_returns_lightweight_rows_facets_and_indexes() {
        let storage = storage();
        let session_id = seed_request_list_fixture(&storage, 250);
        let page = storage
            .query_request_list(default_request_query(session_id.clone()))
            .unwrap();
        assert_eq!(page.items.len(), 100);
        assert_eq!(page.total_count, 250);
        assert_eq!(page.filtered_count, 250);
        assert_eq!(page.hook_count, 20);
        assert_eq!(page.bookmarked_count, 0);
        assert_eq!(page.next_cursor.as_deref(), Some("o:100"));
        assert_eq!(page.items[0].order, 1);
        assert!(page.items[0].has_hook);
        assert!(page.facets.hosts.len() >= 20);
        assert_eq!(
            page.facets
                .sources
                .iter()
                .map(|facet| facet.count)
                .sum::<i64>(),
            250
        );

        let encoded = serde_json::to_string(&page).unwrap();
        assert!(!encoded.contains("responseBody"));
        assert!(!encoded.contains("requestHeaders"));
        assert!(encoded.len() < 100_000);

        let migration_and_indexes = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version = 10",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM pragma_index_list('requests') WHERE name IN ('idx_requests_session_source_sequence', 'idx_requests_session_type_sequence', 'idx_requests_session_protocol_sequence', 'idx_requests_session_risk_sequence', 'idx_requests_session_started')",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(migration_and_indexes, (1, 5));
    }

    #[test]
    fn request_list_window_supports_bounded_random_access_without_summary_queries() {
        let storage = storage();
        let session_id = seed_request_list_fixture(&storage, 250);
        let query = RequestWindowQuery {
            session_id: session_id.clone(),
            filter: None,
            sort: vec![crate::models::RequestSort {
                field: "order".to_string(),
                direction: "asc".to_string(),
            }],
            offset: 175,
            limit: 100,
        };
        let window = storage.query_request_window(query.clone()).unwrap();
        assert_eq!(window.offset, 175);
        assert_eq!(window.items.len(), 75);
        assert_eq!(window.items.first().map(|item| item.order), Some(176));
        assert_eq!(window.items.last().map(|item| item.order), Some(250));
        let encoded = serde_json::to_string(&window).unwrap();
        assert!(!encoded.contains("totalCount"));
        assert!(!encoded.contains("facets"));

        let mut invalid = query;
        invalid.offset = -1;
        assert!(storage
            .query_request_window(invalid)
            .unwrap_err()
            .contains("offset"));
    }

    #[test]
    fn request_list_filter_sort_and_cursor_are_stable() {
        let storage = storage();
        let session_id = seed_request_list_fixture(&storage, 420);
        let filter = FilterExpression::Group {
            operator: "and".to_string(),
            children: vec![
                FilterExpression::Predicate {
                    field: "method".to_string(),
                    operator: "equals".to_string(),
                    value: Some(Value::String("POST".to_string())),
                },
                FilterExpression::Predicate {
                    field: "durationMs".to_string(),
                    operator: "gte".to_string(),
                    value: Some(Value::from(100)),
                },
            ],
        };
        let first = storage
            .query_request_list(RequestQuery {
                session_id: session_id.clone(),
                filter: Some(filter.clone()),
                sort: vec![crate::models::RequestSort {
                    field: "durationMs".to_string(),
                    direction: "desc".to_string(),
                }],
                cursor: None,
                limit: 100,
            })
            .unwrap();
        assert_eq!(first.items.len(), 68);
        assert!(first
            .items
            .windows(2)
            .all(|items| items[0].duration_ms >= items[1].duration_ms));
        assert!(first.items.iter().all(|item| item.method == "POST"));

        let all_first = storage
            .query_request_list(default_request_query(session_id.clone()))
            .unwrap();
        let mut second_query = default_request_query(session_id);
        second_query.cursor = all_first.next_cursor.clone();
        let all_second = storage.query_request_list(second_query).unwrap();
        let first_ids = all_first
            .items
            .iter()
            .map(|item| &item.id)
            .collect::<std::collections::HashSet<_>>();
        assert!(all_second
            .items
            .iter()
            .all(|item| !first_ids.contains(&item.id)));
        assert_eq!(all_second.items.first().map(|item| item.order), Some(101));
    }

    #[test]
    fn request_list_rejects_unknown_fields_and_invalid_cursors() {
        let storage = storage();
        let session_id = seed_request_list_fixture(&storage, 1);
        let mut query = default_request_query(session_id.clone());
        query.sort[0].field = "drop table requests".to_string();
        assert!(storage
            .query_request_list(query)
            .unwrap_err()
            .contains("排序字段"));

        let mut query = default_request_query(session_id);
        query.cursor = Some("not-a-cursor".to_string());
        assert!(storage
            .query_request_list(query)
            .unwrap_err()
            .contains("游标"));
    }

    #[test]
    fn saved_request_views_round_trip_and_cascade_with_session() {
        let storage = storage();
        let session_id = seed_request_list_fixture(&storage, 3);
        let saved = storage
            .save_request_view(SavedRequestViewInput {
                id: None,
                name: "异常 API".to_string(),
                session_id: Some(session_id.clone()),
                filter: Some(FilterExpression::Predicate {
                    field: "status".to_string(),
                    operator: "gte".to_string(),
                    value: Some(Value::from(400)),
                }),
                sort: vec![crate::models::RequestSort {
                    field: "durationMs".to_string(),
                    direction: "desc".to_string(),
                }],
                columns: serde_json::json!({"version":1,"visible":["order","method","url"]}),
            })
            .unwrap();
        let listed = storage.list_saved_request_views(&session_id).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, saved.id);
        assert_eq!(listed[0].name, "异常 API");
        assert_eq!(listed[0].sort[0].field, "durationMs");
        assert_eq!(listed[0].columns["version"], 1);

        storage.delete_session(&session_id).unwrap();
        let remaining = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT COUNT(*) FROM saved_request_views WHERE id = ?1",
                    [&saved.id],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn request_list_regex_is_bounded_and_uses_linear_engine() {
        let storage = storage();
        let session_id = seed_request_list_fixture(&storage, 48);
        let query_with_pattern = |pattern: String| RequestQuery {
            session_id: session_id.clone(),
            filter: Some(FilterExpression::Predicate {
                field: "host".to_string(),
                operator: "regex".to_string(),
                value: Some(Value::String(pattern)),
            }),
            sort: vec![crate::models::RequestSort {
                field: "order".to_string(),
                direction: "asc".to_string(),
            }],
            cursor: None,
            limit: 100,
        };
        let page = storage
            .query_request_list(query_with_pattern(
                "^api-(1|2)\\.example\\.test$".to_string(),
            ))
            .unwrap();
        assert_eq!(page.filtered_count, 4);
        assert!(page.items.iter().all(|item| matches!(
            item.host.as_str(),
            "api-1.example.test" | "api-2.example.test"
        )));

        assert!(storage
            .query_request_list(query_with_pattern("(".to_string()))
            .unwrap_err()
            .contains("正则表达式无效"));
        assert!(storage
            .query_request_list(query_with_pattern("a".repeat(257)))
            .unwrap_err()
            .contains("256"));
    }

    #[test]
    fn cancellable_sql_interrupts_in_flight_and_clears_progress_handler() {
        let storage = Arc::new(storage());
        let mut latencies = Vec::with_capacity(12);

        for sample in 0..12 {
            let cancellation = Arc::new(AtomicBool::new(false));
            let (started_tx, started_rx) = mpsc::channel();
            let worker_storage = Arc::clone(&storage);
            let worker_cancellation = Arc::clone(&cancellation);
            let worker = thread::spawn(move || {
                worker_storage.with_cancellable_connection(worker_cancellation, |connection| {
                    started_tx.send(()).unwrap();
                    connection.query_row(
                        "WITH RECURSIVE sequence(value) AS (
                           VALUES(0)
                           UNION ALL
                           SELECT value + 1 FROM sequence WHERE value < 1000000000
                         )
                         SELECT sum(value) FROM sequence",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                })
            });

            started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("long-running SQL should start");
            thread::sleep(Duration::from_millis(20));
            let cancelled_at = Instant::now();
            cancellation.store(true, Ordering::Release);
            let result = worker.join().expect("query worker should not panic");
            let cancellation_latency = cancelled_at.elapsed();

            assert_eq!(result.unwrap_err(), REQUEST_QUERY_CANCELLED);
            assert!(
                cancellation_latency < Duration::from_millis(500),
                "running SQLite query cancellation sample {sample} took {:.2}ms",
                cancellation_latency.as_secs_f64() * 1_000.0
            );
            latencies.push(cancellation_latency);

            let ordinary_query = storage
                .with_connection(|connection| {
                    connection.query_row("SELECT 42", [], |row| row.get::<_, i64>(0))
                })
                .expect("progress handler must be cleared after cancellation");
            assert_eq!(ordinary_query, 42);
        }

        latencies.sort_unstable();
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[(latencies.len() * 95).div_ceil(100) - 1];
        let maximum = latencies[latencies.len() - 1];
        println!(
            "request query cancellation latency (12 samples): p50={:.2}ms p95={:.2}ms max={:.2}ms",
            p50.as_secs_f64() * 1_000.0,
            p95.as_secs_f64() * 1_000.0,
            maximum.as_secs_f64() * 1_000.0
        );
    }

    #[test]
    #[ignore = "repeatable request-list performance benchmark"]
    fn request_list_performance_benchmark() {
        for count in [1_000usize, 10_000usize] {
            let storage = storage();
            let session_id = seed_request_list_fixture(&storage, count);

            let started = Instant::now();
            let legacy = storage
                .list_requests(&session_id, Some(count as i64), Some(0))
                .unwrap();
            let legacy_ms = started.elapsed().as_secs_f64() * 1_000.0;
            let legacy_bytes = serde_json::to_vec(&legacy).unwrap().len();

            let started = Instant::now();
            let mut query = default_request_query(session_id);
            query.limit = 500;
            let mut summary_items = Vec::with_capacity(count);
            let first_page_started = Instant::now();
            let first_page = storage.query_request_list(query.clone()).unwrap();
            let first_page_ms = first_page_started.elapsed().as_secs_f64() * 1_000.0;
            let first_page_bytes = serde_json::to_vec(&first_page).unwrap().len();
            let mut next_cursor = first_page.next_cursor.clone();
            summary_items.extend(first_page.items);
            while let Some(cursor) = next_cursor {
                query.cursor = Some(cursor);
                let page = storage.query_request_list(query.clone()).unwrap();
                summary_items.extend(page.items);
                next_cursor = page.next_cursor;
            }
            let summary_ms = started.elapsed().as_secs_f64() * 1_000.0;
            let summary_bytes = serde_json::to_vec(&summary_items).unwrap().len();
            println!(
                "{}",
                serde_json::json!({
                    "fixtureRequests": count,
                    "legacy": { "items": legacy.len(), "milliseconds": legacy_ms, "bytes": legacy_bytes },
                    "summaryFirstPage": { "items": 500.min(count), "milliseconds": first_page_ms, "bytes": first_page_bytes },
                    "summary": { "items": summary_items.len(), "milliseconds": summary_ms, "bytes": summary_bytes },
                    "byteReduction": 1.0 - summary_bytes as f64 / legacy_bytes as f64,
                })
            );
            assert_eq!(summary_items.len(), count);
            assert!(summary_bytes < legacy_bytes / 4);
            if count == 10_000 {
                assert!(
                    first_page_ms < 500.0,
                    "10k 会话首屏查询与序列化耗时 {first_page_ms:.2}ms，超过 500ms 门槛"
                );
                assert!(
                    summary_bytes < 100 * 1024 * 1024,
                    "10k 轻量摘要序列化体积 {summary_bytes}B，超过 100MiB 前端增量内存代理门槛"
                );
            }
        }

        let storage = storage();
        let seed_started = Instant::now();
        let session_id = seed_request_list_fixture_with_payload(&storage, 100_000, true);
        let seed_ms = seed_started.elapsed().as_secs_f64() * 1_000.0;
        let mut summary_query = default_request_query(session_id.clone());
        summary_query.limit = 500;
        let first_page_started = Instant::now();
        let first_page = storage.query_request_list(summary_query).unwrap();
        let first_page_ms = first_page_started.elapsed().as_secs_f64() * 1_000.0;
        let first_page_bytes = serde_json::to_vec(&first_page).unwrap().len();
        assert_eq!(first_page.filtered_count, 100_000);
        assert_eq!(first_page.items.len(), 500);

        let mut retained_window_bytes = first_page_bytes;
        let mut windows = Vec::new();
        for offset in [49_750i64, 99_500i64] {
            let started = Instant::now();
            let window = storage
                .query_request_window(RequestWindowQuery {
                    session_id: session_id.clone(),
                    filter: None,
                    sort: vec![crate::models::RequestSort {
                        field: "order".to_string(),
                        direction: "asc".to_string(),
                    }],
                    offset,
                    limit: 500,
                })
                .unwrap();
            let milliseconds = started.elapsed().as_secs_f64() * 1_000.0;
            let bytes = serde_json::to_vec(&window).unwrap().len();
            assert_eq!(window.items.len(), 500);
            assert_eq!(
                window.items.first().map(|item| item.order),
                Some(offset + 1)
            );
            assert!(
                milliseconds < 750.0,
                "100k 会话 offset={offset} 窗口查询耗时 {milliseconds:.2}ms，超过 750ms 门槛"
            );
            retained_window_bytes += bytes;
            windows.push(serde_json::json!({
                "offset": offset,
                "items": window.items.len(),
                "milliseconds": milliseconds,
                "bytes": bytes,
            }));
        }
        println!(
            "{}",
            serde_json::json!({
                "fixtureRequests": 100_000,
                "seedMilliseconds": seed_ms,
                "summaryFirstPage": {
                    "items": first_page.items.len(),
                    "milliseconds": first_page_ms,
                    "bytes": first_page_bytes,
                },
                "randomAccessWindows": windows,
                "threeWindowUpperBoundBytes": retained_window_bytes,
            })
        );
        assert!(
            first_page_ms < 1_500.0,
            "100k 会话首屏统计与查询耗时 {first_page_ms:.2}ms，超过 1500ms 门槛"
        );
        assert!(
            retained_window_bytes < 5 * 1024 * 1024,
            "100k 三窗口序列化上界 {retained_window_bytes}B，超过 5MiB"
        );
    }

    #[test]
    fn persists_sessions_requests_and_counts() {
        let storage = storage();
        let session = storage
            .create_session(Some("API test".to_string()))
            .unwrap();
        let (stored, event) = storage
            .store_request(request(session.id.clone(), 503))
            .unwrap();
        let portable = storage.get_bundle_request(&stored.id).unwrap();

        assert_eq!(stored.order, 1);
        assert_eq!(portable.host, "api.example.test");
        assert_eq!(stored.size, "2.0 KB");
        assert_eq!(event.sequence, 1);
        let sessions = storage.list_sessions().unwrap();
        assert_eq!(sessions[0].request_count, 1);
        assert_eq!(sessions[0].error_count, 1);
        assert_eq!(sessions[0].sources, vec!["terminal"]);
        assert_eq!(
            storage
                .list_requests(&session.id, None, None)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn analysis_names_generated_sessions_without_overwriting_manual_names() {
        let storage = storage();
        let generated = storage
            .create_session(Some("抓包 08-01 09:30".to_string()))
            .unwrap();
        storage
            .store_request(request(generated.id.clone(), 200))
            .unwrap();
        let report = storage
            .create_analysis_report(&generated.id, "auto", 1, "test", "test")
            .unwrap();
        storage
            .finish_analysis_report(&report.id, "# 电商登录链路分析报告\n\n结论")
            .unwrap();
        assert_eq!(
            storage.get_session(&generated.id).unwrap().name,
            "电商登录链路分析"
        );

        let fallback = storage
            .create_session(Some("未命名会话 8".to_string()))
            .unwrap();
        storage
            .store_request(request(fallback.id.clone(), 200))
            .unwrap();
        let fallback_report = storage
            .create_analysis_report(&fallback.id, "api", 1, "test", "test")
            .unwrap();
        storage
            .finish_analysis_report(&fallback_report.id, "# 自动识别报告\n\n结论")
            .unwrap();
        assert_eq!(
            storage.get_session(&fallback.id).unwrap().name,
            "api.example.test · API 协议"
        );

        let manual = storage
            .create_session(Some("未命名会话 9".to_string()))
            .unwrap();
        storage.rename_session(&manual.id, "支付回调排查").unwrap();
        let manual_report = storage
            .create_analysis_report(&manual.id, "security", 0, "test", "test")
            .unwrap();
        storage
            .finish_analysis_report(&manual_report.id, "# 其他标题报告")
            .unwrap();
        assert_eq!(
            storage.get_session(&manual.id).unwrap().name,
            "支付回调排查"
        );
    }

    #[test]
    fn extracts_and_persists_crypto_snippets_for_javascript_responses() {
        let storage = storage();
        let session = storage
            .create_session(Some("Crypto JS".to_string()))
            .unwrap();
        let mut input = request(session.id, 200);
        input.resource_type = "script".to_string();
        input.path = "/assets/sign.js".to_string();
        input.response_headers = vec![HeaderEntry {
            name: "content-type".to_string(),
            value: "application/javascript".to_string(),
        }];
        input.response_body =
            Some("function sign(body, key) { return CryptoJS.HmacSHA256(body, key); }".to_string());
        let (stored, _) = storage.store_request(input).unwrap();
        let snippets = storage.get_crypto_snippets(&stored.id).unwrap();
        let portable = storage.get_bundle_request(&stored.id).unwrap();

        assert_eq!(stored.crypto_snippet_count, 1);
        assert_eq!(snippets.len(), 1);
        assert_eq!(snippets[0].name.as_deref(), Some("sign"));
        assert!(snippets[0].algorithms.contains(&"HMAC".to_string()));
        assert_eq!(portable.crypto_snippets.len(), 1);
    }

    #[test]
    fn persists_analysis_reports_logs_and_followup_context() {
        let storage = storage();
        let session = storage.create_session(Some("AI test".to_string())).unwrap();
        let (request, _) = storage
            .store_request(request(session.id.clone(), 200))
            .unwrap();
        let report = storage
            .create_analysis_report(&session.id, "api", 1, "claudegpt", "gpt-5.6-sol")
            .unwrap();
        storage
            .update_analysis_selection(&report.id, std::slice::from_ref(&request.id))
            .unwrap();
        storage
            .save_analysis_progress(&report.id, "# partial")
            .unwrap();
        let complete = storage
            .finish_analysis_report(&report.id, "# complete")
            .unwrap();
        storage
            .append_analysis_activity(&report.id, "filtering", Some("正在识别关键请求"))
            .unwrap();
        storage
            .append_analysis_activity(
                &report.id,
                "tool",
                Some("内置 Agent 正在调用 shownet_get_request"),
            )
            .unwrap();
        storage
            .append_analysis_activity(
                &report.id,
                "tool-complete",
                Some("shownet_get_request 已返回"),
            )
            .unwrap();
        storage
            .append_analysis_activity(&report.id, "complete", Some("分析报告已生成"))
            .unwrap();
        storage
            .start_skill_run(
                &report.id,
                "api-reverse",
                "API 协议逆向",
                "2.2.0",
                "api",
                &["读取完整请求".to_string()],
                &["shownet_get_request".to_string()],
                &serde_json::json!({ "requestCount": 1 }),
            )
            .unwrap();
        storage
            .begin_skill_tool_call(&report.id, "shownet_get_request")
            .unwrap();
        storage
            .finish_skill_tool_call(&report.id, "shownet_get_request", "complete")
            .unwrap();
        storage
            .finish_skill_runs(
                &report.id,
                "complete",
                &serde_json::json!({ "reportBytes": 10 }),
                None,
            )
            .unwrap();
        storage
            .add_analysis_message(&report.id, "user", "鉴权方式是什么？")
            .unwrap();
        storage
            .add_analysis_message(&report.id, "assistant", "证据显示为 Bearer Token。")
            .unwrap();
        let log_id = storage
            .begin_ai_request_log(
                &report.id,
                "analysis",
                "claudegpt",
                "gpt-5.6-sol",
                "https://claudegpt.org/v1/chat/completions",
            )
            .unwrap();
        storage
            .finish_ai_request_log(&log_id, "complete", None)
            .unwrap();

        assert_eq!(complete.status, "complete");
        assert_eq!(complete.selected_request_ids, vec![request.id]);
        let session_with_report = storage.get_session(&session.id).unwrap();
        assert_eq!(session_with_report.analysis_report_count, 1);
        assert_eq!(
            session_with_report.latest_analysis_status.as_deref(),
            Some("complete")
        );
        assert!(session_with_report.latest_analysis_updated_at.is_some());
        assert_eq!(
            storage
                .latest_analysis_report(&session.id)
                .unwrap()
                .unwrap()
                .content,
            "# complete"
        );
        assert_eq!(storage.list_analysis_messages(&report.id).unwrap().len(), 2);
        let activities = storage.list_analysis_activities(&report.id).unwrap();
        assert_eq!(activities.len(), 4);
        assert_eq!(activities[0].phase, "filtering");
        assert_eq!(activities[1].phase, "tool");
        assert_eq!(activities[2].phase, "tool-complete");
        assert_eq!(activities[3].phase, "complete");
        assert_eq!(activities[1].analysis_id, report.id);
        assert!(storage
            .append_analysis_activity(&report.id, "delta", None)
            .is_err());
        let skill_runs = storage.list_analysis_skill_runs(&report.id).unwrap();
        assert_eq!(skill_runs.len(), 1);
        assert_eq!(skill_runs[0].skill_id, "api-reverse");
        assert_eq!(skill_runs[0].skill_version, "2.2.0");
        assert_eq!(skill_runs[0].status, "complete");
        assert_eq!(skill_runs[0].permissions, vec!["读取完整请求"]);
        assert_eq!(skill_runs[0].actual_tool_calls.len(), 1);
        assert_eq!(skill_runs[0].actual_tool_calls[0].status, "complete");
        assert!(skill_runs[0].duration_ms.is_some());
        let second_report = storage
            .create_analysis_report(&session.id, "security", 1, "claudegpt", "gpt-5.5")
            .unwrap();
        storage
            .finish_analysis_report(&second_report.id, "# security")
            .unwrap();
        let reports = storage.list_analysis_reports(&session.id).unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].id, second_report.id);
        assert_eq!(reports[1].id, report.id);
        let migrations: (i64, i64, i64) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version = 3",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version = 8",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version = 9",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(migrations, (1, 1, 1));
    }

    #[test]
    fn builds_secret_free_akamai_signature_harness_from_stored_requests() {
        const ABCK_SENTINEL: &str = "ABCK_SECRET_MUST_NOT_LEAK";
        const SENSOR_SENTINEL: &str = "SENSOR_SECRET_MUST_NOT_LEAK";

        let storage = storage();
        let session = storage
            .create_session(Some("Akamai adapter".to_string()))
            .unwrap();
        let mut input = request(session.id.clone(), 200);
        input.method = "POST".to_string();
        input.host = "www.example.test".to_string();
        input.path = "/_bm/_data".to_string();
        input.query = Some(format!("sensor_data={SENSOR_SENTINEL}&nonce=42"));
        input.request_headers = vec![HeaderEntry {
            name: "cookie".to_string(),
            value: format!("_abck={ABCK_SENTINEL}; bm_sz=BM_SECRET_MUST_NOT_LEAK"),
        }];
        input.response_headers = vec![HeaderEntry {
            name: "set-cookie".to_string(),
            value: "ak_bmsc=RESPONSE_SECRET_MUST_NOT_LEAK; Path=/; Secure".to_string(),
        }];
        input.request_body = Some(format!(
            r#"{{"sensorData":"{SENSOR_SENTINEL}","device":{{"screen":"1920x1080"}}}}"#
        ));
        let (stored, _) = storage.store_request(input).unwrap();
        storage
            .store_browser_hook(BrowserHookInput {
                session_id: session.id.clone(),
                source_instance_id: Some("chrome-cdp:test".to_string()),
                request_id: Some(stored.id),
                timestamp: Some(now_ms()),
                kind: "crypto".to_string(),
                name: "akamai.sensor.build".to_string(),
                url: Some("https://www.example.test/_bm/_data".to_string()),
                method: Some("POST".to_string()),
                input: serde_json::json!({ "sensor": SENSOR_SENTINEL }),
                output: serde_json::json!({ "length": 128 }),
                stack: Some("at buildSensor (akamai.js:1:1)".to_string()),
                duration_ms: Some(3),
            })
            .unwrap();

        let harness =
            crate::signature_adapter::build_signature_harness(&storage, &session.id, "auto")
                .unwrap();
        let serialized = serde_json::to_string(&harness).unwrap();

        assert_eq!(harness.adapter_id, "akamai-bot-manager");
        assert_eq!(harness.vendor, "Akamai");
        assert!(harness.dynamic_fields.contains(&"sensor_data".to_string()));
        assert!(harness.dynamic_fields.contains(&"sensorData".to_string()));
        assert!(harness.cookie_names.contains(&"_abck".to_string()));
        assert!(harness.cookie_names.contains(&"bm_sz".to_string()));
        assert!(harness.cookie_names.contains(&"ak_bmsc".to_string()));
        assert!(harness
            .hook_names
            .contains(&"crypto:akamai.sensor.build".to_string()));
        for secret in [
            ABCK_SENTINEL,
            SENSOR_SENTINEL,
            "BM_SECRET_MUST_NOT_LEAK",
            "RESPONSE_SECRET_MUST_NOT_LEAK",
        ] {
            assert!(!serialized.contains(secret));
            assert!(!harness.code.contains(secret));
        }
    }

    #[test]
    fn assigns_one_monotonic_sequence_to_all_event_types() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();
        let first = storage
            .append_event(CaptureEventInput {
                session_id: session.id.clone(),
                source: "browser".to_string(),
                source_instance_id: None,
                request_id: None,
                timestamp: None,
                phase: "hook".to_string(),
                payload: Value::Null,
            })
            .unwrap();
        let (_, second) = storage.store_request(request(session.id, 200)).unwrap();

        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
    }

    #[test]
    fn lists_only_ordered_websocket_events_with_a_bounded_limit() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();
        let request_id = "request-websocket";
        for (phase, index) in [("websocket", 1), ("hook", 2), ("websocket", 3)] {
            storage
                .append_event(CaptureEventInput {
                    session_id: session.id.clone(),
                    source: "desktop".to_string(),
                    source_instance_id: Some("proxy:127.0.0.1".to_string()),
                    request_id: Some(request_id.to_string()),
                    timestamp: Some(1_785_393_200_000 + index),
                    phase: phase.to_string(),
                    payload: serde_json::json!({ "index": index }),
                })
                .unwrap();
        }

        let events = storage.list_websocket_events(request_id, Some(2)).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].sequence < events[1].sequence);
        assert_eq!(events[0].payload["index"], 1);
        assert_eq!(events[1].payload["index"], 3);
        assert!(
            storage
                .list_websocket_events(request_id, Some(10_000))
                .unwrap()
                .len()
                <= 2_000
        );
    }

    #[test]
    fn lists_only_ordered_sse_events_with_a_bounded_limit() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();
        let request_id = "request-sse";
        for (phase, index) in [("sse", 1), ("hook", 2), ("sse", 3)] {
            storage
                .append_event(CaptureEventInput {
                    session_id: session.id.clone(),
                    source: "desktop".to_string(),
                    source_instance_id: Some("proxy:127.0.0.1".to_string()),
                    request_id: Some(request_id.to_string()),
                    timestamp: Some(1_785_393_200_000 + index),
                    phase: phase.to_string(),
                    payload: serde_json::json!({ "index": index }),
                })
                .unwrap();
        }

        let events = storage.list_sse_events(request_id, Some(2)).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].sequence < events[1].sequence);
        assert_eq!(events[0].payload["index"], 1);
        assert_eq!(events[1].payload["index"], 3);
        assert!(
            storage
                .list_sse_events(request_id, Some(20_000))
                .unwrap()
                .len()
                <= 2_000
        );
    }

    #[test]
    fn completes_sse_in_place_without_duplicate_session_counts() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();
        let mut streaming = request(session.id.clone(), 200);
        streaming.id = Some("request-streaming".to_string());
        streaming.resource_type = "sse".to_string();
        streaming.size_bytes = 0;
        streaming.duration_ms = 25;
        streaming.response_body = None;
        streaming.response_body_metadata = Some(BodyCaptureMetadata {
            captured: true,
            complete: false,
            ..BodyCaptureMetadata::default()
        });
        let (created, _) = storage.store_request(streaming.clone()).unwrap();
        assert_eq!(created.id, "request-streaming");
        assert_eq!(
            storage.get_request_list_item(&created.id).unwrap().state,
            "streaming"
        );

        streaming.size_bytes = 128;
        streaming.duration_ms = 2_500;
        streaming.response_body = Some("data: complete\n\n".to_string());
        streaming.response_body_metadata = Some(BodyCaptureMetadata {
            captured: true,
            complete: true,
            wire_bytes: 128,
            decoded_bytes: 16,
            format: "text".to_string(),
            ..BodyCaptureMetadata::default()
        });
        let updated = storage
            .update_streaming_request(streaming)
            .unwrap()
            .unwrap();
        assert_eq!(updated.response_body, "data: complete\n\n");
        assert_eq!(updated.duration, 2_500);
        assert!(updated.response_body_metadata.complete);
        assert_eq!(
            storage.get_request_list_item(&updated.id).unwrap().state,
            "complete"
        );

        let counts: (i64, i64) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT request_count FROM sessions WHERE id = ?1",
                        [&session.id],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM capture_events WHERE request_id = ?1 AND phase = 'response'",
                        [&updated.id],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(counts, (1, 1));
    }

    #[test]
    fn correlates_and_persists_complete_browser_hook_chain() {
        let storage = storage();
        let session = storage
            .create_session(Some("Crypto Lab".to_string()))
            .unwrap();
        let timestamp = now_ms() - 1_000;
        let mut input = request(session.id.clone(), 200);
        input.timestamp = Some(timestamp);
        input.method = "POST".to_string();
        input.host = "postman-echo.com".to_string();
        input.path = "/post".to_string();
        let (stored, _) = storage.store_request(input).unwrap();

        let (network, _) = storage
            .store_browser_hook(BrowserHookInput {
                session_id: session.id.clone(),
                source_instance_id: Some("crypto-lab".to_string()),
                request_id: None,
                timestamp: Some(timestamp + 150),
                kind: "network".to_string(),
                name: "fetch".to_string(),
                url: Some("https://postman-echo.com/post".to_string()),
                method: Some("post".to_string()),
                input: serde_json::json!({ "bodyBytes": 128 }),
                output: serde_json::json!({ "status": 200 }),
                stack: None,
                duration_ms: Some(120),
            })
            .unwrap();
        let (crypto, _) = storage
            .store_browser_hook(BrowserHookInput {
                session_id: session.id.clone(),
                source_instance_id: Some("crypto-lab".to_string()),
                request_id: None,
                timestamp: Some(timestamp + 200),
                kind: "crypto".to_string(),
                name: "crypto.subtle.encrypt:AES-GCM".to_string(),
                url: None,
                method: None,
                input: serde_json::json!({
                    "algorithm": "AES-GCM",
                    "password": "must-not-survive"
                }),
                output: serde_json::json!({ "byteLength": 48 }),
                stack: Some("at runCryptoLab".to_string()),
                duration_ms: Some(3),
            })
            .unwrap();

        assert_eq!(network.request_id.as_deref(), Some(stored.id.as_str()));
        assert_eq!(network.correlation, "url-time");
        assert_eq!(crypto.request_id.as_deref(), Some(stored.id.as_str()));
        assert_eq!(crypto.correlation, "time-window");
        assert_eq!(crypto.input["password"], "must-not-survive");

        let hooks = storage.list_browser_hooks(&session.id, None).unwrap();
        let request_hooks = storage
            .list_request_browser_hooks(&stored.id, None)
            .unwrap();
        assert_eq!(hooks.len(), 2);
        assert_eq!(request_hooks.len(), 2);
        assert_eq!(request_hooks[0].name, "fetch");
        assert_eq!(request_hooks[1].name, "crypto.subtle.encrypt:AES-GCM");

        let refreshed = storage
            .list_requests(&session.id, None, None)
            .unwrap()
            .remove(0);
        let legacy = refreshed.hook.expect("crypto summary should be populated");
        assert_eq!(legacy.algorithm, "crypto.subtle.encrypt:AES-GCM");
        assert!(legacy.input.contains("must-not-survive"));

        let (hook_events, migration): (i64, i64) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COUNT(*) FROM capture_events WHERE session_id = ?1 AND phase = 'hook'",
                        [&session.id],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version = 4",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(hook_events, 2);
        assert_eq!(migration, 1);
    }

    #[test]
    fn explicit_browser_hook_request_id_wins_correlation() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();
        let (stored, _) = storage
            .store_request(request(session.id.clone(), 200))
            .unwrap();
        let (hook, _) = storage
            .store_browser_hook(BrowserHookInput {
                session_id: session.id,
                source_instance_id: None,
                request_id: Some(stored.id.clone()),
                timestamp: Some(now_ms()),
                kind: "interaction".to_string(),
                name: "click".to_string(),
                url: Some("https://unrelated.example.test/".to_string()),
                method: None,
                input: serde_json::json!({ "target": "button" }),
                output: Value::Null,
                stack: None,
                duration_ms: None,
            })
            .unwrap();

        assert_eq!(hook.request_id.as_deref(), Some(stored.id.as_str()));
        assert_eq!(hook.correlation, "explicit");
    }

    #[test]
    fn retroactively_correlates_hooks_that_arrive_before_the_request() {
        let storage = storage();
        let session = storage
            .create_session(Some("Late proxy response".to_string()))
            .unwrap();
        let timestamp = now_ms() - 1_000;
        let (network, _) = storage
            .store_browser_hook(BrowserHookInput {
                session_id: session.id.clone(),
                source_instance_id: Some("crypto-lab".to_string()),
                request_id: None,
                timestamp: Some(timestamp),
                kind: "network".to_string(),
                name: "window.fetch".to_string(),
                url: Some("https://postman-echo.com/post".to_string()),
                method: Some("POST".to_string()),
                input: serde_json::json!({ "bodyBytes": 154 }),
                output: Value::Null,
                stack: None,
                duration_ms: None,
            })
            .unwrap();
        let (crypto, _) = storage
            .store_browser_hook(BrowserHookInput {
                session_id: session.id.clone(),
                source_instance_id: Some("crypto-lab".to_string()),
                request_id: None,
                timestamp: Some(timestamp + 50),
                kind: "crypto".to_string(),
                name: "crypto.subtle.encrypt".to_string(),
                url: None,
                method: None,
                input: serde_json::json!({ "algorithm": "AES-GCM" }),
                output: serde_json::json!({ "byteLength": 154 }),
                stack: None,
                duration_ms: Some(3),
            })
            .unwrap();
        assert_eq!(network.correlation, "unmatched");
        assert_eq!(crypto.correlation, "unmatched");

        let mut input = request(session.id.clone(), 200);
        input.timestamp = Some(timestamp + 100);
        input.method = "POST".to_string();
        input.host = "postman-echo.com".to_string();
        input.path = "/post".to_string();
        let (stored, _) = storage.store_request(input).unwrap();

        let hooks = storage
            .list_request_browser_hooks(&stored.id, None)
            .unwrap();
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0].correlation, "url-time");
        assert_eq!(hooks[1].correlation, "time-window");
        assert!(hooks
            .iter()
            .all(|hook| hook.request_id.as_deref() == Some(stored.id.as_str())));
        assert_eq!(
            stored
                .hook
                .expect("crypto summary should be populated")
                .algorithm,
            "crypto.subtle.encrypt"
        );
    }

    #[test]
    fn crypto_hooks_wait_for_the_matching_network_hook_instead_of_background_noise() {
        let storage = storage();
        let session = storage
            .create_session(Some("CDP crypto correlation".to_string()))
            .unwrap();
        let timestamp = now_ms() - 1_000;

        let mut noise = request(session.id.clone(), 200);
        noise.timestamp = Some(timestamp - 400);
        noise.method = "POST".to_string();
        noise.host = "update.googleapis.com".to_string();
        noise.path = "/service/update2/json".to_string();
        let (noise, _) = storage.store_request(noise).unwrap();

        let (crypto, _) = storage
            .store_browser_hook(BrowserHookInput {
                session_id: session.id.clone(),
                source_instance_id: Some("chrome-cdp:42".to_string()),
                request_id: None,
                timestamp: Some(timestamp),
                kind: "crypto".to_string(),
                name: "crypto.subtle.encrypt".to_string(),
                url: Some("http://127.0.0.1/lab/index.html".to_string()),
                method: None,
                input: serde_json::json!({ "algorithm": "AES-GCM" }),
                output: serde_json::json!({ "byteLength": 154 }),
                stack: None,
                duration_ms: Some(3),
            })
            .unwrap();
        assert_eq!(crypto.correlation, "unmatched");

        let mut target = request(session.id.clone(), 200);
        target.timestamp = Some(timestamp + 100);
        target.method = "POST".to_string();
        target.host = "httpbin.org".to_string();
        target.path = "/post".to_string();
        let (target, _) = storage.store_request(target).unwrap();
        assert!(target.hook.is_none());

        let (network, _) = storage
            .store_browser_hook(BrowserHookInput {
                session_id: session.id.clone(),
                source_instance_id: Some("chrome-cdp:42".to_string()),
                request_id: None,
                timestamp: Some(timestamp + 200),
                kind: "network".to_string(),
                name: "window.fetch".to_string(),
                url: Some("https://httpbin.org/post".to_string()),
                method: Some("POST".to_string()),
                input: serde_json::json!({ "bodyBytes": 154 }),
                output: serde_json::json!({ "status": 200 }),
                stack: None,
                duration_ms: Some(120),
            })
            .unwrap();
        assert_eq!(network.request_id.as_deref(), Some(target.id.as_str()));

        let hooks = storage
            .list_request_browser_hooks(&target.id, None)
            .unwrap();
        assert_eq!(hooks.len(), 2);
        assert!(hooks
            .iter()
            .all(|hook| { hook.request_id.as_deref() == Some(target.id.as_str()) }));
        assert!(storage
            .list_request_browser_hooks(&noise.id, None)
            .unwrap()
            .is_empty());
        let refreshed = storage
            .list_requests(&session.id, None, None)
            .unwrap()
            .into_iter()
            .find(|request| request.id == target.id)
            .unwrap();
        assert_eq!(
            refreshed.hook.expect("crypto summary").algorithm,
            "crypto.subtle.encrypt"
        );
    }

    #[test]
    fn persists_structured_tls_fingerprints() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();
        let mut input = request(session.id.clone(), 200);
        input.tls_fingerprint = Some(TlsFingerprintRecord {
            capture_mode: "tunnel".to_string(),
            inbound: ClientTlsFingerprint {
                ja3: "ja3-hash".to_string(),
                ja3_raw: "771,4865,0,29,0".to_string(),
                ja4: "ja4-hash".to_string(),
                ja4_raw: "ja4-raw".to_string(),
                sni: Some("api.example.test".to_string()),
                alpn: vec!["h2".to_string()],
                legacy_version: "TLS 1.2".to_string(),
                offered_versions: vec!["TLS 1.3".to_string()],
                cipher_suites: vec!["1301".to_string()],
                extensions: vec!["0000".to_string()],
                supported_groups: vec!["001d".to_string()],
                signature_algorithms: vec!["0403".to_string()],
                grease: false,
            },
            outbound: OutboundTlsFingerprint {
                mode: "pass-through".to_string(),
                profile: "client-pass-through".to_string(),
                ja3: None,
                note: "tunnel".to_string(),
            },
            http2: None,
        });

        input.tls_fingerprint.as_mut().unwrap().http2 = Some(Http2Fingerprint {
            hash: "h2-hash".to_string(),
            canonical: "settings=1:4096|window=|priority=|priority_update=|pseudo=?".to_string(),
            settings: vec![Http2Setting {
                id: 1,
                name: "HEADER_TABLE_SIZE".to_string(),
                value: 4096,
            }],
            connection_window_updates: vec![],
            priority_frames: vec![],
            priority_updates: vec![],
            pseudo_header_order: None,
            complete: true,
            note: "test".to_string(),
        });

        let (stored, _) = storage.store_request(input).unwrap();
        let fingerprint = stored.tls_fingerprint.unwrap();
        assert_eq!(fingerprint.inbound.ja3, "ja3-hash");
        assert_eq!(fingerprint.inbound.sni.as_deref(), Some("api.example.test"));
        assert_eq!(fingerprint.outbound.mode, "pass-through");
        assert_eq!(fingerprint.http2.unwrap().settings[0].value, 4096);
    }

    #[test]
    fn request_list_distinguishes_mitm_from_tls_tunnels_and_legacy_https() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();

        let legacy = storage
            .store_request(request(session.id.clone(), 200))
            .unwrap()
            .0;

        let mut unrecognized_tunnel = request(session.id.clone(), 200);
        unrecognized_tunnel.method = "CONNECT".to_string();
        unrecognized_tunnel.host = "unknown-tunnel.example".to_string();
        let unrecognized_tunnel = storage.store_request(unrecognized_tunnel).unwrap().0;

        let mut tunnel = request(session.id.clone(), 200);
        tunnel.method = "CONNECT".to_string();
        tunnel.host = "pinned.example".to_string();
        tunnel.tls_fingerprint = Some(tunnel_fingerprint(test_client_tls_fingerprint(
            "pinned.example",
        )));
        let tunnel = storage.store_request(tunnel).unwrap().0;

        let mut mitm = request(session.id, 200);
        mitm.method = "CONNECT".to_string();
        mitm.host = "decoded.example".to_string();
        mitm.tls_fingerprint = Some(mitm_fingerprint(test_client_tls_fingerprint(
            "decoded.example",
        )));
        let mitm = storage.store_request(mitm).unwrap().0;

        assert!(
            storage
                .get_request_list_item(&legacy.id)
                .unwrap()
                .tls_intercepted
        );
        assert!(
            !storage
                .get_request_list_item(&unrecognized_tunnel.id)
                .unwrap()
                .tls_intercepted
        );
        assert!(
            !storage
                .get_request_list_item(&tunnel.id)
                .unwrap()
                .tls_intercepted
        );
        assert!(
            storage
                .get_request_list_item(&mitm.id)
                .unwrap()
                .tls_intercepted
        );
        assert!(request_sort_expression("tlsIntercepted")
            .unwrap()
            .contains("captureMode"));
        assert!(request_filter_expression("tlsIntercepted")
            .unwrap()
            .contains("UPPER(r.method) != 'CONNECT'"));
    }

    #[test]
    fn exports_and_reopens_a_complete_session_bundle() {
        let storage = storage();
        let session = storage
            .create_session(Some("Portable API".to_string()))
            .unwrap();
        let mut input = request(session.id.clone(), 200);
        input.resource_type = "script".to_string();
        input.path = "/assets/sign.js".to_string();
        input.response_headers = vec![HeaderEntry {
            name: "content-type".to_string(),
            value: "application/javascript".to_string(),
        }];
        input.response_body =
            Some("function sign(body, key) { return CryptoJS.HmacSHA256(body, key); }".to_string());
        input.response_body_metadata = Some(BodyCaptureMetadata {
            captured: true,
            content_encoding: Some("gzip".to_string()),
            decoded: true,
            truncated: false,
            complete: true,
            wire_bytes: 31,
            decoded_bytes: 11,
            format: "text".to_string(),
            error: None,
            omitted_reason: None,
        });
        let (stored, _) = storage.store_request(input).unwrap();
        let mut replayed_input = request(session.id.clone(), 201);
        replayed_input.path = "/v1/replayed".to_string();
        replayed_input.request_headers.push(HeaderEntry {
            name: REPLAY_CONTEXT_HEADER.to_string(),
            value: format!("replay-item-export:{}", stored.id),
        });
        let (replayed, _) = storage.store_request(replayed_input).unwrap();
        let rule = storage
            .save_capture_rule(CaptureRuleInput {
                id: None,
                name: "Portable request rule".to_string(),
                enabled: false,
                priority: 10,
                stage: "request".to_string(),
                matcher: FilterExpression::Predicate {
                    field: "host".to_string(),
                    operator: "equals".to_string(),
                    value: Some(Value::String("api.example.test".to_string())),
                },
                action: serde_json::json!({"kind":"delay","latencyMs":20}),
                created_by: "user".to_string(),
            })
            .unwrap();
        storage
            .record_capture_rule_run(&CaptureRuleRun {
                id: format!("rule-run-{}", Uuid::new_v4()),
                request_id: stored.id.clone(),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                revision: rule.revision,
                stage: "request".to_string(),
                result: "applied".to_string(),
                diff_summary: serde_json::json!({"changes":["固定延迟 20ms"]}),
                duration_ms: 1,
                error: None,
                created_at: now_ms(),
            })
            .unwrap();
        storage
            .save_request_annotation(RequestAnnotationInput {
                request_id: stored.id.clone(),
                bookmarked: true,
                color: Some("yellow".to_string()),
                struck_through: false,
                note: "签名逻辑入口".to_string(),
                tags: vec!["crypto".to_string(), "reviewed".to_string()],
            })
            .unwrap();
        storage
            .append_event(CaptureEventInput {
                session_id: session.id.clone(),
                source: "browser".to_string(),
                source_instance_id: Some("tab-1".to_string()),
                request_id: Some(stored.id.clone()),
                timestamp: Some(1_785_393_200_100),
                phase: "hook".to_string(),
                payload: serde_json::json!({
                    "requestId": stored.id,
                    "algorithm": "SHA-256"
                }),
            })
            .unwrap();

        let exported = storage.export_session_bundle(&session.id).unwrap();
        assert_eq!(exported.annotations.len(), 1);
        assert_eq!(exported.annotations[0].note, "签名逻辑入口");
        assert_eq!(exported.rules.len(), 1);
        assert_eq!(exported.rule_traces.len(), 1);
        assert_eq!(
            exported
                .requests
                .iter()
                .find(|request| request.id == replayed.id)
                .unwrap()
                .replayed_from_request_id
                .as_deref(),
            Some(stored.id.as_str())
        );
        let har =
            crate::interchange::render_export(&exported, crate::interchange::ExportFormat::Har)
                .unwrap();
        assert!(har.contains("\"_shownet\""));
        assert!(har.contains("签名逻辑入口"));
        assert!(!har.contains("Portable request rule"));
        let exported_snippets = exported.requests[0].crypto_snippets.clone();
        let encoded = serde_json::to_string(&exported).unwrap();
        let decoded = serde_json::from_str(&encoded).unwrap();
        let imported = storage.import_session_bundle(decoded).unwrap();
        let imported_requests = storage.list_requests(&imported.id, None, None).unwrap();
        let imported_bundle = storage.export_session_bundle(&imported.id).unwrap();
        let imported_snippets = storage
            .get_crypto_snippets(&imported_requests[0].id)
            .unwrap();
        let imported_annotation = storage
            .get_request_annotation(&imported_requests[0].id)
            .unwrap()
            .unwrap();

        assert_eq!(imported.name, "Portable API（导入）");
        assert_eq!(imported_requests.len(), 2);
        assert_eq!(
            imported_requests[0].response_body,
            exported.requests[0].response_body
        );
        assert!(imported_requests[0].response_body_metadata.captured);
        assert!(imported_requests[0].response_body_metadata.decoded);
        assert_eq!(
            imported_requests[0]
                .response_body_metadata
                .content_encoding
                .as_deref(),
            Some("gzip")
        );
        assert_eq!(imported_requests[0].response_body_metadata.wire_bytes, 31);
        assert_eq!(exported_snippets.len(), 1);
        assert_eq!(imported_requests[0].crypto_snippet_count, 1);
        assert_eq!(imported_snippets.len(), 1);
        assert_eq!(imported_bundle.requests[0].crypto_snippets.len(), 1);
        assert_eq!(
            serde_json::to_value(&imported_snippets).unwrap(),
            serde_json::to_value(&exported_snippets).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&imported_bundle.requests[0].crypto_snippets).unwrap(),
            serde_json::to_value(&exported_snippets).unwrap()
        );
        assert_eq!(imported_bundle.events.len(), 3);
        assert_eq!(imported_annotation.note, "签名逻辑入口");
        assert!(imported_annotation.bookmarked);
        assert_eq!(imported_bundle.annotations.len(), 1);
        assert_eq!(imported_bundle.rules.len(), 1);
        assert!(!imported_bundle.rules[0].enabled);
        assert_eq!(imported_bundle.rule_traces.len(), 1);
        let imported_origin = imported_bundle
            .requests
            .iter()
            .find(|request| request.path == "/assets/sign.js")
            .unwrap();
        let imported_replay = imported_bundle
            .requests
            .iter()
            .find(|request| request.path == "/v1/replayed")
            .unwrap();
        let imported_trace = &imported_bundle.rule_traces[0];
        assert_eq!(
            imported_replay.replayed_from_request_id.as_deref(),
            Some(imported_origin.id.as_str())
        );
        assert_eq!(imported_trace.request_id, imported_origin.id);
        assert_eq!(imported_trace.rule_id, imported_bundle.rules[0].id);
        assert_ne!(imported_trace.request_id, stored.id);
        assert_ne!(imported_trace.rule_id, rule.id);
        let hook = imported_bundle
            .events
            .iter()
            .find(|event| event.phase == "hook")
            .unwrap();
        assert_eq!(hook.request_id, imported_requests[0].id);
        assert_eq!(hook.payload["requestId"], imported_requests[0].id);
    }

    #[test]
    fn refuses_to_delete_active_session() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();
        storage.set_active_session(Some(&session.id)).unwrap();
        assert!(storage.delete_session(&session.id).is_err());
        storage.set_active_session(None).unwrap();
        storage.delete_session(&session.id).unwrap();
    }

    #[test]
    fn persists_capture_listener_scope_with_lan_disabled_by_default() {
        let storage = storage();
        assert!(!storage.get_capture_listener_settings().unwrap().lan_enabled);

        let saved = storage
            .save_capture_listener_settings(CaptureListenerSettings {
                lan_enabled: true,
                access_mode: ClientAccessMode::Deny,
                access_rules: vec![
                    " 192.168.8.42 ".to_string(),
                    "192.168.20.12/24".to_string(),
                    "192.168.20.0/24".to_string(),
                ],
            })
            .unwrap();
        assert!(saved.lan_enabled);
        assert_eq!(saved.access_mode, ClientAccessMode::Deny);
        assert_eq!(saved.access_rules, vec!["192.168.8.42", "192.168.20.0/24"]);
        assert_eq!(storage.get_capture_listener_settings().unwrap(), saved);
    }

    #[test]
    fn persists_normalized_tls_interception_settings_in_the_runtime_cache() {
        let storage = storage();
        assert_eq!(
            storage.get_tls_interception_settings().unwrap().mode,
            TlsInterceptionMode::InterceptAll
        );

        let saved = storage
            .save_tls_interception_settings(TlsInterceptionSettings {
                mode: TlsInterceptionMode::BypassSelected,
                bypass: vec![
                    " *.Secure.Example. ".to_string(),
                    "*.secure.example".to_string(),
                    "api.pinned.test".to_string(),
                ],
                show_bypassed_connections: false,
            })
            .unwrap();
        let raw: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [TLS_INTERCEPTION_KEY],
                    |row| row.get(0),
                )
            })
            .unwrap();

        assert_eq!(saved.mode, TlsInterceptionMode::BypassSelected);
        assert_eq!(saved.bypass, vec!["*.secure.example", "api.pinned.test"]);
        assert!(!saved.show_bypassed_connections);
        assert_eq!(storage.get_tls_interception_settings().unwrap(), saved);
        assert!(raw.contains("\"mode\":\"bypass_selected\""));
        assert!(raw.contains("*.secure.example"));
        assert!(raw.contains("\"showBypassedConnections\":false"));
    }

    #[test]
    fn persists_data_storage_settings_and_validates_retention() {
        let storage = storage();
        assert_eq!(
            storage.get_data_storage_settings().unwrap().retention_days,
            30
        );
        assert!(
            !storage
                .get_data_storage_settings()
                .unwrap()
                .save_binary_responses
        );

        let saved = storage
            .save_data_storage_settings(DataStorageSettingsInput {
                auto_cleanup_enabled: false,
                retention_days: 90,
                save_binary_responses: true,
            })
            .unwrap();
        let raw: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [DATA_STORAGE_KEY],
                    |row| row.get(0),
                )
            })
            .unwrap();

        assert!(!saved.auto_cleanup_enabled);
        assert_eq!(saved.retention_days, 90);
        assert!(saved.save_binary_responses);
        assert_eq!(
            storage.get_data_storage_settings().unwrap().retention_days,
            90
        );
        assert!(raw.contains("\"retentionDays\":90"));
        assert!(storage
            .save_data_storage_settings(DataStorageSettingsInput {
                auto_cleanup_enabled: true,
                retention_days: 0,
                save_binary_responses: false,
            })
            .is_err());
    }

    #[test]
    fn persists_reverse_proxy_settings_and_accepts_reverse_capture_source() {
        let storage = Storage::in_memory().unwrap();
        let settings = ReverseProxySettings {
            target_url: "https://api.example.test/v2".to_string(),
            local_port: 9011,
            lan_enabled: true,
            preserve_host: false,
        };
        storage.save_reverse_proxy_settings(&settings).unwrap();
        let restored = storage.get_reverse_proxy_settings().unwrap();
        assert_eq!(restored.target_url, settings.target_url);
        assert_eq!(restored.local_port, 9011);
        assert!(restored.lan_enabled);
        assert!(!restored.preserve_host);

        let session = storage.create_session(Some("reverse".to_string())).unwrap();
        let mut captured = request(session.id.clone(), 200);
        captured.source = "reverse".to_string();
        captured.source_instance_id = Some("reverse:9011".to_string());
        storage.store_request(captured).unwrap();
        assert_eq!(
            storage.get_session(&session.id).unwrap().sources,
            vec!["reverse".to_string()]
        );
    }

    #[test]
    fn applies_binary_response_storage_policy_without_losing_metadata() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();
        let mut omitted_input = request(session.id.clone(), 200);
        omitted_input.response_body = Some("base64:AJ+Slg==".to_string());
        omitted_input.response_body_metadata = Some(BodyCaptureMetadata {
            captured: true,
            wire_bytes: 4,
            decoded_bytes: 4,
            format: "base64".to_string(),
            ..BodyCaptureMetadata::default()
        });
        let (omitted, _) = storage.store_request(omitted_input).unwrap();

        assert!(omitted.response_body.is_empty());
        assert!(!omitted.response_body_metadata.captured);
        assert_eq!(omitted.response_body_metadata.format, "omitted");
        assert_eq!(omitted.response_body_metadata.wire_bytes, 4);
        assert_eq!(
            omitted.response_body_metadata.omitted_reason.as_deref(),
            Some("binary-response-storage-disabled")
        );

        storage
            .save_data_storage_settings(DataStorageSettingsInput {
                auto_cleanup_enabled: true,
                retention_days: 30,
                save_binary_responses: true,
            })
            .unwrap();
        let mut retained_input = request(session.id.clone(), 200);
        retained_input.response_body = Some("base64:AJ+Slg==".to_string());
        retained_input.response_body_metadata = Some(BodyCaptureMetadata {
            captured: true,
            wire_bytes: 4,
            decoded_bytes: 4,
            format: "base64".to_string(),
            ..BodyCaptureMetadata::default()
        });
        let (retained, _) = storage.store_request(retained_input).unwrap();
        assert_eq!(retained.response_body, "base64:AJ+Slg==");
        assert!(retained.response_body_metadata.captured);
        assert!(retained.response_body_metadata.omitted_reason.is_none());
    }

    #[test]
    fn cleanup_removes_only_expired_idle_sessions() {
        let storage = storage();
        let expired = storage.create_session(Some("expired".to_string())).unwrap();
        let recent = storage.create_session(Some("recent".to_string())).unwrap();
        let active = storage.create_session(Some("active".to_string())).unwrap();
        storage.set_active_session(Some(&active.id)).unwrap();
        let old_timestamp = now_ms() - 31 * 24 * 60 * 60 * 1_000;
        storage
            .with_connection(|connection| {
                connection.execute(
                    "UPDATE sessions SET updated_at = ?1 WHERE id IN (?2, ?3)",
                    params![old_timestamp, expired.id, active.id],
                )?;
                Ok(())
            })
            .unwrap();

        let removed = storage.cleanup_expired_sessions().unwrap();
        assert_eq!(removed, 1);
        assert!(storage.get_session(&expired.id).is_err());
        assert!(storage.get_session(&recent.id).is_ok());
        assert!(storage.get_session(&active.id).unwrap().active);
    }

    #[test]
    fn clear_all_sessions_preserves_settings_and_creates_a_fresh_session() {
        let storage = storage();
        storage
            .save_capture_listener_settings(CaptureListenerSettings {
                lan_enabled: true,
                ..CaptureListenerSettings::default()
            })
            .unwrap();
        storage
            .save_data_storage_settings(DataStorageSettingsInput {
                auto_cleanup_enabled: false,
                retention_days: 45,
                save_binary_responses: true,
            })
            .unwrap();
        let session = storage
            .create_session(Some("to clear".to_string()))
            .unwrap();
        storage.store_request(request(session.id, 200)).unwrap();
        let settings_before = storage
            .with_connection(|connection| {
                connection.query_row("SELECT COUNT(*) FROM app_settings", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .unwrap();

        let fresh = storage.clear_all_session_data().unwrap();
        let stats = storage.storage_stats().unwrap();
        let settings_after = storage
            .with_connection(|connection| {
                connection.query_row("SELECT COUNT(*) FROM app_settings", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .unwrap();

        assert_eq!(stats.session_count, 1);
        assert_eq!(stats.request_count, 0);
        assert_eq!(fresh.name, "首次抓包");
        assert_eq!(settings_before, settings_after);
        assert!(storage.get_capture_listener_settings().unwrap().lan_enabled);
        assert_eq!(
            storage.get_data_storage_settings().unwrap().retention_days,
            45
        );
    }

    #[test]
    fn storage_stats_reflect_database_rows_and_stored_response_bytes() {
        let storage = storage();
        let session = storage.create_session(None).unwrap();
        storage.store_request(request(session.id, 200)).unwrap();

        let stats = storage.storage_stats().unwrap();
        assert_eq!(stats.session_count, 1);
        assert_eq!(stats.request_count, 1);
        assert_eq!(stats.response_body_bytes, 11);
        assert!(stats.database_bytes > 0);
        assert_eq!(stats.database_path, ":memory:");
    }

    #[test]
    fn encrypts_upstream_proxy_password_inside_sqlite() {
        let storage = storage();
        let saved = storage
            .save_upstream_proxy_settings(UpstreamProxySettingsInput {
                mode: "socks5".to_string(),
                host: "127.0.0.1".to_string(),
                port: 7890,
                username: "shownet".to_string(),
                password: Some("never-store-plaintext".to_string()),
                clear_password: false,
                bypass: vec!["LOCALHOST".to_string(), " localhost ".to_string()],
            })
            .unwrap();

        let raw: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [UPSTREAM_PROXY_KEY],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert!(saved.has_password);
        assert_eq!(saved.bypass, vec!["localhost"]);
        assert!(!raw.contains("never-store-plaintext"));
        assert_eq!(
            storage.upstream_proxy_password().unwrap().as_deref(),
            Some("never-store-plaintext")
        );
    }

    #[test]
    fn encrypts_ai_api_key_inside_sqlite() {
        let storage = storage();
        let saved = storage
            .save_ai_provider_settings(AiProviderSettingsInput {
                provider: "claudegpt".to_string(),
                base_url: "https://claudegpt.org/v1/".to_string(),
                model: "gpt-5.6-sol".to_string(),
                api_key: Some("ai-key-must-not-be-plaintext".to_string()),
                clear_api_key: false,
            })
            .unwrap();
        let raw: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [AI_PROVIDER_KEY],
                    |row| row.get(0),
                )
            })
            .unwrap();
        let effective = storage.effective_ai_provider_settings().unwrap();

        assert!(saved.has_api_key);
        assert_eq!(saved.base_url, "https://claudegpt.org/v1");
        assert!(!raw.contains("ai-key-must-not-be-plaintext"));
        assert_eq!(
            effective.api_key.as_deref(),
            Some("ai-key-must-not-be-plaintext")
        );
    }

    #[test]
    fn persists_ai_analysis_settings_with_enabled_defaults() {
        let storage = storage();
        let defaults = storage.get_ai_analysis_settings().unwrap();
        assert!(defaults.two_stage_analysis);
        assert!(defaults.allow_mcp_tools);
        assert!(defaults.streaming_output);
        assert_eq!(defaults.max_agent_turns, 8);

        let saved = storage
            .save_ai_analysis_settings(AiAnalysisSettings {
                two_stage_analysis: false,
                allow_mcp_tools: false,
                streaming_output: false,
                max_agent_turns: 128,
            })
            .unwrap();
        assert!(!saved.two_stage_analysis);
        assert!(!saved.allow_mcp_tools);
        assert!(!saved.streaming_output);
        assert_eq!(saved.max_agent_turns, 128);
        assert!(!storage.get_ai_analysis_settings().unwrap().streaming_output);

        let normalized = storage
            .save_ai_analysis_settings(AiAnalysisSettings {
                max_agent_turns: 0,
                ..AiAnalysisSettings::default()
            })
            .unwrap();
        assert_eq!(normalized.max_agent_turns, 1);
    }

    #[test]
    fn keeps_ai_api_key_only_when_the_base_url_is_unchanged() {
        let storage = storage();
        storage
            .save_ai_provider_settings(AiProviderSettingsInput {
                provider: "claudegpt".to_string(),
                base_url: "https://claudegpt.org/v1".to_string(),
                model: "gpt-5.5".to_string(),
                api_key: Some("endpoint-bound-key".to_string()),
                clear_api_key: false,
            })
            .unwrap();

        let same_endpoint = storage
            .save_ai_provider_settings(AiProviderSettingsInput {
                provider: "claudegpt".to_string(),
                base_url: "https://claudegpt.org/v1/".to_string(),
                model: "gpt-5.5".to_string(),
                api_key: None,
                clear_api_key: false,
            })
            .unwrap();
        assert!(same_endpoint.has_api_key);

        let different_endpoint = storage
            .save_ai_provider_settings(AiProviderSettingsInput {
                provider: "compatible".to_string(),
                base_url: "https://api.example.com/v1".to_string(),
                model: "example-model".to_string(),
                api_key: None,
                clear_api_key: false,
            })
            .unwrap();
        assert!(!different_endpoint.has_api_key);
        assert!(storage
            .effective_ai_provider_settings()
            .unwrap()
            .api_key
            .is_none());
    }

    #[test]
    fn encrypts_system_proxy_recovery_and_keeps_loopback_bypassed() {
        let storage = storage();
        let preferences = storage
            .save_system_proxy_preferences(SystemProxySettingsInput {
                enabled: true,
                bypass: vec!["example.internal".to_string()],
            })
            .unwrap();
        assert!(preferences.enabled);
        for required in ["localhost", "127.0.0.1", "::1", "*.local"] {
            assert!(preferences.bypass.iter().any(|value| value == required));
        }

        let snapshot = SystemProxySnapshot::Windows(crate::system_proxy::WindowsProxySnapshot {
            proxy_enable: Some("0x0".to_string()),
            proxy_server: Some("private-proxy.example:8443".to_string()),
            proxy_override: Some("localhost;<local>".to_string()),
            auto_config_url: Some("https://private.example/proxy.pac".to_string()),
        });
        storage.save_system_proxy_recovery(&snapshot).unwrap();

        let raw: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [SYSTEM_PROXY_RECOVERY_KEY],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert!(!raw.contains("private-proxy.example"));
        assert!(!raw.contains("private.example/proxy.pac"));
        assert_eq!(storage.get_system_proxy_recovery().unwrap(), Some(snapshot));
        assert!(storage.has_system_proxy_recovery().unwrap());
        storage.clear_system_proxy_recovery().unwrap();
        assert!(!storage.has_system_proxy_recovery().unwrap());
    }

    #[test]
    fn encrypts_and_rotates_mcp_access_token_inside_sqlite() {
        let storage = storage();
        let settings = storage.ensure_mcp_server_settings().unwrap();
        let first = storage.reveal_mcp_access_token().unwrap();
        let raw: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [MCP_SERVER_KEY],
                    |row| row.get(0),
                )
            })
            .unwrap();
        let second = storage.rotate_mcp_access_token().unwrap();

        assert!(settings.enabled);
        assert!(!settings.allow_writes);
        assert!(settings.has_access_token);
        assert!(first.starts_with("shownet_mcp_"));
        assert!(!raw.contains(&first));
        assert_ne!(first, second);
        assert_eq!(storage.reveal_mcp_access_token().unwrap(), second);
    }

    #[test]
    fn encrypts_external_mcp_tokens_and_clears_them_when_endpoint_changes() {
        let storage = storage();
        let secret = "external-mcp-secret";
        let saved = storage
            .save_mcp_client_settings(McpClientSettingsInput {
                id: None,
                name: "Local Evidence".to_string(),
                endpoint: "http://127.0.0.1:9000/mcp".to_string(),
                enabled: true,
                access_token: Some(secret.to_string()),
                clear_access_token: false,
            })
            .unwrap();
        assert!(saved.has_access_token);
        assert_eq!(
            storage
                .effective_mcp_client(&saved.id)
                .unwrap()
                .access_token
                .as_deref(),
            Some(secret)
        );
        let raw: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT value_json FROM app_settings WHERE key = ?1",
                    [MCP_CLIENTS_KEY],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert!(!raw.contains(secret));

        let changed = storage
            .save_mcp_client_settings(McpClientSettingsInput {
                id: Some(saved.id.clone()),
                name: saved.name,
                endpoint: "http://127.0.0.1:9001/mcp".to_string(),
                enabled: false,
                access_token: None,
                clear_access_token: false,
            })
            .unwrap();
        assert!(!changed.has_access_token);
        assert!(storage.effective_mcp_clients().unwrap().is_empty());
    }

    #[test]
    fn rejects_mcp_self_loops_and_audits_external_tool_calls() {
        let storage = storage();
        storage.ensure_mcp_server_settings().unwrap();
        let result = storage.save_mcp_client_settings(McpClientSettingsInput {
            id: None,
            name: "Self".to_string(),
            endpoint: "http://127.0.0.1:8899/mcp".to_string(),
            enabled: true,
            access_token: None,
            clear_access_token: false,
        });
        assert!(result.is_err());

        let log_id = storage
            .begin_mcp_client_log("mcp-client-test", "lookup")
            .unwrap();
        storage
            .finish_mcp_client_log(&log_id, "complete", None)
            .unwrap();
        let (status, migration): (String, i64) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT status FROM mcp_client_logs WHERE id = ?1",
                        [&log_id],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version = 7",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(status, "complete");
        assert_eq!(migration, 1);
    }

    #[test]
    fn rejects_upstream_proxy_loop() {
        let storage = storage();
        let result = storage.save_upstream_proxy_settings(UpstreamProxySettingsInput {
            mode: "http".to_string(),
            host: "127.0.0.1".to_string(),
            port: 8888,
            username: String::new(),
            password: None,
            clear_password: false,
            bypass: vec![],
        });
        assert!(result.is_err());
    }

    #[test]
    fn replay_batches_enforce_limits_and_link_captured_results() {
        let storage = storage();
        let session = storage.create_session(Some("Replay".into())).unwrap();
        let (source, _) = storage
            .store_request(request(session.id.clone(), 200))
            .unwrap();
        let batch = storage
            .create_replay_batch(&ReplayBatchInput {
                session_id: session.id.clone(),
                request_ids: vec![source.id.clone()],
                settings: crate::models::ReplaySettings::default(),
                confirmed_large_batch: false,
            })
            .unwrap();
        assert_eq!(batch.total, 1);
        let item = &batch.items[0];
        let mut replayed = request(session.id.clone(), 201);
        replayed.request_headers.push(HeaderEntry {
            name: REPLAY_CONTEXT_HEADER.into(),
            value: format!("{}:{}", item.id, source.id),
        });
        let (captured, _) = storage.store_request(replayed).unwrap();
        let linked: (Option<String>, Option<String>, String) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT replayed_from_request_id FROM requests WHERE id=?1",
                        [&captured.id],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT captured_request_id FROM replay_batch_items WHERE id=?1",
                        [&item.id],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT request_headers_json FROM requests WHERE id=?1",
                        [&captured.id],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(linked.0.as_deref(), Some(source.id.as_str()));
        assert_eq!(linked.1.as_deref(), Some(captured.id.as_str()));
        assert!(!linked.2.contains(REPLAY_CONTEXT_HEADER));

        let mut oversized = crate::models::ReplaySettings::default();
        oversized.repeat_count = 101;
        assert!(storage
            .create_replay_batch(&ReplayBatchInput {
                session_id: session.id,
                request_ids: vec![source.id],
                settings: oversized,
                confirmed_large_batch: true,
            })
            .is_err());
    }

    #[test]
    fn encrypts_environment_secrets_and_request_draft_auth() {
        let storage = storage();
        let environment = storage
            .save_environment(EnvironmentInput {
                id: None,
                name: "Production".into(),
                kind: "named".into(),
                active: true,
            })
            .unwrap();
        storage
            .save_environment_variable(EnvironmentVariableInput {
                id: None,
                environment_id: environment.id.clone(),
                name: "token".into(),
                value: Some("environment-secret-value".into()),
                secret: true,
                clear_value: false,
                enabled: true,
            })
            .unwrap();
        let raw_environment: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT encrypted_value FROM environment_variables WHERE environment_id=?1",
                    [&environment.id],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert!(!raw_environment.contains("environment-secret-value"));
        assert_eq!(
            storage
                .effective_environment_values(Some(&environment.id))
                .unwrap()[0]
                .1,
            "environment-secret-value"
        );
        let masked_environment = storage.get_environment(&environment.id).unwrap();
        assert_eq!(masked_environment.variables[0].value, "••••••••");
        assert_eq!(
            storage
                .reveal_environment_variable(&masked_environment.variables[0].id)
                .unwrap(),
            "environment-secret-value"
        );
        let exported_environment = storage
            .export_environment_snapshot(&environment.id)
            .unwrap();
        assert_eq!(exported_environment.source_id, environment.id);
        assert!(exported_environment.variables.iter().any(|variable| {
            variable.name == "token"
                && variable.value == "environment-secret-value"
                && variable.secret
        }));

        let draft = storage
            .save_request_draft(RequestDraftInput {
                id: None,
                session_id: None,
                source_request_id: None,
                name: "Auth request".into(),
                method: "GET".into(),
                url: "https://api.example.test/v1".into(),
                headers: vec![],
                body: String::new(),
                body_type: "none".into(),
                auth: serde_json::json!({"kind":"bearer","token":"draft-auth-secret"}),
                settings: serde_json::json!({}),
                environment_id: Some(environment.id),
                collection_id: None,
                folder_id: None,
                tags: vec![],
            })
            .unwrap();
        assert_eq!(
            draft.auth.get("hasSecret").and_then(Value::as_bool),
            Some(true)
        );
        assert!(draft.auth.get("token").is_none());
        let raw_auth: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT auth_json FROM request_drafts WHERE id=?1",
                    [&draft.id],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert!(!raw_auth.contains("draft-auth-secret"));
        assert_eq!(
            storage.get_request_draft_for_send(&draft.id).unwrap().auth["token"],
            "draft-auth-secret"
        );
    }

    #[test]
    fn collection_defaults_encrypt_auth_and_follow_the_active_environment() {
        let storage = storage();
        let environment = storage
            .save_environment(EnvironmentInput {
                id: None,
                name: "Staging".into(),
                kind: "named".into(),
                active: true,
            })
            .unwrap();
        storage
            .save_environment_variable(EnvironmentVariableInput {
                id: None,
                environment_id: environment.id.clone(),
                name: "tenant".into(),
                value: Some("north".into()),
                secret: false,
                clear_value: false,
                enabled: true,
            })
            .unwrap();
        assert_eq!(
            storage
                .resolve_effective_environment_id(None)
                .unwrap()
                .as_deref(),
            Some(environment.id.as_str())
        );
        assert!(storage
            .effective_environment_values(None)
            .unwrap()
            .iter()
            .any(|(name, value, _)| name == "tenant" && value == "north"));

        let saved = storage
            .save_request_collection(RequestCollectionInput {
                id: None,
                name: "Shop API".into(),
                description: "Staging requests".into(),
                default_headers: vec![HeaderEntry {
                    name: "X-Tenant".into(),
                    value: "{{tenant}}".into(),
                }],
                default_auth: serde_json::json!({"kind":"bearer","token":"collection-auth-secret"}),
                default_environment_id: Some(environment.id.clone()),
            })
            .unwrap();
        assert_eq!(saved.default_auth["kind"], "bearer");
        assert_eq!(saved.default_auth["hasSecret"], true);
        assert!(saved.default_auth.get("token").is_none());
        let raw_auth: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT default_auth_json FROM request_collections WHERE id=?1",
                    [&saved.id],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert!(!raw_auth.contains("collection-auth-secret"));
        assert_eq!(
            storage
                .get_request_collection_for_send(&saved.id)
                .unwrap()
                .default_auth["token"],
            "collection-auth-secret"
        );

        storage
            .save_request_collection(RequestCollectionInput {
                id: Some(saved.id.clone()),
                name: "Shop API v2".into(),
                description: saved.description,
                default_headers: saved.default_headers,
                default_auth: saved.default_auth,
                default_environment_id: saved.default_environment_id,
            })
            .unwrap();
        let restored = storage.get_request_collection_for_send(&saved.id).unwrap();
        assert_eq!(restored.name, "Shop API v2");
        assert_eq!(restored.default_auth["token"], "collection-auth-secret");
        let header_auth = storage
            .save_request_collection(RequestCollectionInput {
                id: None,
                name: "Header Auth".into(),
                description: String::new(),
                default_headers: vec![HeaderEntry {
                    name: "Authorization".into(),
                    value: "plaintext".into(),
                }],
                default_auth: serde_json::json!({"kind":"none"}),
                default_environment_id: None,
            })
            .unwrap();
        assert_eq!(header_auth.default_headers[0].value, "plaintext");
        let migration: i64 = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE version=18",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(migration, 1);
    }

    #[test]
    fn encrypts_and_restores_request_cookie_jar() {
        let storage = storage();
        let request_url = url::Url::parse("https://api.example.test/login").unwrap();
        let mut jar = CookieStore::default();
        let cookie = cookie_store::RawCookie::parse(
            "shownet_session=private-cookie-value; Path=/; Secure; HttpOnly",
        )
        .unwrap()
        .into_owned();
        jar.store_response_cookies(std::iter::once(cookie), &request_url);

        storage.save_request_cookie_store(&jar).unwrap();
        let raw_setting: String = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT value_json FROM app_settings WHERE key=?1",
                    [REQUEST_COOKIE_JAR_KEY],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert!(!raw_setting.contains("private-cookie-value"));

        let restored = storage.load_request_cookie_store().unwrap();
        assert_eq!(
            restored
                .get_request_values(&url::Url::parse("https://api.example.test/account").unwrap())
                .collect::<Vec<_>>(),
            vec![("shownet_session", "private-cookie-value")]
        );
        assert_eq!(restored.iter_unexpired().count(), 1);
    }

    #[test]
    fn request_collection_import_preserves_complete_drafts_and_environments() {
        let storage = storage();
        let imported = storage
            .import_request_collection(CollectionImportCommitInput {
                collection_id: None,
                collection_name: "Shop API".into(),
                collection: Some(CollectionImportMetadata {
                    description: "Imported private collection metadata".into(),
                    default_headers: vec![HeaderEntry {
                        name: "Authorization".into(),
                        value: "Bearer collection-header-secret".into(),
                    }],
                    default_auth: serde_json::json!({"kind":"bearer","token":"collection-auth-secret"}),
                    default_environment_id: Some("imported-environment".into()),
                    source_format: Some("openapi".into()),
                    source_path: Some("/private/specs/shop.openapi.yaml".into()),
                    source_fingerprint: Some("private-source-fingerprint".into()),
                    source_synced_at: Some(1_234),
                }),
                environments: vec![CollectionImportEnvironment {
                    source_id: "imported-environment".into(),
                    name: "Imported Production".into(),
                    variables: vec![
                        CollectionImportEnvironmentVariable {
                            name: "token".into(),
                            value: "environment-secret-value".into(),
                            secret: true,
                            enabled: true,
                        },
                        CollectionImportEnvironmentVariable {
                            name: "tenant".into(),
                            value: "north".into(),
                            secret: false,
                            enabled: true,
                        },
                    ],
                }],
                source_format: None,
                source_path: None,
                source_fingerprint: None,
                items: vec![
                    CollectionImportItem {
                        name: "List products".into(),
                        method: "GET".into(),
                        url: "https://api.example.test/products?token=secret".into(),
                        headers: vec![
                            HeaderEntry {
                                name: "Authorization".into(),
                                value: "Bearer secret".into(),
                            },
                            HeaderEntry {
                                name: "Accept".into(),
                                value: "application/json".into(),
                            },
                        ],
                        body: String::new(),
                        body_type: "none".into(),
                        auth: serde_json::json!({"kind":"bearer","token":"imported-auth-token"}),
                        settings: serde_json::json!({"cookieJar":true,"followRedirects":true,"verifyTls":true,"privateSetting":"settings-secret"}),
                        environment_id: Some("imported-environment".into()),
                        tags: vec!["auth".into()],
                        folder_path: vec!["Catalog".into(), "Public".into()],
                        source_key: None,
                        source_fingerprint: None,
                    },
                    CollectionImportItem {
                        name: "Create product".into(),
                        method: "POST".into(),
                        url: "https://api.example.test/products".into(),
                        headers: vec![],
                        body: r#"{"name":"demo"}"#.into(),
                        body_type: "json".into(),
                        auth: serde_json::json!({"kind":"none"}),
                        settings: serde_json::json!({"cookieJar":false,"followRedirects":true,"verifyTls":true}),
                        environment_id: None,
                        tags: vec!["write".into()],
                        folder_path: vec!["Catalog".into(), "Public".into()],
                        source_key: None,
                        source_fingerprint: None,
                    },
                ],
            })
            .unwrap();
        assert_eq!(imported.imported_count, 2);
        assert_eq!(imported.created_folder_count, 2);
        assert_eq!(imported.imported_environment_count, 1);
        assert_eq!(
            imported.collection.description,
            "Imported private collection metadata"
        );
        assert_eq!(
            imported.collection.default_headers[0].value,
            "Bearer collection-header-secret"
        );
        assert_eq!(imported.collection.default_auth["hasSecret"], true);
        assert_eq!(
            imported.collection.source_format.as_deref(),
            Some("openapi")
        );
        assert_eq!(
            imported.collection.source_path.as_deref(),
            Some("/private/specs/shop.openapi.yaml")
        );
        assert_eq!(
            imported.collection.source_fingerprint.as_deref(),
            Some("private-source-fingerprint")
        );
        assert_eq!(imported.collection.source_synced_at, Some(1_234));
        assert_eq!(
            storage
                .get_request_collection_for_send(&imported.collection.id)
                .unwrap()
                .default_auth["token"],
            "collection-auth-secret"
        );

        let workspace = storage.list_request_collection_workspace().unwrap();
        assert_eq!(workspace.collections[0].draft_count, 2);
        let public_folder = workspace
            .folders
            .iter()
            .find(|folder| folder.name == "Public")
            .unwrap();
        assert_eq!(public_folder.depth, 2);
        let list_draft = workspace
            .drafts
            .iter()
            .find(|draft| draft.name == "List products")
            .unwrap();
        let create_draft = workspace
            .drafts
            .iter()
            .find(|draft| draft.name == "Create product")
            .unwrap();
        assert_eq!(list_draft.headers.len(), 2);
        assert!(list_draft.url.contains("token=secret"));
        assert_eq!(list_draft.auth["hasSecret"], true);
        assert_eq!(list_draft.settings["cookieJar"], true);
        assert_eq!(list_draft.settings["privateSetting"], "settings-secret");
        let imported_environment_id = list_draft.environment_id.as_deref().unwrap();
        assert_ne!(imported_environment_id, "imported-environment");
        assert!(imported_environment_id.starts_with("environment-"));
        assert_eq!(
            imported.collection.default_environment_id.as_deref(),
            Some(imported_environment_id)
        );
        let environment_values = storage
            .effective_environment_values(Some(imported_environment_id))
            .unwrap();
        assert!(environment_values.iter().any(|(name, value, secret)| {
            name == "token" && value == "environment-secret-value" && *secret
        }));
        assert!(environment_values
            .iter()
            .any(|(name, value, secret)| { name == "tenant" && value == "north" && !*secret }));
        let raw_environment: (Option<String>, Option<String>) = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT value,encrypted_value FROM environment_variables WHERE environment_id=?1 AND name='token'",
                    [imported_environment_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
            })
            .unwrap();
        assert!(raw_environment.0.is_none());
        assert!(!raw_environment
            .1
            .unwrap()
            .contains("environment-secret-value"));
        assert_eq!(list_draft.tags, vec!["auth"]);
        assert_eq!(
            storage
                .get_request_draft_for_send(&list_draft.id)
                .unwrap()
                .auth["token"],
            "imported-auth-token"
        );
        let draft_ids = vec![list_draft.id.clone(), create_draft.id.clone()];

        let moved = storage
            .move_request_draft(RequestDraftLocationInput {
                draft_id: list_draft.id.clone(),
                collection_id: Some(imported.collection.id.clone()),
                folder_id: None,
            })
            .unwrap();
        assert_eq!(
            moved.collection_id.as_deref(),
            Some(imported.collection.id.as_str())
        );
        assert!(moved.folder_id.is_none());

        storage
            .delete_request_collection_folder(&public_folder.id)
            .unwrap();
        let retained = storage.get_request_draft(&create_draft.id).unwrap();
        assert_eq!(
            retained.collection_id.as_deref(),
            Some(imported.collection.id.as_str())
        );
        assert!(retained.folder_id.is_none());

        storage
            .delete_request_collection(&imported.collection.id)
            .unwrap();
        for draft_id in draft_ids {
            let retained = storage.get_request_draft(&draft_id).unwrap();
            assert!(retained.collection_id.is_none());
            assert!(retained.folder_id.is_none());
        }
    }

    #[test]
    fn importing_into_existing_collection_keeps_defaults_and_preserves_request_credentials() {
        let storage = storage();
        let item = |name: &str, credential: &str, environment_id: &str| CollectionImportItem {
            name: name.into(),
            method: "POST".into(),
            url: format!(
                "https://developer:url-{credential}@api.example.test/login?token={credential}"
            ),
            headers: vec![
                HeaderEntry {
                    name: "Authorization".into(),
                    value: format!("Bearer {credential}"),
                },
                HeaderEntry {
                    name: "Cookie".into(),
                    value: format!("session={credential}"),
                },
            ],
            body: format!(r#"{{"password":"{credential}"}}"#),
            body_type: "json".into(),
            auth: serde_json::json!({"kind":"bearer","token":credential}),
            settings: serde_json::json!({"cookieJar":true,"privateSetting":credential}),
            environment_id: Some(environment_id.into()),
            tags: vec!["auth".into()],
            folder_path: vec![],
            source_key: None,
            source_fingerprint: None,
        };
        let environment = |source_id: &str, value: &str| CollectionImportEnvironment {
            source_id: source_id.into(),
            name: source_id.into(),
            variables: vec![CollectionImportEnvironmentVariable {
                name: "token".into(),
                value: value.into(),
                secret: true,
                enabled: true,
            }],
        };

        let original = storage
            .import_request_collection(CollectionImportCommitInput {
                collection_id: None,
                collection_name: "Existing API".into(),
                items: vec![item("Original request", "original-request-secret", "original-env")],
                collection: Some(CollectionImportMetadata {
                    description: "Original description".into(),
                    default_headers: vec![HeaderEntry {
                        name: "X-Collection-Key".into(),
                        value: "original-header-secret".into(),
                    }],
                    default_auth: serde_json::json!({"kind":"bearer","token":"original-auth-secret"}),
                    default_environment_id: Some("original-env".into()),
                    source_format: Some("shownet".into()),
                    source_path: Some("/private/original.shownet.json".into()),
                    source_fingerprint: Some("original-source-fingerprint".into()),
                    source_synced_at: Some(1_000),
                }),
                environments: vec![environment("original-env", "original-environment-secret")],
                source_format: Some("shownet".into()),
                source_path: None,
                source_fingerprint: None,
            })
            .unwrap();
        let original_environment_id = original.collection.default_environment_id.clone().unwrap();

        let appended = storage
            .import_request_collection(CollectionImportCommitInput {
                collection_id: Some(original.collection.id.clone()),
                collection_name: "Ignored imported name".into(),
                items: vec![item("Imported request", "incoming-request-secret", "incoming-env")],
                collection: Some(CollectionImportMetadata {
                    description: "Incoming description".into(),
                    default_headers: vec![HeaderEntry {
                        name: "X-Collection-Key".into(),
                        value: "incoming-header-secret".into(),
                    }],
                    default_auth: serde_json::json!({"kind":"bearer","token":"incoming-auth-secret"}),
                    default_environment_id: Some("incoming-env".into()),
                    source_format: Some("postman".into()),
                    source_path: Some("/private/incoming.postman.json".into()),
                    source_fingerprint: Some("incoming-source-fingerprint".into()),
                    source_synced_at: Some(2_000),
                }),
                environments: vec![environment("incoming-env", "incoming-environment-secret")],
                source_format: Some("postman".into()),
                source_path: None,
                source_fingerprint: None,
            })
            .unwrap();

        assert_eq!(appended.imported_count, 1);
        assert_eq!(appended.imported_environment_count, 1);
        assert_eq!(appended.collection.name, "Existing API");
        assert_eq!(appended.collection.description, "Original description");
        assert_eq!(
            appended.collection.default_headers[0].value,
            "original-header-secret"
        );
        assert_eq!(
            appended.collection.default_environment_id.as_deref(),
            Some(original_environment_id.as_str())
        );
        assert_eq!(
            appended.collection.source_format.as_deref(),
            Some("shownet")
        );
        assert_eq!(
            appended.collection.source_path.as_deref(),
            Some("/private/original.shownet.json")
        );
        assert_eq!(
            appended.collection.source_fingerprint.as_deref(),
            Some("original-source-fingerprint")
        );
        assert_eq!(appended.collection.source_synced_at, Some(1_000));
        assert_eq!(
            storage
                .get_request_collection_for_send(&appended.collection.id)
                .unwrap()
                .default_auth["token"],
            "original-auth-secret"
        );

        let imported_draft = storage
            .list_request_collection_workspace()
            .unwrap()
            .drafts
            .into_iter()
            .find(|draft| draft.name == "Imported request")
            .unwrap();
        assert!(imported_draft.url.contains("url-incoming-request-secret@"));
        assert!(imported_draft.url.contains("token=incoming-request-secret"));
        assert!(imported_draft
            .headers
            .iter()
            .any(|header| header.value == "Bearer incoming-request-secret"));
        assert!(imported_draft
            .headers
            .iter()
            .any(|header| header.value == "session=incoming-request-secret"));
        assert!(imported_draft.body.contains("incoming-request-secret"));
        assert_eq!(
            imported_draft.settings["privateSetting"],
            "incoming-request-secret"
        );
        assert_ne!(
            imported_draft.environment_id.as_deref(),
            Some(original_environment_id.as_str())
        );
        assert_eq!(
            storage
                .get_request_draft_for_send(&imported_draft.id)
                .unwrap()
                .auth["token"],
            "incoming-request-secret"
        );
        assert!(storage
            .effective_environment_values(imported_draft.environment_id.as_deref())
            .unwrap()
            .iter()
            .any(|(name, value, secret)| name == "token"
                && value == "incoming-environment-secret"
                && *secret));
    }

    #[test]
    fn unknown_auth_and_runtime_credentials_survive_storage_and_postman_reexport() {
        let storage = storage();
        let path = std::env::temp_dir().join(format!(
            "shownet-postman-auth-roundtrip-{}.json",
            Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            serde_json::json!({
                "info":{"name":"Credential round trip"},
                "item":[{"name":"Digest login","request":{
                    "method":"POST",
                    "url":"https://developer:url-password@api.example.test/login?access_token=query-secret",
                    "header":[
                        {"key":"Authorization","value":"Digest header-secret"},
                        {"key":"Cookie","value":"session=cookie-secret"}
                    ],
                    "auth":{"type":"digest","digest":[
                        {"key":"username","value":"developer"},
                        {"key":"password","value":"digest-password-secret"},
                        {"key":"clientSecret","value":"oauth-client-secret"}
                    ]},
                    "body":{"mode":"raw","raw":"{\"password\":\"body-password-secret\"}","options":{"raw":{"language":"json"}}}
                }}]
            })
            .to_string(),
        )
        .unwrap();
        let preview =
            crate::request_collections::preview_import_path(path.to_str().unwrap()).unwrap();
        let imported = storage
            .import_request_collection(CollectionImportCommitInput {
                collection_id: None,
                collection_name: preview.suggested_name,
                items: preview.items,
                collection: preview.collection,
                environments: preview.environments,
                source_format: Some(preview.source_format),
                source_path: preview.source_path,
                source_fingerprint: preview.source_fingerprint,
            })
            .unwrap();
        let draft = storage
            .list_request_collection_workspace()
            .unwrap()
            .drafts
            .into_iter()
            .find(|draft| draft.collection_id.as_deref() == Some(imported.collection.id.as_str()))
            .unwrap();
        let draft = storage.get_request_draft_for_send(&draft.id).unwrap();
        assert!(draft.url.contains("developer:url-password@"));
        assert!(draft.url.contains("access_token=query-secret"));
        assert!(draft
            .headers
            .iter()
            .any(|header| header.value == "Digest header-secret"));
        assert!(draft
            .headers
            .iter()
            .any(|header| header.value == "session=cookie-secret"));
        assert!(draft.body.contains("body-password-secret"));
        assert_eq!(
            draft.settings["_shownetImportedAuth"]["value"]["digest"][1]["value"],
            "digest-password-secret"
        );

        let collection = storage
            .get_request_collection_for_send(&imported.collection.id)
            .unwrap();
        let exported = crate::request_collections::render_collection_export(
            "postman",
            &collection,
            &[],
            &[draft],
            &[],
        )
        .unwrap();
        for expected in [
            "url-password",
            "query-secret",
            "header-secret",
            "cookie-secret",
            "body-password-secret",
            "digest-password-secret",
            "oauth-client-secret",
        ] {
            assert!(exported.contains(expected), "missing {expected}");
        }
        assert_eq!(
            serde_json::from_str::<Value>(&exported).unwrap()["item"][0]["request"]["auth"]["type"],
            "digest"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn openapi_sync_ignores_json_yaml_only_changes() {
        let storage = storage();
        let json_path = write_openapi_fixture(
            "json",
            r#"{
              "openapi":"3.0.3",
              "info":{"title":"Formatting API"},
              "servers":[{"url":"https://api.example.test"}],
              "paths":{
                "/widgets/{id}":{
                  "get":{
                    "summary":"Read widget",
                    "tags":["Widgets"],
                    "parameters":[
                      {"name":"expand","in":"query","schema":{"type":"string","default":"full"}}
                    ]
                  }
                }
              }
            }"#,
        );
        let yaml_path = write_openapi_fixture(
            "yaml",
            r#"
openapi: 3.0.3
info:
  title: Formatting API
servers:
  - url: https://api.example.test
paths:
  /widgets/{id}:
    get:
      summary: Read widget
      tags: [Widgets]
      parameters:
        - name: expand
          in: query
          schema:
            type: string
            default: full
"#,
        );
        let imported = import_openapi_fixture(&storage, &json_path, "Formatting API");
        let preview = storage
            .preview_request_collection_sync(&imported.collection.id, yaml_path.to_str().unwrap())
            .unwrap();

        assert_eq!(preview.unchanged_count, 1);
        assert!(preview.changes.is_empty());
        assert_eq!(
            imported.collection.source_fingerprint.as_deref(),
            Some(preview.source_fingerprint.as_str())
        );
        let _ = std::fs::remove_file(json_path);
        let _ = std::fs::remove_file(yaml_path);
    }

    #[test]
    fn openapi_sync_preserves_local_state_and_detaches_removed_drafts() {
        let storage = storage();
        let v1_path = write_openapi_fixture("json", OPENAPI_SYNC_V1);
        let v2_path = write_openapi_fixture("json", OPENAPI_SYNC_V2);
        let imported = import_openapi_fixture(&storage, &v1_path, "Sync API");
        assert_eq!(imported.imported_count, 3);
        assert_eq!(
            imported.collection.source_format.as_deref(),
            Some("openapi")
        );
        assert_eq!(imported.collection.source_path.as_deref(), v1_path.to_str());

        let initial_workspace = storage.list_request_collection_workspace().unwrap();
        let change_draft = initial_workspace
            .drafts
            .iter()
            .find(|draft| draft.spec_operation_key.as_deref() == Some("POST /change"))
            .unwrap()
            .clone();
        let removed_draft = initial_workspace
            .drafts
            .iter()
            .find(|draft| draft.spec_operation_key.as_deref() == Some("DELETE /removed"))
            .unwrap()
            .clone();
        assert!(initial_workspace
            .drafts
            .iter()
            .all(|draft| draft.spec_operation_key.is_some() && draft.spec_fingerprint.is_some()));

        let environment = storage
            .save_environment(EnvironmentInput {
                id: None,
                name: "Local sync environment".into(),
                kind: "named".into(),
                active: true,
            })
            .unwrap();
        let local_folder = storage
            .save_request_collection_folder(RequestCollectionFolderInput {
                id: None,
                collection_id: imported.collection.id.clone(),
                parent_id: None,
                name: "Local only".into(),
            })
            .unwrap();
        let local_settings =
            serde_json::json!({"cookieJar":true,"followRedirects":false,"verifyTls":true});
        let customized = storage
            .save_request_draft(RequestDraftInput {
                id: Some(change_draft.id.clone()),
                session_id: change_draft.session_id.clone(),
                source_request_id: change_draft.source_request_id.clone(),
                name: "My local request name".into(),
                method: change_draft.method.clone(),
                url: change_draft.url.clone(),
                headers: change_draft.headers.clone(),
                body: change_draft.body.clone(),
                body_type: change_draft.body_type.clone(),
                auth: serde_json::json!({"kind":"bearer","token":"local-auth-secret"}),
                settings: local_settings.clone(),
                environment_id: Some(environment.id.clone()),
                collection_id: Some(imported.collection.id.clone()),
                folder_id: Some(local_folder.id.clone()),
                tags: vec!["local".into(), "keep".into()],
            })
            .unwrap();
        assert_eq!(
            customized.spec_operation_key.as_deref(),
            Some("POST /change")
        );
        assert_eq!(customized.spec_fingerprint, change_draft.spec_fingerprint);

        let preview = storage
            .preview_request_collection_sync(&imported.collection.id, v2_path.to_str().unwrap())
            .unwrap();
        assert_eq!(preview.unchanged_count, 1);
        assert_eq!(preview.changes.len(), 3);
        assert_eq!(
            preview
                .changes
                .iter()
                .filter(|change| change.kind == "add")
                .count(),
            1
        );
        assert_eq!(
            preview
                .changes
                .iter()
                .filter(|change| change.kind == "modify")
                .count(),
            1
        );
        assert_eq!(
            preview
                .changes
                .iter()
                .filter(|change| change.kind == "remove")
                .count(),
            1
        );
        let modify_change = preview
            .changes
            .iter()
            .find(|change| change.kind == "modify")
            .unwrap();
        assert!(modify_change.local_override);
        assert!(modify_change.changed_fields.contains(&"name".to_string()));
        assert!(modify_change.changed_fields.contains(&"url".to_string()));
        assert!(modify_change.changed_fields.contains(&"body".to_string()));
        assert!(modify_change.changed_fields.contains(&"folder".to_string()));
        let incoming_modified = modify_change.item.clone().unwrap();

        let result = storage
            .sync_request_collection(CollectionSyncCommitInput {
                collection_id: imported.collection.id.clone(),
                source_path: preview.source_path.clone(),
                source_fingerprint: preview.source_fingerprint.clone(),
                selections: preview
                    .changes
                    .iter()
                    .map(|change| CollectionSyncSelection {
                        kind: change.kind.clone(),
                        operation_key: change.operation_key.clone(),
                        item: change.item.clone(),
                        draft_id: change.draft_id.clone(),
                    })
                    .collect(),
            })
            .unwrap();
        assert_eq!(
            (
                result.added_count,
                result.updated_count,
                result.detached_count
            ),
            (1, 1, 1)
        );
        assert_eq!(result.collection.source_path.as_deref(), v2_path.to_str());
        assert_eq!(
            result.collection.source_fingerprint.as_deref(),
            Some(preview.source_fingerprint.as_str())
        );

        let updated = storage.get_request_draft(&change_draft.id).unwrap();
        assert_eq!(updated.name, "My local request name");
        assert_eq!(updated.method, incoming_modified.method);
        assert_eq!(updated.url, incoming_modified.url);
        assert_eq!(updated.headers, incoming_modified.headers);
        assert_eq!(updated.body, incoming_modified.body);
        assert_eq!(updated.body_type, incoming_modified.body_type);
        assert_eq!(updated.folder_id.as_deref(), Some(local_folder.id.as_str()));
        assert_eq!(
            updated.environment_id.as_deref(),
            Some(environment.id.as_str())
        );
        assert_eq!(updated.tags, vec!["local", "keep"]);
        assert_eq!(updated.settings, local_settings);
        assert_eq!(
            storage
                .get_request_draft_for_send(&updated.id)
                .unwrap()
                .auth["token"],
            "local-auth-secret"
        );

        let detached = storage.get_request_draft(&removed_draft.id).unwrap();
        assert_eq!(
            detached.collection_id.as_deref(),
            Some(imported.collection.id.as_str())
        );
        assert!(detached.spec_operation_key.is_none());
        assert!(detached.spec_fingerprint.is_none());
        let final_workspace = storage.list_request_collection_workspace().unwrap();
        assert_eq!(
            final_workspace
                .drafts
                .iter()
                .filter(
                    |draft| draft.collection_id.as_deref() == Some(imported.collection.id.as_str())
                )
                .count(),
            4
        );
        assert!(final_workspace
            .drafts
            .iter()
            .any(|draft| draft.spec_operation_key.as_deref() == Some("PUT /added")));
        let _ = std::fs::remove_file(v1_path);
        let _ = std::fs::remove_file(v2_path);
    }

    #[test]
    fn openapi_sync_rolls_back_on_stale_ids_and_rejects_duplicate_keys() {
        let storage = storage();
        let v1_path = write_openapi_fixture("json", OPENAPI_SYNC_V1);
        let v2_path = write_openapi_fixture("json", OPENAPI_SYNC_V2);
        let imported = import_openapi_fixture(&storage, &v1_path, "Rollback API");
        let original_collection = imported.collection.clone();
        let preview = storage
            .preview_request_collection_sync(&imported.collection.id, v2_path.to_str().unwrap())
            .unwrap();
        let add_change = preview
            .changes
            .iter()
            .find(|change| change.kind == "add")
            .unwrap();
        let modify_change = preview
            .changes
            .iter()
            .find(|change| change.kind == "modify")
            .unwrap();
        let original_modify = storage
            .get_request_draft(modify_change.draft_id.as_deref().unwrap())
            .unwrap();

        let error = storage
            .sync_request_collection(CollectionSyncCommitInput {
                collection_id: imported.collection.id.clone(),
                source_path: preview.source_path.clone(),
                source_fingerprint: preview.source_fingerprint.clone(),
                selections: vec![
                    CollectionSyncSelection {
                        kind: "add".into(),
                        operation_key: add_change.operation_key.clone(),
                        item: add_change.item.clone(),
                        draft_id: None,
                    },
                    CollectionSyncSelection {
                        kind: "modify".into(),
                        operation_key: modify_change.operation_key.clone(),
                        item: modify_change.item.clone(),
                        draft_id: Some("stale-draft-id".into()),
                    },
                ],
            })
            .unwrap_err();
        assert!(error.contains("请重新预览同步"));
        let rolled_back_workspace = storage.list_request_collection_workspace().unwrap();
        assert!(!rolled_back_workspace
            .drafts
            .iter()
            .any(|draft| draft.spec_operation_key.as_deref() == Some("PUT /added")));
        assert!(!rolled_back_workspace
            .folders
            .iter()
            .any(|folder| folder.name == "New"));
        let unchanged_modify = storage.get_request_draft(&original_modify.id).unwrap();
        assert_eq!(unchanged_modify.body, original_modify.body);
        assert_eq!(
            storage
                .get_request_collection(&imported.collection.id)
                .unwrap()
                .source_fingerprint,
            original_collection.source_fingerprint
        );

        let duplicate_error = storage
            .sync_request_collection(CollectionSyncCommitInput {
                collection_id: imported.collection.id,
                source_path: preview.source_path,
                source_fingerprint: preview.source_fingerprint,
                selections: vec![
                    CollectionSyncSelection {
                        kind: "add".into(),
                        operation_key: add_change.operation_key.clone(),
                        item: add_change.item.clone(),
                        draft_id: None,
                    },
                    CollectionSyncSelection {
                        kind: "add".into(),
                        operation_key: add_change.operation_key.clone(),
                        item: add_change.item.clone(),
                        draft_id: None,
                    },
                ],
            })
            .unwrap_err();
        assert!(duplicate_error.contains("重复 operation key"));
        let _ = std::fs::remove_file(v1_path);
        let _ = std::fs::remove_file(v2_path);
    }

    #[test]
    fn request_draft_tags_and_batch_updates_are_atomic() {
        let storage = storage();
        let collection = storage
            .save_request_collection(RequestCollectionInput {
                id: None,
                name: "Batch target".into(),
                description: String::new(),
                default_headers: vec![],
                default_auth: serde_json::json!({"kind":"none"}),
                default_environment_id: None,
            })
            .unwrap();
        let folder = storage
            .save_request_collection_folder(RequestCollectionFolderInput {
                id: None,
                collection_id: collection.id.clone(),
                parent_id: None,
                name: "Auth".into(),
            })
            .unwrap();
        let save_draft = |name: &str, tags: Vec<String>| {
            storage
                .save_request_draft(RequestDraftInput {
                    id: None,
                    session_id: None,
                    source_request_id: None,
                    name: name.into(),
                    method: "GET".into(),
                    url: format!("https://api.example.test/{name}"),
                    headers: vec![],
                    body: String::new(),
                    body_type: "none".into(),
                    auth: serde_json::json!({"kind":"none"}),
                    settings: serde_json::json!({}),
                    environment_id: None,
                    collection_id: None,
                    folder_id: None,
                    tags,
                })
                .unwrap()
        };
        let first = save_draft(
            "first",
            vec![" Auth ".into(), "auth".into(), "Smoke".into()],
        );
        let second = save_draft("second", vec!["Regression".into()]);
        assert_eq!(first.tags, vec!["Auth", "Smoke"]);

        storage
            .update_request_drafts_batch(RequestDraftBatchUpdateInput {
                draft_ids: vec![first.id.clone(), second.id.clone(), first.id.clone()],
                location: Some(crate::models::RequestDraftBatchLocation {
                    collection_id: Some(collection.id.clone()),
                    folder_id: Some(folder.id.clone()),
                }),
                add_tags: vec!["critical".into(), "smoke".into()],
                remove_tags: vec!["AUTH".into()],
            })
            .unwrap();
        let first = storage.get_request_draft(&first.id).unwrap();
        let second = storage.get_request_draft(&second.id).unwrap();
        assert_eq!(first.tags, vec!["Smoke", "critical"]);
        assert_eq!(second.tags, vec!["Regression", "critical", "smoke"]);
        for draft in [&first, &second] {
            assert_eq!(draft.collection_id.as_deref(), Some(collection.id.as_str()));
            assert_eq!(draft.folder_id.as_deref(), Some(folder.id.as_str()));
        }

        let before_missing = first.tags.clone();
        assert!(storage
            .update_request_drafts_batch(RequestDraftBatchUpdateInput {
                draft_ids: vec![first.id.clone(), "draft-missing".into()],
                location: None,
                add_tags: vec!["must-rollback".into()],
                remove_tags: vec![],
            })
            .is_err());
        assert_eq!(
            storage.get_request_draft(&first.id).unwrap().tags,
            before_missing
        );

        let twenty_tags = (0..20)
            .map(|index| format!("tag-{index}"))
            .collect::<Vec<_>>();
        let second = storage
            .save_request_draft(RequestDraftInput {
                id: Some(second.id.clone()),
                session_id: second.session_id,
                source_request_id: second.source_request_id,
                name: second.name,
                method: second.method,
                url: second.url,
                headers: second.headers,
                body: second.body,
                body_type: second.body_type,
                auth: second.auth,
                settings: second.settings,
                environment_id: second.environment_id,
                collection_id: second.collection_id,
                folder_id: second.folder_id,
                tags: twenty_tags.clone(),
            })
            .unwrap();
        let first_before_overflow = storage.get_request_draft(&first.id).unwrap().tags;
        assert!(storage
            .update_request_drafts_batch(RequestDraftBatchUpdateInput {
                draft_ids: vec![first.id.clone(), second.id.clone()],
                location: None,
                add_tags: vec!["overflow".into()],
                remove_tags: vec![],
            })
            .is_err());
        assert_eq!(
            storage.get_request_draft(&first.id).unwrap().tags,
            first_before_overflow
        );
        assert_eq!(
            storage.get_request_draft(&second.id).unwrap().tags,
            twenty_tags
        );

        let (column_count, migration_count): (i64, i64) = storage
            .with_connection(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COUNT(*) FROM pragma_table_info('request_drafts') WHERE name='tags_json'",
                        [],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE version=19",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!((column_count, migration_count), (1, 1));
    }

    #[test]
    fn agent_rules_are_disabled_and_enable_requires_confirmation() {
        let storage = storage();
        let input = CaptureRuleInput {
            id: None,
            name: "Agent header draft".into(),
            enabled: true,
            priority: 100,
            stage: "request".into(),
            matcher: FilterExpression::Predicate {
                field: "host".into(),
                operator: "contains".into(),
                value: Some(Value::String("example".into())),
            },
            action: serde_json::json!({"kind":"rewrite","operations":[{"target":"request.header","op":"set","name":"X-Test","value":"1"}]}),
            created_by: "agent-draft".into(),
        };
        let rule = storage.save_capture_rule(input).unwrap();
        assert!(!rule.enabled);
        assert!(storage
            .set_capture_rule_enabled(&rule.id, true, false)
            .is_err());
        let enabled = storage
            .set_capture_rule_enabled(&rule.id, true, true)
            .unwrap();
        assert!(enabled.enabled);
        assert_eq!(enabled.revision, 1);
        let migrations: i64 = storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE version IN (13,14,15)",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(migrations, 3);
    }

    #[test]
    fn capture_rule_revisions_can_be_listed_and_restored_as_disabled_new_versions() {
        let storage = storage();
        let first = storage
            .save_capture_rule(CaptureRuleInput {
                id: None,
                name: "Revision one".into(),
                enabled: false,
                priority: 10,
                stage: "request".into(),
                matcher: FilterExpression::Predicate {
                    field: "host".into(),
                    operator: "equals".into(),
                    value: Some(Value::String("one.example".into())),
                },
                action: serde_json::json!({"kind":"delay","latencyMs":10}),
                created_by: "user".into(),
            })
            .unwrap();
        let second = storage
            .save_capture_rule(CaptureRuleInput {
                id: Some(first.id.clone()),
                name: "Revision two".into(),
                enabled: true,
                priority: 20,
                stage: "request".into(),
                matcher: FilterExpression::Predicate {
                    field: "host".into(),
                    operator: "equals".into(),
                    value: Some(Value::String("two.example".into())),
                },
                action: serde_json::json!({"kind":"block","direction":"outbound"}),
                created_by: "user".into(),
            })
            .unwrap();
        assert_eq!(second.revision, 2);
        assert!(!second.enabled);

        let revisions = storage.list_capture_rule_revisions(&first.id).unwrap();
        assert_eq!(
            revisions
                .iter()
                .map(|item| item.revision)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert_eq!(revisions[1].snapshot["name"], "Revision one");

        storage
            .set_capture_rule_enabled(&first.id, true, true)
            .unwrap();
        let restored = storage.restore_capture_rule_revision(&first.id, 1).unwrap();
        assert_eq!(restored.revision, 3);
        assert_eq!(restored.name, "Revision one");
        assert_eq!(restored.priority, 10);
        assert_eq!(restored.action["latencyMs"], 10);
        assert!(!restored.enabled);
        assert_eq!(
            storage
                .list_capture_rule_revisions(&first.id)
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn capture_rules_accept_executed_capabilities_and_reject_unsafe_ones() {
        let storage = storage();
        let input = |stage: &str, action: Value| CaptureRuleInput {
            id: None,
            name: "Unsupported rule".into(),
            enabled: false,
            priority: 100,
            stage: stage.into(),
            matcher: FilterExpression::Predicate {
                field: "host".into(),
                operator: "contains".into(),
                value: Some(Value::String("example".into())),
            },
            action,
            created_by: "user".into(),
        };
        let response_rule = storage
            .save_capture_rule(input(
                "response",
                serde_json::json!({"kind":"rewrite","operations":[{"target":"response.header","op":"set","name":"X-Test","value":"1"}]})
            ))
            .unwrap();
        assert!(!response_rule.enabled);
        let throttle_rule = storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({"kind":"throttle","latencyMs":10,"jitterMs":5,"uploadKbps":64,"downloadKbps":128,"packetLossPercent":2.5})
            ))
            .unwrap();
        assert!(!throttle_rule.enabled);
        assert!(storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({"kind":"breakpoint","timeoutMs":120000,"onTimeout":"continue"})
            ))
            .is_ok());
        assert!(storage
            .save_capture_rule(input(
                "response",
                serde_json::json!({"kind":"breakpoint","timeoutMs":300000,"onTimeout":"abort"})
            ))
            .is_ok());
        assert!(storage
            .save_capture_rule(input(
                "connection",
                serde_json::json!({"kind":"breakpoint","timeoutMs":120000,"onTimeout":"continue"})
            ))
            .is_err());
        let mirror_rule = storage
            .save_capture_rule(input(
                "connection",
                serde_json::json!({"kind":"mirror","targetHost":"staging.example","targetPort":8443,"identity":"target"}),
            ))
            .unwrap();
        assert!(!mirror_rule.enabled);
        assert_eq!(mirror_rule.stage, "connection");
        assert!(storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({"kind":"breakpoint","timeoutMs":4999,"onTimeout":"continue"})
            ))
            .is_err());
        assert!(storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({"kind":"delay","latencyMs":10,"jitterMs":5})
            ))
            .is_ok());
        assert!(storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({"kind":"throttle","bytesPerSecond":1024})
            ))
            .is_err());
        assert!(storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({"kind":"rewrite","operations":[{"target":"request.body","op":"set","value":"body"}]})
            ))
            .is_ok());
        assert!(storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({"kind":"rewrite","operations":[{"target":"request.body","op":"replace","pattern":"token=[^&]+","value":"token=masked"}]})
            ))
            .is_ok());
        assert!(storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({"kind":"rewrite","operations":[{"target":"request.body","op":"replace","pattern":"","value":"masked"}]})
            ))
            .is_err());
        assert!(storage
            .save_capture_rule(input(
                "response",
                serde_json::json!({"kind":"rewrite","operations":[{"target":"response.header","op":"set","name":"Content-Length","value":"999"}]})
            ))
            .is_err());
        assert!(storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({"kind":"mirror","targetHost":"mirror.example"})
            ))
            .is_err());
        assert!(storage
            .save_capture_rule(input(
                "connection",
                serde_json::json!({"kind":"mirror","targetHost":"https://mirror.example"})
            ))
            .is_err());
        assert!(storage
            .save_capture_rule(input(
                "connection",
                serde_json::json!({"kind":"block","direction":"outbound"})
            ))
            .is_err());
    }

    #[test]
    fn map_remote_rules_validate_and_round_trip_security_options() {
        let storage = storage();
        let input = |stage: &str, action: Value| CaptureRuleInput {
            id: None,
            name: "Map Remote rule".into(),
            enabled: true,
            priority: 25,
            stage: stage.into(),
            matcher: FilterExpression::Predicate {
                field: "host".into(),
                operator: "equals".into(),
                value: Some(Value::String("api.example.test".into())),
            },
            action,
            created_by: "user".into(),
        };
        let action = serde_json::json!({
            "kind":"redirect",
            "targetTemplate":"https://stage.example.test:8443/base/*",
            "excludePattern":"https://api.example.test/private*",
            "preserveHost":true,
            "preserveCredentials":true,
            "allowInsecureDowngrade":false
        });
        let saved = storage
            .save_capture_rule(input("request", action.clone()))
            .unwrap();
        assert!(!saved.enabled);
        assert_eq!(saved.stage, "request");
        assert_eq!(saved.action, action);
        let loaded = storage
            .list_capture_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.id == saved.id)
            .unwrap();
        assert_eq!(loaded.action["targetTemplate"], action["targetTemplate"]);
        assert_eq!(loaded.action["excludePattern"], action["excludePattern"]);
        assert_eq!(loaded.action["preserveHost"], true);
        assert_eq!(loaded.action["preserveCredentials"], true);
        assert_eq!(loaded.action["allowInsecureDowngrade"], false);

        assert!(storage
            .save_capture_rule(input("response", action.clone()))
            .is_err());
        for invalid in [
            serde_json::json!({"kind":"redirect","targetTemplate":"ftp://stage.example.test/base/*"}),
            serde_json::json!({"kind":"redirect","targetTemplate":"https://user:secret@stage.example.test/base/*"}),
            serde_json::json!({"kind":"redirect","targetTemplate":"https://stage.example.test/base/*#fragment"}),
            serde_json::json!({"kind":"redirect","targetTemplate":r"https://stage.example.test\base\*"}),
            serde_json::json!({"kind":"redirect","targetTemplate":"relative/path"}),
            serde_json::json!({"kind":"redirect","targetTemplate":"https://stage.example.test/base/*","excludePattern":42}),
            serde_json::json!({"kind":"redirect","targetTemplate":"https://stage.example.test/base/*","preserveHost":"yes"}),
            serde_json::json!({"kind":"redirect","targetTemplate":"https://stage.example.test/base/*","preserveCredentials":1}),
            serde_json::json!({"kind":"redirect","targetTemplate":"https://stage.example.test/base/*","allowInsecureDowngrade":[]}),
        ] {
            assert!(storage
                .save_capture_rule(input("request", invalid))
                .is_err());
        }
        assert!(storage
            .save_capture_rule(input(
                "request",
                serde_json::json!({
                    "kind":"redirect",
                    "targetTemplate":"https://stage.example.test/base/*",
                    "excludePattern":"x".repeat(4097)
                }),
            ))
            .is_err());
    }

    #[test]
    fn reveal_real_app_mcp_token_when_env_set() {
        let Ok(out) = std::env::var("SHOWNET_MCP_TOKEN_OUT") else {
            return;
        };
        let home = std::env::var("HOME").expect("HOME");
        let path = std::path::PathBuf::from(home)
            .join("Library/Application Support/com.shownet.desktop/shownet.sqlite3");
        let storage = Storage::open(&path).expect("open app db");
        let token = storage.reveal_mcp_access_token().expect("reveal");
        std::fs::write(&out, token).expect("write token");
    }
}
