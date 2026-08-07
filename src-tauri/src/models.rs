use crate::tls_fingerprint::TlsFingerprintRecord;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub request_count: i64,
    pub error_count: i64,
    pub active: bool,
    pub sources: Vec<String>,
    pub analysis_report_count: i64,
    pub latest_analysis_status: Option<String>,
    pub latest_analysis_updated_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HookRecord {
    pub algorithm: String,
    pub input: String,
    pub output: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHookInput {
    pub session_id: String,
    pub source_instance_id: Option<String>,
    pub request_id: Option<String>,
    pub timestamp: Option<i64>,
    pub kind: String,
    pub name: String,
    pub url: Option<String>,
    pub method: Option<String>,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub output: Value,
    pub stack: Option<String>,
    pub duration_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHookEvent {
    pub id: String,
    pub session_id: String,
    pub source_instance_id: String,
    pub request_id: Option<String>,
    pub sequence: i64,
    pub timestamp: i64,
    pub kind: String,
    pub name: String,
    pub url: Option<String>,
    pub method: Option<String>,
    pub input: Value,
    pub output: Value,
    pub stack: Option<String>,
    pub duration_ms: Option<i64>,
    pub correlation: String,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyBrowserStatus {
    pub running: bool,
    pub debug_port: u16,
    pub target_id: String,
    pub web_socket_debugger_url: String,
    pub source_instance_id: String,
    pub lab_url: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub available: bool,
    pub notes: Option<String>,
    pub published_at: Option<String>,
    pub download_url: Option<String>,
    pub platform: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyCaptureMetadata {
    pub captured: bool,
    pub content_encoding: Option<String>,
    pub decoded: bool,
    pub truncated: bool,
    pub complete: bool,
    pub wire_bytes: i64,
    pub decoded_bytes: i64,
    pub format: String,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted_reason: Option<String>,
}

impl Default for BodyCaptureMetadata {
    fn default() -> Self {
        Self {
            captured: false,
            content_encoding: None,
            decoded: false,
            truncated: false,
            complete: true,
            wire_bytes: 0,
            decoded_bytes: 0,
            format: "empty".to_string(),
            error: None,
            omitted_reason: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoCodeSnippet {
    pub ordinal: i64,
    pub kind: String,
    pub name: Option<String>,
    pub algorithms: Vec<String>,
    pub start_line: i64,
    pub end_line: i64,
    pub code: String,
    pub truncated: bool,
    pub source_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRecord {
    pub id: String,
    pub order: i64,
    pub time: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub status: i64,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub size: String,
    pub duration: i64,
    pub source: String,
    pub protocol: String,
    pub tls: String,
    pub tls_fingerprint: Option<TlsFingerprintRecord>,
    pub risk: String,
    pub request_headers: Vec<HeaderEntry>,
    pub response_headers: Vec<HeaderEntry>,
    pub request_body: Option<String>,
    pub response_body: String,
    pub response_body_metadata: BodyCaptureMetadata,
    pub crypto_snippet_count: i64,
    pub hook: Option<HookRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAnnotationSummary {
    pub bookmarked: bool,
    pub color: Option<String>,
    pub struck_through: bool,
    pub note_preview: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAnnotation {
    pub request_id: String,
    pub bookmarked: bool,
    pub color: Option<String>,
    pub struck_through: bool,
    pub note: String,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAnnotationInput {
    pub request_id: String,
    #[serde(default)]
    pub bookmarked: bool,
    pub color: Option<String>,
    #[serde(default)]
    pub struck_through: bool,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestListItem {
    pub id: String,
    pub order: i64,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub state: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: Option<i64>,
    pub path: String,
    pub query: Option<String>,
    pub status: Option<i64>,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub source: String,
    pub source_instance_id: String,
    pub protocol: String,
    pub size_bytes: i64,
    pub duration_ms: Option<i64>,
    pub risk: String,
    pub has_hook: bool,
    pub crypto_snippet_count: i64,
    pub tls_intercepted: bool,
    pub tls_version: Option<String>,
    pub annotation: Option<RequestAnnotationSummary>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum FilterExpression {
    Group {
        operator: String,
        #[serde(default)]
        children: Vec<FilterExpression>,
    },
    Predicate {
        field: String,
        operator: String,
        value: Option<Value>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestSort {
    pub field: String,
    pub direction: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestQuery {
    pub session_id: String,
    pub filter: Option<FilterExpression>,
    #[serde(default)]
    pub sort: Vec<RequestSort>,
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestWindowQuery {
    pub session_id: String,
    pub filter: Option<FilterExpression>,
    #[serde(default)]
    pub sort: Vec<RequestSort>,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FacetCount {
    pub value: String,
    pub count: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestFacets {
    pub hosts: Vec<FacetCount>,
    pub methods: Vec<FacetCount>,
    pub sources: Vec<FacetCount>,
    pub protocols: Vec<FacetCount>,
    pub statuses: Vec<FacetCount>,
    pub types: Vec<FacetCount>,
    pub risks: Vec<FacetCount>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestListPage {
    pub items: Vec<RequestListItem>,
    pub next_cursor: Option<String>,
    pub total_count: i64,
    pub filtered_count: i64,
    pub hook_count: i64,
    pub bookmarked_count: i64,
    pub facets: RequestFacets,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestListWindow {
    pub items: Vec<RequestListItem>,
    pub offset: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestListEvent {
    pub session_id: String,
    pub item: RequestListItem,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedRequestView {
    pub id: String,
    pub name: String,
    pub session_id: Option<String>,
    pub filter: Option<FilterExpression>,
    #[serde(default)]
    pub sort: Vec<RequestSort>,
    #[serde(default)]
    pub columns: Value,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedRequestViewInput {
    pub id: Option<String>,
    pub name: String,
    pub session_id: Option<String>,
    pub filter: Option<FilterExpression>,
    #[serde(default)]
    pub sort: Vec<RequestSort>,
    #[serde(default)]
    pub columns: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReplaySettings {
    pub repeat_count: i64,
    pub start_delay_ms: i64,
    pub interval_ms: i64,
    pub max_concurrency: i64,
    pub through_capture: bool,
    pub include_cookie: bool,
    pub include_authorization: bool,
    pub follow_redirects: bool,
    pub verify_tls: bool,
    pub use_upstream_proxy: bool,
}

impl Default for ReplaySettings {
    fn default() -> Self {
        Self {
            repeat_count: 1,
            start_delay_ms: 0,
            interval_ms: 0,
            max_concurrency: 4,
            through_capture: false,
            include_cookie: true,
            include_authorization: true,
            follow_redirects: true,
            verify_tls: true,
            use_upstream_proxy: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayBatchInput {
    pub session_id: String,
    pub request_ids: Vec<String>,
    #[serde(default)]
    pub settings: ReplaySettings,
    #[serde(default)]
    pub confirmed_large_batch: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayBatchItem {
    pub id: String,
    pub source_request_id: String,
    pub run_index: i64,
    pub status: String,
    pub captured_request_id: Option<String>,
    pub status_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayBatch {
    pub id: String,
    pub session_id: String,
    pub status: String,
    pub settings: ReplaySettings,
    pub total: i64,
    pub completed: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub items: Vec<ReplayBatchItem>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDraft {
    pub id: String,
    pub session_id: Option<String>,
    pub source_request_id: Option<String>,
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderEntry>,
    pub body: String,
    pub body_type: String,
    pub auth: Value,
    pub settings: Value,
    pub environment_id: Option<String>,
    pub collection_id: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub spec_operation_key: Option<String>,
    pub spec_fingerprint: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDraftInput {
    pub id: Option<String>,
    pub session_id: Option<String>,
    pub source_request_id: Option<String>,
    pub name: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<HeaderEntry>,
    #[serde(default)]
    pub body: String,
    pub body_type: String,
    #[serde(default)]
    pub auth: Value,
    #[serde(default)]
    pub settings: Value,
    pub environment_id: Option<String>,
    pub collection_id: Option<String>,
    pub folder_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCollection {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_headers: Vec<HeaderEntry>,
    pub default_auth: Value,
    pub default_environment_id: Option<String>,
    pub source_format: Option<String>,
    pub source_path: Option<String>,
    pub source_fingerprint: Option<String>,
    pub source_synced_at: Option<i64>,
    pub sort_order: i64,
    pub draft_count: i64,
    pub folder_count: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCollectionInput {
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub default_headers: Vec<HeaderEntry>,
    #[serde(default)]
    pub default_auth: Value,
    pub default_environment_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCollectionFolder {
    pub id: String,
    pub collection_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub depth: i64,
    pub sort_order: i64,
    pub draft_count: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCollectionFolderInput {
    pub id: Option<String>,
    pub collection_id: String,
    pub parent_id: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDraftLocationInput {
    pub draft_id: String,
    pub collection_id: Option<String>,
    pub folder_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDraftBatchLocation {
    pub collection_id: Option<String>,
    pub folder_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDraftBatchUpdateInput {
    pub draft_ids: Vec<String>,
    pub location: Option<RequestDraftBatchLocation>,
    #[serde(default)]
    pub add_tags: Vec<String>,
    #[serde(default)]
    pub remove_tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCollectionWorkspace {
    pub collections: Vec<RequestCollection>,
    pub folders: Vec<RequestCollectionFolder>,
    pub drafts: Vec<RequestDraft>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionImportEnvironmentVariable {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionImportEnvironment {
    pub source_id: String,
    pub name: String,
    #[serde(default)]
    pub variables: Vec<CollectionImportEnvironmentVariable>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionImportMetadata {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub default_headers: Vec<HeaderEntry>,
    #[serde(default)]
    pub default_auth: Value,
    #[serde(default)]
    pub default_environment_id: Option<String>,
    #[serde(default)]
    pub source_format: Option<String>,
    #[serde(default)]
    pub source_path: Option<String>,
    #[serde(default)]
    pub source_fingerprint: Option<String>,
    #[serde(default)]
    pub source_synced_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionImportItem {
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderEntry>,
    pub body: String,
    pub body_type: String,
    #[serde(default)]
    pub auth: Value,
    #[serde(default)]
    pub settings: Value,
    #[serde(default)]
    pub environment_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub folder_path: Vec<String>,
    #[serde(default)]
    pub source_key: Option<String>,
    #[serde(default)]
    pub source_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionImportPreview {
    pub source_format: String,
    pub suggested_name: String,
    pub items: Vec<CollectionImportItem>,
    #[serde(default)]
    pub collection: Option<CollectionImportMetadata>,
    #[serde(default)]
    pub environments: Vec<CollectionImportEnvironment>,
    pub warnings: Vec<String>,
    pub source_path: Option<String>,
    pub source_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionImportCommitInput {
    pub collection_id: Option<String>,
    pub collection_name: String,
    pub items: Vec<CollectionImportItem>,
    #[serde(default)]
    pub collection: Option<CollectionImportMetadata>,
    #[serde(default)]
    pub environments: Vec<CollectionImportEnvironment>,
    pub source_format: Option<String>,
    pub source_path: Option<String>,
    pub source_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionImportResult {
    pub collection: RequestCollection,
    pub imported_count: i64,
    pub created_folder_count: i64,
    pub imported_environment_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionSyncChange {
    pub kind: String,
    pub operation_key: String,
    pub item: Option<CollectionImportItem>,
    pub draft_id: Option<String>,
    pub current_name: Option<String>,
    pub current_method: Option<String>,
    pub current_url: Option<String>,
    pub changed_fields: Vec<String>,
    pub local_override: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionSyncPreview {
    pub collection_id: String,
    pub collection_name: String,
    pub source_path: String,
    pub source_fingerprint: String,
    pub changes: Vec<CollectionSyncChange>,
    pub unchanged_count: i64,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionSyncSelection {
    pub kind: String,
    pub operation_key: String,
    pub item: Option<CollectionImportItem>,
    pub draft_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionSyncCommitInput {
    pub collection_id: String,
    pub source_path: String,
    pub source_fingerprint: String,
    pub selections: Vec<CollectionSyncSelection>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionSyncResult {
    pub collection: RequestCollection,
    pub added_count: i64,
    pub updated_count: i64,
    pub detached_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionExportResult {
    pub path: String,
    pub format: String,
    pub item_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRun {
    pub id: String,
    pub draft_id: String,
    pub status: String,
    pub request_snapshot: Value,
    pub response_snapshot: Value,
    pub error: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCookieRecord {
    pub name: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub expires_at: Option<i64>,
    pub persistent: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentVariable {
    pub id: String,
    pub name: String,
    pub value: String,
    pub secret: bool,
    pub has_value: bool,
    pub enabled: bool,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentVariableInput {
    pub id: Option<String>,
    pub environment_id: String,
    pub name: String,
    pub value: Option<String>,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub clear_value: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub active: bool,
    pub variables: Vec<EnvironmentVariable>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentInput {
    pub id: Option<String>,
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i64,
    pub stage: String,
    pub matcher: FilterExpression,
    pub action: Value,
    pub created_by: String,
    pub revision: i64,
    pub hit_count: i64,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRuleInput {
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    pub priority: i64,
    pub stage: String,
    pub matcher: FilterExpression,
    pub action: Value,
    pub created_by: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRuleRevision {
    pub id: String,
    pub rule_id: String,
    pub revision: i64,
    pub snapshot: Value,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulePreviewResult {
    pub matched: bool,
    pub request_id: String,
    pub stage: String,
    pub before: Value,
    pub after: Value,
    pub changes: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRuleRun {
    pub id: String,
    pub request_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub revision: i64,
    pub stage: String,
    pub result: String,
    pub diff_summary: Value,
    pub duration_ms: i64,
    pub error: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticCheck {
    pub id: String,
    pub label: String,
    pub status: String,
    pub summary: String,
    pub detail: String,
    pub repair_action: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDiagnostics {
    pub checks: Vec<DiagnosticCheck>,
    pub generated_at: i64,
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_source() -> String {
    "desktop".to_string()
}

fn default_resource_type() -> String {
    "fetch".to_string()
}

fn default_protocol() -> String {
    "http/1.1".to_string()
}

fn default_risk() -> String {
    "none".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedRequestInput {
    pub id: Option<String>,
    pub session_id: String,
    #[serde(default = "default_source")]
    pub source: String,
    pub source_instance_id: Option<String>,
    pub timestamp: Option<i64>,
    #[serde(default = "default_method")]
    pub method: String,
    pub scheme: Option<String>,
    pub host: String,
    pub port: Option<i64>,
    pub path: String,
    pub query: Option<String>,
    #[serde(default)]
    pub status: i64,
    #[serde(default = "default_resource_type")]
    pub resource_type: String,
    #[serde(default)]
    pub size_bytes: i64,
    #[serde(default)]
    pub duration_ms: i64,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub tls_version: Option<String>,
    pub tls_fingerprint: Option<TlsFingerprintRecord>,
    #[serde(default = "default_risk")]
    pub risk_level: String,
    #[serde(default)]
    pub request_headers: Vec<HeaderEntry>,
    #[serde(default)]
    pub response_headers: Vec<HeaderEntry>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub response_body_metadata: Option<BodyCaptureMetadata>,
    #[serde(default)]
    pub crypto_snippets: Option<Vec<CryptoCodeSnippet>>,
    pub hook: Option<HookRecord>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureEventInput {
    pub session_id: String,
    #[serde(default = "default_source")]
    pub source: String,
    pub source_instance_id: Option<String>,
    pub request_id: Option<String>,
    pub timestamp: Option<i64>,
    pub phase: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureEvent {
    pub session_id: String,
    pub source: String,
    pub source_instance_id: String,
    pub request_id: String,
    pub sequence: i64,
    pub timestamp: i64,
    pub phase: String,
    pub payload: Value,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAccessMode {
    #[default]
    Private,
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaptureListenerSettings {
    #[serde(default)]
    pub lan_enabled: bool,
    #[serde(default)]
    pub access_mode: ClientAccessMode,
    #[serde(default)]
    pub access_rules: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseProxySettings {
    pub target_url: String,
    pub local_port: u16,
    pub lan_enabled: bool,
    pub preserve_host: bool,
}

impl Default for ReverseProxySettings {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            local_port: 0,
            lan_enabled: false,
            preserve_host: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseProxySettingsInput {
    pub target_url: String,
    #[serde(default)]
    pub local_port: u16,
    #[serde(default)]
    pub lan_enabled: bool,
    #[serde(default)]
    pub preserve_host: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseProxyStatus {
    pub running: bool,
    pub target_url: String,
    pub local_port: u16,
    pub lan_enabled: bool,
    pub preserve_host: bool,
    pub bound_port: Option<u16>,
    pub local_url: Option<String>,
    pub lan_urls: Vec<String>,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataStorageSettings {
    pub auto_cleanup_enabled: bool,
    pub retention_days: i64,
    pub save_binary_responses: bool,
}

impl Default for DataStorageSettings {
    fn default() -> Self {
        Self {
            auto_cleanup_enabled: true,
            retention_days: 30,
            save_binary_responses: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataStorageSettingsInput {
    pub auto_cleanup_enabled: bool,
    pub retention_days: i64,
    pub save_binary_responses: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageStats {
    pub database_bytes: i64,
    pub response_body_bytes: i64,
    pub session_count: i64,
    pub request_count: i64,
    pub database_path: String,
    pub data_directory: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamProxySettings {
    pub mode: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub has_password: bool,
    pub bypass: Vec<String>,
}

impl Default for UpstreamProxySettings {
    fn default() -> Self {
        Self {
            mode: "direct".to_string(),
            host: String::new(),
            port: 7890,
            username: String::new(),
            has_password: false,
            bypass: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "*.local".to_string(),
            ],
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamProxySettingsInput {
    pub mode: String,
    #[serde(default)]
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    pub password: Option<String>,
    #[serde(default)]
    pub clear_password: bool,
    #[serde(default)]
    pub bypass: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxySettings {
    pub enabled: bool,
    pub active: bool,
    pub recovery_pending: bool,
    pub bypass: Vec<String>,
    pub last_error: Option<String>,
}

impl Default for SystemProxySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            active: false,
            recovery_pending: false,
            bypass: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "*.local".to_string(),
            ],
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxySettingsInput {
    pub enabled: bool,
    #[serde(default)]
    pub bypass: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredSystemProxySettings {
    pub enabled: bool,
    pub bypass: Vec<String>,
}

impl Default for StoredSystemProxySettings {
    fn default() -> Self {
        let settings = SystemProxySettings::default();
        Self {
            enabled: settings.enabled,
            bypass: settings.bypass,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EffectiveUpstreamProxy {
    pub mode: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub bypass: Vec<String>,
}

/// Result of probing ShowNet egress (direct or via configured upstream proxy).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamProbeResult {
    pub ok: bool,
    pub mode: String,
    pub host: String,
    pub port: u16,
    pub target: String,
    pub latency_ms: u64,
    pub message: String,
}

/// Parsed from process environment HTTP(S)_PROXY / ALL_PROXY (not used automatically by ShowNet).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedEnvProxy {
    pub mode: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub source: String,
    pub raw: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredCertificateAuthority {
    pub certificate_der: String,
    pub encrypted_private_key: String,
    pub created_at: i64,
}

/// Token window assumed for a provider that has never been configured.
pub const DEFAULT_AI_CONTEXT_TOKENS: u32 = 200_000;
/// Smallest window the analysis prompt builder can still work with.
pub const MIN_AI_CONTEXT_TOKENS: u32 = 1_024;
/// Ceiling that keeps a mistyped value from turning into an unbounded prompt.
pub const MAX_AI_CONTEXT_TOKENS: u32 = 2_000_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiProviderSettings {
    pub provider: String,
    pub base_url: String,
    pub model: String,
    pub context_tokens: u32,
    pub has_api_key: bool,
}

impl Default for AiProviderSettings {
    fn default() -> Self {
        Self {
            provider: "claudegpt".to_string(),
            base_url: "https://claudegpt.org/v1".to_string(),
            model: "gpt-5.5".to_string(),
            context_tokens: DEFAULT_AI_CONTEXT_TOKENS,
            has_api_key: false,
        }
    }
}

fn default_context_tokens() -> u32 {
    DEFAULT_AI_CONTEXT_TOKENS
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AiAnalysisSettings {
    pub two_stage_analysis: bool,
    pub allow_mcp_tools: bool,
    pub streaming_output: bool,
    pub max_agent_turns: u32,
}

impl Default for AiAnalysisSettings {
    fn default() -> Self {
        Self {
            two_stage_analysis: true,
            allow_mcp_tools: true,
            streaming_output: true,
            max_agent_turns: 8,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiModelDiscoveryInput {
    pub base_url: String,
    pub api_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiProviderSettingsInput {
    pub provider: String,
    pub base_url: String,
    pub model: String,
    #[serde(default = "default_context_tokens")]
    pub context_tokens: u32,
    pub api_key: Option<String>,
    #[serde(default)]
    pub clear_api_key: bool,
}

#[derive(Clone, Debug)]
pub struct EffectiveAiProviderSettings {
    pub provider: String,
    pub base_url: String,
    pub model: String,
    pub context_tokens: u32,
    pub api_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAiProviderSettings {
    pub provider: String,
    pub base_url: String,
    pub model: String,
    #[serde(default = "default_context_tokens")]
    pub context_tokens: u32,
    pub encrypted_api_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartAnalysisInput {
    pub session_id: String,
    pub mode: String,
    #[serde(default)]
    pub include_static: bool,
    #[serde(default)]
    pub manual_request_ids: Vec<String>,
    #[serde(default)]
    pub include_annotations: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FollowupAnalysisInput {
    pub analysis_id: String,
    pub question: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisReport {
    pub id: String,
    pub session_id: String,
    pub mode: String,
    pub status: String,
    pub request_count: i64,
    pub key_request_count: i64,
    pub selected_request_ids: Vec<String>,
    pub content: String,
    pub provider: String,
    pub model: String,
    pub error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisActivity {
    pub id: i64,
    pub analysis_id: String,
    pub phase: String,
    pub message: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillToolCallAudit {
    pub id: i64,
    pub analysis_id: String,
    pub tool_name: String,
    pub status: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub duration_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillRunAudit {
    pub id: String,
    pub analysis_id: String,
    pub skill_id: String,
    pub skill_name: String,
    pub skill_version: String,
    pub mode: String,
    pub status: String,
    pub permissions: Vec<String>,
    pub planned_tools: Vec<String>,
    pub actual_tool_calls: Vec<SkillToolCallAudit>,
    pub input_summary: serde_json::Value,
    pub output_summary: serde_json::Value,
    pub error: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub duration_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisStreamEvent {
    pub analysis_id: String,
    pub session_id: String,
    pub phase: String,
    pub delta: String,
    pub request_count: i64,
    pub key_request_count: i64,
    pub report: Option<AnalysisReport>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisChatMessage {
    pub id: i64,
    pub analysis_id: String,
    pub role: String,
    pub content: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerSettings {
    pub enabled: bool,
    pub port: u16,
    pub allow_writes: bool,
    pub has_access_token: bool,
}

impl Default for McpServerSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 8899,
            allow_writes: false,
            has_access_token: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerSettingsInput {
    pub enabled: bool,
    pub port: u16,
    #[serde(default)]
    pub allow_writes: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredMcpServerSettings {
    pub enabled: bool,
    pub port: u16,
    pub allow_writes: bool,
    pub encrypted_access_token: String,
}

#[derive(Clone, Debug)]
pub struct EffectiveMcpServerSettings {
    pub enabled: bool,
    pub port: u16,
    pub allow_writes: bool,
    pub access_token: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpRecentClient {
    pub name: String,
    pub version: Option<String>,
    pub connected_at: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerStatus {
    pub enabled: bool,
    pub running: bool,
    pub starting: bool,
    pub host: String,
    pub port: u16,
    pub endpoint: String,
    pub protocol_version: String,
    pub tool_count: usize,
    pub allow_writes: bool,
    pub has_access_token: bool,
    pub last_error: Option<String>,
    pub recent_clients: Vec<McpRecentClient>,
    pub last_request_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpClientSettings {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub enabled: bool,
    pub has_access_token: bool,
    pub tool_count: usize,
    pub last_connected_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpClientSettingsInput {
    pub id: Option<String>,
    pub name: String,
    pub endpoint: String,
    pub enabled: bool,
    pub access_token: Option<String>,
    #[serde(default)]
    pub clear_access_token: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredMcpClientSettings {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub enabled: bool,
    pub encrypted_access_token: Option<String>,
    #[serde(default)]
    pub tool_count: usize,
    pub last_connected_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EffectiveMcpClientSettings {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub access_token: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpClientTestResult {
    pub server: McpClientSettings,
    pub protocol_version: String,
    pub server_name: String,
    pub tools: Vec<String>,
}
