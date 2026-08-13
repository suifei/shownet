import type { ObservableMethod } from "./httpMethods.ts";

export type ViewId = "traffic" | "analysis" | "browser" | "lab" | "skills" | "settings" | "advanced";

export type SourceType =
  | "browser"
  | "desktop"
  | "terminal"
  | "script"
  | "mobile"
  | "iot"
  | "reverse";

export type RiskLevel = "none" | "info" | "warning" | "critical";

export interface Session {
  id: string;
  name: string;
  createdAt: string;
  requestCount: number;
  errorCount: number;
  active: boolean;
  sources: SourceType[];
  analysisReportCount: number;
  latestAnalysisStatus?: Exclude<AnalysisStatus, "idle">;
  latestAnalysisUpdatedAt?: number;
}

export interface HeaderEntry {
  name: string;
  value: string;
}

export interface ClientTlsFingerprint {
  ja3: string;
  ja3Raw: string;
  ja4: string;
  ja4Raw: string;
  sni?: string;
  alpn: string[];
  legacyVersion: string;
  offeredVersions: string[];
  cipherSuites: string[];
  extensions: string[];
  supportedGroups: string[];
  signatureAlgorithms: string[];
  grease: boolean;
}

export interface Http2Setting {
  id: number;
  name: string;
  value: number;
}

export interface Http2PriorityFrame {
  streamId: number;
  exclusive: boolean;
  dependency: number;
  weight: number;
}

export interface Http2PriorityUpdate {
  prioritizedStreamId: number;
  fieldValue: string;
}

export interface Http2Fingerprint {
  hash: string;
  canonical: string;
  settings: Http2Setting[];
  connectionWindowUpdates: number[];
  priorityFrames: Http2PriorityFrame[];
  priorityUpdates: Http2PriorityUpdate[];
  pseudoHeaderOrder?: string[];
  complete: boolean;
  note: string;
}

export interface TlsFingerprintRecord {
  captureMode: "tunnel" | "mitm";
  inbound: ClientTlsFingerprint;
  outbound: {
    mode: "pass-through" | "independent" | "mapped-from-inbound" | string;
    profile: string;
    ja3?: string;
    /** The stable identifier — compare this with `inbound.ja4`, not the JA3s.
     *  Chrome randomises the GREASE values JA3 covers on every connection, so
     *  inbound JA3 never repeats while inbound JA4 stays fixed. */
    ja4?: string;
    note: string;
    fidelityLabel?: string;
    engine?: string;
    negotiatedAlpn?: string;
    selectedFromInbound?: boolean;
    ja3Parity?: boolean;
    applicationProtocol?: string;
  };
  http2?: Http2Fingerprint;
}

export interface BodyCaptureMetadata {
  captured: boolean;
  contentEncoding?: string;
  decoded: boolean;
  truncated: boolean;
  complete: boolean;
  wireBytes: number;
  decodedBytes: number;
  format: "empty" | "text" | "base64" | "omitted";
  error?: string;
  omittedReason?: string;
}

export type RequestState = "pending" | "streaming" | "complete" | "failed" | "tunnel";

export interface RequestAnnotationSummary {
  bookmarked: boolean;
  color?: "red" | "yellow" | "green" | "blue" | "gray";
  struckThrough: boolean;
  notePreview?: string;
  tags: string[];
}

export interface RequestAnnotation {
  requestId: string;
  bookmarked: boolean;
  color?: "red" | "yellow" | "green" | "blue" | "gray";
  struckThrough: boolean;
  note: string;
  tags: string[];
  createdAt: number;
  updatedAt: number;
}

export interface RequestAnnotationInput {
  requestId: string;
  bookmarked: boolean;
  color?: RequestAnnotation["color"];
  struckThrough: boolean;
  note: string;
  tags: string[];
}

export interface RequestListItem {
  id: string;
  order: number;
  startedAt: number;
  completedAt?: number;
  state: RequestState;
  method: string;
  scheme: string;
  host: string;
  port?: number;
  path: string;
  query?: string;
  status?: number;
  type: string;
  source: SourceType;
  sourceInstanceId: string;
  protocol: string;
  sizeBytes: number;
  durationMs?: number;
  risk: RiskLevel;
  hasHook: boolean;
  cryptoSnippetCount: number;
  tlsIntercepted: boolean;
  tlsVersion?: string;
  annotation?: RequestAnnotationSummary;
}

export type RequestField =
  | "order"
  | "startedAt"
  | "state"
  | "method"
  | "scheme"
  | "host"
  | "path"
  | "url"
  | "status"
  | "type"
  | "source"
  | "sourceInstanceId"
  | "protocol"
  | "sizeBytes"
  | "durationMs"
  | "risk"
  | "hasHook"
  | "cryptoSnippetCount"
  | "tlsIntercepted"
  | "requestHeader"
  | "responseHeader"
  | "requestBody"
  | "responseBody"
  | "hook";

export type FilterExpression =
  | { kind: "group"; operator: "and" | "or"; children: FilterExpression[] }
  | {
      kind: "predicate";
      field: RequestField;
      operator:
        | "contains"
        | "not_contains"
        | "equals"
        | "not_equals"
        | "starts_with"
        | "ends_with"
        | "wildcard"
        | "regex"
        | "gt"
        | "gte"
        | "lt"
        | "lte"
        | "exists";
      value?: string | number | boolean;
    };

export interface RequestSort {
  field: RequestField;
  direction: "asc" | "desc";
}

export interface RequestQuery {
  sessionId: string;
  filter?: FilterExpression;
  sort: RequestSort[];
  cursor?: string;
  limit: number;
}

export interface RequestWindowQuery {
  sessionId: string;
  filter?: FilterExpression;
  sort: RequestSort[];
  offset: number;
  limit: number;
}

export interface RequestQueryCancellationAck {
  queryId: string;
  accepted: boolean;
  settled: boolean;
  backendWaitMs: number;
}

export interface RequestQueryIdleMeasurement extends RequestQueryCancellationAck {
  clickToIdleMs: number;
}

export interface SoakDiagnosticsStatus {
  enabled: boolean;
  sessionId?: string;
  requestCount: number;
  samplesRecorded: number;
  targetSamples: number;
  minimumRequestCount: number;
  requestStride: number;
}

export interface FacetCount {
  value: string;
  count: number;
}

export interface RequestFacets {
  hosts: FacetCount[];
  methods: FacetCount[];
  sources: FacetCount[];
  protocols: FacetCount[];
  statuses: FacetCount[];
  types: FacetCount[];
  risks: FacetCount[];
}

export interface RequestListPage {
  items: RequestListItem[];
  nextCursor?: string;
  totalCount: number;
  filteredCount: number;
  hookCount: number;
  bookmarkedCount: number;
  facets: RequestFacets;
}

export interface RequestListWindow {
  items: RequestListItem[];
  offset: number;
}

export interface RequestListEvent {
  sessionId: string;
  item: RequestListItem;
}

export interface SavedRequestView {
  id: string;
  name: string;
  sessionId?: string;
  filter?: FilterExpression;
  sort: RequestSort[];
  columns?: unknown;
  createdAt: number;
  updatedAt: number;
}

export interface CryptoCodeSnippet {
  ordinal: number;
  kind: string;
  name?: string;
  algorithms: string[];
  startLine: number;
  endLine: number;
  code: string;
  truncated: boolean;
  sourceTruncated: boolean;
}

export interface RequestRecord {
  id: string;
  order: number;
  time: string;
  method: ObservableMethod;
  host: string;
  path: string;
  query?: string;
  status: number;
  type: "fetch" | "xhr" | "document" | "script" | "image" | "font" | "websocket" | "sse";
  size: string;
  duration: number;
  source: SourceType;
  protocol: "h2" | "http/1.1" | "ws";
  tls: string;
  tlsFingerprint?: TlsFingerprintRecord;
  risk: RiskLevel;
  requestHeaders: HeaderEntry[];
  responseHeaders: HeaderEntry[];
  requestBody?: string;
  responseBody: string;
  responseBodyMetadata?: BodyCaptureMetadata;
  cryptoSnippetCount: number;
  hook?: {
    algorithm: string;
    input: string;
    output: string;
  };
}

export interface ReplaySettings {
  repeatCount: number;
  startDelayMs: number;
  intervalMs: number;
  maxConcurrency: number;
  throughCapture: boolean;
  includeCookie: boolean;
  includeAuthorization: boolean;
  followRedirects: boolean;
  verifyTls: boolean;
  useUpstreamProxy: boolean;
}

export interface ReplayBatchItem {
  id: string;
  sourceRequestId: string;
  runIndex: number;
  status: "queued" | "running" | "complete" | "failed" | "cancelled";
  capturedRequestId?: string;
  statusCode?: number;
  durationMs?: number;
  error?: string;
  startedAt?: number;
  finishedAt?: number;
}

export interface ReplayBatch {
  id: string;
  sessionId: string;
  status: "queued" | "running" | "complete" | "failed" | "cancelled";
  settings: ReplaySettings;
  total: number;
  completed: number;
  succeeded: number;
  failed: number;
  items: ReplayBatchItem[];
  createdAt: number;
  updatedAt: number;
}

export interface RequestDraft {
  id: string;
  sessionId?: string;
  sourceRequestId?: string;
  name: string;
  method: string;
  url: string;
  headers: HeaderEntry[];
  body: string;
  bodyType: "none" | "json" | "text" | "xml" | "raw" | "form-data" | "urlencoded" | "file";
  auth: Record<string, unknown>;
  settings: Record<string, unknown>;
  environmentId?: string;
  collectionId?: string;
  folderId?: string;
  tags: string[];
  specOperationKey?: string;
  specFingerprint?: string;
  createdAt: number;
  updatedAt: number;
}

export interface RequestDraftBatchLocation {
  collectionId?: string;
  folderId?: string;
}

export interface RequestDraftBatchUpdateInput {
  draftIds: string[];
  location?: RequestDraftBatchLocation;
  addTags: string[];
  removeTags: string[];
}

export interface RequestCollection {
  id: string;
  name: string;
  description: string;
  defaultHeaders: HeaderEntry[];
  defaultAuth: Record<string, unknown>;
  defaultEnvironmentId?: string;
  sourceFormat?: string;
  sourcePath?: string;
  sourceFingerprint?: string;
  sourceSyncedAt?: number;
  sortOrder: number;
  draftCount: number;
  folderCount: number;
  createdAt: number;
  updatedAt: number;
}

export interface RequestCollectionFolder {
  id: string;
  collectionId: string;
  parentId?: string;
  name: string;
  depth: number;
  sortOrder: number;
  draftCount: number;
  createdAt: number;
  updatedAt: number;
}

export interface RequestCollectionWorkspace {
  collections: RequestCollection[];
  folders: RequestCollectionFolder[];
  drafts: RequestDraft[];
}

export interface CollectionImportItem {
  name: string;
  method: string;
  url: string;
  headers: HeaderEntry[];
  body: string;
  bodyType: RequestDraft["bodyType"];
  auth?: Record<string, unknown>;
  settings?: Record<string, unknown>;
  environmentId?: string;
  tags?: string[];
  folderPath: string[];
  sourceKey?: string;
  sourceFingerprint?: string;
}

export interface CollectionImportEnvironmentVariable {
  name: string;
  value: string;
  secret: boolean;
  enabled: boolean;
}

export interface CollectionImportEnvironment {
  sourceId: string;
  name: string;
  variables: CollectionImportEnvironmentVariable[];
}

export interface CollectionImportMetadata {
  description: string;
  defaultHeaders: HeaderEntry[];
  defaultAuth: Record<string, unknown>;
  defaultEnvironmentId?: string;
  sourceFormat?: string;
  sourcePath?: string;
  sourceFingerprint?: string;
  sourceSyncedAt?: number;
}

export interface CollectionImportPreview {
  sourceFormat: "postman" | "insomnia" | "openapi" | "har" | "shownet";
  suggestedName: string;
  items: CollectionImportItem[];
  collection?: CollectionImportMetadata;
  environments?: CollectionImportEnvironment[];
  warnings: string[];
  sourcePath?: string;
  sourceFingerprint?: string;
}

export interface CollectionImportResult {
  collection: RequestCollection;
  importedCount: number;
  createdFolderCount: number;
  importedEnvironmentCount: number;
}

export interface CollectionSyncChange {
  kind: "add" | "modify" | "remove";
  operationKey: string;
  item?: CollectionImportItem;
  draftId?: string;
  currentName?: string;
  currentMethod?: string;
  currentUrl?: string;
  changedFields: Array<"operation" | "name" | "method" | "url" | "headers" | "body" | "auth" | "settings" | "environment" | "tags" | "folder" | "request">;
  localOverride: boolean;
}

export interface CollectionSyncPreview {
  collectionId: string;
  collectionName: string;
  sourcePath: string;
  sourceFingerprint: string;
  changes: CollectionSyncChange[];
  unchangedCount: number;
  warnings: string[];
}

export interface CollectionSyncResult {
  collection: RequestCollection;
  addedCount: number;
  updatedCount: number;
  detachedCount: number;
}

export interface CollectionExportResult {
  path: string;
  format: "shownet" | "postman";
  itemCount: number;
}

export interface RequestRun {
  id: string;
  draftId: string;
  status: "running" | "complete" | "failed" | "cancelled";
  requestSnapshot: Record<string, unknown>;
  responseSnapshot: Record<string, unknown>;
  error?: string;
  startedAt: number;
  finishedAt?: number;
}

export interface RequestCookieRecord {
  name: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: "Lax" | "Strict" | "None";
  expiresAt?: number;
  persistent: boolean;
}

export interface EnvironmentVariable {
  id: string;
  name: string;
  value: string;
  secret: boolean;
  hasValue: boolean;
  enabled: boolean;
  updatedAt: number;
}

export interface EnvironmentRecord {
  id: string;
  name: string;
  kind: "global" | "named";
  active: boolean;
  variables: EnvironmentVariable[];
  createdAt: number;
  updatedAt: number;
}

export interface CaptureRule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  stage: "connection" | "request" | "response";
  matcher: FilterExpression;
  action: Record<string, unknown>;
  createdBy: "user" | "agent-draft";
  revision: number;
  hitCount: number;
  lastError?: string;
  createdAt: number;
  updatedAt: number;
}

export interface CaptureRuleRevision {
  id: string;
  ruleId: string;
  revision: number;
  snapshot: {
    name?: string;
    enabled?: boolean;
    priority?: number;
    stage?: CaptureRule["stage"];
    matcher?: FilterExpression;
    action?: Record<string, unknown>;
    createdBy?: CaptureRule["createdBy"];
  };
  createdAt: number;
}

export interface RulePreviewResult {
  matched: boolean;
  requestId: string;
  stage: CaptureRule["stage"];
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  changes: string[];
  warnings: string[];
}

export interface CaptureRuleRun {
  id: string;
  requestId: string;
  ruleId: string;
  ruleName: string;
  revision: number;
  stage: string;
  result: string;
  diffSummary: Record<string, unknown>;
  durationMs: number;
  error?: string;
  createdAt: number;
}

export interface BreakpointTask {
  id: string;
  sessionId: string;
  requestId: string;
  ruleId: string;
  ruleName: string;
  stage: "request" | "response";
  method: string;
  url: string;
  status?: number;
  requestHeaders: HeaderEntry[];
  responseHeaders: HeaderEntry[];
  requestBody?: string;
  responseBody?: string;
  bodyEditable: boolean;
  bodyUnavailableReason?: string;
  createdAt: number;
  expiresAt: number;
}

export interface BreakpointQueueSnapshot {
  tasks: BreakpointTask[];
  capacity: number;
  skippedCount: number;
  generatedAt: number;
}

export interface BreakpointDecisionInput {
  taskId: string;
  action: "continue" | "abort";
  method?: string;
  url?: string;
  status?: number;
  requestHeaders?: HeaderEntry[];
  responseHeaders?: HeaderEntry[];
  requestBody?: string;
  responseBody?: string;
}

export interface DiagnosticCheck {
  id: string;
  label: string;
  status: "healthy" | "idle" | "warning" | "error";
  summary: string;
  detail: string;
  repairAction?: string;
}

export interface ConnectionDiagnostics {
  checks: DiagnosticCheck[];
  generatedAt: number;
}

export type AnalysisMode = "auto" | "api" | "security" | "performance" | "crypto";

export type AnalysisStatus = "idle" | "filtering" | "analyzing" | "complete" | "failed";

export interface AnalysisReport {
  id: string;
  sessionId: string;
  mode: AnalysisMode;
  status: Exclude<AnalysisStatus, "idle">;
  requestCount: number;
  keyRequestCount: number;
  selectedRequestIds: string[];
  content: string;
  provider: string;
  model: string;
  error?: string;
  createdAt: number;
  updatedAt: number;
}

export interface AlgorithmReplayExportResult {
  sessionId: string;
  language: string;
  directory: string;
  files: string[];
  packageHash: string;
  gateVerdict: VerificationVerdict;
  bytesWritten: number;
}

export type VerificationVerdict = "verified" | "failed" | "unverifiable";

export interface EvaluationExportResult {
  sessionId: string;
  analysisId?: string;
  directory: string;
  files: string[];
  bytesWritten: number;
  scorecardComposite?: number;
  allFullCredit?: boolean;
}

/** How much of a generated SDK the capture actually established. */
export interface SdkReadiness {
  endpointsConfirmed: number;
  endpointsTotal: number;
  cryptoVerified: number;
  cryptoUnverified: number;
  fingerprintTargetKnown: boolean;
  packageRuntimeVerified: boolean;
  gapCount: number;
}

export interface SdkExportResult {
  sessionId: string;
  language: string;
  directory: string;
  files: string[];
  readiness: SdkReadiness;
  gateVerdict: VerificationVerdict;
  bytesWritten: number;
}

export interface ClientHelloPresetInfo {
  id: string;
  family: string;
  majorVersion: number;
  label: string;
  note: string;
  alpn?: string[];
  documentedJa3?: string | null;
  recipeFingerprint?: string;
  claimsFullBrowserJa3?: boolean;
  h2Settings?: Array<{ id: number; value: number }>;
  h2PseudoHeaderOrder?: string[];
  h2Fingerprint?: string;
}

export interface OutboundTlsProfileStatus {
  profile: string;
  /** Active versioned ClientHello catalog preset id (e.g. chrome150). */
  presetId?: string;
  preset?: ClientHelloPresetInfo | null;
  presets?: ClientHelloPresetInfo[];
  fidelityLabel: string;
  note: string;
  browserFamily?: string;
  browserMajorVersion?: number;
  engine?: string;
  autoFromInbound?: boolean;
  impersonateRequested?: boolean;
  ja3Parity: boolean;
  supportsFullBrowserJa3: boolean;
  realImpersonateStackAvailable?: boolean;
  impersonateUnavailableReason?: string;
  /** Measured alignment (recipe until live ClientHello matches a golden). */
  alignmentLevel?: string;
  alignmentClaim?: string;
  /** Ceiling from a captured golden file — not a wire “已对齐” claim. */
  goldenAuthorisedCeiling?: string;
  goldenAuthorisedClaim?: string;
  goldenStatus?: string | null;
  goldenSource?: string | null;
  toolMatchedGolden?: boolean;
  toolHelloId?: string | null;
  documentedJa3?: string | null;
  h2Fingerprint?: string | null;
  h2Settings?: Array<{ id: number; value: number }> | null;
  h2PseudoHeaderOrder?: string[] | null;
  targetJa3?: string | null;
  targetJa3Label?: string | null;
  /** All preset ids (versioned catalog). */
  profiles?: string[];
  profileCipherFingerprint?: string;
  recipeFingerprint?: string;
}

export interface PxSettings {
  decryptEnabled: boolean;
  interceptEcData: boolean;
}

export interface PxEvidenceItem {
  requestId: string;
  method: string;
  host: string;
  path: string;
  markers: string[];
  hasEcData: boolean;
  cookieHints: string[];
}

export interface PxDecodeResult {
  requestId: string;
  status: string;
  summary: string;
  fields: Record<string, unknown>;
  notes: string[];
}

export interface AnalysisActivity {
  id: number;
  analysisId: string;
  phase: string;
  message: string;
  elapsedMs?: number;
  createdAt: number;
}

export interface SkillToolCallAudit {
  id: number;
  analysisId: string;
  toolName: string;
  status: "running" | "complete" | "failed";
  startedAt: number;
  finishedAt?: number;
  durationMs?: number;
}

export interface SkillRunAudit {
  id: string;
  analysisId: string;
  skillId: string;
  skillName: string;
  skillVersion: string;
  mode: AnalysisMode;
  status: "running" | "complete" | "failed";
  permissions: string[];
  plannedTools: string[];
  actualToolCalls: SkillToolCallAudit[];
  inputSummary: Record<string, unknown>;
  outputSummary: Record<string, unknown>;
  error?: string;
  startedAt: number;
  finishedAt?: number;
  durationMs?: number;
}

export interface AnalysisStreamEvent {
  analysisId: string;
  sessionId: string;
  phase:
    | "filtering"
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
    | "first-visible"
    | "content-reset"
    | "delta"
    | "complete"
    | "error"
    | "followup-start"
    | "followup-delta"
    | "followup-complete"
    | "followup-error";
  delta: string;
  requestCount: number;
  keyRequestCount: number;
  report?: AnalysisReport;
  message?: string;
  elapsedMs?: number;
}

export interface AnalysisChatMessage {
  id: number;
  analysisId: string;
  role: "user" | "assistant";
  content: string;
  createdAt: number;
}

export interface AiProviderSettings {
  provider: "claudegpt" | "compatible" | "local";
  baseUrl: string;
  model: string;
  contextTokens: number;
  hasApiKey: boolean;
}

export interface AiAnalysisSettings {
  twoStageAnalysis: boolean;
  allowMcpTools: boolean;
  streamingOutput: boolean;
  maxAgentTurns: number;
}

export interface McpServerSettings {
  enabled: boolean;
  port: number;
  allowWrites: boolean;
  hasAccessToken: boolean;
}

export interface McpServerStatus extends McpServerSettings {
  running: boolean;
  starting: boolean;
  host: string;
  endpoint: string;
  protocolVersion: string;
  toolCount: number;
  lastError?: string;
  recentClients: McpRecentClient[];
  lastRequestAt?: number | null;
}

export interface McpRecentClient {
  name: string;
  version?: string;
  connectedAt: number;
}

export interface McpClientSettings {
  id: string;
  name: string;
  endpoint: string;
  enabled: boolean;
  hasAccessToken: boolean;
  toolCount: number;
  lastConnectedAt?: number;
  lastError?: string;
}

export interface McpClientTestResult {
  server: McpClientSettings;
  protocolVersion: string;
  serverName: string;
  tools: string[];
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  access: "read" | "write" | "external";
}

export interface SkillDefinition {
  id: string;
  name: string;
  version: string;
  category: string;
  summary: string;
  status: "ready" | "beta";
  trigger: string;
  tools: string[];
  permissions: string[];
  objectives: string[];
  outputs: string[];
}

export interface SkillPlanStage {
  id: string;
  label: string;
  detail: string;
  skillId: string;
  kind: "skill" | "decision" | "artifact" | "report";
  suggestedToolCount: number;
  requiredOutputCount: number;
  maxRetries: number;
}

export interface SkillPlan {
  mode: AnalysisMode;
  selectedSkillIds: string[];
  toolNames: string[];
  reasons: string[];
  stages: SkillPlanStage[];
}

export type GraphNodeKind = "skill" | "decision" | "artifact" | "report";
export type GraphNodeStatus = "pending" | "running" | "succeeded" | "failed" | "skipped";
export type GraphRunStatus = "running" | "completed" | "completedWithGaps" | "failed" | "cancelled";

export interface GraphArtifactContract {
  schemaVersion: string;
  expectedSkillId?: string;
  requiredFields: string[];
  requiredOutputs: string[];
  minEvidenceRefs: number;
}

export interface AnalysisGraphNode {
  id: string;
  label: string;
  detail: string;
  kind: GraphNodeKind;
  skillId?: string;
  suggestedTools: string[];
  permissions: string[];
  artifactContract: GraphArtifactContract;
  maxRetries: number;
}

export interface GraphToolCall {
  toolName: string;
  access: "read" | "write" | "external" | string;
  status: "complete" | "failed" | string;
  error?: string;
  startedAt: number;
  finishedAt: number;
}

export interface GraphNodeRun {
  nodeId: string;
  status: GraphNodeStatus;
  attempt: number;
  modelTurnCount: number;
  toolCallCount: number;
  toolCalls: GraphToolCall[];
  artifact?: unknown;
  validationErrors: string[];
  error?: string;
  startedAt?: number;
  finishedAt?: number;
}

export interface GraphEvent {
  sequence: number;
  nodeId?: string;
  event: string;
  detail: string;
  createdAt: number;
}

export interface AnalysisGraphDefinition {
  id: string;
  schemaVersion: string;
  mode: string;
  entryNodeId: string;
  nodes: AnalysisGraphNode[];
  edges: Array<{ from: string; to: string; condition: string }>;
}

export interface AnalysisGraphRun {
  analysisId: string;
  definition: AnalysisGraphDefinition;
  status: GraphRunStatus;
  currentNodeId?: string;
  maxModelTurns: number;
  modelTurnCount: number;
  nodes: GraphNodeRun[];
  events: GraphEvent[];
  createdAt: number;
  updatedAt: number;
}

export interface SignatureRequestEvidence {
  requestId: string;
  order: number;
  method: string;
  url: string;
  status: number;
  protocol: string;
}

export interface SignatureAdapterHarness {
  adapterId: string;
  adapterVersion: string;
  vendor: string;
  confidence: "high" | "medium" | "low";
  evidenceHash: string;
  matchedRequests: SignatureRequestEvidence[];
  dynamicFields: string[];
  cookieNames: string[];
  hookNames: string[];
  cryptoAlgorithms: string[];
  fingerprintDependencies: string[];
  requiredInputs: string[];
  evidenceGaps: string[];
  language: "javascript";
  code: string;
}

export type ClientAccessMode = "private" | "allow" | "deny";

export interface CaptureListenerSettings {
  lanEnabled: boolean;
  accessMode: ClientAccessMode;
  accessRules: string[];
}

export interface RuntimeStatus extends CaptureListenerSettings {
  appVersion: string;
  platform: string;
  proxyPort: number;
  listenHost: string;
  lanAddresses: string[];
  proxyRunning: boolean;
  activeSessionId?: string;
  caInstalled: boolean;
  transparentModeAvailable: boolean;
  systemProxyEnabled: boolean;
  systemProxyActive: boolean;
  systemProxyRecoveryPending: boolean;
}

export interface ProxyTerminalLaunchResult {
  terminal: string;
  proxyUrl: string;
  caBundleConfigured: boolean;
  environmentKeys: string[];
}

export interface ReverseProxySettingsInput {
  targetUrl: string;
  localPort: number;
  lanEnabled: boolean;
  preserveHost: boolean;
}

export interface ReverseProxyStatus extends ReverseProxySettingsInput {
  running: boolean;
  boundPort?: number;
  localUrl?: string;
  lanUrls: string[];
  sessionId?: string;
}

export interface UpdateCheckResult {
  currentVersion: string;
  latestVersion: string;
  available: boolean;
  notes?: string;
  publishedAt?: string;
  downloadUrl?: string;
  platform: string;
}

export interface CaptureEvent {
  sessionId: string;
  source: SourceType;
  sourceInstanceId: string;
  requestId: string;
  sequence: number;
  timestamp: number;
  phase: "request" | "response" | "websocket" | "sse" | "hook" | "interaction" | "storage" | "connection";
  payload: unknown;
}

export interface WebSocketFramePayload {
  direction: "client_to_server" | "server_to_client";
  opcode: "text" | "binary" | "ping" | "pong" | "close" | "frame" | "capture_limit";
  data: string;
  encoding: "utf8" | "base64";
  sizeBytes: number;
  truncated: boolean;
  index: number;
  closeCode?: number;
  maxEvents?: number;
  maxBytes?: number;
}

export interface WebSocketFrameEvent extends Omit<CaptureEvent, "payload"> {
  payload: WebSocketFramePayload;
}

export interface SseField {
  name: string;
  value: string;
}

export interface SseEventPayload {
  kind: "event" | "heartbeat" | "metadata" | "partial" | "stream_notice" | "stream_end" | "capture_limit";
  event: string;
  id?: string;
  retry?: number;
  data: string;
  raw: string;
  fields: SseField[];
  comments: string[];
  sizeBytes: number;
  truncated: boolean;
  incomplete: boolean;
  index: number;
  complete?: boolean;
  error?: string;
  wireBytes?: number;
  durationMs?: number;
  maxEvents?: number;
  maxEventBytes?: number;
  maxTotalBytes?: number;
  contentEncoding?: string;
}

export interface SseEvent extends Omit<CaptureEvent, "payload"> {
  payload: SseEventPayload;
}

export interface BrowserHookEvent {
  id: string;
  sessionId: string;
  sourceInstanceId: string;
  requestId?: string;
  sequence: number;
  timestamp: number;
  kind: "network" | "crypto" | "encoding" | "storage" | "interaction" | "runtime";
  name: string;
  url?: string;
  method?: string;
  input: unknown;
  output: unknown;
  stack?: string;
  durationMs?: number;
  correlation: "explicit" | "url-time" | "time-window" | "unmatched";
}

export interface ProxyBrowserStatus {
  running: boolean;
  ownerSessionId: string;
  debugPort: number;
  targetId: string;
  webSocketDebuggerUrl: string;
  sourceInstanceId: string;
  labUrl: string;
  honestUserAgent: string;
  browserLanguage: string;
  acceptLanguage: string;
  browserPresetId: string;
  browserPresetFamily: string;
  browserPresetMajorVersion: number;
  browserUserAgentMajorVersion: number;
}

export type UpstreamProxyMode = "direct" | "http" | "https" | "socks5";

export interface UpstreamProxySettings {
  mode: UpstreamProxyMode;
  host: string;
  port: number;
  username: string;
  hasPassword: boolean;
  bypass: string[];
}

export interface UpstreamProbeResult {
  ok: boolean;
  mode: string;
  host: string;
  port: number;
  target: string;
  latencyMs: number;
  message: string;
}

/** Parsed from process env HTTP(S)_PROXY / ALL_PROXY — not applied automatically. */
export interface DetectedEnvProxy {
  mode: UpstreamProxyMode | string;
  host: string;
  port: number;
  username: string;
  source: string;
  raw: string;
}

export type TlsInterceptionMode = "intercept_all" | "bypass_selected" | "bypass_all";

export interface TlsInterceptionSettings {
  mode: TlsInterceptionMode;
  bypass: string[];
  showBypassedConnections: boolean;
}

export interface SystemProxySettings {
  enabled: boolean;
  active: boolean;
  recoveryPending: boolean;
  bypass: string[];
  lastError?: string;
}

export interface DataStorageSettings {
  autoCleanupEnabled: boolean;
  retentionDays: number;
  saveBinaryResponses: boolean;
}

export interface StorageStats {
  databaseBytes: number;
  responseBodyBytes: number;
  sessionCount: number;
  requestCount: number;
  databasePath: string;
  dataDirectory: string;
}

/** Result of the deterministic, AI-free analysis pipeline. */
export interface AutonomousAnalysisResult {
  sessionId: string;
  mode: string;
  skillPlan: unknown;
  protection: unknown;
  export?: unknown | null;
  stages: string[];
  notes: string[];
}
