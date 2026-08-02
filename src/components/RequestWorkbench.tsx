import {
  Activity, Archive, ArrowLeft, Check, ChevronDown, ChevronRight, CircleAlert, Clock3, Code2, Cookie, Copy, Download, FileJson, FileUp, FlaskConical, Folder,
  Eye, EyeOff, FolderInput, FolderOpen, FolderPlus, FolderTree, GitCompareArrows, History, KeyRound, ListRestart, LoaderCircle, LockKeyhole, Pencil, Play, Plus, Save, Search,
  Pause, RefreshCw, RotateCcw, Route, Send, ShieldCheck, SlidersHorizontal, Square, Tag, Trash2, Upload, X,
} from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { initialCollectionSyncPreview, initialRequestCollectionWorkspace, initialRequests } from "../data";
import {
  captureRuleActionFromDraft, captureRuleDraftFromRule, captureRuleDraftValidationError, changeRuleDraftOperationTarget, changeRuleDraftStage,
  createEmptyRuleDraft, createEmptyRuleOperation, prefillMirrorDraftFromRequest,
  type RuleActionKind, type RuleDraft, type RuleOperationDraft, type RuleOperationTarget, type RuleStage,
} from "../captureRuleDraft";
import { matchesRequestDraftSearch, parseDraftTagInput, requestDraftCollectionPath } from "../requestCollections";
import { compareRequestRecords, draftToCurl, parseCurl, type RequestDiffEntry } from "../requestWorkbench";
import { HttpBodyViewer } from "./HttpBodyViewer";
import type {
  BodyCaptureMetadata, BreakpointDecisionInput, BreakpointQueueSnapshot, BreakpointTask, CaptureRule, CaptureRuleRevision, CaptureRuleRun, CollectionExportResult, CollectionImportPreview, CollectionImportResult, CollectionSyncPreview, CollectionSyncResult,
  EnvironmentRecord, EnvironmentVariable, HeaderEntry, ReplayBatch, ReplaySettings, RequestCollection, RequestCollectionFolder,
  RequestCollectionWorkspace, RequestCookieRecord, RequestDraft, RequestDraftBatchUpdateInput, RequestListItem, RequestRecord, RequestRun, RulePreviewResult,
} from "../types";

export type WorkbenchMode = "replay" | "diff" | "lab" | "collections" | "environment" | "rules";

interface Props {
  sessionId: string;
  selected: RequestListItem[];
  initialMode: WorkbenchMode;
  autoCreateFromSelection?: boolean;
  onBack: () => void;
  onOpenRequest: (requestId: string) => void;
}

const tabs = [
  { id: "lab" as const, label: "请求构建", icon: FlaskConical },
  { id: "replay" as const, label: "请求重放", icon: ListRestart },
  { id: "diff" as const, label: "请求对比", icon: GitCompareArrows },
  { id: "collections" as const, label: "请求集合", icon: FolderTree },
  { id: "environment" as const, label: "环境变量", icon: KeyRound },
  { id: "rules" as const, label: "规则工作台", icon: SlidersHorizontal },
];

const bodyTypes = ["none", "json", "text", "xml", "raw", "form-data", "urlencoded", "file"] as const;
const bodyTypeLabels: Record<typeof bodyTypes[number], string> = {
  none: "None", json: "JSON", text: "Text", xml: "XML", raw: "Raw",
  "form-data": "Form Data", urlencoded: "URL Encoded", file: "File",
};
const bodyTypeBadges: Record<typeof bodyTypes[number], string | undefined> = {
  none: undefined, json: "JSON", text: "TXT", xml: "XML", raw: "RAW",
  "form-data": "FORM", urlencoded: "URL", file: "FILE",
};

const replayDefaults: ReplaySettings = {
  repeatCount: 1, startDelayMs: 0, intervalMs: 0, maxConcurrency: 4,
  throughCapture: false, includeCookie: true, includeAuthorization: true,
  followRedirects: true, verifyTls: true, useUpstreamProxy: false,
};

const requestBreakpointManagedHeaders = [
  "connection", "content-length", "host", "keep-alive", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
];
const responseBreakpointManagedHeaders = [
  "connection", "content-encoding", "content-length", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
];

export function RequestWorkbench({ sessionId, selected, initialMode, autoCreateFromSelection = false, onBack, onOpenRequest }: Props) {
  const [mode, setMode] = useState<WorkbenchMode>(initialMode);
  const [requestedDraftId, setRequestedDraftId] = useState<string>();
  const [details, setDetails] = useState<RequestRecord[]>([]);
  const [loading, setLoading] = useState(selected.length > 0);
  const [error, setError] = useState("");

  useEffect(() => {
    let disposed = false;
    if (!selected.length) { setDetails([]); return; }
    setLoading(true);
    const task = isTauri()
      ? Promise.all(selected.slice(0, 20).map((request) => invoke<RequestRecord>("get_request_detail", { requestId: request.id })))
      : Promise.resolve(initialRequests.filter((request) => selected.some((item) => item.id === request.id)));
    task.then((records) => { if (!disposed) setDetails(records); })
      .catch((reason) => { if (!disposed) setError(String(reason)); })
      .finally(() => { if (!disposed) setLoading(false); });
    return () => { disposed = true; };
  }, [selected]);

  return <section className="request-workbench">
      <div className="request-workbench__layout">
        <nav className="request-workbench__nav" aria-label="请求实验室工具">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const disabled = tab.id === "replay" && selected.length === 0 || tab.id === "diff" && selected.length !== 2;
            const title = tab.id === "replay" && disabled ? "请先从流量页带入请求" : tab.id === "diff" && disabled ? "请从流量页带入两条请求" : tab.label;
            return <button key={tab.id} className={mode === tab.id ? "is-active" : ""} disabled={disabled} aria-pressed={mode === tab.id} onClick={() => setMode(tab.id)} title={title}><Icon size={15} /><span>{tab.label}</span></button>;
          })}
          <div className="request-workbench__nav-footer">
            {selected.length > 0 && <span className="request-workbench__context">{selected.length} 条请求上下文</span>}
            <button className="request-workbench__nav-back" onClick={onBack} title="返回流量" aria-label="返回流量"><ArrowLeft size={15} /></button>
          </div>
        </nav>
        <main className={`request-workbench__content ${mode === "lab" ? "is-lab" : ""}`}>
          {error && <Notice>{error}</Notice>}
          {loading && !["collections", "environment", "rules"].includes(mode) ? <div className="workbench-loading"><LoaderCircle className="spin" size={20} /><span>正在读取请求证据</span></div> : <>
            {mode === "replay" && <ReplayPanel sessionId={sessionId} selected={selected} onOpenRequest={onOpenRequest} />}
            {mode === "diff" && <DiffPanel details={details} />}
            {mode === "lab" && <LabPanel sessionId={sessionId} selected={selected} details={details} autoCreateFromSelection={autoCreateFromSelection} initialDraftId={requestedDraftId} onSelectCapture={onBack} />}
            {mode === "collections" && <CollectionPanel sessionId={sessionId} selected={selected} onOpenDraft={(draftId) => { setRequestedDraftId(draftId); setMode("lab"); }} />}
            {mode === "environment" && <EnvironmentPanel />}
            {mode === "rules" && <RulesPanel selected={selected} details={details} />}
          </>}
        </main>
      </div>
    </section>;
}

function ReplayPanel({ sessionId, selected, onOpenRequest }: { sessionId: string; selected: RequestListItem[]; onOpenRequest: (id: string) => void }) {
  const [settings, setSettings] = useState(replayDefaults);
  const [batch, setBatch] = useState<ReplayBatch>();
  const [message, setMessage] = useState("");
  const [starting, setStarting] = useState(false);
  const total = selected.length * settings.repeatCount;

  useEffect(() => {
    if (!isTauri()) return;
    let dispose: (() => void) | undefined;
    void listen<ReplayBatch>("replay://batch-updated", (event) => {
      if (!batch || event.payload.id === batch.id) setBatch(event.payload);
    }).then((unlisten) => { dispose = unlisten; });
    return () => dispose?.();
  }, [batch?.id]);

  const start = async () => {
    if (total > 20 && !window.confirm("即将发送 " + total + " 次请求，确认目标允许这次操作？")) return;
    if (!isTauri()) { setMessage("真实重放需要在桌面应用中运行"); return; }
    setStarting(true); setMessage("");
    try {
      setBatch(await invoke<ReplayBatch>("start_replay_batch", { input: { sessionId, requestIds: selected.map((request) => request.id), settings, confirmedLargeBatch: total > 20 } }));
    } catch (reason) { setMessage(String(reason)); } finally { setStarting(false); }
  };
  const cancel = async () => {
    if (!batch || !isTauri()) return;
    try { setBatch(await invoke<ReplayBatch>("cancel_replay_batch", { batchId: batch.id })); } catch (reason) { setMessage(String(reason)); }
  };

  return <div className="workbench-panel replay-panel">
    <section className="workbench-band">
      <Heading title={selected.length + " 条来源请求，计划发送 " + total + " 次"} meta="RANGE" value="硬上限 100" warning={total > 20} />
      <div className="replay-settings-grid">
        <NumberSetting label="每条次数" value={settings.repeatCount} max={100} onChange={(repeatCount) => setSettings({ ...settings, repeatCount })} />
        <NumberSetting label="开始延迟 ms" value={settings.startDelayMs} min={0} max={60000} onChange={(startDelayMs) => setSettings({ ...settings, startDelayMs })} />
        <NumberSetting label="请求间隔 ms" value={settings.intervalMs} min={0} max={60000} onChange={(intervalMs) => setSettings({ ...settings, intervalMs })} />
        <NumberSetting label="最大并发" value={settings.maxConcurrency} max={8} onChange={(maxConcurrency) => setSettings({ ...settings, maxConcurrency })} />
      </div>
      <div className="workbench-switches">
        <Toggle label="经过 ShowNet 抓包" detail="要求当前 Session 正在抓包" checked={settings.throughCapture} onChange={(throughCapture) => setSettings({ ...settings, throughCapture })} />
        <Toggle label="保留 Cookie" detail="默认按原请求携带" checked={settings.includeCookie} onChange={(includeCookie) => setSettings({ ...settings, includeCookie })} />
        <Toggle label="保留 Authorization" detail="默认按原请求携带" checked={settings.includeAuthorization} onChange={(includeAuthorization) => setSettings({ ...settings, includeAuthorization })} />
        <Toggle label="跟随重定向" detail="最多 10 次" checked={settings.followRedirects} onChange={(followRedirects) => setSettings({ ...settings, followRedirects })} />
        <Toggle label="验证 TLS" detail="关闭仅用于授权测试" checked={settings.verifyTls} onChange={(verifyTls) => setSettings({ ...settings, verifyTls })} />
        <Toggle label="使用上游代理" detail="沿用设置中的出口" checked={settings.useUpstreamProxy} onChange={(useUpstreamProxy) => setSettings({ ...settings, useUpstreamProxy })} />
      </div>
      <div className="workbench-actions"><span>自动删除 hop-by-hop Header，并重算 Content-Length</span><button className="primary-button" onClick={() => void start()} disabled={starting || total > 100 || !!batch && ["queued", "running"].includes(batch.status)}><Play size={14} />{starting ? "正在创建" : "开始重放"}</button></div>
      {message && <p className="workbench-inline-error">{message}</p>}
    </section>
    {batch && <section className="workbench-band replay-progress">
      <Heading meta={"BATCH " + batch.id.slice(-8)} title={batchLabel(batch.status)} value={batch.completed + " / " + batch.total} />
      <div className="replay-progress__bar"><i style={{ width: (batch.total ? batch.completed / batch.total * 100 : 0) + "%" }} /></div>
      <div className="replay-summary"><span><Check size={13} />成功 {batch.succeeded}</span><span><CircleAlert size={13} />失败 {batch.failed}</span><span><Clock3 size={13} />队列 {batch.total - batch.completed}</span>{["queued", "running"].includes(batch.status) && <button className="secondary-button" onClick={() => void cancel()}><Square size={12} />取消批次</button>}</div>
      <div className="replay-items">{batch.items.map((item) => <button key={item.id} disabled={!item.capturedRequestId} onClick={() => item.capturedRequestId && onOpenRequest(item.capturedRequestId)}><span className={"run-status is-" + item.status} /><code>{item.sourceRequestId.slice(-8)} · #{item.runIndex + 1}</code><strong>{item.statusCode ?? item.status}</strong><small>{item.durationMs == null ? "" : item.durationMs + "ms"}</small>{item.error && <em title={item.error}>{item.error}</em>}</button>)}</div>
    </section>}
  </div>;
}

function DiffPanel({ details }: { details: RequestRecord[] }) {
  const [ignored, setIgnored] = useState("headers.x-request-id\nheaders.date\nbody.timestamp");
  const differences = useMemo(() => details.length === 2 ? compareRequestRecords(details[0], details[1], ignored.split(/\r?\n/)) : [], [details, ignored]);
  const sections: RequestDiffEntry["section"][] = ["request", "response", "transport", "evidence"];
  return <div className="workbench-panel diff-panel">
    <section className="diff-overview">{details.map((request, index) => <div key={request.id}><span>{index ? "对比 B" : "基线 A"}</span><strong>{request.method} {request.host}{request.path}</strong><small>HTTP {request.status} · {request.protocol} · {request.duration}ms</small></div>)}<div className="diff-count"><strong>{differences.length}</strong><span>项差异</span></div></section>
    <section className="workbench-band diff-ignore"><label><span>忽略动态字段</span><small>每行一个 Header 或 JSON key 路径</small></label><textarea value={ignored} onChange={(event) => setIgnored(event.target.value)} /></section>
    <section className="diff-results">{sections.map((section) => {
      const entries = differences.filter((entry) => entry.section === section);
      return <div key={section} className="diff-section"><header><strong>{diffLabel(section)}</strong><span>{entries.length}</span></header>{entries.map((entry) => <div key={entry.path + entry.kind} className={"diff-entry is-" + entry.kind}><code>{entry.path}</code><span>{entry.before ?? "未设置"}</span><span>{entry.after ?? "未设置"}</span></div>)}{!entries.length && <p>此维度没有差异</p>}</div>;
    })}</section>
  </div>;
}

function LabPanel({ sessionId, selected, details, autoCreateFromSelection, initialDraftId, onSelectCapture }: { sessionId: string; selected: RequestListItem[]; details: RequestRecord[]; autoCreateFromSelection: boolean; initialDraftId?: string; onSelectCapture: () => void }) {
  const [drafts, setDrafts] = useState<RequestDraft[]>([]);
  const [draft, setDraft] = useState<RequestDraft>();
  const [runs, setRuns] = useState<RequestRun[]>([]);
  const [cookies, setCookies] = useState<RequestCookieRecord[]>([]);
  const [environments, setEnvironments] = useState<EnvironmentRecord[]>([]);
  const [collectionWorkspace, setCollectionWorkspace] = useState<RequestCollectionWorkspace>(emptyCollectionWorkspace());
  const [tab, setTab] = useState<"query" | "headers" | "body" | "auth" | "settings">("headers");
  const [responseTab, setResponseTab] = useState<"body" | "headers" | "history">("body");
  const [curlInput, setCurlInput] = useState("");
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [creatingFromCapture, setCreatingFromCapture] = useState(autoCreateFromSelection && selected.length === 1);
  const timer = useRef<number | undefined>(undefined);
  const autoCreateAttempted = useRef(false);
  const initialDraftOpened = useRef("");
  const loadDrafts = async () => { if (isTauri()) setDrafts(await invoke<RequestDraft[]>("list_request_drafts")); };
  const loadCollections = async () => { if (isTauri()) setCollectionWorkspace(await invoke<RequestCollectionWorkspace>("list_request_collection_workspace")); };
  const loadCookies = async () => { if (isTauri()) setCookies(await invoke<RequestCookieRecord[]>("list_request_cookies")); };

  useEffect(() => {
    void loadDrafts();
    void loadCollections();
    void loadCookies();
    if (isTauri()) void invoke<EnvironmentRecord[]>("list_environments").then(setEnvironments);
  }, []);
  useEffect(() => {
    if (!initialDraftId || initialDraftOpened.current === initialDraftId || !drafts.length) return;
    const target = drafts.find((item) => item.id === initialDraftId);
    if (!target) return;
    initialDraftOpened.current = initialDraftId;
    setDraft(target);
  }, [initialDraftId, drafts]);
  useEffect(() => {
    if (!draft || !isTauri()) return;
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      void invoke("save_request_draft", { input: draftInput(draft) }).then(loadDrafts).catch((reason) => setMessage(String(reason)));
    }, 600);
    return () => window.clearTimeout(timer.current);
  }, [draft]);
  useEffect(() => {
    if (!draft || !isTauri()) { setRuns([]); return; }
    void invoke<RequestRun[]>("list_request_runs", { draftId: draft.id }).then(setRuns);
  }, [draft?.id]);

  const createFromRequest = async () => {
    if (selected.length !== 1) return;
    setMessage("");
    setCreatingFromCapture(true);
    try {
      if (isTauri()) {
        const created = await invoke<RequestDraft>("create_request_draft_from_capture", { requestId: selected[0].id });
        setDraft(created);
        await Promise.all([loadDrafts(), loadCollections()]);
        return;
      }
      const request = details[0];
      if (!request) return;
      setDraft({
        ...emptyDraft(sessionId), sourceRequestId: request.id, name: request.method + " " + request.path,
        method: request.method, url: "https://" + request.host + request.path + (request.query ? "?" + request.query : ""),
        headers: request.requestHeaders, body: request.requestBody ?? "", bodyType: "raw",
      });
    } catch (reason) {
      setMessage(String(reason));
    } finally {
      setCreatingFromCapture(false);
    }
  };
  useEffect(() => {
    if (!autoCreateFromSelection || autoCreateAttempted.current || selected.length !== 1) return;
    if (!isTauri() && !details[0]) {
      autoCreateAttempted.current = true;
      setCreatingFromCapture(false);
      setMessage("未能读取所选请求");
      return;
    }
    autoCreateAttempted.current = true;
    void createFromRequest();
  }, [autoCreateFromSelection, details, selected]);

  const createBlank = () => {
    setMessage("");
    setDraft(emptyDraft(sessionId));
  };
  const changeDraftLocation = (value: string) => {
    if (!draft) return;
    const location = parseDraftLocationValue(value, collectionWorkspace);
    const joiningCollection = !draft.collectionId && !!location.collectionId;
    setDraft({
      ...draft,
      ...location,
      settings: joiningCollection ? { ...draft.settings, inheritCollection: true } : draft.settings,
    });
  };
  const importCurl = () => {
    try {
      const parsed = parseCurl(curlInput);
      const current = draft ?? emptyDraft(sessionId);
      setDraft({ ...current, name: parsed.method + " " + new URL(parsed.url).pathname, method: parsed.method, url: parsed.url, headers: parsed.headers, body: parsed.body });
      setMessage("cURL 已载入草稿");
    } catch (reason) { setMessage(String(reason)); }
  };
  const copyCurl = async () => {
    if (!draft) return;
    try {
      const value = draftToCurl({ method: draft.method, url: draft.url, headers: draft.headers, body: draft.body });
      if (isTauri()) await writeText(value);
      else if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value);
      else throw new Error("当前环境不支持剪贴板");
      setMessage("完整 cURL 已复制");
    } catch (reason) {
      setMessage(`复制失败：${String(reason)}`);
    }
  };
  const send = async () => {
    if (!draft) return;
    if (!isTauri()) { setMessage("真实发送需要在桌面应用中运行"); return; }
    setSending(true); setMessage("");
    try {
      const saved = await invoke<RequestDraft>("save_request_draft", { input: draftInput(draft) });
      setDraft(saved);
      const run = await invoke<RequestRun>("send_request_draft", { draftId: saved.id });
      setRuns((items) => [run, ...items]);
      await loadCookies();
    } catch (reason) { setMessage(String(reason)); } finally { setSending(false); }
  };
  const cancel = async () => {
    if (!draft || !isTauri()) return;
    try { await invoke("cancel_request_draft", { draftId: draft.id }); setMessage("正在取消请求"); }
    catch (reason) { setMessage(String(reason)); }
  };
  const restoreRun = (run: RequestRun) => {
    const snapshot = run.requestSnapshot;
    const restoredBody = bodyFromRunSnapshot(snapshot.body, snapshot.bodyType);
    setDraft({
      ...emptyDraft(),
      sessionId: draft?.sessionId,
      name: `${draft?.name ?? "请求"} · 历史副本`,
      method: String(snapshot.method ?? draft?.method ?? "GET"),
      url: String(snapshot.url ?? draft?.url ?? "https://example.com/"),
      headers: Array.isArray(snapshot.headers) ? snapshot.headers as HeaderEntry[] : [],
      body: restoredBody.body,
      bodyType: restoredBody.bodyType,
      environmentId: typeof snapshot.environmentId === "string" ? snapshot.environmentId : draft?.environmentId,
    });
    setMessage("已从完整发送历史生成新草稿");
  };
  const deleteCookie = async (cookie: RequestCookieRecord) => {
    if (!isTauri()) return;
    try {
      setCookies(await invoke<RequestCookieRecord[]>("delete_request_cookie", { domain: cookie.domain, path: cookie.path, name: cookie.name }));
      setMessage(`已删除 ${cookie.name}`);
    } catch (reason) { setMessage(String(reason)); }
  };
  const clearCookies = async () => {
    if (!isTauri() || !cookies.length || !window.confirm(`清除 Cookie Jar 中的 ${cookies.length} 条 Cookie？`)) return;
    try {
      setCookies(await invoke<RequestCookieRecord[]>("clear_request_cookies"));
      setMessage("Cookie Jar 已清空");
    } catch (reason) { setMessage(String(reason)); }
  };
  const openDraftList = async () => {
    if (draft && isTauri()) {
      window.clearTimeout(timer.current);
      try {
        await invoke("save_request_draft", { input: draftInput(draft) });
        await loadDrafts();
      } catch (reason) {
        setMessage(String(reason));
        return;
      }
    }
    setDraft(undefined);
    setRuns([]);
    setMessage("");
  };

  if (creatingFromCapture) return <div className="lab-create-progress" role="status" aria-live="polite">
    <span className="lab-create-progress__icon"><LoaderCircle className="spin" size={21} /></span>
    <span className="lab-create-progress__copy"><strong>正在创建可编辑请求</strong><code>{selected[0]?.method} {selected[0]?.host}{selected[0]?.path}</code></span>
  </div>;

  if (!draft) return <div className="lab-start">
    <header className="lab-start__header">
      <div><span className="section-kicker">REQUEST LAB</span><h3>新建请求</h3></div>
      <button className="primary-button" onClick={createBlank}><Plus size={14} />空白请求</button>
    </header>
    <div className="lab-start__create-grid">
      <section className="lab-source-section">
        <header><strong>抓包来源</strong><span>{selected.length === 1 ? "已选择 1 条" : "未选择"}</span></header>
        {selected.length === 1 ? <div className="lab-source-request">
          <span className={`method method-${selected[0].method.toLowerCase()}`}>{selected[0].method}</span>
          <div><strong>{selected[0].host}</strong><code>{selected[0].path}{selected[0].query ? `?${selected[0].query}` : ""}</code></div>
          <span className="lab-source-request__meta">{selected[0].status ?? selected[0].state}</span>
          <button className="primary-button" onClick={() => void createFromRequest()}><Plus size={14} />创建草稿</button>
        </div> : <button className="lab-source-request is-empty" onClick={onSelectCapture} title="返回流量选择一条请求">
          <span className="lab-start-action-icon"><Activity size={16} /></span>
          <span className="lab-source-request__copy"><strong>从抓包创建</strong><small>{selected.length > 1 ? `当前带入 ${selected.length} 条请求` : "未选择请求"}</small></span>
          <ChevronRight size={15} />
        </button>}
      </section>
      <section className="lab-curl-section">
        <header><strong>导入 cURL</strong><Code2 size={15} /></header>
        <div className="lab-curl-compose">
          <textarea aria-label="粘贴 cURL 命令" value={curlInput} onChange={(event) => setCurlInput(event.target.value)} placeholder="curl https://api.example.com/..." />
          <button className="secondary-button" onClick={importCurl} disabled={!curlInput.trim()}><Code2 size={14} />导入</button>
        </div>
        {message && <p className="lab-curl-message">{message}</p>}
      </section>
    </div>
    <section className="lab-recents">
      <header><div><strong>最近草稿</strong><span>{drafts.length}</span></div><small>最近更新</small></header>
      {drafts.length > 0 ? <div className="lab-draft-list">{drafts.slice(0, 10).map((item) => {
        const target = draftTarget(item.url);
        return <button key={item.id} onClick={() => setDraft(item)} title={item.url}>
          <span className={`method method-${item.method.toLowerCase()}`}>{item.method}</span>
          <span className="lab-draft-list__name"><strong>{item.name}</strong><small>{draftCollectionLabel(item, collectionWorkspace) ?? target.host}</small></span>
          <code>{target.path}</code>
          <time>{formatDraftTime(item.updatedAt)}</time>
          <ChevronRight size={14} />
        </button>;
      })}</div> : <div className="lab-recents__empty"><History size={17} /><span>暂无草稿</span></div>}
    </section>
  </div>;

  const response = runs[0]?.responseSnapshot;
  const draftCollection = collectionWorkspace.collections.find((item) => item.id === draft.collectionId);
  const inheritsCollection = !!draftCollection && draft.settings.inheritCollection !== false;
  const requestHeaderNames = new Set(draft.headers.map((header) => header.name.trim().toLowerCase()));
  const inheritedHeaderCount = inheritsCollection
    ? draftCollection.defaultHeaders.filter((header) => !requestHeaderNames.has(header.name.trim().toLowerCase())).length
    : 0;
  const requestAuthKind = String(draft.auth.kind ?? "none");
  const inheritedAuthKind = inheritsCollection && requestAuthKind === "none"
    ? String(draftCollection.defaultAuth.kind ?? "none")
    : "none";
  const automaticEnvironmentId = draft.environmentId
    ?? (inheritsCollection ? draftCollection.defaultEnvironmentId : undefined)
    ?? environments.find((item) => item.kind === "named" && item.active)?.id;
  const automaticEnvironment = environments.find((item) => item.id === automaticEnvironmentId);
  const responseHeaders = Array.isArray(response?.headers) ? response.headers as HeaderEntry[] : [];
  const responseMetadata = response?.bodyMetadata as BodyCaptureMetadata | undefined;
  let queryCount = 0;
  try { queryCount = [...new URL(draft.url).searchParams].length; } catch { /* Invalid URLs are handled by QueryEditor. */ }
  const responseStatus = response?.status
    ? "HTTP " + response.status
    : runs[0]?.status === "failed"
      ? "发送失败"
      : runs[0]?.status === "cancelled"
        ? "已取消"
        : "尚未发送";
  return <div className="workbench-panel lab-panel">
    <header className="lab-request-line"><select value={draft.method} onChange={(event) => setDraft({ ...draft, method: event.target.value })}>{["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"].map((method) => <option key={method}>{method}</option>)}</select><input value={draft.url} onChange={(event) => setDraft({ ...draft, url: event.target.value })} />{sending ? <button className="secondary-button lab-cancel-button lab-send-button" onClick={() => void cancel()} title="取消请求"><Square size={13} /><span>取消</span></button> : <button className="primary-button lab-send-button" onClick={() => void send()} title="发送请求"><Send size={14} /><span>发送</span></button>}</header>
    <div className="lab-context-line"><input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /><select value={draft.environmentId ?? ""} onChange={(event) => setDraft({ ...draft, environmentId: event.target.value || undefined })}><option value="">{automaticEnvironment ? `自动 · ${automaticEnvironment.name}` : "仅全局环境"}</option>{environments.filter((item) => item.kind === "named").map((item) => <option key={item.id} value={item.id}>{item.name}{item.active ? "（当前）" : ""}</option>)}</select><select className="lab-location-select" aria-label="请求归属" value={draftLocationValue(draft)} onChange={(event) => changeDraftLocation(event.target.value)}><option value="">未归档</option>{collectionLocationOptions(collectionWorkspace).map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select><button className="icon-button" onClick={() => void openDraftList()} title="草稿列表"><History size={14} /></button><button className="icon-button" onClick={() => void copyCurl()} title="复制完整 cURL"><Copy size={14} /></button><button className="icon-button" onClick={() => void invoke("save_request_draft", { input: draftInput(draft) }).then(() => { setMessage("草稿已保存"); void loadCollections(); })} title="保存草稿"><Save size={14} /></button></div>
    {draftCollection && <div className={`lab-inheritance-bar ${inheritsCollection ? "is-active" : ""}`}><span className="lab-inheritance-source"><FolderTree size={13} /><strong>{draftCollection.name}</strong></span>{inheritsCollection ? <span className="lab-inheritance-summary"><em>{inheritedHeaderCount} 公共 Header</em><em>{inheritedAuthKind === "none" ? "无公共 Auth" : `继承 ${authKindLabel(inheritedAuthKind)}`}</em><em>{automaticEnvironment ? automaticEnvironment.name : "仅全局环境"}</em></span> : <span className="lab-inheritance-summary"><em>已使用请求自身配置</em></span>}<label title="启用或关闭集合公共配置继承"><span>继承</span><input type="checkbox" checked={inheritsCollection} onChange={(event) => setDraft({ ...draft, settings: { ...draft.settings, inheritCollection: event.target.checked } })} /><i /></label></div>}
    <div className="lab-split">
      <div className="lab-request-pane">
        <div className="lab-tabs">{(["query","headers","body","auth","settings"] as const).map((item) => {
          const label = ({ query: "Query", headers: "Headers", body: "Body", auth: "Auth", settings: "Settings" })[item];
          const badge = item === "query" ? queryCount : item === "headers" ? (inheritedHeaderCount ? `${draft.headers.length}+${inheritedHeaderCount}` : draft.headers.length) : item === "body" ? bodyTypeBadges[draft.bodyType] : item === "auth" && (String(draft.auth.kind ?? "none") !== "none" || inheritedAuthKind !== "none") ? "ON" : undefined;
          return <button key={item} className={tab === item ? "is-active" : ""} onClick={() => setTab(item)}><span>{label}</span>{badge !== undefined && <em>{badge}</em>}</button>;
        })}</div>
        <section className="lab-editor">
          {tab === "query" && <QueryEditor url={draft.url} onChange={(url) => setDraft({ ...draft, url })} />}
          {tab === "headers" && <HeaderEditor headers={draft.headers} inheritedCount={inheritedHeaderCount} onChange={(headers) => setDraft({ ...draft, headers })} />}
          {tab === "body" && <><div className="lab-body-type"><select aria-label="正文类型" value={draft.bodyType} onChange={(event) => { const type = event.target.value as typeof bodyTypes[number]; setDraft({ ...draft, bodyType: type, body: bodyForType(type, draft.bodyType, draft.body) }); }}>{bodyTypes.map((type) => <option key={type} value={type}>{bodyTypeLabels[type]}</option>)}</select></div>{draft.bodyType === "form-data" || draft.bodyType === "urlencoded" ? <StructuredBodyEditor mode={draft.bodyType} value={draft.body} onChange={(body) => setDraft({ ...draft, body })} /> : draft.bodyType === "file" ? <FileBodyEditor value={draft.body} onChange={(body) => setDraft({ ...draft, body })} /> : <textarea className="lab-body-editor" value={draft.body} disabled={draft.bodyType === "none"} onChange={(event) => setDraft({ ...draft, body: event.target.value })} />}</>}
          {tab === "auth" && <AuthEditor auth={draft.auth} inheritedKind={inheritedAuthKind} onChange={(auth) => setDraft({ ...draft, auth })} onReveal={() => invoke<Record<string, unknown>>("reveal_request_draft_auth", { draftId: draft.id })} />}
          {tab === "settings" && <div className="lab-settings-stack"><div className="lab-settings"><Toggle label="跟随重定向" detail="最多 10 次" checked={draft.settings.followRedirects !== false} onChange={(value) => setDraft({ ...draft, settings: { ...draft.settings, followRedirects: value } })} /><Toggle label="验证 TLS" detail="默认开启" checked={draft.settings.verifyTls !== false} onChange={(value) => setDraft({ ...draft, settings: { ...draft.settings, verifyTls: value } })} /><Toggle label="Cookie Jar" detail={`${cookies.length} 条 · 本机密文`} checked={draft.settings.cookieJar === true} onChange={(value) => setDraft({ ...draft, settings: { ...draft.settings, cookieJar: value } })} /><Toggle label="使用上游代理" detail="沿用全局出口设置" checked={draft.settings.useUpstreamProxy === true} onChange={(value) => setDraft({ ...draft, settings: { ...draft.settings, useUpstreamProxy: value } })} /></div>{draft.settings.cookieJar === true && <CookieJarManager cookies={cookies} onDelete={deleteCookie} onClear={clearCookies} />}</div>}
        </section>
        {message && <p className="workbench-inline-error lab-message">{message}</p>}
      </div>
      <section className={`lab-response ${runs.length ? "has-response" : "is-empty"}`}>
        <header><div><span>响应</span><strong>{responseStatus}</strong></div><span>{response?.durationMs ? String(response.durationMs) + "ms" : ""}</span></header>
        {runs.length > 0 && <>
          {runs[0]?.error && <Notice>{runs[0].error}</Notice>}
          <div className="lab-response-tabs">{(["body","headers","history"] as const).map((item) => <button key={item} className={responseTab === item ? "is-active" : ""} onClick={() => setResponseTab(item)}>{({ body: "Body", headers: "Headers", history: `历史 ${runs.length}` })[item]}</button>)}</div>
          <div className="lab-response-content">
            {responseTab === "body" && <HttpBodyViewer content={response?.body == null ? undefined : String(response.body)} headers={responseHeaders} metadata={responseMetadata} filename={`${draft.id}-response-body.txt`} />}
            {responseTab === "headers" && <pre>{responseHeaders.length ? responseHeaders.map((header) => header.name + ": " + header.value).join("\n") : "响应 Header 为空"}</pre>}
            {responseTab === "history" && <div className="lab-history">{runs.map((run) => <button key={run.id} onClick={() => restoreRun(run)} title="从这次发送快照生成新草稿"><span className={"run-status is-" + run.status} /><code>{new Date(run.startedAt).toLocaleTimeString()}</code><span>{String(run.responseSnapshot.status ?? run.status)}</span></button>)}</div>}
          </div>
        </>}
      </section>
    </div>
  </div>;
}

type CollectionEditor =
  | { kind: "collection"; id?: string; name: string }
  | { kind: "folder"; id?: string; collectionId: string; parentId?: string; name: string };

interface CollectionDefaultsDraft {
  description: string;
  defaultHeaders: HeaderEntry[];
  defaultAuth: Record<string, unknown>;
  defaultEnvironmentId?: string;
}

function CollectionPanel({ sessionId, selected, onOpenDraft }: { sessionId: string; selected: RequestListItem[]; onOpenDraft: (draftId: string) => void }) {
  const [workspace, setWorkspace] = useState<RequestCollectionWorkspace>(emptyCollectionWorkspace());
  const [selectedCollectionId, setSelectedCollectionId] = useState<string>();
  const [selectedFolderId, setSelectedFolderId] = useState<string>();
  const [expandedCollections, setExpandedCollections] = useState<Set<string>>(new Set());
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());
  const [editor, setEditor] = useState<CollectionEditor>();
  const [preview, setPreview] = useState<CollectionImportPreview>();
  const [syncPreview, setSyncPreview] = useState<CollectionSyncPreview>();
  const [syncSelection, setSyncSelection] = useState<Set<string>>(new Set());
  const [importSelection, setImportSelection] = useState<Set<number>>(new Set());
  const [importCollectionId, setImportCollectionId] = useState("");
  const [importName, setImportName] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [defaultsOpen, setDefaultsOpen] = useState(false);
  const [environments, setEnvironments] = useState<EnvironmentRecord[]>([]);
  const [search, setSearch] = useState("");
  const [selectedDraftIds, setSelectedDraftIds] = useState<Set<string>>(new Set());
  const [batchLocation, setBatchLocation] = useState("");
  const [tagInput, setTagInput] = useState("");

  const load = async () => {
    const result = isTauri()
      ? await invoke<RequestCollectionWorkspace>("list_request_collection_workspace")
      : initialRequestCollectionWorkspace;
    setWorkspace(result);
    setSelectedDraftIds((current) => new Set([...current].filter((id) => result.drafts.some((draft) => draft.id === id))));
    setExpandedCollections((current) => {
      if (current.size || !result.collections.length) return current;
      return new Set(result.collections.map((collection) => collection.id));
    });
    setSelectedCollectionId((current) => current && result.collections.some((item) => item.id === current) ? current : result.collections[0]?.id);
  };

  useEffect(() => {
    void load();
    if (isTauri()) void invoke<EnvironmentRecord[]>("list_environments").then(setEnvironments);
  }, []);

  const selectedCollection = workspace.collections.find((item) => item.id === selectedCollectionId);
  const selectedFolder = workspace.folders.find((item) => item.id === selectedFolderId && item.collectionId === selectedCollectionId);
  const currentDrafts = workspace.drafts.filter((draft) => selectedCollection
    ? draft.collectionId === selectedCollection.id && (selectedFolder ? draft.folderId === selectedFolder.id : !draft.folderId)
    : !draft.collectionId);
  const searchActive = search.trim().length > 0;
  const visibleDrafts = searchActive
    ? workspace.drafts.filter((draft) => matchesRequestDraftSearch(draft, workspace, search))
    : currentDrafts;
  const childFolders = searchActive ? [] : workspace.folders.filter((folder) => selectedCollection && folder.collectionId === selectedCollection.id && folder.parentId === selectedFolder?.id);
  const allVisibleSelected = visibleDrafts.length > 0 && visibleDrafts.every((draft) => selectedDraftIds.has(draft.id));

  const selectCollection = (collectionId?: string) => {
    setSelectedCollectionId(collectionId);
    setSelectedFolderId(undefined);
    setEditor(undefined);
    setPreview(undefined);
    setSyncPreview(undefined);
    setDefaultsOpen(false);
    setMessage("");
    setSelectedDraftIds(new Set());
  };
  const selectFolder = (folder: RequestCollectionFolder) => {
    setSelectedCollectionId(folder.collectionId);
    setSelectedFolderId(folder.id);
    setEditor(undefined);
    setPreview(undefined);
    setSyncPreview(undefined);
    setDefaultsOpen(false);
    setMessage("");
    setSelectedDraftIds(new Set());
  };
  const saveEditor = async () => {
    if (!editor?.name.trim() || !isTauri()) return;
    setBusy(true); setMessage("");
    try {
      if (editor.kind === "collection") {
        const saved = await invoke<RequestCollection>("save_request_collection", { input: {
          id: editor.id,
          name: editor.name,
          description: editor.id ? selectedCollection?.description ?? "" : "",
          defaultHeaders: editor.id ? selectedCollection?.defaultHeaders ?? [] : [],
          defaultAuth: editor.id ? selectedCollection?.defaultAuth ?? { kind: "none" } : { kind: "none" },
          defaultEnvironmentId: editor.id ? selectedCollection?.defaultEnvironmentId : undefined,
        } });
        setSelectedCollectionId(saved.id);
        setExpandedCollections((current) => new Set(current).add(saved.id));
      } else {
        const saved = await invoke<RequestCollectionFolder>("save_request_collection_folder", { input: { id: editor.id, collectionId: editor.collectionId, parentId: editor.parentId, name: editor.name } });
        setSelectedCollectionId(saved.collectionId); setSelectedFolderId(saved.id);
        setExpandedFolders((current) => new Set(current).add(saved.id));
      }
      setEditor(undefined); await load();
    } catch (reason) { setMessage(String(reason)); } finally { setBusy(false); }
  };
  const removeCurrent = async () => {
    if (!isTauri()) return;
    if (selectedFolder) {
      if (!window.confirm(`删除文件夹“${selectedFolder.name}”？其中的请求会移到集合根目录，不会被删除。`)) return;
      await invoke("delete_request_collection_folder", { folderId: selectedFolder.id });
      setSelectedFolderId(selectedFolder.parentId); setMessage("文件夹已删除，请求已保留"); await load();
    } else if (selectedCollection) {
      if (!window.confirm(`删除集合“${selectedCollection.name}”？其中的请求会变为未归档，不会被删除。`)) return;
      await invoke("delete_request_collection", { collectionId: selectedCollection.id });
      setSelectedCollectionId(undefined); setMessage("集合已删除，请求已移到未归档"); await load();
    }
  };
  const toggleDraftSelection = (draftId: string) => {
    setSelectedDraftIds((current) => {
      const next = new Set(current);
      if (next.has(draftId)) next.delete(draftId);
      else if (next.size < 500) next.add(draftId);
      else setMessage("一次最多整理 500 条请求");
      return next;
    });
  };
  const toggleVisibleSelection = () => {
    if (allVisibleSelected) {
      setSelectedDraftIds((current) => {
        const next = new Set(current);
        visibleDrafts.forEach((draft) => next.delete(draft.id));
        return next;
      });
      return;
    }
    const visibleIds = visibleDrafts.slice(0, 500).map((draft) => draft.id);
    setSelectedDraftIds(new Set(visibleIds));
    if (visibleDrafts.length > 500) setMessage("已选择前 500 条；单次批量操作上限为 500 条");
  };
  const runBatchUpdate = async (
    changes: Pick<RequestDraftBatchUpdateInput, "location" | "addTags" | "removeTags">,
    successMessage: string,
  ) => {
    if (!isTauri() || !selectedDraftIds.size) return;
    setBusy(true); setMessage("");
    try {
      await invoke("update_request_drafts_batch", { input: { draftIds: [...selectedDraftIds], ...changes } });
      setSelectedDraftIds(new Set()); setBatchLocation(""); setTagInput("");
      setMessage(successMessage); await load();
    } catch (reason) { setMessage(String(reason)); } finally { setBusy(false); }
  };
  const moveSelectedDrafts = async () => {
    if (!batchLocation) return;
    const location = batchLocation === "unfiled"
      ? {}
      : parseDraftLocationValue(batchLocation, workspace);
    await runBatchUpdate(
      { location, addTags: [], removeTags: [] },
      `已移动 ${selectedDraftIds.size} 条请求`,
    );
  };
  const updateSelectedTags = async (mode: "add" | "remove") => {
    const tags = parseDraftTagInput(tagInput);
    if (!tags.length) { setMessage("请输入至少一个标签"); return; }
    await runBatchUpdate(
      { addTags: mode === "add" ? tags : [], removeTags: mode === "remove" ? tags : [] },
      `已为 ${selectedDraftIds.size} 条请求${mode === "add" ? "添加" : "移除"}标签`,
    );
  };
  const archiveCapture = async () => {
    if (!isTauri() || !selectedCollection || selected.length !== 1) return;
    setBusy(true); setMessage("");
    try {
      const draft = await invoke<RequestDraft>("create_request_draft_from_capture", { requestId: selected[0].id });
      await invoke("move_request_draft", { input: { draftId: draft.id, collectionId: selectedCollection.id, folderId: selectedFolder?.id } });
      setMessage(`已归档 ${selected[0].method} ${selected[0].path}`); await load();
    } catch (reason) { setMessage(String(reason)); } finally { setBusy(false); }
  };
  const chooseImport = async () => {
    if (!isTauri()) { setMessage("集合导入需要在桌面应用中运行"); return; }
    const path = await openDialog({
      multiple: false, directory: false, title: "导入浏览器或 API 请求",
      filters: [{ name: "HAR / Postman / Insomnia / OpenAPI / ShowNet", extensions: ["har", "json", "yaml", "yml"] }],
    });
    if (!path || Array.isArray(path)) return;
    setBusy(true); setMessage("");
    try {
      const result = await invoke<CollectionImportPreview>("preview_request_collection_import", { path });
      setSyncPreview(undefined); setPreview(result); setImportSelection(new Set(result.items.map((_, index) => index)));
      setImportCollectionId(selectedCollection?.id ?? ""); setImportName(result.suggestedName);
    } catch (reason) { setMessage(String(reason)); } finally { setBusy(false); }
  };
  const commitImport = async () => {
    if (!preview || !isTauri() || importSelection.size === 0) return;
    setBusy(true); setMessage("");
    try {
      const result = await invoke<CollectionImportResult>("commit_request_collection_import", { input: {
        collectionId: importCollectionId || undefined,
        collectionName: importName,
        items: preview.items.filter((_, index) => importSelection.has(index)),
        collection: preview.collection,
        environments: preview.environments ?? [],
        sourceFormat: preview.sourceFormat,
        sourcePath: preview.sourcePath,
        sourceFingerprint: preview.sourceFingerprint,
      } });
      setPreview(undefined); setSelectedCollectionId(result.collection.id); setSelectedFolderId(undefined);
      setExpandedCollections((current) => new Set(current).add(result.collection.id));
      setMessage(`已导入 ${result.importedCount} 条请求，创建 ${result.createdFolderCount} 个文件夹和 ${result.importedEnvironmentCount} 个环境`); await load();
    } catch (reason) { setMessage(String(reason)); } finally { setBusy(false); }
  };
  const loadSyncPreview = async (path?: string) => {
    if (!selectedCollection || !isTauri()) return;
    const result = await invoke<CollectionSyncPreview>("preview_request_collection_sync", {
      collectionId: selectedCollection.id,
      path,
    });
    setPreview(undefined); setDefaultsOpen(false); setSyncPreview(result);
    setSyncSelection(new Set(result.changes.filter((change) => change.kind !== "remove").map((change) => change.operationKey)));
  };
  const previewCollectionSync = async () => {
    if (!selectedCollection) return;
    if (!isTauri()) {
      const result = { ...initialCollectionSyncPreview, collectionId: selectedCollection.id, collectionName: selectedCollection.name };
      setSyncPreview(result);
      setSyncSelection(new Set(result.changes.filter((change) => change.kind !== "remove").map((change) => change.operationKey)));
      return;
    }
    setBusy(true); setMessage("");
    try {
      await loadSyncPreview();
    } catch (firstReason) {
      const path = await openDialog({
        multiple: false, directory: false, title: "重新选择 OpenAPI 规范",
        filters: [{ name: "OpenAPI", extensions: ["json", "yaml", "yml"] }],
      });
      if (!path || Array.isArray(path)) setMessage(String(firstReason));
      else await loadSyncPreview(path);
    } finally { setBusy(false); }
  };
  const commitCollectionSync = async () => {
    if (!syncPreview) return;
    if (!isTauri()) {
      setSyncPreview(undefined); setSyncSelection(new Set());
      setMessage("规范同步预览已确认；桌面应用会在单个事务中应用所选变更");
      return;
    }
    setBusy(true); setMessage("");
    try {
      const selectedChanges = syncPreview.changes.filter((change) => syncSelection.has(change.operationKey));
      const result = await invoke<CollectionSyncResult>("commit_request_collection_sync", { input: {
        collectionId: syncPreview.collectionId,
        sourcePath: syncPreview.sourcePath,
        sourceFingerprint: syncPreview.sourceFingerprint,
        selections: selectedChanges.map((change) => ({
          kind: change.kind,
          operationKey: change.operationKey,
          item: change.item,
          draftId: change.draftId,
        })),
      } });
      setSyncPreview(undefined); setSyncSelection(new Set());
      setMessage(`规范同步完成：新增 ${result.addedCount}，更新 ${result.updatedCount}，保留并解除关联 ${result.detachedCount}`);
      await load();
    } catch (reason) { setMessage(String(reason)); } finally { setBusy(false); }
  };
  const exportCollection = async (format: "shownet" | "postman") => {
    if (!selectedCollection || !isTauri()) return;
    const path = await saveDialog({
      title: "导出请求集合",
      defaultPath: `${safeFilename(selectedCollection.name)}.${format === "postman" ? "postman_collection" : "shownet_collection"}.json`,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (!path) return;
    try {
      const result = await invoke<CollectionExportResult>("export_request_collection", { collectionId: selectedCollection.id, path, format });
      setMessage(`已完整导出 ${result.itemCount} 条请求`);
    } catch (reason) { setMessage(String(reason)); }
  };
  const saveCollectionDefaults = async (value: CollectionDefaultsDraft) => {
    if (!selectedCollection || !isTauri()) return;
    setBusy(true); setMessage("");
    try {
      await invoke<RequestCollection>("save_request_collection", { input: {
        id: selectedCollection.id,
        name: selectedCollection.name,
        ...value,
      } });
      setMessage("集合公共配置已保存");
      await load();
    } catch (reason) { setMessage(String(reason)); } finally { setBusy(false); }
  };

  return <div className="collection-workspace">
    <aside className="collection-tree-pane">
      <header><div><span className="section-kicker">REQUEST ASSETS</span><strong>请求集合</strong></div><span><button onClick={() => setEditor({ kind: "collection", name: "" })} title="新建集合"><Plus size={14} /></button></span></header>
      <button className="collection-import-action" onClick={() => void chooseImport()} title="导入浏览器 HAR、Postman、Insomnia、OpenAPI 或 ShowNet 集合"><FileUp size={13} /><span>导入 HAR / API 集合</span></button>
      <button className={`collection-tree-root ${!selectedCollectionId ? "is-active" : ""}`} onClick={() => selectCollection(undefined)}><Archive size={14} /><span>未归档</span><em>{workspace.drafts.filter((draft) => !draft.collectionId).length}</em></button>
      <div className="collection-tree-list">{workspace.collections.map((collection) => {
        const expanded = expandedCollections.has(collection.id);
        return <section key={collection.id}>
          <div className={selectedCollectionId === collection.id && !selectedFolderId ? "is-active" : ""}><button className="collection-expand" onClick={() => setExpandedCollections(toggleSet(expandedCollections, collection.id))} title={expanded ? "折叠" : "展开"}>{expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</button><button className="collection-tree-label" onClick={() => selectCollection(collection.id)}><FolderTree size={14} /><span>{collection.name}</span><em>{collection.draftCount}</em></button></div>
          {expanded && <CollectionFolderTree collectionId={collection.id} parentId={undefined} workspace={workspace} selectedFolderId={selectedFolderId} expandedFolders={expandedFolders} onToggle={(id) => setExpandedFolders(toggleSet(expandedFolders, id))} onSelect={selectFolder} />}
        </section>;
      })}</div>
      {!workspace.collections.length && <div className="collection-tree-empty"><FolderPlus size={18} /><span>还没有请求集合</span></div>}
    </aside>
    <main className="collection-main-pane">
      {syncPreview ? <CollectionSyncPanel
        preview={syncPreview}
        selection={syncSelection}
        busy={busy}
        onToggle={(key) => setSyncSelection((current) => toggleSet(current, key))}
        onRecommended={(selected) => setSyncSelection(selected ? new Set(syncPreview.changes.filter((change) => change.kind !== "remove").map((change) => change.operationKey)) : new Set())}
        onClose={() => { setSyncPreview(undefined); setSyncSelection(new Set()); }}
        onCommit={commitCollectionSync}
      /> : preview ? <section className="collection-import-preview">
        <header className="collection-pane-heading"><div><span>{formatImportSource(preview.sourceFormat)} · {preview.items.length} 条{preview.environments?.length ? ` · ${preview.environments.length} 个环境` : ""}</span><h3>确认导入内容</h3></div><button className="icon-button" onClick={() => setPreview(undefined)} title="关闭导入预览"><X size={14} /></button></header>
        <div className="collection-import-target"><label><span>保存到</span><select value={importCollectionId} onChange={(event) => setImportCollectionId(event.target.value)}><option value="">新建集合</option>{workspace.collections.map((collection) => <option key={collection.id} value={collection.id}>{collection.name}</option>)}</select></label>{!importCollectionId && <label><span>集合名称</span><input value={importName} onChange={(event) => setImportName(event.target.value)} /></label>}</div>
        {preview.warnings.length > 0 && <div className="collection-import-warnings">{preview.warnings.map((warning) => <span key={warning}><CircleAlert size={12} />{warning}</span>)}</div>}
        <div className="collection-import-select"><label><input type="checkbox" checked={importSelection.size === preview.items.length} onChange={(event) => setImportSelection(event.target.checked ? new Set(preview.items.map((_, index) => index)) : new Set())} /><span>选择全部</span></label><strong>{importSelection.size} / {preview.items.length}</strong></div>
        <div className="collection-import-list">{preview.items.map((item, index) => <label key={`${index}-${item.name}`}><input type="checkbox" checked={importSelection.has(index)} onChange={() => setImportSelection(toggleSet(importSelection, index))} /><span className={`method method-${item.method.toLowerCase()}`}>{item.method}</span><span><strong>{item.name}</strong><small>{[...item.folderPath, item.url].join(" / ")}</small></span></label>)}</div>
        <footer><span>导入在单个数据库事务中完成，失败不会留下半个集合</span><button className="primary-button" onClick={() => void commitImport()} disabled={busy || !importSelection.size || (!importCollectionId && !importName.trim())}>{busy ? <LoaderCircle className="spin" size={14} /> : <Upload size={14} />}导入选中请求</button></footer>
      </section> : defaultsOpen && selectedCollection ? <CollectionDefaultsPanel key={`${selectedCollection.id}-${selectedCollection.updatedAt}`} collection={selectedCollection} environments={environments} busy={busy} onClose={() => setDefaultsOpen(false)} onSave={saveCollectionDefaults} /> : <>
        <header className="collection-pane-heading"><div><span>{searchActive ? "SEARCH" : selectedFolder ? "FOLDER" : selectedCollection ? "COLLECTION" : "UNFILED"}</span><h3>{searchActive ? "搜索结果" : selectedFolder?.name ?? selectedCollection?.name ?? "未归档请求"}</h3></div><div className="collection-pane-actions">{selectedCollection && <>{selectedCollection.sourceFormat === "openapi" && <button onClick={() => void previewCollectionSync()} title="同步 OpenAPI 规范"><RefreshCw size={14} /></button>}<button onClick={() => { setDefaultsOpen(true); setEditor(undefined); }} title="集合公共配置"><SlidersHorizontal size={14} /></button><button onClick={() => setEditor({ kind: "folder", collectionId: selectedCollection.id, parentId: selectedFolder?.id, name: "" })} title="新建文件夹"><FolderPlus size={14} /></button>{selected.length === 1 && <button onClick={() => void archiveCapture()} title="归档当前抓包请求"><Archive size={14} /></button>}<button onClick={() => void exportCollection("shownet")} title="导出 ShowNet JSON"><Download size={14} /></button><button onClick={() => void exportCollection("postman")} title="导出 Postman"><FileJson size={14} /></button><button onClick={() => selectedFolder ? setEditor({ kind: "folder", id: selectedFolder.id, collectionId: selectedFolder.collectionId, parentId: selectedFolder.parentId, name: selectedFolder.name }) : setEditor({ kind: "collection", id: selectedCollection.id, name: selectedCollection.name })} title="重命名"><Pencil size={14} /></button><button className="is-danger" onClick={() => void removeCurrent()} title={selectedFolder ? "删除文件夹并保留请求" : "删除集合并保留请求"}><Trash2 size={14} /></button></>}</div></header>
        <div className="collection-search-bar">
          <label className="collection-search-field"><Search size={13} /><input aria-label="搜索请求集合" value={search} onChange={(event) => { setSearch(event.target.value); setSelectedDraftIds(new Set()); }} placeholder="搜索名称、方法、URL、标签或集合路径" />{search && <button onClick={() => { setSearch(""); setSelectedDraftIds(new Set()); }} title="清除搜索"><X size={12} /></button>}</label>
          <label className="collection-select-visible"><input type="checkbox" checked={allVisibleSelected} disabled={!visibleDrafts.length} onChange={toggleVisibleSelection} /><span>{searchActive ? `${visibleDrafts.length} 个结果` : `选择当前 ${visibleDrafts.length} 条`}</span></label>
        </div>
        {selectedCollection?.sourceFormat === "openapi" && !searchActive && <div className="collection-source-strip"><span><RefreshCw size={13} /><strong>OpenAPI</strong><em>{sourceFileName(selectedCollection.sourcePath)}</em>{selectedCollection.sourceSyncedAt && <time>同步于 {formatDraftTime(selectedCollection.sourceSyncedAt)}</time>}</span><button className="secondary-button" disabled={busy} onClick={() => void previewCollectionSync()}>{busy ? <LoaderCircle className="spin" size={13} /> : <RefreshCw size={13} />}同步规范</button></div>}
        {selectedCollection && !searchActive && <div className="collection-breadcrumb"><button onClick={() => selectCollection(selectedCollection.id)}>{selectedCollection.name}</button>{collectionFolderBreadcrumb(selectedFolder, workspace.folders).map((folder) => <span key={folder.id}><ChevronRight size={11} /><button onClick={() => selectFolder(folder)}>{folder.name}</button></span>)}</div>}
        {editor && <div className="collection-inline-editor"><span>{editor.id ? "重命名" : editor.kind === "collection" ? "新建集合" : "新建文件夹"}</span><input autoFocus value={editor.name} onChange={(event) => setEditor({ ...editor, name: event.target.value })} onKeyDown={(event) => { if (event.key === "Enter") void saveEditor(); if (event.key === "Escape") setEditor(undefined); }} /><button className="secondary-button" onClick={() => setEditor(undefined)}>取消</button><button className="primary-button" disabled={busy || !editor.name.trim()} onClick={() => void saveEditor()}><Check size={13} />保存</button></div>}
        <section className="collection-content-list">
          {childFolders.map((folder) => <button className="collection-folder-row" key={folder.id} onClick={() => selectFolder(folder)}><FolderOpen size={16} /><span><strong>{folder.name}</strong><small>{folder.draftCount} 条请求 · 第 {folder.depth} 级</small></span><ChevronRight size={14} /></button>)}
          {visibleDrafts.map((draft) => {
            const target = draftTarget(draft.url);
            const location = requestDraftCollectionPath(draft, workspace);
            return <div className={`collection-draft-row ${selectedDraftIds.has(draft.id) ? "is-selected" : ""}`} key={draft.id}>
              <label className="collection-draft-check" title={`选择 ${draft.name}`}><input type="checkbox" checked={selectedDraftIds.has(draft.id)} onChange={() => toggleDraftSelection(draft.id)} /></label>
              <button className="collection-draft-main" onClick={() => onOpenDraft(draft.id)} title={draft.url}><span className={`method method-${draft.method.toLowerCase()}`}>{draft.method}</span><span><strong>{draft.name}</strong><small>{target.host}{target.path}</small></span></button>
              <div className="collection-draft-assets" title={[location, ...draft.tags].join(" · ")}>{searchActive && <span className="collection-draft-path">{location}</span>}{draft.tags.length > 0 && <span className="collection-draft-tags">{draft.tags.slice(0, 3).map((tag) => <em key={tag}>{tag}</em>)}{draft.tags.length > 3 && <em>+{draft.tags.length - 3}</em>}</span>}</div>
              <time>{formatDraftTime(draft.updatedAt)}</time>
              <button className="collection-open-draft" onClick={() => onOpenDraft(draft.id)} title="打开草稿"><ChevronRight size={14} /></button>
            </div>;
          })}
          {!childFolders.length && !visibleDrafts.length && <div className="collection-content-empty"><Folder size={20} /><strong>{searchActive ? "没有匹配的请求" : selectedCollection ? "这里还没有请求" : "没有未归档请求"}</strong><span>{searchActive ? "换一个名称、URL、标签或集合路径试试" : selectedCollection && selected.length === 1 ? "可用顶部归档按钮保存当前抓包请求" : "新建草稿后可在编辑器中选择集合归属"}</span></div>}
        </section>
        {selectedDraftIds.size > 0 && <footer className="collection-batch-bar">
          <div className="collection-batch-count"><strong>{selectedDraftIds.size}</strong><span>已选</span></div>
          <div className="collection-batch-location"><select aria-label="批量移动目标" value={batchLocation} onChange={(event) => setBatchLocation(event.target.value)}><option value="">选择目标位置</option><option value="unfiled">未归档</option>{collectionLocationOptions(workspace).map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select><button className="secondary-button" disabled={busy || !batchLocation} onClick={() => void moveSelectedDrafts()}><FolderInput size={13} />移动</button></div>
          <div className="collection-batch-tags"><input value={tagInput} maxLength={840} onChange={(event) => setTagInput(event.target.value)} placeholder="标签，用逗号分隔" /><button className="secondary-button" disabled={busy || !tagInput.trim()} onClick={() => void updateSelectedTags("add")}><Tag size={12} />添加</button><button className="secondary-button" disabled={busy || !tagInput.trim()} onClick={() => void updateSelectedTags("remove")}><X size={12} />移除</button></div>
          <button className="collection-batch-clear" onClick={() => setSelectedDraftIds(new Set())} title="清除选择"><X size={14} /></button>
        </footer>}
      </>}
      {message && <p className={`workbench-inline-error collection-message ${selectedDraftIds.size ? "has-batch" : ""}`}>{message}</p>}
    </main>
  </div>;
}

function CollectionSyncPanel({ preview, selection, busy, onToggle, onRecommended, onClose, onCommit }: {
  preview: CollectionSyncPreview;
  selection: Set<string>;
  busy: boolean;
  onToggle: (key: string) => void;
  onRecommended: (selected: boolean) => void;
  onClose: () => void;
  onCommit: () => Promise<void>;
}) {
  const counts = {
    add: preview.changes.filter((change) => change.kind === "add").length,
    modify: preview.changes.filter((change) => change.kind === "modify").length,
    remove: preview.changes.filter((change) => change.kind === "remove").length,
  };
  const recommended = preview.changes.filter((change) => change.kind !== "remove");
  const allRecommendedSelected = recommended.length > 0 && recommended.every((change) => selection.has(change.operationKey));
  return <section className="collection-sync-preview">
    <header className="collection-pane-heading"><div><span>OPENAPI SYNC</span><h3>{preview.collectionName}</h3></div><button className="icon-button" onClick={onClose} title="关闭同步预览"><X size={14} /></button></header>
    <div className="collection-sync-source">
      <span><RefreshCw size={14} /><span><strong>{sourceFileName(preview.sourcePath)}</strong><small>{preview.unchangedCount} 条未变化</small></span></span>
      <div><em className="is-add">新增 {counts.add}</em><em className="is-modify">修改 {counts.modify}</em><em className="is-remove">已删除 {counts.remove}</em></div>
    </div>
    {preview.warnings.length > 0 && <div className="collection-import-warnings">{preview.warnings.map((warning) => <span key={warning}><CircleAlert size={12} />{warning}</span>)}</div>}
    <div className="collection-sync-select"><label><input type="checkbox" checked={allRecommendedSelected} disabled={!recommended.length} onChange={(event) => onRecommended(event.target.checked)} /><span>应用新增和修改</span></label><strong>{selection.size} / {preview.changes.length}</strong></div>
    <div className="collection-sync-list">
      {preview.changes.map((change) => {
        const method = change.item?.method ?? change.currentMethod ?? "HTTP";
        const name = change.kind === "add" ? change.item?.name : change.currentName;
        const url = change.item?.url ?? change.currentUrl ?? change.operationKey;
        return <label className={`is-${change.kind}`} key={change.operationKey}>
          <input type="checkbox" checked={selection.has(change.operationKey)} onChange={() => onToggle(change.operationKey)} />
          <span className={`collection-sync-kind is-${change.kind}`}>{syncChangeKindLabel(change.kind)}</span>
          <span className={`method method-${method.toLowerCase()}`}>{method}</span>
          <span className="collection-sync-main"><strong>{name ?? change.operationKey}</strong><small>{url}</small><span>{change.changedFields.map((field) => <em key={field}>{syncFieldLabel(field)}</em>)}{change.localOverride && <em className="is-local">有本地编辑</em>}</span></span>
          <span className="collection-sync-impact">{change.kind === "remove" ? "解除关联，草稿保留" : change.kind === "modify" ? "保留名称、目录、标签、环境和 Auth" : "按规范创建草稿"}</span>
        </label>;
      })}
      {!preview.changes.length && <div className="collection-sync-empty"><Check size={20} /><strong>规范已经是最新状态</strong><span>{preview.unchangedCount} 条操作与本地来源一致</span></div>}
    </div>
    <footer><span><ShieldCheck size={13} />修改在单个事务中完成；规范删除不会删除草稿</span><button className="primary-button" disabled={busy || (preview.changes.length > 0 && selection.size === 0)} onClick={() => void onCommit()}>{busy ? <LoaderCircle className="spin" size={14} /> : <RefreshCw size={14} />}{preview.changes.length ? `应用 ${selection.size} 项变更` : "完成同步"}</button></footer>
  </section>;
}

function CollectionDefaultsPanel({ collection, environments, busy, onClose, onSave }: { collection: RequestCollection; environments: EnvironmentRecord[]; busy: boolean; onClose: () => void; onSave: (value: CollectionDefaultsDraft) => Promise<void> }) {
  const [description, setDescription] = useState(collection.description);
  const [headers, setHeaders] = useState(collection.defaultHeaders);
  const [auth, setAuth] = useState(collection.defaultAuth);
  const [environmentId, setEnvironmentId] = useState(collection.defaultEnvironmentId ?? "");
  const authKind = String(auth.kind ?? "none");
  const environmentName = environments.find((item) => item.id === environmentId)?.name
    ?? environments.find((item) => item.kind === "named" && item.active)?.name
    ?? "仅全局环境";
  const save = () => onSave({
    description,
    defaultHeaders: headers.filter((header) => header.name.trim()),
    defaultAuth: auth,
    defaultEnvironmentId: environmentId || undefined,
  });
  return <section className="collection-defaults">
    <header className="collection-pane-heading"><div><span>COLLECTION DEFAULTS</span><h3>{collection.name}</h3></div><div className="collection-pane-actions"><button onClick={onClose} title="返回集合内容"><ArrowLeft size={14} /></button></div></header>
    <div className="collection-defaults__summary"><span><FolderTree size={14} /><strong>公共配置</strong></span><em>{headers.filter((header) => header.name.trim()).length} Headers</em><em>{authKind === "none" ? "无 Auth" : authKindLabel(authKind)}</em><em>{environmentName}</em></div>
    <div className="collection-defaults__content">
      <section className="collection-defaults__identity"><label><span>集合说明</span><textarea value={description} maxLength={2000} onChange={(event) => setDescription(event.target.value)} placeholder="用途、服务边界或维护人" /></label><label><span>默认环境</span><select value={environmentId} onChange={(event) => setEnvironmentId(event.target.value)}><option value="">跟随当前激活环境</option>{environments.filter((item) => item.kind === "named").map((item) => <option key={item.id} value={item.id}>{item.name}{item.active ? "（当前）" : ""}</option>)}</select></label></section>
      <section className="collection-defaults__section"><header><div><strong>公共 Header</strong><small>请求同名项优先</small></div><span>{headers.length}</span></header><HeaderEditor headers={headers} scopeLabel="公共" onChange={setHeaders} /></section>
      <section className="collection-defaults__section"><header><div><strong>公共 Auth</strong><small>请求级 Auth 优先</small></div><LockKeyhole size={14} /></header><AuthEditor auth={auth} onChange={setAuth} onReveal={() => invoke<Record<string, unknown>>("reveal_request_collection_auth", { collectionId: collection.id })} /></section>
    </div>
    <footer><span><ShieldCheck size={13} />Auth 本机加密，Header 按原值保存</span><button className="primary-button" disabled={busy} onClick={() => void save()}>{busy ? <LoaderCircle className="spin" size={14} /> : <Save size={14} />}保存公共配置</button></footer>
  </section>;
}

function CollectionFolderTree({ collectionId, parentId, workspace, selectedFolderId, expandedFolders, onToggle, onSelect }: { collectionId: string; parentId?: string; workspace: RequestCollectionWorkspace; selectedFolderId?: string; expandedFolders: Set<string>; onToggle: (id: string) => void; onSelect: (folder: RequestCollectionFolder) => void }) {
  const folders = workspace.folders.filter((folder) => folder.collectionId === collectionId && folder.parentId === parentId);
  if (!folders.length) return null;
  return <div className="collection-folder-tree">{folders.map((folder) => {
    const hasChildren = workspace.folders.some((item) => item.parentId === folder.id);
    const expanded = expandedFolders.has(folder.id);
    return <section key={folder.id}><div className={selectedFolderId === folder.id ? "is-active" : ""} style={{ paddingLeft: `${Math.max(0, folder.depth - 1) * 10}px` }}>{hasChildren ? <button className="collection-expand" onClick={() => onToggle(folder.id)} title={expanded ? "折叠" : "展开"}>{expanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}</button> : <span className="collection-expand-placeholder" />}<button className="collection-tree-label" onClick={() => onSelect(folder)}><Folder size={13} /><span>{folder.name}</span><em>{folder.draftCount}</em></button></div>{expanded && <CollectionFolderTree collectionId={collectionId} parentId={folder.id} workspace={workspace} selectedFolderId={selectedFolderId} expandedFolders={expandedFolders} onToggle={onToggle} onSelect={onSelect} />}</section>;
  })}</div>;
}

function QueryEditor({ url, onChange }: { url: string; onChange: (url: string) => void }) {
  let parsed: URL;
  try { parsed = new URL(url); }
  catch { return <div className="query-editor-error"><CircleAlert size={15} /><span>先输入有效的 HTTP 或 HTTPS URL，再编辑 Query 参数。</span></div>; }
  const entries = [...parsed.searchParams.entries()];
  const commit = (next: Array<[string, string]>) => {
    parsed.search = "";
    next.forEach(([name, value]) => parsed.searchParams.append(name, value));
    onChange(parsed.toString());
  };
  return <div className="query-editor"><div className="query-editor-head"><span>名称</span><span>值</span><span /></div>{entries.map(([name, value], index) => <div key={`${name}-${index}`}><input value={name} onChange={(event) => commit(entries.map((entry, candidate) => candidate === index ? [event.target.value, entry[1]] : entry))} /><input value={value} onChange={(event) => commit(entries.map((entry, candidate) => candidate === index ? [entry[0], event.target.value] : entry))} /><button onClick={() => commit(entries.filter((_, candidate) => candidate !== index))} title="删除参数"><Trash2 size={12} /></button></div>)}<button className="query-add-button" onClick={() => commit([...entries, ["param", ""]])}><Plus size={12} />添加参数</button></div>;
}

function EnvironmentPanel() {
  const [environments, setEnvironments] = useState<EnvironmentRecord[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [name, setName] = useState("");
  const [variable, setVariable] = useState<{ id?: string; name: string; value: string; secret: boolean }>({ name: "", value: "", secret: false });
  const [revealedValues, setRevealedValues] = useState<Record<string, string>>({});
  const [message, setMessage] = useState("");
  const selected = environments.find((item) => item.id === selectedId) ?? environments[0];
  const load = async () => {
    if (!isTauri()) return;
    const result = await invoke<EnvironmentRecord[]>("list_environments");
    setEnvironments(result);
    setSelectedId((current) => current || result.find((item) => item.active)?.id || result[0]?.id || "");
  };
  useEffect(() => { void load(); }, []);
  const create = async (kind: "global" | "named") => {
    if (!isTauri()) { setMessage("环境持久化需要桌面应用"); return; }
    const saved = await invoke<EnvironmentRecord>("save_environment", { input: { name: kind === "global" ? "全局环境" : name.trim(), kind, active: kind === "named" && !environments.some((item) => item.kind === "named" && item.active) } });
    setName(""); await load(); setSelectedId(saved.id);
  };
  const activate = async (item: EnvironmentRecord) => {
    if (!isTauri()) return;
    await invoke("save_environment", { input: { id: item.id, name: item.name, kind: item.kind, active: true } });
    await load();
  };
  const saveVariable = async () => {
    if (!selected || !variable.name.trim() || !isTauri()) return;
    await invoke("save_environment_variable", { input: { id: variable.id, environmentId: selected.id, name: variable.name, value: variable.value || undefined, secret: variable.secret, enabled: true } });
    if (variable.id) setRevealedValues((current) => { const next = { ...current }; delete next[variable.id!]; return next; });
    setVariable({ name: "", value: "", secret: false }); await load();
  };
  const editVariable = (item: EnvironmentVariable) => setVariable({ id: item.id, name: item.name, value: item.secret ? "" : item.value, secret: item.secret });
  const toggleVariable = async (item: EnvironmentVariable) => {
    if (!selected || !isTauri()) return;
    await invoke("save_environment_variable", { input: { id: item.id, environmentId: selected.id, name: item.name, secret: item.secret, enabled: !item.enabled } });
    await load();
  };
  const deleteVariable = async (item: EnvironmentVariable) => {
    if (!isTauri() || !window.confirm(`删除变量“${item.name}”？`)) return;
    await invoke("delete_environment_variable", { variableId: item.id });
    setRevealedValues((current) => { const next = { ...current }; delete next[item.id]; return next; });
    if (variable.id === item.id) setVariable({ name: "", value: "", secret: false });
    await load();
  };
  const toggleVariableValue = async (item: EnvironmentVariable) => {
    if (item.id in revealedValues) {
      setRevealedValues((current) => { const next = { ...current }; delete next[item.id]; return next; });
      return;
    }
    if (!isTauri()) return;
    try {
      const value = await invoke<string>("reveal_environment_variable", { variableId: item.id });
      setRevealedValues((current) => ({ ...current, [item.id]: value }));
    } catch (reason) { setMessage(String(reason)); }
  };
  const deleteSelectedEnvironment = async () => {
    if (!selected || !isTauri() || !window.confirm(`删除环境“${selected.name}”及其变量？`)) return;
    await invoke("delete_environment", { environmentId: selected.id });
    setSelectedId(""); await load();
  };

  return <div className="workbench-panel environment-panel">
    <aside className="environment-list"><header><strong>环境</strong><span>{environments.length}</span></header>{environments.map((item) => <button key={item.id} className={selected?.id === item.id ? "is-active" : ""} onClick={() => setSelectedId(item.id)}><span>{item.name}</span><small>{item.kind === "global" ? "全局" : item.active ? "当前激活" : "命名环境"}</small>{item.active && <Check size={13} />}</button>)}{!environments.some((item) => item.kind === "global") && <button className="environment-global-create" onClick={() => void create("global")}><Plus size={13} /><span>创建全局环境</span></button>}<div className="environment-create"><input value={name} onChange={(event) => setName(event.target.value)} placeholder="命名环境" onKeyDown={(event) => { if (event.key === "Enter" && name.trim()) void create("named"); }} /><button className="environment-create__submit" disabled={!name.trim()} onClick={() => void create("named")} title="创建命名环境" aria-label="创建命名环境"><Plus size={13} /></button></div></aside>
    <section className="environment-editor">{selected ? <>
      <Heading meta={selected.kind === "global" ? "GLOBAL" : "NAMED"} title={selected.name} value={selected.active ? "当前激活" : ""} />
      <div className="environment-actions">{selected.kind === "named" && !selected.active && <button className="secondary-button" onClick={() => void activate(selected)}><Check size={13} />激活环境</button>}<button className="secondary-button is-danger" onClick={() => void deleteSelectedEnvironment()}><Trash2 size={13} />删除环境</button></div>
      <p className="environment-priority">解析优先级：当前激活环境 &gt; 全局环境 &gt; 内建动态变量。Secret 仅在变量列表中隐藏；发送、历史、完整导出和 AI 上下文使用实际值。</p>
      <div className="environment-builtins"><code>{"{{timestamp}}"}</code><code>{"{{timestamp_ms}}"}</code><code>{"{{iso_datetime}}"}</code><code>{"{{uuid}}"}</code></div>
      <div className="environment-table"><div><span>变量</span><span>值</span><span>类型</span><span>状态 / 操作</span></div>{selected.variables.map((item) => <div key={item.id}><code>{item.name}</code><span>{item.secret ? revealedValues[item.id] ?? "••••••••" : item.value}</span><small>{item.secret ? "Secret" : "普通"}</small><span className="environment-row-actions">{item.secret && <button onClick={() => void toggleVariableValue(item)} title={item.id in revealedValues ? "隐藏实际值" : "显示实际值"}>{item.id in revealedValues ? <EyeOff size={11} /> : <Eye size={11} />}</button>}<button className={item.enabled ? "is-enabled" : ""} onClick={() => void toggleVariable(item)}>{item.enabled ? "启用" : "停用"}</button><button onClick={() => editVariable(item)} title="编辑变量"><Pencil size={11} /></button><button onClick={() => void deleteVariable(item)} title="删除变量"><Trash2 size={11} /></button></span></div>)}</div>
      <div className="environment-variable-create"><input value={variable.name} onChange={(event) => setVariable({ ...variable, name: event.target.value })} placeholder="variable_name" /><input type={variable.secret ? "password" : "text"} value={variable.value} onChange={(event) => setVariable({ ...variable, value: event.target.value })} placeholder={variable.id && variable.secret ? "留空保留原 Secret" : "变量值"} /><label><input type="checkbox" checked={variable.secret} onChange={(event) => setVariable({ ...variable, secret: event.target.checked })} />Secret</label><button className="primary-button" onClick={() => void saveVariable()} disabled={!variable.name.trim()}>{variable.id ? <Save size={13} /> : <Plus size={13} />}{variable.id ? "保存" : "添加"}</button>{variable.id && <button className="secondary-button" onClick={() => setVariable({ name: "", value: "", secret: false })}><X size={13} /></button>}</div>
    </> : <div className="workbench-loading"><KeyRound size={22} /><span>创建环境后管理变量</span></div>}{message && <p className="workbench-inline-error">{message}</p>}</section>
  </div>;
}

function RulesPanel({ selected, details }: { selected: RequestListItem[]; details: RequestRecord[] }) {
  const [rules, setRules] = useState<CaptureRule[]>([]);
  const [draft, setDraft] = useState<RuleDraft>(createEmptyRuleDraft);
  const [editingId, setEditingId] = useState("");
  const [revisionRuleId, setRevisionRuleId] = useState("");
  const [revisions, setRevisions] = useState<CaptureRuleRevision[]>([]);
  const [preview, setPreview] = useState<RulePreviewResult>();
  const [ruleTraces, setRuleTraces] = useState<CaptureRuleRun[]>([]);
  const [message, setMessage] = useState("");
  const importRef = useRef<HTMLInputElement>(null);
  const selectedRequestId = selected.length === 1 ? selected[0].id : "";
  const load = async () => { if (isTauri()) setRules(await invoke<CaptureRule[]>("list_capture_rules")); };
  useEffect(() => { void load(); }, []);
  useEffect(() => {
    if (!isTauri() || !selectedRequestId) { setRuleTraces([]); return; }
    void invoke<CaptureRuleRun[]>("list_rule_trace_for_request", { requestId: selectedRequestId })
      .then(setRuleTraces)
      .catch((reason) => setMessage(String(reason)));
  }, [selectedRequestId]);
  const resetEditor = () => { setDraft(createEmptyRuleDraft()); setEditingId(""); };
  const save = async () => {
    if (!isTauri()) { setMessage("规则持久化需要桌面应用"); return; }
    const validationError = captureRuleDraftValidationError(draft);
    if (validationError) { setMessage(validationError); return; }
    const action = captureRuleActionFromDraft(draft);
    try {
      await invoke("save_capture_rule_draft", { input: { id: editingId || undefined, name: draft.name, enabled: false, priority: draft.priority, stage: draft.stage, matcher: { kind: "predicate", field: draft.field, operator: draft.operator, value: draft.operator === "exists" ? undefined : draft.matchValue }, action, createdBy: "user" } });
      setMessage(editingId ? "已保存为新的停用版本" : "已保存停用规则草稿");
      resetEditor(); await load();
      if (revisionRuleId) await loadRevisions(revisionRuleId);
    } catch (reason) { setMessage(String(reason)); }
  };
  const editRule = (rule: CaptureRule) => {
    const editable = captureRuleDraftFromRule(rule);
    if (!editable) { setMessage("这条规则包含组合条件或当前编辑器不支持的操作，请通过导入更新；现有高级结构不会被覆盖。"); return; }
    setEditingId(rule.id); setDraft(editable); setMessage("编辑保存后会生成新版本，并自动停用规则");
  };
  const loadRevisions = async (ruleId: string) => {
    if (!isTauri()) return;
    try {
      setRevisionRuleId(ruleId);
      setRevisions(await invoke<CaptureRuleRevision[]>("list_capture_rule_revisions", { ruleId }));
    } catch (reason) { setMessage(String(reason)); }
  };
  const restoreRevision = async (item: CaptureRuleRevision) => {
    if (!isTauri() || !window.confirm(`恢复 v${item.revision} 的内容为新的停用版本？`)) return;
    try {
      const restored = await invoke<CaptureRule>("restore_capture_rule_revision", { ruleId: item.ruleId, revision: item.revision });
      setMessage(`已从 v${item.revision} 创建 v${restored.revision}，规则保持停用`);
      await load(); await loadRevisions(item.ruleId);
    } catch (reason) { setMessage(String(reason)); }
  };
  const toggle = async (rule: CaptureRule) => {
    if (!isTauri()) return;
    const isBreakpoint = rule.action.kind === "breakpoint";
    const isMirror = rule.action.kind === "mirror";
    const isRedirect = rule.action.kind === "redirect";
    const confirmation = isBreakpoint
      ? `启用人工断点“${rule.name}”？匹配流量会暂停，等待你放行或中止。`
      : isMirror
        ? `启用镜像“${rule.name}”？新建连接会改向 ${String(rule.action.targetHost ?? "目标地址")}，已有 Keep-Alive 连接不受影响。`
        : isRedirect
          ? `启用请求转发“${rule.name}”？匹配请求会改发到 ${String(rule.action.targetTemplate ?? "目标地址")}。${rule.action.preserveCredentials === true ? "此规则会保留认证信息与 Cookie，请确认目标可信。" : "跨域时默认移除认证信息与 Cookie。"}`
      : `启用规则“${rule.name}”（优先级 ${rule.priority}）？规则会影响后续匹配流量。`;
    if (!rule.enabled && !window.confirm(confirmation)) return;
    try { await invoke("set_capture_rule_enabled", { ruleId: rule.id, enabled: !rule.enabled, confirmed: !rule.enabled }); await load(); } catch (reason) { setMessage(String(reason)); }
  };
  const runPreview = async (rule: CaptureRule) => {
    if (selected.length !== 1 || !isTauri()) return;
    try {
      setPreview(await invoke<RulePreviewResult>("preview_capture_rule", { ruleId: rule.id, requestId: selected[0].id }));
      setRuleTraces(await invoke<CaptureRuleRun[]>("list_rule_trace_for_request", { requestId: selected[0].id }));
    } catch (reason) { setMessage(String(reason)); }
  };
  const changeStage = (stage: RuleStage) => {
    const next = changeRuleDraftStage(draft, stage);
    setDraft(stage === "connection" && !editingId && selected.length === 1
      ? prefillMirrorDraftFromRequest(next, selected[0])
      : next);
  };
  const patchOperation = (id: string, patch: Partial<RuleOperationDraft>) => setDraft({
    ...draft,
    operations: draft.operations.map((operation) => operation.id === id ? { ...operation, ...patch } : operation),
  });
  const changeOperationTarget = (id: string, target: RuleOperationTarget) => {
    setDraft(changeRuleDraftOperationTarget(draft, id, target, details[0]));
  };
  const addOperation = () => setDraft({ ...draft, operations: [...draft.operations, createEmptyRuleOperation(draft.stage)] });
  const removeOperation = (id: string) => setDraft({ ...draft, operations: draft.operations.filter((operation) => operation.id !== id) });
  const exportRules = () => {
    const exported = rules.map((rule) => ({ name: rule.name, priority: rule.priority, stage: rule.stage, matcher: rule.matcher, action: rule.action, createdBy: rule.createdBy, revision: rule.revision }));
    downloadJson({ format: "shownet-capture-rules", version: 1, exportedAt: new Date().toISOString(), rules: exported }, `shownet-rules-${Date.now()}.json`);
  };
  const importRules = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !isTauri()) return;
    try {
      const parsed = JSON.parse(await file.text()) as { rules?: CaptureRule[] } | CaptureRule[];
      const imported = Array.isArray(parsed) ? parsed : parsed.rules;
      if (!Array.isArray(imported) || imported.length > 100) throw new Error("规则文件无效或超过 100 条限制");
      for (const rule of imported) await invoke("save_capture_rule_draft", { input: { name: rule.name, enabled: false, priority: rule.priority, stage: rule.stage, matcher: rule.matcher, action: rule.action, createdBy: "user" } });
      setMessage(`已导入 ${imported.length} 条禁用规则草稿`); await load();
    } catch (reason) { setMessage(`导入失败：${String(reason)}`); }
  };

  const validationError = captureRuleDraftValidationError(draft);
  return <div className="workbench-panel rules-panel">
    <BreakpointConsole />
    <section className="rule-list"><div className="rule-list-heading"><Heading meta="DECLARATIVE RULES" title="规则、版本与执行轨迹" value={rules.filter((rule) => rule.enabled).length + " 条启用"} /><div><button className="secondary-button" onClick={exportRules} disabled={!rules.length}><Download size={13} />导出</button><button className="secondary-button" onClick={() => importRef.current?.click()}><Upload size={13} />导入</button><input ref={importRef} type="file" accept="application/json,.json" onChange={(event) => void importRules(event)} hidden /></div></div>{rules.map((rule) => <div key={rule.id} className="rule-row"><button className={"rule-toggle " + (rule.enabled ? "is-on" : "")} onClick={() => void toggle(rule)} title={rule.enabled ? "停用规则" : "确认并启用规则"}><i /></button><span><strong>{rule.name}</strong><small>{ruleStageLabel(rule.stage)} · 优先级 {rule.priority} · v{rule.revision} · 命中 {rule.hitCount}</small></span><code>{ruleActionLabel(String(rule.action.kind))}</code><div className="rule-row-actions"><button onClick={() => editRule(rule)} title="编辑规则"><Pencil size={12} /></button><button className={revisionRuleId === rule.id ? "is-active" : ""} onClick={() => void loadRevisions(rule.id)} title="查看版本"><History size={12} /></button><button disabled={selected.length !== 1} onClick={() => void runPreview(rule)} title="用选中请求预览"><Activity size={12} /></button></div></div>)}{!rules.length && <p className="rule-empty">还没有规则草稿</p>}</section>
    {revisionRuleId && <section className="rule-revisions"><header><strong>{rules.find((rule) => rule.id === revisionRuleId)?.name ?? "规则版本"}</strong><span>{revisions.length} 个版本</span><button onClick={() => { setRevisionRuleId(""); setRevisions([]); }} title="关闭版本列表"><X size={12} /></button></header>{revisions.map((item, index) => <div key={item.id}><span><strong>v{item.revision}</strong><small>{new Date(item.createdAt).toLocaleString("zh-CN")}</small></span>{index === 0 && item.revision === rules.find((rule) => rule.id === item.ruleId)?.revision ? <em>当前</em> : <button className="secondary-button" onClick={() => void restoreRevision(item)}><History size={12} />恢复为新版本</button>}</div>)}</section>}
    <section className="rule-editor">
      <div className="workbench-heading"><div><span>{editingId ? "EDIT REVISION" : "DRAFT"}</span><h3>{editingId ? "编辑规则并创建新版本" : "新建禁用规则草稿"}</h3></div><ShieldCheck size={18} /></div>
      <div className="rule-form">
        <TextField label="规则名称" value={draft.name} maxLength={120} onChange={(name) => setDraft({ ...draft, name })} />
        <label><span>优先级</span><input type="number" min="-10000" max="10000" value={draft.priority} onChange={(event) => setDraft({ ...draft, priority: Number(event.target.value) })} /></label>
        <label><span>阶段</span><select value={draft.stage} onChange={(event) => changeStage(event.target.value as RuleStage)}><option value="connection">连接阶段</option><option value="request">请求阶段</option><option value="response">响应阶段</option></select></label>
        <label><span>匹配字段</span><select value={draft.field} onChange={(event) => setDraft({ ...draft, field: event.target.value, operator: ["gt", "gte", "lt", "lte"].includes(draft.operator) && event.target.value !== "status" ? "equals" : draft.operator })}><option value="host">{draft.stage === "connection" ? "原始 Host" : "Host"}</option>{draft.stage !== "connection" && <><option value="path">Path</option><option value="url">完整 URL</option><option value="method">Method</option></>}<option value="scheme">Scheme</option><option value="source">来源</option><option value="protocol">协议</option>{draft.stage !== "connection" && <option value="requestHeader">请求 Header</option>}{draft.stage === "response" && <><option value="status">响应状态</option><option value="responseHeader">响应 Header</option></>}</select></label>
        <label><span>操作符</span><select value={draft.operator} onChange={(event) => setDraft({ ...draft, operator: event.target.value })}><option value="contains">包含</option><option value="not_contains">不包含</option><option value="equals">等于</option><option value="not_equals">不等于</option><option value="starts_with">开头为</option><option value="ends_with">结尾为</option><option value="wildcard">通配符</option><option value="regex">正则</option><option value="exists">存在</option>{draft.field === "status" && <><option value="gt">大于</option><option value="gte">大于等于</option><option value="lt">小于</option><option value="lte">小于等于</option></>}</select></label>
        {draft.operator !== "exists" && <TextField label="匹配值" value={draft.matchValue} maxLength={draft.operator === "regex" ? 256 : undefined} onChange={(matchValue) => setDraft({ ...draft, matchValue })} />}
        <label><span>动作</span><select value={draft.actionKind} onChange={(event) => setDraft({ ...draft, actionKind: event.target.value as RuleActionKind })}>{draft.stage === "connection" ? <option value="mirror">域名镜像</option> : <><option value="rewrite">{draft.stage === "response" ? "响应重写" : "请求重写"}</option><option value="breakpoint">人工断点</option>{draft.stage === "request" && <><option value="redirect">请求转发（Map Remote）</option><option value="delay">延迟与抖动</option><option value="throttle">弱网条件</option><option value="block">出站阻断</option></>}</>}</select></label>
      </div>
      {draft.actionKind === "rewrite" && <div className="rule-operation-editor">
        <header><div><strong>原子重写操作</strong><span>{draft.operations.length} / 50</span></div><button onClick={addOperation} disabled={draft.operations.length >= 50} title="添加重写操作"><Plus size={13} /></button></header>
        {draft.operations.map((operation, index) => {
          const bodyTarget = operation.target === "request.body" || operation.target === "response.body";
          return <div className={`rule-operation-row ${bodyTarget ? "is-body" : ""}`} key={operation.id}>
            <span>{String(index + 1).padStart(2, "0")}</span>
            <div className="rule-operation-primary"><select aria-label={`操作 ${index + 1} 目标`} value={operation.target} onChange={(event) => changeOperationTarget(operation.id, event.target.value as RuleOperationTarget)}>{draft.stage === "request" ? <><option value="request.header">请求 Header</option><option value="query">Query 参数</option><option value="request.body">请求正文</option></> : <><option value="response.header">响应 Header</option><option value="response.status">响应状态</option><option value="response.body">响应正文</option></>}</select><select aria-label={`操作 ${index + 1} 类型`} value={operation.operation} onChange={(event) => patchOperation(operation.id, { operation: event.target.value as RuleOperationDraft["operation"] })}>{bodyTarget ? <><option value="set">整体设置</option><option value="replace">正则替换</option></> : operation.target === "response.status" ? <option value="set">设置</option> : <><option value="set">设置</option><option value="delete">删除</option></>}</select></div>
            <div className={`rule-operation-fields ${bodyTarget ? "is-body" : ""}`}>
              {(["request.header", "query", "response.header"] as RuleOperationTarget[]).includes(operation.target) && <input aria-label={`操作 ${index + 1} 名称`} maxLength={1024} value={operation.name} onChange={(event) => patchOperation(operation.id, { name: event.target.value })} placeholder={operation.target === "query" ? "参数名称" : "Header 名称"} />}
              {bodyTarget && operation.operation === "replace" && <input aria-label={`操作 ${index + 1} 正则`} maxLength={256} value={operation.pattern} onChange={(event) => patchOperation(operation.id, { pattern: event.target.value })} placeholder="匹配正则（1–256 字节）" />}
              {operation.operation !== "delete" && (bodyTarget
                ? <textarea aria-label={`操作 ${index + 1} 正文`} value={operation.value} onChange={(event) => patchOperation(operation.id, { value: event.target.value })} placeholder={operation.operation === "replace" ? "替换内容" : "新的完整正文"} spellCheck={false} />
                : <input aria-label={`操作 ${index + 1} 值`} type={operation.target === "response.status" ? "number" : "text"} min={operation.target === "response.status" ? 100 : undefined} max={operation.target === "response.status" ? 599 : undefined} value={operation.value} onChange={(event) => patchOperation(operation.id, { value: event.target.value })} placeholder={operation.target === "response.status" ? "200" : "设置值"} />)}
              {bodyTarget && <small className="rule-body-safety"><ShieldCheck size={11} />仅处理完整 UTF-8 文本 · 流量正文不超过 2 MiB · 长度自动维护</small>}
            </div>
            <button onClick={() => removeOperation(operation.id)} disabled={draft.operations.length === 1} title="删除重写操作"><Trash2 size={12} /></button>
          </div>;
        })}
      </div>}
      {draft.actionKind !== "rewrite" && <div className="rule-action-settings">
        {draft.actionKind === "mirror" && <><TextField label="镜像主机" value={draft.mirrorTargetHost} maxLength={253} onChange={(mirrorTargetHost) => setDraft({ ...draft, mirrorTargetHost })} /><label><span>目标端口（可选）</span><input inputMode="numeric" value={draft.mirrorTargetPort} onChange={(event) => setDraft({ ...draft, mirrorTargetPort: event.target.value.replace(/\D/g, "").slice(0, 5) })} placeholder="沿用原端口" /></label><div className="mirror-identity-control"><span>上游身份</span><div role="group" aria-label="镜像上游身份"><button className={draft.mirrorIdentity === "original" ? "is-active" : ""} onClick={() => setDraft({ ...draft, mirrorIdentity: "original" })} title="连接镜像地址，保留原 Host、SNI 与证书校验身份"><ShieldCheck size={12} />兼容模式</button><button className={draft.mirrorIdentity === "target" ? "is-active" : ""} onClick={() => setDraft({ ...draft, mirrorIdentity: "target" })} title="连接、Host、SNI 与上游证书校验均使用镜像地址"><Route size={12} />测试环境</button></div><small>{draft.mirrorIdentity === "original" ? "Host / SNI：原域名" : "Host / SNI：镜像地址"}</small></div></>}
        {draft.actionKind === "breakpoint" && <><label><span>最长等待（秒）</span><input type="number" min="5" max="300" value={draft.breakpointTimeoutSeconds} onChange={(event) => setDraft({ ...draft, breakpointTimeoutSeconds: boundedNumber(event.target.value, 5, 300) })} /></label><label><span>等待超时</span><select value={draft.breakpointOnTimeout} onChange={(event) => setDraft({ ...draft, breakpointOnTimeout: event.target.value as RuleDraft["breakpointOnTimeout"] })}><option value="continue">自动放行</option><option value="abort">中止流量</option></select></label></>}
        {draft.actionKind === "redirect" && <div className="rule-redirect-settings">
          <TextField label="转发目标 URL" value={draft.targetTemplate} maxLength={4096} onChange={(targetTemplate) => setDraft({ ...draft, targetTemplate })} />
          <TextField label="排除 URL（可选）" value={draft.redirectExcludePattern} maxLength={4096} onChange={(redirectExcludePattern) => setDraft({ ...draft, redirectExcludePattern })} />
          <div className="rule-redirect-options">
            <label title="默认使用转发目标的 Host；仅在目标服务明确依赖原 Host 时开启"><input type="checkbox" checked={draft.redirectPreserveHost} onChange={(event) => setDraft({ ...draft, redirectPreserveHost: event.target.checked })} /><span>保留原 Host</span></label>
            <label title="跨域默认移除 Authorization、Cookie 和常见 Token Header"><input type="checkbox" checked={draft.redirectPreserveCredentials} onChange={(event) => setDraft({ ...draft, redirectPreserveCredentials: event.target.checked })} /><span>保留认证与 Cookie</span></label>
            <label title="允许原 HTTPS 请求改发到明文 HTTP 目标"><input type="checkbox" checked={draft.redirectAllowInsecureDowngrade} onChange={(event) => setDraft({ ...draft, redirectAllowInsecureDowngrade: event.target.checked })} /><span>允许 HTTPS → HTTP</span></label>
          </div>
          <small className={`rule-redirect-safety ${draft.redirectPreserveCredentials || draft.redirectAllowInsecureDowngrade ? "is-warning" : ""}`}>{draft.redirectPreserveCredentials || draft.redirectAllowInsecureDowngrade ? <CircleAlert size={11} /> : <ShieldCheck size={11} />}路径 <code>{"{{path}}"}</code> · 查询 <code>{"{{query}}"}</code> · 子目录 <code>/*</code></small>
        </div>}
        {(draft.actionKind === "delay" || draft.actionKind === "throttle") && <><label><span>固定延迟 ms</span><input type="number" min="0" max="30000" value={draft.latencyMs} onChange={(event) => setDraft({ ...draft, latencyMs: boundedNumber(event.target.value, 0, 30000) })} /></label><label><span>随机抖动 ms</span><input type="number" min="0" max="30000" value={draft.jitterMs} onChange={(event) => setDraft({ ...draft, jitterMs: boundedNumber(event.target.value, 0, 30000) })} /></label></>}
        {draft.actionKind === "throttle" && <><label><span>上行 Kbps</span><input type="number" min="0" max="1000000" value={draft.uploadKbps} onChange={(event) => setDraft({ ...draft, uploadKbps: boundedNumber(event.target.value, 0, 1000000) })} /></label><label><span>下行 Kbps</span><input type="number" min="0" max="1000000" value={draft.downloadKbps} onChange={(event) => setDraft({ ...draft, downloadKbps: boundedNumber(event.target.value, 0, 1000000) })} /></label><label><span>丢包率 %</span><input type="number" min="0" max="100" step="0.1" value={draft.packetLossPercent} onChange={(event) => setDraft({ ...draft, packetLossPercent: boundedNumber(event.target.value, 0, 100) })} /></label></>}
      </div>}
      <div className="workbench-actions"><span className={validationError ? "is-warning" : ""}>{validationError ? <CircleAlert size={12} /> : <ShieldCheck size={12} />}{validationError ?? "草稿默认停用"}</span><div>{editingId && <button className="secondary-button" onClick={resetEditor}><X size={13} />取消编辑</button>}<button className="primary-button" disabled={!!validationError} title={validationError} onClick={() => void save()}><Save size={13} />{editingId ? "保存新版本" : "保存草稿"}</button></div></div>
      {message && <p className="workbench-inline-error">{message}</p>}
    </section>
    {preview && <section className={"rule-preview " + (preview.matched ? "is-match" : "")}><header><strong>{preview.matched ? "样本命中" : "样本未命中"}</strong><span>{preview.stage}</span></header>{preview.changes.map((change) => <p key={change}><Check size={12} />{change}</p>)}{preview.warnings.map((warning) => <p key={warning} className="is-warning"><CircleAlert size={12} />{warning}</p>)}<pre>{JSON.stringify(preview.after, null, 2)}</pre></section>}
      {selected.length === 1 && <section className="rule-execution-traces"><header><div><span>EXECUTION TRACE</span><strong>当前请求</strong></div><em>{ruleTraces.length} 条</em></header><div>{ruleTraces.slice(-20).reverse().map((trace) => <article className={`is-${trace.result}`} key={trace.id}><span>{trace.stage === "connection" ? "C" : trace.stage === "response" ? "R" : "Q"}</span><div><strong>{trace.ruleName}</strong><small>{ruleTraceResultLabel(trace.result)} · v{trace.revision} · {trace.durationMs} ms</small>{Array.isArray(trace.diffSummary.changes) && trace.diffSummary.changes.map((change) => <p key={String(change)}>{String(change)}</p>)}{trace.error && <p className="is-error">{trace.error}</p>}</div><time>{new Date(trace.createdAt).toLocaleTimeString("zh-CN", { hour12: false })}</time></article>)}{!ruleTraces.length && <p className="rule-empty">当前请求暂无规则轨迹</p>}</div></section>}
  </div>;
}

interface BreakpointEditDraft {
  taskId: string;
  method: string;
  url: string;
  status: string;
  requestHeaders: HeaderEntry[];
  responseHeaders: HeaderEntry[];
  requestBody: string;
  responseBody: string;
}

function BreakpointConsole() {
  const [queue, setQueue] = useState<BreakpointQueueSnapshot>({ tasks: [], capacity: 32, skippedCount: 0, generatedAt: Date.now() });
  const [selectedTaskId, setSelectedTaskId] = useState("");
  const [draft, setDraft] = useState<BreakpointEditDraft>();
  const [editorTab, setEditorTab] = useState<"headers" | "body">("headers");
  const [message, setMessage] = useState("");
  const [submitting, setSubmitting] = useState<BreakpointDecisionInput["action"] | "">("");
  const [now, setNow] = useState(Date.now());

  const refresh = useCallback(async () => {
    if (!isTauri()) return;
    try {
      setQueue(await invoke<BreakpointQueueSnapshot>("get_breakpoint_queue"));
    } catch (reason) {
      setMessage(String(reason));
    }
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void refresh();
    void listen("capture://breakpoints-changed", () => void refresh()).then((cleanup) => {
      if (disposed) cleanup(); else unlisten = cleanup;
    }).catch((reason) => setMessage(String(reason)));
    return () => { disposed = true; unlisten?.(); };
  }, [refresh]);

  useEffect(() => {
    if (!queue.tasks.length) return;
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [queue.tasks.length]);

  useEffect(() => {
    setSelectedTaskId((current) => queue.tasks.some((task) => task.id === current) ? current : queue.tasks[0]?.id ?? "");
  }, [queue.tasks]);

  const activeTask = queue.tasks.find((task) => task.id === selectedTaskId);
  useEffect(() => {
    if (!activeTask) { setDraft(undefined); return; }
    setDraft((current) => current?.taskId === activeTask.id ? current : breakpointEditDraft(activeTask));
    setMessage("");
  }, [activeTask]);

  const restore = () => {
    if (activeTask) setDraft(breakpointEditDraft(activeTask));
    setMessage("");
  };
  const resolve = async (action: BreakpointDecisionInput["action"]) => {
    if (!activeTask || !draft || !isTauri()) return;
    const input: BreakpointDecisionInput = { taskId: activeTask.id, action };
    if (action === "continue" && activeTask.stage === "request") {
      input.method = draft.method.trim();
      input.url = draft.url.trim();
      input.requestHeaders = draft.requestHeaders;
      if (activeTask.bodyEditable) input.requestBody = draft.requestBody;
    }
    if (action === "continue" && activeTask.stage === "response") {
      const status = Number(draft.status);
      if (!Number.isInteger(status) || status < 100 || status > 599) {
        setMessage("响应状态码必须在 100 到 599 之间");
        return;
      }
      input.status = status;
      input.responseHeaders = draft.responseHeaders;
      if (activeTask.bodyEditable) input.responseBody = draft.responseBody;
    }
    setSubmitting(action);
    setMessage("");
    try {
      await invoke("resolve_breakpoint", { input });
      await refresh();
    } catch (reason) {
      setMessage(String(reason));
    } finally {
      setSubmitting("");
    }
  };

  return <section className={`breakpoint-console ${queue.tasks.length ? "has-pending" : ""}`}>
    <header className="breakpoint-console__heading">
      <div><span className="breakpoint-console__icon"><Pause size={14} fill="currentColor" /></span><span><strong>人工断点</strong><small>{queue.tasks.length ? "等待处理" : "队列空闲"}</small></span></div>
      <div><strong>{queue.tasks.length} / {queue.capacity}</strong>{queue.skippedCount > 0 && <small>{queue.skippedCount} 条已自动放行</small>}</div>
    </header>
    {!queue.tasks.length ? <div className="breakpoint-console__empty"><Pause size={15} /><span>暂无等待流量</span></div> : <div className="breakpoint-console__workspace">
      <aside className="breakpoint-queue" aria-label="待处理断点">
        {queue.tasks.map((task) => {
          const remaining = task.expiresAt - now;
          return <button key={task.id} className={`${task.id === activeTask?.id ? "is-active" : ""} ${remaining <= 10_000 ? "is-urgent" : ""}`} onClick={() => setSelectedTaskId(task.id)}>
            <span className={`breakpoint-stage is-${task.stage}`}>{task.stage === "request" ? "请求" : "响应"}</span>
            <span className="breakpoint-queue__summary"><strong>{task.method} {breakpointUrlLabel(task.url)}</strong><small>{task.ruleName}</small></span>
            <time><Clock3 size={11} />{breakpointRemainingLabel(task.expiresAt, now)}</time>
          </button>;
        })}
      </aside>
      {activeTask && draft && <section className="breakpoint-editor">
        <header><div><span>{activeTask.stage === "request" ? "REQUEST" : "RESPONSE"}</span><strong>{activeTask.ruleName}</strong></div><code>{activeTask.requestId.slice(-8)}</code></header>
        <div className={`breakpoint-editor__target is-${activeTask.stage}`}>
          <label><span>方法</span><input value={draft.method} disabled={activeTask.stage === "response"} onChange={(event) => setDraft({ ...draft, method: event.target.value.toUpperCase() })} /></label>
          <label><span>URL</span><input value={draft.url} disabled={activeTask.stage === "response"} onChange={(event) => setDraft({ ...draft, url: event.target.value })} /></label>
          {activeTask.stage === "response" && <label><span>状态</span><input type="number" min="100" max="599" value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })} /></label>}
        </div>
        <div className="breakpoint-editor__tabs" role="tablist" aria-label="断点编辑内容">
          <button className={editorTab === "headers" ? "is-active" : ""} onClick={() => setEditorTab("headers")}>Headers</button>
          <button className={editorTab === "body" ? "is-active" : ""} onClick={() => setEditorTab("body")}>Body</button>
        </div>
        <div className="breakpoint-editor__content">
          {editorTab === "headers" && <HeaderEditor
            headers={activeTask.stage === "request" ? draft.requestHeaders : draft.responseHeaders}
            lockedNames={activeTask.stage === "request" ? requestBreakpointManagedHeaders : responseBreakpointManagedHeaders}
            scopeLabel={activeTask.stage === "request" ? "请求" : "响应"}
            onChange={(headers) => setDraft(activeTask.stage === "request" ? { ...draft, requestHeaders: headers } : { ...draft, responseHeaders: headers })}
          />}
          {editorTab === "body" && <div className={`breakpoint-body-editor ${activeTask.bodyEditable ? "" : "is-locked"}`}>
            <textarea spellCheck={false} disabled={!activeTask.bodyEditable} value={activeTask.stage === "request" ? draft.requestBody : draft.responseBody} onChange={(event) => setDraft(activeTask.stage === "request" ? { ...draft, requestBody: event.target.value } : { ...draft, responseBody: event.target.value })} />
            {!activeTask.bodyEditable && <p><LockKeyhole size={12} />{activeTask.bodyUnavailableReason ?? "当前正文不能安全编辑"}</p>}
          </div>}
        </div>
        <footer>
          <span className={message ? "is-error" : ""}>{message || `${breakpointRemainingLabel(activeTask.expiresAt, now)} 后按规则自动处理`}</span>
          <div><button className="secondary-button" onClick={restore} disabled={!!submitting}><RotateCcw size={13} />恢复原值</button><button className="breakpoint-abort-button" onClick={() => void resolve("abort")} disabled={!!submitting}><Square size={11} fill="currentColor" />{submitting === "abort" ? "正在中止" : "中止"}</button><button className="primary-button" onClick={() => void resolve("continue")} disabled={!!submitting}><Play size={13} fill="currentColor" />{submitting === "continue" ? "正在放行" : "放行"}</button></div>
        </footer>
      </section>}
    </div>}
  </section>;
}

function breakpointEditDraft(task: BreakpointTask): BreakpointEditDraft {
  return {
    taskId: task.id,
    method: task.method,
    url: task.url,
    status: String(task.status ?? 200),
    requestHeaders: task.requestHeaders.map((header) => ({ ...header })),
    responseHeaders: task.responseHeaders.map((header) => ({ ...header })),
    requestBody: task.requestBody ?? "",
    responseBody: task.responseBody ?? "",
  };
}

function breakpointUrlLabel(value: string) {
  try {
    const url = new URL(value);
    return `${url.host}${url.pathname}${url.search}`;
  } catch {
    return value;
  }
}

function breakpointRemainingLabel(expiresAt: number, now: number) {
  const seconds = Math.max(0, Math.ceil((expiresAt - now) / 1000));
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}

function Heading({ meta, title, value, warning = false }: { meta: string; title: string; value: string; warning?: boolean }) {
  return <div className="workbench-heading"><div><span>{meta}</span><h3>{title}</h3></div><strong className={warning ? "is-warning" : ""}>{value}</strong></div>;
}
function NumberSetting({ label, value, min = 1, max, onChange }: { label: string; value: number; min?: number; max: number; onChange: (value: number) => void }) {
  return <label className="number-setting"><span>{label}</span><input type="number" value={value} min={min} max={max} onChange={(event) => onChange(Math.min(max, Math.max(min, Number(event.target.value) || min)))} /></label>;
}
function Toggle({ label, detail, checked, onChange }: { label: string; detail: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return <label className="workbench-toggle"><span><strong>{label}</strong><small>{detail}</small></span><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><i /></label>;
}
function Notice({ children }: { children: React.ReactNode }) { return <div className="workbench-error"><CircleAlert size={15} /><span>{children}</span></div>; }
function TextField({ label, value, maxLength, onChange }: { label: string; value: string; maxLength?: number; onChange: (value: string) => void }) { return <label><span>{label}</span><input value={value} maxLength={maxLength} onChange={(event) => onChange(event.target.value)} /></label>; }
function batchLabel(status: ReplayBatch["status"]) { return ({ queued: "等待开始", running: "正在重放", complete: "批次已完成", failed: "批次失败", cancelled: "批次已取消" })[status]; }
function diffLabel(section: RequestDiffEntry["section"]) { return ({ request: "请求", response: "响应", transport: "TLS / HTTP / Timing", evidence: "Hook 证据" })[section]; }
function emptyDraft(sessionId?: string): RequestDraft { return { id: crypto.randomUUID(), sessionId, name: "新请求", method: "GET", url: "https://example.com/", headers: [], body: "", bodyType: "none", auth: { kind: "none" }, settings: { followRedirects: true, verifyTls: true, cookieJar: false }, tags: [], createdAt: Date.now(), updatedAt: Date.now() }; }
function draftInput(draft: RequestDraft) { return { id: draft.id, sessionId: draft.sessionId, sourceRequestId: draft.sourceRequestId, name: draft.name, method: draft.method, url: draft.url, headers: draft.headers, body: draft.body, bodyType: draft.bodyType, auth: draft.auth, settings: draft.settings, environmentId: draft.environmentId, collectionId: draft.collectionId, folderId: draft.folderId, tags: draft.tags }; }

function emptyCollectionWorkspace(): RequestCollectionWorkspace { return { collections: [], folders: [], drafts: [] }; }
function toggleSet<T>(current: Set<T>, value: T) { const next = new Set(current); if (next.has(value)) next.delete(value); else next.add(value); return next; }
function draftLocationValue(draft: Pick<RequestDraft, "collectionId" | "folderId">) { return draft.folderId ? `folder:${draft.folderId}` : draft.collectionId ? `collection:${draft.collectionId}` : ""; }
function parseDraftLocationValue(value: string, workspace: RequestCollectionWorkspace): Pick<RequestDraft, "collectionId" | "folderId"> {
  if (value.startsWith("folder:")) {
    const folderId = value.slice(7);
    const folder = workspace.folders.find((item) => item.id === folderId);
    return folder ? { collectionId: folder.collectionId, folderId } : { collectionId: undefined, folderId: undefined };
  }
  if (value.startsWith("collection:")) return { collectionId: value.slice(11), folderId: undefined };
  return { collectionId: undefined, folderId: undefined };
}
function collectionFolderBreadcrumb(folder: RequestCollectionFolder | undefined, folders: RequestCollectionFolder[]) {
  const result: RequestCollectionFolder[] = [];
  let current = folder;
  const seen = new Set<string>();
  while (current && !seen.has(current.id)) {
    seen.add(current.id); result.unshift(current);
    current = current.parentId ? folders.find((item) => item.id === current?.parentId) : undefined;
  }
  return result;
}
function collectionLocationOptions(workspace: RequestCollectionWorkspace) {
  return workspace.collections.flatMap((collection) => {
    const options = [{ value: `collection:${collection.id}`, label: collection.name }];
    const folders = workspace.folders.filter((folder) => folder.collectionId === collection.id);
    const ordered = [...folders].sort((left, right) => left.depth - right.depth || left.sortOrder - right.sortOrder || left.name.localeCompare(right.name));
    return options.concat(ordered.map((folder) => ({
      value: `folder:${folder.id}`,
      label: `${collection.name} / ${collectionFolderBreadcrumb(folder, folders).map((item) => item.name).join(" / ")}`,
    })));
  });
}
function draftCollectionLabel(draft: RequestDraft, workspace: RequestCollectionWorkspace) {
  const collection = workspace.collections.find((item) => item.id === draft.collectionId);
  if (!collection) return undefined;
  const folder = workspace.folders.find((item) => item.id === draft.folderId);
  return folder ? `${collection.name} / ${collectionFolderBreadcrumb(folder, workspace.folders).map((item) => item.name).join(" / ")}` : collection.name;
}
function formatImportSource(value: string) { return ({ postman: "Postman 2.x", insomnia: "Insomnia", openapi: "OpenAPI / Swagger", har: "浏览器 HAR", shownet: "ShowNet JSON" } as Record<string, string>)[value] ?? value; }
function safeFilename(value: string) { return value.trim().replace(/[\\/:*?"<>|]+/g, "-").replace(/\s+/g, "-") || "request-collection"; }
function sourceFileName(value?: string) { return value?.split(/[\\/]/).filter(Boolean).at(-1) ?? "OpenAPI 规范"; }
function syncChangeKindLabel(value: "add" | "modify" | "remove") { return ({ add: "新增", modify: "修改", remove: "已删除" })[value]; }
function syncFieldLabel(value: string) {
  return ({ operation: "操作", name: "名称", method: "方法", url: "URL", headers: "Header", body: "正文", folder: "目录", request: "请求" } as Record<string, string>)[value] ?? value;
}

function draftTarget(value: string) {
  try {
    const url = new URL(value);
    return { host: url.host, path: `${url.pathname}${url.search}` };
  } catch {
    return { host: "URL 待完善", path: value || "/" };
  }
}

function formatDraftTime(value: number) {
  if (!value) return "--";
  return new Date(value).toLocaleString([], { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

interface StructuredBodyField {
  id: string;
  name: string;
  value: string;
  kind: "text" | "file";
  filePath?: string;
  fileName?: string;
  contentType?: string;
  enabled: boolean;
}

interface FileBodyValue {
  filePath: string;
  fileName: string;
  contentType: string;
}

function StructuredBodyEditor({ mode, value, onChange }: { mode: "form-data" | "urlencoded"; value: string; onChange: (value: string) => void }) {
  const fields = parseStructuredBodyFields(value);
  const update = (next: StructuredBodyField[]) => onChange(JSON.stringify(next));
  const patchField = (id: string, patch: Partial<StructuredBodyField>) => update(fields.map((field) => field.id === id ? { ...field, ...patch } : field));
  const addField = () => update([...fields, { id: crypto.randomUUID(), name: "", value: "", kind: "text", enabled: true }]);
  const chooseFile = async (field: StructuredBodyField) => {
    const selected = await openDialog({ multiple: false, directory: false, title: "选择请求正文文件" });
    if (typeof selected !== "string") return;
    patchField(field.id, { filePath: selected, fileName: selected.split(/[\\/]/).pop() ?? "file" });
  };
  return <div className={`structured-body-editor is-${mode}`}>
    <div className="structured-body-head"><span>状态</span>{mode === "form-data" && <span>类型</span>}<span>名称</span><span>值</span><span /></div>
    {fields.map((field) => <div key={field.id} className={!field.enabled ? "is-disabled" : ""}>
      <label className="structured-body-enabled"><input type="checkbox" checked={field.enabled} onChange={(event) => patchField(field.id, { enabled: event.target.checked })} /><i /></label>
      {mode === "form-data" && <select value={field.kind} onChange={(event) => patchField(field.id, { kind: event.target.value as StructuredBodyField["kind"] })}><option value="text">Text</option><option value="file">File</option></select>}
      <input value={field.name} onChange={(event) => patchField(field.id, { name: event.target.value })} />
      {mode === "form-data" && field.kind === "file" ? <div className="structured-file-value"><button className="secondary-button" onClick={() => void chooseFile(field)} title="选择文件"><FileUp size={12} /><span>{field.fileName || "选择文件"}</span></button><input value={field.contentType ?? ""} onChange={(event) => patchField(field.id, { contentType: event.target.value })} placeholder="Content-Type" /></div> : <input value={field.value} onChange={(event) => patchField(field.id, { value: event.target.value })} />}
      <button className="structured-body-remove" onClick={() => update(fields.filter((item) => item.id !== field.id))} title="删除字段"><Trash2 size={12} /></button>
    </div>)}
    <button className="query-add-button" onClick={addField}><Plus size={12} />添加字段</button>
  </div>;
}

function FileBodyEditor({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const file = parseFileBody(value);
  const update = (patch: Partial<FileBodyValue>) => onChange(JSON.stringify({ ...file, ...patch }));
  const chooseFile = async () => {
    const selected = await openDialog({ multiple: false, directory: false, title: "选择请求正文文件" });
    if (typeof selected !== "string") return;
    update({ filePath: selected, fileName: selected.split(/[\\/]/).pop() ?? "file" });
  };
  return <div className="file-body-editor"><button className="secondary-button" onClick={() => void chooseFile()}><FileUp size={14} /><span>{file.fileName || "选择文件"}</span></button><label><span>Content-Type</span><input value={file.contentType} onChange={(event) => update({ contentType: event.target.value })} placeholder="application/octet-stream" /></label>{file.filePath && <code title={file.filePath}>{file.filePath}</code>}</div>;
}

function parseStructuredBodyFields(value: string): StructuredBodyField[] {
  if (!value.trim()) return [];
  try {
    const parsed = JSON.parse(value) as unknown;
    if (Array.isArray(parsed)) return parsed.map((item) => {
      const field = item as Partial<StructuredBodyField>;
      return {
        id: field.id || crypto.randomUUID(), name: String(field.name ?? ""), value: String(field.value ?? ""),
        kind: field.kind === "file" ? "file" : "text", filePath: field.filePath, fileName: field.fileName,
        contentType: field.contentType, enabled: field.enabled !== false,
      };
    });
  } catch { /* Legacy line format is converted below. */ }
  return value.split(/\r?\n/).filter(Boolean).map((line) => {
    const index = line.indexOf("=");
    return { id: crypto.randomUUID(), name: (index < 0 ? line : line.slice(0, index)).trim(), value: index < 0 ? "" : line.slice(index + 1), kind: "text", enabled: true };
  });
}

function parseFileBody(value: string): FileBodyValue {
  try {
    const parsed = JSON.parse(value) as Partial<FileBodyValue>;
    return { filePath: String(parsed.filePath ?? ""), fileName: String(parsed.fileName ?? ""), contentType: String(parsed.contentType ?? "") };
  } catch { return { filePath: "", fileName: "", contentType: "" }; }
}

function bodyForType(next: RequestDraft["bodyType"], current: RequestDraft["bodyType"], body: string) {
  if (next === current) return body;
  if (next === "form-data" || next === "urlencoded") return "[]";
  if (next === "file") return JSON.stringify({ filePath: "", fileName: "", contentType: "" });
  if (next === "none") return "";
  return current === "form-data" || current === "urlencoded" || current === "file" ? "" : body;
}

function bodyFromRunSnapshot(body: unknown, bodyType: unknown): Pick<RequestDraft, "body" | "bodyType"> {
  const type = (["none","json","text","xml","raw","form-data","urlencoded","file"] as const).find((item) => item === bodyType) ?? "raw";
  if (type === "file" && body && typeof body === "object") return { body: JSON.stringify(body), bodyType: type };
  if (type === "form-data" && Array.isArray(body)) {
    const fields = body.map((item) => ({ ...(item as Record<string, unknown>), id: crypto.randomUUID(), enabled: true }));
    return { body: JSON.stringify(fields), bodyType: type };
  }
  return { body: typeof body === "string" ? body : JSON.stringify(body ?? ""), bodyType: type };
}

function CookieJarManager({ cookies, onDelete, onClear }: { cookies: RequestCookieRecord[]; onDelete: (cookie: RequestCookieRecord) => void; onClear: () => void }) {
  return <section className="lab-cookie-jar">
    <header><div><Cookie size={14} /><strong>Cookie Jar</strong><span>{cookies.length}</span></div><button onClick={onClear} disabled={!cookies.length} title="清空 Cookie Jar"><Trash2 size={13} /></button></header>
    <div className="lab-cookie-list">{cookies.map((cookie) => <div key={`${cookie.domain}\n${cookie.path}\n${cookie.name}`}>
      <span><strong>{cookie.name}</strong><small>{cookie.domain}{cookie.path}</small></span>
      <span className="lab-cookie-flags">{cookie.secure && <em>Secure</em>}{cookie.httpOnly && <em>HttpOnly</em>}{cookie.sameSite && <em>{cookie.sameSite}</em>}</span>
      <time>{cookie.expiresAt ? new Date(cookie.expiresAt).toLocaleDateString("zh-CN") : "本次会话"}</time>
      <button onClick={() => onDelete(cookie)} title={`删除 ${cookie.name}`}><Trash2 size={12} /></button>
    </div>)}{!cookies.length && <div className="lab-cookie-empty"><Cookie size={15} /><span>Cookie Jar 为空</span></div>}</div>
    <footer><LockKeyhole size={12} /><span>本机加密存储</span></footer>
  </section>;
}

function HeaderEditor({ headers, inheritedCount = 0, scopeLabel = "请求", lockedNames = [], onChange }: { headers: HeaderEntry[]; inheritedCount?: number; scopeLabel?: string; lockedNames?: string[]; onChange: (headers: HeaderEntry[]) => void }) {
  const [mode, setMode] = useState<"table" | "text">("table");
  const locked = new Set(lockedNames.map((name) => name.toLowerCase()));
  const effectiveMode = locked.size ? "table" : mode;
  const value = headers.map((header) => header.name + ": " + header.value).join("\n");
  const patchHeader = (index: number, patch: Partial<HeaderEntry>) => onChange(headers.map((header, candidate) => candidate === index ? { ...header, ...patch } : header));
  return <div className="header-editor">
    <div className="header-editor-toolbar"><span>{headers.length} {scopeLabel}{inheritedCount > 0 ? ` · ${inheritedCount} 集合` : ""}</span>{locked.size ? <small><LockKeyhole size={10} />代理 Header 已锁定</small> : <div><button className={mode === "table" ? "is-active" : ""} onClick={() => setMode("table")}>表格</button><button className={mode === "text" ? "is-active" : ""} onClick={() => setMode("text")}>文本</button></div>}</div>
    {effectiveMode === "table" ? <div className="header-editor-table">
      <div className="header-editor-head"><span>名称</span><span>值</span><span /></div>
      {headers.map((header, index) => { const isLocked = locked.has(header.name.toLowerCase()); return <div className={`header-editor-row ${isLocked ? "is-locked" : ""}`} key={index}><input value={header.name} disabled={isLocked} onChange={(event) => patchHeader(index, { name: event.target.value })} /><input value={header.value} disabled={isLocked} onChange={(event) => patchHeader(index, { value: event.target.value })} /><button disabled={isLocked} onClick={() => onChange(headers.filter((_, candidate) => candidate !== index))} title={isLocked ? "此 Header 由代理维护" : "删除 Header"}>{isLocked ? <LockKeyhole size={11} /> : <Trash2 size={12} />}</button></div>; })}
      <button className="query-add-button" onClick={() => onChange([...headers, { name: "", value: "" }])}><Plus size={12} />添加 Header</button>
    </div> : <div className="key-value-text-editor"><textarea value={value} onChange={(event) => onChange(event.target.value.split(/\r?\n/).filter(Boolean).map((line) => { const index = line.indexOf(":"); return { name: index < 0 ? line.trim() : line.slice(0,index).trim(), value: index < 0 ? "" : line.slice(index + 1).trim() }; }))} /><small>每行一个 Header，使用“名称: 值”格式</small></div>}
  </div>;
}
function AuthEditor({ auth, inheritedKind = "none", onChange, onReveal }: { auth: Record<string, unknown>; inheritedKind?: string; onChange: (auth: Record<string, unknown>) => void; onReveal?: () => Promise<Record<string, unknown>> }) {
  const kind = String(auth.kind ?? "none");
  const placeholder = auth.hasSecret ? "已加密保存，留空保持不变" : "";
  const reveal = onReveal ? async () => onChange(await onReveal()) : undefined;
  return <div className="auth-editor">
    {kind === "none" && inheritedKind !== "none" && <div className="auth-inheritance-note"><FolderTree size={13} /><span>当前使用集合的 {authKindLabel(inheritedKind)}；选择请求级 Auth 后会自动覆盖。</span></div>}
    <label><span>类型</span><select value={kind} onChange={(event) => onChange({ kind: event.target.value })}><option value="none">None</option><option value="basic">Basic</option><option value="bearer">Bearer</option><option value="api-key">API Key</option></select></label>
    {kind === "basic" && <><label><span>用户名</span><input placeholder="{{username}}" value={String(auth.username ?? "")} onChange={(event) => onChange({ ...auth, username: event.target.value })} /></label><label><span>密码</span><SecretInput placeholder={placeholder || "{{password}}"} value={String(auth.password ?? "")} onChange={(password) => onChange({ ...auth, password })} onReveal={reveal} /></label></>}
    {kind === "bearer" && <label><span>Token</span><SecretInput placeholder={placeholder || "{{token}}"} value={String(auth.token ?? "")} onChange={(token) => onChange({ ...auth, token })} onReveal={reveal} /></label>}
    {kind === "api-key" && <><label><span>位置</span><select value={String(auth.location ?? "header")} onChange={(event) => onChange({ ...auth, location: event.target.value })}><option value="header">Header</option><option value="query">Query</option></select></label><TextField label="名称" value={String(auth.name ?? "X-API-Key")} onChange={(name) => onChange({ ...auth, name })} /><label><span>值</span><SecretInput placeholder={placeholder || "{{api_key}}"} value={String(auth.value ?? "")} onChange={(value) => onChange({ ...auth, value })} onReveal={reveal} /></label></>}
    <p><LockKeyhole size={13} />本机加密保存；眼睛按钮可查看实际值。</p>
  </div>;
}

function SecretInput({ value, placeholder, onChange, onReveal }: { value: string; placeholder: string; onChange: (value: string) => void; onReveal?: () => Promise<void> }) {
  const [visible, setVisible] = useState(false);
  const [revealing, setRevealing] = useState(false);
  const toggle = async () => {
    const next = !visible;
    setVisible(next);
    if (next && !value && onReveal) {
      setRevealing(true);
      try { await onReveal(); } finally { setRevealing(false); }
    }
  };
  return <span className="secret-input"><input type={visible ? "text" : "password"} placeholder={placeholder} value={value} onChange={(event) => onChange(event.target.value)} /><button type="button" onClick={() => void toggle()} disabled={revealing} title={visible ? "隐藏实际值" : "显示实际值"}>{visible ? <EyeOff size={13} /> : <Eye size={13} />}</button></span>;
}

function authKindLabel(kind: string) {
  return ({ basic: "Basic Auth", bearer: "Bearer Token", "api-key": "API Key" } as Record<string, string>)[kind] ?? "Auth";
}

function boundedNumber(value: string, min: number, max: number) {
  return Math.min(max, Math.max(min, Number(value) || 0));
}

function ruleStageLabel(stage: CaptureRule["stage"]) { return ({ request: "请求", response: "响应", connection: "连接" } as const)[stage]; }
function ruleActionLabel(kind: string) { return ({ mirror: "镜像", rewrite: "重写", redirect: "转发", delay: "延迟", throttle: "弱网", block: "阻断", breakpoint: "断点" } as Record<string, string>)[kind] ?? kind; }
function ruleTraceResultLabel(result: string) { return ({ applied: "已执行", inherited: "沿用连接", skipped: "已跳过", preview: "预览", error: "错误", "not-matched": "未命中" } as Record<string, string>)[result] ?? result; }

function downloadJson(value: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url; link.download = filename; link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
