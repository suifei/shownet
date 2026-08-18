import {
  ArrowDown,
  ArrowDownLeft,
  ArrowUp,
  ArrowUpRight,
  Bot,
  Bookmark,
  Braces,
  Globe2 as Browser,
  Check,
  ChevronDown,
  CircleAlert,
  CircleDot,
  Clock3,
  Code2,
  Columns3,
  Copy,
  Download,
  Filter,
  FlaskConical,
  FolderTree,
  GitCompareArrows,
  GripVertical,
  ListFilter,
  ListRestart,
  LoaderCircle,
  LockKeyhole,
  MessagesSquare,
  Maximize2,
  MoreHorizontal,
  Minimize2,
  PanelBottom,
  PanelRight,
  Pause,
  Play,
  Plus,
  Radio,
  RotateCcw,
  Save,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Strikethrough,
  StickyNote,
  Tag,
  Trash2,
  X,
} from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useReducer, useRef, useState, type CSSProperties } from "react";
import { initialRequests, sourceLabels } from "../data";
import type { WorkbenchMode } from "./RequestWorkbench";
import { HttpBodyMetadataGrid, HttpBodyStatus, HttpBodyViewer } from "./HttpBodyViewer";
import {
  buildQuickFilter,
  createPredicate,
  describeActiveFilters,
  emptyQuickFilter,
  METHOD_VALUES,
  normalizeFilterExpression,
  PROTOCOL_LABELS,
  PROTOCOL_VALUES,
  removeActiveFilter,
  requestStateLabel,
  RISK_LABELS,
  SHOWNET_LABELS,
  SHOWNET_VALUES,
  STATUS_LABELS,
  STATUS_VALUES,
  TYPE_LABELS,
  TYPE_VALUES,
  type ActiveFilterChip,
  type QuickFilterState,
  type QuickShownet,
  type QuickStatus,
} from "../requestFilters";
import { headerValue, INSPECTOR_PREFERENCES_KEY, legacyBodyMetadata, parseCookies, parseInspectorPreferences, parseQueryEntries, timingEvidence, type InspectorLayout } from "../requestInspector";
import { initialRequestSelection, requestSelectionReducer } from "../requestSelection";
import type { LiveCaptureDisplaySnapshot } from "../liveCaptureDisplay";
import { nextRequestListWindowOffset, shouldChangeRequestListWindow } from "../requestList";
import { generateRequestCode, requestCodeTemplates, type RequestCodeTemplate } from "../requestCode";
import { t } from "../i18n.ts";
import { calculateVirtualWindow, defaultRequestGridPreferences, estimateRequestColumnWidth, nextRequestSort, parseRequestGridPreferences, reorderRequestColumn, REQUEST_GRID_HEADER_HEIGHT, REQUEST_GRID_PREFERENCES_KEY, REQUEST_GRID_ROW_HEIGHT, requestColumnDefinitions, requestColumnLabel, requestGridTemplate, requestGridWidth, resizeRequestColumn, toggleRequestColumn, visibleRequestColumns, type RequestColumnId } from "../trafficGrid";
import { classifyTrafficStatus, looksLikeProxyErrorBody } from "../trafficStatus";
import { filterAndOrderSseEvents, isSseTerminal, prettySseData, sseEventLabel, type SseOrder } from "../sseInspector";
import type { CaptureRuleRun, CryptoCodeSnippet, FilterExpression, RequestAnnotation, RequestAnnotationInput, RequestAnnotationSummary, RequestFacets, RequestField, RequestListItem, RequestRecord, RequestSort, RiskLevel, SavedRequestView, SourceType, SseEvent, WebSocketFrameEvent } from "../types";
import { formatBytes, formatClock, formatListBytes, getClockLocale, isSlowRequest } from "../format";
import { QUICK_FILTER_METHODS } from "../httpMethods";
import { ruleTraceResultLabel } from "../ruleTrace";
import { useDismissibleLayer, useEscapeDismiss } from "../useDismissibleLayer";
import { sourceIcons } from "../sourceIcons";


type DetailTab = "overview" | "query" | "requestHeaders" | "responseHeaders" | "cookies" | "requestBody" | "responseBody" | "messages" | "sse" | "code" | "fingerprint" | "hook" | "rules" | "timing" | "annotation";
type TrafficMenu = "filter" | "columns" | "live";
type FilterTab = "quick" | "advanced" | "views";

const defaultGridSort: RequestSort[] = [{ field: "order", direction: "asc" }];

interface TrafficViewProps {
  requests: RequestListItem[];
  totalCount: number;
  filteredCount: number;
  hookCount: number;
  bookmarkedCount: number;
  requestWindowOffset: number;
  requestWindowTargetOffset?: number;
  facets: RequestFacets;
  loading: boolean;
  cancelling: boolean;
  /** True only when this viewed session is the live capture target. */
  capturing: boolean;
  captureElsewhere: boolean;
  captureSessionName?: string;
  liveDisplay: LiveCaptureDisplaySnapshot;
  sessionId: string;
  focusRequestId?: string;
  onFocusRequestConsumed: () => void;
  onQueryChange: (filter: FilterExpression | undefined, sort: RequestSort[]) => void;
  onRequestWindowChange: (offset: number) => void;
  onCancelRequestQuery: () => void;
  onOpenAnalysis: () => void;
  onAnalyzeSelection: (requestIds: string[]) => void;
  onOpenWorkbench: (mode: WorkbenchMode, selected: RequestListItem[], options?: { createFromSelection?: boolean }) => void;
  onToggleLiveDisplay: () => void;
  onLiveDisplayAutoProtectionChange: (enabled: boolean) => void;
  onConnect: () => void;
  /** Zero-setup path: open embedded browser capture without CA. */
  onOpenBrowser?: () => void;
  /** Optional jump to settings CA install when MITM HTTPS is needed. */
  onOpenSettingsCapture?: () => void;
}

export function TrafficView({ requests, totalCount, filteredCount, hookCount, bookmarkedCount, requestWindowOffset, requestWindowTargetOffset, facets, loading, cancelling, capturing, captureElsewhere, captureSessionName, liveDisplay, sessionId, focusRequestId, onFocusRequestConsumed, onQueryChange, onRequestWindowChange, onCancelRequestQuery, onOpenAnalysis, onAnalyzeSelection, onOpenWorkbench, onToggleLiveDisplay, onLiveDisplayAutoProtectionChange, onConnect, onOpenBrowser, onOpenSettingsCapture }: TrafficViewProps) {
  const [query, setQuery] = useState("");
  const [quickFilter, setQuickFilter] = useState<QuickFilterState>(emptyQuickFilter);
  const [advancedFilter, setAdvancedFilter] = useState<FilterExpression>();
  const [sort, setSort] = useState<RequestSort[]>(defaultGridSort);
  const [selection, dispatchSelection] = useReducer(requestSelectionReducer, initialRequestSelection);
  /**
   * The first row is auto-selected on load so the detail pane has something to
   * show. That is not a user action, and the contextual action bar must not
   * appear as though the user asked for it.
   */
  const [selectionFromUser, setSelectionFromUser] = useState(false);
  const selectionCacheRef = useRef(new Map<string, RequestListItem>());
  const [bookmarkCountDelta, setBookmarkCountDelta] = useState(0);
  const [pendingFocus, setPendingFocus] = useState<{ index: number; extend: boolean }>();
  const [detailOpen, setDetailOpen] = useState(true);
  const [facetsOpen, setFacetsOpen] = useState(() => (globalThis.innerWidth ?? 0) >= 1440);
  const [menu, setMenu] = useState<TrafficMenu>();
  const [filterTab, setFilterTab] = useState<FilterTab>("quick");
  const [savedViews, setSavedViews] = useState<SavedRequestView[]>([]);
  const [savedViewName, setSavedViewName] = useState("");
  const [annotationOverrides, setAnnotationOverrides] = useState<Record<string, RequestAnnotationSummary>>({});
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number }>();
  const [preferences, setPreferences] = useState(() => parseRequestGridPreferences(globalThis.localStorage?.getItem(REQUEST_GRID_PREFERENCES_KEY)));
  const [inspectorPreferences, setInspectorPreferences] = useState(() => parseInspectorPreferences(globalThis.localStorage?.getItem(INSPECTOR_PREFERENCES_KEY), globalThis.innerWidth));
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(500);
  const [resizing, setResizing] = useState<{ id: RequestColumnId; startX: number; startWidth: number }>();
  const [inspectorResizing, setInspectorResizing] = useState<{ startX: number; startY: number; startSize: number }>();
  const scrollRef = useRef<HTMLDivElement>(null);
  const toolbarRef = useRef<HTMLDivElement>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);
  const [selectionMoreOpen, setSelectionMoreOpen] = useState(false);
  /** Short-lived inline error for actions that have no other feedback surface. */
  const [actionError, setActionError] = useState("");
  const selectionMoreRef = useRef<HTMLDivElement>(null);
  const locatingFocusIdRef = useRef<string | undefined>(undefined);

  useDismissibleLayer(Boolean(menu), toolbarRef, () => setMenu(undefined));
  useDismissibleLayer(Boolean(contextMenu), contextMenuRef, () => setContextMenu(undefined));
  useDismissibleLayer(selectionMoreOpen, selectionMoreRef, () => setSelectionMoreOpen(false));

  useEffect(() => {
    if (!actionError) return;
    const timer = window.setTimeout(() => setActionError(""), 6_000);
    return () => window.clearTimeout(timer);
  }, [actionError]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setQuickFilter((current) => current.text === query ? current : { ...current, text: query });
    }, 250);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    dispatchSelection({ type: "clear" });
    selectionCacheRef.current.clear();
    setBookmarkCountDelta(0);
    setPendingFocus(undefined);
    setScrollTop(0);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
    onQueryChange(buildQuickFilter(quickFilter, normalizeFilterExpression(advancedFilter)), sort);
  }, [advancedFilter, onQueryChange, quickFilter, sessionId, sort]);

  useEffect(() => {
    globalThis.localStorage?.setItem(REQUEST_GRID_PREFERENCES_KEY, JSON.stringify(preferences));
  }, [preferences]);

  useEffect(() => {
    globalThis.localStorage?.setItem(INSPECTOR_PREFERENCES_KEY, JSON.stringify(inspectorPreferences));
  }, [inspectorPreferences]);

  useEffect(() => {
    const element = scrollRef.current;
    if (!element) return;
    const update = () => setViewportHeight(element.clientHeight);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!resizing) return;
    const move = (event: PointerEvent) => setPreferences((current) => resizeRequestColumn(current, resizing.id, resizing.startWidth + event.clientX - resizing.startX));
    const stop = () => setResizing(undefined);
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", stop, { once: true });
    return () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", stop);
    };
  }, [resizing]);

  useEffect(() => {
    if (!inspectorResizing || inspectorPreferences.layout === "maximized") return;
    const move = (event: PointerEvent) => {
      setInspectorPreferences((current) => current.layout === "right"
        ? { ...current, rightWidth: Math.min(760, Math.max(320, inspectorResizing.startSize - (event.clientX - inspectorResizing.startX))) }
        : { ...current, bottomHeight: Math.min(720, Math.max(240, inspectorResizing.startSize - (event.clientY - inspectorResizing.startY))) });
    };
    const stop = () => setInspectorResizing(undefined);
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", stop, { once: true });
    return () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", stop);
    };
  }, [inspectorPreferences.layout, inspectorResizing]);

  useEffect(() => {
    const selectedIds = new Set(selection.selectedIds);
    for (const request of requests) if (selectedIds.has(request.id)) selectionCacheRef.current.set(request.id, request);
    for (const id of selectionCacheRef.current.keys()) if (!selectedIds.has(id)) selectionCacheRef.current.delete(id);
  }, [requests, selection.selectedIds]);

  useEffect(() => {
    if (requestWindowOffset === 0 && requests.length > 0 && selection.selectedIds.length === 0 && !selection.focusedId) {
      dispatchSelection({ type: "click", id: requests[0].id, ids: requests.map((request) => request.id) });
      setSelectionFromUser(false);
    }
  }, [requestWindowOffset, requests, selection.focusedId, selection.selectedIds.length]);

  useEffect(() => {
    if (!pendingFocus) return;
    const localIndex = pendingFocus.index - requestWindowOffset;
    const request = localIndex >= 0 && localIndex < requests.length ? requests[localIndex] : undefined;
    if (!request) return;
    selectionCacheRef.current.set(request.id, request);
    dispatchSelection({
      type: "click",
      id: request.id,
      ids: requests.map((item) => item.id),
      toggle: pendingFocus.extend,
    });
    setPendingFocus(undefined);
  }, [pendingFocus, requestWindowOffset, requests]);

  useEffect(() => {
    const element = scrollRef.current;
    const index = requests.findIndex((request) => request.id === selection.focusedId);
    if (!element || index < 0) return;
    const rowTop = 32 + (requestWindowOffset + index) * REQUEST_GRID_ROW_HEIGHT;
    const rowBottom = rowTop + REQUEST_GRID_ROW_HEIGHT;
    if (rowTop < element.scrollTop + 32) element.scrollTop = Math.max(0, rowTop - 32);
    else if (rowBottom > element.scrollTop + element.clientHeight) element.scrollTop = rowBottom - element.clientHeight;
  }, [requestWindowOffset, requests, selection.focusedId]);

  const loadSavedViews = useCallback(async () => {
    if (!sessionId) return;
    if (isTauri()) {
      setSavedViews(await invoke<SavedRequestView[]>("list_saved_request_views", { sessionId }));
      return;
    }
    const raw = globalThis.localStorage?.getItem(`shownet.saved-request-views.${sessionId}`);
    try { setSavedViews(raw ? JSON.parse(raw) as SavedRequestView[] : []); } catch { setSavedViews([]); }
  }, [sessionId]);

  useEffect(() => { void loadSavedViews(); }, [loadSavedViews]);

  const columns = useMemo(() => visibleRequestColumns(preferences), [preferences]);
  const gridTemplate = useMemo(() => requestGridTemplate(preferences), [preferences]);
  const gridWidth = useMemo(() => requestGridWidth(preferences), [preferences]);
  const virtualWindow = useMemo(
    () => calculateVirtualWindow(filteredCount, scrollTop, viewportHeight),
    [filteredCount, scrollTop, viewportHeight],
  );
  const desiredWindowOffset = useMemo(() => nextRequestListWindowOffset(
    filteredCount,
    requestWindowOffset,
    requests.length,
    virtualWindow.start,
    virtualWindow.end,
  ), [filteredCount, requestWindowOffset, requests.length, virtualWindow.end, virtualWindow.start]);
  useEffect(() => {
    if (shouldChangeRequestListWindow(desiredWindowOffset, requestWindowOffset, requestWindowTargetOffset)) {
      onRequestWindowChange(desiredWindowOffset);
    }
  }, [desiredWindowOffset, onRequestWindowChange, requestWindowOffset, requestWindowTargetOffset]);
  const visibleRows = useMemo(() => Array.from(
    { length: Math.max(0, virtualWindow.end - virtualWindow.start) },
    (_, localIndex) => {
      const absoluteIndex = virtualWindow.start + localIndex;
      const windowIndex = absoluteIndex - requestWindowOffset;
      return {
        absoluteIndex,
        request: windowIndex >= 0 && windowIndex < requests.length ? requests[windowIndex] : undefined,
      };
    },
  ), [requestWindowOffset, requests, virtualWindow.end, virtualWindow.start]);
  const selected = requests.find((request) => request.id === selection.focusedId)
    ?? (selection.focusedId ? selectionCacheRef.current.get(selection.focusedId) : undefined)
    ?? selection.selectedIds.map((id) => selectionCacheRef.current.get(id)).find(Boolean);
  const selectedSet = useMemo(() => new Set(selection.selectedIds), [selection.selectedIds]);
  const apiCount = facets.types.length
    ? sumFacet(facets.types, ["fetch", "xhr"])
    : requests.filter((request) => request.type === "fetch" || request.type === "xhr").length;
  const errorCount = facets.statuses.length
    ? facets.statuses.reduce((count, facet) => count + (Number(facet.value) >= 400 || facet.value === "failed" ? facet.count : 0), 0)
    : requests.filter((request) => request.state === "failed" || (request.status ?? 0) >= 400).length;

  const toggleQuickValue = <K extends "hosts" | "methods" | "protocols" | "types" | "statuses" | "exactStatuses" | "sources" | "risks" | "shownet">(
    key: K,
    value: QuickFilterState[K][number],
  ) => {
    setQuickFilter((current) => {
      const values = current[key] as unknown[];
      return { ...current, [key]: values.includes(value) ? values.filter((candidate) => candidate !== value) : [...values, value] } as QuickFilterState;
    });
  };

  const clearFilters = () => {
    setQuery("");
    setQuickFilter(emptyQuickFilter);
    setAdvancedFilter(undefined);
  };

  // One read-out of everything narrowing the list, whichever surface set it.
  const activeFilterChips = useMemo(
    () => describeActiveFilters(quickFilter, advancedFilter, sourceLabels),
    [advancedFilter, quickFilter],
  );

  const removeFilterChip = (chip: ActiveFilterChip) => {
    if (chip.group === "advanced") { setAdvancedFilter(undefined); return; }
    // The search box owns `query`; `quickFilter.text` is its debounced copy, so
    // clearing the chip has to reset the input or the text reappears.
    if (chip.group === "text") { setQuery(""); return; }
    setQuickFilter((current) => removeActiveFilter(current, chip));
  };

  useEffect(() => {
    if (!focusRequestId) return;
    const request = requests.find((candidate) => candidate.id === focusRequestId);
    if (!request) {
      const defaultSort = sort.length === 1 && sort[0].field === "order" && sort[0].direction === "asc";
      if (hasQuickFilters(quickFilter) || advancedFilter || !defaultSort) {
        clearFilters();
        setSort(defaultGridSort);
        return;
      }
      if (!isTauri() || locatingFocusIdRef.current === focusRequestId) return;
      locatingFocusIdRef.current = focusRequestId;
      void invoke<RequestListItem>("get_request_list_item", { requestId: focusRequestId })
        .then((item) => {
          if (locatingFocusIdRef.current !== focusRequestId) return;
          const targetIndex = Math.max(0, Math.min(filteredCount - 1, item.order - 1));
          setPendingFocus({ index: targetIndex, extend: false });
          onRequestWindowChange(nextRequestListWindowOffset(
            filteredCount,
            requestWindowOffset,
            requests.length,
            targetIndex,
            targetIndex + 1,
          ));
          if (scrollRef.current) scrollRef.current.scrollTop = 32 + targetIndex * REQUEST_GRID_ROW_HEIGHT;
        })
        .catch(() => onFocusRequestConsumed())
        .finally(() => {
          if (locatingFocusIdRef.current === focusRequestId) locatingFocusIdRef.current = undefined;
        });
      return;
    }
    locatingFocusIdRef.current = undefined;
    dispatchSelection({ type: "click", id: request.id, ids: requests.map((candidate) => candidate.id) });
    setDetailOpen(true);
    onFocusRequestConsumed();
  }, [advancedFilter, filteredCount, focusRequestId, onFocusRequestConsumed, onRequestWindowChange, quickFilter, requestWindowOffset, requests, sort]);

  const handleGridKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const ids = requests.map((request) => request.id);
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "a") {
      event.preventDefault();
      const visibleAbsoluteIndex = Math.min(
        Math.max(0, filteredCount - 1),
        Math.max(0, Math.floor((scrollTop - REQUEST_GRID_HEADER_HEIGHT) / REQUEST_GRID_ROW_HEIGHT)),
      );
      const visibleLocalIndex = Math.min(
        Math.max(0, requests.length - 1),
        Math.max(0, visibleAbsoluteIndex - requestWindowOffset),
      );
      dispatchSelection({ type: "selectAll", ids, focusedId: requests[visibleLocalIndex]?.id });
      setSelectionFromUser(true);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const direction = event.key === "ArrowDown" ? 1 : -1;
      const focusedLocalIndex = requests.findIndex((request) => request.id === selection.focusedId);
      const currentIndex = focusedLocalIndex >= 0
        ? requestWindowOffset + focusedLocalIndex
        : Math.min(filteredCount - 1, Math.max(0, virtualWindow.start));
      const targetIndex = Math.min(filteredCount - 1, Math.max(0, currentIndex + direction));
      const targetLocalIndex = targetIndex - requestWindowOffset;
      if (targetLocalIndex >= 0 && targetLocalIndex < requests.length && focusedLocalIndex >= 0) {
        dispatchSelection({ type: "move", direction, ids, extend: event.shiftKey });
        setSelectionFromUser(true);
      } else if (targetIndex !== currentIndex) {
        setPendingFocus({ index: targetIndex, extend: event.shiftKey });
        const targetOffset = nextRequestListWindowOffset(
          filteredCount,
          requestWindowOffset,
          requests.length,
          targetIndex,
          targetIndex + 1,
        );
        onRequestWindowChange(targetOffset);
        if (scrollRef.current) scrollRef.current.scrollTop = 32 + targetIndex * REQUEST_GRID_ROW_HEIGHT;
      }
    } else if (event.key === "Enter" && selected) {
      event.preventDefault();
      setDetailOpen((value) => !value);
    } else if (event.key === "Escape") {
      if (detailOpen) setDetailOpen(false);
      else if (query || hasQuickFilters(quickFilter) || advancedFilter) clearFilters();
      else dispatchSelection({ type: "clear" });
    }
  };

  const saveCurrentView = async () => {
    const name = savedViewName.trim();
    if (!name) return;
    const now = Date.now();
    const input = { name, sessionId, filter: buildQuickFilter(quickFilter, normalizeFilterExpression(advancedFilter)), sort, columns: preferences };
    if (isTauri()) {
      try {
        await invoke("save_request_view", { input });
        await loadSavedViews();
      } catch (reason) { setActionError(t("traffic.saveViewFailed", { error: String(reason) })); return; }
    } else {
      const next = [...savedViews, { ...input, id: crypto.randomUUID(), createdAt: now, updatedAt: now }];
      setSavedViews(next);
      globalThis.localStorage?.setItem(`shownet.saved-request-views.${sessionId}`, JSON.stringify(next));
    }
    setSavedViewName("");
  };

  const deleteSavedView = async (view: SavedRequestView) => {
    if (isTauri()) {
      try {
        await invoke("delete_request_view", { viewId: view.id });
        await loadSavedViews();
      } catch (reason) { setActionError(t("traffic.deleteViewFailed", { error: String(reason) })); return; }
    } else {
      const next = savedViews.filter((candidate) => candidate.id !== view.id);
      setSavedViews(next);
      globalThis.localStorage?.setItem(`shownet.saved-request-views.${sessionId}`, JSON.stringify(next));
    }
  };

  const applySavedView = (view: SavedRequestView) => {
    setQuery("");
    setQuickFilter(emptyQuickFilter);
    setAdvancedFilter(view.filter);
    setSort(view.sort.length ? view.sort : defaultGridSort);
    if (view.columns) setPreferences(parseRequestGridPreferences(JSON.stringify(view.columns)));
    setMenu(undefined);
  };

  const setInspectorLayout = (layout: InspectorLayout) => {
    setInspectorPreferences((current) => ({ ...current, layout }));
    setDetailOpen(true);
  };

  const splitStyle = {
    "--inspector-right-width": `${inspectorPreferences.rightWidth}px`,
    "--inspector-bottom-height": `${inspectorPreferences.bottomHeight}px`,
  } as CSSProperties;

  const loadedRequestsById = new Map(requests.map((request) => [request.id, request]));
  const selectedCurrentWindowCount = selection.selectedIds.reduce(
    (count, id) => count + (loadedRequestsById.has(id) ? 1 : 0),
    0,
  );
  const selectedCurrentWindow = requests.length < filteredCount
    && requests.length > 0
    && selection.selectedIds.length === requests.length
    && selectedCurrentWindowCount === requests.length;
  const selectedRequests = selection.selectedIds
    .map((id) => loadedRequestsById.get(id) ?? selectionCacheRef.current.get(id))
    .filter((request): request is RequestListItem => Boolean(request));
  const copySelectedUrls = async () => {
    await navigator.clipboard?.writeText(selectedRequests.map(requestUrl).join("\n"));
  };
  const exportSelectedSummary = () => {
    const summary = selectedRequests.map((request) => ({ id: request.id, order: request.order, method: request.method, url: requestUrl(request), status: request.status, type: request.type, source: request.source, protocol: request.protocol, sizeBytes: request.sizeBytes, durationMs: request.durationMs, risk: request.risk, hasHook: request.hasHook }));
    downloadBody(JSON.stringify({ format: "shownet-request-evidence", version: 1, exportedAt: new Date().toISOString(), requests: summary }, null, 2), `shownet-evidence-${Date.now()}.json`, "application/json");
  };
  const toggleSelectedBookmark = async () => {
    const request = selectedRequests[0];
    if (!request || selectedRequests.length !== 1) return;
    try {
      const current = annotationOverrides[request.id] ?? request.annotation;
      const loaded = isTauri() ? await invoke<RequestAnnotation | null>("get_request_annotation", { requestId: request.id }) : null;
      const base = loaded ?? emptyAnnotation(request.id, current);
      const input: RequestAnnotationInput = { requestId: request.id, bookmarked: !base.bookmarked, color: base.color, struckThrough: base.struckThrough, note: base.note, tags: base.tags };
      const saved = isTauri() ? await invoke<RequestAnnotation>("save_request_annotation", { input }) : { ...base, ...input, updatedAt: Date.now() };
      setAnnotationOverrides((currentOverrides) => ({ ...currentOverrides, [request.id]: annotationSummary(saved) }));
      setBookmarkCountDelta((delta) => delta + (saved.bookmarked ? 1 : -1));
    } catch (reason) {
      // A bookmark is how the user marks evidence; a silent no-op means they
      // believe it is marked when it is not.
      setActionError(t("traffic.bookmarkFailed", { error: String(reason) }));
    }
  };

  return (
    <section className="traffic-view">
      <div className="traffic-summary">
        <div className="summary-metric">
          <span className={`live-pulse ${capturing ? "is-live" : ""}`} />
          <div>
            <strong>{capturing ? t("traffic.capturing") : captureElsewhere ? t("traffic.browsingOther") : t("traffic.capturePaused")}</strong>
            <span>{liveDisplay.syncing ? t("traffic.syncingLive") : liveDisplay.paused ? t("traffic.uiPaused") : captureElsewhere ? t("traffic.writingOther", { name: captureSessionName ?? t("traffic.otherSession") }) : t("traffic.currentSession")}</span>
          </div>
        </div>
        <div className="summary-metric"><strong>{totalCount}</strong><span>{loading ? t("traffic.readingWindow") : t("traffic.allRequests")}</span></div>
        <div className="summary-metric"><strong>{apiCount}</strong><span>API</span></div>
        <div className={`summary-metric ${errorCount ? "has-error" : ""}`}><strong>{errorCount}</strong><span>{t("traffic.errors")}</span></div>
        <div className="summary-metric"><strong>{hookCount}</strong><span>{t("traffic.cryptoCalls")}</span></div>
        <button
          className="analyze-compact-button"
          onClick={onOpenAnalysis}
          disabled={requests.length === 0}
          title={requests.length === 0 ? t("traffic.analyzeNeedRequests") : t("traffic.analyzeSessionHint")}
        >
          <Sparkles size={15} />
          {t("traffic.analyzeSession")}
        </button>
      </div>

      <div className="traffic-toolbar" ref={toolbarRef}>
        <div className="search-field">
          <Search size={16} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("traffic.searchPlaceholder")} />
          {query && <button onClick={() => setQuery("")} title={t("traffic.clearSearch")}><X size={14} /></button>}
        </div>
        <div className="method-filter" aria-label={t("traffic.methods")}>
          {QUICK_FILTER_METHODS.map((item) => (
            <button key={item} className={quickFilter.methods.includes(item) ? "is-active" : ""} onClick={() => toggleQuickValue("methods", item)}>
              {item}
            </button>
          ))}
        </div>
        {/* One filter surface. Quick facets, the condition builder and saved
            views used to be three sibling popovers behind three toolbar
            buttons, each of which wrote into the same query. */}
        <div className="traffic-menu-anchor">
          <button
            className={`toolbar-command-button ${menu === "filter" ? "is-active" : ""} ${activeFilterChips.length ? "has-filters" : ""}`}
            onClick={() => setMenu(menu === "filter" ? undefined : "filter")}
            aria-expanded={menu === "filter"}
            title={t("traffic.filterTitle")}
          >
            <Filter size={15} /><span>{t("traffic.filter")}</span>
            {activeFilterChips.length > 0 && <em className="toolbar-filter-count">{activeFilterChips.length}</em>}
          </button>
          {menu === "filter" && (
            <div className="traffic-popover filter-panel">
              <div className="filter-panel__tabs" role="tablist" aria-label={t("traffic.filterMode")}>
                {([["quick", t("traffic.filterQuick")], ["advanced", t("traffic.filterAdvanced")], ["views", t("traffic.filterViews")]] as const).map(([id, label]) => (
                  <button
                    key={id}
                    role="tab"
                    aria-selected={filterTab === id}
                    className={filterTab === id ? "is-active" : ""}
                    onClick={() => setFilterTab(id)}
                  >
                    {label}
                    {id === "views" && savedViews.length > 0 && <em>{savedViews.length}</em>}
                    {id === "advanced" && advancedFilter && <em>·</em>}
                  </button>
                ))}
              </div>
              {filterTab === "quick" && <QuickFilterMenu state={quickFilter} facets={facets} onToggle={toggleQuickValue} />}
              {filterTab === "advanced" && (
                <FilterBuilder value={advancedFilter ?? { kind: "group", operator: "and", children: [createPredicate()] }} onChange={setAdvancedFilter} />
              )}
              {filterTab === "views" && (
                <div className="saved-views-pane">
                  <p className="saved-views-pane__hint">{t("traffic.viewsHint")}</p>
                  <div className="saved-view-create"><input value={savedViewName} onChange={(event) => setSavedViewName(event.target.value)} placeholder={t("traffic.viewName")} /><button onClick={() => void saveCurrentView()} disabled={!savedViewName.trim()} title={t("traffic.saveView")}><Plus size={14} /></button></div>
                  <div className="saved-view-list">
                    {savedViews.map((view) => <div key={view.id}><button onClick={() => applySavedView(view)}><span>{view.name}</span><small>{t("traffic.sortCount", { count: view.sort.length })}</small></button><button onClick={() => void deleteSavedView(view)} title={t("traffic.deleteView")}><Trash2 size={13} /></button></div>)}
                    {savedViews.length === 0 && <span className="popover-empty">{t("traffic.noViews")}</span>}
                  </div>
                </div>
              )}
              {/* Always present, so resetting is not a button that appears and
                  disappears from the toolbar depending on filter state. */}
              <footer className="filter-panel__footer">
                <span>{activeFilterChips.length ? t("traffic.filtersActive", { count: activeFilterChips.length }) : t("traffic.noFilters")}</span>
                <button onClick={clearFilters} disabled={!activeFilterChips.length}><RotateCcw size={13} />{t("traffic.resetAll")}</button>
              </footer>
            </div>
          )}
        </div>
        <button className={`toolbar-icon-button ${facetsOpen ? "is-active" : ""}`} onClick={() => setFacetsOpen((open) => !open)} title={facetsOpen ? t("traffic.hideFacets") : t("traffic.showFacets")}><ListFilter size={15} /></button>
        <div className="traffic-menu-anchor">
          <button className={`toolbar-icon-button ${menu === "columns" ? "is-active" : ""}`} onClick={() => setMenu(menu === "columns" ? undefined : "columns")} title={t("traffic.columns")}><Columns3 size={15} /></button>
          {menu === "columns" && (
            <div className="traffic-popover column-menu">
              <div className="popover-title"><strong>{t("traffic.showColumns")}</strong><button onClick={() => setPreferences(defaultRequestGridPreferences())}>{t("traffic.resetColumns")}</button></div>
              {requestColumnDefinitions.map((column) => <label key={column.id}><input type="checkbox" checked={preferences.visible.includes(column.id)} disabled={column.locked} onChange={() => setPreferences((current) => toggleRequestColumn(current, column.id))} /><span>{requestColumnLabel(column.id)}</span></label>)}
            </div>
          )}
        </div>
        <button className="toolbar-command-button" onClick={() => onOpenWorkbench("lab", selectedRequests, { createFromSelection: selectedRequests.length === 1 })}><FlaskConical size={15} /><span>Request Lab</span></button>
        <button className="toolbar-icon-button" onClick={() => onOpenWorkbench("collections", selectedRequests)} title={t("traffic.collections")}><FolderTree size={15} /></button>
        <button className="toolbar-icon-button" onClick={() => onOpenWorkbench("rules", selectedRequests)} title={t("traffic.rules")}><SlidersHorizontal size={15} /></button>
        <div className="traffic-menu-anchor live-display-anchor">
          <div className={`live-display-control ${liveDisplay.paused ? "is-paused" : ""}`}>
            <button className="live-display-control__main" onClick={onToggleLiveDisplay} disabled={liveDisplay.syncing} aria-pressed={liveDisplay.paused} title={liveDisplay.paused ? t("traffic.resumeLive") : t("traffic.pauseLive")}>
              {liveDisplay.syncing ? <LoaderCircle className="spin" size={14} /> : liveDisplay.paused ? <Play size={14} /> : <Pause size={14} />}
              <span>{liveDisplay.syncing ? t("traffic.syncing") : liveDisplay.paused ? t("traffic.pendingSync", { count: liveDisplay.pendingChanges.toLocaleString() }) : `${liveDisplay.ratePerSecond.toLocaleString()}/s`}</span>
            </button>
            <button className={`live-display-control__menu ${menu === "live" ? "is-active" : ""}`} onClick={() => setMenu(menu === "live" ? undefined : "live")} title={t("traffic.liveSettings")}><ChevronDown size={12} /></button>
          </div>
          {menu === "live" && <div className="traffic-popover live-display-popover">
            <header><div><strong>{t("traffic.focusCapture")}</strong><span>{liveDisplay.paused ? t("traffic.livePaused") : t("traffic.liveRefreshing")}</span></div><em>{liveDisplay.ratePerSecond.toLocaleString()} req/s</em></header>
            <label className="live-display-setting"><input type="checkbox" checked={liveDisplay.autoProtection} onChange={(event) => onLiveDisplayAutoProtectionChange(event.target.checked)} /><span><strong>{t("traffic.autoProtect")}</strong><small>{t("traffic.autoProtectHint", { rate: liveDisplay.rateThreshold.toLocaleString() })}</small></span></label>
            <div className="live-display-metrics"><span><small>{t("traffic.peak")}</small><strong>{liveDisplay.peakRatePerSecond.toLocaleString()}/s</strong></span><span><small>{t("traffic.newRequests")}</small><strong>{liveDisplay.pendingCreated.toLocaleString()}</strong></span><span><small>{t("traffic.statusUpdates")}</small><strong>{liveDisplay.pendingUpdated.toLocaleString()}</strong></span></div>
          </div>}
        </div>
        <span className="toolbar-result-count">{filteredCount.toLocaleString()} / {totalCount.toLocaleString()}</span>
      </div>

      {/* Without this, a list narrowed from the search box, the method chips and
          the facet sidebar at once looks exactly like an empty session. */}
      {actionError && (
        <div className="traffic-action-error" role="alert">
          <CircleAlert size={14} />
          <span>{actionError}</span>
          <button onClick={() => setActionError("")} title={t("common.close")}><X size={13} /></button>
        </div>
      )}

      {activeFilterChips.length > 0 && (
        <div className="active-filters" role="region" aria-label={t("traffic.activeFilters")}>
          {activeFilterChips.map((chip) => (
            <button
              key={chip.id}
              className="active-filter-chip"
              onClick={() => removeFilterChip(chip)}
              title={t("traffic.removeFilter", { group: chip.groupLabel, label: chip.label })}
            >
              <em>{chip.groupLabel}</em>
              <span>{chip.label}</span>
              <X size={12} />
            </button>
          ))}
          <button className="active-filters__clear" onClick={clearFilters}>{t("traffic.clearAll")}</button>
        </div>
      )}

      {totalCount === 0 && loading ? (
        <div className="traffic-empty traffic-empty--loading" role="status">
          <LoaderCircle className="spin" size={25} />
          <h2>{t("traffic.readingRequests")}</h2>
          <button className="secondary-button" data-testid="cancel-request-query" onClick={onCancelRequestQuery} disabled={cancelling}>{cancelling ? <LoaderCircle className="spin" size={13} /> : <X size={13} />}{cancelling ? t("traffic.stopping") : t("traffic.cancelQuery")}</button>
        </div>
      ) : totalCount === 0 ? (
        <div className="traffic-empty" data-testid="traffic-empty-oob">
          <div className="traffic-empty__icon"><CircleDot size={25} /></div>
          <h2>{t("traffic.waitFirst")}</h2>
          <p className="traffic-empty__hint">
            <strong>{t("traffic.emptyHintLead")}</strong>{t("traffic.emptyHint")}
          </p>
          <ol className="traffic-empty__steps">
            <li>{t("traffic.emptyStep1")}</li>
            <li>{t("traffic.emptyStep2")}</li>
            <li>{t("traffic.emptyStep3")}</li>
          </ol>
          <div className="empty-actions">
            {onOpenBrowser ? (
              <button type="button" className="primary-button" onClick={onOpenBrowser} data-testid="empty-open-browser">
                <Browser size={14} /> {t("traffic.emptyOpenBrowser")}
              </button>
            ) : null}
            <button type="button" className="secondary-button" onClick={onConnect}>{t("traffic.emptyConnect")}</button>
            {onOpenSettingsCapture ? (
              <button type="button" className="secondary-button" onClick={onOpenSettingsCapture}>{t("traffic.emptyCa")}</button>
            ) : null}
            <button type="button" className="secondary-button" onClick={onOpenAnalysis} disabled title={t("traffic.analyzeNeedRequests")}>
              {t("nav.analysis")}
            </button>
          </div>
        </div>
      ) : (
        <div className={`traffic-data-area ${facetsOpen ? "has-facets" : ""}`}>
          {facetsOpen && <FacetSidebar facets={facets} state={quickFilter} savedViews={savedViews} bookmarkCount={Math.max(0, bookmarkedCount + bookmarkCountDelta)} onToggle={toggleQuickValue} onApplyView={applySavedView} onClose={() => setFacetsOpen(false)} />}
          <div className={`traffic-split ${detailOpen && selected ? `has-detail layout-${inspectorPreferences.layout}` : ""}`} style={splitStyle}>
          <div className="request-grid-shell">
            <div
              className="request-grid-scroll"
              ref={scrollRef}
              tabIndex={0}
              onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
              onKeyDown={handleGridKeyDown}
              role="grid"
              aria-label={t("traffic.grid")}
              aria-rowcount={filteredCount + 1}
              aria-colcount={columns.length}
            >
              <div className="request-grid-header" style={{ gridTemplateColumns: gridTemplate, width: gridWidth }} role="row" aria-rowindex={1}>
                {columns.map((column, columnIndex) => {
                  const sortIndex = sort.findIndex((entry) => entry.field === column.field);
                  const sorting = sortIndex >= 0 ? sort[sortIndex] : undefined;
                  const ariaSort = sorting ? (sorting.direction === "asc" ? "ascending" : "descending") : "none";
                  return <div key={column.id} className="request-grid-header-cell" role="columnheader" aria-colindex={columnIndex + 1} aria-sort={ariaSort} onContextMenu={(event) => { event.preventDefault(); event.stopPropagation(); setMenu("columns"); }} onDragOver={(event) => event.preventDefault()} onDrop={(event) => setPreferences((current) => reorderRequestColumn(current, event.dataTransfer.getData("text/request-column") as RequestColumnId, column.id))}>
                    {!column.locked && <span className="column-drag-handle" draggable onDragStart={(event) => { event.stopPropagation(); event.dataTransfer.effectAllowed = "move"; event.dataTransfer.setData("text/request-column", column.id); }} title={t("traffic.dragColumn", { label: requestColumnLabel(column.id) })}><GripVertical size={12} /></span>}
                    <button type="button" className="request-grid-sort-button" data-sort-field={column.field} onClick={(event) => setSort((current) => nextRequestSort(current, column.field, event.shiftKey))} title={t("traffic.sortTitle", { label: requestColumnLabel(column.id), hint: sorting ? (sorting.direction === "asc" ? t("traffic.sortDesc") : t("traffic.sortOff")) : t("traffic.sortAsc") })}>
                      <span>{requestColumnLabel(column.id)}</span>
                      {sorting && <span className="sort-indicator">{sorting.direction === "asc" ? <ArrowUp size={11} /> : <ArrowDown size={11} />}{sort.length > 1 && <small>{sortIndex + 1}</small>}</span>}
                    </button>
                    <span className="column-resize-handle" onPointerDown={(event) => { event.stopPropagation(); setResizing({ id: column.id, startX: event.clientX, startWidth: preferences.widths[column.id] ?? column.width }); }} onDoubleClick={(event) => { event.stopPropagation(); setPreferences((current) => resizeRequestColumn(current, column.id, estimateRequestColumnWidth(column.id, requests))); }} />
                  </div>;
                })}
              </div>
              <div className="request-grid-body" style={{ height: virtualWindow.totalHeight, width: gridWidth }} role="rowgroup">
                {visibleRows.map(({ request, absoluteIndex }) => {
                  if (!request) return <div key={`loading-${absoluteIndex}`} className="request-grid-row is-loading" style={{ gridTemplateColumns: gridTemplate, width: gridWidth, transform: `translateY(${absoluteIndex * REQUEST_GRID_ROW_HEIGHT}px)` } as CSSProperties} role="row" aria-rowindex={absoluteIndex + 2} aria-busy="true">
                    {columns.map((column) => <div key={column.id} className={`request-grid-cell request-grid-cell--${column.id}`} role="gridcell"><span className="request-grid-loading-bar" /></div>)}
                  </div>;
                  const annotation = annotationOverrides[request.id] ?? request.annotation;
                  const displayedRequest = annotation === request.annotation ? request : { ...request, annotation };
                  const isSelected = selectedSet.has(request.id);
                  const isFocused = selection.focusedId === request.id;
                  return <div key={request.id} data-request-id={request.id} className={`request-grid-row ${isSelected ? "is-selected" : ""} ${isFocused ? "is-focused" : ""} ${request.risk === "critical" ? "has-risk" : ""} ${annotation?.color ? `annotation-${annotation.color}` : ""} ${annotation?.struckThrough ? "is-struck" : ""}`} style={{ gridTemplateColumns: gridTemplate, width: gridWidth, transform: `translateY(${absoluteIndex * REQUEST_GRID_ROW_HEIGHT}px)` } as CSSProperties} role="row" aria-rowindex={absoluteIndex + 2} aria-selected={isSelected} onContextMenu={(event) => {
                    event.preventDefault();
                    if (!selectedSet.has(request.id)) { dispatchSelection({ type: "click", id: request.id, ids: requests.map((item) => item.id) }); setSelectionFromUser(true); }
                    setContextMenu({ x: Math.min(event.clientX, window.innerWidth - 230), y: Math.min(event.clientY, window.innerHeight - 280) });
                  }} onClick={(event) => {
                    dispatchSelection({ type: "click", id: request.id, ids: requests.map((item) => item.id), toggle: event.metaKey || event.ctrlKey, range: event.shiftKey });
                    setSelectionFromUser(true);
                    if (!event.metaKey && !event.ctrlKey) setDetailOpen(true);
                  }}>
                    {columns.map((column) => <div key={column.id} className={`request-grid-cell request-grid-cell--${column.id}`} role="gridcell" title={requestCellTitle(displayedRequest, column.id)}>{renderRequestCell(displayedRequest, column.id)}</div>)}
                  </div>;
                })}
              </div>
            </div>
            {liveDisplay.paused && <div className={`live-display-banner ${liveDisplay.pauseReason === "automatic" ? "is-automatic" : ""}`} role="status">
              <span className="live-display-banner__icon">{liveDisplay.syncing ? <LoaderCircle className="spin" size={15} /> : <Pause size={15} />}</span>
              <span className="live-display-banner__body"><strong>{liveDisplay.syncing ? t("traffic.syncingBanner") : liveDisplay.pauseReason === "automatic" ? t("traffic.autoProtectOn") : t("traffic.uiRefreshPaused")}</strong><small>{liveDisplay.pendingChanges > 0 ? t("traffic.pendingBanner", { created: liveDisplay.pendingCreated.toLocaleString(), updated: liveDisplay.pendingUpdated.toLocaleString() }) : t("traffic.captureOk")}</small></span>
              <button onClick={onToggleLiveDisplay} disabled={liveDisplay.syncing}>{liveDisplay.syncing ? <LoaderCircle className="spin" size={13} /> : <Play size={13} />}<span>{liveDisplay.syncing ? t("traffic.syncing") : t("traffic.syncList")}</span></button>
            </div>}
            {requests.length === 0 && filteredCount === 0 && (
              <div className="filter-empty"><ListFilter size={20} /><span>{t("traffic.noMatch")}</span><button onClick={clearFilters}>{t("traffic.resetFilters")}</button></div>
            )}
            <div className={`request-grid-statusbar ${selection.selectedIds.length ? "has-selection" : ""}`}>
              <span>{t("traffic.total", { count: totalCount.toLocaleString() })}</span>
              <span>{t("traffic.filtered", { count: filteredCount.toLocaleString() })}</span>
              <strong className="request-selection-count">{t("traffic.selectedCount", { count: selection.selectedIds.length.toLocaleString() })}{selectedCurrentWindow && <><span className="selection-window-label"> · {t("traffic.currentWindow")}</span><span className="selection-window-compact">/{requests.length.toLocaleString()}</span></>}</strong>
              {loading ? <span className="request-query-progress" role="status"><LoaderCircle className="spin" size={11} /><span>{cancelling ? t("traffic.stopping") : t("traffic.loadingMore")}</span><button data-testid="cancel-request-query" onClick={onCancelRequestQuery} disabled={cancelling} title={cancelling ? t("traffic.waitStop") : t("traffic.cancelQuery")} aria-label={cancelling ? t("traffic.waitStop") : t("traffic.cancelQuery")}>{cancelling ? <LoaderCircle className="spin" size={11} /> : <X size={11} />}</button></span> : <span>{requests.length ? `${(requestWindowOffset + 1).toLocaleString()}–${(requestWindowOffset + requests.length).toLocaleString()}` : t("traffic.zeroRows")}</span>}
            </div>
            {/* Contextual bar over the grid. The same actions used to be eight
                unlabelled icons wedged into the status bar, where a first-time
                user had to hover each one to find out what it did. */}
            {selectionFromUser && selection.selectedIds.length > 0 && (
              <div className="selection-bar" role="toolbar" aria-label={t("traffic.selectionActions")}>
                <span className="selection-bar__count"><strong>{t("traffic.selectedN", { count: selection.selectedIds.length.toLocaleString() })}</strong></span>
                <span className="selection-bar__divider" aria-hidden="true" />
                {/* The summary strip's button analyses the whole session; this
                    one is scoped to the selection. Both used to read "AI 分析". */}
                <button className="selection-bar__action is-primary" onClick={() => onAnalyzeSelection(selection.selectedIds)} title={t("traffic.analyzeSelectedHint", { count: selection.selectedIds.length })}>
                  <Sparkles size={14} />{t("traffic.analyzeSelected")}
                </button>
                <button className="selection-bar__action" onClick={() => onOpenWorkbench("replay", selectedRequests)} title={t("traffic.replayHint")}>
                  <ListRestart size={14} />{t("traffic.replay")}
                </button>
                <button
                  className="selection-bar__action"
                  onClick={() => onOpenWorkbench("lab", selectedRequests, { createFromSelection: true })}
                  disabled={selection.selectedIds.length !== 1}
                  title={selection.selectedIds.length === 1 ? t("traffic.rewriteHint") : t("traffic.rewriteNeedOne")}
                >
                  <FlaskConical size={14} />{t("traffic.rewrite")}
                </button>
                <button
                  className="selection-bar__action"
                  onClick={() => onOpenWorkbench("diff", selectedRequests)}
                  disabled={selection.selectedIds.length !== 2}
                  title={selection.selectedIds.length === 2 ? t("traffic.diffHint") : t("traffic.diffNeedTwo")}
                >
                  <GitCompareArrows size={14} />{t("traffic.diff")}
                </button>
                <div className="selection-bar__more" ref={selectionMoreRef}>
                  <button className="selection-bar__action" onClick={() => setSelectionMoreOpen((open) => !open)} aria-expanded={selectionMoreOpen} title={t("traffic.moreActions")}>
                    <MoreHorizontal size={14} />{t("traffic.more")}
                  </button>
                  {selectionMoreOpen && (
                    <div className="selection-more-menu" role="menu" aria-label={t("traffic.moreSelected")}>
                      <button role="menuitem" onClick={() => { void copySelectedUrls(); setSelectionMoreOpen(false); }}><Copy size={14} />{t("traffic.copyUrl")}</button>
                      <button role="menuitem" onClick={() => { onOpenWorkbench("collections", selectedRequests); setSelectionMoreOpen(false); }} disabled={selection.selectedIds.length !== 1}><FolderTree size={14} />{t("traffic.archive")}</button>
                      <button role="menuitem" onClick={() => { void toggleSelectedBookmark(); setSelectionMoreOpen(false); }} disabled={selection.selectedIds.length !== 1}><Bookmark size={14} />{selectedRequests[0] && (annotationOverrides[selectedRequests[0].id] ?? selectedRequests[0].annotation)?.bookmarked ? t("traffic.unbookmark") : t("traffic.bookmark")}</button>
                      <button role="menuitem" onClick={() => { exportSelectedSummary(); setSelectionMoreOpen(false); }}><Download size={14} />{t("traffic.exportEvidence")}</button>
                    </div>
                  )}
                </div>
                <button className="selection-bar__clear" onClick={() => { dispatchSelection({ type: "clear" }); setSelectionFromUser(false); }} title={t("traffic.clearSelection")} aria-label={t("traffic.clearSelection")}><X size={14} /></button>
              </div>
            )}
          </div>

          {detailOpen && selected && inspectorPreferences.layout !== "maximized" && <div className={`inspector-resize-handle is-${inspectorPreferences.layout}`} onPointerDown={(event) => setInspectorResizing({ startX: event.clientX, startY: event.clientY, startSize: inspectorPreferences.layout === "right" ? inspectorPreferences.rightWidth : inspectorPreferences.bottomHeight })} />}
          {detailOpen && selected && <RequestDetailLoader item={{ ...selected, annotation: annotationOverrides[selected.id] ?? selected.annotation }} layout={inspectorPreferences.layout} onAnnotationSaved={(annotation) => setAnnotationOverrides((current) => ({ ...current, [annotation.requestId]: annotationSummary(annotation) }))} onAnalyze={() => onAnalyzeSelection([selected.id])} onLayoutChange={setInspectorLayout} onClose={() => setDetailOpen(false)} />}
          </div>
        </div>
      )}
      {contextMenu && <div ref={contextMenuRef} className="request-context-menu" style={{ left: contextMenu.x, top: contextMenu.y }} role="menu" aria-label={t("traffic.requestActions")}>
        <span>{t("traffic.nRequests", { count: selectedRequests.length })}</span>
        <button role="menuitem" onClick={() => { void copySelectedUrls(); setContextMenu(undefined); }}><Copy size={14} />{t("traffic.copyUrl")}</button>
        <button role="menuitem" onClick={() => { setDetailOpen(true); setContextMenu(undefined); }}><PanelRight size={14} />{t("traffic.openDetail")}</button>
        <button role="menuitem" onClick={() => { setInspectorLayout("maximized"); setContextMenu(undefined); }} disabled={selectedRequests.length !== 1}><Maximize2 size={14} />{t("traffic.maxDetail")}</button>
        <button role="menuitem" onClick={() => { onAnalyzeSelection(selection.selectedIds); setContextMenu(undefined); }}><Sparkles size={14} />{t("traffic.analyzeSelectedN", { count: selectedRequests.length })}</button>
        <button role="menuitem" onClick={() => { onOpenWorkbench("replay", selectedRequests); setContextMenu(undefined); }}><ListRestart size={14} />{t("traffic.replaySelected")}</button>
        <button role="menuitem" onClick={() => { onOpenWorkbench("diff", selectedRequests); setContextMenu(undefined); }} disabled={selectedRequests.length !== 2}><GitCompareArrows size={14} />{t("traffic.diffTwo")}</button>
        <button role="menuitem" onClick={() => { onOpenWorkbench("lab", selectedRequests, { createFromSelection: true }); setContextMenu(undefined); }} disabled={selectedRequests.length !== 1}><FlaskConical size={14} />{t("traffic.toLab")}</button>
        <button role="menuitem" onClick={() => { onOpenWorkbench("collections", selectedRequests); setContextMenu(undefined); }} disabled={selectedRequests.length !== 1}><FolderTree size={14} />{t("traffic.archive")}</button>
        <button role="menuitem" onClick={() => { void toggleSelectedBookmark(); setContextMenu(undefined); }} disabled={selectedRequests.length !== 1}><Bookmark size={14} />{selectedRequests[0] && (annotationOverrides[selectedRequests[0].id] ?? selectedRequests[0].annotation)?.bookmarked ? t("traffic.unbookmark") : t("traffic.bookmark")}</button>
        <button role="menuitem" onClick={() => { exportSelectedSummary(); setContextMenu(undefined); }}><Download size={14} />{t("traffic.exportEvidence")}</button>
      </div>}
    </section>
  );
}

function QuickFilterMenu({ state, facets, onToggle }: { state: QuickFilterState; facets: RequestFacets; onToggle: <K extends "hosts" | "methods" | "protocols" | "types" | "statuses" | "exactStatuses" | "sources" | "risks" | "shownet">(key: K, value: QuickFilterState[K][number]) => void }) {
  return <div className="traffic-popover quick-filter-popover">
    <FilterOptions title={t("traffic.method")} values={METHOD_VALUES} selected={state.methods} count={(value) => facetCount(facets.methods, value)} onToggle={(value) => onToggle("methods", value)} />
    <FilterOptions title={t("traffic.protocol")} values={PROTOCOL_VALUES} labels={PROTOCOL_LABELS} selected={state.protocols} count={(value) => facetCount(facets.protocols, value)} onToggle={(value) => onToggle("protocols", value)} />
    <FilterOptions title={t("traffic.type")} values={TYPE_VALUES} labels={TYPE_LABELS} selected={state.types} count={(value) => value === "api" ? sumFacet(facets.types, ["fetch", "xhr"]) : facetCount(facets.types, value)} onToggle={(value) => onToggle("types", value)} />
    <FilterOptions<QuickStatus> title={t("traffic.status")} values={STATUS_VALUES} labels={STATUS_LABELS} selected={state.statuses} count={() => undefined} onToggle={(value) => onToggle("statuses", value)} />
    <FilterOptions<SourceType> title={t("traffic.source")} values={["browser", "desktop", "terminal", "script", "mobile", "iot", "reverse"]} labels={sourceLabels} selected={state.sources} count={(value) => facetCount(facets.sources, value)} onToggle={(value) => onToggle("sources", value)} />
    <FilterOptions<QuickShownet> title={t("traffic.mark")} values={SHOWNET_VALUES} labels={SHOWNET_LABELS} selected={state.shownet} count={() => undefined} onToggle={(value) => onToggle("shownet", value)} />
  </div>;
}

function FacetSidebar({ facets, state, savedViews, bookmarkCount, onToggle, onApplyView, onClose }: { facets: RequestFacets; state: QuickFilterState; savedViews: SavedRequestView[]; bookmarkCount: number; onToggle: <K extends "hosts" | "methods" | "protocols" | "types" | "statuses" | "exactStatuses" | "sources" | "risks" | "shownet">(key: K, value: QuickFilterState[K][number]) => void; onApplyView: (view: SavedRequestView) => void; onClose: () => void }) {
  return <aside className="facet-sidebar" aria-label={t("traffic.facets")}>
    <header><div><strong>{t("traffic.facets")}</strong><span>{t("traffic.facetsHint")}</span></div><button onClick={onClose} title={t("traffic.hideFacets")}><X size={14} /></button></header>
    <FacetSection title={t("traffic.host")} facets={facets.hosts} selected={state.hosts} onToggle={(value) => onToggle("hosts", value)} limit={10} />
    <FacetSection title={t("traffic.source")} facets={facets.sources} selected={state.sources} labels={sourceLabels} onToggle={(value) => onToggle("sources", value as SourceType)} />
    <FacetSection title={t("traffic.protocol")} facets={facets.protocols} selected={state.protocols} labels={PROTOCOL_LABELS} onToggle={(value) => onToggle("protocols", value)} />
    <FacetSection title={t("traffic.type")} facets={facets.types} selected={state.types} labels={TYPE_LABELS} onToggle={(value) => onToggle("types", value)} />
    <FacetSection title={t("traffic.status")} facets={facets.statuses} selected={state.exactStatuses} onToggle={(value) => onToggle("exactStatuses", value)} />
    <FacetSection title={t("traffic.risk")} facets={facets.risks} selected={state.risks} labels={RISK_LABELS} onToggle={(value) => onToggle("risks", value as RiskLevel)} />
    <section className="facet-section facet-organization"><div className="facet-section__title"><strong>{t("traffic.org")}</strong><span>{savedViews.length + bookmarkCount}</span></div><div className="facet-bookmark-summary"><Bookmark size={12} /><span>{t("traffic.loadedBookmarks")}</span><small>{bookmarkCount}</small></div>{savedViews.slice(0, 5).map((view) => <button key={view.id} onClick={() => onApplyView(view)}><Save size={12} /><span>{view.name}</span></button>)}</section>
  </aside>;
}

function FacetSection({ title, facets, selected, labels, onToggle, limit = 8 }: { title: string; facets: Array<{ value: string; count: number }>; selected: readonly string[]; labels?: Record<string, string>; onToggle: (value: string) => void; limit?: number }) {
  return <section className="facet-section"><div className="facet-section__title"><strong>{title}</strong><span>{facets.length}</span></div><div>{facets.slice(0, limit).map((facet) => <button key={facet.value} className={selected.includes(facet.value) ? "is-active" : ""} onClick={() => onToggle(facet.value)} title={facet.value}><span>{selected.includes(facet.value) && <Check size={10} />}{labels?.[facet.value] ?? facet.value}</span><small>{facet.count.toLocaleString()}</small></button>)}</div>{facets.length === 0 && <small className="facet-empty">{t("traffic.noData")}</small>}</section>;
}

function FilterOptions<T extends string>({ title, values, labels, selected, count, onToggle }: { title: string; values: readonly T[]; labels?: Partial<Record<T, string>>; selected: T[]; count: (value: T) => number | undefined; onToggle: (value: T) => void }) {
  return <section className="quick-filter-group"><strong>{title}</strong><div>{values.map((value) => <button key={value} className={selected.includes(value) ? "is-active" : ""} onClick={() => onToggle(value)}><span>{selected.includes(value) && <Check size={11} />}{labels?.[value] ?? value}</span>{count(value) != null && <small>{count(value)}</small>}</button>)}</div></section>;
}

function FilterBuilder({ value, onChange }: { value: FilterExpression; onChange: (value: FilterExpression | undefined) => void }) {
  return <div className="filter-builder">
    <div className="popover-title"><strong>{t("traffic.builder")}</strong><button onClick={() => onChange(undefined)}>{t("traffic.clear")}</button></div>
    <FilterBuilderNode value={value} depth={0} onChange={onChange} />
  </div>;
}

function FilterBuilderNode({ value, depth, onChange, onRemove }: { value: FilterExpression; depth: number; onChange: (value: FilterExpression) => void; onRemove?: () => void }) {
  if (value.kind === "predicate") {
    return <div className="filter-predicate-row">
      <select value={value.field} onChange={(event) => onChange({ ...value, field: event.target.value as RequestField })}>{filterFields().map(([field, label]) => <option key={field} value={field}>{label}</option>)}</select>
      <select value={value.operator} onChange={(event) => onChange({ ...value, operator: event.target.value as typeof value.operator })}>{filterOperators().map(([operator, label]) => <option key={operator} value={operator}>{label}</option>)}</select>
      {value.operator !== "exists" && <input value={String(value.value ?? "")} onChange={(event) => onChange({ ...value, value: numericFilterFields.has(value.field) && event.target.value !== "" ? Number(event.target.value) : event.target.value })} placeholder={t("traffic.value")} />}
      {onRemove && <button onClick={onRemove} title={t("traffic.deletePredicate")}><X size={13} /></button>}
    </div>;
  }
  return <div className={`filter-group-node depth-${depth}`}>
    <div className="filter-group-head"><select value={value.operator} onChange={(event) => onChange({ ...value, operator: event.target.value as "and" | "or" })}><option value="and">{t("traffic.allAnd")}</option><option value="or">{t("traffic.anyOr")}</option></select>{onRemove && <button onClick={onRemove}><Trash2 size={13} /></button>}</div>
    {value.children.map((child, index) => <FilterBuilderNode key={index} value={child} depth={depth + 1} onChange={(next) => onChange({ ...value, children: value.children.map((candidate, candidateIndex) => candidateIndex === index ? next : candidate) })} onRemove={() => onChange({ ...value, children: value.children.filter((_, candidateIndex) => candidateIndex !== index) })} />)}
    <div className="filter-builder-actions"><button onClick={() => onChange({ ...value, children: [...value.children, createPredicate()] })}><Plus size={12} />{t("traffic.predicate")}</button>{depth < 1 && <button onClick={() => onChange({ ...value, children: [...value.children, { kind: "group", operator: "or", children: [createPredicate(), createPredicate()] }] })}><Plus size={12} />{t("traffic.predicateGroup")}</button>}</div>
  </div>;
}

function filterFields(): Array<[RequestField, string]> {
  return [
    ["all", t("traffic.field.all")],
    ["url", t("traffic.field.url")],
    ["host", t("traffic.field.host")],
    ["path", t("traffic.field.path")],
    ["method", t("traffic.field.method")],
    ["status", t("traffic.field.status")],
    ["type", t("traffic.field.type")],
    ["source", t("traffic.field.source")],
    ["protocol", t("traffic.field.protocol")],
    ["durationMs", t("traffic.field.durationMs")],
    ["sizeBytes", t("traffic.field.sizeBytes")],
    ["risk", t("traffic.field.risk")],
    ["requestHeader", t("traffic.field.requestHeader")],
    ["responseHeader", t("traffic.field.responseHeader")],
    ["requestBody", t("traffic.field.requestBody")],
    ["responseBody", t("traffic.field.responseBody")],
    ["hook", t("traffic.field.hook")],
  ];
}
type PredicateOperator = Extract<FilterExpression, { kind: "predicate" }>["operator"];
function filterOperators(): Array<[PredicateOperator, string]> {
  return [
    ["contains", t("traffic.op.contains")],
    ["not_contains", t("traffic.op.not_contains")],
    ["equals", t("traffic.op.equals")],
    ["not_equals", t("traffic.op.not_equals")],
    ["starts_with", t("traffic.op.starts_with")],
    ["ends_with", t("traffic.op.ends_with")],
    ["wildcard", t("traffic.op.wildcard")],
    ["regex", t("traffic.op.regex")],
    ["gt", t("traffic.op.gt")],
    ["gte", t("traffic.op.gte")],
    ["lt", t("traffic.op.lt")],
    ["lte", t("traffic.op.lte")],
    ["exists", t("traffic.op.exists")],
  ];
}
const numericFilterFields = new Set<RequestField>(["order", "startedAt", "status", "sizeBytes", "durationMs", "cryptoSnippetCount"]);

function renderRequestCell(request: RequestListItem, column: RequestColumnId) {
  if (column === "order") return <><span className={`selection-mark ${request.state}`} />{request.annotation?.bookmarked && <Bookmark className="row-bookmark" size={11} fill="currentColor" />}<span className={`risk-mark risk-${request.risk}`} />{request.order}</>;
  if (column === "state") return <span className={`request-state request-state--${request.state}`}>{request.state === "tunnel" && <LockKeyhole size={10} />}{requestStateLabel(request.state)}</span>;
  if (column === "method") return <span className={`method method-${request.method.toLowerCase()}`}>{request.method}</span>;
  if (column === "url") return <span className="grid-url"><strong>{request.host}</strong><span>{request.path}{request.query ? `?${request.query}` : ""}</span>{request.hasHook && <Braces size={11} />}</span>;
  if (column === "status") {
    const presentation = classifyTrafficStatus(request.status, {
      // List rows lack body; 502 still labeled as proxy so users open detail for the full string.
      responseBody: request.status === 502 || request.status === 504 ? null : undefined,
    });
    if (request.status == null && request.state === "pending") {
      return <span className="status-code status-0">…</span>;
    }
    if (request.status == null) {
      return <span className="status-code status-0">{t("traffic.failed")}</span>;
    }
    return (
      <span className={`status-code status-${presentation.cssClass}`} title={presentation.title}>
        {presentation.label}
      </span>
    );
  }
  if (column === "source") { const SourceIcon = sourceIcons[request.source]; return <span className="source-cell"><SourceIcon size={13} />{sourceLabels[request.source]}</span>; }
  if (column === "sizeBytes") return formatListBytes(request.sizeBytes);
  if (column === "durationMs") return <span className={isSlowRequest(request.durationMs) ? "is-slow" : ""}>{request.durationMs == null ? "--" : `${request.durationMs} ms`}</span>;
  if (column === "startedAt") return new Date(request.startedAt).toLocaleTimeString(undefined, { hour12: false });
  if (column === "risk") return request.risk === "none" ? "--" : request.risk;
  if (column === "hasHook") return request.hasHook ? <Braces size={13} /> : "--";
  if (column === "cryptoSnippetCount") return request.cryptoSnippetCount || "--";
  if (column === "tlsIntercepted") return request.tlsIntercepted ? request.tlsVersion ?? "TLS" : t("traffic.notDecrypted");
  return String(request[column] ?? "--");
}

function requestCellTitle(request: RequestListItem, column: RequestColumnId) {
  if (column === "url") return `${request.scheme}://${request.host}${request.path}${request.query ? `?${request.query}` : ""}`;
  return String(request[column] ?? "");
}

function requestUrl(request: RequestListItem) {
  return `${request.scheme}://${request.host}${request.path}${request.query ? `?${request.query}` : ""}`;
}

function hasQuickFilters(state: QuickFilterState) {
  return Boolean(state.text || state.hosts.length || state.methods.length || state.protocols.length || state.types.length || state.statuses.length || state.exactStatuses.length || state.sources.length || state.risks.length || state.shownet.length);
}

function facetCount(facets: Array<{ value: string; count: number }>, value: string) {
  return facets.find((facet) => facet.value === value)?.count ?? 0;
}

function sumFacet(facets: Array<{ value: string; count: number }>, values: string[]) {
  return values.reduce((total, value) => total + facetCount(facets, value), 0);
}

function RequestDetailLoader({ item, layout, onAnnotationSaved, onAnalyze, onLayoutChange, onClose }: { item: RequestListItem; layout: InspectorLayout; onAnnotationSaved: (annotation: RequestAnnotation) => void; onAnalyze: () => void; onLayoutChange: (layout: InspectorLayout) => void; onClose: () => void }) {
  const [request, setRequest] = useState<RequestRecord | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let disposed = false;
    setRequest(null);
    setError("");
    const loaded = isTauri()
      ? invoke<RequestRecord>("get_request_detail", { requestId: item.id })
      : Promise.resolve(previewRequestDetail(item));
    loaded
      .then((detail) => {
        if (disposed) return;
        if (!detail) throw new Error(t("traffic.detailMissing"));
        setRequest(detail);
      })
      .catch((loadError) => { if (!disposed) setError(String(loadError)); });
    return () => { disposed = true; };
  }, [item.id]);

  if (request) return <RequestDetail request={request} annotationSummary={item.annotation} layout={layout} onAnnotationSaved={onAnnotationSaved} onAnalyze={onAnalyze} onLayoutChange={onLayoutChange} onClose={onClose} />;
  return (
    <aside className="request-detail request-detail--loading">
      <div className="request-detail__head">
        <div className="request-detail__title"><span className={`method method-${item.method.toLowerCase()}`}>{item.method}</span><div><h2>{item.path}</h2><span>{item.host}</span></div></div>
        <button className="icon-button" onClick={onClose} title={t("traffic.closeDetail")}><X size={16} /></button>
      </div>
      <div className="detail-empty">{error ? <><CircleAlert size={20} /><span>{error}</span></> : <><Clock3 size={20} /><span>{t("traffic.readingDetail")}</span></>}</div>
    </aside>
  );
}

function previewRequestDetail(item: RequestListItem) {
  const exact = initialRequests.find((candidate) => candidate.id === item.id);
  if (exact) return exact;
  const seed = initialRequests[(Math.max(1, item.order) - 1) % initialRequests.length];
  if (!seed) return undefined;
  return {
    ...seed,
    id: item.id,
    order: item.order,
    method: item.method as RequestRecord["method"],
    host: item.host,
    path: item.path,
    query: item.query,
    status: item.status ?? seed.status,
    type: item.type as RequestRecord["type"],
    source: item.source,
    protocol: item.protocol as RequestRecord["protocol"],
    size: formatListBytes(item.sizeBytes),
    duration: item.durationMs ?? seed.duration,
    risk: item.risk,
    cryptoSnippetCount: item.cryptoSnippetCount,
    tls: item.tlsVersion ?? (item.tlsIntercepted ? "TLS" : "明文"),
  } satisfies RequestRecord;
}

function RequestDetail({ request, annotationSummary, layout, onAnnotationSaved, onAnalyze, onLayoutChange, onClose }: { request: RequestRecord; annotationSummary?: RequestAnnotationSummary; layout: InspectorLayout; onAnnotationSaved: (annotation: RequestAnnotation) => void; onAnalyze: () => void; onLayoutChange: (layout: InspectorLayout) => void; onClose: () => void }) {
  const [tab, setTab] = useState<DetailTab>("overview");
  const [copied, setCopied] = useState(false);
  const [codeOpen, setCodeOpen] = useState(false);
  const [cryptoSnippets, setCryptoSnippets] = useState<CryptoCodeSnippet[]>([]);
  const [cryptoLoading, setCryptoLoading] = useState(false);
  const [cryptoError, setCryptoError] = useState("");
  const [websocketFrames, setWebsocketFrames] = useState<WebSocketFrameEvent[]>([]);
  const [websocketLoading, setWebsocketLoading] = useState(false);
  const [websocketError, setWebsocketError] = useState("");
  const [sseEvents, setSseEvents] = useState<SseEvent[]>([]);
  const [sseLoading, setSseLoading] = useState(false);
  const [sseError, setSseError] = useState("");
  const [ruleTraces, setRuleTraces] = useState<CaptureRuleRun[]>([]);
  const [ruleTraceLoading, setRuleTraceLoading] = useState(false);

  useEffect(() => {
    setTab((current) => isDetailTabAvailable(current, request) ? current : "overview");
  }, [request.id]);

  useEffect(() => {
    let disposed = false;
    setCryptoSnippets([]);
    setCryptoError("");
    if (tab !== "code" || request.cryptoSnippetCount <= 0) return () => { disposed = true; };
    setCryptoLoading(true);
    const loaded = isTauri()
      ? invoke<CryptoCodeSnippet[]>("get_crypto_code_snippets", { requestId: request.id })
      : Promise.resolve(previewCryptoSnippets(request));
    loaded
      .then((snippets) => { if (!disposed) setCryptoSnippets(snippets); })
      .catch((error) => { if (!disposed) setCryptoError(String(error)); })
      .finally(() => { if (!disposed) setCryptoLoading(false); });
    return () => { disposed = true; };
  }, [request, tab]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    setWebsocketFrames([]);
    setWebsocketError("");
    if (tab !== "messages" || request.type !== "websocket") return () => { disposed = true; };
    setWebsocketLoading(true);
    const loaded = isTauri() ? (async () => {
      unlisten = await listen<WebSocketFrameEvent>("capture://event", (event) => {
        const frame = event.payload;
        if (frame.phase !== "websocket" || frame.requestId !== request.id || disposed) return;
        setWebsocketFrames((current) => mergeWebSocketFrames(current, [frame]));
      });
      if (disposed) {
        unlisten();
        unlisten = undefined;
        return [];
      }
      return invoke<WebSocketFrameEvent[]>("list_websocket_frames", { requestId: request.id, limit: 2_000 });
    })() : Promise.resolve(previewWebSocketFrames(request));
    loaded
      .then((frames) => { if (!disposed) setWebsocketFrames((current) => mergeWebSocketFrames(frames, current)); })
      .catch((error) => { if (!disposed) setWebsocketError(String(error)); })
      .finally(() => { if (!disposed) setWebsocketLoading(false); });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [request.id, request.type, tab]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    setSseEvents([]);
    setSseError("");
    if (tab !== "sse" || request.type !== "sse") return () => { disposed = true; };
    setSseLoading(true);
    const loaded = isTauri() ? (async () => {
      unlisten = await listen<SseEvent>("capture://event", (event) => {
        const item = event.payload;
        if (item.phase !== "sse" || item.requestId !== request.id || disposed) return;
        setSseEvents((current) => mergeSseEvents(current, [item]));
      });
      if (disposed) {
        unlisten();
        unlisten = undefined;
        return [];
      }
      return invoke<SseEvent[]>("list_sse_events", { requestId: request.id, limit: 2_000 });
    })() : Promise.resolve(previewSseEvents(request));
    loaded
      .then((events) => { if (!disposed) setSseEvents((current) => mergeSseEvents(events, current)); })
      .catch((error) => { if (!disposed) setSseError(String(error)); })
      .finally(() => { if (!disposed) setSseLoading(false); });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [request.id, request.type, tab]);

  useEffect(() => {
    let disposed = false;
    if (tab !== "rules") return () => { disposed = true; };
    setRuleTraceLoading(true);
    const loaded = isTauri()
      ? invoke<CaptureRuleRun[]>("list_rule_trace_for_request", { requestId: request.id })
      : Promise.resolve([]);
    loaded.then((traces) => { if (!disposed) setRuleTraces(traces); })
      .finally(() => { if (!disposed) setRuleTraceLoading(false); });
    return () => { disposed = true; };
  }, [request.id, tab]);

  const copyUrl = async () => {
    await navigator.clipboard?.writeText(`https://${request.host}${request.path}${request.query ? `?${request.query}` : ""}`);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  const tabs: Array<{ id: DetailTab; label: string; count?: number }> = [
    { id: "overview", label: t("traffic.tab.overview") },
    { id: "query", label: t("traffic.tab.query"), count: parseQueryEntries(request.query).length },
    { id: "requestHeaders", label: t("traffic.reqHeaders"), count: request.requestHeaders.length },
    { id: "responseHeaders", label: t("traffic.resHeaders"), count: request.responseHeaders.length },
    { id: "cookies", label: "Cookie", count: parseCookies([...request.requestHeaders, ...request.responseHeaders]).length },
    { id: "requestBody", label: t("traffic.tab.reqBody") },
    { id: "responseBody", label: t("traffic.tab.resBody") },
    ...(request.type === "websocket" ? [{ id: "messages" as const, label: t("traffic.tab.messages"), count: websocketFrames.length }] : []),
    ...(request.type === "sse" ? [{ id: "sse" as const, label: "SSE", count: sseEvents.length }] : []),
    ...(request.cryptoSnippetCount > 0 ? [{ id: "code" as const, label: t("traffic.tab.code"), count: request.cryptoSnippetCount }] : []),
    ...(request.tlsFingerprint ? [{ id: "fingerprint" as const, label: t("traffic.tab.fingerprint") }] : []),
    { id: "hook", label: "Hook", count: request.hook ? 1 : 0 },
    { id: "rules", label: t("traffic.tab.rules"), count: ruleTraces.length },
    { id: "timing", label: t("traffic.tab.timing") },
    { id: "annotation", label: t("traffic.tab.annotation"), count: annotationSummary?.tags.length },
  ];

  return (
    <>
    <aside className="request-detail">
      <div className="request-detail__head">
        <div className="request-detail__title">
          <span className={`method method-${request.method.toLowerCase()}`}>{request.method}</span>
          <div><h2>{request.path}</h2><span>{request.host}</span></div>
        </div>
        <div className="request-detail__actions">
          <button className={`icon-button ${layout === "right" ? "is-active" : ""}`} onClick={() => onLayoutChange("right")} title={t("traffic.detailRight")}><PanelRight size={15} /></button>
          <button className={`icon-button ${layout === "bottom" ? "is-active" : ""}`} onClick={() => onLayoutChange("bottom")} title={t("traffic.detailBottom")}><PanelBottom size={15} /></button>
          <button className="icon-button" onClick={() => onLayoutChange(layout === "maximized" ? "right" : "maximized")} title={layout === "maximized" ? t("traffic.exitMax") : t("traffic.maxDetail")}>{layout === "maximized" ? <Minimize2 size={15} /> : <Maximize2 size={15} />}</button>
          <button className="icon-button" onClick={() => setCodeOpen(true)} title={t("traffic.genCode")}><Code2 size={15} /></button>
          <button className="icon-button" onClick={copyUrl} title={t("traffic.copyUrl")}>{copied ? <span className="copied-check">✓</span> : <Copy size={15} />}</button>
          <button className="icon-button" onClick={onClose} title={t("traffic.closeDetail")}><X size={16} /></button>
        </div>
      </div>
      <div className="request-meta-line">
        {(() => {
          const presentation = classifyTrafficStatus(request.status, {
            responseBody: request.responseBody,
            server: headerValue(request.responseHeaders, "server"),
          });
          return (
            <span className={`status-code status-${presentation.cssClass}`} title={presentation.title}>
              {presentation.label}
            </span>
          );
        })()}
        <span>{request.protocol}</span><span>{request.tls === "明文" ? t("traffic.plaintext") : request.tls}</span><span>{request.size}</span><span>{request.duration} ms</span>
      </div>
      {request.risk !== "none" && (
        <div className={`risk-banner risk-banner--${request.risk}`}>
          <ShieldAlert size={15} />
          <span>{request.risk === "critical" ? t("traffic.risk.criticalBanner") : request.risk === "warning" ? t("traffic.risk.warningBanner") : t("traffic.risk.infoBanner")}</span>
        </div>
      )}
      {(() => {
        const presentation = classifyTrafficStatus(request.status, {
          responseBody: request.responseBody,
          server: headerValue(request.responseHeaders, "server"),
        });
        if (presentation.kind === "proxy" && request.responseBody?.trim()) {
          return (
            <div className="risk-banner risk-banner--warning proxy-error-banner" role="alert">
              <CircleAlert size={15} />
              <span><strong>{t("traffic.proxyError", { status: request.status })}</strong>{request.responseBody.trim()}</span>
            </div>
          );
        }
        if (presentation.kind === "origin4xx") {
          const server = headerValue(request.responseHeaders, "server");
          return (
            <div className="risk-banner risk-banner--warning origin-4xx-banner" role="status">
              <CircleAlert size={15} />
              <span>
                <strong>{t("traffic.originStatus", { status: request.status })}</strong>
                {server ? ` · Server: ${server}` : ""}
                {t("traffic.origin4xxHint")}
              </span>
            </div>
          );
        }
        return null;
      })()}
      <div className="detail-tabs">
        {tabs.map((item) => (
          <button key={item.id} className={tab === item.id ? "is-active" : ""} onClick={() => setTab(item.id)}>
            {item.label}{item.count !== undefined && <span>{item.count}</span>}
          </button>
        ))}
      </div>
      <div className="detail-content">
        {tab === "overview" && <RequestOverview request={request} />}
        {tab === "query" && <QueryViewer query={request.query} />}
        {tab === "requestHeaders" && <HeaderViewer title={t("traffic.reqHeaders")} headers={request.requestHeaders} />}
        {tab === "responseHeaders" && <HeaderViewer title={t("traffic.resHeaders")} headers={request.responseHeaders} />}
        {tab === "cookies" && <CookieViewer requestHeaders={request.requestHeaders} responseHeaders={request.responseHeaders} />}
        {tab === "messages" && (
          <WebSocketMessages frames={websocketFrames} loading={websocketLoading} error={websocketError} />
        )}
        {tab === "sse" && <SseInspector events={sseEvents} loading={sseLoading} error={sseError} />}
        {tab === "requestBody" && <HttpBodyViewer content={request.requestBody} headers={request.requestHeaders} metadata={legacyBodyMetadata(request.requestBody)} filename={`${request.id}-request-body.txt`} legacyMetadata />}
        {tab === "responseBody" && <HttpBodyViewer content={request.responseBody} headers={request.responseHeaders} metadata={request.responseBodyMetadata} filename={`${request.id}-response-body.txt`} />}
        {tab === "code" && (
          cryptoLoading ? <div className="detail-empty"><Code2 size={20} /><span>{t("traffic.readingSnippets")}</span></div>
            : cryptoError ? <div className="detail-empty"><CircleAlert size={20} /><span>{cryptoError}</span></div>
              : <CryptoCodeDetail snippets={cryptoSnippets} />
        )}
        {tab === "fingerprint" && request.tlsFingerprint && <TlsFingerprintDetail fingerprint={request.tlsFingerprint} />}
        {tab === "hook" && (
          request.hook ? (
            <div className="hook-detail">
              <div className="hook-detail__title"><Code2 size={16} /><strong>{request.hook.algorithm}</strong><span>{t("traffic.hookLinked")}</span></div>
              <label>{t("traffic.hookInput")}</label><CodeBlock content={request.hook.input} />
              <label>{t("traffic.hookOutput")}</label><CodeBlock content={request.hook.output} />
              <button className="secondary-button" onClick={onAnalyze}><Bot size={14} />{t("traffic.explainAlgo")}</button>
            </div>
          ) : <div className="detail-empty"><Braces size={20} /><span>{t("traffic.noHook")}</span></div>
        )}
        {tab === "rules" && <RuleTraceViewer traces={ruleTraces} loading={ruleTraceLoading} />}
        {tab === "timing" && <TimingBreakdown duration={request.duration} />}
        {tab === "annotation" && <AnnotationEditor requestId={request.id} summary={annotationSummary} onSaved={onAnnotationSaved} />}
      </div>
    </aside>
    {codeOpen && <CodeTemplateDialog request={request} onClose={() => setCodeOpen(false)} />}
    </>
  );
}

function isDetailTabAvailable(tab: DetailTab, request: RequestRecord) {
  if (tab === "messages") return request.type === "websocket";
  if (tab === "sse") return request.type === "sse";
  if (tab === "code") return request.cryptoSnippetCount > 0;
  if (tab === "fingerprint") return Boolean(request.tlsFingerprint);
  return true;
}

function RequestOverview({ request }: { request: RequestRecord }) {
  const responseMetadata = request.responseBodyMetadata ?? legacyBodyMetadata(request.responseBody);
  const notProvided = t("traffic.notProvided");
  const server = headerValue(request.responseHeaders, "server") ?? notProvided;
  const contentType = headerValue(request.responseHeaders, "content-type") ?? notProvided;
  const url = `${request.tls === "明文" ? "http" : "https"}://${request.host}${request.path}${request.query ? `?${request.query}` : ""}`;
  const statusPresentation = classifyTrafficStatus(request.status, {
    responseBody: request.responseBody,
    server: headerValue(request.responseHeaders, "server"),
  });
  const proxyError =
    statusPresentation.kind === "proxy" && request.responseBody?.trim()
      ? request.responseBody.trim()
      : looksLikeProxyErrorBody(request.responseBody)
        ? request.responseBody!.trim()
        : "";
  return <div className="request-overview">
    {proxyError && (
      <section className="overview-proxy-error" role="alert">
        <h3>{t("traffic.proxyErrorDetail")}</h3>
        <pre>{proxyError}</pre>
      </section>
    )}
    {statusPresentation.kind === "origin4xx" && (
      <section className="overview-origin-4xx" role="status">
        <h3>{t("traffic.originStatus", { status: request.status })}{server !== notProvided ? ` · ${server}` : ""}</h3>
        <p>{t("traffic.origin4xxBody")}</p>
      </section>
    )}
    <dl className="overview-grid">
      <div className="is-wide"><dt>{t("traffic.dt.url")}</dt><dd>{url}</dd></div>
      <div><dt>{t("traffic.dt.status")}</dt><dd title={statusPresentation.title}>{statusPresentation.label}</dd></div>
      <div><dt>{t("traffic.dt.protocol")}</dt><dd>{request.protocol}</dd></div>
      <div><dt>{t("traffic.dt.tls")}</dt><dd>{request.tls === "明文" ? t("traffic.plaintext") : request.tls}</dd></div>
      <div><dt>{t("traffic.dt.server")}</dt><dd>{server}</dd></div>
      <div><dt>{t("traffic.dt.type")}</dt><dd>{request.type}</dd></div>
      <div><dt>{t("traffic.dt.contentType")}</dt><dd>{contentType}</dd></div>
      <div><dt>{t("traffic.dt.size")}</dt><dd>{request.size}</dd></div>
      <div><dt>{t("traffic.dt.duration")}</dt><dd>{request.duration} ms</dd></div>
      <div><dt>{t("traffic.dt.source")}</dt><dd>{sourceLabels[request.source]}</dd></div>
      <div><dt>{t("traffic.dt.time")}</dt><dd>{request.time}</dd></div>
      <div><dt>{t("traffic.dt.risk")}</dt><dd>{request.risk === "none" ? t("common.none") : request.risk}</dd></div>
    </dl>
    <section className="overview-evidence"><h3>{t("traffic.bodyEvidence")}</h3><HttpBodyStatus metadata={responseMetadata} /><HttpBodyMetadataGrid metadata={responseMetadata} /></section>
  </div>;
}

function QueryViewer({ query }: { query?: string }) {
  const entries = parseQueryEntries(query);
  if (!entries.length) return <div className="detail-empty"><ListFilter size={20} /><span>{t("traffic.noQuery")}</span></div>;
  return <div className="structured-table"><div className="structured-table__head"><span>{t("traffic.name")}</span><span>{t("traffic.decodedValue")}</span><span>{t("traffic.index")}</span></div>{entries.map((entry) => <div key={`${entry.name}-${entry.index}`}><code>{entry.name}</code><span>{entry.value || <em>{t("traffic.emptyValue")}</em>}</span><small>{entry.duplicate ? t("traffic.duplicate", { n: entry.index + 1 }) : entry.index + 1}</small></div>)}</div>;
}

function HeaderViewer({ title, headers }: { title: string; headers: Array<{ name: string; value: string }> }) {
  const [mode, setMode] = useState<"table" | "raw">("table");
  const [search, setSearch] = useState("");
  const normalized = search.trim().toLowerCase();
  const visible = headers.filter((header) => !normalized || `${header.name}: ${header.value}`.toLowerCase().includes(normalized));
  const raw = headers.map((header) => `${header.name}: ${header.value}`).join("\n");
  return <div className="header-viewer">
    <div className="detail-subtoolbar"><div className="segmented-small"><button className={mode === "table" ? "is-active" : ""} onClick={() => setMode("table")}>{t("traffic.table")}</button><button className={mode === "raw" ? "is-active" : ""} onClick={() => setMode("raw")}>{t("traffic.raw")}</button></div><div className="detail-search"><Search size={13} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("traffic.searchIn", { title })} /></div><button className="icon-button" onClick={() => void navigator.clipboard?.writeText(raw)} title={t("traffic.copyAll")}><Copy size={14} /></button></div>
    {mode === "raw" ? <CodeBlock content={raw || t("traffic.emptyTitle", { title })} muted={!raw} /> : <div className="header-table"><div className="header-table__head"><span>{t("traffic.name")}</span><span>{t("traffic.headerValue")}</span><span /></div>{visible.map((header, index) => <div key={`${header.name}-${index}`}><code>{header.name}</code><span>{header.value}</span><button onClick={() => void navigator.clipboard?.writeText(`${header.name}: ${header.value}`)} title={t("traffic.copyItem")}><Copy size={12} /></button></div>)}</div>}
    {visible.length === 0 && <div className="detail-empty detail-empty--compact"><Search size={16} /><span>{t("traffic.noHeaderMatch")}</span></div>}
  </div>;
}

function CookieViewer({ requestHeaders, responseHeaders }: { requestHeaders: Array<{ name: string; value: string }>; responseHeaders: Array<{ name: string; value: string }> }) {
  const cookies = parseCookies([...requestHeaders, ...responseHeaders]);
  if (!cookies.length) return <div className="detail-empty"><ListFilter size={20} /><span>{t("traffic.noCookies")}</span></div>;
  return <div className="cookie-table"><div className="cookie-table__head"><span>{t("traffic.cookieNameValue")}</span><span>{t("traffic.cookieDir")}</span><span>{t("traffic.cookieAttrs")}</span></div>{cookies.map((cookie, index) => <div key={`${cookie.source}-${cookie.name}-${index}`}><span><strong>{cookie.name}</strong><code>{cookie.value || t("traffic.emptyValue")}</code></span><small>{cookie.source === "request" ? t("traffic.cookieReq") : t("traffic.cookieRes")}</small><span className="cookie-attributes">{Object.entries(cookie.attributes).length ? Object.entries(cookie.attributes).map(([name, value]) => <em key={name}>{name}{value === true ? "" : `=${value}`}</em>) : <em>{t("traffic.sessionCookie")}</em>}</span></div>)}</div>;
}

function RuleTraceViewer({ traces, loading }: { traces: CaptureRuleRun[]; loading: boolean }) {
  if (loading) return <div className="detail-empty"><Clock3 size={20} /><span>{t("traffic.readingRules")}</span></div>;
  if (!traces.length) return <div className="detail-empty"><SlidersHorizontal size={20} /><span>{t("traffic.noRules")}</span></div>;
  return <div className="rule-trace-list">{traces.map((trace, index) => <article key={trace.id} className={`rule-trace-item is-${trace.result}`}><header><span>{index + 1}</span><div><strong>{trace.ruleName}</strong><small>{trace.stage} · v{trace.revision}</small></div><em>{ruleTraceResultLabel(trace.result)}</em></header><div>{Array.isArray(trace.diffSummary.changes) && trace.diffSummary.changes.map((change) => <p key={String(change)}><Check size={11} />{String(change)}</p>)}{trace.error && <p className="is-error"><CircleAlert size={11} />{trace.error}</p>}</div><footer><span>{trace.durationMs} ms</span><time>{new Date(trace.createdAt).toLocaleTimeString(getClockLocale(), { hour12: false })}</time></footer></article>)}</div>;
}


function AnnotationEditor({ requestId, summary, onSaved }: { requestId: string; summary?: RequestAnnotationSummary; onSaved: (annotation: RequestAnnotation) => void }) {
  const [annotation, setAnnotation] = useState<RequestAnnotation>(() => emptyAnnotation(requestId, summary));
  const [tagText, setTagText] = useState(summary?.tags.join(", ") ?? "");
  const [loading, setLoading] = useState(isTauri());
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let disposed = false;
    setAnnotation(emptyAnnotation(requestId, summary));
    setTagText(summary?.tags.join(", ") ?? "");
    setMessage("");
    if (!isTauri()) { setLoading(false); return () => { disposed = true; }; }
    setLoading(true);
    invoke<RequestAnnotation | null>("get_request_annotation", { requestId })
      .then((loaded) => {
        if (disposed || !loaded) return;
        setAnnotation(loaded);
        setTagText(loaded.tags.join(", "));
      })
      .catch((error) => { if (!disposed) setMessage(String(error)); })
      .finally(() => { if (!disposed) setLoading(false); });
    return () => { disposed = true; };
  }, [requestId]);

  const saveAnnotation = async () => {
    const tags = [...new Set(tagText.split(",").map((tag) => tag.trim()).filter(Boolean))].slice(0, 20);
    const input: RequestAnnotationInput = {
      requestId,
      bookmarked: annotation.bookmarked,
      color: annotation.color,
      struckThrough: annotation.struckThrough,
      note: annotation.note,
      tags,
    };
    setSaving(true);
    setMessage("");
    try {
      const saved = isTauri()
        ? await invoke<RequestAnnotation>("save_request_annotation", { input })
        : { ...annotation, ...input, tags, updatedAt: Date.now() };
      setAnnotation(saved);
      setTagText(saved.tags.join(", "));
      onSaved(saved);
      setMessage(t("traffic.annotationSaved"));
    } catch (error) {
      setMessage(String(error));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="detail-empty"><Clock3 size={20} /><span>{t("traffic.readingAnnotation")}</span></div>;
  return <div className="annotation-editor">
    <div className="annotation-toggles">
      <button className={annotation.bookmarked ? "is-active" : ""} onClick={() => setAnnotation((current) => ({ ...current, bookmarked: !current.bookmarked }))}><Bookmark size={14} fill={annotation.bookmarked ? "currentColor" : "none"} />{t("traffic.noteToggle")}</button>
      <button className={annotation.struckThrough ? "is-active" : ""} onClick={() => setAnnotation((current) => ({ ...current, struckThrough: !current.struckThrough }))}><Strikethrough size={14} />{t("traffic.strikethrough")}</button>
    </div>
    <label className="annotation-field"><span><StickyNote size={13} />{t("traffic.tab.annotation")}</span><textarea value={annotation.note} maxLength={20_000} onChange={(event) => setAnnotation((current) => ({ ...current, note: event.target.value }))} placeholder={t("traffic.notePlaceholder")} /></label>
    <label className="annotation-field"><span><Tag size={13} />{t("traffic.tags")}</span><input value={tagText} onChange={(event) => setTagText(event.target.value)} placeholder={t("traffic.tagsPlaceholder")} /></label>
    <div className="annotation-colors"><span>{t("traffic.highlight")}</span>{([undefined, "red", "yellow", "green", "blue", "gray"] as const).map((color) => <button key={color ?? "none"} className={`${color ? `color-${color}` : "color-none"} ${annotation.color === color ? "is-active" : ""}`} onClick={() => setAnnotation((current) => ({ ...current, color }))} title={color ? t("traffic.highlightColor", { color }) : t("traffic.clearHighlight")}>{annotation.color === color && <Check size={12} />}</button>)}</div>
    <div className="annotation-footer"><span>{message || (annotation.updatedAt > annotation.createdAt ? t("traffic.updatedAt", { time: new Date(annotation.updatedAt).toLocaleString(getClockLocale()) }) : t("traffic.noteNotToAi"))}</span><button className="primary-button" onClick={() => void saveAnnotation()} disabled={saving}>{saving ? t("common.saving") : t("traffic.saveAnnotation")}</button></div>
  </div>;
}

function emptyAnnotation(requestId: string, summary?: RequestAnnotationSummary): RequestAnnotation {
  const now = Date.now();
  return { requestId, bookmarked: summary?.bookmarked ?? false, color: summary?.color, struckThrough: summary?.struckThrough ?? false, note: summary?.notePreview ?? "", tags: summary?.tags ?? [], createdAt: now, updatedAt: now };
}

function annotationSummary(annotation: RequestAnnotation): RequestAnnotationSummary {
  return { bookmarked: annotation.bookmarked, color: annotation.color, struckThrough: annotation.struckThrough, notePreview: annotation.note.slice(0, 120) || undefined, tags: annotation.tags };
}

function WebSocketMessages({ frames, loading, error }: { frames: WebSocketFrameEvent[]; loading: boolean; error: string }) {
  if (loading) return <div className="detail-empty"><MessagesSquare size={20} /><span>{t("traffic.readingMessages")}</span></div>;
  if (error) return <div className="detail-empty"><CircleAlert size={20} /><span>{error}</span></div>;
  if (!frames.length) return <div className="detail-empty"><MessagesSquare size={20} /><span>{t("traffic.noWsMessages")}</span></div>;
  return (
    <div className="websocket-message-list">
      {frames.map((frame) => {
        const outbound = frame.payload.direction === "client_to_server";
        const limited = frame.payload.opcode === "capture_limit";
        return (
          <article key={`${frame.sequence}-${frame.payload.index}`} className={`websocket-message ${outbound ? "is-outbound" : "is-inbound"} ${limited ? "is-limit" : ""}`}>
            <header>
              <span className="websocket-message__direction">{outbound ? <ArrowUpRight size={13} /> : <ArrowDownLeft size={13} />}{outbound ? t("traffic.wsOut") : t("traffic.wsIn")}</span>
              <span className={`websocket-opcode opcode-${frame.payload.opcode}`}>{frame.payload.opcode}</span>
              <time>{formatClock(frame.timestamp, true)}</time>
              <small>{formatBytes(frame.payload.sizeBytes)}</small>
            </header>
            <pre>{frame.payload.data || (frame.payload.opcode === "close" ? t("traffic.wsClosed") : t("traffic.emptyMessage"))}</pre>
            <footer>
              {frame.payload.encoding === "base64" && <span>BASE64</span>}
              {frame.payload.closeCode !== undefined && <span>CODE {frame.payload.closeCode}</span>}
              {frame.payload.truncated && <span>{t("traffic.truncated")}</span>}
            </footer>
          </article>
        );
      })}
    </div>
  );
}

function SseInspector({ events, loading, error }: { events: SseEvent[]; loading: boolean; error: string }) {
  const [query, setQuery] = useState("");
  const [order, setOrder] = useState<SseOrder>("ascending");
  const [pausedAt, setPausedAt] = useState<number>();
  const [selectedSequence, setSelectedSequence] = useState<number>();
  const visibleEvents = useMemo(
    () => pausedAt === undefined ? events : events.filter((event) => event.sequence <= pausedAt),
    [events, pausedAt],
  );
  const filteredEvents = useMemo(
    () => filterAndOrderSseEvents(visibleEvents, query, order),
    [visibleEvents, query, order],
  );
  const selected = filteredEvents.find((event) => event.sequence === selectedSequence) ?? filteredEvents[0];
  const pendingCount = pausedAt === undefined ? 0 : events.filter((event) => event.sequence > pausedAt).length;
  const terminal = [...events].reverse().find(isSseTerminal);
  const streamState = terminal?.payload.kind === "capture_limit"
    ? t("traffic.sseLimit")
    : terminal?.payload.kind === "stream_end"
      ? terminal.payload.complete ? t("traffic.sseEnded") : t("traffic.sseInterrupted")
      : t("traffic.sseLive");

  useEffect(() => {
    if (!filteredEvents.length) {
      setSelectedSequence(undefined);
      return;
    }
    if (!filteredEvents.some((event) => event.sequence === selectedSequence)) {
      setSelectedSequence(filteredEvents[0].sequence);
    }
  }, [filteredEvents, selectedSequence]);

  if (loading) return <div className="detail-empty"><Radio size={20} /><span>{t("traffic.readingSse")}</span></div>;
  if (error) return <div className="detail-empty"><CircleAlert size={20} /><span>{error}</span></div>;
  if (!events.length) return <div className="detail-empty"><Radio size={20} /><span>{t("traffic.waitSse")}</span></div>;

  return <div className="sse-inspector">
    <header className="sse-toolbar">
      <div className={`sse-stream-state is-${terminal ? "stopped" : "live"}`}>
        <CircleDot size={12} />
        <strong>{streamState}</strong>
        <span>{t("traffic.sseCount", { count: events.length.toLocaleString() })}</span>
      </div>
      <label className="sse-search"><Search size={13} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("traffic.sseSearch")} /><span>{filteredEvents.length}</span></label>
      <div className="sse-order" aria-label={t("traffic.sseOrder")}>
        <button className={order === "ascending" ? "is-active" : ""} onClick={() => setOrder("ascending")} title={t("traffic.sseAscTitle")}><ArrowDown size={13} /><span>{t("traffic.sseAsc")}</span></button>
        <button className={order === "descending" ? "is-active" : ""} onClick={() => setOrder("descending")} title={t("traffic.sseDescTitle")}><ArrowUp size={13} /><span>{t("traffic.sseDesc")}</span></button>
      </div>
      <button className={`sse-pause ${pausedAt !== undefined ? "is-active" : ""}`} onClick={() => setPausedAt((current) => current === undefined ? events.at(-1)?.sequence ?? 0 : undefined)} title={pausedAt === undefined ? t("traffic.ssePauseTitle") : t("traffic.sseResumeTitle")}>
        {pausedAt === undefined ? <Pause size={13} /> : <Play size={13} />}
        <span>{pausedAt === undefined ? t("traffic.ssePause") : pendingCount ? t("traffic.sseResumeN", { count: pendingCount }) : t("traffic.sseResume")}</span>
      </button>
    </header>
    <div className="sse-workspace">
      <div className="sse-event-list" role="listbox" aria-label={t("traffic.sseList")}>
        {filteredEvents.map((event) => <button key={event.sequence} className={`${selected?.sequence === event.sequence ? "is-selected" : ""} is-${event.payload.kind}`} onClick={() => setSelectedSequence(event.sequence)} role="option" aria-selected={selected?.sequence === event.sequence}>
          <span className="sse-event-index">#{event.payload.index}</span>
          <span className="sse-event-summary"><strong>{sseEventLabel(event)}</strong><small>{event.payload.data || event.payload.comments.join(" ") || event.payload.id || t("traffic.sseNoData")}</small></span>
          <span className="sse-event-meta"><time>{formatClock(event.timestamp)}</time><small>{formatBytes(event.payload.sizeBytes)}</small></span>
        </button>)}
        {!filteredEvents.length && <div className="sse-no-results"><Search size={18} /><span>{t("traffic.sseNoMatch")}</span></div>}
      </div>
      <div className="sse-event-detail">
        {selected ? <>
          <header>
            <div><span>#{selected.payload.index}</span><strong>{sseEventLabel(selected)}</strong></div>
            <time>{formatClock(selected.timestamp)}</time>
          </header>
          <dl>
            <div><dt>{t("traffic.dt.event")}</dt><dd>{selected.payload.event}</dd></div>
            <div><dt>ID</dt><dd>{selected.payload.id || "-"}</dd></div>
            <div><dt>{t("traffic.dt.size")}</dt><dd>{formatBytes(selected.payload.sizeBytes)}</dd></div>
            <div><dt>{t("traffic.dt.retry")}</dt><dd>{selected.payload.retry === undefined ? "-" : `${selected.payload.retry} ms`}</dd></div>
          </dl>
          {(selected.payload.truncated || selected.payload.incomplete) && <div className="sse-evidence-warning"><CircleAlert size={13} /><span>{selected.payload.truncated ? t("traffic.sseTruncated") : t("traffic.sseIncomplete")}</span></div>}
          <section><label>DATA</label><pre>{prettySseData(selected.payload.data) || t("traffic.emptyData")}</pre></section>
          {selected.payload.comments.length > 0 && <section><label>COMMENT</label><pre>{selected.payload.comments.join("\n")}</pre></section>}
          {selected.payload.fields.length > 0 && <section><label>FIELDS</label><div className="sse-field-list">{selected.payload.fields.map((field, index) => <div key={`${field.name}-${index}`}><span>{field.name || t("traffic.emptyField")}</span><code>{field.value || "-"}</code></div>)}</div></section>}
          <section><label>RAW</label><pre>{selected.payload.raw || t("traffic.noRaw")}</pre></section>
        </> : <div className="sse-no-results"><Radio size={18} /><span>{t("traffic.pickSse")}</span></div>}
      </div>
    </div>
  </div>;
}

function mergeSseEvents(first: SseEvent[], second: SseEvent[]) {
  const bySequence = new Map<number, SseEvent>();
  [...first, ...second].forEach((event) => bySequence.set(event.sequence, event));
  return [...bySequence.values()].sort((left, right) => left.sequence - right.sequence).slice(0, 2_000);
}

function previewSseEvents(request: RequestRecord): SseEvent[] {
  if (request.type !== "sse") return [];
  const timestamp = Date.now() - 900;
  return [
    {
      sessionId: "preview-session",
      source: request.source,
      sourceInstanceId: "preview-sse",
      requestId: request.id,
      sequence: 1,
      timestamp,
      phase: "sse",
      payload: {
        kind: "event",
        event: "message",
        id: "evt-1842",
        data: '{"type":"order.updated","orderId":"A-1842","status":"paid"}',
        raw: 'id: evt-1842\ndata: {"type":"order.updated","orderId":"A-1842","status":"paid"}\n',
        fields: [{ name: "id", value: "evt-1842" }, { name: "data", value: '{"type":"order.updated","orderId":"A-1842","status":"paid"}' }],
        comments: [],
        sizeBytes: 98,
        truncated: false,
        incomplete: false,
        index: 1,
      },
    },
  ];
}

function mergeWebSocketFrames(first: WebSocketFrameEvent[], second: WebSocketFrameEvent[]) {
  const bySequence = new Map<number, WebSocketFrameEvent>();
  [...first, ...second].forEach((frame) => bySequence.set(frame.sequence, frame));
  return [...bySequence.values()].sort((left, right) => left.sequence - right.sequence).slice(0, 2_000);
}

function previewWebSocketFrames(request: RequestRecord): WebSocketFrameEvent[] {
  if (request.type !== "websocket") return [];
  const startedAt = Date.now() - 1_200;
  const frame = (
    sequence: number,
    direction: "client_to_server" | "server_to_client",
    opcode: "text" | "binary" | "ping",
    data: string,
    encoding: "utf8" | "base64",
    sizeBytes: number,
  ): WebSocketFrameEvent => ({
    sessionId: "preview-session",
    source: request.source,
    sourceInstanceId: "preview-websocket",
    requestId: request.id,
    sequence,
    timestamp: startedAt + sequence * 180,
    phase: "websocket",
    payload: { direction, opcode, data, encoding, sizeBytes, truncated: false, index: sequence },
  });
  return [
    frame(1, "client_to_server", "text", '{"type":"subscribe","channel":"orders:current"}', "utf8", 47),
    frame(2, "server_to_client", "text", '{"type":"subscribed","channel":"orders:current","cursor":"evt_1842"}', "utf8", 70),
    frame(3, "client_to_server", "ping", "cGluZw==", "base64", 4),
    frame(4, "server_to_client", "binary", "AQIDBAUGBwgJCgsMDQ4PEA==", "base64", 16),
  ];
}

function CodeTemplateDialog({ request, onClose }: { request: RequestRecord; onClose: () => void }) {
  const [template, setTemplate] = useState<RequestCodeTemplate>("python");
  const [copied, setCopied] = useState(false);

  useEscapeDismiss(true, onClose);
  const code = generateRequestCode({
    method: request.method,
    url: `${request.tls === "明文" ? "http" : "https"}://${request.host}${request.path}${request.query ? `?${request.query}` : ""}`,
    headers: request.requestHeaders,
    body: request.requestBody,
  }, template);

  const copyCode = async () => {
    await navigator.clipboard?.writeText(code);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section className="code-template-dialog" role="dialog" aria-modal="true" aria-labelledby="request-code-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
        <header className="dialog-header">
          <div><span className="section-kicker">REQUEST CODE</span><h2 id="request-code-dialog-title">{t("traffic.genCode")}</h2><p>{request.method} · {request.host}{request.path}</p></div>
          <button className="icon-button" onClick={onClose} title={t("common.close")}><X size={18} /></button>
        </header>
        <div className="code-template-toolbar"><label><span>{t("traffic.codeLanguage")}</span><select aria-label={t("traffic.codeLanguage")} value={template} onChange={(event) => setTemplate(event.target.value as RequestCodeTemplate)}>{requestCodeTemplates.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label></div>
        <pre className="generated-code">{code}</pre>
        <footer className="dialog-footer"><span /><span className="dialog-actions"><button className="secondary-button" onClick={onClose}>{t("common.close")}</button><button className="primary-button" onClick={copyCode}><Copy size={14} />{copied ? t("common.copied") : t("traffic.copyCode")}</button></span></footer>
      </section>
    </div>
  );
}


function TlsFingerprintDetail({ fingerprint }: { fingerprint: NonNullable<RequestRecord["tlsFingerprint"]> }) {
  const { inbound, outbound } = fingerprint;
  const http2 = fingerprint.http2;
  return (
    <div className="fingerprint-detail">
      <div className="fingerprint-mode">
        <span>{t("traffic.fpInbound")}</span>
        <strong>{fingerprint.captureMode === "tunnel" ? t("traffic.fpTunnel") : t("traffic.fpMitm")}</strong>
        <small>{outbound.note}</small>
      </div>
      <dl className="fingerprint-values">
        <div><dt>JA3</dt><dd>{inbound.ja3}</dd></div>
        <div><dt>JA4</dt><dd>{inbound.ja4}</dd></div>
        <div><dt>SNI</dt><dd>{inbound.sni || t("traffic.notProvided")}</dd></div>
        <div><dt>ALPN</dt><dd>{inbound.alpn.join(", ") || t("traffic.notProvided")}</dd></div>
        <div><dt>{t("traffic.fpTlsVersion")}</dt><dd>{inbound.offeredVersions.join(", ") || inbound.legacyVersion}</dd></div>
        <div><dt>GREASE</dt><dd>{inbound.grease ? t("traffic.fpGreaseOn") : t("traffic.fpGreaseOff")}</dd></div>
        <div><dt>{t("traffic.fpCiphers")}</dt><dd>{inbound.cipherSuites.join(", ")}</dd></div>
        <div><dt>{t("traffic.fpExtensions")}</dt><dd>{inbound.extensions.join(", ")}</dd></div>
        <div><dt>{t("traffic.fpGroups")}</dt><dd>{inbound.supportedGroups.join(", ") || t("traffic.notProvided")}</dd></div>
        <div><dt>{t("traffic.fpSigAlgs")}</dt><dd>{inbound.signatureAlgorithms.join(", ") || t("traffic.notProvided")}</dd></div>
        <div><dt>{t("traffic.fpOutbound")}</dt><dd>{outbound.profile}{outbound.ja3 ? ` · ${outbound.ja3}` : ""}</dd></div>
      </dl>
      {http2 && (
        <section className="http2-fingerprint">
          <div className={`fingerprint-mode ${http2.complete ? "is-complete" : "is-partial"}`}><span>{t("traffic.fpH2Inbound")}</span><strong>{http2.complete ? t("traffic.fpH2Complete") : t("traffic.fpH2Partial")}</strong><small>{http2.note}</small></div>
          <dl className="fingerprint-values">
            <div><dt>{t("traffic.fpH2Hash")}</dt><dd>{http2.hash}</dd></div>
            <div><dt>SETTINGS</dt><dd>{http2.settings.map((setting) => `${setting.id}:${setting.value} (${setting.name})`).join("; ") || t("traffic.fpNotObserved")}</dd></div>
            <div><dt>{t("traffic.fpWindowUpdate")}</dt><dd>{http2.connectionWindowUpdates.join(", ") || t("traffic.fpNotObserved")}</dd></div>
            <div><dt>PRIORITY</dt><dd>{http2.priorityFrames.map((priority) => `stream=${priority.streamId}, dependency=${priority.dependency}, weight=${priority.weight}${priority.exclusive ? ", exclusive" : ""}`).join("; ") || t("traffic.fpNotObserved")}</dd></div>
            <div><dt>PRIORITY_UPDATE</dt><dd>{http2.priorityUpdates.map((priority) => `stream=${priority.prioritizedStreamId}, ${priority.fieldValue}`).join("; ") || t("traffic.fpNotObserved")}</dd></div>
            <div><dt>{t("traffic.fpPseudoOrder")}</dt><dd>{http2.pseudoHeaderOrder?.join(", ") || t("traffic.fpPseudoHidden")}</dd></div>
          </dl>
        </section>
      )}
      <details className="fingerprint-raw"><summary>{t("traffic.fpRaw")}</summary><code>{inbound.ja3Raw}</code><code>{inbound.ja4Raw}</code>{http2 && <code>{http2.canonical}</code>}</details>
    </div>
  );
}

function CodeBlock({ content, muted = false }: { content: string; muted?: boolean }) {
  return <pre className={`code-block ${muted ? "is-muted" : ""}`}>{content}</pre>;
}

function downloadBody(content: string, filename: string, contentType: string) {
  const url = URL.createObjectURL(new Blob([content], { type: contentType }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function CryptoCodeDetail({ snippets }: { snippets: CryptoCodeSnippet[] }) {
  if (snippets.length === 0) return <div className="detail-empty"><Code2 size={20} /><span>{t("traffic.noCrypto")}</span></div>;
  return (
    <div className="crypto-code-list">
      {snippets.map((snippet) => (
        <section className="crypto-code-snippet" key={`${snippet.ordinal}-${snippet.startLine}`}>
          <header>
            <div><strong>{snippet.name || snippet.kind}</strong><span>{t("traffic.line", { line: snippet.endLine !== snippet.startLine ? `${snippet.startLine}-${snippet.endLine}` : snippet.startLine })}</span></div>
            <span>{snippet.algorithms.map((algorithm) => <em key={algorithm}>{algorithm}</em>)}</span>
          </header>
          {(snippet.truncated || snippet.sourceTruncated) && <small>{snippet.truncated ? t("traffic.snippetTrimmed") : t("traffic.sourceIncomplete")}</small>}
          <CodeBlock content={snippet.code} />
        </section>
      ))}
    </div>
  );
}

function previewCryptoSnippets(request: RequestRecord): CryptoCodeSnippet[] {
  if (request.cryptoSnippetCount <= 0) return [];
  return [{
    ordinal: 1,
    kind: "function-expression",
    name: "sign",
    algorithms: ["Web Crypto", "SHA-256"],
    startLine: 1,
    endLine: 1,
    code: "const sign = (payload, nonce) =>\n  crypto.subtle.digest(\"SHA-256\", encode(payload + nonce));",
    truncated: false,
    sourceTruncated: false,
  }];
}


function TimingBreakdown({ duration }: { duration: number }) {
  const evidence = timingEvidence(duration);
  return (
    <div className="timing-breakdown">
      <div className="timing-total"><Clock3 size={16} /><strong>{evidence.totalMs} ms</strong><span>{t("traffic.e2eDuration")}</span></div>
      <div className="detail-empty detail-empty--compact"><CircleAlert size={16} /><span>{evidence.note}</span></div>
    </div>
  );
}
