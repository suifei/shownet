import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { buildQuickFilter, emptyQuickFilter, normalizeFilterExpression, parseFilterExpression, serializeFilterExpression } from "../src/requestFilters.ts";
import { initialRequestSelection, requestSelectionReducer } from "../src/requestSelection.ts";
import { calculateVirtualWindow, defaultRequestGridPreferences, nextRequestSort, parseRequestGridPreferences, reorderRequestColumn, resizeRequestColumn, toggleRequestColumn, visibleRequestColumns } from "../src/trafficGrid.ts";

describe("request grid virtualization and preferences", () => {
  it("keeps the mounted row window bounded for ten thousand requests", () => {
    const first = calculateVirtualWindow(10_000, 0, 760);
    const middle = calculateVirtualWindow(10_000, 190_000, 760);
    assert.equal(first.start, 0);
    assert.ok(first.end - first.start < 50);
    assert.ok(middle.start > 4_000);
    assert.ok(middle.end - middle.start < 50);
    assert.equal(middle.totalHeight, 380_000);
  });

  it("keeps a 100k remote result set virtualized at the tail", () => {
    const tail = calculateVirtualWindow(100_000, 3_799_000, 844);
    assert.ok(tail.start > 99_900);
    assert.ok(tail.end - tail.start < 60);
    assert.equal(tail.totalHeight, 3_800_000);
  });

  it("persists valid columns and falls back for corrupt or old settings", () => {
    let preferences = defaultRequestGridPreferences();
    preferences = toggleRequestColumn(preferences, "protocol");
    preferences = resizeRequestColumn(preferences, "url", 9999);
    preferences = reorderRequestColumn(preferences, "status", "method");
    const restored = parseRequestGridPreferences(JSON.stringify(preferences));
    assert.equal(restored.widths.url, 720);
    assert.equal(visibleRequestColumns(restored).some((column) => column.id === "protocol"), false);
    assert.ok(restored.order.indexOf("status") < restored.order.indexOf("method"));
    assert.deepEqual(parseRequestGridPreferences("broken"), defaultRequestGridPreferences());
    assert.deepEqual(parseRequestGridPreferences('{"version":0}'), defaultRequestGridPreferences());
  });

  it("cycles single and additive multi-column sorting", () => {
    const first = nextRequestSort([], "status", false);
    assert.deepEqual(first, [{ field: "status", direction: "asc" }]);
    const second = nextRequestSort(first, "status", false);
    assert.deepEqual(second, [{ field: "status", direction: "desc" }]);
    assert.deepEqual(nextRequestSort(second, "status", false), []);
    assert.deepEqual(nextRequestSort(first, "durationMs", true), [
      { field: "status", direction: "asc" },
      { field: "durationMs", direction: "asc" },
    ]);
  });
});

describe("request selection", () => {
  const ids = ["a", "b", "c", "d", "e"];

  it("supports plain, toggle, range and window-wide selection", () => {
    let state = requestSelectionReducer(initialRequestSelection, { type: "click", id: "b", ids });
    state = requestSelectionReducer(state, { type: "click", id: "d", ids, toggle: true });
    assert.deepEqual(state.selectedIds, ["b", "d"]);
    state = requestSelectionReducer(state, { type: "click", id: "e", ids, range: true });
    assert.deepEqual(state.selectedIds, ["d", "e"]);
    state = requestSelectionReducer(state, { type: "selectAll", ids, focusedId: "c" });
    assert.deepEqual(state.selectedIds, ids);
    assert.equal(state.focusedId, "c");
  });

  it("moves focus, extends a range and reconciles removed rows", () => {
    let state = requestSelectionReducer(initialRequestSelection, { type: "click", id: "b", ids });
    state = requestSelectionReducer(state, { type: "move", direction: 1, ids, extend: true });
    state = requestSelectionReducer(state, { type: "move", direction: 1, ids, extend: true });
    assert.deepEqual(state.selectedIds, ["b", "c", "d"]);
    state = requestSelectionReducer(state, { type: "reconcile", ids: ["a", "c", "d", "e"] });
    assert.deepEqual(state.selectedIds, ["c", "d"]);
    assert.equal(state.focusedId, "d");
  });
});

describe("filter AST", () => {
  it("combines values in one quick group with OR and groups with AND", () => {
    const expression = buildQuickFilter({
      ...emptyQuickFilter,
      methods: ["GET", "POST"],
      statuses: ["4xx", "5xx"],
      sources: ["browser"],
    });
    assert.equal(expression?.kind, "group");
    assert.equal(expression?.kind === "group" ? expression.operator : "", "and");
    const children = expression?.kind === "group" ? expression.children : [];
    assert.equal(children.length, 3);
    assert.equal(children[0].kind === "group" ? children[0].operator : "", "or");
  });

  it("normalizes empty conditions and round trips nested expressions", () => {
    const nested = {
      kind: "group" as const,
      operator: "and" as const,
      children: [
        { kind: "predicate" as const, field: "host" as const, operator: "contains" as const, value: "api" },
        { kind: "group" as const, operator: "or" as const, children: [
          { kind: "predicate" as const, field: "status" as const, operator: "gte" as const, value: 400 },
          { kind: "predicate" as const, field: "path" as const, operator: "contains" as const, value: "" },
        ] },
      ],
    };
    const normalized = normalizeFilterExpression(nested);
    assert.deepEqual(parseFilterExpression(serializeFilterExpression(normalized)), normalized);
    assert.equal(normalized?.kind === "group" && normalized.children[1].kind === "predicate", true);
  });
});

describe("request lab navigation", () => {
  it("uses a first-class workspace and carries selected traffic into a draft", async () => {
    const [app, traffic, workbench, styles, requestCode] = await Promise.all([
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      readFile(new URL("../src/requestCode.ts", import.meta.url), "utf8"),
    ]);

    assert.match(app, /primaryNavigationGroups/);
    assert.match(app, /label: "请求工具", views: \["lab"\]/);
    assert.match(app, /activeView === "lab"/);
    assert.match(app, /activeView === "lab" \? "is-workbench-hidden"/);
    assert.match(traffic, /createFromSelection: selectedRequests\.length === 1/);
    assert.match(traffic, /onOpenWorkbench\("lab", selectedRequests, \{ createFromSelection: true \}\)/);
    assert.doesNotMatch(workbench, /modal-backdrop|workbench-backdrop/);
    assert.match(workbench, /autoCreateFromSelection/);
    assert.match(workbench, /正在创建可编辑请求/);
    assert.match(workbench, /aria-label="请求实验室工具"/);
    assert.match(workbench, /空白请求/);
    assert.match(workbench, /从抓包创建/);
    assert.match(workbench, /onSelectCapture/);
    assert.match(workbench, /title="草稿列表"/);
    assert.match(workbench, /title="生成代码"/);
    assert.match(workbench, /aria-label="代码语言"/);
    assert.match(workbench, /requestCodeTemplates/);
    assert.match(requestCode, /Python \(requests\)/);
    assert.match(requestCode, /Java \(HttpClient\)/);
    assert.match(workbench, /list_request_cookies/);
    assert.match(workbench, /CookieJarManager/);
    assert.match(workbench, /delete_request_cookie/);
    assert.match(workbench, /<option value="query">Query<\/option>/);
    assert.match(styles, /grid-template-rows: 44px minmax\(0, 1fr\)/);
    assert.match(styles, /\.lab-cookie-list/);
    assert.doesNotMatch(styles, /grid-template-columns: 148px minmax\(0, 1fr\)/);
  });

  it("keeps the navigation rail width stable when Request Lab hides the session panel", async () => {
    const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
    const responsiveShellStates = String.raw`\.app-shell,\s*\.app-shell:has\(\.sessions-panel\.is-compact\),\s*\.app-shell:has\(\.sessions-panel\.is-workbench-hidden\)`;

    assert.match(
      styles,
      new RegExp(`${responsiveShellStates}\\s*\\{\\s*grid-template-columns: 58px minmax\\(0, 1fr\\);`),
    );
    assert.match(
      styles,
      new RegExp(`${responsiveShellStates}\\s*\\{\\s*grid-template-columns: 52px minmax\\(0, 1fr\\);`),
    );
  });

  it("uses compact, explicit creation controls for empty environment lists", async () => {
    const [workbench, styles] = await Promise.all([
      readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
    ]);

    assert.match(workbench, /className="environment-global-create"/);
    assert.match(workbench, /className="environment-create__submit"/);
    assert.match(workbench, /aria-label="创建命名环境"/);
    assert.match(styles, /button\.environment-global-create[^}]+border: 1px dashed/);
    assert.match(styles, /\.environment-create__submit[^}]+place-items: center/);
  });

  it("makes collection defaults visible and independently disableable", async () => {
    const [workbench, styles, types] = await Promise.all([
      readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      readFile(new URL("../src/types.ts", import.meta.url), "utf8"),
    ]);

    assert.match(types, /defaultHeaders: HeaderEntry\[\]/);
    assert.match(types, /defaultAuth: Record<string, unknown>/);
    assert.match(workbench, /CollectionDefaultsPanel/);
    assert.match(workbench, /title="集合公共配置"/);
    assert.match(workbench, /inheritCollection/);
    assert.match(workbench, /请求同名项优先/);
    assert.match(workbench, /scopeLabel="公共"/);
    assert.match(workbench, /Auth 本机加密/);
    assert.match(styles, /\.lab-inheritance-bar/);
    assert.match(styles, /\.collection-defaults__content/);
  });

  it("keeps collection search, explicit multi-select and batch organization visible", async () => {
    const [workbench, styles, types] = await Promise.all([
      readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      readFile(new URL("../src/types.ts", import.meta.url), "utf8"),
    ]);

    assert.match(types, /tags: string\[\]/);
    assert.match(types, /RequestDraftBatchUpdateInput/);
    assert.match(workbench, /aria-label="搜索请求集合"/);
    assert.match(workbench, /matchesRequestDraftSearch/);
    assert.match(workbench, /update_request_drafts_batch/);
    assert.match(workbench, /collection-batch-bar/);
    assert.match(workbench, /一次最多整理 500 条请求/);
    assert.match(styles, /\.collection-search-bar/);
    assert.match(styles, /\.collection-draft-row\.is-selected/);
    assert.match(styles, /\.collection-batch-tags/);
  });

  it("uses the Codex accent for collection interaction without native button fills", async () => {
    const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");

    assert.match(styles, /--codex-accent: #339cff;/);
    assert.match(styles, /\.request-workbench__nav button\.is-active\s*\{[^}]*var\(--codex-accent-soft\)[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /\.collection-tree-label\s*\{[^}]*background: transparent;/s);
    assert.match(styles, /\.collection-folder-tree\s*\{[^}]*background: transparent;/s);
    assert.match(styles, /\.collection-draft-main\s*\{[^}]*background: transparent;/s);
    assert.match(styles, /\.collection-tree-root\.is-active,[^}]+\{[^}]*var\(--codex-accent-soft\)[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /\.collection-tree-root\.is-active > svg,[^}]+\{[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /\.collection-draft-main > \.method\s*\{[^}]*var\(--codex-accent-ink\)[^}]*var\(--codex-accent-soft\)[^}]*var\(--codex-accent-border\)/s);
    assert.match(styles, /\.collection-draft-row\.is-selected\s*\{[^}]*var\(--codex-accent-soft\)[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /\.collection-source-strip\s*\{[^}]*var\(--codex-accent-softest\)/s);
    assert.match(styles, /\.collection-batch-bar\s*\{[^}]*var\(--codex-accent-softest\)[^}]*var\(--codex-accent-border\)/s);
  });

  it("keeps artificial breakpoints visible, bounded and responsive", async () => {
    const [app, workbench, styles, types] = await Promise.all([
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      readFile(new URL("../src/types.ts", import.meta.url), "utf8"),
    ]);

    assert.match(types, /export interface BreakpointQueueSnapshot/);
    assert.match(app, /listen\("capture:\/\/breakpoints-changed"/);
    assert.match(app, /className="breakpoint-alert-button"/);
    assert.match(app, /title="打开人工断点队列"/);
    assert.match(workbench, /<option value="breakpoint">人工断点<\/option>/);
    assert.match(workbench, /min="5" max="300"/);
    assert.match(workbench, /最长等待（秒）/);
    assert.match(workbench, /自动放行/);
    assert.match(workbench, /invoke<BreakpointQueueSnapshot>\("get_breakpoint_queue"\)/);
    assert.match(workbench, /invoke\("resolve_breakpoint", \{ input \}\)/);
    assert.match(workbench, /lockedNames=\{activeTask\.stage === "request"/);
    assert.match(workbench, /正在放行/);
    assert.match(workbench, /正在中止/);
    assert.match(styles, /\.breakpoint-alert-button\s*\{[^}]*var\(--codex-accent-soft\)[^}]*var\(--codex-accent-border\)/s);
    assert.match(styles, /\.breakpoint-console__workspace\s*\{[^}]*grid-template-columns:/s);
    assert.match(styles, /\.breakpoint-queue > button\.is-active\s*\{[^}]*var\(--codex-accent-soft\)[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /@media \(max-width: 620px\)[\s\S]*\.breakpoint-console__workspace\s*\{[^}]*grid-template-columns: minmax\(0, 1fr\)/s);
  });

  it("keeps a cancellable request query visible in the grid status bar", async () => {
    const [traffic, styles, app] = await Promise.all([
      readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
    ]);

    assert.match(traffic, /onCancelRequestQuery: \(\) => void/);
    assert.match(traffic, /className="request-query-progress"[^>]*role="status"/);
    assert.match(traffic, /data-testid="cancel-request-query"/);
    assert.match(traffic, /cancelling \? "正在停止" : "正在载入"/);
    assert.match(traffic, /traffic-empty traffic-empty--loading/);
    assert.match(app, /invoke<boolean>\("cancel_request_query", \{ queryId \}\)/);
    assert.match(app, /invoke<RequestQueryCancellationAck>\("cancel_request_query_and_wait", \{ queryId \}\)/);
    assert.match(app, /waitForNextPaint\(\)/);
    assert.match(styles, /\.request-query-progress\s*\{[^}]*var\(--codex-accent-softest\)[^}]*var\(--codex-accent-border\)/s);
  });

  it("previews all OpenAPI sync states and keeps destructive choices explicit", async () => {
    const [workbench, styles, types] = await Promise.all([
      readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      readFile(new URL("../src/types.ts", import.meta.url), "utf8"),
    ]);

    assert.match(types, /export interface CollectionSyncPreview/);
    assert.match(types, /sourceFormat\?: string/);
    assert.match(workbench, /title="同步 OpenAPI 规范"/);
    assert.match(workbench, /change\.kind !== "remove"/);
    assert.match(workbench, /新增 \{counts\.add\}/);
    assert.match(workbench, /修改 \{counts\.modify\}/);
    assert.match(workbench, /已删除 \{counts\.remove\}/);
    assert.match(workbench, /应用新增和修改/);
    assert.match(workbench, /解除关联，草稿保留/);
    assert.match(workbench, /规范删除不会删除草稿/);
    assert.match(workbench, /保留名称、目录、标签、环境和 Auth/);
    assert.match(styles, /\.collection-sync-kind\.is-add/);
    assert.match(styles, /\.collection-sync-kind\.is-modify/);
    assert.match(styles, /\.collection-sync-kind\.is-remove/);
  });

  it("exposes browser and common API-tool imports as a first-class collection action", async () => {
    const workbench = await readFile(
      new URL("../src/components/RequestWorkbench.tsx", import.meta.url),
      "utf8",
    );

    assert.match(workbench, /className="collection-import-action"/);
    assert.match(workbench, /导入 HAR \/ API 集合/);
    assert.match(workbench, /HAR \/ Postman \/ Insomnia \/ OpenAPI \/ ShowNet/);
    assert.match(workbench, /insomnia: "Insomnia"/);
    assert.match(workbench, /shownet: "ShowNet JSON"/);
  });

  it("exposes executed mirror, response, weak-network and breakpoint rule capabilities", async () => {
    const [workbench, styles, ruleDraft] = await Promise.all([
      readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      readFile(new URL("../src/captureRuleDraft.ts", import.meta.url), "utf8"),
    ]);

    assert.match(workbench, /<option value="response">响应阶段<\/option>/);
    assert.match(workbench, /<option value="connection">连接阶段<\/option>/);
    assert.match(workbench, /<option value="mirror">域名镜像<\/option>/);
    assert.match(workbench, /兼容模式/);
    assert.match(workbench, /测试环境/);
    assert.match(workbench, /Host \/ SNI：原域名/);
    assert.match(workbench, /<option value="response\.header">响应 Header<\/option>/);
    assert.match(workbench, /<option value="response\.status">响应状态<\/option>/);
    assert.match(workbench, /<option value="response\.body">响应正文<\/option>/);
    assert.match(workbench, /<option value="request\.body">请求正文<\/option>/);
    assert.match(workbench, /aria-label=\{`操作 \$\{index \+ 1\} 正文`\}/);
    assert.match(workbench, /仅处理完整 UTF-8 文本/);
    assert.match(workbench, /流量正文不超过 2 MiB/);
    assert.match(workbench, /长度自动维护/);
    assert.match(workbench, /<option value="throttle">弱网条件<\/option>/);
    assert.match(workbench, /<option value="breakpoint">人工断点<\/option>/);
    assert.match(workbench, /<option value="redirect">请求转发（Map Remote）<\/option>/);
    assert.match(workbench, /转发目标 URL/);
    assert.match(workbench, /排除 URL（可选）/);
    assert.match(workbench, /保留原 Host/);
    assert.match(workbench, /保留认证与 Cookie/);
    assert.match(workbench, /允许 HTTPS → HTTP/);
    assert.match(workbench, /随机抖动 ms/);
    assert.match(workbench, /上行 Kbps/);
    assert.match(workbench, /下行 Kbps/);
    assert.match(workbench, /丢包率 %/);
    assert.match(workbench, /草稿默认停用/);
    assert.match(workbench, /确认并启用规则/);
    assert.match(workbench, /rule-execution-traces/);
    assert.match(ruleDraft, /MANAGED_HEADERS/);
    assert.match(ruleDraft, /mirrorTargetHost/);
    assert.match(ruleDraft, /identity: draft\.mirrorIdentity/);
    assert.match(styles, /\.mirror-identity-control button\.is-active/);
    assert.match(styles, /\.rule-operation-fields\.is-body textarea/);
    assert.match(styles, /\.rule-body-safety/);
    assert.match(styles, /\.rule-redirect-options/);
    assert.match(styles, /\.rule-redirect-safety/);
    assert.match(styles, /\.request-workbench__nav > button:focus-visible\s*\{[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /@media \(max-width: 900px\)[\s\S]*\.rule-operation-row[\s\S]*\.rule-action-settings/);
    assert.match(styles, /@media \(max-width: 620px\)[\s\S]*\.rule-execution-traces article/);
  });
});
