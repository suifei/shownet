/**
 * Single source of truth for MITM Advanced Console workflow phases,
 * per-tab guidance, and capture-vs-analysis capability mapping.
 * UI, Agent skill previews, and structural tests import this module.
 */

export type WorkflowPhaseId = "capture" | "evidence" | "analysis" | "export";

export type ConsoleTabId =
  | "overview"
  | "capture"
  | "hooks"
  | "rules"
  | "fingerprint"
  | "px"
  | "recaptcha"
  | "config";

export type CapabilityPhase = "capture" | "analysis" | "both";

export interface WorkflowStage {
  id: WorkflowPhaseId;
  step: number;
  label: string;
  shortLabel: string;
  summary: string;
  beginnerTip: string;
  primaryNav: string;
}

export interface ConsoleTabGuide {
  id: ConsoleTabId;
  label: string;
  phase: WorkflowPhaseId;
  whenToUse: string;
  bestPractice: string;
  nextStep: string;
  emptyHint: string;
  /** Real UI / Tauri invoke names used by this tab (not agent tool names). */
  uiActions: string[];
  /** Agent/MCP tools that read evidence this tab surfaces (must exist in registry). */
  agentTools: string[];
}

export interface CapabilityEntry {
  id: string;
  name: string;
  phase: CapabilityPhase;
  /** When this capability is active in the product lifecycle. */
  when: string;
  /** How it connects to traffic / browser / settings / AI. */
  linksTo: string;
  /** Real entry points: UI, Tauri command, or MCP/agent tool name. */
  entryPoints: string[];
  honesty?: string;
}

/** Ordered beginner workflow shown at the top of Advanced Console. */
export const WORKFLOW_STAGES: WorkflowStage[] = [
  {
    id: "capture",
    step: 1,
    label: "抓包",
    shortLabel: "1 抓包",
    summary: "装 CA（可选）· 代理/内嵌浏览器 · 出站 TLS 预置 · PX 开关",
    beginnerTip: "只看网页：内嵌浏览器「开始抓包」即可，不必先装证书。",
    primaryNav: "浏览器 / 设置 · 抓包",
  },
  {
    id: "evidence",
    step: 2,
    label: "证据",
    shortLabel: "2 证据",
    summary: "流量列表 · Hook · TLS 指纹 · PX/reCAPTCHA 标记",
    beginnerTip: "在「流量」点开请求，再回高级控制台看指纹与 PX 证据。",
    primaryNav: "流量 / 高级控制台",
  },
  {
    id: "analysis",
    step: 3,
    label: "AI 分析",
    shortLabel: "3 分析",
    summary: "Agent 只读会话证据：指纹、Hook、PX 结构解码、动态防护 Skill",
    beginnerTip: "有请求后进「AI 分析」选加密/API 模式；Agent 会自动调取证工具。",
    primaryNav: "AI 分析",
  },
  {
    id: "export",
    step: 4,
    label: "导出",
    shortLabel: "4 导出",
    summary: "算法重放包 · Request Lab 客户端代码 · 集合导入导出",
    beginnerTip: "报告确认后导出算法重放，或在实验室生成多语言调用代码。",
    primaryNav: "报告导出 / 请求实验室",
  },
];

/** Tab metadata: when / next / empty / real wiring. */
export const CONSOLE_TAB_GUIDES: ConsoleTabGuide[] = [
  {
    id: "overview",
    label: "总览",
    phase: "capture",
    whenToUse: "第一次打开高级控制台：先看阶段条与能力分工，再进具体分区。",
    bestPractice: "按 抓包→证据→分析→导出 顺序；不要在空会话上改 PX/指纹期望。",
    nextStep: "无流量时打开内嵌浏览器开始抓包；有流量时查看指纹或 PX。",
    emptyHint: "尚未选择会话或会话为空时，先去流量/浏览器产生请求。",
    uiActions: ["nav:advanced", "nav:browser", "nav:traffic", "nav:analysis"],
    agentTools: [
      "shownet_list_requests",
      "shownet_get_tls_fingerprints",
      "shownet_get_outbound_tls_status",
      "shownet_list_px_evidence",
    ],
  },
  {
    id: "capture",
    label: "数据包捕获",
    phase: "capture",
    whenToUse: "抓包进行中：确认代理端口、会话请求量、快速跳转流量工作台。",
    bestPractice: "先保证代理/浏览器在跑；高级区只做摘要，详细检视用「流量」。",
    nextStep: "打开流量视图筛选关键接口，或继续配置出站 TLS / PX。",
    emptyHint: "当前会话 0 条请求：用内嵌浏览器开始抓包，或把系统代理指到本机端口。",
    uiActions: ["onOpenTraffic", "runtime.proxyPort"],
    agentTools: ["shownet_list_requests", "shownet_runtime_status"],
  },
  {
    id: "hooks",
    label: "Hook 管理",
    phase: "evidence",
    whenToUse: "内嵌浏览器抓包后：查看页面脚本前注入的加解密/网络 Hook。",
    bestPractice: "Hook 与代理请求按序关联；分析加密时务必先有 Hook 或 AST 片段。",
    nextStep: "打开浏览器 Hook 面板；有加密线索后启动 AI 加密逆向。",
    emptyHint: "暂无 Hook：在内嵌浏览器打开目标页并开始抓包，等待脚本注入。",
    uiActions: ["list_browser_hooks", "onOpenBrowser"],
    agentTools: ["shownet_get_hooks", "shownet_get_crypto_snippets"],
  },
  {
    id: "rules",
    label: "替换规则",
    phase: "capture",
    whenToUse: "抓包中需要改包、断点或镜像时：入口跳转到规则工作台。",
    bestPractice: "配合「拦截 ecData」标记后，在规则台对敏感字段做可控改写。",
    nextStep: "打开替换规则工作台编辑；改完回流量验证。",
    emptyHint: "规则本体在请求实验室，不在本页内联编辑。",
    uiActions: ["onOpenRules", "set_px_settings.interceptEcData"],
    agentTools: [],
  },
  {
    id: "fingerprint",
    label: "指纹数据",
    phase: "evidence",
    whenToUse: "MITM 解密 HTTPS 后：对照入站 JA3/JA4 与出站预置配方。",
    bestPractice: "看 ja3Parity / supportsFullBrowserJa3：当前 rustls 不为位级浏览器克隆。",
    nextStep: "需要改出站形象时去「配置」选 ClientHello 预置；分析时 Agent 会读指纹。",
    emptyHint: "暂无指纹：需 MITM 成功解密（装 CA + 代理到本机），隧道透传无本表。",
    uiActions: ["get_tls_fingerprints", "get_outbound_tls_profile"],
    agentTools: ["shownet_get_tls_fingerprints", "shownet_get_outbound_tls_status"],
  },
  {
    id: "px",
    label: "PX 证据",
    phase: "evidence",
    whenToUse: "会话出现 PerimeterX / HUMAN / ecData 相关请求时，查看证据、结构解码、标记对比或生成改写规则。",
    bestPractice: "解码是结构解析，不是无密钥硬破。先解码看结构，再决定对比字段还是生成可回滚的改写规则。",
    nextStep: "点请求解码查看字段；切到「对比」标记 A/B 后去流量做 diff，切到「改写」生成规则再进规则台验证。",
    emptyHint: "未发现 PX 证据：先抓含 PX 脚本/传感器的页面，或开启拦截 ecData 再操作。对比至少需要两条 PX 请求。",
    uiActions: ["list_px_evidence", "decode_px_payload", "get_px_settings", "compareA/B", "onOpenRules"],
    agentTools: ["shownet_list_px_evidence", "shownet_decode_px_payload", "shownet_get_request"],
  },
  {
    id: "recaptcha",
    label: "reCAPTCHA",
    phase: "evidence",
    whenToUse: "会话出现 recaptcha / grecaptcha 资源时快速定位。",
    bestPractice: "完整解题走 Web 风控 Lab / 视觉验证码工具，不在本页硬解。",
    nextStep: "有标记后用 AI 动态防护 Skill 或 Web 风控 Lab 继续。",
    emptyHint: "未捕获 reCAPTCHA 资源。",
    uiActions: ["request filter recaptcha"],
    agentTools: [
      "shownet_analyze_dynamic_protection",
      "shownet_build_vision_captcha_package",
      "shownet_solve_vision_captcha",
    ],
  },
  {
    id: "config",
    label: "配置",
    phase: "capture",
    whenToUse: "开抓前或抓包中：选择出站 ClientHello 预置、入站自动选档、跳转系统设置。",
    bestPractice: "优先 chrome150 等版本预置；开「入站自动选档」时观察指纹页映射结果。",
    nextStep: "改完预置后重新发起 HTTPS 请求再看指纹；系统 CA/端口在设置页。",
    emptyHint: "预置列表来自后端目录；若为空请检查 get_outbound_tls_profile。",
    uiActions: [
      "set_outbound_tls_profile",
      "set_outbound_tls_auto_from_inbound",
      "get_outbound_tls_profile",
      "onOpenSettings",
    ],
    agentTools: ["shownet_get_outbound_tls_status"],
  },
];

/**
 * Capture-time vs analysis-time capabilities (machine-readable).
 * entryPoints must match real UI invokes, Tauri commands, or MCP tool names.
 */
export const CAPABILITY_CATALOG: CapabilityEntry[] = [
  // —— Capture phase ——
  {
    id: "outbound-tls-preset",
    name: "出站 ClientHello 预置",
    phase: "capture",
    when: "MITM 出站握手前/中；在高级控制台「配置」或设置页选择",
    linksTo: "决定源站看到的出站配方；impersonate 引擎下主路径固定用 wreq 配方，预置只作用于 rustls 回退",
    entryPoints: [
      "set_outbound_tls_profile",
      "get_outbound_tls_profile",
      "shownet_get_outbound_tls_status",
    ],
    // Was "ja3Parity=false；supportsFullBrowserJa3=false（rustls）". Both are
    // live values that depend on the engine and on a measured handshake, and
    // this catalog is static — so the card asserted rustls-only while the
    // config panel beside it reported supportsFullBrowserJa3=true. State the
    // contract; the numbers belong to the status.
    honesty: "parity 仅在实测出站握手与浏览器目标一致时为真；当前引擎与实测值见「配置」页",
  },
  {
    id: "inbound-auto-preset",
    name: "入站自动选档",
    phase: "capture",
    when: "开启后按入站 JA3/JA4 启发式映射出站预置家族",
    linksTo: "配置开关 → 后续握手 → 指纹记录 selectedFromInbound",
    entryPoints: ["set_outbound_tls_auto_from_inbound", "shownet_get_outbound_tls_status"],
  },
  {
    id: "px-capture-toggles",
    name: "PX 解密 / 拦截 ecData",
    phase: "capture",
    when: "抓 PX 前打开；影响标记与后续证据收集",
    linksTo: "高级控制台顶栏开关 → 代理路径标记 → 证据列表",
    entryPoints: ["get_px_settings", "set_px_settings"],
    honesty: "结构解码非无密钥硬破",
  },
  {
    id: "browser-hook-inject",
    name: "浏览器 Hook 注入",
    phase: "capture",
    when: "内嵌浏览器开始抓包后，页面脚本前注入",
    linksTo: "浏览器视图 → Hook 事件 → 流量关联 → AI 读 Hook",
    entryPoints: ["list_browser_hooks", "shownet_get_hooks"],
  },
  {
    id: "proxy-capture",
    name: "代理 / 会话抓包",
    phase: "capture",
    when: "代理运行或内嵌浏览器抓包全程",
    linksTo: "流量列表与请求持久化",
    entryPoints: ["shownet_list_requests", "shownet_runtime_status", "onOpenTraffic"],
  },
  {
    id: "tls-fingerprint-record",
    name: "TLS 指纹记录",
    phase: "both",
    when: "MITM 成功时写入；分析时只读汇总",
    linksTo: "指纹 tab 展示；Agent shownet_get_tls_fingerprints",
    entryPoints: ["get_tls_fingerprints", "shownet_get_tls_fingerprints"],
    honesty: "入站客户端指纹 vs 出站 MITM 配方分列",
  },
  {
    id: "px-evidence-collect",
    name: "PX 证据收集与解码",
    phase: "both",
    when: "抓包中标记；证据/分析阶段列表与结构解码",
    linksTo: "PX tabs → decode_px_payload → Agent list/decode 工具",
    entryPoints: [
      "list_px_evidence",
      "decode_px_payload",
      "shownet_list_px_evidence",
      "shownet_decode_px_payload",
    ],
    honesty: "结构解析，非无密钥硬破 PerimeterX",
  },
  // —— Analysis phase ——
  {
    id: "agent-tls-read",
    name: "Agent 读取 TLS 指纹",
    phase: "analysis",
    when: "加密逆向 / 动态防护 / 自动爬虫 Skill 规划取证",
    linksTo: "AI 分析 Graph → MCP 工具调用",
    entryPoints: ["shownet_get_tls_fingerprints"],
  },
  {
    id: "agent-outbound-status",
    name: "Agent 读取出站 TLS 状态",
    phase: "analysis",
    when: "报告保真边界、JA3 诚实标签、当前预置",
    linksTo: "crypto / dynamic-signature / auto-crawler 取证",
    entryPoints: ["shownet_get_outbound_tls_status"],
    honesty: "工具描述声明 rustls 非位级全量对齐",
  },
  {
    id: "agent-px-read",
    name: "Agent 读取 PX 证据",
    phase: "analysis",
    when: "动态防护 / 加密分析需要 PX 结构时",
    linksTo: "dynamic-signature 等 Skill 工具列表",
    entryPoints: ["shownet_list_px_evidence", "shownet_decode_px_payload"],
  },
  {
    id: "agent-dynamic-protection",
    name: "动态防护聚合与 scorecard",
    phase: "analysis",
    when: "检测到 WAF/captcha/sensor 线索时",
    linksTo: "AI 分析 Skill 编排",
    entryPoints: [
      "shownet_analyze_dynamic_protection",
      "shownet_decode_challenge_js",
      "shownet_eval_scorecard",
      "shownet_build_signature_harness",
    ],
  },
  {
    id: "agent-hooks-crypto",
    name: "Hook 与加密代码取证",
    phase: "analysis",
    when: "JS 加密逆向 / 算法重放",
    linksTo: "crypto-reverse / algorithm-replay Skill",
    entryPoints: ["shownet_get_hooks", "shownet_get_crypto_snippets", "shownet_get_request"],
  },
  {
    id: "export-replay-code",
    name: "算法重放与客户端代码导出",
    phase: "analysis",
    when: "分析报告完成后",
    linksTo: "报告导出 / Request Lab / auto-crawler",
    entryPoints: [
      "shownet_build_algorithm_replay",
      "shownet_generate_code",
      "shownet_build_auto_crawler",
      "shownet_export_analysis_artifacts",
    ],
  },
];

export function tabGuide(id: ConsoleTabId): ConsoleTabGuide {
  const found = CONSOLE_TAB_GUIDES.find((tab) => tab.id === id);
  if (!found) {
    throw new Error(`unknown console tab: ${id}`);
  }
  return found;
}

export function capabilitiesForPhase(phase: CapabilityPhase | "capture" | "analysis"): CapabilityEntry[] {
  if (phase === "capture") {
    return CAPABILITY_CATALOG.filter((entry) => entry.phase === "capture" || entry.phase === "both");
  }
  if (phase === "analysis") {
    return CAPABILITY_CATALOG.filter((entry) => entry.phase === "analysis" || entry.phase === "both");
  }
  return CAPABILITY_CATALOG.filter((entry) => entry.phase === phase);
}

/** All agent tool names referenced by the capability catalog or tab guides. */
export function catalogAgentToolNames(): string[] {
  const names = new Set<string>();
  for (const entry of CAPABILITY_CATALOG) {
    for (const point of entry.entryPoints) {
      if (point.startsWith("shownet_")) names.add(point);
    }
  }
  for (const tab of CONSOLE_TAB_GUIDES) {
    for (const tool of tab.agentTools) names.add(tool);
  }
  return [...names].sort();
}

/** Suggest next workflow stage from simple session stats. */
export function suggestWorkflowStage(stats: {
  requestCount: number;
  hookCount: number;
  fingerprintCount: number;
  pxCount: number;
  hasReport?: boolean;
}): WorkflowPhaseId {
  if (stats.hasReport) return "export";
  if (stats.requestCount === 0) return "capture";
  if (stats.fingerprintCount > 0 || stats.hookCount > 0 || stats.pxCount > 0) {
    return "analysis";
  }
  return "evidence";
}

/**
 * The one line that tells the user what their traffic actually leaves as.
 *
 * It used to be a constant reading "rustls 配方（ja3Parity=false）" whatever the
 * engine was, so a build with the impersonate engine active showed a header
 * claiming rustls directly above a panel reporting `engine=impersonate`. A
 * banner whose whole job is honesty cannot be the one element that ignores the
 * status it sits next to.
 *
 * Undefined status keeps the conservative wording: before the backend answers,
 * the weaker claim is the true one.
 */
export function honestyBanner(
  status?: { engine?: string; ja3Parity?: boolean } | null,
): string {
  const engine =
    status?.engine === "impersonate"
      ? "wreq 的逐字节 Chrome 配方（产品固定，不可切回非浏览器出站）"
      : "rustls 配方（仅未链接 impersonate 的开发构建）";
  const parity = status?.ja3Parity === true ? "true" : "false";
  return `出站 TLS 为 ${engine}（ja3Parity=${parity}）；PX 解码为结构解析，非无密钥硬破。`;
}
