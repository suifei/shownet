import type {
  AnalysisMode,
  RequestListItem,
  SkillDefinition,
  SkillPlan,
  ToolDefinition,
} from "./types";

export const builtInSkillPreview: SkillDefinition[] = [
  skill(
    "noise-filter",
    "智能噪声过滤",
    "1.3.0",
    "分析基础",
    "Phase 1 请求相关性筛选与确定性兜底",
    "请求不少于 20 条时自动启用；性能模式保留全量请求",
    ["shownet_list_requests", "shownet_get_request"],
    ["读取会话", "读取完整请求"],
    ["保留鉴权、写操作、错误、慢请求、风险项和 Hook 关联请求", "过滤静态资源、遥测、预检和重复噪声", "模型筛选失败时回退到确定性规则结果"],
    ["关键请求集合", "完整请求索引", "筛选理由"],
  ),
  skill(
    "api-reverse",
    "API 协议逆向",
    "2.2.0",
    "协议分析",
    "接口、参数、鉴权、状态变化与调用链还原",
    "API 模式固定启用；自动模式检测到 XHR、Fetch 或写操作时启用",
    ["shownet_list_requests", "shownet_get_request", "shownet_generate_code"],
    ["读取会话", "读取完整请求", "生成完整请求代码"],
    ["建立端点清单和请求依赖链", "推断鉴权凭据的获取、刷新和传递过程", "区分证据、推断与待验证项"],
    ["端点矩阵", "鉴权链路", "数据模型", "复现模板"],
  ),
  skill(
    "security-audit",
    "安全审计",
    "1.5.0",
    "风险检测",
    "敏感数据、鉴权边界与错误泄露审计",
    "安全模式固定启用；自动模式检测到风险标记或错误响应时启用",
    ["shownet_list_requests", "shownet_get_request"],
    ["读取会话", "读取完整请求"],
    ["仅报告可由抓包证据支持的问题", "区分已确认风险与需要主动验证的假设", "检查凭据传输、跨域、缓存和安全响应头"],
    ["风险分级", "证据引用", "验证步骤", "修复建议"],
  ),
  skill(
    "realtime-protocol",
    "实时协议分析",
    "1.1.0",
    "协议分析",
    "还原 WebSocket 双向消息与 SSE 单向事件流、心跳和完整性",
    "会话中检测到 WebSocket 或 SSE 请求时自动启用",
    ["shownet_list_requests", "shownet_get_request", "shownet_get_websocket_frames", "shownet_get_sse_events"],
    ["读取完整请求", "读取有界完整 WebSocket / SSE 采样"],
    ["先识别实时协议，再按方向或事件顺序重建消息流", "识别 WebSocket 控制帧/关闭语义，以及 SSE event/id/retry/注释/心跳", "区分完整、提前关闭、压缩未实时解析、截断与达到保存上限的证据"],
    ["消息或事件时序", "订阅与重连语义", "状态机", "证据缺口"],
  ),
  skill(
    "performance-analysis",
    "性能分析",
    "1.2.0",
    "诊断",
    "慢请求、串行阻塞、重复调用与缓存分析",
    "性能模式固定启用；自动模式检测到慢请求或重复端点时启用",
    ["shownet_list_requests", "shownet_get_request"],
    ["读取会话", "读取完整请求"],
    ["保留全量时序避免筛选破坏瀑布关系", "识别串行依赖、重复请求和大载荷", "按影响和实现成本给出优化优先级"],
    ["时序瓶颈", "重复请求", "缓存诊断", "优化优先级"],
  ),
  skill(
    "crypto-reverse",
    "JS 加密逆向",
    "2.4.0",
    "加密分析",
    "关联 Hook、网络参数、代码片段与 TLS 指纹证据",
    "加密模式固定启用；自动模式检测到 Hook、加密代码或签名参数时启用",
    ["shownet_get_hooks", "shownet_get_request", "shownet_get_crypto_snippets", "shownet_get_tls_fingerprints"],
    ["读取完整 Hook", "读取完整请求", "读取完整代码", "读取 TLS 指纹"],
    ["还原明文到密文或签名的转换链", "识别算法、密钥来源、随机量和参数排序", "用调用证据区分真实算法和相似命名"],
    ["算法证据", "参数变换链", "密钥线索", "复现框架"],
  ),
  {
    ...skill(
      "dynamic-signature",
      "动态防护协议分析",
      "0.14.0",
      "加密分析",
      "聚合 AWS WAF、Akamai、Cloudflare、reCAPTCHA 的 challenge/captcha/telemetry/token 与动态算法证据",
      "检测到 awswaf、challenge、captcha、telemetry、sensor、_abck、bm_sz、akamai、cf-chl、recaptcha 或业务签名参数时启用",
      [
        "shownet_list_requests",
        "shownet_get_request",
        "shownet_get_hooks",
        "shownet_get_crypto_snippets",
        "shownet_get_tls_fingerprints",
        "shownet_analyze_dynamic_protection",
        "shownet_decode_challenge_js",
        "shownet_eval_scorecard",
        "shownet_build_signature_harness",
      ],
      ["读取完整请求", "读取完整 Hook", "读取 TLS 指纹", "沙箱 decoder", "机检 scorecard L0/L1/L2"],
      [
        "按提供商、脚本、端点和时序聚合动态防护证据",
        "必须调用 shownet_eval_scorecard；禁止工具失败时虚构满分",
        "CAPTCHA 条目计数≠字段级；报告 fidelity 标签",
        "严格区分已确认、合理推断和本次未捕获项",
      ],
      ["防护提供商候选", "有序协议链", "协议字段 schema", "scorecard L0/L1/L2", "fidelity 标签", "未捕获项"],
    ),
    status: "beta",
  },
  skill(
    "algorithm-replay",
    "算法还原与重播",
    "1.1.0",
    "工程落地",
    "从分析报告/Hook/代码片段还原算法流水线并生成可校验的多语言重播实现；VMP/魔改走 trace 混合策略",
    "crypto/auto 模式在检测到动态防护、签名参数、Hook 或加密代码时启用",
    [
      "shownet_get_report",
      "shownet_analyze_dynamic_protection",
      "shownet_decode_challenge_js",
      "shownet_eval_scorecard",
      "shownet_build_signature_harness",
      "shownet_build_algorithm_replay",
      "shownet_export_analysis_artifacts",
      "shownet_get_crypto_snippets",
      "shownet_get_hooks",
    ],
    ["读取分析报告", "读取 Hook/代码/防护 schema", "算法还原与重播实现", "导出算法包"],
    [
      "输出 ALGORITHM_SPEC 与可运行重播（已还原步骤）",
      "VMP/魔改仅 trace 策略，不伪造完整 VM",
      "离线 validate_against_capture 对齐抓包",
      "禁止嵌入明文密钥",
    ],
    ["ALGORITHM_SPEC", "多语言重播实现", "分析报告", "校验清单", "导出目录"],
  ),
  skill(
    "auto-crawler",
    "自动爬虫代码生成",
    "1.0.0",
    "工程落地",
    "从抓包分析生成多语言、依赖尽量少的客户端源码：JA3/JA4 保真标签、代理 env、算法还原模式、离线对照抓包校验与测试文档",
    "crypto/auto 在检测到动态防护、签名参数、Hook 或加密代码时与算法重播一并启用",
    [
      "shownet_get_report",
      "shownet_analyze_dynamic_protection",
      "shownet_build_algorithm_replay",
      "shownet_build_auto_crawler",
      "shownet_export_auto_crawler",
      "shownet_export_analysis_artifacts",
      "shownet_get_tls_fingerprints",
      "shownet_get_hooks",
    ],
    ["读取会话与防护 schema", "生成多语言爬虫客户端", "离线对照抓包校验", "导出爬虫包"],
    [
      "生成 client_crawler 源码（py/js/ts/go/rust 等）",
      "诚实标注 JA3/JA4 与出站 TLS 保真，不宣称完整 impersonate",
      "代理仅 SHOWNET_PROXY / HTTPS_PROXY 等 env",
      "算法模式按证据标注；禁止嵌入密钥/token",
      "输出 CRAWLER_ANALYSIS / TEST_STATUS / VALIDATION_REPORT",
    ],
    ["client_crawler.*", "CAPTURE_SHAPE.json", "CRAWLER_ANALYSIS.md", "TEST_STATUS.md", "导出目录"],
  ),
  skill(
    "web-risk-lab",
    "Web 风控研究 Lab",
    "1.0.0",
    "浏览器实验",
    "固定调试参数、请求体劫持、JS 沙箱、对象自吐、物理点击计划与视觉验证码包",
    "crypto/auto 检测到动态防护/验证码/交互 Hook 时启用",
    [
      "shownet_list_js_debug_profiles",
      "shownet_build_web_risk_lab",
      "shownet_seed_web_risk_fixture",
      "shownet_run_offline_lab_probe",
      "shownet_browser_install_lab",
      "shownet_browser_status",
      "shownet_browser_evaluate",
      "shownet_browser_click",
      "shownet_browser_screenshot",
      "shownet_browser_navigate",
      "shownet_browser_insert_text",
      "shownet_eval_js_sandbox",
      "shownet_build_request_hijack_script",
      "shownet_build_object_dump_script",
      "shownet_plan_physical_interactions",
      "shownet_build_vision_captcha_package",
      "shownet_map_vision_captcha_indices",
      "shownet_solve_vision_captcha",
      "shownet_get_hooks",
      "shownet_decode_challenge_js",
      "shownet_analyze_dynamic_protection",
    ],
    ["读取会话/Hook", "Browser 总线点/截/评", "一键装 Lab", "离线探针", "视觉 VLM"],
    [
      "固定 UA/viewport/webdriver 调试档",
      "fixture → offline probe → objectDump",
      "browser_install_lab 注入并返回自吐",
      "browser_* 统一总线执行",
      "截图 + VLM 宫格映射点击",
    ],
    ["调试档", "Lab/objectDump", "offline probe", "browser_* 结果", "视觉索引/坐标"],
  ),
];

export const mcpToolPreview: ToolDefinition[] = [
  readTool("shownet_runtime_status", "读取抓包代理、CA 与运行状态"),
  readTool("shownet_list_sessions", "列出统一抓包会话及来源统计"),
  readTool("shownet_list_requests", "列出保留查询实际值的会话请求摘要"),
  readTool("shownet_get_request", "读取单条完整请求、TLS 指纹与关联 Hook"),
  readTool("shownet_get_hooks", "读取会话中的完整加密 Hook"),
  readTool("shownet_get_crypto_snippets", "读取从 JavaScript 语法树提取的完整有界加密代码"),
  readTool("shownet_get_websocket_frames", "读取保留实际值的有界 WebSocket 消息"),
  readTool("shownet_get_sse_events", "读取保留实际值的有界 SSE 事件、字段、注释与完整性证据"),
  readTool("shownet_get_tls_fingerprints", "读取 JA3/JA4、HTTP/2 SETTINGS/窗口/优先级与出站 TLS 说明"),
  readTool("shownet_analyze_dynamic_protection", "聚合动态防护链路、协议 schema、JS 静态特征与未捕获项"),
  readTool("shownet_decode_challenge_js", "受限沙箱 string-array decoder（完整配置候选）"),
  readTool("shownet_eval_scorecard", "机检 L0/L1/L2 分轨 scorecard（禁止虚构满分）"),
  readTool("shownet_get_report", "读取会话最新 AI 分析报告"),
  readTool("shownet_get_skill_runs", "读取最新分析的 Skill 版本、权限、工具调用与耗时审计"),
  readTool("shownet_generate_code", "生成包含完整凭据与正文值的请求调用代码"),
  readTool("shownet_build_signature_harness", "生成版本化动态签名适配器与重放骨架"),
  readTool("shownet_build_algorithm_replay", "生成指定语言的算法重播包（报告/schema/源码）"),
  readTool("shownet_list_js_debug_profiles", "列出 Web 风控调试固定参数档"),
  readTool("shownet_build_web_risk_lab", "生成劫持/自吐/点击/视觉验证 lab 包"),
  readTool("shownet_eval_js_sandbox", "受限 JS 沙箱求值"),
  readTool("shownet_build_request_hijack_script", "生成请求体劫持脚本"),
  readTool("shownet_build_object_dump_script", "生成对象 Hook 自吐脚本"),
  readTool("shownet_plan_physical_interactions", "生成物理点击 CDP 计划"),
  readTool("shownet_build_vision_captcha_package", "生成视觉验证码 VLM 包"),
  readTool("shownet_run_offline_lab_probe", "离线 Lab 探针：注入契约 + objectDump"),
  readTool("shownet_map_vision_captcha_indices", "宫格索引 → 点击坐标"),
  readTool("shownet_list_skills", "列出内置 Skill 的版本化执行契约"),
  readTool("shownet_plan_analysis", "按会话证据生成 Skill 与工具执行计划"),
  // Browser bus / write when MCP writes enabled
  readTool("shownet_browser_status", "统一 Browser 总线状态"),
  readTool("shownet_browser_evaluate", "Browser 总线 Runtime.evaluate"),
  readTool("shownet_browser_click", "Browser 总线物理点击"),
  readTool("shownet_browser_screenshot", "Browser 总线截图"),
  readTool("shownet_browser_navigate", "Browser 总线导航"),
  readTool("shownet_browser_install_lab", "一键注入 Lab 并返回 objectDump"),
  readTool("shownet_solve_vision_captcha", "视觉验证码 VLM 求解/映射/可选点击"),
  readTool("shownet_seed_web_risk_fixture", "种子 VJ/AWS 形态 fixture 会话"),
];

export function buildPreviewSkillPlan(mode: AnalysisMode, requests: RequestListItem[]): SkillPlan {
  const selected = new Set<string>();
  const reasons: string[] = [];

  if (requests.length >= 20) {
    selected.add("noise-filter");
    reasons.push(`${requests.length} 条请求需要 Phase 1 降噪`);
  }

  const apiCount = requests.filter((request) => request.type === "xhr" || request.type === "fetch").length;
  const hasErrorOrRisk = requests.some((request) => (request.status ?? 0) >= 400 || request.risk !== "none");
  const slowCount = requests.filter((request) => (request.durationMs ?? 0) >= 1_000).length;
  const hasHook = requests.some((request) => request.hasHook);
  const hasCryptoCode = requests.some((request) => request.cryptoSnippetCount > 0);
  const hasSignature = requests.some(hasSignatureMarker);
  const hasDynamic = requests.some(hasDynamicMarker);
  const hasWebSocket = requests.some((request) => request.type === "websocket");
  const hasSse = requests.some((request) => request.type === "sse");
  const endpoints = new Set<string>();
  const hasDuplicate = requests.some((request) => {
    const endpoint = `${request.method} ${request.host}${request.path}`;
    if (endpoints.has(endpoint)) return true;
    endpoints.add(endpoint);
    return false;
  });

  if (mode === "api") {
    selected.add("api-reverse");
    reasons.push("用户选择 API 协议逆向");
  } else if (mode === "security") {
    selected.add("security-audit");
    reasons.push("用户选择安全审计");
  } else if (mode === "performance") {
    selected.add("performance-analysis");
    reasons.push("性能分析保留完整请求时序");
  } else if (mode === "crypto") {
    selected.add("crypto-reverse");
    reasons.push("用户选择 JS 加密逆向");
  } else {
    if (apiCount > 0 || requests.some((request) => isMutation(request.method))) {
      selected.add("api-reverse");
      reasons.push(`检测到 ${apiCount} 条 API 请求或状态变更操作`);
    }
    if (hasErrorOrRisk) {
      selected.add("security-audit");
      reasons.push("检测到错误响应或风险标记");
    }
    if (slowCount > 0 || hasDuplicate) {
      selected.add("performance-analysis");
      reasons.push(`检测到 ${slowCount} 条慢请求或重复端点`);
    }
    if (hasHook || hasCryptoCode || hasSignature) {
      selected.add("crypto-reverse");
      reasons.push("检测到 Hook、加密代码或签名参数");
    }
    if (selected.size === 0) {
      selected.add("api-reverse");
      reasons.push("使用通用协议分析路径");
    }
  }

  if (hasDynamic && (mode === "auto" || mode === "crypto")) {
    selected.add("dynamic-signature");
    reasons.push("检测到动态签名或传感器端点线索");
  }
  if (
    (mode === "auto" || mode === "crypto") &&
    (hasDynamic || hasSignature || hasHook || hasCryptoCode)
  ) {
    selected.add("algorithm-replay");
    reasons.push("检测到可工程化的动态算法/签名/Hook 证据，启用算法重播编程");
    selected.add("auto-crawler");
    reasons.push("启用自动爬虫代码生成：多语言客户端 + JA3/代理/算法模式 + 离线对照抓包校验");
  }
  if (
    (mode === "auto" || mode === "crypto") &&
    (hasDynamic || hasHook || hasCryptoCode)
  ) {
    selected.add("web-risk-lab");
    reasons.push("启用 Web 风控研究 Lab：固定参数/劫持/沙箱/点击/视觉验证");
  }
  if (hasWebSocket || hasSse) {
    selected.add("realtime-protocol");
    reasons.push(hasWebSocket && hasSse
      ? "检测到 WebSocket 与 SSE 实时消息流"
      : hasWebSocket
        ? "检测到 WebSocket 升级和双向消息流"
        : "检测到 SSE 单向事件流和重连语义");
  }

  const selectedSkills = builtInSkillPreview.filter((entry) => selected.has(entry.id));
  const toolNames = [...new Set(selectedSkills.flatMap((entry) => entry.id === "noise-filter" ? [] : entry.tools))].sort();
  const stages: SkillPlan["stages"] = selectedSkills.map((entry) => ({
    id: entry.id === "noise-filter" ? "filter" : `skill-${entry.id}`,
    label: entry.id === "noise-filter" ? "智能过滤" : entry.name,
    detail: entry.id === "noise-filter" ? "Phase 1" : entry.version,
    skillId: entry.id,
    kind: "skill" as const,
    suggestedToolCount: entry.tools.length,
    requiredOutputCount: entry.outputs.length,
    maxRetries: 1,
  }));
  stages.push(
    { id: "quality-gate", label: "产物校验", detail: "证据与契约", skillId: "quality-gate", kind: "decision", suggestedToolCount: 0, requiredOutputCount: 3, maxRetries: 0 },
    { id: "report", label: "生成报告", detail: "Markdown + Evidence", skillId: "report", kind: "report", suggestedToolCount: 0, requiredOutputCount: 2, maxRetries: 1 },
  );

  return {
    mode,
    selectedSkillIds: selectedSkills.map((entry) => entry.id),
    toolNames,
    reasons,
    stages,
  };
}

function skill(
  id: string,
  name: string,
  version: string,
  category: string,
  summary: string,
  trigger: string,
  tools: string[],
  permissions: string[],
  objectives: string[],
  outputs: string[],
): SkillDefinition {
  return { id, name, version, category, summary, status: "ready", trigger, tools, permissions, objectives, outputs };
}

function readTool(name: string, description: string): ToolDefinition {
  return { name, description, inputSchema: { type: "object" }, access: "read" };
}

function isMutation(method: string) {
  return method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE";
}

function hasSignatureMarker(request: RequestListItem) {
  const evidence = [
    request.path,
    request.query ?? "",
    request.type,
  ].join(" ").toLowerCase();
  return [
    "signature",
    "x-sign",
    "x-signature",
    "x-request-time",
    "x-request-nonce",
    "x-device-id",
    "x-client-machine-id",
    "x-session-id",
    "x-pow-nonce",
    "x-aws-waf-token",
    "sign=",
    "hmac",
    "nonce",
    "digest",
  ].some((marker) => evidence.includes(marker));
}

function hasDynamicMarker(request: RequestListItem) {
  const evidence = [
    request.host,
    request.path,
    request.query ?? "",
    request.type ?? "",
  ]
    .join(" ")
    .toLowerCase();
  return [
    "awswaf",
    "aws-waf",
    "aws-waf-token",
    "x-aws-waf-token",
    "awswaf_session_storage",
    "challenge.js",
    "captcha.js",
    "mp_verify",
    "edge.sdk.awswaf",
    "edge.captcha",
    "token.awswaf",
    "captcha.awswaf",
    "telemetry",
    "/problem",
    "/verify",
    "/voucher",
    "gokuprops",
    "recaptcha",
    "grecaptcha",
    "cf-chl",
    "cf_clearance",
    "__cf_bm",
    "turnstile",
    "akamai",
    "sensor_data",
    "sensordata",
    "_abck",
    "bm_sz",
    "sec-cpt",
    "bot-manager",
  ].some((marker) => evidence.includes(marker));
}
