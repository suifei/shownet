use crate::models::RequestRecord;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillDefinition {
    pub id: String,
    pub name: String,
    pub version: String,
    pub category: String,
    pub summary: String,
    pub status: String,
    pub trigger: String,
    pub tools: Vec<String>,
    pub permissions: Vec<String>,
    pub objectives: Vec<String>,
    pub outputs: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPlanStage {
    pub id: String,
    pub label: String,
    pub detail: String,
    pub skill_id: String,
    pub kind: String,
    pub suggested_tool_count: usize,
    pub required_output_count: usize,
    pub max_retries: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPlan {
    pub mode: String,
    pub selected_skill_ids: Vec<String>,
    pub tool_names: Vec<String>,
    pub reasons: Vec<String>,
    pub stages: Vec<SkillPlanStage>,
}

pub fn built_in_skills() -> Vec<SkillDefinition> {
    vec![
        skill(
            "noise-filter",
            "智能噪声过滤",
            "1.3.0",
            "分析基础",
            "Phase 1 请求相关性筛选与确定性兜底",
            "ready",
            "请求不少于 20 条时自动启用；性能模式保留全量请求",
            &["shownet_list_requests", "shownet_get_request"],
            &["读取会话", "读取完整请求"],
            &[
                "保留鉴权、写操作、错误、慢请求、风险项和 Hook 关联请求",
                "过滤静态资源、遥测、预检和重复噪声",
                "模型筛选失败时回退到确定性规则结果",
            ],
            &["关键请求集合", "完整请求索引", "筛选理由"],
        ),
        skill(
            "api-reverse",
            "API 协议逆向",
            "2.2.0",
            "协议分析",
            "接口、参数、鉴权、状态变化与调用链还原",
            "ready",
            "API 模式固定启用；自动模式检测到 XHR、Fetch 或写操作时启用",
            &[
                "shownet_list_requests",
                "shownet_get_request",
                "shownet_generate_code",
            ],
            &["读取会话", "读取完整请求", "生成完整请求代码"],
            &[
                "建立端点清单和请求依赖链",
                "推断鉴权凭据的获取、刷新和传递过程",
                "区分证据、推断与待验证项",
            ],
            &["端点矩阵", "鉴权链路", "数据模型", "复现模板"],
        ),
        skill(
            "security-audit",
            "安全审计",
            "1.5.0",
            "风险检测",
            "敏感数据、鉴权边界、错误泄露与安全响应头审计",
            "ready",
            "安全模式固定启用；自动模式检测到风险标记或错误响应时启用",
            &["shownet_list_requests", "shownet_get_request"],
            &["读取会话", "读取完整请求"],
            &[
                "仅报告可由抓包证据支持的问题",
                "区分已确认风险与需要主动验证的假设",
                "检查凭据传输、跨域、缓存和安全响应头",
            ],
            &["风险分级", "证据引用", "验证步骤", "修复建议"],
        ),
        skill(
            "realtime-protocol",
            "实时协议分析",
            "1.1.0",
            "协议分析",
            "还原 WebSocket 双向消息与 SSE 单向事件流、心跳和完整性",
            "ready",
            "会话中检测到 WebSocket 或 SSE 请求时自动启用",
            &[
                "shownet_list_requests",
                "shownet_get_request",
                "shownet_get_websocket_frames",
                "shownet_get_sse_events",
            ],
            &["读取完整请求", "读取有界完整 WebSocket / SSE 采样"],
            &[
                "先识别实时协议，再按方向或事件顺序重建消息流",
                "识别 WebSocket 控制帧/关闭语义，以及 SSE event/id/retry/注释/心跳",
                "区分完整、提前关闭、压缩未实时解析、截断与达到保存上限的证据",
            ],
            &["消息或事件时序", "订阅与重连语义", "状态机", "证据缺口"],
        ),
        skill(
            "performance-analysis",
            "性能分析",
            "1.2.0",
            "诊断",
            "慢请求、串行阻塞、重复调用、载荷和缓存分析",
            "ready",
            "性能模式固定启用；自动模式检测到慢请求或重复端点时启用",
            &["shownet_list_requests", "shownet_get_request"],
            &["读取会话", "读取完整请求"],
            &[
                "保留全量时序避免筛选破坏瀑布关系",
                "识别串行依赖、重复请求和大载荷",
                "按影响和实现成本给出优化优先级",
            ],
            &["时序瓶颈", "重复请求", "缓存诊断", "优化优先级"],
        ),
        skill(
            "crypto-reverse",
            "JS 加密逆向",
            "2.4.0",
            "加密分析",
            "关联 Hook、网络参数、调用栈与 TLS 指纹证据",
            "ready",
            "加密模式固定启用；自动模式检测到 Hook 或签名参数时启用",
            &[
                "shownet_get_hooks",
                "shownet_get_request",
                "shownet_get_crypto_snippets",
                "shownet_get_tls_fingerprints",
                "shownet_get_outbound_tls_status",
                "shownet_list_px_evidence",
                "shownet_decode_px_payload",
            ],
            &["读取完整 Hook", "读取完整请求", "读取 TLS / HTTP2 指纹", "出站 TLS 状态", "PX 证据结构解码"],
            &[
                "还原明文到密文或签名的转换链",
                "识别算法、密钥来源、随机量和参数排序",
                "用调用证据区分真实算法和相似命名",
                "报告 TLS 保真边界（ja3Parity / rustls）与 PX 结构线索（非硬破）",
            ],
            &["算法证据", "参数变换链", "密钥线索", "复现框架", "TLS/PX 证据边界"],
        ),
        skill(
            "dynamic-signature",
            "动态防护协议分析",
            "0.15.0",
            "加密分析",
            "聚合 AWS WAF、Akamai、Cloudflare、reCAPTCHA、PerimeterX 的 challenge/captcha/telemetry/token 与动态算法证据",
            "beta",
            "检测到 awswaf、challenge、captcha、telemetry、sensor、_abck、bm_sz、akamai、cf-chl、recaptcha、px、perimeterx 或业务签名参数时启用",
            &[
                "shownet_list_requests",
                "shownet_get_request",
                "shownet_get_hooks",
                "shownet_get_crypto_snippets",
                "shownet_get_tls_fingerprints",
                "shownet_get_outbound_tls_status",
                "shownet_list_px_evidence",
                "shownet_decode_px_payload",
                "shownet_analyze_dynamic_protection",
                "shownet_decode_challenge_js",
                "shownet_eval_scorecard",
                "shownet_build_signature_harness",
            ],
            &["读取完整请求", "读取完整 Hook", "读取 TLS / 出站状态 / PX 证据", "沙箱 decoder", "机检 scorecard"],
            &[
                "按提供商、脚本、端点和时序聚合动态防护证据",
                "从网络载荷还原 challenge input/hmac/region、signals、PoW 类型、telemetry 会话链与 token 结构",
                "对 challenge.js 运行受限沙箱 string-array decoder，恢复完整配置候选",
                "必须调用 shownet_eval_scorecard，以 L0/L1/L2 分轨机检为权威；禁止工具不可用时虚构满分",
                "从 JS 静态特征报告混淆形态、AES-GCM/CRC32 封包线索与部署 path hash",
                "对 CAPTCHA 五步协议（gokuProps /problem /verify /voucher）仅在有抓包证据时展开；条目计数≠字段级",
                "有 PX 线索时调用 shownet_list_px_evidence / shownet_decode_px_payload（结构解码，非无密钥硬破）",
                "报告 fidelity 标签：入站 JA3 vs 出站 MITM、Headless UA、Hook 加密/解密侧确认；读取 shownet_get_outbound_tls_status",
                "严格区分已确认、合理推断和本次未捕获项，禁止用通用 WAF 知识填补缺口",
            ],
            &[
                "防护提供商候选",
                "有序协议链",
                "协议字段 schema（challenge/telemetry/captcha/token）",
                "PX 结构证据（若有）",
                "机检 scorecard L0/L1/L2",
                "JS 混淆与配置线索",
                "PoW / AES-GCM / CRC32 / Hook 联合证据",
                "TLS/HTTP2 保真边界",
                "未捕获项",
            ],
        ),
        skill(
            "algorithm-replay",
            "算法还原与重播",
            "1.1.0",
            "工程落地",
            "从分析报告/Hook/代码片段/协议 schema 还原算法流水线，生成可校验的多语言重播实现；VMP/魔改脚本走 trace 混合策略",
            "ready",
            "crypto/auto 模式在检测到动态防护、签名参数、Hook 或加密代码时启用；报告完成后可再生成/导出",
            &[
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
            &[
                "读取分析报告",
                "读取 Hook/代码片段/防护 schema",
                "算法还原与多语言重播实现",
                "导出报告与算法包",
            ],
            &[
                "从证据还原算法步骤（HMAC/PoW/AES-GCM/telemetry/业务签名等），输出 ALGORITHM_SPEC",
                "生成可运行重播代码：已还原步骤直接实现；VMP/魔改仅声明 trace 策略，不伪造完整 VM",
                "提供 validate_against_capture 离线校验，字段形状对齐抓包后再做授权目标测试",
                "报告中应嵌入 ```algorithm-spec``` JSON 以便精确物化公式",
                "禁止嵌入明文密钥/token；密钥只走环境变量",
            ],
            &[
                "ALGORITHM_RECONSTRUCTION.md / ALGORITHM_SPEC.json",
                "多语言算法重播实现",
                "分析报告与协议 schema",
                "离线校验清单",
                "导出目录路径",
            ],
        ),
        skill(
            "auto-crawler",
            "自动爬虫代码生成",
            "1.0.0",
            "工程落地",
            "从抓包分析生成多语言、依赖尽量少的客户端/爬虫源码包：JA3/JA4 保真标签、代理出口环境变量、算法还原模式标注、离线 validate-against-capture 与测试状态文档",
            "ready",
            "crypto/auto 在检测到动态防护、签名参数、Hook 或加密代码时与算法重播一并启用；可单独生成/导出爬虫包",
            &[
                "shownet_get_report",
                "shownet_analyze_dynamic_protection",
                "shownet_build_algorithm_replay",
                "shownet_build_auto_crawler",
                "shownet_export_auto_crawler",
                "shownet_export_analysis_artifacts",
                "shownet_get_tls_fingerprints",
                "shownet_get_outbound_tls_status",
                "shownet_get_hooks",
            ],
            &[
                "读取会话与防护 schema",
                "读取出站 TLS 保真状态",
                "生成多语言爬虫客户端源码",
                "离线对照抓包校验",
                "导出爬虫包目录",
            ],
            &[
                "基于 CAPTURE_SHAPE 生成无额外依赖倾向的 client_crawler（py/js/ts/go/rust 等）",
                "诚实标注入站 JA3/JA4 与出站 TLS 保真标签，不宣称完整浏览器 impersonate",
                "代理出口仅通过 SHOWNET_PROXY / HTTPS_PROXY 等环境变量配置",
                "按证据标注 algorithm reconstruction 模式（reconstructed/partial/trace/sandbox/wasm/jsvmp）",
                "离线 validate-against-capture：字段形状对齐抓包；禁止嵌入密钥/token",
                "输出 CRAWLER_ANALYSIS.md / TEST_STATUS.md / VALIDATION_REPORT.json",
            ],
            &[
                "client_crawler.* 源码",
                "CAPTURE_SHAPE.json",
                "CRAWLER_ANALYSIS.md",
                "TEST_STATUS.md / VALIDATION_REPORT.json",
                "导出目录路径",
            ],
        ),
        skill(
            "web-risk-lab",
            "Web 风控研究 Lab",
            "1.0.0",
            "浏览器实验",
            "固定调试参数、请求体劫持、JS 虚拟沙箱、对象 Hook 自吐、物理点击 CDP 计划与视觉验证码包，服务内置 Agent 做风控逆向",
            "ready",
            "crypto/auto 检测到动态防护、验证码、交互 Hook 或 challenge/captcha 脚本时启用",
            &[
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
            &[
                "读取会话/Hook",
                "生成浏览器注入脚本与 CDP 计划",
                "统一 Browser 总线点/截/评/一键装 Lab",
                "离线 fixture → objectDump 探针",
                "受限 JS 沙箱求值",
                "视觉验证码 VLM + 索引映射点击",
            ],
            &[
                "选用固定 UA/viewport/locale/webdriver 调试档，保证实验可复现",
                "无浏览器时：shownet_seed_web_risk_fixture → shownet_run_offline_lab_probe",
                "有浏览器时：shownet_browser_install_lab 一键注入并读取返回的 objectDump",
                "通过 shownet_browser_* 统一总线执行点选、截图、evaluate、导航（不另开 CDP 客户端）",
                "对算法片段使用 shownet_eval_js_sandbox；大 challenge.js 走 decoder",
                "宫格验证码用 shownet_solve_vision_captcha（截图/VLM）；离线用 dryRunIndices 或 map_vision",
                "不代替用户对未授权目标发起绕过攻击",
            ],
            &[
                "调试档与固定参数脚本",
                "劫持/自吐注入脚本与 objectDump",
                "offline lab probe 结果",
                "browser_* 执行结果",
                "沙箱求值结果",
                "CDP 点击计划",
                "视觉索引/坐标/点击结果",
                "视觉验证码 package",
            ],
        ),
    ]
}

pub fn build_plan(mode: &str, requests: &[RequestRecord]) -> Result<SkillPlan, String> {
    if !matches!(mode, "auto" | "api" | "security" | "performance" | "crypto") {
        return Err(format!("不支持的分析模式: {mode}"));
    }

    let mut selected = BTreeSet::new();
    let mut reasons = Vec::new();
    if requests.len() >= 20 {
        selected.insert("noise-filter");
        reasons.push(format!("{} 条请求需要 Phase 1 降噪", requests.len()));
    }

    let api_count = requests
        .iter()
        .filter(|request| matches!(request.resource_type.as_str(), "xhr" | "fetch"))
        .count();
    let error_or_risk = requests
        .iter()
        .any(|request| request.status >= 400 || request.risk != "none");
    let slow_count = requests
        .iter()
        .filter(|request| request.duration >= 1_000)
        .count();
    let has_hooks = requests.iter().any(|request| request.hook.is_some());
    let has_crypto_code = requests
        .iter()
        .any(|request| request.crypto_snippet_count > 0);
    let has_signature_evidence = requests.iter().any(has_signature_marker);
    let has_dynamic_evidence = requests.iter().any(has_dynamic_marker);
    let has_websocket = requests
        .iter()
        .any(|request| request.resource_type == "websocket");
    let has_sse = requests
        .iter()
        .any(|request| request.resource_type == "sse");
    let has_duplicate_endpoint = {
        let mut endpoints = BTreeSet::new();
        requests.iter().any(|request| {
            !endpoints.insert(format!(
                "{} {}{}",
                request.method, request.host, request.path
            ))
        })
    };

    match mode {
        "api" => {
            selected.insert("api-reverse");
            reasons.push("用户选择 API 协议逆向".to_string());
        }
        "security" => {
            selected.insert("security-audit");
            reasons.push("用户选择安全审计".to_string());
        }
        "performance" => {
            selected.insert("performance-analysis");
            reasons.push("性能分析保留完整请求时序".to_string());
        }
        "crypto" => {
            selected.insert("crypto-reverse");
            reasons.push("用户选择 JS 加密逆向".to_string());
        }
        "auto" => {
            if api_count > 0 || requests.iter().any(|request| is_mutation(&request.method)) {
                selected.insert("api-reverse");
                reasons.push(format!("检测到 {api_count} 条 API 请求或状态变更操作"));
            }
            if error_or_risk {
                selected.insert("security-audit");
                reasons.push("检测到错误响应或风险标记".to_string());
            }
            if slow_count > 0 || has_duplicate_endpoint {
                selected.insert("performance-analysis");
                reasons.push(format!("检测到 {slow_count} 条慢请求或重复端点"));
            }
            if has_hooks || has_crypto_code || has_signature_evidence {
                selected.insert("crypto-reverse");
                reasons.push("检测到 Hook、加密代码或签名参数".to_string());
            }
            if selected.is_empty() {
                selected.insert("api-reverse");
                reasons.push("使用通用协议分析路径".to_string());
            }
        }
        _ => unreachable!(),
    }

    if has_dynamic_evidence && matches!(mode, "auto" | "crypto") {
        selected.insert("dynamic-signature");
        reasons.push("检测到动态签名或传感器端点线索".to_string());
    }
    if matches!(mode, "auto" | "crypto")
        && (has_dynamic_evidence || has_signature_evidence || has_hooks || has_crypto_code)
    {
        selected.insert("algorithm-replay");
        reasons.push("检测到可工程化的动态算法/签名/Hook 证据，启用算法重播编程".to_string());
        selected.insert("auto-crawler");
        reasons.push(
            "启用自动爬虫代码生成：多语言客户端 + JA3/代理/算法模式 + 离线对照抓包校验".to_string(),
        );
    }
    let has_captcha_or_interaction = requests.iter().any(|request| {
        let blob = format!(
            "{} {} {}",
            request.host, request.path, request.resource_type
        )
        .to_ascii_lowercase();
        blob.contains("captcha")
            || blob.contains("challenge.js")
            || blob.contains("recaptcha")
            || blob.contains("turnstile")
            || request.hook.as_ref().is_some_and(|hook| {
                let name = hook.algorithm.to_ascii_lowercase();
                name.contains("click") || name.contains("interaction")
            })
    }) || has_hooks;
    if matches!(mode, "auto" | "crypto")
        && (has_dynamic_evidence || has_captcha_or_interaction || has_crypto_code)
    {
        selected.insert("web-risk-lab");
        reasons.push("启用 Web 风控研究 Lab：固定参数/劫持/沙箱/点击/视觉验证".to_string());
    }
    if has_websocket || has_sse {
        selected.insert("realtime-protocol");
        reasons.push(
            match (has_websocket, has_sse) {
                (true, true) => "检测到 WebSocket 与 SSE 实时消息流",
                (true, false) => "检测到 WebSocket 升级和双向消息流",
                (false, true) => "检测到 SSE 单向事件流和重连语义",
                (false, false) => unreachable!(),
            }
            .to_string(),
        );
    }

    let definitions = built_in_skills();
    let mut tool_names = BTreeSet::new();
    let mut stages = Vec::new();
    if selected.contains("noise-filter") {
        let definition = definitions
            .iter()
            .find(|definition| definition.id == "noise-filter")
            .ok_or_else(|| "Skill 定义不存在: noise-filter".to_string())?;
        stages.push(skill_stage("filter", "智能过滤", "Phase 1", definition));
    }
    for definition in definitions.iter().filter(|definition| {
        selected.contains(definition.id.as_str()) && definition.id != "noise-filter"
    }) {
        definition.tools.iter().for_each(|tool| {
            tool_names.insert(tool.clone());
        });
        stages.push(skill_stage(
            &format!("skill-{}", definition.id),
            &definition.name,
            &definition.version,
            definition,
        ));
    }
    stages.push(control_stage(
        "quality-gate",
        "产物校验",
        "证据与契约",
        "decision",
        0,
    ));
    stages.push(control_stage(
        "report",
        "生成报告",
        "Markdown + Evidence",
        "report",
        1,
    ));

    let selected_skill_ids = definitions
        .iter()
        .filter(|definition| selected.contains(definition.id.as_str()))
        .map(|definition| definition.id.clone())
        .collect();
    Ok(SkillPlan {
        mode: mode.to_string(),
        selected_skill_ids,
        tool_names: tool_names.into_iter().collect(),
        reasons,
        stages,
    })
}

pub fn prompt_contract(plan: &SkillPlan) -> String {
    let definitions = built_in_skills();
    let sections = plan
        .selected_skill_ids
        .iter()
        .filter_map(|id| definitions.iter().find(|skill| &skill.id == id))
        .map(|skill| {
            format!(
                "### {} v{}\n目标：\n- {}\n输出：{}",
                skill.name,
                skill.version,
                skill.objectives.join("\n- "),
                skill.outputs.join("、")
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    format!("以下 Skill 已由编排器选中，严格按其证据和输出契约执行：\n\n{sections}")
}

fn skill(
    id: &str,
    name: &str,
    version: &str,
    category: &str,
    summary: &str,
    status: &str,
    trigger: &str,
    tools: &[&str],
    permissions: &[&str],
    objectives: &[&str],
    outputs: &[&str],
) -> SkillDefinition {
    SkillDefinition {
        id: id.to_string(),
        name: name.to_string(),
        version: version.to_string(),
        category: category.to_string(),
        summary: summary.to_string(),
        status: status.to_string(),
        trigger: trigger.to_string(),
        tools: strings(tools),
        permissions: strings(permissions),
        objectives: strings(objectives),
        outputs: strings(outputs),
    }
}

fn skill_stage(id: &str, label: &str, detail: &str, skill: &SkillDefinition) -> SkillPlanStage {
    SkillPlanStage {
        id: id.to_string(),
        label: label.to_string(),
        detail: detail.to_string(),
        skill_id: skill.id.clone(),
        kind: "skill".to_string(),
        suggested_tool_count: skill.tools.len(),
        required_output_count: skill.outputs.len(),
        max_retries: 1,
    }
}

fn control_stage(
    id: &str,
    label: &str,
    detail: &str,
    kind: &str,
    max_retries: u32,
) -> SkillPlanStage {
    SkillPlanStage {
        id: id.to_string(),
        label: label.to_string(),
        detail: detail.to_string(),
        skill_id: id.to_string(),
        kind: kind.to_string(),
        suggested_tool_count: 0,
        required_output_count: if kind == "report" { 2 } else { 3 },
        max_retries,
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn is_mutation(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn has_signature_marker(request: &RequestRecord) -> bool {
    let evidence = format!(
        "{} {} {} {}",
        request.path,
        request.query.as_deref().unwrap_or_default(),
        request.request_body.as_deref().unwrap_or_default(),
        request
            .request_headers
            .iter()
            .map(|header| header.name.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_ascii_lowercase();
    [
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
    ]
    .iter()
    .any(|marker| evidence.contains(marker))
}

fn has_dynamic_marker(request: &RequestRecord) -> bool {
    let header_blob = request
        .request_headers
        .iter()
        .chain(request.response_headers.iter())
        .map(|header| format!("{}:{}", header.name, header.value))
        .collect::<Vec<_>>()
        .join("\n");
    let evidence = format!(
        "{} {} {} {} {} {} {}",
        request.host,
        request.path,
        request.query.as_deref().unwrap_or_default(),
        header_blob,
        request.request_body.as_deref().unwrap_or_default(),
        request.response_body,
        request.resource_type
    )
    .to_ascii_lowercase();
    [
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
    ]
    .iter()
    .any(|marker| evidence.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str, resource_type: &str, duration: i64) -> RequestRecord {
        RequestRecord {
            id: path.to_string(),
            order: 1,
            time: "now".to_string(),
            method: "GET".to_string(),
            host: "example.test".to_string(),
            path: path.to_string(),
            query: None,
            status: 200,
            resource_type: resource_type.to_string(),
            size: "0 B".to_string(),
            duration,
            source: "browser".to_string(),
            protocol: "h2".to_string(),
            tls: "TLS 1.3".to_string(),
            tls_fingerprint: None,
            risk: "none".to_string(),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: String::new(),
            response_body_metadata: Default::default(),
            crypto_snippet_count: 0,
            hook: None,
        }
    }

    #[test]
    fn automatic_plan_selects_evidence_driven_skills() {
        let requests = vec![
            request("/api/login", "fetch", 120),
            request("/akamai/sensor", "xhr", 1_500),
        ];
        let plan = build_plan("auto", &requests).unwrap();
        assert!(plan.selected_skill_ids.contains(&"api-reverse".to_string()));
        assert!(plan
            .selected_skill_ids
            .contains(&"performance-analysis".to_string()));
        assert!(plan
            .selected_skill_ids
            .contains(&"dynamic-signature".to_string()));
        assert!(plan.tool_names.contains(&"shownet_get_request".to_string()));
    }

    #[test]
    fn automatic_plan_enables_crypto_skill_for_extracted_code() {
        let mut script = request("/assets/sign.js", "script", 40);
        script.crypto_snippet_count = 2;
        let plan = build_plan("auto", &[script]).unwrap();
        assert!(plan
            .selected_skill_ids
            .contains(&"crypto-reverse".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_get_crypto_snippets".to_string()));
    }

    #[test]
    fn automatic_plan_enables_realtime_skill_for_websocket_requests() {
        let websocket = request("/stream", "websocket", 12);
        let plan = build_plan("auto", &[websocket]).unwrap();
        assert!(plan
            .selected_skill_ids
            .contains(&"realtime-protocol".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_get_websocket_frames".to_string()));
    }

    #[test]
    fn automatic_plan_enables_realtime_skill_and_sse_tool_for_event_streams() {
        let sse = request("/events", "sse", 12);
        let plan = build_plan("auto", &[sse]).unwrap();
        assert!(plan
            .selected_skill_ids
            .contains(&"realtime-protocol".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_get_sse_events".to_string()));
        assert!(plan.reasons.iter().any(|reason| reason.contains("SSE")));
    }

    #[test]
    fn filter_skill_activates_at_twenty_requests() {
        let requests = (0..20)
            .map(|index| request(&format!("/api/{index}"), "fetch", 10))
            .collect::<Vec<_>>();
        let plan = build_plan("api", &requests).unwrap();
        assert_eq!(plan.selected_skill_ids[0], "noise-filter");
    }

    #[test]
    fn dynamic_signature_skill_plans_scorecard_and_decode_tools() {
        let skills = built_in_skills();
        let dyn_skill = skills
            .iter()
            .find(|s| s.id == "dynamic-signature")
            .expect("dynamic-signature");
        assert!(
            dyn_skill.version.starts_with("0.14"),
            "version={}",
            dyn_skill.version
        );
        for required in [
            "shownet_eval_scorecard",
            "shownet_decode_challenge_js",
            "shownet_analyze_dynamic_protection",
        ] {
            assert!(
                dyn_skill.tools.iter().any(|t| t == required),
                "missing {required} in {:?}",
                dyn_skill.tools
            );
        }
    }

    #[test]
    fn crypto_plan_selects_dynamic_signature_for_aws_waf_host() {
        let mut challenge = request("/73472ccc2f21/0416b5675b4f/challenge.js", "script", 80);
        challenge.host = "73472ccc2f21.edge.sdk.awswaf.com".to_string();
        let mut verify = request("/73472ccc2f21/0416b5675b4f/mp_verify", "fetch", 120);
        verify.host = "73472ccc2f21.edge.sdk.awswaf.com".to_string();
        verify.method = "POST".to_string();
        verify.request_body = Some(
            r#"{"challenge":{"input":"eyJ","hmac":"x"},"signals":[{"name":"Zoey"}]}"#.to_string(),
        );
        let plan = build_plan("crypto", &[challenge, verify]).unwrap();
        assert!(plan
            .selected_skill_ids
            .contains(&"crypto-reverse".to_string()));
        assert!(plan
            .selected_skill_ids
            .contains(&"dynamic-signature".to_string()));
        assert!(plan
            .selected_skill_ids
            .contains(&"algorithm-replay".to_string()));
        assert!(plan
            .selected_skill_ids
            .contains(&"web-risk-lab".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_analyze_dynamic_protection".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_eval_scorecard".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_decode_challenge_js".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_build_algorithm_replay".to_string()));
        assert!(plan
            .selected_skill_ids
            .contains(&"auto-crawler".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_build_auto_crawler".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_export_auto_crawler".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_build_web_risk_lab".to_string()));
        assert!(plan
            .tool_names
            .contains(&"shownet_eval_js_sandbox".to_string()));
    }

    #[test]
    fn dynamic_marker_detects_body_only_waf_fields() {
        let mut request = request("/api/booking", "fetch", 40);
        request.host = "api.example.com".to_string();
        request.request_body =
            Some(r#"{"awswaf_session_storage":"null","existing_token":"t"}"#.to_string());
        assert!(has_dynamic_marker(&request));
    }

    #[test]
    fn auto_and_crypto_plans_select_dynamic_skill_for_protection_only_session() {
        let mut challenge = request("/cdn-cgi/challenge-platform/h/b/orchestrate", "script", 80);
        challenge.host = "challenges.cloudflare.com".to_string();
        challenge.response_body = "cf-chl __cf_bm turnstile".to_string();

        let auto = build_plan("auto", &[challenge.clone()]).unwrap();
        assert!(
            auto.selected_skill_ids
                .contains(&"dynamic-signature".to_string()),
            "auto skills={:?}",
            auto.selected_skill_ids
        );
        assert!(
            auto.tool_names
                .contains(&"shownet_analyze_dynamic_protection".to_string()),
            "auto tools={:?}",
            auto.tool_names
        );

        let crypto = build_plan("crypto", &[challenge]).unwrap();
        assert!(
            crypto
                .selected_skill_ids
                .contains(&"dynamic-signature".to_string()),
            "crypto skills={:?}",
            crypto.selected_skill_ids
        );
        assert!(
            crypto
                .tool_names
                .contains(&"shownet_analyze_dynamic_protection".to_string()),
            "crypto tools={:?}",
            crypto.tool_names
        );
    }

    #[test]
    fn auto_plan_selects_dynamic_skill_for_each_provider_marker_family() {
        let cases = [
            (
                "73472.edge.sdk.awswaf.com",
                "/x/challenge.js",
                "awswaf_session_storage mp_verify",
            ),
            ("www.example.com", "/_bm/sensor", "sensor_data _abck bm_sz"),
            (
                "challenges.cloudflare.com",
                "/cdn-cgi/challenge",
                "cf_clearance",
            ),
            ("www.google.com", "/recaptcha/api.js", "grecaptcha"),
        ];
        for (host, path, body) in cases {
            let mut req = request(path, "script", 30);
            req.host = host.to_string();
            req.response_body = body.to_string();
            let plan = build_plan("auto", &[req]).unwrap();
            assert!(
                plan.selected_skill_ids
                    .contains(&"dynamic-signature".to_string()),
                "host={host} path={path} skills={:?}",
                plan.selected_skill_ids
            );
            assert!(plan
                .tool_names
                .contains(&"shownet_analyze_dynamic_protection".to_string()));
        }
    }
}
