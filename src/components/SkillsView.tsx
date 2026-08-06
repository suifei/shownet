import {
  Activity,
  Braces,
  Check,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Code2,
  Copy,
  Database,
  FileCode2,
  Filter,
  Gauge,
  GitBranch,
  KeyRound,
  LockKeyhole,
  RadioTower,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Sparkles,
  Terminal,
  Unplug,
  Wrench,
  Zap,
} from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ANALYSIS_MODES } from "../analysisModes";
import { buildPreviewSkillPlan, builtInSkillPreview, mcpToolPreview } from "../capabilities";
import { defaultMcpServerStatus } from "../mcpDefaults";
import { calculateWorkflowLayout, partitionWorkflowStages } from "../workflowLayout";
import type {
  AnalysisMode,
  McpServerStatus,
  RequestListItem,
  SkillDefinition,
  SkillPlan,
  SkillPlanStage,
  SignatureAdapterHarness,
  ToolDefinition,
} from "../types";

type CapabilityTab = "skills" | "mcp" | "workflow";

const fallbackStatus: McpServerStatus = defaultMcpServerStatus();

const workflows = ANALYSIS_MODES.map((entry) => ({ mode: entry.id, name: entry.label, icon: entry.icon }));

const iconBySkill: Record<string, typeof Sparkles> = {
  "noise-filter": Filter,
  "api-reverse": Code2,
  "security-audit": ShieldCheck,
  "performance-analysis": Gauge,
  "crypto-reverse": KeyRound,
  "dynamic-signature": FileCode2,
  "agent-tools": Wrench,
  report: FileCode2,
};

interface SkillsViewProps {
  sessionId: string;
  requests: RequestListItem[];
  /** External MCP servers are configured in Settings, not here. */
  onOpenMcpSettings: () => void;
  /** Shared with AI 分析 — the same pipeline, so the same selected mode. */
  mode: AnalysisMode;
  onModeChange: (mode: AnalysisMode) => void;
}

export function SkillsView({ sessionId, requests, onOpenMcpSettings, mode: workflowMode, onModeChange: setWorkflowMode }: SkillsViewProps) {
  const [tab, setTab] = useState<CapabilityTab>("skills");
  const [skills, setSkills] = useState<SkillDefinition[]>(builtInSkillPreview);
  const [tools, setTools] = useState<ToolDefinition[]>(mcpToolPreview);
  const [mcpStatus, setMcpStatus] = useState<McpServerStatus>(fallbackStatus);
  const [selectedSkill, setSelectedSkill] = useState("crypto-reverse");
  const [plan, setPlan] = useState<SkillPlan>(() => buildPreviewSkillPlan(workflowMode, requests));
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState(false);
  const [harnessCopied, setHarnessCopied] = useState(false);
  const [signatureHarness, setSignatureHarness] = useState<SignatureAdapterHarness | null>(null);
  const [generatingHarness, setGeneratingHarness] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const refreshCapabilities = useCallback(async () => {
    if (!isTauri()) return;
    setRefreshing(true);
    try {
      const [loadedSkills, loadedTools, status] = await Promise.all([
        invoke<SkillDefinition[]>("list_built_in_skills"),
        invoke<ToolDefinition[]>("list_mcp_tools"),
        invoke<McpServerStatus>("get_mcp_server_status"),
      ]);
      setSkills(loadedSkills);
      setTools(loadedTools);
      setMcpStatus(status);
      setSelectedSkill((current) => loadedSkills.some((skill) => skill.id === current) ? current : loadedSkills[0]?.id ?? "");
      setError("");
    } catch (loadError) {
      setError(`能力状态读取失败：${String(loadError)}`);
    } finally {
      setRefreshing(false);
    }
  }, []);

  const refreshPlan = useCallback(async (mode: AnalysisMode) => {
    if (!isTauri() || !sessionId) {
      setPlan(buildPreviewSkillPlan(mode, requests));
      return;
    }
    setRefreshing(true);
    try {
      const loaded = await invoke<SkillPlan>("get_analysis_skill_plan", { sessionId, mode });
      setPlan(loaded);
      setError("");
    } catch (loadError) {
      setError(`编排计划读取失败：${String(loadError)}`);
    } finally {
      setRefreshing(false);
    }
  }, [requests, sessionId]);

  useEffect(() => {
    void refreshCapabilities();
  }, [refreshCapabilities]);

  useEffect(() => {
    void refreshPlan(workflowMode);
  }, [refreshPlan, workflowMode]);

  useEffect(() => {
    setSignatureHarness(null);
    setHarnessCopied(false);
  }, [sessionId]);

  const selected = skills.find((skill) => skill.id === selectedSkill) ?? skills[0];
  const SelectedIcon = selected ? iconBySkill[selected.id] ?? Sparkles : Sparkles;
  const filtered = useMemo(
    () => skills.filter((skill) => `${skill.name} ${skill.category} ${skill.summary}`.toLowerCase().includes(query.toLowerCase())),
    [query, skills],
  );

  const copyEndpoint = async () => {
    await navigator.clipboard?.writeText(mcpStatus.endpoint);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  const generateSignatureHarness = async () => {
    if (!sessionId || generatingHarness) return;
    setGeneratingHarness(true);
    try {
      const generated = isTauri()
        ? await invoke<SignatureAdapterHarness>("build_signature_harness", { sessionId, adapter: "auto" })
        : previewSignatureHarness(requests);
      setSignatureHarness(generated);
      setError("");
    } catch (generateError) {
      setError(`适配器生成失败：${String(generateError)}`);
    } finally {
      setGeneratingHarness(false);
    }
  };

  const copyHarness = async () => {
    if (!signatureHarness) return;
    await navigator.clipboard?.writeText(signatureHarness.code);
    setHarnessCopied(true);
    window.setTimeout(() => setHarnessCopied(false), 1200);
  };

  return (
    <section className="capabilities-view">
      <div className="capabilities-tabs">
        <button className={tab === "skills" ? "is-active" : ""} onClick={() => setTab("skills")}><Sparkles size={16} />内置 Skills<span>{skills.length}</span></button>
        <button className={tab === "mcp" ? "is-active" : ""} onClick={() => setTab("mcp")}><Server size={16} />MCP 服务<span>{mcpStatus.toolCount}</span></button>
        <button className={tab === "workflow" ? "is-active" : ""} onClick={() => setTab("workflow")}><GitBranch size={16} />Agent 编排<span>{plan.selectedSkillIds.length}</span></button>
      </div>

      {error && <div className="capability-error">{error}</div>}

      {tab === "skills" && selected && (
        <div className="skills-layout">
          <div className="skill-directory">
            <div className="skill-directory__toolbar">
              <div className="search-field search-field--compact"><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索 Skill" /></div>
              <button className="icon-button" title="刷新" onClick={() => void refreshCapabilities()}><RefreshCw className={refreshing ? "spin" : ""} size={16} /></button>
            </div>
            <div className="skill-list">
              {filtered.map((skill) => {
                const Icon = iconBySkill[skill.id] ?? Sparkles;
                return <button key={skill.id} className={selectedSkill === skill.id ? "is-active" : ""} onClick={() => setSelectedSkill(skill.id)}><span className="skill-list__icon"><Icon size={17} /></span><span><strong>{skill.name}</strong><small>{skill.summary}</small></span><i className={skill.status === "ready" ? "is-ready" : "is-beta"}>{skill.status === "ready" ? "启用" : "BETA"}</i></button>;
              })}
            </div>
          </div>
          <div className="skill-detail">
            <header className="skill-detail__header"><div className="skill-detail__identity"><span><SelectedIcon size={22} /></span><div><span className="section-kicker">{selected.category}</span><h2>{selected.name}</h2><p>{selected.summary}</p></div></div></header>
            <div className="skill-detail__meta"><span><Check size={13} />{selected.status === "ready" ? "已启用" : "Beta"}</span><span>v{selected.version}</span><span>ShowNet 内置</span><span>内置 Agent</span></div>
            <section className="skill-section"><div className="skill-section__heading"><h3>工具契约</h3><span>{selected.tools.length}</span></div><div className="skill-tools">{selected.tools.map((tool) => <div key={tool}><Wrench size={14} /><code>{tool}</code><ChevronRight size={14} /></div>)}</div></section>
            <section className="skill-section"><div className="skill-section__heading"><h3>触发规则</h3></div><div className="trigger-rule"><Zap size={16} /><span>{selected.trigger}</span></div></section>
            <section className="skill-section"><div className="skill-section__heading"><h3>权限与输出</h3></div><div className="permission-chips">{selected.permissions.map((permission) => <span key={permission}><LockKeyhole size={13} />{permission}</span>)}{selected.outputs.map((output) => <span key={output}><Braces size={13} />{output}</span>)}</div></section>
            {selected.id === "dynamic-signature" && (
              <section className="skill-section signature-adapter">
                <div className="skill-section__heading">
                  <div><span className="section-kicker">VERSIONED ADAPTER</span><h3>动态签名适配器</h3></div>
                  <button className="adapter-generate-button" onClick={() => void generateSignatureHarness()} disabled={generatingHarness || !sessionId}>
                    {generatingHarness ? <RefreshCw className="spin" size={14} /> : <FileCode2 size={14} />}
                    {generatingHarness ? "正在生成" : signatureHarness ? "重新生成" : "生成适配器"}
                  </button>
                </div>
                {signatureHarness && (
                  <div className="adapter-result">
                    <div className="adapter-result__meta">
                      <span><strong>{signatureHarness.vendor}</strong><small>{signatureHarness.adapterId} · v{signatureHarness.adapterVersion}</small></span>
                      <i className={`confidence-${signatureHarness.confidence}`}>{confidenceLabel(signatureHarness.confidence)}</i>
                      <code title={signatureHarness.evidenceHash}>{signatureHarness.evidenceHash.slice(0, 12)}</code>
                    </div>
                    <div className="adapter-result__metrics">
                      <span><strong>{signatureHarness.matchedRequests.length}</strong><small>匹配请求</small></span>
                      <span><strong>{signatureHarness.dynamicFields.length}</strong><small>动态字段</small></span>
                      <span><strong>{signatureHarness.hookNames.length}</strong><small>Hook</small></span>
                      <span><strong>{signatureHarness.fingerprintDependencies.length}</strong><small>指纹依赖</small></span>
                    </div>
                    <div className="adapter-evidence-row">
                      {signatureHarness.dynamicFields.slice(0, 8).map((field) => <code key={field}>{field}</code>)}
                      {signatureHarness.dynamicFields.length === 0 && <span>未识别动态字段</span>}
                    </div>
                    <div className="adapter-code-head"><span>Node.js · evidence {signatureHarness.evidenceHash.slice(0, 8)}</span><button onClick={() => void copyHarness()}>{harnessCopied ? <Check size={13} /> : <Copy size={13} />}{harnessCopied ? "已复制" : "复制代码"}</button></div>
                    <pre className="adapter-code"><code>{signatureHarness.code}</code></pre>
                    {signatureHarness.evidenceGaps.length > 0 && <div className="adapter-gaps">{signatureHarness.evidenceGaps.map((gap) => <span key={gap}><CircleDot size={12} />{gap}</span>)}</div>}
                  </div>
                )}
              </section>
            )}
          </div>
        </div>
      )}

      {tab === "mcp" && (
        <div className="mcp-layout">
          <section className="mcp-own-server">
            <header><div><span className="server-emblem"><RadioTower size={22} /></span><div><span className="section-kicker">SHOWNET MCP SERVER</span><h2>本机服务</h2></div></div><span className={`server-running ${mcpStatus.running ? "" : "is-off"}`}><span className={`live-dot ${mcpStatus.running ? "is-on" : ""}`} />{mcpStatus.starting ? "启动中" : mcpStatus.running ? "运行中" : "已停止"}</span></header>
            <div className="endpoint-row"><code>{mcpStatus.endpoint}</code><button onClick={copyEndpoint} title="复制地址">{copied ? <Check size={15} /> : <Copy size={15} />}</button></div>
            <div className="server-metrics"><div><strong>{tools.length}</strong><span>Tools</span></div><div><strong>{mcpStatus.allowWrites ? "读写" : "只读"}</strong><span>Access</span></div><div><strong>Streamable</strong><span>HTTP Transport</span></div><div><strong>{mcpStatus.protocolVersion}</strong><span>Protocol</span></div></div>
            <div className="mcp-tools-header"><h3>对外工具 · {mcpStatus.allowWrites ? "读写" : "只读"}</h3><button onClick={() => void refreshCapabilities()}><RefreshCw className={refreshing ? "spin" : ""} size={14} />刷新</button></div>
            <div className="mcp-tool-grid">{tools.map((tool) => <div className="mcp-tool-item" key={tool.name} title={tool.description}><Wrench size={13} /><code>{tool.name}</code><span className={`tool-access tool-access--${tool.access}`}>{tool.access === "write" ? "写" : "读"}</span></div>)}</div>
          </section>
          <aside className="mcp-connections">
            <div className="mcp-connections__head"><div><span className="section-kicker">AGENT TOOL SOURCE</span><h2>能力边界</h2></div></div>
            <div className="connection-list">
              <div className="connection-item"><span className="connection-logo connection-logo--fs"><Sparkles size={17} /></span><span><strong>内置 Agent</strong><small>{plan.toolNames.length} 个按需取证工具</small></span><i className="is-ready">可用</i></div>
              <div className="connection-item"><span className="connection-logo connection-logo--git"><Server size={17} /></span><span><strong>ShowNet MCP</strong><small>与 Agent 共用工具实现</small></span><i className={mcpStatus.running ? "is-ready" : ""}>{mcpStatus.running ? "已连接" : "关闭"}</i></div>
              <button type="button" className="connection-item is-actionable" onClick={onOpenMcpSettings} title="在设置里添加外部 MCP Server"><span className="connection-logo connection-logo--db"><Unplug size={17} /></span><span><strong>外部 MCP</strong><small>接入第三方 MCP 工具</small></span><i>去配置</i></button>
            </div>
          </aside>
        </div>
      )}

      {tab === "workflow" && (
        <WorkflowView
          mode={workflowMode}
          plan={plan}
          refreshing={refreshing}
          onModeChange={setWorkflowMode}
          onRefresh={() => void refreshPlan(workflowMode)}
        />
      )}
    </section>
  );
}

function WorkflowView({ mode, plan, refreshing, onModeChange, onRefresh }: { mode: AnalysisMode; plan: SkillPlan; refreshing: boolean; onModeChange: (mode: AnalysisMode) => void; onRefresh: () => void }) {
  const activeWorkflow = workflows.find((workflow) => workflow.mode === mode) ?? workflows[0];
  const flowRef = useRef<HTMLDivElement>(null);
  const [flowSize, setFlowSize] = useState({ width: 720, height: 420 });

  useEffect(() => {
    const flow = flowRef.current;
    if (!flow) return;

    const measure = () => {
      const next = { width: Math.round(flow.clientWidth), height: Math.round(flow.clientHeight) };
      setFlowSize((current) => current.width === next.width && current.height === next.height ? current : next);
    };
    measure();

    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", measure);
      return () => window.removeEventListener("resize", measure);
    }

    const observer = new ResizeObserver(measure);
    observer.observe(flow);
    return () => observer.disconnect();
  }, []);

  const layout = useMemo(
    () => calculateWorkflowLayout(plan.stages.length, flowSize.width, flowSize.height),
    [flowSize.height, flowSize.width, plan.stages.length],
  );
  const stageRows = useMemo(
    () => partitionWorkflowStages(plan.stages, layout.columns),
    [layout.columns, plan.stages],
  );

  return (
    <div className="workflow-layout">
      <aside className="workflow-list" aria-label="分析流程"><div className="workflow-list__head"><span className="section-kicker">WORKFLOWS</span></div>{workflows.map((workflow) => { const Icon = workflow.icon; return <button key={workflow.mode} className={mode === workflow.mode ? "is-active" : ""} onClick={() => onModeChange(workflow.mode)}><span><Icon size={15} /></span><div><strong>{workflow.name}</strong><small>{mode === workflow.mode ? `${plan.selectedSkillIds.length} Skills · ${plan.toolNames.length} Tools` : "按会话证据编排"}</small></div><ChevronRight size={14} /></button>; })}</aside>
      <section className="workflow-canvas">
        <header><div><span className="section-kicker">CURRENT PLAN</span><h2>{activeWorkflow.name}</h2></div><button className="analysis-start-button" onClick={onRefresh} disabled={refreshing}>{refreshing ? <Activity className="spin" size={15} /> : <RefreshCw size={14} />}{refreshing ? "编排中" : "刷新计划"}</button></header>
        <div className="workflow-flow" ref={flowRef}>
          <div
            className="workflow-track"
            data-columns={layout.columns}
            data-rows={layout.rows}
            role="list"
            aria-label={`${activeWorkflow.name}执行流程`}
            style={{ width: layout.graphWidth, minHeight: layout.graphHeight }}
          >
            {stageRows.map((row, rowIndex) => {
              const reverse = rowIndex % 2 === 1;
              return (
                <Fragment key={row[0]?.id ?? rowIndex}>
                  <div className={`workflow-row ${reverse ? "is-reverse" : ""}`}>
                    {row.map((stage, stageIndex) => (
                      <Fragment key={stage.id}>
                        <WorkflowStage stage={stage} />
                        {stageIndex < row.length - 1 && <span className="workflow-edge" aria-hidden="true"><ChevronRight size={15} /></span>}
                      </Fragment>
                    ))}
                  </div>
                  {rowIndex < stageRows.length - 1 && (
                    <span className={`workflow-turn ${reverse ? "is-left" : "is-right"}`} aria-hidden="true"><ChevronDown size={15} /></span>
                  )}
                </Fragment>
              );
            })}
          </div>
        </div>
        <div className="workflow-log">{plan.reasons.slice(0, 3).map((reason, index) => <div key={reason}><CircleDot size={14} /><span>{index === 0 ? "触发" : "证据"}</span><code>{reason}</code></div>)}<div><Database size={14} /><span>输出</span><code>report + tool trace</code></div></div>
      </section>
    </div>
  );
}

function WorkflowStage({ stage }: { stage: SkillPlanStage }) {
  const Icon = iconBySkill[stage.skillId] ?? (stage.id === "evidence" ? Terminal : Sparkles);
  return <div className="workflow-node state-ready" role="listitem"><span><Icon size={18} /></span><strong>{stage.label}</strong><small>{stage.detail}</small></div>;
}

function confidenceLabel(confidence: SignatureAdapterHarness["confidence"]) {
  if (confidence === "high") return "高置信";
  if (confidence === "medium") return "中置信";
  return "低置信";
}

function previewSignatureHarness(requests: RequestListItem[]): SignatureAdapterHarness {
  const evidenceFor = (request: RequestListItem) => `${request.host} ${request.path} ${request.query ?? ""} ${request.hasHook ? "runtime-hook" : ""}`.toLowerCase();
  const akamaiMarkers = ["akamai", "sensor_data", "_abck", "bm_sz", "ak_bmsc", "sec-cpt", "bot-manager"];
  const isAkamai = requests.some((request) => akamaiMarkers.some((marker) => evidenceFor(request).includes(marker)));
  const matched = requests.filter((request) => isAkamai
    ? akamaiMarkers.some((marker) => evidenceFor(request).includes(marker))
    : request.hasHook || request.cryptoSnippetCount > 0 || ["signature", "x-sign", "nonce"].some((marker) => evidenceFor(request).includes(marker)));
  const dynamicFields = [...new Set(matched.flatMap((request) => {
    const queryFields = (request.query ?? "").split("&").map((part) => part.split("=")[0]).filter(Boolean);
    return queryFields;
  }))];
  const evidenceHash = "8c53e72f4a10f304c9cf5122f9e6d1f0";
  const endpoints = matched.map((request) => ({ requestId: request.id, order: request.order, method: request.method, url: `${request.scheme}://${request.host}${request.path}`, status: request.status ?? 0, protocol: request.protocol }));
  const adapterId = isAkamai ? "akamai-bot-manager" : "generic-dynamic-signature";
  const requiredInputs = isAkamai ? ["timestamp", "userAgent", "cookies", "viewport"] : ["timestamp", "userAgent", "runtimeHooks"];
  const manifest = { adapterId, adapterVersion: "1.0.0", evidenceHash, endpoints, dynamicFields, requiredInputs };
  return {
    adapterId,
    adapterVersion: "1.0.0",
    vendor: isAkamai ? "Akamai" : "Generic",
    confidence: matched.length ? "medium" : "low",
    evidenceHash,
    matchedRequests: endpoints,
    dynamicFields,
    cookieNames: isAkamai ? ["_abck", "bm_sz"] : [],
    hookNames: matched.some((request) => request.hasHook) ? ["runtime:correlated-hook"] : [],
    cryptoAlgorithms: [],
    fingerprintDependencies: matched.some((request) => request.tlsIntercepted) ? ["TLS", "H2"] : [],
    requiredInputs: manifest.requiredInputs,
    evidenceGaps: [isAkamai ? "适配器必须用当前目标版本的真实响应与 Cookie 状态回归验证" : "缺少厂商特征，已生成通用动态字段输入契约"],
    language: "javascript",
    code: `// Generated by ShowNet. Runtime credentials are supplied through context; captured evidence remains in ShowNet.\nexport const manifest = Object.freeze(${JSON.stringify(manifest, null, 2)});\n\nexport function createSignatureAdapter(computeDynamicFields) {\n  return { manifest, buildRequest: async (context) => ({\n    url: manifest.endpoints[0]?.url,\n    method: manifest.endpoints[0]?.method ?? "POST",\n    headers: { ...context.headers },\n    body: JSON.stringify({ ...context.staticFields, ...await computeDynamicFields(context) }),\n  }) };\n}\n`,
  };
}
