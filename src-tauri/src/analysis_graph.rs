use crate::skills::{built_in_skills, SkillPlan};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const GRAPH_SCHEMA_VERSION: &str = "1.0.0";
const MAX_GRAPH_EVENTS: usize = 512;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GraphNodeKind {
    Skill,
    #[serde(alias = "approval")]
    Decision,
    Artifact,
    Report,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GraphNodeStatus {
    Pending,
    #[serde(alias = "waitingApproval")]
    Running,
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GraphRunStatus {
    #[serde(alias = "waitingApproval")]
    Running,
    Completed,
    CompletedWithGaps,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GraphEdgeCondition {
    Succeeded,
    RetryableFailure,
    ExhaustedFailure,
    Degraded,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphArtifactContract {
    pub schema_version: String,
    pub expected_skill_id: Option<String>,
    pub required_fields: Vec<String>,
    pub required_outputs: Vec<String>,
    pub min_evidence_refs: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisGraphNode {
    pub id: String,
    pub label: String,
    pub detail: String,
    pub kind: GraphNodeKind,
    pub skill_id: Option<String>,
    #[serde(alias = "allowedTools")]
    pub suggested_tools: Vec<String>,
    pub permissions: Vec<String>,
    pub artifact_contract: GraphArtifactContract,
    pub max_retries: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisGraphEdge {
    pub from: String,
    pub to: String,
    pub condition: GraphEdgeCondition,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisGraphDefinition {
    pub id: String,
    pub schema_version: String,
    pub mode: String,
    pub entry_node_id: String,
    pub nodes: Vec<AnalysisGraphNode>,
    pub edges: Vec<AnalysisGraphEdge>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphToolCall {
    pub tool_name: String,
    pub access: String,
    pub status: String,
    pub error: Option<String>,
    pub started_at: i64,
    pub finished_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNodeRun {
    pub node_id: String,
    pub status: GraphNodeStatus,
    pub attempt: u32,
    pub model_turn_count: u32,
    pub tool_call_count: u32,
    pub tool_calls: Vec<GraphToolCall>,
    pub artifact: Option<Value>,
    pub validation_errors: Vec<String>,
    pub error: Option<String>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEvent {
    pub sequence: u64,
    pub node_id: Option<String>,
    pub event: String,
    pub detail: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisGraphRun {
    pub analysis_id: String,
    pub definition: AnalysisGraphDefinition,
    pub status: GraphRunStatus,
    pub current_node_id: Option<String>,
    pub max_model_turns: u32,
    pub model_turn_count: u32,
    pub nodes: Vec<GraphNodeRun>,
    pub events: Vec<GraphEvent>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeFailureDisposition {
    Retry,
    ContinueDegraded,
}

pub fn compile_skill_graph(plan: &SkillPlan) -> Result<AnalysisGraphDefinition, String> {
    let definitions = built_in_skills();
    let mut nodes = Vec::new();

    if plan
        .selected_skill_ids
        .iter()
        .any(|skill_id| skill_id == "noise-filter")
    {
        let skill = definitions
            .iter()
            .find(|skill| skill.id == "noise-filter")
            .ok_or_else(|| "Skill 定义不存在: noise-filter".to_string())?;
        nodes.push(skill_node(skill, "filter", "智能过滤", "Phase 1"));
    }

    for skill_id in plan
        .selected_skill_ids
        .iter()
        .filter(|skill_id| skill_id.as_str() != "noise-filter")
    {
        let skill = definitions
            .iter()
            .find(|skill| &skill.id == skill_id)
            .ok_or_else(|| format!("Skill 定义不存在: {skill_id}"))?;
        nodes.push(skill_node(
            skill,
            &format!("skill-{}", skill.id),
            &skill.name,
            &skill.version,
        ));
    }

    nodes.push(AnalysisGraphNode {
        id: "quality-gate".to_string(),
        label: "产物校验".to_string(),
        detail: "证据与契约".to_string(),
        kind: GraphNodeKind::Decision,
        skill_id: None,
        suggested_tools: Vec::new(),
        permissions: Vec::new(),
        artifact_contract: GraphArtifactContract {
            schema_version: GRAPH_SCHEMA_VERSION.to_string(),
            expected_skill_id: None,
            required_fields: vec![
                "successfulSkills".to_string(),
                "failedSkills".to_string(),
                "evidenceRefs".to_string(),
            ],
            required_outputs: Vec::new(),
            min_evidence_refs: 0,
        },
        max_retries: 0,
    });
    nodes.push(AnalysisGraphNode {
        id: "report".to_string(),
        label: "生成报告".to_string(),
        detail: "Markdown + Evidence".to_string(),
        kind: GraphNodeKind::Report,
        skill_id: None,
        suggested_tools: Vec::new(),
        permissions: Vec::new(),
        artifact_contract: GraphArtifactContract {
            schema_version: GRAPH_SCHEMA_VERSION.to_string(),
            expected_skill_id: None,
            required_fields: vec!["contentBytes".to_string(), "skillArtifacts".to_string()],
            required_outputs: Vec::new(),
            min_evidence_refs: 0,
        },
        max_retries: 1,
    });

    let mut edges = Vec::new();
    for pair in nodes.windows(2) {
        let from = pair[0].id.clone();
        let to = pair[1].id.clone();
        edges.push(AnalysisGraphEdge {
            from: from.clone(),
            to: to.clone(),
            condition: GraphEdgeCondition::Succeeded,
        });
        edges.push(AnalysisGraphEdge {
            from: from.clone(),
            to,
            condition: GraphEdgeCondition::ExhaustedFailure,
        });
        if pair[0].max_retries > 0 {
            edges.push(AnalysisGraphEdge {
                from: from.clone(),
                to: from,
                condition: GraphEdgeCondition::RetryableFailure,
            });
        }
    }
    edges.push(AnalysisGraphEdge {
        from: "quality-gate".to_string(),
        to: "report".to_string(),
        condition: GraphEdgeCondition::Degraded,
    });

    let entry_node_id = nodes
        .first()
        .map(|node| node.id.clone())
        .ok_or_else(|| "分析 Graph 没有入口节点".to_string())?;
    Ok(AnalysisGraphDefinition {
        id: format!("shownet-analysis-{}", plan.mode),
        schema_version: GRAPH_SCHEMA_VERSION.to_string(),
        mode: plan.mode.clone(),
        entry_node_id,
        nodes,
        edges,
    })
}

fn skill_node(
    skill: &crate::skills::SkillDefinition,
    id: &str,
    label: &str,
    detail: &str,
) -> AnalysisGraphNode {
    AnalysisGraphNode {
        id: id.to_string(),
        label: label.to_string(),
        detail: detail.to_string(),
        kind: GraphNodeKind::Skill,
        skill_id: Some(skill.id.clone()),
        suggested_tools: skill.tools.clone(),
        permissions: skill.permissions.clone(),
        artifact_contract: GraphArtifactContract {
            schema_version: GRAPH_SCHEMA_VERSION.to_string(),
            expected_skill_id: Some(skill.id.clone()),
            required_fields: vec![
                "skillId".to_string(),
                "summary".to_string(),
                "findings".to_string(),
                "evidenceRefs".to_string(),
                "gaps".to_string(),
                "outputs".to_string(),
            ],
            required_outputs: skill.outputs.clone(),
            min_evidence_refs: usize::from(skill.id != "noise-filter"),
        },
        max_retries: 1,
    }
}

impl AnalysisGraphDefinition {
    pub fn node(&self, node_id: &str) -> Option<&AnalysisGraphNode> {
        self.nodes.iter().find(|node| node.id == node_id)
    }

    pub fn next_node(&self, node_id: &str, condition: GraphEdgeCondition) -> Option<&str> {
        self.edges
            .iter()
            .find(|edge| edge.from == node_id && edge.condition == condition)
            .map(|edge| edge.to.as_str())
    }
}

impl AnalysisGraphRun {
    pub fn new(
        analysis_id: impl Into<String>,
        definition: AnalysisGraphDefinition,
        max_model_turns: u32,
        now: i64,
    ) -> Self {
        let nodes = definition
            .nodes
            .iter()
            .map(|node| GraphNodeRun {
                node_id: node.id.clone(),
                status: GraphNodeStatus::Pending,
                attempt: 0,
                model_turn_count: 0,
                tool_call_count: 0,
                tool_calls: Vec::new(),
                artifact: None,
                validation_errors: Vec::new(),
                error: None,
                started_at: None,
                finished_at: None,
            })
            .collect();
        let mut run = Self {
            analysis_id: analysis_id.into(),
            definition,
            status: GraphRunStatus::Running,
            current_node_id: None,
            max_model_turns: max_model_turns.max(1),
            model_turn_count: 0,
            nodes,
            events: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        run.push_event(None, "graph-created", "建议分析 Graph 已创建", now);
        run
    }

    pub fn node(&self, node_id: &str) -> Option<&GraphNodeRun> {
        self.nodes.iter().find(|node| node.node_id == node_id)
    }

    pub fn node_mut(&mut self, node_id: &str) -> Result<&mut GraphNodeRun, String> {
        self.nodes
            .iter_mut()
            .find(|node| node.node_id == node_id)
            .ok_or_else(|| format!("Graph 节点不存在: {node_id}"))
    }

    pub fn start_node(&mut self, node_id: &str, now: i64) -> Result<(), String> {
        let definition = self
            .definition
            .node(node_id)
            .ok_or_else(|| format!("Graph 节点定义不存在: {node_id}"))?;
        let label = definition.label.clone();
        let node = self.node_mut(node_id)?;
        if !matches!(
            node.status,
            GraphNodeStatus::Pending | GraphNodeStatus::Running
        ) {
            return Err(format!("Graph 节点 {node_id} 当前状态不可启动"));
        }
        node.status = GraphNodeStatus::Running;
        node.attempt = node.attempt.saturating_add(1);
        node.started_at.get_or_insert(now);
        node.finished_at = None;
        node.error = None;
        node.validation_errors.clear();
        self.status = GraphRunStatus::Running;
        self.current_node_id = Some(node_id.to_string());
        self.updated_at = now;
        self.push_event(Some(node_id), "node-started", &label, now);
        Ok(())
    }

    pub fn consume_model_turn(&mut self, node_id: &str, now: i64) -> Result<(), String> {
        // Graph observes model turns but never spends or partitions the Agent's
        // configured turn allowance. The model runtime remains the sole owner of
        // maxAgentTurns so Skill orchestration cannot silently reduce it.
        self.model_turn_count = self.model_turn_count.saturating_add(1);
        let node = self.node_mut(node_id)?;
        node.model_turn_count = node.model_turn_count.saturating_add(1);
        self.updated_at = now;
        Ok(())
    }

    pub fn route_tool(
        &mut self,
        tool_name: &str,
        access: &str,
        now: i64,
    ) -> Result<String, String> {
        let previous_node = self.current_node_id.clone();
        let current_owner = previous_node.as_deref().filter(|node_id| {
            self.definition
                .node(node_id)
                .is_some_and(|node| node.suggested_tools.iter().any(|tool| tool == tool_name))
        });
        let selected_owner = self
            .definition
            .nodes
            .iter()
            .find(|node| node.suggested_tools.iter().any(|tool| tool == tool_name))
            .map(|node| node.id.clone());
        let node_id = if let Some(current_owner) = current_owner {
            current_owner.to_string()
        } else if let Some(selected_owner) = selected_owner {
            selected_owner
        } else {
            self.ensure_dynamic_evidence_node(tool_name, access, now)
        };

        let status = self
            .node(&node_id)
            .map(|node| node.status.clone())
            .ok_or_else(|| format!("Graph 节点运行状态不存在: {node_id}"))?;
        match status {
            GraphNodeStatus::Pending => self.start_node(&node_id, now)?,
            GraphNodeStatus::Running => {
                self.current_node_id = Some(node_id.clone());
                self.updated_at = now;
            }
            GraphNodeStatus::Succeeded | GraphNodeStatus::Failed | GraphNodeStatus::Skipped => {
                let node = self.node_mut(&node_id)?;
                node.status = GraphNodeStatus::Running;
                node.finished_at = None;
                self.current_node_id = Some(node_id.clone());
                self.updated_at = now;
            }
        }
        if previous_node
            .as_deref()
            .is_some_and(|previous| previous != node_id)
        {
            self.push_event(
                Some(&node_id),
                "agent-deviation",
                &format!(
                    "Agent 根据证据从 {} 动态切换到 {}，工具 {}",
                    previous_node.as_deref().unwrap_or("graph-entry"),
                    node_id,
                    tool_name,
                ),
                now,
            );
        }
        Ok(node_id)
    }

    fn ensure_dynamic_evidence_node(&mut self, tool_name: &str, access: &str, now: i64) -> String {
        let node_id = "dynamic-evidence".to_string();
        if let Some(node) = self
            .definition
            .nodes
            .iter_mut()
            .find(|node| node.id == node_id)
        {
            if !node.suggested_tools.iter().any(|tool| tool == tool_name) {
                node.suggested_tools.push(tool_name.to_string());
            }
            return node_id;
        }

        let insert_at = self
            .definition
            .nodes
            .iter()
            .position(|node| node.id == "quality-gate")
            .unwrap_or(self.definition.nodes.len());
        self.definition.nodes.insert(
            insert_at,
            AnalysisGraphNode {
                id: node_id.clone(),
                label: "Agent 自主分支".to_string(),
                detail: "GrokBuild dynamic deviation".to_string(),
                kind: GraphNodeKind::Artifact,
                skill_id: None,
                suggested_tools: vec![tool_name.to_string()],
                permissions: vec!["Agent 自主能力".to_string()],
                artifact_contract: GraphArtifactContract {
                    schema_version: GRAPH_SCHEMA_VERSION.to_string(),
                    expected_skill_id: None,
                    required_fields: vec!["tools".to_string(), "evidenceRefs".to_string()],
                    required_outputs: Vec::new(),
                    min_evidence_refs: 0,
                },
                max_retries: 0,
            },
        );
        self.nodes.insert(
            insert_at,
            GraphNodeRun {
                node_id: node_id.clone(),
                status: GraphNodeStatus::Pending,
                attempt: 0,
                model_turn_count: 0,
                tool_call_count: 0,
                tool_calls: Vec::new(),
                artifact: None,
                validation_errors: Vec::new(),
                error: None,
                started_at: None,
                finished_at: None,
            },
        );
        self.push_event(
            Some(&node_id),
            "dynamic-branch-created",
            &format!("{access} 工具 {tool_name} 触发 Agent 自主分支"),
            now,
        );
        node_id
    }

    pub fn record_tool_call(
        &mut self,
        node_id: &str,
        tool_name: &str,
        access: &str,
        result: Result<(), &str>,
        started_at: i64,
        finished_at: i64,
    ) -> Result<(), String> {
        let node = self.node_mut(node_id)?;
        node.tool_call_count = node.tool_call_count.saturating_add(1);
        node.tool_calls.push(GraphToolCall {
            tool_name: tool_name.to_string(),
            access: access.to_string(),
            status: if result.is_ok() { "complete" } else { "failed" }.to_string(),
            error: result.err().map(str::to_string),
            started_at,
            finished_at,
        });
        self.updated_at = finished_at;
        Ok(())
    }

    pub fn complete_node(
        &mut self,
        node_id: &str,
        artifact: Value,
        now: i64,
    ) -> Result<(), String> {
        let definition = self
            .definition
            .node(node_id)
            .ok_or_else(|| format!("Graph 节点定义不存在: {node_id}"))?;
        let validation_errors = validate_artifact(&definition.artifact_contract, &artifact);
        if !validation_errors.is_empty() {
            return Err(validation_errors.join("；"));
        }
        let node = self.node_mut(node_id)?;
        node.status = GraphNodeStatus::Succeeded;
        node.artifact = Some(artifact);
        node.validation_errors.clear();
        node.error = None;
        node.finished_at = Some(now);
        self.current_node_id = self
            .definition
            .next_node(node_id, GraphEdgeCondition::Succeeded)
            .map(str::to_string);
        self.updated_at = now;
        self.push_event(Some(node_id), "artifact-valid", "产物契约校验通过", now);
        Ok(())
    }

    pub fn fail_node(
        &mut self,
        node_id: &str,
        error: &str,
        validation_errors: Vec<String>,
        now: i64,
    ) -> Result<NodeFailureDisposition, String> {
        let max_retries = self
            .definition
            .node(node_id)
            .ok_or_else(|| format!("Graph 节点定义不存在: {node_id}"))?
            .max_retries;
        let node = self.node_mut(node_id)?;
        node.error = Some(error.to_string());
        node.validation_errors = validation_errors;
        node.finished_at = Some(now);
        let disposition = if node.attempt <= max_retries {
            node.status = GraphNodeStatus::Pending;
            NodeFailureDisposition::Retry
        } else {
            node.status = GraphNodeStatus::Failed;
            NodeFailureDisposition::ContinueDegraded
        };
        self.current_node_id = self
            .definition
            .next_node(
                node_id,
                if disposition == NodeFailureDisposition::Retry {
                    GraphEdgeCondition::RetryableFailure
                } else {
                    GraphEdgeCondition::ExhaustedFailure
                },
            )
            .map(str::to_string);
        self.updated_at = now;
        self.push_event(
            Some(node_id),
            if disposition == NodeFailureDisposition::Retry {
                "node-retry"
            } else {
                "node-degraded"
            },
            error,
            now,
        );
        Ok(disposition)
    }

    pub fn degrade_node(
        &mut self,
        node_id: &str,
        error: &str,
        validation_errors: Vec<String>,
        now: i64,
    ) -> Result<(), String> {
        let node = self.node_mut(node_id)?;
        node.status = GraphNodeStatus::Failed;
        node.error = Some(error.to_string());
        node.validation_errors = validation_errors;
        node.finished_at = Some(now);
        self.current_node_id = self
            .definition
            .next_node(node_id, GraphEdgeCondition::ExhaustedFailure)
            .map(str::to_string);
        self.updated_at = now;
        self.push_event(Some(node_id), "node-degraded", error, now);
        Ok(())
    }

    pub fn finish(&mut self, now: i64) {
        self.status = if self
            .nodes
            .iter()
            .any(|node| node.status == GraphNodeStatus::Failed)
        {
            GraphRunStatus::CompletedWithGaps
        } else {
            GraphRunStatus::Completed
        };
        self.current_node_id = None;
        self.updated_at = now;
        self.push_event(None, "graph-completed", "分析 Graph 执行结束", now);
    }

    pub fn fail(&mut self, error: &str, now: i64) {
        self.status = GraphRunStatus::Failed;
        self.current_node_id = None;
        self.updated_at = now;
        self.push_event(None, "graph-failed", error, now);
    }

    fn push_event(&mut self, node_id: Option<&str>, event: &str, detail: &str, now: i64) {
        let sequence = self
            .events
            .last()
            .map_or(1, |item| item.sequence.saturating_add(1));
        self.events.push(GraphEvent {
            sequence,
            node_id: node_id.map(str::to_string),
            event: event.to_string(),
            detail: detail.to_string(),
            created_at: now,
        });
        if self.events.len() > MAX_GRAPH_EVENTS {
            self.events.drain(..self.events.len() - MAX_GRAPH_EVENTS);
        }
    }
}

pub fn parse_artifact(content: &str) -> Result<Value, String> {
    let trimmed = content.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return Ok(value);
    }
    for fence in ["```json", "```"] {
        if let Some(start) = trimmed.find(fence) {
            let body_start = start + fence.len();
            if let Some(end) = trimmed[body_start..].find("```") {
                let candidate = trimmed[body_start..body_start + end].trim();
                if let Ok(value) = serde_json::from_str::<Value>(candidate) {
                    return Ok(value);
                }
            }
        }
    }
    let start = trimmed
        .find('{')
        .ok_or_else(|| "Skill 产物缺少 JSON 对象".to_string())?;
    let end = trimmed
        .rfind('}')
        .filter(|end| *end >= start)
        .ok_or_else(|| "Skill 产物 JSON 对象不完整".to_string())?;
    serde_json::from_str::<Value>(&trimmed[start..=end])
        .map_err(|error| format!("Skill 产物不是有效 JSON: {error}"))
}

pub fn validate_artifact(contract: &GraphArtifactContract, artifact: &Value) -> Vec<String> {
    let Some(object) = artifact.as_object() else {
        return vec!["产物必须是 JSON 对象".to_string()];
    };
    let mut errors = Vec::new();
    for field in &contract.required_fields {
        // Presence check: key must exist. Empty arrays/objects are valid (e.g. failedSkills: []
        // when every skill succeeded). Blank strings are still invalid for string fields.
        if required_field_missing(object.get(field)) {
            errors.push(format!("缺少必填产物字段: {field}"));
        }
    }
    if let Some(expected_skill_id) = contract.expected_skill_id.as_deref() {
        if object.get("skillId").and_then(Value::as_str) != Some(expected_skill_id) {
            errors.push(format!("skillId 必须为 {expected_skill_id}"));
        }
    }
    let evidence_count = object
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .map_or(0, |items| {
            items.iter().filter(|item| !value_is_empty(item)).count()
        });
    if evidence_count < contract.min_evidence_refs {
        errors.push(format!(
            "证据引用不足: 至少需要 {} 条",
            contract.min_evidence_refs
        ));
    }
    if !contract.required_outputs.is_empty() {
        let outputs = object.get("outputs").and_then(Value::as_object);
        for output in &contract.required_outputs {
            if outputs
                .and_then(|outputs| outputs.get(output))
                .is_none_or(value_is_empty)
            {
                errors.push(format!("缺少 Skill 约定输出: {output}"));
            }
        }
    }
    errors
}

/// Required-field presence: missing/null/blank string fail; empty `[]` / `{}` pass.
fn required_field_missing(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.trim().is_empty(),
        Some(Value::Array(_)) | Some(Value::Object(_)) | Some(Value::Bool(_)) | Some(Value::Number(_)) => {
            false
        }
    }
}

fn value_is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(value) => value.trim().is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills;
    use serde_json::json;

    fn api_graph() -> AnalysisGraphDefinition {
        let plan = skills::build_plan("api", &[]).unwrap();
        compile_skill_graph(&plan).unwrap()
    }

    #[test]
    fn graph_contains_contract_gate_and_failure_loops() {
        let graph = api_graph();
        let skill = graph.node("skill-api-reverse").unwrap();
        assert_eq!(skill.kind, GraphNodeKind::Skill);
        assert!(skill
            .suggested_tools
            .iter()
            .any(|tool| tool == "shownet_get_request"));
        assert!(graph.node("quality-gate").is_some());
        assert_eq!(
            graph.next_node("skill-api-reverse", GraphEdgeCondition::RetryableFailure),
            Some("skill-api-reverse")
        );
        assert_eq!(
            graph.next_node("skill-api-reverse", GraphEdgeCondition::ExhaustedFailure),
            Some("quality-gate")
        );
    }

    #[test]
    fn graph_routes_unplanned_tools_without_restricting_agent_capabilities() {
        let graph = api_graph();
        let mut run = AnalysisGraphRun::new("analysis-1", graph, 8, 1);
        run.start_node("skill-api-reverse", 2).unwrap();
        assert_eq!(
            run.route_tool("shownet_get_request", "read", 3).unwrap(),
            "skill-api-reverse"
        );
        let dynamic_node = run
            .route_tool("shownet_delete_session", "write", 4)
            .unwrap();
        assert_eq!(dynamic_node, "dynamic-evidence");
        assert!(run
            .definition
            .node(&dynamic_node)
            .unwrap()
            .suggested_tools
            .iter()
            .any(|tool| tool == "shownet_delete_session"));
        assert!(run
            .events
            .iter()
            .any(|event| event.event == "dynamic-branch-created"));

        let mut crypto_plan = skills::build_plan("crypto", &[]).unwrap();
        crypto_plan
            .selected_skill_ids
            .push("algorithm-replay".to_string());
        let graph = compile_skill_graph(&crypto_plan).unwrap();
        let mut run = AnalysisGraphRun::new("analysis-2", graph, 8, 1);
        run.start_node("skill-algorithm-replay", 2).unwrap();
        assert_eq!(
            run.route_tool("shownet_export_analysis_artifacts", "write", 3)
                .unwrap(),
            "skill-algorithm-replay"
        );
    }

    #[test]
    fn invalid_skill_artifact_retries_once_then_degrades() {
        let graph = api_graph();
        let mut run = AnalysisGraphRun::new("analysis-1", graph, 8, 1);
        run.start_node("skill-api-reverse", 2).unwrap();
        let first = run
            .fail_node(
                "skill-api-reverse",
                "missing outputs",
                vec!["缺少输出".to_string()],
                3,
            )
            .unwrap();
        assert_eq!(first, NodeFailureDisposition::Retry);
        run.start_node("skill-api-reverse", 4).unwrap();
        let second = run
            .fail_node(
                "skill-api-reverse",
                "still missing",
                vec!["缺少输出".to_string()],
                5,
            )
            .unwrap();
        assert_eq!(second, NodeFailureDisposition::ContinueDegraded);
        assert_eq!(
            run.node("skill-api-reverse").unwrap().status,
            GraphNodeStatus::Failed
        );
        assert_eq!(run.current_node_id.as_deref(), Some("quality-gate"));
    }

    #[test]
    fn validates_machine_readable_skill_outputs() {
        let graph = api_graph();
        let contract = &graph.node("skill-api-reverse").unwrap().artifact_contract;
        let artifact = json!({
            "skillId": "api-reverse",
            "summary": "identified login chain",
            "findings": ["token exchange"],
            "evidenceRefs": ["#1 POST /login"],
            "gaps": ["refresh not captured"],
            "outputs": {
                "端点矩阵": ["POST /login"],
                "鉴权链路": "challenge -> token",
                "数据模型": { "token": "runtime-token" },
                "复现模板": "curl with captured request values"
            }
        });
        assert!(validate_artifact(contract, &artifact).is_empty());
        let missing = json!({ "skillId": "api-reverse", "summary": "x" });
        assert!(!validate_artifact(contract, &missing).is_empty());
    }

    #[test]
    fn quality_gate_accepts_empty_failed_skills_when_all_skills_succeeded() {
        let graph = api_graph();
        let contract = &graph.node("quality-gate").unwrap().artifact_contract;
        let gate = json!({
            "successfulSkills": ["api-reverse"],
            "failedSkills": [],
            "evidenceRefs": ["#1 GET /api/v1/items"],
            "planReasons": ["用户选择 API 协议逆向"],
        });
        let errors = validate_artifact(contract, &gate);
        assert!(
            errors.is_empty(),
            "empty failedSkills must be valid (no failures): {errors:?}"
        );

        let mut run = AnalysisGraphRun::new("analysis-gate", graph, 8, 1);
        run.start_node("quality-gate", 2).unwrap();
        run.complete_node("quality-gate", gate, 3)
            .expect("quality-gate complete_node must accept failedSkills: []");
        assert_eq!(
            run.node("quality-gate").unwrap().status,
            GraphNodeStatus::Succeeded
        );
    }

    #[test]
    fn quality_gate_rejects_missing_failed_skills_key() {
        let graph = api_graph();
        let contract = &graph.node("quality-gate").unwrap().artifact_contract;
        let gate = json!({
            "successfulSkills": ["api-reverse"],
            "evidenceRefs": ["#1 GET /x"],
        });
        let errors = validate_artifact(contract, &gate);
        assert!(
            errors.iter().any(|e| e.contains("failedSkills")),
            "missing key must still fail: {errors:?}"
        );
    }

    #[test]
    fn skill_artifact_allows_empty_gaps_array() {
        let graph = api_graph();
        let contract = &graph.node("skill-api-reverse").unwrap().artifact_contract;
        let artifact = json!({
            "skillId": "api-reverse",
            "summary": "ok",
            "findings": ["one"],
            "evidenceRefs": ["#1 POST /login"],
            "gaps": [],
            "outputs": {
                "端点矩阵": ["POST /login"],
                "鉴权链路": "n/a",
                "数据模型": { "note": "no extra fields" },
                "复现模板": "curl"
            }
        });
        let errors = validate_artifact(contract, &artifact);
        assert!(
            errors.is_empty(),
            "gaps: [] is a valid explicit empty list: {errors:?}"
        );
    }

    #[test]
    fn graph_observes_turns_without_enforcing_the_agent_limit() {
        let graph = api_graph();
        let mut run = AnalysisGraphRun::new("analysis-1", graph, 1, 1);
        run.start_node("skill-api-reverse", 2).unwrap();
        run.consume_model_turn("skill-api-reverse", 3).unwrap();
        run.consume_model_turn("skill-api-reverse", 4).unwrap();
        assert_eq!(run.max_model_turns, 1);
        assert_eq!(run.model_turn_count, 2);
    }

    #[test]
    fn graph_json_migrates_legacy_enforcement_fields_to_advisory_state() {
        let graph = api_graph();
        let mut run = AnalysisGraphRun::new("analysis-1", graph, 8, 1);
        run.start_node("skill-api-reverse", 2).unwrap();
        let current = serde_json::to_value(&run).unwrap();
        let current_node = current["definition"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["id"] == "skill-api-reverse")
            .unwrap();
        assert!(current_node.get("suggestedTools").is_some());
        assert!(current_node.get("allowedTools").is_none());
        assert!(current_node.get("approvalPolicy").is_none());
        assert!(current_node.get("maxToolCalls").is_none());

        let mut legacy = current;
        legacy["status"] = json!("waitingApproval");
        legacy["nodes"][1]["status"] = json!("waitingApproval");
        for node in legacy["definition"]["nodes"].as_array_mut().unwrap() {
            let object = node.as_object_mut().unwrap();
            if let Some(tools) = object.remove("suggestedTools") {
                object.insert("allowedTools".to_string(), tools);
            }
            object.insert("approvalPolicy".to_string(), json!("never"));
            object.insert("maxToolCalls".to_string(), json!(16));
        }
        let restored = serde_json::from_value::<AnalysisGraphRun>(legacy).unwrap();
        assert_eq!(restored.status, GraphRunStatus::Running);
        assert_eq!(restored.nodes[1].status, GraphNodeStatus::Running);
        assert!(restored
            .definition
            .node("skill-api-reverse")
            .unwrap()
            .suggested_tools
            .iter()
            .any(|tool| tool == "shownet_get_request"));
    }
}
