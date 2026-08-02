use crate::models::HeaderEntry;
use hyper::header::{HeaderName, HeaderValue};
use hyper::Method;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};
use url::Url;
use uuid::Uuid;

pub const MAX_PENDING_BREAKPOINTS: usize = 32;
pub const MAX_BREAKPOINT_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_BREAKPOINT_TIMEOUT_MS: u64 = 120_000;

type QueueNotifier = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone, Debug)]
pub struct RuntimeBreakpointRule {
    pub id: String,
    pub name: String,
    pub stage: String,
    pub revision: i64,
    pub timeout_ms: u64,
    pub abort_on_timeout: bool,
}

#[derive(Clone, Debug)]
pub struct BreakpointTaskInput {
    pub session_id: String,
    pub request_id: String,
    pub stage: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub request_headers: Vec<HeaderEntry>,
    pub response_headers: Vec<HeaderEntry>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub body_editable: bool,
    pub body_unavailable_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreakpointTask {
    pub id: String,
    pub session_id: String,
    pub request_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub stage: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub request_headers: Vec<HeaderEntry>,
    pub response_headers: Vec<HeaderEntry>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub body_editable: bool,
    pub body_unavailable_reason: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreakpointQueueSnapshot {
    pub tasks: Vec<BreakpointTask>,
    pub capacity: usize,
    pub skipped_count: u64,
    pub generated_at: i64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BreakpointDecisionInput {
    pub task_id: String,
    pub action: String,
    pub method: Option<String>,
    pub url: Option<String>,
    pub status: Option<u16>,
    pub request_headers: Option<Vec<HeaderEntry>>,
    pub response_headers: Option<Vec<HeaderEntry>>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct BreakpointEdit {
    pub method: Option<String>,
    pub url: Option<String>,
    pub status: Option<u16>,
    pub request_headers: Option<Vec<HeaderEntry>>,
    pub response_headers: Option<Vec<HeaderEntry>>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
}

#[derive(Clone, Debug)]
pub enum BreakpointResolution {
    Continue(BreakpointEdit),
    Abort,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakpointCompletion {
    Submitted,
    TimedOut,
    QueueFull,
    Cancelled(String),
}

#[derive(Clone, Debug)]
pub struct BreakpointWaitResult {
    pub resolution: BreakpointResolution,
    pub completion: BreakpointCompletion,
}

struct PendingSignal {
    resolution: BreakpointResolution,
    completion: BreakpointCompletion,
}

struct PendingBreakpoint {
    task: BreakpointTask,
    sender: oneshot::Sender<PendingSignal>,
}

#[derive(Default)]
struct BreakpointQueueState {
    pending: HashMap<String, PendingBreakpoint>,
    order: VecDeque<String>,
    skipped_count: u64,
}

pub struct BreakpointCoordinator {
    state: Mutex<BreakpointQueueState>,
    capacity: usize,
    notifier: QueueNotifier,
}

impl Default for BreakpointCoordinator {
    fn default() -> Self {
        Self::new(Arc::new(|| {}))
    }
}

impl BreakpointCoordinator {
    pub fn new(notifier: QueueNotifier) -> Self {
        Self {
            state: Mutex::new(BreakpointQueueState::default()),
            capacity: MAX_PENDING_BREAKPOINTS,
            notifier,
        }
    }

    #[cfg(test)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Mutex::new(BreakpointQueueState::default()),
            capacity,
            notifier: Arc::new(|| {}),
        }
    }

    pub fn snapshot(&self) -> Result<BreakpointQueueSnapshot, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "断点队列已损坏".to_string())?;
        Ok(BreakpointQueueSnapshot {
            tasks: state
                .order
                .iter()
                .filter_map(|id| state.pending.get(id).map(|pending| pending.task.clone()))
                .collect(),
            capacity: self.capacity,
            skipped_count: state.skipped_count,
            generated_at: now_ms(),
        })
    }

    pub async fn pause(
        self: &Arc<Self>,
        rule: &RuntimeBreakpointRule,
        input: BreakpointTaskInput,
    ) -> BreakpointWaitResult {
        let created_at = now_ms();
        let task_id = format!("breakpoint-{}", Uuid::new_v4());
        let task = BreakpointTask {
            id: task_id.clone(),
            session_id: input.session_id,
            request_id: input.request_id,
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            stage: input.stage,
            method: input.method,
            url: input.url,
            status: input.status,
            request_headers: input.request_headers,
            response_headers: input.response_headers,
            request_body: input.request_body,
            response_body: input.response_body,
            body_editable: input.body_editable,
            body_unavailable_reason: input.body_unavailable_reason,
            created_at,
            expires_at: created_at.saturating_add(rule.timeout_ms as i64),
        };
        let (sender, receiver) = oneshot::channel();
        let inserted = self
            .state
            .lock()
            .map(|mut state| {
                if state.pending.len() >= self.capacity {
                    state.skipped_count = state.skipped_count.saturating_add(1);
                    false
                } else {
                    state.order.push_back(task_id.clone());
                    state
                        .pending
                        .insert(task_id.clone(), PendingBreakpoint { task, sender });
                    true
                }
            })
            .unwrap_or(false);
        (self.notifier)();
        if !inserted {
            return BreakpointWaitResult {
                resolution: BreakpointResolution::Continue(BreakpointEdit::default()),
                completion: BreakpointCompletion::QueueFull,
            };
        }

        let mut lease = BreakpointWaitLease {
            coordinator: Arc::downgrade(self),
            task_id,
            armed: true,
        };
        let result = match timeout(Duration::from_millis(rule.timeout_ms), receiver).await {
            Ok(Ok(signal)) => BreakpointWaitResult {
                resolution: signal.resolution,
                completion: signal.completion,
            },
            Ok(Err(_)) => BreakpointWaitResult {
                resolution: BreakpointResolution::Continue(BreakpointEdit::default()),
                completion: BreakpointCompletion::Cancelled("等待任务已关闭".to_string()),
            },
            Err(_) => BreakpointWaitResult {
                resolution: if rule.abort_on_timeout {
                    BreakpointResolution::Abort
                } else {
                    BreakpointResolution::Continue(BreakpointEdit::default())
                },
                completion: BreakpointCompletion::TimedOut,
            },
        };
        lease.cleanup();
        result
    }

    pub fn resolve(&self, input: BreakpointDecisionInput) -> Result<(), String> {
        let (pending, resolution) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "断点队列已损坏".to_string())?;
            let task = state
                .pending
                .get(&input.task_id)
                .map(|pending| pending.task.clone())
                .ok_or_else(|| "断点任务已结束、超时或失效".to_string())?;
            let resolution = validate_decision(&task, input)?;
            let pending = remove_pending(&mut state, &task.id)
                .ok_or_else(|| "断点任务已结束、超时或失效".to_string())?;
            (pending, resolution)
        };
        let _ = pending.sender.send(PendingSignal {
            resolution,
            completion: BreakpointCompletion::Submitted,
        });
        (self.notifier)();
        Ok(())
    }

    pub fn cancel_rule(&self, rule_id: &str, reason: &str) -> usize {
        self.cancel_matching(
            |task| task.rule_id == rule_id,
            BreakpointCompletion::Cancelled(reason.to_string()),
        )
    }

    pub fn cancel_session(&self, session_id: &str, reason: &str) -> usize {
        self.cancel_matching(
            |task| task.session_id == session_id,
            BreakpointCompletion::Cancelled(reason.to_string()),
        )
    }

    pub fn cancel_all(&self, reason: &str) -> usize {
        self.cancel_matching(
            |_| true,
            BreakpointCompletion::Cancelled(reason.to_string()),
        )
    }

    fn cancel_matching(
        &self,
        predicate: impl Fn(&BreakpointTask) -> bool,
        completion: BreakpointCompletion,
    ) -> usize {
        let pending = self
            .state
            .lock()
            .map(|mut state| {
                let ids = state
                    .order
                    .iter()
                    .filter(|id| {
                        state
                            .pending
                            .get(*id)
                            .is_some_and(|pending| predicate(&pending.task))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                ids.into_iter()
                    .filter_map(|id| remove_pending(&mut state, &id))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let count = pending.len();
        for pending in pending {
            let _ = pending.sender.send(PendingSignal {
                resolution: BreakpointResolution::Continue(BreakpointEdit::default()),
                completion: completion.clone(),
            });
        }
        if count > 0 {
            (self.notifier)();
        }
        count
    }

    fn cleanup_task(&self, task_id: &str) {
        let removed = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| remove_pending(&mut state, task_id))
            .is_some();
        if removed {
            (self.notifier)();
        }
    }
}

struct BreakpointWaitLease {
    coordinator: Weak<BreakpointCoordinator>,
    task_id: String,
    armed: bool,
}

impl BreakpointWaitLease {
    fn cleanup(&mut self) {
        if self.armed {
            if let Some(coordinator) = self.coordinator.upgrade() {
                coordinator.cleanup_task(&self.task_id);
            }
            self.armed = false;
        }
    }
}

impl Drop for BreakpointWaitLease {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn remove_pending(state: &mut BreakpointQueueState, task_id: &str) -> Option<PendingBreakpoint> {
    state.order.retain(|id| id != task_id);
    state.pending.remove(task_id)
}

fn validate_decision(
    task: &BreakpointTask,
    input: BreakpointDecisionInput,
) -> Result<BreakpointResolution, String> {
    match input.action.as_str() {
        "abort" => return Ok(BreakpointResolution::Abort),
        "continue" => {}
        _ => return Err("断点操作必须是 continue 或 abort".to_string()),
    }
    if task.stage == "request" {
        if let Some(method) = input.method.as_deref() {
            Method::from_bytes(method.trim().as_bytes()).map_err(|_| "请求方法无效".to_string())?;
        }
        if let Some(url) = input.url.as_deref() {
            validate_same_origin_url(&task.url, url)?;
        }
        if let Some(headers) = input.request_headers.as_ref() {
            validate_headers(headers)?;
            validate_managed_headers("request", &task.request_headers, headers)?;
        }
        validate_body_edit(task, input.request_body.as_deref())?;
    } else if task.stage == "response" {
        if let Some(status) = input.status {
            if !(100..=599).contains(&status) {
                return Err("响应状态码必须在 100 到 599 之间".to_string());
            }
        }
        if let Some(headers) = input.response_headers.as_ref() {
            validate_headers(headers)?;
            validate_managed_headers("response", &task.response_headers, headers)?;
        }
        validate_body_edit(task, input.response_body.as_deref())?;
    } else {
        return Err("断点阶段无效".to_string());
    }
    Ok(BreakpointResolution::Continue(BreakpointEdit {
        method: input.method.map(|value| value.trim().to_string()),
        url: input.url.map(|value| value.trim().to_string()),
        status: input.status,
        request_headers: input.request_headers,
        response_headers: input.response_headers,
        request_body: input.request_body,
        response_body: input.response_body,
    }))
}

fn validate_same_origin_url(original: &str, edited: &str) -> Result<(), String> {
    let original = Url::parse(original).map_err(|_| "原始请求 URL 无效".to_string())?;
    let edited = Url::parse(edited.trim()).map_err(|_| "请求 URL 无效".to_string())?;
    if original.scheme() != edited.scheme()
        || original.host_str() != edited.host_str()
        || original.port_or_known_default() != edited.port_or_known_default()
    {
        return Err("人工断点只允许修改同源 URL 的路径和参数".to_string());
    }
    Ok(())
}

fn validate_headers(headers: &[HeaderEntry]) -> Result<(), String> {
    if headers.len() > 200 {
        return Err("Header 最多 200 项".to_string());
    }
    let mut encoded_bytes = 0usize;
    for header in headers {
        if header.name.starts_with(':') {
            return Err("HTTP 伪 Header 由代理自动维护".to_string());
        }
        HeaderName::from_bytes(header.name.trim().as_bytes())
            .map_err(|_| format!("Header 名称无效: {}", header.name))?;
        HeaderValue::from_str(&header.value)
            .map_err(|_| format!("Header 值无效: {}", header.name))?;
        encoded_bytes = encoded_bytes
            .saturating_add(header.name.len())
            .saturating_add(header.value.len());
    }
    if encoded_bytes > 64 * 1024 {
        return Err("Header 总大小不能超过 64 KiB".to_string());
    }
    Ok(())
}

fn validate_managed_headers(
    stage: &str,
    original: &[HeaderEntry],
    edited: &[HeaderEntry],
) -> Result<(), String> {
    for name in managed_header_names(stage) {
        let before = header_values(original, name);
        let after = header_values(edited, name);
        if before != after {
            return Err(format!("{name} 由代理自动维护，不能在断点中直接修改"));
        }
    }
    Ok(())
}

fn managed_header_names(stage: &str) -> &'static [&'static str] {
    if stage == "request" {
        &[
            "connection",
            "content-length",
            "host",
            "keep-alive",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ]
    } else {
        &[
            "connection",
            "content-encoding",
            "content-length",
            "keep-alive",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ]
    }
}

fn header_values<'a>(headers: &'a [HeaderEntry], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
        .collect()
}

fn validate_body_edit(task: &BreakpointTask, body: Option<&str>) -> Result<(), String> {
    let Some(body) = body else {
        return Ok(());
    };
    if !task.body_editable {
        return Err(task
            .body_unavailable_reason
            .clone()
            .unwrap_or_else(|| "当前正文不能安全编辑".to_string()));
    }
    if body.len() > MAX_BREAKPOINT_BODY_BYTES {
        return Err("断点正文不能超过 2 MiB".to_string());
    }
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(timeout_ms: u64) -> RuntimeBreakpointRule {
        RuntimeBreakpointRule {
            id: "rule-1".to_string(),
            name: "登录断点".to_string(),
            stage: "request".to_string(),
            revision: 1,
            timeout_ms,
            abort_on_timeout: false,
        }
    }

    fn task() -> BreakpointTaskInput {
        BreakpointTaskInput {
            session_id: "session-1".to_string(),
            request_id: "request-1".to_string(),
            stage: "request".to_string(),
            method: "POST".to_string(),
            url: "https://example.com/login?a=1".to_string(),
            status: None,
            request_headers: vec![HeaderEntry {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            }],
            response_headers: vec![],
            request_body: Some("{\"a\":1}".to_string()),
            response_body: None,
            body_editable: true,
            body_unavailable_reason: None,
        }
    }

    async fn wait_for_queue_len(coordinator: &Arc<BreakpointCoordinator>, expected: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let actual = coordinator.snapshot().unwrap().tasks.len();
            if actual == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "断点队列未在时限内达到 {expected} 项，实际为 {actual} 项"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn resolves_a_waiting_task_with_validated_edits() {
        let coordinator = Arc::new(BreakpointCoordinator::default());
        let pending = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.pause(&rule(5_000), task()).await }
        });
        wait_for_queue_len(&coordinator, 1).await;
        let snapshot = coordinator.snapshot().unwrap();
        assert_eq!(snapshot.tasks.len(), 1);
        coordinator
            .resolve(BreakpointDecisionInput {
                task_id: snapshot.tasks[0].id.clone(),
                action: "continue".to_string(),
                method: Some("PUT".to_string()),
                url: Some("https://example.com/login?a=2".to_string()),
                request_body: Some("{\"a\":2}".to_string()),
                ..Default::default()
            })
            .unwrap();
        let result = pending.await.unwrap();
        assert_eq!(result.completion, BreakpointCompletion::Submitted);
        let BreakpointResolution::Continue(edit) = result.resolution else {
            panic!("expected continue")
        };
        assert_eq!(edit.method.as_deref(), Some("PUT"));
        assert_eq!(edit.request_body.as_deref(), Some("{\"a\":2}"));
        assert!(coordinator.snapshot().unwrap().tasks.is_empty());
    }

    #[tokio::test]
    async fn times_out_without_leaving_a_stale_task() {
        let coordinator = Arc::new(BreakpointCoordinator::default());
        let result = coordinator.pause(&rule(10), task()).await;
        assert_eq!(result.completion, BreakpointCompletion::TimedOut);
        assert!(matches!(
            result.resolution,
            BreakpointResolution::Continue(_)
        ));
        assert!(coordinator.snapshot().unwrap().tasks.is_empty());
    }

    #[tokio::test]
    async fn timeout_can_abort_without_leaving_a_stale_task() {
        let coordinator = Arc::new(BreakpointCoordinator::default());
        let mut aborting_rule = rule(10);
        aborting_rule.abort_on_timeout = true;
        let result = coordinator.pause(&aborting_rule, task()).await;
        assert_eq!(result.completion, BreakpointCompletion::TimedOut);
        assert!(matches!(result.resolution, BreakpointResolution::Abort));
        assert!(coordinator.snapshot().unwrap().tasks.is_empty());
    }

    #[tokio::test]
    async fn keeps_the_queue_bounded_and_never_blocks_on_overflow() {
        let coordinator = Arc::new(BreakpointCoordinator::with_capacity(1));
        let first = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.pause(&rule(5_000), task()).await }
        });
        wait_for_queue_len(&coordinator, 1).await;
        let overflow = coordinator.pause(&rule(5_000), task()).await;
        assert_eq!(overflow.completion, BreakpointCompletion::QueueFull);
        assert_eq!(coordinator.snapshot().unwrap().skipped_count, 1);
        coordinator.cancel_all("测试结束");
        let _ = first.await;
    }

    #[tokio::test]
    async fn dropping_the_waiter_invalidates_the_task() {
        let coordinator = Arc::new(BreakpointCoordinator::default());
        let pending = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.pause(&rule(5_000), task()).await }
        });
        wait_for_queue_len(&coordinator, 1).await;
        assert_eq!(coordinator.snapshot().unwrap().tasks.len(), 1);
        pending.abort();
        wait_for_queue_len(&coordinator, 0).await;
        assert!(coordinator.snapshot().unwrap().tasks.is_empty());
    }

    #[tokio::test]
    async fn cancelling_a_rule_releases_only_its_waiting_tasks() {
        let coordinator = Arc::new(BreakpointCoordinator::default());
        let first = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.pause(&rule(5_000), task()).await }
        });
        let second = tokio::spawn({
            let coordinator = coordinator.clone();
            async move {
                let mut other_rule = rule(5_000);
                other_rule.id = "rule-2".to_string();
                coordinator.pause(&other_rule, task()).await
            }
        });
        wait_for_queue_len(&coordinator, 2).await;
        assert_eq!(coordinator.cancel_rule("rule-1", "规则已停用"), 1);
        let first = first.await.unwrap();
        assert_eq!(
            first.completion,
            BreakpointCompletion::Cancelled("规则已停用".to_string())
        );
        assert_eq!(coordinator.snapshot().unwrap().tasks.len(), 1);
        coordinator.cancel_all("测试结束");
        let _ = second.await;
    }

    #[test]
    fn rejects_cross_origin_and_managed_header_edits() {
        let task = BreakpointTask {
            id: "task-1".to_string(),
            session_id: "session-1".to_string(),
            request_id: "request-1".to_string(),
            rule_id: "rule-1".to_string(),
            rule_name: "test".to_string(),
            stage: "request".to_string(),
            method: "GET".to_string(),
            url: "https://example.com/a".to_string(),
            status: None,
            request_headers: vec![HeaderEntry {
                name: "Host".to_string(),
                value: "example.com".to_string(),
            }],
            response_headers: vec![],
            request_body: None,
            response_body: None,
            body_editable: true,
            body_unavailable_reason: None,
            created_at: 0,
            expires_at: 1,
        };
        assert!(validate_decision(
            &task,
            BreakpointDecisionInput {
                task_id: task.id.clone(),
                action: "continue".to_string(),
                url: Some("https://other.example/a".to_string()),
                ..Default::default()
            }
        )
        .is_err());
        assert!(validate_decision(
            &task,
            BreakpointDecisionInput {
                task_id: task.id.clone(),
                action: "continue".to_string(),
                request_headers: Some(vec![]),
                ..Default::default()
            }
        )
        .is_err());
    }
}
