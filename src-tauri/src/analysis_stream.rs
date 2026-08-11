use std::time::Instant;

pub(crate) const GRAPH_ARTIFACT_MARKER: &str = "```graph-artifacts";

#[derive(Default)]
pub(crate) struct NativeReportStream {
    pending: String,
    visible: String,
    artifact_block_started: bool,
}

impl NativeReportStream {
    pub(crate) fn push(&mut self, delta: &str) -> String {
        if self.artifact_block_started || delta.is_empty() {
            return String::new();
        }
        self.pending.push_str(delta);
        if let Some(start) = self.pending.find(GRAPH_ARTIFACT_MARKER) {
            let visible = self.pending[..start].to_string();
            self.pending.clear();
            self.artifact_block_started = true;
            self.visible.push_str(&visible);
            return visible;
        }

        let retained = (1..GRAPH_ARTIFACT_MARKER.len())
            .rev()
            .find(|length| self.pending.ends_with(&GRAPH_ARTIFACT_MARKER[..*length]))
            .unwrap_or(0);
        let emit_end = self.pending.len().saturating_sub(retained);
        let visible = self.pending[..emit_end].to_string();
        self.pending.drain(..emit_end);
        self.visible.push_str(&visible);
        visible
    }

    pub(crate) fn finish(&mut self) -> String {
        if self.artifact_block_started {
            return String::new();
        }
        let visible = std::mem::take(&mut self.pending);
        self.visible.push_str(&visible);
        visible
    }

    pub(crate) fn visible(&self) -> &str {
        &self.visible
    }
}

pub(crate) struct FirstVisibleLatency {
    started_at: Instant,
    recorded: bool,
}

impl FirstVisibleLatency {
    pub(crate) fn new(started_at: Instant) -> Self {
        Self {
            started_at,
            recorded: false,
        }
    }

    pub(crate) fn observe(&mut self, visible_delta: &str) -> Option<u64> {
        self.observe_at(visible_delta, Instant::now())
    }

    fn observe_at(&mut self, visible_delta: &str, observed_at: Instant) -> Option<u64> {
        if self.recorded || visible_delta.trim().is_empty() {
            return None;
        }
        self.recorded = true;
        let elapsed = observed_at
            .saturating_duration_since(self.started_at)
            .as_millis();
        Some(elapsed.min(u128::from(u64::MAX)) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn streams_visible_text_and_hides_split_artifacts() {
        let mut stream = NativeReportStream::default();
        assert_eq!(stream.push("# 分析报告\n\n结论"), "# 分析报告\n\n结论");
        assert_eq!(stream.push("已生成。\n\n```graph-art"), "已生成。\n\n");
        assert_eq!(
            stream.push("ifacts\n{\"artifacts\":[{\"skillId\":\"api\"}]}\n```"),
            ""
        );
        assert_eq!(stream.finish(), "");
        assert_eq!(stream.visible(), "# 分析报告\n\n结论已生成。\n\n");
    }

    #[test]
    fn flushes_trailing_marker_prefix_when_no_artifact_block_arrives() {
        let mut stream = NativeReportStream::default();
        assert_eq!(stream.push("报告正文```graph-art"), "报告正文");
        assert_eq!(stream.finish(), "```graph-art");
        assert_eq!(stream.visible(), "报告正文```graph-art");
    }

    #[test]
    fn records_only_the_first_non_whitespace_visible_delta() {
        let started_at = Instant::now();
        let mut latency = FirstVisibleLatency::new(started_at);
        assert_eq!(
            latency.observe_at(" \n", started_at + Duration::from_millis(100)),
            None
        );
        assert_eq!(
            latency.observe_at("# 报告", started_at + Duration::from_millis(420)),
            Some(420)
        );
        assert_eq!(
            latency.observe_at("后续", started_at + Duration::from_millis(900)),
            None
        );
    }
}
