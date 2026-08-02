//! Session-id-driven autonomous analysis pipeline (no GUI).
//!
//! Chains skill planning → dynamic-protection aggregation → optional
//! algorithm-replay package export for already-captured sessions.

use crate::algorithm_replay;
use crate::protection_analysis;
use crate::skills;
use crate::storage::Storage;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutonomousAnalysisResult {
    pub session_id: String,
    pub mode: String,
    pub skill_plan: Value,
    pub protection: Value,
    pub export: Option<Value>,
    pub stages: Vec<String>,
    pub notes: Vec<String>,
}

/// Plan skills, run one-shot protection aggregation, optionally export replay artifacts.
pub fn run_autonomous_session_analysis(
    storage: &Storage,
    session_id: &str,
    mode: &str,
    export_language: Option<&str>,
    export_dir: Option<&Path>,
) -> Result<AutonomousAnalysisResult, String> {
    storage.get_session(session_id)?;
    let mode = if mode.trim().is_empty() {
        "crypto"
    } else {
        mode.trim()
    };
    if !matches!(mode, "auto" | "api" | "security" | "performance" | "crypto") {
        return Err(format!("不支持的分析模式: {mode}"));
    }

    let mut stages = Vec::new();
    let mut notes = Vec::new();

    let requests = storage.list_requests(session_id, Some(10_000), Some(0))?;
    let plan = skills::build_plan(mode, &requests)?;
    stages.push("plan_skills".into());
    notes.extend(plan.reasons.iter().cloned());

    let protection = protection_analysis::analyze_session(storage, session_id)?;
    stages.push("aggregate_dynamic_protection".into());

    let export = if let Some(language) = export_language {
        let exported =
            algorithm_replay::export_algorithm_replay(storage, session_id, language, export_dir)?;
        stages.push("export_analysis_artifacts".into());
        Some(serde_json::to_value(exported).map_err(|error| error.to_string())?)
    } else {
        notes.push(
            "Export skipped (no language). Pass language to materialize ALGORITHM_SPEC + replay package."
                .into(),
        );
        None
    };

    let skill_plan = serde_json::to_value(&plan).map_err(|error| error.to_string())?;

    Ok(AutonomousAnalysisResult {
        session_id: session_id.to_string(),
        mode: mode.to_string(),
        skill_plan,
        protection,
        export,
        stages,
        notes,
    })
}

pub fn pipeline_summary_json(result: &AutonomousAnalysisResult) -> Value {
    json!({
        "sessionId": result.session_id,
        "mode": result.mode,
        "stages": result.stages,
        "selectedSkillIds": result.skill_plan.get("selectedSkillIds").cloned().unwrap_or(json!([])),
        "toolNames": result.skill_plan.get("toolNames").cloned().unwrap_or(json!([])),
        "providerCandidates": result.protection.get("providerCandidates").cloned().unwrap_or(json!([])),
        "challengeJs": result.protection.pointer("/protocolSchemas/challengeJs").cloned().unwrap_or(json!({})),
        "exportDirectory": result.export.as_ref().and_then(|value| value.get("directory").cloned()),
        "notes": result.notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CapturedRequestInput, HeaderEntry};
    use crate::storage::Storage;

    fn storage() -> Storage {
        Storage::in_memory().expect("memory")
    }

    fn base(session_id: &str, host: &str, path: &str) -> CapturedRequestInput {
        CapturedRequestInput {
            id: None,
            session_id: session_id.to_string(),
            source: "browser".into(),
            source_instance_id: Some("pipe".into()),
            timestamp: Some(1_785_393_200_000),
            method: "GET".into(),
            scheme: Some("https".into()),
            host: host.to_string(),
            port: Some(443),
            path: path.to_string(),
            query: None,
            status: 200,
            resource_type: "fetch".into(),
            size_bytes: 100,
            duration_ms: 10,
            protocol: "h2".into(),
            tls_version: Some("TLS 1.3".into()),
            tls_fingerprint: None,
            risk_level: "none".into(),
            request_headers: vec![],
            response_headers: vec![],
            request_body: None,
            response_body: Some(String::new()),
            response_body_metadata: None,
            crypto_snippets: None,
            hook: None,
        }
    }

    #[test]
    fn autonomous_pipeline_plans_aggregates_and_exports_without_gui() {
        let storage = storage();
        let session = storage.create_session(Some("pipe".into())).unwrap();
        let sid = session.id.clone();

        let mut script = base(
            &sid,
            "73472ccc2f21.edge.sdk.awswaf.com",
            "/73472ccc2f21/0416b5675b4f/challenge.js",
        );
        script.resource_type = "script".into();
        script.response_headers = vec![HeaderEntry {
            name: "content-type".into(),
            value: "application/javascript".into(),
        }];
        script.response_body = Some(
            r#"
function a0_0x1fd3(){
  var _0x345a0b = ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','Zoey','Present','2.4.0','mp_verify'];
  a0_0x1fd3 = function(){ return _0x345a0b; };
  return _0x345a0b;
}
function a0_0x4f2e(index, key){
  var arr = a0_0x1fd3();
  return a0_0x4f2e = function(index, key){ index = index - 0; return arr[index]; }, a0_0x4f2e(index, key);
}
const t = "awswaf_session_storage";
"#
            .into(),
        );
        storage.store_request(script).unwrap();

        let mut verify = base(
            &sid,
            "73472ccc2f21.edge.sdk.awswaf.com",
            "/73472ccc2f21/0416b5675b4f/mp_verify",
        );
        verify.method = "POST".into();
        verify.request_body = Some(
            r#"{"challenge":{"input":"eyJ","hmac":"x","region":"ap-east-1"},"signals":[{"name":"Zoey"}]}"#
                .into(),
        );
        verify.response_body =
            Some(r#"{"token":"2e1254cf-d58d-4c53-8afb-08be29b8d202:AAoA:xx"}"#.into());
        storage.store_request(verify).unwrap();

        let dir = std::env::temp_dir().join(format!(
            "shownet-auto-pipe-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        let result = run_autonomous_session_analysis(
            &storage,
            &sid,
            "crypto",
            Some("python"),
            Some(dir.as_path()),
        )
        .unwrap();

        assert!(result.stages.iter().any(|s| s == "plan_skills"));
        assert!(result
            .stages
            .iter()
            .any(|s| s == "aggregate_dynamic_protection"));
        assert!(result
            .stages
            .iter()
            .any(|s| s == "export_analysis_artifacts"));

        let skills = result.skill_plan["selectedSkillIds"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            skills
                .iter()
                .any(|s| s.as_str() == Some("dynamic-signature")),
            "skills={skills:?}"
        );
        let tools = result.skill_plan["toolNames"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            tools
                .iter()
                .any(|t| t.as_str() == Some("shownet_analyze_dynamic_protection")),
            "tools={tools:?}"
        );

        let providers = result.protection["providerCandidates"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(providers
            .iter()
            .any(|p| p["provider"].as_str() == Some("AWS WAF")));

        let export = result.export.expect("export");
        assert!(export["directory"].as_str().is_some());
        assert!(Path::new(export["directory"].as_str().unwrap()).exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
