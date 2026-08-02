//! One-click evaluation package export: report + protocolSchemas + scorecard + fidelity.

use crate::protection_analysis;
use crate::scorecard;
use crate::storage::Storage;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationExportResult {
    pub session_id: String,
    pub analysis_id: Option<String>,
    pub directory: String,
    pub files: Vec<String>,
    pub bytes_written: usize,
    pub scorecard_composite: Option<f64>,
    pub all_full_credit: Option<bool>,
}

pub fn export_evaluation_package(
    storage: &Storage,
    session_id: &str,
    analysis_id: Option<&str>,
    output_dir: Option<&Path>,
) -> Result<EvaluationExportResult, String> {
    storage.get_session(session_id)?;
    let directory = match output_dir {
        Some(path) => path.join(package_folder_name(session_id)),
        None => default_directory(storage, session_id)?,
    };
    std::fs::create_dir_all(&directory)
        .map_err(|e| format!("创建评估包目录失败 {}: {e}", directory.display()))?;

    let protection = protection_analysis::analyze_session(storage, session_id)?;
    let card = scorecard::score_session_storage(storage, session_id, false)?;

    let report = match analysis_id {
        Some(id) if !id.is_empty() => storage.get_analysis_report(id).ok(),
        _ => storage.latest_analysis_report(session_id).ok().flatten(),
    };

    let mut files = Vec::new();
    let mut bytes = 0usize;

    let write = |name: &str,
                 content: &str,
                 files: &mut Vec<String>,
                 bytes: &mut usize|
     -> Result<(), String> {
        let path = directory.join(name);
        std::fs::write(&path, content.as_bytes()).map_err(|e| format!("写入 {name} 失败: {e}"))?;
        *bytes += content.len();
        files.push(path.to_string_lossy().to_string());
        Ok(())
    };

    let manifest = json!({
        "kind": "shownet-evaluation-package",
        "version": 1,
        "sessionId": session_id,
        "analysisId": report.as_ref().map(|r| r.id.clone()),
        "exportedAtUnixMs": now_ms(),
        "scorecard": {
            "weightedComposite": card.weighted_composite,
            "allFullCredit": card.all_full_credit,
            "l0": card.layers.l0_product.as_ref().map(|d| d.score),
            "l1": card.layers.l1_evidence_depth.as_ref().map(|d| d.score),
            "l2": card.layers.l2_algorithm_depth.as_ref().map(|d| d.score),
        },
        "files": [
            "README.md",
            "manifest.json",
            "evidence-header.json",
            "protocol-schemas.json",
            "capture-fidelity.json",
            "scorecard.json",
            "analysis-report.md",
            "evidence-discipline.json"
        ],
    });
    write(
        "manifest.json",
        &serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?,
        &mut files,
        &mut bytes,
    )?;

    let readme = format!(
        r#"# ShowNet 评估包

- session: `{session_id}`
- analysis: `{analysis}`
- scorecard L0 composite: **{composite}** (allFullCredit={full})
- L1 evidence depth: {l1}
- L2 algorithm depth: {l2}

## 内容

| 文件 | 说明 |
|------|------|
| evidence-header.json | 证据头（工具/decoder/provider） |
| protocol-schemas.json | 字段级协议 schema |
| capture-fidelity.json | 入站/出站 TLS、Headless、Hook 解密侧 |
| scorecard.json | L0/L1/L2 机检 |
| analysis-report.md | AI 报告（若有） |
| evidence-discipline.json | confirmed / inference / notCaptured |

默认 **不包含** bypass exploit。已采集的配置候选与密钥值按证据原样写入有界产物。
"#,
        analysis = report.as_ref().map(|r| r.id.as_str()).unwrap_or("(none)"),
        composite = card.weighted_composite,
        full = card.all_full_credit,
        l1 = card
            .layers
            .l1_evidence_depth
            .as_ref()
            .map(|d| d.score.to_string())
            .unwrap_or_else(|| "n/a".into()),
        l2 = card
            .layers
            .l2_algorithm_depth
            .as_ref()
            .map(|d| d.score.to_string())
            .unwrap_or_else(|| "n/a".into()),
    );
    write("README.md", &readme, &mut files, &mut bytes)?;

    write_json(
        &directory,
        "evidence-header.json",
        protection.get("evidenceHeader").unwrap_or(&Value::Null),
        &mut files,
        &mut bytes,
    )?;
    write_json(
        &directory,
        "protocol-schemas.json",
        protection.get("protocolSchemas").unwrap_or(&Value::Null),
        &mut files,
        &mut bytes,
    )?;
    write_json(
        &directory,
        "capture-fidelity.json",
        protection
            .get("captureFidelity")
            .or_else(|| protection.pointer("/protocolSchemas/fidelity"))
            .unwrap_or(&Value::Null),
        &mut files,
        &mut bytes,
    )?;
    write_json(
        &directory,
        "evidence-discipline.json",
        protection.get("evidenceDiscipline").unwrap_or(&Value::Null),
        &mut files,
        &mut bytes,
    )?;

    let card_json = serde_json::to_value(&card).map_err(|e| e.to_string())?;
    write_json(
        &directory,
        "scorecard.json",
        &card_json,
        &mut files,
        &mut bytes,
    )?;

    let report_md = report
        .as_ref()
        .map(|r| r.content.clone())
        .unwrap_or_else(|| "_No analysis report in package scope._\n".into());
    write("analysis-report.md", &report_md, &mut files, &mut bytes)?;

    Ok(EvaluationExportResult {
        session_id: session_id.to_string(),
        analysis_id: report.map(|r| r.id),
        directory: directory.to_string_lossy().to_string(),
        files,
        bytes_written: bytes,
        scorecard_composite: Some(card.weighted_composite),
        all_full_credit: Some(card.all_full_credit),
    })
}

fn write_json(
    dir: &Path,
    name: &str,
    value: &Value,
    files: &mut Vec<String>,
    bytes: &mut usize,
) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    let path = dir.join(name);
    std::fs::write(&path, text.as_bytes()).map_err(|e| format!("写入 {name} 失败: {e}"))?;
    *bytes += text.len();
    files.push(path.to_string_lossy().to_string());
    Ok(())
}

fn package_folder_name(session_id: &str) -> String {
    let short = session_id
        .strip_prefix("session-")
        .unwrap_or(session_id)
        .chars()
        .take(12)
        .collect::<String>();
    format!("shownet-eval-{}-{}", short, now_ms())
}

fn default_directory(storage: &Storage, session_id: &str) -> Result<PathBuf, String> {
    let base = storage
        .data_directory()
        .unwrap_or_else(|_| dirs_fallback())
        .join("exports")
        .join("evaluation");
    Ok(base.join(package_folder_name(session_id)))
}

fn dirs_fallback() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/Application Support/com.shownet.desktop")
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scorecard::seed_scorecard_fixture;

    #[test]
    fn exports_evaluation_package_with_scorecard_and_schemas() {
        let storage = Storage::in_memory().expect("mem");
        let sid = seed_scorecard_fixture(&storage).expect("seed");
        let dir = std::env::temp_dir().join(format!("shownet-eval-test-{}", now_ms()));
        let result =
            export_evaluation_package(&storage, &sid, None, Some(dir.as_path())).expect("export");
        assert!(Path::new(&result.directory).join("scorecard.json").exists());
        assert!(Path::new(&result.directory)
            .join("protocol-schemas.json")
            .exists());
        assert!(Path::new(&result.directory).join("manifest.json").exists());
        assert!(Path::new(&result.directory)
            .join("capture-fidelity.json")
            .exists());
        assert!(result.bytes_written > 100);
        let _ = std::fs::remove_dir_all(dir);
    }
}
