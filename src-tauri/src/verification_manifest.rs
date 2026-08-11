use crate::algorithm_verification::VerificationReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(crate) const VERIFICATION_MANIFEST_SCHEMA_VERSION: &str = "1.0.0";
pub(crate) const ARTIFACT_VERSION: &str = "1.0.0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationVerdict {
    Verified,
    Failed,
    Unverifiable,
}

impl VerificationVerdict {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "verified" => Ok(Self::Verified),
            "failed" => Ok(Self::Failed),
            "unverifiable" => Ok(Self::Unverifiable),
            other => Err(format!("unsupported verification verdict: {other}")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactDescriptor {
    pub kind: String,
    pub version: String,
    pub session_id: String,
    pub language: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSummary {
    pub identifiers: Vec<String>,
    pub count: usize,
    pub hashes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeVerification {
    pub step_id: String,
    pub step_name: String,
    pub implementation_sha256: String,
    pub language: String,
    pub runtime: String,
    pub verdict: VerificationVerdict,
    pub attempted: usize,
    pub passed: usize,
    pub failed: usize,
    pub end_to_end_passed: usize,
    pub notes: Vec<String>,
}

impl RuntimeVerification {
    pub(crate) fn from_report(report: &VerificationReport) -> Result<Self, String> {
        Ok(Self {
            step_id: report.step_id.clone(),
            step_name: report.step_name.clone(),
            implementation_sha256: report.implementation_sha256.clone(),
            language: report.language.clone(),
            runtime: report.runtime.clone(),
            verdict: VerificationVerdict::parse(&report.verdict)?,
            attempted: report.attempted,
            passed: report.passed,
            failed: report.failed,
            end_to_end_passed: report.end_to_end_passed,
            notes: report.notes.clone(),
        })
    }

    pub(crate) fn unverifiable(language: &str, runtime: &str, note: &str) -> Self {
        Self {
            step_id: String::new(),
            step_name: String::new(),
            implementation_sha256: String::new(),
            language: language.to_string(),
            runtime: runtime.to_string(),
            verdict: VerificationVerdict::Unverifiable,
            attempted: 0,
            passed: 0,
            failed: 0,
            end_to_end_passed: 0,
            notes: vec![note.to_string()],
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerdictCounts {
    pub verified: usize,
    pub failed: usize,
    pub unverifiable: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedFileDigest {
    pub name: String,
    pub role: String,
    pub bytes: usize,
    pub sha256: String,
}

impl GeneratedFileDigest {
    pub(crate) fn from_content(name: &str, role: &str, content: &str) -> Self {
        Self {
            name: name.to_string(),
            role: role.to_string(),
            bytes: content.len(),
            sha256: format!("{:x}", Sha256::digest(content.as_bytes())),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationGate {
    pub verdict: VerificationVerdict,
    pub executable_verified_logic_emitted: bool,
    pub package_runtime_required: bool,
    pub package_runtime_verified: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactVerificationManifest {
    pub schema_version: String,
    pub artifact: ArtifactDescriptor,
    pub evidence: EvidenceSummary,
    pub runtimes: Vec<RuntimeVerification>,
    pub verdict_counts: VerdictCounts,
    /// Digests of every generated artifact file except this manifest itself.
    /// Including the manifest would require a recursive, unstable digest.
    pub generated_files: Vec<GeneratedFileDigest>,
    pub gaps: Vec<String>,
    pub gate: VerificationGate,
}

pub(crate) struct ManifestInput {
    pub kind: String,
    pub session_id: String,
    pub language: String,
    pub evidence_identifiers: Vec<String>,
    pub evidence_hashes: Vec<String>,
    pub runtimes: Vec<RuntimeVerification>,
    pub generated_files: Vec<GeneratedFileDigest>,
    pub gaps: Vec<String>,
    pub executable_verified_logic_emitted: bool,
    pub package_runtime_required: bool,
    pub package_runtime_verified: bool,
}

impl ArtifactVerificationManifest {
    pub(crate) fn build(mut input: ManifestInput) -> Self {
        input.evidence_identifiers.sort();
        input.evidence_identifiers.dedup();
        input.evidence_hashes.sort();
        input.evidence_hashes.dedup();
        input.gaps.sort();
        input.gaps.dedup();

        if input.runtimes.is_empty()
            && !(input.package_runtime_required && input.package_runtime_verified)
        {
            input.runtimes.push(RuntimeVerification::unverifiable(
                &input.language,
                expected_runtime(&input.language),
                "no candidate implementation was executed for this artifact",
            ));
        }

        let mut verdict_counts = VerdictCounts::default();
        for run in &input.runtimes {
            match run.verdict {
                VerificationVerdict::Verified => verdict_counts.verified += 1,
                VerificationVerdict::Failed => verdict_counts.failed += 1,
                VerificationVerdict::Unverifiable => verdict_counts.unverifiable += 1,
            }
        }

        let mut reasons = Vec::new();
        let verdict = if verdict_counts.failed > 0 {
            reasons.push(format!(
                "{} runtime verification run(s) produced a wrong result",
                verdict_counts.failed
            ));
            VerificationVerdict::Failed
        } else {
            if verdict_counts.unverifiable > 0 {
                reasons.push(format!(
                    "{} runtime verification run(s) could not be established",
                    verdict_counts.unverifiable
                ));
            }
            if !input.executable_verified_logic_emitted {
                reasons
                    .push("no executable logic backed by a verified run was emitted".to_string());
            }
            if input.package_runtime_required && !input.package_runtime_verified {
                reasons.push("the generated package was not executed end to end".to_string());
            }
            if !input.gaps.is_empty() {
                reasons.push(format!(
                    "{} explicit evidence gap(s) remain",
                    input.gaps.len()
                ));
            }
            if reasons.is_empty() {
                reasons.push(
                    "every required runtime run passed and no evidence gaps remain".to_string(),
                );
                VerificationVerdict::Verified
            } else {
                VerificationVerdict::Unverifiable
            }
        };

        Self {
            schema_version: VERIFICATION_MANIFEST_SCHEMA_VERSION.to_string(),
            artifact: ArtifactDescriptor {
                kind: input.kind,
                version: ARTIFACT_VERSION.to_string(),
                session_id: input.session_id,
                language: input.language,
            },
            evidence: EvidenceSummary {
                count: input.evidence_identifiers.len(),
                identifiers: input.evidence_identifiers,
                hashes: input.evidence_hashes,
            },
            runtimes: input.runtimes,
            verdict_counts,
            generated_files: input.generated_files,
            gaps: input.gaps,
            gate: VerificationGate {
                verdict,
                executable_verified_logic_emitted: input.executable_verified_logic_emitted,
                package_runtime_required: input.package_runtime_required,
                package_runtime_verified: input.package_runtime_verified,
                reasons,
            },
        }
    }
}

pub(crate) fn runtime_verifications_for_language(
    reports: &[VerificationReport],
    language: &str,
) -> Result<Vec<RuntimeVerification>, String> {
    reports
        .iter()
        .filter(|report| report.language.eq_ignore_ascii_case(language))
        .map(RuntimeVerification::from_report)
        .collect()
}

pub(crate) fn evidence_identifiers_for_language(
    reports: &[VerificationReport],
    language: &str,
) -> Vec<String> {
    reports
        .iter()
        .filter(|report| report.language.eq_ignore_ascii_case(language))
        .flat_map(|report| report.cases.iter().map(|case| case.case_id.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn evidence_hashes_for_language(
    reports: &[VerificationReport],
    language: &str,
) -> Vec<String> {
    reports
        .iter()
        .filter(|report| report.language.eq_ignore_ascii_case(language))
        .flat_map(|report| report.cases.iter().map(|case| case.evidence_sha256.clone()))
        .filter(|hash| !hash.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn expected_runtime(language: &str) -> &'static str {
    match language {
        "javascript" | "typescript" => "boa",
        "python" => "python3",
        "go" => "go",
        "java" => "javac+java",
        "csharp" => "dotnet",
        _ => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(verdict: VerificationVerdict) -> RuntimeVerification {
        RuntimeVerification {
            step_id: "step-1".into(),
            step_name: "candidate".into(),
            implementation_sha256: "candidate-sha256".into(),
            language: "python".into(),
            runtime: "python3".into(),
            verdict,
            attempted: 1,
            passed: usize::from(verdict == VerificationVerdict::Verified),
            failed: usize::from(verdict == VerificationVerdict::Failed),
            end_to_end_passed: 0,
            notes: Vec::new(),
        }
    }

    fn manifest(verdict: VerificationVerdict) -> ArtifactVerificationManifest {
        ArtifactVerificationManifest::build(ManifestInput {
            kind: "test-package".into(),
            session_id: "session-1".into(),
            language: "python".into(),
            evidence_identifiers: vec!["request:1".into()],
            evidence_hashes: vec!["abc".into()],
            runtimes: vec![run(verdict)],
            generated_files: vec![GeneratedFileDigest::from_content("a.py", "code", "pass\n")],
            gaps: Vec::new(),
            executable_verified_logic_emitted: true,
            package_runtime_required: false,
            package_runtime_verified: false,
        })
    }

    #[test]
    fn a_wrong_candidate_can_never_produce_a_verified_gate() {
        let manifest = manifest(VerificationVerdict::Failed);
        assert_eq!(manifest.gate.verdict, VerificationVerdict::Failed);
        assert_eq!(manifest.verdict_counts.failed, 1);
        assert_eq!(manifest.verdict_counts.verified, 0);
    }

    #[test]
    fn an_absent_runtime_is_unverifiable_not_verified() {
        let manifest = ArtifactVerificationManifest::build(ManifestInput {
            kind: "test-package".into(),
            session_id: "session-1".into(),
            language: "csharp".into(),
            evidence_identifiers: vec!["request:1".into()],
            evidence_hashes: Vec::new(),
            runtimes: vec![RuntimeVerification::unverifiable(
                "csharp",
                "dotnet",
                "runtime absent",
            )],
            generated_files: Vec::new(),
            gaps: Vec::new(),
            executable_verified_logic_emitted: false,
            package_runtime_required: false,
            package_runtime_verified: false,
        });
        assert_eq!(manifest.gate.verdict, VerificationVerdict::Unverifiable);
        assert_eq!(manifest.verdict_counts.unverifiable, 1);
    }

    #[test]
    fn the_manifest_uses_only_the_shared_three_verdict_vocabulary() {
        for (verdict, encoded_verdict) in [
            (VerificationVerdict::Verified, "verified"),
            (VerificationVerdict::Failed, "failed"),
            (VerificationVerdict::Unverifiable, "unverifiable"),
        ] {
            let encoded = serde_json::to_value(manifest(verdict)).unwrap();
            assert_eq!(
                encoded
                    .pointer("/gate/verdict")
                    .and_then(|value| value.as_str()),
                Some(encoded_verdict)
            );
        }
    }

    #[test]
    fn a_required_package_run_cannot_be_inferred_from_component_checks() {
        let manifest = ArtifactVerificationManifest::build(ManifestInput {
            kind: "api-sdk".into(),
            session_id: "session-1".into(),
            language: "python".into(),
            evidence_identifiers: vec!["request:1".into()],
            evidence_hashes: vec!["abc".into()],
            runtimes: vec![run(VerificationVerdict::Verified)],
            generated_files: vec![GeneratedFileDigest::from_content(
                "client.py",
                "client",
                "pass\n",
            )],
            gaps: Vec::new(),
            executable_verified_logic_emitted: true,
            package_runtime_required: true,
            package_runtime_verified: false,
        });

        assert_eq!(manifest.gate.verdict, VerificationVerdict::Unverifiable);
        assert!(manifest
            .gate
            .reasons
            .iter()
            .any(|reason| reason.contains("not executed end to end")));
    }

    #[test]
    fn evidence_hashes_are_scoped_to_the_export_language_and_deduplicated() {
        use crate::algorithm_verification::CaseOutcome;

        let outcome = |hash: &str| CaseOutcome {
            case_id: "case-1".into(),
            origin: "request".into(),
            field: "x-signature".into(),
            evidence_sha256: hash.into(),
            passed: true,
            expected: "expected".into(),
            actual: Some("expected".into()),
            error: None,
        };
        let mut python = VerificationReport::for_test("verified");
        python.language = "python".into();
        python.cases = vec![outcome("python-case-hash"), outcome("python-case-hash")];
        let mut javascript = VerificationReport::for_test("verified");
        javascript.language = "javascript".into();
        javascript.cases = vec![outcome("javascript-case-hash")];

        assert_eq!(
            evidence_hashes_for_language(&[python, javascript], "python"),
            vec!["python-case-hash"]
        );
    }

    #[test]
    fn a_verified_package_without_crypto_does_not_require_a_fake_crypto_run() {
        let manifest = ArtifactVerificationManifest::build(ManifestInput {
            kind: "api-sdk".into(),
            session_id: "session-1".into(),
            language: "python".into(),
            evidence_identifiers: vec!["request:1".into()],
            evidence_hashes: vec!["abc".into()],
            runtimes: Vec::new(),
            generated_files: vec![GeneratedFileDigest::from_content(
                "client.py",
                "client",
                "pass\n",
            )],
            gaps: Vec::new(),
            executable_verified_logic_emitted: true,
            package_runtime_required: true,
            package_runtime_verified: true,
        });

        assert!(manifest.runtimes.is_empty());
        assert_eq!(manifest.gate.verdict, VerificationVerdict::Verified);
    }
}
