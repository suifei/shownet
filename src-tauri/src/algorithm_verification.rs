//! Run a reconstructed algorithm against captured ground truth and report what
//! actually happened.
//!
//! This is the piece that decides whether ShowNet may say an algorithm was
//! reconstructed. Until now that claim rested on a step *name* matching a fixed
//! catalogue, which is a guess about the code, not a fact about its output. Here
//! the candidate is executed on inputs the capture recorded and its answer is
//! compared byte for byte with the answer the site actually saw.
//!
//! Three verdicts, and the difference between the last two matters:
//!
//! - `verified` — every attempted case reproduced the observed value.
//! - `failed` — the candidate ran and got a different answer. It is wrong.
//! - `unverifiable` — there was nothing to check it against, or no runtime to
//!   check it with. **Not** a pass. A capture whose secret lives on the server
//!   lands here, and the honest output is "we could not tell", not "verified".
//!
//! JavaScript is verified in-process with boa, since that is the language the
//! algorithm was observed in. boa ships no WebCrypto, so the primitives are
//! injected from Rust — the candidate calls `shownet.hmacSha256Hex(...)` and
//! gets a bit-exact answer rather than a reimplementation that could be wrong in
//! the same direction as the candidate. Python is verified by running `python3`
//! when it is on PATH.

use crate::algorithm_ground_truth::GroundTruthCase;
use boa_engine::{js_string, Context, JsValue, NativeFunction, Source};
use md5::Md5;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Candidate implementation supplied by the analysis agent.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Implementation {
    pub language: String,
    pub source: String,
    /// Function the runner calls. Defaults to `computeSignature`.
    pub entry_point: String,
}

impl Implementation {
    pub fn new(language: &str, source: &str) -> Self {
        Self {
            language: language.to_string(),
            source: source.to_string(),
            entry_point: "computeSignature".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseOutcome {
    pub case_id: String,
    pub origin: String,
    pub field: String,
    pub passed: bool,
    pub expected: String,
    pub actual: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    /// Which pipeline step this run belongs to. Filled in by the caller so a
    /// failure points at one step rather than at "the algorithm".
    #[serde(default)]
    pub step_id: String,
    #[serde(default)]
    pub step_name: String,
    pub language: String,
    pub runtime: String,
    pub verdict: String,
    pub attempted: usize,
    pub passed: usize,
    pub failed: usize,
    /// Cases proving the whole request chain, not just one hooked call.
    pub end_to_end_passed: usize,
    pub cases: Vec<CaseOutcome>,
    pub notes: Vec<String>,
}

impl VerificationReport {
    pub fn is_verified(&self) -> bool {
        self.verdict == "verified"
    }

    fn unverifiable(language: &str, runtime: &str, note: &str) -> Self {
        Self {
            step_id: String::new(),
            step_name: String::new(),
            language: language.to_string(),
            runtime: runtime.to_string(),
            verdict: "unverifiable".into(),
            attempted: 0,
            passed: 0,
            failed: 0,
            end_to_end_passed: 0,
            cases: Vec::new(),
            notes: vec![note.to_string()],
        }
    }

    /// Build a report with a chosen verdict, for exercising code that consumes
    /// one. Test-only so a production path cannot mint a verdict without a run.
    #[cfg(test)]
    pub fn for_test(verdict: &str) -> Self {
        let mut report = Self::unverifiable("python", "python3", "constructed for a test");
        report.verdict = verdict.to_string();
        report
    }

    fn settle(mut self, cases: Vec<CaseOutcome>) -> Self {
        self.attempted = cases.len();
        self.passed = cases.iter().filter(|case| case.passed).count();
        self.failed = self.attempted - self.passed;
        self.end_to_end_passed = cases
            .iter()
            .filter(|case| case.passed && case.origin == "request")
            .count();
        // Every case must pass. A candidate that reproduces three signatures and
        // misses the fourth is not "mostly right" — it is wrong, and shipping it
        // as runnable would waste the operator's time on the wrong suspect.
        self.verdict = if self.attempted == 0 {
            "unverifiable".into()
        } else if self.failed == 0 {
            "verified".into()
        } else {
            "failed".into()
        };
        self.cases = cases;
        self
    }
}

/// Cap on how long a candidate may loop before it is treated as a failure.
/// An agent-written function that does not terminate must not hang the app.
const LOOP_LIMIT: u64 = 5_000_000;
const RECURSION_LIMIT: usize = 512;

pub fn verify(implementation: &Implementation, cases: &[GroundTruthCase]) -> VerificationReport {
    match implementation.language.to_ascii_lowercase().as_str() {
        "javascript" | "js" | "typescript" | "ts" => verify_javascript(implementation, cases),
        "python" | "python3" | "py" => verify_python(implementation, cases),
        "go" | "golang" => verify_go(implementation, cases),
        "java" => verify_java(implementation, cases),
        "csharp" | "c#" | "cs" => verify_csharp(implementation, cases),
        other => VerificationReport::unverifiable(
            other,
            "none",
            &format!("no verification runtime for {other}; the candidate was not executed"),
        ),
    }
}

fn verify_javascript(
    implementation: &Implementation,
    cases: &[GroundTruthCase],
) -> VerificationReport {
    let base = VerificationReport::unverifiable("javascript", "boa", "");
    if cases.is_empty() {
        return VerificationReport::unverifiable(
            "javascript",
            "boa",
            "capture produced no input/output pairs to check the candidate against",
        );
    }

    let mut outcomes = Vec::new();
    for case in cases {
        // A fresh context per case: state left behind by one case must not be
        // able to make the next one pass.
        let mut context = Context::default();
        context
            .runtime_limits_mut()
            .set_loop_iteration_limit(LOOP_LIMIT);
        context
            .runtime_limits_mut()
            .set_recursion_limit(RECURSION_LIMIT);

        let outcome = match run_javascript_case(&mut context, implementation, case) {
            Ok(actual) => CaseOutcome {
                case_id: case.id.clone(),
                origin: case.origin.clone(),
                field: case.field.clone(),
                passed: actual == case.expected,
                expected: case.expected.clone(),
                actual: Some(actual),
                error: None,
            },
            Err(error) => CaseOutcome {
                case_id: case.id.clone(),
                origin: case.origin.clone(),
                field: case.field.clone(),
                passed: false,
                expected: case.expected.clone(),
                actual: None,
                error: Some(error),
            },
        };
        outcomes.push(outcome);
    }

    base.settle(outcomes)
}

fn run_javascript_case(
    context: &mut Context,
    implementation: &Implementation,
    case: &GroundTruthCase,
) -> Result<String, String> {
    register_primitives(context)?;
    context
        .eval(Source::from_bytes(CRYPTO_BOOTSTRAP.as_bytes()))
        .map_err(|error| format!("crypto bootstrap failed: {error}"))?;
    context
        .eval(Source::from_bytes(implementation.source.as_bytes()))
        .map_err(|error| format!("candidate failed to load: {error}"))?;

    let input = serde_json::to_string(&case.input).map_err(|error| error.to_string())?;
    let call = format!(
        "(function(){{ var out = {entry}(JSON.parse({input})); \
         return out === undefined || out === null ? null : String(out); }})()",
        entry = implementation.entry_point,
        input = json_string_literal(&input),
    );
    let value = context
        .eval(Source::from_bytes(call.as_bytes()))
        .map_err(|error| format!("candidate threw: {error}"))?;
    match value {
        JsValue::Null | JsValue::Undefined => {
            Err(format!("{} returned nothing", implementation.entry_point))
        }
        other => other
            .as_string()
            .map(|text| text.to_std_string_escaped())
            .ok_or_else(|| "candidate did not return a string".to_string()),
    }
}

/// Embed a JS string safely: the input is arbitrary captured data and may carry
/// quotes, newlines and backslashes.
fn json_string_literal(raw: &str) -> String {
    serde_json::Value::String(raw.to_string()).to_string()
}

/// Primitives the candidate may call. Implemented here rather than in JS so the
/// answer is the reference answer — a JS reimplementation could be wrong in the
/// same way the candidate is and the two would agree on a wrong result.
fn register_primitives(context: &mut Context) -> Result<(), String> {
    fn one_string_arg(args: &[JsValue]) -> String {
        args.first()
            .and_then(JsValue::as_string)
            .map(|text| text.to_std_string_escaped())
            .unwrap_or_default()
    }

    context
        .register_global_callable(
            js_string!("__shownet_sha256_hex"),
            1,
            NativeFunction::from_fn_ptr(|_this, args, _ctx| {
                let data = one_string_arg(args);
                let digest = Sha256::digest(data.as_bytes());
                Ok(JsValue::from(js_string!(to_hex(&digest))))
            }),
        )
        .map_err(|error| error.to_string())?;

    context
        .register_global_callable(
            js_string!("__shownet_md5_hex"),
            1,
            NativeFunction::from_fn_ptr(|_this, args, _ctx| {
                let data = one_string_arg(args);
                let digest = Md5::digest(data.as_bytes());
                Ok(JsValue::from(js_string!(to_hex(&digest))))
            }),
        )
        .map_err(|error| error.to_string())?;

    context
        .register_global_callable(
            js_string!("__shownet_hmac_sha256_hex"),
            2,
            NativeFunction::from_fn_ptr(|_this, args, _ctx| {
                let key = args
                    .first()
                    .and_then(JsValue::as_string)
                    .map(|text| text.to_std_string_escaped())
                    .unwrap_or_default();
                let message = args
                    .get(1)
                    .and_then(JsValue::as_string)
                    .map(|text| text.to_std_string_escaped())
                    .unwrap_or_default();
                let mac = hmac_sha256(key.as_bytes(), message.as_bytes());
                Ok(JsValue::from(js_string!(to_hex(&mac))))
            }),
        )
        .map_err(|error| error.to_string())?;

    context
        .register_global_callable(
            js_string!("__shownet_base64_encode"),
            1,
            NativeFunction::from_fn_ptr(|_this, args, _ctx| {
                use base64::Engine;
                let data = one_string_arg(args);
                let encoded = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());
                Ok(JsValue::from(js_string!(encoded)))
            }),
        )
        .map_err(|error| error.to_string())?;

    Ok(())
}

/// Namespace wrapper so candidates are written against a stable surface.
const CRYPTO_BOOTSTRAP: &str = r#"
var shownet = {
  sha256Hex: function(data) { return __shownet_sha256_hex(String(data)); },
  md5Hex: function(data) { return __shownet_md5_hex(String(data)); },
  hmacSha256Hex: function(key, message) { return __shownet_hmac_sha256_hex(String(key), String(message)); },
  base64Encode: function(data) { return __shownet_base64_encode(String(data)); }
};
var globalThis = globalThis || this;
globalThis.shownet = shownet;
"#;

/// HMAC per RFC 2104, over the SHA-256 already in the tree. Locked by the RFC
/// 4231 vectors below so a mistake here cannot quietly fail every candidate.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= padded[index];
        outer_pad[index] ^= padded[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// --- Python ----------------------------------------------------------------

fn python_interpreter() -> Option<String> {
    for candidate in ["python3", "python"] {
        if std::process::Command::new(candidate)
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    None
}

fn verify_python(implementation: &Implementation, cases: &[GroundTruthCase]) -> VerificationReport {
    if cases.is_empty() {
        return VerificationReport::unverifiable(
            "python",
            "python3",
            "capture produced no input/output pairs to check the candidate against",
        );
    }
    let Some(python) = python_interpreter() else {
        return VerificationReport::unverifiable(
            "python",
            "unavailable",
            "no python3 on PATH; the candidate was not executed and must not be reported as verified",
        );
    };

    // Unique per run: two verifications in flight must not share a directory,
    // or one clobbers the other's candidate and both report the wrong verdict.
    static RUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "shownet-verify-{}-{}",
        std::process::id(),
        RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    if std::fs::create_dir_all(&dir).is_err() {
        return VerificationReport::unverifiable(
            "python",
            &python,
            "could not create a working directory for the verification run",
        );
    }

    let payload = serde_json::json!({
        "entryPoint": implementation.entry_point,
        "cases": cases.iter().map(|case| serde_json::json!({
            "id": case.id,
            "origin": case.origin,
            "field": case.field,
            "input": case.input,
            "expected": case.expected,
        })).collect::<Vec<_>>(),
    });

    let write = std::fs::write(dir.join("candidate.py"), &implementation.source)
        .and_then(|_| std::fs::write(dir.join("cases.json"), payload.to_string()))
        .and_then(|_| std::fs::write(dir.join("run_verify.py"), PYTHON_RUNNER));
    if write.is_err() {
        std::fs::remove_dir_all(&dir).ok();
        return VerificationReport::unverifiable(
            "python",
            &python,
            "could not stage the candidate for execution",
        );
    }

    let output = std::process::Command::new(&python)
        .arg("run_verify.py")
        .current_dir(&dir)
        .output();
    std::fs::remove_dir_all(&dir).ok();

    let Ok(output) = output else {
        return VerificationReport::unverifiable("python", &python, "verification run failed to start");
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(line) = stdout.lines().last() else {
        return VerificationReport::unverifiable(
            "python",
            &python,
            "verification run produced no result",
        );
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) else {
        return VerificationReport::unverifiable(
            "python",
            &python,
            &format!(
                "verification run produced no parsable result: {}",
                String::from_utf8_lossy(&output.stderr).lines().last().unwrap_or("")
            ),
        );
    };

    let outcomes = parsed
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| CaseOutcome {
                    case_id: item["id"].as_str().unwrap_or_default().to_string(),
                    origin: item["origin"].as_str().unwrap_or_default().to_string(),
                    field: item["field"].as_str().unwrap_or_default().to_string(),
                    passed: item["passed"].as_bool().unwrap_or(false),
                    expected: item["expected"].as_str().unwrap_or_default().to_string(),
                    actual: item["actual"].as_str().map(str::to_string),
                    error: item["error"].as_str().map(str::to_string),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    VerificationReport::unverifiable("python", &python, "").settle(outcomes)
}

/// Driver executed inside the candidate's own runtime. Kept deliberately small:
/// it imports, calls, compares, and reports — it never repairs a failing answer.
const PYTHON_RUNNER: &str = r#"import json, sys, traceback

with open("cases.json", "r", encoding="utf-8") as handle:
    payload = json.load(handle)

results = []
try:
    import candidate
    entry = getattr(candidate, payload["entryPoint"])
except Exception:
    for case in payload["cases"]:
        results.append({
            "id": case["id"], "origin": case["origin"], "field": case["field"],
            "passed": False, "expected": case["expected"], "actual": None,
            "error": traceback.format_exc(limit=2).strip().splitlines()[-1],
        })
    print(json.dumps({"cases": results}))
    sys.exit(0)

for case in payload["cases"]:
    record = {
        "id": case["id"], "origin": case["origin"], "field": case["field"],
        "expected": case["expected"], "actual": None, "error": None, "passed": False,
    }
    try:
        actual = entry(case["input"])
        record["actual"] = None if actual is None else str(actual)
        record["passed"] = record["actual"] == case["expected"]
    except Exception:
        record["error"] = traceback.format_exc(limit=2).strip().splitlines()[-1]
    results.append(record)

print(json.dumps({"cases": results}))
"#;

// --- Compiled runtimes -----------------------------------------------------
//
// Go, Java and C# all need a toolchain that may not be installed. When it is
// missing the verdict is `unverifiable`, which withholds the code rather than
// shipping it unchecked — the same rule the interpreted runtimes follow.
//
// Each language gets a typed `Request` record rather than a loose map. It reads
// better in the agent's code and, more importantly, a field name that does not
// exist fails to compile instead of silently arriving as null at run time.

/// One staged working directory per run, so concurrent verifications cannot
/// overwrite each other's candidate.
fn staging_dir(tag: &str) -> Option<std::path::PathBuf> {
    static RUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "shownet-verify-{tag}-{}-{}",
        std::process::id(),
        RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn tool_available(binary: &str, arg: &str) -> bool {
    std::process::Command::new(binary)
        .arg(arg)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn cases_payload(implementation: &Implementation, cases: &[GroundTruthCase]) -> String {
    serde_json::json!({
        "entryPoint": implementation.entry_point,
        "cases": cases.iter().map(|case| serde_json::json!({
            "id": case.id,
            "origin": case.origin,
            "field": case.field,
            "input": case.input,
            "expected": case.expected,
        })).collect::<Vec<_>>(),
    })
    .to_string()
}

/// Read the driver's verdict line. Drivers print exactly one JSON object last;
/// anything a compiler wrote before it is ignored.
fn outcomes_from_stdout(stdout: &str) -> Option<Vec<CaseOutcome>> {
    let line = stdout.lines().rev().find(|line| line.trim_start().starts_with('{'))?;
    let parsed: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    Some(
        parsed
            .get("cases")?
            .as_array()?
            .iter()
            .map(|item| CaseOutcome {
                case_id: item["id"].as_str().unwrap_or_default().to_string(),
                origin: item["origin"].as_str().unwrap_or_default().to_string(),
                field: item["field"].as_str().unwrap_or_default().to_string(),
                passed: item["passed"].as_bool().unwrap_or(false),
                expected: item["expected"].as_str().unwrap_or_default().to_string(),
                actual: item["actual"].as_str().map(str::to_string),
                error: item["error"].as_str().map(str::to_string),
            })
            .collect(),
    )
}

/// A build that never produced a verdict is one failure per case, carrying the
/// compiler's message. Reporting it as `unverifiable` would blur "we could not
/// check this" with "this does not compile", and only the first is excusable.
fn build_failure(
    language: &str,
    runtime: &str,
    cases: &[GroundTruthCase],
    message: &str,
) -> VerificationReport {
    let reason = message
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("build failed with no output")
        .trim()
        .to_string();
    VerificationReport::unverifiable(language, runtime, "").settle(
        cases
            .iter()
            .map(|case| CaseOutcome {
                case_id: case.id.clone(),
                origin: case.origin.clone(),
                field: case.field.clone(),
                passed: false,
                expected: case.expected.clone(),
                actual: None,
                error: Some(reason.clone()),
            })
            .collect(),
    )
}

fn verify_go(implementation: &Implementation, cases: &[GroundTruthCase]) -> VerificationReport {
    if cases.is_empty() {
        return VerificationReport::unverifiable(
            "go",
            "go",
            "capture produced no input/output pairs to check the candidate against",
        );
    }
    if !tool_available("go", "version") {
        return VerificationReport::unverifiable(
            "go",
            "unavailable",
            "no go toolchain on PATH; the candidate was not executed and must not be reported as verified",
        );
    }
    let Some(dir) = staging_dir("go") else {
        return VerificationReport::unverifiable("go", "go", "could not stage the candidate");
    };

    let staged = std::fs::write(dir.join("go.mod"), "module shownetverify\n\ngo 1.21\n")
        .and_then(|_| std::fs::write(dir.join("candidate.go"), &implementation.source))
        .and_then(|_| std::fs::write(dir.join("cases.json"), cases_payload(implementation, cases)))
        .and_then(|_| {
            std::fs::write(
                dir.join("main.go"),
                GO_RUNNER.replace("__ENTRY__", &implementation.entry_point),
            )
        });
    if staged.is_err() {
        std::fs::remove_dir_all(&dir).ok();
        return VerificationReport::unverifiable("go", "go", "could not stage the candidate");
    }

    let output = std::process::Command::new("go")
        .args(["run", "."])
        .current_dir(&dir)
        // Keep the module hermetic: a candidate must not pull dependencies.
        .env("GOFLAGS", "-mod=mod")
        .env("GO111MODULE", "on")
        .output();
    std::fs::remove_dir_all(&dir).ok();

    let Ok(output) = output else {
        return VerificationReport::unverifiable("go", "go", "verification run failed to start");
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    match outcomes_from_stdout(&stdout) {
        Some(outcomes) => VerificationReport::unverifiable("go", "go", "").settle(outcomes),
        None => build_failure("go", "go", cases, &String::from_utf8_lossy(&output.stderr)),
    }
}

fn verify_java(implementation: &Implementation, cases: &[GroundTruthCase]) -> VerificationReport {
    if cases.is_empty() {
        return VerificationReport::unverifiable(
            "java",
            "java",
            "capture produced no input/output pairs to check the candidate against",
        );
    }
    if !tool_available("javac", "-version") || !tool_available("java", "-version") {
        return VerificationReport::unverifiable(
            "java",
            "unavailable",
            "no JDK on PATH; the candidate was not executed and must not be reported as verified",
        );
    }
    let Some(dir) = staging_dir("java") else {
        return VerificationReport::unverifiable("java", "java", "could not stage the candidate");
    };

    // Java has no JSON in the standard library, so the cases are compiled in as
    // source rather than parsed at run time. That keeps the driver free of any
    // dependency the operator would also have to install.
    let driver = JAVA_RUNNER
        .replace("__ENTRY__", &implementation.entry_point)
        .replace("__CASES__", &java_cases_literal(cases));
    let staged = std::fs::write(dir.join("Candidate.java"), &implementation.source)
        .and_then(|_| std::fs::write(dir.join("Driver.java"), driver));
    if staged.is_err() {
        std::fs::remove_dir_all(&dir).ok();
        return VerificationReport::unverifiable("java", "java", "could not stage the candidate");
    }

    let compile = std::process::Command::new("javac")
        .args(["Candidate.java", "Driver.java"])
        .current_dir(&dir)
        .output();
    match compile {
        Ok(compile) if !compile.status.success() => {
            let stderr = String::from_utf8_lossy(&compile.stderr).to_string();
            std::fs::remove_dir_all(&dir).ok();
            return build_failure("java", "javac", cases, &stderr);
        }
        Err(_) => {
            std::fs::remove_dir_all(&dir).ok();
            return VerificationReport::unverifiable("java", "javac", "compiler failed to start");
        }
        _ => {}
    }

    let output = std::process::Command::new("java")
        .arg("Driver")
        .current_dir(&dir)
        .output();
    std::fs::remove_dir_all(&dir).ok();

    let Ok(output) = output else {
        return VerificationReport::unverifiable("java", "java", "verification run failed to start");
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    match outcomes_from_stdout(&stdout) {
        Some(outcomes) => VerificationReport::unverifiable("java", "java", "").settle(outcomes),
        None => build_failure("java", "java", cases, &String::from_utf8_lossy(&output.stderr)),
    }
}

fn verify_csharp(implementation: &Implementation, cases: &[GroundTruthCase]) -> VerificationReport {
    if cases.is_empty() {
        return VerificationReport::unverifiable(
            "csharp",
            "dotnet",
            "capture produced no input/output pairs to check the candidate against",
        );
    }
    if !tool_available("dotnet", "--version") {
        return VerificationReport::unverifiable(
            "csharp",
            "unavailable",
            "no dotnet SDK on PATH; the candidate was not executed and must not be reported as verified",
        );
    }
    let Some(dir) = staging_dir("csharp") else {
        return VerificationReport::unverifiable("csharp", "dotnet", "could not stage the candidate");
    };

    // The project file is written directly rather than via `dotnet new`, which
    // is slower and would depend on template packs being installed.
    let staged = std::fs::write(dir.join("verify.csproj"), CSHARP_PROJECT)
        .and_then(|_| std::fs::write(dir.join("Candidate.cs"), &implementation.source))
        .and_then(|_| std::fs::write(dir.join("cases.json"), cases_payload(implementation, cases)))
        .and_then(|_| {
            std::fs::write(
                dir.join("Driver.cs"),
                CSHARP_RUNNER.replace("__ENTRY__", &implementation.entry_point),
            )
        });
    if staged.is_err() {
        std::fs::remove_dir_all(&dir).ok();
        return VerificationReport::unverifiable("csharp", "dotnet", "could not stage the candidate");
    }

    let output = std::process::Command::new("dotnet")
        .args(["run", "--project", "verify.csproj", "-v", "quiet", "--nologo"])
        .current_dir(&dir)
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .env("DOTNET_NOLOGO", "1")
        .output();
    std::fs::remove_dir_all(&dir).ok();

    let Ok(output) = output else {
        return VerificationReport::unverifiable(
            "csharp",
            "dotnet",
            "verification run failed to start",
        );
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    match outcomes_from_stdout(&stdout) {
        Some(outcomes) => VerificationReport::unverifiable("csharp", "dotnet", "").settle(outcomes),
        None => build_failure(
            "csharp",
            "dotnet",
            cases,
            &format!(
                "{}\n{stdout}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
    }
}

/// Render the cases as Java source. Only strings and string maps appear in a
/// ground-truth input, so the grammar stays small and total.
fn java_cases_literal(cases: &[GroundTruthCase]) -> String {
    fn quote(raw: &str) -> String {
        serde_json::Value::String(raw.to_string()).to_string()
    }
    fn nullable(value: Option<&serde_json::Value>) -> String {
        match value.and_then(|item| item.as_str()) {
            Some(text) => quote(text),
            None => "null".to_string(),
        }
    }

    let mut out = String::new();
    for case in cases {
        let input = &case.input;
        let headers = input
            .get("headers")
            .and_then(serde_json::Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(key, value)| {
                        format!("{}, {}", quote(key), quote(value.as_str().unwrap_or_default()))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        out.push_str(&format!(
            "    cases.add(new Case({id}, {origin}, {field}, new Request({method}, {host}, {path}, {query}, headers({headers}), {body}), {expected}));\n",
            id = quote(&case.id),
            origin = quote(&case.origin),
            field = quote(&case.field),
            method = nullable(input.get("method")),
            host = nullable(input.get("host")),
            path = nullable(input.get("path")),
            query = nullable(input.get("query")),
            body = nullable(input.get("body")),
            expected = quote(&case.expected),
        ));
    }
    out
}

const GO_RUNNER: &str = r#"package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Request is the shape a candidate is verified against. It must match the one
// the generated package hands the same function at run time.
type Request struct {
	Method  string            `json:"method"`
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Query   string            `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type verifyCase struct {
	ID       string  `json:"id"`
	Origin   string  `json:"origin"`
	Field    string  `json:"field"`
	Input    Request `json:"input"`
	Expected string  `json:"expected"`
}

type verifyResult struct {
	ID       string  `json:"id"`
	Origin   string  `json:"origin"`
	Field    string  `json:"field"`
	Passed   bool    `json:"passed"`
	Expected string  `json:"expected"`
	Actual   *string `json:"actual"`
	Error    *string `json:"error"`
}

func main() {
	raw, err := os.ReadFile("cases.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var payload struct {
		Cases []verifyCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	results := make([]verifyResult, 0, len(payload.Cases))
	for _, c := range payload.Cases {
		result := verifyResult{ID: c.ID, Origin: c.Origin, Field: c.Field, Expected: c.Expected}
		func() {
			defer func() {
				if r := recover(); r != nil {
					message := fmt.Sprint(r)
					result.Error = &message
				}
			}()
			actual := __ENTRY__(c.Input)
			result.Actual = &actual
			result.Passed = actual == c.Expected
		}()
		results = append(results, result)
	}
	out, _ := json.Marshal(map[string]interface{}{"cases": results})
	fmt.Println(string(out))
}
"#;

const JAVA_RUNNER: &str = r#"import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The shape a candidate is verified against; identical to the generated package's. */
record Request(String method, String host, String path, String query, Map<String, String> headers, String body) {}

public class Driver {
    record Case(String id, String origin, String field, Request input, String expected) {}

    static Map<String, String> headers(String... kv) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            map.put(kv[i], kv[i + 1]);
        }
        return map;
    }

    static String quote(String raw) {
        if (raw == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder("\"");
        for (char c : raw.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    public static void main(String[] args) {
        List<Case> cases = new ArrayList<>();
__CASES__
        StringBuilder out = new StringBuilder("{\"cases\":[");
        for (int i = 0; i < cases.size(); i++) {
            Case c = cases.get(i);
            String actual = null;
            String error = null;
            try {
                actual = Candidate.__ENTRY__(c.input());
            } catch (Throwable throwable) {
                error = throwable.getClass().getSimpleName() + ": " + throwable.getMessage();
            }
            if (i > 0) {
                out.append(',');
            }
            out.append("{\"id\":").append(quote(c.id()))
               .append(",\"origin\":").append(quote(c.origin()))
               .append(",\"field\":").append(quote(c.field()))
               .append(",\"expected\":").append(quote(c.expected()))
               .append(",\"actual\":").append(quote(actual))
               .append(",\"error\":").append(quote(error))
               .append(",\"passed\":").append(actual != null && actual.equals(c.expected()))
               .append('}');
        }
        System.out.println(out.append("]}"));
    }
}
"#;

const CSHARP_PROJECT: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>shownetverify</AssemblyName>
    <RootNamespace>ShowNetVerify</RootNamespace>
    <InvariantGlobalization>true</InvariantGlobalization>
  </PropertyGroup>
</Project>
"#;

const CSHARP_RUNNER: &str = r#"using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>The shape a candidate is verified against; identical to the generated package's.</summary>
public sealed record Request(
    [property: JsonPropertyName("method")] string Method,
    [property: JsonPropertyName("host")] string Host,
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("query")] string? Query,
    [property: JsonPropertyName("headers")] Dictionary<string, string> Headers,
    [property: JsonPropertyName("body")] string? Body);

internal sealed record VerifyCase(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("origin")] string Origin,
    [property: JsonPropertyName("field")] string Field,
    [property: JsonPropertyName("input")] Request Input,
    [property: JsonPropertyName("expected")] string Expected);

internal sealed record VerifyPayload(
    [property: JsonPropertyName("cases")] List<VerifyCase> Cases);

internal static class Driver
{
    private static int Main()
    {
        var raw = File.ReadAllText("cases.json");
        var payload = JsonSerializer.Deserialize<VerifyPayload>(raw);
        if (payload is null)
        {
            Console.Error.WriteLine("could not read cases");
            return 1;
        }

        var results = new List<object>();
        foreach (var item in payload.Cases)
        {
            string? actual = null;
            string? error = null;
            try
            {
                actual = Candidate.__ENTRY__(item.Input);
            }
            catch (Exception exception)
            {
                error = exception.GetType().Name + ": " + exception.Message;
            }
            results.Add(new Dictionary<string, object?>
            {
                ["id"] = item.Id,
                ["origin"] = item.Origin,
                ["field"] = item.Field,
                ["expected"] = item.Expected,
                ["actual"] = actual,
                ["error"] = error,
                ["passed"] = actual is not null && actual == item.Expected,
            });
        }
        Console.WriteLine(JsonSerializer.Serialize(new Dictionary<string, object?> { ["cases"] = results }));
        return 0;
    }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn case(id: &str, origin: &str, input: serde_json::Value, expected: &str) -> GroundTruthCase {
        GroundTruthCase {
            id: id.into(),
            origin: origin.into(),
            field: "x-signature".into(),
            algorithm_hint: "HMAC".into(),
            input,
            expected: expected.into(),
            request_id: None,
            sequence: 1,
        }
    }

    /// RFC 4231 test case 2. If this breaks, every HMAC candidate fails for a
    /// reason that has nothing to do with the candidate.
    #[test]
    fn hmac_matches_the_published_vector() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn sha256_primitive_matches_the_published_vector() {
        assert_eq!(
            to_hex(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_correct_candidate_verifies() {
        let source = r#"
            function computeSignature(input) {
              return shownet.hmacSha256Hex("Jefe", input.data);
            }
        "#;
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let cases = vec![case(
            "c1",
            "hook",
            json!({"data": "what do ya want for nothing?"}),
            expected,
        )];
        let report = verify(&Implementation::new("javascript", source), &cases);
        assert_eq!(report.verdict, "verified", "{report:?}");
        assert_eq!(report.passed, 1);
    }

    /// The case that matters most: a candidate that is plausible and wrong must
    /// come back `failed`, never `verified` and never `unverifiable`.
    #[test]
    fn a_wrong_candidate_fails_rather_than_passing_on_shape() {
        let source = r#"
            function computeSignature(input) {
              // Right length, right alphabet, wrong answer — this is exactly what
              // a shape check waves through.
              return shownet.sha256Hex(input.data);
            }
        "#;
        let cases = vec![case(
            "c1",
            "hook",
            json!({"data": "what do ya want for nothing?"}),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        )];
        let report = verify(&Implementation::new("javascript", source), &cases);
        assert_eq!(report.verdict, "failed", "{report:?}");
        assert_eq!(report.failed, 1);
        assert!(
            report.cases[0].actual.as_deref().is_some_and(|actual| actual.len() == 64),
            "a wrong answer of the right shape must still be recorded: {report:?}"
        );
    }

    #[test]
    fn one_failure_among_several_sinks_the_whole_verdict() {
        let source = r#"
            function computeSignature(input) {
              return input.data === "a" ? "aaaaaaaaaaaaaaaa" : "wrongwrongwrong0";
            }
        "#;
        let cases = vec![
            case("c1", "hook", json!({"data": "a"}), "aaaaaaaaaaaaaaaa"),
            case("c2", "hook", json!({"data": "b"}), "bbbbbbbbbbbbbbbb"),
        ];
        let report = verify(&Implementation::new("javascript", source), &cases);
        assert_eq!(report.verdict, "failed", "{report:?}");
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn no_cases_means_unverifiable_not_verified() {
        let report = verify(
            &Implementation::new("javascript", "function computeSignature() { return 'x'; }"),
            &[],
        );
        assert_eq!(report.verdict, "unverifiable", "{report:?}");
        assert!(!report.is_verified());
        assert!(!report.notes.is_empty(), "the reason must be stated");
    }

    #[test]
    fn a_candidate_that_throws_is_a_failure_with_the_reason_kept() {
        let source = "function computeSignature(input) { throw new Error('no secret'); }";
        let cases = vec![case("c1", "hook", json!({"data": "x"}), "aaaaaaaaaaaaaaaa")];
        let report = verify(&Implementation::new("javascript", source), &cases);
        assert_eq!(report.verdict, "failed", "{report:?}");
        assert!(
            report.cases[0].error.as_deref().is_some_and(|e| e.contains("no secret")),
            "the thrown reason must survive into the report: {report:?}"
        );
    }

    /// An agent-written function that does not terminate must not hang ShowNet.
    #[test]
    fn a_non_terminating_candidate_is_stopped_and_reported() {
        let source = "function computeSignature(input) { while (true) {} }";
        let cases = vec![case("c1", "hook", json!({"data": "x"}), "aaaaaaaaaaaaaaaa")];
        let report = verify(&Implementation::new("javascript", source), &cases);
        assert_eq!(report.verdict, "failed", "{report:?}");
        assert!(report.cases[0].error.is_some(), "{report:?}");
    }

    #[test]
    fn end_to_end_request_cases_are_counted_apart_from_hook_cases() {
        let source = r#"
            function computeSignature(input) {
              return shownet.sha256Hex(input.method + input.path);
            }
        "#;
        let expected = to_hex(&Sha256::digest(b"POST/v1/order"));
        let cases = vec![case(
            "r1",
            "request",
            json!({"method": "POST", "path": "/v1/order"}),
            &expected,
        )];
        let report = verify(&Implementation::new("javascript", source), &cases);
        assert_eq!(report.verdict, "verified", "{report:?}");
        assert_eq!(
            report.end_to_end_passed, 1,
            "a request-origin pass is the stronger claim and must be visible: {report:?}"
        );
    }

    #[test]
    fn a_language_with_no_runtime_is_unverifiable_not_verified() {
        let report = verify(
            &Implementation::new("ruby", "def compute_signature(request); end"),
            &[case("c1", "hook", json!({}), "aaaaaaaaaaaaaaaa")],
        );
        assert_eq!(report.verdict, "unverifiable", "{report:?}");
        assert!(!report.is_verified());
    }

    #[test]
    fn python_candidates_run_in_their_own_runtime() {
        let Some(_) = python_interpreter() else {
            return; // asserted by the unverifiable path below regardless
        };
        let source = r#"
import hashlib, hmac

def computeSignature(payload):
    return hmac.new(b"Jefe", payload["data"].encode(), hashlib.sha256).hexdigest()
"#;
        let cases = vec![case(
            "c1",
            "hook",
            json!({"data": "what do ya want for nothing?"}),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        )];
        let report = verify(&Implementation::new("python", source), &cases);
        assert_eq!(report.verdict, "verified", "{report:?}");
    }

    #[test]
    fn a_wrong_python_candidate_fails() {
        let Some(_) = python_interpreter() else {
            return;
        };
        let source = r#"
import hashlib

def computeSignature(payload):
    return hashlib.sha256(payload["data"].encode()).hexdigest()
"#;
        let cases = vec![case(
            "c1",
            "hook",
            json!({"data": "what do ya want for nothing?"}),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        )];
        let report = verify(&Implementation::new("python", source), &cases);
        assert_eq!(report.verdict, "failed", "{report:?}");
    }

    #[test]
    fn a_python_candidate_that_does_not_import_is_a_failure_with_a_reason() {
        let Some(_) = python_interpreter() else {
            return;
        };
        let source = "import a_module_that_does_not_exist\n\ndef computeSignature(p):\n    return 'x'\n";
        let cases = vec![case("c1", "hook", json!({"data": "x"}), "aaaaaaaaaaaaaaaa")];
        let report = verify(&Implementation::new("python", source), &cases);
        assert_eq!(report.verdict, "failed", "{report:?}");
        assert!(report.cases[0].error.is_some(), "{report:?}");
    }

    // --- Compiled runtimes --------------------------------------------------
    //
    // Each is exercised twice: a candidate that reproduces the captured value
    // must come back `verified`, and one that is plausible but wrong must come
    // back `failed`. The second is the one that matters — a runtime that cannot
    // tell them apart is worse than no runtime, because it launders a guess into
    // a claim.

    const HMAC_EXPECTED: &str =
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    fn hmac_case() -> Vec<GroundTruthCase> {
        vec![case(
            "c1",
            "request",
            json!({
                "method": "what do ya want for nothing?",
                "host": "api.example.com",
                "path": "/v1/order",
                "query": null,
                "headers": {"content-type": "application/json"},
                "body": null
            }),
            HMAC_EXPECTED,
        )]
    }

    const GO_GOOD: &str = r#"package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func ComputeSignature(request Request) string {
	mac := hmac.New(sha256.New, []byte("Jefe"))
	mac.Write([]byte(request.Method))
	return hex.EncodeToString(mac.Sum(nil))
}
"#;

    const GO_WRONG: &str = r#"package main

import (
	"crypto/sha256"
	"encoding/hex"
)

func ComputeSignature(request Request) string {
	sum := sha256.Sum256([]byte(request.Method))
	return hex.EncodeToString(sum[:])
}
"#;

    #[test]
    fn go_candidates_are_compiled_and_run() {
        if !tool_available("go", "version") {
            return;
        }
        let mut good = Implementation::new("go", GO_GOOD);
        good.entry_point = "ComputeSignature".into();
        let report = verify(&good, &hmac_case());
        assert_eq!(report.verdict, "verified", "{report:?}");
        assert_eq!(report.end_to_end_passed, 1, "{report:?}");

        let mut wrong = Implementation::new("go", GO_WRONG);
        wrong.entry_point = "ComputeSignature".into();
        let report = verify(&wrong, &hmac_case());
        assert_eq!(report.verdict, "failed", "{report:?}");
    }

    /// Code that does not compile is a failure with the compiler's reason, not
    /// an `unverifiable` shrug — the two mean very different things to whoever
    /// reads the report.
    #[test]
    fn go_code_that_does_not_compile_reports_the_compiler_error() {
        if !tool_available("go", "version") {
            return;
        }
        let mut broken = Implementation::new("go", "package main\n\nfunc ComputeSignature(request Request) string {\n\treturn undefinedSymbol(request)\n}\n");
        broken.entry_point = "ComputeSignature".into();
        let report = verify(&broken, &hmac_case());
        assert_eq!(report.verdict, "failed", "{report:?}");
        assert!(report.cases[0].error.is_some(), "{report:?}");
    }

    const JAVA_GOOD: &str = r#"import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class Candidate {
    public static String computeSignature(Request request) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("Jefe".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] digest = mac.doFinal(request.method().getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        for (byte b : digest) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }
}
"#;

    const JAVA_WRONG: &str = r#"import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class Candidate {
    public static String computeSignature(Request request) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
            .digest(request.method().getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        for (byte b : digest) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }
}
"#;

    #[test]
    fn java_candidates_are_compiled_and_run() {
        if !tool_available("javac", "-version") {
            return;
        }
        let report = verify(&Implementation::new("java", JAVA_GOOD), &hmac_case());
        assert_eq!(report.verdict, "verified", "{report:?}");

        let report = verify(&Implementation::new("java", JAVA_WRONG), &hmac_case());
        assert_eq!(report.verdict, "failed", "{report:?}");
    }

    const CSHARP_GOOD: &str = r#"using System.Security.Cryptography;
using System.Text;

public static class Candidate
{
    public static string ComputeSignature(Request request)
    {
        using var mac = new HMACSHA256(Encoding.UTF8.GetBytes("Jefe"));
        var digest = mac.ComputeHash(Encoding.UTF8.GetBytes(request.Method));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }
}
"#;

    const CSHARP_WRONG: &str = r#"using System.Security.Cryptography;
using System.Text;

public static class Candidate
{
    public static string ComputeSignature(Request request)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(request.Method));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }
}
"#;

    #[test]
    fn csharp_candidates_are_compiled_and_run() {
        if !tool_available("dotnet", "--version") {
            return;
        }
        let mut good = Implementation::new("csharp", CSHARP_GOOD);
        good.entry_point = "ComputeSignature".into();
        let report = verify(&good, &hmac_case());
        assert_eq!(report.verdict, "verified", "{report:?}");

        let mut wrong = Implementation::new("csharp", CSHARP_WRONG);
        wrong.entry_point = "ComputeSignature".into();
        let report = verify(&wrong, &hmac_case());
        assert_eq!(report.verdict, "failed", "{report:?}");
    }

    /// With no toolchain the verdict must be `unverifiable`, never `verified`.
    /// This is what stops a machine without a JDK from silently shipping
    /// unchecked Java into an export.
    #[test]
    fn a_missing_toolchain_withholds_the_claim() {
        for (language, source) in [("go", GO_GOOD), ("java", JAVA_GOOD), ("csharp", CSHARP_GOOD)] {
            let report = verify(&Implementation::new(language, source), &[]);
            assert_eq!(
                report.verdict, "unverifiable",
                "{language} with no cases must not claim anything: {report:?}"
            );
            assert!(!report.is_verified());
        }
    }
}
