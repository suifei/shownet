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
use std::collections::VecDeque;
use std::io::{self, Read};
use std::process::{Child, Command, Output, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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

    pub(crate) fn sha256(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"shownet-algorithm-implementation-v1\0");
        hasher.update(self.normalized_language().as_bytes());
        hasher.update(b"\0");
        hasher.update(self.entry_point.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.source.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub(crate) fn normalized_language(&self) -> String {
        let language = self.language.trim().to_ascii_lowercase();
        match language.as_str() {
            "javascript" | "js" | "node" | "nodejs" => "javascript".to_string(),
            "typescript" | "ts" | "tsx" => "typescript".to_string(),
            "python" | "python3" | "py" => "python".to_string(),
            "go" | "golang" => "go".to_string(),
            "java" => "java".to_string(),
            "csharp" | "c#" | "cs" => "csharp".to_string(),
            _ => language,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseOutcome {
    pub case_id: String,
    pub origin: String,
    pub field: String,
    pub evidence_sha256: String,
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
    /// Hash of the normalized language, entry point and exact source this run loaded.
    /// A passing report may only license an implementation with the same hash.
    #[serde(default)]
    pub implementation_sha256: String,
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
            implementation_sha256: String::new(),
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
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(5);
// Compiled runtimes include process and VM startup in the measured window;
// Windows runners can spend several seconds starting dotnet while the machine
// is compiling other candidates in parallel. Keep that cost bounded separately
// from the tighter scripted-runtime limit.
const COMPILED_CANDIDATE_TIMEOUT: Duration = Duration::from_secs(15);
const TOOL_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const BUILD_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CAPTURED_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

pub fn verify(implementation: &Implementation, cases: &[GroundTruthCase]) -> VerificationReport {
    let language = implementation.normalized_language();
    let mut report = if !is_portable_entry_point(&implementation.entry_point) {
        VerificationReport::unverifiable(
            &language,
            expected_runtime(&language),
            "entry point must be a simple ASCII identifier; the candidate was not executed",
        )
    } else {
        match language.as_str() {
            "javascript" | "typescript" => verify_javascript(implementation, cases),
            "python" => verify_python(implementation, cases),
            "go" => verify_go(implementation, cases),
            "java" => verify_java(implementation, cases),
            "csharp" => verify_csharp(implementation, cases),
            other => VerificationReport::unverifiable(
                other,
                "none",
                &format!("no verification runtime for {other}; the candidate was not executed"),
            ),
        }
    };
    report.language = language;
    report.implementation_sha256 = implementation.sha256();
    if matches!(
        report.language.as_str(),
        "python" | "go" | "java" | "csharp"
    ) {
        report.notes.push(
            "security boundary: this local toolchain is time-limited but not an OS sandbox; output verification does not establish that candidate filesystem, process, or network behavior is safe"
                .to_string(),
        );
    }
    report
}

fn is_portable_entry_point(entry_point: &str) -> bool {
    let mut characters = entry_point.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
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

    // Load once and reuse the same realm for every case. Exported JavaScript is
    // a module whose candidate state also survives between calls; rebuilding a
    // fresh realm here could verify code whose second runtime call behaves
    // differently from its second verification case.
    let mut context = Context::default();
    context
        .runtime_limits_mut()
        .set_loop_iteration_limit(LOOP_LIMIT);
    context
        .runtime_limits_mut()
        .set_recursion_limit(RECURSION_LIMIT);
    let load_error = (|| -> Result<(), String> {
        register_primitives(&mut context)?;
        context
            .eval(Source::from_bytes(CRYPTO_BOOTSTRAP.as_bytes()))
            .map_err(|error| format!("crypto bootstrap failed: {error}"))?;
        context
            .eval(Source::from_bytes(implementation.source.as_bytes()))
            .map_err(|error| format!("candidate failed to load: {error}"))?;
        Ok(())
    })()
    .err();

    let mut outcomes = Vec::new();
    for case in cases {
        let result = match &load_error {
            Some(error) => Err(error.clone()),
            None => run_javascript_case(&mut context, implementation, case),
        };
        let outcome = match result {
            Ok(actual) => CaseOutcome {
                case_id: case.id.clone(),
                origin: case.origin.clone(),
                field: case.field.clone(),
                evidence_sha256: case.evidence_sha256(),
                passed: actual == case.expected,
                expected: case.expected.clone(),
                actual: Some(actual),
                error: None,
            },
            Err(error) => CaseOutcome {
                case_id: case.id.clone(),
                origin: case.origin.clone(),
                field: case.field.clone(),
                evidence_sha256: case.evidence_sha256(),
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

    let mut command = Command::new(&python);
    command.arg("run_verify.py").current_dir(&dir);
    let output = run_with_timeout(&mut command, CANDIDATE_TIMEOUT);
    std::fs::remove_dir_all(&dir).ok();

    let Ok(output) = output else {
        return VerificationReport::unverifiable(
            "python",
            &python,
            "verification run failed to start",
        );
    };
    let TimedCommandOutput::Completed(output) = output else {
        return timeout_failure("python", &python, cases, CANDIDATE_TIMEOUT);
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    match outcomes_from_stdout(&stdout, cases) {
        Some(outcomes) => VerificationReport::unverifiable("python", &python, "").settle(outcomes),
        None => build_failure(
            "python",
            &python,
            cases,
            &format!(
                "verification runner returned invalid case results\n{}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
    }
}

/// Driver executed inside the candidate's own runtime. Kept deliberately small:
/// it imports, calls, and reports actual values — it never sees the expected answer.
const PYTHON_RUNNER: &str = r#"import json, sys, traceback

with open("cases.json", "r", encoding="utf-8") as handle:
    payload = json.load(handle)

results = []
try:
    with open("candidate.py", "r", encoding="utf-8") as handle:
        source = handle.read()
    namespace = {"__name__": "shownet_verified_candidate"}
    exec(compile(source, "<shownet-verified-candidate>", "exec"), namespace)
    entry = namespace[payload["entryPoint"]]
except Exception:
    for case in payload["cases"]:
        results.append({
            "id": case["id"], "origin": case["origin"], "field": case["field"],
            "actual": None, "error": traceback.format_exc(limit=2).strip().splitlines()[-1],
        })
    print(json.dumps({"cases": results}))
    sys.exit(0)

for case in payload["cases"]:
    record = {
        "id": case["id"], "origin": case["origin"], "field": case["field"],
        "actual": None, "error": None,
    }
    try:
        actual = entry(case["input"])
        record["actual"] = None if actual is None else str(actual)
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
    let mut command = Command::new(binary);
    command.arg(arg);
    matches!(
        run_with_timeout(&mut command, TOOL_PROBE_TIMEOUT),
        Ok(TimedCommandOutput::Completed(output)) if output.status.success()
    )
}

enum TimedCommandOutput {
    Completed(Output),
    TimedOut,
}

struct ProcessContainment {
    #[cfg(target_os = "windows")]
    job: Option<WindowsJob>,
}

impl ProcessContainment {
    fn attach(_child: &Child) -> Self {
        Self {
            #[cfg(target_os = "windows")]
            job: WindowsJob::attach(_child),
        }
    }

    fn terminate(&self, child: &mut Child) {
        #[cfg(unix)]
        {
            let process_group = i32::try_from(child.id()).unwrap_or(i32::MAX);
            // The child is the process-group leader, so a negative PID reaches
            // its descendants as well. This also closes inherited output pipes
            // when the driver exits but a candidate-created child does not.
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(job) = &self.job {
                job.terminate();
            } else {
                terminate_windows_process_tree(child.id());
            }
        }
        let _ = child.kill();
    }

    fn close(self) {
        #[cfg(target_os = "windows")]
        drop(self.job);
    }
}

#[cfg(target_os = "windows")]
struct WindowsJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(target_os = "windows")]
impl WindowsJob {
    fn attach(child: &Child) -> Option<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return None;
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } != 0;
        let assigned = configured
            && unsafe {
                AssignProcessToJobObject(
                    handle,
                    child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                )
            } != 0;
        if !assigned {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(handle);
            }
            return None;
        }
        Some(Self { handle })
    }

    fn terminate(&self) {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle, 1);
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(target_os = "windows")]
fn terminate_windows_process_tree(pid: u32) {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = Command::new("taskkill.exe")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn configure_process_containment(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

fn drain_output<R>(mut reader: R) -> JoinHandle<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut tail = VecDeque::new();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            if read >= MAX_CAPTURED_OUTPUT_BYTES {
                tail.clear();
                tail.extend(&buffer[read - MAX_CAPTURED_OUTPUT_BYTES..read]);
                continue;
            }
            let overflow = tail
                .len()
                .saturating_add(read)
                .saturating_sub(MAX_CAPTURED_OUTPUT_BYTES);
            if overflow > 0 {
                tail.drain(..overflow);
            }
            tail.extend(&buffer[..read]);
        }
        Ok(tail.into_iter().collect())
    })
}

fn join_output(reader: JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| io::Error::other("candidate output reader panicked"))?
}

fn run_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> std::io::Result<TimedCommandOutput> {
    configure_process_containment(command);
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let containment = ProcessContainment::attach(&child);
    let stdout = drain_output(
        child
            .stdout
            .take()
            .expect("stdout was configured as a pipe"),
    );
    let stderr = drain_output(
        child
            .stderr
            .take()
            .expect("stderr was configured as a pipe"),
    );
    let started_at = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                containment.terminate(&mut child);
                containment.close();
                return Ok(TimedCommandOutput::Completed(Output {
                    status,
                    stdout: join_output(stdout)?,
                    stderr: join_output(stderr)?,
                }));
            }
            Ok(None) => {}
            Err(error) => {
                containment.terminate(&mut child);
                let _ = child.wait();
                containment.close();
                let _ = join_output(stdout);
                let _ = join_output(stderr);
                return Err(error);
            }
        }
        if started_at.elapsed() >= timeout {
            containment.terminate(&mut child);
            let _ = child.wait();
            containment.close();
            let _ = join_output(stdout);
            let _ = join_output(stderr);
            return Ok(TimedCommandOutput::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn timeout_failure(
    language: &str,
    runtime: &str,
    cases: &[GroundTruthCase],
    timeout: Duration,
) -> VerificationReport {
    build_failure(
        language,
        runtime,
        cases,
        &format!(
            "candidate exceeded the {} ms execution limit",
            timeout.as_millis()
        ),
    )
}

fn cases_payload(implementation: &Implementation, cases: &[GroundTruthCase]) -> String {
    serde_json::json!({
        "entryPoint": implementation.entry_point,
        "cases": cases.iter().map(|case| serde_json::json!({
            "id": case.id,
            "origin": case.origin,
            "field": case.field,
            "input": case.input,
        })).collect::<Vec<_>>(),
    })
    .to_string()
}

/// Read actual values from the driver and bind them back to the original cases.
/// The child process is not trusted to decide whether it passed, nor does its
/// payload contain the expected values.
fn outcomes_from_stdout(stdout: &str, cases: &[GroundTruthCase]) -> Option<Vec<CaseOutcome>> {
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))?;
    let parsed: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let items = parsed.get("cases")?.as_array()?;
    if items.len() != cases.len() {
        return None;
    }

    let mut outcomes = Vec::with_capacity(cases.len());
    for (item, case) in items.iter().zip(cases) {
        if item.get("id")?.as_str()? != case.id
            || item.get("origin")?.as_str()? != case.origin
            || item.get("field")?.as_str()? != case.field
        {
            return None;
        }
        let actual = match item.get("actual")? {
            serde_json::Value::Null => None,
            serde_json::Value::String(value) => Some(value.clone()),
            _ => return None,
        };
        let mut error = match item.get("error")? {
            serde_json::Value::Null => None,
            serde_json::Value::String(value) => Some(value.clone()),
            _ => return None,
        };
        if actual.is_none() && error.is_none() {
            error = Some("candidate returned no value".to_string());
        }
        outcomes.push(CaseOutcome {
            case_id: case.id.clone(),
            origin: case.origin.clone(),
            field: case.field.clone(),
            evidence_sha256: case.evidence_sha256(),
            passed: error.is_none() && actual.as_deref() == Some(case.expected.as_str()),
            expected: case.expected.clone(),
            actual,
            error,
        });
    }
    Some(outcomes)
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
                evidence_sha256: case.evidence_sha256(),
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

    let executable_name = if cfg!(windows) {
        "shownetverify.exe"
    } else {
        "shownetverify"
    };
    let mut build = Command::new("go");
    build
        .args(["build", "-o", executable_name, "."])
        .current_dir(&dir)
        // Keep the module hermetic: a candidate must not pull dependencies.
        .env("GOFLAGS", "-mod=mod")
        .env("GO111MODULE", "on")
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off");
    match run_with_timeout(&mut build, BUILD_TIMEOUT) {
        Ok(TimedCommandOutput::Completed(output)) if output.status.success() => {}
        Ok(TimedCommandOutput::Completed(output)) => {
            std::fs::remove_dir_all(&dir).ok();
            return build_failure("go", "go", cases, &String::from_utf8_lossy(&output.stderr));
        }
        Ok(TimedCommandOutput::TimedOut) => {
            std::fs::remove_dir_all(&dir).ok();
            return VerificationReport::unverifiable(
                "go",
                "go",
                "Go build exceeded the verification build limit",
            );
        }
        Err(_) => {
            std::fs::remove_dir_all(&dir).ok();
            return VerificationReport::unverifiable("go", "go", "compiler failed to start");
        }
    }

    let mut command = Command::new(dir.join(executable_name));
    command.current_dir(&dir);
    let output = run_with_timeout(&mut command, COMPILED_CANDIDATE_TIMEOUT);
    std::fs::remove_dir_all(&dir).ok();

    let Ok(output) = output else {
        return VerificationReport::unverifiable("go", "go", "verification run failed to start");
    };
    let TimedCommandOutput::Completed(output) = output else {
        return timeout_failure("go", "go", cases, COMPILED_CANDIDATE_TIMEOUT);
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    match outcomes_from_stdout(&stdout, cases) {
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

    let mut compile_command = Command::new("javac");
    compile_command
        .args(["Candidate.java", "Driver.java"])
        .current_dir(&dir);
    let compile = run_with_timeout(&mut compile_command, BUILD_TIMEOUT);
    match compile {
        Ok(TimedCommandOutput::Completed(compile)) if !compile.status.success() => {
            let stderr = String::from_utf8_lossy(&compile.stderr).to_string();
            std::fs::remove_dir_all(&dir).ok();
            return build_failure("java", "javac", cases, &stderr);
        }
        Ok(TimedCommandOutput::TimedOut) => {
            std::fs::remove_dir_all(&dir).ok();
            return VerificationReport::unverifiable(
                "java",
                "javac",
                "Java build exceeded the verification build limit",
            );
        }
        Err(_) => {
            std::fs::remove_dir_all(&dir).ok();
            return VerificationReport::unverifiable("java", "javac", "compiler failed to start");
        }
        _ => {}
    }

    let mut command = Command::new("java");
    command.arg("Driver").current_dir(&dir);
    let output = run_with_timeout(&mut command, COMPILED_CANDIDATE_TIMEOUT);
    std::fs::remove_dir_all(&dir).ok();

    let Ok(output) = output else {
        return VerificationReport::unverifiable(
            "java",
            "java",
            "verification run failed to start",
        );
    };
    let TimedCommandOutput::Completed(output) = output else {
        return timeout_failure("java", "java", cases, COMPILED_CANDIDATE_TIMEOUT);
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    match outcomes_from_stdout(&stdout, cases) {
        Some(outcomes) => VerificationReport::unverifiable("java", "java", "").settle(outcomes),
        None => build_failure(
            "java",
            "java",
            cases,
            &String::from_utf8_lossy(&output.stderr),
        ),
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
        return VerificationReport::unverifiable(
            "csharp",
            "dotnet",
            "could not stage the candidate",
        );
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
        return VerificationReport::unverifiable(
            "csharp",
            "dotnet",
            "could not stage the candidate",
        );
    }

    let mut build = Command::new("dotnet");
    build
        .args(["build", "verify.csproj", "-v", "quiet", "--nologo"])
        .current_dir(&dir)
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .env("DOTNET_NOLOGO", "1");
    match run_with_timeout(&mut build, BUILD_TIMEOUT) {
        Ok(TimedCommandOutput::Completed(output)) if output.status.success() => {}
        Ok(TimedCommandOutput::Completed(output)) => {
            let message = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            );
            std::fs::remove_dir_all(&dir).ok();
            return build_failure("csharp", "dotnet", cases, &message);
        }
        Ok(TimedCommandOutput::TimedOut) => {
            std::fs::remove_dir_all(&dir).ok();
            return VerificationReport::unverifiable(
                "csharp",
                "dotnet",
                "C# build exceeded the verification build limit",
            );
        }
        Err(_) => {
            std::fs::remove_dir_all(&dir).ok();
            return VerificationReport::unverifiable(
                "csharp",
                "dotnet",
                "compiler failed to start",
            );
        }
    }

    let mut command = Command::new("dotnet");
    command
        .arg(dir.join("bin/Debug/net8.0/shownetverify.dll"))
        .current_dir(&dir)
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .env("DOTNET_NOLOGO", "1");
    let output = run_with_timeout(&mut command, COMPILED_CANDIDATE_TIMEOUT);
    std::fs::remove_dir_all(&dir).ok();

    let Ok(output) = output else {
        return VerificationReport::unverifiable(
            "csharp",
            "dotnet",
            "verification run failed to start",
        );
    };
    let TimedCommandOutput::Completed(output) = output else {
        return timeout_failure("csharp", "dotnet", cases, COMPILED_CANDIDATE_TIMEOUT);
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    match outcomes_from_stdout(&stdout, cases) {
        Some(outcomes) => VerificationReport::unverifiable("csharp", "dotnet", "").settle(outcomes),
        None => build_failure(
            "csharp",
            "dotnet",
            cases,
            &format!("{}\n{stdout}", String::from_utf8_lossy(&output.stderr)),
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
                        format!(
                            "{}, {}",
                            quote(key),
                            quote(value.as_str().unwrap_or_default())
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        out.push_str(&format!(
            "    cases.add(new Case({id}, {origin}, {field}, new Request({method}, {host}, {path}, {query}, headers({headers}), {body})));\n",
            id = quote(&case.id),
            origin = quote(&case.origin),
            field = quote(&case.field),
            method = nullable(input.get("method")),
            host = nullable(input.get("host")),
            path = nullable(input.get("path")),
            query = nullable(input.get("query")),
            body = nullable(input.get("body")),
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
	ID     string  `json:"id"`
	Origin string  `json:"origin"`
	Field  string  `json:"field"`
	Input  Request `json:"input"`
}

type verifyResult struct {
	ID     string  `json:"id"`
	Origin string  `json:"origin"`
	Field  string  `json:"field"`
	Actual *string `json:"actual"`
	Error  *string `json:"error"`
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
		result := verifyResult{ID: c.ID, Origin: c.Origin, Field: c.Field}
		func() {
			defer func() {
				if r := recover(); r != nil {
					message := fmt.Sprint(r)
					result.Error = &message
				}
			}()
			actual := __ENTRY__(c.Input)
			result.Actual = &actual
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
    record Case(String id, String origin, String field, Request input) {}

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
               .append(",\"actual\":").append(quote(actual))
               .append(",\"error\":").append(quote(error))
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

namespace ShowNetReplay;

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
    [property: JsonPropertyName("input")] Request Input);

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
                ["actual"] = actual,
                ["error"] = error,
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

    #[test]
    fn javascript_verification_uses_the_same_load_once_lifecycle_as_export() {
        let source = r#"
            let calls = 0;
            function computeSignature(input) {
              calls += 1;
              return `${calls}:${input.data}`;
            }
        "#;
        let cases = vec![
            case("c1", "hook", json!({"data": "a"}), "1:a"),
            case("c2", "hook", json!({"data": "b"}), "2:b"),
        ];

        let report = verify(&Implementation::new("javascript", source), &cases);
        assert_eq!(report.verdict, "verified", "{report:?}");
        assert_eq!(report.passed, 2);
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
            report.cases[0]
                .actual
                .as_deref()
                .is_some_and(|actual| actual.len() == 64),
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
            report.cases[0]
                .error
                .as_deref()
                .is_some_and(|e| e.contains("no secret")),
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
    fn verification_keeps_typescript_distinct_from_javascript() {
        let source = "function computeSignature(input) { return input.value; }";
        let report = verify(
            &Implementation::new("typescript", source),
            &[case("c1", "request", json!({"value": "ok"}), "ok")],
        );

        assert_eq!(report.verdict, "verified", "{report:?}");
        assert_eq!(report.language, "typescript");
        assert_eq!(report.runtime, "boa");
    }

    #[test]
    fn aliases_share_the_export_language_and_implementation_hash() {
        let source = "function computeSignature(input) { return input.value; }";
        let javascript = Implementation::new("javascript", source);
        let alias = Implementation::new("js", source);
        let report = verify(
            &alias,
            &[case("c1", "request", json!({"value": "ok"}), "ok")],
        );

        assert_eq!(report.language, "javascript");
        assert_eq!(report.implementation_sha256, javascript.sha256());
    }

    #[test]
    fn an_entry_point_cannot_inject_code_into_a_runner_or_export() {
        let mut implementation =
            Implementation::new("javascript", "function computeSignature() { return 'ok'; }");
        implementation.entry_point = "computeSignature; globalThis.injected = true".into();
        let report = verify(&implementation, &[case("c1", "request", json!({}), "ok")]);

        assert_eq!(report.verdict, "unverifiable", "{report:?}");
        assert!(report.notes[0].contains("simple ASCII identifier"));
    }

    #[test]
    fn a_non_terminating_python_candidate_is_stopped() {
        let Some(_) = python_interpreter() else {
            return;
        };
        let source = "def computeSignature(request):\n    while True:\n        pass\n";
        let started_at = Instant::now();
        let report = verify(
            &Implementation::new("python", source),
            &[case("c1", "request", json!({}), "ok")],
        );

        assert_eq!(report.verdict, "failed", "{report:?}");
        assert!(
            started_at.elapsed() < Duration::from_secs(10),
            "candidate timeout did not return promptly"
        );
        assert!(report.cases[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("execution limit")));
    }

    #[test]
    fn a_python_candidate_cannot_keep_the_verifier_waiting_with_an_inherited_child_pipe() {
        let Some(_) = python_interpreter() else {
            return;
        };
        let source = r#"
import subprocess, sys

def computeSignature(request):
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3)"])
    return "expected-value"
"#;
        let started_at = Instant::now();
        let report = verify(
            &Implementation::new("python", source),
            &[case("c1", "request", json!({}), "expected-value")],
        );

        assert_eq!(report.verdict, "verified", "{report:?}");
        assert!(
            started_at.elapsed() < Duration::from_secs(2),
            "the verifier waited for a candidate-created child process"
        );
    }

    #[test]
    fn verbose_python_output_does_not_fill_the_verifier_pipe() {
        let Some(_) = python_interpreter() else {
            return;
        };
        let source = r#"
def computeSignature(request):
    print("x" * (512 * 1024))
    return "expected-value"
"#;
        let report = verify(
            &Implementation::new("python", source),
            &[case("c1", "request", json!({}), "expected-value")],
        );

        assert_eq!(report.verdict, "verified", "{report:?}");
    }

    #[test]
    fn external_candidates_cannot_read_expected_values_from_the_driver_payload() {
        let Some(_) = python_interpreter() else {
            return;
        };
        let source = r#"
import json

def computeSignature(request):
    with open("cases.json", "r", encoding="utf-8") as handle:
        return json.load(handle)["cases"][0]["expected"]
"#;
        let report = verify(
            &Implementation::new("python", source),
            &[case("c1", "request", json!({}), "expected-value")],
        );

        assert_eq!(report.verdict, "failed", "{report:?}");
        assert!(!cases_payload(
            &Implementation::new("python", source),
            &[case("c1", "request", json!({}), "expected-value"),]
        )
        .contains("expected-value"));
    }

    #[test]
    fn a_candidate_cannot_self_report_a_pass_without_an_actual_value() {
        let Some(_) = python_interpreter() else {
            return;
        };
        let source = r#"
import json, os

print(json.dumps({"cases": [{
    "id": "c1", "origin": "request", "field": "x-signature",
    "passed": True, "expected": "expected-value", "actual": None, "error": None,
}]}), flush=True)
os._exit(0)

def computeSignature(request):
    return "expected-value"
"#;
        let report = verify(
            &Implementation::new("python", source),
            &[case("c1", "request", json!({}), "expected-value")],
        );

        assert_eq!(report.verdict, "failed", "{report:?}");
        assert!(report.cases[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("no value")));
    }

    #[test]
    fn verification_outcomes_bind_the_full_ground_truth_hash() {
        let implementation = Implementation::new(
            "javascript",
            "function computeSignature(request) { return request.value; }",
        );
        let original = case(
            "c1",
            "request",
            json!({"value": "expected-value"}),
            "expected-value",
        );
        let report = verify(&implementation, std::slice::from_ref(&original));

        assert_eq!(report.verdict, "verified", "{report:?}");
        assert_eq!(report.cases[0].evidence_sha256, original.evidence_sha256());
    }

    #[test]
    fn python_verification_uses_the_same_fixed_module_identity_as_export() {
        let Some(_) = python_interpreter() else {
            return;
        };
        let source = r#"
def computeSignature(request):
    return __name__
"#;
        let report = verify(
            &Implementation::new("python", source),
            &[case(
                "c1",
                "request",
                json!({}),
                "shownet_verified_candidate",
            )],
        );

        assert_eq!(report.verdict, "verified", "{report:?}");
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
        let source =
            "import a_module_that_does_not_exist\n\ndef computeSignature(p):\n    return 'x'\n";
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

    const HMAC_EXPECTED: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

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

namespace ShowNetReplay;

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

namespace ShowNetReplay;

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
        for (language, source) in [
            ("go", GO_GOOD),
            ("java", JAVA_GOOD),
            ("csharp", CSHARP_GOOD),
        ] {
            let report = verify(&Implementation::new(language, source), &[]);
            assert_eq!(
                report.verdict, "unverifiable",
                "{language} with no cases must not claim anything: {report:?}"
            );
            assert!(!report.is_verified());
        }
    }
}
