//! Restricted challenge.js string-array decoder recovery.
//!
//! Extracts array + rotation IIFE + decoder bootstrap from AWS-WAF-style
//! obfuscated scripts and evaluates them in an isolated Boa JS context
//! (no network, bounded time conceptually via pure in-memory eval).
//! Recovered config is best-effort; failures surface explicit gaps.

use boa_engine::{Context, Source};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

const MAX_SCRIPT_BYTES: usize = 2_000_000;
const MAX_DECODE_INDEX: i32 = 0x700;
const MAX_DECODED_STRINGS: usize = 4_096;
const MAX_DECODE_WALL: Duration = Duration::from_secs(8);

const BUILTIN_IDENTIFIERS: &[&str] = &[
    "Present",
    "Error",
    "Captcha",
    "Challenge",
    "Browser",
    "Undefined",
    "Null",
    "Object",
    "String",
    "Number",
    "Boolean",
    "Array",
    "Function",
    "Window",
    "Document",
    "Navigator",
    "Chrome",
    "Safari",
    "Firefox",
    "Amazon",
    "Aws",
    "Token",
    "Signal",
    "Telemetry",
];

#[derive(Clone, Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeConfigCandidates {
    pub aes_key_hex64: Option<String>,
    pub identifier: Option<String>,
    pub signal_version: Option<String>,
    pub type_names: Vec<String>,
    pub api_paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeDecodeResult {
    pub success: bool,
    pub decoded_string_dump: bool,
    pub decoded_count: usize,
    pub unique_count: usize,
    pub array_function: Option<String>,
    pub decoder_function: Option<String>,
    pub rotation_found: bool,
    pub config: ChallengeConfigCandidates,
    pub config_recovered: Value,
    pub sample_strings: Vec<String>,
    /// Call-site RC4/key candidates harvested from the script.
    pub call_site_key_count: usize,
    pub call_site_keys_effective: usize,
    /// True when AES-GCM trial decrypt of a network-style frame produced checksum#JSON or JSON.
    pub aes_decrypt_side_confirmed: bool,
    pub aes_decrypt_sample_kind: Option<String>,
    pub errors: Vec<String>,
    pub limitations: Vec<String>,
    pub duration_ms: u128,
}

impl Default for ChallengeDecodeResult {
    fn default() -> Self {
        Self {
            success: false,
            decoded_string_dump: false,
            decoded_count: 0,
            unique_count: 0,
            array_function: None,
            decoder_function: None,
            rotation_found: false,
            config: ChallengeConfigCandidates::default(),
            config_recovered: json!({
                "aesKeyHex64": false,
                "signalVersion": false,
                "typeNames": false,
                "identifierFromDecoder": false
            }),
            sample_strings: Vec::new(),
            call_site_key_count: 0,
            call_site_keys_effective: 0,
            aes_decrypt_side_confirmed: false,
            aes_decrypt_sample_kind: None,
            errors: Vec::new(),
            limitations: Vec::new(),
            duration_ms: 0,
        }
    }
}

/// Public entry: recover decoded strings + deployment config candidates from challenge.js source.
pub fn decode_challenge_js(source: &str) -> ChallengeDecodeResult {
    let started = Instant::now();
    let mut result = ChallengeDecodeResult::default();

    if source.is_empty() || source.starts_with("base64:") {
        result
            .errors
            .push("challenge.js body is empty or not decoded text".into());
        result.limitations.push(
            "No executable JavaScript body available for string-array decoder recovery.".into(),
        );
        result.duration_ms = started.elapsed().as_millis();
        return result;
    }

    let scan_end = source.len().min(MAX_SCRIPT_BYTES);
    let source = &source[..floor_char_boundary(source, scan_end)];

    let Some(array_name) = find_array_function_name(source) else {
        result
            .errors
            .push("string-array function (a0_0x* / similar) not located".into());
        result.limitations.push(
            "challenge.js did not match string-array + decoder extraction patterns; static markers only."
                .into(),
        );
        result.duration_ms = started.elapsed().as_millis();
        return result;
    };
    result.array_function = Some(array_name.clone());

    let Some(decoder_name) = find_decoder_function_name(source, &array_name) else {
        result.errors.push(format!(
            "decoder function referencing {array_name} not located"
        ));
        result.limitations.push(
            "Array function found but decoder could not be extracted; config mining skipped."
                .into(),
        );
        result.duration_ms = started.elapsed().as_millis();
        return result;
    };
    result.decoder_function = Some(decoder_name.clone());

    let Some(array_source) = extract_function_source(source, &array_name) else {
        result
            .errors
            .push("failed to extract array function source (brace balance)".into());
        result.duration_ms = started.elapsed().as_millis();
        return result;
    };
    let Some(decoder_source) = extract_function_source(source, &decoder_name) else {
        result
            .errors
            .push("failed to extract decoder function source (brace balance)".into());
        result.duration_ms = started.elapsed().as_millis();
        return result;
    };

    let rotation = find_rotation_iife(source, &array_name);
    result.rotation_found = rotation.is_some();

    let mut bootstrap = String::new();
    bootstrap.push_str("var window = globalThis; var document = {}; var navigator = {};\n");
    bootstrap.push_str("var self = globalThis; var global = globalThis;\n");
    bootstrap.push_str("var atob = globalThis.atob || function(s){ return s; };\n");
    bootstrap.push_str(&array_source);
    bootstrap.push('\n');
    if let Some(rotation_src) = rotation.as_deref() {
        bootstrap.push_str(rotation_src);
        bootstrap.push('\n');
    }
    bootstrap.push_str(&decoder_source);
    bootstrap.push('\n');
    bootstrap.push_str(&format!(
        "globalThis.__shownet_decoder__ = {decoder_name};\n"
    ));

    // Call-site keys: a0_0xdec(0x12, 'key') / a0_0xdec(0x12, "key") mined from full source.
    let mut call_site_keys = harvest_call_site_keys(source, &decoder_name);
    // Also try short literals from the array as potential RC4 keys (bounded).
    for lit in harvest_string_literals(&array_source) {
        if is_plausible_rc4_key(&lit) && !call_site_keys.contains(&lit) {
            call_site_keys.push(lit);
        }
        if call_site_keys.len() >= MAX_CALL_SITE_KEYS {
            break;
        }
    }
    result.call_site_key_count = call_site_keys.len();

    // Always harvest raw + base64-decoded string literals from the array body as a
    // fallback (helps RC4-keyed AWS WAF tables when call-site keys are unknown).
    let mut static_literals = harvest_string_literals(&array_source);
    static_literals.extend(base64_expand_literals(&static_literals));

    let sandbox = run_decoder_sandbox(&bootstrap, &call_site_keys);
    let decoded = match sandbox {
        Ok(outcome) => {
            result.call_site_keys_effective = outcome.keys_that_produced_strings;
            let mut values = outcome.strings;
            for lit in static_literals {
                if !values.contains(&lit) {
                    values.push(lit);
                }
            }
            values
        }
        Err(error) => {
            if static_literals.is_empty() {
                result.errors.push(error);
                result.limitations.push(
                    "Sandbox evaluation of array/rotation/decoder bootstrap failed; no decoded string dump."
                        .into(),
                );
                result.duration_ms = started.elapsed().as_millis();
                return result;
            }
            result.errors.push(format!(
                "sandbox decode partial failure (using static array literals): {error}"
            ));
            result.limitations.push(
                "Sandbox decoder did not fully execute; config mining uses string-array literals + base64 expand only."
                    .into(),
            );
            static_literals
        }
    };

    let mut unique = BTreeSet::new();
    for value in &decoded {
        unique.insert(value.clone());
    }
    result.decoded_count = decoded.len();
    result.unique_count = unique.len();
    result.decoded_string_dump = !decoded.is_empty();
    result.success = result.decoded_string_dump;
    result.sample_strings = unique
        .iter()
        .filter(|value| value.len() <= 80)
        .take(24)
        .cloned()
        .collect();

    let config = identify_config(&decoded);
    result.config_recovered = json!({
        "aesKeyHex64": config.aes_key_hex64.is_some(),
        "signalVersion": config.signal_version.is_some(),
        "typeNames": !config.type_names.is_empty() || !config.api_paths.is_empty(),
        "identifierFromDecoder": config.identifier.is_some()
    });
    result.config = config;

    // Offline AES-GCM closed-loop trial on synthetic/network-like frames found in dump.
    if let Some(key) = result.config.aes_key_hex64.clone() {
        if let Some(kind) = trial_aes_decrypt_from_strings(&key, &decoded) {
            result.aes_decrypt_side_confirmed = true;
            result.aes_decrypt_sample_kind = Some(kind);
        }
    }

    if !result.config_recovered["aesKeyHex64"]
        .as_bool()
        .unwrap_or(false)
    {
        result.limitations.push(
            "64-hex AES key candidate not identified in decoded strings (may be absent or still encoded)."
                .into(),
        );
    }
    if !result.config_recovered["identifierFromDecoder"]
        .as_bool()
        .unwrap_or(false)
    {
        result
            .limitations
            .push("Signal identifier not recovered via Present-backtrack heuristic.".into());
    }
    if !result.rotation_found {
        result.limitations.push(
            "Rotation IIFE not found; decoder may still work if array is pre-ordered.".into(),
        );
    }
    if result.call_site_key_count == 0 {
        result.limitations.push(
            "No call-site RC4 keys harvested; decoder tried empty/'0' keys only plus array literals."
                .into(),
        );
    }
    if result.config.aes_key_hex64.is_some() && !result.aes_decrypt_side_confirmed {
        result.limitations.push(
            "AES key candidate present but offline AES-GCM trial decrypt of dump frames did not yield CRC32#JSON/JSON plaintext."
                .into(),
        );
    }

    result.duration_ms = started.elapsed().as_millis();
    if started.elapsed() > MAX_DECODE_WALL {
        result
            .limitations
            .push("Decoder wall-time budget approached; indices may be incomplete.".into());
    }
    result
}

const MAX_CALL_SITE_KEYS: usize = 48;
const MAX_KEYS_PER_INDEX: usize = 12;

struct SandboxOutcome {
    strings: Vec<String>,
    keys_that_produced_strings: usize,
}

fn run_decoder_sandbox(
    bootstrap: &str,
    call_site_keys: &[String],
) -> Result<SandboxOutcome, String> {
    let mut context = Context::default();
    context
        .eval(Source::from_bytes(bootstrap.as_bytes()))
        .map_err(|error| format!("bootstrap eval failed: {error}"))?;

    let mut key_variants: Vec<String> = vec![String::new(), "0".into()];
    for key in call_site_keys.iter().take(MAX_CALL_SITE_KEYS) {
        if !key_variants.iter().any(|k| k == key) {
            key_variants.push(key.clone());
        }
    }

    let mut decoded = Vec::new();
    let mut effective_keys: BTreeSet<usize> = BTreeSet::new();
    let started = Instant::now();
    for index in 0..=MAX_DECODE_INDEX {
        if started.elapsed() > MAX_DECODE_WALL {
            break;
        }
        if decoded.len() >= MAX_DECODED_STRINGS {
            break;
        }
        let mut got = None;
        for (key_idx, key) in key_variants.iter().enumerate().take(MAX_KEYS_PER_INDEX) {
            let script = if key.is_empty() {
                format!("globalThis.__shownet_decoder__({index})")
            } else {
                let escaped = key.replace('\\', "\\\\").replace('\'', "\\'");
                format!("globalThis.__shownet_decoder__({index}, '{escaped}')")
            };
            if let Some(text) = eval_decoder_to_string(&mut context, &script) {
                got = Some(text);
                effective_keys.insert(key_idx);
                break;
            }
        }
        if let Some(value) = got {
            decoded.push(value);
        }
    }
    if decoded.is_empty() {
        return Err("decoder returned no strings across scanned indices".into());
    }
    Ok(SandboxOutcome {
        strings: decoded,
        keys_that_produced_strings: effective_keys.len(),
    })
}

fn eval_decoder_to_string(context: &mut Context, script: &str) -> Option<String> {
    match context.eval(Source::from_bytes(script.as_bytes())) {
        Ok(value) => {
            if let Some(text) = value.as_string() {
                let owned = text.to_std_string_escaped();
                if !owned.is_empty() {
                    return Some(owned);
                }
            }
            let coerce = format!("String({script})");
            if let Ok(coerced) = context.eval(Source::from_bytes(coerce.as_bytes())) {
                if let Some(text) = coerced.as_string() {
                    let owned = text.to_std_string_escaped();
                    if !owned.is_empty() && owned != "undefined" && owned != "null" {
                        return Some(owned);
                    }
                }
            }
            None
        }
        Err(_) => None,
    }
}

fn harvest_call_site_keys(source: &str, decoder_name: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let pattern = format!("{decoder_name}(");
    let mut search = 0usize;
    while let Some(rel) = source[search..].find(&pattern) {
        let start = search + rel + pattern.len();
        let window = &source[start..floor_char_boundary(source, start + 120)];
        // index, 'key'  or index,"key"
        if let Some(comma) = window.find(',') {
            let after = window[comma + 1..].trim_start();
            if let Some(key) = parse_js_string_literal(after) {
                if is_plausible_rc4_key(&key) && !keys.iter().any(|k| k == &key) {
                    keys.push(key);
                }
            }
        }
        search += rel + pattern.len();
        if keys.len() >= MAX_CALL_SITE_KEYS {
            break;
        }
    }
    keys
}

fn parse_js_string_literal(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let quote = bytes[0];
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut out = String::new();
    let mut i = 1usize;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i];
        if escaped {
            out.push(c as char);
            escaped = false;
            i += 1;
            continue;
        }
        if c == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if c == quote {
            return Some(out);
        }
        out.push(c as char);
        i += 1;
        if out.len() > 64 {
            return None;
        }
    }
    None
}

fn is_plausible_rc4_key(value: &str) -> bool {
    let len = value.len();
    (2..=40).contains(&len)
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_-+/=".contains(ch))
}

/// Try AES-256-GCM decrypt on `nonceHex::tagHex::ctHex` or two-segment frames found in strings.
pub fn try_aes_gcm_decrypt_frame(key_hex64: &str, frame: &str) -> Option<String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    if key_hex64.len() != 64 || !key_hex64.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let key_bytes = hex_decode(key_hex64)?;
    if key_bytes.len() != 32 {
        return None;
    }
    let parts: Vec<&str> = frame.split("::").collect();
    let (nonce_hex, tag_hex, ct_hex) = if parts.len() >= 3 {
        (parts[0], parts[1], parts[2])
    } else if parts.len() == 2 {
        // prefix::payload — not enough structure
        return None;
    } else {
        return None;
    };
    let nonce = hex_decode(nonce_hex)?;
    let tag = hex_decode(tag_hex)?;
    let mut ciphertext = hex_decode(ct_hex)?;
    if nonce.len() != 12 || tag.len() != 16 || ciphertext.is_empty() {
        return None;
    }
    ciphertext.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).ok()?;
    let nonce = Nonce::from_slice(&nonce);
    let plain = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
    String::from_utf8(plain).ok()
}

fn trial_aes_decrypt_from_strings(key_hex64: &str, strings: &[String]) -> Option<String> {
    for value in strings {
        if !value.contains("::") {
            continue;
        }
        if let Some(plain) = try_aes_gcm_decrypt_frame(key_hex64, value) {
            if plain.contains('#') && plain.contains('{') {
                return Some("crc32_hash_json".into());
            }
            if plain.trim_start().starts_with('{') {
                return Some("json_object".into());
            }
            if plain.is_ascii() && plain.len() >= 8 {
                return Some("ascii_blob".into());
            }
        }
    }
    // Self-test: encrypt known plaintext and decrypt to prove stack works (offline capability).
    if self_test_aes_roundtrip(key_hex64).is_some() {
        return None; // stack ok but no frame in dump — leave unconfirmed
    }
    None
}

fn self_test_aes_roundtrip(key_hex64: &str) -> Option<()> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let key_bytes = hex_decode(key_hex64)?;
    if key_bytes.len() != 32 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).ok()?;
    let nonce_bytes = [7u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, b"CRC32#{\"t\":1}".as_ref()).ok()?;
    let plain = cipher.decrypt(nonce, ct.as_ref()).ok()?;
    if plain.starts_with(b"CRC32#") {
        Some(())
    } else {
        None
    }
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    if value.len() % 2 != 0 || value.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decrypt network signal Present frames with a recovered AES key (for protection_analysis).
pub fn decrypt_signal_present_frames(key_hex64: &str, frames: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    for frame in frames.iter().take(12) {
        if let Some(plain) = try_aes_gcm_decrypt_frame(key_hex64, frame) {
            let kind = if plain.contains('#') && plain.contains('{') {
                "crc32_hash_json"
            } else if plain.trim_start().starts_with('{') {
                "json_object"
            } else {
                "opaque_utf8"
            };
            out.push(json!({
                "framePreview": bounded_frame(frame),
                "plaintextKind": kind,
                "plaintextPreview": bounded_plaintext(&plain),
                "decryptSideConfirmed": true,
            }));
        }
    }
    out
}

fn bounded_frame(frame: &str) -> String {
    truncate_utf8(frame, 4_096)
}

fn bounded_plaintext(plain: &str) -> String {
    truncate_utf8(plain, 16_384)
}

fn identify_config(decoded: &[String]) -> ChallengeConfigCandidates {
    let mut aes_key_hex64 = None;
    let mut signal_version = None;
    let mut type_names = BTreeSet::new();
    let mut api_paths = BTreeSet::new();

    for value in decoded {
        // Takes the first hex64 seen; the pass below upgrades it if this one
        // turned out to be zero-padded. The two arms this replaces both did
        // exactly this — the second was guarded by a repeat of the outer
        // `is_none()` test and so could never be reached with a different
        // outcome, which read as a preference that was not implemented here.
        if aes_key_hex64.is_none() && is_hex64(value) {
            aes_key_hex64 = Some(value.clone());
        }
        if signal_version.is_none() {
            if let Some(version) = match_signal_version(value) {
                signal_version = Some(version);
            }
        }
        if value == "mp_verify"
            || value == "verify"
            || value == "telemetry"
            || value == "voucher"
            || value == "challenge"
        {
            api_paths.insert(value.clone());
            type_names.insert(value.clone());
        }
        if value.starts_with('h')
            && value.len() >= 60
            && value.chars().all(|ch| ch.is_ascii_hexdigit() || ch == 'h')
        {
            type_names.insert(format!("hash:{value}"));
        }
    }

    // Prefer first non-trivial hex64 if zeros-only was picked first
    if let Some(key) = aes_key_hex64.clone() {
        if key.chars().filter(|ch| *ch != '0').count() < 8 {
            for value in decoded {
                if is_hex64(value) && value.chars().filter(|ch| *ch != '0').count() >= 8 {
                    aes_key_hex64 = Some(value.clone());
                    break;
                }
            }
        }
    }

    let identifier = find_identifier_from_decoded(decoded);

    ChallengeConfigCandidates {
        aes_key_hex64,
        identifier,
        signal_version,
        type_names: type_names.into_iter().take(24).collect(),
        api_paths: api_paths.into_iter().collect(),
    }
}

fn find_identifier_from_decoded(decoded: &[String]) -> Option<String> {
    let present_index = decoded.iter().position(|value| value.contains("Present"))?;
    let forbidden: BTreeSet<&str> = BUILTIN_IDENTIFIERS.iter().copied().collect();
    let start = present_index.saturating_sub(30);
    for index in (start..present_index).rev() {
        let candidate = decoded[index].as_str();
        if is_identifier_token(candidate) && !forbidden.contains(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn is_identifier_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    if value.len() < 2 || value.len() > 16 {
        return false;
    }
    if !bytes[0].is_ascii_uppercase() {
        return false;
    }
    value.chars().skip(1).all(|ch| ch.is_ascii_lowercase())
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn match_signal_version(value: &str) -> Option<String> {
    // e.g. 2.4.0 but not 0.1.0
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    if parts
        .iter()
        .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
    {
        if value == "0.1.0" {
            return None;
        }
        return Some(value.to_string());
    }
    None
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[TRUNCATED]", &value[..end])
}

fn harvest_string_literals(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = bytes[i];
        if ch == b'\'' || ch == b'"' {
            let quote = ch;
            i += 1;
            let mut lit = String::new();
            let mut escaped = false;
            while i < bytes.len() {
                let c = bytes[i];
                if escaped {
                    match c {
                        b'n' => lit.push('\n'),
                        b'r' => lit.push('\r'),
                        b't' => lit.push('\t'),
                        b'\\' => lit.push('\\'),
                        b'\'' => lit.push('\''),
                        b'"' => lit.push('"'),
                        // The two bytes after \x may be the middle of one
                        // character rather than hex digits; slicing them then
                        // panics instead of simply failing to parse.
                        b'x' if i + 2 < bytes.len() && source.is_char_boundary(i + 3) => {
                            let hex = &source[i + 1..i + 3];
                            if let Ok(v) = u8::from_str_radix(hex, 16) {
                                lit.push(v as char);
                                i += 2;
                            } else {
                                lit.push('x');
                            }
                        }
                        other => lit.push(other as char),
                    }
                    escaped = false;
                    i += 1;
                    continue;
                }
                if c == b'\\' {
                    escaped = true;
                    i += 1;
                    continue;
                }
                if c == quote {
                    i += 1;
                    break;
                }
                lit.push(c as char);
                i += 1;
            }
            if !lit.is_empty() && lit.len() <= 512 {
                out.push(lit);
            }
            continue;
        }
        i += 1;
    }
    out
}

fn base64_expand_literals(literals: &[String]) -> Vec<String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    let mut expanded = Vec::new();
    for lit in literals {
        if lit.len() < 8 || lit.len() > 256 {
            continue;
        }
        if !lit
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "+/=_-".contains(ch))
        {
            continue;
        }
        for engine in [&STANDARD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            if let Ok(bytes) = engine.decode(lit.as_bytes()) {
                if let Ok(text) = String::from_utf8(bytes) {
                    if !text.is_empty()
                        && text.is_ascii()
                        && text
                            .chars()
                            .all(|ch| ch.is_ascii_graphic() || ch.is_ascii_whitespace())
                    {
                        expanded.push(text);
                        break;
                    }
                }
            }
        }
    }
    expanded
}

fn find_array_function_name(source: &str) -> Option<String> {
    // Prefer the highest-scoring string-array holder. Live AWS WAF challenge.js often
    // places a complex base64/RC4 decoder (also named a0_0x*) *before* the real array
    // function; picking the first match breaks sandbox recovery.
    let mut best: Option<(i32, String)> = None;
    let mut search = 0usize;
    while let Some(rel) = source[search..].find("function ") {
        let start = search + rel;
        let after = start + "function ".len();
        // name()
        if let Some(name_end) = source[after..].find('(').map(|n| after + n) {
            let name = source[after..name_end].trim();
            let args = source
                .get(name_end..source.len().min(name_end + 40))
                .unwrap_or("");
            // Array holders are typically zero-arg: function a0_0xabc()
            if is_obfuscated_fn_name(name) && args.starts_with("()") {
                if let Some(fn_src) = extract_function_source(source, name) {
                    let score = score_string_array_function(&fn_src, name);
                    if score > 0 && best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
                        best = Some((score, name.to_string()));
                    }
                }
            }
        }
        search = after;
        if search >= source.len() {
            break;
        }
    }
    best.map(|(_, name)| name)
}

/// Higher score => more likely the rotating/base string table, not a decoder.
fn score_string_array_function(fn_src: &str, name: &str) -> i32 {
    if !(fn_src.contains("=[")
        || fn_src.contains("= [")
        || fn_src.contains("=['")
        || fn_src.contains("=[\""))
    {
        // Still allow `var x=['a','b']; name=function(){return x}`
        if !fn_src.contains('[') {
            return 0;
        }
    }
    let single_commas = fn_src.matches("','").count();
    let double_commas = fn_src.matches("\",\"").count();
    let quote_count = fn_src.matches('\'').count() + fn_src.matches('"').count();
    let literal_commas = single_commas + double_commas;
    if literal_commas < 3 && quote_count < 12 {
        return 0;
    }
    let mut score = (literal_commas as i32) * 4 + (quote_count as i32 / 2);
    // Classic self-rebind array holder.
    if fn_src.contains(&format!("{name} = function"))
        || fn_src.contains(&format!("{name}=function"))
        || fn_src.contains("return _0x")
        || fn_src.contains("return [")
    {
        score += 40;
    }
    // Decoder/base64 alphabet & RC4-style loops should not win over large tables.
    if fn_src.contains("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=") {
        score -= 80;
    }
    if fn_src.contains("charCodeAt") && fn_src.contains("fromCharCode") {
        score -= 50;
    }
    if fn_src.contains("indexOf") && fn_src.contains("%") && fn_src.contains("charAt") {
        score -= 30;
    }
    // Two-parameter bodies are almost never the array table.
    if fn_src.contains("function") && fn_src.matches(',').count() > 20 && literal_commas < 10 {
        score -= 20;
    }
    score
}

fn find_decoder_function_name(source: &str, array_name: &str) -> Option<String> {
    // Prefer function that references array_name and takes two params
    let mut best: Option<(usize, String)> = None;
    let mut search = 0usize;
    while let Some(rel) = source[search..].find("function ") {
        let start = search + rel;
        let after = start + "function ".len();
        // name(args)
        let header_end = source[after..].find('{').map(|n| after + n)?;
        let header = &source[after..header_end];
        if let Some(paren) = header.find('(') {
            let name = header[..paren].trim();
            let args = &header[paren..];
            if is_obfuscated_fn_name(name) && args.matches(',').count() >= 1 && name != array_name {
                if let Some(body) = extract_function_source(source, name) {
                    if body.contains(array_name) {
                        let score = body.matches(array_name).count() * 10
                            + if body.contains("return") { 5 } else { 0 };
                        if best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
                            best = Some((score, name.to_string()));
                        }
                    }
                }
            }
        }
        search = after;
        if search >= source.len() {
            break;
        }
    }
    // Common pattern: decoder is first function in file
    if best.is_none() {
        if let Some(rel) = source.find("function a0_0x") {
            let after = rel + "function ".len();
            if let Some(name_end) = source[after..].find('(').map(|n| after + n) {
                let name = source[after..name_end].trim();
                if name != array_name && is_obfuscated_fn_name(name) {
                    return Some(name.to_string());
                }
            }
        }
    }
    best.map(|(_, name)| name)
}

fn find_rotation_iife(source: &str, array_name: &str) -> Option<String> {
    // Find (function ... array_name ... push ... shift
    let mut search = 0usize;
    while let Some(rel) = source[search..].find("(function") {
        let start = search + rel;
        let window_end = floor_char_boundary(source, start + 12_000);
        let window = &source[start..window_end];
        if window.contains(array_name)
            && window.contains("push")
            && (window.contains("shift") || window.contains("unshift"))
        {
            // Extract balanced paren group starting at start
            if let Some(end) = extract_balanced_from(source, start, '(', ')') {
                // Often ends with )(arrayName, offset);
                let extended_end = floor_char_boundary(source, end + 120);
                let tail = &source[end..extended_end];
                if tail.contains(array_name) {
                    if let Some(call_end) = find_call_end(source, end) {
                        return Some(source[start..call_end].to_string());
                    }
                }
                return Some(source[start..end].to_string());
            }
        }
        search = start + 9;
    }
    None
}

fn find_call_end(source: &str, from: usize) -> Option<usize> {
    // from points at ')' of IIFE; scan forward for trailing )( ... );
    let bytes = source.as_bytes();
    let mut i = from;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'(' {
        // maybe already consumed
        return Some(from);
    }
    extract_balanced_from(source, i, '(', ')')
}

fn extract_function_source(source: &str, name: &str) -> Option<String> {
    let pattern = format!("function {name}");
    let start = source.find(&pattern)?;
    let brace = source[start..].find('{').map(|n| start + n)?;
    let end = extract_balanced_from(source, brace, '{', '}')?;
    Some(source[start..end].to_string())
}

fn extract_balanced_from(
    source: &str,
    open_index: usize,
    open: char,
    close: char,
) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_template = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut escaped = false;
    let chars: Vec<char> = source[open_index..].chars().collect();
    let mut offset = 0usize;
    while offset < chars.len() {
        let ch = chars[offset];
        let next = chars.get(offset + 1).copied();
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
            }
            offset += 1;
            continue;
        }
        if in_block_comment {
            if ch == '*' && next == Some('/') {
                in_block_comment = false;
                offset += 2;
                continue;
            }
            offset += 1;
            continue;
        }
        if in_single {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '\'' {
                in_single = false;
            }
            offset += 1;
            continue;
        }
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            offset += 1;
            continue;
        }
        if in_template {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '`' {
                in_template = false;
            }
            offset += 1;
            continue;
        }
        if ch == '/' && next == Some('/') {
            in_line_comment = true;
            offset += 2;
            continue;
        }
        if ch == '/' && next == Some('*') {
            in_block_comment = true;
            offset += 2;
            continue;
        }
        if ch == '\'' {
            in_single = true;
            offset += 1;
            continue;
        }
        if ch == '"' {
            in_double = true;
            offset += 1;
            continue;
        }
        if ch == '`' {
            in_template = true;
            offset += 1;
            continue;
        }
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                // return exclusive end index in original string
                let slice: String = chars[..=offset].iter().collect();
                return Some(open_index + slice.len());
            }
        }
        offset += 1;
    }
    None
}

fn is_obfuscated_fn_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 40 {
        return false;
    }
    name.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && (name.contains("0x") || name.starts_with('_') || name.starts_with('a'))
}

#[allow(dead_code)]
fn find_slice(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Largest char boundary at or below `index`, clamped to the string.
///
/// Every window in this file is cut from JS lifted off the wire, which carries
/// Chinese string literals as a matter of course. `source.len().min(x)` keeps a
/// slice inside the string but says nothing about landing between characters,
/// and the difference is a panic on the site being analysed.
fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_challenge_js() -> String {
        // Synthetic AWS-WAF-like string-array + rotation + decoder fixture.
        // Decoded strings intentionally include recoverable config.
        r#"
function a0_0x1fd3(){
  var _0x345a0b = [
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'Zoey',
    'Present',
    '2.4.0',
    'mp_verify',
    'telemetry',
    'ha9faaffddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee'
  ];
  a0_0x1fd3 = function(){ return _0x345a0b; };
  return _0x345a0b;
}
(function(arrayFunc, targetOffset){
  var arr = arrayFunc();
  var i = 0;
  while(i < targetOffset){
    arr.push(arr.shift());
    i++;
  }
})(a0_0x1fd3, 0);
function a0_0x4f2e(index, key){
  var arr = a0_0x1fd3();
  return a0_0x4f2e = function(index, key){
    index = index - 0;
    var value = arr[index];
    return value;
  }, a0_0x4f2e(index, key);
}
"#
        .to_string()
    }

    #[test]
    fn scanning_windows_do_not_split_a_character() {
        // floor_char_boundary was added for the entry point at the top of
        // decode(), but three later windows clamped to source.len() only. The
        // source here is obfuscated JS lifted from captured traffic, which
        // routinely carries Chinese string literals, so a window edge landing
        // mid-character panicked on the site being analysed.

        // 1. harvest_call_site_keys: 120 bytes after the call site.
        let decoder = "_0xabc";
        let call = format!("{decoder}({}抓包", "0".repeat(119));
        assert!(
            !call.is_char_boundary(decoder.len() + 1 + 120),
            "the edge must be mid-character or this proves nothing"
        );
        let _ = harvest_call_site_keys(&call, decoder);

        // 2. find_rotation_iife: the 12_000-byte window. The window has to
        //    match on array name, push and shift or the body is skipped before
        //    it can be sliced.
        let head = "(function _0xarr push shift ";
        let wide = format!("{head}{}抓包", "0".repeat(11_999 - head.len()));
        assert!(
            !wide.is_char_boundary(12_000),
            "the 12k edge must be mid-character"
        );
        let _ = find_rotation_iife(&wide, "_0xarr");

        // 3. find_rotation_iife: the 120-byte tail past the balanced group.
        let closed = "(function _0xarr push shift )";
        let tailed = format!("{closed}{}抓包", "0".repeat(119));
        let _ = find_rotation_iife(&tailed, "_0xarr");

        // 4. An \x escape whose two following bytes are inside one character.
        let _ = harvest_string_literals("'\\x抓包'");
    }

    #[test]
    fn cutting_a_string_short_never_splits_a_character() {
        // Both helpers slice by byte index, and this app's strings are mostly
        // Chinese — a cut inside a three-byte character panics rather than
        // returning something wrong, taking the analysis down with it. Neither
        // had a test; these are the boundaries where an off-by-one would show.
        let chinese = "抓包解密验证通过";
        assert_eq!(chinese.len(), 24, "three bytes per character");

        // Every byte index, including inside characters and past the end.
        for limit in 0..=30 {
            let cut = truncate_utf8(chinese, limit);
            if limit >= chinese.len() {
                assert_eq!(cut, chinese, "nothing to cut at {limit}");
            } else {
                assert!(cut.ends_with("\n[TRUNCATED]"), "{limit}: {cut}");
                let kept = cut.trim_end_matches("\n[TRUNCATED]");
                assert!(chinese.starts_with(kept), "{limit}: {kept}");
                assert!(kept.len() <= limit, "{limit}: kept {} bytes", kept.len());
            }
        }

        for index in 0..=30 {
            let floored = floor_char_boundary(chinese, index);
            assert!(chinese.is_char_boundary(floored), "{index} -> {floored}");
            assert!(floored <= index.min(chinese.len()), "{index} -> {floored}");
            // The result is the *nearest* boundary at or below, not merely some
            // boundary — a helper that always returned 0 would satisfy the rest.
            assert!(
                index >= chinese.len() || floored + 3 > index,
                "{index} -> {floored} skipped a boundary"
            );
        }

        // Mixed widths, and an empty string, which is where a decrement would
        // underflow if the zero case were not already a boundary.
        assert_eq!(truncate_utf8("", 0), "");
        assert_eq!(floor_char_boundary("", 5), 0);
        let mixed = "ab解c包";
        for limit in 0..=mixed.len() + 2 {
            let cut = truncate_utf8(mixed, limit);
            assert!(cut.is_char_boundary(0));
            let kept = cut.trim_end_matches("\n[TRUNCATED]");
            assert!(mixed.starts_with(kept), "{limit}: {kept}");
        }
    }

    #[test]
    fn a_padded_placeholder_does_not_beat_the_real_key() {
        // Both are valid hex64, so the order they appear in the dump decided
        // which one was taken. The comment said non-zero-looking keys were
        // preferred; the guard made that unreachable, and the AES trial that
        // follows had nothing to work with when a placeholder came first.
        let placeholder = "0".repeat(58) + "000000";
        let real = "9f3c7a1e2b4d6f8a0c5e7b9d1f3a5c7e9b2d4f6a8c0e2b4d6f8a1c3e5b7d9f0a";
        assert_eq!(placeholder.len(), 64);
        assert_eq!(real.len(), 64);

        let placeholder_first = identify_config(&[placeholder.clone(), real.to_string()]);
        assert_eq!(
            placeholder_first.aes_key_hex64.as_deref(),
            Some(real),
            "a real key must win however late it appears"
        );

        // Order must not matter.
        let real_first = identify_config(&[real.to_string(), placeholder.clone()]);
        assert_eq!(real_first.aes_key_hex64.as_deref(), Some(real));

        // With nothing better, the placeholder is still worth reporting.
        let only_placeholder = identify_config(&[placeholder.clone()]);
        assert_eq!(
            only_placeholder.aes_key_hex64.as_deref(),
            Some(placeholder.as_str()),
            "a weak key is better than none"
        );

        // The first strong key wins; a later one does not churn the choice.
        let second_real = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b";
        let two_real = identify_config(&[real.to_string(), second_real.to_string()]);
        assert_eq!(two_real.aes_key_hex64.as_deref(), Some(real));
    }

    #[test]
    fn decodes_string_array_and_recovers_config() {
        let result = decode_challenge_js(&sample_challenge_js());
        assert!(
            result.success && result.decoded_string_dump,
            "errors={:?} limitations={:?}",
            result.errors,
            result.limitations
        );
        assert!(
            result.decoded_count >= 5,
            "decoded={}",
            result.decoded_count
        );
        assert_eq!(
            result.config.aes_key_hex64.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(result.config.identifier.as_deref(), Some("Zoey"));
        assert_eq!(result.config.signal_version.as_deref(), Some("2.4.0"));
        assert!(
            result.config.api_paths.iter().any(|p| p == "mp_verify"),
            "api_paths={:?}",
            result.config.api_paths
        );
        assert_eq!(result.config_recovered["aesKeyHex64"], true);
        assert_eq!(result.config_recovered["identifierFromDecoder"], true);
        assert_eq!(result.config_recovered["signalVersion"], true);
    }

    #[test]
    fn empty_or_unmatched_script_sets_explicit_gaps_without_fabricated_key() {
        let empty = decode_challenge_js("");
        assert!(!empty.success);
        assert!(!empty.decoded_string_dump);
        assert!(empty.config.aes_key_hex64.is_none());
        assert!(!empty.errors.is_empty() || !empty.limitations.is_empty());

        let plain = decode_challenge_js("console.log('hello challenge');");
        assert!(!plain.success);
        assert!(plain.config.aes_key_hex64.is_none());
        assert_eq!(plain.config_recovered["aesKeyHex64"], false);
    }

    #[test]
    fn live_challenge_js_env_path_decodes_when_present() {
        let Ok(path) = std::env::var("SHOWNET_LIVE_CHALLENGE_JS") else {
            return;
        };
        let source = std::fs::read_to_string(&path).expect("read live challenge.js");
        let result = decode_challenge_js(&source);
        assert!(
            result.array_function.is_some(),
            "array function not found: {:?}",
            result.errors
        );
        assert!(
            result.success || result.decoded_count > 0 || !result.sample_strings.is_empty(),
            "expected some recovery on live script: {:?}",
            result
        );
        // Write a small evidence file when requested.
        if let Ok(out) = std::env::var("SHOWNET_LIVE_DECODE_OUT") {
            let body = serde_json::json!({
                "success": result.success,
                "decodedStringDump": result.decoded_string_dump,
                "decodedCount": result.decoded_count,
                "uniqueCount": result.unique_count,
                "arrayFunction": result.array_function,
                "decoderFunction": result.decoder_function,
                "configRecovered": result.config_recovered,
                "identifier": result.config.identifier,
                "signalVersion": result.config.signal_version,
                "aesKeyPresent": result.config.aes_key_hex64.is_some(),
                "typeNames": result.config.type_names,
                "apiPaths": result.config.api_paths,
                "errors": result.errors,
                "limitations": result.limitations,
                "durationMs": result.duration_ms,
            });
            std::fs::write(out, serde_json::to_string_pretty(&body).unwrap()).unwrap();
        }
    }

    #[test]
    fn harvests_call_site_keys_and_aes_roundtrip_helpers() {
        let source = r#"
function a0_0xarr1(){
  var _0x = [
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'Zoey','Present','2.4.0','mp_verify'
  ];
  a0_0xarr1 = function(){ return _0x; };
  return _0x;
}
function a0_0xdec1(i,k){
  var a=a0_0xarr1();
  return a0_0xdec1=function(i,k){ i=i-0; return a[i]; }, a0_0xdec1(i,k);
}
var x = a0_0xdec1(0x1, 'rc4key');
var y = a0_0xdec1(0x2, "otherKey");
"#;
        let keys = harvest_call_site_keys(source, "a0_0xdec1");
        assert!(keys.iter().any(|k| k == "rc4key"), "{keys:?}");
        assert!(keys.iter().any(|k| k == "otherKey"), "{keys:?}");
        let result = decode_challenge_js(source);
        assert!(result.success);
        assert!(result.call_site_key_count >= 1);
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key_bytes = hex_decode(key).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
        let nonce = [9u8; 12];
        let mut ct = cipher
            .encrypt(Nonce::from_slice(&nonce), b"CRC32#{\"ok\":1}".as_ref())
            .unwrap();
        let tag = ct.split_off(ct.len() - 16);
        let to_hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let frame = format!("{}::{}::{}", to_hex(&nonce), to_hex(&tag), to_hex(&ct));
        let plain = try_aes_gcm_decrypt_frame(key, &frame).expect("decrypt");
        assert!(plain.starts_with("CRC32#"));
    }

    #[test]
    fn prefers_string_array_function_over_decoder_named_a0() {
        // Live AWS WAF layout: decoder a0_0x* appears *before* the array holder.
        let source = r#"
function a0_0xdec1(index, key){
  var arr = a0_0xarr1();
  var alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
  return a0_0xdec1 = function(index, key){
    index = index - 0;
    var value = arr[index];
    var out = '';
    for (var i = 0; i < value.length; i++) {
      out += String.fromCharCode(value.charCodeAt(i));
    }
    return out;
  }, a0_0xdec1(index, key);
}
function a0_0xarr1(){
  var _0x = [
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'Zoey',
    'Present',
    '2.4.0',
    'mp_verify',
    'telemetry'
  ];
  a0_0xarr1 = function(){ return _0x; };
  return _0x;
}
"#;
        let result = decode_challenge_js(source);
        assert!(
            result.success && result.decoded_string_dump,
            "errors={:?} limitations={:?}",
            result.errors,
            result.limitations
        );
        assert_eq!(result.array_function.as_deref(), Some("a0_0xarr1"));
        assert_eq!(result.decoder_function.as_deref(), Some("a0_0xdec1"));
        assert_eq!(result.config.identifier.as_deref(), Some("Zoey"));
        assert_eq!(
            result.config.aes_key_hex64.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn rotation_fixture_still_recovers_present_identifier() {
        let source = r#"
function a0_0xabc1(){
  var _0xarr = ['Present','2.5.1','Zoey','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','verify'];
  a0_0xabc1 = function(){ return _0xarr; };
  return _0xarr;
}
(function(f,n){ var a=f(); for (var i=0;i<n;i++){ a.push(a.shift()); } })(a0_0xabc1, 2);
function a0_0xdec1(i,k){
  var a=a0_0xabc1();
  return a0_0xdec1=function(i,k){ i=i-0; return a[i]; }, a0_0xdec1(i,k);
}
"#;
        let result = decode_challenge_js(source);
        assert!(result.success, "{:?}", result.errors);
        assert!(result.rotation_found);
        // After 2 rotations: ['Zoey','bbbb...','verify','Present','2.5.1']
        // identifier backtrack from Present still finds Zoey when order differs —
        // may recover Zoey if within 30 window of Present in decoded sequential dump.
        assert!(result.decoded_count >= 5);
        assert!(
            result.config.aes_key_hex64.is_some()
                || result.config.signal_version.is_some()
                || result.config.identifier.is_some()
                || !result.config.api_paths.is_empty(),
            "expected some config recovery: {:?}",
            result.config
        );
    }
}
