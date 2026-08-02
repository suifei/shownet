use crate::models::CryptoCodeSnippet;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

pub const MAX_SCRIPT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SNIPPETS_PER_SCRIPT: usize = 24;
pub const MAX_SNIPPET_BYTES: usize = 12 * 1024;
pub const MAX_TOTAL_SNIPPET_BYTES: usize = 96 * 1024;
const MAX_CANDIDATE_SCAN_BYTES: usize = 256 * 1024;

#[derive(Clone)]
struct Candidate {
    start: usize,
    end: usize,
    kind: String,
    name: Option<String>,
    algorithms: Vec<String>,
    priority: u8,
}

pub fn extract_crypto_snippets(
    source: &str,
    source_truncated: bool,
) -> Result<Vec<CryptoCodeSnippet>, String> {
    if source.is_empty() || source.starts_with("base64:") {
        return Ok(Vec::new());
    }
    let parse_end = floor_char_boundary(source, source.len().min(MAX_SCRIPT_BYTES));
    let parsed_source = &source[..parse_end];
    let source_truncated = source_truncated || parse_end < source.len();
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .map_err(|error| format!("初始化 JavaScript 语法树失败: {error}"))?;
    let tree = parser
        .parse(parsed_source, None)
        .ok_or_else(|| "JavaScript 语法树解析失败".to_string())?;
    let mut candidates = Vec::new();
    collect_candidates(tree.root_node(), parsed_source, &mut candidates);
    candidates.sort_by_key(|candidate| {
        (
            candidate.priority,
            candidate.end.saturating_sub(candidate.start),
            candidate.start,
        )
    });

    let mut selected: Vec<Candidate> = Vec::new();
    for candidate in candidates {
        if selected
            .iter()
            .any(|existing| ranges_overlap(existing, &candidate))
        {
            continue;
        }
        selected.push(candidate);
    }
    selected.sort_by_key(|candidate| candidate.start);

    let mut snippets = Vec::new();
    let mut total_bytes = 0usize;
    for candidate in selected {
        if snippets.len() >= MAX_SNIPPETS_PER_SCRIPT || total_bytes >= MAX_TOTAL_SNIPPET_BYTES {
            break;
        }
        let budget = MAX_SNIPPET_BYTES.min(MAX_TOTAL_SNIPPET_BYTES - total_bytes);
        let (clip_start, clip_end, snippet_truncated) =
            clip_range(parsed_source, candidate.start, candidate.end, budget);
        let code = parsed_source[clip_start..clip_end].to_string();
        if code.trim().is_empty() {
            continue;
        }
        total_bytes += code.len();
        snippets.push(CryptoCodeSnippet {
            ordinal: snippets.len() as i64 + 1,
            kind: candidate.kind,
            name: candidate.name,
            algorithms: candidate.algorithms,
            start_line: line_at(parsed_source, clip_start),
            end_line: line_at(parsed_source, clip_end),
            code,
            truncated: snippet_truncated,
            source_truncated,
        });
    }
    Ok(snippets)
}

pub fn bounded_code(source: &str) -> String {
    let end = floor_char_boundary(source, source.len().min(MAX_SNIPPET_BYTES));
    if end == source.len() {
        source.to_string()
    } else {
        format!("{}\n[TRUNCATED]", &source[..end])
    }
}

fn collect_candidates(node: Node<'_>, source: &str, candidates: &mut Vec<Candidate>) {
    if let Some(priority) = candidate_priority(node.kind()) {
        let start = node.start_byte();
        let end = node.end_byte().min(source.len());
        if end > start && end - start <= MAX_CANDIDATE_SCAN_BYTES {
            let text = &source[start..end];
            let algorithms = detect_algorithms(text);
            if !algorithms.is_empty() {
                candidates.push(Candidate {
                    start,
                    end,
                    kind: display_kind(node.kind()).to_string(),
                    name: node_name(node, source),
                    algorithms,
                    priority,
                });
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_candidates(child, source, candidates);
    }
}

fn candidate_priority(kind: &str) -> Option<u8> {
    match kind {
        "function_declaration"
        | "generator_function_declaration"
        | "method_definition"
        | "function_expression"
        | "generator_function"
        | "arrow_function" => Some(0),
        "lexical_declaration" | "variable_declaration" => Some(1),
        "class_declaration" => Some(2),
        "expression_statement" => Some(3),
        _ => None,
    }
}

fn display_kind(kind: &str) -> &'static str {
    match kind {
        "function_declaration" | "generator_function_declaration" => "function",
        "method_definition" => "method",
        "function_expression" | "generator_function" | "arrow_function" => "function-expression",
        "lexical_declaration" | "variable_declaration" => "declaration",
        "class_declaration" => "class",
        _ => "statement",
    }
}

fn node_name(node: Node<'_>, source: &str) -> Option<String> {
    if let Some(name) = node.child_by_field_name("name") {
        return node_text(name, source);
    }
    let mut parent = node.parent();
    for _ in 0..3 {
        let Some(current) = parent else { break };
        if current.kind() == "variable_declarator" {
            if let Some(name) = current.child_by_field_name("name") {
                return node_text(name, source);
            }
        }
        parent = current.parent();
    }
    None
}

fn node_text(node: Node<'_>, source: &str) -> Option<String> {
    source
        .get(node.start_byte()..node.end_byte())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 160)
        .map(ToOwned::to_owned)
}

fn detect_algorithms(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut algorithms = BTreeSet::new();
    let mut detect = |name: &str, markers: &[&str]| {
        if markers.iter().any(|marker| lower.contains(marker)) {
            algorithms.insert(name.to_string());
        }
    };
    detect("Web Crypto", &["crypto.subtle", "subtlecrypto"]);
    detect(
        "AES",
        &["cryptojs.aes", "aes-gcm", "aes-cbc", "aes-ctr", "aes-kw"],
    );
    detect(
        "DES/3DES",
        &["cryptojs.des", "tripledes", "3des", "des-ede"],
    );
    detect(
        "RSA",
        &[
            "jsencrypt",
            "rsa-oaep",
            "rsassa",
            "forge.pki",
            "rsaencrypt",
            "rsasign",
        ],
    );
    detect("HMAC", &["hmac", "cryptojs.hmac"]);
    detect("SHA-1", &["sha1", "sha-1"]);
    detect("SHA-256", &["sha256", "sha-256"]);
    detect("SHA-384", &["sha384", "sha-384"]);
    detect("SHA-512", &["sha512", "sha-512"]);
    detect("MD5", &["md5", "cryptojs.md5"]);
    detect("PBKDF2", &["pbkdf2"]);
    detect("RC4", &["cryptojs.rc4", "rc4drop"]);
    detect("Rabbit", &["cryptojs.rabbit"]);
    detect("SM2", &["sm2", "dosignature", "doencrypt"]);
    detect("SM3", &["sm3"]);
    detect("SM4", &["sm4"]);
    detect(
        "Akamai Sensor",
        &["_abck", "bm_sz", "akamai", "sensor_data", "sensordata"],
    );
    if algorithms.is_empty()
        && [".encrypt(", ".decrypt(", ".digest(", ".sign(", ".verify("]
            .iter()
            .any(|marker| lower.contains(marker))
    {
        algorithms.insert("Crypto API".to_string());
    }
    algorithms.into_iter().collect()
}

fn ranges_overlap(left: &Candidate, right: &Candidate) -> bool {
    left.start < right.end && right.start < left.end
}

fn clip_range(source: &str, start: usize, end: usize, budget: usize) -> (usize, usize, bool) {
    if end - start <= budget {
        return (start, end, false);
    }
    let text = &source[start..end];
    let lower = text.to_ascii_lowercase();
    let marker = [
        "crypto.subtle",
        "cryptojs",
        "jsencrypt",
        "forge.pki",
        "sha256",
        "hmac",
        "pbkdf2",
        "sm2",
        "sm3",
        "sm4",
        "_abck",
        "akamai",
        ".encrypt(",
        ".sign(",
    ]
    .iter()
    .filter_map(|marker| lower.find(marker))
    .min()
    .unwrap_or_default();
    let preferred_start = start + marker.saturating_sub(budget / 3);
    let clip_start = ceil_char_boundary(source, preferred_start.min(end));
    let clip_end = floor_char_boundary(source, (clip_start + budget).min(end));
    (clip_start, clip_end, true)
}

fn line_at(source: &str, offset: usize) -> i64 {
    source.as_bytes()[..offset.min(source.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as i64
        + 1
}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index < value.len() && !value.is_char_boundary(index) {
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_named_crypto_functions_with_lines_and_algorithms() {
        let source = r#"
const noise = () => 1;
function signPayload(payload, key) {
  return CryptoJS.HmacSHA256(payload, key).toString();
}
async function encrypt(data, key) {
  return crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
}
"#;
        let snippets = extract_crypto_snippets(source, false).unwrap();
        assert_eq!(snippets.len(), 2);
        assert_eq!(snippets[0].name.as_deref(), Some("signPayload"));
        assert!(snippets[0].algorithms.contains(&"HMAC".to_string()));
        assert!(snippets[0].algorithms.contains(&"SHA-256".to_string()));
        assert_eq!(snippets[0].start_line, 3);
        assert_eq!(snippets[1].name.as_deref(), Some("encrypt"));
        assert!(snippets[1].algorithms.contains(&"Web Crypto".to_string()));
        assert!(snippets[1].algorithms.contains(&"AES".to_string()));
    }

    #[test]
    fn recognizes_sm_and_dynamic_signature_code() {
        let source = r#"
const sign = (message, privateKey) => sm2.doSignature(message, privateKey);
function sensor() { return { _abck: cookie, sensor_data: buildSensor() }; }
"#;
        let snippets = extract_crypto_snippets(source, false).unwrap();
        assert_eq!(snippets.len(), 2);
        assert!(snippets[0].algorithms.contains(&"SM2".to_string()));
        assert!(snippets[1]
            .algorithms
            .contains(&"Akamai Sensor".to_string()));
    }

    #[test]
    fn bounds_large_minified_snippets_around_the_crypto_marker() {
        let mut source = "const bundle=()=>{\n".to_string();
        source.push_str(&"x++;".repeat(MAX_SNIPPET_BYTES));
        source.push_str("return CryptoJS.AES.encrypt(data,key);\n};");
        let snippets = extract_crypto_snippets(&source, true).unwrap();
        assert_eq!(snippets.len(), 1);
        assert!(snippets[0].code.len() <= MAX_SNIPPET_BYTES);
        assert!(snippets[0].code.contains("CryptoJS.AES.encrypt"));
        assert!(snippets[0].truncated);
        assert!(snippets[0].source_truncated);
    }

    #[test]
    fn ignores_plain_javascript_and_base64_bodies() {
        assert!(
            extract_crypto_snippets("function add(a,b){return a+b}", false)
                .unwrap()
                .is_empty()
        );
        assert!(extract_crypto_snippets("base64:YWJj", false)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn preserves_sensitive_javascript_values_in_bounded_evidence() {
        let source = r#"const apiKey = "live-key";
const headers = { Authorization: `Bearer ${token}`, nonce: "visible" };
config.privateKey = pem;
return CryptoJS.HmacSHA256(body, apiKey);"#;
        let bounded = bounded_code(source);
        assert!(bounded.contains("live-key"));
        assert!(bounded.contains("Bearer ${token}"));
        assert!(bounded.contains("config.privateKey = pem"));
        assert!(bounded.contains("nonce: \"visible\""));
        assert!(bounded.contains("CryptoJS.HmacSHA256"));
    }
}
