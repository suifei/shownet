//! CLI for the loopback ClientHello probe (Phase 0 golden workflow).
//!
//! Modes:
//!   measure-rustls  — self-connect with a catalog rustls preset (recipe only)
//!   wait            — accept one external client (tool/browser) within a budget
//!
//! Honesty: `measure-rustls` output is never a tool-matched or browser-matched
//! golden. Only an external client captured via `wait` may later fill those.
//!
//! Usage (from repo root):
//!   node scripts/rust-stable.mjs cargo run --manifest-path src-tauri/Cargo.toml --bin tls-golden-probe -- measure-rustls --preset chrome150
//!   node scripts/rust-stable.mjs cargo run --manifest-path src-tauri/Cargo.toml --bin tls-golden-probe -- wait --seconds 30

use shownet_lib::tls_probe::{measure_rustls_preset, wait_for_external_client};
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        std::process::exit(if args.is_empty() { 2 } else { 0 });
    }

    let mode = args.remove(0);
    match mode.as_str() {
        "measure-rustls" => {
            let preset = take_flag(&mut args, "--preset").unwrap_or_else(|| "chrome150".into());
            match measure_rustls_preset(&preset).await {
                Ok(captured) => {
                    let body = serde_json::json!({
                        "ok": true,
                        "mode": "measure-rustls",
                        "presetId": preset,
                        "alignmentCeiling": "recipe",
                        "honesty": "rustls recipe measurement only; must not fill tool-matched or browser-matched goldens",
                        "golden": captured.to_golden_json(),
                        "peer": captured.peer.to_string(),
                    });
                    println!("{}", serde_json::to_string_pretty(&body).unwrap());
                }
                Err(error) => {
                    eprintln!("tls-golden-probe error: {error}");
                    std::process::exit(1);
                }
            }
        }
        "wait" => {
            let seconds: u64 = take_flag(&mut args, "--seconds")
                .and_then(|s| s.parse().ok())
                .unwrap_or(30);
            match wait_for_external_client(Duration::from_secs(seconds)).await {
                Ok((addr, captured)) => {
                    let body = serde_json::json!({
                        "ok": true,
                        "mode": "wait",
                        "probeAddr": addr.to_string(),
                        "alignmentCeiling": "tool-matched-or-browser-matched",
                        "honesty": "external ClientHello captured; set source.kind to tool-capture or browser-capture before promoting entry status",
                        "golden": captured.to_golden_json(),
                        "peer": captured.peer.to_string(),
                    });
                    println!("{}", serde_json::to_string_pretty(&body).unwrap());
                }
                Err(error) => {
                    eprintln!("tls-golden-probe error: {error}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown mode: {other}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn take_flag(args: &mut Vec<String>, name: &str) -> Option<String> {
    if let Some(i) = args.iter().position(|a| a == name) {
        args.remove(i);
        if i < args.len() {
            return Some(args.remove(i));
        }
    }
    None
}

fn print_help() {
    eprintln!(
        "tls-golden-probe — local ClientHello capture for ShowNet goldens

Modes:
  measure-rustls --preset <id>   Measure rustls recipe ClientHello (alignment ceiling: recipe)
  wait [--seconds N]             Wait for external TLS client (tool/browser)

Examples:
  cargo run --bin tls-golden-probe -- measure-rustls --preset chrome150
  cargo run --bin tls-golden-probe -- wait --seconds 45
"
    );
}
