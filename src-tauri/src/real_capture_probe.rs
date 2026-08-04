//! Run the deterministic analysers against a REAL captured session and dump
//! their output for inspection.
//!
//! The point is falsifiability. The analysers claim to derive their conclusions
//! from captured evidence; the only way to check that is to feed them a real
//! capture and see whether the output tracks the input — in particular whether
//! a field the decoder reports as *not recovered* still shows up populated
//! downstream.
//!
//! Nothing here runs in CI: the test is `#[ignore]`d and needs a session id.
//!
//! ```text
//! SHOWNET_SESSION=session-… \
//!   cargo test --manifest-path src-tauri/Cargo.toml \
//!   dump_real_session_analysis -- --ignored --nocapture
//! ```
//!
//! Optional env:
//!   SHOWNET_DB   path to shownet.sqlite3 (default: the macOS app data dir)
//!   SHOWNET_OUT  output directory        (default: /tmp/shownet-real-analysis)

#[cfg(test)]
mod tests {
    use crate::{challenge_decoder, protection_analysis, scorecard, storage::Storage};
    use std::path::PathBuf;

    fn database_path() -> PathBuf {
        if let Ok(explicit) = std::env::var("SHOWNET_DB") {
            return PathBuf::from(explicit);
        }
        PathBuf::from(std::env::var("HOME").expect("HOME"))
            .join("Library/Application Support/com.shownet.desktop/shownet.sqlite3")
    }

    fn output_dir() -> PathBuf {
        let dir = std::env::var("SHOWNET_OUT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/shownet-real-analysis"));
        std::fs::create_dir_all(&dir).expect("create output dir");
        dir
    }

    #[test]
    #[ignore = "needs a real captured session; set SHOWNET_SESSION"]
    fn dump_real_session_analysis() {
        let session = std::env::var("SHOWNET_SESSION")
            .expect("set SHOWNET_SESSION to a session id present in the database");
        let storage = Storage::open(&database_path()).expect("open the capture database");
        let out = output_dir();

        // 1. Protection analysis over the whole session.
        let protection = protection_analysis::analyze_session(&storage, &session)
            .expect("analyze_session over the real capture");
        std::fs::write(
            out.join("protection_analysis.json"),
            serde_json::to_string_pretty(&protection).expect("serialise"),
        )
        .expect("write protection_analysis.json");
        println!("wrote protection_analysis.json");

        // 2. The challenge.js decoder, fed the largest captured script body.
        let requests = storage
            .list_requests(&session, Some(10_000), Some(0))
            .expect("list requests");
        let script = requests
            .iter()
            .filter(|request| {
                request.path.contains("challenge.js") && !request.response_body.is_empty()
            })
            .map(|request| (request.path.clone(), request.response_body.clone()))
            .max_by_key(|(_, body)| body.len());
        match script {
            Some((path, body)) => {
                println!("decoding {path} ({} bytes)", body.len());
                let decoded = challenge_decoder::decode_challenge_js(&body);
                println!(
                    "  identifier={:?} signalVersion={:?} aesKey={}",
                    decoded.config.identifier,
                    decoded.config.signal_version,
                    decoded.config.aes_key_hex64.is_some()
                );
                for limitation in &decoded.limitations {
                    println!("  limitation: {limitation}");
                }
                std::fs::write(
                    out.join("challenge_decode.json"),
                    serde_json::to_string_pretty(&decoded).expect("serialise"),
                )
                .expect("write challenge_decode.json");
                println!("wrote challenge_decode.json");
            }
            None => println!("no challenge.js body in this session"),
        }

        // 3. Scorecard dimension B over the analyser output, gate by gate. The
        //    per-gate detail is what shows whether a gate examined anything.
        let protocol = protection
            .get("protocolSchemas")
            .cloned()
            .unwrap_or_else(|| protection.clone());
        let dimension = scorecard::score_protocol_reconstruction(&protocol);
        std::fs::write(
            out.join("scorecard_dimension_b.json"),
            serde_json::to_string_pretty(&dimension).expect("serialise"),
        )
        .expect("write scorecard_dimension_b.json");
        println!(
            "scorecard B: score={} over {} gates",
            dimension.score,
            dimension.gates.len()
        );
        for gate in &dimension.gates {
            println!(
                "  [{}] {} — {}",
                if gate.passed { "PASS" } else { "FAIL" },
                gate.id,
                gate.detail
            );
        }
    }
}
