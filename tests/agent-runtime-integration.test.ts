import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const source = (path: string) => readFile(new URL(path, import.meta.url), "utf8");

describe("system Grok integration boundaries", () => {
  it("keeps official installation user-triggered, direct by default, and outside release builds", async () => {
    const [runtime, commands, settingsView, workflow, bundleConfig] = await Promise.all([
      source("../src-tauri/src/agent_runtime.rs"),
      source("../src-tauri/src/lib.rs"),
      source("../src/components/SettingsView.tsx"),
      source("../.github/workflows/release.yml"),
      source("../src-tauri/tauri.grok.conf.json"),
    ]);

    assert.match(runtime, /https:\/\/x\.ai\/cli\/install\.sh/);
    assert.match(runtime, /https:\/\/x\.ai\/cli\/install\.ps1/);
    assert.match(runtime, /Client::builder\(\)\s*\.no_proxy\(\)/);
    assert.match(runtime, /if upstream\.mode == "direct"\s*\{\s*return Ok\(\(\)\);/);
    assert.match(runtime, /\.env_remove\("GROK_DEPLOYMENT_KEY"\)/);
    assert.match(runtime, /\.env_remove\("GROK_PROXY_URL"\)/);
    assert.match(commands, /use_upstream_proxy\.unwrap_or\(false\)/);
    assert.match(commands, /if use_upstream_proxy && configured\.mode == "direct"/);
    assert.match(settingsView, /\[installAgentWithProxy, setInstallAgentWithProxy\] = useState\(false\)/);
    assert.match(settingsView, /install_official_agent_runtime[\s\S]*useUpstreamProxy: installAgentWithProxy/);
    assert.match(settingsView, /disabled=\{!agentRuntime\.installSupported \|\| installingAgent\}/);
    assert.doesNotMatch(workflow, /x\.ai\/cli\/install\.(?:sh|ps1)|grok-build-public-artifacts/);
    assert.doesNotMatch(bundleConfig, /externalBin|grok-build/);
  });

  it("isolates ShowNet endpoint, tools, and proxy settings to the launched process", async () => {
    const [runtime, analysis, mcp] = await Promise.all([
      source("../src-tauri/src/grok_runtime.rs"),
      source("../src-tauri/src/analysis.rs"),
      source("../src-tauri/src/mcp.rs"),
    ]);

    assert.match(runtime, /\.join\("agent-runtime"\)/);
    assert.match(runtime, /GROK_HOME/);
    assert.match(runtime, /remove_dir_all/);
    assert.match(runtime, /use_upstream_proxy\.then_some\(upstream\)/);
    assert.match(analysis, /graph_mcp_tools/);
    assert.match(mcp, /allowed_tools/);
    assert.match(mcp, /analysis_id/);
    assert.match(mcp, /session_id/);
  });
});
