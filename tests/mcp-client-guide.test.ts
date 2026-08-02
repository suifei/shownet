import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildMcpClientGuide,
  MCP_GUIDE_CLIENTS,
} from "../src/mcpClientGuide.ts";

const endpoint = "http://127.0.0.1:8899/mcp";
const token = "shownet_mcp_test-secret";

describe("MCP client guide", () => {
  it("covers the four supported AI clients", () => {
    assert.deepEqual(MCP_GUIDE_CLIENTS.map((client) => client.id), [
      "codex",
      "claude-code",
      "cursor",
      "vscode",
    ]);
  });

  it("keeps the access token out of secure defaults", () => {
    for (const client of MCP_GUIDE_CLIENTS) {
      const guide = buildMcpClientGuide(client.id, endpoint);
      assert.match(guide.config, /127\.0\.0\.1:8899\/mcp/);
      assert.doesNotMatch(guide.config, new RegExp(token));
      assert.equal(guide.embedsToken, false);
    }
    assert.match(buildMcpClientGuide("codex", endpoint).config, /bearer_token_env_var/);
    assert.match(buildMcpClientGuide("cursor", endpoint).config, /\$\{env:SHOWNET_MCP_TOKEN\}/);
    assert.match(buildMcpClientGuide("vscode", endpoint).config, /promptString/);
  });

  it("generates complete token-bearing configs only when explicitly requested", () => {
    for (const client of MCP_GUIDE_CLIENTS) {
      const guide = buildMcpClientGuide(client.id, endpoint, token);
      assert.match(guide.config, new RegExp(token));
      assert.equal(guide.embedsToken, true);
    }
  });

  it("uses each client's native top-level schema", () => {
    const claude = JSON.parse(buildMcpClientGuide("claude-code", endpoint).config);
    const cursor = JSON.parse(buildMcpClientGuide("cursor", endpoint).config);
    const vscode = JSON.parse(buildMcpClientGuide("vscode", endpoint).config);

    assert.equal(claude.mcpServers.shownet.type, "http");
    assert.equal(cursor.mcpServers.shownet.url, endpoint);
    assert.equal(vscode.servers.shownet.type, "http");
    assert.equal(vscode.inputs[0].password, true);
  });
});
