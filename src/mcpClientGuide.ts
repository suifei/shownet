import { t } from "./i18n.ts";

export type McpGuideClientId = "codex" | "claude-code" | "cursor" | "vscode";

export interface McpClientGuide {
  id: McpGuideClientId;
  name: string;
  configPath: string;
  configLabel: string;
  config: string;
  authSummary: string;
  reloadHint: string;
  verifyHint: string;
  embedsToken: boolean;
}

function tomlString(value: string) {
  // The twin of toml_string in src-tauri/src/grok_runtime.rs, and it had the
  // same hole: JSON escaping covers TOML's basic string except for U+007F,
  // which TOML forbids literally and JSON permits. Generating this guide with a
  // token carrying a DEL produced a ~/.codex/config.toml that Codex cannot
  // parse. Neither the endpoint nor the token is user-typed today — both come
  // from ShowNet's own MCP server — so this is a latent hole rather than a
  // reachable one, but the function is named for TOML and should emit it.
  return JSON.stringify(value).replace(/\u007f/g, "\\u007F");
}

function jsonConfig(value: unknown) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function bearer(token?: string) {
  return `Bearer ${token || "PASTE_SHOWNET_TOKEN_HERE"}`;
}

export const MCP_GUIDE_CLIENTS: Array<Pick<McpClientGuide, "id" | "name">> = [
  { id: "codex", name: "Codex" },
  { id: "claude-code", name: "Claude Code" },
  { id: "cursor", name: "Cursor" },
  { id: "vscode", name: "VS Code" },
];

export function buildMcpClientGuide(
  id: McpGuideClientId,
  endpoint: string,
  token?: string,
): McpClientGuide {
  const cleanEndpoint = endpoint.trim();
  const embedsToken = Boolean(token);

  if (id === "codex") {
    const config = embedsToken
      ? [
          "[mcp_servers.shownet]",
          `url = ${tomlString(cleanEndpoint)}`,
          `http_headers = { Authorization = ${tomlString(bearer(token))} }`,
          "enabled = true",
          "",
        ].join("\n")
      : [
          "[mcp_servers.shownet]",
          `url = ${tomlString(cleanEndpoint)}`,
          'bearer_token_env_var = "SHOWNET_MCP_TOKEN"',
          "enabled = true",
          "",
        ].join("\n");
    return {
      id,
      name: "Codex",
      configPath: "~/.codex/config.toml",
      configLabel: t("settings.mcp.tomlConfig"),
      config,
      authSummary: embedsToken
        ? t("settings.mcp.tokenInFile")
        : t("settings.mcp.tokenFromEnv"),
      reloadHint: t("settings.mcp.reloadCodex"),
      verifyHint: t("settings.mcp.verifyCodex"),
      embedsToken,
    };
  }

  if (id === "claude-code") {
    const authorization = embedsToken ? bearer(token) : "Bearer ${SHOWNET_MCP_TOKEN}";
    return {
      id,
      name: "Claude Code",
      configPath: t("settings.mcp.projectRoot", { path: ".mcp.json" }),
      configLabel: t("settings.mcp.projectConfig"),
      config: jsonConfig({
        mcpServers: {
          shownet: {
            type: "http",
            url: cleanEndpoint,
            headers: { Authorization: authorization },
          },
        },
      }),
      authSummary: embedsToken
        ? t("settings.mcp.tokenInProject")
        : t("settings.mcp.tokenFromEnv"),
      reloadHint: t("settings.mcp.reloadClaude"),
      verifyHint: t("settings.mcp.verifyClaude"),
      embedsToken,
    };
  }

  if (id === "cursor") {
    const authorization = embedsToken ? bearer(token) : "Bearer ${env:SHOWNET_MCP_TOKEN}";
    return {
      id,
      name: "Cursor",
      configPath: t("settings.mcp.projectRoot", { path: ".cursor/mcp.json" }),
      configLabel: t("settings.mcp.cursorConfig"),
      config: jsonConfig({
        mcpServers: {
          shownet: {
            url: cleanEndpoint,
            headers: { Authorization: authorization },
          },
        },
      }),
      authSummary: embedsToken
        ? t("settings.mcp.tokenInProject")
        : t("settings.mcp.tokenFromEnv"),
      reloadHint: t("settings.mcp.reloadCursor"),
      verifyHint: t("settings.mcp.verifyCursor"),
      embedsToken,
    };
  }

  const headers = embedsToken
    ? { Authorization: bearer(token) }
    : { Authorization: "Bearer ${input:shownet-mcp-token}" };
  const inputs = embedsToken
    ? undefined
    : [{
        type: "promptString",
        id: "shownet-mcp-token",
        description: "ShowNet MCP access token",
        password: true,
      }];
  return {
    id,
    name: "VS Code",
    configPath: t("settings.mcp.projectRoot", { path: ".vscode/mcp.json" }),
    configLabel: t("settings.mcp.vscodeConfig"),
    config: jsonConfig({
      ...(inputs ? { inputs } : {}),
      servers: {
        shownet: {
          type: "http",
          url: cleanEndpoint,
          headers,
        },
      },
    }),
    authSummary: embedsToken
      ? t("settings.mcp.tokenInProject")
      : t("settings.mcp.tokenFromVscode"),
    reloadHint: t("settings.mcp.reloadVscode"),
    verifyHint: t("settings.mcp.verifyVscode"),
    embedsToken,
  };
}
