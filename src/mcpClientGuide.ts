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
  return JSON.stringify(value);
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
      configLabel: "TOML 配置",
      config,
      authSummary: embedsToken
        ? "访问令牌已写入配置，请勿提交或分享此文件"
        : "从环境变量 SHOWNET_MCP_TOKEN 读取令牌",
      reloadHint: "保存后重新打开 Codex",
      verifyHint: "在 Codex 的 MCP 列表中确认 shownet 已启用",
      embedsToken,
    };
  }

  if (id === "claude-code") {
    const authorization = embedsToken ? bearer(token) : "Bearer ${SHOWNET_MCP_TOKEN}";
    return {
      id,
      name: "Claude Code",
      configPath: "项目根目录/.mcp.json",
      configLabel: "项目 MCP 配置",
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
        ? "访问令牌已写入项目配置，请勿提交到 Git"
        : "从环境变量 SHOWNET_MCP_TOKEN 读取令牌",
      reloadHint: "保存后重新启动 Claude Code",
      verifyHint: "运行 /mcp，确认 shownet 为 connected",
      embedsToken,
    };
  }

  if (id === "cursor") {
    const authorization = embedsToken ? bearer(token) : "Bearer ${env:SHOWNET_MCP_TOKEN}";
    return {
      id,
      name: "Cursor",
      configPath: "项目根目录/.cursor/mcp.json",
      configLabel: "Cursor MCP 配置",
      config: jsonConfig({
        mcpServers: {
          shownet: {
            url: cleanEndpoint,
            headers: { Authorization: authorization },
          },
        },
      }),
      authSummary: embedsToken
        ? "访问令牌已写入项目配置，请勿提交到 Git"
        : "从环境变量 SHOWNET_MCP_TOKEN 读取令牌",
      reloadHint: "保存后在 Cursor 设置中刷新 MCP Servers",
      verifyHint: "确认 shownet 显示绿色连接状态",
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
    configPath: "项目根目录/.vscode/mcp.json",
    configLabel: "VS Code MCP 配置",
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
      ? "访问令牌已写入项目配置，请勿提交到 Git"
      : "首次启动时由 VS Code 安全询问令牌",
    reloadHint: "保存后运行 MCP: List Servers",
    verifyHint: "启动 shownet，并确认状态为 Running",
    embedsToken,
  };
}
