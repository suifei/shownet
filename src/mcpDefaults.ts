/**
 * What the MCP panels show before the backend answers.
 *
 * This was declared twice with different values: Settings claimed 28 tools and
 * `hasAccessToken: false`, Skills claimed `mcpToolPreview.length` and
 * `hasAccessToken: true`. The two panels therefore reported different facts
 * about the same server during the first frame, and one of them kept being
 * wrong whenever the tool list changed.
 *
 * The authoritative count comes from `get_mcp_server_status`; this is only the
 * placeholder, so it derives from the preview catalogue rather than a literal.
 */
import { mcpToolPreview } from "./capabilities.ts";
import type { McpServerStatus } from "./types.ts";

export const MCP_DEFAULT_HOST = "127.0.0.1";
export const MCP_DEFAULT_PORT = 8899;
export const MCP_PROTOCOL_VERSION = "2025-06-18";

export function mcpEndpoint(host: string, port: number) {
  return `http://${host}:${port}/mcp`;
}

/** Placeholder status. `enabled` is the one field a caller may reasonably vary. */
export function defaultMcpServerStatus(overrides: Partial<McpServerStatus> = {}): McpServerStatus {
  return {
    enabled: false,
    running: false,
    starting: false,
    host: MCP_DEFAULT_HOST,
    port: MCP_DEFAULT_PORT,
    endpoint: mcpEndpoint(MCP_DEFAULT_HOST, MCP_DEFAULT_PORT),
    protocolVersion: MCP_PROTOCOL_VERSION,
    toolCount: mcpToolPreview.length,
    allowWrites: false,
    hasAccessToken: false,
    recentClients: [],
    ...overrides,
  };
}
