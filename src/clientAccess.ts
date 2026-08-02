import type { CaptureListenerSettings, ClientAccessMode } from "./types";

export const MAX_CLIENT_ACCESS_RULES = 128;

export function parseClientAccessRules(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((rule) => rule.trim())
    .filter(Boolean);
}

export function validateClientAccessSettings(settings: CaptureListenerSettings): string | undefined {
  if (settings.accessRules.length > MAX_CLIENT_ACCESS_RULES) {
    return `设备范围最多支持 ${MAX_CLIENT_ACCESS_RULES} 条 IP 或 CIDR`;
  }
  if (settings.accessMode === "allow" && settings.accessRules.length === 0) {
    return "仅受信设备模式至少需要一个私网 IP 或 CIDR";
  }
  return undefined;
}

export function clientAccessModeLabel(mode: ClientAccessMode): string {
  if (mode === "allow") return "仅受信设备";
  if (mode === "deny") return "除已阻止设备外";
  return "所有私网设备";
}

export function clientAccessModeSummary(mode: ClientAccessMode, ruleCount: number): string {
  if (mode === "allow") return `仅允许 ${ruleCount} 条受信范围`;
  if (mode === "deny") return `已阻止 ${ruleCount} 条设备范围`;
  return "允许当前私网中的设备";
}
