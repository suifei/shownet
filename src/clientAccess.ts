import { t } from "./i18n.ts";
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
    return t("settings.device.maxRules", { count: MAX_CLIENT_ACCESS_RULES });
  }
  if (settings.accessMode === "allow" && settings.accessRules.length === 0) {
    return t("settings.device.allowNeedRule");
  }
  return undefined;
}

export function clientAccessModeLabel(mode: ClientAccessMode): string {
  if (mode === "allow") return t("settings.device.allowOnly");
  if (mode === "deny") return t("settings.device.denyListed");
  return t("settings.device.allPrivate");
}

export function clientAccessModeSummary(mode: ClientAccessMode, ruleCount: number): string {
  if (mode === "allow") return t("settings.device.allowSummary", { count: ruleCount });
  if (mode === "deny") return t("settings.device.denySummary", { count: ruleCount });
  return t("settings.device.privateSummary");
}
