import type { MessageKey, Translate } from "./i18nTypes.ts";
import type { ViewId } from "./types.ts";

export const NAV_VIEWS: ViewId[] = [
  "traffic",
  "browser",
  "lab",
  "advanced",
  "analysis",
  "skills",
  "settings",
];

export const NAV_KEYS: Record<ViewId, MessageKey> = {
  traffic: "nav.traffic",
  browser: "nav.browser",
  lab: "nav.lab",
  advanced: "nav.advanced",
  analysis: "nav.analysis",
  skills: "nav.skills",
  settings: "nav.settings",
};

export const VIEW_TITLE_KEYS: Record<ViewId, MessageKey> = {
  traffic: "view.traffic",
  browser: "view.browser",
  lab: "view.lab",
  advanced: "view.advanced",
  analysis: "view.analysis",
  skills: "view.skills",
  settings: "view.settings",
};

export function chromeLabel(t: Translate, view: ViewId): string {
  return t(NAV_KEYS[view]);
}

export function chromeTitle(t: Translate, view: ViewId): string {
  return t(VIEW_TITLE_KEYS[view]);
}
