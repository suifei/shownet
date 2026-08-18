export type MessageKey =
  | "nav.traffic"
  | "nav.browser"
  | "nav.lab"
  | "nav.advanced"
  | "nav.analysis"
  | "nav.skills"
  | "nav.settings"
  | "view.traffic"
  | "view.browser"
  | "view.lab"
  | "view.advanced"
  | "view.analysis"
  | "view.skills"
  | "view.settings"
  | "navGroup.capture"
  | "navGroup.tools"
  | "navGroup.intelligence"
  | "clock.justNow"
  | "clock.today"
  | "clock.yesterday";

export type MessageCatalog = Record<MessageKey, string>;

export interface LanguagePack {
  /** Stable id, also used as the fallback target (`zh`). */
  id: string;
  /** BCP-47 tags this pack claims (language and optional language-region). */
  tags: string[];
  /** `Intl` locale for chrome clocks. */
  intlLocale: string;
  messages: MessageCatalog;
}

export type Translate = (key: MessageKey) => string;
