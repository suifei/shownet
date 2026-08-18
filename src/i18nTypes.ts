export type MessageVars = Record<string, string | number>;

export interface LanguagePack<K extends string = string> {
  /** Stable id, also used as the fallback target (`zh`). */
  id: string;
  /** BCP-47 tags this pack claims (language and optional language-region). */
  tags: string[];
  /** Language name in that language, for the switcher. */
  nativeName: string;
  /** `Intl` locale for chrome clocks. */
  intlLocale: string;
  messages: Record<K, string>;
}

export type Translate<K extends string = string> = (key: K, vars?: MessageVars) => string;
