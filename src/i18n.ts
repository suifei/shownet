/**
 * App language packs.
 *
 * Resolve walks the **registered** pack list (language, then region). Adding a
 * pack file and appending it to REGISTERED_PACKS is enough for a new region.
 * This is not a closed `zh` vs `en` branch.
 *
 * Host locale is `navigator.language` (the renderer’s honest signal). Missing
 * keys fall back to the documented fallback pack, then the key itself — never
 * an empty string.
 */

import { setClockLocale } from "./format.ts";
import { EN_PACK } from "./locales/en.ts";
import { ZH_PACK, type MessageKey } from "./locales/zh.ts";
import type { LanguagePack, MessageVars } from "./i18nTypes.ts";
import type { Translate as GenericTranslate } from "./i18nTypes.ts";

export type { LanguagePack, MessageVars } from "./i18nTypes";
export type { MessageKey } from "./locales/zh.ts";
export type Translate = GenericTranslate<MessageKey>;
export type MessageCatalog = Record<MessageKey, string>;

/** When no registered pack matches, prefer this id if present; else packs[0]. */
export const FALLBACK_PACK_ID = "zh";

export const NAV_MESSAGE_KEYS = [
  "nav.traffic",
  "nav.browser",
  "nav.lab",
  "nav.advanced",
  "nav.analysis",
  "nav.skills",
  "nav.settings",
] as const satisfies readonly MessageKey[];

export function parseLocaleTag(raw: string): { language: string; region: string; tag: string } {
  const normalized = raw.trim().replace(/_/g, "-").toLowerCase();
  const [language = "", region = ""] = normalized.split("-");
  const tag = region ? `${language}-${region}` : language;
  return { language, region, tag };
}

/**
 * Pick a pack from `packs` for `locale`.
 *
 * Match, in order: exact tag (`zh-cn`), language+region listed on a pack,
 * language-only (`zh-TW` → a pack that claims `zh`), then FALLBACK_PACK_ID
 * (or the first registered pack). Walks `packs`; extra entries are eligible.
 */
export function resolveLanguagePack(locale: string, packs: readonly LanguagePack<MessageKey>[]): LanguagePack<MessageKey> {
  if (packs.length === 0) {
    throw new Error("resolveLanguagePack: registered pack list is empty");
  }
  const wanted = parseLocaleTag(locale);
  if (wanted.language) {
    const scored = packs.map((pack) => {
      let score = 0;
      for (const raw of pack.tags) {
        const tag = parseLocaleTag(raw);
        if (!tag.language) continue;
        if (wanted.tag && tag.tag === wanted.tag) score = Math.max(score, 3);
        else if (wanted.region && tag.language === wanted.language && tag.region === wanted.region) {
          score = Math.max(score, 2);
        } else if (tag.language === wanted.language) {
          score = Math.max(score, 1);
        }
      }
      return { pack, score };
    });
    scored.sort((left, right) => right.score - left.score);
    if (scored[0].score > 0) return scored[0].pack;
  }
  return packs.find((pack) => pack.id === FALLBACK_PACK_ID) ?? packs[0];
}

export function interpolate(template: string, vars?: MessageVars): string {
  if (!vars) return template;
  return template.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (all, name: string) => (
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : all
  ));
}

export function lookupMessage(
  pack: LanguagePack<MessageKey>,
  key: MessageKey,
  packs: readonly LanguagePack<MessageKey>[] = REGISTERED_PACKS,
): string {
  const own = pack.messages[key];
  if (own) return own;
  const fallback = packs.find((item) => item.id === FALLBACK_PACK_ID) ?? packs[0];
  if (fallback && fallback.messages[key]) return fallback.messages[key];
  return key;
}

export function detectHostLocale(source?: { language?: string }): string {
  const fromArg = source?.language?.trim();
  if (fromArg) return fromArg;
  const fromNavigator = globalThis.navigator?.language?.trim();
  if (fromNavigator) return fromNavigator;
  return "";
}

export const UI_LOCALE_STORAGE_KEY = "shownet.ui.locale";

function isNodeTestContext(): boolean {
  return typeof process !== "undefined" && Boolean(process.env.NODE_TEST_CONTEXT);
}

function readStorage(storage?: Storage | null): Storage | null {
  if (storage) return storage;
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/** True when `locale` matches a registered pack id or tag, not just the fallback. */
export function localeMatchesRegisteredPack(
  locale: string,
  packs: readonly LanguagePack<MessageKey>[] = REGISTERED_PACKS,
): boolean {
  const wanted = parseLocaleTag(locale);
  if (!wanted.language) return false;
  return packs.some((pack) => {
    if (pack.id === wanted.language || pack.id === wanted.tag) return true;
    return pack.tags.some((raw) => {
      const tag = parseLocaleTag(raw);
      return tag.tag === wanted.tag || tag.language === wanted.language;
    });
  });
}

export function readStoredUiLocale(storage?: Storage | null): string {
  try {
    return readStorage(storage)?.getItem(UI_LOCALE_STORAGE_KEY)?.trim() ?? "";
  } catch {
    return "";
  }
}

export function writeStoredUiLocale(locale: string, storage?: Storage | null): void {
  try {
    readStorage(storage)?.setItem(UI_LOCALE_STORAGE_KEY, locale);
  } catch {
    // Private mode / missing storage must not block a live switch.
  }
}

/**
 * Stored choice wins over the host locale. Node unit tests stay pinned to
 * zh-CN so existing Chinese-string assertions remain honest.
 */
export function resolveUiLocale(options?: {
  stored?: string | null;
  host?: string;
  packs?: readonly LanguagePack<MessageKey>[];
}): string {
  const packs = options?.packs ?? REGISTERED_PACKS;
  const explicit = options !== undefined;
  if (isNodeTestContext() && !explicit) return "zh-CN";
  const stored = options?.stored === undefined && !explicit
    ? readStoredUiLocale()
    : (options?.stored ?? "");
  if (stored && localeMatchesRegisteredPack(stored, packs)) return stored;
  if (options?.host !== undefined) return detectHostLocale({ language: options.host });
  if (isNodeTestContext()) return "zh-CN";
  return detectHostLocale();
}

export function createTranslator(
  locale: string,
  packs: readonly LanguagePack<MessageKey>[] = REGISTERED_PACKS,
): { pack: LanguagePack<MessageKey>; t: Translate; intlLocale: string } {
  const pack = resolveLanguagePack(locale, packs);
  return {
    pack,
    intlLocale: pack.intlLocale,
    t: (key, vars) => interpolate(lookupMessage(pack, key, packs), vars),
  };
}

let activeIntlLocale = "zh-CN";
let activePack: LanguagePack<MessageKey> = ZH_PACK;

export function getActiveIntlLocale(): string {
  return activeIntlLocale;
}

export function getActivePack(): LanguagePack<MessageKey> {
  return activePack;
}

export function activateUiLocale(locale: string, packs: readonly LanguagePack<MessageKey>[] = REGISTERED_PACKS): LanguagePack<MessageKey> {
  const pack = resolveLanguagePack(locale, packs);
  activePack = pack;
  activeIntlLocale = pack.intlLocale;
  setClockLocale(pack.intlLocale);
  if (typeof document !== "undefined") document.documentElement.lang = pack.intlLocale;
  return pack;
}

/** Translate against the active pack. Call at render time, not module init. */
export function t(key: MessageKey, vars?: MessageVars): string {
  return interpolate(lookupMessage(activePack, key), vars);
}

/** Shipped catalog. Append a new pack here to support another region. */
export const REGISTERED_PACKS: LanguagePack<MessageKey>[] = [ZH_PACK, EN_PACK];

export { EN_PACK, ZH_PACK };

// node --test inherits the host locale (here often en-*). Pin zh-CN so
// existing Chinese-string assertions stay honest, matching jsdom / Playwright.
activateUiLocale(resolveUiLocale());
