/**
 * App chrome 语言包.
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
import { ZH_PACK } from "./locales/zh.ts";
import type { LanguagePack, MessageKey, Translate } from "./i18nTypes.ts";

export type { LanguagePack, MessageCatalog, MessageKey, Translate } from "./i18nTypes";

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
export function resolveLanguagePack(locale: string, packs: readonly LanguagePack[]): LanguagePack {
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

export function lookupMessage(
  pack: LanguagePack,
  key: MessageKey,
  packs: readonly LanguagePack[] = REGISTERED_PACKS,
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

export function createTranslator(
  locale: string,
  packs: readonly LanguagePack[] = REGISTERED_PACKS,
): { pack: LanguagePack; t: Translate; intlLocale: string } {
  const pack = resolveLanguagePack(locale, packs);
  return {
    pack,
    intlLocale: pack.intlLocale,
    t: (key) => lookupMessage(pack, key, packs),
  };
}

let activeIntlLocale = "zh-CN";

export function getActiveIntlLocale(): string {
  return activeIntlLocale;
}

export function activateUiLocale(locale: string, packs: readonly LanguagePack[] = REGISTERED_PACKS): LanguagePack {
  const pack = resolveLanguagePack(locale, packs);
  activeIntlLocale = pack.intlLocale;
  setClockLocale(pack.intlLocale);
  return pack;
}

/** Shipped catalog. Append a new pack here to support another region. */
export const REGISTERED_PACKS: LanguagePack[] = [ZH_PACK, EN_PACK];

export { EN_PACK, ZH_PACK };

activateUiLocale(detectHostLocale());
