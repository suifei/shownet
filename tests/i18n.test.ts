/**
 * Language-pack resolve + lookup. Expected strings come from the shipped
 * packs through lookupMessage — not a second map sitting beside them.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  createTranslator,
  EN_PACK,
  FALLBACK_PACK_ID,
  localeMatchesRegisteredPack,
  lookupMessage,
  NAV_MESSAGE_KEYS,
  readStoredUiLocale,
  REGISTERED_PACKS,
  resolveLanguagePack,
  resolveUiLocale,
  UI_LOCALE_STORAGE_KEY,
  writeStoredUiLocale,
  ZH_PACK,
} from "../src/i18n.ts";
import { chromeLabel } from "../src/navChrome.ts";
import type { LanguagePack } from "../src/i18n.ts";

const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");

describe("language pack resolve and lookup", () => {
  it("registers Chinese and English packs that differ on every nav key", () => {
    assert.equal(ZH_PACK.id, "zh");
    assert.equal(EN_PACK.id, "en");
    assert.ok(REGISTERED_PACKS.includes(ZH_PACK));
    assert.ok(REGISTERED_PACKS.includes(EN_PACK));
    for (const key of NAV_MESSAGE_KEYS) {
      const zh = lookupMessage(ZH_PACK, key);
      const en = lookupMessage(EN_PACK, key);
      assert.ok(zh, `zh missing ${key}`);
      assert.ok(en, `en missing ${key}`);
      assert.notEqual(zh, en, `${key} must not be identical across packs`);
    }
  });

  it("resolves zh-CN and zh to the Chinese pack via lookup", () => {
    for (const locale of ["zh-CN", "zh", "zh_CN"]) {
      const pack = resolveLanguagePack(locale, REGISTERED_PACKS);
      assert.equal(pack.id, "zh", locale);
      assert.equal(lookupMessage(pack, "nav.settings"), lookupMessage(ZH_PACK, "nav.settings"));
      assert.equal(lookupMessage(pack, "nav.traffic"), lookupMessage(ZH_PACK, "nav.traffic"));
    }
  });

  it("resolves en-US and en to the English pack via lookup", () => {
    for (const locale of ["en-US", "en", "en_GB"]) {
      const pack = resolveLanguagePack(locale, REGISTERED_PACKS);
      assert.equal(pack.id, "en", locale);
      assert.equal(lookupMessage(pack, "nav.settings"), lookupMessage(EN_PACK, "nav.settings"));
      assert.equal(lookupMessage(pack, "nav.traffic"), lookupMessage(EN_PACK, "nav.traffic"));
    }
  });

  it("falls back to the documented pack when no registered pack matches", () => {
    const pack = resolveLanguagePack("th-TH", REGISTERED_PACKS);
    assert.equal(pack.id, FALLBACK_PACK_ID);
    assert.equal(lookupMessage(pack, "nav.settings"), lookupMessage(ZH_PACK, "nav.settings"));
  });

  it("selects a third registered pack when the locale matches it", () => {
    const extra: LanguagePack = {
      ...EN_PACK,
      id: "th",
      tags: ["th", "th-TH"],
      intlLocale: "th-TH",
      messages: {
        ...EN_PACK.messages,
        "nav.settings": "ตั้งค่า",
      },
    };
    const packs = [...REGISTERED_PACKS, extra];
    const pack = resolveLanguagePack("th-TH", packs);
    assert.equal(pack.id, "th");
    assert.equal(lookupMessage(pack, "nav.settings", packs), lookupMessage(extra, "nav.settings", packs));
    assert.notEqual(lookupMessage(pack, "nav.settings", packs), lookupMessage(ZH_PACK, "nav.settings"));
    assert.notEqual(lookupMessage(pack, "nav.settings", packs), lookupMessage(EN_PACK, "nav.settings"));
  });
});

describe("chrome lookup wiring", () => {
  it("navChrome labels come from lookup of the active pack", () => {
    const zh = (key: typeof NAV_MESSAGE_KEYS[number]) => lookupMessage(ZH_PACK, key);
    const en = (key: typeof NAV_MESSAGE_KEYS[number]) => lookupMessage(EN_PACK, key);
    assert.equal(chromeLabel(zh, "settings"), lookupMessage(ZH_PACK, "nav.settings"));
    assert.equal(chromeLabel(en, "settings"), lookupMessage(EN_PACK, "nav.settings"));
    assert.equal(chromeLabel(zh, "traffic"), lookupMessage(ZH_PACK, "nav.traffic"));
    assert.equal(chromeLabel(en, "traffic"), lookupMessage(EN_PACK, "nav.traffic"));
    assert.notEqual(chromeLabel(zh, "settings"), chromeLabel(en, "settings"));
  });

  it("App nav and palette titles call chrome lookup, not only Chinese literals", async () => {
    assert.match(app, /chromeLabel\(t,/);
    assert.match(app, /resolveUiLocale/);
    assert.match(app, /createTranslator/);
    assert.match(app, /t\("nav\.settings"\)/);
    assert.match(app, /id: "go-settings"/);
    assert.match(app, /id: "go-browser"/);
    assert.match(app, /title: chromeLabel\(t, "settings"\)/);
    assert.match(app, /title: chromeLabel\(t, "traffic"\)/);
    assert.match(app, /t\("shell\.command"\)/);
    assert.match(app, /t\("shell\.sessions"\)/);
    assert.doesNotMatch(app, /label: "流量"/);
    assert.doesNotMatch(app, /<span>设置<\/span>/);
    assert.doesNotMatch(app, /<span>命令<\/span>/);
    assert.match(app, /<LocaleSwitcher onChange=\{applyUiLocale\} \/>/);
    const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
    assert.match(css, /\.topbar\s*\{[^}]*z-index:\s*40/s);
  });

  it("lets a stored pack override the host locale", () => {
    const storage = memoryStorage();
    writeStoredUiLocale("en", storage);
    assert.equal(readStoredUiLocale(storage), "en");
    assert.equal(storage.getItem(UI_LOCALE_STORAGE_KEY), "en");
    assert.equal(resolveUiLocale({ stored: "en", host: "zh-CN" }), "en");
    assert.equal(resolveUiLocale({ stored: "zh", host: "en-US" }), "zh");
    assert.equal(resolveUiLocale({ stored: "nope", host: "en-GB" }), "en-GB");
    assert.ok(localeMatchesRegisteredPack("en-US"));
    assert.ok(localeMatchesRegisteredPack("zh-CN"));
    assert.equal(localeMatchesRegisteredPack("th"), false);
  });

  it("interpolates named placeholders", () => {
    assert.equal(lookupMessage(ZH_PACK, "shell.reports").includes("{count}"), true);
    const { t } = createTranslator("en-US");
    assert.equal(t("shell.reports", { count: 2 }), "2 reports");
    assert.equal(t("shell.sourcesCount", { count: 3 }), "3 sources");
  });
});

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() { return data.size; },
    clear() { data.clear(); },
    getItem(key) { return data.has(key) ? data.get(key)! : null; },
    key(index) { return [...data.keys()][index] ?? null; },
    removeItem(key) { data.delete(key); },
    setItem(key, value) { data.set(key, String(value)); },
  };
}
