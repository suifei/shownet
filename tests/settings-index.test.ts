/**
 * Settings is thirteen collapsible sections across four tabs. The index is what
 * makes "where do I turn on X" answerable from one search box, and what decides
 * the order sections appear in — so it has to stay in sync with the view.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  DEFAULT_OPEN_SECTIONS,
  parseOpenSections,
  searchSettings,
  sectionsForTab,
  SETTINGS_INDEX,
  SETTINGS_OPEN_SECTIONS_KEY,
  SETTINGS_TAB_LABELS,
} from "../src/settingsIndex.ts";

describe("settings index", () => {
  it("covers every section the view renders, with matching ids and titles", async () => {
    const view = await readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8");
    const rendered = [...view.matchAll(/<SettingsSection id="([^"]+)" title=\{settingsSectionTitle\("([^"]+)"\)\}>/g)]
      .map((match) => ({ id: match[1], titleId: match[2] }));

    assert.equal(rendered.length, SETTINGS_INDEX.length, "index and view must describe the same sections");
    for (const section of rendered) {
      const entry = SETTINGS_INDEX.find((item) => item.id === section.id);
      assert.ok(entry, `${section.id} is rendered but missing from the index`);
      assert.equal(section.titleId, section.id, `${section.id} title lookup must use the same id`);
    }
  });

  it("leads the capture tab with the certificate, not the upstream proxy", () => {
    // Installing the CA is the most common reason to open Settings at all; it
    // used to sit third, collapsed, below the longest section on the page.
    assert.deepEqual(
      sectionsForTab("capture").map((entry) => entry.id),
      ["capture.https", "capture.routing", "capture.devices", "capture.upstream"],
    );
  });

  it("renders capture sections in the index order", async () => {
    const view = await readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8");
    const order = [...view.matchAll(/<SettingsSection id="(capture\.[^"]+)"/g)].map((match) => match[1]);
    assert.deepEqual(order, sectionsForTab("capture").map((entry) => entry.id));
  });

  it("gives every section a summary and searchable aliases", () => {
    for (const entry of SETTINGS_INDEX) {
      assert.ok(entry.summary.length > 0, `${entry.id} needs a summary`);
      assert.ok(entry.keywords.length >= 3, `${entry.id} needs aliases people would actually type`);
      assert.ok(SETTINGS_TAB_LABELS[entry.tab], `${entry.id} points at an unknown tab`);
    }
  });

  it("uses unique ids", () => {
    assert.equal(new Set(SETTINGS_INDEX.map((entry) => entry.id)).size, SETTINGS_INDEX.length);
  });

  it("finds sections by English term, Chinese word and symptom", () => {
    assert.equal(searchSettings("cert")[0].id, "capture.https");
    assert.equal(searchSettings("证书")[0].id, "capture.https");
    assert.equal(searchSettings("ja3")[0].id, "capture.upstream");
    assert.equal(searchSettings("502")[0].id, "capture.upstream", "a symptom should reach its cause");
    assert.equal(searchSettings("token")[0].id, "mcp.auth");
    assert.equal(searchSettings("手机")[0].id, "capture.devices");
  });

  it("ranks a title match above a keyword match", () => {
    const hits = searchSettings("认证");
    assert.equal(hits[0].id, "mcp.auth");
  });

  it("labels each hit with the tab that owns it", () => {
    const hit = searchSettings("模型")[0];
    assert.ok(hit, "模型 must match something");
    assert.equal(hit.tabLabel, SETTINGS_TAB_LABELS[hit.tab]);
  });

  it("returns nothing for an empty or unmatched query", () => {
    assert.deepEqual(searchSettings(""), []);
    assert.deepEqual(searchSettings("   "), []);
    assert.deepEqual(searchSettings("zzzznotasetting"), []);
  });

  it("opens beginner sections by default and folds the power-user ones", () => {
    assert.ok(DEFAULT_OPEN_SECTIONS.includes("capture.https"));
    assert.ok(DEFAULT_OPEN_SECTIONS.includes("ai.provider"));
    assert.ok(!DEFAULT_OPEN_SECTIONS.includes("capture.upstream"), "the 190-line section stays folded");
    assert.ok(!DEFAULT_OPEN_SECTIONS.includes("data.danger"), "destructive actions stay folded");
  });

  it("survives a missing or corrupt persisted preference", () => {
    assert.deepEqual(parseOpenSections(null), DEFAULT_OPEN_SECTIONS);
    assert.deepEqual(parseOpenSections(""), DEFAULT_OPEN_SECTIONS);
    assert.deepEqual(parseOpenSections("{not json"), DEFAULT_OPEN_SECTIONS);
    assert.deepEqual(parseOpenSections('{"a":1}'), DEFAULT_OPEN_SECTIONS);
  });

  it("round-trips a saved preference and drops non-string entries", () => {
    assert.deepEqual(parseOpenSections('["capture.https","mcp.auth"]'), ["capture.https", "mcp.auth"]);
    assert.deepEqual(parseOpenSections('["capture.https",7,null]'), ["capture.https"]);
    assert.deepEqual(parseOpenSections("[]"), [], "an explicit all-collapsed choice must be honoured");
  });
});

describe("settings view wiring", () => {
  it("persists open sections across tab switches", async () => {
    const view = await readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8");
    assert.match(view, /SETTINGS_OPEN_SECTIONS_KEY/);
    assert.match(view, /localStorage\?\.setItem\(SETTINGS_OPEN_SECTIONS_KEY, JSON\.stringify\(next\)\)/);
    assert.equal(SETTINGS_OPEN_SECTIONS_KEY, "shownet.settings.open-sections.v1");
  });

  it("shows search results instead of a tab body while searching", async () => {
    const view = await readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8");
    assert.match(view, /className="settings-search"/);
    assert.match(view, /className="settings-search-results"/);
    for (const tab of ["capture", "ai", "data", "mcp"]) {
      assert.match(view, new RegExp(`\\{!settingsQuery && tab === "${tab}" && \\(`), `${tab} must hide while searching`);
    }
  });

  it("jumps to the owning tab and expands the section", async () => {
    const view = await readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8");
    assert.match(view, /const revealSection = \(id: string\)/);
    assert.match(view, /setTab\(entry\.tab\)/);
    assert.match(view, /data-settings-section=\{id\}/);
    assert.match(view, /scrollIntoView\(\{ behavior: "smooth", block: "start" \}\)/);
  });

  it("keeps a folded section self-describing", async () => {
    const [view, styles] = await Promise.all([
      readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
    ]);
    assert.match(view, /className="settings-section__heading"/);
    assert.match(view, /\{entry && <small>\{settingsSectionSummary\(entry\.id\)\}<\/small>\}/);
    assert.match(styles, /\.settings-section__heading small/);
  });
});
