/**
 * The command palette is the app's single "reach anything" surface, so its
 * matching, grouping and keyboard cursor have to behave predictably.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  COMMAND_GROUP_LABELS,
  filterCommands,
  flattenCommands,
  groupCommands,
  moveCommandCursor,
  type CommandAction,
} from "../src/commandRegistry.ts";

function action(id: string, title: string, overrides: Partial<CommandAction> = {}): CommandAction {
  return { id, title, group: "navigate", run: () => undefined, ...overrides };
}

const registry: CommandAction[] = [
  action("setup", "打开新手引导", { group: "start", keywords: ["setup", "guide"] }),
  action("capture", "开始抓包", { group: "capture", keywords: ["capture", "start", "proxy"] }),
  action("export", "导出为 HAR / Postman / OpenAPI", { group: "session", keywords: ["export", "har", "postman"] }),
  action("traffic", "实时流量", { group: "navigate", subtitle: "请求列表、筛选与详情" }),
  action("ca", "安装 HTTPS 证书", { group: "config", keywords: ["ca", "cert", "https"] }),
];

describe("command registry", () => {
  it("returns the curated order when the query is empty", () => {
    const filtered = filterCommands(registry, "   ");
    assert.deepEqual(filtered.map((entry) => entry.id), ["setup", "capture", "export", "traffic", "ca"]);
  });

  it("matches the Chinese label", () => {
    assert.deepEqual(filterCommands(registry, "抓包").map((entry) => entry.id), ["capture"]);
  });

  it("matches English aliases so API developers can type what they know", () => {
    assert.deepEqual(filterCommands(registry, "har").map((entry) => entry.id), ["export"]);
    assert.deepEqual(filterCommands(registry, "cert").map((entry) => entry.id), ["ca"]);
  });

  it("falls back to the subtitle when neither label nor keyword matches", () => {
    assert.deepEqual(filterCommands(registry, "筛选").map((entry) => entry.id), ["traffic"]);
  });

  it("ranks a label hit above a keyword hit for the same query", () => {
    const actions = [
      action("keyword-only", "导出会话包", { keywords: ["har"] }),
      action("label-hit", "har 导入"),
    ];
    assert.equal(filterCommands(actions, "har")[0].id, "label-hit");
  });

  it("drops non-matching actions entirely", () => {
    assert.deepEqual(filterCommands(registry, "zzzz"), []);
  });

  it("groups actions in a fixed order and labels every group", () => {
    const groups = groupCommands(registry);
    assert.deepEqual(groups.map((group) => group.id), ["start", "capture", "session", "navigate", "config"]);
    for (const group of groups) {
      assert.equal(group.label, COMMAND_GROUP_LABELS[group.id]);
      assert.ok(group.actions.length > 0, `group ${group.id} must not render empty`);
    }
  });

  it("omits groups that have no matching actions", () => {
    const groups = groupCommands(filterCommands(registry, "抓包"));
    assert.deepEqual(groups.map((group) => group.id), ["capture"]);
  });

  it("flattens groups into the same order the list renders", () => {
    assert.deepEqual(
      flattenCommands(groupCommands(registry)).map((entry) => entry.id),
      ["setup", "capture", "export", "traffic", "ca"],
    );
  });

  it("skips disabled rows so Enter always has a runnable target", () => {
    const actions = [
      action("a", "A"),
      action("b", "B", { disabled: true }),
      action("c", "C"),
    ];
    assert.equal(moveCommandCursor(actions, 0, 1), 2, "forward must jump over the disabled row");
    assert.equal(moveCommandCursor(actions, 2, -1), 0, "backward must jump over it too");
  });

  it("wraps around the ends of the list", () => {
    const actions = [action("a", "A"), action("b", "B")];
    assert.equal(moveCommandCursor(actions, 1, 1), 0);
    assert.equal(moveCommandCursor(actions, 0, -1), 1);
  });

  it("holds the cursor still when every row is disabled", () => {
    const actions = [action("a", "A", { disabled: true }), action("b", "B", { disabled: true })];
    assert.equal(moveCommandCursor(actions, 0, 1), 0);
  });
});

describe("command palette wiring", () => {
  it("indexes actions well beyond plain navigation", async () => {
    const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");

    // The palette exists so a user never has to know which view owns a control.
    for (const id of [
      "capture-toggle",
      "connect-sources",
      "session-export",
      "install-ca",
      "ai-settings",
      "mcp-settings",
      "go-collections",
      "go-rules",
      "go-environment",
    ]) {
      assert.match(app, new RegExp(`id: "${id}"`), `palette must expose ${id}`);
    }

    assert.match(app, /<CommandPalette actions=\{commandActions\}/);
    assert.match(app, /event\.key\.toLowerCase\(\) === "k"/);
    assert.match(app, /setCommandOpen\(\(open\) => !open\)/);
  });

  it("explains disabled commands instead of leaving them dead", async () => {
    const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
    assert.match(app, /disabledReason: "请先停止抓包"/);
    assert.match(app, /action\.disabled \? action\.disabledReason/);
  });
});
