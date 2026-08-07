/**
 * Covers the third pass: controls that misrepresented what they could do,
 * actions whose scope was ambiguous, prompts that fell out of the app's visual
 * language, and interactions that had no affordance at all.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const settings = await readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8");
const traffic = await readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8");
const workbench = await readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8");
const confirmDialog = await readFile(new URL("../src/components/ConfirmDialog.tsx", import.meta.url), "utf8");
const shortcuts = await readFile(new URL("../src/components/ShortcutsSheet.tsx", import.meta.url), "utf8");
const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const analysis = await readFile(new URL("../src/components/AnalysisView.tsx", import.meta.url), "utf8");
const bodyViewer = await readFile(new URL("../src/components/HttpBodyViewer.tsx", import.meta.url), "utf8");

describe("settings stop offering edits that do not exist", () => {
  it("presents the listener address and port as facts, not form fields", () => {
    // They were `readOnly` inputs — no command anywhere changes either value,
    // so the field read as editable-but-broken.
    assert.match(settings, /className="settings-fact-row"/);
    assert.doesNotMatch(settings, /<span>代理端口<\/span><input type="number" value=\{runtime\.proxyPort\} readOnly \/>/);
    assert.match(styles, /\.settings-fact \{/);
  });

  it("says what to do when the fixed port is taken", () => {
    assert.match(settings, /端口固定为 \{runtime\.proxyPort\}。若被占用/);
  });

  it("still lets the user copy the endpoint", () => {
    assert.match(settings, /copyText\(`\$\{runtime\.listenHost\}:\$\{runtime\.proxyPort\}`, "代理地址"\)/);
  });
});

describe("recorded failures are shown, not just stored", () => {
  it("tells the user why a capture rule stopped working", () => {
    // `last_error` is written on every rule run (storage.rs), but the row only
    // ever showed 命中 0 — a rule whose action keeps failing looked idle.
    assert.match(workbench, /rule\.lastError && <small className="rule-row__error"/);
    assert.match(styles, /\.rule-row__error \{/);
  });

  it("tells the user why a skill run failed", () => {
    // The status dot went red and nothing said what went wrong.
    assert.match(analysis, /run\.error && <span className="agent-skill-runs__error"/);
    assert.match(styles, /\.agent-skill-runs__error \{/);
  });

  it("does not treat an omitted binary body as a fault", () => {
    // 保存二进制响应 is off by default, so every image would carry an alert.
    assert.match(bodyViewer, /const warning = Boolean\(metadata\.error \|\| metadata\.truncated \|\| !metadata\.complete\)/);
    assert.doesNotMatch(bodyViewer, /const warning = Boolean\(omitted \|\|/);
    assert.match(styles, /\.response-body-status\.is-omitted \{/);
  });
});

describe("analysis entry points state their scope", () => {
  it("names the session-wide and selection-scoped buttons differently", () => {
    // Both used to read "AI 分析" with nothing conveying which was which.
    assert.match(traffic, /分析整个会话/);
    assert.match(traffic, /\/>分析选中\n/);
  });

  it("puts the selection count in the context menu item", () => {
    assert.match(traffic, /分析选中的 \{selectedRequests\.length\} 条请求/);
  });
});

describe("request lab labels match the rest of the app", () => {
  it("names request parts in Chinese, like the traffic detail pane does", () => {
    assert.match(workbench, /query: "参数", headers: "请求头", body: "请求体", auth: "认证", settings: "发送设置"/);
    assert.doesNotMatch(workbench, /query: "Query", headers: "Headers", body: "Body"/);
  });

  it("no longer mixes languages inside the response tab group", () => {
    // It read `Body / Headers / 历史`.
    assert.match(workbench, /body: "响应体", headers: "响应头", history: `历史/);
  });
});

describe("diff mode explains itself", () => {
  it("says what to do when the selection is not two requests", () => {
    // It rendered a bare shell reading "0 项差异", which looks like the two
    // requests are identical.
    assert.match(workbench, /if \(details\.length !== 2\) \{/);
    assert.match(workbench, /请先选中两条请求/);
    assert.match(workbench, /一次只能对比两条请求/);
    assert.match(styles, /\.workbench-empty \{/);
  });
});

describe("confirmations live in the app", () => {
  it("replaces every native confirm", () => {
    assert.doesNotMatch(workbench, /window\.confirm/);
    const controllers = (workbench.match(/useConfirm\(\)/g) ?? []).length;
    assert.equal(controllers, 5, "each panel that asks owns a controller");
    assert.equal((workbench.match(/\{dialog\}/g) ?? []).length, controllers, "and renders it");
    // The count alone let a controller exist that nothing ever opened: the
    // Cookie Jar panel held one and rendered its dialog while both its buttons
    // called their callbacks directly, so the code read as if it confirmed.
    // Confirmation for the destructive action lives with the handler instead.
    assert.ok(
      (workbench.match(/await confirm\(/g) ?? []).length >= controllers,
      "a controller nobody opens is a dialog that never appears",
    );
  });

  it("resolves to false on cancel, Escape and backdrop", () => {
    assert.match(confirmDialog, /role="alertdialog"/);
    assert.match(confirmDialog, /onMouseDown=\{\(\) => settle\(false\)\}/);
    assert.match(confirmDialog, /if \(event\.key === "Escape"\) settle\(false\)/);
  });

  it("never strands a promise when a second confirm opens", () => {
    assert.match(confirmDialog, /pendingRef\.current\?\.resolve\(false\)/);
  });

  it("keeps the rule warning as the body and names the kind in the title", () => {
    assert.match(workbench, /const confirmKind = isBreakpoint \? "人工断点"/);
    assert.match(workbench, /title: `启用\$\{confirmKind\}“\$\{rule\.name\}”？`/);
    assert.match(workbench, /detail: confirmation/);
    // Credential behaviour is the part a user most needs to read.
    assert.match(workbench, /此规则会保留认证信息与 Cookie，请确认目标可信。/);
  });

  it("marks destructive confirmations as such", () => {
    assert.equal((workbench.match(/tone: "danger"/g) ?? []).length, 5);
    assert.match(styles, /\.confirm-dialog\.is-danger/);
  });
});

describe("hidden grid interactions are documented", () => {
  it("covers the interactions that had no affordance", () => {
    for (const phrase of [
      "追加为次级排序条件",
      "全选当前窗口的请求",
      "连选一段范围",
      "按内容自适应列宽",
      "调整列的先后顺序",
      "配置显示哪些列",
    ]) {
      assert.match(shortcuts, new RegExp(phrase), `${phrase} must be documented`);
    }
  });

  it("distinguishes alternative keys from combinations", () => {
    // ↑ and ↓ are alternatives; ⌘ and K are pressed together.
    assert.match(shortcuts, /description: "上下移动当前行", alt: true/);
    assert.match(shortcuts, /item\.alt \? "\/" : "\+"/);
  });

  it("opens from the keyboard and the command palette", () => {
    assert.match(app, /<ShortcutsSheet onClose=\{\(\) => setShortcutsOpen\(false\)\} \/>/);
    assert.match(app, /id: "shortcuts"/);
    assert.match(app, /event\.key === "\?" && !isEditableTarget\(event\.target\)/);
    assert.match(styles, /\.shortcuts-sheet \{/);
  });

  it("does not hijack ? while the user is typing", () => {
    assert.match(app, /function isEditableTarget\(target: EventTarget \| null\)/);
    assert.match(app, /target instanceof HTMLTextAreaElement/);
    assert.match(app, /target\.isContentEditable/);
  });
});
