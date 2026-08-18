/**
 * Actions must not fail silently.
 *
 * Every handler below ran `await invoke(...)` bare inside a `void fn()` click
 * handler. On failure the promise rejected unhandled: nothing on screen changed
 * and nothing was said, so the control read as dead. The destructive ones were
 * worse — they fire *after* a confirm dialog, so the user believed the thing
 * was deleted when it was not.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const read = (name: string) => readFile(new URL(`../src/${name}`, import.meta.url), "utf8");

/** The body of `const name = async ... => { ... }`, by brace matching. */
function handlerBody(source: string, name: string, from = 0) {
  const start = source.indexOf(`const ${name} = async `, from);
  assert.ok(start >= 0, `handler ${name} not found`);
  let depth = 0;
  let index = source.indexOf("{", start);
  const open = index;
  for (; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) break;
    }
  }
  return source.slice(open, index + 1);
}

describe("environment panel reports every failure", () => {
  const labels: Record<string, string> = {
    load: "读取环境失败",
    create: "创建环境失败",
    activate: "切换环境失败",
    saveVariable: "保存变量失败",
    toggleVariable: "更新变量失败",
    deleteVariable: "删除变量失败",
    deleteSelectedEnvironment: "删除环境失败",
  };

  it("wraps each handler and names what went wrong", async () => {
    const source = await read("components/RequestWorkbench.tsx");
    const panel = source.slice(source.indexOf("function EnvironmentPanel("));
    for (const [name, label] of Object.entries(labels)) {
      const body = handlerBody(panel, name);
      assert.match(body, /try \{/, `${name} must catch`);
      assert.match(body, new RegExp(label), `${name} must say "${label}"`);
    }
  });

  it("keeps the destructive confirm before the write", async () => {
    // A cancelled confirm must return, not fall into the catch as an "error".
    const source = await read("components/RequestWorkbench.tsx");
    const panel = source.slice(source.indexOf("function EnvironmentPanel("));
    const body = handlerBody(panel, "deleteVariable");
    assert.ok(body.indexOf("confirm({") < body.indexOf("delete_environment_variable"));
    assert.match(body, /\}\)\) return;/);
  });
});

describe("traffic view has a channel for failed actions", () => {
  it("declares one and clears it on a timer", async () => {
    const source = await read("components/TrafficView.tsx");
    assert.match(source, /const \[actionError, setActionError\] = useState\(""\)/);
    assert.match(source, /className="traffic-action-error" role="alert"/);
    assert.match(source, /window\.setTimeout\(\(\) => setActionError\(""\), 6_000\)/);
  });

  it("uses it for bookmarks and saved views", async () => {
    const source = await read("components/TrafficView.tsx");
    // A bookmark is how a user marks evidence; a silent no-op means they think
    // it is marked when it is not.
    assert.match(source, /setActionError\(t\("traffic.bookmarkFailed"/);
    assert.match(source, /setActionError\(t\("traffic.saveViewFailed"/);
    assert.match(source, /setActionError\(t\("traffic.deleteViewFailed"/);
  });

  it("styles the channel so it reads as an error", async () => {
    const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
    assert.match(styles, /\.traffic-action-error \{[^}]*var\(--danger-bg\)/s);
  });
});

describe("loads distinguish empty from failed", () => {
  it("says so when the collection workspace cannot be read", async () => {
    // An empty list and a failed read looked identical, so a user could rebuild
    // collections they already had.
    const source = await read("components/RequestWorkbench.tsx");
    assert.match(source, /读取请求集合失败/);
  });

  it("says so when the rule list cannot be read", async () => {
    // These rules rewrite live traffic; "you have none" is the wrong thing to
    // imply when the query errored.
    const source = await read("components/RequestWorkbench.tsx");
    assert.match(source, /读取规则失败/);
  });
});

describe("destructive and save paths report failure", () => {
  it("covers collection and folder deletion", async () => {
    const source = await read("components/RequestWorkbench.tsx");
    assert.match(source, /删除文件夹失败/);
    assert.match(source, /删除集合失败/);
  });

  it("covers saving a draft", async () => {
    const source = await read("components/RequestWorkbench.tsx");
    assert.match(source, /\.catch\(\(reason\) => setMessage\(`保存草稿失败/);
  });
});
