import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

async function readUtf8(relativePath: string): Promise<string> {
  const raw = await readFile(join(root, relativePath), "utf8");
  // Normalise line endings so assertions that anchor on "\n" hold regardless of
  // how the file was checked out. .gitattributes pins LF, but a working tree
  // configured before that lands would still carry CRLF.
  return raw.replace(/\r\n/g, "\n");
}

async function assertNonEmptyFile(relativePath: string, minBytes = 1024): Promise<number> {
  const info = await stat(join(root, relativePath));
  assert.ok(info.isFile(), `${relativePath} must be a file`);
  assert.ok(info.size >= minBytes, `${relativePath} must be >= ${minBytes} bytes, got ${info.size}`);
  return info.size;
}

describe("marketing: core capabilities, demo assets, beginner path", () => {
  it("README leads with user pain and unnamed scenarios, not a feature catalog", async () => {
    const readme = await readUtf8("README.md");

    assert.match(readme, /系统浏览器能登|重放发不出去/);
    assert.match(readme, /## 它解决什么/);
    assert.match(readme, /## 真实场景/);
    assert.match(readme, /某某网站|某某 App|某某接口/);
    assert.match(readme, /## AI 端点与支持/);
    assert.match(readme, /https:\/\/claudegpt\.org\/v1/);
    assert.match(readme, /553354813/);
    assert.match(readme, /href="\.\/README\.en\.md"/);
    assert.match(readme, /For international readers/);
    assert.match(readme, /English README/);

    // Product-truth guards (must not overclaim)
    assert.match(readme, /不宣称.*JA3|位级浏览器 JA3/);
    assert.match(readme, /无需 Root/);
    assert.doesNotMatch(readme, /12306|春秋航空|kyfw\.|ch\.com/i);

    const sceneArt = [
      "docs/assets/readme/hero-workspace.jpg",
      "docs/assets/readme/scenario-login-split.jpg",
      "docs/assets/readme/scenario-device-ca.jpg",
      "docs/assets/readme/scenario-signature.jpg",
      "docs/assets/readme/scenario-to-code.jpg",
    ];
    for (const path of sceneArt) {
      assert.ok(readme.includes(path), `README must use scene illustration ${path}`);
      await assertNonEmptyFile(path, 50_000);
    }
    assert.match(readme, /场景示意/);
  });

  it("README beginner path is zero-to-success ordered: browser without CA → CA → AI → code", async () => {
    const readme = await readUtf8("README.md");
    const start = readme.indexOf("## 十分钟上手");
    assert.ok(start >= 0, "missing 十分钟上手 section");
    const nextHeading = readme.indexOf("\n## ", start + 1);
    const section = nextHeading >= 0 ? readme.slice(start, nextHeading) : readme.slice(start);

    assert.match(section, /十分钟上手|小白开箱|推荐上手路径/);
    assert.match(section, /### 1\..*零配置|不必先装证书|不必.*装证书/);
    assert.match(section, /内嵌浏览器/);
    assert.match(section, /开始抓包/);
    assert.match(section, /### 2\..*装证书|安装 CA/);
    assert.match(section, /### 3\..*AI/);
    assert.match(section, /### 4\..*代码|算法重放/);
    assert.match(section, /Request Lab|算法重放包/);

    // Step 1 must appear before step 2 cert language in the path section
    const browserIdx = section.search(/零配置|不必先装证书/);
    const certIdx = section.search(/### 2\./);
    const aiIdx = section.search(/### 3\./);
    const codeIdx = section.search(/### 4\./);
    assert.ok(browserIdx >= 0 && certIdx > browserIdx && aiIdx > certIdx && codeIdx > aiIdx);
  });

  it("tutorial SRT narrates 证书 → 证据/浏览器 → AI 逆向 → 生成代码", async () => {
    const srt = await readUtf8("docs/assets/tutorial/ShowNet-真实操作新手教程.srt");

    assert.match(srt, /自动部署数字证书|安装 ShowNet Root CA|装证书/);
    assert.match(srt, /内嵌浏览器|开始抓包/);
    assert.match(srt, /不必先装证书|开箱即用/);
    assert.match(srt, /高级控制台|MITM/);
    assert.match(srt, /AI 分析|内置 Agent|自动逆向|加密逆向|API 逆向/);
    assert.match(srt, /算法重放|Request Lab|客户端代码|生成.*代码/);
    // Each cue should be a complete sentence-ish line (not truncated mid-phrase markers)
    const cues = srt.split(/\n\n+/).filter((block) => /\d+\n\d{2}:/.test(block));
    assert.ok(cues.length >= 9, `expected full multi-scene SRT, got ${cues.length}`);
    for (const cue of cues) {
      const text = cue.split("\n").slice(2).join("");
      assert.ok(text.length >= 20, `cue too short (possible truncation): ${text}`);
      assert.match(text, /[。！？.]$/, `cue should end with sentence punctuation: ${text.slice(-20)}`);
    }
    // Honesty: no Root requirement claim for Android
    assert.doesNotMatch(srt, /需要 Root|必须 Root|Root 权限/);
  });

  it("landscape and portrait tutorial MP4s exist and are playable-sized", async () => {
    const landscape = "docs/assets/tutorial/ShowNet-真实操作新手教程-B站横版.mp4";
    const portrait = "docs/assets/tutorial/ShowNet-真实操作新手教程-小红书竖版.mp4";
    const landscapeSize = await assertNonEmptyFile(landscape, 100_000);
    const portraitSize = await assertNonEmptyFile(portrait, 100_000);
    assert.ok(landscapeSize > 1_000_000, `landscape mp4 too small: ${landscapeSize}`);
    assert.ok(portraitSize > 1_000_000, `portrait mp4 too small: ${portraitSize}`);

    // ftyp box at start of ISO BMFF
    const head = await readFile(join(root, landscape));
    assert.ok(head.subarray(4, 8).toString("ascii") === "ftyp", "landscape is not an ISO MP4 (missing ftyp)");
    const headP = await readFile(join(root, portrait));
    assert.ok(headP.subarray(4, 8).toString("ascii") === "ftyp", "portrait is not an ISO MP4 (missing ftyp)");
  });

  it("README links the published tutorial assets that exist on disk", async () => {
    const readme = await readUtf8("README.md");
    const linked = [
      "docs/assets/tutorial/ShowNet-真实操作新手教程-B站横版.mp4",
      "docs/assets/tutorial/ShowNet-真实操作新手教程-小红书竖版.mp4",
      "docs/assets/tutorial/ShowNet-真实操作新手教程.srt",
    ];
    for (const path of linked) {
      assert.ok(readme.includes(path), `README must link ${path}`);
      await assertNonEmptyFile(path, path.endsWith(".srt") ? 200 : 100_000);
    }
  });

  it("ships a full English homepage that mirrors the Chinese one", async () => {
    const zh = await readUtf8("README.md");
    const en = await readUtf8("README.en.md");

    assert.match(zh, /简体中文/);
    assert.match(en, /href="\.\/README\.md"/);
    assert.match(en, /## What it actually fixes/);
    assert.match(en, /## Real scenarios/);
    assert.match(en, /## Ten minutes to first traffic/);
    assert.match(en, /## AI endpoint and support/);
    assert.match(en, /a certain site|a certain app|a certain API/i);
    assert.match(en, /https:\/\/claudegpt\.org\/v1/);
    assert.match(en, /553354813/);
    assert.match(en, /does not claim.*JA3|not claim.*JA3/i);
    assert.match(en, /no Root required/);
    assert.doesNotMatch(en, /12306|春秋航空|kyfw\.|ch\.com/i);

    const start = en.indexOf("## Ten minutes to first traffic");
    assert.ok(start >= 0, "missing English beginner path");
    const nextHeading = en.indexOf("\n## ", start + 1);
    const section = nextHeading >= 0 ? en.slice(start, nextHeading) : en.slice(start);
    assert.match(section, /### 1\..*Zero config|no CA first/);
    assert.match(section, /### 2\..*Install the CA/);
    assert.match(section, /### 3\..*AI/);
    assert.match(section, /### 4\..*replay|client code/);
    const browserIdx = section.search(/Zero config|no CA first/);
    const certIdx = section.search(/### 2\./);
    const aiIdx = section.search(/### 3\./);
    const codeIdx = section.search(/### 4\./);
    assert.ok(browserIdx >= 0 && certIdx > browserIdx && aiIdx > certIdx && codeIdx > aiIdx);

    const sceneArt = [
      "docs/assets/readme/hero-workspace.jpg",
      "docs/assets/readme/scenario-login-split.jpg",
      "docs/assets/readme/scenario-device-ca.jpg",
      "docs/assets/readme/scenario-signature.jpg",
      "docs/assets/readme/scenario-to-code.jpg",
    ];
    for (const path of sceneArt) {
      assert.ok(en.includes(path), `English README must use scene illustration ${path}`);
    }
    assert.match(en, /scene illustration/);
  });
});
