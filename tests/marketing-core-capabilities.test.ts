import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

async function readUtf8(relativePath: string): Promise<string> {
  return readFile(join(root, relativePath), "utf8");
}

async function assertNonEmptyFile(relativePath: string, minBytes = 1024): Promise<number> {
  const info = await stat(join(root, relativePath));
  assert.ok(info.isFile(), `${relativePath} must be a file`);
  assert.ok(info.size >= minBytes, `${relativePath} must be >= ${minBytes} bytes, got ${info.size}`);
  return info.size;
}

describe("marketing: core capabilities, demo assets, beginner path", () => {
  it("README leads with four dedicated core-capability sections", async () => {
    const readme = await readUtf8("README.md");

    assert.match(readme, /AI 原生抓包 · 自动部署数字证书 · 自动协议逆向 · 一键生成可运行逆向 \/ 客户端代码/);
    assert.match(readme, /## 核心能力（重点）/);
    assert.match(readme, /### 1\. AI 能力：可审计的自动逆向/);
    assert.match(readme, /### 2\. 自动部署数字证书：本机与设备一条链路/);
    assert.match(readme, /### 3\. 自动逆向：从流量到算法 \/ 接口结论/);
    assert.match(readme, /### 4\. 自动生成逆向与客户端代码/);

    // Product-truth guards (must not overclaim)
    assert.match(readme, /不宣称.*JA3|位级浏览器 JA3/);
    assert.match(readme, /无需 Root/);
  });

  it("README beginner path is zero-to-success ordered: browser without CA → CA → AI → code", async () => {
    const readme = await readUtf8("README.md");
    const start = readme.indexOf("## 推荐上手路径");
    assert.ok(start >= 0, "missing 推荐上手路径 section");
    const nextHeading = readme.indexOf("\n## ", start + 1);
    const section = nextHeading >= 0 ? readme.slice(start, nextHeading) : readme.slice(start);

    assert.match(section, /小白开箱|推荐上手路径/);
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
    assert.match(srt, /AI 分析|内置 Agent|自动逆向|加密逆向|API 逆向/);
    assert.match(srt, /算法重放|Request Lab|客户端代码|生成.*代码/);
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
});
