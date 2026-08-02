import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import {
  augmentIco,
  flattenPng,
  inspectIcns,
  inspectIco,
  inspectPng,
  validateAppIconSources,
} from "../scripts/app-icon-tools.mjs";

describe("app icon tooling", () => {
  it("decodes the generated RGBA PNG and measures its visible bounds", async () => {
    const image = inspectPng(
      await readFile(new URL("../src-tauri/icons/icon.png", import.meta.url)),
      "icon.png",
    );
    assert.equal(image.width, 512);
    assert.equal(image.height, 512);
    assert.ok(image.stats.visiblePixels > 0);
    assert.ok(image.stats.visibleBounds);
  });

  it("keeps all Windows sizes when 20px and 128px entries are refreshed", async () => {
    const original = await readFile(new URL("../src-tauri/icons/icon.ico", import.meta.url));
    const originalEntries = inspectIco(original).entries;
    const enhanced = augmentIco(original, [
      await readFile(new URL("../src-tauri/icons/ios/AppIcon-20x20@1x.png", import.meta.url)),
      await readFile(new URL("../src-tauri/icons/128x128.png", import.meta.url)),
    ]);
    const sizes = new Set(inspectIco(enhanced).entries.map(({ width, height }) => `${width}x${height}`));
    for (const size of [16, 20, 24, 32, 48, 64, 128, 256]) {
      assert.ok(sizes.has(`${size}x${size}`), `missing ${size}x${size}`);
    }
    assert.equal(inspectIco(enhanced).entries.length, originalEntries.length);
  });

  it("flattens platform artwork into a true opaque RGB PNG for iOS", async () => {
    const flattened = inspectPng(flattenPng(
      await readFile(new URL("../src-tauri/icons/icon.png", import.meta.url)),
    ));
    assert.equal(flattened.colorType, 2);
    assert.equal(flattened.stats.transparentPixels, 0);
    assert.equal(flattened.stats.translucentPixels, 0);
  });

  it("recognizes the complete macOS ICNS resolution family", async () => {
    const icon = inspectIcns(await readFile(new URL("../src-tauri/icons/icon.icns", import.meta.url)));
    const types = new Set(icon.entries.map(({ type }) => type));
    for (const type of ["ic07", "ic08", "ic09", "ic10", "ic11", "ic12", "ic13", "ic14"]) {
      assert.ok(types.has(type), `missing ${type}`);
    }
  });

  it("relinks both Windows executables when the application icon changes", async () => {
    const [applicationBuild, launcherBuild] = await Promise.all([
      readFile(new URL("../src-tauri/build.rs", import.meta.url), "utf8"),
      readFile(new URL("../packaging/windows/launcher/build.rs", import.meta.url), "utf8"),
    ]);
    assert.match(applicationBuild, /cargo:rerun-if-changed=icons\/icon\.ico/);
    assert.match(launcherBuild, /cargo:rerun-if-changed=\{\}[^\n]*icon\.display/);
  });

  it("reports a missing official source as an actionable release error", async () => {
    await assert.rejects(
      validateAppIconSources(new URL("../tmp/missing-brand-assets", import.meta.url).pathname),
      /Missing required official app icon source: shownet-app-icon-source\.png/,
    );
  });
});
