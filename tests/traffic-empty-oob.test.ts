/**
 * Empty traffic workspace must present a zero-setup out-of-box path.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("traffic empty out-of-box path", () => {
  it("offers embedded browser first and documents no-CA start", async () => {
    const [traffic, app, styles] = await Promise.all([
      readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
    ]);

    assert.match(traffic, /onOpenBrowser\?/);
    assert.match(traffic, /traffic-empty-oob/);
    assert.match(traffic, /traffic\.emptyHint|traffic\.emptyStep1/);
    assert.match(traffic, /empty-open-browser/);
    assert.match(traffic, /traffic\.emptyOpenBrowser/);
    assert.match(traffic, /traffic\.emptyCa/);
    assert.match(traffic, /traffic\.emptyStep3/);

    assert.match(app, /onOpenBrowser=\{\(\) => setActiveView\("browser"\)\}/);
    assert.match(app, /onOpenSettingsCapture/);

    assert.match(styles, /\.traffic-empty__hint/);
    assert.match(styles, /\.traffic-empty__steps/);
    assert.match(styles, /\.empty-actions \.primary-button[^}]*--codex-accent/s);
  });

  it("feature map documents capture vs analysis workflow", async () => {
    const map = await readFile(new URL("../docs/feature-map.md", import.meta.url), "utf8");
    assert.match(map, /抓包.*证据.*分析.*导出|1 抓包/);
    assert.match(map, /shownet_get_tls_fingerprints/);
    assert.match(map, /shownet_list_px_evidence/);
    assert.match(map, /开箱即用|零配置/);
    assert.match(map, /ja3Parity|不宣称/);
  });
});
