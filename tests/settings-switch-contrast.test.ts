/**
 * #54: Settings switches must stay readable on the dark panel.
 *
 * The failure was token collapse: off/on/knob reused the panel ramp, so the
 * control disappeared into `.settings-panel`. This drives the shipped CSS
 * (resolved backgrounds on the real selectors) and the SettingsView markup.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const settings = await readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8");

const NAMED_SWITCH_LABELS = [
  't("settings.route.takeover")',
  't("settings.device.allowLan")',
  't("settings.ai.twoStage")',
  't("settings.ai.allowMcp")',
  't("settings.ai.streaming")',
  't("settings.data.autoCleanup")',
  't("settings.data.saveBinary")',
] as const;

interface Rgb {
  r: number;
  g: number;
  b: number;
}

function stripComments(css: string): string {
  return css.replace(/\/\*[\s\S]*?\*\//g, "");
}

function blockAfter(css: string, prelude: string): string {
  const idx = css.indexOf(prelude);
  assert.ok(idx >= 0, `missing ${prelude}`);
  const open = css.indexOf("{", idx);
  assert.ok(open >= 0, `${prelude} has no {`);
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    const ch = css[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return css.slice(open + 1, i);
    }
  }
  throw new Error(`${prelude} is unclosed`);
}

function rootVars(css: string): Map<string, string> {
  const body = stripComments(blockAfter(css, ":root"));
  const vars = new Map<string, string>();
  for (const chunk of body.split(";")) {
    const match = chunk.match(/^\s*(--[\w-]+)\s*:\s*([\s\S]+)$/);
    if (match) vars.set(match[1], match[2].trim());
  }
  return vars;
}

function resolveValue(raw: string, vars: Map<string, string>, seen = new Set<string>()): string {
  const trimmed = raw.trim();
  const match = trimmed.match(/^var\(\s*(--[\w-]+)\s*(?:,\s*([\s\S]+))?\s*\)$/);
  if (!match) return trimmed;
  const name = match[1];
  assert.ok(!seen.has(name), `cycle at ${name}`);
  seen.add(name);
  const next = vars.get(name);
  if (next) return resolveValue(next, vars, seen);
  if (match[2]) return resolveValue(match[2], vars, seen);
  throw new Error(`unresolved ${name}`);
}

function declaration(body: string, property: string): string | undefined {
  for (const chunk of stripComments(body).split(";")) {
    const match = chunk.match(/^\s*([\w-]+)\s*:\s*([\s\S]+)$/);
    if (match?.[1] === property) return match[2].trim();
  }
  return undefined;
}

function ruleBody(css: string, selector: string): string {
  const source = stripComments(css);
  const matches: string[] = [];
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let hit: RegExpExecArray | null;
  while ((hit = re.exec(source))) {
    const selectors = hit[1].split(",").map((part) => part.trim()).filter(Boolean);
    if (selectors.includes(selector)) matches.push(hit[2]);
  }
  assert.ok(matches.length > 0, `no rule for ${selector}`);
  return matches.join("\n");
}

function parseRgb(value: string): Rgb {
  const hex = value.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (hex) {
    const raw = hex[1];
    const full = raw.length === 3 ? raw.split("").map((ch) => ch + ch).join("") : raw;
    return {
      r: Number.parseInt(full.slice(0, 2), 16),
      g: Number.parseInt(full.slice(2, 4), 16),
      b: Number.parseInt(full.slice(4, 6), 16),
    };
  }
  const rgb = value.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([\d.]+))?\s*\)$/);
  assert.ok(rgb, `not a color: ${value}`);
  const alpha = rgb[4] === undefined ? 1 : Number(rgb[4]);
  return {
    r: Math.round(Number(rgb[1]) * alpha),
    g: Math.round(Number(rgb[2]) * alpha),
    b: Math.round(Number(rgb[3]) * alpha),
  };
}

function luminance({ r, g, b }: Rgb): number {
  const channel = (value: number) => {
    const v = value / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(a: Rgb, b: Rgb): number {
  const light = Math.max(luminance(a), luminance(b));
  const dark = Math.min(luminance(a), luminance(b));
  return (light + 0.05) / (dark + 0.05);
}

function key(rgb: Rgb): string {
  return `${rgb.r},${rgb.g},${rgb.b}`;
}

function resolvedBackground(css: string, vars: Map<string, string>, selector: string): Rgb {
  const body = ruleBody(css, selector);
  const raw = declaration(body, "background") ?? declaration(body, "background-color");
  assert.ok(raw, `${selector} has no background`);
  return parseRgb(resolveValue(raw, vars));
}

describe("Settings switch contrast (#54)", () => {
  const vars = rootVars(styles);

  it("names dedicated off / on / knob tokens that are not the panel ramp", () => {
    for (const name of ["--switch-track-off", "--switch-track-on", "--switch-knob"] as const) {
      assert.ok(vars.has(name), `missing ${name}`);
    }
    const off = resolveValue("var(--switch-track-off)", vars);
    const on = resolveValue("var(--switch-track-on)", vars);
    const knob = resolveValue("var(--switch-knob)", vars);
    const panel = resolveValue("var(--surface-panel)", vars);
    const sunken = resolveValue("var(--surface-sunken)", vars);
    const raised = resolveValue("var(--dark-raised)", vars);
    const successBg = resolveValue("var(--success-bg)", vars);
    assert.notEqual(off, on);
    assert.notEqual(off, knob);
    assert.notEqual(on, knob);
    assert.notEqual(off, panel);
    assert.notEqual(on, panel);
    assert.notEqual(knob, panel);
    assert.notEqual(off, sunken);
    assert.notEqual(on, raised);
    assert.notEqual(on, successBg);
    assert.notEqual(knob, panel);
  });

  it("paints settings-switch-row and compact-switch from those tokens", () => {
    const expected = {
      ".settings-switch-row i": "--switch-track-off",
      ".settings-switch-row input:checked + i": "--switch-track-on",
      ".settings-switch-row i::after": "--switch-knob",
      ".compact-switch i": "--switch-track-off",
      ".compact-switch input:checked + i": "--switch-track-on",
      ".compact-switch i::after": "--switch-knob",
    } as const;
    for (const [selector, token] of Object.entries(expected)) {
      const body = ruleBody(styles, selector);
      const raw = declaration(body, "background") ?? declaration(body, "background-color");
      assert.equal(raw, `var(${token})`, `${selector} must use ${token}`);
    }
  });

  it("keeps off, on, and knob distinct from the settings panel and each other", () => {
    const off = resolvedBackground(styles, vars, ".settings-switch-row i");
    const on = resolvedBackground(styles, vars, ".settings-switch-row input:checked + i");
    const knob = resolvedBackground(styles, vars, ".settings-switch-row i::after");
    const compactOff = resolvedBackground(styles, vars, ".compact-switch i");
    const compactOn = resolvedBackground(styles, vars, ".compact-switch input:checked + i");
    const compactKnob = resolvedBackground(styles, vars, ".compact-switch i::after");

    const panelSolid = parseRgb(resolveValue("var(--surface-panel)", vars));
    const material = resolveValue("var(--material-regular)", vars);
    const panelGlass = parseRgb(material);

    assert.notEqual(key(off), key(on), "off and on tracks must differ");
    assert.notEqual(key(off), key(knob), "knob must differ from off track");
    assert.notEqual(key(on), key(knob), "knob must differ from on track");
    for (const [name, color] of [
      ["off", off],
      ["on", on],
      ["knob", knob],
    ] as const) {
      assert.notEqual(key(color), key(panelSolid), `${name} matches --surface-panel`);
      assert.notEqual(key(color), key(panelGlass), `${name} matches the frosted settings pane`);
      assert.ok(
        contrast(color, panelSolid) >= 3,
        `${name} vs panel ${contrast(color, panelSolid).toFixed(2)}:1`,
      );
      assert.ok(
        contrast(color, panelGlass) >= 3,
        `${name} vs glass panel ${contrast(color, panelGlass).toFixed(2)}:1`,
      );
    }
    assert.ok(contrast(knob, off) >= 3, `knob vs off ${contrast(knob, off).toFixed(2)}:1`);
    assert.ok(contrast(knob, on) >= 3, `knob vs on ${contrast(knob, on).toFixed(2)}:1`);

    assert.deepEqual(compactOff, off);
    assert.deepEqual(compactOn, on);
    assert.deepEqual(compactKnob, knob);
  });

  it("wires the reported Settings switches to those classes", () => {
    for (const label of NAMED_SWITCH_LABELS) {
      const needle = `<strong>{${label}}</strong>`;
      const at = settings.indexOf(needle);
      assert.ok(at >= 0, `missing switch label ${label}`);
      const window = settings.slice(Math.max(0, at - 180), at);
      assert.match(window, /className="settings-switch-row"/, `${label} is not a settings-switch-row`);
    }
    assert.match(settings, /className="compact-switch"/);
    assert.match(settings, /title=\{server\.enabled \? t\("settings\.mcp\.disableAgent"\) : t\("settings\.mcp\.enableAgent"\)\}/);
    assert.match(settings, /t\("settings\.mcp\.forBuiltin"\)/);
  });
});
