import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("Agent Activity report layout", () => {
  it("starts compact and exposes an accessible expand control", async () => {
    const source = await readFile(join(process.cwd(), "src/components/AnalysisView.tsx"), "utf8");
    expect(source).toMatch(/const \[expanded, setExpanded\] = useState\(false\)/);
    expect(source).toMatch(/aria-expanded=\{expanded\}/);
    expect(source).toMatch(/expanded && recent\.length/);
    expect(source).toMatch(/expanded && skillRuns\.length/);
  });

  it("keeps the live activity panel in normal document flow", async () => {
    const source = await readFile(join(process.cwd(), "src/styles.css"), "utf8");
    expect(source).toMatch(/\.agent-activity\.is-live\s*\{\s*border-color/);
    expect(source).not.toMatch(/\.agent-activity\.is-live\s*\{[^}]*position:\s*sticky/s);
    expect(source).toMatch(/\.generated-report\s*\{[^}]*width:\s*min\(1040px/s);
  });
});
