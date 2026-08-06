import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import App from "../../src/App";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

const goTo = (label: string) =>
  userEvent.click(screen.getByRole("button", { name: new RegExp(`^${label}$`) }));

describe("analysis without an AI key", () => {
  it("offers a scan that says plainly it does not call the model", async () => {
    // Everything else on this page needs a configured provider. This is the one
    // path that does not, so the label has to make that obvious rather than
    // leaving the user to discover it by trying.
    render(<App />);
    await goTo("AI 分析");

    const quickScan = screen.getByRole("button", { name: /免 AI 快速分析/ });
    expect(quickScan).toBeInTheDocument();
    expect(quickScan.getAttribute("title")).toMatch(/不调用 AI/);
    expect(quickScan.getAttribute("title")).toMatch(/API key/);
  });

  it("keeps it distinct from the button that does spend a model call", async () => {
    render(<App />);
    await goTo("AI 分析");

    const quickScan = screen.getByRole("button", { name: /免 AI 快速分析/ });
    // The AI trigger appears in more than one place; none of them may be this one.
    const aiStarts = screen.getAllByRole("button", {
      name: /^(开始分析|重新分析|暂无可分析请求)/,
    });
    expect(aiStarts.length).toBeGreaterThan(0);
    expect(aiStarts).not.toContain(quickScan);
  });
});
