import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import App from "../../src/App";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

const goTo = (label: string) => userEvent.click(screen.getByRole("button", { name: new RegExp(`^${label}$`) }));

function modeRail() {
  return screen.getByRole("heading", { name: "分析模式" }).closest(".analysis-config__section") as HTMLElement;
}

function selectedMode() {
  return within(modeRail())
    .getAllByRole("button")
    .find((button) => button.className.includes("is-active"))
    ?.textContent ?? "";
}

/** The left rail of the Agent 编排 tab; the plan heading repeats the same names. */
function workflowList() {
  return screen.getByRole("complementary", { name: "分析流程" });
}

async function openWorkflowTab() {
  await goTo("能力");
  await userEvent.click(screen.getByRole("button", { name: /Agent 编排/ }));
}

describe("analysis mode is shared between the two views", () => {
  it("carries a mode picked in AI 分析 over to Skill 编排", async () => {
    render(<App />);
    await goTo("AI 分析");
    await userEvent.click(within(modeRail()).getByRole("button", { name: /性能分析/ }));

    await openWorkflowTab();
    expect(screen.getByRole("heading", { name: "性能分析" })).toBeInTheDocument();
  });

  it("carries a mode picked in Skill 编排 back to AI 分析", async () => {
    render(<App />);
    await openWorkflowTab();
    await userEvent.click(within(workflowList()).getByRole("button", { name: /JS 加密逆向/ }));

    await goTo("AI 分析");
    expect(selectedMode()).toContain("JS 加密逆向");
  });

  it("keeps the selection when the view unmounts and comes back", async () => {
    // AnalysisView is conditionally rendered, so its local state used to be
    // discarded on every navigation.
    render(<App />);
    await goTo("AI 分析");
    await userEvent.click(within(modeRail()).getByRole("button", { name: /安全审计/ }));

    await goTo("流量");
    await goTo("AI 分析");
    expect(selectedMode()).toContain("安全审计");
  });

  it("does not let the restored report overwrite the picked mode", async () => {
    // The last report is restored on mount as a convenience; adopting its mode
    // would silently undo a choice made in the other view.
    render(<App />);
    await goTo("AI 分析");
    await userEvent.click(within(modeRail()).getByRole("button", { name: /JS 加密逆向/ }));

    await goTo("流量");
    await goTo("AI 分析");
    expect(selectedMode()).toContain("JS 加密逆向");
  });

  it("titles the report with the mode that produced it, not the picker", async () => {
    render(<App />);
    await goTo("AI 分析");
    // The preview session restores an API 逆向 report.
    expect(screen.getByRole("heading", { name: "API 逆向报告" })).toBeInTheDocument();

    await userEvent.click(within(modeRail()).getByRole("button", { name: /安全审计/ }));
    expect(screen.getByRole("heading", { name: "API 逆向报告" })).toBeInTheDocument();
  });

  it("drops the skill count when the plan no longer describes the report", async () => {
    render(<App />);
    await goTo("AI 分析");
    const meta = () => screen.getByText(/条关键请求/);
    expect(meta()).toHaveTextContent("Skills");

    await userEvent.click(within(modeRail()).getByRole("button", { name: /性能分析/ }));
    expect(meta()).not.toHaveTextContent("Skills");
  });
});

describe("analysis mode naming", () => {
  it("uses the same name in both views", async () => {
    render(<App />);
    await goTo("AI 分析");
    const railNames = within(modeRail())
      .getAllByRole("button")
      .map((button) => button.querySelector("strong")?.textContent ?? "");

    await openWorkflowTab();
    const list = workflowList();
    for (const name of railNames.filter(Boolean)) {
      expect(within(list).getByText(name)).toBeInTheDocument();
    }
  });
});
