import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SetupGuide } from "../../src/components/SetupGuide";
import { buildSetupSteps, setupProgress, type SetupSignals } from "../../src/setupChecklist";

const cold: SetupSignals = {
  capturing: false,
  requestCount: 0,
  caInstalled: false,
  aiConfigured: false,
  sourceCount: 0,
};

function renderGuide(signals: Partial<SetupSignals> = {}) {
  const steps = buildSetupSteps({ ...cold, ...signals });
  const onRunStep = vi.fn();
  const onClose = vi.fn();
  const onDismissForever = vi.fn();
  render(
    <SetupGuide
      steps={steps}
      progress={setupProgress(steps)}
      onRunStep={onRunStep}
      onClose={onClose}
      onDismissForever={onDismissForever}
    />,
  );
  return { onRunStep, onClose, onDismissForever };
}

describe("SetupGuide", () => {
  it("renders every step with its own action", () => {
    renderGuide();
    const steps = screen.getAllByRole("listitem");
    expect(steps).toHaveLength(4);
    // Asserted against the row's text, because a title like "开始抓包" is also
    // the label of that row's own button.
    for (const [index, title] of ["开始抓包", "接入流量来源", "安装 HTTPS 证书", "配置 AI 分析"].entries()) {
      expect(steps[index]).toHaveTextContent(title);
      expect(within(steps[index]).getAllByRole("button")).toHaveLength(1);
    }
  });

  it("disables a blocked step so it cannot be run out of order", async () => {
    renderGuide();
    // The source step is blocked until capture runs; there is nothing to
    // connect to yet.
    const blocked = screen.getByRole("button", { name: /打开内嵌浏览器/ });
    expect(blocked).toBeDisabled();

    await userEvent.click(blocked);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("unblocks the source step once capture is running", () => {
    renderGuide({ capturing: true });
    expect(screen.getByRole("button", { name: /打开内嵌浏览器/ })).toBeEnabled();
  });

  it("routes each step's button to the right id", async () => {
    const { onRunStep } = renderGuide({ capturing: true });
    await userEvent.click(screen.getByRole("button", { name: /一键安装 CA/ }));
    expect(onRunStep).toHaveBeenCalledWith("certificate");
  });

  it("never offers to stop a running capture", () => {
    renderGuide({ capturing: true });
    expect(screen.queryByRole("button", { name: /停止抓包/ })).toBeNull();
    expect(screen.getByRole("button", { name: /代理设置/ })).toBeInTheDocument();
  });

  it("reports progress over required steps only", () => {
    renderGuide({ capturing: true, requestCount: 5 });
    // Certificate and AI are optional, so two of two required steps are done.
    expect(screen.getByText("2 / 2 必做步骤")).toBeInTheDocument();
    expect(screen.getByText("已经可以开始了")).toBeInTheDocument();
  });

  it("closes from the backdrop and from the dismiss action", async () => {
    const { onClose, onDismissForever } = renderGuide();
    await userEvent.click(screen.getByRole("button", { name: "不再自动显示" }));
    expect(onDismissForever).toHaveBeenCalled();

    await userEvent.click(screen.getByTitle("关闭"));
    expect(onClose).toHaveBeenCalled();
  });
});
