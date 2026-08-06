import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import App from "../../src/App";
import { useConfirm } from "../../src/components/ConfirmDialog";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

/** Minimal host that exercises the promise contract of useConfirm. */
function ConfirmHarness({ onResult }: { onResult: (value: boolean) => void }) {
  const { confirm, dialog } = useConfirm();
  return (
    <>
      <button onClick={() => void confirm({ title: "删除这个集合？", detail: "请求会保留。", confirmLabel: "删除", tone: "danger" }).then(onResult)}>
        first
      </button>
      <button onClick={() => void confirm({ title: "第二个确认" }).then(onResult)}>second</button>
      {dialog}
    </>
  );
}

describe("useConfirm", () => {
  it("resolves true only when the user confirms", async () => {
    const onResult = vi.fn();
    render(<ConfirmHarness onResult={onResult} />);

    await userEvent.click(screen.getByText("first"));
    expect(screen.getByRole("alertdialog")).toHaveTextContent("删除这个集合？");
    expect(screen.getByRole("alertdialog")).toHaveTextContent("请求会保留。");

    await userEvent.click(screen.getByRole("button", { name: "删除" }));
    expect(onResult).toHaveBeenCalledWith(true);
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("resolves false on cancel", async () => {
    const onResult = vi.fn();
    render(<ConfirmHarness onResult={onResult} />);
    await userEvent.click(screen.getByText("first"));
    await userEvent.click(screen.getByRole("button", { name: "取消" }));
    expect(onResult).toHaveBeenCalledWith(false);
  });

  it("resolves false when dismissed by the backdrop", async () => {
    const onResult = vi.fn();
    const { container } = render(<ConfirmHarness onResult={onResult} />);
    await userEvent.click(screen.getByText("first"));

    const backdrop = container.querySelector(".modal-backdrop");
    expect(backdrop).not.toBeNull();
    await userEvent.click(backdrop as Element);
    expect(onResult).toHaveBeenCalledWith(false);
  });

  it("never strands the first promise when a second confirm opens", async () => {
    // Without settling the pending one, the first caller would await forever.
    const onResult = vi.fn();
    render(<ConfirmHarness onResult={onResult} />);

    await userEvent.click(screen.getByText("first"));
    await userEvent.click(screen.getByText("second"));

    expect(onResult).toHaveBeenCalledWith(false);
    expect(screen.getByRole("alertdialog")).toHaveTextContent("第二个确认");
  });

  it("marks a destructive confirm so it does not read like a neutral prompt", async () => {
    render(<ConfirmHarness onResult={vi.fn()} />);
    await userEvent.click(screen.getByText("first"));
    expect(screen.getByRole("alertdialog")).toHaveClass("is-danger");
  });
});

describe("traffic selection bar", () => {
  async function selectFirstRow() {
    render(<App />);
    const rows = screen.getAllByRole("row").filter((row) => row.getAttribute("aria-selected") !== null);
    await userEvent.click(rows[0]);
    return screen.getByRole("toolbar", { name: "选中请求操作" });
  }

  it("appears only once something is selected", async () => {
    render(<App />);
    expect(screen.queryByRole("toolbar", { name: "选中请求操作" })).toBeNull();
  });

  it("labels its actions with text rather than tooltips alone", async () => {
    const bar = await selectFirstRow();
    for (const label of ["分析选中", "重放", "改写与生成代码", "对比", "更多"]) {
      expect(within(bar).getByRole("button", { name: new RegExp(label) })).toBeInTheDocument();
    }
  });

  it("disables the actions whose selection count is not met, and says what they need", async () => {
    const bar = await selectFirstRow();
    const diff = within(bar).getByRole("button", { name: /对比/ });
    expect(diff).toBeDisabled();
    expect(diff).toHaveAttribute("title", "请选择两条请求");

    // One row is selected, so the single-request action is available.
    expect(within(bar).getByRole("button", { name: /改写与生成代码/ })).toBeEnabled();
  });

  it("distinguishes selection-scoped analysis from the session-wide button", async () => {
    const bar = await selectFirstRow();
    expect(within(bar).getByRole("button", { name: /分析选中/ })).toBeInTheDocument();
    // The summary strip keeps its own, differently named button.
    expect(screen.getByRole("button", { name: "分析整个会话" })).toBeInTheDocument();
  });

  it("keeps low-frequency actions behind 更多 until asked", async () => {
    const bar = await selectFirstRow();
    expect(screen.queryByRole("menu", { name: "更多选中操作" })).toBeNull();

    await userEvent.click(within(bar).getByRole("button", { name: /更多/ }));
    const menu = screen.getByRole("menu", { name: "更多选中操作" });
    for (const label of ["复制 URL", "归档到请求集合", "导出证据摘要"]) {
      expect(within(menu).getByRole("menuitem", { name: new RegExp(label) })).toBeInTheDocument();
    }
  });

  it("clears the selection and hides itself", async () => {
    const bar = await selectFirstRow();
    await userEvent.click(within(bar).getByRole("button", { name: "清除选择" }));
    expect(screen.queryByRole("toolbar", { name: "选中请求操作" })).toBeNull();
  });
});
