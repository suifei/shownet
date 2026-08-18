import { CircleAlert, X } from "lucide-react";
import { useCallback, useRef, useState, type ReactNode } from "react";

import { t } from "../i18n.ts";

/**
 * In-app confirmation, replacing `window.confirm`.
 *
 * The native dialog rendered in the OS chrome with no styling control, which
 * matters most exactly where it was used: the rule-enable prompts spell out
 * what a rule will do to live traffic and to credentials, and that copy has to
 * read like part of the app rather than a browser alert.
 */

export interface ConfirmOptions {
  title: string;
  /** The consequence, spelled out. Shown under the title. */
  detail?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** `danger` styles the confirm button as destructive. */
  tone?: "default" | "danger";
}

interface PendingConfirm extends ConfirmOptions {
  resolve: (confirmed: boolean) => void;
}

export interface ConfirmController {
  /** Resolves true when the user confirms, false on cancel, Escape or backdrop. */
  confirm: (options: ConfirmOptions) => Promise<boolean>;
  /** Render this somewhere inside the component that owns the controller. */
  dialog: ReactNode;
}

export function useConfirm(): ConfirmController {
  const [pending, setPending] = useState<PendingConfirm>();
  // A second confirm opening while one is pending would strand the first
  // promise forever; settle it as a cancel instead.
  const pendingRef = useRef<PendingConfirm | undefined>(undefined);

  const confirm = useCallback((options: ConfirmOptions) => new Promise<boolean>((resolve) => {
    pendingRef.current?.resolve(false);
    const next = { ...options, resolve };
    pendingRef.current = next;
    setPending(next);
  }), []);

  const settle = useCallback((confirmed: boolean) => {
    pendingRef.current?.resolve(confirmed);
    pendingRef.current = undefined;
    setPending(undefined);
  }, []);

  const dialog = pending ? (
    <div className="modal-backdrop" onMouseDown={() => settle(false)}>
      <section
        className={`confirm-dialog ${pending.tone === "danger" ? "is-danger" : ""}`}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={(event) => { if (event.key === "Escape") settle(false); }}
      >
        <header>
          <span className="confirm-dialog__icon"><CircleAlert size={18} /></span>
          <div>
            <h2 id="confirm-dialog-title">{pending.title}</h2>
            {pending.detail && <p>{pending.detail}</p>}
          </div>
          <button className="icon-button" onClick={() => settle(false)} title={t("common.close")}><X size={17} /></button>
        </header>
        <footer>
          <button className="secondary-button" onClick={() => settle(false)}>{pending.cancelLabel ?? t("common.cancel")}</button>
          <button
            autoFocus
            className={pending.tone === "danger" ? "primary-button is-danger" : "primary-button"}
            onClick={() => settle(true)}
          >
            {pending.confirmLabel ?? t("common.confirm")}
          </button>
        </footer>
      </section>
    </div>
  ) : null;

  return { confirm, dialog };
}
