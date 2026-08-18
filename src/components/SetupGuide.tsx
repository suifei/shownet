import { Check, ChevronRight, Lock, Sparkles, X } from "lucide-react";
import { t } from "../i18n.ts";
import type { SetupStep, SetupProgress, SetupStepId } from "../setupChecklist";

interface SetupGuideProps {
  steps: SetupStep[];
  progress: SetupProgress;
  onRunStep: (id: SetupStepId) => void;
  onClose: () => void;
  /** Suppresses the auto-open on future launches. */
  onDismissForever: () => void;
}

/**
 * The one screen that answers "what do I still need to do".
 *
 * Everything here is reachable elsewhere; the point is that a beginner does not
 * have to know it is spread across the topbar, a dialog and two settings tabs.
 */
export function SetupGuide({ steps, progress, onRunStep, onClose, onDismissForever }: SetupGuideProps) {
  const percent = progress.total ? Math.round((progress.done / progress.total) * 100) : 100;

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="setup-guide"
        role="dialog"
        aria-modal="true"
        aria-labelledby="setup-guide-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="setup-guide__header">
          <div>
            <span className="section-kicker">GET STARTED</span>
            <h2 id="setup-guide-title">{progress.ready ? t("setup.readyTitle") : t("setup.startTitle")}</h2>
            <p>
              {progress.ready ? t("setup.readyBody") : t("setup.startBody")}
            </p>
          </div>
          <button className="icon-button" onClick={onClose} title={t("common.close")}><X size={18} /></button>
        </header>

        <div className="setup-guide__progress" role="img" aria-label={t("setup.progressAria", { done: progress.done, total: progress.total })}>
          <div className="setup-guide__progress-bar"><i style={{ width: `${percent}%` }} /></div>
          <span>{t("setup.progress", { done: progress.done, total: progress.total })}</span>
        </div>

        <ol className="setup-guide__steps">
          {steps.map((step, index) => (
            <li key={step.id} className={`setup-step is-${step.state} ${step.optional ? "is-optional" : ""}`}>
              <span className="setup-step__marker" aria-hidden="true">
                {step.state === "done" ? <Check size={14} /> : step.state === "blocked" ? <Lock size={12} /> : index + 1}
              </span>
              <span className="setup-step__body">
                <strong>
                  {step.title}
                  {step.optional && <em className="setup-step__tag">{t("common.optional")}</em>}
                </strong>
                <small>{step.state === "done" ? step.summary : step.hint}</small>
              </span>
              <button
                className={step.id === progress.next?.id ? "primary-button" : "secondary-button"}
                onClick={() => onRunStep(step.id)}
                disabled={step.state === "blocked"}
                title={step.state === "blocked" ? t("setup.blocked") : step.actionLabel}
              >
                {step.actionLabel}
                <ChevronRight size={14} />
              </button>
            </li>
          ))}
        </ol>

        <footer className="setup-guide__footer">
          <span><Sparkles size={14} />{t("setup.hint")}</span>
          <span className="dialog-actions">
            <button className="secondary-button" onClick={onDismissForever}>{t("setup.dismiss")}</button>
            <button className="primary-button" onClick={onClose}>{t("common.knowIt")}</button>
          </span>
        </footer>
      </section>
    </div>
  );
}
