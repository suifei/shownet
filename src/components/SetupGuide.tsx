import { Check, ChevronRight, Lock, Sparkles, X } from "lucide-react";
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
            <h2 id="setup-guide-title">{progress.ready ? "已经可以开始了" : "三分钟跑通第一条流量"}</h2>
            <p>
              {progress.ready
                ? "抓包链路已就绪，剩下的是可选增强。"
                : "按顺序完成下面两步就能看到流量，证书和 AI 可以之后再说。"}
            </p>
          </div>
          <button className="icon-button" onClick={onClose} title="关闭"><X size={18} /></button>
        </header>

        <div className="setup-guide__progress" role="img" aria-label={`必做步骤完成 ${progress.done} / ${progress.total}`}>
          <div className="setup-guide__progress-bar"><i style={{ width: `${percent}%` }} /></div>
          <span>{progress.done} / {progress.total} 必做步骤</span>
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
                  {step.optional && <em className="setup-step__tag">可选</em>}
                </strong>
                <small>{step.state === "done" ? step.summary : step.hint}</small>
              </span>
              <button
                className={step.id === progress.next?.id ? "primary-button" : "secondary-button"}
                onClick={() => onRunStep(step.id)}
                disabled={step.state === "blocked"}
                title={step.state === "blocked" ? "先完成上一步" : step.actionLabel}
              >
                {step.actionLabel}
                <ChevronRight size={14} />
              </button>
            </li>
          ))}
        </ol>

        <footer className="setup-guide__footer">
          <span><Sparkles size={14} />随时按 ⌘K 搜索任何功能</span>
          <span className="dialog-actions">
            <button className="secondary-button" onClick={onDismissForever}>不再自动显示</button>
            <button className="primary-button" onClick={onClose}>知道了</button>
          </span>
        </footer>
      </section>
    </div>
  );
}
