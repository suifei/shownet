import { Check, Copy, ExternalLink, Github, Scale, X } from "lucide-react";
import { useState } from "react";

import shownetAppIcon from "../assets/shownet-app-icon.png";
import { t } from "../i18n.ts";
import type { RuntimeStatus } from "../types";

interface AboutDialogProps {
  runtime: RuntimeStatus;
  /** Whether the app is running inside the desktop shell rather than a browser preview. */
  native: boolean;
  onClose: () => void;
  onCopy: (value: string, label: string) => void;
  onOpenExternal: (url: string) => void;
}

const PROJECT_URL = "https://github.com/suifei/shownet";
const LICENSE = "GPL-3.0-only";

function platformLabel(platform: string) {
  if (platform === "macos") return "macOS";
  if (platform === "windows") return "Windows";
  if (platform === "linux") return "Linux";
  return platform || t("common.unknownPlatform");
}

export function AboutDialog({ runtime, native, onClose, onCopy, onOpenExternal }: AboutDialogProps) {
  const [copied, setCopied] = useState(false);

  // What a bug report needs, in one line the user can paste.
  const diagnostics = [
    `ShowNet ${runtime.appVersion}`,
    platformLabel(runtime.platform),
    native ? t("common.desktopEdition") : t("common.browserPreview"),
    `${t("about.proxy")} ${runtime.listenHost}:${runtime.proxyPort}`,
    `CA ${runtime.caInstalled ? t("common.trusted") : t("common.notInstalled")}`,
  ].join(" · ");

  const copyDiagnostics = () => {
    onCopy(diagnostics, t("about.diagnosticsLabel"));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="about-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="about-dialog-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="icon-button about-dialog__close" onClick={onClose} title={t("common.close")}><X size={18} /></button>

        <header className="about-dialog__identity">
          <img src={shownetAppIcon} alt="" aria-hidden="true" />
          <h2 id="about-dialog-title">ShowNet</h2>
          <p className="about-dialog__tagline">{t("about.tagline")}</p>
          <p className="about-dialog__version">
            {t("about.version", { version: runtime.appVersion })}
            <span aria-hidden="true"> · </span>
            {platformLabel(runtime.platform)}
            {!native && <em className="about-dialog__preview">{t("common.browserPreview")}</em>}
          </p>
        </header>

        <dl className="about-dialog__facts">
          <div>
            <dt>{t("about.proxy")}</dt>
            <dd><code>{runtime.listenHost}:{runtime.proxyPort}</code></dd>
          </div>
          <div>
            <dt>{t("about.certificate")}</dt>
            <dd className={runtime.caInstalled ? "is-ok" : "is-pending"}>
              {runtime.caInstalled ? t("about.caInStore") : t("about.caMissing")}
            </dd>
          </div>
          <div>
            <dt>{t("about.license")}</dt>
            <dd><Scale size={13} />{LICENSE}</dd>
          </div>
        </dl>

        <footer className="about-dialog__footer">
          <span>{t("about.feedback")}</span>
          <div className="about-dialog__actions">
            <button className="secondary-button" onClick={() => onOpenExternal(PROJECT_URL)}>
              <Github size={14} />{t("about.homepage")}<ExternalLink size={12} />
            </button>
            <button className="primary-button" onClick={copyDiagnostics}>
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? t("common.copied") : t("about.copyDiagnostics")}
            </button>
          </div>
        </footer>
      </section>
    </div>
  );
}
