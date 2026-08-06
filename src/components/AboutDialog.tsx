import { Check, Copy, ExternalLink, Github, Scale, X } from "lucide-react";
import { useState } from "react";

import shownetAppIcon from "../assets/shownet-app-icon.png";
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
  return platform || "未知平台";
}

export function AboutDialog({ runtime, native, onClose, onCopy, onOpenExternal }: AboutDialogProps) {
  const [copied, setCopied] = useState(false);

  // What a bug report needs, in one line the user can paste.
  const diagnostics = [
    `ShowNet ${runtime.appVersion}`,
    platformLabel(runtime.platform),
    native ? "桌面版" : "浏览器预览",
    `代理 ${runtime.listenHost}:${runtime.proxyPort}`,
    `CA ${runtime.caInstalled ? "已信任" : "未安装"}`,
  ].join(" · ");

  const copyDiagnostics = () => {
    onCopy(diagnostics, "版本信息");
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
        <button className="icon-button about-dialog__close" onClick={onClose} title="关闭"><X size={18} /></button>

        <header className="about-dialog__identity">
          <img src={shownetAppIcon} alt="" aria-hidden="true" />
          <h2 id="about-dialog-title">ShowNet</h2>
          <p className="about-dialog__tagline">AI 原生抓包 · 自动部署证书 · 自动协议逆向</p>
          <p className="about-dialog__version">
            版本 {runtime.appVersion}
            <span aria-hidden="true"> · </span>
            {platformLabel(runtime.platform)}
            {!native && <em className="about-dialog__preview">浏览器预览</em>}
          </p>
        </header>

        <dl className="about-dialog__facts">
          <div>
            <dt>代理地址</dt>
            <dd><code>{runtime.listenHost}:{runtime.proxyPort}</code></dd>
          </div>
          <div>
            <dt>HTTPS 证书</dt>
            <dd className={runtime.caInstalled ? "is-ok" : "is-pending"}>
              {runtime.caInstalled ? "已写入系统信任库" : "尚未安装"}
            </dd>
          </div>
          <div>
            <dt>开源许可</dt>
            <dd><Scale size={13} />{LICENSE}</dd>
          </div>
        </dl>

        <footer className="about-dialog__footer">
          <span>反馈问题时附上这一行，能省去大半来回。</span>
          <div className="about-dialog__actions">
            <button className="secondary-button" onClick={() => onOpenExternal(PROJECT_URL)}>
              <Github size={14} />项目主页<ExternalLink size={12} />
            </button>
            <button className="primary-button" onClick={copyDiagnostics}>
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? "已复制" : "复制版本信息"}
            </button>
          </div>
        </footer>
      </section>
    </div>
  );
}
