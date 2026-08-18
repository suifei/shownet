import { t } from "./i18n.ts";

export function defaultCaptureSessionName(now = new Date()) {
  const pad = (value: number) => String(value).padStart(2, "0");
  const stamp = `${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}`;
  return t("shell.sessionDefaultName", { stamp });
}
