export function defaultCaptureSessionName(now = new Date()) {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `抓包 ${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}`;
}
