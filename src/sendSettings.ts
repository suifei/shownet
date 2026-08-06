/**
 * Descriptions for the send options that both 请求重放 and 请求构建 expose.
 *
 * They were declared separately, so the same switch explained itself
 * differently in the two places — most importantly 验证 TLS, which carried the
 * "only for authorized testing" warning in the replay panel and a bare
 * "默认开启" in the lab, where turning it off is exactly as risky.
 */

export interface SendSettingCopy {
  label: string;
  detail: string;
}

export const SEND_SETTINGS: Record<"followRedirects" | "verifyTls" | "useUpstreamProxy", SendSettingCopy> = {
  followRedirects: { label: "跟随重定向", detail: "最多 10 次" },
  verifyTls: { label: "验证 TLS", detail: "关闭仅用于授权测试" },
  useUpstreamProxy: { label: "使用上游代理", detail: "沿用设置中的出口代理" },
};
