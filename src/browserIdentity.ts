import type { ProxyBrowserStatus } from "./types";

export type BrowserIdentityStatus = Pick<
  ProxyBrowserStatus,
  "browserPresetFamily" | "browserPresetMajorVersion" | "browserUserAgentMajorVersion" | "honestUserAgent"
>;

/**
 * Keep CDP's high-entropy browser identity aligned when the launch UA major is
 * deliberately different from the installed Chrome binary. The launch flag
 * covers every request; this metadata covers navigator.userAgentData and the
 * attached page's client hints.
 */
export function userAgentMetadataFor(status: BrowserIdentityStatus) {
  const major = status.browserUserAgentMajorVersion;
  const family = status.browserPresetFamily;
  if (
    (family !== "chrome" && family !== "edge")
    || status.browserPresetMajorVersion <= 0
    || major <= 0
  ) return undefined;
  const product = family === "edge" ? "Microsoft Edge" : "Google Chrome";
  return {
    brands: [
      { brand: "Not/A Brand", version: "99" },
      { brand: "Chromium", version: String(major) },
      { brand: product, version: String(major) },
    ],
    fullVersionList: [
      { brand: "Not/A Brand", version: "99.0.0.0" },
      { brand: "Chromium", version: `${major}.0.0.0` },
      { brand: product, version: `${major}.0.0.0` },
    ],
    platform: /Mac/i.test(status.honestUserAgent)
      ? "macOS"
      : /Win/i.test(status.honestUserAgent)
        ? "Windows"
        : "Linux",
    platformVersion: "",
    architecture: /Mac/i.test(status.honestUserAgent) ? "" : "x86",
    model: "",
    mobile: false,
  };
}
