const PAGE_HOOK_EXCLUDED_HOST_PATTERN = /(^|\.)12306\.cn$/i;

/**
 * Page hooks are useful for ordinary traffic but can change an authentication
 * site's crypto/cookie execution. MITM still captures those requests, so the
 * sensitive-site path should keep transport capture while leaving page APIs
 * native.
 */
export function pageHooksAllowedForUrl(url: string): boolean {
  try {
    return !PAGE_HOOK_EXCLUDED_HOST_PATTERN.test(new URL(url).hostname.replace(/\.$/, ""));
  } catch {
    return true;
  }
}

export function pageHookGuardSource(): string {
  return `if (!/${PAGE_HOOK_EXCLUDED_HOST_PATTERN.source}/i.test(location.hostname)) {`;
}
