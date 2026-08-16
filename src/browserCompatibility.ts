// Transport capture must preserve the page's native JavaScript environment.
// Deep runtime hooks are an explicit analysis mode because they replace browser
// APIs used by authentication, device-risk and payment flows.
export const DEFAULT_PAGE_HOOKS_ENABLED = false;
