/** How a host keystroke should reach the CDP screencast. */

export function isImeReservedShortcut(key: string, metaKey: boolean, ctrlKey: boolean) {
  if (!(metaKey || ctrlKey)) return false;
  return ["c", "x", "v", "a", "z", "l", "r"].includes(key.toLowerCase());
}

/**
 * Raw `Input.dispatchKeyEvent` with `text: event.key` is the pre-fix English-only
 * path. Composition and printable keys on the IME surface must not take it.
 */
export function shouldForwardRawKeyToCdp(input: {
  composing: boolean;
  key: string;
  metaKey: boolean;
  ctrlKey: boolean;
  imeSurfaceFocused: boolean;
}) {
  if (input.composing) return false;
  if (isImeReservedShortcut(input.key, input.metaKey, input.ctrlKey)) return false;
  if (input.imeSurfaceFocused && input.key.length === 1 && !input.metaKey && !input.ctrlKey) {
    return false;
  }
  return true;
}

export function cdpInsertTextPayload(text: string) {
  if (!text) return null;
  return { method: "Input.insertText" as const, params: { text } };
}
