/**
 * POSIX single-quoting for generated shell commands.
 *
 * This was implemented twice — once for the Lab's cURL export and once for the
 * request-code templates — and the copies drifted. The second one replaced `'`
 * with `"'"'` instead of `'"'"'`, dropping the leading quote, so any URL,
 * header or body containing an apostrophe produced a command that would not
 * run. Both callers now share this one.
 */
export function shellQuote(value: string): string {
  // Close the quote, emit a literal ', reopen. `'` → `'\''` in the shell's eyes.
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}
