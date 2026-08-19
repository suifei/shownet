/**
 * What the ClientHello dropdown should show. A missing `presetId` must not be
 * displayed as chrome150 — that was the silent “auto Chrome 150” after capture.
 */
export function displayedClientHelloPresetId(
  status: { presetId?: string; profile?: string } | null | undefined,
) {
  if (status?.presetId) return status.presetId;
  if (status?.profile) return status.profile;
  return "";
}
