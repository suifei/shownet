export interface CaptureSessionTarget {
  id: string;
}

export interface CaptureSessionResolution {
  sessionId: string;
  created: boolean;
}

export async function ensureCaptureSession(
  activeSessionId: string,
  createSession: () => Promise<CaptureSessionTarget | null>,
): Promise<CaptureSessionResolution | null> {
  if (activeSessionId) return { sessionId: activeSessionId, created: false };
  const created = await createSession();
  return created?.id ? { sessionId: created.id, created: true } : null;
}
