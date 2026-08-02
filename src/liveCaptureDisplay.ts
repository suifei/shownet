export const LIVE_CAPTURE_DISPLAY_PREFERENCES_KEY = "shownet.live-capture-display.v1";
export const DEFAULT_LIVE_CAPTURE_RATE_THRESHOLD = 120;
export const DEFAULT_LIVE_CAPTURE_SUSTAIN_MS = 2_000;

export type LiveCapturePauseReason = "manual" | "automatic";

export interface LiveCaptureDisplayPreferences {
  version: 1;
  autoProtection: boolean;
}

export interface LiveCaptureDisplaySnapshot {
  paused: boolean;
  syncing: boolean;
  pauseReason?: LiveCapturePauseReason;
  pendingCreated: number;
  pendingUpdated: number;
  pendingChanges: number;
  ratePerSecond: number;
  peakRatePerSecond: number;
  autoProtection: boolean;
  rateThreshold: number;
}

interface LiveCaptureDisplayOptions {
  autoProtection?: boolean;
  rateThreshold?: number;
  sustainMs?: number;
  rateWindowMs?: number;
}

export interface LiveCaptureDisplayController {
  recordCreated: (now: number) => void;
  recordUpdated: () => void;
  tick: (now: number) => LiveCaptureDisplaySnapshot;
  snapshot: (now: number) => LiveCaptureDisplaySnapshot;
  pause: (reason: LiveCapturePauseReason, now: number) => LiveCaptureDisplaySnapshot;
  startSync: (now: number) => LiveCaptureDisplaySnapshot;
  finishSync: (now: number) => LiveCaptureDisplaySnapshot;
  failSync: (now: number) => LiveCaptureDisplaySnapshot;
  setAutoProtection: (enabled: boolean, now: number) => LiveCaptureDisplaySnapshot;
  reset: (now: number) => LiveCaptureDisplaySnapshot;
}

export function parseLiveCaptureDisplayPreferences(raw: string | null | undefined): LiveCaptureDisplayPreferences {
  if (!raw) return { version: 1, autoProtection: true };
  try {
    const value = JSON.parse(raw) as Partial<LiveCaptureDisplayPreferences>;
    if (value.version !== 1 || typeof value.autoProtection !== "boolean") {
      return { version: 1, autoProtection: true };
    }
    return { version: 1, autoProtection: value.autoProtection };
  } catch {
    return { version: 1, autoProtection: true };
  }
}

export function createLiveCaptureDisplayController(options: LiveCaptureDisplayOptions = {}): LiveCaptureDisplayController {
  const rateThreshold = boundedInteger(options.rateThreshold, DEFAULT_LIVE_CAPTURE_RATE_THRESHOLD, 1, 100_000);
  const sustainMs = boundedInteger(options.sustainMs, DEFAULT_LIVE_CAPTURE_SUSTAIN_MS, 0, 60_000);
  const rateWindowMs = boundedInteger(options.rateWindowMs, 1_000, 100, 10_000);
  let autoProtection = options.autoProtection ?? true;
  let paused = false;
  let syncing = false;
  let pauseReason: LiveCapturePauseReason | undefined;
  let pendingCreated = 0;
  let pendingUpdated = 0;
  let peakRatePerSecond = 0;
  let highRateSince: number | undefined;
  let samples: number[] = [];
  let firstSample = 0;

  const currentRate = (now: number) => {
    const cutoff = now - rateWindowMs;
    while (firstSample < samples.length && samples[firstSample] < cutoff) firstSample += 1;
    if (firstSample > 2_048 && firstSample * 2 > samples.length) {
      samples = samples.slice(firstSample);
      firstSample = 0;
    }
    return Math.round(((samples.length - firstSample) * 1_000) / rateWindowMs);
  };

  const buildSnapshot = (now: number): LiveCaptureDisplaySnapshot => {
    const ratePerSecond = currentRate(now);
    peakRatePerSecond = Math.max(peakRatePerSecond, ratePerSecond);
    return {
      paused,
      syncing,
      pauseReason,
      pendingCreated,
      pendingUpdated,
      pendingChanges: pendingCreated + pendingUpdated,
      ratePerSecond,
      peakRatePerSecond,
      autoProtection,
      rateThreshold,
    };
  };

  return {
    recordCreated(now) {
      samples.push(now);
      if (paused) pendingCreated += 1;
    },
    recordUpdated() {
      if (paused) pendingUpdated += 1;
    },
    tick(now) {
      const rate = currentRate(now);
      peakRatePerSecond = Math.max(peakRatePerSecond, rate);
      if (!paused && autoProtection && rate >= rateThreshold) {
        highRateSince ??= now;
        if (now - highRateSince >= sustainMs) {
          paused = true;
          pauseReason = "automatic";
          syncing = false;
          highRateSince = undefined;
        }
      } else if (!paused) {
        highRateSince = undefined;
      }
      return buildSnapshot(now);
    },
    snapshot: buildSnapshot,
    pause(reason, now) {
      paused = true;
      syncing = false;
      pauseReason = reason;
      highRateSince = undefined;
      return buildSnapshot(now);
    },
    startSync(now) {
      if (paused) syncing = true;
      return buildSnapshot(now);
    },
    finishSync(now) {
      paused = false;
      syncing = false;
      pauseReason = undefined;
      pendingCreated = 0;
      pendingUpdated = 0;
      highRateSince = undefined;
      return buildSnapshot(now);
    },
    failSync(now) {
      syncing = false;
      return buildSnapshot(now);
    },
    setAutoProtection(enabled, now) {
      autoProtection = enabled;
      if (!enabled) highRateSince = undefined;
      return buildSnapshot(now);
    },
    reset(now) {
      paused = false;
      syncing = false;
      pauseReason = undefined;
      pendingCreated = 0;
      pendingUpdated = 0;
      peakRatePerSecond = 0;
      highRateSince = undefined;
      samples = [];
      firstSample = 0;
      return buildSnapshot(now);
    },
  };
}

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number) {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(maximum, Math.max(minimum, Math.round(value as number)));
}
