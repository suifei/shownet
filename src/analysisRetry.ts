import type { AiProviderSettings } from "./types";

export type AnalysisRetryProvider = AiProviderSettings["provider"];

export interface AnalysisRetryDraft {
  prompt: string;
  provider: AnalysisRetryProvider;
  model: string;
  baseUrl: string;
}

export const LOCAL_AI_BASE_URL = "http://127.0.0.1:11434/v1";

export function initialAnalysisRetryDraft(
  settings: Pick<AiProviderSettings, "provider" | "model" | "baseUrl">,
  prompt = "",
): AnalysisRetryDraft {
  return {
    prompt,
    provider: settings.provider,
    model: settings.model,
    baseUrl: settings.baseUrl,
  };
}

/** Switch the in-flight retry to a local OpenAI-compatible endpoint without touching saved settings. */
export function continueOnLocalModel(draft: AnalysisRetryDraft, model = draft.model): AnalysisRetryDraft {
  return {
    ...draft,
    provider: "local",
    model: model.trim() || draft.model,
    baseUrl: draft.provider === "local" && draft.baseUrl.trim() ? draft.baseUrl : LOCAL_AI_BASE_URL,
  };
}

export function analysisRetryInvokeInput(
  base: {
    sessionId: string;
    mode: string;
    includeStatic: boolean;
    manualRequestIds: string[];
    includeAnnotations: boolean;
  },
  draft: AnalysisRetryDraft,
) {
  const prompt = draft.prompt.trim();
  const model = draft.model.trim();
  const baseUrl = draft.baseUrl.trim();
  return {
    ...base,
    promptOverride: prompt || undefined,
    provider: draft.provider,
    model: model || undefined,
    baseUrl: baseUrl || undefined,
  };
}
