import { resolve } from "node:path";

export const DEFAULT_GROK_TARGET_DIRECTORY = "src-tauri/.sidecar-target";

export function resolveGrokTargetDirectory(projectRoot, environment = process.env) {
  const configured = environment.SHOWNET_GROK_TARGET_DIR?.trim();
  return resolve(projectRoot, configured || DEFAULT_GROK_TARGET_DIRECTORY);
}

export function grokBuildArtifact(targetDirectory, target, executableSuffix = "") {
  return resolve(targetDirectory, target, "release", `xai-grok-pager${executableSuffix}`);
}
