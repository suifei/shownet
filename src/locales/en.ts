import type { LanguagePack } from "../i18nTypes";
import { advancedCatalogEn } from "./parts/advancedCatalog.ts";
import { analysisEn } from "./parts/analysis.ts";
import { chromeEn } from "./parts/chrome.ts";
import { commandsEn } from "./parts/commands.ts";
import { commonEn } from "./parts/common.ts";
import { dialogsEn } from "./parts/dialogs.ts";
import { settingsEn } from "./parts/settings.ts";
import { shellEn } from "./parts/shell.ts";
import { skillsEn } from "./parts/skills.ts";
import { sourceEn } from "./parts/source.ts";
import { trafficEn } from "./parts/traffic.ts";
import { viewsEn } from "./parts/views.ts";
import type { MessageKey } from "./zh.ts";

export const EN_MESSAGES: Record<MessageKey, string> = {
  ...chromeEn,
  ...commonEn,
  ...sourceEn,
  ...shellEn,
  ...commandsEn,
  ...settingsEn,
  ...trafficEn,
  ...dialogsEn,
  ...analysisEn,
  ...viewsEn,
  ...advancedCatalogEn,
  ...skillsEn,
};

export const EN_PACK: LanguagePack<MessageKey> = {
  id: "en",
  tags: ["en", "en-US", "en-GB", "en-AU"],
  nativeName: "English",
  intlLocale: "en-US",
  messages: EN_MESSAGES,
};
