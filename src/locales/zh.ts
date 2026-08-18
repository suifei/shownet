import type { LanguagePack } from "../i18nTypes";
import { advancedCatalogZh } from "./parts/advancedCatalog.ts";
import { analysisZh } from "./parts/analysis.ts";
import { chromeZh } from "./parts/chrome.ts";
import { commandsZh } from "./parts/commands.ts";
import { commonZh } from "./parts/common.ts";
import { dialogsZh } from "./parts/dialogs.ts";
import { settingsZh } from "./parts/settings.ts";
import { shellZh } from "./parts/shell.ts";
import { skillsZh } from "./parts/skills.ts";
import { sourceZh } from "./parts/source.ts";
import { trafficZh } from "./parts/traffic.ts";
import { viewsZh } from "./parts/views.ts";

export const ZH_MESSAGES = {
  ...chromeZh,
  ...commonZh,
  ...sourceZh,
  ...shellZh,
  ...commandsZh,
  ...settingsZh,
  ...trafficZh,
  ...dialogsZh,
  ...analysisZh,
  ...viewsZh,
  ...advancedCatalogZh,
  ...skillsZh,
} as const;

export type MessageKey = keyof typeof ZH_MESSAGES;

export const ZH_PACK: LanguagePack<MessageKey> = {
  id: "zh",
  tags: ["zh", "zh-CN", "zh-Hans", "zh-SG"],
  nativeName: "简体中文",
  intlLocale: "zh-CN",
  messages: ZH_MESSAGES,
};
