import { Braces, Globe2 as Browser, Laptop, Radio, Route, Terminal, Wifi } from "lucide-react";

import type { SourceType } from "./types.ts";

/**
 * Glyph for each traffic source. Declared once: App and TrafficView each held
 * an identical copy, so adding a source meant remembering both.
 */
export const sourceIcons: Record<SourceType, typeof Browser> = {
  browser: Browser,
  desktop: Laptop,
  terminal: Terminal,
  script: Braces,
  mobile: Wifi,
  iot: Radio,
  reverse: Route,
};
