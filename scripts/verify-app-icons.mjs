import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateAppIconSet } from "./app-icon-tools.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const result = await validateAppIconSet(root);

console.log(
  `Verified ${result.files.length} ShowNet icon files, ${result.ico.entries.length} ICO sizes, and ${result.icns.entries.length} ICNS entries.`,
);
