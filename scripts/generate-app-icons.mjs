import { copyFile, cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  APP_ICON_SOURCE_FILES,
  IOS_PNG_SIZES,
  augmentIco,
  flattenPng,
  validateAppIconSet,
  validateAppIconSources,
  validateGeneratedIconDirectory,
} from "./app-icon-tools.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const brandDir = join(root, "docs", "assets", "brand");
const manifest = join(brandDir, "app-icon-manifest.json");
const iconDir = join(root, "src-tauri", "icons");
const tauri = join(root, "node_modules", ".bin", "tauri");

await stat(tauri);
await validateAppIconSources(brandDir);

const stagingRoot = await mkdtemp(join(tmpdir(), "shownet-icons-"));
const stagedIconDir = join(stagingRoot, "icons");
const customPngDir = join(stagingRoot, "custom-png");
const hdpiSquareDir = join(stagingRoot, "android-hdpi-square");
const hdpiRoundDir = join(stagingRoot, "android-hdpi-round");

try {
  runTauriIcon([manifest, "--output", stagedIconDir]);
  runTauriIcon([
    join(brandDir, APP_ICON_SOURCE_FILES.master),
    "--output",
    customPngDir,
    "--png",
    "20",
  ]);

  // Tauri CLI 2.11.4 emits 49px legacy hdpi launchers; Android requires 72px.
  runTauriIcon([
    join(stagedIconDir, "android/mipmap-xhdpi/ic_launcher.png"),
    "--output",
    hdpiSquareDir,
    "--png",
    "72",
  ]);
  runTauriIcon([
    join(stagedIconDir, "android/mipmap-xhdpi/ic_launcher_round.png"),
    "--output",
    hdpiRoundDir,
    "--png",
    "72",
  ]);
  await copyFile(
    join(hdpiSquareDir, "72x72.png"),
    join(stagedIconDir, "android/mipmap-hdpi/ic_launcher.png"),
  );
  await copyFile(
    join(hdpiRoundDir, "72x72.png"),
    join(stagedIconDir, "android/mipmap-hdpi/ic_launcher_round.png"),
  );

  for (const file of IOS_PNG_SIZES.keys()) {
    const path = join(stagedIconDir, file);
    await writeFile(path, flattenPng(await readFile(path), [0x10, 0x13, 0x15], file));
  }

  const icoPath = join(stagedIconDir, "icon.ico");
  const enhancedIco = augmentIco(
    await readFile(icoPath),
    [
      await readFile(join(customPngDir, "20x20.png")),
      await readFile(join(stagedIconDir, "128x128.png")),
    ],
  );
  await writeFile(icoPath, enhancedIco);
  await validateGeneratedIconDirectory(stagedIconDir);

  await rm(iconDir, { recursive: true, force: true });
  await cp(stagedIconDir, iconDir, { recursive: true });
  await removeFinderMetadata(iconDir);

  const copies = [
    [join(iconDir, "icon.png"), join(root, "src", "assets", "shownet-app-icon.png")],
    [join(iconDir, "32x32.png"), join(root, "public", "favicon.png")],
    [join(iconDir, "ios", "AppIcon-60x60@3x.png"), join(root, "public", "apple-touch-icon.png")],
    [join(iconDir, "128x128@2x.png"), join(brandDir, "shownet-app-icon-readme.png")],
  ];

  for (const [from, to] of copies) {
    await mkdir(dirname(to), { recursive: true });
    await copyFile(from, to);
  }

  await validateAppIconSet(root);
} finally {
  await rm(stagingRoot, { recursive: true, force: true });
}

function runTauriIcon(args) {
  const generated = spawnSync(tauri, ["icon", ...args], {
    cwd: root,
    encoding: "utf8",
    stdio: "inherit",
  });
  if (generated.error) throw generated.error;
  if (generated.status !== 0) throw new Error(`Tauri icon generation exited with ${generated.status ?? "no status"}`);
}

async function removeFinderMetadata(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.name === ".DS_Store") await rm(path, { force: true });
    else if (entry.isDirectory()) await removeFinderMetadata(path);
  }
}

console.log("Generated ShowNet app icons for macOS, Windows, iOS, Android, web, and README.");
