import { execFileSync, spawnSync } from "node:child_process";
import { delimiter, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [command, ...args] = process.argv.slice(2);
if (!new Set(["cargo", "tauri", "xwin"]).has(command)) {
  throw new Error("usage: rust-stable.mjs <cargo|tauri|xwin> [...args]");
}

const rustup = process.platform === "win32" ? "rustup.exe" : "rustup";
const locate = (binary) => execFileSync(
  rustup,
  ["which", "--toolchain", "stable", binary],
  { encoding: "utf8" },
).trim();
const cargo = locate("cargo");
const rustc = locate("rustc");
const toolchainBin = dirname(cargo);
const env = {
  ...process.env,
  CARGO: cargo,
  RUSTC: rustc,
  RUSTUP_TOOLCHAIN: "stable",
  PATH: `${toolchainBin}${delimiter}${process.env.PATH ?? ""}`,
};

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const executable = command === "cargo"
  ? cargo
  : command === "xwin"
    ? (process.platform === "win32" ? "cargo-xwin.exe" : "cargo-xwin")
    : process.execPath;
const commandArgs = command === "cargo"
  ? args
  : command === "xwin"
    ? ["xwin", ...args]
    : [resolve(root, "node_modules/@tauri-apps/cli/tauri.js"), ...args];
const result = spawnSync(executable, commandArgs, { cwd: root, env, stdio: "inherit" });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
