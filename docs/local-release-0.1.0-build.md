# ShowNet 0.1.0 本地 QA 产物构建记录

构建时间（UTC）：2026-08-03T04:03:34Z  
通道：`local-unsigned-qa`  
命令顺序：`tauri:bundle` → Windows sidecar/xwin → `build:windows:cross` → portable launcher → `package:windows:portable` → `archive:local-release --replace` → `clean:local-build-cache --confirm --include-xwin-cache`

## 归档目录

路径（本地，默认不进 Git）：`release/ShowNet-0.1.0-local-qa/`

| 文件 | 大小 | SHA-256 |
|------|------|---------|
| `ShowNet_0.1.0_macOS_arm64.dmg` | 75 726 296 B (~72 MiB) | `e1269b5acffe8bc81877599177fe2ea62c7ffd915521ebe9e4d49512bc99bed8` |
| `ShowNetPortable_0.1.0_windows_x86_64.zip` | 68 624 833 B (~65 MiB) | `a57c33369a77557a2f26ad3f7afee255c311e40968e2ea1137d3ce19dbafbbf6` |
| `release-manifest.json` | — | `a2a8768b54f5726f768f47b7c238e1c938e749fbd99fc3eef9446fd995ad74c1` |

## 签名

- macOS：ad-hoc（未公证）
- Windows：unsigned

## 清理

已清理约 **34.1 GiB** 本地编译缓存（`src-tauri/target`、`.sidecar-src`、`dist`、生成的 Agent sidecar、cargo-xwin 缓存）。  
**保留** QA 归档目录 `release/ShowNet-0.1.0-local-qa/`。

## 复现

```bash
npm run tauri:bundle
npm run build:agent-sidecar -- --target x86_64-pc-windows-msvc --xwin
npm run build:windows:cross
npm run build:windows:portable-launcher:cross
npm run package:windows:portable -- --target x86_64-pc-windows-msvc
npm run archive:local-release -- --replace
npm run clean:local-build-cache -- --confirm --include-xwin-cache
```

详见 [release.md](./release.md) 与 [clienthello-catalog-and-mitm-console.md](./clienthello-catalog-and-mitm-console.md)。
