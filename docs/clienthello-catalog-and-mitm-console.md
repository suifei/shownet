# 版本化 ClientHello 目录 · MITM 高级控制台 · 本地正式发布说明

本文档描述 ShowNet **0.1.0** 起落地的出站 TLS ClientHello 版本化预置、MITM 高级管理控制台、相关 IPC，以及本地正式发布门禁与诚实边界。实现以仓库源码为准；发布操作另见 [release.md](./release.md)。

---

## 1. 功能概览

| 能力 | 说明 |
|------|------|
| **ClientHello 版本化目录** | 按浏览器家族 + 大版本维护出站 TLS 配方（cipher / kx / ALPN 顺序），产品默认 `chrome150` |
| **出站 TLS 选择** | 设置页与高级控制台可选预置；选择驱动 MITM → origin 的真实 `ClientConfig`，而非仅改文案 |
| **入站自动选档** | 可按入站 JA3/JA4 启发式映射到目录预置（粗粒度家族） |
| **MITM 高级控制台** | 导航「请求工具 → 高级」：抓包状态、Hook、规则入口、指纹、PX×3、reCAPTCHA、配置 |
| **PX 控制台设置** | 解密开关、拦截 ecData；会话证据列表与结构解码（非无密钥硬破） |
| **Auto-crawler** | Skill / 工具注册，可按会话证据生成多语言客户端包 |
| **行业对照表** | 与 tls-client / uTLS / curl-impersonate / wreq 等公开目录做 **id/版本覆盖** 一致性核对（非位级 JA3 克隆） |

---

## 2. 诚实边界（必读）

| 声明 | 真值 |
|------|------|
| 出站 TLS 引擎 | **rustls**（非 BoringSSL / curl-impersonate） |
| `ja3Parity` | **始终为 false**，除非未来接入且实测通过的真实 impersonate 栈 |
| `supportsFullBrowserJa3` | **false**（同上） |
| 版本预置含义 | rustls 上的 **cipher / key-exchange / ALPN 配方标签**，可区分版本、可测得不同 ClientHello 材料 |
| **不是** | 与真实 Chrome 149/150 位级一致的完整 ClientHello（扩展顺序 shuffle、GREASE、ECH、ML-KEM 等） |

UI 与 status API 不得在 rustls-only 下声称「完整浏览器 JA3 对齐」。隧道透传（pass-through）模式下，目标站看到的是**客户端原始** ClientHello，与 MITM 出站配方是另一条路径。

---

## 3. ClientHello 目录

### 3.1 模块

| 路径 | 职责 |
|------|------|
| `src-tauri/src/tls_clienthello_catalog.rs` | 预置表、`get_preset` / `list_presets` / `set_active_preset_id`、cipher/kx 配方应用 |
| `src-tauri/src/tls_clienthello_reference.rs` | 业界 id 矩阵与覆盖报告（测试 / 审计） |
| `src-tauri/src/tls_outbound.rs` | 激活预置、构建 `ClientConfig`、status JSON、冷启动默认 `chrome150` |
| `src-tauri/src/tls_impersonate.rs` | 目标 JA3 模板与 parity 比较辅助（**不**表示已挂真实栈） |
| `src-tauri/src/tls_fingerprint.rs` | 入站解析、MITM 指纹记录、`list_session_tls_fingerprints`（UI + Agent 共用） |

### 3.2 预置 ID 约定

- 稳定 id：`chrome150`、`firefox133`、`safari-ios18` 等（无下划线、小写）
- 粗粒度别名：`chrome-like` → 解析到该家族最新版本化 id（如 `chrome151`）
- 产品默认 active：`chrome150`（与 bogdanfinn/tls-client 默认 `Chrome_150` 对齐）
- 粗档位枚举 `OutboundTlsProfile` 与目录同步：`ChromeLike` ↔ chrome 家族 active 预置

### 3.3 覆盖范围（示例，以源码 `CATALOG` 为准）

**Chrome 桌面：** 120、124、128、131、133、136、140、144、145、146、149、**150**、151  

**其它：** chrome-android、edge、firefox、safari、safari-ios，以及 `default` / `chrome-like` / `firefox-like` / `safari-ios-like`  

### 3.4 构建路径

```text
UI / set_outbound_tls_profile(presetId)
        │
        ▼
tls_outbound::set_active_preset
        │
        ▼
build_client_config / build_client_config_for_preset
        │  CryptoProvider 按配方重排 cipher + kx
        │  ALPN = h2, http/1.1（多数预置）
        │  enable_sni = true
        ▼
proxy connect_verified_tls_measured  →  origin MITM 出站握手
```

选择 `chrome149` 再连接时，同家族 `ChromeLike` 解析会优先使用 active 的 `chrome149`，而不是写死 `chrome150`。

### 3.5 Status 字段（`get_outbound_tls_profile`）

| 字段 | 含义 |
|------|------|
| `presetId` | 当前版本化预置 id |
| `presets` | 完整目录视图（label / family / majorVersion / note） |
| `browserFamily` / `browserMajorVersion` | 家族与大版本 |
| `engine` | `rustls` |
| `ja3Parity` | false |
| `supportsFullBrowserJa3` | false |
| `autoFromInbound` | 是否按入站自动选档 |
| `profileCipherFingerprint` / `recipeFingerprint` | 配方/套件指纹（测试与排障） |

设置持久化键：`outbound_tls`（含 `presetId`、`profile`、`autoFromInbound`），应用启动时恢复。

---

## 4. MITM 高级控制台

### 4.1 入口

- 主导航分组：**请求工具** → 视图 `advanced`（标签「高级」）
- 组件：`src/components/AdvancedConsoleView.tsx`
- 样式：`src/styles.css` 中 advanced-console 相关类

### 4.2 标签页

| Tab | 内容 |
|-----|------|
| 数据包捕获 | 会话请求计数、代理端口、快捷入口 |
| Hook 管理 | `list_browser_hooks` |
| 替换规则 | 跳转规则工作台；ecData 拦截提示 |
| 指纹数据 | `get_tls_fingerprints` + 出站 status |
| PX 替换重放 / 对比 / 篡改 | `list_px_evidence`、`decode_px_payload` |
| reCAPTCHA | 会话内路径启发列表 |
| 配置 | ClientHello 预置、入站自动选档、PX 开关、打开设置 |

### 4.3 关键 Tauri 命令（必须均在 `generate_handler!` 中注册）

| 命令 | 用途 |
|------|------|
| `get_outbound_tls_profile` | 出站 TLS / 预置 status |
| `set_outbound_tls_profile` | 设置预置或粗档位（接受 `chrome150` 等 id） |
| `set_outbound_tls_auto_from_inbound` | 入站自动选档 |
| `list_clienthello_presets` | 仅列目录 |
| `get_px_settings` / `set_px_settings` | PX 开关 |
| `list_px_evidence` | 会话 PX 证据 |
| `decode_px_payload` | 结构解码 |
| `list_browser_hooks` | Hook 列表 |
| **`get_tls_fingerprints`** | 会话内已存 TLS 指纹行 + 出站 status |

`get_tls_fingerprints` 与 Agent 工具共用：

`tls_fingerprint::list_session_tls_fingerprints(storage, sessionId)`  
→ `{ inboundFingerprints, outbound, boundaryNote }`。

指纹 Tab **不得**用 `.catch(() => ({ inboundFingerprints: [] }))` 吞掉 IPC 失败；错误应进入控制台统一错误提示。

结构门禁测试：`tests/advanced-console-ui.test.ts`（校验 AdvancedConsole 每个 `invoke("…")` 均已注册）。

---

## 5. 设置页 UI

路径：设置 → 抓包与 HTTPS → **出口代理** 区域。

- 粗档位 chips：`default` / `chrome-like` / `firefox-like` / `safari-ios-like`
- **ClientHello 版本预置** `<select>`：完整 `presets` 列表
- 展示当前 `presetId`、family/version、诚实说明（非全量浏览器 JA3）
- 入站 JA3/JA4 自动选档开关

类型：`src/types.ts` → `OutboundTlsProfileStatus`、`ClientHelloPresetInfo`、`PxSettings` 等。

---

## 6. 业界对照与测试

### 6.1 参考来源（只读审计，非 vendored）

- [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) `profiles`（默认 Chrome_150）
- [refraction-networking/utls](https://github.com/refraction-networking/utls) `HelloChrome_*`
- [lwthiker/curl-impersonate](https://github.com/lwthiker/curl-impersonate) / [lexiforest](https://github.com/lexiforest/curl-impersonate) `browsers.json`
- [0x676e67/wreq](https://github.com/0x676e67/wreq) Emulation 命名类

### 6.2 一致性含义

- **覆盖一致**：核心 Chrome major（如 120/124/131/133/144/146/149/150）在目录中存在且配方互异  
- **路径一致**：`set_active_preset` → `preset_id_for_profile` → builder 材料与 `preset_cipher_fingerprint` 一致  
- **线区分**：不同预置经 MITM 出站实测可产生不同 JA3（rustls 配方差异）  
- **位级一致**：与真实浏览器 / uTLS parrot **不**作为验收条件  

相关测试模块：`tls_clienthello_catalog`、`tls_clienthello_reference`、`tls_outbound`、`proxy`（`industry_chrome_presets_measure_distinct_wire_ja3` 等）、`storage::persists_structured_tls_fingerprints`（含 list 路径）。

---

## 7. 本地正式发布门禁

「100%」指：**已执行门禁中 0 失败**；`#[ignore]` /  live 网络用例保持 ignored 并记在此表，不计入失败。

### 7.1 命令

```bash
# 前端生产构建
npm run build

# 前端 hygiene（示例；与 CI/本地门禁一致的一组）
npm run test:browser-drag
npm run test:browser-bus
npm run test:replay-export-ui
npm run test:request-list
npm run test:traffic-workbench
npm run test:request-inspector
npm run test:sse-inspector
npm run test:request-workbench
npm run test:request-collections
npm run test:reverse-proxy-ui
npm run test:tls-interception-ui
npm run test:client-access-ui
npm run test:mcp-guide
npm run test:analysis-scope
npm run test:soak-harness
node --experimental-strip-types --test tests/advanced-console-ui.test.ts

# Rust 全量 lib（非 ignored）
cd src-tauri && cargo test --lib

# macOS 本地包
npm run tauri:bundle
```

### 7.2 典型通过结果（示例快照）

| 门禁 | 结果 |
|------|------|
| `cargo test --lib` | ~333 passed / 0 failed / ~25 ignored |
| `npm run build` | exit 0 |
| 前端 hygiene + advanced-console-ui | 0 fail |
| `npm run tauri:bundle` | `ShowNet.app` + `ShowNet_0.1.0_aarch64.dmg` |

### 7.3 产物路径（macOS arm64 本地）

```text
src-tauri/target/release/shownet
src-tauri/target/release/bundle/macos/ShowNet.app
src-tauri/target/release/bundle/dmg/ShowNet_0.1.0_aarch64.dmg
```

- 签名：ad-hoc（identity `-`）  
- 公证：无 Apple 凭据时跳过  
- 多平台归档：`npm run archive:local-release`（需同时具备 DMG 与 Windows portable，见 [release.md](./release.md)）

### 7.4 Ignored / live-only（不记失败）

- `cargo test --lib` 中 `#[ignore]`：local socket、live egress、Agent sidecar、性能基准等  
- `npm run test:egress` / `test:rust:network` / `test:agent-sidecar`：需本机环境与 sidecar  

---

## 8. 源码与导航索引

| 区域 | 文件 |
|------|------|
| 目录 / 出站 | `tls_clienthello_catalog.rs`, `tls_outbound.rs`, `tls_clienthello_reference.rs` |
| 指纹 list IPC | `tls_fingerprint.rs` → `list_session_tls_fingerprints`, `lib.rs` `get_tls_fingerprints` |
| 代理出站测量 | `proxy.rs` `connect_verified_tls_measured` |
| PX | `px_analysis.rs` |
| Auto-crawler | `auto_crawler.rs`, `skills.rs`, `agent_tools.rs` |
| UI | `AdvancedConsoleView.tsx`, `SettingsView.tsx`, `App.tsx` |
| 类型 | `types.ts` |
| 结构测试 | `tests/advanced-console-ui.test.ts` |

---

## 9. 变更记录（摘要）

| 主题 | 说明 |
|------|------|
| 版本化 ClientHello | 多浏览器大版本预置；默认 chrome150；设置 + 高级控制台可选 |
| 诚实 status | rustls 下不宣称全量浏览器 JA3 |
| 高级控制台 | 完整 IPC 面；指纹 Tab 使用真实 `get_tls_fingerprints` |
| 发布 | 门禁绿 + macOS app/DMG 可本地分发（ad-hoc） |

更细的架构背景见 [architecture.md](./architecture.md) 的 TLS / 指纹章节；发布渠道与 sidecar 见 [release.md](./release.md)。

---

## 10. 后续（非本版验收）

- 接入真实 BoringSSL / curl-impersonate（或等价）后，才可将 `supportsFullBrowserJa3` / 实测 parity 按栈能力打开  
- HTTP/2 SETTINGS / 伪头顺序与 ClientHello 预置绑定（参考 tls-client profile 形态）  
- 将 `list_clienthello_presets` 与 status 中 `documentedJa3` 与公开样本库对齐（可选）  
