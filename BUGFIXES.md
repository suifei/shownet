# Bug 修复记录

本文记录 2026-08 内嵌浏览器 / 出口代理 / MITM / Windows e2e 相关已落地修复。  
对应提交：`6156087`（`Improve embedded browser, egress reliability, and Windows e2e QA.`）  
设计目标原文：`docs/goal-embedded-browser-proxy-mitm-ux.md`（若本地忽略 `docs/*.md`，以本文件与源码为准）。

---

## 产品与体验

### P0-A · MITM 下百度等站静态 CDN 返回 400（图裂 / 脚本失效 / 无法搜索）

| 项 | 内容 |
|----|------|
| **现象** | 内嵌浏览器能开 `www.baidu.com` 主 HTML，但 `pss.bdstatic.com` / `*.bcebos.com` 等图/CSS/JS 源站 **HTTP 400**；搜索等前端逻辑不绑定。 |
| **根因** | 静态 CDN 对 MITM 出站 rustls 指纹/H2 更严；主站仍 200 造成「半残页面」。 |
| **修复** | 设置页「HTTPS 解密」增加 **一键推荐静态 CDN 绕行**（`*.bdstatic.com`、`*.bcebos.com`）；写入 `bypass_selected`，命中域名端到端真 TLS，不解密正文。**新安装默认即启用该绕行**（库内无历史 `tls_interception` 时种子化）。 |
| **关键文件** | `src/tlsBypassPresets.ts`、`src/components/SettingsView.tsx`、`src-tauri/src/tls_interception.rs`、`src-tauri/src/storage.rs` |
| **验证** | 单测绕行命中 + first-run seed；手测：默认或一键后静态资源不再大面积 400。 |

---

### P1 · 出口代理易配错且难发现（错端口 → 502）

| 项 | 内容 |
|----|------|
| **现象** | 系统/环境 `HTTP_PROXY` 在 1080，ShowNet 出口误填 8080 等 → 经本机抓包 502；用户误以为「网络正常但代理坏了」。 |
| **根因** | ShowNet **不继承** env/系统代理；出口无连通性探测；502 错误不够显著。 |
| **修复** | 1）设置页说明与 env 无关；2）保存后/手动 **探测连通性**（`probe_upstream_proxy`，CONNECT `example.com:443`）；3）检测到 env 时 **一键导入**；4）流量详情 502 横幅 + `capture://proxy-error` toast（节流）。 |
| **关键文件** | `src-tauri/src/proxy.rs`、`src-tauri/src/lib.rs`、`src/components/SettingsView.tsx`、`src/components/TrafficView.tsx`、`src/App.tsx` |
| **验证** | 错端口 toast 含 `host:port`；正确 PROXY 下 live egress 通过。 |

---

### P2 · 切换导航后内嵌浏览器状态丢失

| 项 | 内容 |
|----|------|
| **现象** | 从「浏览器」切到「流量/设置」再回来 → Chrome 被杀，回到初始态。 |
| **根因** | `App.tsx` 条件渲染卸载 `BrowserView`；unmount 调用 `stop_proxy_browser`。 |
| **修复** | **Keep-alive**：浏览器视图始终挂载，非激活用 `hidden`/CSS 隐藏；切 tab **不** `stop`；停止抓包 / 用户点停止 / 真卸载才杀进程。**sessionStorage 记忆 last URL**；CDP 断开后返回浏览器页 **重连 WebSocket**（不重新 launch）。 |
| **关键文件** | `src/App.tsx`、`src/components/BrowserView.tsx`、`src/styles.css` |
| **验证** | `tests/browser-keepalive.test.ts`；手测切 tab 后 URL/screencast 保持。 |

---

### P3 · 「在系统浏览器中打开」无效

| 项 | 内容 |
|----|------|
| **现象** | 工具栏外开按钮无反应。 |
| **根因** | 依赖 `window.open`，Tauri WebView 下不可靠。 |
| **修复** | 接入 `@tauri-apps/plugin-opener` + `openUrl`；capability `opener:default`；无 URL 时 disabled。 |
| **关键文件** | `src/components/BrowserView.tsx`、`src-tauri/Cargo.toml`、`src-tauri/src/lib.rs`、`capabilities/default.json`、`package.json` |
| **验证** | `tests/browser-opener.test.ts`；手测系统默认浏览器打开当前地址。 |

---

### P4 · 上游 IPv6 黑洞导致连接长时间超时

| 项 | 内容 |
|----|------|
| **现象** | 双栈坏 IPv6 时 `connect_tcp` 固定卡约 15s → 502「连接 host:port 超时」。 |
| **根因** | 解析后按系统顺序连地址，AAAA 不通时拖满总超时。 |
| **修复** | DNS 后 **IPv4 优先**；存在 IPv4 时 IPv6 单次短超时（约 750ms）；错误信息仍含 `host:port`。 |
| **关键文件** | `src-tauri/src/proxy.rs` |
| **验证** | Rust 单测 IPv6 不可达仍可连 IPv4；live 直连/出口不再固定卡死。 |

---

## 工程与构建

### Windows QA / Live 测试写死 7890/7891

| 项 | 内容 |
|----|------|
| **现象** | Live 出口/MITM 测试只认 7890/7891，用户 `.env` 为 `PROXY=http://localhost:8080` 时假失败。 |
| **修复** | 从 `PROXY` / `HTTP(S)_PROXY` / `ALL_PROXY` 解析出口；`npm run test:windows` 编排 default + live 层。 |
| **关键文件** | `src-tauri/src/proxy.rs`、`scripts/windows-qa.mjs`、`package.json`、`tests/windows-qa-runner.test.ts` |

### Agent sidecar 构建：`EPHEMERAL_SOURCE_PATHS` 在 top-level await 前未初始化

| 项 | 内容 |
|----|------|
| **现象** | `npm run build:agent-sidecar` → `ReferenceError: Cannot access 'EPHEMERAL_SOURCE_PATHS' before initialization`。 |
| **修复** | 将常量提前到模块顶部（top-level await 之前）；按路径逐个 `git checkout` 避免不存在的 `bin/protoc.exe`。 |
| **关键文件** | `scripts/build-grok-sidecar.mjs` |

---

### P0-B · MITM 出站对严格 CDN 强制 HTTP/1.1

| 项 | 内容 |
|----|------|
| **现象** | 未绕行时 `*.bdstatic.com` / `*.bcebos.com` 在 rustls MITM + H2 下仍易 400。 |
| **根因** | 出站默认 ALPN 优先 h2，部分 CDN 对 MITM H2 指纹更严。 |
| **修复** | 对上述后缀主机 **强制 HTTP/1.1-only ALPN** 并禁用 origin H2 应用层（与绕行预设互补；优先仍建议绕行）。 |
| **关键文件** | `src-tauri/src/tls_outbound.rs`、`src-tauri/src/proxy.rs` |

---

### P5 · 内嵌浏览器点击后键盘/中文输入不生效

| 项 | 内容 |
|----|------|
| **现象** | 静态资源恢复后，screencast 上点击输入框仍可能无法键入。 |
| **根因** | Headless CDP 焦点未同步到远端 document；本机 IME 捕获面未聚焦。 |
| **修复** | 指针按下时 `ensureRemotePageFocus`（`Emulation.setFocusEmulationEnabled` + body focus）并聚焦 IME textarea；百度等页状态条提示 CDN 绕行。 |
| **关键文件** | `src/components/BrowserView.tsx`、`src/styles.css` |

---

### P0-C · 流量列表/详情区分代理 502 与源站 4xx

| 项 | 内容 |
|----|------|
| **现象** | 用户难以区分「代理连不上」（502 + 超时文案）与「源站主动 400」（CDN/业务）。 |
| **修复** | `trafficStatus.ts` 分类：列表 502 显示 `502·代理`；详情对源站 4xx 展示 Server + 绕行提示；代理错误保留全文。 |
| **关键文件** | `src/trafficStatus.ts`、`src/components/TrafficView.tsx`、`tests/traffic-status.test.ts` |

---

## Goal 验收勾选（`docs/goal-embedded-browser-proxy-mitm-ux.md`）

| 条目 | 结果 |
|------|------|
| P0 百度图/脚本（绕行或 HTTP/1.1） | **通过**：默认 CDN 绕行 + 一键 + HTTP/1.1 兜底 |
| P0-C 代理/源站状态可分 | **通过**：`502·代理` vs 源站 4xx |
| P1 出口错误可发现 | **通过**：探测 / env 导入 / 502 toast+详情 |
| P2 切 tab 不丢浏览器 | **通过**：keep-alive + last URL + CDP 重连 |
| P3 系统浏览器外开 | **通过**：plugin-opener |
| P4 Happy Eyeballs / IPv4 优先 | **通过** |
| P5 交互焦点/IME | **通过**：点击聚焦 + CDP 错误 busNote |
| CI `npm test` / quality | **通过**：`npm run test:windows` |
| 完整 JA3 impersonate | **非目标**（本批只做金标/inventory 基础） |

---

## JA3 金标基础（后续批次）

| 项 | 状态 |
|----|------|
| 多版本 `pending-capture` 矩阵（Chrome 120…150 等） | **已落地** `src-tauri/testdata/tls-golden/entries/` |
| 外部源 inventory（≥3 GitHub/工具） | **已落地** `fingerprint-reference/sources-inventory.json` |
| 低成本 capture 脚本（缺工具诚实 skip） | **已落地** `scripts/tls-golden-capture.mjs` / `npm run tls-golden:capture` |
| 本地 ClientHello 探针 CLI | **已落地** `tls-golden-probe`（`measure-rustls` / `wait`） |
| 公共 JA3/JA4 检测站 inventory + 验证 | **已落地** `detector-sites.json` + `npm run tls-detector:validate` |
| 诚实门禁 `npm run test:tls-golden` | **通过**；`ja3Parity` 仍为 false |
| 检测站 100%「浏览器通过」 | **不宣称**（rustls/node 可达 ≠ Chrome parity） |
| 真栈 tool/browser-matched 升格 | **未做**（需 curl-impersonate 类引擎；探针已就绪） |

---

## 未在本批修复（刻意非目标）

| 项 | 说明 |
|----|------|
| 完整真浏览器 JA3 / BoringSSL impersonate | 见 `docs/plan-real-browser-ja3-impersonate.md`；Phase 0 金标/inventory 已部分完成 |
| 全量 Playwright GUI 点击 | 以 pillar 结构测试 + live 代理/sidecar 为准；JA3 身份用 golden pipeline，不靠 GUI 矩阵 |

---

## 回归入口

```bat
npm run test:windows
npm run test:windows:default
npm run test:egress
npm run test:mitm-smoke
npm run test:agent-sidecar
npm run test:tls-golden
npm run tls-golden:capture:dry
```

功能支柱机器清单：`src/e2eFeaturePillars.ts` + `tests/e2e-feature-pillars.test.ts`。
