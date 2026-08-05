# Goal: 内嵌浏览器 / 出口代理 / MITM 静态资源 · Windows 可迭代修复

**Audience:** Grok Build（Windows 本机自动迭代）  
**Repo:** shownet (Tauri 2 + React + Rust MITM proxy)  
**Primary OS for verify:** Windows 10/11  
**Evidence export:** `首次抓包.shownet`（用户导出，format=`shownet-session` v1）  
**Date context:** 2026-08-05  

---

## 0. 一句话目标

在 **Windows** 上让内嵌浏览器经 ShowNet 抓包访问百度等站时：

1. **静态资源（图/CSS/JS）可加载**（不再大面积 400 裂图、脚本失效）；  
2. **页面可交互**（输入搜索词、点击「百度一下」能进入结果页）；  
3. **切换应用功能后浏览器状态保持**（不杀 Chrome、不丢标签/URL）；  
4. **「在系统浏览器中打开」可用**；  
5. **出口代理配置正确且可观测**（端口错误/未生效时用户能立刻发现问题）。

验收以 **Windows 真机 + 可选 `.shownet` 导出对比** 为准。

---

## 1. 背景与已确认事实

### 1.1 网络拓扑（用户环境）

- 用户机器常挂系统代理：`HTTP(S)_PROXY=http://127.0.0.1:1080`（或类似本地代理客户端）。  
- ShowNet 本地抓包监听：`0.0.0.0:8888`（示例）。  
- ShowNet **不会自动继承** 系统/环境变量里的 `HTTP_PROXY`/`HTTPS_PROXY` 作为上游。  
- 未配「出口代理」时，ShowNet 对目标站是 **直连**。  
- 用户曾把出口误配成 **`localhost:8080`**，而真实代理在 **1080** → 502。  
- 用户删除 env 代理并重启后，主站 HTML 可打开，但图裂、不能搜索仍在。

### 1.2 内嵌浏览器实现要点（代码）

| 点 | 位置 | 行为 |
|----|------|------|
| 启动 | `src-tauri/src/browser.rs` `ProxyBrowserHandle::launch` | Headless Chrome，`--proxy-server=http://127.0.0.1:{proxy_port}`，随机 profile + incognito |
| 启动前置 | `src-tauri/src/lib.rs` `launch_proxy_browser` | 要求 CA 已装 + **当前会话已开始抓包** |
| 画面 | `src/components/BrowserView.tsx` | CDP `Page.startScreencast`，UI 显示 JPEG 帧 |
| 卸载 | `BrowserView` unmount + `App.tsx` 条件渲染 | **调用 `stop_proxy_browser` 杀掉 Chrome** |
| 外开 | `BrowserView.tsx` | `window.open(url)` — Tauri 下通常无效 |
| 上游 TCP | `src-tauri/src/proxy.rs` `connect_tcp` | `TcpStream::connect((host, port))`，15s 超时 → 中文错误 `连接 {host}:{port} 超时`（UTF-8 长度 31 当 host=www.baidu.com） |
| 出口 | Settings「出口代理」+ storage | mode=direct\|http\|https\|socks5 |

### 1.3 导出证据摘要（`首次抓包.shownet`）

- `requests`: 97；时间上两段访问簇（约 02:52 与 02:56），模式一致 → **与「有无 8080 出口」无关**。  
- `www.baidu.com` GET `/` → **200**（MITM OK）。  
- `pss.bdstatic.com` GET（图/CSS/**JS**/字体）→ **全部 HTTP 400**（源站 body：`400 Bad Request` / `JSP3/2.0.14`）。  
- CONNECT 到 `pss.bdstatic.com` → **200**（隧道与 MITM 握手成功）。  
- `psstatic.cdn.bcebos.com` 图片 → **400**。  
- `hectorstatic.baidu.com` 部分 JS → **200**（并非所有域名都拒）。  
- 存在 `GET /home/page/data/pageserver?errno=7004` → **302** → `/search/error.html`。  
- **无 POST、无 `/s?wd=` 搜索结果请求** → 搜索从未真正发出。  
- TLS 元数据：`browserParity=false`，`wireDiffers=true`，出站 **rustls** 非真 Chrome JA3。  
- UA：`HeadlessChrome/150.0.0.0`。

---

## 2. 问题清单（现象 → 根因 → 修法）

按优先级排序。每一条都可独立验收。

---

### P0 — MITM 下百度静态 CDN 返回 400（图裂 + 脚本失效 + 无法搜索）

#### 现象（用户可见）

- 内嵌浏览器能打开 `https://www.baidu.com/` 标题与热搜文字。  
- **图片裂图**、导航图标空白。  
- **无法输入搜索关键字**，点击「百度一下」**不进结果页**。  
- 出口 8080 与直连两种抓包导出表现一致。

#### 现象（抓包证据）

- `pss.bdstatic.com` / `*.bcebos.com` 静态 GET → 源站 **400**（非代理超时 502）。  
- 关键键 JS（jquery、min_super、instant_search 等）全 400 → 前端事件未绑定。  
- `pageserver?errno=7004` → 错误页。

#### 根因（分析结论）

1. ShowNet 对 CDN **做了 MITM 解密** 后，用 **rustls 出站** 向源站重放 HTTP/1.1 或 H2。  
2. 百度静态 CDN（JSP3）对「非浏览器指纹 / H2 兼容差异」更严，**主动 400**。  
3. 主站 HTML 仍 200，造成「半残页面」：能开壳、不能用。  
4. **不是** CA 未安装；**不是** 单纯出口代理；**不是** screencast 画质问题。

#### 修法（实现方向，可组合）

**A. 产品默认 / 一键策略（优先，收益最大）**

1. HTTPS 解密「绕行指定」增加 **内置静态 CDN 预设**，或安装向导推荐：  
   - `*.bdstatic.com`  
   - `pss.bdstatic.com`  
   - `*.bcebos.com`  
   - `psstatic.cdn.bcebos.com`  
   - 可选：`*.bdstatic.com` 通配已覆盖时不必重复  
2. UI：解密策略页增加「推荐：绕过常见静态 CDN（修复百度等站图裂/脚本）」开关，一键写入绕行列表。  
3. 绕行后浏览器与 CDN **端到端真 TLS**（Headless Chrome 指纹），ShowNet 只记 CONNECT/隧道元数据（按现有 bypass 逻辑）。

**B. MITM 出站兼容（中长期）**

1. 排查对 `pss.bdstatic.com` 的 H2 转发是否缺伪头 / 错 authority / 错误连接复用。  
2. 对严格 CDN：MITM 出站 **强制 HTTP/1.1** 或禁用 H2 试一下是否变 200（加集成测试）。  
3. 文档诚实说明：`browserParity=false` 时部分 CDN 会拒；完整修复见 `docs/plan-real-browser-ja3-impersonate.md`。

**C. 可观测性**

1. 流量列表区分：  
   - 代理自身错误（502 + `连接 x 超时`）  
   - 源站 4xx（展示 status + server）  
2. 内嵌浏览器状态条：当关键 JS/静态域失败率高时提示「建议绕行静态 CDN」。

#### 验收（P0）

- [ ] Windows：抓包 + 内嵌浏览器打开 baidu.com。  
- [ ] 流量中 `pss.bdstatic.com` 的 **图片/JS 不再大面积 400**（绕行时为 tunnel/bypass 成功；或 MITM 修复后为 200）。  
- [ ] 页面 **可见 logo/导航图标**（允许热搜图仍有个别失败）。  
- [ ] 地址栏输入关键字，点搜索或回车，**出现搜索结果页请求**（如 `/s?` 或等价），且页面有结果 UI。  
- [ ] 导出 `.shownet`：不再出现「全部 pss GET=400」模式（或明确为用户关闭绕行时的预期）。  
- [ ] 自动化：至少 1 个 Rust/集成测试或脚本，模拟「绕行列表命中 → 不走 MITM 解密路径」；若改 H2，则对 fixture/录制响应有回归测。

---

### P1 — 出口代理：用户易配错且难发现

#### 现象

- 系统 `HTTP_PROXY=127.0.0.1:1080`，ShowNet 出口填 **8080** → 经 8888 访问外网 **502**。  
- `curl -x http://127.0.0.1:8888` → `Content-Length: 31` → `连接 www.baidu.com:443 超时`。  
- 直连 `curl https://www.baidu.com` 因系统代理成功，用户误判「网络正常却代理坏了」。

#### 根因

1. ShowNet **不读** env 代理。  
2. 出口 host/port **无连通性探测**。  
3. 502 正文未在 UI 显著展示。

#### 修法

1. 保存出口代理后 **可选探测**：`CONNECT www.baidu.com:443` 或 `example.com:443` via upstream，失败 toast 明确「出口 127.0.0.1:port 连不上」。  
2. 设置页文案：说明「与系统 HTTP_PROXY 无关，必须在此单独配置」。  
3. 若检测到环境变量 `HTTP_PROXY`/`HTTPS_PROXY` 且出口为直连，**提示可一键导入**（解析 host/port/scheme）。  
4. 502 时在流量详情 / toast 显示完整错误字符串。

#### 验收（P1）

- [ ] 出口填错误端口 → 保存或探测时 **明确失败提示**（含 host:port）。  
- [ ] 一键从 env 导入（若实现）后 host/port 与 env 一致。  
- [ ] 出口正确时，`curl -x 127.0.0.1:8888 -I https://example.com` 不再因「直连超时」502（在用户无直连、仅上游可达的环境）。

---

### P2 — 内嵌浏览器切换功能后状态丢失

#### 现象

- 从「浏览器」切到「流量/设置」再回来 → 浏览器回到初始态（example.com / 空白），需重新启动 CDP。

#### 根因

```text
App.tsx:  {activeView === "browser" && <BrowserView />}   // 卸载
BrowserView unmount: invoke("stop_proxy_browser")         // 杀 Chrome
```

#### 修法

1. **Keep-alive**：`BrowserView` 始终挂载，非激活时用 CSS `hidden`/`display:none`/`inert`，**禁止 unmount 杀进程**。  
2. unmount/隐藏时：**不要**默认 `stop_proxy_browser`；仅在以下情况停止：  
   - 用户点击停止 Chrome  
   - 抓包停止（可保留可配置）  
   - 会话切换 / 退出应用  
3. 再次显示时：若 `get_proxy_browser_status().running`，**重连 WebSocket CDP + 恢复 screencast**，不重新 launch。  
4. 可选：持久化 last URL 到 sessionStorage，重连后 `Page.navigate` 仅当进程已死。

#### 验收（P2）

- [ ] 启动内嵌浏览器打开 baidu → 切到流量 → 再回浏览器：  
  - Chrome 进程仍在（或 status.running=true）  
  - URL/标题仍为百度（或至少非强制回 example.com）  
  - screencast 恢复实时帧  
- [ ] 用户点「停止」后进程结束。  
- [ ] 停止抓包后的行为有单测或文档约定（默认停浏览器可接受，但需不误杀于「仅切 tab」）。

---

### P3 — 「在系统浏览器中打开」无效

#### 现象

- 点击外链图标无反应或打不开系统浏览器。

#### 根因

```tsx
window.open(currentUrl, "_blank", "noopener,noreferrer")
```

Tauri 2 WebView 下不可靠；项目未使用 `@tauri-apps/plugin-opener` / shell open。

#### 修法

1. 依赖：`@tauri-apps/plugin-opener`（或现有 shell 插件若可用）。  
2. Rust/capabilities：允许 open URL。  
3. 前端：`open(currentUrl)`，失败 toast。  
4. 禁止依赖 `window.open` 作为桌面唯一路径。

#### 验收（P3）

- [ ] Windows：点击工具栏外开，**系统默认浏览器**打开当前 URL。  
- [ ] 无 URL 时按钮 disabled 或 toast。  
- [ ] 单元/组件测试：桌面路径调用 opener mock，而非 `window.open`。

---

### P4 — 上游连接 IPv6 黑洞 / 超时（加固）

#### 现象

- `nslookup`/`ping` 优先 AAAA，IPv6 不通；`connect_tcp` 15s 超时 → 502。  
- 与「仅直连、无出口」叠加时更严重。

#### 修法

1. `connect_tcp`：**Happy Eyeballs** 或 **IPv4 优先**，IPv6 短超时 fallback。  
2. 超时错误信息保留 host:port，便于 UI 展示。

#### 验收（P4）

- [ ] 单元测试：mock 多地址时 IPv6 失败仍可连 IPv4。  
- [ ] Windows 双栈坏 IPv6 环境：直连出站不再固定 15s 卡死（有出口时次要）。

---

### P5 — 内嵌浏览器输入/点击体验（Headless + screencast）

#### 现象

- 即使静态资源恢复后，CDP 转发的键盘/鼠标仍可能在复杂页有问题。  
- 当前导出中 **无搜索请求**，主因是 JS 400；修复 P0 后需回归。

#### 修法

1. P0 通过后，手动回归：聚焦搜索框、中文 IME、点击按钮。  
2. 若仍失败：检查 `BrowserView` 指针坐标映射、`Emulation.setFocusEmulationEnabled`、IME 路径。  
3. 评估非 headless 或 `--headless=new` 参数集（可选实验 flag）。

#### 验收（P5）

- [ ] P0 通过前提下：中文输入 ≥1 字 + 触发搜索导航成功。  
- [ ] 失败时有日志（CDP error / bus note），不静默。

---

## 3. 非目标（本次不做）

- 完整 BoringSSL/curl-impersonate 级 **真浏览器 JA3**（可另开 goal，参见 `docs/plan-real-browser-ja3-impersonate.md`）。  
- 强制用户关闭系统 IPv6。  
- macOS 公证 / 商店分发。  
- 改变默认抓包端口 8888（除非冲突处理）。  
- 修复与本次无关的分析 Agent / 技能系统。

---

## 4. 推荐实现顺序（Grok Build 迭代）

| 迭代 | 内容 | 预估风险 |
|------|------|----------|
| **Iter 1** | P2 keep-alive + 停止条件收紧 | 中：生命周期 |
| **Iter 2** | P3 opener 外开 | 低 |
| **Iter 3** | P0-A 静态 CDN 绕行预设 + UI 一键 | 低，收益最高 |
| **Iter 4** | P1 出口探测 + env 提示/导入 | 低 |
| **Iter 5** | P4 connect Happy Eyeballs / IPv4 优先 | 中：网络栈 |
| **Iter 6** | P0-B 可选 H2/出站兼容调研与小修复 | 高 |
| **Iter 7** | P5 交互回归 + 必要 CDP 修复 | 中 |

每轮：改代码 → `npm test` / `cargo test` 相关 → Windows 手测清单 → 提交。

---

## 5. Windows 验证清单（每轮必跑）

### 5.1 环境准备

1. 安装并信任 ShowNet Root CA。  
2. 确认本机可上网（系统代理或直连按你的真实环境）。  
3. 若必须经本地代理出网：ShowNet **出口** = 实际端口（如 `127.0.0.1:1080`，类型 HTTP 或 SOCKS5 与客户端一致）。  
4. **不要**把出口设成 8888。

### 5.2 代理与出口

```bat
curl -x http://127.0.0.1:8888 -I --max-time 20 https://www.baidu.com
curl -x http://127.0.0.1:8888 -I --max-time 20 https://example.com
```

- 期望：非 502；若 MITM 证书导致 curl 报错，可用 `--ssl-no-revoke` 或 `-k` 仅作连通性参考。

### 5.3 内嵌浏览器

1. 当前会话 **开始抓包**。  
2. 打开内嵌浏览器，启动 CDP。  
3. 打开 `https://www.baidu.com/`。  
4. 确认图片/图标大致正常（P0）。  
5. 输入关键字并搜索，进入结果页（P0/P5）。  
6. 切换到「流量」再回「浏览器」：状态保持（P2）。  
7. 点外开：系统浏览器打开（P3）。  
8. 导出 `.shownet`，抽查 `pss.bdstatic.com` 是否仍「全 400」。

### 5.4 回归

- [ ] 停止抓包后内嵌浏览器行为符合约定。  
- [ ] CA 未安装时 launch 仍有明确错误。  
- [ ] `npm test` / 关键 `cargo test` 通过。

---

## 6. 关键文件索引

| 区域 | 路径 |
|------|------|
| 内嵌浏览器 UI | `src/components/BrowserView.tsx` |
| 视图挂载 | `src/App.tsx` |
| Chrome 启动参数 | `src-tauri/src/browser.rs` |
| launch/stop 命令 | `src-tauri/src/lib.rs` (`launch_proxy_browser`, `stop_proxy_browser`) |
| CONNECT / MITM / 上游 | `src-tauri/src/proxy.rs` (`handle_connect`, `connect_tcp`, `connect_destination`) |
| 出口设置 UI | `src/components/SettingsView.tsx` |
| 出口存储 | `src-tauri/src/storage.rs` |
| 解密/绕行规则 | `src-tauri/src/capture_rules.rs`（及设置中 HTTPS 解密策略 UI） |
| 浏览器总线 | `src/browserBus.ts`, `src-tauri/src/browser_bus.rs` |
| JA3 诚实说明 | `docs/plan-real-browser-ja3-impersonate.md`, `src-tauri/src/tls_outbound.rs` |

---

## 7. 给 Grok Build 的执行约束

1. **小步提交**：每迭代一个可验证行为；避免巨型无关重构。  
2. **Windows 优先验证** P0/P2/P3；macOS 不破坏编译即可。  
3. **诚实**：不在 UI 声称「完整 Chrome JA3」除非 `browserParity=true`。  
4. **默认安全**：绕行静态 CDN 是 **降低 MITM 覆盖** 换可用性；UI 写清「这些域名将不解密正文」。  
5. **测试**：新增逻辑配单测；代理路径优先纯 Rust 测 + 可选手动清单。  
6. **证据**：修复前后可用 `.shownet` 导出对比 `pss.bdstatic.com` 状态码分布。  
7. **不要** 在未确认用户代理类型时硬编码 1080；预设绕行域名可以写死常见 CDN。

---

## 8. 完成定义（Definition of Done）

全部满足即可关闭本 goal：

1. **P0** 验收通过（百度图可见 + 可搜索出结果，或文档化的一键绕行默认开启且通过手测）。  
2. **P2** 切 tab 不丢浏览器状态。  
3. **P3** 系统浏览器外开可用。  
4. **P1** 至少具备出口错误可发现性（探测或显著错误文案）。  
5. CI：`npm test` 与现有 quality 相关检查不回退。  
6. 本文件「验收」勾选项在 PR/提交说明中勾选结果。  
7. （可选）P4 Happy Eyeballs 落地。  

---

## 9. 用户原始问题 ↔ 本 goal 映射

| 用户描述 | 对应条目 |
|----------|----------|
| CA 已装，内嵌浏览器打不开百度 `ERR_TUNNEL` | 先 P1/出口/直连超时；连通后归 P0 |
| `curl -x 8888` 502 / 删 env 后主站可开 | P1 + 文档拓扑 |
| 图裂（有出口/直连导出均有） | **P0** |
| 输入关键字、点按钮无效 | **P0**（JS 400）+ **P5** |
| 切换功能浏览器回初始 | **P2** |
| 无法打开外部浏览器 | **P3** |
| 出口配了仍不行（8080 vs 1080） | **P1** |

---

## 10. 建议的首条 Agent Prompt（可直接粘贴）

```text
在 Windows 上实现 docs/goal-embedded-browser-proxy-mitm-ux.md。

按迭代顺序：先 P2（BrowserView keep-alive，切 view 不 stop_proxy_browser），
再 P3（tauri opener 外开），再 P0-A（静态 CDN 解密绕行预设 + 设置页一键启用）。
每步运行相关测试，并给出 Windows 手测步骤。
不要做完整 JA3 impersonate。提交信息用英文完整句子。
```

---

*End of goal document.*
