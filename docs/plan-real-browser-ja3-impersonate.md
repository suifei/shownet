# 计划：真正接近浏览器 JA3 / JA4（BoringSSL · curl-impersonate · Android / iOS）

> **状态**：规划文档（未实施）  
> **关联现状**：[clienthello-catalog-and-mitm-console.md](./clienthello-catalog-and-mitm-console.md)  
> **代码锚点**：`tls_outbound.rs`、`tls_impersonate.rs`、`tls_fingerprint.rs`、`tls_clienthello_catalog.rs`  
> **当前诚实边界**：出站引擎 = **rustls**；`ja3Parity` / `supportsFullBrowserJa3` **恒为 false**，直至本计划验收门禁通过。

---

## 1. 目标

### 1.1 产品目标

在 **MITM 出站**（代理 → 源站）路径上，让源站测得的 **JA3（及尽可能 JA4）** 与选定目标客户端 **实测对齐**，而不是仅 rustls 上的 cipher/kx/ALPN「配方标签」。

覆盖对象（按优先级）：

| 优先级 | 目标客户端 | 栈特征（概念） |
|--------|------------|----------------|
| P0 | Chrome 桌面（近 2–3 个大版本，如 149–151） | Chromium + **BoringSSL** |
| P0 | 可选「跟随入站」：用入站指纹选最近预置 | 入站解析已有 |
| P1 | Firefox 桌面近版本 | NSS（非 BoringSSL；需独立路径） |
| P1 | Edge 桌面 | Chromium/BoringSSL 系，多与 Chrome 同源 |
| P2 | **Chrome Android** 近版本 | Android Chromium + BoringSSL 分支/补丁 |
| P2 | **Safari iOS** 近版本 | Apple **Network.framework / Secure Transport 演进** + 自有扩展集（**不是**桌面 Chrome BoringSSL） |
| P3 | 其它：Safari macOS、Samsung Internet、系统 WebView | 个案采集 |

### 1.2 非目标（本计划明确不做）

- 宣称「任意 App 证书锁定可被绕过」。
- 在 **未实测通过** 时把 UI/`status` 的 `ja3Parity` 设为 true。
- 用手写假 ClientHello 字节冒充完整握手（无真实密钥协商）——只允许 **真实 TLS 栈** 出站。
- 用目录里的 `documentedJa3` 字符串单独打开 parity（现有测试已禁止）。

### 1.3 成功定义（可机检）

对每个启用的预置 `presetId`：

1. 在受控环境对 **回环捕获探针**（或已知 JA3 测量端）发起 MITM 出站握手。  
2. 解析本端发出的 ClientHello，得到 `measured_ja3` / `measured_ja4`。  
3. 与该预置的 **金标**（见 §4）比对：  
   - **硬门禁（JA3）**：`measured_ja3 == golden_ja3` → 该预置可标 `ja3Parity=true`（且仅当引擎为真实 impersonate 栈）。  
   - **软门禁（JA4）**：记录 `ja4Match`；允许分阶段：先 JA3 全对齐，再收敛 JA4（扩展顺序/ALPN/版本串更敏感）。  
4. 全局 `supportsFullBrowserJa3`：至少 **一个** 桌面 Chrome 预置硬门禁通过且默认引擎可走该栈时，才可为 true。

---

## 2. 现状与差距

### 2.1 今天有什么

| 能力 | 状态 |
|------|------|
| 入站 JA3/JA4 解析与会话存储 | ✅ |
| 版本化预置目录（chrome150 等） | ✅ rustls 配方 |
| 入站 → 预置启发式选档 | ✅ 粗粒度 |
| 出站可测不同 ClientHello 材料 | ✅ 但非浏览器位级 |
| `tls_impersonate` 离线模板 / parity 谓词 | ✅ 仅测试数学，**未挂线** |
| `real_impersonate_stack_available()` | ✅ 恒 false 直至真栈链接 |
| Agent / UI 诚实字段 | ✅ 不宣称全量对齐 |

### 2.2 真浏览器 ClientHello 通常还包含（rustls 配方不够）

- 扩展 **类型顺序** 与 **长度**（JA3 对扩展列表哈希敏感）  
- **GREASE** 值与插入位置  
- 压缩方法、session id、cipher 列表与 **伪随机 GREASE cipher**  
- **supported_versions / key_share / psk_key_exchange_modes** 形态  
- **ALPN** 字节精确序列  
- **padding / compress_certificate / application_settings (ALPS)** 等 Chromium 特色扩展  
- 新版本：**ECH**、**ML-KEM / 后量子** 相关扩展与 group（随 Chrome 大版本变）  
- HTTP/2 层（非 JA3，但风控常一起看）：SETTINGS、WINDOW_UPDATE、PRIORITY —— 产品已有 H2 recipe 绑定方向，真栈路径需一并验收

### 2.3 概念分层（避免混谈）

```text
┌─────────────────────────────────────────────────────────┐
│  入站 ClientHello（浏览器/App → ShowNet）                 │
│  → 已能采 JA3/JA4；隧道透传时源站直接看到它               │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│  出站 ClientHello（ShowNet → 源站）  ← 本计划主战场       │
│  rustls 配方 ≈ 可区分标签                                 │
│  BoringSSL/curl-impersonate ≈ 接近真浏览器               │
└─────────────────────────────────────────────────────────┘
```

---

## 3. 技术路线选型

### 3.1 推荐总体架构：双引擎

```text
                    ┌──────────────────┐
  presetId + policy │  tls_outbound    │
                    │  engine router   │
                    └────────┬─────────┘
              rustls │       │ impersonate
                     ▼       ▼
              build_client   real stack connector
              _config()      (feature-gated)
                     │       │
                     └───┬───┘
                         ▼
              measure ClientHello → JA3/JA4
                         │
              parity gate → status.ja3Parity
```

- **默认引擎**：保持 **rustls**（可移植、可维护、无原生链接负担）。  
- **可选引擎**：`impersonate` / `boring`（Cargo feature，如现有讨论中的 `impersonate-boring`），仅在链接成功且门禁通过时启用。  
- **UI**：高级控制台 / 设置中选预置；仅当 `supportsFullBrowserJa3` 或单预置 `ja3Parity` 为真时展示「浏览器级对齐」文案。

### 3.2 候选栈对比

| 方案 | 优点 | 缺点 | 建议 |
|------|------|------|------|
| **A. curl-impersonate 类**（lexiforest/curl-impersonate 等 fork，或封装库） | 浏览器配置表成熟；社区持续跟 Chrome 大版本 | C/Go 依赖、打包体积、与 Rust MITM 集成需 FFI/子进程 | **P0 优先调研**：子进程或静态链 libcurl-impersonate |
| **B. 直接 BoringSSL + 自研/移植 ClientHello 构造** | 与 Chromium 同源；可控 | 工程量大；需跟 Chromium 版本同步补丁 | **P1 中长期**；Android/定制必备 |
| **C. 基于 rquest / wreq / bogdanfinn tls-client 等现成客户端** | 快 | 多为「客户端库」而非代理内嵌；许可证与进程模型 | 可作 **金标对照** 与 **第一阶段 sidecar** |
| **D. uTLS（Go）sidecar** | HelloChrome_xxx 丰富 | Go 运行时、双语言运维 | 可选 **对照服务**，不作为唯一生产路径 |
| **E. 系统 API 出站**（macOS Secure Transport / Windows SChannel） | 像系统浏览器 | 难精细选「Chrome 150」；不可跨平台统一 | 仅辅助，不主路径 |

**建议落地顺序：**

1. **Phase 0**：金标采集与 CI 探针（不换栈）。  
2. **Phase 1**：sidecar 或 FFI 接入 **curl-impersonate 类**，打通「出站一次握手 + 测 JA3」。  
3. **Phase 2**：嵌入式 / 同进程 BoringSSL 路径（减少延迟与进程管理）。  
4. **Phase 3**：Android / iOS 专用配置矩阵与金标。  
5. **Phase 4**：入站跟随 + 自动选最近对齐预置；JA4 硬门禁。

### 3.3 与现有 MITM 的衔接点

今日出站在 `proxy` 路径：`connect_verified_tls_measured` + rustls `ClientConfig`。

真栈接入时需替换的最小接口（建议）：

```rust
// 概念 API（非最终签名）
trait OriginTlsConnector {
    fn connect(&self, host: &str, sni: &str, preset_id: &str)
        -> Result<(TlsStream, MeasuredClientHello), Error>;
}
```

- `MeasuredClientHello`：原始 handshake 字节 + 解析后的 ja3/ja4，写入现有 `tls_fingerprint` 出站记录。  
- 证书校验、上游代理（HTTP/SOCKS）、H2 协商：必须与现网路径行为一致或可配置降级。  
- **失败回退**：impersonate 连接失败 → 明确错误或可选回退 rustls（回退时 **禁止** 仍报 ja3Parity=true）。

---

## 4. 金标（Golden）数据与版本矩阵

### 4.1 金标从哪里来

每个 `presetId` 维护：

| 字段 | 说明 |
|------|------|
| `family` / `major` | 如 chrome / 150 |
| `platform` | `desktop-linux` / `desktop-macos` / `desktop-windows` / `android` / `ios` |
| `stack` | `chromium-boringssl` / `gecko-nss` / `apple-network` / … |
| `stack_version` | 例如 Chromium 提交、BoringSSL 日期标签、iOS 系统版本 |
| `golden_ja3` / `golden_ja3_raw` | 金标 |
| `golden_ja4` / `golden_ja4_raw` | 金标（可后补） |
| `source` | 采集方法：真实浏览器抓包 / curl-impersonate 自测 / 公开库 |
| `captured_at` | ISO 日期 |
| `notes` | GREASE 是否固定、是否含 ECH 等 |

**采集方法（推荐）：**

1. 真实浏览器访问受控 HTTPS，在 **浏览器侧** 或中间透明抓 **客户端→服务器** ClientHello（注意：不是 MITM 出站）。  
2. 或对 `curl-impersonate --chrome150` 类工具自连接探针，解析其 ClientHello 作为 **工具金标**（需注明「对齐 curl-impersonate」还是「对齐真 Chrome」——二者可能仍有细微差）。  
3. 产品验收默认以 **真浏览器抓包金标** 为准；工具金标仅作开发期代理。

### 4.2 桌面 Chrome（BoringSSL）

- Chromium 桌面使用 **BoringSSL**（随 Chromium 树内联，版本与 Chrome 大版本绑定，而非独立「BoringSSL 1.x」用户可见号）。  
- 计划维护表（示例结构，数值以采集为准更新）：

| presetId | 对齐对象 | 栈说明 | 金标状态 |
|----------|----------|--------|----------|
| chrome149 | Chrome 149 desktop | Chromium 149 + tree BoringSSL | 待采 |
| chrome150 | Chrome 150 desktop | 同上 | 待采（产品默认目标） |
| chrome151 | Chrome 151 desktop | 同上 | 待采 |

每个大版本变更关注：cipher 列表、extension 顺序、key_share groups、是否默认 PQ、ALPS/ECH。

### 4.3 Firefox（对照）

- 栈为 **NSS**，不是 BoringSSL。  
- 若做 `firefox136` 等位级对齐，需 **独立 connector**（或 curl-impersonate 的 firefox profile），不可复用 Chrome BoringSSL 配置硬套。

### 4.4 Android（Chrome / WebView / 系统）

Android 上「接近浏览器 JA3」至少分三类：

| 类型 | 典型栈 | 计划要点 |
|------|--------|----------|
| **Chrome for Android** | Chromium + BoringSSL（与桌面同源族，但 **平台/ALPN/扩展可能不同**） | 单独 `chrome-android{NN}` 预置；金标必须用 **真机/模拟器 Chrome** 抓包，禁止直接复用 desktop chromeNN 金标 |
| **Android System WebView** | 随设备更新的 Chromium 轨 | 版本碎片化严重；只对「明确版本 + 设备 API level」做可选预置 |
| **OkHttp / 应用自建 TLS** | Conscrypt / BoringSSL / JSSE 不一 | **不属于浏览器 impersonate**；入站指纹记录即可，出站勿冒充「Chrome Android」除非用户显式选 App 类预置 |

**BoringSSL 版本怎么记：**

- 不追求单一 semver；记录：  
  - `chromium_major`（如 131）  
  - `chromium_full`（如 131.0.6778.x）  
  - `boringssl_commit` 或 Chromium 树内 `third_party/boringssl` 修订（从对应 Chromium 源码树读取）  
  - `android_api` / 设备架构（arm64）  
- 金标按 **(chrome-android major × 采集环境)** 存档，避免「一个 android 预置打天下」。

### 4.5 iOS（Safari / WebKit / Chrome iOS）

| 类型 | 典型栈 | 计划要点 |
|------|--------|----------|
| **Safari iOS** | Apple **Network.framework**（历史 Secure Transport 演进），**不是** Chromium BoringSSL | 预置 `safari-ios{NN}`；金标来自真机 Safari；扩展集与 Chrome 差异大 |
| **Chrome iOS** | 受 App Store 限制，TLS 往往走 **Apple 网络栈**，与桌面 Chrome **显著不同** | 单独家族 `chrome-ios`（若做）；**禁止**用 desktop chrome JA3 冒充 |
| **App URLSession** | 系统栈 | 仅入站观测 |

**版本记录：**

- `ios_version`（如 18.2）  
- `webkit_version` / CFNetwork 相关可见版本（以采集环境为准）  
- 不写「BoringSSL x.y」除非实测确认该客户端链的是 BoringSSL（多数系统 HTTPS **不是**）。

### 4.6 平台矩阵（验收用最小集）

| 平台 | P0 预置 | P1 | 金标采集环境 |
|------|---------|----|--------------|
| macOS arm64 | chrome150 | firefox 近版本、safari 近版本 | 本机 Chrome/Firefox/Safari |
| Windows x64 | chrome150 | edge 近版本 | CI 或开发机 |
| Linux x64 | chrome150 | — | CI 探针 |
| Android arm64 | chrome-android 近 1 个 major | WebView 可选 | 模拟器/真机 |
| iOS arm64 | safari-ios 近 1 个 major | chrome-ios 研究 | 真机 |

---

## 5. 实施阶段

### Phase 0 — 测量与门禁基建（1–2 周量级）

- [x] 固定 **JA3/JA4 探针**：`tls_probe` 环回监听 + CLI `tls-golden-probe`（`measure-rustls` / `wait`）；解析复用 `tls_fingerprint`。  
- [x] 金标仓库：`src-tauri/testdata/tls-golden/`（schema + multi-version `pending-capture` entries + honesty gates）。  
- [x] 外部源清单（低成本、免装全量浏览器）：`fingerprint-reference/sources-inventory.json`（curl-impersonate / curl_cffi / uTLS / wreq 等）+ `scripts/tls-golden-capture.mjs`。  
- [x] CI/本地：`npm run test:tls-golden` 与 `tls_golden` / `tls_probe` Rust 门禁；rustls 路径 `ja3Parity==false`。  
- [x] 文档/UI：「对齐级别」枚举 `recipe` | `tool-matched` | `browser-matched`（`tls_golden::AlignmentLevel`）。

### Phase 1 — curl-impersonate 类接入（MVP 真 JA3）

- [ ] 选型：静态库 FFI vs 子进程（子进程更易先跑通）。  
- [ ] 实现 `OriginTlsConnector` 的 impersonate 后端；预设映射 `chrome150` → 工具 profile 名。  
- [ ] 出站测得 JA3 与 **工具金标** 对齐后，预置级 `ja3Parity` 可 true（标注 source=tool）。  
- [ ] 打包：macOS/Windows/Linux 可选组件或 `feature = "impersonate"` 正式包变体。  
- [ ] 失败、超时、证书错误路径与现网一致审计。

### Phase 2 — 真浏览器金标 + 收紧

- [ ] 用真实 Chrome 149/150/151 抓金标，替换/并列 tool 金标。  
- [ ] 差一字节 diff 工具（扩展列表、GREASE 策略说明）。  
- [ ] 仅 `browser-matched` 时，对外文案允许「接近 Chrome NNN JA3」。  
- [x] H2 SETTINGS 与真浏览器对照 —— **不是可选门禁,而是首要项**。

  issue #4(lionairthai 无限重载)的原因就是 h2 而非 JA3:同一套 TLS 下,
  h2 出口让页面 20 秒内重载 23 次,降级到 h1 后一次导航即稳定。指纹权重上
  h2 不低于 JA3。

  已实测对照(Chromium 151,自建 TLS+ALPN 监听器直接解帧;我方经
  `Http2FingerprintCollector` 读回):

  | 项 | Chrome 151 | 我方 | 状态 |
  |---|---|---|---|
  | SETTINGS 集合 | `1,2,4,6` | `1,2,4,5,6` | 多 `5 MAX_FRAME_SIZE` |
  | SETTINGS 数值 | 65536 / 0 / 6291456 / 262144 | 相同 | 一致 |
  | WINDOW_UPDATE | `+15663105` | `+15663105` | 一致 |
  | PRIORITY 帧 | 无 | 无 | 一致 |
  | 伪头顺序 | `method,authority,scheme,path`(实测) | `method,scheme,authority,path`(h2 源码 `frame/headers.rs`) | 顺序不同 |

  **SETTINGS 已完全对齐,且未使用打补丁的 h2。** 我方原本多发两项:
  `MAX_CONCURRENT_STREAMS` 是自己设的,停设即可;`MAX_FRAME_SIZE` 是
  hyper 默认 `Some(16384)` 并宣告的 —— `max_frame_size` 的签名是
  `impl Into<Option<u32>>`,而 `proto/h2/client.rs` 只在 `if let Some(max)`
  时转发,所以传 `None` 就不上线。行为不变:不宣告即用协议默认值,正是
  原先宣告的 16384。

  **剩余差异只有伪头顺序一项,且已确认无法通过配置解决**:h2 的 `Pseudo`
  是具名字段结构体而非有序容器,顺序完全来自 `frame/headers.rs` 中 `Iter`
  的 `if let` 先后;全 crate 无任何 `pseudo order` / `header_order` 配置。
  改它必须 `[patch.crates-io]` 接管 h2 0.4.15(52 文件、3 万余行、hyper
  的传递依赖),意味着长期自行跟进其安全更新(h2 有过 Rapid Reset 类
  CVE)。

  **实测:引发 issue #4 的站点已不再拒绝我们的 h2。** 用当前 SETTINGS
  (即上表四项)向 `www.lionairthai.com` 开一条 TLS+ALPN h2 连接,并按我方
  伪头顺序(`method,scheme,authority,path`,即与 Chrome 不同的那个)发出
  一个 GET,源站返回 SETTINGS / WINDOW_UPDATE / HEADERS / DATA —— **无
  GOAWAY、无 RST_STREAM**。

  也就是说:**当初触发 h1 降级的 h2 拒绝,是 SETTINGS 造成的,不是伪头
  顺序**;剩下这一项差异在该站点上不足以被拒。

  两个必须说明的边界:一,这是单站点、单次请求的观测,风控可能随负载或
  会话状态变化;二,探针用的是 Node 的 TLS ClientHello,不是 ShowNet 的
  rustls —— 因此它证明的是 **h2 层不再被拒**,不等于 ShowNet 端到端可用
  (那需要跑起应用来验)。

  **结论:为剩下这一项差异接管一个 HTTP/2 实现,当前判断是不划算** ——
  收益已被实测压到很小,而代价是长期维护 3 万行带 CVE 史的协议实现。这是
  取舍不是技术障碍;若要做,验收标准已就位:重跑本节探针,伪头顺序应变为
  `method,authority,scheme,path`。

  另注:`impersonate-boring` 目前是空 feature,不链接任何 BoringSSL 栈,
  因此没有现成的 impersonation 依赖可顺带提供已打补丁的 h2。

### Phase 3 — 嵌入 BoringSSL（可选强化）

- [ ] 评估直接链接 BoringSSL（或 chromium boringssl）与证书校验、会话恢复。  
- [ ] 将 Phase 1 的 profile 配置迁到自研/移植的 ClientHello 策略表。  
- [ ] 减少子进程延迟，利于高并发 MITM。

### Phase 4 — Android / iOS

- [ ] Android：采集 Chrome Android 金标；新增 preset 与目录项；模拟器自动化。  
- [ ] iOS：Safari 金标；明确 **非 BoringSSL** 文案；评估是否仅提供「系统栈出站」近似而非 JA3 位级。  
- [ ] 入站自动选档：desktop vs mobile 分族，避免桌面 chrome150 误用于 iOS 入站。

### Phase 5 — 产品化

- [ ] 设置 / 高级控制台：引擎选择、对齐级别徽章、金标来源展示。  
- [ ] Agent：`shownet_get_outbound_tls_status` 增加 `alignmentLevel`、`goldenSource`、`measuredJa3`。  
- [ ] Auto-crawler 导出：诚实标签升级为「recipe / tool / browser」。  
- [ ] 发布说明与默认引擎策略（默认仍可 rustls，专家模式开 impersonate）。

---

## 6. 模块改动清单（预期）

| 模块 | 改动 |
|------|------|
| `tls_outbound.rs` | 引擎路由、`real_impersonate_stack_available` 真实现、status 字段扩展 |
| `tls_impersonate.rs` | 从「离线模板」升级为「真栈适配 + 测量」；保留模板仅作单测 |
| `tls_clienthello_catalog.rs` | 增加 `alignment`、`platform`、`golden_*`、Android/iOS 条目 |
| `tls_clienthello_reference.rs` | 对照 curl-impersonate / uTLS / 真浏览器金标覆盖率 |
| `tls_fingerprint.rs` | 出站测量写入与列表展示 |
| `proxy.rs` | 出站 connect 换 connector |
| 打包 / CI | feature、原生依赖、多平台 artifact |
| UI | 对齐级别、失败提示、禁止虚假文案 |
| 文档 | 本文 + 更新 clienthello 文档诚实边界表 |

---

## 7. 风险与合规

| 风险 | 缓解 |
|------|------|
| 原生依赖导致构建失败 | feature 默认关；CI 矩阵分「纯 rustls」与「impersonate」 |
| 体积膨胀 | 可选组件 / 按平台下载 | 
| 版本漂移（Chrome 月更） | 金标日期 + major 跟踪；过期预置降级为 recipe |
| 法律与 ToS | 工具用于授权测试与自身产品调试；文档不鼓励未授权绕过 |
| 性能 | 连接池、会话复用、异步 FFI；压测 MITM 吞吐 |
| 假阳性宣传 | **仅门禁通过写 parity**；代码审查禁止硬编码 true |

---

## 8. 决策记录（待评审）

| # | 问题 | 倾向 |
|---|------|------|
| D1 | MVP 用子进程 curl-impersonate 还是同进程 FFI？ | 先 **子进程/sidecar** 换速度，再嵌库 |
| D2 | 默认引擎是否改为 impersonate？ | **否**，默认 rustls；用户/专家模式开启 |
| D3 | Android/iOS 是否承诺 JA3 位级？ | Android Chrome **努力位级**；iOS Safari **先金标再评估可行性**，可能只做「近似」 |
| D4 | Firefox 是否进 P0？ | **否**，P1；避免与 BoringSSL 路径抢工期 |
| D5 | `documentedJa3` 是否继续保留？ | 保留作参考，**永不单独驱动 parity** |

---

## 9. 里程碑验收清单（摘要）

- [x] Phase 0：探针 + 金标格式 + CI 诚实断言（真栈 tool-matched 仍属 Phase 1）
- [ ] Phase 1：至少 1 个 desktop Chrome 预置 **tool-matched** JA3 通过  
- [ ] Phase 2：同一预置 **browser-matched** JA3 通过；`supportsFullBrowserJa3` 策略文档化  
- [ ] Phase 4：至少 1 个 `chrome-android*` 或明确「仅 desktop」范围声明  
- [ ] 全文案 / Agent / auto-crawler 与 status API 一致  

---

## 10. 参考（实现时核对最新上游）

- 本仓库：`tls_clienthello_reference.rs` 中的 industry id 映射与 curl-impersonate 条目  
- Chromium / BoringSSL 树内版本（按目标 Chrome major 检出）  
- curl-impersonate 及活跃 fork 的 browser profile 表  
- bogdanfinn/tls-client、uTLS HelloChrome_*（对照而非唯一真理）  
- Apple CFNetwork / iOS 版本发布说明（Safari 指纹变化）  

---

## 11. 修订

| 日期 | 说明 |
|------|------|
| 2026-08-03 | 初稿：目标、双引擎、金标、桌面/Android/iOS、阶段与门禁 |

**下一步（执行层）**：评审 D1–D5 → 开 Phase 0 探针与 `tls-golden` 目录 → 再立项 Phase 1 工程任务。

---

## 10. 决策与进展（2026-08-09）

### 10.1 已落地：Phase 1 boring 连接器(过渡)

`impersonate-boring` 特性链接真实 BoringSSL 出站连接器
(`proxy::connect_verified_tls_boring`),从抓包实测确诊有效但**不逐字节 Chrome**:

- 密码套件哈希已对齐 Chrome 151(`8daaf6152771`),加了后量子曲线 + SCT/OCSP + 扩展乱序;
- **天花板**:这版 boring-sys(4.22)发不出 ALPS(`0x44cd`)、ECH(`0xfe0d`),也没有
  Chrome 151 的 MLKEM768 曲线 → JA4 落在 `t13d1513h2` 而非 Chrome 的 `t13d1516h2`;
- 另一条独立缺口:**h2 伪头顺序**。`h2` crate(0.4.15)把顺序硬编码为
  `method,scheme,authority,path`,配置改不了;Chrome 是 `method,authority,scheme,path`。
- 因此 `supportsFullBrowserJa3` 恒为 false,UI 明说"浏览器系,非逐字节 Chrome"。

### 10.2 已决:生产引擎选 **wreq**(已实测证明)

`wreq` 5.x(rquest 后继)自带 patched boring2 + patched h2,**一个库同时把 TLS 逐字节
和 h2 伪头顺序都做对**。对 `tls.peet.ws/api/all` 实测:

- TLS JA4:`t13d1516h2_8daaf6152771_...`(16 扩展,与 Chrome 一致)
- h2 akamai:`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`(伪头 `m,a,s,p` = Chrome)

### 10.3 约束:boring 与 wreq 不能共存

`boring-sys`(过渡连接器)与 `boring-sys2`(wreq 内部)都 `links = "boringssl"`,
cargo 禁止两个包链接同一原生库。**所以迁移到 wreq 必须整体替换 boring,不能并存。**

### 10.4 集成方案(下一次专门做)

wreq 是完整 HTTP 客户端(非流级连接器),集成点在**请求级**,不在连接器级:

1. 删 `boring`/`tokio-boring` 依赖与 `connect_verified_tls_boring` 及其测试。
2. 出站派发处(`proxy.rs` 的 CONNECT 隧道主路径 ~1613、`dedicated_request_sender_factory`、
   ~4800)在 impersonate 激活时,不走 `connect_verified_tls_measured + handshake_origin_https`,
   改为用 wreq 客户端(带上游代理)整发整收。`HttpsRequestSender` 需加 `Impersonate` 变体或
   在更高层分流;`send_request` 返回体从 `Incoming` 改为 boxed body。
3. 流式(SSE)/WebSocket:wreq 不覆盖的走现有 rustls 路径回退。
4. 指纹记录:wreq 逐字节,记录目标 JA4 并置 parity=true(或自检实测)。
5. **自动测试**(已写好待接):`wreq_egress_is_byte_exact_chrome`——
   断言 JA4 以 `t13d1516h2` 开头、akamai 以 `|m,a,s,p` 结尾。

**为何不在本轮完成**:这是对 11k 行流式 MITM 出站路径的整体替换(流式/ws/隧道共享
sender/GOAWAY/抓包都要处理),半途会弄坏代理。boring 过渡路径保持已测可用,wreq 作为
下一次专门工程,靶子(§10.2)与接缝(§10.4)已定。

---

## 11. 测量推翻了"版本不匹配"诊断(2026-08-09)

Cloudflare 托管挑战在抓包时反复循环。此前的判断是 **wreq-util 落后浏览器约 14 个
版本**(内嵌浏览器 Chrome 151,wreq-util 2.2.6 最高 Chrome 137)导致指纹版本不一致。
本轮做了完整测量,**该判断是错的**。

### 11.1 实测数据

反射器 `tls.peet.ws/api/all`,同一网络出口:

| 客户端 | JA4 |
|---|---|
| 真实 Chrome 151(抓包库中的入站记录 + headless 复测) | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| 真实 Chrome 151 + `--disable-features=TlsMldsaSignatures` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| 真实 Chrome 137(Chrome for Testing 137.0.7151.70) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| wreq-util 2.2.6 `Chrome137`(当前出站) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| wreq-util 3.0.0-rc.14 `Chrome140/145/149` | `t13d1517h2_8daaf6152771_b6f405a00624` |

逐段拆开,Chrome 151 与 wreq Chrome137 的差异**只有签名算法列表开头三个值**
`0904,0905,0906`(ML-DSA:mldsa44/65/87);密码套件与扩展列表(含 ALPS `44cd`、
ECH `fe0d`)完全一致。

### 11.2 结论

1. **不是版本代差。** 真实 Chrome 137 与关闭 ML-DSA 的真实 Chrome 151 产生**同一个
   JA4** —— ML-DSA 是 137→151 之间唯一的 ClientHello 差异。因此"TLS 像 137、UA 说
   151"不是异常组合,大量真实 151 装机就是这个指纹。
2. **升级 wreq 无用且更差。** wreq-util 3.0.0-rc.14 虽然把目录扩到 Chrome149,但其
   Chrome140+ 配方多了扩展 `0029` → 17 扩展(`t13d1517h2`),且同样不带 ML-DSA,
   离真浏览器比现在更远。3.0/6.0 均为 rc,底层也从 boring2 换成了 btls。
3. **补不上 ML-DSA。** boring-sys2 4.15.15 中没有 ML-DSA,`sigalgs_list` 虽可配置
   但底层不认这三个值。

### 11.3 真正的原因:UA 自报 HeadlessChrome

同一个抓包库中,**17,763 条真正发往源站的 GET/POST/OPTIONS** 携带

```
user-agent: Mozilla/5.0 (...) HeadlessChrome/151.0.0.0 Safari/537.36
```

以 lionairthai 为例:`/api/socket.io/` 17,288 条泄露,主文档 `/` 382 条已改写。
原有防护是渲染器级的 CDP `Emulation.setUserAgentOverride`,**只覆盖它附着的那个
页面**,子资源与 worker 全部漏出。TLS 指纹做到逐字节也救不了自报无头的 UA。

同时该覆盖硬编码 `"Not_A Brand";v="24"`,而真实 Chrome 151 发的是
`"Not=A?Brand";v="99"` —— 且 headless Chrome 151 自身的 `sec-ch-ua` 本就干净
(实测),该 metadata 改写没有解决任何问题,反而制造了它本想防止的身份分裂。

### 11.4 本轮落地

- `browser.rs`:启动加 `--user-agent`(由 `chrome --version` 读主版本 + Chrome
  精简 UA 的固定平台串构造),对所有渲染器/worker/子资源生效。
- `BrowserView.tsx`:删除手写 `userAgentMetadata`(及随之死掉的 `uaPlatform`/
  `uaArchitecture`),让 Chrome 自己提供客户端提示;仅保留 UA 串覆盖作为页面级兜底,
  因为 Chrome 不提供读回 `--user-agent` 的接口,两者只能按同一主版本各自构造。
- `DISABLED_FEATURES` 加 `TlsMldsaSignatures`。**注意这不改变源站看到的东西** ——
  浏览器的 ClientHello 终止在 ShowNet 自己的监听端口。它修的是 `ja3Parity`:开启时
  该指标为一个出站栈永远补不上的固定差值长期报红,指向不可行动的方向(本次即因此
  误判)。
- 测试:`disabled_feature_list_stays_well_formed_and_keeps_ja4_parity`、
  `launch_user_agent_never_announces_automation`、
  `chrome_version_parsing_reads_the_major_from_every_build_wording`(常规);
  `launch_user_agent_matches_the_browsers_own_client_hints`(`npm run test:browser-ua`)、
  `browser_and_egress_present_one_fingerprint`(`npm run test:ja4-parity`)。

### 11.5 仍未验证

Cloudflare 循环是否因此消失,**尚未在真实站点上验证**。UA 泄露是有证据的缺陷且已修,
但它是不是该循环的唯一原因还需要一次真实抓包确认。
