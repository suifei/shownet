# TLS 金标（Golden Fingerprints）

本目录存放**出站 ClientHello 指纹金标**，用于判定某个预置（`presetId`）是否真的与目标客户端对齐。

对应计划：[plan-real-browser-ja3-impersonate.md](../../../docs/plan-real-browser-ja3-impersonate.md) §4。
现状边界：[clienthello-catalog-and-mitm-console.md](../../../docs/clienthello-catalog-and-mitm-console.md)。

---

## 1. 这个目录是干什么的

ShowNet 默认的出站引擎是 **rustls**。rustls 只能调整 cipher / kx / ALPN 的顺序，
**无法**复刻浏览器 ClientHello 的扩展顺序、GREASE 插入位置、ALPS/ECH 等特征。
因此当前所有预置的对齐级别都只是 `recipe`（配方级），`ja3Parity` 恒为 `false`。

要把某个预置升级为「真的对齐」，必须有一个**可复核的金标**：
一份在受控环境下、从**目标客户端本身**采集到的 ClientHello 指纹。
门禁比对的是「本端实测发出的 JA3」与「金标 JA3」，两者逐字节相等才允许标记对齐。

**没有金标 = 不允许声称对齐。** 这是产品的诚实契约，不是流程建议。

---

## 2. 对齐级别（alignment）

| 级别 | 含义 | 允许的对外表述 |
|------|------|----------------|
| `recipe` | 仅 rustls 配方调序，产生可区分的出站材料 | 「出站预置（rustls 配方）」；**不得**提及浏览器对齐 |
| `tool-matched` | 实测 JA3 == 某 impersonate 工具（如 curl-impersonate）金标 | 「对齐 curl-impersonate 的 chromeNNN 配置」，必须点名工具 |
| `browser-matched` | 实测 JA3 == **真实浏览器**抓包金标 | 「接近 Chrome NNN 的 JA3」 |

三者严格递进。`tool-matched` **不等于** `browser-matched`——
impersonate 工具与真浏览器之间仍可能有细微差异，文案必须如实区分。

---

## 3. 文件组织

```
src-tauri/testdata/tls-golden/
  README.md          本文
  schema.json        条目的 JSON Schema（draft 2020-12）
  entries/
    <presetId>--<platform>.json
  fingerprint-reference/          # 低成本外部源清单（非金标本身）
    README.md
    sources-inventory.json        # ≥3 个 GitHub/工具源 + 版本覆盖备注
    sources-inventory.schema.json
    version-matrix.json           # 多版本 preset×platform 状态索引
```

一个 `presetId` 在不同平台上是**不同的金标**，必须分开存档。
例如 Chrome 150 桌面版与 Chrome Android 150 的 ClientHello 并不相同，
禁止用桌面金标去判定 Android 预置（见计划 §4.4）。

**多版本矩阵**：`entries/` 为 industry-floor Chrome majors（120/124/131/133/144/146/149/150 等）
提供 `pending-capture` 占位；在采集完成前全部停留在 `recipe`。
外部工具支持哪些版本见 `fingerprint-reference/sources-inventory.json`——
**仅凭 inventory 不能**把任何预置升到 `tool-matched` / `browser-matched`。

---

## 4. 怎么采集

### 4.1 真浏览器金标（验收基准，`source: "browser-capture"`）

1. 在受控网络中让目标浏览器访问一个只记录 ClientHello 的 TLS 探针。
2. 抓的是**浏览器 → 服务器**这一跳，**不是** ShowNet 的 MITM 出站跳。
3. 记录完整的 `clientHelloHex`，JA3/JA4 由本仓库的解析器计算，便于日后算法升级后重算。

> 采集时务必记录浏览器完整版本号与操作系统。Chrome 月度大版本会改动
> cipher 列表、扩展顺序、key_share group 与是否默认启用后量子算法。

### 4.2 工具金标（开发期代理，`source: "tool-capture"`）

对 `curl-impersonate` / `curl_cffi` 一类工具自连探针，解析其 ClientHello。
可用于打通 Phase 1 链路，但**只能**支撑 `tool-matched`，不能升到 `browser-matched`。

低成本刷新入口（优先工具，缺省时诚实 skip，不静默假绿）：

```bash
# 校验 inventory + 多版本矩阵；列出已安装工具
npm run tls-golden:capture -- --dry-run

# 尝试对某一 Chrome major 做工具侧观测（无二进制则打印 skip 行）
npm run tls-golden:capture -- --preset chrome150 --platform desktop-windows

# 门禁测试
npm run test:tls-golden
```

脚本：`scripts/tls-golden-capture.mjs`。  
完整 `status: captured` 仍需要本地 ClientHello 探针产出的 `clientHelloHex`；
仅从公开 JA3 探针拿到 hash **不足以** 升格 alignment。

外部源清单（避免为每个 major 下载完整浏览器）：
`fingerprint-reference/sources-inventory.json`（curl-impersonate 系、curl_cffi、uTLS、wreq/rquest 等）。

### 4.3 禁止事项

- 禁止手工编造或从文章/博客里抄一个 JA3 字符串当金标。
- 禁止用 `documentedJa3`（目录里的参考值）充当金标——它只是资料，
  现有测试已禁止它单独驱动 parity（计划 D5）。
- 禁止在 `status` 仍为 `pending-capture` 时把任何预置标为已对齐。

---

## 5. 条目状态机

```
pending-capture ──采集并复核──> captured ──目标版本过期──> superseded
```

- `pending-capture`：占位条目，指纹字段必须为 `null`。门禁视为「无金标」。
- `captured`：已采集且复核通过，可参与门禁比对。
- `superseded`：目标客户端已升级，该金标不再代表当前版本，降级回 `recipe`。

---

## 6. 门禁怎么用这些数据

```
实测出站 ClientHello
      │
      ├─ 解析得 measuredJa3 / measuredJa4
      │
      ├─ 查 entries/<presetId>--<platform>.json
      │     status != "captured"        → alignment = recipe
      │     goldenJa3 == measuredJa3    → alignment = tool-matched | browser-matched（取 source）
      │     否则                         → alignment = recipe，并记录 mismatch
      │
      └─ ja3Parity = (alignment != recipe) && 真实 impersonate 栈已链接
```

JA4 为**软门禁**：先记录 `ja4Match`，允许 JA3 先行对齐、JA4 后续收敛
（JA4 对扩展顺序与版本串更敏感，见计划 §1.3）。

---

## 7. 复核清单

新增或更新一条金标时，提交里必须能回答：

- [ ] 采集环境写清楚了吗（客户端完整版本、OS、架构）？
- [ ] `source` 如实标注是真浏览器还是工具？
- [ ] `clientHelloHex` 在场，可供日后重算？
- [ ] `capturedAt` 是真实采集日期？
- [ ] 若是 Android/iOS，确认**没有**复用桌面金标？
- [ ] 若目标栈不是 BoringSSL（如 iOS Safari、Firefox），`stack` 是否如实填写？
