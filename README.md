<p align="center">
  <img src="docs/assets/brand/shownet-app-icon-readme.png" alt="ShowNet" width="96" height="96" />
</p>

<h1 align="center">ShowNet</h1>

<p align="center">
  <strong>简体中文</strong> · <a href="./README.en.md">English</a>
</p>

<blockquote>
<p><strong>For international readers.</strong> Login works in a normal browser, then dies the moment you capture? Requests show up, but replay never lands? ShowNet keeps traffic, certificates, TLS fingerprints, and AI analysis on one local path so the protocol actually runs.</p>
<p>This page is the Chinese homepage. Please read the <a href="./README.en.md"><strong>English README</strong></a> for the full product story, setup path, and honesty bounds.</p>
</blockquote>

<p align="center">系统浏览器能登、一开抓包就失败？请求看得见、重放发不出去？<br />ShowNet 把流量、证书、指纹和 AI 分析收进同一条本地链路，帮你把协议真正跑通。</p>

<p align="center">
  <a href="https://github.com/suifei/shownet/releases/latest">下载</a> ·
  <a href="#十分钟上手">上手</a> ·
  <a href="#ai-端点与支持">AI 端点</a> ·
  <a href="#联系">QQ 群</a>
</p>

<p align="center">
  <img src="docs/assets/readme/ui-traffic.jpg" alt="ShowNet 实时流量" width="920" />
</p>

当前发布版：[v0.4.31](https://github.com/suifei/shownet/releases/tag/v0.4.31)。更细的能力边界见 [功能全景](docs/feature-map.md)。

## 它解决什么

抓包工具很多。痛点通常不在「能不能看见一条 HTTP」，而在看见之后还是还原不了。

- **登录在系统浏览器里好好的，套上代理就掉线。** 源站看的是 TLS 指纹、Cookie 是否被拆碎、语言头是否重复、出站是不是还带着无头痕迹。ShowNet 用内嵌 Chrome + MITM + 与 Chrome 对齐的出站握手，把这些一起落进同一个会话。
- **列表里有请求，自己重放永远 403。** 签名往往在页面脚本里现算：时间戳、挑战码、HMAC、国密。ShowNet 可以按请求顺序留下 Hook 与代码片段，再让 AI 只根据这份证据写出可复查的步骤。
- **手机 App 只能看到 CONNECT，看不到正文。** 本机一键装 CA，或让设备扫码装证并指向代理；证书锁定的 App 仍然只能看到元数据——产品不会假装能解开它。
- **分析完了还是得手抄客户端。** 从已证实的请求生成算法重放包和调用代码；没证实的部分会写进缺口，而不是编一段「看起来能跑」的签名。

产品原则很短：**开箱能抓、证据能回看、结论能复现。** 不关 TLS 解密，不加站点白名单，也不把配置里的 JA4 目标说成「这次握手已经一致」。

<p align="center">
  <img src="docs/assets/readme/hero-workspace.jpg" alt="本地工作台上的会话分析（场景示意）" width="920" />
</p>

## 真实场景

下面用「某某网站 / 某某 App」说话，只谈技术点，不点名具体站点。本节配图是场景示意，不是产品截图；对应界面见 [十分钟上手](#十分钟上手)。

### 1. 某某网站：扫码登录成功，回跳后又回到登录页

**技术点：** HTTP/2 下 Cookie 被拆成多条头、出站 JA4 与浏览器不一致、`Accept-Language` 带重复权重、页面 Hook 改写了 `fetch` / SubtleCrypto。

**你遇到的痛：** 系统浏览器一次通过，抓包会话里挑战码过了、Cookie 却丢了，或者源站直接拒绝握手。

**ShowNet 怎么收：** 默认不注入页面 Hook；Cookie 碎屑会合后再发给源站；正式包装了与 Chrome 对齐的出站。指纹面板只在**测到当次连接**时才说匹配，不会把预置目标当成证据。

<img src="docs/assets/readme/scenario-login-split.jpg" alt="同一会话在系统浏览器成功、在抓包链路断开（场景示意）" width="920" />

### 2. 某某 App：电脑抓得到元数据，手机 HTTPS 全是乱码或空白

**技术点：** 设备不信任本地 Root CA、代理没指到 `8888`、App 做了证书锁定。

**你遇到的痛：** 只能看到 CONNECT，看不到 JSON；或者装了别人的证书，私钥散落在桌面。

**ShowNet 怎么收：** 每份安装自带独立 Root CA，私钥加密存在本地库。本机一键写入系统信任库；手机扫码页同时给证书和 Wi‑Fi 代理参数。Android 可从电脑推用户证书，**无需 Root**。证书锁定的 App 只采元数据，不会伪造成功解密。

<img src="docs/assets/readme/scenario-device-ca.jpg" alt="手机与电脑通过本地证书连在同一条抓包链路上（场景示意）" width="920" />

### 3. 某某接口：请求体看懂了，签名永远对不上

**技术点：** 动态 `sign` / `token`、Web Crypto、CryptoJS、SM 系列、挑战脚本。字段每次变，HAR 导出去也不能用。

**你遇到的痛：** 抄了 Header 再发，源站说非法签名；不知道哪一步用了响应里的挑战码。

**ShowNet 怎么收：** 需要时再打开 JS Hook，把加解密调用和代理请求按时间对齐。AI 分析只读当前会话，报告必须链回 `#序号` 请求。算法重放只写入**用抓包真值跑通**的步骤；识别到但没复现的只列名。

<img src="docs/assets/readme/scenario-signature.jpg" alt="签名链路里的密钥与摘要节点（场景示意）" width="920" />

### 4. 某某后台：抓了一下午，还要手写一套客户端

**技术点：** 同一资源不同 ID、登录响应里的 token 后续被带上、gzip/br 正文、多语言调用。

**你遇到的痛：** 导出的是一堆 URL，不是 `get_user(id)`；凭据一写进仓库就泄漏，不写进去又调不通。

**ShowNet 怎么收：** 把样本收成端点，抓到的凭据变成构造函数参数，而不是写死的密钥。能推出登录链路就生成 `authenticate_*()`。缺口进 `GAPS.md`。Request Lab 还可直接生成 Python / JS / Go / cURL。

<img src="docs/assets/readme/scenario-to-code.jpg" alt="会话证据整理成可调用的客户端草稿（场景示意）" width="920" />

## 十分钟上手

按顺序做。**第 1 步不装证书也能看到流量。**

### 1. 零配置：内嵌浏览器开始抓包（不必先装证书）

打开应用 → **内嵌浏览器** → **开始抓包** → 访问目标页。请求进当前会话，列表立刻可点。默认不装页面 Hook，登录和支付走 Chrome 原生 API。

<img src="docs/assets/readme/ui-browser.jpg" alt="内嵌浏览器开始抓包" width="920" />

### 2. 要解密 App / 系统 HTTPS 时，再安装 CA

设置里「安装 CA」写入本机信任库；手机用扫码页。代理入口默认 `127.0.0.1:8888`。失败可导出 DER/PEM 手动装。

<img src="docs/assets/readme/ui-settings.jpg" alt="本机 Root CA 一键安装与解密策略" width="920" />

### 3. 用 AI 把会话说清楚

选自动 / API / 安全 / 性能 / JS 加密等模式。Agent 只读本会话。失败时会展示模型返回的错误码（而不是只显示 502），也可以改上次提示词重试或换本地模型。

<p align="center">
  <img src="docs/assets/readme/ui-analysis-start.jpg" alt="选择分析模式并开始" width="920" />
</p>

下面 7 帧是真实软件里「选模式 → 出报告 → Graph / Skill / 控制台 / 实验室 / 流量」走一遍（循环播放）：

<p align="center">
  <img src="docs/assets/readme/ui-analysis-flow.webp" alt="从分析到报告的七帧界面" width="920" />
</p>

<p align="center">
  <img src="docs/assets/readme/ui-analysis-report.jpg" alt="已完成的 API 逆向报告" width="920" />
</p>

<p align="center">
  <img src="docs/assets/readme/ui-analysis-graph.jpg" alt="真实分析报告：Phase、Graph 与 Agent 轨迹" width="920" />
</p>

### 4. 从报告导出算法重放或客户端代码

分析报告可导出算法重放包；流量或集合可进 Request Lab 生成代码。没证实的步骤会标出来。

<img src="docs/assets/readme/ui-lab.jpg" alt="请求实验室：从抓包构建、重放与生成代码" width="920" />

更完整的功能关系：[功能全景与工作流](docs/feature-map.md)。TLS 预置与控制台：[ClientHello 文档](docs/clienthello-catalog-and-mitm-console.md)。

## 安装

从 [Releases](https://github.com/suifei/shownet/releases/latest) 下载：

| 平台 | 文件 |
|------|------|
| macOS (Apple Silicon) | `ShowNet_<版本>_aarch64.dmg` |
| Windows (x64) | `ShowNetPortable_<版本>_windows_x86_64.zip` |

当前发布包**未经过商业代码签名**，首次打开会被系统拦一次。先核对附件 `SHA256SUMS.txt`。

```bash
# macOS / Linux
grep ShowNet_<版本>_aarch64.dmg SHA256SUMS.txt | shasum -a 256 -c -
```

```powershell
# Windows
(Get-FileHash ShowNetPortable_<版本>_windows_x86_64.zip -Algorithm SHA256).Hash
```

**macOS：** 拖进「应用程序」后，**右键 ShowNet.app → 打开**，再点一次「打开」。若提示已损坏：

```bash
xattr -dr com.apple.quarantine /Applications/ShowNet.app
```

**Windows：** 运行 `ShowNetPortable.exe`，SmartScreen 选「更多信息」→「仍要运行」。便携版不写注册表。

## AI 端点与支持

分析要用一个 OpenAI 兼容端点。应用内推荐：

| 项 | 值 |
|----|----|
| 服务 | [ClaudeGPT](https://claudegpt.org/)（OpenAI 兼容） |
| Base URL | `https://claudegpt.org/v1` |
| 默认模型 | `gpt-5.5` |
| 免费额度 | 加群后联系管理员，申请一次性 5 美金 |

也可以改成其他兼容厂商，或本地 `http://127.0.0.1:11434/v1`（Ollama / LM Studio）。API Key 加密保存在本机。

**系统 Grok（可选）。** ShowNet 不捆绑 Grok。设置 → AI 模型 → Agent 运行时：先刷新探测；没有再用官方安装器。

| 平台 | 官方安装器 | 默认位置 |
|------|------------|----------|
| macOS / Linux | [install.sh](https://x.ai/cli/install.sh) | `~/.grok/bin/grok` |
| Windows | [install.ps1](https://x.ai/cli/install.ps1) | `%USERPROFILE%\.grok\bin\grok.exe` |

安装默认直连。只有直连失败才去「出口代理与 TLS 指纹」里配置 **ShowNet 出口代理**（和抓包口 `8888`、系统 `HTTP_PROXY` 不是一回事）。Windows 官方安装器不支持 SOCKS5。ShowNet 的端点、Key、Skill、MCP 只注入这次 Agent 进程，不改 Grok 的全局配置。

## 联系

免费额度与使用问题进 QQ 群 **553354813**，加群后联系管理员。

<p>
  <img src="src/assets/qq-group-fridare.jpg" alt="QQ 群 553354813 二维码" width="240" />
</p>

服务站：[claudegpt.org](https://claudegpt.org/)

## 教程视频

<table>
  <tr>
    <td width="50%" valign="top">
      <a href="docs/assets/tutorial/ShowNet-真实操作新手教程-B站横版.mp4">
        <img src="docs/assets/readme/ui-analysis-report.jpg" alt="横版教程预览" width="100%" />
      </a>
      <br />
      <strong>横版教程</strong><br />
      <a href="docs/assets/tutorial/ShowNet-真实操作新手教程-B站横版.mp4">播放 MP4</a> ·
      <a href="docs/assets/tutorial/ShowNet-真实操作新手教程.srt">中文字幕</a>
    </td>
    <td width="50%" valign="top">
      <a href="docs/assets/tutorial/ShowNet-真实操作新手教程-小红书竖版.mp4">
        <img src="docs/assets/readme/ui-advanced.jpg" alt="竖版教程预览" width="100%" />
      </a>
      <br />
      <strong>竖版教程</strong><br />
      <a href="docs/assets/tutorial/ShowNet-真实操作新手教程-小红书竖版.mp4">播放 MP4</a> ·
      <a href="docs/assets/tutorial/ShowNet-真实操作新手教程.srt">中文字幕</a>
    </td>
  </tr>
</table>

## 开发

```bash
npm install
npm run dev
npm run build
npm run tauri dev
```

网络相关集成测试默认 ignore：`npm run test:rust:network`。

## 诚实边界

- 正式包出站走 wreq Chrome 配置；**不宣称**位级浏览器 JA3 克隆。JA3 含 GREASE，一次加载就会量到多个不同 JA3，比对用 JA4。
- WebSocket 出站握手走与 HTTPS 同一套 wreq Chrome TLS；Upgrade 由 wreq 的 websocket 构建器完成，帧仍由 ShowNet 转发并落库。不宣称位级 JA3 克隆。
- 证书锁定、TUN 透明导流、商店级签名安装包仍是后续项。

## License

Copyright (C) 2026 ShowNet contributors.

ShowNet is free software licensed under the [GNU General Public License version 3](LICENSE) (`GPL-3.0-only`). Optional Agent notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
