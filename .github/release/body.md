## 0.4.19 更新

- **修复 Chrome 151 JA4 不一致（#10）。** 出站 ClientHello 现在包含 ML-DSA `0x0904/0905/0906`，JA4 从 `...d8a2da3f94cd` 更新为与真实 Chrome 151 一致的 `t13d1516h2_8daaf6152771_806a8c22fdea`。
- **HTTP/2 指纹保持不变。** SETTINGS、连接窗口与伪头顺序继续为 `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`。
- **SSE 和大请求不再被整包缓冲。** wreq 路径现在流式转发请求体和响应体，首个 SSE 事件可在源站关闭前到达。
- **wreq 出站完整遵守上游代理。** HTTP、HTTPS、SOCKS5（远程 DNS）、认证和直连域名规则均走统一产品路径。
- **Cloudflare 重试更稳健。** 先确认正式 impersonate 能力再关闭页面 Hook；重启失败会恢复原 Hook 状态。

正式包仍固定启用逐字节 Chrome 出站，无需额外开关。遇到真人验证时保持抓包，点「关闭 Hook 并重试」后手动完成验证。

## 安装

| 平台 | 文件 |
|------|------|
| macOS (Apple Silicon) | `ShowNet_{{VERSION}}_aarch64.dmg` |
| Windows (x64) | `ShowNetPortable_{{VERSION}}_windows_x86_64.zip` |

### 首次打开会被系统拦截，这是正常的

本次发布**未经过商业代码签名**，所以 macOS Gatekeeper 和 Windows SmartScreen 会拦一次。这不代表包有问题，只代表它没有付费证书背书 —— 但也正因如此，请先用下方附件 `SHA256SUMS.txt` 核对校验和再运行。

### 怎么核对校验和

只挑你下载的那一个文件，在下载目录里执行：

```bash
# macOS
grep ShowNet_{{VERSION}}_aarch64.dmg SHA256SUMS.txt | shasum -a 256 -c -
# Linux 上把 shasum -a 256 换成 sha256sum
```

```powershell
# Windows（PowerShell）
(Get-FileHash ShowNetPortable_{{VERSION}}_windows_x86_64.zip -Algorithm SHA256).Hash
# 与 SHA256SUMS.txt 里对应那行比对（大小写不敏感）
```

不要直接 `shasum -a 256 -c SHA256SUMS.txt`：那份清单列出了两个平台的全部附件，只下载其中一个的话，其余几行会报 `FAILED open or read`，看着像出了问题，其实只是文件不在本地。

**macOS**

拖进「应用程序」后，**右键点 ShowNet.app → 打开**，在弹窗里再点一次「打开」。只需做一次。直接双击是不行的 —— 那个弹窗没有「仍要打开」按钮。

若提示「已损坏，无法打开」，是隔离标记造成的：

```bash
xattr -dr com.apple.quarantine /Applications/ShowNet.app
```

**Windows**

解压后运行 `ShowNetPortable.exe`，SmartScreen 弹窗点**「更多信息」→「仍要运行」**。便携版不写注册表，删除目录即完全卸载。

### 附件里的两份 `release-verification-*.json`

它们记录构建产物**实测**的签名状态，不是构建流程的声明 —— macOS 那份来自挂载 DMG 后对 `ShowNet.app` 跑 `codesign`，Windows 那份来自对打包内每个可执行文件跑 `Get-AuthenticodeSignature`。当前应为 `"mode": "ad-hoc"` 与 `NotSigned`，与上文「未经过商业代码签名」一致。

想自己复核 macOS 这份：

```bash
hdiutil attach ShowNet_{{VERSION}}_aarch64.dmg
codesign -dv --verbose=2 /Volumes/ShowNet/ShowNet.app
```

---
