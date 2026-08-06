## 安装

| 平台 | 文件 |
|------|------|
| macOS (Apple Silicon) | `ShowNet_{{VERSION}}_aarch64.dmg` |
| Windows (x64) | `ShowNetPortable_{{VERSION}}_windows_x86_64.zip` |

### 首次打开会被系统拦截，这是正常的

本次发布**未经过商业代码签名**，所以 macOS Gatekeeper 和 Windows SmartScreen 会拦一次。这不代表包有问题，只代表它没有付费证书背书 —— 但也正因如此，请先用下方附件 `SHA256SUMS.txt` 核对校验和再运行。

**macOS**

拖进「应用程序」后，**右键点 ShowNet.app → 打开**，在弹窗里再点一次「打开」。只需做一次。直接双击是不行的 —— 那个弹窗没有「仍要打开」按钮。

若提示「已损坏，无法打开」，是隔离标记造成的：

```bash
xattr -dr com.apple.quarantine /Applications/ShowNet.app
```

**Windows**

解压后运行 `ShowNetPortable.exe`，SmartScreen 弹窗点**「更多信息」→「仍要运行」**。便携版不写注册表，删除目录即完全卸载。

---
