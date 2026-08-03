# ShowNet 功能全景与工作流

本文盘点产品前后端能力、前后关系与自动化边界，便于开箱使用与二次开发。实现以仓库源码为准。

## 1. 一句话定位

**AI 原生抓包 + 自动证书 + 自动协议逆向 + 一键生成可运行代码。**  
设计原则：能自动化的默认自动化；小白有零配置路径；专家可进高级控制台与 Skill。

## 2. 推荐工作流（抓包 → 证据 → 分析 → 导出）

| 阶段 | 用户做什么 | 产品自动做什么 | 主入口 |
|------|------------|----------------|--------|
| **1 抓包** | 内嵌浏览器开始抓包；或装 CA 后代理手机/App | 会话持久化、MITM 解密、Hook 注入、出站 TLS 预置 | 浏览器 / 设置 / 高级控制台「配置」 |
| **2 证据** | 在流量点开请求 | 关联 Hook、AST 加密片段、TLS 指纹、PX/reCAPTCHA 标记 | 流量 / 高级控制台 |
| **3 分析** | 选模式启动 AI 分析 | Skill 编排、MCP 取证、Graph 阶段、可审计报告 | AI 分析 |
| **4 导出** | 确认报告 / Lab 生成 | 算法重放包、多语言客户端、Auto-crawler、集合导入导出 | 报告 / Request Lab / Skill |

零配置最短路径：**浏览器「开始抓包」→ 看流量 → AI 分析 → 导出代码**（无需先装 CA）。

## 3. 前端视图盘点

| 视图 | 职责 | 与其它模块关系 |
|------|------|----------------|
| **流量 Traffic** | 会话请求列表、筛选、详情、指纹/Hook/代码 tab | 启动 Lab / AI 分析 / 连接来源；空态引导零配置浏览器 |
| **内嵌浏览器 Browser** | 隔离 Chrome、开始抓包、Hook 面板 | 证据写入当前会话；加密 Lab 可送分析 |
| **AI 分析 Analysis** | 模式选择、Agent 进度、报告、工具轨迹 | 只读会话 + MCP；导出算法包 |
| **请求实验室 Lab** | 重放、规则、代码生成、集合 | 从流量多选进入；规则与 PX 改写衔接 |
| **高级控制台 Advanced** | 阶段引导、TLS 预置、PX、指纹、能力分工表 | 跳转流量/浏览器/设置/分析；Agent 读证工具同源 |
| **设置 Settings** | 代理端口、CA 安装、TLS 拦截、AI、MCP、设备引导 | 抓包前置条件 |
| **Skills** | 内置 Skill 契约预览 | 与分析规划一致 |

## 4. 后端 / 代理能力盘点

| 模块 | 能力 | 自动化 |
|------|------|--------|
| **MITM 代理** | HTTP/1.1·H2、CONNECT 隧道、系统代理可选接管与恢复 | 启动即监听默认 `127.0.0.1:8888` |
| **Root CA** | 每安装独立 CA、本机安装、导出、设备扫码页 | 一键安装；Android 可推送证书与代理 |
| **出站 TLS** | 版本化 ClientHello 预置（rustls）、入站自动选档 | 握手按预置改配方；**不宣称**位级浏览器 JA3 |
| **TLS 指纹** | 入站 JA3/JA4、出站说明 | 会话记录；Agent `shownet_get_tls_fingerprints` |
| **浏览器 Hook** | 脚本前注入网络/加解密 Hook | 与请求按序关联 |
| **AST 加密提取** | Web Crypto / CryptoJS / 国密 SM 等有界片段 | 响应解析自动写入 |
| **PX 控制台** | 解密开关、ecData 拦截、证据列表、结构解码 | 开关影响抓包标记；解码非硬破 |
| **动态防护分析** | WAF/captcha/sensor 聚合、scorecard | Skill 自动启用 |
| **算法重放 / Auto-crawler** | 多语言模板与离线校验 | 分析后导出 |
| **MCP / Agent** | 本地工具 + 可选外部 MCP、grok-build sidecar | 规划后按需调用只读工具 |

## 5. 抓包过程 vs 分析过程（能力分工）

机读表见 `src/advancedConsoleCapabilities.ts`（UI 总览与测试共用）。

**抓包过程（配置与采集）**

- 出站 ClientHello 预置 / 入站自动选档  
- PX 解密、拦截 ecData  
- 浏览器 Hook 注入、代理会话写入  
- TLS 指纹与 PX 证据落库  

**分析过程（只读取证与导出）**

- `shownet_get_tls_fingerprints`、`shownet_get_outbound_tls_status`  
- `shownet_list_px_evidence`、`shownet_decode_px_payload`  
- `shownet_analyze_dynamic_protection`、scorecard、harness  
- Hook / crypto snippets / algorithm replay / code generate  

## 6. 诚实边界（产品与 Agent 文案一致）

- 出站引擎默认 **rustls**；`ja3Parity` / `supportsFullBrowserJa3` 为 false，除非未来接入实测通过的 impersonate 栈。  
- PX / challenge 解码是**结构解析**，不是无密钥硬破。  
- 证书锁定 App 通常只能采连接元数据。  
- Agent 默认**只读取证**；改预置 / PX 开关由用户在 UI 操作。

## 7. 最佳实践清单

1. 先用内嵌浏览器验证产品是否工作，再装 CA 抓 App。  
2. 出站预置优先 `chrome150` 等版本化 id；观察指纹页 `ja3Parity`。  
3. 有 Hook 或加密片段时用 **JS 加密逆向**；有 WAF/captcha 用自动模式让 dynamic-signature 入选。  
4. 报告中的发现点回请求核对后再导出算法包。  
5. 高级控制台按阶段使用，避免空会话上空调参数。

## 8. 相关文档

- [ClientHello 与高级控制台](./clienthello-catalog-and-mitm-console.md)  
- [Skill / Graph / MCP 架构](./skill-graph-mcp-agent-architecture.md)  
- [证书 onboarding 实现](./certificate-onboarding-implementation.md)  
- [发布与本地构建](./release.md) / [local-release-0.1.0-build.md](./local-release-0.1.0-build.md)  
