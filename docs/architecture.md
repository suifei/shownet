# ShowNet Architecture

## 1. Capture strategy

The default path is an explicit local proxy backed by a local certificate authority. TUN is an optional routing layer, not a TLS decoder.

```text
Embedded browser ── CDP events ─────────────────────┐
                                                    │
Desktop / CLI / scripts ── system or manual proxy ──┼── Normalize ── Session
                                                    │
Mobile / IoT ── Wi-Fi or gateway proxy ─────────────┤
                                                    │
Non-proxy-aware apps ── optional TUN redirect ── MITM proxy
                                                    │
                                                    └── direct / HTTP(S) / SOCKS5 egress ── target
```

### HTTPS

- ShowNet generates one root CA per installation. By product decision, its private key is encrypted in SQLite with the embedded application key; ShowNet does not use macOS Keychain or Windows Credential Manager.
- The user explicitly installs the public root certificate into the system or test-device trust store.
- The MITM layer generates and caches leaf certificates per hostname.
- TLS 1.2/1.3 is terminated locally, then a separate verified TLS connection is opened upstream.
- HTTP/1.1 and HTTP/2 request/response streams, streaming responses, and compressed bodies are normalized before persistence. The inbound HTTP/2 connection is decoded after ALPN negotiation and translated onto the existing verified HTTP/1.1 upstream transport, so CONNECT remains an HTTP/1.1 record while inner application records are marked `h2`.
- Classic HTTP/1.1 WebSocket upgrades and RFC 8441 extended CONNECT streams are terminated on both sides so messages can be relayed and recorded in order. For RFC 8441, ShowNet advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`, translates the inbound `CONNECT + :protocol=websocket` request to a verified upstream HTTP/1.1 WebSocket handshake, and translates the accepted `101` back to an HTTP/2 `200` tunnel. The Session record retains `h2`, `CONNECT`, and `:protocol=websocket` evidence. Extension negotiation is removed to avoid forwarding compressed RSV frames without a negotiated decoder; subprotocol negotiation is preserved. Message storage is bounded independently from forwarding.
- Private keys, authorization headers, cookies, and bodies are redacted before model transmission according to policy.

### TUN

TUN mode captures connection routing for processes that ignore proxy configuration. It redirects eligible TCP flows to the same MITM proxy. It does not make pinned TLS decryptable and should not be the default because it needs elevated OS permissions, adds routing complexity, and has a larger failure surface.

TUN is not implemented in the current native build. The renderer hides transparent mode until the native runtime reports a supported driver, so users only see capture paths that can actually be used. Current paths are isolated proxy Chrome, opt-in system proxy, manual HTTP(S) proxy configuration, environment variables, code-level proxy settings, and device Wi-Fi/gateway proxy settings.

### Certificate pinning

When a client pins its server certificate, ShowNet records destination, SNI, ALPN, bytes, timing, and failure state. Content decryption requires authorized client instrumentation or a test build with pinning disabled. The UI must never claim that TUN bypasses pinning.

### TLS and HTTP fingerprints

Fingerprinting is split by TLS direction because an HTTPS MITM creates two independent handshakes:

- Inbound client observation records JA3, JA4, SNI, ALPN, offered TLS versions, cipher suites, extensions, supported groups, signature algorithms, and GREASE presence from the original ClientHello.
- In blind CONNECT tunnel mode the ClientHello is forwarded unchanged, so the target observes the original client fingerprint.
- In MITM mode the target observes ShowNet's outbound TLS profile. A normal rustls connection cannot inherit an arbitrary client JA3, and the product must never claim otherwise.
- Outbound emulation is a separate, explicit feature. Browser/device presets may target Chrome, Firefox, and iOS TLS behavior, but every preset must expose its engine and fidelity limits.
- **Versioned ClientHello catalog** (product path): presets such as `chrome150` reorder rustls cipher/kx/ALPN for measurable outbound differences. Default active preset is `chrome150`. Full browser JA3 parity requires a real impersonate stack and remains disabled under rustls-only. UI: Settings + Advanced console. Details: [clienthello-catalog-and-mitm-console.md](./clienthello-catalog-and-mitm-console.md).
- Server-side analysis records JA3S and negotiated TLS parameters independently from the client fingerprint.
- HTTP/2 application decoding is independent from HTTP/2 fingerprinting. ShowNet observes the decrypted inbound connection without modifying it and records, in wire order before the first HEADERS frame, client SETTINGS, connection WINDOW_UPDATE, legacy PRIORITY, and RFC 9218 PRIORITY_UPDATE frames. A version-stable canonical string and SHA-256 hash retain these inputs separately from JA3/JA4. Hyper does not expose HPACK blocks before normalization, so pseudo-header order remains explicitly unavailable and is excluded from the hash; ShowNet does not present this partial evidence as a complete Akamai fingerprint.

GREASE values are retained in raw metadata for inspection but excluded where the JA3/JA4 specifications require normalization. Fingerprint algorithm versions and raw canonical strings are stored alongside hashes so results remain auditable after algorithm updates.

### Upstream egress proxy

- Direct, HTTP, HTTPS, and SOCKS5 routes are selected before each capture run.
- HTTP and HTTPS upstreams use authenticated CONNECT tunnels. SOCKS5 supports no-auth and username/password negotiation.
- `localhost`, loopback IPs, configured bypass patterns, and ShowNet's own port `8888` listener are protected from proxy loops.
- Capture binds `127.0.0.1:8888` by default. The persisted LAN setting is explicit and locked while capture runs; when enabled, capture binds `0.0.0.0:8888` but accepts only loopback, RFC1918/private, and link-local peers. Runtime status advertises only detected private/link-local IPv4 addresses.
- The device QR encodes `http://<detected-private-ip>:8888/device`. That local page serves the public Root CA in DER or PEM form and the matching Wi-Fi proxy parameters. Requests are handled internally rather than persisted as capture evidence. Host isolation requires the requested address and port to equal the accepted socket's own local address, preventing unrelated private `:8888` traffic from being intercepted as onboarding.
- Upstream failures are surfaced separately from target failures.
- The upstream password is AES-256-GCM encrypted with a random nonce and stored in SQLite. The key is embedded in the application by product decision, so this prevents casual plaintext database inspection but does not protect against binary reverse engineering.

## 2. Native module boundaries

```text
src-tauri/src/
  capture/       source adapters and normalized CaptureEvent channel
  proxy/         listener, CONNECT, direct/HTTP(S)/SOCKS5 upstream transport
  ca/            root CA, leaf certificate cache, OS trust installation
  cdp/           browser tabs, Network domain, Runtime injection, screenshots
  session/       lifecycle, event ordering, source membership
  storage/       SQLite repositories, bodies, migrations, retention
  hooks/         fetch/XHR/crypto/storage/interaction event correlation
  analysis/      assembly, filtering, prompts, LLM routing, streaming
  skills/        built-in and user-installed Skill registry and executor
  mcp/           ShowNet MCP server and external MCP client manager
  commands/      narrow Tauri command facade for the renderer
```

The renderer never owns capture state. It subscribes to events and invokes commands; native services own lifecycle, persistence, secrets, ports, and elevated operations.

The source onboarding panel derives every local or private-LAN endpoint from native runtime status. Browser traffic opens the isolated CDP workspace, desktop applications can use the opt-in system proxy or copy the explicit listener, terminal clients receive platform-specific environment variables, and script clients receive Python, Node.js, or Go proxy templates. Mobile and IoT addresses are shown only after private-LAN access is explicitly enabled; a detected interface address alone never implies that the listener is externally reachable.

## 3. Unified Session model

Every source adapter emits the same envelope:

```ts
type CaptureEvent = {
  sessionId: string
  source: "browser" | "desktop" | "terminal" | "script" | "mobile" | "iot"
  sourceInstanceId: string
  requestId: string
  sequence: number
  timestamp: number
  phase: "request" | "response" | "websocket" | "hook" | "interaction" | "storage" | "connection"
  payload: unknown
}
```

The persistence layer assigns monotonically increasing Session sequence numbers. Correlation uses request ID first, then URL/method/time windows for browser Hook events that do not expose a network request ID.

Recommended tables:

- `sessions`
- `source_instances`
- `requests`
- `response_bodies`
- `websocket_frames`
- `js_hooks`
- `interaction_events`
- `storage_snapshots`
- `analysis_reports`
- `ai_request_logs`
- `skill_runs`

Large and binary response bodies are stored as content-addressed files; SQLite keeps metadata and hashes. Each response records truncation and decoding state.

### Response body normalization

The HTTP and HTTPS paths share the same streaming body tap. The original frames and headers are forwarded to the client unchanged while ShowNet keeps a bounded side copy for persistence and analysis. The wire copy is capped at 2 MiB and decoded output at 4 MiB, preventing unbounded memory growth and compression bombs. `gzip`, Brotli, zlib/raw `deflate`, `zstd`, and stacked `Content-Encoding` values are decoded in reverse order. Unsupported, incomplete, or still-encoded payloads are retained as Base64 rather than lossy text.

Each stored response records the content encoding, wire and decoded byte counts, completeness, truncation, output format, and decode error. The request inspector, `.shownet` archive, HAR extension metadata, built-in Agent evidence, and MCP request detail expose the same state. HAR binary content uses the standard `encoding: base64` representation.

### Static JavaScript crypto extraction

Captured JavaScript responses are parsed with Tree-sitter instead of line-based regular expressions. The extractor identifies Web Crypto, CryptoJS, AES/DES/3DES, RSA, HMAC, SHA, MD5, PBKDF2, RC4, Rabbit, SM2/3/4, and dynamic-signature/Akamai sensor evidence, then selects non-overlapping function, method, or lexical candidates with source line metadata.

Extraction is bounded before persistence: at most 4 MiB of one script is parsed, at most 24 snippets are retained, each snippet is capped at 12 KiB, the aggregate snippet budget is 96 KiB, and any individual AST candidate scan is capped at 256 KiB. The request list exposes only the snippet count; full snippets are loaded on demand in the request inspector. `.shownet` archives preserve the original snippets and restore them when reopened.

SQLite retains captured source and extracted snippets locally. Before code is included in initial Agent evidence or returned through `shownet_get_crypto_snippets`, AST-aware redaction replaces values assigned to sensitive names such as API keys, tokens, passwords, and private keys. The crypto-reverse and dynamic-signature Skills can request the same bounded, redacted evidence through the shared Agent/MCP tool implementation.

## 4. Browser capture and Hooks

The current browser workspace launches an isolated headless Chrome process with a fresh per-launch incognito profile, `--proxy-server=127.0.0.1:8888`, and a random loopback CDP port. Browser-vendor account, update, safe-browsing, and push service traffic is disabled for this disposable capture process so it does not pollute the user's Session; direct navigation to Google, OAuth, or other sites remains available. The renderer attaches to that target, installs the native binding and Hook runtime with `Page.addScriptToEvaluateOnNewDocument`, starts `Page.startScreencast`, and renders acknowledged frames inside the ShowNet window. Workspace resize, pointer, wheel, and keyboard input are forwarded through CDP Emulation/Input commands. Network payloads still come from the common MITM proxy, so browser and external traffic share the same Session sequence. The profile is deleted when the browser stops. This surface is frame-stream based rather than a platform-native child webview. ShowNet therefore bridges native application edit accelerators and the Tauri text clipboard into CDP selection and `Input.insertText` operations; a hidden WebKit composition target commits IME text through the same CDP path. Native accessibility semantics and drag-and-drop parity still require separate adapters.

### Unified Browser execution bus (dual path)

Discrete browser commands share one native owner path so Agent, MCP, and UI do not each open long-lived CDP clients:

```text
UI (screencast + high-freq pointer/keyboard)
  └── long-lived CDP WebSocket  ── Page.startScreencast / Input.* stream

Agent / MCP / UI discrete commands
  └── Tauri browser_* ── BrowserBus (short-lived CDP call) ── same page target
```

| Path | Owner | Use |
|------|--------|-----|
| UI CDP WebSocket | `BrowserView` | Screencast frames, continuous pointer/wheel/key, IME `insertText`, Hook bindings |
| Browser bus | `browser_bus.rs` via `browser_*` / `shownet_browser_*` | Navigate, reload (evaluate), one-shot evaluate/click/screenshot, install risk Lab |

Rules:

- Agent never owns a parallel long-lived CDP session; it calls `shownet_browser_*` tools that go through `BrowserBus`.
- UI prefers the bus for address-bar navigation, reload, Crypto Lab open, and **风控 Lab** install; falls back to its own CDP socket if the bus is unavailable.
- High-frequency input stays on the UI socket for latency; forcing every mouse move through short-lived bus calls would thrash connect/disconnect.
- Frontend wrappers live in `src/browserBus.ts`; statusbar shows bus readiness (`总线就绪` / last command note).

Initial Hook coverage:

- `window.fetch`
- `XMLHttpRequest`
- `WebSocket`
- `crypto.subtle.sign/digest/encrypt/decrypt/deriveKey`
- CryptoJS AES/DES/TripleDES/Rabbit/RC4, hashes, HMAC, PBKDF2, encoders
- JSEncrypt and node-forge surfaces exposed in the page
- SM2/SM3/SM4 common browser libraries
- `btoa`, `atob`, cookie writes, local/session storage
- clicks, form inputs, scrolls, and navigation

Hooks must preserve the original function's `this`, descriptor behavior, return type, error behavior, and observable `toString()` where practical. Arguments are bounded and redacted before storage.

The bundled Crypto Lab exercises SHA-256, AES-GCM, HMAC-SHA256, and an HTTPS `fetch` inside the isolated proxy Chrome. Its page reports `running`, `complete`, and `error` through a dedicated pre-document CDP binding; browser-only preview retains a same-origin `postMessage` fallback. The explicit `验证分析` action records the scenario in the current Session, waits for completion, refreshes persisted requests, switches to JavaScript crypto mode, includes static JavaScript evidence, and starts the configured built-in Agent. It always uses the user's saved provider/model settings and never embeds a test API credential.

## 5. Two-stage AI analysis

### Phase 1: relevance filter

- Skip filtering below 20 requests.
- Batch up to 100 request summaries per model call.
- Always keep errors, authentication, state-changing APIs, Hook-correlated requests, and manually selected items.
- Performance mode receives the full request set.
- Fall back to the full set if fewer than three valid requests are selected or filtering fails.

### Phase 2: focused analysis

The assembler provides selected requests, Hook records, extracted crypto code, storage state, interaction steps, scene hints, and an index of all requests. The agent receives a local `get_request_detail` tool so it can recover omitted bodies without placing the entire Session into the initial context.

Reports stream to the renderer and persist incrementally. Follow-up chat reuses a compacted report context and can call the same local and MCP tools.

## 6. Analysis modes and Skills

The five user-facing modes are orchestration presets, not five separate analyzers:

- Automatic scene recognition
- API reverse engineering
- Security audit
- Performance analysis
- JavaScript crypto reverse engineering

Built-in Skills provide professional judgment, suggested tools, and machine-checkable output contracts. They do not remove GrokBuild capabilities. Dynamic algorithm support is implemented as versioned adapters. An Akamai adapter, for example, detects sensor endpoints and runtime mutation points, captures deterministic inputs, and generates a replay harness. It must not ship a hard-coded promise that every vendor version can be reproduced.

Skill runs record inputs, outputs, tool calls, permissions, duration, and the exact Skill version used.

### Advisory Graph and Agent autonomy

The analysis Graph is an advisory route and an audit model, not an Agent sandbox. It records the suggested Skill sequence, actual dynamic branches, retries, tool calls, output-contract results, and final report gate. GrokBuild may change Skill order, revisit a completed area, create subagents, and use its default planning, file, terminal, web, memory, and other built-in capabilities when evidence warrants it. Unplanned tools are attached to a dynamic Agent branch instead of being rejected.

`maxAgentTurns` remains owned exclusively by GrokBuild. The exact user value is passed once through `--max-turns`; Graph nodes neither divide nor consume that allowance. The setting has no product ceiling beyond the serialized integer range. The native compatibility executor also gives each Skill node the complete configured allowance instead of partitioning it. A runtime watchdog scales linearly with the selected turn value, and explicit user cancellation remains available.

The sidecar runs with GrokBuild's default tool set, planning and subagents enabled, `bypassPermissions`, and no filesystem sandbox profile. Per-analysis temporary configuration still keeps API/MCP credentials out of files and is deleted after the run. This intentionally preserves full Agent capability; it is not a security boundary. ShowNet's own MCP write surface remains controlled by the user's MCP `allowWrites` setting, which is independent of Graph routing.

## 7. MCP boundary

ShowNet exposes a loopback-only Streamable HTTP MCP server, defaulting to `127.0.0.1:8899/mcp`. The implemented read-only surface contains fourteen tools:

- Runtime and sessions: `shownet_runtime_status`, `shownet_list_sessions`
- Traffic evidence: `shownet_list_requests`, `shownet_get_request`, `shownet_get_hooks`, `shownet_get_crypto_snippets`, `shownet_get_websocket_frames`, `shownet_get_tls_fingerprints`
- Agent outputs and audit: `shownet_get_report`, `shownet_get_skill_runs`, `shownet_generate_code`, `shownet_build_signature_harness`
- Skill discovery and planning: `shownet_list_skills`, `shownet_plan_analysis`

When the user explicitly enables writes, `shownet_create_session`, `shownet_delete_session`, and `shownet_run_analysis` are added. The server also exposes Session, runtime, and Skill resources, a per-Session report resource template, and five analysis prompts.

The GrokBuild sidecar calls ShowNet's own loopback MCP endpoint with a short-lived per-analysis token. That token exists for attribution and expires when the analysis execution ends; it exposes the same MCP surface selected by the user's server settings and does not apply Graph-specific tool filtering. Calls are attached to the current advisory Graph for audit. A short per-analysis lock serializes only Graph JSON updates, so concurrent subagents can execute tools without overwriting each other's traces. The server always requires a bearer token, accepts only local Origins, caps request bodies, and never binds beyond loopback.

ShowNet can also act as a Streamable HTTP MCP client. External Servers are absent by default and must be added and enabled explicitly. Each connection performs MCP initialization, preserves a returned session ID, supports JSON or SSE responses, and discovers at most 64 tools. Remote tools are exposed to the built-in Agent as stable `mcp__server__tool` names, schema-validated, capped, and kept separate from ShowNet's local tools. Local HTTP endpoints are allowed; remote endpoints require HTTPS. Optional bearer tokens are AES-256-GCM encrypted in SQLite and are cleared when the endpoint changes unless a replacement is supplied. Connections honor ShowNet's direct/HTTP(S)/SOCKS5 egress routing and bypass rules. Calls record server/tool/status/timing without persisting arguments or results. External results carry `external_mcp` and `untrusted` markers, and Agent system prompts explicitly forbid treating their contents as instructions.

## 8. Session portability and request generation

- `.shownet` is the lossless portable Session format. Version 1 stores requests, response bodies, extracted crypto snippets, Hook records, connection events, TLS fingerprints, original timestamps, and Session sequence numbers as validated JSON.
- Opening a `.shownet` file creates a new idle Session with remapped request IDs while preserving event correlations. The importer rejects unknown versions, duplicate IDs/sequences, oversized files, and invalid event types.
- HAR 1.2 export targets browsers and traffic tools. Postman Collection 2.1 targets API testing workflows. OpenAPI 3.1 provides a generated starting specification and keeps per-operation server origins when a Session spans hosts.
- Exchange exports redact Authorization, Cookie, API key, and access-token headers by default. The user must explicitly opt into including them. A `.shownet` save is a complete local archive and therefore retains captured values.
- Request code generation covers cURL, HTTPie, Python requests, JavaScript fetch, Axios, and Go. It uses the exact captured URL, method, headers, and body while applying the same default redaction policy.

## 9. AI service entry

The renderer presents `https://claudegpt.org/v1` as the recommended OpenAI-compatible base URL and selects `gpt-5.5` as the default model. It discovers available models from the provider's `/models` endpoint and falls back to manual model-name entry when discovery is unavailable. New users may join QQ group `553354813` and contact an administrator to request one USD 5 promotional credit, then use the issued personal API key. No shared service secret is compiled into the desktop binary. The product surface calls the orchestration runtime only `内置 Agent`; provider and model identities remain separate settings. Other OpenAI-compatible vendors and local Ollama/LM Studio endpoints remain explicit alternatives. User API keys are never compiled into the application or prefilled in the renderer. Community support metadata and the QQ group QR image are product assets, separate from provider credentials.

## 10. Security and platform constraints

- Never send captured data to a model until provider, redaction policy, and Session scope are visible to the user.
- The product does not integrate with Keychain or Credential Manager. Local credentials use authenticated encryption in SQLite with an embedded application key; this is an explicit convenience tradeoff, not OS-backed secret protection.
- System-proxy takeover is opt-in and disabled by default. ShowNet snapshots macOS network services or Windows WinINet settings, encrypts the recovery record in SQLite before applying changes, restores it on stop/exit/startup recovery, and refuses to overwrite authenticated macOS proxy credentials that cannot be read back safely.
- Future TUN routing must use an equivalent crash-recovery journal before it is exposed as available.
- Bind proxy and MCP ports to loopback by default. LAN proxy mode is an explicit setting.
- Require privilege only for CA trust, system routing, or TUN setup; the main app runs unprivileged.
- Sign and notarize macOS builds; sign Windows builds and clearly surface driver requirements for optional TUN mode.

## 11. Delivery order

1. Session storage and real explicit HTTP proxy
2. Root CA lifecycle and HTTPS CONNECT interception
3. Unified proxy events in the renderer
4. Isolated proxy Chrome/CDP and pre-document Hook injection
5. Two-stage model pipeline and report persistence
6. ShowNet MCP server and external MCP clients
7. Optional transparent routing on macOS and Windows
8. Signed installers, recovery, updates, and end-to-end device tests

## 12. Current implementation evidence

- Implemented: SQLite Session persistence, ordered capture events, explicit HTTP proxy, opt-in private-LAN device listening, direct/HTTP/HTTPS/SOCKS5 egress, loop protection, encrypted upstream credentials, and portable Session/export formats.
- Verified: browser, desktop application, terminal, script, mobile, and IoT clients all traverse one live proxy instance and enter the same Session capture sink with their normalized source type.
- Implemented: per-installation Root CA persisted in SQLite with AES-256-GCM encrypted PKCS#8 material, cached per-host leaf certificates, verified upstream TLS, and HTTPS HTTP/1.1 request/response capture.
- Implemented: inbound ALPN negotiation for `h2`, Hyper HTTP/2 stream decoding, bounded request/response body capture, protocol-correct forbidden-header removal, and conversion onto the verified HTTP/1.1 upstream transport. Verified in memory and with the real embedded Chrome Crypto Lab against `https://httpbin.org/post`.
- Implemented: inbound ClientHello JA3/JA4 metadata with an explicit independent rustls outbound profile. ShowNet does not claim to preserve the client JA3 during MITM.
- Implemented: ordered inbound HTTP/2 SETTINGS, connection WINDOW_UPDATE, legacy PRIORITY and RFC 9218 PRIORITY_UPDATE observation with a stable SHA-256 evidence hash. Pseudo-header order remains explicitly unavailable because Hyper exposes requests after HPACK normalization.
- Verified: real HTTPS capture through local HTTP `127.0.0.1:7890` and SOCKS5 `127.0.0.1:7891` egress proxies.
- Implemented: isolated proxy Chrome lifecycle with fresh disposable profiles, random loopback CDP endpoint, in-window CDP Screencast rendering, pointer/keyboard forwarding, pre-document Hook injection, and Hook/request correlation in the common Session.
- Implemented: unified Browser execution bus (`browser_bus` / `browser_*` / `shownet_browser_*`) for discrete navigate/evaluate/click/screenshot/Lab install; UI keeps long-lived CDP only for screencast and high-frequency input.
- Implemented: Web 风控 Lab finishable path — `shownet_seed_web_risk_fixture` → `shownet_run_offline_lab_probe` (objectDump without browser); live `shownet_browser_install_lab` returns `objectDump`/`labState`; vision captcha via `shownet_solve_vision_captcha` (VLM or `dryRunIndices`) + index→click mapping.
- Implemented: native application edit accelerators plus least-privilege text clipboard permissions for copy, cut, paste, select-all, undo, and redo across both ShowNet inputs and the CDP frame-stream browser; IME composition commits through a hidden WebKit input target and CDP `Input.insertText`.
- Implemented: bundled Web Crypto validation Lab with native CDP status reporting and an explicit capture-to-Agent automation path using crypto mode and static JavaScript evidence.
- Implemented: opt-in macOS/Windows system-proxy takeover with safe defaults, loopback bypass protection, encrypted crash-recovery state, and stop/exit/startup restoration paths.
- Implemented: OpenAI-compatible two-stage model analysis, streaming persistence and follow-up chat; versioned built-in Skill planning; advisory Graph runs persisted in SQLite with dynamic deviations, tool calls, artifact validation, retry/degraded paths and final quality gates; Skill-run audits with exact versions, declared permissions, planned and actual tool calls, bounded input/output summaries, status and duration.
- Implemented: full-capability official headless Agent runtime packaged as a pinned Tauri sidecar, with exact user-configured `--max-turns`, planning/subagents/default tools enabled, unrestricted file/terminal/web access, per-analysis private configuration, environment-only credentials, scaled runtime watchdog, cancellation, temporary-directory cleanup, live auditable activity events, unified selected-model routing for main and auxiliary calls, real loopback OpenAI-compatible and ShowNet MCP release gates, and a native OpenAI-compatible fallback for development builds where the sidecar is absent.
- Implemented: loopback Streamable HTTP MCP Server with bearer authentication, local Origin validation, request limits, resources/prompts, encrypted token persistence, shared Agent/MCP read tools, and write tools disabled by default.
- Implemented: external Streamable HTTP MCP client connections with explicit enablement, JSON/SSE negotiation, namespaced tool discovery, encrypted bearer tokens, egress routing, bounded calls, audit logs, and untrusted-result isolation inside initial analysis and follow-up tool rounds.
- Implemented: streaming response capture that forwards original bytes unchanged, bounded gzip/Brotli/deflate/zstd normalization, structured decode/truncation metadata, portable Session/HAR persistence, and Agent/MCP evidence propagation.
- Implemented: bounded Tree-sitter JavaScript crypto extraction, on-demand request inspection, lossless `.shownet` round trips, local-source retention, and AST-aware secret redaction for Agent/MCP evidence.
- Implemented: a versioned dynamic-signature adapter generator shared by the desktop UI, internal Agent, and MCP. The Akamai/automatic path emits matched endpoints, field and Cookie names, Hook/algorithm evidence, TLS/HTTP2 dependencies, required runtime inputs, evidence gaps, a stable evidence hash, and a secret-free Node.js integration skeleton.
- Implemented: plain and MITM WebSocket upgrade relaying plus RFC 8441 extended CONNECT translation, bounded ordered text/binary/control-message persistence, request-inspector rendering, and shared Agent/MCP realtime-protocol evidence tools.
- Pending: TUN routing, signed installers, physical-device end-to-end coverage, and native accessibility/drag-and-drop adapters for the frame-stream browser surface.
