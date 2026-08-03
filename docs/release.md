# ShowNet Release And Update Operations

ShowNet checks `https://claudegpt.org/shownet/latest.json` for updates. The desktop client only reads release metadata and opens an explicit HTTPS download link; it never silently downloads or installs a package. macOS Gatekeeper and Windows Authenticode remain the final trust checks.

For the **0.1.0-era ClientHello catalog, Advanced MITM console, local package gates, and honesty limits**, see [clienthello-catalog-and-mitm-console.md](./clienthello-catalog-and-mitm-console.md) (feature surface + release-gate commands used for formal local QA builds).

Windows is distributed as an AMD64 PortableApps-format ZIP. `ShowNetPortable.exe` launches `App/ShowNet/ShowNet.exe` with an absolute `SHOWNET_DATA_DIR` pointing to `Data/ShowNet`. Sessions, settings, certificates, browser profiles, and generated state therefore travel with the portable folder. Launching the application executable directly from the standard `App/ShowNet` layout resolves the same directory as a fallback. macOS and mobile builds continue to use their platform-default application data directories.

## Versioning

A release tag must be `v<semver>` and must match all three files:

- `package.json`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`

The release workflow rejects a tag when these versions differ. The application reports the Rust package version in its runtime status and update UI.

## Built-In Agent Sidecar

Signed bundles contain the official `xai-org/grok-build` headless binary as an isolated Tauri sidecar. The exact upstream version, full Git commit, license, and Rust toolchain are locked in `third-party/grok-build/SOURCE.json`. Product UI refers to the runtime only as `内置 Agent`; the bundled notices retain the upstream attribution required for distribution.

The platform release runner performs these steps before Tauri packaging:

1. Installs the pinned Agent Rust toolchain independently of ShowNet's `rustup stable` toolchain.
2. Fetches the exact source commit and verifies the upstream crate version.
3. Builds `xai-grok-pager-bin` for the native release target.
4. On Windows, Authenticode-signs the sidecar itself before packaging; macOS signs it as nested code inside the application bundle.
5. Writes the target-named Tauri sidecar, SHA-256 file, and build metadata. Windows regenerates integrity metadata after signing so it describes the distributed bytes.
6. Runs `npm run check:release -- --require-agent-target <target>` to recompute the digest and compare every source/build field.
7. Runs `npm run test:agent-sidecar` against loopback OpenAI-compatible SSE and MCP services, proving the real binary uses the configured model for both analysis and auxiliary requests, streams events, limits model-visible tools to the MCP discovery/dispatch pair, completes a ShowNet evidence-tool round trip, and removes its isolated runtime directory.
8. Bundles the binary together with the complete upstream `LICENSE`, `THIRD-PARTY-NOTICES`, and `SOURCE.json` files through `src-tauri/tauri.grok.conf.json` on macOS or the verified PortableApps packager on Windows, then verifies the packaged copies and executable version.

Local commands for the current machine are:

```bash
npm run build:agent-sidecar
npm run check:release -- --require-agent-target aarch64-apple-darwin
npm run test:agent-sidecar
```

Windows CI uses `x86_64-pc-windows-msvc`. Sidecar binaries and generated digest metadata are build artifacts and are intentionally excluded from source control.

On an Apple Silicon development machine with `cargo-xwin` installed, the local
unsigned QA binaries can be reproduced without allowing Homebrew Cargo to leak
into the rustup toolchain:

```bash
npm run build:windows:cross
npm run build:windows:portable-launcher:cross
npm run package:windows:portable -- --target x86_64-pc-windows-msvc
npm run archive:local-release
```

The first two commands pin both the top-level compiler and every xwin child
process to `rustup stable`. The packager then requires AMD64 PE machine type,
Windows GUI subsystem for both user-facing executables, an AMD64 Agent sidecar,
and a byte-for-byte valid internal SHA-256 manifest before accepting the
PortableApps directory.

The archive command runs only after both platform packages exist. It verifies
the DMG checksum container, re-verifies the PortableApps directory, creates and
tests a metadata-free ZIP, and writes a stable local QA directory containing
the DMG, ZIP, `release-manifest.json`, and `SHA256SUMS.txt`. The manifest labels
local artifacts accurately as ad-hoc macOS and unsigned Windows builds. Keep
this archive before deleting `src-tauri/target` or the `cargo-xwin` cache.

After reviewing the archived files, run the cleanup gate in preview mode and
then explicitly confirm it:

```bash
npm run clean:local-build-cache
npm run clean:local-build-cache -- --confirm --include-xwin-cache
```

The cleanup command refuses to proceed unless the archive product, version,
channel, file sizes, artifact hashes, and `SHA256SUMS.txt` all verify. It removes
only known project build outputs and generated Agent sidecars; the external
`cargo-xwin` cache requires the separate flag. It does not touch Cargo's shared
registry, source files, platform icons, `node_modules`, or the verified release
archive.

## GitHub Repository Secrets

The workflow reads signing material only from GitHub Actions Secrets. Never commit a certificate, private key, PFX/P12 file, password, or deployment token.

### macOS

- `APPLE_CERTIFICATE`: Base64-encoded Developer ID Application `.p12` file.
- `APPLE_CERTIFICATE_PASSWORD`: Password used to export the `.p12` file.
- `APPLE_ID`: Apple ID used for notarization.
- `APPLE_PASSWORD`: App-specific password for that Apple ID.
- `APPLE_TEAM_ID`: Apple Developer Team ID.

Tauri imports the certificate into an ephemeral CI keychain and infers the Developer ID Application identity from that certificate. The bundle configuration intentionally does not set `signingIdentity: "-"`, because that value forces an ad-hoc identity and conflicts with a CI Developer ID certificate. Tauri signs the application and nested Agent sidecar, submits the artifacts for notarization, and staples the tickets.

Before publishing anything, `npm run verify:release:macos` independently verifies the app, main executable, Agent sidecar, and DMG. It requires strict deep signatures, one matching Team ID, hardened runtime on executable code, byte-identical bundled notices, the pinned Agent version, the requested architecture, valid DMG checksums, stapled app and DMG tickets, and `spctl` acceptance with `source=Notarized Developer ID`. It writes `release-verification-macos.json` beside the bundles so the release retains machine-readable evidence. A local ad-hoc bundle fails this gate by design.

For local macOS QA, `npm run tauri:bundle` merges `src-tauri/tauri.local.macos.conf.json` after the release bundle configuration and applies only the ad-hoc `"-"` identity. The tagged CI command never loads that local overlay. This keeps local DMGs launchable for development while preventing the ad-hoc identity from conflicting with or masquerading as Developer ID signing.

### Windows

- `WINDOWS_CERTIFICATE_BASE64`: Base64-encoded code-signing PFX.
- `WINDOWS_CERTIFICATE_PASSWORD`: PFX import password.

The workflow writes the PFX only into the ephemeral runner directory, imports it into the current-user certificate store, and deletes the temporary PFX. It signs the ShowNet executable, built-in Agent, and `ShowNetPortable.exe` launcher separately, verifies all three with `Get-AuthenticodeSignature`, builds the PortableApps directory, rejects mutable/build-only files, and publishes a checksum alongside the ZIP.

## Update Manifest

The tagged workflow creates `latest.json`, adds it to the GitHub Release, and can publish it to ClaudeGPT.org. The supported schema is:

```json
{
  "version": "0.2.0",
  "notes": "Release notes shown inside ShowNet.",
  "publishedAt": "2026-07-30T12:00:00Z",
  "platforms": {
    "darwin-aarch64": {
      "url": "https://github.com/example/shownet/releases/download/v0.2.0/ShowNet_0.2.0_aarch64.dmg"
    },
    "windows-x86_64": {
      "url": "https://github.com/example/shownet/releases/download/v0.2.0/ShowNetPortable_0.2.0_windows_x86_64.zip"
    }
  }
}
```

All manifest and artifact URLs must use HTTPS. The client rejects invalid SemVer, insecure download URLs, responses larger than 128 KB, and release notes larger than 16 KB. `downloadUrl` is accepted as a platform-independent fallback.

To publish automatically, configure both optional Secrets:

- `SHOWNET_UPDATE_PUBLISH_URL`: HTTPS endpoint that accepts the final manifest with `PUT`.
- `SHOWNET_UPDATE_PUBLISH_TOKEN`: Bearer token accepted by that endpoint.

Set `SHOWNET_UPDATE_PUBLISH_URL` to the deployment endpoint, not necessarily the public read URL. If either Secret is absent, the workflow still publishes the signed GitHub Release and attaches `latest.json`; an operator must then deploy that file to `https://claudegpt.org/shownet/latest.json`.

## Release Procedure

1. Update and test all three version fields. Run `npm run check:release`; it also validates the stable bundle identifier, native icons, pinned Agent source metadata, complete third-party notices, and Tauri sidecar resources.
2. Commit the release changes.
3. Create an annotated tag such as `git tag -a v0.2.0 -m "ShowNet 0.2.0"`.
4. Push the tag. The quality matrix must pass on macOS and Windows before signing begins.
5. Confirm both platform jobs built and checksum-verified their pinned Agent sidecars, then verified Apple notarization, Gatekeeper assessment, and Windows Authenticode.
6. Confirm the GitHub Release contains the DMG, Windows PortableApps ZIP and its checksum, `release-verification-macos.json`, `SHA256SUMS.txt`, and `latest.json`.
7. Confirm the public ClaudeGPT.org manifest returns the same JSON over HTTPS, then use ShowNet's Settings > Check for updates action from both platforms.

Local unsigned debug builds do not prove signing or notarization. The release is valid only after the CI verification steps pass with the real production credentials.

The same macOS/Windows quality matrix runs for pull requests and pushes to `main` or `master`. It builds the frontend, checks Rust formatting, validates the sidecar configuration and notices, runs the native test suite plus the explicit local-socket integration suite, and compiles the Tauri desktop executable on each operating system before a release tag exists. Tag builds repeat those gates, build the official Agent from its pinned commit on each native target, verify its SHA-256 and metadata, run the real sidecar against loopback OpenAI-compatible and MCP services, then merge the sidecar resources with the platform signing configuration before packaging. The local-socket suite covers the OpenAI-compatible SSE transport, external Streamable HTTP MCP, LAN listener, HTTP forwarding, WebSocket relay, and compressed-script capture. The sidecar gate additionally covers selected-model routing for both main and auxiliary calls, environment-only credentials, live activity/output events, strict model-visible tool isolation, a ShowNet MCP evidence round trip, and temporary-directory cleanup. The two smoke tests that depend on user-provided HTTP/SOCKS5 egress services on ports `7890/7891` remain manual conditions rather than CI release gates.
