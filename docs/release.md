# ShowNet Release And Update Operations

ShowNet checks the GitHub Releases API (`https://api.github.com/repos/suifei/shownet/releases/latest`) for updates. The desktop client only reads release metadata and opens an explicit HTTPS download link; it never silently downloads or installs a package. macOS Gatekeeper and Windows Authenticode remain the final trust checks.

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

Signing goes through [SignPath](https://signpath.io), whose Foundation programme
signs open-source projects for free — this repository qualifies (public,
GPL-3.0). Configure all five as repository Secrets; with any of the first four
missing the workflow builds an unsigned ZIP instead of failing:

- `SIGNPATH_API_TOKEN`
- `SIGNPATH_ORGANIZATION_ID`
- `SIGNPATH_PROJECT_SLUG`
- `SIGNPATH_SIGNING_POLICY_SLUG`
- `SIGNPATH_ARTIFACT_CONFIGURATION_SLUG`

There is no PFX to import. Since June 2023 a publicly trusted code-signing key
may not leave its hardware or cloud HSM, so no CA issues exportable key material
any more; SignPath holds the key and signs binaries submitted to it.

### Why signing sits where it does

The three executables are signed **after they are compiled and before the
portable package is assembled**, never afterwards. The package records a
checksum of every file it contains and verifies them at runtime, so signing
after packaging would leave those checksums describing bytes that no longer
exist, and the package would fail its own integrity check on the user's machine.
The Agent sidecar carries its own checksum file as well, which is re-stamped
once the signed binary comes back.

Order in `release-windows`: build sidecar → build app and launcher → collect the
three into one archive → submit to SignPath → verify each returned binary is
`Valid` and put it back → re-stamp the sidecar → package → verify every
executable inside the package is still `Valid` → zip and checksum.

## Update Source

The published GitHub release *is* the manifest. There is no separately hosted
`latest.json`: it could only restate what the release already says — the tag, the
notes, the download URLs — while being able to drift from it or go missing if
publishing failed after the release was already public.

`src-tauri/src/updates.rs` reads `/releases/latest`, which excludes drafts and
pre-releases by definition, and maps it as follows:

| Release field | Shown as |
| --- | --- |
| `tag_name` (leading `v` stripped) | version compared against the running build |
| `body` | release notes, truncated to 16 KB |
| `published_at` | publish date |
| `assets[].browser_download_url` | the download, chosen per platform |

### Asset naming

Asset selection requires an architecture token **and** an extension the user can
open, so the checksum and metadata files that sit beside the installers are never
offered. Keep these names stable:

- macOS: `ShowNet_<version>_aarch64.dmg`
- Windows: `ShowNetPortable_<version>_windows_x86_64.zip`

A release with no asset for the current platform falls back to the release page
rather than reporting an update the user cannot obtain. Downloads must be HTTPS;
the client rejects invalid SemVer, insecure URLs and responses over 128 KB.

### Rate limit

Unauthenticated GitHub allows 60 requests an hour per address. The client reports
that explicitly on 403/429, and reports "no release published yet" on 404 rather
than surfacing a raw HTTP status.

### Pointing somewhere else

A fork can override the endpoint at build time with
`SHOWNET_UPDATE_MANIFEST_URL`; any endpoint returning the GitHub release schema
works. No secrets, no deployment step, nothing to keep in sync.

## Release Procedure

1. Update and test all three version fields. Run `npm run check:release`; it also validates the stable bundle identifier, native icons, pinned Agent source metadata, complete third-party notices, and Tauri sidecar resources.
2. Commit the release changes.
3. Create an annotated tag such as `git tag -a v0.2.0 -m "ShowNet 0.2.0"`.
4. Push the tag. The quality matrix must pass on macOS and Windows before signing begins.
5. Confirm both platform jobs built and checksum-verified their pinned Agent sidecars, then verified Apple notarization, Gatekeeper assessment, and Windows Authenticode.
6. Confirm the GitHub Release contains the DMG, Windows PortableApps ZIP and its checksum, `release-verification-macos.json`, and `SHA256SUMS.txt`, and that the asset names match the pattern above — update checking resolves the download from them.
7. Use ShowNet's Settings > Check for updates action from both platforms.

Local unsigned debug builds do not prove signing or notarization. The release is valid only after the CI verification steps pass with the real production credentials.

The same macOS/Windows quality matrix runs for pull requests and pushes to `main` or `master`. It builds the frontend, checks Rust formatting, validates the sidecar configuration and notices, runs the native test suite plus the explicit local-socket integration suite, and compiles the Tauri desktop executable on each operating system before a release tag exists. Tag builds repeat those gates, build the official Agent from its pinned commit on each native target, verify its SHA-256 and metadata, run the real sidecar against loopback OpenAI-compatible and MCP services, then merge the sidecar resources with the platform signing configuration before packaging. The local-socket suite covers the OpenAI-compatible SSE transport, external Streamable HTTP MCP, LAN listener, HTTP forwarding, WebSocket relay, and compressed-script capture. The sidecar gate additionally covers selected-model routing for both main and auxiliary calls, environment-only credentials, live activity/output events, strict model-visible tool isolation, a ShowNet MCP evidence round trip, and temporary-directory cleanup. The two smoke tests that depend on user-provided HTTP/SOCKS5 egress services on ports `7890/7891` remain manual conditions rather than CI release gates.
