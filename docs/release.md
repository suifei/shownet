# ShowNet Release Guide

Updated: 2026-08-14

## Release outputs

ShowNet publishes two native packages:

- macOS Apple Silicon: `ShowNet_<version>_aarch64.dmg`
- Windows x86_64: `ShowNetPortable_<version>_windows_x86_64.zip`

The Windows portable package contains the ShowNet application and its portable
launcher. Grok is not compiled, downloaded, signed, or bundled by release jobs.
The macOS bundle likewise contains only ShowNet-owned executable code.

## Agent runtime policy

ShowNet uses a compatible Grok installation from the user's system. If Grok is
missing, Settings offers an explicit one-click action that downloads and runs
the current official x.ai installer:

- macOS/Linux: `https://x.ai/cli/install.sh`
- Windows: `https://x.ai/cli/install.ps1`

Installation defaults to a direct connection. A user who has saved a ShowNet
HTTP/HTTPS egress proxy may opt into using it for installation and update
checks. That choice is independent from the separate option that injects the
ShowNet proxy into an analysis process.

The installer owns the system installation, PATH changes, update metadata, and
platform-specific binary selection. ShowNet validates the installed executable
and required command-line options before saving it. Release automation must not
fetch Grok, its source tree, or its binary artifacts.

## Quality gates

Pull requests and pushes to the default branch run the macOS and Windows quality
matrix. It builds the frontend, checks Rust formatting, runs the native and
renderer tests, exercises browser tests, and compiles the Tauri application on
both platforms. The release check additionally enforces:

- all three ShowNet version fields match;
- bundle identifier, icons, and project license are release-ready;
- no Tauri `externalBin` entry contains Grok;
- release workflows do not download, build, or package Grok;
- the Windows package contains only the ShowNet app and portable launcher;
- macOS release configuration uses hardened runtime and no forced ad-hoc identity.

The local-socket suite covers OpenAI-compatible streaming, external MCP, LAN
listening, forwarding, WebSocket relay, and captured script decoding. Tests that
need user-provided egress services remain explicit manual checks.

## Signing

### macOS

The workflow reads these GitHub Actions secrets:

- `APPLE_CERTIFICATE`
- `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_ID`
- `APPLE_PASSWORD`
- `APPLE_TEAM_ID`

Tauri imports the Developer ID Application certificate into an ephemeral
keychain, signs ShowNet, submits it for notarization, and staples the result.
`npm run verify:release:macos` independently verifies the app and DMG, matching
Team ID, hardened runtime, notarization tickets, checksums, and Gatekeeper
acceptance. It writes `release-verification-macos.json` beside the bundle.

Local `npm run tauri:bundle` uses `tauri.local.macos.conf.json` for ad-hoc QA.
Tagged CI never uses that overlay for the signed path.

### Windows

SignPath uses these repository secrets when available:

- `SIGNPATH_API_TOKEN`
- `SIGNPATH_ORGANIZATION_ID`
- `SIGNPATH_PROJECT_SLUG`
- `SIGNPATH_SIGNING_POLICY_SLUG`
- `SIGNPATH_ARTIFACT_CONFIGURATION_SLUG`

The ShowNet app and portable launcher are compiled first, submitted for signing,
verified as `Valid`, and only then assembled into the PortableApps package. The
package records and verifies checksums of those two executables. Missing signing
secrets produce an explicitly unsigned QA package rather than a falsely signed
artifact.

## Local archives and cleanup

`npm run archive:local-release` records a locally built release and its hashes.
`npm run clean:local-build-cache -- --confirm` removes only the project's known,
reproducible build outputs, including legacy sidecar build directories. When a
local release archive exists it is verified before cleanup; the strict output
allowlist can still be cleaned when no archive exists. The command does not
remove source files, `node_modules`, shared Cargo registries, or verified release
archives unless a separately documented option explicitly says so.

## Update source

The published GitHub release is the update manifest. `src-tauri/src/updates.rs`
reads `/releases/latest`, validates SemVer and HTTPS asset URLs, and selects an
artifact by platform and architecture. A missing compatible asset opens the
release page instead of offering an unusable download.

Keep these names stable:

- `ShowNet_<version>_aarch64.dmg`
- `ShowNetPortable_<version>_windows_x86_64.zip`

## Release procedure

1. Resolve every open issue selected for the release and confirm the open issue count.
2. Update and verify the three ShowNet version fields.
3. Run `npm run check:release` and the required quality tests.
4. Commit and push the release candidate; wait for the macOS and Windows matrix to pass on that exact commit.
5. Merge to the default branch and confirm its quality run passes.
6. Create and push the new annotated version tag. Never move or reuse a published tag.
7. Confirm signing, notarization, packaging, checksums, and release verification reports pass.
8. Confirm the GitHub Release contains the DMG, Windows Portable ZIP, verification reports, and `SHA256SUMS.txt`.
9. Verify update discovery from macOS and Windows.
10. Run the local build-cache cleanup and record remaining disk usage.

Local builds do not prove signing or notarization. A release is complete only
when the tagged workflow and published asset checks pass.
