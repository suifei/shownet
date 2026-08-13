# Third-Party Notices

ShowNet can optionally run the official installer for, and invoke, the following separately maintained component.

## xai-org/grok-build

- Purpose: optional Agent runtime invoked by ShowNet
- Upstream: https://github.com/xai-org/grok-build
- Version: latest stable version selected by the official x.ai installer when the user starts a one-click installation
- Official binary channel: https://x.ai/cli/stable
- Official fallback channel: https://storage.googleapis.com/grok-build-public-artifacts/cli/stable
- Copyright: 2023-2026 SpaceXAI
- License: Apache License 2.0

Grok is not bundled with ShowNet releases. The complete upstream license and
generated dependency notices are retained in `third-party/grok-build/` for
attribution. When requested by the user, ShowNet downloads and runs the official
`install.sh` or `install.ps1`, then validates the installed version and command
line compatibility. ShowNet-specific AI endpoints, credentials, Skills, MCP,
and proxy choices are never written into Grok's global configuration.
