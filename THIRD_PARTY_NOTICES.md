# Third-Party Notices

ShowNet release bundles include the following separately maintained component.

## xai-org/grok-build

- Purpose: isolated headless runtime for ShowNet's built-in Agent
- Upstream: https://github.com/xai-org/grok-build
- Version: latest stable version resolved once by GitHub Actions for each ShowNet release
- Official binary channel: https://x.ai/cli/stable
- Official fallback channel: https://storage.googleapis.com/grok-build-public-artifacts/cli/stable
- Copyright: 2023-2026 SpaceXAI
- License: Apache License 2.0

The complete upstream license and generated dependency notices are stored in
`third-party/grok-build/` and bundled with desktop releases. Each package also
contains `licenses/grok-build/SOURCE.json` with the exact downloaded version,
official artifact URL, reported version, target platform, and SHA-256. ShowNet's
product interface identifies this component only as the built-in Agent; this
notice preserves the required source and license attribution.
