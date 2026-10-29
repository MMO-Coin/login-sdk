# Development dependency audit

Date: 2026-10-30. Package: `@mmo-coin/login-sdk@0.6.5`.

The complete checkout audit went from 18 findings to zero. This includes development tools
and the peer packages installed for SDK tests. No authentication source, wallet encryption,
signed messages or database formats changed.

## Fixes

- Updated compatible dependencies, including Handlebars, js-yaml, Browserslist,
  brace-expansion, baseline-browser-mapping and the MySQL test driver.
- Kept Solana v1 support and selected Jayson 5.0.0, which removes the affected UUID and
  stream-json dependencies. Tests verify request IDs, RPC responses, errors and browser bundling.
- Selected esbuild 0.28.2 for tsup to address GHSA-g7r4-m6w7-qqqr without raising the SDK's
  Node.js requirement.
- Added a development-only [deepmerge patch](../vendor/deepmerge/README.md) because the
  latest upstream release still has GHSA-gcqx-w48m-w2h4. The patch retains the original MIT
  license and defines merged keys as own data properties. The original 4.3.1 artifact reproduced
  the poisoning issue; the installed patch rejected it. Tests also cover the existing merge API.

## Validation

- A clean `npm ci` passed. Regenerating the lockfile and `npm ls --all` found no invalid links
  or missing dependencies.
- `npm run verify` passed: formatting, types, build, 825 tests, SIWS and package checks.
  Twelve database tests remain skipped because their local services are unavailable.
- `npm audit --include=dev` reported zero findings at every severity.
- A normal tarball install in an isolated React 19 app passed ESM/CommonJS loading and key clearing after logout.
- CI now runs the full audit as a blocking step. The local patch is excluded from the SDK tarball.

## Application boundary

Dependency overrides apply to this checkout, not to applications that install the SDK.
Applications must review their own peer dependency versions and lockfiles when integrating it.
Replace the local merge patch when an upstream fixed release is available.
