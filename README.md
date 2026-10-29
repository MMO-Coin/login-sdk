# @mmo-coin/login-sdk

Email and passphrase, Solana wallet, and passkey authentication for React and Next.js.
Wallet keys are generated and encrypted in the browser. You host the auth API and database.
The server stores encrypted wallet keys, public keys, and hashed session tokens.

This is MMO Coin's fork of [Tetrac login SDK](https://github.com/tetrac-official/tetrac-login-sdk).

[![CI](https://github.com/MMO-Coin/login-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/MMO-Coin/login-sdk/actions/workflows/ci.yml)
[MIT license](./LICENSE)

## Install

Use Node.js 22.12 or newer. Development uses Node.js 24.

Build a local package from this repository:

```bash
npm ci
npm run verify
npm pack
```

Install the tarball in your application, adjusting the path to your checkout:

```bash
npm i ../login-sdk/mmo-coin-login-sdk-0.6.4.tgz @solana/web3.js tweetnacl
```

React and Next are optional peers. Add them if you use the React or Next entry points.
Then install one storage driver:

```bash
npm i pg                # Postgres, Supabase, Neon, RDS/Aurora, Railway, Render, Fly, CockroachDB
npm i mysql2            # MySQL, MariaDB
npm i better-sqlite3    # SQLite, libSQL, Turso
npm i @upstash/redis    # Upstash (edge-compatible)
npm i ioredis           # self-hosted or managed Redis (Node runtime only)
```

Optional extras: `viem` for EVM wallets, `@ledgerhq/hw-app-solana` + a transport for Ledger.

## Server

One catch-all route serves every endpoint.

```ts
// app/api/auth/[...action]/route.ts
import { createNextAuthRoutes } from "@mmo-coin/login-sdk/next";
import { createPostgresAuthStore } from "@mmo-coin/login-sdk/storage/sql";
import { Pool } from "pg";

const store = await createPostgresAuthStore({ client: new Pool() });

export const { GET, POST } = createNextAuthRoutes({
  store,
  config: {
    appId: "myapp.example",
    origin: "https://myapp.example",
    allowedAppIds: ["myapp.example"],
  },
});
```

Generate the schema once with `schemaFor("postgres" | "mysql" | "sqlite")` and run it against your
database. Redis-family backends use `{ storage }` instead of `{ store }`:

```ts
import { resolveStorageAdapter } from "@mmo-coin/login-sdk/storage";
const storage = await resolveStorageAdapter();   // reads Upstash / REDIS_URL from env
```

## Client

```tsx
// app/providers.tsx
"use client";
import { AuthProvider } from "@mmo-coin/login-sdk/react";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider apiBaseUrl="/api/auth" config={{ appId: "myapp.example" }}>
      {children}
    </AuthProvider>
  );
}
```

## Existing deployments

Keep the same `appId`, canonical origin, database, and key prefixes when switching packages.
These values identify stored accounts and determine how wallet keys are decrypted. The fork
retains the original protocol strings, storage names, and `tetrac.vault` symbol for compatibility.

If you are moving from version 0.6.0, update the client and server together. Version 0.6.1
changed the wallet login proof to the Sign In With Solana format. Old and new login proofs
do not verify across versions.

Pending login, unlock, reveal, and signing actions are cancelled when their session changes or
locks. The client exports `SessionChangedError` for these cancellations. Check
`error.name === "SessionChangedError"` across package entry points. Start a new action after
signing in or unlocking again. Revealed keys and cached wallet records clear when the
account changes.

## Configuration

`config` is a deep-partial of `AuthConfig`, accepted by both `createNextAuthRoutes` and
`AuthProvider`. Set `appId` and `origin` identically on both.

### Identity • permanent, set once

Both are app-key derivation input. **Changing either re-derives every app key and existing encrypted
wallets stop decrypting.**

| Option | Default | |
|---|---|---|
| `appId` | `"ttc"` | Per-deployment identifier. Domain-separates key derivation and namespaces every storage key, so several apps can share one database. The default provides no isolation • override it. |
| `origin` | *(required on the server)* | Canonical http(s) origin, e.g. `"https://myapp.example"` • scheme + host (+ port), no path, query or fragment; `createAuthHandlers` throws otherwise. Binds wallet signatures to your site so they cannot be relayed from another. Defaults to `window.location.origin` in the browser. |
| `allowedAppIds` | *(unset)* | Accepted `appId` values. Unset, any well-formed `appId` mints a namespace • a client sending the wrong one registers into a separate tenant under a different key. Warns at boot. |

### Key derivation

| Option | Default | |
|---|---|---|
| `securityLevel` | `2` | PBKDF2-HMAC-SHA256 iterations for email accounts: `1` = 100k, `2` = 600k (OWASP 2023 minimum), `3` = 1M. The resolved count is pinned per user at registration, so changing this never orphans an existing account. |

### Sessions and challenges

| Option | Default | |
|---|---|---|
| `sessionTtlSeconds` | `86400` | Session lifetime. A backstop only • each login revokes the previous token immediately. |
| `challengeTtlSeconds` | `300` | Login-challenge lifetime. |
| `bindSessionToUserAgent` | `false` | Bind each session to `SHA-256(user-agent)`. Coarse; a browser update logs the user out. |

### Rate limiting

| Option | Default | |
|---|---|---|
| `rateLimit` | `{ windowSeconds: 60, maxAttempts: 10 }` | General per-endpoint limit. |
| `accountCreationRateLimit` | `{ windowSeconds: 60, maxAttempts: 2 }` | Deployment-wide ceiling on **new accounts**, charged only when a record is created. Not app-scoped and not keyed on anything the caller supplies, so there is nothing to rotate. |
| `trustProxyHeaders` | `false` | Honor `x-forwarded-for`. Enable **only** behind a proxy you operate • on a directly reachable app the header is caller-supplied and trusting it is worse than leaving the per-IP limit off. Warns at boot while unset. |
| `trustedProxyHops` | `0` | Proxies to skip from the right of `x-forwarded-for`. `0` = a single trusted edge (e.g. Vercel). |

### Browser vault

The app key is held in memory only • never in `localStorage` or `sessionStorage`.

| Option | Default | |
|---|---|---|
| `autoLockMs` | `15000` | Idle timeout before the vault locks. Signing then throws `VaultLockedError` until re-auth. |
| `lockOnHide` | `true` | Also lock on tab hide, page freeze, and bfcache restore. |
| `revealRequiresReauth` | `true` | Revealing a plaintext key always runs a fresh re-auth ceremony rather than using the ambient session key. |

### WebAuthn

| Option | Default | |
|---|---|---|
| `webauthn.rpName` | `"TTC"` | Relying-party name shown in the biometric prompt. |
| `webauthn.rpId` | *(unset)* | Relying-party ID; must match the site's registrable domain. |

The WebAuthn PRF extension is **required** for every biometric flow. An authenticator without it
throws `PrfUnavailableError` • there is no opt-out and no fallback mode. Catch it and offer
email + passkey instead.

### Storage keys

| Option | Default | |
|---|---|---|
| `keyPrefixes` | `challenge:` `pubKey:` `session:` `email:` `ratelimit:` | Key namespaces. Override only to share a database with unrelated keys; prefixes must stay mutually disjoint. |

### Client-only options

Passed to `AuthProvider` / `createAuthClient` alongside `config`.

| Option | Default | |
|---|---|---|
| `apiBaseUrl` | *(required)* | Base URL of the auth API, e.g. `"/api/auth"`. |
| `walletGen` | `{ solana: ["funds","signing"], evm: ["funds","signing"] }` | Which wallets to generate at sign-up. A record holds at most one wallet per `(chain, role)`. |
| `externalSolanaAddress` | `null` | Address of a connected external wallet; `useActiveWallet()` returns it in place of the embedded funds wallet. |

### Boot warnings

`createAuthHandlers` reports configuration hazards at startup. Route them into your logger with
`onWarning`; each names the consequence, not just the setting.

```ts
createNextAuthRoutes({ store, config, onWarning: (w) => logger.warn(w.code, w.message) });
```

| Code | Meaning |
|---|---|
| `unrestricted_app_id` | `allowedAppIds` unset • any `appId` is accepted and silently creates a namespace. |
| `default_app_id` | `appId` left at `"ttc"` • no cross-app key isolation. |
| `no_requester_identity` | `trustProxyHeaders` false • the per-IP limit is skipped, so abuse controls fall back to keying on caller-supplied identifiers. |

## License

MIT. The original Tetrac copyright notice is retained in [LICENSE](./LICENSE).
