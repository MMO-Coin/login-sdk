# Changelog

## 0.6.6

- Close SQL test connections after preflight suites so CI can exit cleanly.
- Keep package verification compatible with npm 10 when prepare writes build output.
- Show the email or wallet fallback when packaged login UI encounters an authenticator without PRF.
- Add native Chromium WebAuthn and PRF tests, including reload, cancellation, tampering and logout races.
- Run passkey browser tests on Linux and Windows, and support manually triggered CI runs.
- Preserve Docker test failures, clean up partial starts and support Windows without shell-specific environment syntax.
- Bind test database ports to localhost so test services are not exposed to the network.
- Verify actual tarball installs with React 18 and 19 on Linux and Windows in CI.
- Check consumer type declarations, browser bundles, wallet recovery and dependency audits, and document application-level overrides.

## 0.6.5

- Update vulnerable development dependencies and patch the unresolved deepmerge issue locally.
- Keep Solana v1 support with a patched JSON-RPC dependency and verify browser bundling.
- Run the full dependency audit as a required check in verification and CI.

## 0.6.4

- Cancel pending authentication, unlock, reveal, and signing actions after logout, lock, or account changes.
- Clear revealed keys and cached wallet records when the active account changes.
- Remove old session metadata and clean up cancelled biometric registrations.

## 0.6.3

- Package the MMO Coin fork as `@mmo-coin/login-sdk` and point repository links to MMO Coin.
- Preserve existing wallet encryption, protocol identifiers, and stored account formats.
- Build packages during installation and verify all published entry points before release.
- Check supported Node.js versions in CI and use consistent line endings across platforms.

## 0.6.2

- Replace the deprecated Vercel KV adapter with Upstash Redis.

## 0.6.1

- Wallet login signs a valid Sign In With Solana message. Phantom 26.30.x refused the previous text with "The app's signature request cannot be shown due to invalid formatting." `walletLoginMessage` takes `{ challenge, origin, address }` and names the signer; clients and servers on 0.6.0 and 0.6.1 cannot verify each other's wallet-login or registration signatures, so run one version on both.
- `createAuthHandlers` throws at construction unless `config.origin` is a bare http(s) origin • scheme and host, optional port. The check is exported as `parseOrigin`.

## 0.6.0

- Postgres/Supabase, MySQL, and SQLite ship first-party (`@tetrac/login-sdk/storage/sql`), each with a preflight that refuses to boot on a world-readable schema, a truncating MySQL, or a web-served SQLite file.
- Wallet signatures and app-key derivation are bound to `config.origin`, which is now required • this re-derives every Web3 account's app key, so wallets encrypted on 0.5.x no longer decrypt.
- User records became per-field writable (`putWalletSlot`, `setSessionPointer`); a concurrent login and wallet import used to resolve last-write-wins and destroy the only copy of a private key.
- Challenges accumulate one row per value, so issuing one can no longer invalidate a challenge its owner is mid-signature on.
- WebAuthn gate mode removed • PRF is required and fails closed with `PrfUnavailableError`, because the stored gate secret was readable by any same-origin script with no biometric prompt.
- Wallet records are bounded to four `(chain, role)` slots and imports replace in place; appending left the old address active and receiving deposits.
- Ledger accounts pin their off-chain envelope at registration, so a firmware change can no longer silently derive a different app key.
- Sessions last 24h, are enforced against the record's current pointer on every request, and re-login revokes the previous token immediately even under concurrency.
- `/challenge` answers unknown emails with an unstored dummy instead of a 400, and always returns the iteration count • the old shape was an account-existence oracle.
- Anti-abuse hardened: 128 KB body cap, wallet payloads rebuilt from an allowlist, a global account-creation ceiling with no key to rotate, and requester-keyed `/challenge` limiting where a trustworthy IP exists.
- `createAuthHandlers` warns at boot on `unrestricted_app_id`, `default_app_id`, and `no_requester_identity`; route them via `onWarning`.
- Header names are fixed constants • `sessionHeader` / `publicKeyHeader` / `appIdHeader` and `webauthn.preferPrf` are gone.

## 0.5.0

- Added the `AuthStore` domain port alongside the KV `StorageAdapter`, so the SDK can be backed by a real database instead of emulating Redis.
- Session tokens are stored only as `SHA-256` digests, so a database read yields no replayable credential.

## 0.4.0

- Multi-app support: `appId` domain-separates key derivation and namespaces every storage key, letting several deployments share one database.
- Ledger hardware wallet support, including the off-chain envelope cascade that fixes login on legacy firmware.

## 0.3.0

- Memory-only app-key vault shared across bundle copies, with idle auto-lock, tab-hide locking, and cross-tab propagation.

## 0.2.0

- Biometric (WebAuthn) login for every account type.
- Dropped `crypto-es` for `@noble/hashes`, leaving one runtime dependency.

## 0.1.0

- First release: email + passkey, Web3 wallet, and biometric login with client-side wallet generation and encryption.
