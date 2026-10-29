# Session lifecycle audit

Date: 2026-10-30. Package: `@mmo-coin/login-sdk@0.6.4`.

Scope: pending authentication, unlock, reveal and signing operations; account switching;
biometric setup; and the React wallet cache.

## Resolved findings

- **SL-01, high:** A delayed unlock could restore a wallet key after logout. Session guards
  now reject stale completions after logout, lock or account replacement, including changes
  from another tab. The in-memory key is bound to its session identity.
  [Session guard](../src/client/session.ts#L138), [unlock](../src/client/authClient.ts#L247).
- **SL-02, high:** A mounted export hook could retain a revealed key after logout or a wallet
  change. It now clears the value, masks a previous wallet's value during render, and rejects
  cancelled reveals instead of returning their plaintext.
  [Export hook](../src/react/useExportKey.ts#L58).
- **SL-03, medium:** Account replacement retained old email, derivation metadata and cached
  wallet records. Session replacement removes missing metadata, clears the previous account's
  biometric state, and ignores delayed records for another identity.
  [Session replacement](../src/client/session.ts#L263), [wallet cache](../src/react/AuthProvider.tsx#L52).
- **SL-04, high:** A decrypt-to-sign operation could continue after logout. The helpers now
  check the session before using decrypted material and before returning a result. A cancelled
  Solana keypair is cleared. Cancelled biometric setup also removes its unfinished wrapped key.
  [Signing helpers](../src/react/useSigner.ts#L33), [biometric setup](../src/client/biometricUnlock.ts#L184).

## Validation

- 816 tests passed; 12 real-engine tests skipped because Docker is unavailable locally.
- Formatting, TypeScript, build, SIWS verification and package checks passed.
- Package checks cover ESM, CommonJS, React context and shared cancellation state.
- A separate React 19 consumer smoke test verifies rendered key clearing after logout in jsdom.
- Original 0.6.0 wallet recovery fixtures still pass. Key derivation, signed messages, database
  schemas and protocol identifiers did not change.

## Follow-up

`npm audit --omit=dev` reports zero findings. The development tree still has the previously
reported 18 findings: 1 critical, 3 high, 6 moderate and 8 low. Dependency cleanup remains a
separate task. Real-device passkey testing and the remote database CI matrix remain to be verified.
