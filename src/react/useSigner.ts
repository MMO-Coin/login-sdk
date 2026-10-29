// Hook for accessing the in-session app key and decrypt-to-sign helpers.
// Honors the vault lock: when locked (auto-lock idle, tab hidden, or logged out)
// every helper throws VaultLockedError instead of operating on a stale key.
//
// The hook subscribes to lock/unlock transitions via useSyncExternalStore so it
// re-renders the moment the vault locks. Crucially, the app key is read INSIDE
// each callback at CALL TIME (never captured at render) — so even a lock that
// races a render can never let a stale key decrypt.
import { useCallback, useSyncExternalStore } from "react";
import {
  getAppKey,
  lockSnapshot,
  subscribeLock,
  touchVault,
  VaultLockedError,
  captureSessionGuard,
} from "../client/session.js";
import { decryptWalletSecret, toSolanaKeypair, withDecryptedKey } from "../client/wallet.js";
import type { EncryptedWallet } from "../core/types.js";

// Pure snapshot (no re-hydrate / no reschedule) — safe for useSyncExternalStore.
const isLockedSnapshot = (): boolean => !lockSnapshot();
const serverSnapshot = (): boolean => true; // locked on the server (no key)

export function useSigner() {
  // Re-render on every lock/unlock transition. `unlocked` is derived live.
  const locked = useSyncExternalStore(subscribeLock, isLockedSnapshot, serverSnapshot);

  const decrypt = useCallback((wallet: EncryptedWallet) => {
    const appKey = getAppKey(); // read at call time — null when the vault is locked
    if (!appKey) throw new VaultLockedError();
    touchVault();
    const assertCurrent = captureSessionGuard();
    return decryptWalletSecret(wallet, appKey).then((secret) => {
      assertCurrent();
      return secret;
    });
  }, []);

  const solanaKeypair = useCallback((wallet: EncryptedWallet) => {
    const appKey = getAppKey();
    if (!appKey) throw new VaultLockedError();
    touchVault();
    const assertCurrent = captureSessionGuard();
    return toSolanaKeypair(wallet, appKey).then((keypair) => {
      try {
        assertCurrent();
        return keypair;
      } catch (error) {
        keypair.secretKey.fill(0);
        throw error;
      }
    });
  }, []);

  const sign = useCallback(<T>(wallet: EncryptedWallet, fn: (secret: string) => Promise<T> | T) => {
    const appKey = getAppKey();
    if (!appKey) throw new VaultLockedError();
    touchVault(); // active use extends the unlocked window
    const assertCurrent = captureSessionGuard();
    return withDecryptedKey(wallet, appKey, (secret) => {
      assertCurrent();
      return fn(secret);
    }).then((result) => {
      assertCurrent();
      return result;
    });
  }, []);

  return { unlocked: !locked, decrypt, solanaKeypair, sign };
}
