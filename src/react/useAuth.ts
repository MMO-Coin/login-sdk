// Primary hook: exposes status + bound action wrappers that refresh state.
import { useCallback } from "react";
import { useAuthContext } from "./AuthProvider.js";
import { captureSessionGuard, lockVault, SessionExpiredError } from "../client/session.js";
import type { ReauthCredentials } from "../client/authClient.js";
import type { AuthResult } from "../core/types.js";
import type { PasskeyRegistration } from "../client/webauthn.js";

export function useAuth() {
  const { client, status, sessionState, publicKey, email, refresh } = useAuthContext();

  // Wrap each action so React state reflects the new session immediately.
  const wrap = useCallback(
    <Args extends unknown[], R>(fn: (...args: Args) => Promise<R>) =>
      async (...args: Args): Promise<R> => {
        const r = await fn(...args);
        refresh();
        return r;
      },
    [refresh],
  );

  return {
    status,
    sessionState,
    isSessionExpired: sessionState.session === "expired",
    needsLogin: sessionState.session === "absent" || sessionState.session === "expired",
    needsUnlock:
      sessionState.session !== "absent" &&
      sessionState.session !== "expired" &&
      sessionState.vault === "locked",
    publicKey,
    email,
    isAuthenticated: status === "authenticated",
    /** Account exists but the vault is locked (auto-lock or manual) — re-auth to decrypt. */
    isLocked: status === "session_expired",
    /** There is an account (logged in), regardless of whether the vault is locked. */
    hasAccount: status !== "unauthenticated",
    /** Lock the vault now (drops the in-memory app key). */
    lock: useCallback(() => {
      lockVault();
      refresh();
    }, [refresh]),
    /**
     * Re-run the auth ceremony to unlock the vault after an auto-lock. Validates
     * against a known wallet (so a wrong passkey is rejected, not silently armed).
     */
    reauthenticate: useCallback(
      async (creds: ReauthCredentials) => {
        const assertCurrent = captureSessionGuard();
        const fresh = await client.fetchUserData();
        if (!fresh) throw new SessionExpiredError();
        assertCurrent();
        const wallet = fresh.wallets[0];
        if (!wallet) throw new Error("No encrypted wallet is available to verify the unlock.");
        await client.unlock(creds, wallet);
        refresh();
      },
      [client, refresh],
    ),
    registerWithEmail: wrap((p: { email: string; passkey: string }) => client.registerWithEmail(p)) as (p: {
      email: string;
      passkey: string;
    }) => Promise<AuthResult>,
    loginWithEmail: wrap((p: { email: string; passkey: string }) => client.loginWithEmail(p)) as (p: {
      email: string;
      passkey: string;
    }) => Promise<AuthResult>,
    loginWithWallet: wrap(
      (p: {
        publicKey: string;
        signMessage: (m: Uint8Array) => Promise<Uint8Array>;
        hardwareWallet?: boolean;
      }) => client.loginWithWallet(p),
    ),
    connectWallet: wrap(
      (p: {
        publicKey: string;
        signMessage: (m: Uint8Array) => Promise<Uint8Array>;
        hardwareWallet?: boolean;
      }) => client.connectWallet(p),
    ),
    registerWithWallet: wrap(
      (p: {
        publicKey: string;
        signMessage: (m: Uint8Array) => Promise<Uint8Array>;
        hardwareWallet?: boolean;
      }) => client.registerWithWallet(p),
    ),
    registerWithBiometric: wrap((p: { userName: string }) => client.registerWithBiometric(p)),
    loginWithBiometric: wrap((p: { registration: PasskeyRegistration }) => client.loginWithBiometric(p)),
    logout: useCallback(() => {
      client.logout();
      refresh();
    }, [client, refresh]),
  };
}
