// Reveal-a-private-key hook.
//
// SECURITY (PRD §10 "Re-auth to reveal", docs/PRD_HOTFIX.md): reveal ALWAYS runs
// a fresh re-authentication ceremony and derives a one-time key — it never reads
// the ambient (possibly hot) session app key. That means a reveal cannot happen
// silently, and repeated Reveal → Hide → Reveal each require credentials again.
//
// The decrypted secret lives in React state only as long as the consumer holds
// it; `clear()` (or the auto-clear timer) releases it. JS strings can't be truly
// zeroed, so <ExportKeyPanel> keeps the window tight (auto-clear + clipboard wipe).
import { useCallback, useEffect, useRef, useState } from "react";
import { useAuthContext } from "./AuthProvider.js";
import type { ReauthCredentials } from "../client/authClient.js";
import type { EncryptedWallet } from "../core/types.js";
import { captureSessionGuard, SessionChangedError, subscribeSessionInvalidation } from "../client/session.js";

export interface UseExportKeyOptions {
  /**
   * Auto-clear the revealed plaintext from state after this many milliseconds.
   * Defaults to 30_000 (30s) — a revealed private key shouldn't linger in React
   * state indefinitely. Pass 0 to disable auto-clear (then the caller MUST clear()).
   */
  autoClearMs?: number;
}

export interface UseExportKeyResult {
  /**
   * Run a re-auth ceremony and reveal the wallet's plaintext secret. Requires
   * credentials every time — there is no silent path.
   */
  reveal: (reauth: ReauthCredentials) => Promise<string>;
  /** Drops the plaintext from state. */
  clear: () => void;
  /** Currently revealed plaintext, or null. */
  plaintext: string | null;
  /** True while a reveal call is in flight. */
  loading: boolean;
  /** Error from the last reveal call, or null. */
  error: Error | null;
}

export function useExportKey(
  wallet: EncryptedWallet | null | undefined,
  options: UseExportKeyOptions = {},
): UseExportKeyResult {
  const { client } = useAuthContext();
  const { autoClearMs = 30_000 } = options; // auto-clear ON by default; pass 0 to disable
  const walletId = JSON.stringify([wallet?.chain, wallet?.role, wallet?.publicKey, wallet?.encryptedSecret]);
  const activeWalletId = useRef(walletId);
  activeWalletId.current = walletId;
  const [revealed, setRevealed] = useState<{ secret: string; walletId: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const revealSeq = useRef(0);
  const mounted = useRef(true);

  const clear = useCallback(() => {
    revealSeq.current++;
    setRevealed(null);
    setLoading(false);
    setError(null);
  }, []);

  useEffect(() => {
    mounted.current = true;
    clear();
    const unsubscribe = subscribeSessionInvalidation(clear);
    return () => {
      mounted.current = false;
      revealSeq.current++;
      unsubscribe();
    };
  }, [client, walletId, clear]);

  const reveal = useCallback(
    async (reauth: ReauthCredentials): Promise<string> => {
      if (!mounted.current || activeWalletId.current !== walletId) throw new SessionChangedError();
      if (!wallet) {
        const err = new Error("useExportKey: no wallet provided");
        setError(err);
        throw err;
      }
      const assertCurrent = captureSessionGuard();
      const mySeq = ++revealSeq.current;
      setRevealed(null);
      setLoading(true);
      setError(null);
      try {
        const secret = await client.revealSecret(wallet, reauth);
        assertCurrent();
        if (!mounted.current || mySeq !== revealSeq.current || activeWalletId.current !== walletId) {
          throw new SessionChangedError();
        }
        setRevealed({ secret, walletId });
        return secret;
      } catch (e) {
        const err = e instanceof Error ? e : new Error(String(e));
        if (mounted.current && mySeq === revealSeq.current) setError(err);
        throw err;
      } finally {
        if (mounted.current && mySeq === revealSeq.current) setLoading(false);
      }
    },
    [wallet, walletId, client],
  );

  // Mask a previous wallet's key during render, before effects perform cleanup.
  const plaintext = revealed?.walletId === walletId ? revealed.secret : null;
  useEffect(() => {
    if (!plaintext || !autoClearMs) return;
    const timer = setTimeout(clear, autoClearMs);
    return () => clearTimeout(timer);
  }, [plaintext, autoClearMs, clear]);

  return { reveal, clear, plaintext, loading, error };
}
