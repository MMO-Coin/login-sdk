// React context that wraps an AuthClient and tracks auth status + user data.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { AuthClient, type AuthClientOptions } from "../client/authClient.js";
import {
  getAuthStatus,
  getSessionState,
  getPublicKey,
  getEmail,
  getAuthToken,
  subscribeSessionState,
} from "../client/session.js";
import type { AuthSessionState, AuthStatus, UserData } from "../core/types.js";

export interface AuthContextValue {
  client: AuthClient;
  status: AuthStatus;
  /** Server session validity, separate from whether local signing keys are locked. */
  sessionState: AuthSessionState;
  publicKey: string | null;
  email: string | null;
  /** Re-read status from storage (call after a custom flow mutates the session). */
  refresh: () => void;
  /** Cached user record (encrypted wallets + identity). Null until the first fetch resolves. */
  user: UserData | null;
  /** True while a user-data fetch is in flight. */
  userLoading: boolean;
  /** A failed user-data request. Network failures do not mean the login expired. */
  userError: Error | null;
  /** Force a fresh user-data fetch (e.g. after importing a wallet). */
  refetchUser: () => Promise<void>;
  /**
   * Address of an externally connected Solana wallet (Phantom/Backpack/etc.).
   * Passed in via the <AuthProvider externalSolanaAddress=…> prop. The SDK
   * doesn't subscribe to @solana/wallet-adapter-react itself — the app pipes it in.
   */
  externalSolanaAddress: string | null;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export interface AuthProviderProps extends AuthClientOptions {
  children: React.ReactNode;
  /**
   * Address of an externally connected Solana wallet. When set, useActiveWallet()
   * returns this in place of the embedded funds wallet (the "external connected wins"
   * rule). Set to null/undefined when no external wallet is connected.
   */
  externalSolanaAddress?: string | null;
}

export function AuthProvider({ children, externalSolanaAddress = null, ...options }: AuthProviderProps) {
  // Stable client across renders; options are read once on mount.
  const client = useMemo(() => new AuthClient(options), []); // eslint-disable-line react-hooks/exhaustive-deps
  const [status, setStatus] = useState<AuthStatus>("unauthenticated");
  const [sessionState, setSessionState] = useState<AuthSessionState>({
    session: "absent",
    vault: "locked",
    lockReason: null,
  });
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [user, setUser] = useState<UserData | null>(null);
  const [userLoading, setUserLoading] = useState(false);
  const [userError, setUserError] = useState<Error | null>(null);
  const fetchSeq = useRef(0);
  const activeIdentity = useRef<string | null>(null);
  const activeToken = useRef<string | null>(null);

  const refresh = useCallback(() => {
    const nextIdentity = getPublicKey();
    const nextToken = getAuthToken();
    if (nextToken !== activeToken.current) {
      activeToken.current = nextToken;
      fetchSeq.current++;
      setUserLoading(false);
      setUserError(null);
    }
    if (nextIdentity !== activeIdentity.current) {
      activeIdentity.current = nextIdentity;
      fetchSeq.current++;
      setUser(null);
      setUserLoading(false);
      setUserError(null);
    }
    setStatus(getAuthStatus());
    setSessionState(getSessionState());
    setPublicKey(nextIdentity);
    setToken(nextToken);
    setEmail(getEmail());
  }, []);

  const refetchUser = useCallback(async () => {
    const mySeq = ++fetchSeq.current;
    const requestedIdentity = getPublicKey();
    const requestedToken = getAuthToken();
    setUserLoading(true);
    setUserError(null);
    try {
      const fresh = await client.fetchUserData();
      if (
        mySeq === fetchSeq.current &&
        requestedIdentity === getPublicKey() &&
        requestedToken === getAuthToken()
      ) {
        setUser(fresh?.publicKey === requestedIdentity ? fresh : null);
      }
    } catch (error) {
      if (
        mySeq === fetchSeq.current &&
        requestedIdentity === getPublicKey() &&
        requestedToken === getAuthToken()
      ) {
        setUserError(error instanceof Error ? error : new Error(String(error)));
      }
      throw error;
    } finally {
      if (mySeq === fetchSeq.current) setUserLoading(false);
      refresh();
    }
  }, [client, refresh]);

  // Hydrate from storage on mount (client-only).
  useEffect(() => {
    refresh();
    return () => {
      fetchSeq.current++;
    };
  }, [refresh]);

  // Re-read status whenever the vault locks/unlocks (auto-lock, manual lock,
  // re-auth). This is what flips `status` to "session_expired" on auto-lock.
  useEffect(() => subscribeSessionState(refresh), [refresh]);

  // Fetch user-data whenever an account exists (token + public key), and keep it
  // loaded across a LOCK — a locked session still knows who you are and needs the
  // encrypted wallets for the re-auth ceremony. Only an actual logout clears it.
  useEffect(() => {
    if (publicKey) {
      void refetchUser().catch(() => {
        /* The error is exposed through userError. */
      });
    } else {
      // Bump seq so any in-flight fetch is ignored on resolution.
      fetchSeq.current++;
      setUser(null);
      setUserLoading(false);
      setUserError(null);
    }
  }, [publicKey, token, refetchUser]);

  const value = useMemo<AuthContextValue>(
    () => ({
      client,
      status,
      sessionState,
      publicKey,
      email,
      refresh,
      user: user?.publicKey === publicKey ? user : null,
      userLoading,
      userError,
      refetchUser,
      externalSolanaAddress,
    }),
    [
      client,
      status,
      sessionState,
      publicKey,
      email,
      refresh,
      user,
      userLoading,
      userError,
      refetchUser,
      externalSolanaAddress,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthContext(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
