// Browser session storage + the app-key "vault".
//
// SECURITY MODEL (see docs/PRD.md §10, docs/PRD_HOTFIX.md):
//  - The app (encryption) key lives in MEMORY ONLY — never sessionStorage, never
//    localStorage, never the network. A tab reload (or crash) drops it, so the
//    user must re-authenticate; storage-scraping XSS finds no key at rest.
//  - It auto-locks after `autoLockMs` of inactivity (default 15s) and on tab hide
//    / page freeze / bfcache restore. While locked, getAppKey() returns null, so
//    every signer/decrypt path refuses to operate until the caller re-derives it.
//  - To survive a reload WITHOUT re-running a passkey ceremony, use the
//    biometric-unlock feature: it re-arms the key from a Touch/Face-ID-gated
//    wrapped blob, not from a raw key sitting in web storage.
import { AUTH_TOKEN_HEADER, PUBLIC_KEY_HEADER } from "../core/config.js";
import type { AuthStatus } from "../core/types.js";

const TOKEN_KEY = "ttc-auth-token";
const PUBKEY_KEY = "ttc-public-key";
const EMAIL_KEY = "user_email";
const EK_ITER_KEY = "ttc_pbkdf2_iter"; // per-user PBKDF2 iteration count, pinned at register/login
// Per-account off-chain envelope for HARDWARE wallets, pinned at register/login. Like the
// iteration count it is derivation input, not a secret: re-deriving under the other layout
// silently produces a different app key and every stored wallet fails to decrypt.
const EK_ENVELOPE_KEY = "ttc_offchain_envelope";
const LOCK_SIGNAL_KEY = "ttc_lock_signal"; // cross-tab lock sentinel (CLIENTVAULT-7) — a bumped
// timestamp, never a secret; writing it fires a `storage` event in sibling tabs.

/** Thrown by signer/decrypt helpers when the vault is locked. */
export class VaultLockedError extends Error {
  constructor(message = "Vault is locked — re-authenticate to unlock your keys") {
    super(message);
    this.name = "VaultLockedError";
  }
}

// --- vault state: ONE instance shared across every subpath bundle -------------
// The SDK ships as several independently-bundled subpaths (/client, /react, /ui,
// …). tsup builds with `splitting:false` and does NOT externalize this module, so
// its code is INLINED into more than one bundle. If the vault state lived in plain
// module-scope `let`s, each inlined copy would own a SEPARATE memoryAppKey:
// login() (run through the /react hooks) would arm the react copy while a consumer
// calling getAppKey() from "@mmo-coin/login-sdk/client" read a different, never-armed
// copy and got null forever ("Vault is locked"). To make every copy operate on ONE
// runtime state we hang it off a process-global keyed by a cross-realm Symbol.for():
// both copies resolve the same registered symbol and therefore the same object.
// It is non-enumerable (never shows up in for-in / JSON.stringify of globalThis)
// and memory-only as before — a real page reload starts a NEW realm with a fresh
// empty slot, so nothing is rehydrated from storage.
interface VaultState {
  /** The app/encryption key — memory-only, never persisted to web storage. */
  memoryAppKey: string | null;
  /** Epoch ms at which the key auto-locks (null when no key is armed). */
  lockDeadline: number | null;
  lockTimer: ReturnType<typeof setTimeout> | null;
  // Config (set by configureVault; defaults match DEFAULT_CONFIG).
  autoLockMs: number;
  lockOnHide: boolean;
  hideHandlerBound: boolean;
  /** Lock/unlock subscribers. Shared so a notify() from ANY bundle copy reaches
   *  subscribers registered through any other copy (cross-copy reactivity). */
  listeners: Set<() => void>;
  /** clearSession() (logout) hooks — e.g. biometricUnlock's blob purge. Shared so
   *  a logout through ANY copy fires every registered hook. Kept here (not imported
   *  by session.ts) so feature modules register without creating an import cycle. */
  clearHooks: Set<() => void>;
  generation: number;
  owner?: { token: string | null; publicKey: string | null } | null;
  invalidationListeners: Set<() => void>;
}

const VAULT_STATE_KEY = Symbol.for("tetrac.vault");

/**
 * Resolve the one shared vault state, creating it on first access. Every bundle
 * copy calls this at import and — via the global Symbol registry — gets the SAME
 * object, so arming/locking/notifying done through one subpath is visible from
 * every other (/client, /react, /ui, …).
 */
function resolveVaultState(): VaultState {
  const g = globalThis as unknown as Record<symbol, VaultState | undefined>;
  let state = g[VAULT_STATE_KEY];
  if (!state) {
    state = {
      memoryAppKey: null,
      lockDeadline: null,
      lockTimer: null,
      autoLockMs: 15_000,
      lockOnHide: true,
      hideHandlerBound: false,
      listeners: new Set<() => void>(),
      clearHooks: new Set<() => void>(),
      generation: 0,
      invalidationListeners: new Set<() => void>(),
    };
    // Non-enumerable so it stays out of for-in / JSON of globalThis. Left
    // configurable so a test harness can delete the slot to simulate a page
    // reload (a real reload gets a fresh realm anyway); not writable so a stray
    // `globalThis[sym] = …` can't silently swap out the live vault.
    Object.defineProperty(g, VAULT_STATE_KEY, {
      value: state,
      enumerable: false,
      writable: false,
      configurable: true,
    });
  }
  // An older SDK bundle may have created the shared slot first.
  state.generation ??= 0;
  state.invalidationListeners ??= new Set();
  return state;
}

// Resolved once per bundle copy at import time — every copy shares this object.
const vault = resolveVaultState();

/**
 * Register a callback fired on every clearSession() (logout). Returns an
 * unregister fn. Hooks are best-effort and must not throw — a throwing hook is
 * swallowed so one feature's cleanup can't block logout. Used by
 * biometricUnlock to purge wrapped blobs + gate secrets on logout.
 */
export function registerSessionClearHook(fn: () => void): () => void {
  vault.clearHooks.add(fn);
  return () => {
    vault.clearHooks.delete(fn);
  };
}

const hasWindow = (): boolean => typeof window !== "undefined";
const nowMs = (): number => Date.now();

export class SessionChangedError extends Error {
  constructor(message = "Session changed or locked. Try again.") {
    super(message);
    this.name = "SessionChangedError";
  }
}

/** Bind pending work to the current session, including changes made in another tab. */
export function captureSessionGuard(): () => void {
  isLocked();
  const generation = vault.generation;
  const token = getAuthToken();
  const publicKey = getPublicKey();
  return () => {
    isLocked();
    if (generation !== vault.generation || token !== getAuthToken() || publicKey !== getPublicKey()) {
      throw new SessionChangedError();
    }
  };
}

export function subscribeSessionInvalidation(fn: () => void): () => void {
  vault.invalidationListeners.add(fn);
  return () => {
    vault.invalidationListeners.delete(fn);
  };
}

function invalidateSessionOperations(): void {
  vault.generation++;
  for (const listener of vault.invalidationListeners) {
    try {
      listener();
    } catch {
      /* A listener must not prevent a lock or logout. */
    }
  }
}

function runSessionClearHooks(): void {
  for (const hook of vault.clearHooks) {
    try {
      hook();
    } catch {
      /* Feature cleanup must not prevent session replacement. */
    }
  }
}

function notify(): void {
  for (const cb of vault.listeners) cb();
}

/** Subscribe to lock/unlock transitions. Returns an unsubscribe fn. */
export function subscribeLock(cb: () => void): () => void {
  vault.listeners.add(cb);
  return () => {
    vault.listeners.delete(cb);
  };
}

/** Configure auto-lock behavior. Called once by AuthClient from resolved config. */
export function configureVault(opts: { autoLockMs?: number; lockOnHide?: boolean }): void {
  if (typeof opts.autoLockMs === "number") vault.autoLockMs = opts.autoLockMs;
  if (typeof opts.lockOnHide === "boolean") vault.lockOnHide = opts.lockOnHide;
  bindHideHandler();
}

function bindHideHandler(): void {
  // Bind once, but RE-CHECK lockOnHide at fire time — so configureVault({
  // lockOnHide:false }) disables hide-locking even after the listeners are bound.
  if (!hasWindow() || vault.hideHandlerBound) return;
  vault.hideHandlerBound = true;
  const lockOnHideEvt = (): void => {
    if (vault.lockOnHide) lockVault(false); // per-tab hide — don't propagate to siblings
  };
  if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
    document.addEventListener("visibilitychange", () => {
      if (vault.lockOnHide && document.visibilityState === "hidden") lockVault(false);
    });
    // Page Lifecycle: a frozen page (bfcache / mobile background) pauses timers, so
    // the idle auto-lock can't fire — lock proactively when the page freezes.
    document.addEventListener("freeze", lockOnHideEvt);
  }
  if (typeof window.addEventListener === "function") {
    // pagehide is the reliable "page is going away" signal — fires before unload AND
    // before bfcache entry across browsers.
    window.addEventListener("pagehide", lockOnHideEvt);
    // bfcache freezes and RESTORES the JS heap, so an unlocked in-memory key can ride
    // a back/forward navigation. On restore (event.persisted), force a re-lock — a
    // bfcache restore is a session-continuity break, stronger than an ordinary hide.
    window.addEventListener("pageshow", (e) => {
      if ((e as PageTransitionEvent).persisted) lockVault(false);
    });
    // Cross-tab coordination (CLIENTVAULT-7): a logout removes the auth token from the
    // shared localStorage, and an explicit lock bumps LOCK_SIGNAL_KEY — either fires a
    // `storage` event in OTHER same-origin tabs, where we drop the hot key locally
    // (propagate=false — the originating tab already did its part).
    window.addEventListener("storage", (e) => {
      const ev = e as StorageEvent;
      if (
        ev.key === null ||
        [TOKEN_KEY, PUBKEY_KEY, EMAIL_KEY, EK_ITER_KEY, EK_ENVELOPE_KEY, LOCK_SIGNAL_KEY].includes(ev.key)
      ) {
        lockVault(false);
      }
    });
  }
}

function clearTimer(): void {
  if (vault.lockTimer) {
    clearTimeout(vault.lockTimer);
    vault.lockTimer = null;
  }
}

function scheduleLock(): void {
  clearTimer();
  if (!vault.memoryAppKey || vault.lockDeadline == null || !hasWindow()) return;
  const ms = Math.max(0, vault.lockDeadline - nowMs());
  vault.lockTimer = setTimeout(() => lockVault(false), ms); // idle lock is per-tab — don't propagate
}

/** Drop the key and cancel pending work before a callback can publish a stale result. */
function clearKeyState(): void {
  clearTimer();
  vault.memoryAppKey = null;
  vault.owner = null;
  vault.lockDeadline = null;
  invalidateSessionOperations();
}

export function setSession(params: {
  publicKey: string;
  authToken: string;
  appKey: string;
  email?: string;
  /** PBKDF2 iteration count this account's app key was derived with (email users). */
  pbkdf2Iterations?: number;
  /** Off-chain envelope this account's hardware wallet derives under. */
  offchainEnvelope?: string;
}): void {
  if (!hasWindow()) return;
  const accountChanged = getPublicKey() !== params.publicKey;
  clearKeyState();
  if (accountChanged) runSessionClearHooks();
  localStorage.setItem(TOKEN_KEY, params.authToken);
  localStorage.setItem(PUBKEY_KEY, params.publicKey);
  if (params.email) localStorage.setItem(EMAIL_KEY, params.email);
  else localStorage.removeItem(EMAIL_KEY);
  if (typeof params.pbkdf2Iterations === "number") {
    localStorage.setItem(EK_ITER_KEY, String(params.pbkdf2Iterations));
  } else localStorage.removeItem(EK_ITER_KEY);
  if (params.offchainEnvelope) localStorage.setItem(EK_ENVELOPE_KEY, params.offchainEnvelope);
  else localStorage.removeItem(EK_ENVELOPE_KEY);
  armAppKey(params.appKey);
}

/** Install/refresh the app key and (re)start the auto-lock window. Fires listeners. */
export function armAppKey(appKey: string): void {
  vault.memoryAppKey = appKey;
  vault.owner = { token: getAuthToken(), publicKey: getPublicKey() };
  vault.lockDeadline = nowMs() + vault.autoLockMs;
  scheduleLock();
  notify();
}

/** Extend the unlocked window after a successful sensitive op (signing). */
export function touchVault(): void {
  if (isLocked()) return;
  vault.lockDeadline = nowMs() + vault.autoLockMs;
  scheduleLock();
}

/**
 * Lock the vault now: drop the key and notify subscribers. When `propagate` is true
 * (the default for an explicit, app-initiated lock), also bump the cross-tab lock
 * sentinel so sibling tabs of the same origin lock too — a shared device shouldn't
 * leave other tabs hot (CLIENTVAULT-7). Automatic locks (idle timer, tab hide, page
 * freeze, bfcache restore) pass false: they are per-tab events and must NOT lock a
 * sibling tab that is still in active use.
 */
export function lockVault(propagate = true): void {
  clearKeyState();
  if (propagate && hasWindow()) {
    try {
      localStorage.setItem(LOCK_SIGNAL_KEY, String(nowMs()));
    } catch {
      /* best-effort cross-tab signal */
    }
  }
  notify();
}

/**
 * True when there is no usable app key — either never set, expired, or locked.
 * The key is memory-only, so a reload always starts locked (nothing to re-hydrate).
 * Lazily expires a stale key (the scheduled timer is the primary path; this is the
 * safety net for when timers were paused, e.g. a backgrounded/frozen tab).
 */
export function isLocked(): boolean {
  if (!vault.memoryAppKey) return true;
  if (vault.owner && (vault.owner.token !== getAuthToken() || vault.owner.publicKey !== getPublicKey())) {
    clearKeyState();
    return true;
  }
  if (vault.lockDeadline != null && nowMs() > vault.lockDeadline) {
    clearKeyState(); // silent — the scheduled timer fires the notify
    return true;
  }
  return false;
}

/**
 * Pure, side-effect-free snapshot of vault usability for useSyncExternalStore.
 * Returns true when the key is currently usable. Unlike isLocked() this never
 * re-hydrates from sessionStorage, mutates state, or reschedules the timer — so
 * it returns a stable value across calls within a render (no infinite loop).
 * Re-hydration still happens via isLocked()/getAppKey() on the actual use path.
 */
export function lockSnapshot(): boolean {
  if (!vault.memoryAppKey) return false;
  if (vault.owner && (vault.owner.token !== getAuthToken() || vault.owner.publicKey !== getPublicKey()))
    return false;
  if (vault.lockDeadline != null && nowMs() > vault.lockDeadline) return false;
  return true;
}

export function getAuthToken(): string | null {
  return hasWindow() ? localStorage.getItem(TOKEN_KEY) : null;
}

export function getPublicKey(): string | null {
  return hasWindow() ? localStorage.getItem(PUBKEY_KEY) : null;
}

export function getEmail(): string | null {
  return hasWindow() ? localStorage.getItem(EMAIL_KEY) : null;
}

/** PBKDF2 iteration count pinned for this account (email users), or null if unset/legacy. */
export function getPbkdf2Iterations(): number | null {
  if (!hasWindow()) return null;
  const raw = localStorage.getItem(EK_ITER_KEY);
  if (raw == null) return null;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) ? n : null;
}

/** Off-chain envelope pinned for this account (hardware wallets), or null. */
export function getOffchainEnvelope(): string | null {
  return hasWindow() ? localStorage.getItem(EK_ENVELOPE_KEY) : null;
}

/** The app/encryption key, or null when the vault is locked. */
export function getAppKey(): string | null {
  if (isLocked()) return null;
  return vault.memoryAppKey;
}

export function clearSession(): void {
  clearKeyState();
  if (hasWindow()) {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(PUBKEY_KEY);
    localStorage.removeItem(EMAIL_KEY);
    localStorage.removeItem(EK_ITER_KEY);
    localStorage.removeItem(EK_ENVELOPE_KEY);
  }
  runSessionClearHooks();
  notify();
}

/**
 * Status model:
 *  - authenticated:    token + public key present AND vault unlocked (app key hot)
 *  - session_expired:  account known (token/pubKey) but vault LOCKED — re-auth to decrypt
 *  - unauthenticated:  nothing
 *
 * Note: an auto-locked session reports `session_expired` — the account is intact,
 * only the encryption key is gone until the user re-authenticates.
 */
export function getAuthStatus(): AuthStatus {
  const hasAccount = !!getAuthToken() && !!getPublicKey();
  if (!hasAccount) return "unauthenticated";
  return getAppKey() ? "authenticated" : "session_expired";
}

/** Headers to attach to authenticated API requests. */
export function authHeaders(): Record<string, string> {
  const token = getAuthToken();
  const pubKey = getPublicKey();
  const headers: Record<string, string> = {};
  // The SAME constants the server reads. These were once two independent strings — a
  // config field on the server and a literal here — which meant renaming the header broke
  // authentication silently.
  if (token) headers[AUTH_TOKEN_HEADER] = token;
  if (pubKey) headers[PUBLIC_KEY_HEADER] = pubKey;
  return headers;
}
