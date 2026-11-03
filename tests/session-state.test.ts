/** @jest-environment jsdom */
import {
  armAppKey,
  captureSessionGuard,
  captureSessionValidation,
  clearSession,
  configureVault,
  getAppKey,
  getAuthStatus,
  getPublicKey,
  getSessionState,
  lockVault,
  SessionChangedError,
  SessionExpiredError,
  setSession,
  subscribeLock,
  subscribeSessionState,
} from "../src/client/session";

const login = (authToken = "synthetic-token", publicKey = "synthetic-account") =>
  setSession({ publicKey, authToken, appKey: "ab".repeat(32) });

beforeEach(() => {
  clearSession();
  localStorage.clear();
  configureVault({ autoLockMs: 100_000, lockOnHide: false });
});
afterEach(() => {
  clearSession();
  jest.useRealTimers();
});

it("distinguishes a cold saved token from a verified session", () => {
  expect(getSessionState()).toEqual({ session: "absent", vault: "locked", lockReason: null });
  localStorage.setItem("ttc-auth-token", "saved-token");
  localStorage.setItem("ttc-public-key", "saved-account");
  expect(getSessionState()).toEqual({ session: "unverified", vault: "locked", lockReason: "reload" });
  expect(getAuthStatus()).toBe("session_expired");
});

it("a manual lock preserves server validity while legacy status remains compatible", () => {
  login();
  expect(getSessionState()).toEqual({ session: "valid", vault: "unlocked", lockReason: null });
  lockVault();
  expect(getSessionState()).toEqual({ session: "valid", vault: "locked", lockReason: "manual" });
  expect(getAuthStatus()).toBe("session_expired");
});

it("reports idle expiry separately from login expiry", () => {
  jest.useFakeTimers();
  configureVault({ autoLockMs: 100 });
  login();
  jest.advanceTimersByTime(101);
  expect(getSessionState()).toEqual({ session: "valid", vault: "locked", lockReason: "idle" });
});

it("reports a lifecycle lock without expiring the login", () => {
  configureVault({ lockOnHide: true });
  login();
  document.dispatchEvent(new Event("freeze"));
  expect(getSessionState()).toEqual({ session: "valid", vault: "locked", lockReason: "background" });
});

it("a current server rejection drops signing keys and pending sensitive work", () => {
  login();
  const pending = captureSessionGuard();
  expect(captureSessionValidation()("expired")).toBe(true);
  expect(getSessionState()).toEqual({ session: "expired", vault: "locked", lockReason: "session_expired" });
  expect(getPublicKey()).toBe("synthetic-account");
  expect(getAppKey()).toBeNull();
  expect(pending).toThrow(SessionChangedError);
  expect(() => armAppKey("ab".repeat(32))).toThrow(SessionExpiredError);
});

it("successful validation informs auth state without cancelling existing signer work", () => {
  login();
  const lockListener = jest.fn();
  const stateListener = jest.fn();
  const unsubscribeLock = subscribeLock(lockListener);
  const unsubscribeState = subscribeSessionState(stateListener);
  const pending = captureSessionGuard();
  try {
    expect(captureSessionValidation()("valid")).toBe(true);
    expect(lockListener).not.toHaveBeenCalled();
    expect(stateListener).toHaveBeenCalledTimes(1);
    expect(pending).not.toThrow();
    expect(getAppKey()).toBe("ab".repeat(32));
    expect(captureSessionValidation()("expired")).toBe(true);
    expect(lockListener).toHaveBeenCalledTimes(1);
    expect(stateListener).toHaveBeenCalledTimes(2);
    expect(pending).toThrow(SessionChangedError);
  } finally {
    unsubscribeLock();
    unsubscribeState();
  }
});

it("a fresh login can unlock after a rejected session", () => {
  login();
  captureSessionValidation()("expired");
  login("fresh-token");
  expect(getSessionState()).toEqual({ session: "valid", vault: "unlocked", lockReason: null });
});

it("a late successful response cannot revive a rejected token", () => {
  login();
  const successfulRequest = captureSessionValidation();
  captureSessionValidation()("expired");
  expect(successfulRequest("valid")).toBe(false);
  expect(getSessionState().session).toBe("expired");
});

it("a validation callback cannot cross an explicit session replacement even with the same token", () => {
  login();
  const previousRequest = captureSessionValidation();
  login();
  expect(previousRequest("expired")).toBe(false);
  expect(getSessionState().session).toBe("valid");
});

it.each(["valid", "expired"] as const)("ignores a late %s result after token replacement", (result) => {
  login("old-token");
  const record = captureSessionValidation();
  login("new-token");
  expect(record(result)).toBe(false);
  expect(getSessionState()).toEqual({ session: "valid", vault: "unlocked", lockReason: null });
});

it("ignores a late successful validation after logout", () => {
  login();
  const record = captureSessionValidation();
  clearSession();
  expect(record("valid")).toBe(false);
  expect(getSessionState()).toEqual({ session: "absent", vault: "locked", lockReason: null });
});

it("a sibling-tab token replacement is unverified and cannot keep the previous key", () => {
  login();
  const record = captureSessionValidation();
  localStorage.setItem("ttc-auth-token", "sibling-token");
  window.dispatchEvent(new StorageEvent("storage", { key: "ttc-auth-token", newValue: "sibling-token" }));
  expect(getSessionState()).toEqual({
    session: "unverified",
    vault: "locked",
    lockReason: "session_changed",
  });
  expect(record("expired")).toBe(false);
  expect(getAppKey()).toBeNull();
});
