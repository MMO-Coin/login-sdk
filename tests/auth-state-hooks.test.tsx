/** @jest-environment jsdom */
import React from "react";
import { act, renderHook } from "@testing-library/react";
import { AuthProvider } from "../src/react/AuthProvider";
import { useAuth } from "../src/react/useAuth";
import { useUser } from "../src/react/useUser";
import { clearSession, getAppKey, lockVault, setSession } from "../src/client/session";

const user = {
  appId: "example-app",
  publicKey: "test-account",
  authMethod: "email",
  wallets: [],
  createdAt: 1,
};
const response = (body: unknown, status = 200) =>
  ({ status, ok: status >= 200 && status < 300, json: async () => body }) as Response;
function wrapper({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider
      apiBaseUrl="/auth/example"
      config={{ appId: "example-app", autoLockMs: 100_000, lockOnHide: false }}
    >
      {children}
    </AuthProvider>
  );
}
beforeEach(() => {
  clearSession();
  localStorage.clear();
});
afterEach(() => {
  clearSession();
  jest.restoreAllMocks();
});

it("shows unlock rather than login for a valid but locally locked account", async () => {
  globalThis.fetch = jest.fn(async () => response({ user }));
  setSession({ publicKey: user.publicKey, authToken: "test-token", appKey: "ab".repeat(32) });
  const hook = renderHook(() => useAuth(), { wrapper });
  await act(async () => {});
  act(() => lockVault());
  expect(hook.result.current.sessionState.session).toBe("valid");
  expect(hook.result.current.needsUnlock).toBe(true);
  expect(hook.result.current.needsLogin).toBe(false);
});

it("a current 401 asks for login and drops an unlocked signing key", async () => {
  globalThis.fetch = jest.fn(async () => response({}, 401));
  setSession({ publicKey: user.publicKey, authToken: "test-token", appKey: "ab".repeat(32) });
  const hook = renderHook(() => useAuth(), { wrapper });
  await act(async () => {});
  expect(hook.result.current.sessionState.session).toBe("expired");
  expect(hook.result.current.needsLogin).toBe(true);
  expect(hook.result.current.needsUnlock).toBe(false);
  expect(getAppKey()).toBeNull();
});

it("a network failure exposes an error without treating a saved login as expired", async () => {
  globalThis.fetch = jest.fn(async () => {
    throw new Error("Synthetic offline request");
  });
  localStorage.setItem("ttc-auth-token", "saved-token");
  localStorage.setItem("ttc-public-key", user.publicKey);
  const hook = renderHook(() => ({ auth: useAuth(), user: useUser() }), { wrapper });
  await act(async () => {});
  expect(hook.result.current.auth.sessionState.session).toBe("unverified");
  expect(hook.result.current.auth.needsLogin).toBe(false);
  expect(hook.result.current.user.error?.message).toBe("Synthetic offline request");
  expect(hook.result.current.user.loading).toBe(false);
});
