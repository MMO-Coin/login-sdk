import { AuthClient } from "../src/client/authClient";
import {
  armAppKey,
  touchVault,
  captureSessionGuard,
  clearSession,
  configureVault,
  getAppKey,
  getAuthToken,
  getEmail,
  getOffchainEnvelope,
  getPbkdf2Iterations,
  getPublicKey,
  lockVault,
  setSession,
  SessionChangedError,
} from "../src/client/session";
import { deriveAppKeyFromSignature, encryptSecret } from "../src/core/crypto";
import type { EncryptedWallet } from "../src/core/types";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
const values = new Map<string, string>();
const handlers: Record<string, Array<(event: { key: string | null; newValue: string | null }) => void>> = {};
const KEY_A = "ab".repeat(32);
const KEY_B = "cd".repeat(32);
const signature = new Uint8Array(64).fill(7);
const originalFetch = globalThis.fetch;
let client: AuthClient;

beforeAll(() => {
  Object.assign(globalThis, {
    localStorage: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, String(value)),
      removeItem: (key: string) => values.delete(key),
    },
    window: {
      location: { origin: "https://test.example" },
      addEventListener: (
        name: string,
        fn: (event: { key: string | null; newValue: string | null }) => void,
      ) => {
        (handlers[name] ??= []).push(fn);
      },
    },
  });
});
beforeEach(() => {
  clearSession();
  values.clear();
  globalThis.fetch = jest.fn(async () => new Response("{}")) as typeof fetch;
  client = new AuthClient({
    apiBaseUrl: "https://test.example/auth",
    config: { appId: "test-app", origin: "https://test.example", autoLockMs: 60000, lockOnHide: false },
  });
  setSession({
    publicKey: "account-a",
    authToken: "token-a",
    appKey: KEY_A,
    email: "a@example.com",
    pbkdf2Iterations: 100000,
  });
});
afterEach(() => clearSession());
afterAll(() => {
  globalThis.fetch = originalFetch;
});

const changes = [
  { name: "logout", apply: () => client.logout(), expectedKey: null },
  {
    name: "account replacement",
    apply: () => setSession({ publicKey: "account-b", authToken: "token-b", appKey: KEY_B }),
    expectedKey: KEY_B,
  },
  { name: "explicit lock", apply: () => lockVault(), expectedKey: null },
  {
    name: "cross-tab logout",
    apply: () => {
      values.delete("ttc-auth-token");
      for (const handler of handlers.storage ?? []) handler({ key: "ttc-auth-token", newValue: null });
    },
    expectedKey: null,
  },
];

describe("pending key operations", () => {
  it.each(changes)("does not unlock after $name", async ({ apply, expectedKey }) => {
    const prompt = deferred<Uint8Array>();
    const pending = client.unlock({ signMessage: () => prompt.promise });
    apply();
    prompt.resolve(signature);
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
    expect(getAppKey()).toBe(expectedKey);
  });

  it.each(changes)("does not reveal a secret after $name", async ({ apply, expectedKey }) => {
    const key = deriveAppKeyFromSignature(Buffer.from(signature).toString("hex"));
    const wallet: EncryptedWallet = {
      chain: "solana",
      role: "funds",
      publicKey: "public-test-wallet",
      encryptedSecret: await encryptSecret("public-test-secret", key),
    };
    const prompt = deferred<Uint8Array>();
    const pending = client.revealSecret(wallet, { signMessage: () => prompt.promise });
    apply();
    prompt.resolve(signature);
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
    expect(getAppKey()).toBe(expectedKey);
  });

  it("keeps an unchanged session usable", async () => {
    await client.unlock({ signMessage: async () => signature });
    expect(getAppKey()).toBe(deriveAppKeyFromSignature(Buffer.from(signature).toString("hex")));
  });

  it("invalidates work even when logout starts and ends without a stored identity", () => {
    clearSession();
    const check = captureSessionGuard();
    client.logout();
    expect(check).toThrow(SessionChangedError);
  });

  it("detects another tab's replacement before a storage event is delivered", () => {
    const check = captureSessionGuard();
    values.set("ttc-auth-token", "token-b");
    values.set("ttc-public-key", "account-b");
    expect(check).toThrow(SessionChangedError);
    expect(getAppKey()).toBeNull();
  });

  it("does not extend an already expired key", () => {
    configureVault({ autoLockMs: 1 });
    armAppKey(KEY_A);
    const clock = jest.spyOn(Date, "now");
    const now = Date.now();
    clock.mockReturnValue(now + 100);
    touchVault();
    expect(getAppKey()).toBeNull();
    clock.mockRestore();
  });
});

describe("pending login responses", () => {
  it.each(changes.slice(0, 2))("does not restore a session after $name", async ({ apply, expectedKey }) => {
    const response = deferred<Response>();
    const requestStarted = deferred<void>();
    globalThis.fetch = jest.fn(async (input) => {
      const url = String(input);
      if (url.endsWith("/challenge"))
        return new Response(JSON.stringify({ challenge: "a".repeat(64), pbkdf2Iterations: 100000 }));
      if (url.endsWith("/login")) {
        requestStarted.resolve();
        return response.promise;
      }
      return new Response("{}");
    }) as typeof fetch;
    const pending = client.loginWithEmail({ email: "a@example.com", passkey: "public-test-passphrase" });
    await requestStarted.promise;
    apply();
    response.resolve(
      new Response(JSON.stringify({ publicKey: "account-a", authToken: "late-token", user: {} })),
    );
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
    expect(getAppKey()).toBe(expectedKey);
    expect(getAuthToken()).not.toBe("late-token");
  });

  it.each(["loginWithWallet", "connectWallet", "registerWithWallet"] as const)(
    "cancels %s before asking for another signature",
    async (method) => {
      const prompt = deferred<Uint8Array>();
      const started = deferred<void>();
      const signMessage = jest.fn(() => {
        started.resolve();
        return prompt.promise;
      });
      globalThis.fetch = jest.fn(
        async () => new Response(JSON.stringify({ challenge: "a".repeat(64) })),
      ) as typeof fetch;
      const pending = client[method]({ publicKey: "11111111111111111111111111111111", signMessage });
      await started.promise;
      client.logout();
      prompt.resolve(signature);
      await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
      expect(signMessage).toHaveBeenCalledTimes(1);
      expect(getAppKey()).toBeNull();
      expect(getPublicKey()).toBeNull();
    },
  );
});

describe("account metadata replacement", () => {
  it("removes email and iteration metadata when switching to a wallet account", () => {
    setSession({ publicKey: "wallet-user", authToken: "wallet-token", appKey: KEY_B });
    expect(getEmail()).toBeNull();
    expect(getPbkdf2Iterations()).toBeNull();
    expect(getPublicKey()).toBe("wallet-user");
  });

  it("removes the previous hardware wallet envelope for an email session", () => {
    setSession({
      publicKey: "hardware-user",
      authToken: "hardware-token",
      appKey: KEY_A,
      offchainEnvelope: "v0",
    });
    setSession({
      publicKey: "email-user",
      authToken: "email-token",
      appKey: KEY_B,
      email: "b@example.com",
      pbkdf2Iterations: 600000,
    });
    expect(getOffchainEnvelope()).toBeNull();
    expect(getEmail()).toBe("b@example.com");
    expect(getPbkdf2Iterations()).toBe(600000);
  });

  it("removes the previous account's biometric marker and descriptor", () => {
    values.set("ttc_biometric_unlock", "public-test-credential");
    setSession({ publicKey: "account-b", authToken: "token-b", appKey: KEY_B });
    expect(values.has("ttc_biometric_unlock")).toBe(false);
  });
});
