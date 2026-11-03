import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { AuthClient } from "../src/client/authClient";
import { deriveAuthPublicKey } from "../src/client/authKey";
import {
  createEncryptedRecoveryKit,
  MAX_RECOVERY_KIT_BYTES,
  openRecoveryKit,
  parseRecoveryKit,
  serializeRecoveryKit,
  type CreatedRecoveryKit,
} from "../src/client/recovery";
import {
  captureSessionValidation,
  clearSession,
  getAppKey,
  getAuthToken,
  getPublicKey,
  getSessionState,
  lockVault,
  setSession,
} from "../src/client/session";
import { generateWalletBundle, flattenBundle } from "../src/client/wallet";
import { decryptSecret, deriveAppKeyFromPasskey, encryptSecret } from "../src/core/crypto";
import { createAuthHandlers, type AuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { KvAuthStore } from "../src/storage/store";
import type { UserData } from "../src/core/types";
import legacy from "./fixtures/tetrac-0.6.0.json";

const ORIGIN = "https://recovery.example";
const APP_ID = "recovery-test";
const EMAIL = "reader@example.com";
const PASSPHRASE = "Synthetic recovery test passphrase";
const originalFetch = globalThis.fetch;
const originalGlobals = new Map(
  ["window", "document", "localStorage"].map((key) => [
    key,
    Object.getOwnPropertyDescriptor(globalThis, key),
  ]),
);
let client: AuthClient;
let store: KvAuthStore;
let handlers: AuthHandlers;
let requests: string[];
let responseHook: ((path: string, response: Response) => Promise<Response>) | undefined;

function installBrowser() {
  const data = new Map<string, string>();
  const noop = () => {};
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => data.set(key, value),
      removeItem: (key: string) => data.delete(key),
      clear: () => data.clear(),
    },
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: { origin: ORIGIN, hostname: "recovery.example" },
      addEventListener: noop,
      removeEventListener: noop,
      dispatchEvent: () => true,
    },
  });
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { visibilityState: "visible", addEventListener: noop, removeEventListener: noop },
  });
}

function newClient(appId = APP_ID) {
  return new AuthClient({
    apiBaseUrl: "/auth",
    config: { appId, origin: ORIGIN, securityLevel: 1, autoLockMs: 600_000, lockOnHide: false },
    walletGen: { solana: ["funds"], evm: ["funds"] },
  });
}

beforeEach(() => {
  installBrowser();
  clearSession();
  store = new KvAuthStore(new MemoryAdapter());
  handlers = createAuthHandlers({
    store,
    config: { appId: APP_ID, allowedAppIds: [APP_ID, legacy.appId], origin: ORIGIN, trustProxyHeaders: true },
  });
  requests = [];
  responseHook = undefined;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), ORIGIN);
    const path = url.pathname.split("/").pop()!;
    requests.push(path);
    const table: Record<string, (request: Request) => Promise<Response>> = {
      challenge: handlers.challenge,
      register: handlers.register,
      login: handlers.login,
      "user-data": handlers.userData,
      "connect-wallet": handlers.connectWallet,
      logout: handlers.logout,
    };
    const response = await table[path]!(
      new Request(url, {
        method: init?.method ?? "GET",
        headers: init?.headers,
        body: init?.body as BodyInit,
      }),
    );
    return responseHook ? responseHook(path, response) : response;
  }) as typeof fetch;
  client = newClient();
});

afterEach(() => {
  clearSession();
  globalThis.fetch = originalFetch;
});
afterAll(() => {
  for (const [key, descriptor] of originalGlobals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
});

async function accountAndBackup() {
  const registered = await client.registerWithEmail({ email: EMAIL, passkey: PASSPHRASE });
  const backup = await client.createRecoveryKit({ passkey: PASSPHRASE });
  return { registered, backup, appKey: getAppKey()! };
}

async function changedPayload(backup: CreatedRecoveryKit, change: (payload: any) => void) {
  const key = backup.recoveryCode.replace(/[\s-]/g, "").slice(4).toLowerCase();
  const payload = JSON.parse(await decryptSecret(backup.kit.ciphertext, key));
  change(payload);
  return { ...backup.kit, ciphertext: await encryptSecret(JSON.stringify(payload), key) };
}

it("exports only encrypted content, uses independently generated codes and never changes the stored wallets", async () => {
  const { registered, backup, appKey } = await accountAndBackup();
  const second = await client.createRecoveryKit({ passkey: PASSPHRASE });
  expect(second.recoveryCode).not.toBe(backup.recoveryCode);
  expect(second.kit.ciphertext).not.toBe(backup.kit.ciphertext);
  expect(backup.recoveryCode).toMatch(/^MMO1-(?:[A-F0-9]{8}-){7}[A-F0-9]{8}$/);
  const json = serializeRecoveryKit(backup.kit);
  for (const secret of [appKey, PASSPHRASE, EMAIL, registered.authToken, backup.recoveryCode])
    expect(json).not.toContain(secret);
  expect(parseRecoveryKit(json)).toEqual(backup.kit);
  expect((await store.getUser(APP_ID, registered.publicKey))!.wallets).toEqual(registered.user.wallets);
  expect(getAppKey()).toBe(appKey);
});

it("verifies a downloaded file offline while locked without arming the key or sending requests", async () => {
  const { backup } = await accountAndBackup();
  lockVault();
  const count = requests.length;
  const verified = await client.verifyRecoveryKit(
    serializeRecoveryKit(backup.kit),
    backup.recoveryCode.toLowerCase(),
  );
  expect(verified).toEqual(backup.verification);
  expect(verified.wallets).toHaveLength(2);
  expect(JSON.stringify(verified)).not.toContain("encryptedSecret");
  expect(getAppKey()).toBeNull();
  expect(requests).toHaveLength(count);
});

it("requires fresh correct credentials to create a kit and does not unlock a locked vault", async () => {
  await client.registerWithEmail({ email: EMAIL, passkey: PASSPHRASE });
  lockVault();
  await expect(client.createRecoveryKit({ passkey: "wrong" })).rejects.toThrow(/wrong credentials/);
  const backup = await client.createRecoveryKit({ passkey: PASSPHRASE });
  expect(backup.verification.email).toBe(EMAIL);
  expect(getAppKey()).toBeNull();
});

it("recovers the exact original Solana/EVM wallets on a fresh browser session without registering or importing", async () => {
  const { registered, backup, appKey } = await accountAndBackup();
  const originalWallets = registered.user.wallets;
  clearSession();
  requests.length = 0;
  const recovered = await client.recoverWithKit({
    kit: serializeRecoveryKit(backup.kit),
    recoveryCode: backup.recoveryCode,
  });
  expect(recovered.publicKey).toBe(registered.publicKey);
  expect(recovered.user.wallets).toEqual(originalWallets);
  expect(recovered.authToken).not.toBe(registered.authToken);
  expect(getAppKey()).toBe(appKey);
  expect(requests).toEqual(["challenge", "login"]);
  expect((await store.getUser(APP_ID, registered.publicKey))!.wallets).toEqual(originalWallets);
  // Normal credentials still work. Recovery does not reset or rotate them.
  clearSession();
  expect((await client.loginWithEmail({ email: EMAIL, passkey: PASSPHRASE })).publicKey).toBe(
    registered.publicKey,
  );
});

it("can recover biometric-primary accounts without requiring their old device", async () => {
  const appKey = "ab".repeat(32);
  const wallets = flattenBundle(await generateWalletBundle({ appKey, solana: ["funds"], evm: ["funds"] }));
  const user: UserData = {
    appId: APP_ID,
    publicKey: wallets[0]!.publicKey,
    email: "bio_fixture@passkey.local",
    authMethod: "biometric",
    authPublicKey: deriveAuthPublicKey(appKey),
    wallets,
    createdAt: Date.now(),
  };
  await store.putUser(user);
  const backup = await createEncryptedRecoveryKit(user, appKey, ORIGIN);
  const recovered = await client.recoverWithKit({ kit: backup.kit, recoveryCode: backup.recoveryCode });
  expect(recovered.user.authMethod).toBe("biometric");
  expect(recovered.user.wallets).toEqual(wallets);
  expect(getAppKey()).toBe(appKey);
});

it.each([
  "wrong code",
  "ciphertext tampering",
  "unknown version",
  "extra field",
  "oversize",
  "cross app",
  "cross origin",
])("rejects %s before any authentication request", async (mode) => {
  const { backup } = await accountAndBackup();
  clearSession();
  requests.length = 0;
  let kit: unknown = backup.kit;
  let code = backup.recoveryCode;
  let receiver = client;
  if (mode === "wrong code") code = "MMO1-" + "12".repeat(32);
  if (mode === "ciphertext tampering")
    kit = {
      ...backup.kit,
      ciphertext:
        backup.kit.ciphertext.slice(0, 20) +
        (backup.kit.ciphertext[20] === "A" ? "B" : "A") +
        backup.kit.ciphertext.slice(21),
    };
  if (mode === "unknown version") kit = { ...backup.kit, version: 2 };
  if (mode === "extra field") kit = { ...backup.kit, url: "https://attacker.example" };
  if (mode === "oversize") kit = "x".repeat(MAX_RECOVERY_KIT_BYTES + 1);
  if (mode === "cross app") receiver = newClient("other-app");
  if (mode === "cross origin") (globalThis.window as any).location.origin = "https://another.example";
  await expect(receiver.recoverWithKit({ kit, recoveryCode: code })).rejects.toThrow();
  expect(requests).toEqual([]);
  expect(getAppKey()).toBeNull();
  expect(getAuthToken()).toBeNull();
});

it.each(["wallet address", "auth key", "duplicate slot", "unknown payload field", "short app key"])(
  "rejects a decrypted kit with an invalid %s before networking",
  async (mode) => {
    const { backup } = await accountAndBackup();
    const kit = await changedPayload(backup, (payload) => {
      if (mode === "wallet address")
        payload.user.wallets.find((wallet: any) => wallet.chain === "evm").publicKey = "0x" + "11".repeat(20);
      if (mode === "auth key") payload.user.authPublicKey = "00".repeat(32);
      if (mode === "duplicate slot") payload.user.wallets.push(payload.user.wallets[0]);
      if (mode === "unknown payload field") payload.callback = "https://attacker.example";
      if (mode === "short app key") payload.appKey = "1234";
    });
    clearSession();
    requests.length = 0;
    await expect(client.recoverWithKit({ kit, recoveryCode: backup.recoveryCode })).rejects.toThrow();
    expect(requests).toEqual([]);
    expect(getAppKey()).toBeNull();
  },
);

it("fails closed if the server record is missing, without registering a new account", async () => {
  const { backup } = await accountAndBackup();
  clearSession();
  handlers = createAuthHandlers({ storage: new MemoryAdapter(), config: { appId: APP_ID, origin: ORIGIN } });
  requests.length = 0;
  await expect(client.recoverWithKit({ kit: backup.kit, recoveryCode: backup.recoveryCode })).rejects.toThrow(
    /Invalid credentials/,
  );
  expect(requests).toEqual(["challenge", "login"]);
  expect(getAppKey()).toBeNull();
});

it("rejects a replaced wallet slot on the server without overwriting it or arming a session", async () => {
  const { registered, backup, appKey } = await accountAndBackup();
  const replacement = flattenBundle(await generateWalletBundle({ appKey, evm: ["funds"] }))[0]!;
  await store.putWalletSlot(APP_ID, registered.publicKey, replacement);
  clearSession();
  await expect(client.recoverWithKit({ kit: backup.kit, recoveryCode: backup.recoveryCode })).rejects.toThrow(
    /wallet changed/,
  );
  expect(getAppKey()).toBeNull();
  expect(getAuthToken()).toBeNull();
  expect((await store.getUser(APP_ID, registered.publicKey))!.wallets).toContainEqual(replacement);
});

it("validates newly added wallet slots under the recovered key without replacing the saved slots", async () => {
  const { registered, backup, appKey } = await accountAndBackup();
  const added = flattenBundle(await generateWalletBundle({ appKey, evm: ["signing"] }))[0]!;
  await store.putWalletSlot(APP_ID, registered.publicKey, added);
  clearSession();
  const result = await client.recoverWithKit({ kit: backup.kit, recoveryCode: backup.recoveryCode });
  expect(result.user.wallets).toHaveLength(3);
  expect(result.user.wallets).toContainEqual(added);
});

it("rejects a newly added wallet encrypted under another key", async () => {
  const { registered, backup } = await accountAndBackup();
  const added = flattenBundle(await generateWalletBundle({ appKey: "cd".repeat(32), evm: ["signing"] }))[0]!;
  await store.putWalletSlot(APP_ID, registered.publicKey, added);
  clearSession();
  await expect(
    client.recoverWithKit({ kit: backup.kit, recoveryCode: backup.recoveryCode }),
  ).rejects.toThrow();
  expect(getAppKey()).toBeNull();
  expect(getAuthToken()).toBeNull();
});

it.each(["iterations", "email", "method", "auth key", "account"])(
  "rejects unexpected server %s metadata before saving a session",
  async (field) => {
    const { backup } = await accountAndBackup();
    clearSession();
    responseHook = async (path, response) => {
      if (path !== "login") return response;
      const body = await response.json();
      if (field === "iterations") body.user.pbkdf2Iterations += 1;
      if (field === "email") body.user.email = "other@example.com";
      if (field === "method") body.user.authMethod = "biometric";
      if (field === "auth key") body.user.authPublicKey = "00".repeat(32);
      if (field === "account") body.user.publicKey = Keypair.generate().publicKey.toBase58();
      return new Response(JSON.stringify(body));
    };
    await expect(
      client.recoverWithKit({ kit: backup.kit, recoveryCode: backup.recoveryCode }),
    ).rejects.toThrow(/does not match/);
    expect(getAppKey()).toBeNull();
    expect(getAuthToken()).toBeNull();
  },
);

it("recovers the same account after its saved token is known to be expired", async () => {
  const { registered, backup, appKey } = await accountAndBackup();
  captureSessionValidation()("expired");
  expect(getSessionState().session).toBe("expired");
  const result = await client.recoverWithKit({ kit: backup.kit, recoveryCode: backup.recoveryCode });
  expect(result.publicKey).toBe(registered.publicKey);
  expect(getSessionState().session).toBe("valid");
  expect(getAppKey()).toBe(appKey);
});

it("discards an aborted decryption before requesting an authentication challenge", async () => {
  const { backup } = await accountAndBackup();
  clearSession();
  requests.length = 0;
  const controller = new AbortController();
  const pending = client.recoverWithKit({
    kit: backup.kit,
    recoveryCode: backup.recoveryCode,
    signal: controller.signal,
  });
  controller.abort();
  await expect(pending).rejects.toThrow();
  expect(requests).toEqual([]);
  expect(getAppKey()).toBeNull();
});

it("rejects another logged-in identity before proof and cannot switch accounts silently", async () => {
  const { backup } = await accountAndBackup();
  clearSession();
  await client.registerWithEmail({ email: "other@example.com", passkey: PASSPHRASE });
  const current = getPublicKey();
  const appKey = getAppKey();
  requests.length = 0;
  await expect(client.recoverWithKit({ kit: backup.kit, recoveryCode: backup.recoveryCode })).rejects.toThrow(
    /Log out/,
  );
  expect(requests).toEqual([]);
  expect(getPublicKey()).toBe(current);
  expect(getAppKey()).toBe(appKey);
});

it.each(["logout", "abort", "account switch", "lock"])(
  "does not arm recovery when %s happens while the login response is in flight",
  async (mode) => {
    const { backup } = await accountAndBackup();
    clearSession();
    const controller = new AbortController();
    responseHook = async (path, response) => {
      if (path === "login") {
        if (mode === "logout") clearSession();
        if (mode === "abort") controller.abort();
        if (mode === "lock") lockVault();
        if (mode === "account switch")
          setSession({
            authToken: "ef".repeat(32),
            publicKey: Keypair.generate().publicKey.toBase58(),
            appKey: "de".repeat(32),
          });
      }
      return response;
    };
    await expect(
      client.recoverWithKit({
        kit: backup.kit,
        recoveryCode: backup.recoveryCode,
        signal: controller.signal,
      }),
    ).rejects.toThrow();
    if (mode === "account switch") expect(getAppKey()).toBe("de".repeat(32));
    else expect(getAppKey()).toBeNull();
  },
);

it("rejects an already aborted recovery before crypto or network work", async () => {
  const controller = new AbortController();
  controller.abort();
  await expect(
    client.recoverWithKit({ kit: {}, recoveryCode: "x", signal: controller.signal }),
  ).rejects.toThrow();
  expect(requests).toEqual([]);
});

it("backs up wallets under legacy derivation inputs without changing the original encrypted fixture", async () => {
  const appKey = deriveAppKeyFromPasskey(legacy.passphrase, legacy.email, legacy.iterations, legacy.appId);
  expect(appKey).toBe(legacy.appKey);
  // The historical encrypted fixture is a generic 64-byte test string, rather
  // than a valid wallet key. Keep it unchanged and verify its original bytes.
  expect(await decryptSecret(legacy.ciphertext, appKey)).toBe(legacy.secret);
  const wallets = flattenBundle(await generateWalletBundle({ appKey, solana: ["funds"], evm: ["funds"] }));
  const user: UserData = {
    appId: legacy.appId,
    publicKey: wallets[0]!.publicKey,
    email: legacy.email.toLowerCase().trim(),
    authMethod: "email",
    authPublicKey: legacy.authPublicKey,
    pbkdf2Iterations: legacy.iterations,
    createdAt: Date.now(),
    wallets,
  };
  const backup = await createEncryptedRecoveryKit(user, appKey, legacy.origin);
  const opened = await openRecoveryKit(backup.kit, backup.recoveryCode, legacy.appId, legacy.origin);
  expect(opened.payload.appKey).toBe(legacy.appKey);
  expect(opened.payload.user.wallets).toEqual(wallets);
  expect(opened.payload.user.pbkdf2Iterations).toBe(legacy.iterations);
  expect(await decryptSecret(legacy.ciphertext, opened.payload.appKey)).toBe(legacy.secret);
});

it("keeps external-wallet recovery with the original wallet", async () => {
  const pair = Keypair.generate();
  await client.connectWallet({
    publicKey: pair.publicKey.toBase58(),
    signMessage: async (message) => nacl.sign.detached(message, pair.secretKey),
  });
  await expect(
    client.createRecoveryKit({ signMessage: async (message) => nacl.sign.detached(message, pair.secretKey) }),
  ).rejects.toThrow(/External wallet/);
  pair.secretKey.fill(0);
});
