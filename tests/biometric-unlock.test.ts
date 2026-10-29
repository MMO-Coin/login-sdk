// unlockViaBiometric — optional biometric UNLOCK for ANY account (PRD §7, §12).
//
// Verifies the wrap/unwrap round-trip arms the EXACT app key for both an
// email-style key (PBKDF2 hex) and a web3-style key (SHA256 hex); that enable
// throws when the vault is locked; that a tampered AES-GCM blob and a declined
// assertion both fail closed; that disable purges the blob; that an authenticator
// without PRF is REFUSED rather than downgraded; and the DISTINCTION GUARD — for
// the same credential, `{ registration }` (primary) and `{ biometricUnlock }`
// (wrap) resolve to DIFFERENT keys.
//
// Runs in the node env with Web Crypto (Node 18+), against an in-memory IndexedDB
// + navigator.credentials mock with a switchable PRF assertion. Only ephemeral key
// material is used.
import { deriveAppKeyFromPasskey, deriveAppKeyFromSignature } from "../src/core/crypto";

const subtle = globalThis.crypto?.subtle;
const describeCrypto = subtle ? describe : describe.skip;

// --- in-memory IndexedDB shim (shared v2 DB; multi-store; supports delete) ---

type StoreMap = Map<string, unknown>;
let assertionGate: Promise<void> | null = null;
let writeGate: { wait: Promise<void>; started: () => void } | null = null;
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function makeIdbShim() {
  // dbName -> { version, stores: Map<storeName, StoreMap> }
  const dbs = new Map<string, { version: number; stores: Map<string, StoreMap> }>();

  function makeDb(name: string) {
    const entry = dbs.get(name)!;
    const dbObj = {
      get objectStoreNames() {
        return { contains: (s: string) => entry.stores.has(s) };
      },
      createObjectStore(s: string) {
        entry.stores.set(s, new Map());
      },
      transaction(s: string) {
        const store = entry.stores.get(s)!;
        const tx: {
          objectStore: () => {
            put: (value: unknown, key: string) => void;
            get: (key: string) => { onsuccess?: () => void; onerror?: () => void; result?: unknown };
            delete: (key: string) => void;
          };
          oncomplete?: () => void;
          onerror?: () => void;
          error?: unknown;
        } = {
          objectStore: () => ({
            put(value: unknown, key: string) {
              const commit = () => {
                store.set(key, value);
                queueMicrotask(() => tx.oncomplete?.());
              };
              if (writeGate) {
                writeGate.started();
                void writeGate.wait.then(commit);
              } else commit();
            },
            get(key: string) {
              const req: { onsuccess?: () => void; onerror?: () => void; result?: unknown } = {};
              queueMicrotask(() => {
                req.result = store.get(key);
                req.onsuccess?.();
              });
              return req;
            },
            delete(key: string) {
              store.delete(key);
              queueMicrotask(() => tx.oncomplete?.());
            },
          }),
        };
        return tx;
      },
    };
    return dbObj;
  }

  return {
    dbs,
    open(name: string, version: number) {
      const req: {
        onupgradeneeded?: () => void;
        onsuccess?: () => void;
        onerror?: () => void;
        result?: unknown;
        error?: unknown;
      } = {};
      queueMicrotask(() => {
        const existing = dbs.get(name);
        const oldVersion = existing?.version ?? 0;
        if (!existing) dbs.set(name, { version, stores: new Map() });
        else if (version > existing.version) existing.version = version;
        req.result = makeDb(name);
        if (version > oldVersion) req.onupgradeneeded?.();
        req.onsuccess?.();
      });
      return req;
    },
  };
}

const idb = makeIdbShim();

// --- localStorage shim (for the sync hasBiometricUnlock marker) ---

function storageShim(): Storage {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    key: () => null,
    get length() {
      return m.size;
    },
  } as Storage;
}

// --- WebAuthn mock: PRF supported or not, and decline ---

let prfSupported = true;
let declineAssertion = false;
// Deterministic PRF output per (credentialId via the assertion). We key it on a
// module-scope value set right before derivePasskeySecret runs.
let nextPrfHex = "11".repeat(32);

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out.buffer;
}

// rawId returned by create(): a stable 4-byte id "AAAA" decodes from the b64url
// the SDK assigns. We mint a fresh random id per registration instead.
function randomRawId(): ArrayBuffer {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  return b.buffer;
}

let pendingRawId: ArrayBuffer = randomRawId();

function makeNavigator() {
  return {
    credentials: {
      create: async () => ({
        rawId: pendingRawId,
        getClientExtensionResults: () => (prfSupported ? { prf: { enabled: true } } : {}),
      }),
      get: async () => {
        if (assertionGate) await assertionGate;
        if (declineAssertion) return null; // user declined / cancelled
        return {
          getClientExtensionResults: () =>
            prfSupported ? { prf: { results: { first: hexToArrayBuffer(nextPrfHex) } } } : {},
        };
      },
    },
  };
}

beforeAll(() => {
  Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true });
  Object.defineProperty(globalThis, "indexedDB", { value: idb, configurable: true });
  Object.defineProperty(globalThis, "localStorage", { value: storageShim(), configurable: true });
  Object.defineProperty(globalThis, "sessionStorage", { value: storageShim(), configurable: true });
  Object.defineProperty(globalThis, "navigator", { value: makeNavigator(), configurable: true });
  // configureVault binds a visibilitychange listener once window exists.
  Object.defineProperty(globalThis, "document", {
    value: { addEventListener: () => {}, visibilityState: "visible" },
    configurable: true,
  });
});

// Import AFTER the globals exist so the modules' browser paths are live.
// (Static import is hoisted, but these modules only touch the globals lazily.)
import {
  enableBiometricUnlock,
  unlockViaBiometric,
  disableBiometricUnlock,
  hasBiometricUnlock,
  unwrapAppKey,
} from "../src/client/biometricUnlock";
import { derivePasskeySecret, type PasskeyRegistration } from "../src/client/webauthn";
import {
  armAppKey,
  getAppKey,
  lockVault,
  clearSession,
  configureVault,
  VaultLockedError,
  SessionChangedError,
  setSession,
} from "../src/client/session";

const cfg = { rpId: "localhost", rpName: "TTC test" };

async function freshEnable(appKey: string): Promise<PasskeyRegistration> {
  prfSupported = true;
  declineAssertion = false;
  pendingRawId = randomRawId();
  configureVault({ autoLockMs: 60_000 });
  armAppKey(appKey);
  expect(getAppKey()).toBe(appKey);
  const reg = await enableBiometricUnlock(cfg, "user");
  return reg;
}

describeCrypto("biometric unlock — wrap/unwrap round-trip", () => {
  beforeEach(() => {
    lockVault();
    localStorage.clear();
    declineAssertion = false;
  });

  // Drop the in-memory key + clear the pending auto-lock timer so Jest exits.
  afterAll(() => {
    lockVault();
  });

  it("PRF mode: round-trips an email-style app key (PBKDF2 output)", async () => {
    const appKey = deriveAppKeyFromPasskey("hunter2-ephemeral", "user@example.com", 1_000);
    const reg = await freshEnable(appKey);
    expect(hasBiometricUnlock()).toBe(true);

    lockVault();
    expect(getAppKey()).toBeNull();

    await unlockViaBiometric(reg);
    expect(getAppKey()).toBe(appKey); // exact app key re-armed
  });

  it("round-trips a web3-style app key (SHA256 output)", async () => {
    const appKey = deriveAppKeyFromSignature("ab".repeat(32));
    const reg = await freshEnable(appKey);

    lockVault();
    await unlockViaBiometric(reg);
    expect(getAppKey()).toBe(appKey);
  });

  it("enable throws VaultLockedError when the vault is locked", async () => {
    configureVault({ autoLockMs: 60_000 });
    lockVault();
    expect(getAppKey()).toBeNull();
    await expect(enableBiometricUnlock(cfg, "user")).rejects.toBeInstanceOf(VaultLockedError);
    expect(hasBiometricUnlock()).toBe(false);
  });

  it("a tampered AES-GCM blob fails closed (auth tag check)", async () => {
    const appKey = deriveAppKeyFromSignature("cd".repeat(32));
    const reg = await freshEnable(appKey);

    // Flip a ciphertext byte in the stored blob.
    const store = idb.dbs.get("ttc_passkey_store")!.stores.get("unlock_blobs")!;
    const blob = store.get(reg.credentialId) as { v: 1; iv: Uint8Array; ciphertext: ArrayBuffer };
    const ct = new Uint8Array(blob.ciphertext);
    ct[0] ^= 0xff;
    blob.ciphertext = ct.buffer;

    lockVault();
    await expect(unlockViaBiometric(reg)).rejects.toThrow();
    expect(getAppKey()).toBeNull(); // never armed a wrong/garbage key
  });

  it("a declined/absent assertion fails closed", async () => {
    const appKey = deriveAppKeyFromSignature("ef".repeat(32));
    const reg = await freshEnable(appKey);

    lockVault();
    declineAssertion = true;
    await expect(unlockViaBiometric(reg)).rejects.toThrow();
    expect(getAppKey()).toBeNull();
  });

  it("disable purges the blob (subsequent unlock fails closed)", async () => {
    const appKey = deriveAppKeyFromSignature("12".repeat(32));
    const reg = await freshEnable(appKey);
    expect(hasBiometricUnlock()).toBe(true);

    await disableBiometricUnlock(reg);
    expect(hasBiometricUnlock()).toBe(false);

    const store = idb.dbs.get("ttc_passkey_store")!.stores.get("unlock_blobs")!;
    expect(store.get(reg.credentialId)).toBeUndefined();

    lockVault();
    declineAssertion = false;
    await expect(unlockViaBiometric(reg)).rejects.toThrow(); // no blob -> fail closed
  });

  it("clearSession (logout) purges the unlock blob (PRD §7)", async () => {
    // The clearSession hook is a DISTINCT path from disableBiometricUnlock: it
    // reads the credentialId from the localStorage marker (not a registration
    // arg) and fires the async purge best-effort.
    const appKey = deriveAppKeyFromSignature("34".repeat(32));
    const reg = await freshEnable(appKey);
    expect(hasBiometricUnlock()).toBe(true);

    const blobStore = idb.dbs.get("ttc_passkey_store")!.stores.get("unlock_blobs")!;
    expect(blobStore.get(reg.credentialId)).toBeDefined();

    clearSession();
    // Marker is removed synchronously inside the hook.
    expect(hasBiometricUnlock()).toBe(false);

    // The durable store is cleared asynchronously (best-effort); the in-memory
    // shim resolves via queueMicrotask, so drain the event loop before asserting.
    await new Promise((r) => setTimeout(r, 0));
    expect(blobStore.get(reg.credentialId)).toBeUndefined();

    // No blob -> a subsequent unlock fails closed.
    lockVault();
    declineAssertion = false;
    await expect(unlockViaBiometric(reg)).rejects.toThrow();
    expect(getAppKey()).toBeNull();
  });

  it("🚨 an authenticator without PRF is REFUSED, never downgraded to on-device storage", async () => {
    // Gate mode used to cover this case by minting a random secret and keeping it in
    // IndexedDB under a non-extractable AES-GCM key. That key's HANDLE sat beside its
    // own ciphertext, so any same-origin script could decrypt it with no biometric
    // ceremony — and for a biometric-PRIMARY account that secret WAS the app key, i.e.
    // IndexedDB was its sole custodian. The mode is gone: no PRF, no credential.
    prfSupported = false;
    declineAssertion = false;
    pendingRawId = randomRawId();
    configureVault({ autoLockMs: 60_000 });
    armAppKey("aa".repeat(32));

    await expect(enableBiometricUnlock(cfg, "user")).rejects.toThrow(/PRF extension/);

    // Nothing was persisted on the way out.
    const db = idb.dbs.get("ttc_passkey_store");
    expect(db?.stores.get("gate_secrets")).toBeUndefined(); // the store no longer exists
    expect(hasBiometricUnlock()).toBe(false);
    prfSupported = true;
  });

  it("DISTINCTION GUARD: { registration } secret != { biometricUnlock } unwrapped key", async () => {
    // For the SAME credential: derivePasskeySecret(reg) (the biometric-PRIMARY
    // path) must NOT equal the app key recovered by unwrapping the blob (the
    // biometric-UNLOCK path). Confusing the two is the exact bug this prevents.
    const appKey = deriveAppKeyFromPasskey("ephemeral-pw", "guard@example.com", 1_000);
    const reg = await freshEnable(appKey);

    const primarySecret = await derivePasskeySecret(reg); // would be the app key for a PRIMARY account
    const unlockedKey = await unwrapAppKey(reg.credentialId, primarySecret); // the wrap path

    expect(unlockedKey).toBe(appKey); // unlock recovers the account's real key
    expect(primarySecret).not.toBe(unlockedKey); // ...and that is NOT the raw secret
    expect(primarySecret).toBe(nextPrfHex); // sanity: primary path == raw PRF output
  });
});

describeCrypto("biometric operation cancellation", () => {
  beforeEach(() => {
    assertionGate = null;
    writeGate = null;
    clearSession();
    localStorage.clear();
    declineAssertion = false;
    prfSupported = true;
    pendingRawId = randomRawId();
    configureVault({ autoLockMs: 60000 });
  });
  afterEach(() => {
    assertionGate = null;
    writeGate = null;
    clearSession();
  });

  it("does not enable biometric unlock when logout happens during the assertion", async () => {
    armAppKey("aa".repeat(32));
    const gate = deferred<void>();
    assertionGate = gate.promise;
    const pending = enableBiometricUnlock(cfg, "public-test-user");
    await Promise.resolve();
    clearSession();
    gate.resolve();
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
    expect(hasBiometricUnlock()).toBe(false);
    expect(getAppKey()).toBeNull();
  });

  it("removes an unfinished wrapped key when logout happens during its storage write", async () => {
    armAppKey("aa".repeat(32));
    const commit = deferred<void>();
    const started = deferred<void>();
    writeGate = { wait: commit.promise, started: () => started.resolve() };
    const pending = enableBiometricUnlock(cfg, "public-test-user");
    await started.promise;
    clearSession();
    writeGate = null;
    commit.resolve();
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
    const blobs = idb.dbs.get("ttc_passkey_store")!.stores.get("unlock_blobs")!;
    expect(blobs.has(Buffer.from(pendingRawId).toString("base64url"))).toBe(false);
    expect(hasBiometricUnlock()).toBe(false);
    expect(getAppKey()).toBeNull();
  });

  it("does not unlock the old account after an account replacement during the prompt", async () => {
    const registration = await freshEnable("aa".repeat(32));
    lockVault();
    const gate = deferred<void>();
    assertionGate = gate.promise;
    const pending = unlockViaBiometric(registration);
    setSession({ publicKey: "public-account-b", authToken: "public-token-b", appKey: "bb".repeat(32) });
    gate.resolve();
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
    expect(getAppKey()).toBe("bb".repeat(32));
  });

  it("does not remove another credential's marker when disabling an older registration", async () => {
    const first = await freshEnable("aa".repeat(32));
    const second = await freshEnable("bb".repeat(32));
    await disableBiometricUnlock(first);
    expect(localStorage.getItem("ttc_biometric_unlock")).toBe(second.credentialId);
    expect(hasBiometricUnlock()).toBe(true);
  });
});
