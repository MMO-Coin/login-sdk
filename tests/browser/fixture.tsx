import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { LoginPanel } from "@mmo-coin/login-sdk/ui";
import { AuthProvider, useAuth, useBiometricUnlock, useWallets } from "@mmo-coin/login-sdk/react";
import {
  getAppKey,
  getAuthStatus,
  getPublicKey,
  hasBiometricUnlock,
  registerPasskey,
  derivePasskeySecret,
  type PasskeyRegistration,
} from "@mmo-coin/login-sdk/client";

const config = {
  appId: "browser-passkey-test",
  origin: window.location.origin,
  securityLevel: 1 as const,
  autoLockMs: 300_000,
  lockOnHide: false,
  webauthn: { rpName: "SDK browser test", rpId: "localhost" },
};
let primary: PasskeyRegistration | null = null;
let assertionController: AbortController | null = null;
let releaseCredential: (() => void) | null = null;
const publicPassphrase = "public-browser-test-passphrase-only";

async function fingerprint(value: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function withBlob<T>(
  read: (store: IDBObjectStore, id: string) => Promise<T>,
  mode: IDBTransactionMode,
): Promise<T> {
  const id = localStorage.getItem("ttc_biometric_unlock") ?? "";
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("ttc_passkey_store", 2);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains("unlock_blobs"))
        request.result.createObjectStore("unlock_blobs");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await read(db.transaction("unlock_blobs", mode).objectStore("unlock_blobs"), id);
  } finally {
    db.close();
  }
}

export interface PasskeySnapshot {
  status: string;
  publicKey: string | null;
  keyFingerprint: string | null;
  enabled: boolean;
  registrationStored: boolean;
  storageContainsAppKey: boolean;
}
export interface PasskeyTestApi {
  snapshot: () => Promise<PasskeySnapshot>;
  blobCount: () => Promise<number>;
  tamperBlob: () => Promise<void>;
  prepareAbortableAssertion: () => void;
  cancelAssertion: () => void;
  assertionStarted: boolean;
  credentialResultReady: boolean;
  deferCredentialResult: (kind: "get" | "create") => void;
  releaseCredentialResult: () => void;
}
declare global {
  interface Window {
    passkeyTest: PasskeyTestApi;
  }
}
window.passkeyTest = {
  async snapshot() {
    const key = getAppKey();
    return {
      status: getAuthStatus(),
      publicKey: getPublicKey(),
      keyFingerprint: key ? await fingerprint(key) : null,
      enabled: hasBiometricUnlock(),
      registrationStored: localStorage.getItem("ttc_biometric_reg") !== null,
      storageContainsAppKey:
        !!key && Object.values(localStorage).some((value) => String(value).includes(key)),
    };
  },
  blobCount: () =>
    withBlob(
      (store) =>
        new Promise((resolve, reject) => {
          const request = store.count();
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        }),
      "readonly",
    ),
  tamperBlob: () =>
    withBlob(
      (store, id) =>
        new Promise<void>((resolve, reject) => {
          const request = store.get(id);
          request.onsuccess = () => {
            const blob = request.result;
            const bytes = new Uint8Array(blob.ciphertext);
            bytes[0] = bytes[0]! ^ 1;
            store.put(blob, id);
          };
          request.onerror = () => reject(request.error);
          store.transaction.oncomplete = () => resolve();
          store.transaction.onerror = () => reject(store.transaction.error);
        }),
      "readwrite",
    ),
  credentialResultReady: false,
  deferCredentialResult(kind) {
    const gate = new Promise<void>((resolve) => {
      releaseCredential = resolve;
    });
    window.passkeyTest.credentialResultReady = false;
    if (kind === "get") {
      const nativeGet = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = async (options) => {
        navigator.credentials.get = nativeGet;
        const credential = await nativeGet(options);
        window.passkeyTest.credentialResultReady = true;
        await gate;
        return credential;
      };
    } else {
      const nativeCreate = navigator.credentials.create.bind(navigator.credentials);
      navigator.credentials.create = async (options) => {
        navigator.credentials.create = nativeCreate;
        const credential = await nativeCreate(options);
        window.passkeyTest.credentialResultReady = true;
        await gate;
        return credential;
      };
    }
  },
  releaseCredentialResult() {
    releaseCredential?.();
  },
  assertionStarted: false,
  prepareAbortableAssertion() {
    const nativeGet = navigator.credentials.get.bind(navigator.credentials);
    assertionController = new AbortController();
    window.passkeyTest.assertionStarted = false;
    navigator.credentials.get = (options) => {
      navigator.credentials.get = nativeGet;
      window.passkeyTest.assertionStarted = true;
      // Only cancellation is controlled. The credential and PRF result come from Chromium.
      return nativeGet({ ...options, signal: assertionController!.signal });
    };
  },
  cancelAssertion() {
    assertionController?.abort();
  },
};

function Harness() {
  const auth = useAuth();
  const biometric = useBiometricUnlock();
  const wallets = useWallets();
  const [operation, setOperation] = useState("Ready");
  const [errorName, setErrorName] = useState("");
  const [probe, setProbe] = useState("");
  async function run(action: () => unknown | Promise<unknown>) {
    setOperation("Working");
    setErrorName("");
    try {
      await action();
      setOperation("Done");
    } catch (error) {
      setErrorName(error instanceof Error ? error.name : "UnknownError");
      setOperation("Failed");
    }
  }
  return (
    <main>
      <h1>SDK passkey browser tests</h1>
      <output data-testid="status">{auth.status}</output>
      <output data-testid="available">{String(biometric.available)}</output>
      <output data-testid="enabled">{String(biometric.isEnabled)}</output>
      <output data-testid="operation">{operation}</output>
      <output data-testid="error-name">{errorName}</output>
      <output data-testid="wallets">{JSON.stringify(wallets.map((wallet) => wallet.address))}</output>
      <output data-testid="probe">{probe}</output>
      <section aria-label="Packaged login panel">
        <LoginPanel methods={["biometric"]} biometricUserName="browser-ui-test" />
      </section>
      <button
        onClick={() =>
          void run(() =>
            auth.registerWithEmail({
              email: "browser-" + crypto.randomUUID() + "@example.invalid",
              passkey: publicPassphrase,
            }),
          )
        }
      >
        Create email account
      </button>
      <button onClick={() => void run(() => biometric.enable("browser-test"))}>Enable passkey unlock</button>
      <button onClick={() => void run(() => auth.lock())}>Lock wallet</button>
      <button onClick={() => void run(() => biometric.unlock())}>Unlock with passkey</button>
      <button onClick={() => void run(() => biometric.disable())}>Disable passkey unlock</button>
      <button onClick={() => void run(() => auth.logout())}>Sign out</button>
      <button
        onClick={() =>
          void run(async () => {
            const created = await auth.registerWithBiometric({ userName: "browser-test" });
            primary = created.registration;
          })
        }
      >
        Register passkey account
      </button>
      <button
        onClick={() =>
          void run(() => {
            if (!primary) throw new Error("No primary credential");
            return auth.loginWithBiometric({ registration: primary });
          })
        }
      >
        Sign in with passkey
      </button>
      <button
        onClick={() =>
          void run(async () => {
            const reg = await registerPasskey(config.webauthn, "prf-test");
            const first = await derivePasskeySecret(reg);
            const second = await derivePasskeySecret(reg);
            const salt = new Uint8Array(32);
            crypto.getRandomValues(salt);
            const encoded = btoa(String.fromCharCode(...salt))
              .replace(/\+/g, "-")
              .replace(/\//g, "_")
              .replace(/=+$/, "");
            const changed = await derivePasskeySecret({ ...reg, salt: encoded });
            setProbe(
              JSON.stringify({
                first: await fingerprint(first),
                second: await fingerprint(second),
                changed: await fingerprint(changed),
              }),
            );
          })
        }
      >
        Probe native PRF
      </button>
    </main>
  );
}
createRoot(document.getElementById("root")!).render(
  <AuthProvider apiBaseUrl="/auth" config={config} walletGen={{ solana: ["funds"], evm: ["funds"] }}>
    <Harness />
  </AuthProvider>,
);
