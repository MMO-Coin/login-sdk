/** @jest-environment jsdom */
import React from "react";
import { act, renderHook } from "@testing-library/react";
import { AuthClient } from "../src/client/authClient";
import { AuthProvider } from "../src/react/AuthProvider";
import { useUser } from "../src/react/useUser";
import { useSigner } from "../src/react/useSigner";
import { Keypair } from "@solana/web3.js";
import { useExportKey } from "../src/react/useExportKey";
import { useBiometricUnlock } from "../src/react/useBiometricUnlock";
import { clearSession, lockVault, setSession, SessionChangedError } from "../src/client/session";
import { deriveAppKeyFromPasskey, encryptSecret } from "../src/core/crypto";
import type { EncryptedWallet } from "../src/core/types";

const EMAIL = "public-test@example.com";
const PASSPHRASE = "public-test-passphrase";
const APP_ID = "test-app";
const SECRET = "public-test-secret";
const APP_KEY = deriveAppKeyFromPasskey(PASSPHRASE, EMAIL, 100000, APP_ID);
let wallet: EncryptedWallet;
function wrapper({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider
      apiBaseUrl="/auth"
      config={{ appId: APP_ID, origin: window.location.origin, autoLockMs: 60000, lockOnHide: false }}
    >
      {children}
    </AuthProvider>
  );
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
beforeAll(async () => {
  wallet = {
    chain: "solana",
    role: "funds",
    publicKey: "public-wallet-a",
    encryptedSecret: await encryptSecret(SECRET, APP_KEY),
  };
});
beforeEach(() => {
  clearSession();
  localStorage.clear();
  globalThis.fetch = jest.fn(async () => ({
    status: 200,
    ok: true,
    json: async () => ({ user: null }),
  })) as unknown as typeof fetch;
  setSession({
    publicKey: "account-a",
    authToken: "token-a",
    appKey: APP_KEY,
    email: EMAIL,
    pbkdf2Iterations: 100000,
  });
});
afterEach(() => {
  jest.restoreAllMocks();
  lockVault();
});

const lifecycleChanges = [
  { name: "logout", apply: () => clearSession() },
  { name: "lock", apply: () => lockVault() },
  {
    name: "account change",
    apply: () => setSession({ publicKey: "account-b", authToken: "token-b", appKey: "cd".repeat(32) }),
  },
];

describe("revealed private keys", () => {
  it.each(lifecycleChanges)("clears the plaintext on $name while still mounted", async ({ apply }) => {
    const hook = renderHook(() => useExportKey(wallet), { wrapper });
    await act(async () => {});
    await act(async () => {
      await hook.result.current.reveal({ passkey: PASSPHRASE });
    });
    expect(hook.result.current.plaintext).toBe(SECRET);
    await act(async () => {
      apply();
    });
    expect(hook.result.current.plaintext).toBeNull();
    expect(hook.result.current.loading).toBe(false);
  });

  it("clears a previous wallet's plaintext when the wallet prop changes", async () => {
    const hook = renderHook(({ currentWallet }) => useExportKey(currentWallet), {
      wrapper,
      initialProps: { currentWallet: wallet },
    });
    await act(async () => {});
    await act(async () => {
      await hook.result.current.reveal({ passkey: PASSPHRASE });
    });
    const staleReveal = hook.result.current.reveal;
    hook.rerender({ currentWallet: { ...wallet, publicKey: "public-wallet-b" } });
    expect(hook.result.current.plaintext).toBeNull();
    await expect(staleReveal({ passkey: PASSPHRASE })).rejects.toBeInstanceOf(SessionChangedError);
  });

  it("clears the plaintext when an encrypted wallet slot is replaced", async () => {
    const hook = renderHook(({ currentWallet }) => useExportKey(currentWallet), {
      wrapper,
      initialProps: { currentWallet: wallet },
    });
    await act(async () => {});
    await act(async () => {
      await hook.result.current.reveal({ passkey: PASSPHRASE });
    });
    hook.rerender({ currentWallet: { ...wallet, encryptedSecret: "replacement-ciphertext" } });
    expect(hook.result.current.plaintext).toBeNull();
  });

  it.each(lifecycleChanges)(
    "rejects a pending reveal after $name without returning the secret",
    async ({ apply }) => {
      const result = deferred<string>();
      jest.spyOn(AuthClient.prototype, "revealSecret").mockReturnValueOnce(result.promise);
      const hook = renderHook(() => useExportKey(wallet), { wrapper });
      await act(async () => {});
      let pending!: Promise<string>;
      act(() => {
        pending = hook.result.current.reveal({ passkey: PASSPHRASE });
      });
      await act(async () => {
        apply();
      });
      await act(async () => {
        result.resolve(SECRET);
        await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
      });
      expect(hook.result.current.plaintext).toBeNull();
      expect(hook.result.current.loading).toBe(false);
    },
  );

  it.each(["hide", "wallet change", "unmount"])("rejects a pending reveal after %s", async (action) => {
    const result = deferred<string>();
    jest.spyOn(AuthClient.prototype, "revealSecret").mockReturnValueOnce(result.promise);
    const hook = renderHook(({ currentWallet }) => useExportKey(currentWallet), {
      wrapper,
      initialProps: { currentWallet: wallet },
    });
    await act(async () => {});
    let pending!: Promise<string>;
    act(() => {
      pending = hook.result.current.reveal({ passkey: PASSPHRASE });
    });
    act(() => {
      if (action === "hide") hook.result.current.clear();
      else if (action === "wallet change")
        hook.rerender({ currentWallet: { ...wallet, publicKey: "public-wallet-b" } });
      else hook.unmount();
    });
    await act(async () => {
      result.resolve(SECRET);
      await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
    });
    expect(hook.result.current.plaintext).toBeNull();
  });

  it("does not let an older reveal replace a newer result", async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    jest
      .spyOn(AuthClient.prototype, "revealSecret")
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const hook = renderHook(() => useExportKey(wallet), { wrapper });
    await act(async () => {});
    let older!: Promise<string>;
    let newer!: Promise<string>;
    act(() => {
      older = hook.result.current.reveal({ passkey: PASSPHRASE });
    });
    act(() => {
      newer = hook.result.current.reveal({ passkey: PASSPHRASE });
    });
    await act(async () => {
      second.resolve("new-public-secret");
      await newer;
    });
    await act(async () => {
      first.resolve("old-public-secret");
      await expect(older).rejects.toBeInstanceOf(SessionChangedError);
    });
    expect(hook.result.current.plaintext).toBe("new-public-secret");
    expect(hook.result.current.error).toBeNull();
    expect(hook.result.current.loading).toBe(false);
  });
});

it("updates an already mounted biometric hook after logout", async () => {
  localStorage.setItem("ttc_biometric_unlock", "public-credential");
  localStorage.setItem("ttc_biometric_reg", "{}");
  const hook = renderHook(() => useBiometricUnlock(), { wrapper });
  await act(async () => {});
  await act(async () => {});
  expect(hook.result.current.isEnabled).toBe(true);
  act(() => clearSession());
  expect(hook.result.current.isEnabled).toBe(false);
  expect(localStorage.getItem("ttc_biometric_reg")).toBeNull();
});

it("does not persist a registration returned after the account changes", async () => {
  const pendingRegistration = deferred<{ credentialId: string; salt: string; rpId: string }>();
  jest.spyOn(AuthClient.prototype, "enableBiometricUnlock").mockReturnValueOnce(pendingRegistration.promise);
  const hook = renderHook(() => useBiometricUnlock(), { wrapper });
  await act(async () => {});
  await act(async () => {});
  let pending!: Promise<void>;
  act(() => {
    pending = hook.result.current.enable();
  });
  act(() => {
    setSession({ publicKey: "account-b", authToken: "token-b", appKey: "cd".repeat(32) });
  });
  await act(async () => {
    pendingRegistration.resolve({
      credentialId: "old-public-credential",
      salt: "public-salt",
      rpId: "localhost",
    });
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
  });
  expect(localStorage.getItem("ttc_biometric_reg")).toBeNull();
  expect(hook.result.current.isEnabled).toBe(false);
});

describe("pending decrypt and sign operations", () => {
  it("does not return plaintext after logout during decryption", async () => {
    const hook = renderHook(() => useSigner());
    await act(async () => {});
    const pending = hook.result.current.decrypt(wallet);
    act(() => clearSession());
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
  });

  it("does not run the signing callback after logout during decryption", async () => {
    const hook = renderHook(() => useSigner());
    await act(async () => {});
    const sign = jest.fn(() => "public-signature");
    const pending = hook.result.current.sign(wallet, sign);
    act(() => clearSession());
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
    expect(sign).not.toHaveBeenCalled();
  });

  it("does not return a Solana keypair after logout during decryption", async () => {
    const keypair = Keypair.fromSeed(new Uint8Array(32).fill(1));
    const signingWallet: EncryptedWallet = {
      ...wallet,
      publicKey: keypair.publicKey.toBase58(),
      encryptedSecret: await encryptSecret(Buffer.from(keypair.secretKey).toString("hex"), APP_KEY),
    };
    const hook = renderHook(() => useSigner());
    await act(async () => {});
    const pending = hook.result.current.solanaKeypair(signingWallet);
    act(() => clearSession());
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
  });

  it("does not return a signature completed after logout", async () => {
    const completed = deferred<string>();
    const started = deferred<void>();
    const hook = renderHook(() => useSigner());
    await act(async () => {});
    const pending = hook.result.current.sign(wallet, () => {
      started.resolve();
      return completed.promise;
    });
    await started.promise;
    act(() => clearSession());
    completed.resolve("public-signature");
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
  });
});

describe("cached account records", () => {
  const response = (publicKey: string) => ({
    status: 200,
    ok: true,
    json: async () => ({
      user: { appId: APP_ID, publicKey, authMethod: "email", wallets: [wallet], createdAt: 1 },
    }),
  });
  it("clears the previous account's wallet record before loading the next account", async () => {
    const nextRecord = deferred<ReturnType<typeof response>>();
    globalThis.fetch = jest
      .fn()
      .mockResolvedValueOnce(response("account-a"))
      .mockReturnValueOnce(nextRecord.promise);
    const hook = renderHook(() => useUser(), { wrapper });
    await act(async () => {});
    await act(async () => {});
    expect(hook.result.current.user?.publicKey).toBe("account-a");
    await act(async () => {
      setSession({ publicKey: "account-b", authToken: "token-b", appKey: "cd".repeat(32) });
    });
    expect(hook.result.current.user).toBeNull();
    await act(async () => {
      nextRecord.resolve(response("account-b"));
    });
    expect(hook.result.current.user?.publicKey).toBe("account-b");
  });

  it("ignores an old account response delivered after an account switch", async () => {
    const oldRecord = deferred<ReturnType<typeof response>>();
    const nextRecord = deferred<ReturnType<typeof response>>();
    globalThis.fetch = jest
      .fn()
      .mockReturnValueOnce(oldRecord.promise)
      .mockReturnValueOnce(nextRecord.promise);
    const hook = renderHook(() => useUser(), { wrapper });
    await act(async () => {});
    await act(async () => {
      setSession({ publicKey: "account-b", authToken: "token-b", appKey: "cd".repeat(32) });
    });
    await act(async () => {
      oldRecord.resolve(response("account-a"));
    });
    expect(hook.result.current.user).toBeNull();
    await act(async () => {
      nextRecord.resolve(response("account-b"));
    });
    expect(hook.result.current.user?.publicKey).toBe("account-b");
  });
});

it("does not clear a new account's registration when an older disable finishes", async () => {
  const completed = deferred<void>();
  localStorage.setItem(
    "ttc_biometric_reg",
    JSON.stringify({ credentialId: "credential-a", salt: "salt", rpId: "localhost" }),
  );
  jest.spyOn(AuthClient.prototype, "disableBiometricUnlock").mockReturnValueOnce(completed.promise);
  const hook = renderHook(() => useBiometricUnlock(), { wrapper });
  await act(async () => {});
  let pending!: Promise<void>;
  act(() => {
    pending = hook.result.current.disable();
  });
  await act(async () => {
    setSession({ publicKey: "account-b", authToken: "token-b", appKey: "cd".repeat(32) });
  });
  const nextRegistration = JSON.stringify({ credentialId: "credential-b", salt: "salt", rpId: "localhost" });
  localStorage.setItem("ttc_biometric_reg", nextRegistration);
  localStorage.setItem("ttc_biometric_unlock", "credential-b");
  await act(async () => {
    completed.resolve();
    await expect(pending).rejects.toBeInstanceOf(SessionChangedError);
  });
  expect(localStorage.getItem("ttc_biometric_reg")).toBe(nextRegistration);
  expect(localStorage.getItem("ttc_biometric_unlock")).toBe("credential-b");
});
