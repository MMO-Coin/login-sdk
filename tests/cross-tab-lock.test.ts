// CLIENTVAULT-7 — cross-tab lock propagation via the `storage` event. The node test
// env has no real window, so we polyfill window + a listener registry and fire the
// captured handlers to simulate a sibling tab logging out / locking.
function makeStore() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    keys: () => [...m.keys()],
  };
}

type Handlers = Record<string, Array<(e: any) => void>>;

function installWindow(): {
  handlers: Handlers;
  sessionStorage: ReturnType<typeof makeStore>;
  localStorage: ReturnType<typeof makeStore>;
} {
  const handlers: Handlers = {};
  const sessionStorage = makeStore();
  const localStorage = makeStore();
  (globalThis as any).window = globalThis;
  (globalThis as any).sessionStorage = sessionStorage;
  (globalThis as any).localStorage = localStorage;
  (globalThis as any).document = { addEventListener: () => {}, visibilityState: "visible" };
  (globalThis as any).addEventListener = (type: string, fn: (e: any) => void) => {
    (handlers[type] ??= []).push(fn);
  };
  return { handlers, sessionStorage, localStorage };
}

async function freshSession() {
  jest.resetModules();
  // The vault state is now a process-global (Symbol.for("tetrac.vault")) shared
  // across bundle copies; jest.resetModules() does NOT clear it. Delete the slot so
  // the re-imported module starts fresh — in particular hideHandlerBound resets to
  // false, so bindHideHandler() re-registers the `storage` listener against THIS
  // test's new handler registry (a real reload gets a brand-new realm anyway).
  delete (globalThis as any)[Symbol.for("tetrac.vault")];
  const ctx = installWindow();
  const mod = await import("../src/client/session");
  mod.lockVault(false); // belt-and-suspenders: start locked without writing the sentinel
  return { mod, ...ctx };
}

function fireStorage(handlers: Handlers, key: string | null, newValue: string | null) {
  for (const fn of handlers["storage"] ?? []) fn({ key, newValue });
}

describe("CLIENTVAULT-7 — cross-tab lock via the storage event", () => {
  it("a logout in a sibling tab (auth token removed) drops this tab's hot key", async () => {
    const { mod, handlers } = await freshSession();
    mod.configureVault({ autoLockMs: 100_000 }); // binds the storage listener
    mod.armAppKey("HOTKEY");
    expect(mod.getAppKey()).toBe("HOTKEY");

    fireStorage(handlers, "ttc-auth-token", null); // sibling tab cleared the token
    expect(mod.getAppKey()).toBeNull();
    expect(mod.isLocked()).toBe(true);
  });

  it("an explicit lock in a sibling tab (lock sentinel) drops this tab's hot key", async () => {
    const { mod, handlers } = await freshSession();
    mod.configureVault({ autoLockMs: 100_000 });
    mod.armAppKey("HOTKEY");

    fireStorage(handlers, "ttc_lock_signal", "1700000000000"); // sibling tab locked
    expect(mod.getAppKey()).toBeNull();
  });

  it("an unrelated storage key does NOT lock the vault", async () => {
    const { mod, handlers } = await freshSession();
    mod.configureVault({ autoLockMs: 100_000 });
    mod.armAppKey("HOTKEY");

    fireStorage(handlers, "some_other_key", "x");
    expect(mod.getAppKey()).toBe("HOTKEY"); // unaffected
    mod.lockVault(false); // clear the pending auto-lock timer
  });

  it("explicit lockVault() bumps the cross-tab sentinel; an automatic lock(false) does not", async () => {
    const { mod, localStorage } = await freshSession();
    mod.configureVault({ autoLockMs: 100_000 });

    mod.armAppKey("HOTKEY");
    mod.lockVault(false); // automatic/per-tab lock — must NOT signal siblings
    expect(localStorage.getItem("ttc_lock_signal")).toBeNull();

    mod.armAppKey("HOTKEY2");
    mod.lockVault(); // explicit lock — signals siblings via the sentinel
    expect(localStorage.getItem("ttc_lock_signal")).not.toBeNull();
  });
});

describe("cross-tab session replacement", () => {
  it.each(["ttc-auth-token", "ttc-public-key", null])(
    "locks on a change to %s, including storage.clear()",
    async (key) => {
      const { mod, handlers } = await freshSession();
      mod.configureVault({ autoLockMs: 100000 });
      mod.armAppKey("public-test-key");
      const check = mod.captureSessionGuard();
      fireStorage(handlers, key, key === null ? null : "replacement");
      expect(mod.getAppKey()).toBeNull();
      expect(check).toThrow(mod.SessionChangedError);
    },
  );

  it("reports locked before another tab's storage event is delivered", async () => {
    const { mod, localStorage } = await freshSession();
    mod.configureVault({ autoLockMs: 100000 });
    mod.setSession({ publicKey: "account-a", authToken: "token-a", appKey: "public-test-key" });
    localStorage.setItem("ttc-auth-token", "token-b");
    expect(mod.lockSnapshot()).toBe(false);
    expect(mod.getAppKey()).toBeNull();
  });
});
