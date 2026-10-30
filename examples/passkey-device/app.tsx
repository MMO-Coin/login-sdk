import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { AuthProvider, useAuth, useAuthContext, useBiometricUnlock } from "@mmo-coin/login-sdk/react";
import {
  authHeaders,
  getAppKey,
  getAuthStatus,
  getPublicKey,
  hasBiometricUnlock,
  type PasskeyRegistration,
} from "@mmo-coin/login-sdk/client";

type Result = "not_run" | "pass" | "fail" | "unsupported";
const labels = {
  email_registration: "Synthetic email wallet created",
  passkey_enable: "Passkey unlock enabled with PRF",
  manual_lock: "Manual lock clears the key",
  passkey_unlock: "Passkey restores the same wallet key",
  reload_lock: "Reload starts with the wallet locked",
  reload_unlock: "Passkey restores the same key after reload",
  cancellation: "Cancelled prompt leaves the wallet locked",
  background_lock: "Background and return leaves the wallet locked",
  passkey_disable: "Disabling unlock removes its registration",
  logout: "Email session cleared and server token revoked",
  primary_registration: "Passkey account created with PRF",
  primary_logout: "Passkey session cleared and server token revoked",
  primary_relogin: "Passkey account signs in with the same wallet key",
} as const;
type Check = keyof typeof labels;
type Info = { instanceId: string; version: string; appId: string };
type Baseline = { fingerprint: string; identity: string; wallets: string[] };
type RunState = {
  instanceId: string;
  checks: Record<Check, Result>;
  mode: "email" | "primary" | null;
  email?: Baseline;
  primary?: Baseline;
  registration?: PasskeyRegistration;
  awaitingReload?: boolean;
  reloadPending?: boolean;
  awaitingBackground?: boolean;
};
const stateKey = "mmo_passkey_device_qa_v1";
const testPassphrase = "public-passkey-device-qa-passphrase-only";
const checkNames = Object.keys(labels) as Check[];
const fresh = (info: Info): RunState => ({
  instanceId: info.instanceId,
  mode: null,
  checks: Object.fromEntries(checkNames.map((key) => [key, "not_run"])) as RunState["checks"],
});
function load(info: Info): RunState {
  try {
    const value = JSON.parse(sessionStorage.getItem(stateKey) ?? "null") as RunState | null;
    if (!value || value.instanceId !== info.instanceId) return fresh(info);
    const next = fresh(info);
    next.mode = value.mode === "email" || value.mode === "primary" ? value.mode : null;
    for (const name of checkNames)
      if (["not_run", "pass", "fail", "unsupported"].includes(value.checks?.[name]))
        next.checks[name] = value.checks[name];
    for (const mode of ["email", "primary"] as const) {
      const baseline = value[mode];
      if (
        baseline &&
        /^[0-9a-f]{64}$/.test(baseline.fingerprint) &&
        typeof baseline.identity === "string" &&
        Array.isArray(baseline.wallets) &&
        baseline.wallets.length === 2 &&
        baseline.wallets.every((item) => typeof item === "string")
      )
        next[mode] = baseline;
    }
    const reg = value.registration;
    if (
      reg &&
      typeof reg.credentialId === "string" &&
      typeof reg.salt === "string" &&
      /^[A-Za-z0-9_-]{1,4096}$/.test(reg.credentialId) &&
      /^[A-Za-z0-9_-]{1,128}$/.test(reg.salt) &&
      reg.rpId === location.hostname
    )
      next.registration = { credentialId: reg.credentialId, salt: reg.salt, rpId: reg.rpId };
    next.awaitingReload = value.awaitingReload === true;
    next.reloadPending = value.reloadPending === true;
    return next;
  } catch {
    return fresh(info);
  }
}
function sessionStorageAvailable() {
  try {
    const probe = stateKey + ":probe";
    sessionStorage.setItem(probe, "ready");
    const available = sessionStorage.getItem(probe) === "ready";
    sessionStorage.removeItem(probe);
    return available;
  } catch {
    return false;
  }
}
function checkFailed(name: string): never {
  const error = new Error("Device QA check failed.");
  error.name = name;
  throw error;
}
async function fingerprint(key: string) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function browserSummary() {
  const ua = navigator.userAgent;
  for (const [name, pattern] of [
    ["Edge", /Edg\/(\d+)/],
    ["Firefox", /(?:Firefox|FxiOS)\/(\d+)/],
    ["Chrome", /(?:Chrome|CriOS)\/(\d+)/],
    ["Safari", /Version\/(\d+).*Safari/],
  ] as const) {
    const match = ua.match(pattern);
    if (match) return { name, major: match[1] };
  }
  return { name: "other", major: "unknown" };
}
function DeviceCheck({ info }: { info: Info }) {
  const auth = useAuth();
  const { client } = useAuthContext();
  const biometric = useBiometricUnlock();
  const [state, setState] = useState(() => load(info));
  const current = useRef(state);
  const generation = useRef(0);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("Start with a new synthetic email wallet.");
  const [errorName, setErrorName] = useState("");
  const [storageReady, setStorageReady] = useState(sessionStorageAvailable);
  const secure = window.isSecureContext;
  const webauthn = !!window.PublicKeyCredential && !!navigator.credentials;
  function write(patch: Partial<RunState>) {
    const next = { ...current.current, ...patch };
    current.current = next;
    setState(next);
    try {
      sessionStorage.setItem(stateKey, JSON.stringify(next));
    } catch {
      setStorageReady(false);
    }
  }
  function mark(name: Check, result: Result) {
    write({ checks: { ...current.current.checks, [name]: result } });
  }
  async function snapshot(): Promise<Baseline> {
    const key = getAppKey();
    if (!key || getAuthStatus() !== "authenticated") checkFailed("WalletLocked");
    const record = await client.fetchUserData();
    if (!record || record.wallets.length !== 2 || getAppKey() !== key) checkFailed("WalletUnavailable");
    return {
      fingerprint: await fingerprint(key),
      identity: getPublicKey()!,
      wallets: record.wallets.map((wallet) => wallet.publicKey).sort(),
    };
  }
  async function sameWallet(mode: "email" | "primary") {
    const baseline = current.current[mode];
    const actual = await snapshot();
    if (
      !baseline ||
      actual.fingerprint !== baseline.fingerprint ||
      actual.identity !== baseline.identity ||
      JSON.stringify(actual.wallets) !== JSON.stringify(baseline.wallets)
    )
      checkFailed("WalletContinuityFailed");
  }
  async function run(name: Check, action: () => Promise<void> | void, cancellation = false) {
    if (busy) return;
    const ticket = generation.current;
    setBusy(name);
    setErrorName("");
    setMessage(
      cancellation
        ? "Dismiss the passkey prompt. The wallet should stay locked."
        : "Complete the requested step.",
    );
    try {
      await action();
      if (ticket !== generation.current) return;
      if (cancellation) {
        auth.lock();
        mark(name, "not_run");
        setMessage("The prompt was accepted. Lock again and dismiss the prompt to test cancellation.");
      } else {
        mark(name, "pass");
        setMessage(labels[name] + ".");
      }
    } catch (error) {
      if (ticket !== generation.current) return;
      const kind = error instanceof Error ? error.name : "UnknownError";
      setErrorName(kind);
      if (cancellation && ["AbortError", "NotAllowedError"].includes(kind) && !getAppKey()) {
        mark(name, "pass");
        setMessage("Prompt dismissed and the wallet stayed locked.");
        setErrorName("");
      } else if (kind === "PrfUnavailableError") {
        mark(name, "unsupported");
        setMessage(
          "This authenticator does not provide PRF. Record the unsupported result and use email or a wallet in your app.",
        );
      } else {
        mark(name, "fail");
        setMessage("This step did not complete. Check the error name, then retry or start a new run.");
      }
    } finally {
      if (ticket === generation.current) setBusy("");
    }
  }
  useEffect(() => {
    if (current.current.awaitingReload) {
      const locked = !getAppKey() && getAuthStatus() === "session_expired";
      mark("reload_lock", locked ? "pass" : "fail");
      write({ awaitingReload: false, reloadPending: true });
      setMessage("Page reloaded. Unlock with your passkey and compare the wallet key.");
    }
    let hidden = false;
    const observe = () => {
      if (!current.current.awaitingBackground) return;
      if (document.hidden) hidden = true;
      else if (hidden) {
        mark("background_lock", !getAppKey() && getAuthStatus() === "session_expired" ? "pass" : "fail");
        write({ awaitingBackground: false });
        setMessage("Background lock check recorded. Unlock to continue.");
      }
    };
    document.addEventListener("visibilitychange", observe);
    return () => document.removeEventListener("visibilitychange", observe);
  }, []);
  async function signOut() {
    const headers = authHeaders();
    auth.logout();
    if (getAppKey() || getAuthStatus() !== "unauthenticated") checkFailed("SessionNotCleared");
    for (let attempt = 0; attempt < 20; attempt++) {
      const response = await fetch("/auth/user-data", { headers, cache: "no-store" });
      if (response.status === 401) return;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    checkFailed("ServerSessionNotRevoked");
  }
  const results = Object.values(state.checks);
  const report = {
    schemaVersion: 1,
    sdkVersion: info.version,
    environment: navigator.webdriver ? "automated" : "manual",
    capabilities: {
      browser: browserSummary(),
      secureContext: secure,
      webauthn,
      platformAuthenticator: biometric.available,
      sessionStorage: storageReady,
      platform: /Android/.test(navigator.userAgent)
        ? "Android"
        : /iPhone|iPad/.test(navigator.userAgent)
          ? "iOS"
          : /Windows/.test(navigator.userAgent)
            ? "Windows"
            : "other",
    },
    outcome: results.includes("fail")
      ? "fail"
      : results.includes("unsupported")
        ? "unsupported"
        : results.every((value) => value === "pass")
          ? "pass"
          : "incomplete",
    checks: Object.fromEntries(checkNames.map((name) => [name, state.checks[name]])),
  };
  const ready = secure && webauthn && storageReady;
  const unavailable = !!busy || !ready;
  return (
    <main>
      <h1>Passkey device check</h1>
      <p className="muted">SDK {info.version}. Check the browser and authenticator you plan to use.</p>
      <p className="notice">
        Use synthetic accounts only. This page creates unfunded test wallets in memory. Server restarts remove
        the test accounts. Complete device prompts yourself.
      </p>
      <section aria-label="Readiness">
        <h2>Browser readiness</h2>
        <dl>
          <dt>Secure context</dt>
          <dd data-testid="qa-secure">{String(secure)}</dd>
          <dt>WebAuthn</dt>
          <dd>{String(webauthn)}</dd>
          <dt>Platform authenticator</dt>
          <dd data-testid="qa-platform">{String(biometric.available)}</dd>
          <dt>Wallet status</dt>
          <dd data-testid="qa-status">{auth.status}</dd>
          <dt>Passkey unlock</dt>
          <dd data-testid="qa-enabled">{biometric.isEnabled ? "enabled" : "disabled"}</dd>
        </dl>
        <p className="muted">
          Availability does not prove PRF support. Registration and unlock check it on the chosen
          authenticator. The wallet locks when this page is hidden and after five minutes of inactivity.
        </p>
        {!ready && (
          <p role="alert">
            Use a top-level page with browser storage enabled. Phones need a trusted HTTPS origin; localhost
            works on this computer.
          </p>
        )}
      </section>
      <section>
        {auth.hasAccount && !state.mode && (
          <p role="alert">This session has no matching QA run. Reset this QA run before continuing.</p>
        )}
        <h2>1. Email wallet and passkey unlock</h2>
        <p>
          Create the test wallet, enable passkey unlock, then lock and unlock. Reload while unlocked and
          unlock again. For cancellation, lock first and dismiss the next prompt.
        </p>
        <div className="controls">
          <button
            disabled={unavailable || auth.hasAccount || state.checks.email_registration === "pass"}
            onClick={() =>
              void run("email_registration", async () => {
                await auth.registerWithEmail({
                  email: "device-" + crypto.randomUUID() + "@example.invalid",
                  passkey: testPassphrase,
                });
                write({ mode: "email", email: await snapshot() });
              })
            }
          >
            Create synthetic email wallet
          </button>
          <button
            disabled={
              unavailable ||
              !biometric.available ||
              state.mode !== "email" ||
              !auth.isAuthenticated ||
              biometric.isEnabled
            }
            onClick={() =>
              void run("passkey_enable", () => biometric.enable("SDK QA " + info.instanceId.slice(0, 8)))
            }
          >
            Enable passkey unlock
          </button>
          <button
            disabled={unavailable || !auth.isAuthenticated}
            onClick={() =>
              void run("manual_lock", () => {
                auth.lock();
                if (getAppKey()) checkFailed("WalletNotLocked");
              })
            }
          >
            Lock wallet
          </button>
          <button
            disabled={unavailable || state.mode !== "email" || !auth.isLocked || !biometric.isEnabled}
            onClick={() => {
              const name = current.current.reloadPending ? "reload_unlock" : "passkey_unlock";
              void run(name, async () => {
                await biometric.unlock();
                await sameWallet("email");
                write({ reloadPending: false });
              });
            }}
          >
            Unlock with passkey
          </button>
          <button
            disabled={unavailable || state.mode !== "email" || !auth.isAuthenticated || !biometric.isEnabled}
            onClick={() => {
              write({ awaitingReload: true });
              location.reload();
            }}
          >
            Reload page
          </button>
          <button
            disabled={unavailable || state.mode !== "email" || !auth.isLocked || !biometric.isEnabled}
            onClick={() => void run("cancellation", () => biometric.unlock(), true)}
          >
            Test cancellation
          </button>
          <button
            disabled={unavailable || state.mode !== "email" || !auth.isAuthenticated}
            onClick={() => {
              write({ awaitingBackground: true });
              setMessage("Switch to another app, then return to this page.");
            }}
          >
            Check background lock
          </button>
          <button
            disabled={unavailable || state.mode !== "email" || !biometric.isEnabled}
            onClick={() =>
              void run("passkey_disable", async () => {
                await biometric.disable();
                if (hasBiometricUnlock()) checkFailed("PasskeyStillEnabled");
              })
            }
          >
            Disable passkey unlock
          </button>
        </div>
      </section>
      <section>
        <h2>2. Passkey account</h2>
        <p>
          Sign out of the email account first. Create a passkey account, sign out, then sign in with its saved
          passkey.
        </p>
        <div className="controls">
          <button
            disabled={unavailable || !biometric.available || auth.hasAccount || !!state.registration}
            onClick={() =>
              void run("primary_registration", async () => {
                const created = await auth.registerWithBiometric({
                  userName: "SDK QA " + info.instanceId.slice(0, 8),
                });
                write({ mode: "primary", registration: created.registration, primary: await snapshot() });
              })
            }
          >
            Create passkey account
          </button>
          <button
            disabled={unavailable || auth.hasAccount || !state.registration}
            onClick={() =>
              void run("primary_relogin", async () => {
                await auth.loginWithBiometric({ registration: current.current.registration! });
                await sameWallet("primary");
              })
            }
          >
            Sign in with saved passkey
          </button>
          <button
            disabled={unavailable || !auth.hasAccount}
            onClick={() => void run(state.mode === "primary" ? "primary_logout" : "logout", signOut)}
          >
            Sign out
          </button>
        </div>
      </section>
      <section aria-label="Results">
        <h2>Results</h2>
        <p role="status" aria-live="polite" data-testid="qa-message">
          {message}
        </p>
        <p data-testid="qa-error">{errorName}</p>
        {busy && <p>Waiting for {labels[busy as Check].toLowerCase()}...</p>}
        <table>
          <thead>
            <tr>
              <th>Check</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {checkNames.map((name) => (
              <tr key={name}>
                <td>{labels[name]}</td>
                <td data-testid={"result-" + name} data-result={state.checks[name]}>
                  {state.checks[name]}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted">
          The report contains capabilities and check results. Wallet addresses, account identifiers, keys,
          tokens and passkey descriptors are excluded. Reports stay on your device.
        </p>
        <div className="controls">
          <button
            onClick={() => {
              const url = URL.createObjectURL(
                new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
              );
              const link = document.createElement("a");
              link.href = url;
              link.download = "passkey-device-report.json";
              document.body.append(link);
              link.click();
              link.remove();
              setTimeout(() => URL.revokeObjectURL(url), 1000);
            }}
          >
            Download report
          </button>
          <button
            onClick={() => {
              generation.current++;
              auth.logout();
              const next = fresh(info);
              current.current = next;
              setState(next);
              try {
                sessionStorage.removeItem(stateKey);
              } catch {
                setStorageReady(false);
              }
              setBusy("");
              setErrorName("");
              setMessage("New run ready. Device-saved passkeys must be removed in your passkey manager.");
            }}
          >
            Reset this QA run
          </button>
        </div>
        <details>
          <summary>Report preview</summary>
          <pre data-testid="qa-report">{JSON.stringify(report, null, 2)}</pre>
        </details>
        <p className="muted">
          This tab keeps non-secret test state across reloads. Remove credentials named SDK QA from your
          device's passkey manager after testing.
        </p>
      </section>
    </main>
  );
}
async function main() {
  const response = await fetch("/qa-info", { cache: "no-store" });
  if (!response.ok) throw new Error("The QA server is unavailable.");
  const info = (await response.json()) as Info;
  if (info.appId !== "passkey-device-qa" || !info.instanceId || !info.version)
    throw new Error("This is not the dedicated SDK QA server.");
  createRoot(document.getElementById("root")!).render(
    <AuthProvider
      apiBaseUrl="/auth"
      config={{
        appId: info.appId,
        origin: location.origin,
        securityLevel: 1,
        autoLockMs: 300_000,
        lockOnHide: true,
        webauthn: { rpName: "SDK device QA", rpId: location.hostname },
      }}
      walletGen={{ solana: ["funds"], evm: ["funds"] }}
    >
      <DeviceCheck info={info} />
    </AuthProvider>,
  );
}
void main().catch((error) => {
  const text = document.createElement("p");
  text.textContent = error instanceof Error ? error.message : "QA startup failed.";
  document.getElementById("root")!.replaceChildren(text);
});
