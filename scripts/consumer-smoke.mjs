import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { build } from "esbuild";
import React from "react";
import { renderToString } from "react-dom/server";
import { AuthProvider } from "@mmo-coin/login-sdk/react";
import { LoginPanel } from "@mmo-coin/login-sdk/ui";
import * as core from "@mmo-coin/login-sdk/core";
import * as client from "@mmo-coin/login-sdk/client";

const require = createRequire(import.meta.url);
const pkg = JSON.parse(readFileSync("node_modules/@mmo-coin/login-sdk/package.json", "utf8"));
for (const subpath of Object.keys(pkg.exports)) {
  const name = pkg.name + (subpath === "." ? "" : subpath.slice(1));
  await import(name);
  require(name);
}
const markup = renderToString(
  React.createElement(AuthProvider, {
    apiBaseUrl: "/auth",
    config: { appId: "consumer-test", origin: "https://app.example.com" },
    children: React.createElement(LoginPanel, { methods: ["email"] }),
  }),
);
assert.ok(markup.includes('type="email"'), "Packaged UI and provider must share their React context");

const fixture = JSON.parse(readFileSync("legacy-fixture.json", "utf8"));
const appKey = core.deriveAppKeyFromPasskey(
  fixture.passphrase,
  fixture.email,
  fixture.iterations,
  fixture.appId,
);
assert.equal(appKey, fixture.appKey);
assert.equal(await core.decryptSecret(fixture.ciphertext, appKey), fixture.secret);
assert.equal(core.walletAppKeyMessage(fixture.appId, fixture.origin), fixture.walletMessage);

const previous = new Map(
  ["window", "localStorage"].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]),
);
const storage = new Map();
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: { addEventListener() {}, removeEventListener() {}, location: { origin: "https://app.example.com" } },
});
Object.defineProperty(globalThis, "localStorage", {
  configurable: true,
  value: {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: (key) => storage.delete(key),
  },
});
try {
  const commonJs = require(pkg.name + "/client");
  client.configureVault({ autoLockMs: 60_000, lockOnHide: false });
  client.setSession({ publicKey: "public-consumer-identity", authToken: "public-consumer-token", appKey });
  assert.equal(commonJs.getAppKey(), appKey, "ESM and CommonJS must share an unlocked vault");
  commonJs.lockVault();
  assert.equal(client.getAppKey(), null);
  const auth = client.createAuthClient({
    apiBaseUrl: "/auth",
    config: { appId: fixture.appId, origin: fixture.origin, lockOnHide: false },
  });
  let finish;
  auth.deriveAppKey = () =>
    new Promise((resolve) => {
      finish = resolve;
    });
  const pending = auth.unlock({ passkey: fixture.passphrase });
  commonJs.clearSession();
  finish(appKey);
  await assert.rejects(pending, { name: "SessionChangedError" });
  assert.equal(client.getAppKey(), null);
} finally {
  client.clearSession();
  for (const [key, descriptor] of previous) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
}

await build({
  entryPoints: ["browser-entry.js"],
  bundle: true,
  platform: "browser",
  format: "esm",
  target: "es2022",
  write: false,
  logLevel: "error",
});
console.log(
  "Clean consumer passed: React " +
    React.version +
    ", packed exports, wallet recovery, shared vault and browser bundle.",
);
