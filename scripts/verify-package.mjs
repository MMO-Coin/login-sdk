import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, "Run this check with npm run verify:package.");

const [pack] = JSON.parse(
  execFileSync(process.execPath, [npmCli, "pack", "--dry-run", "--ignore-scripts", "--json"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }),
);
assert.equal(pack.name, pkg.name);
assert.equal(pack.version, pkg.version);
const files = new Set(pack.files.map((file) => file.path));
for (const file of ["package.json", "README.md", "LICENSE"]) assert.ok(files.has(file), file);
for (const file of files) {
  assert.ok(
    file.startsWith("dist/") || ["package.json", "README.md", "LICENSE"].includes(file),
    "Unexpected package file: " + file,
  );
}

for (const [subpath, targets] of Object.entries(pkg.exports)) {
  for (const target of Object.values(targets)) {
    assert.ok(files.has(target.replace(/^\.\//, "")), "Missing packed export: " + target);
  }
  const cjsTypes = targets.types.replace(/\.d\.ts$/, ".d.cts");
  assert.ok(files.has(cjsTypes.replace(/^\.\//, "")), "Missing CommonJS types: " + cjsTypes);
  const specifier = pkg.name + (subpath === "." ? "" : subpath.slice(1));
  await import(specifier);
  require(specifier);
  for (const target of [targets.import, targets.require]) {
    const file = new URL("../" + target, import.meta.url);
    assert.ok(existsSync(file), target);
    const code = readFileSync(file, "utf8");
    assert.ok(!code.includes("@tetrac/login-sdk"), "Upstream package import in " + target);
    if (["./react", "./ui", "./ledger"].includes(subpath)) {
      assert.ok(code.startsWith('"use client";'), "Missing client directive: " + target);
    }
  }
}

const React = await import("react");
const { renderToString } = await import("react-dom/server");
const { AuthProvider } = await import(pkg.name + "/react");
const { LoginPanel } = await import(pkg.name + "/ui");
const markup = renderToString(
  React.createElement(
    AuthProvider,
    { apiBaseUrl: "/auth", config: { appId: "package-smoke", origin: "https://smoke.example" } },
    React.createElement(LoginPanel, { methods: ["email"] }),
  ),
);
assert.ok(markup.includes('type="email"'), "The UI must use the packaged AuthProvider context.");

const client = await import(pkg.name + "/client");
const commonJsClient = require(pkg.name + "/client");
try {
  client.armAppKey("ab".repeat(32));
  assert.equal(commonJsClient.getAppKey(), client.getAppKey(), "ESM and CommonJS must share the vault.");
  commonJsClient.lockVault();
  assert.equal(client.getAppKey(), null, "A lock must reach every package entry point.");
} finally {
  client.lockVault();
}
console.log(
  "Verified " +
    pkg.name +
    "@" +
    pkg.version +
    ": packed exports, ESM, CommonJS, React context, and shared vault.",
);
