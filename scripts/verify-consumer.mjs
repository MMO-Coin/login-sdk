import assert from "node:assert/strict";
import { packPackage } from "./pack-package.mjs";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, "Run this check with npm run verify:consumer.");
const args = process.argv.slice(2);
assert.ok(
  args.every((arg) => /^--react=(18|19)$/.test(arg)) && args.length <= 1,
  "Use --react=18 or --react=19.",
);
const versions = args.length ? [args[0].slice("--react=".length)] : ["18", "19"];
const temp = realpathSync(tmpdir());
const work = mkdtempSync(path.join(temp, "mmo-login-consumer-"));
const env = { ...process.env };
delete env.NODE_PATH;
const npm = (args, cwd) =>
  execFileSync(process.execPath, [npmCli, ...args], {
    cwd,
    env,
    encoding: "utf8",
    stdio: "inherit",
  });
try {
  const pack = packPackage({ cwd: root, destination: work, npmCli, env });
  assert.equal(pack.name, pkg.name);
  assert.equal(pack.version, pkg.version);
  for (const file of pack.files) {
    assert.ok(
      file.path.startsWith("dist/") || ["README.md", "LICENSE", "package.json"].includes(file.path),
      "Unexpected package file: " + file.path,
    );
  }
  for (const major of versions) {
    const cwd = path.join(work, "react-" + major);
    mkdirSync(cwd);
    const react = major === "18" ? "^18.3.1" : "^19.0.0";
    writeFileSync(
      path.join(cwd, "package.json"),
      JSON.stringify(
        {
          name: "sdk-consumer-check",
          private: true,
          type: "module",
          dependencies: {
            [pkg.name]: "file:../" + pack.filename,
            react,
            "react-dom": react,
            "@solana/web3.js": pkg.peerDependencies["@solana/web3.js"],
            tweetnacl: pkg.peerDependencies.tweetnacl,
            viem: pkg.peerDependencies.viem,
          },
          devDependencies: {
            "@types/react": "^" + major,
            "@types/react-dom": "^" + major,
            typescript: pkg.devDependencies.typescript,
            esbuild: pkg.overrides.tsup.esbuild,
          },
          // Overrides in an installed library do not apply to its consuming application.
          overrides: { "@solana/web3.js": pkg.overrides["@solana/web3.js"] },
        },
        null,
        2,
      ) + "\n",
    );
    copyFileSync(new URL("./consumer-smoke.mjs", import.meta.url), path.join(cwd, "smoke.mjs"));
    copyFileSync(
      new URL("../tests/fixtures/tetrac-0.6.0.json", import.meta.url),
      path.join(cwd, "legacy-fixture.json"),
    );
    writeFileSync(
      path.join(cwd, "browser-entry.js"),
      [
        'export { AuthProvider, useAuth } from "@mmo-coin/login-sdk/react";',
        'export { LoginPanel } from "@mmo-coin/login-sdk/ui";',
        'export { createAuthClient, getAppKey } from "@mmo-coin/login-sdk/client";',
      ].join("\n"),
    );
    writeFileSync(
      path.join(cwd, "smoke.tsx"),
      [
        'import React from "react";',
        'import { AuthProvider, type AuthProviderProps } from "@mmo-coin/login-sdk/react";',
        'import { LoginPanel } from "@mmo-coin/login-sdk/ui";',
        'const props: AuthProviderProps = { apiBaseUrl: "/auth", config: { appId: "consumer-test" }, children: <LoginPanel methods={["email"]} /> };',
        "export const app = <AuthProvider {...props} />;",
      ].join("\n"),
    );
    npm(["install", "--legacy-peer-deps=false", "--strict-peer-deps", "--no-audit", "--no-fund"], cwd);
    const lock = JSON.parse(readFileSync(path.join(cwd, "package-lock.json"), "utf8"));
    assert.equal(lock.packages["node_modules/" + pkg.name].version, pkg.version);
    assert.ok(
      lock.packages["node_modules/" + pkg.name].integrity,
      "The SDK must be installed from a packed archive",
    );
    assert.equal(
      lock.packages["node_modules/jest"],
      undefined,
      "The SDK's test tools must not reach consumers",
    );
    const ts = path.join(cwd, "node_modules/typescript/bin/tsc");
    execFileSync(
      process.execPath,
      [
        ts,
        "--noEmit",
        "--strict",
        "--skipLibCheck",
        "--module",
        "nodenext",
        "--moduleResolution",
        "nodenext",
        "--target",
        "es2022",
        "--jsx",
        "react-jsx",
        "smoke.tsx",
      ],
      { cwd, env, stdio: "inherit" },
    );
    execFileSync(process.execPath, ["smoke.mjs"], { cwd, env, stdio: "inherit" });
    npm(["audit", "--audit-level=low"], cwd);
  }
} finally {
  const target = path.resolve(work);
  assert.equal(path.dirname(target), temp, "Cleanup must stay inside the generated temporary directory");
  assert.ok(path.basename(target).startsWith("mmo-login-consumer-"));
  rmSync(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
