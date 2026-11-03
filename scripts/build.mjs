import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const output = path.resolve(root, "dist");
assert.equal(path.dirname(output), root, "Build cleanup must stay inside the SDK directory.");
assert.equal(path.basename(output), "dist", "Only generated dist files may be removed.");
// Both tsup configurations write here. Clean once before starting either pass,
// otherwise the slower declaration pass can remove the other pass's output.
rmSync(output, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });

const require = createRequire(import.meta.url);
const tsupManifest = require.resolve("tsup/package.json");
const tsupPackage = JSON.parse(readFileSync(tsupManifest, "utf8"));
const cli = path.resolve(path.dirname(tsupManifest), tsupPackage.bin.tsup);
const result = spawnSync(process.execPath, [cli], { cwd: root, stdio: "inherit", shell: false });
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);

const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
for (const targets of Object.values(pkg.exports)) {
  for (const target of [...Object.values(targets), targets.types.replace(/\.d\.ts$/, ".d.cts")]) {
    assert.ok(existsSync(path.resolve(root, target)), "Build is missing an exported file: " + target);
  }
}
