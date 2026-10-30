import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

export function packPackage({
  cwd,
  destination,
  dryRun = false,
  npmCli = process.env.npm_execpath,
  env = process.env,
}) {
  assert.ok(npmCli, "Run this check with npm run.");
  const args = ["pack", "--ignore-scripts", "--foreground-scripts=false", "--json"];
  if (dryRun) args.push("--dry-run");
  if (destination) args.push("--pack-destination", destination);
  // npm 10 can run prepare despite ignore-scripts. Keep its output off the JSON stream.
  const packs = JSON.parse(
    execFileSync(process.execPath, [npmCli, ...args], {
      cwd,
      env,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    }),
  );
  assert.ok(Array.isArray(packs) && packs.length === 1, "Expected one packed package.");
  return packs[0];
}
