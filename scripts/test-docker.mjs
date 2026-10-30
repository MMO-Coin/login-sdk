import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
const jest = fileURLToPath(new URL("../node_modules/jest/bin/jest.js", import.meta.url));

function runCommand(command, args, options) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { ...options, stdio: "inherit", shell: false });
    child.once("error", (error) => {
      console.error("Could not run " + command + ": " + error.message);
    });
    child.once("close", (code) => resolve(code ?? 1));
  });
}

export async function runDockerTests({
  enginesOnly = false,
  run = runCommand,
  env = process.env,
  signal,
  project = "login-sdk-tests-" + process.pid,
  onError = (error) => console.error(error.message),
} = {}) {
  const compose = ["compose", "-p", project, "-f", path.join(root, "docker-compose.test.yml")];
  let result = 1;
  try {
    result = await run("docker", [...compose, "up", "-d", "--wait", "--wait-timeout", "120"], {
      cwd: root,
      env,
      signal,
    });
    if (result === 0) {
      result = await run(
        process.execPath,
        [jest, "--runInBand", ...(enginesOnly ? ["storage-conformance", "sql-conformance"] : [])],
        {
          cwd: root,
          signal,
          env: {
            ...env,
            REDIS_URL: "redis://127.0.0.1:56379",
            POSTGRES_URL: "postgres://postgres:pw@127.0.0.1:55432/tetrac_test",
            MYSQL_URL: "mysql://root:pw@127.0.0.1:53306/tetrac_test",
          },
        },
      );
    }
  } catch (error) {
    result = 1;
    onError(error);
  } finally {
    // Cleanup must run even after partial startup or an interrupted test.
    // Use this run's project only; do not touch a manually started stack.
    try {
      const cleanup = await run("docker", [...compose, "down", "-v"], { cwd: root, env });
      if (result === 0) result = cleanup;
    } catch (error) {
      onError(error);
      if (result === 0) result = 1;
    }
  }
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const controller = new AbortController();
  let interrupted = 0;
  const interrupt = (signal) => {
    interrupted = signal === "SIGINT" ? 130 : 143;
    controller.abort();
  };
  const onInt = () => interrupt("SIGINT");
  const onTerm = () => interrupt("SIGTERM");
  process.on("SIGINT", onInt);
  process.on("SIGTERM", onTerm);
  try {
    const result = await runDockerTests({
      enginesOnly: process.argv.includes("--engines"),
      signal: controller.signal,
    });
    process.exitCode = interrupted || result;
  } finally {
    process.off("SIGINT", onInt);
    process.off("SIGTERM", onTerm);
  }
}
