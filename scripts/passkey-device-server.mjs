import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { deviceQaOptions, allowsDeviceQaRequest } from "./passkey-device-options.mjs";

export async function startDeviceQa(options = deviceQaOptions(process.argv.slice(2))) {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const [{ build }, { createNextAuthRoutes }, { MemoryAdapter }] = await Promise.all([
    import("esbuild"),
    import("@mmo-coin/login-sdk/next"),
    import("@mmo-coin/login-sdk/storage"),
  ]);
  const appId = "passkey-device-qa";
  const instanceId = randomUUID();
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const routes = createNextAuthRoutes({
    storage: new MemoryAdapter(),
    config: {
      appId,
      origin: options.origin,
      allowedAppIds: [appId],
      securityLevel: 1,
      accountCreationRateLimit: { maxAttempts: 100, windowSeconds: 900 },
    },
    onWarning() {},
  });
  const built = await build({
    entryPoints: [path.join(root, "examples/passkey-device/app.tsx")],
    bundle: true,
    platform: "browser",
    format: "iife",
    target: "es2022",
    minify: true,
    write: false,
    tsconfigRaw: { compilerOptions: { jsx: "react-jsx" } },
    define: { "process.env.NODE_ENV": '"production"' },
  });
  const css = await readFile(new URL("../examples/passkey-device/qa.css", import.meta.url));
  const html =
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Passkey device check</title><link rel="stylesheet" href="/qa.css"></head><body><div id="root"></div><script src="/qa.js" defer></script></body></html>';
  const server = createServer(async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    res.setHeader(
      "Permissions-Policy",
      "publickey-credentials-create=(self), publickey-credentials-get=(self)",
    );
    const send = (status, type, body) => {
      res.writeHead(status, { "content-type": type });
      res.end(body);
    };
    try {
      if (req.method === "GET" && req.url === "/health")
        return send(200, "application/json", '{"status":"ok"}');
      if (!allowsDeviceQaRequest(req.headers, options.origin))
        return send(403, "text/plain", "Use the configured QA origin.");
      const url = new URL(req.url, options.origin);
      if (url.origin !== options.origin) return send(400, "text/plain", "Invalid request origin.");
      if (req.method === "GET") {
        if (url.pathname === "/") return send(200, "text/html; charset=utf-8", html);
        if (url.pathname === "/qa.js")
          return send(200, "text/javascript; charset=utf-8", built.outputFiles[0].contents);
        if (url.pathname === "/qa.css") return send(200, "text/css; charset=utf-8", css);
        if (url.pathname === "/qa-info")
          return send(200, "application/json", JSON.stringify({ appId, instanceId, version: pkg.version }));
      }
      if (!url.pathname.startsWith("/auth/")) return send(404, "text/plain", "Not found.");
      if (!["GET", "POST"].includes(req.method)) return send(405, "text/plain", "Method not allowed.");
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 128 * 1024) return send(413, "text/plain", "Request too large.");
        chunks.push(chunk);
      }
      const request = new Request(url, {
        method: req.method,
        headers: req.headers,
        body: req.method === "GET" ? undefined : Buffer.concat(chunks),
      });
      const context = { params: Promise.resolve({ action: url.pathname.slice(6).split("/") }) };
      const response = await routes[req.method](request, context);
      const headers = new Headers(response.headers);
      headers.set("cache-control", "no-store");
      res.writeHead(response.status, Object.fromEntries(headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      if (!res.headersSent) send(500, "text/plain", "QA server error.");
      else res.end();
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, "127.0.0.1", resolve);
  });
  console.log("Passkey device QA ready at " + options.origin);
  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startDeviceQa().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
