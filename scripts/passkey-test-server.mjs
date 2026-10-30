import { createServer } from "node:http";
import { build } from "esbuild";
import { createNextAuthRoutes } from "@mmo-coin/login-sdk/next";
import { MemoryAdapter } from "@mmo-coin/login-sdk/storage";

// This server is test-only, loopback-only and keeps account data in memory.
const origin = "http://localhost:4193";
const appId = "browser-passkey-test";
const routes = createNextAuthRoutes({
  storage: new MemoryAdapter(),
  config: {
    appId,
    origin,
    allowedAppIds: [appId],
    securityLevel: 1,
    accountCreationRateLimit: { maxAttempts: 100, windowSeconds: 60 },
  },
  onWarning() {},
});
const built = await build({
  entryPoints: ["tests/browser/fixture.tsx"],
  bundle: true,
  platform: "browser",
  format: "iife",
  target: "es2022",
  write: false,
  tsconfigRaw: { compilerOptions: { jsx: "react-jsx" } },
  define: { "process.env.NODE_ENV": '"production"' },
});
const javascript = built.outputFiles[0].contents;
const html =
  '<!doctype html><html lang="en"><meta charset="utf-8"><title>SDK passkey tests</title><div id="root"></div><script src="/fixture.js"></script></html>';
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, origin);
    if (url.pathname === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end(html);
    }
    if (url.pathname === "/fixture.js") {
      res.writeHead(200, { "content-type": "text/javascript; charset=utf-8" });
      return res.end(javascript);
    }
    if (!url.pathname.startsWith("/auth/")) {
      res.writeHead(404);
      return res.end();
    }
    const chunks = [];
    let bytes = 0;
    for await (const chunk of req) {
      bytes += chunk.length;
      if (bytes > 128 * 1024) {
        res.writeHead(413);
        return res.end();
      }
      chunks.push(chunk);
    }
    const request = new Request(url, {
      method: req.method,
      headers: req.headers,
      body: ["GET", "HEAD"].includes(req.method) ? undefined : Buffer.concat(chunks),
    });
    const ctx = { params: Promise.resolve({ action: url.pathname.slice("/auth/".length).split("/") }) };
    const response = req.method === "GET" ? await routes.GET(request, ctx) : await routes.POST(request, ctx);
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    console.error(error);
    res.writeHead(500);
    res.end("Test server error");
  }
});
server.listen(4193, "127.0.0.1", () => console.log("Passkey test server ready"));
