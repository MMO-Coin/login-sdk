import { createRequire } from "node:module";
import { Connection, PublicKey } from "@solana/web3.js";

// Resolve the dependency actually loaded by Jest, including its local override.
const jestRequire = createRequire(require.resolve("jest-config"));
const buildRequire = createRequire(require.resolve("tsup"));
const solanaRequire = createRequire(require.resolve("@solana/web3.js"));
const { build } = buildRequire("esbuild");
const merge = jestRequire("deepmerge");
const mergePackage = jestRequire("deepmerge/package.json");
const cleanPrototype = Object.getPrototypeOf(merge({}, {}));

describe("patched development merge dependency", () => {
  it("uses the reviewed local patch", () => {
    expect(mergePackage.name).toBe("@mmo-coin/deepmerge");
    expect(mergePackage.version).toBe("4.3.1-mmo.1");
  });

  it("does not poison the result while cloning a target with an own __proto__ key", () => {
    const target = JSON.parse('{"__proto__":{"injected":true},"safe":1}');
    const result = merge(target, {});
    expect(Object.getPrototypeOf(result)).toBe(cleanPrototype);
    expect(result.injected).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(result, "__proto__")).toBe(true);
    expect(result.safe).toBe(1);
    expect(({} as Record<string, unknown>).injected).toBeUndefined();
  });

  it("does not poison the result when merging into a null-prototype target", () => {
    const source = JSON.parse('{"__proto__":{"injected":true}}');
    const result = merge(Object.create(null), source);
    expect(Object.getPrototypeOf(result)).toBe(cleanPrototype);
    expect(result.injected).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(result, "__proto__")?.value).toEqual({ injected: true });
  });

  it("keeps nested prototype keys as data without changing the prototype chain", () => {
    const target = JSON.parse('{"nested":{"__proto__":{"injected":true}}}');
    const result = merge(target, { nested: { safe: true } });
    expect(Object.getPrototypeOf(result.nested)).toBe(cleanPrototype);
    expect(result.nested.injected).toBeUndefined();
    expect(result.nested.safe).toBe(true);
  });

  it("preserves nested globals, array merging and enumerable symbols", () => {
    const symbol = Symbol("config");
    const result = merge(
      { globals: { list: [1], nested: { a: 1 } }, [symbol]: "kept" },
      { globals: { list: [2], nested: { b: 2 } } },
    );
    expect(result.globals).toEqual({ list: [1, 2], nested: { a: 1, b: 2 } });
    expect(result[symbol]).toBe("kept");
  });

  it("preserves clone, arrayMerge, customMerge and all options", () => {
    const shared = { value: 1 };
    expect(merge({}, { shared }, { clone: false }).shared).toBe(shared);
    expect(merge([1], [2], { arrayMerge: (_target: number[], source: number[]) => source })).toEqual([2]);
    expect(
      merge(
        { value: { first: true } },
        { value: { second: true } },
        { customMerge: (key: string) => (key === "value" ? () => ({ custom: true }) : undefined) },
      ),
    ).toEqual({ value: { custom: true } });
    expect(merge.all([{ a: 1 }, { b: 2 }])).toEqual({ a: 1, b: 2 });
  });
});

describe("Solana v1 with the patched JSON-RPC client", () => {
  const owner = new PublicKey("11111111111111111111111111111111");
  it("preserves request IDs and account balance response parsing", async () => {
    expect(solanaRequire("jayson/package.json").version).toBe("5.0.0");
    let sent: { method: string; params: unknown[]; id: string; jsonrpc: string } | undefined;
    const fetchRpc = jest.fn(async (_url, options) => {
      sent = JSON.parse(options!.body as string);
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: sent!.id, result: { context: { slot: 123 }, value: 42 } }),
      );
    }) as unknown as typeof fetch;
    const connection = new Connection("https://rpc.invalid", {
      fetch: fetchRpc,
      disableRetryOnRateLimit: true,
    });
    await expect(connection.getBalance(owner, "confirmed")).resolves.toBe(42);
    expect(sent?.jsonrpc).toBe("2.0");
    expect(sent?.method).toBe("getBalance");
    expect(sent?.params).toEqual([owner.toBase58(), { commitment: "confirmed" }]);
    expect(sent?.id).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it("preserves JSON-RPC errors", async () => {
    const fetchRpc = jest.fn(async (_url, options) => {
      const request = JSON.parse(options!.body as string);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: request.id,
          error: { code: -32000, message: "Public test RPC error" },
        }),
      );
    }) as unknown as typeof fetch;
    const connection = new Connection("https://rpc.invalid", {
      fetch: fetchRpc,
      disableRetryOnRateLimit: true,
    });
    await expect(connection.getBalance(owner)).rejects.toThrow("Public test RPC error");
  });

  it("still bundles for browsers without Node core shims", async () => {
    expect(buildRequire("esbuild/package.json").version).toBe("0.28.2");
    const result = await build({
      stdin: {
        contents: 'export { Connection, Keypair } from "@solana/web3.js";',
        resolveDir: process.cwd(),
      },
      bundle: true,
      platform: "browser",
      format: "esm",
      target: "es2022",
      write: false,
      logLevel: "silent",
      metafile: true,
    });
    expect(result.outputFiles[0]?.text).toContain("Connection");
    expect(
      Object.keys(result.metafile!.inputs).some((path) => path.includes("jayson/lib/client/browser")),
    ).toBe(true);
    expect(Object.keys(result.metafile!.inputs).some((path) => path.includes("stream-json"))).toBe(false);
  });
});
