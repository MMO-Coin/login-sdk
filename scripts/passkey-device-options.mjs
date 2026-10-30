export function deviceQaOptions(args = []) {
  const values = { port: "4194", origin: undefined };
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]?.replace(/^--/, "");
    if (!["port", "origin"].includes(name) || !args[index + 1] || args[index + 1].startsWith("--"))
      throw new Error("Use --port NUMBER and optionally --origin https://qa.example.test.");
    values[name] = args[index + 1];
  }
  if (!/^\d+$/.test(values.port)) throw new Error("Port must be an integer from 1 to 65535.");
  const port = Number(values.port);
  if (port < 1 || port > 65535) throw new Error("Port must be an integer from 1 to 65535.");
  let url;
  try {
    url = new URL(values.origin ?? "http://localhost:" + port);
  } catch {
    throw new Error("QA origin must be a bare HTTPS origin or local HTTP origin.");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    !(url.protocol === "https:" || (url.protocol === "http:" && loopback))
  )
    throw new Error("QA origin must be a bare HTTPS origin or local HTTP origin.");
  if (url.protocol === "http:" && Number(url.port || 80) !== port)
    throw new Error("The local HTTP origin port must match --port.");
  return { port, origin: url.origin };
}

export function allowsDeviceQaRequest(headers, origin) {
  return (
    typeof headers.host === "string" &&
    headers.host.toLowerCase() === new URL(origin).host.toLowerCase() &&
    (!headers.origin || headers.origin === origin) &&
    headers["sec-fetch-site"] !== "cross-site"
  );
}
