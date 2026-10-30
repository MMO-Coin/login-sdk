import assert from "node:assert/strict";
import { test } from "node:test";
import { deviceQaOptions, allowsDeviceQaRequest } from "./passkey-device-options.mjs";

test("device QA defaults to loopback and accepts a dedicated HTTPS proxy origin", () => {
  assert.deepEqual(deviceQaOptions(), { port: 4194, origin: "http://localhost:4194" });
  assert.deepEqual(deviceQaOptions(["--origin", "https://qa.example.test", "--port", "5000"]), {
    port: 5000,
    origin: "https://qa.example.test",
  });
});
test("device QA refuses insecure remote origins and credentials in URLs", () => {
  for (const origin of [
    "http://192.0.2.1:4194",
    "http://qa.example.test",
    "https://user:secret@qa.example.test",
    "https://qa.example.test/path",
    "https://qa.example.test?x=1",
    "https://qa.example.test#x",
    "file:///tmp/test",
  ]) {
    assert.throws(() => deviceQaOptions(["--origin", origin]));
  }
});
test("device QA rejects invalid ports, unknown arguments and mismatched local origins", () => {
  for (const args of [
    ["--port", "0"],
    ["--port", "65536"],
    ["--port", "12abc"],
    ["--host", "0.0.0.0"],
    ["--origin"],
    ["--origin", "http://localhost:5000"],
  ]) {
    assert.throws(() => deviceQaOptions(args));
  }
});
test("device QA permits same-origin traffic and refuses foreign Host or Origin headers", () => {
  const origin = "https://qa.example.test";
  assert.equal(allowsDeviceQaRequest({ host: "qa.example.test" }, origin), true);
  assert.equal(allowsDeviceQaRequest({ host: "qa.example.test", origin }, origin), true);
  assert.equal(allowsDeviceQaRequest({ host: "evil.example.test", origin }, origin), false);
  assert.equal(
    allowsDeviceQaRequest({ host: "qa.example.test", origin: "https://evil.example.test" }, origin),
    false,
  );
  assert.equal(allowsDeviceQaRequest({ host: "qa.example.test", origin: "null" }, origin), false);
  assert.equal(
    allowsDeviceQaRequest({ host: "qa.example.test", "sec-fetch-site": "cross-site" }, origin),
    false,
  );
});
