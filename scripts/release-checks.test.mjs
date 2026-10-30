import assert from "node:assert/strict";
import { test } from "node:test";
import { runDockerTests } from "./test-docker.mjs";

function fakeCommands(results) {
  const calls = [];
  const run = async (command, args, options) => {
    calls.push({ command, args, options });
    const next = results.shift();
    if (next instanceof Error) throw next;
    assert.notEqual(next, undefined, "Unexpected command");
    return next;
  };
  return { calls, run };
}

test("a failing test stays failed after successful Docker cleanup", async () => {
  const fake = fakeCommands([0, 7, 0]);
  assert.equal(await runDockerTests({ run: fake.run }), 7);
  assert.equal(fake.calls.length, 3);
  assert.deepEqual(fake.calls[2].args.slice(-2), ["down", "-v"]);
});

test("partial startup failure is cleaned up without running Jest", async () => {
  const fake = fakeCommands([12, 0]);
  assert.equal(await runDockerTests({ run: fake.run }), 12);
  assert.ok(fake.calls.every((call) => call.command === "docker"));
});

test("successful tests do not hide a failed cleanup", async () => {
  const fake = fakeCommands([0, 0, 3]);
  assert.equal(await runDockerTests({ run: fake.run }), 3);
});

test("a missing Docker executable returns failure and still attempts cleanup", async () => {
  const fake = fakeCommands([new Error("Docker unavailable"), new Error("Docker unavailable")]);
  const errors = [];
  assert.equal(await runDockerTests({ run: fake.run, onError: (error) => errors.push(error.message) }), 1);
  assert.equal(fake.calls.length, 2);
  assert.deepEqual(errors, ["Docker unavailable", "Docker unavailable"]);
});

test("cleanup errors preserve the original test failure", async () => {
  const fake = fakeCommands([0, 9, new Error("cleanup failed")]);
  assert.equal(await runDockerTests({ run: fake.run, onError() {} }), 9);
});

test("engine mode uses isolated test URLs and portable argument lists", async () => {
  const fake = fakeCommands([0, 0, 0]);
  const env = { EXAMPLE_SETTING: "kept", REDIS_URL: "redis://other-host" };
  assert.equal(await runDockerTests({ run: fake.run, enginesOnly: true, env, project: "isolated-tests" }), 0);
  const [startup, tests, cleanup] = fake.calls;
  assert.deepEqual(startup.args.slice(0, 3), ["compose", "-p", "isolated-tests"]);
  assert.deepEqual(tests.args.slice(-3), ["--runInBand", "storage-conformance", "sql-conformance"]);
  assert.equal(tests.options.env.EXAMPLE_SETTING, "kept");
  assert.equal(tests.options.env.REDIS_URL, "redis://127.0.0.1:56379");
  assert.equal(env.REDIS_URL, "redis://other-host");
  assert.deepEqual(cleanup.args.slice(0, 5), startup.args.slice(0, 5));
});

test("an aborted test cannot prevent cleanup from running", async () => {
  const controller = new AbortController();
  const fake = fakeCommands([0, new Error("aborted"), 0]);
  controller.abort();
  assert.equal(await runDockerTests({ run: fake.run, signal: controller.signal, onError() {} }), 1);
  assert.equal(fake.calls[1].options.signal, controller.signal);
  assert.equal(fake.calls[2].options.signal, undefined);
});
