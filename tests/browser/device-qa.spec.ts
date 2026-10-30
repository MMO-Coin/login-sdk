import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import { readFile } from "node:fs/promises";

const origin = "http://localhost:4194";
async function open(page: Page, context: BrowserContext, hasPrf = true) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf,
    },
  });
  await page.goto(origin);
  await expect(page.getByTestId("qa-platform")).toHaveText("true");
  return { cdp, authenticatorId };
}
async function step(page: Page, button: string, result: string) {
  await page.getByRole("button", { name: button, exact: true }).click();
  await expect(page.getByTestId("result-" + result)).toHaveText("pass");
}
test("device QA completes native flows, survives reload and exports a redacted report", async ({
  page,
  context,
}) => {
  const { cdp, authenticatorId } = await open(page, context);
  await step(page, "Create synthetic email wallet", "email_registration");
  await step(page, "Enable passkey unlock", "passkey_enable");
  await step(page, "Lock wallet", "manual_lock");
  await step(page, "Unlock with passkey", "passkey_unlock");
  await page.getByRole("button", { name: "Reload page", exact: true }).click();
  await expect(page.getByTestId("result-reload_lock")).toHaveText("pass");
  await step(page, "Unlock with passkey", "reload_unlock");
  await step(page, "Lock wallet", "manual_lock");
  await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: false });
  await page.evaluate(() => {
    const nativeGet = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = (options) => {
      navigator.credentials.get = nativeGet;
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 100);
      return nativeGet({ ...options, signal: controller.signal });
    };
  });
  await step(page, "Test cancellation", "cancellation");
  await expect(page.getByTestId("qa-status")).toHaveText("session_expired");
  await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: true });
  await step(page, "Unlock with passkey", "passkey_unlock");
  await step(page, "Disable passkey unlock", "passkey_disable");
  await step(page, "Sign out", "logout");
  await step(page, "Create passkey account", "primary_registration");
  await step(page, "Sign out", "primary_logout");
  await step(page, "Sign in with saved passkey", "primary_relogin");
  await step(page, "Sign out", "primary_logout");
  const report = JSON.parse((await page.getByTestId("qa-report").textContent()) ?? "{}");
  expect(report.environment).toBe("automated");
  expect(report.outcome).toBe("incomplete");
  expect(report.checks.background_lock).toBe("not_run");
  expect(Object.keys(report).sort()).toEqual([
    "capabilities",
    "checks",
    "environment",
    "outcome",
    "schemaVersion",
    "sdkVersion",
  ]);
  const stored = await page.evaluate(() => JSON.parse(sessionStorage.getItem("mmo_passkey_device_qa_v1")!));
  const json = JSON.stringify(report);
  for (const value of [
    stored.email.fingerprint,
    stored.email.identity,
    stored.primary.fingerprint,
    stored.primary.identity,
    stored.registration.credentialId,
    stored.registration.salt,
    ...stored.email.wallets,
  ]) {
    expect(json).not.toContain(value);
  }
  const waiting = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download report", exact: true }).click();
  const download = await waiting;
  expect(JSON.parse(await readFile((await download.path())!, "utf8"))).toEqual(report);
});
test("device QA records unsupported PRF without claiming the device passed", async ({ page, context }) => {
  await open(page, context, false);
  await step(page, "Create synthetic email wallet", "email_registration");
  await page.getByRole("button", { name: "Enable passkey unlock", exact: true }).click();
  await expect(page.getByTestId("result-passkey_enable")).toHaveText("unsupported");
  await expect(page.getByTestId("qa-enabled")).toHaveText("disabled");
  await expect(page.getByTestId("qa-status")).toHaveText("authenticated");
  const report = JSON.parse((await page.getByTestId("qa-report").textContent()) ?? "{}");
  expect(report.outcome).toBe("unsupported");
});
test("device QA serves strict browser policies and rejects foreign origins", async ({ request }) => {
  const page = await request.get(origin);
  expect(page.status()).toBe(200);
  expect(page.headers()["cache-control"]).toBe("no-store");
  expect(page.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(page.headers()["content-security-policy"]).not.toContain("unsafe-");
  const host = await request.get(origin + "/qa-info", { headers: { Host: "evil.example.test" } });
  expect(host.status()).toBe(403);
  const crossOrigin = await request.post(origin + "/auth/register", {
    headers: { Origin: "https://evil.example.test" },
    data: {},
  });
  expect(crossOrigin.status()).toBe(403);
  expect((await request.get(origin + "/package.json")).status()).toBe(404);
});

test("device QA reports blocked test-state storage before creating an account", async ({ page }) => {
  await page.addInitScript(() => {
    const nativeSet = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      if (this === sessionStorage) throw new DOMException("Storage blocked", "QuotaExceededError");
      return nativeSet.call(this, key, value);
    };
  });
  await page.goto(origin);
  await expect(
    page.getByRole("button", { name: "Create synthetic email wallet", exact: true }),
  ).toBeDisabled();
  const report = JSON.parse((await page.getByTestId("qa-report").textContent()) ?? "{}");
  expect(report.capabilities.sessionStorage).toBe(false);
  expect(report.outcome).toBe("incomplete");
});
