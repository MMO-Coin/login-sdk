import { test, expect, type BrowserContext, type CDPSession, type Page } from "@playwright/test";
import type { PasskeySnapshot } from "./fixture";

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
  await page.goto("/");
  await expect(page.getByTestId("operation")).toHaveText("Ready");
  await expect(page.getByTestId("available")).toHaveText("true");
  return { cdp, authenticatorId };
}

async function act(page: Page, name: string) {
  await page.getByRole("button", { name, exact: true }).click();
  await expect(page.getByTestId("operation")).toHaveText("Done");
  await expect(page.getByTestId("error-name")).toBeEmpty();
}
const snapshot = (page: Page): Promise<PasskeySnapshot> => page.evaluate(() => window.passkeyTest.snapshot());
const blobCount = (page: Page) => page.evaluate(() => window.passkeyTest.blobCount());
async function holdPresence(cdp: CDPSession, authenticatorId: string, enabled: boolean) {
  await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled });
}

test("native PRF is stable for one salt and changes for a different salt", async ({ page, context }) => {
  const { cdp, authenticatorId } = await open(page, context);
  await act(page, "Probe native PRF");
  const probe = JSON.parse(await page.getByTestId("probe").innerText()) as {
    first: string;
    second: string;
    changed: string;
  };
  expect(probe.first).toHaveLength(64);
  expect(probe.second).toBe(probe.first);
  expect(probe.changed).not.toBe(probe.first);
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(credentials).toHaveLength(1);
  expect((await snapshot(page)).status).toBe("unauthenticated");
});

test("email wallet passkey unlock survives reload and disable removes its stored wrapper", async ({
  page,
  context,
}) => {
  await open(page, context);
  await act(page, "Create email account");
  const before = await snapshot(page);
  await expect(page.getByTestId("wallets")).not.toHaveText("[]");
  const addresses = await page.getByTestId("wallets").innerText();
  await act(page, "Enable passkey unlock");
  await expect(page.getByTestId("enabled")).toHaveText("true");
  expect(await blobCount(page)).toBe(1);
  await act(page, "Lock wallet");
  expect((await snapshot(page)).keyFingerprint).toBeNull();
  await page.reload();
  await expect(page.getByTestId("status")).toHaveText("session_expired");
  await expect(page.getByTestId("enabled")).toHaveText("true");
  await act(page, "Unlock with passkey");
  const after = await snapshot(page);
  expect(after.keyFingerprint).toBe(before.keyFingerprint);
  expect(after.publicKey).toBe(before.publicKey);
  expect(after.storageContainsAppKey).toBe(false);
  await expect(page.getByTestId("wallets")).toHaveText(addresses);
  await act(page, "Disable passkey unlock");
  await expect(page.getByTestId("enabled")).toHaveText("false");
  expect(await blobCount(page)).toBe(0);
  expect((await snapshot(page)).registrationStored).toBe(false);
  await act(page, "Lock wallet");
  await page.getByRole("button", { name: "Unlock with passkey", exact: true }).click();
  await expect(page.getByTestId("operation")).toHaveText("Failed");
  expect((await snapshot(page)).keyFingerprint).toBeNull();
});

test("a biometric-primary account reauthenticates with the same PRF-derived key", async ({
  page,
  context,
}) => {
  await open(page, context);
  await act(page, "Register passkey account");
  const before = await snapshot(page);
  await expect(page.getByTestId("wallets")).not.toHaveText("[]");
  const addresses = await page.getByTestId("wallets").innerText();
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/auth/logout") && response.status() === 200),
    act(page, "Sign out"),
  ]);
  await expect(page.getByTestId("status")).toHaveText("unauthenticated");
  await act(page, "Sign in with passkey");
  const after = await snapshot(page);
  expect(after.keyFingerprint).toBe(before.keyFingerprint);
  expect(after.publicKey).toBe(before.publicKey);
  expect(after.storageContainsAppKey).toBe(false);
  await expect(page.getByTestId("wallets")).toHaveText(addresses);
});

test("an authenticator without PRF cannot enable a wallet-key fallback", async ({ page, context }) => {
  await open(page, context, false);
  await act(page, "Create email account");
  const before = await snapshot(page);
  await page.getByRole("button", { name: "Enable passkey unlock", exact: true }).click();
  await expect(page.getByTestId("error-name")).toHaveText("PrfUnavailableError");
  const after = await snapshot(page);
  expect(after.keyFingerprint).toBe(before.keyFingerprint);
  expect(after.enabled).toBe(false);
  expect(after.registrationStored).toBe(false);
  expect(await blobCount(page)).toBe(0);
});

test("biometric-primary registration without PRF sends no account registration", async ({
  page,
  context,
}) => {
  await open(page, context, false);
  let registrations = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/auth/register")) registrations++;
  });
  await page.getByRole("button", { name: "Register passkey account", exact: true }).click();
  await expect(page.getByTestId("error-name")).toHaveText("PrfUnavailableError");
  expect(registrations).toBe(0);
  const state = await snapshot(page);
  expect(state.status).toBe("unauthenticated");
  expect(state.keyFingerprint).toBeNull();
});

test("cancelling a native assertion leaves the wallet locked and allows a retry", async ({
  page,
  context,
}) => {
  const { cdp, authenticatorId } = await open(page, context);
  await act(page, "Create email account");
  const before = await snapshot(page);
  await act(page, "Enable passkey unlock");
  await act(page, "Lock wallet");
  await holdPresence(cdp, authenticatorId, false);
  await page.evaluate(() => window.passkeyTest.prepareAbortableAssertion());
  await page.getByRole("button", { name: "Unlock with passkey", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.passkeyTest.assertionStarted)).toBe(true);
  await page.evaluate(() => window.passkeyTest.cancelAssertion());
  await expect(page.getByTestId("error-name")).toHaveText("AbortError");
  expect((await snapshot(page)).keyFingerprint).toBeNull();
  await holdPresence(cdp, authenticatorId, true);
  await act(page, "Unlock with passkey");
  expect((await snapshot(page)).keyFingerprint).toBe(before.keyFingerprint);
});

test("cross-tab logout during a native assertion cannot restore a stale app key", async ({
  page,
  context,
}) => {
  await open(page, context);
  await act(page, "Create email account");
  await act(page, "Enable passkey unlock");
  await act(page, "Lock wallet");
  await page.evaluate(() => window.passkeyTest.deferCredentialResult("get"));
  await page.getByRole("button", { name: "Unlock with passkey", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.passkeyTest.credentialResultReady)).toBe(true);
  const sibling = await context.newPage();
  await sibling.goto("/");
  await expect(sibling.getByTestId("status")).toHaveText("session_expired");
  await act(sibling, "Sign out");
  await expect(page.getByTestId("status")).toHaveText("unauthenticated");
  await page.evaluate(() => window.passkeyTest.releaseCredentialResult());
  await expect(page.getByTestId("error-name")).toHaveText("SessionChangedError");
  const state = await snapshot(page);
  expect(state.keyFingerprint).toBeNull();
  expect(state.enabled).toBe(false);
  expect(state.registrationStored).toBe(false);
  await expect.poll(() => blobCount(page)).toBe(0);
});

test("tampering with the native IndexedDB wrapper fails closed", async ({ page, context }) => {
  await open(page, context);
  await act(page, "Create email account");
  await act(page, "Enable passkey unlock");
  await page.evaluate(() => window.passkeyTest.tamperBlob());
  await act(page, "Lock wallet");
  await page.getByRole("button", { name: "Unlock with passkey", exact: true }).click();
  await expect(page.getByTestId("error-name")).toHaveText("OperationError");
  expect((await snapshot(page)).keyFingerprint).toBeNull();
  await expect(page.getByTestId("status")).toHaveText("session_expired");
});

test("logout before a native credential result is delivered cannot persist a late wrapper", async ({
  page,
  context,
}) => {
  await open(page, context);
  await act(page, "Create email account");
  await page.evaluate(() => window.passkeyTest.deferCredentialResult("create"));
  await page.getByRole("button", { name: "Enable passkey unlock", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.passkeyTest.credentialResultReady)).toBe(true);
  await act(page, "Sign out");
  await expect(page.getByTestId("status")).toHaveText("unauthenticated");
  await page.evaluate(() => window.passkeyTest.releaseCredentialResult());
  await expect(page.getByTestId("error-name")).toHaveText("SessionChangedError");
  const state = await snapshot(page);
  expect(state.keyFingerprint).toBeNull();
  expect(state.enabled).toBe(false);
  expect(state.registrationStored).toBe(false);
  await expect.poll(() => blobCount(page)).toBe(0);
});

test("the packaged login panel retires a biometric option that has no PRF", async ({ page, context }) => {
  await open(page, context, false);
  const panel = page.getByRole("region", { name: "Packaged login panel" });
  await panel.getByRole("button", { name: "Continue with biometric", exact: true }).click();
  await expect(panel).toContainText(
    "This device can't protect a wallet key with biometrics. Continue with email or a wallet instead.",
  );
  await expect(panel.getByRole("button")).toHaveCount(0);
  expect((await snapshot(page)).keyFingerprint).toBeNull();
});
