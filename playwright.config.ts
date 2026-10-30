import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  outputDir: "./output/playwright/results",
  reporter: "list",
  use: {
    browserName: "chromium",
    baseURL: "http://localhost:4193",
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      command: "node scripts/passkey-test-server.mjs",
      url: "http://127.0.0.1:4193",
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: "node scripts/passkey-device-server.mjs",
      url: "http://127.0.0.1:4194/health",
      reuseExistingServer: false,
      timeout: 30_000,
    },
  ],
});
