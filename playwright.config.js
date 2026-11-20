import { defineConfig, devices } from "@playwright/test";

const localChrome = process.env.SENTINEL_CHROME;
export default defineConfig({
  testDir:"./tests/browser",
  timeout:90_000,
  workers:1,
  use:{
    ...devices["Desktop Chrome"],
    baseURL:process.env.SENTINEL_HTTP || "http://127.0.0.1:8080",
    launchOptions:localChrome ? {executablePath:localChrome} : {},
    trace:"retain-on-failure",
  },
});
