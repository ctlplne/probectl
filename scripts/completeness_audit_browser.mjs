#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// CL-002's browser leg deliberately runs inside the digest-pinned WebKit image.
// It talks to the release control image and real Dex. There is no request
// interception, fixture transport, or TLS bypass in this file.

import { createRequire } from "node:module";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const require = createRequire("/worker/package.json");
const { webkit } = require("playwright");

const mode = process.argv[2] ?? "journey";
const baseURL = mustEnv("AUDIT_BASE_URL");
const artifactDir = mustEnv("AUDIT_ARTIFACT_DIR");
const sensitiveValues = [];

function mustEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function sanitizeText(value) {
  let sanitized = String(value);
  for (const secret of sensitiveValues) sanitized = sanitized.replaceAll(secret, "[redacted]");
  return sanitized
    .replace(/(code|state|nonce|token|session)=([^\s&]+)/gi, "$1=[redacted]")
    .slice(0, 1000);
}

function sanitizeTLSFailure(value) {
  return sanitizeText(value).replace(/\s+/g, " ").trim().slice(0, 512);
}

function exactKeys(value, required, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const got = Object.keys(value).sort();
  const want = [...required].sort();
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    throw new Error(`${label} keys ${got.join(",")} do not match ${want.join(",")}`);
  }
}

function validateDriver(driver, label, builtinPath) {
  if (driver?.kind === "builtin") {
    exactKeys(driver, ["kind", "runtime_path"], label);
    if (driver.runtime_path !== builtinPath) throw new Error(`${label} has an unknown builtin path`);
    return;
  }
  if (driver?.kind === "source_bound") {
    exactKeys(driver, ["kind", "runtime_path", "source_path", "sha256", "git_blob_sha"], label);
    if (typeof driver.runtime_path !== "string" || driver.runtime_path.length === 0 ||
        typeof driver.source_path !== "string" || driver.source_path.length === 0 ||
        driver.source_path.startsWith("/") || driver.source_path.split("/").includes("..") ||
        !/^sha256:[0-9a-f]{64}$/.test(driver.sha256) || !/^[0-9a-f]{40}$/.test(driver.git_blob_sha)) {
      throw new Error(`${label} is not safely source-bound`);
    }
    return;
  }
  throw new Error(`${label} has an unsupported kind`);
}

async function loadCapabilityManifest() {
  const path = mustEnv("AUDIT_CAPABILITY_MANIFEST");
  const manifest = JSON.parse(await readFile(path, "utf8"));
  exactKeys(manifest, ["schema", "item", "capability_id", "scope", "human_path", "binary", "api", "browser_api", "cli", "ui", "docs_path", "activation", "summary"], "manifest");
  exactKeys(manifest.scope, ["mode", "browser_auth_mode", "cli_auth_mode", "provider_compatibility_validated", "capability_driver", "browser_driver"], "manifest.scope");
  validateDriver(manifest.scope.capability_driver, "manifest.scope.capability_driver", "scripts/run_completeness_audit.sh#run_f50_capability");
  validateDriver(manifest.scope.browser_driver, "manifest.scope.browser_driver", "scripts/completeness_audit_browser.mjs");
  exactKeys(manifest.human_path, ["id", "path_class", "coverage", "summary"], "manifest.human_path");
  exactKeys(manifest.binary, ["entrypoint", "default_build_command"], "manifest.binary");
  exactKeys(manifest.api, ["operation_id", "method", "path"], "manifest.api");
  exactKeys(manifest.browser_api, ["operation_id", "method", "path", "required_get_paths"], "manifest.browser_api");
  exactKeys(manifest.cli, ["commands", "primary_operation"], "manifest.cli");
  exactKeys(manifest.ui, ["observations", "primary_route"], "manifest.ui");
  if (manifest.schema !== "probectl.completeness-audit-capability/v1") throw new Error("unsupported capability manifest schema");
  if (manifest.scope.mode !== "tenant_plane" || manifest.scope.browser_auth_mode !== "tenant_oidc" ||
      manifest.scope.cli_auth_mode !== "tenant_mcp_bearer" ||
      manifest.scope.provider_compatibility_validated !== false) {
    throw new Error("built-in browser driver supports only explicit tenant_plane/tenant_oidc manifests");
  }
  if (manifest.scope.browser_driver.kind !== "builtin") {
    throw new Error("arbitrary browser code is forbidden; the browser driver must remain fixed and builtin");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(manifest.human_path.id) ||
      manifest.human_path.path_class !== "executable_end_user" ||
      manifest.human_path.coverage !== "one_governed_end_user_path" ||
      typeof manifest.human_path.summary !== "string" || manifest.human_path.summary.length === 0) {
    throw new Error("invalid governed human path");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(manifest.item) ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(manifest.capability_id)) throw new Error("invalid manifest item/capability id");
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(manifest.api.operation_id) ||
      !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(manifest.api.method) ||
      !manifest.api.path.startsWith("/v1/")) throw new Error("invalid manifest API operation");
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(manifest.browser_api.operation_id) || manifest.browser_api.method !== "GET" ||
      !manifest.browser_api.path.startsWith("/v1/")) throw new Error("invalid safe browser API observation");
  if (!Array.isArray(manifest.browser_api.required_get_paths) || manifest.browser_api.required_get_paths.length === 0 ||
      manifest.browser_api.required_get_paths.some((path) => typeof path !== "string" || !path.startsWith("/v1/")) ||
      !manifest.browser_api.required_get_paths.includes(manifest.browser_api.path)) {
    throw new Error("invalid required natural browser GET paths");
  }
  if (!Array.isArray(manifest.cli.commands) || manifest.cli.commands.length === 0 ||
      manifest.cli.commands.some((command) => typeof command !== "string" || !command.startsWith("probectl "))) {
    throw new Error("manifest CLI commands must be non-empty probectl commands");
  }
  if (!Array.isArray(manifest.ui.observations) || manifest.ui.observations.length < 2 || manifest.ui.observations.length > 16) {
    throw new Error("manifest must describe between two and sixteen tenant-bound browser observations");
  }
  for (const [index, observation] of manifest.ui.observations.entries()) {
    exactKeys(observation, ["tenant", "tenant_name", "product_path", "route", "heading", "content_scope", "own_text", "foreign_text", "screenshot"], `manifest.ui.observations[${index}]`);
    exactKeys(observation.heading, ["role", "name"], `manifest.ui.observations[${index}].heading`);
    if ([observation.tenant, observation.tenant_name, observation.own_text, observation.foreign_text].some((value) => typeof value !== "string" || value.length === 0) ||
        observation.own_text === observation.foreign_text || !observation.product_path.startsWith("/ui/") ||
        !observation.route.startsWith("/") || observation.heading.role !== "heading" || observation.content_scope !== "#main-content" ||
        typeof observation.heading.name !== "string" || !/^[A-Za-z0-9._-]+\.png$/.test(observation.screenshot)) {
      throw new Error(`invalid manifest.ui.observations[${index}]`);
    }
  }
  if (new Set(manifest.ui.observations.map(({ tenant }) => tenant)).size !== 2) {
    throw new Error("browser observations must cover exactly two distinct tenants");
  }
  return manifest;
}

function sanitizeURL(raw) {
  try {
    const url = new URL(raw);
    url.username = "";
    url.password = "";
    for (const key of [...url.searchParams.keys()]) {
      // Query values are not needed for delivery evidence. Redacting all of
      // them is both simpler and safer than maintaining a secret-name list.
      url.searchParams.set(key, "[redacted]");
    }
    url.hash = "";
    return url.toString();
  } catch {
    return "[invalid-url-redacted]";
  }
}

async function writeJSON(name, value) {
  await mkdir(artifactDir, { recursive: true });
  await writeFile(join(artifactDir, name), `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o644,
  });
}

async function rejectWithoutCA() {
  const browser = await webkit.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: false });
  const page = await context.newPage();
  let rejected = false;
  let diagnostic = "";
  try {
    await page.goto(`${baseURL}/readyz`, {
      waitUntil: "domcontentloaded",
      timeout: 15_000,
    });
  } catch (error) {
    diagnostic = sanitizeTLSFailure(error instanceof Error ? error.message : error);
    rejected = /certificate|cert_|ssl|tls|authority|issuer|self[- ]signed|trust/i.test(diagnostic);
    if (!rejected) {
      throw new Error(`pre-trust navigation failed for a non-certificate reason: ${diagnostic}`);
    }
  } finally {
    await context.close();
    await browser.close();
  }
  if (!rejected) {
    throw new Error("WebKit unexpectedly trusted the disposable CA before installation");
  }
  await writeJSON("tls-pretrust.json", {
    schema: "probectl.delivery-audit-browser-pretrust/v1",
    browser: "webkit",
    ignore_https_errors: false,
    rejected_without_ca: true,
    rejection_class: "certificate_trust",
    diagnostic,
  });
  process.stdout.write("WebKit rejected the untrusted disposable CA as required.\n");
}

function observeNetwork(page, requests, failures) {
  page.on("response", (response) => {
    if (requests.length >= 256) return;
    const request = response.request();
    const url = sanitizeURL(response.url());
    if (!url.startsWith("https://")) {
      failures.push(`non-HTTPS browser response: ${url}`);
    }
    requests.push({ method: request.method(), url, status: response.status() });
  });
  page.on("pageerror", (error) => failures.push(`page: ${sanitizeText(error.message)}`));
}

async function loginAndVerify(browser, spec, email, password, requests) {
  const context = await browser.newContext({
    ignoreHTTPSErrors: false,
    viewport: { width: 1440, height: 960 },
    colorScheme: "dark",
  });
  const page = await context.newPage();
  const failures = [];
  observeNetwork(page, requests, failures);
  try {
    await page.goto(`${baseURL}/auth/login?tenant=${encodeURIComponent(spec.tenant)}`, {
      waitUntil: "domcontentloaded",
      timeout: 30_000,
    });
    const loginInput = page.locator('input[name="login"]');
    if ((await loginInput.count()) === 0) {
      // `alwaysShowLoginScreen` makes Dex present its connector chooser even
      // when the disposable password database is the only connector. Exercise
      // that real user-visible hop instead of assuming the password form is the
      // first OIDC page.
      const emailConnector = page.getByRole("link", { name: "Log in with Email", exact: true });
      await emailConnector.waitFor({ state: "visible", timeout: 10_000 });
      await emailConnector.click();
    }
    await loginInput.fill(email);
    await page.locator('input[name="password"]').fill(password);
    await Promise.all([
      // Do not stop at /auth/callback: navigating away while that callback is
      // still redirecting aborts the shell's first /v1/me and /branding fetches
      // and WebKit reports those aborts as access-control errors. /ui/ is the
      // first fully authenticated landing page.
      page.waitForURL((url) => url.origin === baseURL && url.pathname.startsWith("/ui/"), {
        waitUntil: "domcontentloaded",
        timeout: 30_000,
      }),
      page.locator('button[type="submit"]').click(),
    ]);
    await page.waitForLoadState("networkidle", { timeout: 30_000 });

    // Keep the authenticated landing document alive and open the asserted
    // product route in a second page that shares this context's session
    // cookies. The landing shell polls onboarding progress every five seconds;
    // reusing it for page.goto() can abort a just-started same-origin fetch,
    // which WebKit misleadingly reports as an access-control error. A fresh
    // page removes that navigation race without ignoring any browser, TLS, or
    // HTTP failure from either document.
    const productPage = await context.newPage();
    observeNetwork(productPage, requests, failures);
    await productPage.goto(`${baseURL}${spec.product_path}`, {
      waitUntil: "networkidle",
      timeout: 30_000,
    });
    await productPage.getByRole(spec.heading.role, { name: spec.heading.name, exact: true }).waitFor({
      state: "visible",
      timeout: 20_000,
    });
    const currentTenant = productPage.getByLabel(`Current tenant: ${spec.tenant_name}`, { exact: true });
    const switchTenant = productPage.getByLabel(`Switch tenant; current tenant ${spec.tenant_name}`, { exact: true });
    if ((await currentTenant.count()) > 0) {
      await currentTenant.first().waitFor({ state: "visible", timeout: 20_000 });
    } else {
      await switchTenant.first().waitFor({ state: "visible", timeout: 20_000 });
    }
    // The shell's tenant switcher legitimately names every tenant available to
    // this same-email user. Product-data isolation is therefore asserted only
    // inside the route's main content; the shell tenant indicator is checked
    // independently above.
    const mainContent = productPage.locator(spec.content_scope);
    await mainContent.getByText(spec.own_text, { exact: true }).first().waitFor({
      state: "visible",
      timeout: 20_000,
    });
    if ((await mainContent.getByText(spec.foreign_text, { exact: true }).count()) !== 0) {
      failures.push(`foreign tenant evidence rendered: ${spec.foreign_text}`);
    }
    if (failures.length > 0) throw new Error(failures.join("\n"));
    await productPage.screenshot({
      path: join(artifactDir, spec.screenshot),
      fullPage: true,
    });
    return {
      auth_mode: "tenant_oidc",
      tenant: spec.tenant,
      route: spec.route,
      screenshot: spec.screenshot,
      rendered: true,
      credentialed_login: true,
      tenant_indicator_visible: true,
      expected_evidence_visible: true,
      foreign_evidence_absent: true,
    };
  } finally {
    await context.close();
  }
}

async function runJourney() {
  const email = mustEnv("AUDIT_DEX_EMAIL");
  const password = mustEnv("AUDIT_DEX_PASSWORD");
  sensitiveValues.push(password);
  const manifest = await loadCapabilityManifest();
  await mkdir(artifactDir, { recursive: true });
  const browser = await webkit.launch({ headless: true });
  const requests = [];
  try {
    const sessions = [];
    for (const observation of manifest.ui.observations) {
      sessions.push(await loginAndVerify(browser, observation, email, password, requests));
    }
    const apiRequests = requests.filter((request) => {
      try {
        return new URL(request.url).pathname.startsWith("/v1/");
      } catch {
        return false;
      }
    });
    if (!apiRequests.some((request) => request.method === manifest.browser_api.method && new URL(request.url).pathname === manifest.browser_api.path)) {
      throw new Error(`live browser trace did not naturally observe ${manifest.browser_api.method} ${manifest.browser_api.path}`);
    }
    for (const path of manifest.browser_api.required_get_paths) {
      if (!apiRequests.some((request) => request.method === "GET" && new URL(request.url).pathname === path && request.status >= 200 && request.status < 400)) {
        throw new Error(`live browser trace did not naturally observe successful GET ${path}`);
      }
    }
    await writeJSON("browser-network.json", {
      schema: "probectl.delivery-audit-browser-network/v1",
      browser: "webkit",
      live_https: true,
      request_interception: false,
      ignore_https_errors: false,
      requests,
      sessions,
    });
  } finally {
    await browser.close();
  }
  process.stdout.write(`Real-Dex WebKit rendered ${manifest.ui.observations.length} tenant-bound UI observations.\n`);
}

if (mode === "pretrust") {
  await rejectWithoutCA();
} else if (mode === "journey") {
  await runJourney();
} else {
  throw new Error(`unknown mode ${mode}; want pretrust|journey`);
}
