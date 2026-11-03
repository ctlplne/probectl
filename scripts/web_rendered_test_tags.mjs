// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Production-build Chromium rendering with synthetic API data. This is not
// source/sender, SSO, tenant storage isolation or release-stack evidence.
import { join } from "node:path";

export const TEST_TAG_CONTEXT_CASES = [
  "ready",
  "legacy",
  "missing-grant",
  "foreign",
];
export const TEST_TAG_CONTEXT_SURFACES = ["results", "rca"];
const testID = "11111111-1111-4111-8111-111111111111";
const revision = "9007199254740993";
const stagesFor = (mode) =>
  mode === "ready" ? ["ready", "expanded", "refused"] : ["no-disclosure"];

export function validateTestTagContextMatrix(checks, themes, viewports) {
  const failures = [];
  const expected =
    themes.length *
    viewports.length *
    TEST_TAG_CONTEXT_CASES.length *
    TEST_TAG_CONTEXT_SURFACES.length;
  if (checks.length !== expected)
    failures.push(
      `test tag matrix incomplete: expected ${expected}, recorded ${checks.length}`,
    );
  for (const surface of TEST_TAG_CONTEXT_SURFACES)
    for (const theme of themes)
      for (const viewport of viewports)
        for (const mode of TEST_TAG_CONTEXT_CASES) {
          const rows = checks.filter(
            (row) =>
              row.surface === surface &&
              row.theme === theme &&
              row.viewport === viewport.name &&
              row.mode === mode,
          );
          if (rows.length !== 1) {
            failures.push(
              `test tag matrix ${surface} ${viewport.name} ${theme} ${mode}: expected one record, found ${rows.length}`,
            );
            continue;
          }
          const row = rows[0];
          const names = stagesFor(mode);
          if (
            row.passed !== true ||
            !Array.isArray(row.runtime) ||
            !Array.isArray(row.errors) ||
            row.runtime?.length ||
            row.errors?.length ||
            row.theme_verified !== true ||
            row.request_ids_verified !== true ||
            !Array.isArray(row.stages) ||
            row.stages.length !== names.length ||
            names.some(
              (name) =>
                row.stages.filter(
                  (stage) =>
                    stage.name === name &&
                    stage.passed === true &&
                    ["axe", "targets", "overflow", "clipping"].every(
                      (field) =>
                        Array.isArray(stage[field]) &&
                        stage[field].length === 0,
                    ),
                ).length !== 1,
            )
          )
            failures.push(
              `test tag matrix ${surface} ${viewport.name} ${theme} ${mode}: required state or browser check did not pass`,
            );
          if (
            mode === "ready"
              ? row.full_value_exact !== true || row.refusal_cleared !== true
              : row.no_disclosure !== true || row.no_metadata_request !== true
          )
            failures.push(
              `test tag matrix ${surface} ${viewport.name} ${theme} ${mode}: exact disclosure/refusal proof absent`,
            );
        }
  return failures;
}

function fixtureSource(mode) {
  return `(() => {
    const mode = ${JSON.stringify(mode)};
    const id = ${JSON.stringify(testID)};
    const revision = ${JSON.stringify(revision)};
    const wide = '🌐'.repeat(24000);
    const base = window.fetch.bind(window);
    const state = window.__probectlTestTagProof = { refuse: false, requests: [] };
    const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'x-probectl-fixture': '1' } });
    window.fetch = async (input, init) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, window.location.href);
      const path = url.pathname;
      if (path === '/v1/me') {
        const response = await base(input, init);
        const me = await response.json();
        state.tenantID = me.tenant_id;
        me.permissions = mode === 'missing-grant' ? ['ai.query', 'test.read'] : ['ai.query', 'test.read', 'tags.read'];
        return json(me);
      }
      if (path === '/v1/ai/ask') return json({
        id: 'test-tag-proof-answer', tenant: mode === 'foreign' ? 'foreign-tenant' : state.tenantID,
        question: 'Why is this test slow?', root_cause: 'The cited test metric has elevated latency.',
        root_cause_citations: [{ evidence_id: 'E1' }], root_cause_grounded: true,
        confidence: 'medium', findings: [], model: 'builtin', insufficient_evidence: false,
        reasoning: { adapter: 'builtin', execution: 'builtin_local', egress_consent: 'not_required' },
        evidence: [
          { id: 'E1', domain: 'metrics', title: 'Test latency', fields: mode === 'legacy' ? { target: 'https://probe.example/health' } : { test_id: id } },
          { id: 'E2', domain: 'metrics', fields: { test_id: '22222222-2222-4222-8222-222222222222' } },
        ],
      });
      if (path === '/v1/tests') return json({ items: [{ id, name: 'Tag proof probe', type: 'http', target: 'https://probe.example/health', interval_seconds: 60, timeout_seconds: 5, enabled: true, params: {}, created_at: '2026-11-03T00:00:00Z', updated_at: '2026-11-03T00:00:00Z' }] });
      if (path === '/v1/results/latest') return json({ collector_running: true, items: [{ agent_id: 'fixture-agent', type: 'http', target: 'https://probe.example/health', success: true, duration_ms: 184, metrics: { 'http.total.ms': 184, 'http.status': 200 }, observed_at: '2026-11-02T00:00:00Z', attributes: mode === 'legacy' ? {} : { 'probectl.test.id': mode === 'foreign' ? '22222222-2222-4222-8222-222222222222' : id } }] });
      if (path === '/v1/tags/tests/resolve') {
        const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
        const body = init?.body ?? (input instanceof Request ? await input.clone().text() : '');
        state.requests.push({ method, body: JSON.parse(String(body)) });
        if (state.refuse) return json({ error: { code: 'forbidden', message: 'Current context refused' } }, 403);
        return json({ tag_revision: revision, as_of: '2026-11-03T00:00:00Z', items: [{ context_id: '33333333-3333-4333-8333-333333333333', target_kind: 'test', target_id: id, tag_revision: revision, as_of: '2026-11-03T00:00:00Z', items: [{ tag_id: '44444444-4444-4444-8444-444444444444', key: 'customer', value: wide, source: 'rule' }] }] });
      }
      return base(input, init);
    };
  })();`;
}

export function testTagContextSelfTest() {
  const themes = ["light", "dark"];
  const viewports = [{ name: "desktop" }, { name: "mobile" }];
  const records = TEST_TAG_CONTEXT_SURFACES.flatMap((surface) =>
    themes.flatMap((theme) =>
      viewports.flatMap((viewport) =>
        TEST_TAG_CONTEXT_CASES.map((mode) => ({
          surface,
          theme,
          viewport: viewport.name,
          mode,
          passed: true,
          runtime: [],
          errors: [],
          theme_verified: true,
          request_ids_verified: true,
          full_value_exact: true,
          refusal_cleared: true,
          no_disclosure: true,
          no_metadata_request: true,
          stages: stagesFor(mode).map((name) => ({
            name,
            passed: true,
            axe: [],
            targets: [],
            overflow: [],
            clipping: [],
          })),
        })),
      ),
    ),
  );
  if (validateTestTagContextMatrix(records, themes, viewports).length)
    throw Error("complete test-tag matrix was refused");
  const missingStage = structuredClone(records);
  missingStage[0].stages.pop();
  const wrongIdentity = structuredClone(records);
  wrongIdentity[0].request_ids_verified = false;
  const contradictoryPass = structuredClone(records);
  contradictoryPass[0].stages[0].axe.push("blocking finding");
  const unobservedRuntime = structuredClone(records);
  delete unobservedRuntime[0].runtime;
  for (const invalid of [
    [],
    records.slice(1),
    [...records, records[0]],
    missingStage,
    wrongIdentity,
    contradictoryPass,
    unobservedRuntime,
  ])
    if (!validateTestTagContextMatrix(invalid, themes, viewports).length)
      throw Error("missing/duplicate/unproved test-tag state was accepted");
  for (const mode of TEST_TAG_CONTEXT_CASES) new Function(fixtureSource(mode));
}

export async function runTestTagContextChecks({
  browser,
  baseURL,
  axeSource,
  receiptDir,
  themes,
  viewports,
  helpers,
}) {
  const checks = [];
  for (const surface of TEST_TAG_CONTEXT_SURFACES)
    for (const viewport of viewports)
      for (const theme of themes)
        for (const mode of TEST_TAG_CONTEXT_CASES) {
          const record = {
            surface,
            theme,
            viewport: viewport.name,
            mode,
            passed: false,
            stages: [],
            errors: [],
            runtime: [],
            source:
              "simulation: current production build and synthetic API; no sender/storage isolation claim",
          };
          checks.push(record);
          const context = await browser.newContext({
            viewport,
            colorScheme: theme,
            locale: "en-US",
            hasTouch: viewport.name === "mobile",
          });
          const page = await context.newPage();
          page.on("pageerror", (error) => record.runtime.push(error.message));
          const inspect = async (name) => {
            const stage = {
              name,
              passed: false,
              axe: [],
              targets: [],
              overflow: [],
              clipping: [],
            };
            record.stages.push(stage);
            stage.axe = helpers.blockingAxeResults(
              await helpers.runAxe(page, axeSource),
            );
            stage.targets = await helpers.targetAndTabChecks(page);
            stage.overflow = await helpers.horizontalOverflowCheck(page);
            stage.clipping = await helpers.interactiveClippingCheck(page);
            await page.screenshot({
              path: join(
                receiptDir,
                `test-tags-${surface}-${viewport.name}-${theme}-${mode}-${name}.png`,
              ),
              fullPage: true,
            });
            if (
              stage.axe.length ||
              stage.targets.length ||
              stage.overflow.length ||
              stage.clipping.length
            )
              throw Error(
                `test tag ${name} has accessibility/geometry failures`,
              );
            stage.passed = true;
          };
          try {
            await context.addInitScript(
              helpers.fetchStubSource(theme) + fixtureSource(mode),
            );
            await page.goto(
              `${baseURL}/ui/${surface === "results" ? "targets" : "ask"}`,
              {
                waitUntil: "networkidle",
              },
            );
            await page.addStyleTag({
              content:
                "*, *::before, *::after { transition-duration: 0s !important; animation-duration: 0s !important; }",
            });
            record.theme_verified = await page.evaluate(
              (expected) =>
                document.documentElement.getAttribute("data-theme") ===
                expected,
              theme,
            );
            if (!record.theme_verified)
              throw Error("requested theme was not active");
            if (surface === "results") {
              await page
                .getByRole("button", {
                  name: "Results for Tag proof probe",
                  exact: true,
                })
                .click();
              await page.getByRole("dialog").waitFor();
            } else {
              await page
                .getByLabel(/Your question/i)
                .fill("Why is this test slow?");
              await page.getByRole("button", { name: /^Ask$/i }).click();
              await page
                .getByText("The cited test metric has elevated latency.", {
                  exact: true,
                })
                .waitFor();
            }
            const dialog =
              surface === "results" ? page.getByRole("dialog") : page;
            if (mode === "ready") {
              await dialog
                .getByRole("button", {
                  name: "Show current test tags",
                  exact: true,
                })
                .click();
              await dialog.getByText(revision, { exact: true }).waitFor();
              await inspect("ready");
              const disclosure = dialog.locator(
                "details:has([data-tag-value-full])",
              );
              await disclosure.locator("summary").focus();
              await page.keyboard.press("Enter");
              const full = disclosure.locator("[data-tag-value-full]");
              await full.waitFor({ state: "visible" });
              record.full_value_exact =
                (await full.textContent()) === "🌐".repeat(24000);
              if (!record.full_value_exact)
                throw Error("complete Unicode tag value changed");
              await inspect("expanded");
              await page.evaluate(() => {
                window.__probectlTestTagProof.refuse = true;
              });
              await dialog
                .getByRole("button", {
                  name: "Refresh current test tags",
                  exact: true,
                })
                .click();
              await dialog
                .getByText(/Current test tag context could not be loaded/)
                .waitFor();
              record.refusal_cleared =
                (await dialog.locator("[data-tag-value-full]").count()) === 0 &&
                (await dialog.getByText(revision, { exact: true }).count()) ===
                  0;
              if (!record.refusal_cleared)
                throw Error("refused refresh retained earlier tag disclosure");
              await inspect("refused");
            } else {
              if (surface === "results" && mode === "foreign")
                await dialog
                  .getByText("No cached results", { exact: true })
                  .waitFor();
              else if (surface === "results")
                await dialog.getByLabel("HTTP timing waterfall").waitFor();
              record.no_disclosure =
                (await dialog
                  .getByRole("button", {
                    name: "Show current test tags",
                    exact: true,
                  })
                  .count()) === 0 &&
                (await dialog.locator("[data-tag-value-full]").count()) === 0;
              if (!record.no_disclosure)
                throw Error(
                  "unbound or unauthorized result acquired tag disclosure",
                );
              await inspect("no-disclosure");
            }
            const requests = await page.evaluate(
              () => window.__probectlTestTagProof.requests,
            );
            record.request_ids_verified =
              mode === "ready"
                ? requests.length === 2 &&
                  requests.every(
                    (entry) =>
                      entry.method === "POST" &&
                      Object.keys(entry.body).length === 1 &&
                      JSON.stringify(entry.body.test_ids) ===
                        JSON.stringify([testID]),
                  )
                : requests.length === 0;
            record.no_metadata_request = requests.length === 0;
            if (!record.request_ids_verified)
              throw Error(
                "result tag read used a target/fact hint or wrong test ID",
              );
            if (record.runtime.length)
              throw Error("test tag state raised a browser runtime error");
            record.passed = true;
          } catch (error) {
            record.errors.push(
              error instanceof Error ? error.message : String(error),
            );
          } finally {
            await context.close();
          }
        }
  return {
    checks,
    failures: validateTestTagContextMatrix(checks, themes, viewports),
  };
}
