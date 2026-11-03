// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Synthetic API/current production-build UI proof, not storage/auth/sender proof.
import { join } from "node:path";

export const ALERT_TAG_CASES = [
  "ready",
  "read-only",
  "clear-only",
  "missing-grant",
  "foreign",
];
const ruleID = "11111111-1111-4111-8111-111111111111";
const revision = "9007199254740993";
const stagesFor = (mode) => [
  "receipt",
  ...(mode === "ready"
    ? ["ready", "saved", "refused"]
    : mode === "clear-only"
      ? ["confirm", "cleared"]
      : [mode === "read-only" ? "read-only" : "no-disclosure"]),
];

export function validateAlertTagMatrix(checks, themes, viewports) {
  const failures = [];
  if (
    !Array.isArray(checks) ||
    checks.length !== themes.length * viewports.length * ALERT_TAG_CASES.length
  )
    failures.push("alert tag matrix incomplete");
  for (const theme of themes)
    for (const viewport of viewports)
      for (const mode of ALERT_TAG_CASES) {
        const rows = (checks ?? []).filter(
          (row) =>
            row.theme === theme &&
            row.viewport === viewport.name &&
            row.mode === mode,
        );
        if (rows.length !== 1) {
          failures.push(
            `alert tag ${theme}/${viewport.name}/${mode}: missing or duplicate cell`,
          );
          continue;
        }
        const row = rows[0];
        if (
          row.passed !== true ||
          row.theme_verified !== true ||
          row.requests_verified !== true ||
          row.execution_clock_verified !== true ||
          row.receipt_requests_verified !== true ||
          !Array.isArray(row.runtime) ||
          row.runtime.length ||
          !Array.isArray(row.errors) ||
          row.errors.length ||
          !Array.isArray(row.stages) ||
          row.stages.length !== stagesFor(mode).length ||
          stagesFor(mode).some(
            (name) =>
              row.stages.filter(
                (stage) =>
                  stage.name === name &&
                  stage.passed === true &&
                  ["axe", "targets", "overflow", "clipping"].every(
                    (key) =>
                      Array.isArray(stage[key]) && stage[key].length === 0,
                  ),
              ).length !== 1,
          )
        )
          failures.push(
            `alert tag ${theme}/${viewport.name}/${mode}: browser/transport stage failed`,
          );
        const required =
          mode === "ready"
            ? ["full_value_exact", "saved_input_exact", "refusal_cleared"]
            : mode === "read-only"
              ? ["full_value_exact", "mutations_disabled"]
              : mode === "clear-only"
                ? ["confirmation_observed", "clear_without_read"]
                : ["no_disclosure"];
        if (required.some((key) => row[key] !== true))
          failures.push(
            `alert tag ${theme}/${viewport.name}/${mode}: required observation missing`,
          );
      }
  return failures;
}

function fixtureSource(mode) {
  return `(() => {
    const mode = ${JSON.stringify(mode)}, id = ${JSON.stringify(ruleID)}, revision = ${JSON.stringify(revision)};
    const tagID = '22222222-2222-4222-8222-222222222222';
    const base = window.fetch.bind(window), wide = '🌐'.repeat(24000);
    const state = window.__probectlAlertTagProof = { requests: [], receipt_requests: [], refuse: false, filter: { match: 'all', groups: [
      { conditions: [{ field: 'tag.customer', op: 'eq', values: [wide] }] },
      { mode: 'exclude', conditions: [{ field: 'tag.customer', op: 'regex', values: ['excluded$'] }] }
    ] } };
    const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'x-probectl-fixture': '1' } });
    window.fetch = async (input, init) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, location.href);
      const path = url.pathname, method = init?.method ?? 'GET';
      if (path === '/v1/me') {
        const me = await (await base(input, init)).json(); state.tenant = me.tenant_id;
        const reads = ['alert.read','tags.read','test.read','metrics.read'];
        me.permissions = mode === 'missing-grant' ? ['alert.read'] : mode === 'clear-only' ? ['alert.read','alert.write'] : mode === 'read-only' ? reads : [...reads, 'alert.write'];
        return json(me);
      }
      if (path === '/v1/alerts') return json({ alerting_active: true, items: [{ id, tenant_id: mode === 'foreign' ? 'foreign-tenant' : state.tenant, name: 'Tag criterion rule', enabled: false, metric: 'probectl_probe_duration_seconds', type: 'threshold', comparison: 'gt', threshold: 1, severity: 'warning', has_tag_filter: true, channels: [], created_at: '2026-11-03T00:00:00Z', updated_at: '2026-11-03T00:00:00Z' }] });
      if (path === '/v1/alerts/active') return json({ items: mode === 'foreign' ? [] : [{ fingerprint: 'active-fixture', evaluation_fingerprint: 'eval:fixture', rule_id: id, rule_name: 'Tag criterion rule', severity: 'warning', metric: 'probectl_probe_duration_seconds', value: 2, reason: 'fixture threshold', labels: { test_id: 'owned-fixture' }, since: '2026-11-03T00:00:00Z', last_seen_at: '2026-11-03T01:00:00Z' }], evaluator_running: true });
      if (path === '/v1/alerts/maintenance') return json({ items: [] });
      if (path === '/v1/alerts/' + id + '/evaluations') {
        state.receipt_requests.push({method, path, tenant: new Headers(init?.headers).get('X-Probectl-Tenant'), query: url.search});
        const allowed = mode === 'ready' || mode === 'read-only';
        return json({contract_version: 'probectl.alert-evaluations/v1', tag_selection_access: allowed ? 'available' : 'withheld', items: [{ contract_version: 'probectl.alert-evaluation/v1', fingerprint: 'eval:fixture', rule_id: id, rule_revision: '2026-11-03T00:00:00Z', state: 'firing', observed_at: '2026-11-03T01:00:00Z', observed_value: 2, expectation: {kind: 'threshold',comparison: 'gt',threshold: 1}, breach_count: 1, required_breaches: 1, reason: 'fixture threshold', ...(mode === 'read-only' ? {} : {tag_selection: {target_kind: 'test',tag_revision: '9007199254740995',as_of: '2026-11-03T00:59:00Z'}}) }], truncated: false, limit: 64, freshness: 'current', evaluator_running: true, persistence_running: true, retention: {max_per_series:64,max_per_rule:256,expires_days:7}});
      }
      if (path === '/v1/alerts/active/active-fixture/workflow') return json({operations:[],deliveries:[],evaluator_running:true,persistence_running:true,connector_running:false});
      if (path === '/v1/incidents') return json({items:[]});
      if (path === '/v1/oncall/status') return json({configured:false,outbound_configured:false,inbound_configured:false,outbound_connector_count:0,inbound_webhook_count:0,tls_required:true,secrets_redacted:true,providers:[],outbound:[],inbound:[]});
      if (path === '/v1/alerts/rules/' + id + '/tag-filter') {
        const body = init?.body ? JSON.parse(String(init.body)) : null;
        state.requests.push({ method, body, tenant: new Headers(init?.headers).get('X-Probectl-Tenant'), query: url.search });
        if (state.refuse) return json({ error: { code: 'forbidden', message: 'current criteria refused' } }, 403);
        if (method === 'DELETE') return new Response(null, { status: 204 });
        if (method === 'PUT') state.filter = body.filter;
        return json({ rule_id: id, has_tag_filter: true, tag_filter: { version: 1, target_kind: 'test', filter: state.filter, tag_ids: { 'tag.customer': tagID }, owner_user_id: '33333333-3333-4333-8333-333333333333', tag_revision: revision, as_of: '2026-11-03T00:00:00Z' }, editor: { tag_revision: revision, as_of: '2026-11-03T01:00:00Z', fields: [{ name: 'tag.customer', tag_id: tagID, type: 'text', operators: ['eq','ne','in','not_in','contains','not_contains','regex','not_regex'] }], limits: { max_group_entries: 250, max_expanded_conditions: 1000, max_filter_depth: 5, max_regex_bytes: 1024, max_values_per_predicate: 1000, max_value_bytes: 65536, grammar_bytes: 2097152 } } });
      }
      return base(input, init);
    };
  })();`;
}

export function alertTagSelfTest() {
  const themes = ["light", "dark"],
    viewports = [{ name: "desktop" }, { name: "mobile" }];
  const records = themes.flatMap((theme) =>
    viewports.flatMap((viewport) =>
      ALERT_TAG_CASES.map((mode) => ({
        theme,
        viewport: viewport.name,
        mode,
        passed: true,
        theme_verified: true,
        requests_verified: true,
        execution_clock_verified: true,
        receipt_requests_verified: true,
        runtime: [],
        errors: [],
        full_value_exact: true,
        saved_input_exact: true,
        refusal_cleared: true,
        mutations_disabled: true,
        confirmation_observed: true,
        clear_without_read: true,
        no_disclosure: true,
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
  );
  if (validateAlertTagMatrix(records, themes, viewports).length)
    throw Error("complete alert tag matrix refused");
  for (const corrupt of [
    (r) => r.pop(),
    (r) => r.push(r[0]),
    (r) => {
      r[0].stages.pop();
    },
    (r) => {
      r[0].full_value_exact = false;
    },
    (r) => {
      r[0].execution_clock_verified = false;
    },
    (r) => {
      r[0].receipt_requests_verified = false;
    },
    (r) => {
      r[0].saved_input_exact = false;
    },
    (r) => {
      r[0].refusal_cleared = false;
    },
    (r) => {
      r[1].mutations_disabled = false;
    },
    (r) => {
      r[2].clear_without_read = false;
    },
    (r) => {
      r[2].confirmation_observed = false;
    },
    (r) => {
      r[3].no_disclosure = false;
    },
    (r) => {
      r[0].stages[0].axe.push({ id: "planted" });
    },
    (r) => {
      r[0].requests_verified = false;
    },
    (r) => {
      r[0].runtime.push("planted");
    },
  ]) {
    const invalid = structuredClone(records);
    corrupt(invalid);
    if (!validateAlertTagMatrix(invalid, themes, viewports).length)
      throw Error("incomplete alert tag observation accepted");
  }
}

export async function runAlertTagChecks({
  browser,
  baseURL,
  axeSource,
  receiptDir,
  themes,
  viewports,
  helpers,
}) {
  const checks = [];
  for (const viewport of viewports)
    for (const theme of themes)
      for (const mode of ALERT_TAG_CASES) {
        const record = {
          viewport: viewport.name,
          theme,
          mode,
          passed: false,
          stages: [],
          runtime: [],
          errors: [],
          source:
            "simulation: current production build and synthetic API; no auth/storage/sender claim",
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
              `alert-tags-${viewport.name}-${theme}-${mode}-${name}.png`,
            ),
            fullPage: true,
          });
          if (
            [stage.axe, stage.targets, stage.overflow, stage.clipping].some(
              (rows) => rows.length,
            )
          )
            throw Error(`alert tag ${name} accessibility/geometry failed`);
          stage.passed = true;
        };
        try {
          await context.addInitScript(
            helpers.fetchStubSource(theme) + fixtureSource(mode),
          );
          await page.goto(`${baseURL}/ui/alerts`, { waitUntil: "networkidle" });
          await page.addStyleTag({
            content:
              "*, *::before, *::after { transition-duration: 0s !important; animation-duration: 0s !important; }",
          });
          record.theme_verified = await page.evaluate(
            (expected) =>
              document.documentElement.getAttribute("data-theme") ===
                expected &&
              document.documentElement.classList.contains("dark") ===
                (expected === "dark"),
            theme,
          );
          if (!record.theme_verified)
            throw Error("alert tag theme did not apply");
          await page
            .getByRole("table", { name: "Alert rules", exact: true })
            .waitFor();
          if (mode === "foreign") {
            record.execution_clock_verified =
              (await page
                .getByRole("button", { name: "Details", exact: true })
                .count()) === 0;
            if (!record.execution_clock_verified)
              throw Error("foreign rule exposed receipt detail");
            await inspect("receipt");
          } else {
            await page
              .getByRole("button", { name: "Details", exact: true })
              .click();
            const detail = page.getByRole("dialog", {
              name: "Tag criterion rule",
              exact: true,
            });
            const timeline = detail.getByRole("list", {
              name: "Deterministic evaluation receipts",
              exact: true,
            });
            await timeline.waitFor();
            if (mode === "ready") {
              record.execution_clock_verified =
                (await timeline
                  .getByText("9007199254740995", { exact: true })
                  .count()) === 1 &&
                (await timeline
                  .getByText("Metadata revision used", { exact: true })
                  .count()) === 1 &&
                (await timeline
                  .getByText("Selection as of", { exact: true })
                  .count()) === 1 &&
                (await timeline
                  .getByText(revision, { exact: true })
                  .count()) === 0;
            } else {
              record.execution_clock_verified =
                (await timeline
                  .getByText("Metadata revision used", { exact: true })
                  .count()) === 0 &&
                (await timeline
                  .getByText("9007199254740995", { exact: true })
                  .count()) === 0;
              if (mode !== "read-only")
                record.execution_clock_verified &&=
                  (await detail
                    .getByText(/Metadata selection evidence is withheld/)
                    .count()) === 1;
            }
            if (!record.execution_clock_verified)
              throw Error(
                "receipt used a binding revision, exposed withheld evidence, or fabricated legacy provenance",
              );
            await inspect("receipt");
            await detail.press("Escape");
            await detail.waitFor({ state: "hidden" });
          }
          const opener = page.getByRole("button", {
            name: "Test tag criteria for Tag criterion rule",
            exact: true,
          });
          if (mode === "missing-grant") {
            record.no_disclosure = (await opener.count()) === 0;
            if (!record.no_disclosure)
              throw Error("missing grant exposed alert metadata control");
            await inspect("no-disclosure");
          } else {
            await opener.click();
            const dialog = page.getByRole("dialog", {
              name: "Current test tags: Tag criterion rule",
              exact: true,
            });
            if (mode === "foreign") {
              record.no_disclosure = (await dialog.count()) === 0;
              if (!record.no_disclosure)
                throw Error("foreign rule acquired metadata editor");
              await inspect("no-disclosure");
            } else if (mode === "clear-only") {
              await dialog.waitFor();
              if (
                await dialog
                  .getByRole("button", {
                    name: "Load current criteria",
                    exact: true,
                  })
                  .count()
              )
                throw Error("clear-only user acquired metadata read");
              await dialog
                .getByRole("button", { name: "Clear tag filter", exact: true })
                .click();
              const confirm = page.getByRole("dialog", {
                name: "Clear tag filter",
                exact: true,
              });
              await confirm.waitFor();
              record.confirmation_observed = await page.evaluate(
                () => window.__probectlAlertTagProof.requests.length === 0,
              );
              await inspect("confirm");
              await confirm
                .getByRole("button", { name: "Clear criteria", exact: true })
                .click();
              await dialog
                .getByText(
                  "Tag filter cleared. The rule uses its ordinary metric selection.",
                  { exact: true },
                )
                .waitFor();
              await inspect("cleared");
            } else {
              await dialog
                .getByRole("button", {
                  name: "Load current criteria",
                  exact: true,
                })
                .click();
              const value = dialog.getByLabel("Condition 1.1.1 value 1", {
                exact: true,
              });
              await value.waitFor();
              record.full_value_exact =
                (await value.inputValue()) === "🌐".repeat(24000) &&
                (await dialog.getByText(revision, { exact: true }).count()) ===
                  2;
              if (
                !record.full_value_exact ||
                (await dialog
                  .getByRole("button", { name: /Add saved filter/ })
                  .count())
              )
                throw Error(
                  "alert criteria/clock changed or saved-flow control exposed",
                );
              if (mode === "read-only") {
                record.mutations_disabled =
                  (await dialog
                    .getByRole("button", {
                      name: "Save current criteria",
                      exact: true,
                    })
                    .isDisabled()) &&
                  (await dialog
                    .getByRole("button", {
                      name: "Clear tag filter",
                      exact: true,
                    })
                    .isDisabled()) &&
                  (await value.isDisabled());
                if (!record.mutations_disabled)
                  throw Error("read-only metadata controls mutate");
                await inspect("read-only");
              } else {
                await inspect("ready");
                await dialog
                  .getByLabel("Condition 1.2.1 value 1", { exact: true })
                  .fill("changed$");
                await dialog
                  .getByRole("button", {
                    name: "Save current criteria",
                    exact: true,
                  })
                  .click();
                await value.waitFor();
                record.saved_input_exact = await page.evaluate(() => {
                  const put = window.__probectlAlertTagProof.requests.filter(
                    (r) => r.method === "PUT",
                  );
                  return (
                    put.length === 1 &&
                    JSON.stringify(Object.keys(put[0].body).sort()) ===
                      JSON.stringify(["filter", "target_kind"]) &&
                    put[0].body.target_kind === "test" &&
                    put[0].body.filter.groups[0].conditions[0].values[0] ===
                      "🌐".repeat(24000) &&
                    put[0].body.filter.groups[1].mode === "exclude" &&
                    put[0].body.filter.groups[1].conditions[0].values[0] ===
                      "changed$"
                  );
                });
                if (
                  !record.saved_input_exact ||
                  (await value.inputValue()) !== "🌐".repeat(24000)
                )
                  throw Error("saved alert criteria lost full nested input");
                await inspect("saved");
                await page.evaluate(() => {
                  window.__probectlAlertTagProof.refuse = true;
                });
                await dialog
                  .getByRole("button", {
                    name: "Refresh current criteria",
                    exact: true,
                  })
                  .click();
                await dialog
                  .getByText(/Previous criteria have been cleared/)
                  .waitFor();
                record.refusal_cleared =
                  (await value.count()) === 0 &&
                  (await dialog
                    .getByText(revision, { exact: true })
                    .count()) === 0 &&
                  (await dialog
                    .getByRole("button", {
                      name: "Save current criteria",
                      exact: true,
                    })
                    .count()) === 0;
                if (!record.refusal_cleared)
                  throw Error("refused alert refresh retained old criteria");
                await inspect("refused");
              }
            }
          }
          const observed = await page.evaluate(() => ({
            requests: window.__probectlAlertTagProof.requests,
            tenant: window.__probectlAlertTagProof.tenant,
            receipt_requests: window.__probectlAlertTagProof.receipt_requests,
          }));
          const methods = observed.requests.map((r) => r.method);
          const expected =
            mode === "ready"
              ? ["GET", "PUT", "GET", "GET"]
              : mode === "read-only"
                ? ["GET"]
                : mode === "clear-only"
                  ? ["DELETE"]
                  : [];
          record.receipt_requests_verified =
            observed.receipt_requests.length === (mode === "foreign" ? 0 : 1) &&
            observed.receipt_requests.every(
              (r) =>
                r.method === "GET" &&
                r.tenant === null &&
                r.path === "/v1/alerts/" + ruleID + "/evaluations" &&
                r.query === "?fingerprint=eval%3Afixture",
            );
          if (!record.receipt_requests_verified)
            throw Error(
              "receipt query changed owned rule, scope or fingerprint",
            );
          record.requests_verified =
            JSON.stringify(methods) === JSON.stringify(expected) &&
            observed.requests.every(
              (r) =>
                r.tenant === observed.tenant &&
                r.query === "" &&
                (r.method === "PUT" || r.body === null),
            );
          record.clear_without_read =
            mode === "clear-only" && record.requests_verified;
          if (!record.requests_verified || record.runtime.length)
            throw Error("alert metadata transport scope or runtime failed");
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
    failures: validateAlertTagMatrix(checks, themes, viewports),
  };
}
