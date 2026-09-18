// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.
//
// The provider/operator console (S-T1): a VISUALLY-SEPARATE surface from any
// tenant app — its own shell, a loud PROVIDER-PLANE banner, no tenant
// indicator. It is deliberately absent from the tenant nav, and the API
// behind it 404s when unlicensed (hidden-unlicensed), which this console
// renders honestly as "not enabled".

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, NotEnabledError, useProviderData } from "./providerData";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  Select,
  StatusDot,
  Table,
  type Column,
} from "../../../web/src/components";
import { useI18n } from "../../../web/src/i18n/useI18n";
import styles from "./ProviderConsole.module.css";
import { TenantsCard } from "./TenantsCard";

interface Operator {
  id: string;
  email: string;
  name: string;
  role: string;
  status: string;
  enrolled: boolean;
}

interface FleetRow {
  tenant_id: string;
  tenant_slug: string;
  tenant_name: string;
  tenant_status: string;
  agents_total: number;
  agents_online: number;
  agents_stale: number;
  versions: Record<string, number>;
}

interface GrantRow {
  id: string;
  operator_email: string;
  tenant_id: string;
  reason: string;
  expires_at: string;
  use_count: number;
  state: string;
}

interface LicenseInfo {
  tier: string;
  pricing_model?: "flat" | "consumption";
  state: string;
  customer?: string;
  tenant_band?: number;
}

// api/NotEnabledError/APIError moved to providerData.ts so every card shares
// one fetch contract and the react-query read layer below it.

/**
 * demoRequested reports whether the URL asks for the isolated demo workspace.
 *
 * DPR-155: the provider console sits OUTSIDE the tenant shell, and therefore
 * outside DemoModeProvider — which is correct, because it is a separate
 * privilege domain. The consequence was not: `?demo=1` on this route entered
 * nothing, the console fetched live provider data, and the screens showed real
 * operator identities and real cross-tenant usage with no Demo badge and no hint
 * that demo mode was not in effect. A mode whose whole promise is "these are
 * samples" must not answer with production data on one surface and stay silent
 * about it.
 */
function demoRequested(search: string): boolean {
  return new URLSearchParams(search).get("demo") === "1";
}

/** What the route passes in: the current query string, nothing more. */
export interface ProviderConsoleProps {
  search?: string;
}

/** The console root: demo-refused / not-enabled / login / dashboard. */
export function ProviderConsole({ search = "" }: ProviderConsoleProps) {
  const { t } = useI18n();
  const demo = demoRequested(search);
  const [phase, setPhase] = useState<
    "probe" | "login" | "dashboard" | "disabled" | "demo"
  >(demo ? "demo" : "probe");
  const [operator, setOperator] = useState<Operator | null>(null);

  useEffect(() => {
    // Fail closed: in the demo workspace this console fetches nothing at all,
    // rather than fetching live data and labelling it a sample.
    if (demo) return;
    let cancelled = false;
    api<{ operator: Operator }>("GET", "/provider/v1/me")
      .then((r) => {
        if (!cancelled) {
          setOperator(r.operator);
          setPhase("dashboard");
        }
      })
      .catch((err) => {
        if (cancelled) return;
        setPhase(err instanceof NotEnabledError ? "disabled" : "login");
      });
    return () => {
      cancelled = true;
    };
  }, [demo]);

  return (
    <div className={styles.shell}>
      <header className={styles.domainBanner}>
        <h1 className={styles.domainName}>{t("provider.banner.title")}</h1>
        <Badge tone="warning">{t("provider.banner.domain")}</Badge>
        {operator ? (
          <Badge tone="info">
            {operator.email} ({operator.role})
          </Badge>
        ) : null}
      </header>
      <main className={styles.main}>
        {phase === "probe" ? (
          <LoadingState label={t("provider.loading")} />
        ) : null}
        {phase === "demo" ? (
          <>
            {/* keep the h1→h2→h3 ladder intact for the EmptyState's h3 */}
            <h2 className={styles.title}>{t("provider.demo.title")}</h2>
            <EmptyState
              icon="admin"
              title={t("provider.demo.notCoveredTitle")}
              description={t("provider.demo.description")}
            />
          </>
        ) : null}
        {phase === "disabled" ? (
          <>
            {/* keep the h1→h2→h3 ladder intact for the EmptyState's h3 */}
            <h2 className={styles.title}>{t("provider.disabled.title")}</h2>
            <EmptyState
              icon="admin"
              title={t("provider.disabled.licenseTitle")}
              description={t("provider.disabled.description")}
            />
          </>
        ) : null}
        {phase === "login" ? (
          <LoginScreen
            onLoggedIn={(op) => {
              setOperator(op);
              setPhase("dashboard");
            }}
          />
        ) : null}
        {phase === "dashboard" && operator ? (
          <Dashboard operator={operator} />
        ) : null}
      </main>
    </div>
  );
}

function LoginScreen({ onLoggedIn }: { onLoggedIn: (op: Operator) => void }) {
  const { t } = useI18n();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const r = await api<{ operator: Operator }>(
        "POST",
        "/provider/v1/auth/login",
        {
          email,
          password,
          totp,
        },
      );
      onLoggedIn(r.operator);
    } catch {
      setError(t("provider.login.failed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={styles.loginWrap}>
      <Card>
        <CardHeader
          title={t("provider.login.title")}
          description={t("provider.login.description")}
        />
        <CardBody>
          <form className={styles.form} onSubmit={submit}>
            <Field
              label={t("provider.login.email")}
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <Field
              label={t("provider.login.password")}
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <Field
              label={t("provider.login.authenticator")}
              inputMode="numeric"
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              required
            />
            {error ? (
              <p role="alert" className={styles.note}>
                {error}
              </p>
            ) : null}
            <Button type="submit" variant="primary" disabled={busy}>
              {busy
                ? t("provider.login.signingIn")
                : t("provider.login.signIn")}
            </Button>
          </form>
        </CardBody>
      </Card>
    </div>
  );
}

function Dashboard({ operator }: { operator: Operator }) {
  const { t } = useI18n();
  const [fleetExceptions, setFleetExceptions] = useState(0);
  const [pendingBreakGlass, setPendingBreakGlass] = useState(0);
  const [usageAvailable, setUsageAvailable] = useState(false);
  const licenseQuery = useProviderData<LicenseInfo>(
    ["license"],
    "/provider/v1/license",
  );
  const license = licenseQuery.data ?? null;
  const readOnly = license?.state === "read_only";

  return (
    <div className={styles.dashboard}>
      <div className={styles.dashboardIntro}>
        <h2 className={styles.title}>{t("provider.dashboard.title")}</h2>
        <p className={styles.note}>{t("provider.dashboard.subtitle")}</p>
        {license ? (
          <p
            className={styles.licenseState}
            role={readOnly ? "status" : undefined}
          >
            {t("provider.license.prefix")} <strong>{license.tier}</strong> ·{" "}
            {license.state}
            {license.pricing_model ? ` · ${license.pricing_model}` : null}
            {license.tenant_band ? (
              <>
                {" "}
                ·{" "}
                {t("provider.license.tenantBand", {
                  band: license.tenant_band,
                })}
              </>
            ) : null}
            {license.state === "grace"
              ? ` — ${t("provider.license.grace")}`
              : null}
            {readOnly ? ` — ${t("provider.license.readOnly")}` : null}
          </p>
        ) : null}
      </div>

      <ProviderTaskNavigation
        fleetExceptions={fleetExceptions}
        pendingBreakGlass={pendingBreakGlass}
        usageAvailable={usageAvailable}
        isAdmin={operator.role === "admin"}
      />

      <div className={styles.taskStack}>
        <div
          id="provider-exceptions"
          className={styles.taskSection}
          tabIndex={-1}
        >
          <FleetCard onExceptionsChange={setFleetExceptions} />
        </div>
        <div id="provider-tenants" className={styles.taskSection} tabIndex={-1}>
          <TenantsCard readOnly={readOnly} api={api} />
        </div>
        <div id="provider-usage" className={styles.taskSection} tabIndex={-1}>
          <UsageCard
            isAdmin={operator.role === "admin"}
            readOnly={readOnly}
            onAvailability={setUsageAvailable}
          />
        </div>
        <div
          id="provider-fairness"
          className={styles.taskSection}
          tabIndex={-1}
        >
          <FairnessCard
            isAdmin={operator.role === "admin"}
            readOnly={readOnly}
          />
        </div>
        <div
          id="provider-breakglass"
          className={styles.taskSection}
          tabIndex={-1}
        >
          <BreakGlassCard
            readOnly={readOnly}
            onPendingChange={setPendingBreakGlass}
          />
        </div>
        <div
          id="provider-governance"
          className={styles.taskSection}
          tabIndex={-1}
        >
          <GovernanceCard
            isAdmin={operator.role === "admin"}
            readOnly={readOnly}
          />
        </div>
        {operator.role === "admin" ? (
          <div
            id="provider-operators"
            className={styles.taskSection}
            tabIndex={-1}
          >
            <OperatorsCard readOnly={readOnly} />
          </div>
        ) : null}
        {operator.role === "admin" ? (
          <div
            id="provider-activity"
            className={styles.taskSection}
            tabIndex={-1}
          >
            <ActivityCard />
          </div>
        ) : null}
      </div>
    </div>
  );
}

function ProviderTaskNavigation({
  fleetExceptions,
  pendingBreakGlass,
  usageAvailable,
  isAdmin,
}: {
  fleetExceptions: number;
  pendingBreakGlass: number;
  usageAvailable: boolean;
  isAdmin: boolean;
}) {
  const { t } = useI18n();
  const tasks = [
    {
      rank: "01",
      href: "#provider-exceptions",
      key: "x",
      label: t("provider.tasks.exceptions", { count: fleetExceptions }),
    },
    {
      rank: "02",
      href: "#provider-tenants",
      key: "t",
      label: t("provider.tasks.tenants"),
    },
    ...(usageAvailable
      ? [
          {
            rank: "03",
            href: "#provider-usage",
            key: "u",
            label: t("provider.tasks.usage"),
          },
        ]
      : []),
    {
      rank: "04",
      href: "#provider-fairness",
      key: "f",
      label: t("provider.tasks.fairness"),
    },
    {
      rank: "05",
      href: "#provider-breakglass",
      key: "b",
      label: t("provider.tasks.breakglass", { count: pendingBreakGlass }),
    },
    {
      rank: "06",
      href: "#provider-governance",
      key: "g",
      label: t("provider.tasks.governance"),
    },
    ...(isAdmin
      ? [
          {
            rank: "07",
            href: "#provider-operators",
            key: "o",
            label: t("provider.tasks.operators"),
          },
          {
            rank: "08",
            href: "#provider-activity",
            key: "a",
            label: t("provider.tasks.activity"),
          },
        ]
      : []),
  ];

  return (
    <nav className={styles.taskNav} aria-label={t("provider.tasks.label")}>
      <ol className={styles.taskList}>
        {tasks.map((task) => (
          <li key={task.href}>
            <a
              className={styles.taskLink}
              href={task.href}
              accessKey={task.key}
              aria-keyshortcuts={`Alt+${task.key.toUpperCase()}`}
            >
              <span className={styles.taskRank}>{task.rank}</span>
              <span>{task.label}</span>
              <kbd className={styles.taskKey}>{task.key.toUpperCase()}</kbd>
            </a>
          </li>
        ))}
      </ol>
      {usageAvailable ? (
        <a
          className={styles.exportTask}
          href="/provider/v1/usage/export?format=csv&rollup=day"
          download
          accessKey="e"
          aria-keyshortcuts="Alt+E"
        >
          {t("provider.tasks.export")}
          <kbd className={styles.taskKey}>E</kbd>
        </a>
      ) : null}
    </nav>
  );
}

function FleetCard({
  onExceptionsChange,
}: {
  onExceptionsChange: (count: number) => void;
}) {
  const fleetQuery = useProviderData<{ items: FleetRow[] }>(
    ["fleet"],
    "/provider/v1/fleet",
  );
  const rows = useMemo(
    () =>
      fleetQuery.data
        ? [...(fleetQuery.data.items ?? [])].sort(
            (a, b) => fleetExceptionScore(b) - fleetExceptionScore(a),
          )
        : null,
    [fleetQuery.data],
  );
  const failed = fleetQuery.isError;
  const [selected, setSelected] = useState<FleetRow | null>(null);
  useEffect(() => {
    if (rows) {
      onExceptionsChange(
        rows.filter((row) => fleetExceptionScore(row) > 0).length,
      );
    }
  }, [rows, onExceptionsChange]);

  const columns: Column<FleetRow>[] = [
    {
      key: "priority",
      header: "Priority",
      render: (f) =>
        fleetExceptionScore(f) > 0 ? (
          <Badge tone="warning">P1 exception</Badge>
        ) : (
          <Badge tone="success">Healthy</Badge>
        ),
    },
    {
      key: "tenant",
      header: "Tenant",
      render: (f) => <code>{f.tenant_slug}</code>,
    },
    { key: "total", header: "Agents", render: (f) => f.agents_total },
    {
      key: "online",
      header: "Online",
      render: (f) =>
        f.agents_total === 0 ? (
          "—"
        ) : f.agents_online === f.agents_total ? (
          <StatusDot tone="success" label={String(f.agents_online)} />
        ) : (
          <StatusDot
            tone="danger"
            label={`${f.agents_online}/${f.agents_total}`}
          />
        ),
    },
    {
      key: "stale",
      header: "Stale (>5m)",
      render: (f) =>
        f.agents_stale > 0 ? (
          <Badge tone="warning">{f.agents_stale}</Badge>
        ) : (
          "0"
        ),
    },
    {
      key: "versions",
      header: "Versions",
      render: (f) =>
        Object.entries(f.versions ?? {})
          .map(([v, n]) => `${v}×${n}`)
          .join(", ") || "—",
    },
    {
      key: "action",
      header: "Safe next step",
      render: (f) =>
        fleetExceptionScore(f) > 0 ? (
          <Button size="sm" variant="secondary" onClick={() => setSelected(f)}>
            Triage {f.tenant_slug} exception
          </Button>
        ) : (
          "No action"
        ),
    },
  ];

  return (
    <Card>
      <CardHeader
        title="Fleet across tenants"
        description="Agent health per tenant — counts and versions only. Operators hold no implicit access to tenant telemetry; the storage role physically cannot read it."
      />
      <CardBody>
        {selected ? (
          <div className={styles.exceptionReceipt} role="status">
            <strong>
              {selected.tenant_name} needs provider-level attention.
            </strong>
            <span>
              {selected.agents_stale} stale; {selected.agents_online}/
              {selected.agents_total} agents online. This metadata-only triage
              grants no tenant telemetry access. Inspecting tenant data still
              requires explicit tenant consent, a time-bounded break-glass
              grant, and a separate provider audit receipt.
            </span>
            <a href="#provider-tenants">Continue to tenant lifecycle</a>
          </div>
        ) : null}
        {failed ? (
          <ErrorState description="Could not load the fleet view." />
        ) : rows === null ? (
          <LoadingState label="Aggregating fleet health…" />
        ) : (
          <Table
            caption="Fleet across tenants"
            columns={columns}
            rows={rows}
            rowKey={(f) => f.tenant_id}
            empty={
              <EmptyState
                icon="admin"
                title="No tenants yet"
                description="Fleet health appears once tenants run agents."
              />
            }
          />
        )}
      </CardBody>
    </Card>
  );
}

function fleetExceptionScore(row: FleetRow): number {
  return (
    row.agents_stale * 10 +
    Math.max(0, row.agents_total - row.agents_online) * 5 +
    (row.tenant_status === "active" ? 0 : 1)
  );
}

function BreakGlassCard({
  readOnly,
  onPendingChange,
}: {
  readOnly: boolean;
  onPendingChange: (count: number) => void;
}) {
  const [tenantID, setTenantID] = useState("");
  const [reason, setReason] = useState("");
  const [ttl, setTtl] = useState("60");
  const [error, setError] = useState("");

  const grantsQuery = useProviderData<{ items: GrantRow[] }>(
    ["breakglass"],
    "/provider/v1/breakglass",
  );
  const grants = useMemo(
    () => (grantsQuery.data ? (grantsQuery.data.items ?? []) : null),
    [grantsQuery.data],
  );
  const queryError = grantsQuery.error
    ? (grantsQuery.error as Error).message
    : "";
  const { refetch: refetchGrants } = grantsQuery;
  const load = useCallback(() => {
    void refetchGrants();
  }, [refetchGrants]);
  useEffect(() => {
    if (grants) {
      onPendingChange(
        grants.filter((grant) => grant.state === "pending").length,
      );
    }
  }, [grants, onPendingChange]);

  const request = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await api("POST", "/provider/v1/breakglass", {
        tenant_id: tenantID,
        reason,
        ttl_minutes: Number(ttl),
      });
      setReason("");
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const revoke = async (id: string) => {
    setError("");
    try {
      await api("POST", `/provider/v1/breakglass/${id}/revoke`);
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const toneFor = (state: string) =>
    state === "active" ? "danger" : state === "pending" ? "warning" : "neutral";

  const columns: Column<GrantRow>[] = [
    {
      key: "tenant",
      header: "Tenant",
      render: (g) => <code>{g.tenant_id}</code>,
    },
    { key: "operator", header: "Operator", render: (g) => g.operator_email },
    { key: "reason", header: "Reason", render: (g) => g.reason },
    {
      key: "state",
      header: "State",
      render: (g) => <Badge tone={toneFor(g.state)}>{g.state}</Badge>,
    },
    { key: "uses", header: "Audited uses", render: (g) => g.use_count },
    {
      key: "actions",
      header: "Actions",
      render: (g) =>
        g.state === "active" || g.state === "pending" ? (
          <Button
            size="sm"
            variant="secondary"
            disabled={readOnly}
            onClick={() => revoke(g.id)}
          >
            Revoke
          </Button>
        ) : null,
    },
  ];

  return (
    <Card>
      <CardHeader
        title="Break-glass"
        description="The ONLY path to tenant telemetry: explicit, time-bounded, and usable only after the tenant's admin consents. Every access is written to the provider audit stream."
      />
      <CardBody>
        {readOnly ? (
          <p className={styles.readOnlyNotice} role="status">
            Read-only license: requesting or revoking break-glass access is
            disabled. Existing grants and their separate audit receipts remain
            visible.
          </p>
        ) : null}
        <form className={styles.row} onSubmit={request}>
          <span className={styles.grow}>
            <Field
              label="Tenant ID"
              value={tenantID}
              onChange={(e) => setTenantID(e.target.value)}
              required
              disabled={readOnly}
            />
          </span>
          <span className={styles.grow}>
            <Field
              label="Reason (required — it is audited)"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              required
              disabled={readOnly}
            />
          </span>
          <Select
            label="TTL"
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            disabled={readOnly}
            options={[
              { value: "30", label: "30 minutes" },
              { value: "60", label: "1 hour" },
              { value: "240", label: "4 hours" },
            ]}
          />
          <Button type="submit" variant="primary" disabled={readOnly}>
            Request access
          </Button>
        </form>
        {error || queryError ? (
          <p role="alert" className={styles.note}>
            {error || queryError}
          </p>
        ) : null}
        {grants === null ? (
          <LoadingState label="Loading grants…" />
        ) : (
          <Table
            caption="Break-glass grants"
            columns={columns}
            rows={grants}
            rowKey={(g) => g.id}
            empty={
              <EmptyState
                icon="admin"
                title="No grants"
                description="No break-glass access has been requested."
              />
            }
          />
        )}
      </CardBody>
    </Card>
  );
}

interface UsageRow {
  tenant_id: string;
  tenant_slug: string;
  meter: string;
  kind: string;
  period_start: string;
  period_end: string;
  value: number;
  unit: string;
}

/** UsageCard (S-T3): per-tenant showback for the current month + the
 *  billing-export feed (CSV/JSONL) + per-tenant creation quotas (admin).
 *  Hidden honestly when the metering feature is not licensed (the API 404s). */
function UsageCard({
  isAdmin,
  readOnly,
  onAvailability,
}: {
  isAdmin: boolean;
  readOnly: boolean;
  onAvailability: (available: boolean) => void;
}) {
  const [quotaTenant, setQuotaTenant] = useState("");
  const [maxAgents, setMaxAgents] = useState("");
  const [maxTests, setMaxTests] = useState("");
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const usageQuery = useProviderData<{ items: UsageRow[] }>(
    ["usage", "day"],
    "/provider/v1/usage?rollup=day",
  );
  const rows = useMemo(
    () => (usageQuery.data ? (usageQuery.data.items ?? []) : null),
    [usageQuery.data],
  );
  const enabled = !(usageQuery.error instanceof NotEnabledError);
  const loadError =
    usageQuery.error && enabled ? (usageQuery.error as Error).message : "";
  useEffect(() => {
    if (rows) onAvailability(true);
    if (!enabled) onAvailability(false);
  }, [rows, enabled, onAvailability]);

  if (!enabled) return null; // metering not licensed: no lockware, no card

  // Aggregate the month per tenant × meter (rows are daily).
  const perTenant = new Map<string, Record<string, number>>();
  for (const r of rows ?? []) {
    const m = perTenant.get(r.tenant_slug) ?? {};
    m[r.meter] =
      r.kind === "gauge"
        ? Math.max(m[r.meter] ?? 0, r.value)
        : (m[r.meter] ?? 0) + r.value;
    perTenant.set(r.tenant_slug, m);
  }
  const tenants = [...perTenant.entries()].map(([slug, meters]) => ({
    slug,
    ...meters,
  })) as Array<{ slug: string } & Record<string, number>>;

  const meterCols = [
    "agents",
    "tests",
    "results_ingested",
    "ingest_bytes",
    "flow_events",
    "ai_calls",
  ];
  const columns: Column<(typeof tenants)[number]>[] = [
    { key: "slug", header: "Tenant", render: (t) => <code>{t.slug}</code> },
    ...meterCols.map((m) => ({
      key: m,
      header: m.replace(/_/g, " "),
      render: (t: (typeof tenants)[number]) =>
        ((t[m] as number | undefined) ?? 0).toLocaleString(),
    })),
  ];

  const saveQuota = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSaved(false);
    try {
      await api("PUT", `/provider/v1/tenants/${quotaTenant}/quotas`, {
        max_agents: maxAgents === "" ? null : Number(maxAgents),
        max_tests: maxTests === "" ? null : Number(maxTests),
      });
      setSaved(true);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <Card>
      <CardHeader
        title="Usage & showback"
        description="Month-to-date per-tenant usage, metered from the streams already flowing. Export feeds your PSA/billing system (CSV/JSONL, stable columns). Quotas gate resource creation only — telemetry is never dropped."
      />
      <CardBody>
        <p className={styles.actions}>
          <a
            className={styles.note}
            href="/provider/v1/usage/export?format=csv&rollup=day"
            download
          >
            Export CSV
          </a>
          <a
            className={styles.note}
            href="/provider/v1/usage/export?format=jsonl&rollup=day"
            download
          >
            Export JSONL
          </a>
        </p>
        {rows === null ? (
          <LoadingState label="Aggregating usage…" />
        ) : (
          <Table
            caption="Usage and showback"
            columns={columns}
            rows={tenants}
            rowKey={(t) => t.slug}
            empty={
              <EmptyState
                icon="admin"
                title="No usage yet"
                description="Meters fill as tenant telemetry flows."
              />
            }
          />
        )}
        {isAdmin ? (
          <form className={styles.row} onSubmit={saveQuota}>
            <span className={styles.grow}>
              <Field
                label="Tenant ID (quotas)"
                value={quotaTenant}
                onChange={(e) => setQuotaTenant(e.target.value)}
                required
                disabled={readOnly}
              />
            </span>
            <Field
              label="Max agents (blank = unlimited)"
              inputMode="numeric"
              value={maxAgents}
              onChange={(e) => setMaxAgents(e.target.value)}
              disabled={readOnly}
            />
            <Field
              label="Max tests (blank = unlimited)"
              inputMode="numeric"
              value={maxTests}
              onChange={(e) => setMaxTests(e.target.value)}
              disabled={readOnly}
            />
            <Button type="submit" variant="primary" disabled={readOnly}>
              Save quotas
            </Button>
          </form>
        ) : null}
        {saved ? <p className={styles.note}>Quotas saved.</p> : null}
        {error || loadError ? (
          <p role="alert" className={styles.note}>
            {error || loadError}
          </p>
        ) : null}
      </CardBody>
    </Card>
  );
}

/** FairnessCard (S-T7): cross-tenant fairness — live admitted/shed/rejected
 *  accounting from the core gate + the tuneable per-tenant policy (admin).
 *  Enforcement is core; this is the operator's view of it. */
interface GovernanceView {
  classifications: Record<string, string>;
  redact_from: string;
  redact_export: boolean;
  residency?: string;
  isolation_model: string;
  retention_days?: number | null;
  byok?: string;
}

/** GovernanceCard (S-EE3): per-tenant data governance — the COMPOSED view
 *  (classification + redaction + residency [S-T2] + retention [S-T5] + BYOK
 *  [S-T6]) and the redaction policy editor. Hidden when the governance feature
 *  is not licensed (the per-tenant GET 404s). */
function GovernanceCard({
  isAdmin,
  readOnly,
}: {
  isAdmin: boolean;
  readOnly: boolean;
}) {
  const [tenant, setTenant] = useState("");
  const [view, setView] = useState<GovernanceView | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [redactFrom, setRedactFrom] = useState("pii");
  const [redactExport, setRedactExport] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  if (!enabled) return null;

  const load = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSaved(false);
    try {
      const v = await api<GovernanceView>(
        "GET",
        `/provider/v1/tenants/${tenant}/governance`,
      );
      setView(v);
      setRedactFrom(v.redact_from || "pii");
      setRedactExport(!!v.redact_export);
    } catch (err) {
      if (err instanceof NotEnabledError) setEnabled(false);
      else setError((err as Error).message);
    }
  };

  const save = async () => {
    setError("");
    setSaved(false);
    try {
      await api("PUT", `/provider/v1/tenants/${tenant}/governance`, {
        redact_from: redactFrom,
        redact_export: redactExport,
      });
      setSaved(true);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const piiCats = view
    ? Object.entries(view.classifications).filter(
        ([, c]) => c === "pii" || c === "restricted",
      )
    : [];

  return (
    <Card>
      <CardHeader
        title="Data governance"
        description="Per-tenant data classification + redaction, composed with residency (S-T2), retention (S-T5) and BYOK (S-T6). IPs are PII by default; a redacted export masks PII-class values."
      />
      <CardBody>
        <form className={styles.row} onSubmit={load}>
          <span className={styles.grow}>
            <Field
              label="Tenant ID (governance)"
              value={tenant}
              onChange={(e) => setTenant(e.target.value)}
              required
            />
          </span>
          <Button type="submit" variant="secondary">
            Load
          </Button>
        </form>
        {view ? (
          <>
            <p className={styles.note}>
              Residency:{" "}
              <Badge tone={view.residency ? "accent" : "neutral"}>
                {view.residency || "unset"}
              </Badge>
              {" · "}
              Isolation: {view.isolation_model}
              {" · "}
              Retention:{" "}
              {view.retention_days != null
                ? `${view.retention_days}d`
                : "default"}
              {" · "}
              BYOK:{" "}
              <Badge
                tone={view.byok && view.byok !== "none" ? "success" : "neutral"}
              >
                {view.byok || "none"}
              </Badge>
              {" · "}
              Redact from {view.redact_from}
              {view.redact_export ? " · export redacted" : ""}
            </p>
            <p className={styles.note}>
              PII / restricted categories:{" "}
              {piiCats.length
                ? piiCats.map(([cat]) => (
                    <Badge key={cat} tone="warning">
                      {cat}
                    </Badge>
                  ))
                : "—"}
            </p>
            {isAdmin ? (
              <div className={styles.row}>
                <Select
                  label="Redact from class"
                  value={redactFrom}
                  onChange={(e) => setRedactFrom(e.target.value)}
                  options={[
                    { value: "public", label: "public" },
                    { value: "internal", label: "internal" },
                    { value: "confidential", label: "confidential" },
                    { value: "pii", label: "pii (default)" },
                    { value: "restricted", label: "restricted" },
                  ]}
                  disabled={readOnly}
                />
                <label className={styles.note}>
                  <input
                    type="checkbox"
                    checked={redactExport}
                    onChange={(e) => setRedactExport(e.target.checked)}
                    disabled={readOnly}
                  />{" "}
                  Force redacted export
                </label>
                <Button
                  type="button"
                  variant="primary"
                  onClick={save}
                  disabled={readOnly}
                >
                  Save governance
                </Button>
              </div>
            ) : null}
          </>
        ) : null}
        {saved ? <p className={styles.note}>Governance policy saved.</p> : null}
        {error ? (
          <p role="alert" className={styles.note}>
            {error}
          </p>
        ) : null}
      </CardBody>
    </Card>
  );
}

interface FairnessSnap {
  tenant_id: string;
  policy: Record<string, number>;
  ingest: Record<
    string,
    {
      admitted_units: number;
      shed_units: number;
      admitted_calls: number;
      shed_calls: number;
    }
  >;
  queries: {
    allowed: number;
    rejected_concurrency: number;
    rejected_budget: number;
    in_flight: number;
  };
}

function FairnessCard({
  isAdmin,
  readOnly,
}: {
  isAdmin: boolean;
  readOnly: boolean;
}) {
  const [tenant, setTenant] = useState("");
  const [resultsSec, setResultsSec] = useState("");
  const [flowsSec, setFlowsSec] = useState("");
  const [deviceSec, setDeviceSec] = useState("");
  const [otlpSec, setOtlpSec] = useState("");
  const [queriesMin, setQueriesMin] = useState("");
  const [queryConc, setQueryConc] = useState("");
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const fairnessQuery = useProviderData<{ items: FairnessSnap[] }>(
    ["fairness"],
    "/provider/v1/fairness",
  );
  const snaps = useMemo(
    () => (fairnessQuery.data ? (fairnessQuery.data.items ?? []) : null),
    [fairnessQuery.data],
  );
  const enabled = !(fairnessQuery.error instanceof NotEnabledError);
  const loadError =
    fairnessQuery.error && enabled
      ? (fairnessQuery.error as Error).message
      : "";

  if (!enabled) return null;

  const shed = (t: FairnessSnap) =>
    Object.values(t.ingest ?? {}).reduce((a, c) => a + (c.shed_units ?? 0), 0);
  const columns: Column<FairnessSnap>[] = [
    {
      key: "tenant",
      header: "Tenant",
      render: (t) => <code>{t.tenant_id}</code>,
    },
    {
      key: "shed",
      header: "Shed units (MTD)",
      render: (t) =>
        shed(t) > 0 ? (
          <Badge tone="warning">{shed(t).toLocaleString()}</Badge>
        ) : (
          "0"
        ),
    },
    {
      key: "q",
      header: "Query rejections",
      render: (t) => {
        const n =
          (t.queries?.rejected_concurrency ?? 0) +
          (t.queries?.rejected_budget ?? 0);
        return n > 0 ? <Badge tone="warning">{n.toLocaleString()}</Badge> : "0";
      },
    },
    {
      key: "bounds",
      header: "Bounds",
      render: (t) => {
        const p = t.policy ?? {};
        const parts = [];
        if (p.results_per_sec) parts.push(`${p.results_per_sec}/s results`);
        if (p.flow_events_per_sec)
          parts.push(`${p.flow_events_per_sec}/s flows`);
        if (p.device_metrics_per_sec)
          parts.push(`${p.device_metrics_per_sec}/s device`);
        if (p.otlp_series_per_sec)
          parts.push(`${p.otlp_series_per_sec}/s OTLP`);
        if (p.queries_per_min) parts.push(`${p.queries_per_min}/min queries`);
        if (p.query_concurrency)
          parts.push(`${p.query_concurrency} concurrent`);
        return parts.length ? parts.join(" · ") : "unbounded";
      },
    },
  ];

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSaved(false);
    try {
      await api("PUT", `/provider/v1/tenants/${tenant}/fairness`, {
        results_per_sec: resultsSec === "" ? 0 : Number(resultsSec),
        flow_events_per_sec: flowsSec === "" ? 0 : Number(flowsSec),
        device_metrics_per_sec: deviceSec === "" ? 0 : Number(deviceSec),
        otlp_series_per_sec: otlpSec === "" ? 0 : Number(otlpSec),
        queries_per_min: queriesMin === "" ? 0 : Number(queriesMin),
        query_concurrency: queryConc === "" ? 0 : Number(queryConc),
      });
      setSaved(true);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <Card>
      <CardHeader
        title="Fairness"
        description="Noisy-neighbor protection: per-tenant ingest bounds and query-cost guards (0/blank = unlimited). Shed work is counted and attributable — never silent. Enforcement is core; tenants see their own view at /v1/fairness."
      />
      <CardBody>
        {snaps === null ? (
          <LoadingState label="Loading fairness accounting…" />
        ) : (
          <Table
            caption="Per-tenant fairness accounting"
            columns={columns}
            rows={snaps}
            rowKey={(t) => t.tenant_id}
            empty={
              <EmptyState
                icon="admin"
                title="No accounting yet"
                description="Counters appear as tenant traffic flows."
              />
            }
          />
        )}
        {isAdmin ? (
          <form className={styles.row} onSubmit={save}>
            <span className={styles.grow}>
              <Field
                label="Tenant ID (fairness)"
                value={tenant}
                onChange={(e) => setTenant(e.target.value)}
                required
                disabled={readOnly}
              />
            </span>
            <Field
              label="Results/sec"
              inputMode="numeric"
              value={resultsSec}
              onChange={(e) => setResultsSec(e.target.value)}
              disabled={readOnly}
            />
            <Field
              label="Flow events/sec"
              inputMode="numeric"
              value={flowsSec}
              onChange={(e) => setFlowsSec(e.target.value)}
              disabled={readOnly}
            />
            <Field
              label="Device metrics/sec"
              inputMode="numeric"
              value={deviceSec}
              onChange={(e) => setDeviceSec(e.target.value)}
              disabled={readOnly}
            />
            <Field
              label="OTLP series/sec"
              inputMode="numeric"
              value={otlpSec}
              onChange={(e) => setOtlpSec(e.target.value)}
              disabled={readOnly}
            />
            <Field
              label="Queries/min"
              inputMode="numeric"
              value={queriesMin}
              onChange={(e) => setQueriesMin(e.target.value)}
              disabled={readOnly}
            />
            <Field
              label="Query concurrency"
              inputMode="numeric"
              value={queryConc}
              onChange={(e) => setQueryConc(e.target.value)}
              disabled={readOnly}
            />
            <Button type="submit" variant="primary" disabled={readOnly}>
              Save policy
            </Button>
          </form>
        ) : null}
        {saved ? (
          <p className={styles.note}>
            Fairness policy saved — enforced on the next admission.
          </p>
        ) : null}
        {error || loadError ? (
          <p role="alert" className={styles.note}>
            {error || loadError}
          </p>
        ) : null}
      </CardBody>
    </Card>
  );
}

function OperatorsCard({ readOnly }: { readOnly: boolean }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("operator");
  const [enrollToken, setEnrollToken] = useState("");
  const [error, setError] = useState("");

  const operatorsQuery = useProviderData<{ items: Operator[] }>(
    ["operators"],
    "/provider/v1/operators",
  );
  const operators = useMemo(
    () => (operatorsQuery.data ? (operatorsQuery.data.items ?? []) : null),
    [operatorsQuery.data],
  );
  const loadError = operatorsQuery.error
    ? (operatorsQuery.error as Error).message
    : "";
  const { refetch: refetchOperators } = operatorsQuery;
  const load = useCallback(() => {
    void refetchOperators();
  }, [refetchOperators]);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const r = await api<{ enroll_token: string }>(
        "POST",
        "/provider/v1/operators",
        { email, name, role },
      );
      setEnrollToken(r.enroll_token);
      setEmail("");
      setName("");
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: Column<Operator>[] = [
    { key: "email", header: "Email", render: (o) => o.email },
    {
      key: "role",
      header: "Role",
      render: (o) => (
        <Badge tone={o.role === "admin" ? "warning" : "neutral"}>
          {o.role}
        </Badge>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (o) =>
        !o.enrolled ? (
          <StatusDot tone="neutral" label="Awaiting enrollment" />
        ) : o.status === "active" ? (
          <StatusDot tone="success" label="Active" />
        ) : (
          <StatusDot tone="danger" label={o.status} />
        ),
    },
  ];

  return (
    <Card>
      <CardHeader
        title="Operators"
        description="Separation of duties: admins manage operators; operators run tenant lifecycle and break-glass. Enrollment binds an authenticator — MFA is not optional."
      />
      <CardBody>
        <form className={styles.row} onSubmit={create}>
          <span className={styles.grow}>
            <Field
              label="Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={readOnly}
            />
          </span>
          <span className={styles.grow}>
            <Field
              label="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              disabled={readOnly}
            />
          </span>
          <Select
            label="Role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            disabled={readOnly}
            options={[
              { value: "operator", label: "operator" },
              { value: "admin", label: "admin" },
            ]}
          />
          <Button type="submit" variant="primary" disabled={readOnly}>
            Create
          </Button>
        </form>
        {enrollToken ? (
          <p className={styles.secret}>
            One-time enrollment token (share it over a secure channel; it is
            never shown again): <strong>{enrollToken}</strong>
          </p>
        ) : null}
        {error || loadError ? (
          <p role="alert" className={styles.note}>
            {error || loadError}
          </p>
        ) : null}
        {operators === null ? (
          <LoadingState label="Loading operators…" />
        ) : (
          <Table
            caption="Provider operators"
            columns={columns}
            rows={operators}
            rowKey={(o) => o.id}
            empty={
              <EmptyState
                icon="admin"
                title="No operators"
                description="Bootstrap the first admin with the deployment token."
              />
            }
          />
        )}
      </CardBody>
    </Card>
  );
}

interface ActivityRow {
  seq: number;
  actor: string;
  action: string;
  target: string;
  data: Record<string, unknown>;
  created_at: string;
}

/** ActivityCard (DPR-037): the plane's own audit stream, newest-first — every
 *  bootstrap, login, lockout, operator change, tenant lifecycle step,
 *  break-glass request/consent/access/revoke and provisioning outcome. It is
 *  the same tamper-evident stream the WORM export and SIEM feed carry; reading
 *  it never appends to it. Admin-only (a governance view). */
function ActivityCard() {
  const [actionFilter, setActionFilter] = useState("");
  const [applied, setApplied] = useState("");
  const query = useProviderData<{ items: ActivityRow[]; next: number }>(
    ["audit", applied],
    `/provider/v1/audit?order=desc&limit=50${applied ? `&action=${encodeURIComponent(applied)}` : ""}`,
  );
  const rows = query.data?.items ?? [];
  const queryError = query.error ? (query.error as Error).message : "";
  const columns: Column<ActivityRow>[] = [
    { key: "when", header: "When", render: (r) => <time dateTime={r.created_at}>{r.created_at}</time> },
    { key: "actor", header: "Actor", render: (r) => <code>{r.actor}</code> },
    { key: "action", header: "Action", render: (r) => <code>{r.action}</code> },
    { key: "target", header: "Target", render: (r) => <code>{r.target || "—"}</code> },
    {
      key: "detail",
      header: "Detail",
      render: (r) => {
        const keys = Object.keys(r.data ?? {});
        if (keys.length === 0) return "—";
        return keys
          .slice(0, 4)
          .map((k) => `${k}=${String(r.data[k])}`)
          .join(" · ");
      },
    },
  ];
  return (
    <Card>
      <CardHeader
        title="Activity"
        description="What this provider plane recorded about its own operators: bootstrap, logins and lockouts, operator changes, tenant lifecycle, break-glass request → consent → audited access → revoke, provisioning outcomes. Newest first; the same tamper-evident rows the WORM export and SIEM feed carry."
      />
      <CardBody>
        <form
          className={styles.row}
          aria-label="Filter activity"
          onSubmit={(e) => {
            e.preventDefault();
            setApplied(actionFilter.trim());
          }}
        >
          <Field
            label="Action contains"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            placeholder="breakglass, tenant, operator…"
          />
          <Button type="submit">Filter</Button>
        </form>
        {queryError ? (
          <p role="alert" className={styles.note}>
            {queryError}
          </p>
        ) : null}
        {query.isPending ? (
          <LoadingState label="Loading activity…" />
        ) : (
          <Table
            caption="Provider activity"
            columns={columns}
            rows={rows}
            rowKey={(r) => String(r.seq)}
            empty={
              <EmptyState
                icon="admin"
                title="No activity yet"
                description="Nothing has been recorded on the provider audit stream that matches."
              />
            }
          />
        )}
      </CardBody>
    </Card>
  );
}
