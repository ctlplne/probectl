// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

import { useEffect, useRef, useState } from "react";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Select,
  Table,
} from "../../../web/src/components";
import { api, NotEnabledError, useProviderData } from "./providerData";
import styles from "./ProviderConsole.module.css";

type Tenant = { id: string; name: string; slug: string; status: string };
type Progress = {
  tenant_id: string;
  eligible: number;
  queued: number;
  pending: number;
  delivered: number;
  inactive: number;
  replay: boolean;
};
type ProspectRevisions = {
  engagement_revision: number;
  access_revision: number;
};
type ProspectProgress = ProspectRevisions & {
  tenant_id: string;
  phase: "collecting" | "due" | "filed";
  ends_at: string;
  request_pending: boolean;
};
type ReportBatch = {
  id: string;
  tenants: string[];
  prospectRevisions: Map<string, ProspectRevisions>;
};
type Result = {
  id: string;
  progress?: Progress | ProspectProgress;
  error?: string;
};
type ReportKind = "monthly" | "compliance" | "prospect";
const maxProspectSelection = 100;

const reportKinds = {
  prospect: {
    title: "Prospect assessments",
    queue: "Request due assessments",
    label: "Prospect assessment",
  },
  monthly: {
    title: "Monthly client reports",
    queue: "Queue monthly reports",
    label: "Monthly report",
  },
  compliance: {
    title: "Compliance evidence",
    queue: "Queue compliance reports",
    label: "Compliance report",
  },
};

export function MonthlyReportsCard({ readOnly }: { readOnly: boolean }) {
  const tenants = useProviderData<{ items: Tenant[] }>(
    ["tenants"],
    "/provider/v1/tenants",
  );
  const active = (tenants.data?.items ?? []).filter(
    (item) => item.status === "active",
  );
  const [kind, setKind] = useState<ReportKind>("monthly");
  const family = reportKinds[kind];
  const [selected, setSelected] = useState<string[]>([]);
  const [request, setRequest] = useState<ReportBatch>();
  const [results, setResults] = useState<Result[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [page, setPage] = useState(0);
  const lifetime = useRef(true);
  useEffect(() => {
    lifetime.current = true;
    return () => {
      lifetime.current = false;
    };
  }, []);
  const pageSize = 100;
  const rows = active.slice(page * pageSize, (page + 1) * pageSize);
  async function run(mode: "new" | "retry" | "refresh") {
    if (busy) return;
    const batch =
      mode === "new" || (mode === "refresh" && kind === "prospect")
        ? {
            id: mode === "new" ? crypto.randomUUID() : "",
            tenants: [...selected],
            prospectRevisions: new Map<string, ProspectRevisions>(),
          }
        : request;
    if (!batch || batch.tenants.length === 0) return;
    setBusy(true);
    setError("");
    setResults([]);
    const collected: Result[] = [];
    try {
      for (const id of batch.tenants) {
        if (!lifetime.current) return;
        try {
          const path = `/provider/v1/tenants/${encodeURIComponent(id)}/${kind}-reports`;
          let result: Progress | ProspectProgress;
          if (kind === "prospect") {
            const prospectPath = `/provider/v1/tenants/${encodeURIComponent(id)}/prospect-report`;
            if (mode === "retry") {
              const revisions = batch.prospectRevisions.get(id);
              if (!revisions) continue;
              result = await api<ProspectProgress>("POST", prospectPath, {
                request_id: batch.id,
                ...revisions,
              });
            } else {
              result = await api<ProspectProgress>("GET", prospectPath);
              if (result.tenant_id !== id)
                throw new Error("Report queue response scope mismatch.");
              if (mode === "new" && result.phase === "due") {
                const { engagement_revision, access_revision } = result;
                const revisions = { engagement_revision, access_revision };
                batch.prospectRevisions.set(id, revisions);
                result = await api<ProspectProgress>("POST", prospectPath, {
                  request_id: batch.id,
                  ...revisions,
                });
              }
            }
          } else {
            result =
              mode === "refresh"
                ? await api<Progress>(
                    "GET",
                    `${path}/${encodeURIComponent(batch.id)}`,
                  )
                : await api<Progress>("POST", path, { request_id: batch.id });
          }
          if (result.tenant_id !== id)
            throw new Error("Report queue response scope mismatch.");
          collected.push({ id, progress: result });
        } catch (cause) {
          collected.push({
            id,
            error:
              kind === "prospect" && cause instanceof NotEnabledError
                ? "Prospect assessment unavailable"
                : String(cause),
          });
        }
        if (lifetime.current) setResults([...collected]);
      }
    } catch (cause) {
      if (lifetime.current) setError(String(cause));
    } finally {
      if (lifetime.current) {
        if (mode === "new") setRequest(batch);
        setBusy(false);
      }
    }
  }
  return (
    <Card>
      <CardHeader
        title={family.title}
        description="Run the selected work for tenants that have opted in. Report files stay accessible to tenant users."
        actions={<Badge tone="info">Tenant consent required</Badge>}
      />
      <CardBody className={styles.form}>
        {tenants.isError && <p role="alert">Tenant metadata is unavailable.</p>}
        {error && <p role="alert">{error}</p>}
        <Select
          label="Report family"
          value={kind}
          disabled={busy}
          options={[
            { value: "monthly", label: "Monthly client operations" },
            { value: "compliance", label: "Compliance control evidence" },
            { value: "prospect", label: "Prospect assessments" },
          ]}
          onChange={(event) => {
            const nextKind = event.target.value as ReportKind;
            setKind(nextKind);
            if (
              nextKind === "prospect" &&
              selected.length > maxProspectSelection
            )
              setSelected([]);
            setRequest(undefined);
            setResults([]);
            setError("");
          }}
        />
        <div className={styles.actions}>
          <Button
            disabled={
              busy || (readOnly && kind !== "prospect") || active.length === 0
            }
            onClick={() =>
              setSelected(
                (kind === "prospect" ? rows : active).map((item) => item.id),
              )
            }
          >
            {kind === "prospect"
              ? "Select this page"
              : "Select all active tenants"}
          </Button>
          <Button disabled={busy} onClick={() => setSelected([])}>
            Clear report selection
          </Button>
          <Button
            variant="primary"
            disabled={busy || readOnly || selected.length === 0}
            onClick={() => void run("new")}
          >
            {family.queue}
          </Button>
          <Button
            disabled={
              busy ||
              readOnly ||
              !request ||
              (kind === "prospect" && request.prospectRevisions.size === 0)
            }
            onClick={() => void run("retry")}
          >
            Retry same report request
          </Button>
          <Button
            disabled={
              busy || (kind === "prospect" ? selected.length === 0 : !request)
            }
            onClick={() => void run("refresh")}
          >
            Refresh report progress
          </Button>
        </div>
        <p role="status">
          {selected.length} tenants selected · {results.length} operational
          responses{busy ? " · working…" : ""}.
        </p>
        <Table
          caption={family.label + " tenant selection"}
          rows={rows}
          rowKey={(item) => item.id}
          columns={[
            {
              key: "selected",
              header: "Selected",
              render: (item) => (
                <label>
                  <input
                    type="checkbox"
                    disabled={
                      busy ||
                      (readOnly && kind !== "prospect") ||
                      (kind === "prospect" &&
                        selected.length >= maxProspectSelection &&
                        !selected.includes(item.id))
                    }
                    checked={selected.includes(item.id)}
                    onChange={(event) =>
                      setSelected((old) =>
                        event.target.checked
                          ? [...old, item.id]
                          : old.filter((id) => id !== item.id),
                      )
                    }
                  />{" "}
                  Select {item.name}
                </label>
              ),
            },
            { key: "tenant", header: "Tenant", render: (item) => item.name },
            { key: "slug", header: "Tenant slug", render: (item) => item.slug },
          ]}
        />
        <div className={styles.actions}>
          <Button
            disabled={page === 0}
            onClick={() => setPage((old) => old - 1)}
          >
            Previous report tenants
          </Button>
          <Button
            disabled={(page + 1) * pageSize >= active.length}
            onClick={() => setPage((old) => old + 1)}
          >
            Next report tenants
          </Button>
          <span>
            Showing {page * pageSize + (rows.length ? 1 : 0)}–
            {page * pageSize + rows.length} of {active.length}; queuing uses the
            complete selection.
          </span>
        </div>
        <ul aria-label={family.label + " operational progress"}>
          {results.map((item) => (
            <li key={item.id}>
              <strong>
                {active.find((tenant) => tenant.id === item.id)?.name ??
                  item.id}
              </strong>
              :{" "}
              {item.error ??
                (item.progress
                  ? "phase" in item.progress
                    ? `${item.progress.phase}${item.progress.request_pending ? " · retry requested" : ""}`
                    : `${item.progress.eligible} eligible; ${item.progress.queued} queued; ${item.progress.pending} pending; ${item.progress.delivered} delivered; ${item.progress.inactive} inactive`
                  : "unavailable")}
            </li>
          ))}
        </ul>
        <p className={styles.note}>
          Pending work checks the tenant owner's current permissions and source
          authority. No report content, evidence or download link is available
          through this provider action.
        </p>
      </CardBody>
    </Card>
  );
}
