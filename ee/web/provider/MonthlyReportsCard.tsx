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
  Table,
} from "../../../web/src/components";
import { api, useProviderData } from "./providerData";
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
type Result = { id: string; progress?: Progress; error?: string };

export function MonthlyReportsCard({ readOnly }: { readOnly: boolean }) {
  const tenants = useProviderData<{ items: Tenant[] }>(
    ["tenants"],
    "/provider/v1/tenants",
  );
  const active = (tenants.data?.items ?? []).filter(
    (item) => item.status === "active",
  );
  const [selected, setSelected] = useState<string[]>([]);
  const [request, setRequest] = useState<{ id: string; tenants: string[] }>();
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
      mode === "new"
        ? { id: crypto.randomUUID(), tenants: [...selected] }
        : request;
    if (!batch || batch.tenants.length === 0) return;
    setRequest(batch);
    setBusy(true);
    setError("");
    setResults([]);
    const collected: Result[] = [];
    try {
      for (const id of batch.tenants) {
        if (!lifetime.current) return;
        try {
          const path = `/provider/v1/tenants/${encodeURIComponent(id)}/monthly-reports`;
          const result =
            mode === "refresh"
              ? await api<Progress>(
                  "GET",
                  `${path}/${encodeURIComponent(batch.id)}`,
                )
              : await api<Progress>("POST", path, { request_id: batch.id });
          if (result.tenant_id !== id)
            throw new Error("Report queue response scope mismatch.");
          collected.push({ id, progress: result });
        } catch (cause) {
          collected.push({ id, error: String(cause) });
        }
        if (lifetime.current) setResults([...collected]);
      }
    } catch (cause) {
      if (lifetime.current) setError(String(cause));
    } finally {
      if (lifetime.current) setBusy(false);
    }
  }
  return (
    <Card>
      <CardHeader
        title="Monthly client reports"
        description="Run each tenant's explicitly opted-in monthly schedules. Reports stay in tenant inboxes; this console receives operational counts."
        actions={<Badge tone="info">Tenant consent required</Badge>}
      />
      <CardBody className={styles.form}>
        {tenants.isError && <p role="alert">Tenant metadata is unavailable.</p>}
        {error && <p role="alert">{error}</p>}
        <div className={styles.actions}>
          <Button
            disabled={busy || readOnly || active.length === 0}
            onClick={() => setSelected(active.map((item) => item.id))}
          >
            Select all active tenants
          </Button>
          <Button disabled={busy} onClick={() => setSelected([])}>
            Clear report selection
          </Button>
          <Button
            variant="primary"
            disabled={busy || readOnly || selected.length === 0}
            onClick={() => void run("new")}
          >
            Queue monthly reports
          </Button>
          <Button
            disabled={busy || readOnly || !request}
            onClick={() => void run("retry")}
          >
            Retry same report request
          </Button>
          <Button
            disabled={busy || !request}
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
          caption="Monthly report tenant selection"
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
                    disabled={busy || readOnly}
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
        <ul aria-label="Monthly report operational progress">
          {results.map((item) => (
            <li key={item.id}>
              <strong>
                {active.find((tenant) => tenant.id === item.id)?.name ??
                  item.id}
              </strong>
              :{" "}
              {item.error ??
                (item.progress
                  ? `${item.progress.eligible} eligible; ${item.progress.queued} queued; ${item.progress.pending} pending; ${item.progress.delivered} delivered; ${item.progress.inactive} inactive`
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
