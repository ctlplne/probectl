// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.
//
// QuarantineCard (D-62): the tenants a control-plane replica holds
// quarantined because an isolation precondition failed at startup — every
// read and write of them is refused while every other tenant runs. Each row
// names the failed precondition, the residency plane, the operator-side cause
// and the fix; the replica releases the tenant by itself once the fix lands.

import { useProviderData } from "./providerData";
import {
  Badge,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  LoadingState,
  Table,
  type Column,
} from "../../../web/src/components";
import styles from "./ProviderConsole.module.css";

export interface QuarantineRow {
  tenant_id: string;
  slug: string;
  name: string;
  isolation_model: string;
  plane: string;
  reason: string;
  detail: string;
  remedy: string;
  replica: string;
  since: string;
  checked_at: string;
  stale: boolean;
}

const reasonLabels: Record<string, string> = {
  residency_plane_missing: "Residency plane not configured",
  residency_plane_unreachable: "Residency plane unreachable",
  reader_credential_missing: "Reader credential missing",
  reader_scope_unproven: "Reader scope unproven",
  silo_schema_catchup_failed: "Silo schema catch-up failed",
};

export function QuarantineCard() {
  const query = useProviderData<{ items: QuarantineRow[] }>(
    ["quarantine"],
    "/provider/v1/tenants/quarantine",
  );
  const rows = query.data?.items ?? [];
  const queryError = query.error ? (query.error as Error).message : "";
  const columns: Column<QuarantineRow>[] = [
    {
      key: "tenant",
      header: "Tenant",
      render: (r) => (
        <span>
          <strong>{r.slug}</strong> <code>{r.tenant_id}</code>
        </span>
      ),
    },
    {
      key: "reason",
      header: "Failed check",
      render: (r) => (
        <span>
          <Badge tone={r.stale ? "neutral" : "danger"}>
            {reasonLabels[r.reason] ?? r.reason}
          </Badge>{" "}
          <code>{r.reason}</code>
        </span>
      ),
    },
    {
      key: "plane",
      header: "Plane",
      render: (r) => <code>{r.plane || "default"}</code>,
    },
    { key: "detail", header: "Cause", render: (r) => r.detail || "—" },
    { key: "remedy", header: "Fix", render: (r) => r.remedy || "—" },
    {
      key: "since",
      header: "Since",
      render: (r) => <time dateTime={r.since}>{r.since}</time>,
    },
    {
      key: "replica",
      header: "Replica",
      render: (r) => (
        <span>
          <code>{r.replica}</code>
          {r.stale ? " (stale: not re-checked recently)" : null}
        </span>
      ),
    },
  ];
  return (
    <Card>
      <CardHeader
        title="Quarantined tenants"
        description="Tenants whose isolated data plane could not be proven safe at startup. Every read and write of a quarantined tenant is refused on that replica while every other tenant keeps running; the replica re-checks it and releases it by itself once the fix lands."
      />
      <CardBody>
        {queryError ? (
          <p role="alert" className={styles.note}>
            {queryError}
          </p>
        ) : null}
        {query.isPending ? (
          <LoadingState label="Loading quarantined tenants…" />
        ) : (
          <Table
            caption="Quarantined tenants"
            columns={columns}
            rows={rows}
            rowKey={(r) => `${r.tenant_id}/${r.replica}`}
            empty={
              <EmptyState
                icon="admin"
                title="No tenant is quarantined"
                description="Every siloed and hybrid tenant passed its isolation checks on every replica."
              />
            }
          />
        )}
      </CardBody>
    </Card>
  );
}
