// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.
//
// Tenant-side break-glass consent (DPR-038). The provider plane's consent
// endpoints are authenticated by the TENANT session and need directory.write,
// so the only place a tenant administrator can legitimately approve or deny an
// operator's request is inside the tenant app. Until this card existed the
// documented "the tenant decides" step had no screen: an admin would have had
// to hand-craft a browser request. An approved grant stays listed while it is
// active so the tenant can revoke it (AUD-13): the authority to stop an access
// belongs to the tenant that consented to it. Hidden-unlicensed stays honest —
// when the API answers 404 (no provider plane) the card renders nothing at all.

import { useState } from "react";
import { api, APIError, NotEnabledError, useProviderData } from "./providerData";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  Table,
  type Column,
} from "../../../web/src/components";
import { DateTime } from "../../../web/src/time/DateTime";
import styles from "./ProviderConsole.module.css";

/** A grant this tenant can act on: pending (decide it) or active (revoke it). */
export interface TenantBreakGlassGrant {
  id: string;
  operator_email: string;
  reason: string;
  scope: string;
  state: string;
  granted_at: string;
  expires_at: string;
  use_count: number;
}

export function ConsentCard() {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const grants = useProviderData<{ items: TenantBreakGlassGrant[] }>(
    ["consent"],
    "/provider/v1/consent",
  );
  const { refetch } = grants;

  // No provider plane on this deployment, or a tenant user who may not decide:
  // nothing to show, and nothing to advertise.
  if (grants.error instanceof NotEnabledError) return null;
  if (grants.error instanceof APIError && grants.error.code === "forbidden") return null;

  const act = async (
    grant: TenantBreakGlassGrant,
    action: "approve" | "deny" | "revoke",
  ) => {
    setBusy(grant.id);
    setError("");
    setNotice("");
    try {
      if (action === "revoke") {
        await api("POST", `/provider/v1/consent/${grant.id}/revoke`);
        setNotice(
          `Revoked: ${grant.operator_email} can no longer read this tenant's telemetry. The revocation is on this tenant's audit trail and the provider's.`,
        );
      } else {
        await api("POST", `/provider/v1/consent/${grant.id}`, { decision: action });
        setNotice(
          action === "approve"
            ? `Approved: ${grant.operator_email} may read this tenant's latest results until the grant expires or you revoke it; every read is written to the audit trail first.`
            : `Denied: ${grant.operator_email} gets no access. The decision is on the audit trail.`,
        );
      }
      await refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not record the decision.");
    } finally {
      setBusy("");
    }
  };

  const columns: Column<TenantBreakGlassGrant>[] = [
    { key: "operator", header: "Operator", render: (g) => <code>{g.operator_email}</code> },
    { key: "reason", header: "Reason", render: (g) => g.reason },
    { key: "scope", header: "Scope", render: (g) => <Badge>{g.scope || "read"}</Badge> },
    {
      key: "state",
      header: "State",
      render: (g) => (
        <Badge tone={g.state === "active" ? "danger" : "warning"}>{g.state}</Badge>
      ),
    },
    { key: "requested", header: "Requested", render: (g) => <DateTime value={g.granted_at} /> },
    { key: "expires", header: "Expires", render: (g) => <DateTime value={g.expires_at} /> },
    { key: "reads", header: "Audited reads", render: (g) => g.use_count },
    {
      key: "decision",
      header: "Decision",
      render: (g) =>
        g.state === "active" ? (
          <Button
            type="button"
            size="sm"
            aria-label={`Revoke ${g.operator_email}`}
            disabled={busy !== ""}
            onClick={() => {
              void act(g, "revoke");
            }}
          >
            Revoke
          </Button>
        ) : (
          <span className={styles.actions}>
            <Button
              type="button"
              size="sm"
              variant="primary"
              aria-label={`Approve ${g.operator_email}`}
              disabled={busy !== ""}
              onClick={() => {
                void act(g, "approve");
              }}
            >
              Approve
            </Button>{" "}
            <Button
              type="button"
              size="sm"
              aria-label={`Deny ${g.operator_email}`}
              disabled={busy !== ""}
              onClick={() => {
                void act(g, "deny");
              }}
            >
              Deny
            </Button>
          </span>
        ),
    },
  ];

  return (
    <Card>
      <CardHeader
        title="Break-glass requests"
        description="Your provider's operators have no standing access to this tenant's telemetry. A request below is a time-bounded, read-only grant that only a tenant administrator can approve; every access it carries is audited before any data is returned. An approved grant stays here while it is active, and revoking it ends the access at once."
      />
      <CardBody>
        {error ? (
          <p role="alert" className={styles.note}>
            {error}
          </p>
        ) : null}
        {notice ? (
          <p role="status" className={styles.note}>
            {notice}
          </p>
        ) : null}
        {grants.isPending ? (
          <LoadingState label="Loading break-glass requests…" />
        ) : grants.isError ? (
          <ErrorState
            title="Break-glass requests unavailable"
            description={(grants.error as Error).message}
          />
        ) : (
          <Table
            caption="Break-glass requests and active grants"
            columns={columns}
            rows={grants.data?.items ?? []}
            rowKey={(g) => g.id}
            empty={
              <EmptyState
                icon="admin"
                title="No requests or active grants"
                description="No operator is asking for access to this tenant and no approved grant is active. A request appears here the moment it is made; an approved grant stays here, revocable, until it ends."
              />
            }
          />
        )}
      </CardBody>
    </Card>
  );
}
