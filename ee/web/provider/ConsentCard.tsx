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
// to hand-craft a browser request. Hidden-unlicensed stays honest — when the
// API answers 404 (no provider plane) the card renders nothing at all.

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

export interface PendingBreakGlassRequest {
  id: string;
  operator_email: string;
  reason: string;
  scope: string;
  granted_at: string;
  expires_at: string;
}

export function ConsentCard() {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const pending = useProviderData<{ items: PendingBreakGlassRequest[] }>(
    ["consent"],
    "/provider/v1/consent",
  );
  const { refetch } = pending;

  // No provider plane on this deployment, or a tenant user who may not decide:
  // nothing to show, and nothing to advertise.
  if (pending.error instanceof NotEnabledError) return null;
  if (pending.error instanceof APIError && pending.error.code === "forbidden") return null;

  const decide = async (request: PendingBreakGlassRequest, decision: "approve" | "deny") => {
    setBusy(request.id);
    setError("");
    setNotice("");
    try {
      await api("POST", `/provider/v1/consent/${request.id}`, { decision });
      setNotice(
        decision === "approve"
          ? `Approved: ${request.operator_email} may read this tenant's latest results until the request expires; every read is written to the audit trail first.`
          : `Denied: ${request.operator_email} gets no access. The decision is on the audit trail.`,
      );
      await refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not record the decision.");
    } finally {
      setBusy("");
    }
  };

  const columns: Column<PendingBreakGlassRequest>[] = [
    { key: "operator", header: "Operator", render: (g) => <code>{g.operator_email}</code> },
    { key: "reason", header: "Reason", render: (g) => g.reason },
    { key: "scope", header: "Scope", render: (g) => <Badge>{g.scope || "read"}</Badge> },
    { key: "requested", header: "Requested", render: (g) => <DateTime value={g.granted_at} /> },
    { key: "expires", header: "Expires", render: (g) => <DateTime value={g.expires_at} /> },
    {
      key: "decision",
      header: "Decision",
      render: (g) => (
        <span className={styles.actions}>
          <Button
            type="button"
            size="sm"
            variant="primary"
            aria-label={`Approve ${g.operator_email}`}
            disabled={busy !== ""}
            onClick={() => {
              void decide(g, "approve");
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
              void decide(g, "deny");
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
        description="Your provider's operators have no standing access to this tenant's telemetry. A request below is a time-bounded, read-only grant that only a tenant administrator can approve; every access it carries is audited before any data is returned, and you can revoke nothing here because an approved grant ends on expiry or the operator's own revocation."
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
        {pending.isPending ? (
          <LoadingState label="Loading break-glass requests…" />
        ) : pending.isError ? (
          <ErrorState
            title="Break-glass requests unavailable"
            description={(pending.error as Error).message}
          />
        ) : (
          <Table
            caption="Pending break-glass requests"
            columns={columns}
            rows={pending.data?.items ?? []}
            rowKey={(g) => g.id}
            empty={
              <EmptyState
                icon="admin"
                title="No pending requests"
                description="No operator is asking for access to this tenant. Requests appear here the moment one is made and disappear once you decide."
              />
            }
          />
        )}
      </CardBody>
    </Card>
  );
}
