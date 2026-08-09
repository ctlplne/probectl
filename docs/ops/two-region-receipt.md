# Two-region upgrade and disaster-recovery receipt

This is the fill-once evidence contract for BL-029, BL-031, and the regional
part of BL-034. ELI5: the repository now contains the map and a successful
tabletop rehearsal; this receipt is the photograph proving the same trip was
driven on two real roads by someone other than the map's author.

## Fixed profile

- two independent Kubernetes API failure domains/regions;
- Terraform root: `deploy/terraform/examples/two-region`;
- continuing reconciler: ArgoCD
  `deploy/gitops/argocd/applicationset-multiregion.yaml`;
- chart: hardened `values-multiregion.yaml`, immutable signed image digests;
- source/rollback binary: `v0.5.0` (`ae2ca1dc7f70a77dff7467d6b18c40f31a565433`);
- target: current release exact commit and image digest;
- PostgreSQL: one fenced writer endpoint, synchronous `remote_apply`, metadata
  RPO `0`, metadata RTO `<=60s`;
- ClickHouse: restore/replication RPO and RTO measured separately; and
- S3/MinIO object store: versioning/Object Lock/replication recovery measured
  separately.

## Required receipt fields

| Area | Evidence that must be attached | Pass condition |
| --- | --- | --- |
| identity | commit, signed image/chart digests, Terraform/Helm/Argo versions, UTC start/end, operator | no mutable tag or dirty tree |
| topology | redacted Terraform plan, two kube contexts/regions, failure domains, writer/read endpoints, TLS issuers | two distinct regional control planes; no secret value in receipt |
| provision | `terraform apply`, pod rollout, HTTPS `/readyz`, tenant-isolation smoke | clean apply with no undocumented click/manual step |
| GitOps handoff | ownership change record, Argo sync/health, live annotation drift and self-heal time | no dual Terraform/Argo ownership; drift detected and repaired |
| upgrade | v0.5.0 → current rollout timeline, migration ledger, tenant counts/hashes, keys, audit head | all reconcile; no cross-tenant row; HTTPS remains enforced |
| failed upgrade | bad digest or deliberately failing health gate | atomic rollback; old healthy release and data remain |
| rollback | current → v0.5.0 binary against additive schema, then roll forward | old and new health/data/security checks pass |
| metadata failover | acknowledged write ledger, sync-state proof, old-writer fence, promote/repoint timestamps | RPO 0, RTO <=60s, exactly one writable primary |
| control/ingest | region loss, agent reconnect, duplicate/lost event ledger | bounded recovery; no cross-tenant or duplicate side effect |
| ClickHouse | latest artifact timestamp, restore start/end, tenant row hashes | separately stated RPO/RTO and isolation pass |
| object store | version/replica timestamp, restore start/end, per-tenant object digests | separately stated RPO/RTO and byte equality pass |
| cleanup | Terraform destroy or approved retained-environment record, Argo deletion/finalizers, residual-resource query | no unowned resource or secret-bearing log |
| usability | non-author name/role, deviations, elapsed steps, unclear instructions | operator completes from runbook; every deviation lands as a doc fix |

## Failure-injection matrix

Run one recoverable fault at each boundary, never in production:

1. before migration: unreachable writer or invalid credential must fail without
   changing the ledger;
2. during additive migration: terminate the migration pod; advisory-lock and
   per-migration transaction/no-tx replay must converge on rerun;
3. during rollout: use a bad signed digest or health failure; Helm atomic/Argo
   health gates must retain the old serving revision;
4. after a current-version write: roll back the binary and prove the old code
   can still read/write its supported fields; and
5. during regional failover: isolate the old writer before promotion, then
   prove its lower epoch cannot accept a probectl write after reconnection.

## Current status and the one external dependency

Repository-local Terraform, Helm, ArgoCD, migration, HTTPS, rollback,
synchronous PostgreSQL failover, backup/restore, RLS, key-byte, and audit-chain
checks are executable and locally passing. This file is intentionally **not** a
regional receipt yet: no two live Kubernetes region credentials/endpoints are
available in this workspace, and no non-author operator has executed it.

Recommended remediation: give the first MSP design partner or an independent
platform operator a disposable two-region account/project, two kubeconfigs,
managed synchronous PostgreSQL, ClickHouse and S3/MinIO recovery targets, DNS or
proxy control, and the signed v0.5.0/current images. They run this matrix while
the author observes without taking the keyboard. Until that happens, retain the
words “local rehearsal” and do not claim representative regional RPO/RTO.
