# Journey J6 — Operate in production

A monitoring platform is itself a service somebody has to keep alive at 3 a.m.
This page walks the operational path end to end: upgrade with no outage, roll a
new agent version across the fleet a slice at a time, prove the hardened
cryptographic mode is live, survive the loss of a whole region in a drill, hand a
diagnostician a secret-free support bundle, and run a resilience self-test. Terms
of art (TLS, mTLS, FIPS, HA) are in the [glossary](../glossary.md).

## Who this is for

A site-reliability engineer or operator running probectl in production. You own
upgrades, failover, and the on-call runbook. You are not changing what probectl
observes — you are keeping the observer healthy while it observes.

## Before you start

- You run the control plane as interchangeable replicas behind a load balancer,
  and you can apply database migrations. With a single replica there is no
  zero-downtime path — there is nothing to roll to.
- You can read the API over HTTPS and hold admin rights (the support bundle and
  deep diagnostics are admin-only). The examples pass `--cacert ca.crt` so `curl`
  trusts a self-signed certificate; drop it against a publicly trusted one.
- For the FIPS step you run the hardened-crypto build. FIPS (the Federal
  Information Processing Standards mode) is a build, not a runtime toggle — the
  binary you run is the gate.
- For the failover drill you run multi-region high availability (HA) on real
  infrastructure. The live disaster-recovery exercise is yours to run; probectl
  ships the runbook and an automated drill, not the infrastructure.

## The path

1. **Upgrade with zero downtime and a staged fleet rollout.** Apply the additive
   migrations first — they are safe for the still-running release — then replace
   control-plane replicas one at a time. Liveness and readiness are separate on
   purpose: a draining replica stays alive while it stops taking new traffic.
   ```sh
   curl https://control.example/healthz   # liveness: is the process alive?
   curl https://control.example/readyz    # readiness: send it traffic now?
   ```
   You observe `/healthz` stay `200` during a graceful shutdown while `/readyz`
   flips to `503` (draining); the replacement serves only once `/readyz` returns
   `200`. For agents, promote a new version ring by ring — a small **canary**
   cohort first, then **early**, then the **main** fleet — advancing one ring at a
   time while you watch health, so a regression hurts a few percent, not everyone.
   Powered by [running probectl in production](../features/operations.md).

2. **Run a multi-region high-availability failover drill.** probectl runs
   active-active across regions for the stateless parts; durable state is a
   single-writer database with streaming read replicas. The safety core is
   split-brain fencing — it refuses to write unless the target is provably the
   current primary. Trigger a failover and watch the readiness endpoint, which
   carries the cluster view.
   ```json
   {
     "status": "ready",
     "cluster": { "topology": { "region": "eu" }, "writer": { "role": "reader" }, "writes_usable": false }
   }
   ```
   You observe `writes_usable: false` during the flip: writes pause (fenced) so
   state can never corrupt, while reads and telemetry ingest keep flowing. Writes
   resume automatically on the next probe once the writer endpoint resolves to the
   promoted primary. Be precise in your runbook: the durable state database
   recovers in seconds, but the high-volume telemetry store does **not** replicate
   cross-region by default — its recovery point equals your off-region backup
   cadence unless you opt into telemetry-store replication. This is backup-cadence
   recovery, not live replication; record both numbers. Powered by [running probectl in production](../features/operations.md).

3. **Confirm FIPS-mode crypto is active.** Every cryptographic operation flows
   through one internal choke point, which is what lets a FIPS 140-3 validated
   module compile in transparently. Both the control plane and the agent run a
   power-on self-test before serving traffic and fail closed if it errors. Read the
   live posture.
   ```sh
   curl --cacert ca.crt "https://control.example/v1/editions"
   ```
   You observe a `fips` block with `build_tag`, `module_active`, `enforced`, and
   `self_test_passed`. `self_test_passed: true` means the self-test ran and the
   validated module is live — if it had failed, the process would not have started
   at all. The honest claim: the build operates the validated Go Cryptographic
   Module; verify its certificate number with the validating body yourself.
   Powered by [running probectl in production](../features/operations.md).

4. **Generate a tenant-scoped, secret-stripped support bundle.** A support bundle
   is one archive of diagnostic files — version, redacted config, deep-health
   report, self-metrics, an anonymized topology summary, and a runtime snapshot.
   Its non-negotiable property is that it never contains secrets, credentials, or
   personally identifiable information, kept true by an allowlist of known-non-secret
   config keys, counts-only topology, and a final scrub of this deployment's actual
   secret values.
   ```sh
   curl --cacert ca.crt "https://control.example/v1/diagnostics/bundle" -o probectl-support.tar.gz
   ```
   You observe a gzipped archive of JSON files: database URLs have their passwords
   stripped, and the encryption key appears only as a boolean
   `envelope_key_configured`, never the key itself. Powered by [running probectl in production](../features/operations.md).

5. **Chaos-test resilience (a self-test).** The chaos injector deliberately
   injects a known network fault — added delay, packet loss, a full outage — to
   prove your monitoring and SLO alerts actually fire when the network breaks. Be
   honest about what it is: a self-test, not an API. It perturbs only traffic
   addressed to its own listener, cannot be triggered remotely, and never mutates a
   live cluster. A run has a fixed shape — healthy baseline, inject, observe, heal,
   observe.
   ```text
   healthy baseline   → SLO quiet, probes pass, latency normal
   inject a partition → probes fail for real, the multi-window burn alert fires
   heal               → attainment recovers, the alert clears
   ```
   You observe the burn alert fire under the injected fault and clear after the
   heal. If a known fault does not make the alert fire, that is a failure of the
   platform's core promise — which is exactly what the self-test catches. Powered
   by [cost, reliability, chaos and carbon](../features/cost-slo-and-chaos.md).

## You're done when

- You have rolled the control plane with `/readyz` flipping to `503` on the
  draining replica and back to `200` on its replacement — no outage.
- A failover drill shows `writes_usable: false` during the flip and automatic
  write resumption after, with both recovery points recorded.
- `GET /v1/editions` reports `self_test_passed: true` under `fips`.
- A support bundle is produced and confirmed secret-free.
- A chaos self-test fires the burn alert under fault and clears on heal.

## Next

Bring the first tenant and its agents online — the path that produces the data
everything here keeps alive — in [stand up and isolate a tenant](./tenant-setup.md).

**Journey:** J6 · **Visits:** F28, F32, F33, F35, F47
