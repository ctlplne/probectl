#!/usr/bin/env bash
# One command from a clean checkout to a REAL measurement. It drives
# deploy/compose/eval.yml + eval-synthetic.yml: the control plane, the agent CA,
# an enrolled canary, and a real HTTPS probe whose result travels the production
# path — agent -> mTLS gRPC -> bus -> consumer -> API.
#
# EVAL ONLY. This stack runs dev auth (every request is an unauthenticated
# admin), a plaintext bus and a self-signed certificate, and the control plane
# REFUSES to start if dev auth is given anything but a loopback bind. That is
# also why the measurement is read through the in-namespace `viewer` helper
# rather than in the browser: the UI this binary embeds is not reachable from
# the host in this stack. For the UI, run the production-shaped stack with real
# SSO (docs/install.md plus deploy/compose/dex-demo.yml).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
compose=(docker compose -f deploy/compose/eval.yml -f deploy/compose/eval-synthetic.yml)
env_file="deploy/compose/.env.eval"
tenant="${PROBECTL_FIRST_DATA_TENANT:-00000000-0000-0000-0000-000000000001}"
# The eval canary advertises the http capability, and this URL is the control
# plane's own readiness endpoint on the loopback it shares — a real HTTPS
# measurement with real certificate verification, and no internet needed.
target="${PROBECTL_FIRST_DATA_TARGET:-https://127.0.0.1:8443/readyz}"
api_port=8443   # the control plane's loopback bind inside its container
started=$(date +%s)

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

command -v docker >/dev/null || { echo "first-data: docker is required" >&2; exit 1; }

# 1. The one secret this path needs: agent-ca init refuses to seal the agent-CA
#    intermediate key with nothing (KEYS-003, DPR-133), and control must unseal
#    with the same value. Generated once, reused on every later run.
if [ ! -s "$env_file" ]; then
  say "generating the eval envelope key ($env_file, gitignored)"
  umask 077
  printf 'PROBECTL_EVAL_ENVELOPE_KEY=%s\n' "$(openssl rand -base64 32)" > "$env_file"
fi
compose=(docker compose --env-file "$env_file" -f deploy/compose/eval.yml -f deploy/compose/eval-synthetic.yml)

# 2. Build and start: postgres, kafka, the control plane, the agent CA, and the
#    agent gRPC listener. The eBPF fixture agent comes up with them.
#
#    DPR-138: an identity volume left by an earlier run holds an SVID signed by
#    a CA that this run's database does not have, and the agent would loop on
#    "tls: unknown certificate authority" forever. If the control plane is not
#    already running, start from a clean identity rather than inheriting one.
if ! "${compose[@]}" ps --status running --services 2>/dev/null | grep -qx control; then
  "${compose[@]}" --profile synthetic --profile browser-synthetic down -v >/dev/null 2>&1 || true
fi
say "starting the evaluation stack (first run builds the images)"
"${compose[@]}" up --build -d

# 3. Wait for readiness through a helper that shares the control plane's network
#    namespace — the API binds loopback, which is the point.
say "waiting for the control plane"
"${compose[@]}" --profile tools run --rm --no-deps -e URL=/readyz viewer >/dev/null

# 4. Create the first test through the API: a real HTTPS check of a real
#    endpoint, so first data is an observation rather than a fixture, and it
#    proves the write path too. Dev auth needs no credential.
say "creating the first test (http $target every 10s)"
test_id="$("${compose[@]}" --profile tools run --rm --no-deps --entrypoint /bin/sh viewer -c "
  curl -fsS --cacert /certs/ca.crt -X POST https://127.0.0.1:${api_port}/v1/tests \
    -H 'Content-Type: application/json' \
    -d '{\"name\":\"first-data\",\"type\":\"http\",\"target\":\"${target}\",\"interval_seconds\":10,\"enabled\":true}'
" | tr -d '\r' | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
[ -n "$test_id" ] || { echo "first-data: the control plane did not return a test id" >&2; exit 1; }
echo "    test id: $test_id"

# 5. Mint a single-use join token and hand it to the canary, which enrolls itself
#    on boot over mTLS. No plaintext or token-only agent transport exists.
say "enrolling the canary"
token="$("${compose[@]}" exec -T control /usr/local/bin/app enroll-token -tenant "$tenant" -name first-data \
  | tr -d '\r' | grep -oE 'pjt_[A-Za-z0-9_-]+' | head -1)"
[ -n "$token" ] || { echo "first-data: enroll-token did not print a pjt_ token" >&2; exit 1; }
# --no-deps: the one-shots this service depends on have already completed, and
# re-running them is at best wasted work.
PROBECTL_JOIN_TOKEN="$token" "${compose[@]}" --profile synthetic up --build -d --no-deps canary

# 6. Wait for the first real result to arrive through the bus and the consumer.
#    Two probes are in flight: the canary's own config carries one, and the test
#    created above is assigned by the control plane. Whichever lands first IS
#    first data, so wait for either and then say which arrived.
say "waiting for the first measurement"
result=""
for _ in $(seq 1 60); do
  body="$("${compose[@]}" --profile tools run --rm --no-deps -e URL=/v1/results/latest viewer 2>/dev/null || true)"
  if printf '%s' "$body" | grep -q '"result_id"'; then result="$body"; break; fi
  sleep 5
done
[ -n "$result" ] || {
  echo "first-data: no measurement arrived within the wait. Inspect:" >&2
  echo "    ${compose[*]} logs canary control" >&2
  exit 1
}
if printf '%s' "$result" | grep -q "$test_id"; then
  server_side="yes — the test created above is being probed"
else
  server_side="not yet — this came from the probe in the canary's own config"
fi

elapsed=$(( $(date +%s) - started ))
say "first data in ${elapsed}s"
printf '%s\n' "$result" | head -c 900; echo
echo
echo "    server-side test $test_id: $server_side"
cat <<EOF

That measurement came from an enrolled agent over mTLS, through the bus and the
consumer, and out of the tenant-scoped API — the same path production uses.

Read more from the same API:
  ${compose[*]} --profile tools run --rm --no-deps -e URL=/v1/tests viewer
  ${compose[*]} --profile tools run --rm --no-deps viewer      # the topology graph

To see it in the WEB UI, run the production-shaped stack with real SSO instead:
dev auth is refused on anything but a loopback bind, so the UI this binary
embeds is not reachable from a browser here. See docs/install.md and
deploy/compose/dex-demo.yml.

Tear it all down (the profiles matter — see DPR-138):
  ${compose[*]} --profile synthetic --profile browser-synthetic down -v
EOF
