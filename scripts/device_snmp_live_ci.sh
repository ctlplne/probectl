#!/usr/bin/env bash
# Start a loopback net-snmp target and require the live SNMP integration test to
# hit it through gosnmp. CI sets PROBECTL_TEST_SNMP_TARGET so the test cannot
# silently skip.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${PROBECTL_TEST_SNMP_TARGET:?device-live CI must set PROBECTL_TEST_SNMP_TARGET}"
: "${PROBECTL_TEST_SNMP_COMMUNITY:=public}"
export PROBECTL_TEST_SNMP_TARGET PROBECTL_TEST_SNMP_COMMUNITY

target_host="${PROBECTL_TEST_SNMP_TARGET%:*}"
target_port="${PROBECTL_TEST_SNMP_TARGET##*:}"
if [[ "$target_host" == "$PROBECTL_TEST_SNMP_TARGET" || -z "$target_host" || -z "$target_port" ]]; then
  echo "PROBECTL_TEST_SNMP_TARGET must be host:port for the CI loopback target" >&2
  exit 1
fi

conf="${RUNNER_TEMP:-/tmp}/probectl-snmpd.conf"
log="${RUNNER_TEMP:-/tmp}/probectl-snmpd.log"
cat > "$conf" <<EOF
agentAddress udp:${target_host}:${target_port}
rocommunity ${PROBECTL_TEST_SNMP_COMMUNITY} ${target_host}
sysName probectl-ci-snmp
sysLocation probectl-ci
sysContact probectl-ci@example.invalid
EOF

sudo snmpd -C -c "$conf" -Lf "$log"
trap 'sudo pkill -f "snmpd .*probectl-snmpd.conf" >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 20); do
  if go test -count=1 -run '^TestSNMPIntegration$' -v ./internal/device; then
    exit 0
  fi
  sleep 1
done

echo "::error::live SNMP integration did not pass against ${PROBECTL_TEST_SNMP_TARGET}" >&2
cat "$log" >&2 || true
exit 1
