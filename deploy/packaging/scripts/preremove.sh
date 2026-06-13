#!/bin/sh
# OPS-004: stop + disable the unit on package removal (best-effort).
set -e
if command -v systemctl >/dev/null 2>&1; then
    for svc in probectl-agent probectl-ebpf-agent probectl-flow-agent probectl-device-agent probectl-endpoint; do
        systemctl disable --now "$svc" >/dev/null 2>&1 || true
    done
    systemctl daemon-reload || true
fi
