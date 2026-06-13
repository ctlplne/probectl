#!/bin/sh
# OPS-004: register the unit. We do NOT auto-start — the agent has no identity
# until it is enrolled (mTLS) or registered (bus collectors); starting it before
# that just produces connect errors. The operator enrolls, then starts it.
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
echo "probectl agent installed. Next:"
echo "  1. enroll:  probectl-agent enroll --server https://<control-host>:8443 --token <token>"
echo "     (bus collectors: probectl-control register-collector ... on the control plane instead)"
echo "  2. edit /etc/probectl/<agent>.yaml"
echo "  3. systemctl enable --now probectl-<agent>"
