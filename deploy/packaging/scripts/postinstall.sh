#!/bin/sh
# OPS-004: register the unit. We do NOT auto-start a FRESH install — the agent
# has no identity until it is enrolled (mTLS) or registered (bus collectors);
# starting it before that just produces connect errors. The operator enrolls,
# then starts it.
#
# SUP-05: on an UPGRADE, restart THIS package's own unit (and only if it is
# already running) so the freshly-installed binary actually takes effect.
# `try-restart` is a no-op on an inactive unit, so an un-enrolled agent stays
# stopped — no connect-error noise — while a running agent is bounced onto the
# new binary. The agent name is baked in at package-build time, so this names
# only this package's own unit.
#
# Upgrade vs fresh install:
#   deb postinst: $1 = "configure"; $2 = the previously-configured version,
#                 which is empty on a fresh install and set on an upgrade.
#   rpm %post   : $1 = the number of installed versions — 1 on a fresh install,
#                 >=2 on an upgrade.
set -e

svc="probectl-${AGENT}"

upgrade=0
case "${1:-}" in
    configure)                 [ -n "${2:-}" ] && upgrade=1 ;;   # deb
    2|[3-9]|[1-9][0-9]*)       upgrade=1 ;;                      # rpm: installed count >=2
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    if [ "$upgrade" -eq 1 ]; then
        systemctl try-restart "$svc" >/dev/null 2>&1 || true
    fi
fi

if [ "$upgrade" -eq 0 ]; then
    echo "probectl agent installed. Next:"
    echo "  1. enroll:  probectl-agent enroll --server https://<control-host>:8443 --token <token>"
    echo "     (bus collectors: probectl-control register-collector ... on the control plane instead)"
    echo "  2. edit /etc/probectl/${AGENT}.yaml"
    echo "  3. systemctl enable --now probectl-${AGENT}"
fi
