#!/bin/sh
# OPS-004 / SUP-05: stop + disable ONLY this package's own unit, and ONLY on a
# real removal.
#
# The agent name is baked in at package-build time (release.yml /
# packaging-smoke.sh render this per agent), so each package's prerm names only
# its own unit (e.g. probectl-flow-agent) and nothing else. The previous shared script
# looped over EVERY agent unit on EVERY remove/upgrade and ran
# `systemctl disable --now`, so upgrading one agent stopped AND un-enabled
# (symlink-removed) the entire fleet — the other agents never came back, even
# across a reboot. A package's maintainer scripts must touch only that package.
#
# "Real removal" excludes the remove half of an upgrade:
#   deb prerm $1 : "remove" on a true removal; "upgrade"/"deconfigure"/
#                  "failed-upgrade" while an upgrade is in flight.
#   rpm %preun $1: the count of versions that will REMAIN — 0 on a true removal,
#                  >=1 during an upgrade.
set -e

svc="probectl-${AGENT}"

removing=0
case "${1:-}" in
    remove|purge)                        removing=1 ;;   # deb: true removal
    upgrade|deconfigure|failed-upgrade)  removing=0 ;;   # deb: part of an upgrade
    0)                                   removing=1 ;;   # rpm: last version leaving
    [0-9]*)                              removing=0 ;;   # rpm: >=1 version remains (upgrade)
    *)                                   removing=1 ;;   # no/unknown arg: fail safe toward cleanup
esac

if [ "$removing" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
    systemctl daemon-reload || true
fi
