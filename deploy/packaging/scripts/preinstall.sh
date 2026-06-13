#!/bin/sh
# OPS-004: create the unprivileged system user the agent runs as (idempotent).
set -e
if ! getent group probectl >/dev/null 2>&1; then
    groupadd --system probectl
fi
if ! getent passwd probectl >/dev/null 2>&1; then
    useradd --system --gid probectl --no-create-home \
        --home-dir /var/lib/probectl --shell /usr/sbin/nologin probectl
fi
