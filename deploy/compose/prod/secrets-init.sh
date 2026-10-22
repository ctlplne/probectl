#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
#
# secrets-init — the root one-shot of the durable production Compose profile
# (deploy/compose/probectl.prod.yml, beta gate G2). It runs on every `up`,
# after certgen, and before any backing service starts:
#
#   * installs a per-service copy of the certgen TLS bundle that only that
#     service's uid can read (NATS root, ClickHouse 101, Prometheus 65534) —
#     the same move the Postgres service makes for its own key;
#   * writes the Prometheus web config (TLS + a bcrypt hash generated here, so
#     the plaintext password never lands in Prometheus's config) and the
#     promtool healthcheck client config;
#   * writes the control plane's ClickHouse and Prometheus credentials as
#     owner-only 0600 JSON files (PROBECTL_CLICKHOUSE_BASIC_AUTH_FILE,
#     PROBECTL_TSDB_BASIC_AUTH_FILE) owned by the control image user (65532);
#   * hands the WORM audit-export volume to the control image user.
#
# Every password is validated first and the script fails closed on a missing
# or unsafe value: they are spliced into JSON, YAML, SQL and the NATS config,
# so only [A-Za-z0-9._~-] is accepted (generate with: openssl rand -hex 24).
# No value is ever printed.
set -euo pipefail
umask 077

CERTS=/certs
OUT=/out
CONTROL_UID=65532

die() {
  echo "secrets-init: $*" >&2
  exit 1
}

require_secret() { # require_secret <ENV_NAME>
  local name="$1" value="${!1:-}"
  [ -n "$value" ] || die "$name is empty; set it in deploy/compose/.env (openssl rand -hex 24)"
  [ "${#value}" -ge 16 ] || die "$name is shorter than 16 characters (openssl rand -hex 24)"
  case "$value" in
    *[!A-Za-z0-9._~-]*) die "$name may contain only letters, digits, '.', '_', '~' and '-' (openssl rand -hex 24)" ;;
  esac
}

for name in NATS_PASSWORD CLICKHOUSE_CONTROL_PASSWORD PROMETHEUS_CONTROL_PASSWORD; do
  require_secret "$name"
done

for f in tls.crt tls.key ca.crt; do
  [ -s "$CERTS/$f" ] || die "$CERTS/$f is missing or empty; certgen (or PROBECTL_TLS_DIR) must provide the full bundle"
done

own_dir() { # own_dir <dir> <uid> <gid> — the volume root itself, created or not
  install -d "$1"
  chown "$2:$3" "$1"
  chmod 0700 "$1"
}

install_bundle() { # install_bundle <dir> <uid> <gid>
  local dir="$1" uid="$2" gid="$3"
  own_dir "$dir" "$uid" "$gid"
  install -o "$uid" -g "$gid" -m 0644 "$CERTS/tls.crt" "$dir/tls.crt"
  install -o "$uid" -g "$gid" -m 0644 "$CERTS/ca.crt" "$dir/ca.crt"
  install -o "$uid" -g "$gid" -m 0600 "$CERTS/tls.key" "$dir/tls.key"
}

write_private() { # write_private <path> <uid> <gid>  (content on stdin)
  local path="$1" uid="$2" gid="$3" tmp
  tmp="$(mktemp "$(dirname "$path")/.tmp.XXXXXX")"
  cat >"$tmp"
  chown "$uid:$gid" "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$path"
}

# docs/guardrails.md G7-12: each backing service serves TLS from its own copy.
install_bundle "$OUT/nats" 0 0
install_bundle "$OUT/clickhouse" 101 101
install_bundle "$OUT/prometheus" 65534 65534

# Prometheus basic auth takes a bcrypt hash. glibc's crypt(3) (libxcrypt on the
# Debian-based Postgres image) computes it; the result is re-verified before use
# so a libc without bcrypt fails closed instead of writing a broken config.
prom_hash="$(perl -e '
  open(my $u, "<", "/dev/urandom") or die "urandom: $!\n";
  read($u, my $raw, 22) == 22 or die "urandom: short read\n";
  close($u);
  my @alphabet = (".", "/", "A" .. "Z", "a" .. "z", "0" .. "9");
  my @last = (".", "O", "e", "u");
  my $salt = join("", map { $alphabet[ord($_) & 63] } split(//, substr($raw, 0, 21)))
    . $last[ord(substr($raw, 21, 1)) & 3];
  my $pw = $ENV{PROMETHEUS_CONTROL_PASSWORD};
  my $hash = crypt($pw, "\$2b\$12\$" . $salt);
  defined($hash) && length($hash) == 60 && substr($hash, 0, 7) eq "\$2b\$12\$"
    && crypt($pw, $hash) eq $hash or die "bcrypt is unavailable in this libc\n";
  print $hash;
')" || die "could not compute the Prometheus bcrypt hash"

write_private "$OUT/prometheus/web.yml" 65534 65534 <<EOF
tls_server_config:
  cert_file: /run/probectl-prometheus/tls.crt
  key_file: /run/probectl-prometheus/tls.key
  min_version: TLS12
basic_auth_users:
  probectl: '${prom_hash}'
EOF

write_private "$OUT/prometheus/health-client.yml" 65534 65534 <<EOF
basic_auth:
  username: probectl
  password: '${PROMETHEUS_CONTROL_PASSWORD}'
tls_config:
  ca_file: /run/probectl-prometheus/ca.crt
  server_name: prometheus
EOF

# The control plane's datastore credentials (owner-only, regular files; the
# loader refuses anything but 0600).
own_dir "$OUT/control" "$CONTROL_UID" "$CONTROL_UID"
printf '{"username":"probectl","password":"%s"}\n' "$CLICKHOUSE_CONTROL_PASSWORD" |
  write_private "$OUT/control/clickhouse-basic-auth.json" "$CONTROL_UID" "$CONTROL_UID"
printf '{"username":"probectl","password":"%s"}\n' "$PROMETHEUS_CONTROL_PASSWORD" |
  write_private "$OUT/control/prometheus-basic-auth.json" "$CONTROL_UID" "$CONTROL_UID"

# The signed WORM audit-export directory (PROBECTL_AUDIT_WORM_DIR) is its own
# named volume; the read-only, capability-free control plane must own it.
own_dir "$OUT/audit-worm" "$CONTROL_UID" "$CONTROL_UID"

echo "secrets-init: service TLS bundles, Prometheus web config and control credentials installed"
