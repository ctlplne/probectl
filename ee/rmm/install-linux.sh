#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Probectl-Commercial
#
# Licensed under the probectl Commercial Source License; see ee/LICENSE.
# Production use requires a valid commercial agreement; resale additionally
# requires an MSP entitlement and reseller agreement.

# RMM jobs may enable shell tracing. Disable it before reading the secret.
set +x
set +v
set +a
set -euo pipefail
umask 077

fail() {
    printf '%s\n' "probectl RMM: $1" >&2
    exit 1
}

case "${PROBECTL_RMM_VENDOR-}" in
    ninjaone|connectwise-rmm|datto-rmm) ;;
    *) fail "select the vendor of this site policy" ;;
esac
site=${PROBECTL_RMM_SITE_ID-}
tenant=${PROBECTL_RMM_TENANT_ID-}
enroll_url=${PROBECTL_RMM_ENROLL_URL-}
grpc_addr=${PROBECTL_RMM_GRPC_ADDR-}
unset join_secret
join_secret=${PROBECTL_RMM_JOIN_TOKEN-}
unset PROBECTL_RMM_JOIN_TOKEN

[[ "$site" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || fail "set the mapped site ID"
[[ "$tenant" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
   "$tenant" != 00000000-0000-0000-0000-000000000000 ]] || fail "set the mapped tenant UUID"
authority='([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:]+\])'
[[ "$enroll_url" =~ ^https://${authority}(:[1-9][0-9]{0,4})?$ ]] || fail "set the HTTPS enrollment origin"
if [[ "$enroll_url" =~ :([1-9][0-9]{0,4})$ ]]; then
    (( BASH_REMATCH[1] <= 65535 )) || fail "enrollment port is out of range"
fi
[[ "$grpc_addr" =~ ^${authority}:[1-9][0-9]{0,4}$ ]] || fail "set the TLS agent host and port"
(( ${grpc_addr##*:} <= 65535 )) || fail "agent port is out of range"
[[ -z "$join_secret" || "$join_secret" =~ ^pjt_[0-9a-f]{64}$ ]] || fail "the protected token variable has invalid contents"

[[ $EUID == 0 && -d /run/systemd/system ]] || fail "run as root on a Linux systemd host"
command -v flock >/dev/null || fail "flock is required for concurrent RMM jobs"
lock_dir=/run/probectl-rmm
[[ ! -L "$lock_dir" ]] || fail "unexpected link at the RMM lock directory"
if [[ ! -e "$lock_dir" ]]; then
    install -d -m 0700 -o root -g root "$lock_dir"
fi
[[ -d "$lock_dir" && "$(stat -c '%u:%g:%a' -- "$lock_dir")" == '0:0:700' ]] ||
    fail "the RMM lock directory must be private to root"
lock_file=$lock_dir/agent.lock
[[ ! -L "$lock_file" && ( ! -e "$lock_file" || -f "$lock_file" ) ]] ||
    fail "unexpected RMM lock file"
exec 9>>"$lock_file"
flock -n 9 || fail "another enrollment job is in progress"

# The agent package resets ownership under /etc/probectl. Keep the RMM
# policy and operator-staged enrollment trust outside that package tree.
config_dir=/etc/probectl-rmm
config=$config_dir/agent.yaml
ca_file=$config_dir/control-ca.pem
state_dir=/var/lib/probectl-agent
identity=$state_dir/identity
unit=probectl-agent.service
unit_dir=/etc/systemd/system/$unit.d
drop_in=$unit_dir/60-probectl-rmm.conf

[[ -f "$ca_file" && ! -L "$ca_file" && ! -L "$config_dir" ]] || fail "stage the verified control-plane CA bundle"
[[ ! -L "$config" && ! -L "$unit_dir" && ! -L "$drop_in" ]] || fail "unexpected link in the managed unit or configuration"
staged_paths=("$config_dir" "$ca_file")
if [[ -e "$config" ]]; then
    [[ -f "$config" ]] || fail "the managed RMM configuration must be a regular file"
    staged_paths+=("$config")
fi
for staged_path in "${staged_paths[@]}"; do
    [[ -O "$staged_path" ]] || fail "staged RMM files and their directory must be owned by root"
    mode=$(stat -c '%a' -- "$staged_path") || fail "cannot read the staged RMM file permissions"
    (( (8#$mode & 8#022) == 0 )) || fail "staged RMM files and their directory must be writable only by root"
done
[[ ! -L "${identity%/*}" && ! -L "$identity" ]] || fail "unexpected link in the agent state directory"
if [[ ! -e "$config" ]]; then
    if [[ -e "$identity/cert.pem" || -L "$identity/cert.pem" || -e "$drop_in" ]] ||
       systemctl is-active --quiet "$unit"; then
        fail "this host already has an unmanaged agent"
    fi
fi
# The agent publishes cert.pem through a versioned identity directory. Only
# this link layout may reach the unprivileged enrollment command for validation.
if [[ -L "$identity/cert.pem" ]]; then
    version=$(readlink -- "$identity/current") || fail "unexpected link in the managed identity"
    [[ "$(readlink -- "$identity/cert.pem")" == current/cert.pem &&
       "$version" =~ ^v-[a-z0-9]+-[0-9]+$ && ! -L "$identity/$version" &&
       -d "$identity/$version" && ! -L "$identity/$version/cert.pem" &&
       -f "$identity/$version/cert.pem" ]] || fail "unexpected link in the managed identity"
fi
if [[ -z "$join_secret" && ( ! -f "$identity/cert.pem" || ! -s "$identity/cert.pem" ) ]]; then
    fail "set the protected join token to enroll an agent"
fi

# Package repositories and their signing keys are staged by the MSP's policy.
# The package's fresh-install hooks leave the unit stopped until enrollment.
if [[ ! -x /usr/bin/probectl-agent ]]; then
    if command -v apt-get >/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get -o APT::Get::AllowUnauthenticated=false install -y --no-install-recommends probectl-agent
    elif command -v dnf >/dev/null; then
        dnf -y --setopt=gpgcheck=1 --setopt=repo_gpgcheck=1 install probectl-agent
    else
        fail "install the signed probectl-agent package for this distribution"
    fi
fi
id probectl >/dev/null 2>&1 || fail "the agent package did not create the probectl account"
runuser -u probectl -- test -r "$ca_file" || fail "the agent cannot read the staged CA bundle"

if [[ ! -d "$state_dir" ]]; then
    install -d -m 0750 -o probectl -g probectl "$state_dir"
fi
if [[ ! -d "$unit_dir" ]]; then
    install -d -m 0755 "$unit_dir"
fi

draft_config=$(mktemp "$config_dir/.agent-rmm.XXXXXX")
draft_unit=$(mktemp "$unit_dir/.probectl-rmm.XXXXXX")
trap 'rm -f -- "$draft_config" "$draft_unit"' EXIT
cat > "$draft_config" <<CONFIG
# Managed by probectl RMM for $PROBECTL_RMM_VENDOR / $site / $tenant
apiVersion: probectl.io/agent/v1
control_plane:
  grpc_addr: "$grpc_addr"
tls:
  cert_file: "$identity/cert.pem"
  key_file: "$identity/key.pem"
  ca_file: "$ca_file"
identity:
  server: "$enroll_url"
agent:
  heartbeat_interval: 30s
CONFIG
cat > "$draft_unit" <<UNIT
[Service]
ExecStart=
ExecStart=/usr/bin/probectl-agent --config $config
UNIT

if [[ -e "$config" ]] && ! cmp -s "$draft_config" "$config"; then
    fail "this host already has a different managed site configuration"
fi
if [[ -e "$drop_in" ]] && ! cmp -s "$draft_unit" "$drop_in"; then
    fail "a different managed systemd override is present"
fi
chown root:probectl "$draft_config"
chmod 0640 "$draft_config"
chmod 0644 "$draft_unit"
# Write the ownership marker first so an interrupted successful enrollment is
# recognized by the next run. The existing service starts only after enrollment.
[[ -e "$config" ]] || mv -T -- "$draft_config" "$config"
[[ -e "$drop_in" ]] || mv -T -- "$draft_unit" "$drop_in"

# With a current identity, enroll may exit before reading the pipe.
if ! (
    set +o pipefail
    printf '%s\n' "$join_secret" | runuser -u probectl -- /usr/bin/probectl-agent enroll \
        --token-stdin --expected-tenant "$tenant" --if-needed \
        --server "$enroll_url" --ca-file "$ca_file" --dir "$identity"
); then
    fail "agent enrollment refused or failed"
fi
unset join_secret
cmp -s "$ca_file" "$identity/server-ca.pem" || fail "the enrolled identity uses a different control-plane trust bundle"

systemctl daemon-reload
effective_start=$(systemctl show "$unit" --property=ExecStart --value)
[[ "$effective_start" == *"argv[]=/usr/bin/probectl-agent --config $config ;"* ]] ||
    fail "the effective unit does not use the managed agent configuration"
systemctl enable --now "$unit"
