#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

set +x
set +v
set +a
set -euo pipefail
umask 077

fail() {
    printf '%s\n' "probectl vantage: $1" >&2
    exit 1
}

[[ $EUID == 0 && -d /run/systemd/system ]] || fail "run the managed enrollment on its Linux VM"
if [[ $# == 1 && "$1" == --isolate-metadata ]]; then
    agent_uid=$(id -u probectl)
    [[ "$agent_uid" =~ ^[1-9][0-9]*$ ]] || fail "the canary must run as an unprivileged user"
    # Preserve DNS on clouds that host their resolver at the metadata address.
    nft -f - <<NFT
add table inet probectl_vantage
add chain inet probectl_vantage metadata_guard { type filter hook output priority filter; policy accept; }
flush chain inet probectl_vantage metadata_guard
add rule inet probectl_vantage metadata_guard meta skuid $agent_uid ip daddr 169.254.169.254 udp dport 53 return
add rule inet probectl_vantage metadata_guard meta skuid $agent_uid ip daddr 169.254.169.254 tcp dport 53 return
add rule inet probectl_vantage metadata_guard meta skuid $agent_uid ip6 daddr fd20:ce::254 udp dport 53 return
add rule inet probectl_vantage metadata_guard meta skuid $agent_uid ip6 daddr fd20:ce::254 tcp dport 53 return
add rule inet probectl_vantage metadata_guard meta skuid $agent_uid ip daddr 169.254.169.254 reject
add rule inet probectl_vantage metadata_guard meta skuid $agent_uid ip6 daddr { fd00:ec2::254, fd20:ce::254 } reject
NFT
    exit
fi

[[ $# == 7 ]] || fail "the managed enrollment metadata is incomplete"
cloud=$1
reference=$2
tenant=$3
origin=$4
hostname=$5
region=$6
azure_client_id=$7
ca_file=/etc/probectl-vantage/control-ca.pem
config=/etc/probectl-vantage/agent.yaml
identity=/var/lib/probectl-agent/identity
unit=probectl-agent.service

[[ -x /usr/bin/probectl-agent && -s "$ca_file" && -s "$config" && ! -L "${identity%/*}" &&
    ! -L "$identity" ]] || fail "the prepared image or managed configuration is incomplete"
systemctl daemon-reload
systemctl start probectl-vantage-metadata.service
install -d -m 0750 -o probectl -g probectl "${identity%/*}"
scratch=$(mktemp -d /run/probectl-vantage.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
cloud_env=(env -i PATH=/usr/local/bin:/usr/bin:/bin)

read_token() {
    case "$cloud" in
        aws)
            "${cloud_env[@]}" AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
                timeout -k 2s 15s aws secretsmanager get-secret-value --region "$region" --secret-id "$reference" \
                    --query SecretString --output text --no-cli-pager >"$scratch/token"
            ;;
        azure)
            local -a azure_env=("${cloud_env[@]}" "AZURE_CONFIG_DIR=$scratch/azure" AZURE_CORE_COLLECT_TELEMETRY=0 AZURE_AUTO_UPGRADE_ENABLE=no)
            "${azure_env[@]}" timeout -k 2s 15s az login --identity --client-id "$azure_client_id" \
                --allow-no-subscriptions --output none --only-show-errors &&
                "${azure_env[@]}" timeout -k 2s 15s az keyvault secret show --id "$reference" \
                    --query value --output tsv --only-show-errors >"$scratch/token"
            ;;
        gcp)
            "${cloud_env[@]}" "CLOUDSDK_CONFIG=$scratch/gcp" CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=true \
                CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true \
                timeout -k 2s 15s gcloud secrets versions access latest --project="${reference%%:*}" \
                    --secret="${reference#*:}" --out-file="$scratch/token" --quiet >/dev/null
            ;;
        *) return 1 ;;
    esac
}

enroll=(runuser -u probectl -- /usr/bin/probectl-agent enroll --if-needed --token-stdin
    --server "$origin" --ca-file "$ca_file" --expected-tenant "$tenant" --hostname "$hostname" --dir "$identity")

# A retried boot verifies existing enrollment before asking the cloud for a token.
if [[ -d "$identity" && -n "$(ls -A -- "$identity")" ]]; then
    "${enroll[@]}" </dev/null
else
    ready=0
    for attempt in {1..12}; do
        rm -f -- "$scratch/token"
        if read_token 2>/dev/null && [[ -f "$scratch/token" && -s "$scratch/token" ]]; then
            ready=1
            break
        fi
        [[ $attempt == 12 ]] || sleep 5
    done
    [[ $ready == 1 ]] || fail "the VM identity could not read its enrollment secret"
    "${enroll[@]}" <"$scratch/token"
    rm -f -- "$scratch/token"
fi

systemctl enable --now "$unit"
