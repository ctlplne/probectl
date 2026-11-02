#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
set -euo pipefail

if [[ "${1:-}" != serve ]]; then
  install -m 644 /fixture/ca.crt /opt/netbox/ci-ca.crt
  install -m 644 /fixture/netbox_config.py /opt/netbox/netbox/netbox/probectl_ci_configuration.py
  exec /opt/netbox/docker-entrypoint.sh /bin/bash /opt/probectl-ci-launch.sh serve
fi

# Begin with a fresh Unit state directory containing no TCP listeners. Load
# the ephemeral certificate through the Unix control socket before enabling
# the only listener, HTTPS. Never bring up the image's default HTTP config.
mkdir -p /opt/unit/probectl-ci-state /opt/unit/probectl-ci-tmp
socket=/opt/unit/probectl-ci.sock
configure() {
  for _ in $(seq 1 40); do
    if [[ -S "$socket" ]]; then
      curl --fail --silent --show-error --output /dev/null \
        --unix-socket "$socket" --request PUT \
        --data-binary @/fixture/netbox.bundle http://localhost/certificates/fixture
      curl --fail --silent --show-error --output /dev/null \
        --unix-socket "$socket" --request PUT \
        --data-binary @/fixture/unit.json http://localhost/config
      return
    fi
    sleep 1
  done
  return 1
}
configure &
exec unitd --no-daemon --control "unix:$socket" \
  --pid /opt/unit/probectl-ci.pid --log /dev/stdout \
  --statedir /opt/unit/probectl-ci-state/ --tmpdir /opt/unit/probectl-ci-tmp/ \
  --user unit --group root
