#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
set -euo pipefail

# Apply only to the disposable GitHub runner. Playwright invokes apt itself,
# so command-line options on our own apt calls would leave that path uncovered.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]] || {
  echo 'apt transport configuration requires a Linux GitHub Actions runner' >&2
  exit 1
}
sudo tee /etc/apt/apt.conf.d/80probectl-ci-transport >/dev/null <<'APT'
Acquire::Retries "3";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
APT::Update::Error-Mode "any";
APT
