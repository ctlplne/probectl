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
# CI installs Ubuntu packages. Keep the runner's signed Ubuntu archive
# definitions and avoid refreshing unrelated vendor indexes for these jobs.
[[ -r /etc/apt/sources.list.d/ubuntu.sources ]] || {
  echo 'the Linux runner is missing its Ubuntu apt archive definitions' >&2
  exit 1
}
sudo tee /etc/apt/apt.conf.d/80probectl-ci-transport >/dev/null <<'APT'
Dir::Etc::SourceList "/etc/apt/sources.list.d/ubuntu.sources";
Dir::Etc::SourceParts "/dev/null";
Acquire::Retries "3";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
APT::Update::Error-Mode "any";
APT
