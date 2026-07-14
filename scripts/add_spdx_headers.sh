#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Compatibility wrapper. L2 finalized the core license as MPL-2.0; the old
# placeholder stamper must never reintroduce LicenseRef-probectl-TBD.
set -euo pipefail
exec "$(dirname "$0")/apply_license_headers.sh" "$@"
