#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

# Compatibility wrapper. L2 finalized the core license as MPL-2.0; this old
# entry point delegates to the canonical stamper and cannot reintroduce the
# retired pre-MPL placeholder identifier.
set -euo pipefail
exec "$(dirname "$0")/apply_license_headers.sh" "$@"
