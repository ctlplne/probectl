# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Smoke test proving the analyzer test harness and CI are wired (S0)."""

import probectl_analyzer


def test_version_is_exposed() -> None:
    assert probectl_analyzer.__version__
    assert isinstance(probectl_analyzer.__version__, str)
