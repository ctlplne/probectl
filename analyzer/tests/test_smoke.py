# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Smoke test proving the analyzer test harness and CI are wired (S0)."""

import probectl_analyzer


def test_version_is_exposed() -> None:
    assert probectl_analyzer.__version__
    assert isinstance(probectl_analyzer.__version__, str)
