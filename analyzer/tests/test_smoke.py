"""Smoke test proving the analyzer test harness and CI are wired (S0)."""

import netctl_analyzer


def test_version_is_exposed() -> None:
    assert netctl_analyzer.__version__
    assert isinstance(netctl_analyzer.__version__, str)
