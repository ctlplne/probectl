"""Smoke test proving the analyzer test harness and CI are wired (S0)."""

import probectl_analyzer


def test_version_is_exposed() -> None:
    assert probectl_analyzer.__version__
    assert isinstance(probectl_analyzer.__version__, str)
