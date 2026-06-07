"""U-094: coverage for the core paths the original suite skipped — the CLI
entry point end-to-end, the RPKI VRP URL fetch (success + graceful degrade),
the JSONL sink contract, and the RIS Live client's subscribe/reconnect logic.
"""

from __future__ import annotations

import io
import json
import sys
import types

import pytest

from probectl_analyzer.__main__ import main
from probectl_analyzer.config import AnalyzerConfig
from probectl_analyzer.emit import JsonlSink
from probectl_analyzer.events import BGPEvent, EventType, RPKIStatus, Severity
from probectl_analyzer.pipeline import load_vrp
from probectl_analyzer.rislive import RISLiveClient

HIJACK_MESSAGE = {
    "type": "ris_message",
    "data": {
        "type": "UPDATE",
        "timestamp": 1700000000.0,
        "peer": "192.0.2.1",
        "peer_asn": "64511",
        "host": "rrc00",
        "path": [64511, 64500, 65551],  # origin 65551 != expected 64496
        "announcements": [{"next_hop": "192.0.2.1", "prefixes": ["192.0.2.0/24"]}],
        "withdrawals": [],
    },
}


def write_config(tmp_path, **overrides):
    cfg = {
        "tenant_id": "t-test",
        "monitored_prefixes": [{"prefix": "192.0.2.0/24", "expected_origins": [64496]}],
    }
    cfg.update(overrides)
    p = tmp_path / "config.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return str(p)


# ── CLI end-to-end (replay source → JSONL out) ──────────────────────────────


def test_cli_replay_writes_events(tmp_path):
    replay = tmp_path / "capture.jsonl"
    replay.write_text(json.dumps(HIJACK_MESSAGE) + "\n", encoding="utf-8")
    out = tmp_path / "events.jsonl"

    rc = main(["--config", write_config(tmp_path), "--replay", str(replay), "--out", str(out)])

    assert rc == 0
    lines = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert lines, "an unexpected-origin announcement must emit at least one event"
    assert any(ev["prefix"] == "192.0.2.0/24" for ev in lines)
    assert all(ev["tenant_id"] == "t-test" for ev in lines), "every event is tenant-stamped"


def test_cli_requires_a_source(tmp_path):
    with pytest.raises(SystemExit):
        main(["--config", write_config(tmp_path)])  # no --mrt/--replay/--ris-live


# ── RPKI VRP loading via URL (success + degrade, guardrail 10) ──────────────


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_load_vrp_from_url(monkeypatch, tmp_path):
    body = json.dumps(
        {"roas": [{"prefix": "192.0.2.0/24", "asn": "AS64496", "maxLength": 24}]}
    ).encode()
    monkeypatch.setattr(
        "probectl_analyzer.pipeline.urllib.request.urlopen",
        lambda req, timeout, context: _FakeResponse(body),
    )
    cfg = AnalyzerConfig.from_file(write_config(tmp_path, rpki_vrp_url="https://rpki.example/vrp"))
    vrp = load_vrp(cfg)
    assert vrp is not None and len(vrp) == 1


def test_load_vrp_url_failure_degrades_to_none(monkeypatch, tmp_path):
    def boom(req, timeout, context):
        raise OSError("validator unreachable")

    monkeypatch.setattr("probectl_analyzer.pipeline.urllib.request.urlopen", boom)
    cfg = AnalyzerConfig.from_file(write_config(tmp_path, rpki_vrp_url="https://rpki.example/vrp"))
    assert load_vrp(cfg) is None, "a down validator must degrade to unknown, not break analysis"


def test_load_vrp_no_source_is_none(tmp_path):
    assert load_vrp(AnalyzerConfig.from_file(write_config(tmp_path))) is None


# ── JSONL sink contract (one event per line, flushed) ───────────────────────


def test_jsonl_sink_writes_one_line_per_event():
    buf = io.StringIO()
    sink = JsonlSink(buf)
    ev = BGPEvent(
        tenant_id="t-test",
        event_type=EventType.POSSIBLE_HIJACK,
        prefix="192.0.2.0/24",
        severity=Severity.CRITICAL,
        rpki_status=RPKIStatus.UNKNOWN,
        message="test",
    )
    sink.emit(ev)
    sink.emit(ev)
    lines = buf.getvalue().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["prefix"] == "192.0.2.0/24"


# ── RIS Live client: subscriptions + the reconnect/backoff loop ─────────────


def test_subscribe_messages_per_prefix_with_host():
    c = RISLiveClient(host="rrc00", prefixes=["192.0.2.0/24", "198.51.100.0/24"])
    msgs = [json.loads(m) for m in c._subscribe_messages()]
    assert len(msgs) == 2
    assert all(m["type"] == "ris_subscribe" for m in msgs)
    assert {m["data"]["prefix"] for m in msgs} == {"192.0.2.0/24", "198.51.100.0/24"}
    assert all(m["data"]["host"] == "rrc00" for m in msgs)


def test_subscribe_messages_firehose_without_prefixes():
    msgs = [json.loads(m) for m in RISLiveClient()._subscribe_messages()]
    assert len(msgs) == 1
    assert "prefix" not in msgs[0]["data"]


class _FakeWS:
    """One connection: accepts subscriptions, yields canned messages, then EOF."""

    def __init__(self, messages):
        self._messages = messages
        self.sent = []

    def send(self, m):
        self.sent.append(m)

    def __iter__(self):
        return iter(self._messages)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_messages_reconnects_with_backoff(monkeypatch):
    """First connect dies mid-stream; the client backs off and reconnects."""
    raw = json.dumps(HIJACK_MESSAGE)
    attempts = []

    def fake_connect(url):
        attempts.append(url)
        if len(attempts) == 1:
            raise ConnectionError("first attempt refused")
        return _FakeWS([raw, raw])

    fake_mod = types.ModuleType("websockets")
    fake_sync = types.ModuleType("websockets.sync")
    fake_client = types.ModuleType("websockets.sync.client")
    fake_client.connect = fake_connect
    fake_mod.sync = fake_sync
    fake_sync.client = fake_client
    monkeypatch.setitem(sys.modules, "websockets", fake_mod)
    monkeypatch.setitem(sys.modules, "websockets.sync", fake_sync)
    monkeypatch.setitem(sys.modules, "websockets.sync.client", fake_client)

    naps = []
    monkeypatch.setattr("probectl_analyzer.rislive.time.sleep", lambda s: naps.append(s))

    client = RISLiveClient(url="wss://example.test/ris", max_backoff=4.0)
    it = client.messages()
    assert next(it) == raw
    assert next(it) == raw
    assert len(attempts) == 2, "must reconnect after the refused first attempt"
    assert naps == [1.0], "one backoff nap after the first failure"
