"""A recorded run can be replayed without the network and gives the same answers and dates."""

import asyncio

import pytest

from vulnometry import config, evidence, net


def _fresh(monkeypatch, **env):
    for key in ("VULNOMETRY_EVIDENCE_RECORD", "VULNOMETRY_EVIDENCE_REPLAY"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    config.reset_settings()
    evidence.reset()
    net._shared = None


def test_record_then_replay_answers_from_the_file_and_never_calls_out(tmp_path, monkeypatch):
    path = tmp_path / "evidence.sqlite3"
    calls = []

    async def live(self, method, url, **kw):
        calls.append(url)
        return {"epss": "0.01"} if "first" in url else None

    monkeypatch.setattr(net.Client, "_request_live", live)
    _fresh(monkeypatch, VULNOMETRY_EVIDENCE_RECORD=str(path))
    client = net.client()
    assert asyncio.run(client.get_json("https://api.first.org/x", source="epss")) == {"epss": "0.01"}
    assert asyncio.run(client.get_json("https://api.osv.dev/y", source="osv")) is None
    recorded_at = evidence.run_timestamp()
    assert len(calls) == 2 and recorded_at

    async def offline(self, method, url, **kw):
        raise AssertionError("a replay must not reach the network")

    monkeypatch.setattr(net.Client, "_request_live", offline)
    _fresh(monkeypatch, VULNOMETRY_EVIDENCE_REPLAY=str(path))
    client = net.client()
    assert asyncio.run(client.get_json("https://api.first.org/x", source="epss")) == {"epss": "0.01"}
    assert asyncio.run(client.get_json("https://api.osv.dev/y", source="osv")) is None, \
        "an empty answer is replayed as empty, not as missing"
    with pytest.raises(net.FeedError, match="not in the evidence file"):
        asyncio.run(client.get_json("https://api.github.com/z", source="github"))
    assert evidence.run_timestamp() == recorded_at, "the replay is dated from the recorded run"
    assert evidence.run_date().isoformat() == recorded_at[:10]


def test_a_missing_evidence_file_is_an_error_not_a_live_run(tmp_path, monkeypatch):
    _fresh(monkeypatch, VULNOMETRY_EVIDENCE_REPLAY=str(tmp_path / "nope.sqlite3"))
    with pytest.raises(FileNotFoundError):
        evidence.evidence()
