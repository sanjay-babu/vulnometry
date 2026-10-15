import pytest


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNOMETRY_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("VULNOMETRY_INVENTORY", raising=False)
    monkeypatch.delenv("VULNOMETRY_EVIDENCE_RECORD", raising=False)
    monkeypatch.delenv("VULNOMETRY_EVIDENCE_REPLAY", raising=False)
    from vulnometry import config, evidence, net

    config.reset_settings()
    evidence.reset()
    net._cache = None
    net._buckets = None
    yield
    config.reset_settings()
    evidence.reset()
    net._cache = None
