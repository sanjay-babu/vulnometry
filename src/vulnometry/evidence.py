"""Evidence files: every feed response a run used, so the run can be reproduced exactly.

Feeds move: EPSS is re-scored daily, CISA KEV grows, exploit repositories appear. A run made
with ``VULNOMETRY_EVIDENCE_RECORD=path`` writes each response it used to ``path`` (SQLite), with
the run's timestamp. A later run with ``VULNOMETRY_EVIDENCE_REPLAY=path`` answers every request
from that file and never touches the network, and dates its findings and due dates from the
recorded run. Same scanner export, same inventory, same model version and same evidence give
the same result.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import settings


class Evidence:
    def __init__(self, path: Path, replaying: bool):
        self.path = Path(path)
        self.replaying = replaying
        self._lock = asyncio.Lock()
        if replaying and not self.path.is_file():
            raise FileNotFoundError(f"evidence file to replay not found: {self.path}")
        if not replaying:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.unlink(missing_ok=True)  # one file per run, never a mix of two
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("CREATE TABLE IF NOT EXISTS evidence (key TEXT PRIMARY KEY, source TEXT, body TEXT)")
        self._conn.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
        if not replaying:
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._conn.execute("INSERT OR REPLACE INTO meta VALUES ('recorded_at', ?)", (stamp,))
        self._conn.commit()
        row = self._conn.execute("SELECT v FROM meta WHERE k = 'recorded_at'").fetchone()
        self.recorded_at = row[0] if row else datetime.now(timezone.utc).isoformat(timespec="seconds")

    async def get(self, key: str) -> tuple[bool, Any]:
        async with self._lock:
            row = self._conn.execute("SELECT body FROM evidence WHERE key = ?", (key,)).fetchone()
        return (False, None) if row is None else (True, json.loads(row[0]))

    async def put(self, key: str, source: str, payload: Any) -> None:
        async with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO evidence VALUES (?, ?, ?)",
                               (key, source, json.dumps(payload, sort_keys=True)))
            self._conn.commit()


_store: Evidence | None = None
_opened = False


def evidence() -> Evidence | None:
    """The run's evidence file, if recording or replaying, else None."""
    global _store, _opened
    if not _opened:
        _opened = True
        cfg = settings()
        if cfg.evidence_replay:
            _store = Evidence(Path(cfg.evidence_replay), replaying=True)
        elif cfg.evidence_record:
            _store = Evidence(Path(cfg.evidence_record), replaying=False)
    return _store


def reset() -> None:
    """Forget the open evidence file (tests, and a second run in one process)."""
    global _store, _opened
    _store, _opened = None, False


def run_timestamp() -> str | None:
    """The fixed timestamp of a recorded or replayed run; None for an ordinary run."""
    store = evidence()
    return store.recorded_at if store else None


def run_date():
    """The date a run counts from: the recorded run's date when replaying, else today."""
    from datetime import date

    stamp = run_timestamp()
    return date.fromisoformat(stamp[:10]) if stamp else date.today()
