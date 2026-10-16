"""Durable, incremental storage for server-owned audit runs.

Standard-library :mod:`sqlite3`, because a local workbench should not take a
database dependency to remember what it did. Three tables:

``runs``       one row per run: its reviewed, credential-free configuration, a
               live snapshot for the UI to poll, and the export-shaped record.
``exchanges``  one row per dispatched request, written *before* the request
               leaves and updated once its outcome is known. A row still marked
               ``dispatched`` after the process ends is the honest signature of
               an interrupted run: the request was sent, its outcome is unknown,
               and it is never re-sent.
``cases``      one row per completed operation or inventory sweep, holding the
               fully-redacted result the engine produced.

Everything written here is already redacted by the engine's existing paths
(:meth:`Exchange.to_dict`, ``redact_evidence``); no credential ever reaches a
row, a log line or an export. Executing runs hold credential values in memory;
optional encrypted profile storage is handled separately by the desktop vault.
An interrupted run is never silently resumed: it must be reviewed and
authorised again even when its identity profile remains available.

Writes are serialised under one lock over a single WAL connection, because a
run fans its probes across worker threads that all record receipts here.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path

RETENTION_DEFAULT = 100
SCHEMA_VERSION = 1


def default_db_path() -> Path:
    """Where runs live. Overridable for tests and for operators who relocate it."""
    from ..desktop_state import data_paths, desktop_enabled
    if desktop_enabled():
        return data_paths().runs_db
    env = os.environ.get("NAMAZU_STATE_DIR")
    base = Path(env) if env else Path.home() / ".namazu"
    return base / "runs.db"


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


class RunStore:
    """One SQLite file holding every retained run."""

    def __init__(self, path: str | Path | None = None, *, retention: int | None = None) -> None:
        self.path = Path(path) if path else default_db_path()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention = int(os.environ.get("NAMAZU_RUN_RETENTION", retention or RETENTION_DEFAULT))
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SCHEMA_VERSION):
            self._conn.close()
            raise ValueError("The run database uses an unsupported schema version; upgrade Namazu before opening it.")
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs(
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT, updated_at TEXT,
                    status TEXT, phase TEXT, kind TEXT,
                    revision INTEGER DEFAULT 0,
                    interrupted INTEGER DEFAULT 0,
                    title TEXT, target TEXT,
                    config_json TEXT, snapshot_json TEXT, export_json TEXT
                );
                CREATE TABLE IF NOT EXISTS exchanges(
                    run_id TEXT, exchange_id TEXT, case_id TEXT, seq INTEGER,
                    state TEXT, mutating INTEGER,
                    dispatched_at TEXT, settled_at TEXT,
                    method TEXT, label TEXT, record_json TEXT,
                    PRIMARY KEY(run_id, exchange_id)
                );
                CREATE INDEX IF NOT EXISTS exchanges_by_run ON exchanges(run_id, seq);
                CREATE TABLE IF NOT EXISTS cases(
                    run_id TEXT, case_id TEXT, seq INTEGER,
                    operation TEXT, scope TEXT, status TEXT,
                    updated_at TEXT, result_json TEXT,
                    PRIMARY KEY(run_id, case_id)
                );
                """
            )
            self._conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    # -- run rows ---------------------------------------------------------

    def create_run(self, run_id: str, *, created_at: str, status: str, phase: str,
                   kind: str, title: str, target: str, config: dict, snapshot: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO runs(run_id, created_at, updated_at, status, phase, kind, revision,"
                " interrupted, title, target, config_json, snapshot_json, export_json)"
                " VALUES(?,?,?,?,?,?,1,0,?,?,?,?,?)",
                (run_id, created_at, created_at, status, phase, kind, title, target,
                 _json(config), _json(snapshot), _json(None)),
            )
        self._prune()

    def update_run(self, run_id: str, *, updated_at: str, status: str | None = None,
                   phase: str | None = None, interrupted: bool | None = None,
                   snapshot: dict | None = None, export: dict | None = None) -> int:
        """Apply changes and bump the revision. Returns the new revision."""
        with self._lock, self._conn:
            row = self._conn.execute("SELECT revision FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                return 0
            revision = int(row["revision"]) + 1
            sets = ["updated_at=?", "revision=?"]
            params: list = [updated_at, revision]
            for column, value in (("status=?", status), ("phase=?", phase),
                                  ("interrupted=?", None if interrupted is None else (1 if interrupted else 0)),
                                  ("snapshot_json=?", None if snapshot is None else _json(snapshot)),
                                  ("export_json=?", None if export is None else _json(export))):
                include = value is not None if column != "interrupted=?" else interrupted is not None
                if include:
                    sets.append(column)
                    params.append(value)
            params.append(run_id)
            self._conn.execute(f"UPDATE runs SET {', '.join(sets)} WHERE run_id=?", params)
            return revision

    def get_run(self, run_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return self._run_row(row) if row else None

    def list_runs(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT run_id, created_at, updated_at, status, phase, kind, revision,"
                " interrupted, title, target FROM runs ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_run(self, run_id: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM runs WHERE run_id=?", (run_id,))
            self._conn.execute("DELETE FROM exchanges WHERE run_id=?", (run_id,))
            self._conn.execute("DELETE FROM cases WHERE run_id=?", (run_id,))
            return cur.rowcount > 0

    def delete_all(self) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM runs")
            self._conn.execute("DELETE FROM exchanges")
            self._conn.execute("DELETE FROM cases")
            return cur.rowcount

    def _run_row(self, row: sqlite3.Row) -> dict:
        out = dict(row)
        for key in ("config_json", "snapshot_json", "export_json"):
            raw = out.pop(key)
            out[key[:-5]] = json.loads(raw) if raw else None
        return out

    # -- exchanges (durable receipts) ------------------------------------

    def dispatch_exchange(self, run_id: str, case_id: str, exchange_id: str, seq: int,
                          *, dispatched_at: str, method: str, label: str,
                          mutating: bool, record: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO exchanges(run_id, exchange_id, case_id, seq, state,"
                " mutating, dispatched_at, settled_at, method, label, record_json)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, exchange_id, case_id, seq, "dispatched", 1 if mutating else 0,
                 dispatched_at, None, method, label, _json(record)),
            )

    def settle_exchange(self, run_id: str, exchange_id: str, *, settled_at: str,
                        outcome: str, record: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE exchanges SET state=?, settled_at=?, record_json=? WHERE run_id=? AND exchange_id=?",
                (outcome or "responded", settled_at, _json(record), run_id, exchange_id),
            )

    def exchanges(self, run_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT exchange_id, case_id, seq, state, mutating, dispatched_at, settled_at,"
                " method, label, record_json FROM exchanges WHERE run_id=? ORDER BY seq", (run_id,)
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["record"] = json.loads(item.pop("record_json")) if item["record_json"] else None
            out.append(item)
        return out

    def dispatched_unsettled(self, run_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM exchanges WHERE run_id=? AND state='interrupted-unknown'", (run_id,)
            ).fetchone()
        return int(row["n"]) if row else 0

    # -- cases ------------------------------------------------------------

    def save_case(self, run_id: str, case_id: str, seq: int, *, operation: str, scope: str,
                  status: str, updated_at: str, result: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO cases(run_id, case_id, seq, operation, scope, status,"
                " updated_at, result_json) VALUES(?,?,?,?,?,?,?,?)",
                (run_id, case_id, seq, operation, scope, status, updated_at, _json(result)),
            )

    def cases(self, run_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT case_id, seq, operation, scope, status, result_json FROM cases"
                " WHERE run_id=? ORDER BY seq", (run_id,)
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["result"] = json.loads(item.pop("result_json")) if item["result_json"] else None
            out.append(item)
        return out

    # -- lifecycle --------------------------------------------------------

    def mark_interrupted_on_start(self) -> list[str]:
        """Any run still 'running' or 'starting' when the process restarts was
        interrupted. Mark it, and turn every still-dispatched request into an
        honest 'interrupted-unknown'. Nothing here re-sends anything."""
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT run_id FROM runs WHERE status IN ('starting','running')"
            ).fetchall()
            ids = [row["run_id"] for row in rows]
            if ids:
                marks = ",".join("?" for _ in ids)
                self._conn.execute(
                    f"UPDATE runs SET status='interrupted', interrupted=1 WHERE run_id IN ({marks})", ids)
            self._conn.execute(
                "UPDATE exchanges SET state='interrupted-unknown' WHERE state='dispatched'")
        return ids

    def _prune(self) -> None:
        if self.retention <= 0:
            return
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT run_id FROM runs ORDER BY created_at DESC LIMIT -1 OFFSET ?", (self.retention,)
            ).fetchall()
            for row in rows:
                run_id = row["run_id"]
                self._conn.execute("DELETE FROM runs WHERE run_id=?", (run_id,))
                self._conn.execute("DELETE FROM exchanges WHERE run_id=?", (run_id,))
                self._conn.execute("DELETE FROM cases WHERE run_id=?", (run_id,))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
