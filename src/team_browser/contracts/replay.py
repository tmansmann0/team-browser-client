"""SQLite replay guard for an already-approved private local database.

The caller supplies a connection factory backed by its secure workspace store.
This module does not select filesystem paths, create device credentials, store
cookies, or relax file permissions. Each operation needs a fresh connection.
"""

from __future__ import annotations

from datetime import datetime
import sqlite3
from typing import Callable

from .bootstrap import BootstrapRejected, _aware, _id


class SQLiteReplayGuard:
    def __init__(self, connections: Callable[[], sqlite3.Connection]):
        self._connections = connections
        connection = self._connections()
        try:
            connection.execute("""CREATE TABLE IF NOT EXISTS bootstrap_replay_v1 (
                organization_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                command_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (organization_id, device_id, command_id)
            )""")
            connection.commit()
        finally:
            connection.close()

    def consume(
        self, organization_id: str, device_id: str, command_id: str, expires_at: datetime
    ) -> bool:
        for value in (organization_id, device_id, command_id):
            _id(value)
        expires = _aware(expires_at).isoformat()
        connection = self._connections()
        try:
            # Commit before returning plaintext permission. SQLite serializes the
            # write; the compound primary key makes competing consumers exclusive.
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                """INSERT INTO bootstrap_replay_v1
                (organization_id, device_id, command_id, expires_at) VALUES (?, ?, ?, ?)
                ON CONFLICT (organization_id, device_id, command_id) DO NOTHING""",
                (organization_id, device_id, command_id, expires),
            )
            consumed = result.rowcount == 1
            connection.commit()
            return consumed
        except sqlite3.Error as exc:
            connection.rollback()
            raise BootstrapRejected("Bootstrap replay ledger is unavailable") from exc
        finally:
            connection.close()
