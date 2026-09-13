"""Durable SQLite store for the SPP v1 relay.

Persists the canonical signed bytes of accepted assertions and the relay-local
indexes derived from them. Storage is transactional and WAL-journaled. This
module performs no validation and never dereferences `ref`/`descriptor`
locators; the caller has already completed frozen §20 validation.
"""

from __future__ import annotations

import base64
import binascii
import re
import sqlite3
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = (HERE / "schema.sql").read_text(encoding="utf-8")

# §28: next is null or a string over the unpadded base64url alphabet.
_CURSOR_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class BadCursor(ValueError):
    """A cursor query value that is malformed transport input."""


def encode_cursor(seq: int) -> str:
    raw = base64.urlsafe_b64encode(str(seq).encode("ascii")).rstrip(b"=")
    return raw.decode("ascii")


def decode_cursor(token: str) -> int:
    if not _CURSOR_RE.fullmatch(token):
        raise BadCursor("cursor is not unpadded base64url")
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise BadCursor("cursor is not valid base64url") from exc
    try:
        seq = int(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BadCursor("cursor does not decode to an integer") from exc
    if seq < 0:
        raise BadCursor("cursor out of range")
    return seq


class Store:
    def __init__(self, db_path: str, page_size: int = 32) -> None:
        self.db_path = str(db_path)
        self.page_size = max(1, int(page_size))
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _initialize(self) -> None:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            # WAL is persistent on the database file; set it once here.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def add(
        self,
        *,
        ident: str,
        envelope: bytes,
        type_: str,
        actor: str,
        channel: str | None,
        object_hash: str | None,
    ) -> bool:
        """Persist an accepted assertion. Return True when newly inserted.

        Returns False for an idempotent re-submission. The assertion row, the
        advertised-channel row, and all derived indexes commit together.
        """
        accepted_at = int(time.time())
        conn = self._connect()
        try:
            with conn:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO assertions "
                    "(id, envelope, type, actor, channel, object_hash, accepted_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        ident,
                        sqlite3.Binary(envelope),
                        type_,
                        actor,
                        channel,
                        object_hash,
                        accepted_at,
                    ),
                )
                if cur.rowcount == 0:
                    return False
                if type_ == "channel":
                    conn.execute(
                        "INSERT OR IGNORE INTO advertised_channels "
                        "(channel, assertion_id) VALUES (?, ?)",
                        (ident, ident),
                    )
            return True
        finally:
            conn.close()

    def get_assertion(self, channel_hex: str) -> bytes | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT envelope FROM assertions WHERE id = ?",
                ("sha256:" + channel_hex,),
            ).fetchone()
            return bytes(row[0]) if row else None
        finally:
            conn.close()

    def _paginate(self, rows: list[tuple]) -> tuple[list[tuple], str | None]:
        more = len(rows) > self.page_size
        rows = rows[: self.page_size]
        nxt = encode_cursor(rows[-1][0]) if more and rows else None
        return rows, nxt

    def channel_assertions(
        self, channel_hex: str, after_seq: int
    ) -> tuple[list[bytes], str | None]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT seq, envelope FROM assertions "
                "WHERE channel = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
                ("sha256:" + channel_hex, after_seq, self.page_size + 1),
            ).fetchall()
        finally:
            conn.close()
        rows, nxt = self._paginate(rows)
        return [bytes(r[1]) for r in rows], nxt

    def object_assertions(
        self, object_hex: str, after_seq: int
    ) -> tuple[list[bytes], str | None]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT seq, envelope FROM assertions "
                "WHERE object_hash = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
                ("sha256:" + object_hex, after_seq, self.page_size + 1),
            ).fetchall()
        finally:
            conn.close()
        rows, nxt = self._paginate(rows)
        return [bytes(r[1]) for r in rows], nxt

    def advertised_channels(
        self, after_seq: int
    ) -> tuple[list[str], str | None]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT a.seq, a.id FROM advertised_channels ac "
                "JOIN assertions a ON a.id = ac.assertion_id "
                "WHERE a.seq > ? ORDER BY a.seq ASC LIMIT ?",
                (after_seq, self.page_size + 1),
            ).fetchall()
        finally:
            conn.close()
        rows, nxt = self._paginate(rows)
        return [r[1] for r in rows], nxt
