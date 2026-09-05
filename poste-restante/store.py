"""SQLite storage for the station.

Deliberately thin: no ORM, no migrations framework, one file on disk. A drop is
owned by an opaque cookie handle, never by a person -- there is no account, no
email, and no password to lose.
"""

import os
import secrets
import sqlite3
import threading
import time

# How many independent flags seal a drop from further pickups.
SEAL_THRESHOLD = 3

_ID_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alike glyphs

SCHEMA = """
CREATE TABLE IF NOT EXISTS drops (
    id            TEXT PRIMARY KEY,
    owner         TEXT NOT NULL,
    title         TEXT NOT NULL,
    body_src      TEXT NOT NULL,
    body_html     TEXT NOT NULL,
    css_src       TEXT NOT NULL,
    envelope_css  TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    sealed        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS drops_by_owner ON drops (owner, created_at DESC);

CREATE TABLE IF NOT EXISTS pickups (
    drop_id  TEXT NOT NULL,
    courier  TEXT NOT NULL,
    seen_at  INTEGER NOT NULL,
    PRIMARY KEY (drop_id, courier)
);

CREATE TABLE IF NOT EXISTS flags (
    drop_id    TEXT NOT NULL,
    reporter   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    flagged_at INTEGER NOT NULL,
    PRIMARY KEY (drop_id, reporter)
);
"""


def new_id(length=10):
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(length))


class Store:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()

    # -- drops ------------------------------------------------------------
    def create_drop(self, owner, title, body_src, body_html, css_src, envelope_css):
        with self._lock:
            for _ in range(8):
                drop_id = new_id()
                try:
                    self._conn.execute(
                        "INSERT INTO drops (id, owner, title, body_src, body_html,"
                        " css_src, envelope_css, created_at) VALUES (?,?,?,?,?,?,?,?)",
                        (drop_id, owner, title, body_src, body_html, css_src,
                         envelope_css, int(time.time())),
                    )
                    self._conn.commit()
                    return drop_id
                except sqlite3.IntegrityError:
                    continue  # id collision, draw again
            raise RuntimeError("could not allocate a drop id")

    def get_drop(self, drop_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM drops WHERE id = ?", (drop_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_drops(self, owner, limit=100):
        with self._lock:
            rows = self._conn.execute(
                "SELECT d.*, (SELECT COUNT(*) FROM pickups p WHERE p.drop_id = d.id)"
                " AS pickups FROM drops d WHERE d.owner = ?"
                " ORDER BY d.created_at DESC, d.id DESC LIMIT ?",
                (owner, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def count_recent_by_owner(self, owner, since):
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM drops WHERE owner = ? AND created_at >= ?",
                (owner, since),
            ).fetchone()
        return row["n"]

    # -- pickups ----------------------------------------------------------
    def record_pickup(self, drop_id, courier):
        """Log a distinct courier collecting the drop; return the pickup count."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO pickups (drop_id, courier, seen_at)"
                " VALUES (?,?,?)",
                (drop_id, courier, int(time.time())),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM pickups WHERE drop_id = ?", (drop_id,)
            ).fetchone()
        return row["n"]

    def count_pickups(self, drop_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM pickups WHERE drop_id = ?", (drop_id,)
            ).fetchone()
        return row["n"]

    # -- flags ------------------------------------------------------------
    def flag_drop(self, drop_id, reporter, reason):
        """Record one report per reporter; seal the drop once enough pile up."""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO flags (drop_id, reporter, reason, flagged_at)"
                " VALUES (?,?,?,?)",
                (drop_id, reporter, reason, int(time.time())),
            )
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM flags WHERE drop_id = ?", (drop_id,)
            ).fetchone()
            count = row["n"]
            sealed = count >= SEAL_THRESHOLD
            if sealed:
                self._conn.execute(
                    "UPDATE drops SET sealed = 1 WHERE id = ?", (drop_id,)
                )
            self._conn.commit()
        return count, sealed

    def has_flagged(self, drop_id, reporter):
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM flags WHERE drop_id = ? AND reporter = ?",
                (drop_id, reporter),
            ).fetchone()
        return row is not None

    def count_flags(self, drop_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM flags WHERE drop_id = ?", (drop_id,)
            ).fetchone()
        return row["n"]
