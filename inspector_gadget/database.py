"""
inspector_gadget - database.py
SQLite database layer. Handles schema creation, inserts, queries, and
all persistent state for clusters, sessions, and artifacts.
"""

import sqlite3
import threading
import logging
from contextlib import contextmanager
from datetime import datetime

import config

logger = logging.getLogger("inspector_gadget.database")


class Database:
    """Thread-safe SQLite database wrapper for Inspector Gadget."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or config.DB_PATH
        self._local = threading.local()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    @contextmanager
    def transaction(self):
        """Context manager for a database transaction."""
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_schema(self):
        """Create all tables and indices if they don't exist."""
        conn = self._get_conn()
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        logger.info("Database schema initialized at %s", self.db_path)

    # ------------------------------------------------------------------
    # Ingestion tracking
    # ------------------------------------------------------------------

    def get_ingested_file(self, file_path: str) -> dict | None:
        """Return ingested file record or None if not yet ingested."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM ingested_files WHERE file_path = ?", (file_path,)
        ).fetchone()
        return dict(row) if row else None

    def upsert_ingested_file(self, file_path: str, line_count: int):
        """Mark a log file as ingested up to line_count."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO ingested_files (file_path, line_count, ingested_at)
               VALUES (?, ?, ?)
               ON CONFLICT(file_path) DO UPDATE SET
                 line_count = excluded.line_count,
                 ingested_at = excluded.ingested_at""",
            (file_path, line_count, _now()),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Session operations
    # ------------------------------------------------------------------

    def insert_session(self, session_id: str, src_ip: str, src_port: int,
                       dst_port: int, start_time: str, log_file: str,
                       end_time: str = None) -> bool:
        """Insert a new session. Returns False if it already exists."""
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO sessions
                   (session_id, src_ip, src_port, dst_port, start_time,
                    end_time, log_file, ingested_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, src_ip, src_port, dst_port, start_time,
                 end_time, log_file, _now()),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # already exists

    def update_session_end(self, session_id: str, end_time: str):
        """Update the end_time of an existing session."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE sessions SET end_time = ? WHERE session_id = ?",
            (end_time, session_id),
        )
        conn.commit()

    def update_session_cmd_hash(self, session_id: str, cmd_hash: str):
        """Set the command-sequence hash for a session."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE sessions SET cmd_sequence_hash = ? WHERE session_id = ?",
            (cmd_hash, session_id),
        )
        conn.commit()

    def assign_cluster(self, session_id: str, cluster_id: int):
        """Assign a session to a cluster."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE sessions SET cluster_id = ? WHERE session_id = ?",
            (cluster_id, session_id),
        )
        conn.commit()

    def get_session(self, session_id: str) -> dict | None:
        """Retrieve a single session by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_unassigned_sessions(self) -> list[dict]:
        """Return all sessions without a cluster assignment."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM sessions WHERE cluster_id IS NULL"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_cluster_sessions(self, cluster_id: int) -> list[dict]:
        """Return all sessions belonging to a cluster."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM sessions WHERE cluster_id = ?", (cluster_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # SSH keys
    # ------------------------------------------------------------------

    def insert_ssh_key(self, session_id: str, fingerprint: str,
                       key_type: str = None):
        """Insert an SSH key observation."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO ssh_keys (session_id, fingerprint, key_type)
               VALUES (?, ?, ?)""",
            (session_id, fingerprint, key_type),
        )
        conn.commit()

    def find_sessions_by_fingerprint(self, fingerprint: str) -> list[str]:
        """Return session IDs that used a given SSH key fingerprint."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT session_id FROM ssh_keys WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchall()
        return [r["session_id"] for r in rows]

    def get_fingerprints_for_session(self, session_id: str) -> list[str]:
        """Return all fingerprints observed in a session."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT fingerprint FROM ssh_keys WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        return [r["fingerprint"] for r in rows]

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------

    def insert_credential(self, session_id: str, username: str,
                          password: str, success: bool = False):
        """Insert a login attempt."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO credentials (session_id, username, password, success)
               VALUES (?, ?, ?, ?)""",
            (session_id, username, password, int(success)),
        )
        conn.commit()

    def find_sessions_by_password(self, password: str) -> list[str]:
        """Return session IDs where a specific password was used."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT session_id FROM credentials WHERE password = ?",
            (password,),
        ).fetchall()
        return [r["session_id"] for r in rows]

    def get_passwords_for_session(self, session_id: str) -> list[str]:
        """Return all unique passwords attempted in a session."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT password FROM credentials WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        return [r["password"] for r in rows]

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def insert_command(self, session_id: str, timestamp: str, cmd_input: str):
        """Insert a command executed in a session."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO commands (session_id, timestamp, input)
               VALUES (?, ?, ?)""",
            (session_id, timestamp, cmd_input),
        )
        conn.commit()

    def get_commands_for_session(self, session_id: str) -> list[dict]:
        """Return all commands for a session, ordered by timestamp."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM commands WHERE session_id = ?
               ORDER BY timestamp ASC""",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def find_sessions_by_cmd_hash(self, cmd_hash: str) -> list[str]:
        """Return session IDs with a matching command-sequence hash."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT session_id FROM sessions WHERE cmd_sequence_hash = ?",
            (cmd_hash,),
        ).fetchall()
        return [r["session_id"] for r in rows]

    def find_sessions_by_command_text(self, search_text: str) -> list[str]:
        """Return session IDs where any command contains the search text."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT session_id FROM commands WHERE input LIKE ?",
            (f"%{search_text}%",),
        ).fetchall()
        return [r["session_id"] for r in rows]

    # ------------------------------------------------------------------
    # Downloads
    # ------------------------------------------------------------------

    def insert_download(self, session_id: str, url: str = None,
                        sha256: str = None, filename: str = None):
        """Insert a file download event."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO downloads (session_id, url, sha256, filename)
               VALUES (?, ?, ?, ?)""",
            (session_id, url, sha256, filename),
        )
        conn.commit()

    def find_sessions_by_sha256(self, sha256: str) -> list[str]:
        """Return session IDs that downloaded a file with this hash."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT session_id FROM downloads WHERE sha256 = ?",
            (sha256,),
        ).fetchall()
        return [r["session_id"] for r in rows]

    def get_downloads_for_session(self, session_id: str) -> list[dict]:
        """Return all downloads for a session."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM downloads WHERE session_id = ?", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # IP-based session lookup (with time window)
    # ------------------------------------------------------------------

    def find_sessions_by_ip_timewindow(self, src_ip: str,
                                        ref_time: str,
                                        window_seconds: int = None
                                        ) -> list[str]:
        """
        Return session IDs from the same IP within a time window
        around ref_time. Used for IP-based BFS linking.
        """
        window = window_seconds or config.IP_LINK_WINDOW
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT session_id FROM sessions
               WHERE src_ip = ?
                 AND ABS(strftime('%%s', start_time) - strftime('%%s', ?)) <= ?""",
            (src_ip, ref_time, window),
        ).fetchall()
        return [r["session_id"] for r in rows]

    # ------------------------------------------------------------------
    # Clusters
    # ------------------------------------------------------------------

    def create_cluster(self, name: str, description: str = None) -> int:
        """Create a new cluster and return its ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO clusters (name, created_at, description)
               VALUES (?, ?, ?)""",
            (name, _now(), description),
        )
        conn.commit()
        return cursor.lastrowid

    def get_cluster_by_name(self, name: str) -> dict | None:
        """Look up a cluster by name."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM clusters WHERE name = ?", (name,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_clusters(self) -> list[dict]:
        """Return all clusters."""
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM clusters").fetchall()
        return [dict(r) for r in rows]

    def get_cluster_session_count(self, cluster_id: int) -> int:
        """Return the number of sessions in a cluster."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM sessions WHERE cluster_id = ?",
            (cluster_id,),
        ).fetchone()
        return row["cnt"]

    def delete_cluster(self, cluster_id: int):
        """Delete a cluster and unassign all its sessions."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE sessions SET cluster_id = NULL WHERE cluster_id = ?",
            (cluster_id,),
        )
        conn.execute("DELETE FROM seeds WHERE cluster_id = ?", (cluster_id,))
        conn.execute("DELETE FROM clusters WHERE id = ?", (cluster_id,))
        conn.commit()

    # ------------------------------------------------------------------
    # Seeds
    # ------------------------------------------------------------------

    def add_seed(self, cluster_id: int, seed_type: str, seed_value: str):
        """Add a seed to a cluster."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO seeds (cluster_id, seed_type, seed_value, added_at)
               VALUES (?, ?, ?, ?)""",
            (cluster_id, seed_type, seed_value, _now()),
        )
        conn.commit()

    def get_seeds(self, cluster_id: int) -> list[dict]:
        """Return all seeds for a cluster."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM seeds WHERE cluster_id = ?", (cluster_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_seeds(self) -> list[dict]:
        """Return all seeds across all clusters."""
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM seeds").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Statistics (for reports)
    # ------------------------------------------------------------------

    def count_total_sessions(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM sessions").fetchone()
        return row["cnt"]

    def count_unassigned_sessions(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM sessions WHERE cluster_id IS NULL"
        ).fetchone()
        return row["cnt"]

    def get_unique_ips_for_cluster(self, cluster_id: int) -> list[str]:
        """Return unique source IPs in a cluster."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT src_ip FROM sessions WHERE cluster_id = ?",
            (cluster_id,),
        ).fetchall()
        return [r["src_ip"] for r in rows]

    def get_unique_passwords_for_cluster(self, cluster_id: int) -> list[str]:
        """Return unique passwords used across a cluster."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT DISTINCT c.password FROM credentials c
               JOIN sessions s ON c.session_id = s.session_id
               WHERE s.cluster_id = ?""",
            (cluster_id,),
        ).fetchall()
        return [r["password"] for r in rows]

    def get_unique_fingerprints_for_cluster(self, cluster_id: int) -> list[str]:
        """Return unique SSH key fingerprints in a cluster."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT DISTINCT k.fingerprint FROM ssh_keys k
               JOIN sessions s ON k.session_id = s.session_id
               WHERE s.cluster_id = ?""",
            (cluster_id,),
        ).fetchall()
        return [r["fingerprint"] for r in rows]

    def get_unique_downloads_for_cluster(self, cluster_id: int) -> list[dict]:
        """Return unique downloads in a cluster."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT DISTINCT d.sha256, d.url, d.filename FROM downloads d
               JOIN sessions s ON d.session_id = s.session_id
               WHERE s.cluster_id = ?""",
            (cluster_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_cluster_time_range(self, cluster_id: int) -> dict | None:
        """Return earliest and latest session times for a cluster."""
        conn = self._get_conn()
        row = conn.execute(
            """SELECT MIN(start_time) as first_seen,
                      MAX(start_time) as last_seen
               FROM sessions WHERE cluster_id = ?""",
            (cluster_id,),
        ).fetchone()
        if row and row["first_seen"]:
            return {"first_seen": row["first_seen"], "last_seen": row["last_seen"]}
        return None

    def get_top_unassigned_ips(self, limit: int = 10) -> list[dict]:
        """Return top IPs from unassigned sessions by frequency."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT src_ip, COUNT(*) as cnt FROM sessions
               WHERE cluster_id IS NULL
               GROUP BY src_ip ORDER BY cnt DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_top_unassigned_passwords(self, limit: int = 10) -> list[dict]:
        """Return top passwords from unassigned sessions."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT c.password, COUNT(DISTINCT c.session_id) as cnt
               FROM credentials c
               JOIN sessions s ON c.session_id = s.session_id
               WHERE s.cluster_id IS NULL AND c.password != ''
               GROUP BY c.password ORDER BY cnt DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_sessions_since(self, since: str, cluster_id: int = None) -> list[dict]:
        """Return sessions since a given ISO timestamp, optionally filtered."""
        conn = self._get_conn()
        if cluster_id is not None:
            rows = conn.execute(
                """SELECT * FROM sessions
                   WHERE start_time >= ? AND cluster_id = ?""",
                (since, cluster_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE start_time >= ?", (since,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_db_size_mb(self) -> float:
        """Return database file size in megabytes."""
        import os
        try:
            return os.path.getsize(self.db_path) / (1024 * 1024)
        except OSError:
            return 0.0


def _now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------
# Schema SQL
# ------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id        TEXT PRIMARY KEY,
    src_ip            TEXT NOT NULL,
    src_port          INTEGER,
    dst_port          INTEGER,
    start_time        TEXT NOT NULL,
    end_time          TEXT,
    cluster_id        INTEGER REFERENCES clusters(id),
    cmd_sequence_hash TEXT,
    log_file          TEXT NOT NULL,
    ingested_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    fingerprint  TEXT NOT NULL,
    key_type     TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    username     TEXT,
    password     TEXT,
    success      INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commands (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    timestamp    TEXT NOT NULL,
    input        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS downloads (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    url          TEXT,
    sha256       TEXT,
    filename     TEXT
);

CREATE TABLE IF NOT EXISTS clusters (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT UNIQUE NOT NULL,
    created_at   TEXT NOT NULL,
    description  TEXT
);

CREATE TABLE IF NOT EXISTS seeds (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id   INTEGER NOT NULL REFERENCES clusters(id),
    seed_type    TEXT NOT NULL,
    seed_value   TEXT NOT NULL,
    added_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingested_files (
    file_path    TEXT PRIMARY KEY,
    line_count   INTEGER NOT NULL,
    ingested_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_ip       ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_cluster   ON sessions(cluster_id);
CREATE INDEX IF NOT EXISTS idx_sessions_start     ON sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_sessions_cmd_hash  ON sessions(cmd_sequence_hash);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_fp        ON ssh_keys(fingerprint);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_session   ON ssh_keys(session_id);
CREATE INDEX IF NOT EXISTS idx_credentials_pw     ON credentials(password);
CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_id);
CREATE INDEX IF NOT EXISTS idx_downloads_sha      ON downloads(sha256);
CREATE INDEX IF NOT EXISTS idx_downloads_session   ON downloads(session_id);
CREATE INDEX IF NOT EXISTS idx_commands_session    ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_seeds_cluster       ON seeds(cluster_id);
"""
