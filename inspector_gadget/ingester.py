"""
inspector_gadget - ingester.py
Daemon component that continuously reads Cowrie JSON log files,
parses events, and populates the database. Handles daily log rotation
and tracks read positions to avoid re-processing.
"""

import os
import json
import glob
import hashlib
import logging
import time
from datetime import datetime

import config
from database import Database

logger = logging.getLogger("inspector_gadget.ingester")

# Cowrie event types we care about
EVENT_SESSION_CONNECT = "cowrie.session.connect"
EVENT_SESSION_CLOSED = "cowrie.session.closed"
EVENT_LOGIN_SUCCESS = "cowrie.login.success"
EVENT_LOGIN_FAILED = "cowrie.login.failed"
EVENT_COMMAND_INPUT = "cowrie.command.input"
EVENT_COMMAND_FAILED = "cowrie.command.failed"
EVENT_SESSION_FILE_DOWNLOAD = "cowrie.session.file_download"
EVENT_SESSION_FILE_UPLOAD = "cowrie.session.file_upload"
EVENT_CLIENT_KEX = "cowrie.client.kex"
EVENT_CLIENT_KEY = "cowrie.client.fingerprint"
EVENT_DIRECT_TCPIP_REQUEST = "cowrie.direct-tcpip.request"


class Ingester:
    """
    Reads Cowrie JSON log files and inserts events into the database.
    Tracks file positions so it can resume after restart.
    """

    def __init__(self, db: Database):
        self.db = db
        self.log_dir = config.COWRIE_LOG_DIR
        # Track open file handles and their read positions for the active log
        self._file_positions: dict[str, int] = {}
        # Session data accumulated during ingestion (for cmd hash calculation)
        self._session_commands: dict[str, list[str]] = {}

    def run_once(self) -> int:
        """
        Scan log directory, process all new lines.
        Returns the number of new lines processed.
        """
        total_new = 0
        log_files = self._discover_log_files()

        for log_file in log_files:
            new_lines = self._process_file(log_file)
            total_new += new_lines

        # After processing all files, compute command-sequence hashes
        # for sessions that have accumulated enough commands
        self._compute_cmd_hashes()

        if total_new > 0:
            logger.info("Ingested %d new log lines across %d files",
                        total_new, len(log_files))
        return total_new

    def run_forever(self):
        """Run the ingester in an infinite loop with configurable interval."""
        logger.info("Ingester daemon started, polling every %ds", config.INGEST_INTERVAL)
        while True:
            try:
                self.run_once()
            except Exception:
                logger.exception("Error during ingestion cycle")
            time.sleep(config.INGEST_INTERVAL)

    def _discover_log_files(self) -> list[str]:
        """
        Find all Cowrie JSON log files in the log directory.
        Cowrie creates files like:
          - cowrie.json           (current day, actively written)
          - cowrie.json.2025-04-11 (rotated, complete)
          - cowrie.json.2025-04-10
        Returns sorted list (oldest first so we process chronologically).
        """
        pattern = os.path.join(self.log_dir, "cowrie.json*")
        files = glob.glob(pattern)

        # Sort: dated files first (chronologically), then the active 'cowrie.json' last
        def sort_key(f):
            basename = os.path.basename(f)
            if basename == "cowrie.json":
                return "9999-99-99"  # always last
            return basename

        files.sort(key=sort_key)
        return files

    def _process_file(self, file_path: str) -> int:
        """
        Process a single log file from where we last left off.
        Returns number of new lines processed.
        """
        record = self.db.get_ingested_file(file_path)
        last_line_count = record["line_count"] if record else 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as e:
            logger.error("Cannot read %s: %s", file_path, e)
            return 0

        current_count = len(lines)

        if current_count <= last_line_count:
            return 0  # no new lines

        # Process only new lines
        new_lines = lines[last_line_count:]
        processed = 0

        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                self._handle_event(event, file_path)
                processed += 1
            except json.JSONDecodeError:
                logger.debug("Skipping malformed JSON line in %s", file_path)
            except Exception:
                logger.exception("Error processing event in %s", file_path)

        # Update tracking
        self.db.upsert_ingested_file(file_path, current_count)
        return processed

    def _handle_event(self, event: dict, log_file: str):
        """Route a Cowrie event to the appropriate handler."""
        event_id = event.get("eventid", "")
        session_id = event.get("session", "")
        timestamp = event.get("timestamp", "")

        if not session_id:
            return

        if event_id == EVENT_SESSION_CONNECT:
            self._on_session_connect(event, log_file)

        elif event_id == EVENT_SESSION_CLOSED:
            self._on_session_closed(event)

        elif event_id in (EVENT_LOGIN_SUCCESS, EVENT_LOGIN_FAILED):
            self._on_login(event)

        elif event_id in (EVENT_COMMAND_INPUT, EVENT_COMMAND_FAILED):
            self._on_command(event)

        elif event_id in (EVENT_SESSION_FILE_DOWNLOAD, EVENT_SESSION_FILE_UPLOAD):
            self._on_download(event)

        elif event_id == EVENT_CLIENT_KEY:
            self._on_client_key(event)

    def _on_session_connect(self, event: dict, log_file: str):
        """Handle new SSH connection."""
        session_id = event["session"]
        src_ip = event.get("src_ip", "")
        src_port = event.get("src_port", 0)
        dst_port = event.get("dst_port", 0)
        timestamp = event.get("timestamp", "")

        self.db.insert_session(
            session_id=session_id,
            src_ip=src_ip,
            src_port=int(src_port) if src_port else 0,
            dst_port=int(dst_port) if dst_port else 0,
            start_time=timestamp,
            log_file=log_file,
        )

    def _on_session_closed(self, event: dict):
        """Handle session close - update end_time."""
        session_id = event["session"]
        timestamp = event.get("timestamp", "")
        self.db.update_session_end(session_id, timestamp)

    def _on_login(self, event: dict):
        """Handle login attempt (success or failure)."""
        session_id = event["session"]
        username = event.get("username", "")
        password = event.get("password", "")
        success = event.get("eventid") == EVENT_LOGIN_SUCCESS

        self.db.insert_credential(
            session_id=session_id,
            username=username,
            password=password,
            success=success,
        )

    def _on_command(self, event: dict):
        """Handle command execution."""
        session_id = event["session"]
        timestamp = event.get("timestamp", "")
        cmd_input = event.get("input", "")

        if not cmd_input:
            return

        self.db.insert_command(
            session_id=session_id,
            timestamp=timestamp,
            cmd_input=cmd_input,
        )

        # Accumulate for cmd hash calculation
        if session_id not in self._session_commands:
            self._session_commands[session_id] = []
        self._session_commands[session_id].append(cmd_input)

    def _on_download(self, event: dict):
        """Handle file download/upload."""
        session_id = event["session"]
        url = event.get("url", "")
        sha256 = event.get("shasum", "") or event.get("sha256", "")
        filename = event.get("destfile", "") or event.get("filename", "")

        if sha256 or url:
            self.db.insert_download(
                session_id=session_id,
                url=url,
                sha256=sha256,
                filename=filename,
            )

    def _on_client_key(self, event: dict):
        """Handle SSH client key fingerprint."""
        session_id = event["session"]
        fingerprint = event.get("fingerprint", "")
        key_type = event.get("key", "") or event.get("kexAlg", "")

        if fingerprint:
            self.db.insert_ssh_key(
                session_id=session_id,
                fingerprint=fingerprint,
                key_type=key_type,
            )

    def _compute_cmd_hashes(self):
        """
        Compute command-sequence hashes for sessions that have
        accumulated enough commands during this ingestion cycle.
        """
        min_cmds = config.MIN_CMD_SEQUENCE_LENGTH

        for session_id, commands in self._session_commands.items():
            if len(commands) < min_cmds:
                continue

            # Build deterministic hash: commands in execution order, joined by pipe
            sequence = "|".join(commands)
            cmd_hash = hashlib.sha256(sequence.encode("utf-8")).hexdigest()

            self.db.update_session_cmd_hash(session_id, cmd_hash)

        # Clear accumulated commands after processing
        self._session_commands.clear()

    def get_ingestion_status(self) -> dict:
        """Return current ingestion status for /status command."""
        log_files = self._discover_log_files()
        total_sessions = self.db.count_total_sessions()

        latest_file = log_files[-1] if log_files else "none"
        record = self.db.get_ingested_file(latest_file) if log_files else None

        return {
            "log_files_found": len(log_files),
            "latest_file": os.path.basename(latest_file),
            "latest_lines": record["line_count"] if record else 0,
            "total_sessions": total_sessions,
        }
