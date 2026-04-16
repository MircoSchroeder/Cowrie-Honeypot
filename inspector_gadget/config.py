"""
inspector_gadget - config.py
Central configuration. All values are overridable via environment variables
so no secrets or deployment-specific paths are baked into source.
"""

import os

# --- Telegram Bot ---
TELEGRAM_TOKEN = os.environ.get("IG_TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("IG_TELEGRAM_CHAT_ID", "")

# --- Cowrie Log Path ---
# Directory containing Cowrie JSON log files (cowrie.json, cowrie.json.YYYY-MM-DD, ...)
COWRIE_LOG_DIR = os.environ.get(
    "IG_COWRIE_LOG_DIR",
    "/path/to/cowrie/var/log/cowrie/",
)

# --- Database ---
DB_PATH = os.environ.get("IG_DB_PATH", "/opt/inspector_gadget/inspector_gadget.db")

# --- Ingester ---
# How often to poll for new log lines (seconds)
INGEST_INTERVAL = int(os.environ.get("IG_INGEST_INTERVAL", "30"))

# --- BFS / Clustering ---
# Time window for IP-based session linking (seconds). Default: 72 hours.
IP_LINK_WINDOW = int(os.environ.get("IG_IP_LINK_WINDOW", str(72 * 3600)))

# Minimum number of commands for a command-sequence hash to count as a link
MIN_CMD_SEQUENCE_LENGTH = int(os.environ.get("IG_MIN_CMD_SEQ", "3"))

# Passwords too common to be useful as cluster links.
# These will NOT be used for BFS linking.
PASSWORD_BLACKLIST = {
    "", "123456", "password", "12345678", "1234", "12345",
    "123456789", "admin", "root", "toor", "test", "guest",
    "master", "qwerty", "abc123", "letmein", "welcome",
    "monkey", "dragon", "login", "passw0rd", "hello",
    "1234567", "1234567890", "123123", "000000", "654321",
    "123321", "666666", "888888", "111111", "qwerty123",
    "password123", "admin123", "root123", "P@ssw0rd",
    "p@ssw0rd", "pass", "1q2w3e4r", "1qaz2wsx",
}

# --- Weekly Report ---
# Day of week for automatic report (0=Monday, 6=Sunday)
WEEKLY_REPORT_DAY = 6   # Sunday
WEEKLY_REPORT_HOUR = 10  # 10:00 UTC

# --- Logging ---
LOG_LEVEL = os.environ.get("IG_LOG_LEVEL", "INFO")
LOG_FILE = os.environ.get("IG_LOG_FILE", "/opt/inspector_gadget/inspector_gadget.log")
