"""
analyze_cowrie.py
Real-time Cowrie honeypot log watcher with Telegram alerting,
AbuseIPDB enrichment, VirusTotal lookups, and Inspector Gadget
cluster-based filtering.

Sessions belonging to known clusters (tracked by the Inspector Gadget
daemon) are suppressed here, so only NEW or UNCLUSTERED attackers
generate alerts. This keeps the signal-to-noise ratio high.

Configuration is read from environment variables (see .env.example).
"""

import json
import os
import sqlite3
import time

import requests

# --- CONFIGURATION (loaded from environment) ---
COWRIE_LOG = os.environ.get("COWRIE_LOG", "/path/to/cowrie/var/log/cowrie/cowrie.json")
TG_TOKEN = os.environ.get("TG_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "YOUR_TELEGRAM_CHAT_ID")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "YOUR_ABUSEIPDB_API_KEY")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_KEY", "YOUR_VIRUSTOTAL_API_KEY")

# IPs with AbuseIPDB score >= this value are suppressed.
# Default 101 = report everything. Set to 50 for stricter filtering.
ABUSEIPDB_SCORE_THRESHOLD = int(os.environ.get("ABUSEIPDB_SCORE_THRESHOLD", "101"))

# Persistent cache so we don't re-query AbuseIPDB on every restart.
IP_CACHE_FILE = os.environ.get("IP_CACHE_FILE", "/var/lib/analyze_cowrie/ip_cache.json")

# Inspector Gadget DB - used to suppress alerts for already-clustered attackers.
IG_DB_PATH = os.environ.get("IG_DB_PATH", "/opt/inspector_gadget/inspector_gadget.db")


# --- IP CACHE ---

def load_ip_cache():
    """Load cached IP check results from disk."""
    if os.path.exists(IP_CACHE_FILE):
        try:
            with open(IP_CACHE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_ip_cache(cache):
    """Save IP cache to disk."""
    cache_dir = os.path.dirname(IP_CACHE_FILE)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
    try:
        with open(IP_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except IOError as e:
        print(f"Cache write error: {e}")


# Global cache loaded at startup
ip_cache = load_ip_cache()


def check_ip(ip):
    """Check IP against AbuseIPDB, using cache to avoid duplicate lookups."""
    global ip_cache

    if ip in ip_cache:
        cached = ip_cache[ip]
        return cached["info"], cached["score"]

    if not ABUSEIPDB_KEY or ABUSEIPDB_KEY == "YOUR_ABUSEIPDB_API_KEY":
        return "No AbuseIPDB key", -1

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_KEY}
    try:
        response = requests.get(
            url,
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=5,
        )
        data = response.json()
        score = data["data"]["abuseConfidenceScore"]
        country = data["data"]["countryCode"]
        info = f"{country} (Score: {score}%)"

        ip_cache[ip] = {"info": info, "score": score}
        save_ip_cache(ip_cache)

        return info, score
    except Exception:
        return "Check failed", -1


def check_virustotal(sha256_hash):
    """Check a file hash against VirusTotal API."""
    if not VIRUSTOTAL_KEY or VIRUSTOTAL_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return None

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            name = attrs.get("popular_threat_classification", {}) \
                        .get("suggested_threat_label", "")
            type_tag = attrs.get("type_tag", "")

            if malicious > 0:
                result = f"{malicious}/{total} detected"
                if name:
                    result += f" | {name}"
                elif type_tag:
                    result += f" | {type_tag}"
                return result
            return f"0/{total} - clean"
        if response.status_code == 404:
            return "Not known to VT"
        return None
    except Exception:
        return None


def is_filtered_session(ip, events):
    """
    Return True if this session belongs to a known Inspector Gadget cluster.

    Three checks:
      1. IP already assigned to a cluster.
      2. Any credential password matches a cluster seed.
      3. Any command contains a command_text seed.
    """
    try:
        if not os.path.exists(IG_DB_PATH):
            return False

        conn = sqlite3.connect(IG_DB_PATH)
        conn.row_factory = sqlite3.Row

        # 1: Is this IP in any cluster?
        row = conn.execute(
            """SELECT c.name FROM sessions s
               JOIN clusters c ON s.cluster_id = c.id
               WHERE s.src_ip = ? AND s.cluster_id IS NOT NULL
               LIMIT 1""",
            (ip,),
        ).fetchone()

        if row:
            conn.close()
            return True

        # 2: Do any passwords match a seed?
        for event in events:
            if event.get("eventid") in ("cowrie.login.success", "cowrie.login.failed"):
                pw = event.get("password", "")
                if pw:
                    row = conn.execute(
                        """SELECT 1 FROM seeds
                           WHERE seed_type = 'password' AND seed_value = ?
                           LIMIT 1""",
                        (pw,),
                    ).fetchone()
                    if row:
                        conn.close()
                        return True

        # 3: Do any commands match a command_text seed?
        cmd_seeds = conn.execute(
            "SELECT seed_value FROM seeds WHERE seed_type = 'command_text'"
        ).fetchall()

        for event in events:
            if event.get("eventid") == "cowrie.command.input":
                cmd = event.get("input", "")
                if cmd:
                    for seed_row in cmd_seeds:
                        if seed_row["seed_value"] in cmd:
                            conn.close()
                            return True

        conn.close()
    except Exception as e:
        print(f"IG DB check failed: {e}")

    return False


def send_telegram(message):
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": message, "parse_mode": "HTML"}
    while True:
        try:
            r = requests.post(url, json=payload, timeout=5)
            if r.status_code == 429:
                retry_after = r.json().get("parameters", {}).get("retry_after", 60)
                print(f"Telegram rate limit. Waiting {retry_after}s...")
                time.sleep(retry_after + 5)
                continue
            break
        except Exception as e:
            print(f"Telegram error: {e}")
            break


def build_report(ip, ip_info, ip_score, events):
    logins = [e for e in events if e.get("eventid") == "cowrie.login.success"]
    commands = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    downloads = [e for e in events if e.get("eventid") == "cowrie.session.file_download"]
    failed = [e for e in events if e.get("eventid") == "cowrie.login.failed"]

    if not logins and not commands and not downloads:
        return None

    lines = []
    lines.append("\U0001f4cb <b>Attack Report</b>")
    lines.append(f"\U0001f310 IP: <code>{ip}</code> | {ip_info}")
    lines.append(f"\U0001f534 Failed logins: {len(failed)}")

    if logins:
        lines.append(f"\n\U0001f6a8 <b>Successful breaches: {len(logins)}</b>")
        seen = []
        for e in logins:
            combo = (e.get("username", "?"), e.get("password", "?"))
            if combo not in seen:
                seen.append(combo)
            if len(seen) >= 5:
                break
        for user, pw in seen:
            lines.append(f"  \U0001f464 <code>{user}</code> / \U0001f511 <code>{pw}</code>")
        if len(logins) > len(seen):
            lines.append("  ... and more attempts")

    if commands:
        lines.append(f"\n\U0001f4bb <b>Executed commands: {len(commands)}</b>")
        unique_cmds = list(dict.fromkeys([e.get("input", "?") for e in commands]))[:5]
        for cmd in unique_cmds:
            lines.append(f"  \u2328\ufe0f <code>{cmd[:80]}</code>")
        if len(commands) > 5:
            lines.append(f"  ... and {len(commands) - 5} more")

    if downloads:
        lines.append(f"\n\u2b07\ufe0f <b>Downloaded files: {len(downloads)}</b>")
        for d in downloads[:3]:
            sha = d.get("shasum", "")
            url_or_file = d.get("url") or d.get("outfile") or "unknown"
            lines.append(f"  \U0001f517 {str(url_or_file)[:80]}")
            if sha:
                vt_result = check_virustotal(sha)
                if vt_result:
                    lines.append(f"  \U0001f9ea VT: {vt_result}")

    return "\n".join(lines)


def monitor_logs():
    print("Live monitor started. Waiting for attacks...")
    print(f"IP cache: {len(ip_cache)} IPs loaded")
    print(f"AbuseIPDB score threshold: <{ABUSEIPDB_SCORE_THRESHOLD}%")
    if os.path.exists(IG_DB_PATH):
        print(f"Inspector Gadget filter: ACTIVE ({IG_DB_PATH})")
    else:
        print("Inspector Gadget filter: DB not found, filter disabled")
    if VIRUSTOTAL_KEY and VIRUSTOTAL_KEY != "YOUR_VIRUSTOTAL_API_KEY":
        print("VirusTotal: active")
    else:
        print("VirusTotal: disabled (no key)")

    f = open(COWRIE_LOG, "r")
    f.seek(0, os.SEEK_END)
    current_inode = os.stat(COWRIE_LOG).st_ino

    current_ip = None
    current_events = []

    while True:
        line = f.readline()

        if not line:
            time.sleep(1)
            try:
                new_inode = os.stat(COWRIE_LOG).st_ino
                if new_inode != current_inode:
                    print("Log rotation detected, switching...")
                    if current_ip and current_events:
                        _process_session(current_ip, current_events)
                    f.close()
                    f = open(COWRIE_LOG, "r")
                    current_inode = new_inode
                    current_ip = None
                    current_events = []
            except Exception as e:
                print(f"File check error: {e}")
            continue

        try:
            event = json.loads(line.strip())
        except json.JSONDecodeError:
            continue

        ip = event.get("src_ip")
        if not ip:
            continue

        event_id = event.get("eventid", "")

        if event_id not in ("cowrie.login.success", "cowrie.login.failed",
                            "cowrie.command.input", "cowrie.session.file_download"):
            continue

        if ip != current_ip:
            if current_ip and current_events:
                _process_session(current_ip, current_events)
            current_ip = ip
            current_events = []

        current_events.append(event)


def _process_session(ip, events):
    """Process a completed session: filter, check, report."""
    if is_filtered_session(ip, events):
        return

    ip_info, ip_score = check_ip(ip)

    if ip_score >= ABUSEIPDB_SCORE_THRESHOLD:
        return

    report = build_report(ip, ip_info, ip_score, events)
    if report:
        print(f"Sending report for {ip} (Score: {ip_score}%)...")
        send_telegram(report)


if __name__ == "__main__":
    monitor_logs()
