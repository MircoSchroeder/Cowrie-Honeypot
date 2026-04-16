"""
inspector_gadget - reporter.py (v3)
Formats all reports for Telegram output.
All list outputs are capped and show totals so nothing explodes.
"""

import logging
from datetime import datetime, timedelta

from database import Database

logger = logging.getLogger("inspector_gadget.reporter")

MAX_MSG_LEN = 4000
# Default display limits for list sections
LIST_LIMIT = 15


class Reporter:
    """Generates formatted text reports from database state."""

    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------
    # Cluster report with optional section filter
    # ------------------------------------------------------------------

    def cluster_report(self, cluster_name: str, section: str = None,
                       page: int = 0) -> str:
        """
        Generate cluster report.
        section: None=overview, 'ips', 'passwords', 'keys', 'downloads', 'commands'
        page: for paginated sections (0-indexed)
        """
        cluster = self.db.get_cluster_by_name(cluster_name)
        if not cluster:
            return f"Cluster '{cluster_name}' not found."

        cid = cluster["id"]

        if section is None:
            return self._cluster_overview(cluster_name, cid)
        elif section == "ips":
            return self._cluster_ips(cluster_name, cid, page)
        elif section == "passwords":
            return self._cluster_passwords(cluster_name, cid, page)
        elif section == "keys":
            return self._cluster_keys(cluster_name, cid)
        elif section == "downloads":
            return self._cluster_downloads(cluster_name, cid)
        elif section == "commands":
            return self._cluster_commands(cluster_name, cid, page)
        else:
            return (f"Unknown section '{section}'.\n"
                    f"Use: ips, passwords, keys, downloads, commands")

    def _cluster_overview(self, name: str, cid: int) -> str:
        """Full cluster overview with limited samples."""
        sessions = self.db.get_cluster_sessions(cid)
        ips = self.db.get_unique_ips_for_cluster(cid)
        passwords = self.db.get_unique_passwords_for_cluster(cid)
        fingerprints = self.db.get_unique_fingerprints_for_cluster(cid)
        downloads = self.db.get_unique_downloads_for_cluster(cid)
        seeds = self.db.get_seeds(cid)
        time_range = self.db.get_cluster_time_range(cid)

        lines = [f"\U0001f4c1 Cluster: {name}", "\u2501" * 20]

        if time_range:
            lines.append(f"\U0001f550 First seen: {_short_time(time_range['first_seen'])}")
            lines.append(f"\U0001f550 Last seen:  {_short_time(time_range['last_seen'])}")

        lines.append("")
        lines.append(f"\U0001f4ca Sessions: {len(sessions)}")
        lines.append(f"\U0001f310 Unique IPs: {len(ips)}")
        lines.append(f"\U0001f511 SSH Keys: {len(fingerprints)}")
        lines.append(f"\U0001f510 Passwords: {len(passwords)}")
        lines.append(f"\U0001f4e5 Downloads: {len(downloads)}")
        lines.append(f"\U0001f331 Seeds: {len(seeds)}")

        # Seeds (always show all)
        lines.append("")
        lines.append("\U0001f331 Seeds:")
        for s in seeds:
            lines.append(f"  \u2022 {s['seed_type']}: {_trunc(s['seed_value'], 40)}")

        # Top IPs (preview)
        if ips:
            lines.append("")
            lines.append(f"\U0001f310 IPs (top 5 of {len(ips)}):")
            ip_counts = {}
            for s in sessions:
                ip_counts[s["src_ip"]] = ip_counts.get(s["src_ip"], 0) + 1
            sorted_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:5]
            for ip, count in sorted_ips:
                lines.append(f"  \u2022 {ip} ({count}x)")
            if len(ips) > 5:
                lines.append(f"  \u27a1 /report {name} ips")

        # SSH Keys (preview)
        if fingerprints:
            lines.append("")
            lines.append(f"\U0001f511 SSH Keys ({len(fingerprints)}):")
            for fp in fingerprints[:3]:
                lines.append(f"  \u2022 {_trunc(fp, 50)}")
            if len(fingerprints) > 3:
                lines.append(f"  \u27a1 /report {name} keys")

        # Passwords (preview)
        if passwords:
            lines.append("")
            lines.append(f"\U0001f510 Passwords (5 of {len(passwords)}):")
            for pw in passwords[:5]:
                lines.append(f"  \u2022 {_trunc(pw, 40)}")
            if len(passwords) > 5:
                lines.append(f"  \u27a1 /report {name} passwords")

        # Downloads (preview)
        if downloads:
            lines.append("")
            lines.append(f"\U0001f4e5 Downloads ({len(downloads)}):")
            for dl in downloads[:3]:
                sha = _trunc(dl.get("sha256", "?"), 16)
                url = _trunc(dl.get("url", "?"), 40)
                lines.append(f"  \u2022 {sha} ({url})")
            if len(downloads) > 3:
                lines.append(f"  \u27a1 /report {name} downloads")

        return _truncate_message("\n".join(lines))

    def _cluster_ips(self, name: str, cid: int, page: int) -> str:
        """Paginated IP list for a cluster."""
        sessions = self.db.get_cluster_sessions(cid)
        ip_counts = {}
        for s in sessions:
            ip_counts[s["src_ip"]] = ip_counts.get(s["src_ip"], 0) + 1
        sorted_ips = sorted(ip_counts.items(), key=lambda x: -x[1])

        return _paginate(
            title=f"\U0001f310 IPs for '{name}'",
            items=[f"{ip} ({cnt}x)" for ip, cnt in sorted_ips],
            page=page,
            per_page=30,
            next_cmd=f"/report {name} ips",
        )

    def _cluster_passwords(self, name: str, cid: int, page: int) -> str:
        """Paginated password list for a cluster."""
        passwords = self.db.get_unique_passwords_for_cluster(cid)

        return _paginate(
            title=f"\U0001f510 Passwords for '{name}'",
            items=passwords,
            page=page,
            per_page=40,
            next_cmd=f"/report {name} passwords",
        )

    def _cluster_keys(self, name: str, cid: int) -> str:
        """All SSH keys for a cluster."""
        fingerprints = self.db.get_unique_fingerprints_for_cluster(cid)

        lines = [
            f"\U0001f511 SSH Keys for '{name}' ({len(fingerprints)})",
            "\u2501" * 20,
        ]
        for fp in fingerprints:
            lines.append(f"  \u2022 {fp}")

        return _truncate_message("\n".join(lines))

    def _cluster_downloads(self, name: str, cid: int) -> str:
        """All downloads for a cluster."""
        downloads = self.db.get_unique_downloads_for_cluster(cid)

        lines = [
            f"\U0001f4e5 Downloads for '{name}' ({len(downloads)})",
            "\u2501" * 20,
        ]
        for dl in downloads:
            sha = dl.get("sha256", "?")
            url = _trunc(dl.get("url", ""), 60)
            lines.append(f"  \u2022 {sha}")
            if url:
                lines.append(f"    {url}")

        return _truncate_message("\n".join(lines))

    def _cluster_commands(self, name: str, cid: int, page: int) -> str:
        """Paginated unique commands for a cluster."""
        sessions = self.db.get_cluster_sessions(cid)
        all_cmds = set()
        for s in sessions[:500]:  # cap to avoid memory issues
            cmds = self.db.get_commands_for_session(s["session_id"])
            for c in cmds:
                all_cmds.add(c["input"])

        return _paginate(
            title=f"\U0001f4bb Commands for '{name}'",
            items=sorted(all_cmds),
            page=page,
            per_page=30,
            next_cmd=f"/report {name} commands",
        )

    # ------------------------------------------------------------------
    # Unknown pool report
    # ------------------------------------------------------------------

    def unknown_report(self) -> str:
        """Summary of unassigned sessions including SSH keys."""
        total = self.db.count_unassigned_sessions()
        top_ips = self.db.get_top_unassigned_ips(10)
        top_pws = self.db.get_top_unassigned_passwords(10)
        top_keys = self._get_top_unassigned_keys(10)

        lines = [
            "\u2753 Unassigned Sessions",
            "\u2501" * 20,
            f"\U0001f4ca Total: {total}",
            "",
        ]

        if top_ips:
            lines.append("\U0001f310 Top IPs:")
            for entry in top_ips:
                lines.append(f"  \u2022 {entry['src_ip']} ({entry['cnt']}x)")

        if top_keys:
            lines.append("")
            lines.append("\U0001f511 Top SSH Keys:")
            for entry in top_keys:
                fp = _trunc(entry["fingerprint"], 40)
                lines.append(f"  \u2022 {fp} ({entry['cnt']}x)")

        if top_pws:
            lines.append("")
            lines.append("\U0001f510 Top Passwords:")
            for entry in top_pws:
                lines.append(f"  \u2022 {_trunc(entry['password'], 30)} ({entry['cnt']}x)")

        return _truncate_message("\n".join(lines))

    def _get_top_unassigned_keys(self, limit: int) -> list[dict]:
        """Get top SSH keys from unassigned sessions."""
        conn = self.db._get_conn()
        rows = conn.execute(
            """SELECT k.fingerprint, COUNT(DISTINCT k.session_id) as cnt
               FROM ssh_keys k
               JOIN sessions s ON k.session_id = s.session_id
               WHERE s.cluster_id IS NULL
               GROUP BY k.fingerprint
               ORDER BY cnt DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Inspect report
    # ------------------------------------------------------------------

    def inspect_report(self, data: dict) -> str:
        """Format an IP inspection result with capped lists."""
        if "error" in data:
            return data["error"]

        lines = [
            f"\U0001f50d IP: {data['ip']}",
            "\u2501" * 20,
            f"\U0001f4ca Sessions: {data['total_sessions']}",
            f"\U0001f550 First: {_short_time(data['first_seen'])}",
            f"\U0001f550 Last:  {_short_time(data['last_seen'])}",
            f"\U0001f4c1 Clusters: {', '.join(data['clusters'])}",
        ]

        if data.get("fingerprints"):
            lines.append("")
            lines.append(f"\U0001f511 SSH Keys ({len(data['fingerprints'])}):")
            for fp in data["fingerprints"][:5]:
                lines.append(f"  \u2022 {_trunc(fp, 50)}")
            if len(data["fingerprints"]) > 5:
                lines.append(f"  ... +{len(data['fingerprints']) - 5} more")

        if data.get("passwords"):
            lines.append("")
            total_pw = data.get("total_passwords", len(data["passwords"]))
            lines.append(f"\U0001f510 Passwords ({total_pw} total, showing {len(data['passwords'])}):")
            for pw in data["passwords"]:
                lines.append(f"  \u2022 {_trunc(pw, 40)}")
            if total_pw > len(data["passwords"]):
                lines.append(f"  ... +{total_pw - len(data['passwords'])} more")

        if data.get("commands"):
            lines.append("")
            total_cmd = data.get("total_commands", len(data["commands"]))
            lines.append(f"\U0001f4bb Commands ({total_cmd} total, showing {len(data['commands'])}):")
            for cmd in data["commands"]:
                lines.append(f"  \u2022 {_trunc(cmd, 60)}")
            if total_cmd > len(data["commands"]):
                lines.append(f"  ... +{total_cmd - len(data['commands'])} more")

        if data.get("downloads"):
            lines.append("")
            lines.append(f"\U0001f4e5 Downloads ({len(data['downloads'])}):")
            for dl in data["downloads"]:
                lines.append(f"  \u2022 {_trunc(dl.get('sha256', '?'), 16)}")

        return _truncate_message("\n".join(lines))

    # ------------------------------------------------------------------
    # Search, topseed, weekly, status
    # ------------------------------------------------------------------

    def search_report(self, search_text: str, data: dict) -> str:
        lines = [
            f"\U0001f50e Search: '{search_text}'",
            "\u2501" * 20,
            f"Commands: {data['command_sessions']} sessions",
            f"Passwords: {len(data['password_matches'])} matches",
            f"Fingerprints: {len(data['fingerprint_matches'])} matches",
        ]

        if data.get("password_matches"):
            lines.append("")
            lines.append("\U0001f510 Password matches:")
            for m in data["password_matches"]:
                lines.append(f"  \u2022 {m['pw']}")

        if data.get("fingerprint_matches"):
            lines.append("")
            lines.append("\U0001f511 Fingerprint matches:")
            for m in data["fingerprint_matches"]:
                lines.append(f"  \u2022 {_trunc(m['fp'], 50)}")

        return _truncate_message("\n".join(lines))

    def topseed_report(self, data: dict) -> str:
        lines = [
            "\U0001f4a1 Seed Suggestions",
            "\u2501" * 20,
        ]

        if data.get("downloads"):
            lines.append("")
            lines.append("\U0001f4e5 Recurring downloads:")
            for d in data["downloads"]:
                lines.append(f"  \u2022 {_trunc(d['sha256'], 20)} ({d['sessions']} sessions)")
                lines.append(f"    /seed <name> sha256 {d['sha256']}")

        if data.get("fingerprints"):
            lines.append("")
            lines.append("\U0001f511 Recurring SSH keys:")
            for f in data["fingerprints"]:
                lines.append(f"  \u2022 {_trunc(f['fingerprint'], 30)} ({f['sessions']} sessions)")
                lines.append(f"    /seed <name> fingerprint {f['fingerprint']}")

        if data.get("cmd_sequences"):
            lines.append("")
            lines.append("\U0001f4bb Recurring command patterns:")
            for c in data["cmd_sequences"]:
                lines.append(f"  \u2022 {_trunc(c['hash'], 20)} ({c['sessions']} sessions)")
                lines.append(f"    /seed <name> command_seq {c['hash']}")

        if not any(data.get(k) for k in ("downloads", "fingerprints", "cmd_sequences")):
            lines.append("No strong seed candidates found.")

        return _truncate_message("\n".join(lines))

    def weekly_report(self) -> str:
        since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        clusters = self.db.get_all_clusters()

        lines = [
            "\U0001f4f0 Weekly Report",
            "\u2501" * 20,
            "\U0001f4c5 Period: last 7 days",
            "",
        ]

        for c in clusters:
            cid = c["id"]
            week_sessions = self.db.get_sessions_since(since, cluster_id=cid)
            if not week_sessions:
                lines.append(f"\U0001f4c1 {c['name']}: no activity")
                continue

            week_ips = set(s["src_ip"] for s in week_sessions)
            lines.append(f"\U0001f4c1 {c['name']}:")
            lines.append(f"  \U0001f4ca New sessions: {len(week_sessions)}")
            lines.append(f"  \U0001f310 Active IPs: {len(week_ips)}")
            for ip in list(week_ips)[:5]:
                lines.append(f"    \u2022 {ip}")
            if len(week_ips) > 5:
                lines.append(f"    ... +{len(week_ips) - 5} more")
            lines.append("")

        total = self.db.count_total_sessions()
        unassigned = self.db.count_unassigned_sessions()
        all_week = self.db.get_sessions_since(since)
        db_size = self.db.get_db_size_mb()

        lines.append("\U0001f4ca Overall:")
        lines.append(f"  Total sessions: {total}")
        lines.append(f"  Assigned: {total - unassigned} | Unassigned: {unassigned}")
        lines.append(f"  New this week: {len(all_week)}")
        lines.append(f"  Clusters: {len(clusters)}")
        lines.append(f"  DB size: {db_size:.1f} MB")

        return _truncate_message("\n".join(lines))

    def status_report(self, ingester_status: dict) -> str:
        total = self.db.count_total_sessions()
        unassigned = self.db.count_unassigned_sessions()
        clusters = len(self.db.get_all_clusters())
        db_size = self.db.get_db_size_mb()

        return "\n".join([
            "\u2699\ufe0f Inspector Gadget Status",
            "\u2501" * 20,
            f"\U0001f4c2 Log files: {ingester_status['log_files_found']}",
            f"\U0001f4c4 Latest: {ingester_status['latest_file']}",
            f"\U0001f4cf Lines: {ingester_status['latest_lines']}",
            "",
            f"\U0001f4ca Sessions: {total}",
            f"\U0001f4c1 Clusters: {clusters}",
            f"\u2753 Unassigned: {unassigned}",
            f"\U0001f4be DB: {db_size:.1f} MB",
        ])

    def clusters_overview(self) -> str:
        clusters = self.db.get_all_clusters()
        if not clusters:
            return "No clusters yet. Use /seed to create one."

        lines = ["\U0001f4cb All Clusters", "\u2501" * 20]

        for c in clusters:
            count = self.db.get_cluster_session_count(c["id"])
            tr = self.db.get_cluster_time_range(c["id"])
            last = f" | last: {_short_time(tr['last_seen'])}" if tr else ""
            lines.append(f"  \u2022 {c['name']}: {count} sessions{last}")

        total = self.db.count_total_sessions()
        unassigned = self.db.count_unassigned_sessions()
        lines.append("")
        lines.append(f"\U0001f4ca Total: {total} ({unassigned} unassigned)")

        return "\n".join(lines)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _paginate(title: str, items: list, page: int,
              per_page: int, next_cmd: str) -> str:
    """Generic paginator for list outputs."""
    total = len(items)
    start = page * per_page
    end = start + per_page
    page_items = items[start:end]
    total_pages = (total + per_page - 1) // per_page

    lines = [
        title,
        f"Total: {total} | Page {page + 1}/{max(total_pages, 1)}",
        "\u2501" * 20,
    ]

    for item in page_items:
        lines.append(f"  \u2022 {_trunc(str(item), 60)}")

    if end < total:
        lines.append("")
        lines.append(f"\u27a1 Next: {next_cmd} {page + 1}")

    return _truncate_message("\n".join(lines))


def _trunc(text: str, max_len: int) -> str:
    if not text:
        return "?"
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def _truncate_message(text: str) -> str:
    if len(text) <= MAX_MSG_LEN:
        return text
    return text[:MAX_MSG_LEN - 20] + "\n\n... (truncated)"


def _short_time(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, AttributeError):
        return iso_str or "?"
