"""
inspector_gadget - analyser.py (v2)
Two-layer cluster analysis engine.

Layer 1 (Direct): Find all sessions matching the seed directly.
Layer 2 (Expansion): From Layer 1 sessions, expand ONLY through
  strong indicators (SSH key fingerprints, download hashes,
  command-sequence hashes). Never expand through passwords or IPs.

Passwords and IPs are collected for reporting but never used as links.
"""

import logging
from collections import deque

import config
from database import Database

logger = logging.getLogger("inspector_gadget.analyser")

# Valid seed types for creating clusters
SEED_TYPES = {"fingerprint", "password", "sha256", "command_seq", "command_text", "ip"}

# Indicator types used for BFS expansion (Layer 2)
STRONG_INDICATORS = {"fingerprint", "sha256", "command_seq"}


class Analyser:
    """
    Two-layer seed-based clustering engine.

    Layer 1: Direct matches from seed.
    Layer 2: BFS expansion ONLY through strong indicators
             (SSH key, download hash, command-sequence hash).
             Passwords and IPs are never used for expansion.
    """

    def __init__(self, db: Database):
        self.db = db

    def seed_cluster(self, cluster_name: str, seed_type: str,
                     seed_value: str) -> dict:
        """Create a new cluster from a seed and run two-layer analysis."""
        if seed_type not in SEED_TYPES:
            return {"error": f"Invalid seed type. Use: {', '.join(sorted(SEED_TYPES))}"}

        existing = self.db.get_cluster_by_name(cluster_name)
        if existing:
            return {"error": f"Cluster '{cluster_name}' already exists. "
                             f"Use /addseed to add more seeds."}

        cluster_id = self.db.create_cluster(cluster_name)
        self.db.add_seed(cluster_id, seed_type, seed_value)

        found_sessions = self._two_layer_expand(cluster_id)

        return {
            "cluster_name": cluster_name,
            "cluster_id": cluster_id,
            "seed_type": seed_type,
            "seed_value": seed_value,
            "sessions_found": len(found_sessions),
        }

    def add_seed_to_cluster(self, cluster_name: str, seed_type: str,
                            seed_value: str) -> dict:
        """Add a new seed to an existing cluster and re-run analysis."""
        if seed_type not in SEED_TYPES:
            return {"error": f"Invalid seed type. Use: {', '.join(sorted(SEED_TYPES))}"}

        cluster = self.db.get_cluster_by_name(cluster_name)
        if not cluster:
            return {"error": f"Cluster '{cluster_name}' not found."}

        self.db.add_seed(cluster["id"], seed_type, seed_value)
        found_sessions = self._two_layer_expand(cluster["id"])

        return {
            "cluster_name": cluster_name,
            "new_seed": f"{seed_type}:{seed_value}",
            "total_sessions": len(found_sessions),
        }

    def recluster(self, cluster_name: str) -> dict:
        """Unassign all sessions and re-run analysis from scratch."""
        cluster = self.db.get_cluster_by_name(cluster_name)
        if not cluster:
            return {"error": f"Cluster '{cluster_name}' not found."}

        cluster_id = cluster["id"]

        current_sessions = self.db.get_cluster_sessions(cluster_id)
        for s in current_sessions:
            self.db.assign_cluster(s["session_id"], None)

        found_sessions = self._two_layer_expand(cluster_id)

        return {
            "cluster_name": cluster_name,
            "previous_sessions": len(current_sessions),
            "current_sessions": len(found_sessions),
        }

    def match_new_sessions(self) -> dict:
        """
        Check all unassigned sessions against existing clusters.
        Uses SQL batch queries instead of per-session lookups for performance.
        """
        all_clusters = self.db.get_all_clusters()
        if not all_clusters:
            return {"matched": 0}

        conn = self.db._get_conn()
        matched = 0
        matches_per_cluster = {}

        for cluster in all_clusters:
            cid = cluster["id"]
            cname = cluster["name"]
            seeds = self.db.get_seeds(cid)
            newly_matched = 0

            for seed in seeds:
                st = seed["seed_type"]
                sv = seed["seed_value"]

                if st == "command_text":
                    # Match unassigned sessions with commands containing seed text
                    rows = conn.execute(
                        """UPDATE sessions SET cluster_id = ?
                           WHERE cluster_id IS NULL AND session_id IN (
                             SELECT DISTINCT session_id FROM commands
                             WHERE input LIKE ?
                           )""",
                        (cid, f"%{sv}%"),
                    )
                    newly_matched += rows.rowcount

                elif st == "password":
                    rows = conn.execute(
                        """UPDATE sessions SET cluster_id = ?
                           WHERE cluster_id IS NULL AND session_id IN (
                             SELECT DISTINCT session_id FROM credentials
                             WHERE password = ?
                           )""",
                        (cid, sv),
                    )
                    newly_matched += rows.rowcount

                elif st == "fingerprint":
                    rows = conn.execute(
                        """UPDATE sessions SET cluster_id = ?
                           WHERE cluster_id IS NULL AND session_id IN (
                             SELECT DISTINCT session_id FROM ssh_keys
                             WHERE fingerprint = ?
                           )""",
                        (cid, sv),
                    )
                    newly_matched += rows.rowcount

                elif st == "sha256":
                    rows = conn.execute(
                        """UPDATE sessions SET cluster_id = ?
                           WHERE cluster_id IS NULL AND session_id IN (
                             SELECT DISTINCT session_id FROM downloads
                             WHERE sha256 = ?
                           )""",
                        (cid, sv),
                    )
                    newly_matched += rows.rowcount

                elif st == "command_seq":
                    rows = conn.execute(
                        """UPDATE sessions SET cluster_id = ?
                           WHERE cluster_id IS NULL
                             AND cmd_sequence_hash = ?""",
                        (cid, sv),
                    )
                    newly_matched += rows.rowcount

                elif st == "ip":
                    rows = conn.execute(
                        """UPDATE sessions SET cluster_id = ?
                           WHERE cluster_id IS NULL AND src_ip = ?""",
                        (cid, sv),
                    )
                    newly_matched += rows.rowcount

            # Layer 2: Match via strong indicators already in the cluster
            # SSH fingerprints
            rows = conn.execute(
                """UPDATE sessions SET cluster_id = ?
                   WHERE cluster_id IS NULL AND session_id IN (
                     SELECT DISTINCT k2.session_id FROM ssh_keys k2
                     WHERE k2.fingerprint IN (
                       SELECT DISTINCT k1.fingerprint FROM ssh_keys k1
                       JOIN sessions s1 ON k1.session_id = s1.session_id
                       WHERE s1.cluster_id = ?
                     )
                   )""",
                (cid, cid),
            )
            newly_matched += rows.rowcount

            # Download hashes
            rows = conn.execute(
                """UPDATE sessions SET cluster_id = ?
                   WHERE cluster_id IS NULL AND session_id IN (
                     SELECT DISTINCT d2.session_id FROM downloads d2
                     WHERE d2.sha256 IS NOT NULL AND d2.sha256 IN (
                       SELECT DISTINCT d1.sha256 FROM downloads d1
                       JOIN sessions s1 ON d1.session_id = s1.session_id
                       WHERE s1.cluster_id = ? AND d1.sha256 IS NOT NULL
                     )
                   )""",
                (cid, cid),
            )
            newly_matched += rows.rowcount

            # Command sequence hashes
            rows = conn.execute(
                """UPDATE sessions SET cluster_id = ?
                   WHERE cluster_id IS NULL
                     AND cmd_sequence_hash IS NOT NULL
                     AND cmd_sequence_hash IN (
                       SELECT DISTINCT cmd_sequence_hash FROM sessions
                       WHERE cluster_id = ?
                         AND cmd_sequence_hash IS NOT NULL
                     )""",
                (cid, cid),
            )
            newly_matched += rows.rowcount

            if newly_matched > 0:
                matches_per_cluster[cname] = newly_matched
                matched += newly_matched

        conn.commit()

        if matched > 0:
            logger.info("Matched %d new sessions to clusters: %s",
                        matched, matches_per_cluster)

        return {"matched": matched, "per_cluster": matches_per_cluster}

    # ------------------------------------------------------------------
    # Two-layer expansion
    # ------------------------------------------------------------------

    def _two_layer_expand(self, cluster_id: int) -> set[str]:
        """
        Layer 1: Direct seed matches.
        Layer 2: BFS through strong indicators only (fingerprint,
                 download hash, command-sequence hash).
        """
        seeds = self.db.get_seeds(cluster_id)
        if not seeds:
            return set()

        # --- Layer 1: Direct seed matches ---
        layer1: set[str] = set()
        for seed in seeds:
            direct = self._sessions_from_seed(seed)
            layer1.update(direct)

        logger.info("Layer 1: %d direct sessions from %d seeds",
                    len(layer1), len(seeds))

        # --- Layer 2: BFS through strong indicators only ---
        visited: set[str] = set(layer1)
        queue: deque[str] = deque(layer1)

        while queue:
            current_sid = queue.popleft()
            strong_neighbors = self._find_strong_neighbors(current_sid)
            for neighbor_sid in strong_neighbors:
                if neighbor_sid not in visited:
                    visited.add(neighbor_sid)
                    queue.append(neighbor_sid)

        logger.info("Layer 2: %d total sessions after expansion", len(visited))

        # Assign all to cluster
        for sid in visited:
            self.db.assign_cluster(sid, cluster_id)

        return visited

    def _sessions_from_seed(self, seed: dict) -> list[str]:
        """Find sessions directly matching a seed."""
        seed_type = seed["seed_type"]
        seed_value = seed["seed_value"]

        if seed_type == "fingerprint":
            return self.db.find_sessions_by_fingerprint(seed_value)
        elif seed_type == "password":
            return self.db.find_sessions_by_password(seed_value)
        elif seed_type == "sha256":
            return self.db.find_sessions_by_sha256(seed_value)
        elif seed_type == "command_seq":
            return self.db.find_sessions_by_cmd_hash(seed_value)
        elif seed_type == "command_text":
            return self.db.find_sessions_by_command_text(seed_value)
        elif seed_type == "ip":
            conn = self.db._get_conn()
            rows = conn.execute(
                "SELECT session_id FROM sessions WHERE src_ip = ?",
                (seed_value,),
            ).fetchall()
            return [r["session_id"] for r in rows]
        else:
            return []

    def _find_strong_neighbors(self, session_id: str) -> set[str]:
        """
        Find sessions linked through STRONG indicators only:
        - Same SSH key fingerprint
        - Same download SHA256 hash
        - Same command-sequence hash

        Passwords and IPs are EXCLUDED.
        """
        neighbors: set[str] = set()
        session = self.db.get_session(session_id)
        if not session:
            return neighbors

        # SSH key fingerprints
        fingerprints = self.db.get_fingerprints_for_session(session_id)
        for fp in fingerprints:
            linked = self.db.find_sessions_by_fingerprint(fp)
            neighbors.update(linked)

        # Download hashes
        downloads = self.db.get_downloads_for_session(session_id)
        for dl in downloads:
            if dl.get("sha256"):
                linked = self.db.find_sessions_by_sha256(dl["sha256"])
                neighbors.update(linked)

        # Command-sequence hash
        if session.get("cmd_sequence_hash"):
            linked = self.db.find_sessions_by_cmd_hash(session["cmd_sequence_hash"])
            neighbors.update(linked)

        neighbors.discard(session_id)
        return neighbors

    # ------------------------------------------------------------------
    # Discovery helpers
    # ------------------------------------------------------------------

    def inspect_ip(self, ip: str) -> dict:
        """Get detailed breakdown of all activity from an IP."""
        conn = self.db._get_conn()
        sessions = conn.execute(
            "SELECT * FROM sessions WHERE src_ip = ? ORDER BY start_time",
            (ip,),
        ).fetchall()

        if not sessions:
            return {"error": f"No sessions found for IP {ip}"}

        all_passwords = set()
        all_fingerprints = set()
        all_downloads = []
        all_commands = []
        clusters_seen = set()

        for s in sessions:
            sid = s["session_id"]
            all_passwords.update(self.db.get_passwords_for_session(sid))
            all_fingerprints.update(self.db.get_fingerprints_for_session(sid))
            all_downloads.extend(self.db.get_downloads_for_session(sid))
            all_commands.extend(self.db.get_commands_for_session(sid))
            if s["cluster_id"]:
                c = next((x for x in self.db.get_all_clusters()
                          if x["id"] == s["cluster_id"]), None)
                if c:
                    clusters_seen.add(c["name"])

        return {
            "ip": ip,
            "total_sessions": len(sessions),
            "first_seen": sessions[0]["start_time"],
            "last_seen": sessions[-1]["start_time"],
            "clusters": list(clusters_seen) if clusters_seen else ["unassigned"],
            "passwords": sorted(all_passwords)[:20],
            "fingerprints": list(all_fingerprints),
            "downloads": [{"sha256": d.get("sha256", "?"), "url": d.get("url", "")}
                          for d in all_downloads][:10],
            "commands": [c["input"] for c in all_commands][:20],
        }

    def search_all(self, search_text: str) -> dict:
        """Search across commands, passwords, fingerprints for a text fragment."""
        conn = self.db._get_conn()

        cmd_sessions = self.db.find_sessions_by_command_text(search_text)

        pw_rows = conn.execute(
            """SELECT DISTINCT c.session_id, c.password
               FROM credentials c WHERE c.password LIKE ? LIMIT 50""",
            (f"%{search_text}%",),
        ).fetchall()

        fp_rows = conn.execute(
            """SELECT DISTINCT session_id, fingerprint
               FROM ssh_keys WHERE fingerprint LIKE ? LIMIT 50""",
            (f"%{search_text}%",),
        ).fetchall()

        return {
            "command_sessions": len(cmd_sessions),
            "command_sample": cmd_sessions[:10],
            "password_matches": [{"session": r["session_id"], "pw": r["password"]}
                                 for r in pw_rows][:10],
            "fingerprint_matches": [{"session": r["session_id"], "fp": r["fingerprint"]}
                                    for r in fp_rows][:10],
        }

    def suggest_seeds(self) -> dict:
        """Suggest potential seeds from unassigned session pool."""
        conn = self.db._get_conn()

        top_downloads = conn.execute(
            """SELECT d.sha256, COUNT(DISTINCT d.session_id) as cnt
               FROM downloads d
               JOIN sessions s ON d.session_id = s.session_id
               WHERE s.cluster_id IS NULL AND d.sha256 IS NOT NULL AND d.sha256 != ''
               GROUP BY d.sha256 HAVING cnt >= 2
               ORDER BY cnt DESC LIMIT 10"""
        ).fetchall()

        top_fingerprints = conn.execute(
            """SELECT k.fingerprint, COUNT(DISTINCT k.session_id) as cnt
               FROM ssh_keys k
               JOIN sessions s ON k.session_id = s.session_id
               WHERE s.cluster_id IS NULL
               GROUP BY k.fingerprint HAVING cnt >= 2
               ORDER BY cnt DESC LIMIT 10"""
        ).fetchall()

        top_cmd_hashes = conn.execute(
            """SELECT cmd_sequence_hash, COUNT(*) as cnt
               FROM sessions
               WHERE cluster_id IS NULL
                 AND cmd_sequence_hash IS NOT NULL AND cmd_sequence_hash != ''
               GROUP BY cmd_sequence_hash HAVING cnt >= 3
               ORDER BY cnt DESC LIMIT 10"""
        ).fetchall()

        return {
            "downloads": [{"sha256": r["sha256"], "sessions": r["cnt"]}
                          for r in top_downloads],
            "fingerprints": [{"fingerprint": r["fingerprint"], "sessions": r["cnt"]}
                             for r in top_fingerprints],
            "cmd_sequences": [{"hash": r["cmd_sequence_hash"], "sessions": r["cnt"]}
                              for r in top_cmd_hashes],
        }
