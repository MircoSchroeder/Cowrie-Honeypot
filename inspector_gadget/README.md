# 🔍 Inspector Gadget

> Long-running honeypot analysis daemon that ingests Cowrie logs, clusters attack sessions by shared indicators, and provides an interactive Telegram interface for threat hunting.

A second-generation evolution of the earlier `analyze_cowrie.py` script. Where the original sent one alert per session, Inspector Gadget operates on the full historical log archive — clustering tens of thousands of sessions into named attack campaigns and answering ad-hoc questions about them on demand.

---

## 📋 Table of Contents

- [Why This Exists](#why-this-exists)
- [Architecture](#architecture)
- [Clustering Model](#clustering-model)
- [Telegram Commands](#telegram-commands)
- [Live Clusters](#live-clusters)
- [Setup](#setup)
- [Module Overview](#module-overview)
- [Known Limitations](#known-limitations)

---

## Why This Exists

Running a public-facing honeypot for weeks produces hundreds of thousands of sessions. The original `analyze_cowrie.py` worked well for live alerting, but had two structural problems:

1. **No memory.** Every session was reported in isolation. The same botnet hitting us 500 times in a month generated 500 independent alerts.
2. **No grouping.** There was no way to answer "show me every session where the attacker used the `mdrfckr` SSH key."

Inspector Gadget solves both: the ingester populates a normalized SQLite DB from all historical logs, and an analyser links sessions into named clusters based on shared strong indicators. `analyze_cowrie.py` now defers to this DB — any session matching a known cluster is suppressed at the alert layer, so the Telegram channel only surfaces genuinely new activity.

---

## Architecture

```
┌─────────────────┐
│   Cowrie JSON   │  (rotated daily, /path/to/cowrie/var/log/cowrie/)
│      logs       │
└────────┬────────┘
         │ poll every 30s
         ▼
┌─────────────────┐      ┌──────────────────┐
│    ingester     │─────▶│   SQLite DB      │
│  (run_once)     │      │  sessions,       │
└─────────────────┘      │  commands,       │
                         │  credentials,    │
┌─────────────────┐      │  downloads,      │
│    analyser     │◀────▶│  ssh_keys,       │
│  seed_cluster   │      │  clusters,       │
│  BFS expand     │      │  seeds           │
│  match_new      │      └──────────────────┘
└────────┬────────┘               ▲
         │                        │
         ▼                        │
┌─────────────────┐               │
│    reporter     │───────────────┘
│  section views  │
│  pagination     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Telegram Bot   │  ◀── user commands
│   (bot.py)      │
└─────────────────┘
```

Single systemd service. One event loop runs the bot; a background thread drives the ingester + analyser on a fixed interval.

---

## Clustering Model

The core idea: an attack **campaign** is a set of sessions connected by shared strong indicators. Inspector Gadget uses a **two-layer approach**:

**Layer 1 — Direct Seed Match.** The operator provides a seed like `command_text = "mdrfckr"` or `fingerprint = "SHA256:..."`. The DB is queried for every session containing that exact indicator. These sessions become the initial cluster membership.

**Layer 2 — BFS Expansion.** For each seed session, find other sessions that share *strong* indicators — specifically:

- SSH client key fingerprint
- Download SHA256
- Command-sequence hash (SHA256 of all commands in execution order)

Each newly-added session becomes a new frontier node, and the search continues until no new sessions are found.

### What's Deliberately Excluded from BFS

Two categories of indicators are intentionally **not** used for BFS expansion:

- **Passwords** — too many campaigns share common passwords like `admin` or `123456`. Letting BFS follow password edges causes "mega-cluster contamination" where unrelated campaigns merge.
- **Source IPs** — attackers rotate IPs constantly; linking by IP would merge every botnet that happens to share a compromised host.

Passwords *can* still serve as Layer 1 seeds when operator-curated, they just can't drive Layer 2 expansion automatically.

A SHA256 blacklist in `config.py` also prevents trivial/empty hashes from contaminating clusters via download edges.

---

## Telegram Commands

```
📁 Clusters
/seed <name> <type> <value>       Create cluster from a seed
/addseed <name> <type> <value>    Add a seed to existing cluster
/recluster <name>                 Re-run BFS for a cluster
/delete <name>                    Remove cluster, free its sessions

📊 Reports
/report <name> [section] [page]   Cluster detail view
   sections: ips, passwords, keys, downloads, commands
/clusters                         Overview of all clusters
/unknown                          Top indicators from UNCLUSTERED sessions
/weekly                           Manual trigger of weekly summary
/status                           Ingestion stats

🔎 Discovery
/inspect <ip>                     Everything the DB knows about an IP
/search <text>                    Free-text search across all events
/topseed                          Suggest high-value seed candidates

⚙️ System
/ingest                           Force an ingestion cycle
```

Valid seed types: `command_text`, `fingerprint`, `sha256`, `password`, `ip`, `cmd_sequence_hash`.

---

## Live Clusters

Two major clusters identified so far:

| Cluster | Sessions | Seed | Notes |
|---|---|---|---|
| **mdrfckr** | ~7.5k | `command_text = mdrfckr` | SSH key persistence botnet, documented in main README |
| **6F6B** | ~37.8k | `command_text = \x6F\x6B` | Massive brute-forcer from only 2 IPs, ~25k unique passwords tried |

Both were identified by seeding a single `command_text` indicator, then letting BFS expand via shared command-sequence hashes.

---

## Setup

**Requirements:** Python 3.10+, a running Cowrie honeypot, a Telegram bot token.

```bash
# Clone into the deployment location
sudo git clone https://github.com/MircoSchroeder/Cowrie-Honeypot /opt/cowrie-honeypot
sudo cp -r /opt/cowrie-honeypot/inspector_gadget /opt/inspector_gadget
cd /opt/inspector_gadget

# Install dependencies
sudo pip3 install -r requirements.txt --break-system-packages

# Configure
sudo cp .env.example .env
sudo nano .env    # fill in Telegram token, chat ID, Cowrie log path

# Install systemd service
sudo cp inspector_gadget.service /etc/systemd/system/
sudo nano /etc/systemd/system/inspector_gadget.service   # set User=/Group=
sudo systemctl daemon-reload
sudo systemctl enable --now inspector_gadget

# Check it's running
sudo systemctl status inspector_gadget
journalctl -u inspector_gadget -f
```

On first run the ingester walks the full Cowrie log archive and populates the DB — this can take several minutes on large deployments.

---

## Module Overview

| File | Responsibility |
|---|---|
| `main.py` | Entry point. Sets up logging, starts ingester thread and bot event loop. |
| `config.py` | All tunables, loaded from env vars. |
| `database.py` | SQLite schema, CRUD, session/cluster/seed operations. |
| `ingester.py` | Reads Cowrie JSON logs, tracks read positions, inserts events. |
| `analyser.py` | Seeding, two-layer BFS clustering, session matching. |
| `reporter.py` | Formats cluster reports, pagination, section filters. |
| `bot.py` | Telegram command handlers, scheduled weekly report. |

---

## Known Limitations

- **SSH key fingerprint logging** — Cowrie's out-of-the-box config may not emit `cowrie.client.fingerprint` events. If your `ssh_keys` table stays empty, this is why. The ingester handles the event correctly; the issue is upstream in Cowrie's logger config.
- **Last-write-wins on cluster conflicts** — if a session matches seeds from two different clusters, it ends up in whichever was processed last. A future version could flag these as ambiguous.
- **No web UI** — everything is driven from Telegram. This is deliberate (mobile-first operator experience) but limits exploratory analysis. CSV export per cluster would be a natural addition.
