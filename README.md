# 🍯 Cowrie SSH Honeypot — Production Deployment & Threat Intelligence

> A fully operational SSH honeypot running on a public-facing Hetzner VPS, capturing real-world attack campaigns, malware samples, and attacker TTY sessions — with automated Telegram alerting and AbuseIPDB reporting.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Infrastructure](#infrastructure)
- [Live Honeypot Activity](#live-honeypot-activity)
- [Telegram Alert Bot](#telegram-alert-bot)
- [Threat Campaign: mdrfckr Botnet](#threat-campaign-mdrfckr-botnet)
- [Captured Malware & Downloads](#captured-malware--downloads)
- [Malware Analysis: VirusTotal](#malware-analysis-virustotal)
- [IOC List](#ioc-list)
- [Setup](#setup)
- [Repository Structure](#repository-structure)

---

## Overview

This project documents a **production SSH honeypot** deployed on a real public IP, not a local lab. It captures live attack traffic from automated botnets and manual intrusion attempts worldwide.

**Goals:**
- Capture attacker TTY sessions and command sequences
- Collect and analyze dropped malware samples
- Identify and document recurring threat campaigns
- Automate real-time alerting with IP reputation enrichment

**Stack:** Cowrie · Python · Telegram Bot API · AbuseIPDB · Hetzner VPS · Ubuntu 24.04

---

## Infrastructure

| Component | Details |
|---|---|
| **VPS Provider** | Hetzner Cloud |
| **OS** | Ubuntu 24.04 LTS |
| **RAM** | 4 GB |
| **Cowrie Mode** | Native (non-Docker) |
| **Honeypot Port** | 22 (redirected via iptables) |
| **Real SSH Port** | Custom (not disclosed) |
| **Additional Services** | Portainer, Nginx Proxy Manager, Uptime Kuma, Fail2Ban |

Cowrie runs natively on the host (migrated from Docker) for better log access and process isolation. Real SSH traffic is separated via `iptables` port redirection.

---

## Live Honeypot Activity

The following screenshot shows Cowrie's debug output during a live attack session — including the SSH key exchange (`curve25519-sha256`), cipher negotiation (`aes256-ctr`), and a failed login attempt with username `planka` / password `123456`.

![Cowrie Live Log](screenshots/cowrie_live_log.jpg)
*Real-time Cowrie log output: SSH handshake, key exchange, and failed authentication attempt captured live.*

This level of detail allows reconstruction of exactly what an attacker's client sent — including which SSH algorithms they support, which can be used for attacker fingerprinting.

---

## Telegram Alert Bot

All honeypot events are forwarded in real-time to a private Telegram channel via `analyze_cowrie.py`. The bot enriches each event with:

- **AbuseIPDB score** — reputation check per attacker IP
- **Country flag** — geolocation
- **Event type** — login attempt, successful auth, command executed

### System Reconnaissance

This screenshot shows an attacker running a full automated recon script immediately after gaining access — collecting hostname, OS version, CPU info, memory, running processes, open ports, cron jobs, and more in a single command chain using `___BSEP_A1B2C3___` as a delimiter to parse output programmatically.

![Telegram Bot - Attacker Commands](screenshots/telegram_commands.jpg)
*Automated post-exploitation recon script captured via Telegram alert — attacker systematically enumerating the system.*

This is consistent with an automated exploitation framework, not manual hacking.

---

## Threat Campaign: mdrfckr Botnet

One of the most significant findings was a **recurring botnet campaign** identified by its SSH key fingerprint `mdrfckr`. The same key was observed across multiple IPs in France 🇫🇷, China 🇨🇳, and South Korea 🇰🇷 — strongly suggesting a coordinated botnet with persistent infrastructure.

### What the Attacker Did

After authentication, the attacker immediately:
1. Cleared the `.ssh` directory
2. Injected their own SSH public key into `authorized_keys` (persistence)
3. Set restrictive permissions to lock out the legitimate owner
4. Attempted further credential-based attacks from the same IP

![Telegram Bot - mdrfckr Campaign](screenshots/telegram_mdrfckr.jpg)
*Telegram alert showing the mdrfckr SSH key being written to `authorized_keys` — classic persistence mechanism. Note the AbuseIPDB score of 100% for all involved IPs.*

The key comment `mdrfckr` in the public key string allowed correlation across multiple sessions and IPs, turning a single event into a trackable campaign.

---

## Captured Malware & Downloads

Cowrie's download capture feature saved all files that attackers attempted to fetch or execute. The files were stored with their SHA256 hashes as filenames — a common convention for malware repositories.

![Malware Downloads - Part 1](screenshots/cowrie_downloads_1.jpg)
*Cowrie download directory — captured binaries stored by SHA256 hash. Note file sizes ranging from small stagers (96 bytes) to full payloads (30+ MB).*

![Malware Downloads - Part 2](screenshots/tty_directory.jpg)
*Additional captured samples — timestamps show activity across multiple days, indicating sustained campaign activity.*

### Attacker Dropper Command

The following TTY session shows the full malware deployment command captured by Cowrie. The attacker uses a multi-fallback download chain (`curl` → `wget` → raw TCP socket via `/dev/tcp`) to fetch a binary from `8.222.174.150:60111`, then executes it with a base64-encoded payload argument.

![TTY Session - Malware Dropper](screenshots/cowrie_tty_session.jpg)
*Full attacker TTY session: multi-stage dropper using curl/wget/dev/tcp fallback chain, followed by execution with a large base64-encoded payload — consistent with XMRig miner deployment.*

**Observed TTY techniques:**
- `curl` with fallback to `wget` and raw `/dev/tcp` socket
- Binary dropped to `/tmp/` with random filename
- `chmod +x` followed by immediate execution
- Base64-encoded configuration blob passed as argument (XMRig pool config)
- Credential written to `/tmp/.opass`

---

## Malware Analysis: VirusTotal

Captured samples were submitted to VirusTotal for static analysis. The primary sample was identified as a **UPX-packed ELF binary** with advanced evasion techniques.

![VirusTotal Analysis](screenshots/virustotal.jpg)
*VirusTotal analysis of captured binary — classified as `miner.cciiu/mirai` by multiple vendors. Cynet: Malicious (score 99). Uses `memfd_create` for fileless execution.*

**Key findings:**
| Property | Value |
|---|---|
| **Packer** | UPX 5.0 |
| **Family** | miner.cciiu / Mirai variant |
| **Execution** | Fileless via `memfd_create` syscall |
| **Fallback** | `/dev/shm` temporary file |
| **Evasion** | Direct syscalls instead of library imports |
| **AhnLab** | Linux/CoinMiner.Gen3 |
| **AliCloud** | Miner:Multi/XmrigGo.SY |
| **Cynet Score** | 99/100 (Malicious) |

The use of `memfd_create` to unpack and execute the payload entirely in memory — with no file written to disk — represents a sophisticated evasion technique commonly seen in advanced Linux malware.

---

## IOC List

Indicators of Compromise collected during operation:

### SSH Key Fingerprints
| Fingerprint | Campaign |
|---|---|
| `mdrfckr` (key comment) | mdrfckr botnet persistence |

### Malicious IPs (AbuseIPDB Score 100%)
| IP | Country | Activity |
|---|---|---|
| `50.104.70.175` | 🇺🇸 US | mdrfckr key injection, credential brute-force |
| `187.191.2.213` | 🇲🇽 MX | Post-auth command execution |
| `8.222.174.150` | 🇨🇳 CN | Malware C2 / payload host |

### Malware Hashes (SHA256)
> See `/downloads/` directory in Cowrie data path for full sample collection.

---

## Setup

See [`scripts/setup_cowrie.sh`](scripts/setup_cowrie.sh) for the full automated installation script.

**Quick overview:**

```bash
# 1. Clone and run setup
git clone https://github.com/MircoSchroeder/Cowrie-Honeypot
cd Cowrie-Honeypot
chmod +x scripts/setup_cowrie.sh
sudo bash scripts/setup_cowrie.sh

# 2. Configure Telegram bot
cp scripts/analyze_cowrie.example.env scripts/analyze_cowrie.env
nano scripts/analyze_cowrie.env  # Add your bot token + chat ID

# 3. Start alert bot
python3 scripts/analyze_cowrie.py
```

**iptables redirect (port 22 → Cowrie's 2222):**
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables-save > /etc/iptables/rules.v4
```

---

## Repository Structure

```
Cowrie-Honeypot/
├── README.md
├── screenshots/
│   ├── cowrie_live_log.jpeg        # Live Cowrie debug output
│   ├── cowrie_downloads_1.jpeg     # Captured malware samples (part 1)
│   ├── cowrie_downloads_2.jpeg     # Captured malware samples (part 2)
│   ├── cowrie_tty_session.jpeg     # Full attacker TTY session
│   ├── telegram_commands.jpeg      # Telegram alert: recon commands
│   ├── telegram_mdrfckr.jpeg       # Telegram alert: mdrfckr campaign
│   └── virustotal.jpeg             # VirusTotal malware analysis
└── scripts/
    ├── setup_cowrie.sh             # Automated Cowrie installation
    ├── analyze_cowrie.py           # Telegram alert bot
    └── analyze_cowrie.example.env  # Config template
```

---

## Skills Demonstrated

- **SSH Honeypot Deployment** — Production VPS, iptables redirection, native Cowrie
- **Threat Intelligence** — Campaign correlation via SSH key fingerprinting across multiple IPs
- **Malware Analysis** — Static analysis with VirusTotal, identifying UPX packing, fileless execution, miner families
- **Python Automation** — Real-time log parsing, Telegram API integration, AbuseIPDB enrichment
- **Linux Administration** — systemd service management, iptables, log rotation, process isolation
- **Incident Documentation** — IOC extraction, TTY session analysis, dropper command reconstruction

---

*All data collected on infrastructure I own and operate. Attacker IPs have been reported to AbuseIPDB.*
