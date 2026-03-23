🛡️ Project Overview
This project demonstrates the deployment, maintenance, and analysis of a Cowrie Honeypot to monitor real-world automated attacks and malware campaigns. By simulating a vulnerable SSH server, I collected and analyzed TTY sessions and malicious binaries to understand modern attack patterns like Cryptojacking and Data Exfiltration.
Key Technical Skills Demonstrated:
 * Linux Administration: Hardening, SSH configuration, and process monitoring.
 * Network Security: Port redirection, firewall management (iptables/nftables).
 * Forensics & Analysis: Log file parsing, malware behavior analysis, and TTY session reconstruction.
🏗️ Deployment & Architecture
Describe how you built it. For a SysAdmin role, this is the most important part!
 * OS: Ubuntu 22.04 LTS (Hardened)
 * Environment: Docker / Virtual Private Server (VPS)
 * Redirection: Used iptables to redirect traffic from port 22 to the Cowrie listener on port 2222.
 * Logging: Integrated with JSON logs for automated parsing.
> Internal Tooling: [Optional: Mention if you used ELK Stack, Splunk, or just custom Bash scripts for analysis].
> 
🔍 Case Study: March 2026 Attack Campaign
Here you use the info from your screenshot.
Based on the analysis of collected TTY sessions and downloads, a highly coordinated campaign by actors RedTail and Multiverze was identified.
1. Attack Phases
 * Reconnaissance: Automated scripts used uname, whoami, and netstat with custom delimiters (e.g., BSEP_A1B2C3) for database parsing.
 * Data Exfiltration: Targeted search for Telegram session data (.local/share/TelegramDesktop) and SMS gateway interfaces (/dev/ttyUSB), likely to bypass Two-Factor Authentication (2FA).
 * Infection: Redundant download strategy using curl, wget, and TCP-redirection from Alibaba Cloud IPs.
2. Malware Analysis (Cryptojacking)
 * Payloads: Multistage attack deploying Monero (XMR) miners.
 * Persistence: Automated injection of SSH public keys into authorized_keys.
 * Evasion: * Use of memfd_create for fileless execution in RAM.
   * UPX-packed binaries and static compilation to remain environment-independent.
   * Cleanup scripts (clean.sh) to remove competing malware/miners.
🛠️ Maintenance & Operations
This shows you can "run" a system long-term.
 * Log Rotation: Configured to prevent disk exhaustion during mass-scanning events.
 * Monitoring: [Describe how you check if it's still alive – e.g., a simple Cronjob or Uptime-Kuma].
 * System Updates: Regular patching of the host OS while maintaining the "vulnerable" state of the container.
📈 Lessons Learned
 * Automated Aggression: The speed at which attackers deploy cleanup scripts shows a highly competitive "market" for hijacked CPU power.
 * Beyond Mining: The focus on SMS and Telegram logs indicates that simple cryptojacking is often paired with identity theft.
 * Detection: Standard file scanners are insufficient against modern memfd_create techniques; behavior-based monitoring is key.
Was du noch hinzufügen könntest (der "Pro"-Faktor):
 * Ein kleiner "How to run this"-Teil: Ein kurzes docker-compose.yml Snippet in der README zeigt, dass du mit "Infrastructure as Code" vertraut bist.
 * Screenshots: Wenn du ein Dashboard hast (z.B. von den Cowrie-Logs), füge einen Screenshot ein. Visuelle Beweise wirken bei Recruitern Wunder.
 * Security Note: Füge einen Disclaimer hinzu ("This was built for research purposes in a controlled environment"), das zeigt Verantwortungsbewusstsein.
![IMG_4761](https://github.com/user-attachments/assets/7dfdab5d-1d1e-4b4d-bd3e-763f4492a3ed)
