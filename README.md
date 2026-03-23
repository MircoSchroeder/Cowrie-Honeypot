🛡️ Projektübersicht
Dieses Projekt demonstriert die Bereitstellung, Wartung und Analyse eines Cowrie-Honeypots zur Überwachung realer automatisierter Angriffe und Malware-Kampagnen. Durch die Simulation eines verwundbaren SSH-Servers habe ich TTY-Sitzungen und bösartige Binärdateien gesammelt, um moderne Angriffsmuster wie Cryptojacking und Datenexfiltration zu verstehen.
Wichtige technische Kernkompetenzen:
 * Linux-Administration: Systemhärtung, SSH-Konfiguration und Prozessüberwachung.
 * Netzwerksicherheit: Port-Redirection, Firewall-Management (iptables/nftables).
 * Forensik & Analyse: Log-Parsing, Malware-Verhaltensanalyse und TTY-Sitzungsrekonstruktion.
___________________________________

🏗️ Bereitstellung & Architektur
Der Fokus lag hier auf einer stabilen und isolierten Umgebung, um das Host-System vor Ausbrüchen zu schützen.
 * Betriebssystem: Ubuntu 22.04 LTS (gehärtet)
 * Umgebung: Docker auf einem Virtual Private Server (VPS)

![IMG_4871](https://github.com/user-attachments/assets/37551694-8240-41b1-a79a-482cdb1cbf9c)

   
 * Netzwerk: Einsatz von iptables, um eingehenden Traffic von Port 22 auf den Cowrie-Listener (Port 2222) umzuleiten.
 * Protokollierung: Integration von JSON-Logs für eine automatisierte Auswertung.
> Internal Tooling: Zur Analyse wurden benutzerdefinierte Python-Skripte eingesetzt.
___________________________________

🔍 Fallstudie: Angriffskampagne März 2026
Basierend auf der Analyse der gesammelten TTY-Sitzungen und Downloads wurde eine koordinierte Kampagne der Akteure RedTail und Multiverze identifiziert.

![IMG_4874](https://github.com/user-attachments/assets/2357231d-5d5f-4c10-a844-b64f188bdac8)
![IMG_4873](https://github.com/user-attachments/assets/c5554393-2540-445b-9adb-dea3710536d9)


1. Angriffsphasen
 * Reconnaissance (Aufklärung): Automatisierte Skripte nutzten Befehle wie uname, whoami und netstat mit speziellen Delimitern (z. B. BSEP_A1B2C3), um die Ergebnisse effizient für Datenbanken zu parsen.
 * Datenexfiltration: Gezielte Suche nach Telegram-Sitzungsdaten (.local/share/TelegramDesktop) und SMS-Gateway-Schnittstellen (/dev/ttyUSB), vermutlich um Multi-Faktor-Authentifizierungen (2FA) zu umgehen.
 * Infektion: Redundante Download-Strategie mittels curl, wget und TCP-Redirection über IP-Adressen der Alibaba Cloud.
2. Malware-Analyse (Cryptojacking)
 * Payloads: Mehrstufiger Angriff zur Installation von Monero (XMR) Minern.
 * Persistenz: Automatische Injektion von SSH-Public-Keys in die authorized_keys.
 * Evasion (Tarnung):
   * Nutzung von memfd_create für Fileless Execution direkt im RAM.
   * UPX-gepackte Binärdateien und statische Kompilierung für maximale Kompatibilität.
   * Einsatz von Cleanup-Skripten (clean.sh), um konkurrierende Malware und Miner zu entfernen.
___________________________________

🛠️ Wartung & Betrieb
Ein produktiver Honeypot erfordert kontinuierliches Management:
 * Log-Rotation: Konfiguriert, um Speicherplatzmangel bei Massenscans zu verhindern.
 * Monitoring: Überwachung der Systemverfügbarkeit via Uptime-Kuma.
 * System-Updates: Regelmäßiges Patchen des Host-Betriebssystems, während der "verwundbare" Zustand des Containers für die Forschung erhalten bleibt.
___________________________________

📈 Erkenntnisse (Lessons Learned)
 * Automatisierte Aggression: Die Geschwindigkeit, mit der Angreifer Bereinigungsskripte einsetzen, zeigt einen hart umkämpften "Markt" für gekaperte CPU-Leistung.

 * Mehr als nur Mining: Der Fokus auf SMS- und Telegram-Logs beweist, dass Cryptojacking oft nur der erste Schritt zum Identitätsdiebstahl ist.
   
 * Detektion: Standard-Dateiscanner greifen bei modernen memfd_create-Techniken ins Leere; verhaltensbasierte Überwachung ist essenziell.

   ![IMG_4875](https://github.com/user-attachments/assets/af69de1e-5187-46cd-895c-a935105e65bc)

   ![IMG_4751](https://github.com/user-attachments/assets/3dcc543d-aca7-4c75-835b-5781a9c37a55)



 * Security Note: Haftungsausschluss: Dieses Projekt wurde ausschließlich zu Forschungszwecken in einer kontrollierten Umgebung erstellt.
