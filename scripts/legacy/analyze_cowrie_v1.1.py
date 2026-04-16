import json
import requests
import time
import os

# --- KONFIGURATION ---
COWRIE_LOG = '/home/.../cowrie.json'
TG_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'
TG_CHAT_ID = 'YOUR_TELEGRAM_CHAT_ID'
ABUSEIPDB_KEY = 'YOUR_ABUSEIPDB_API_KEY'

def check_ip(ip):
    if ABUSEIPDB_KEY == 'DEIN_ABUSE_KEY':
        return "Kein AbuseIPDB-Key"
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_KEY}
    try:
        response = requests.get(url, headers=headers, params={'ipAddress': ip, 'maxAgeInDays': '90'}, timeout=5)
        data = response.json()
        return f"{data['data']['countryCode']} (Score: {data['data']['abuseConfidenceScore']}%)"
    except:
        return "Prüfung fehlgeschlagen"

def send_telegram(message):
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": message, "parse_mode": "HTML"}
    while True:
        try:
            r = requests.post(url, json=payload, timeout=5)
            if r.status_code == 429:
                retry_after = r.json().get('parameters', {}).get('retry_after', 60)
                print(f"⚠️ Telegram Rate Limit. Warte {retry_after} Sekunden...")
                time.sleep(retry_after + 5)
                continue
            break
        except Exception as e:
            print(f"Telegram Fehler: {e}")
            break

def build_report(ip, ip_info, events):
    logins = [e for e in events if e.get('eventid') == 'cowrie.login.success']
    commands = [e for e in events if e.get('eventid') == 'cowrie.command.input']
    downloads = [e for e in events if e.get('eventid') == 'cowrie.session.file_download']
    failed = [e for e in events if e.get('eventid') == 'cowrie.login.failed']

    if not logins and not commands and not downloads:
        return None

    lines = []
    lines.append(f"📋 <b>Angriffsbericht</b>")
    lines.append(f"🌐 IP: <code>{ip}</code> | {ip_info}")
    lines.append(f"🔴 Fehlgeschlagene Logins: {len(failed)}")

    if logins:
        lines.append(f"\n🚨 <b>Erfolgreiche Einbrüche: {len(logins)}</b>")
        # Einzigartige User/Passwort Kombinationen, max 5
        seen = []
        for e in logins:
            combo = (e.get('username', '?'), e.get('password', '?'))
            if combo not in seen:
                seen.append(combo)
            if len(seen) >= 5:
                break
        for user, pw in seen:
            lines.append(f"  👤 <code>{user}</code> / 🔑 <code>{pw}</code>")
        if len(logins) > len(seen):
            lines.append(f"  ... und weitere Versuche mit denselben Kombinationen")

    if commands:
        lines.append(f"\n💻 <b>Ausgeführte Befehle: {len(commands)}</b>")
        unique_cmds = list(dict.fromkeys([e.get('input', '?') for e in commands]))[:5]
        for cmd in unique_cmds:
            lines.append(f"  ⌨️ <code>{cmd[:80]}</code>")
        if len(commands) > 5:
            lines.append(f"  ... und {len(commands) - 5} weitere Befehle")

    if downloads:
        lines.append(f"\n⬇️ <b>Heruntergeladene Dateien: {len(downloads)}</b>")
        for d in downloads[:3]:
            file_info = d.get('url') or d.get('outfile') or d.get('shasum', 'unbekannt')
            lines.append(f"  🔗 {str(file_info)[:80]}")

    return "\n".join(lines)

def monitor_logs():
    print("🚀 Live-Überwachung gestartet. Warte auf neue Angriffe...")

    f = open(COWRIE_LOG, 'r')
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
                    print("🔄 Neue Log-Datei erkannt, wechsle...")
                    if current_ip and current_events:
                        ip_info = check_ip(current_ip)
                        report = build_report(current_ip, ip_info, current_events)
                        if report:
                            send_telegram(report)
                    f.close()
                    f = open(COWRIE_LOG, 'r')
                    current_inode = new_inode
                    current_ip = None
                    current_events = []
            except Exception as e:
                print(f"Fehler bei Dateiprüfung: {e}")
            continue

        try:
            event = json.loads(line.strip())
        except json.JSONDecodeError:
            continue

        ip = event.get('src_ip')
        if not ip:
            continue

        event_id = event.get('eventid', '')

        if event_id not in ('cowrie.login.success', 'cowrie.login.failed',
                            'cowrie.command.input', 'cowrie.session.file_download'):
            continue

        if ip != current_ip:
            if current_ip and current_events:
                ip_info = check_ip(current_ip)
                report = build_report(current_ip, ip_info, current_events)
                if report:
                    print(f"📤 Sende Bericht für {current_ip}...")
                    send_telegram(report)
            current_ip = ip
            current_events = []

        current_events.append(event)

if __name__ == "__main__":
    monitor_logs()
