#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════╗
║        ShieldScan - Security Auditor v2.0        ║
║    Cross-platform PC Security Audit Tool         ║
║            Windows & Linux | MIT License          ║
╚══════════════════════════════════════════════════╝

Auto-detects OS (Windows/Linux) and runs relevant security checks.
Displays results in a beautiful TUI with a final security score.

Usage:
    python security_auditor.py          # full scan
    python security_auditor.py --quick  # quick scan (skip slow checks)
    python security_auditor.py --export # export results to JSON

Requirements:
    pip install rich
"""

import platform
import subprocess
import socket
import os
import sys
import json
import re
import argparse
import hashlib
import glob
import stat
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich import box
except ImportError:
    print("[!] Library 'rich' is required. Install it:")
    print("    pip install rich")
    sys.exit(1)

# Fix Windows console encoding for Unicode (cp1251 → utf-8)
import io
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "buffer"):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "buffer"):
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
        os.system("chcp 65001 >nul 2>&1")
    except Exception:
        pass

console = Console(force_terminal=True)

# ─── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    name: str
    status: str          # "pass", "warn", "fail", "info"
    message: str
    details: Optional[str] = None
    score_impact: int = 0  # negative = bad

@dataclass
class CategoryResult:
    name: str
    icon: str
    checks: list = field(default_factory=list)

# ─── Helpers ───────────────────────────────────────────────────────────────────

def run_cmd(cmd: str, shell: bool = True, timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def run_ps(cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    return run_cmd(f'powershell -NoProfile -Command "{cmd}"', timeout=timeout)

def is_admin() -> bool:
    if CURRENT_OS == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def status_icon(s: str) -> str:
    return {"pass": "[green]✔[/]", "warn": "[yellow]⚠[/]", "fail": "[red]✘[/]", "info": "[blue]ℹ[/]"}.get(s, "?")

def score_color(score: int) -> str:
    if score >= 80: return "green"
    if score >= 60: return "yellow"
    return "red"

CURRENT_OS = platform.system()

# ╔═══════════════════════════════════════════════════════════════════════════════╗
# ║  CROSS-PLATFORM CHECKS                                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════════╝

def check_open_ports() -> CheckResult:
    if CURRENT_OS == "Windows":
        code, out, _ = run_cmd("netstat -an | findstr LISTENING")
    else:
        code, out, _ = run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")

    if not out:
        return CheckResult("Открытые порты", "info", "Не удалось получить список портов")

    lines = [l.strip() for l in out.splitlines() if l.strip()]
    risky_ports = {
        21: "FTP", 23: "Telnet", 25: "SMTP", 135: "RPC", 137: "NetBIOS", 139: "NetBIOS",
        445: "SMB", 1433: "MSSQL", 1434: "MSSQL-Browser", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
        5986: "WinRM-S", 6379: "Redis", 8080: "HTTP-Alt", 9200: "Elasticsearch",
        27017: "MongoDB", 11211: "Memcached"
    }

    found_risky = set()
    for line in lines:
        for port, name in risky_ports.items():
            if f":{port} " in line or f":{port}\t" in line or line.endswith(f":{port}"):
                found_risky.add(f":{port} ({name})")

    details = f"Всего слушающих портов: {len(lines)}"
    if found_risky:
        details += f"\nПотенциально опасные: {', '.join(sorted(found_risky))}"

    if len(found_risky) >= 3:
        return CheckResult("Открытые порты", "fail", f"Найдено {len(found_risky)} потенциально опасных портов", details, -15)
    elif found_risky:
        return CheckResult("Открытые порты", "warn", f"Найдено {len(found_risky)} потенциально опасных портов", details, -8)
    return CheckResult("Открытые порты", "pass", f"Опасных портов не обнаружено ({len(lines)} всего)", details, 0)

def check_suspicious_connections() -> CheckResult:
    if CURRENT_OS == "Windows":
        code, out, _ = run_cmd("netstat -an | findstr ESTABLISHED")
    else:
        code, out, _ = run_cmd("ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null | grep ESTABLISHED")

    if not out:
        return CheckResult("Активные соединения", "info", "Не удалось получить данные")

    lines = [l for l in out.splitlines() if l.strip()]
    suspicious_ports = {4444, 5555, 6666, 6667, 6668, 6669, 1234, 31337, 12345, 9001, 4443, 8443, 1337, 7777}
    found = set()
    for line in lines:
        for part in line.split():
            try:
                if ":" in part:
                    port = int(part.rsplit(":", 1)[-1])
                    if port in suspicious_ports:
                        found.add(f"Порт {port}")
            except (ValueError, IndexError):
                continue

    details = f"Всего ESTABLISHED: {len(lines)}"
    if found:
        details += f"\nПодозрительные: {', '.join(found)}"
        return CheckResult("Активные соединения", "warn", "Обнаружены подозрительные соединения", details, -10)
    if len(lines) > 300:
        return CheckResult("Активные соединения", "warn", f"Аномально много соединений: {len(lines)}", details, -5)
    return CheckResult("Активные соединения", "pass", f"Подозрительных нет ({len(lines)} всего)", details, 0)

def check_dns_settings() -> CheckResult:
    if CURRENT_OS == "Windows":
        code, out, _ = run_cmd('ipconfig /all | findstr /C:"DNS Servers" /C:"DNS-серверы"')
    else:
        code, out, _ = run_cmd("cat /etc/resolv.conf 2>/dev/null | grep nameserver")

    if not out:
        return CheckResult("DNS-настройки", "info", "Не удалось определить DNS")

    known_safe = {
        "8.8.8.8": "Google", "8.8.4.4": "Google", "1.1.1.1": "Cloudflare",
        "1.0.0.1": "Cloudflare", "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
        "77.88.8.8": "Yandex", "77.88.8.1": "Yandex",
        "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    }

    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', out)
    recognized, unknown = [], []
    for ip in ips:
        if ip in known_safe:
            recognized.append(f"{ip} ({known_safe[ip]})")
        elif ip.startswith(("127.", "192.168.", "10.", "172.")):
            recognized.append(f"{ip} (Локальный)")
        else:
            unknown.append(ip)

    details = "DNS: " + ", ".join(recognized + unknown)
    if unknown:
        return CheckResult("DNS-настройки", "warn", f"Неизвестные DNS: {', '.join(unknown)}", details, -5)
    if ips:
        return CheckResult("DNS-настройки", "pass", f"DNS: {', '.join(recognized)}", details, 0)
    return CheckResult("DNS-настройки", "info", "DNS не определены", details, 0)

def check_hosts_file() -> CheckResult:
    hosts = r"C:\Windows\System32\drivers\etc\hosts" if CURRENT_OS == "Windows" else "/etc/hosts"
    try:
        with open(hosts, "r", errors="ignore") as f:
            content = f.read()
    except (PermissionError, FileNotFoundError) as e:
        return CheckResult("Файл hosts", "info", f"Нет доступа: {type(e).__name__}")

    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
    suspicious = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            ip, host = parts[0], parts[1]
            if host == "localhost" or "localhost" in host:
                continue
            suspicious.append(f"{ip} → {host}")

    details = f"Нестандартных записей: {len(suspicious)}"
    if suspicious:
        details += "\n" + "\n".join(suspicious[:10])
    if len(suspicious) > 20:
        return CheckResult("Файл hosts", "warn", f"Много нестандартных записей: {len(suspicious)}", details, -5)
    if suspicious:
        return CheckResult("Файл hosts", "info", f"{len(suspicious)} нестандартных записей", details, 0)
    return CheckResult("Файл hosts", "pass", "Файл hosts чистый", details, 0)

def check_uptime() -> CheckResult:
    if CURRENT_OS == "Windows":
        _, out, _ = run_ps("(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object -ExpandProperty Days")
    else:
        _, out, _ = run_cmd("awk '{print int($1/86400)}' /proc/uptime 2>/dev/null")
    try:
        days = int(out.strip())
    except (ValueError, AttributeError):
        return CheckResult("Аптайм системы", "info", "Не удалось определить")
    if days > 30:
        return CheckResult("Аптайм системы", "warn", f"Без перезагрузки {days} дней", "Обновления могут ждать перезагрузки", -5)
    return CheckResult("Аптайм системы", "pass", f"Последняя перезагрузка: {days} дн. назад", None, 0)

def check_temp_suspicious() -> CheckResult:
    """Scan temp dirs for suspicious executables."""
    if CURRENT_OS == "Windows":
        temp_dirs = [os.environ.get("TEMP", r"C:\Users\Default\AppData\Local\Temp")]
        exts = (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".scr", ".com", ".msi")
    else:
        temp_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
        exts = (".sh", ".elf", ".bin", ".py")

    suspicious = []
    for td in temp_dirs:
        if not os.path.isdir(td):
            continue
        try:
            for entry in os.scandir(td):
                try:
                    if entry.is_file() and entry.name.lower().endswith(exts):
                        size_kb = entry.stat().st_size // 1024
                        suspicious.append(f"{entry.path} ({size_kb}KB)")
                except (PermissionError, OSError):
                    continue
        except PermissionError:
            continue

    if len(suspicious) > 10:
        return CheckResult("Файлы в TEMP", "warn", f"{len(suspicious)} исполняемых файлов", "\n".join(suspicious[:8]), -8)
    elif suspicious:
        return CheckResult("Файлы в TEMP", "info", f"{len(suspicious)} исполняемых файлов", "\n".join(suspicious[:8]), -3)
    return CheckResult("Файлы в TEMP", "pass", "Подозрительных файлов нет", None, 0)

def check_ip_forwarding() -> CheckResult:
    """Check if IP forwarding is enabled."""
    if CURRENT_OS == "Windows":
        code, out, _ = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v IPEnableRouter 2>nul')
        if "0x1" in out:
            return CheckResult("IP Forwarding", "warn", "IP-маршрутизация ВКЛЮЧЕНА", None, -5)
        return CheckResult("IP Forwarding", "pass", "IP-маршрутизация выключена", None, 0)
    else:
        _, out, _ = run_cmd("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null")
        if out.strip() == "1":
            return CheckResult("IP Forwarding", "warn", "IP-маршрутизация ВКЛЮЧЕНА", "sysctl net.ipv4.ip_forward = 1", -5)
        return CheckResult("IP Forwarding", "pass", "IP-маршрутизация выключена", None, 0)

def check_ipv6_status() -> CheckResult:
    """Check IPv6 status."""
    if CURRENT_OS == "Windows":
        code, out, _ = run_ps("Get-NetAdapterBinding -ComponentId ms_tcpip6 | Select-Object Name,Enabled | ConvertTo-Json")
        if code != 0:
            return CheckResult("IPv6", "info", "Не удалось проверить")
        try:
            data = json.loads(out)
            if isinstance(data, dict): data = [data]
            enabled = [d["Name"] for d in data if d.get("Enabled")]
            if enabled:
                return CheckResult("IPv6", "info", f"IPv6 включён на: {', '.join(enabled[:3])}", "Если не используется — дополнительная поверхность атаки", 0)
        except Exception:
            pass
        return CheckResult("IPv6", "info", "Не удалось определить")
    else:
        _, out, _ = run_cmd("cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
        if out.strip() == "0":
            return CheckResult("IPv6", "info", "IPv6 включён", "Если не используется — можно отключить", 0)
        if out.strip() == "1":
            return CheckResult("IPv6", "pass", "IPv6 отключён", None, 0)
        return CheckResult("IPv6", "info", "Не удалось определить")

def check_arp_table() -> CheckResult:
    """Check ARP table for spoofing indicators."""
    if CURRENT_OS == "Windows":
        _, out, _ = run_cmd("arp -a")
    else:
        _, out, _ = run_cmd("ip neigh show 2>/dev/null || arp -n 2>/dev/null")

    if not out:
        return CheckResult("ARP-таблица", "info", "Не удалось получить")

    macs = {}
    for line in out.splitlines():
        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
        if mac_match:
            mac = mac_match.group(0).lower()
            if mac not in ("ff:ff:ff:ff:ff:ff", "ff-ff-ff-ff-ff-ff"):
                macs.setdefault(mac, []).append(line[:60])

    duplicates = {mac: e for mac, e in macs.items() if len(e) > 1}
    if duplicates:
        details = "\n".join(f"MAC {mac}: {len(e)} IP" for mac, e in duplicates.items())
        return CheckResult("ARP-таблица", "warn", f"Дублирующиеся MAC-адреса ({len(duplicates)})", details, -8)
    return CheckResult("ARP-таблица", "pass", f"ARP в норме ({len(macs)} записей)", None, 0)

# ╔═══════════════════════════════════════════════════════════════════════════════╗
# ║  WINDOWS-SPECIFIC CHECKS                                                     ║
# ╚═══════════════════════════════════════════════════════════════════════════════╝

def win_check_defender() -> CheckResult:
    code, out, _ = run_ps("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,AntispywareEnabled | ConvertTo-Json")
    if code != 0 or not out:
        return CheckResult("Windows Defender", "info", "Не удалось получить статус")
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return CheckResult("Windows Defender", "info", "Ошибка парсинга")

    av = data.get("AntivirusEnabled", False)
    rt = data.get("RealTimeProtectionEnabled", False)
    asp = data.get("AntispywareEnabled", False)
    sig = data.get("AntivirusSignatureLastUpdated", "")
    issues, impact = [], 0

    if not av: issues.append("Антивирус ВЫКЛЮЧЕН"); impact -= 20
    if not rt: issues.append("Real-time ВЫКЛЮЧЕН"); impact -= 15
    if not asp: issues.append("Антишпион ВЫКЛЮЧЕН"); impact -= 10

    if sig:
        try:
            m = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2})', str(sig))
            if m and (datetime.now() - datetime.strptime(m.group(1), "%Y-%m-%d")).days > 7:
                issues.append("Базы устарели"); impact -= 10
        except Exception: pass

    details = f"AV: {'✔' if av else '✘'} | RT: {'✔' if rt else '✘'} | AS: {'✔' if asp else '✘'}"
    if impact <= -20:
        return CheckResult("Windows Defender", "fail", " | ".join(issues), details, impact)
    if issues:
        return CheckResult("Windows Defender", "warn", " | ".join(issues), details, impact)
    return CheckResult("Windows Defender", "pass", "Defender активен, базы актуальны", details, 0)

def win_check_defender_exclusions() -> CheckResult:
    """Check Defender exclusions."""
    code, out, _ = run_ps("Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension | ConvertTo-Json")
    if code != 0 or not out:
        return CheckResult("Исключения Defender", "info", "Не удалось проверить")
    try:
        data = json.loads(out)
        ep = data.get("ExclusionPath") or []
        epr = data.get("ExclusionProcess") or []
        ee = data.get("ExclusionExtension") or []
        total = len(ep) + len(epr) + len(ee)
        sus_ext = [e for e in ee if e.lower() in (".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr")]
        sus_path = [p for p in ep if any(kw in p.lower() for kw in ("temp", "appdata", "downloads", "desktop"))]
        details = f"Путей: {len(ep)} | Процессов: {len(epr)} | Расширений: {len(ee)}"
        if sus_ext or sus_path:
            return CheckResult("Исключения Defender", "warn", f"Подозрительные исключения ({total})", details, -10)
        if total > 10:
            return CheckResult("Исключения Defender", "warn", f"Много исключений: {total}", details, -5)
        return CheckResult("Исключения Defender", "pass", f"Исключений: {total}", details, 0)
    except Exception:
        return CheckResult("Исключения Defender", "info", "Ошибка парсинга")

def win_check_firewall() -> CheckResult:
    code, out, _ = run_ps("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json")
    if code != 0 or not out:
        return CheckResult("Брандмауэр", "info", "Не удалось проверить")
    try:
        profiles = json.loads(out)
        if isinstance(profiles, dict): profiles = [profiles]
    except json.JSONDecodeError:
        return CheckResult("Брандмауэр", "info", "Ошибка парсинга")
    disabled = [p["Name"] for p in profiles if not p.get("Enabled", True)]
    details = " | ".join(f"{p['Name']}: {'✔' if p.get('Enabled') else '✘'}" for p in profiles)
    if len(disabled) == len(profiles):
        return CheckResult("Брандмауэр", "fail", "Все профили ВЫКЛЮЧЕНЫ!", details, -20)
    if disabled:
        return CheckResult("Брандмауэр", "warn", f"Выключены: {', '.join(disabled)}", details, -10)
    return CheckResult("Брандмауэр", "pass", "Все профили активны", details, 0)

def win_check_uac() -> CheckResult:
    _, out, _ = run_cmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA')
    if "0x0" in out:
        return CheckResult("UAC", "fail", "UAC ВЫКЛЮЧЕН!", None, -15)
    if "0x1" in out:
        _, out2, _ = run_cmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin')
        if "0x0" in out2:
            return CheckResult("UAC", "warn", "UAC вкл., но промпт отключён (auto-elevate)", None, -8)
        return CheckResult("UAC", "pass", "UAC включён", None, 0)
    return CheckResult("UAC", "info", "Не удалось определить")

def win_check_autologon() -> CheckResult:
    _, out, _ = run_cmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v AutoAdminLogon 2>nul')
    if "0x1" in out or '"1"' in out:
        return CheckResult("Автовход", "fail", "Авто-вход ВКЛЮЧЁН", None, -15)
    return CheckResult("Автовход", "pass", "Авто-вход выключен", None, 0)

def win_check_rdp() -> CheckResult:
    _, out, _ = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections')
    if "0x0" in out:
        _, nla, _ = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication')
        if "0x0" in nla:
            return CheckResult("RDP", "fail", "RDP вкл. БЕЗ NLA — BlueKeep!", None, -15)
        return CheckResult("RDP", "warn", "RDP включён (NLA активна)", "Убедитесь, что доступ ограничен", -5)
    if "0x1" in out:
        return CheckResult("RDP", "pass", "RDP выключен", None, 0)
    return CheckResult("RDP", "info", "Не удалось определить")

def win_check_smb_v1() -> CheckResult:
    code, out, _ = run_ps("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json")
    if code != 0: return CheckResult("SMBv1", "info", "Не удалось проверить")
    try:
        if json.loads(out).get("EnableSMB1Protocol", False):
            return CheckResult("SMBv1", "fail", "SMBv1 ВКЛЮЧЁН — EternalBlue!", None, -15)
        return CheckResult("SMBv1", "pass", "SMBv1 выключен", None, 0)
    except Exception:
        return CheckResult("SMBv1", "info", "Не удалось определить")

def win_check_winrm() -> CheckResult:
    _, out, _ = run_cmd("sc query winrm 2>nul")
    if "RUNNING" in out:
        return CheckResult("WinRM", "warn", "WinRM запущен — удалённое управление", "Stop-Service WinRM если не нужно", -8)
    return CheckResult("WinRM", "pass", "WinRM не запущен", None, 0)

def win_check_updates() -> CheckResult:
    code, out, _ = run_ps(
        "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results | "
        "Select-Object LastInstallationSuccessDate | ConvertTo-Json", timeout=15)
    if code != 0 or not out:
        return CheckResult("Обновления Windows", "info", "Не удалось проверить")
    try:
        li = json.loads(out).get("LastInstallationSuccessDate", "")
        if li:
            m = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2})', str(li))
            if m:
                age = (datetime.now() - datetime.strptime(m.group(1), "%Y-%m-%d")).days
                if age > 60: return CheckResult("Обновления", "fail", f"Не обновлялось {age} дней!", None, -15)
                if age > 30: return CheckResult("Обновления", "warn", f"Не обновлялось {age} дней", None, -10)
                return CheckResult("Обновления", "pass", f"Обновлено {age} дн. назад", None, 0)
    except Exception: pass
    return CheckResult("Обновления", "info", "Не удалось определить")

def win_check_autorun() -> CheckResult:
    entries, suspicious = [], []
    for loc in [
        r'reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul',
        r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul',
        r'reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul',
        r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul',
    ]:
        _, out, _ = run_cmd(loc)
        if out:
            for line in out.splitlines():
                line = line.strip()
                if line and "REG_" in line and "HKEY_" not in line:
                    entries.append(line)
    sus_kw = ["temp", "appdata\\local\\temp", "cmd.exe /c", "powershell -e",
              "powershell -enc", "mshta", "wscript", "cscript", "regsvr32",
              "rundll32", "bitsadmin", "certutil"]
    for entry in entries:
        lower = entry.lower()
        for kw in sus_kw:
            if kw in lower: suspicious.append(entry[:80]); break
    if suspicious:
        return CheckResult("Автозагрузка (безопасность)", "warn", f"{len(suspicious)} подозрительных", "\n".join(suspicious[:5]), -10)
    return CheckResult("Автозагрузка (безопасность)", "pass", f"Автозагрузка в норме ({len(entries)})", None, 0)

def win_check_autorun_bloat() -> CheckResult:
    """Analyze startup apps and identify unnecessary bloat that slows boot."""
    # ── Known unnecessary / bloatware (safe to disable) ──
    UNNECESSARY = {
        # Messaging & social
        "discord": "Discord", "telegram": "Telegram", "skype": "Skype",
        "skypebridge": "Skype", "teams": "Microsoft Teams", "slack": "Slack",
        "viber": "Viber", "icq": "ICQ", "whatsapp": "WhatsApp",
        "line": "LINE", "wechat": "WeChat", "zoom": "Zoom",
        # Gaming
        "steam": "Steam", "steamclientbootstrapper": "Steam",
        "epicgameslauncher": "Epic Games", "galaxyclient": "GOG Galaxy",
        "origin": "EA Origin", "ubisoft": "Ubisoft Connect",
        "ubisoftconnect": "Ubisoft Connect", "bethesdanetlauncher": "Bethesda",
        "riotclient": "Riot Client", "battle.net": "Battle.net",
        "razer": "Razer Synapse", "razercentralservice": "Razer Central",
        "razersynapse": "Razer Synapse", "corsair": "iCUE (Corsair)",
        "icue": "iCUE (Corsair)", "logitechg": "Logitech G Hub",
        "lghub": "Logitech G Hub", "steelseries": "SteelSeries GG",
        "msiafterburner": "MSI Afterburner",
        # Cloud storage
        "onedrive": "OneDrive", "dropbox": "Dropbox",
        "googledrivesync": "Google Drive", "googledrivefs": "Google Drive",
        "megasync": "MEGA", "yandexdisk": "Яндекс.Диск",
        "mailrucloud": "Облако Mail.ru", "icloud": "iCloud",
        "nextcloud": "Nextcloud",
        # Browsers
        "chrome": "Google Chrome", "msedge": "Microsoft Edge",
        "yandexbrowser": "Яндекс.Браузер", "opera": "Opera",
        "brave": "Brave", "firefox": "Firefox",
        # Adobe & creative
        "adobecreativecloud": "Adobe CC", "ccxprocess": "Adobe CC Helper",
        "adobe": "Adobe Reader/Updater", "adobearm": "Adobe Updater",
        "adobegclient": "Adobe Genuine", "acrobat": "Adobe Acrobat",
        "acrotray": "Adobe Acrobat Tray",
        # Music & media
        "spotify": "Spotify", "itunes": "iTunes", "ituneshelper": "iTunes Helper",
        "vkmusic": "VK Music", "yandexmusic": "Яндекс.Музыка",
        # Updaters (almost always unnecessary at startup)
        "updater": "Updater (общий)", "update": "Update сервис",
        "softwareupdate": "Software Update", "autoupdate": "Auto Update",
        "googleupdate": "Google Update", "chromeupdater": "Chrome Updater",
        "javaupdatesched": "Java Update", "jusched": "Java Updater",
        "adobeaupdate": "Adobe Update",
        # System tools (usually not needed)
        "ccleaner": "CCleaner", "ccleanerbrowser": "CCleaner Browser",
        "everything": "Everything", "anydesk": "AnyDesk",
        "teamviewer": "TeamViewer",
        # OEM bloatware
        "samsungmagician": "Samsung Magician", "lenovovantage": "Lenovo Vantage",
        "hpsupportassistant": "HP Support Assistant", "dellsupportassist": "Dell SupportAssist",
        "myasus": "MyASUS", "asusoptimization": "ASUS Optimization",
        "aaboradmin": "Acer Quick Access",
        # Misc
        "grammarly": "Grammarly", "notion": "Notion", "todoist": "Todoist",
        "clipchamp": "Clipchamp", "cortana": "Cortana",
        "gamingservices": "Gaming Services", "xbox": "Xbox App",
        "microsoftedgeupdate": "Edge Update",
        "yourphone": "Связь с телефоном", "phonelink": "Phone Link",
    }

    # ── Known essential / needed for security & hardware ──
    ESSENTIAL = {
        "securityhealthsystray": "Windows Security",
        "windowsdefender": "Windows Defender",
        "securityhealth": "Windows Security",
        "msascui": "Windows Defender UI",
        "windowssecurity": "Windows Security",
        "realtekhdaudiomanager": "Realtek Audio",
        "rthdvcpl": "Realtek Audio",
        "rtkngui64": "Realtek Audio",
        "nvidiashare": "NVIDIA Share",
        "nvcontainer": "NVIDIA Container",
        "nvcpldaemon": "NVIDIA Control Panel",
        "nvidiabackend": "NVIDIA Backend",
        "igfxtray": "Intel Graphics",
        "igfxem": "Intel Graphics",
        "persistence": "Intel Graphics",
        "hotkeyscmds": "Intel Hotkeys",
        "synaptics": "Synaptics Touchpad",
        "touchpaddriver": "Touchpad Driver",
        "etdctrl": "ELAN Touchpad",
        "sysmon": "Sysmon (мониторинг)",
        "kaspersky": "Kaspersky AV",
        "avp": "Kaspersky AV",
        "avgui": "AVG AV",
        "avast": "Avast AV",
        "esetnod32": "ESET NOD32",
        "drweb": "Dr.Web",
        "bdagent": "Bitdefender",
    }

    # Collect autorun entries from registry + startup folder + WMI
    raw_entries = []

    # Registry
    for loc in [
        r'reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul',
        r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul',
    ]:
        _, out, _ = run_cmd(loc)
        if out:
            for line in out.splitlines():
                line = line.strip()
                if line and "REG_" in line and "HKEY_" not in line:
                    parts = line.split(None, 2)
                    name = parts[0] if parts else line
                    path = parts[2] if len(parts) > 2 else ""
                    raw_entries.append({"name": name, "path": path, "source": "Реестр"})

    # Startup folder
    startup_paths = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    ]
    for sp in startup_paths:
        if os.path.isdir(sp):
            try:
                for f in os.listdir(sp):
                    if f.lower().endswith((".lnk", ".exe", ".bat", ".cmd", ".url")):
                        raw_entries.append({"name": f.rsplit(".", 1)[0], "path": os.path.join(sp, f), "source": "Папка автозагрузки"})
            except PermissionError:
                pass

    # WMI startup (fallback / additional)
    code, out, _ = run_ps(
        "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | ConvertTo-Json",
        timeout=15)
    if code == 0 and out:
        try:
            wmi = json.loads(out)
            if isinstance(wmi, dict): wmi = [wmi]
            existing_names = {e["name"].lower() for e in raw_entries}
            for item in wmi:
                n = item.get("Name", "")
                if n.lower() not in existing_names:
                    raw_entries.append({
                        "name": n,
                        "path": item.get("Command", ""),
                        "source": item.get("Location", "WMI")
                    })
        except Exception:
            pass

    if not raw_entries:
        return CheckResult("Автозагрузка (анализ)", "info", "Не удалось получить список")

    # Categorize
    unnecessary = []
    essential = []
    unknown = []

    for entry in raw_entries:
        name_lower = entry["name"].lower().replace(" ", "").replace("-", "").replace("_", "")
        path_lower = entry.get("path", "").lower().replace(" ", "").replace("-", "").replace("_", "")
        combined = name_lower + " " + path_lower

        matched = False

        # Check essential first
        for key, label in ESSENTIAL.items():
            if key in combined:
                essential.append({"label": label, **entry})
                matched = True
                break

        if matched:
            continue

        # Check unnecessary
        for key, label in UNNECESSARY.items():
            if key in combined:
                unnecessary.append({"label": label, **entry})
                matched = True
                break

        if not matched:
            unknown.append(entry)

    # Build details
    details_lines = []

    if unnecessary:
        details_lines.append(f"🔴 МОЖНО УБРАТЬ ({len(unnecessary)}):")
        for item in unnecessary:
            details_lines.append(f"  ✘ {item['label']} ({item['name']})")

    if essential:
        details_lines.append(f"\n🟢 НУЖНЫЕ ({len(essential)}):")
        for item in essential:
            details_lines.append(f"  ✔ {item['label']}")

    if unknown:
        details_lines.append(f"\n🔵 НЕ ОПРЕДЕЛЕНО ({len(unknown)}):")
        for item in unknown:
            details_lines.append(f"  ? {item['name']}")

    if unnecessary:
        details_lines.append(f"\n💡 Как отключить: Ctrl+Shift+Esc → Автозагрузка")
        details_lines.append(f"   или: Параметры → Приложения → Автозагрузка")

    details = "\n".join(details_lines)
    total = len(raw_entries)
    msg = f"Всего: {total} | Ненужных: {len(unnecessary)} | Нужных: {len(essential)} | Неизвестных: {len(unknown)}"

    if len(unnecessary) >= 8:
        return CheckResult("Автозагрузка (анализ)", "warn", msg, details, -8)
    if len(unnecessary) >= 4:
        return CheckResult("Автозагрузка (анализ)", "info", msg, details, -3)
    if unnecessary:
        return CheckResult("Автозагрузка (анализ)", "info", msg, details, 0)
    return CheckResult("Автозагрузка (анализ)", "pass", msg, details, 0)

def win_check_scheduled_tasks() -> CheckResult:
    code, out, _ = run_ps("Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -and $_.TaskPath -notlike '\\\\Microsoft\\\\*'} | Select-Object TaskName,TaskPath | ConvertTo-Json", timeout=15)
    if code != 0 or not out:
        return CheckResult("Планировщик задач", "info", "Не удалось проверить")
    try:
        tasks = json.loads(out)
        if isinstance(tasks, dict): tasks = [tasks]
        if len(tasks) > 30:
            return CheckResult("Планировщик задач", "warn", f"Много задач: {len(tasks)}", None, -5)
        return CheckResult("Планировщик задач", "pass", f"Задачи в норме ({len(tasks)})", None, 0)
    except Exception:
        return CheckResult("Планировщик задач", "info", "Ошибка парсинга")

def win_check_guest_account() -> CheckResult:
    _, out, _ = run_cmd("net user Guest 2>nul")
    ol = out.lower()
    if ("active" in ol and "yes" in ol) or ("активна" in ol and "да" in ol):
        return CheckResult("Гостевой аккаунт", "fail", "Гостевой аккаунт АКТИВЕН", None, -10)
    return CheckResult("Гостевой аккаунт", "pass", "Гостевой аккаунт отключён", None, 0)

def win_check_password_policy() -> CheckResult:
    _, out, _ = run_cmd("net accounts")
    if not out: return CheckResult("Политика паролей", "info", "Не удалось проверить")
    issues = []
    for line in out.splitlines():
        ll = line.lower()
        if "minimum password length" in ll or "минимальная длина пароля" in ll:
            try:
                v = int(re.search(r'(\d+)', line).group(1))
                if v < 8: issues.append(f"Мин. длина: {v}")
            except Exception: pass
        if ("lockout threshold" in ll or "блокировка" in ll) and ("never" in ll or "никогда" in ll or ": 0" in line):
            issues.append("Блокировка выключена")
    if issues:
        return CheckResult("Политика паролей", "warn", " | ".join(issues), None, -5 * len(issues))
    return CheckResult("Политика паролей", "pass", "Политика в норме", None, 0)

def win_check_bitlocker() -> CheckResult:
    code, out, _ = run_ps("Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus | ConvertTo-Json")
    if code != 0 or not out:
        _, out2, _ = run_cmd("manage-bde -status C: 2>nul")
        if "Protection On" in out2 or "Защита включена" in out2:
            return CheckResult("BitLocker", "pass", "BitLocker активен на C:", None, 0)
        if "Protection Off" in out2 or "Защита выключена" in out2:
            return CheckResult("BitLocker", "warn", "BitLocker ВЫКЛЮЧЕН на C:", None, -10)
        return CheckResult("BitLocker", "info", "Не удалось определить")
    try:
        vols = json.loads(out)
        if isinstance(vols, dict): vols = [vols]
        unp = [v["MountPoint"] for v in vols if v.get("ProtectionStatus", 0) == 0]
        if unp: return CheckResult("BitLocker", "warn", f"Не зашифрованы: {', '.join(unp)}", None, -10)
        return CheckResult("BitLocker", "pass", "Все диски зашифрованы", None, 0)
    except Exception:
        return CheckResult("BitLocker", "info", "Ошибка парсинга")

def win_check_secure_boot() -> CheckResult:
    _, out, _ = run_ps("Confirm-SecureBootUEFI")
    if "True" in out: return CheckResult("Secure Boot", "pass", "Secure Boot включён", None, 0)
    if "False" in out: return CheckResult("Secure Boot", "warn", "Secure Boot ВЫКЛЮЧЕН", "Включите в BIOS/UEFI", -8)
    return CheckResult("Secure Boot", "info", "Не удалось определить (Legacy BIOS?)")

def win_check_powershell_policy() -> CheckResult:
    _, out, _ = run_ps("Get-ExecutionPolicy")
    if not out: return CheckResult("PS Execution Policy", "info", "Не удалось определить")
    policy = out.strip()
    if policy in ("Unrestricted", "Bypass"):
        return CheckResult("PS Execution Policy", "fail", f"{policy} — любой скрипт запустится!", None, -12)
    if policy == "RemoteSigned":
        return CheckResult("PS Execution Policy", "pass", f"{policy}", None, 0)
    if policy == "Restricted":
        return CheckResult("PS Execution Policy", "pass", f"{policy} (максимальная)", None, 0)
    return CheckResult("PS Execution Policy", "info", f"{policy}")

def win_check_network_shares() -> CheckResult:
    _, out, _ = run_cmd("net share 2>nul")
    if not out: return CheckResult("Сетевые шары", "info", "Не удалось проверить")
    custom = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("Share") or line.startswith("Имя"): continue
        name = line.split()[0] if line.split() else ""
        if name and not name.endswith("$") and name not in ("The", "command", "Команда"):
            custom.append(name)
    if len(custom) > 3: return CheckResult("Сетевые шары", "warn", f"Открытые: {', '.join(custom)}", None, -8)
    if custom: return CheckResult("Сетевые шары", "info", f"Шары: {', '.join(custom)}", None, 0)
    return CheckResult("Сетевые шары", "pass", "Нет пользовательских шар", None, 0)

def win_check_security_events() -> CheckResult:
    _, out, _ = run_ps(
        "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 50 -ErrorAction SilentlyContinue | "
        "Measure-Object | Select-Object -ExpandProperty Count", timeout=15)
    try:
        count = int(out.strip())
    except (ValueError, AttributeError):
        return CheckResult("Журнал безопасности", "info", "Не удалось прочитать")
    if count >= 50: return CheckResult("Журнал безопасности", "warn", f"Много неудачных входов: {count}+", "Возможна brute-force", -10)
    if count >= 10: return CheckResult("Журнал безопасности", "info", f"Неудачных попыток: {count}", None, -3)
    return CheckResult("Журнал безопасности", "pass", f"Неудачных попыток: {count}", None, 0)

def win_check_core_isolation() -> CheckResult:
    _, out, _ = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity" /v Enabled 2>nul')
    if "0x1" in out: return CheckResult("Core Isolation (HVCI)", "pass", "Целостность памяти включена", None, 0)
    if "0x0" in out: return CheckResult("Core Isolation (HVCI)", "warn", "Целостность памяти ВЫКЛЮЧЕНА", None, -8)
    return CheckResult("Core Isolation (HVCI)", "info", "Не удалось определить")

def win_check_wsl() -> CheckResult:
    _, out, _ = run_cmd("wsl --list --verbose 2>nul")
    if out and "NAME" in out.upper():
        distros = [l.strip() for l in out.splitlines()[1:] if l.strip()]
        return CheckResult("WSL", "info", f"WSL-дистрибутивов: {len(distros)}", "Расширяет поверхность атаки", -3)
    return CheckResult("WSL", "pass", "WSL не обнаружен", None, 0)

def win_check_usb_history() -> CheckResult:
    _, out, _ = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR" 2>nul')
    if not out: return CheckResult("История USB", "info", "Не удалось проверить")
    devices = [l for l in out.splitlines() if "USBSTOR\\" in l and "Disk" in l]
    if len(devices) > 20:
        return CheckResult("История USB", "warn", f"Подключалось {len(devices)} накопителей", "Рассмотрите политику USB", -3)
    return CheckResult("История USB", "info", f"USB-накопителей: {len(devices)}", None, 0)

def win_check_spectre_meltdown() -> CheckResult:
    _, out, _ = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v FeatureSettingsOverride 2>nul')
    if "0x0" in out: return CheckResult("Spectre/Meltdown", "pass", "Защита активна", None, 0)
    return CheckResult("Spectre/Meltdown", "info", "Статус неопределён", None, 0)

# ╔═══════════════════════════════════════════════════════════════════════════════╗
# ║  LINUX-SPECIFIC CHECKS                                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════════╝

def linux_check_firewall() -> CheckResult:
    code, out, _ = run_cmd("ufw status 2>/dev/null")
    if code == 0 and out:
        if "active" in out.lower(): return CheckResult("Брандмауэр (UFW)", "pass", "UFW активен", out[:200], 0)
        if "inactive" in out.lower(): return CheckResult("Брандмауэр (UFW)", "fail", "UFW ВЫКЛЮЧЕН", None, -15)
    code, out, _ = run_cmd("iptables -L -n 2>/dev/null | head -20")
    if code == 0 and out:
        rules = [l for l in out.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("target")]
        if rules: return CheckResult("Брандмауэр (iptables)", "pass", f"{len(rules)} правил", None, 0)
        return CheckResult("Брандмауэр (iptables)", "warn", "iptables без правил", None, -10)
    code, out, _ = run_cmd("nft list ruleset 2>/dev/null | head -5")
    if code == 0 and out.strip(): return CheckResult("Брандмауэр (nftables)", "pass", "nftables активен", None, 0)
    return CheckResult("Брандмауэр", "fail", "Файрвол не обнаружен", None, -15)

def linux_check_ssh() -> CheckResult:
    config = "/etc/ssh/sshd_config"
    if not os.path.exists(config): return CheckResult("SSH-сервер", "info", "SSH не установлен")
    try:
        with open(config) as f: content = f.read()
    except PermissionError:
        return CheckResult("SSH-сервер", "info", "Нет доступа к sshd_config")
    issues = []
    root = re.search(r'^\s*PermitRootLogin\s+(\S+)', content, re.MULTILINE)
    if root and root.group(1).lower() == "yes": issues.append("Root-вход разрешён")
    pas = re.search(r'^\s*PasswordAuthentication\s+(\S+)', content, re.MULTILINE)
    if pas and pas.group(1).lower() == "yes": issues.append("Парольная авторизация")
    port = re.search(r'^\s*Port\s+(\d+)', content, re.MULTILINE)
    p = port.group(1) if port else "22"
    if p == "22": issues.append("Порт 22")
    x11 = re.search(r'^\s*X11Forwarding\s+(\S+)', content, re.MULTILINE)
    if x11 and x11.group(1).lower() == "yes": issues.append("X11 Forwarding")
    max_auth = re.search(r'^\s*MaxAuthTries\s+(\d+)', content, re.MULTILINE)
    if max_auth and int(max_auth.group(1)) > 6: issues.append(f"MaxAuthTries={max_auth.group(1)}")
    if len(issues) >= 3: return CheckResult("SSH-сервер", "warn", " | ".join(issues), f"Порт: {p}", -4 * len(issues))
    if issues: return CheckResult("SSH-сервер", "info", " | ".join(issues), f"Порт: {p}", -4 * len(issues))
    return CheckResult("SSH-сервер", "pass", "SSH настроен безопасно", f"Порт: {p}", 0)

def linux_check_selinux_apparmor() -> CheckResult:
    code, out, _ = run_cmd("getenforce 2>/dev/null")
    if code == 0 and out.strip():
        mode = out.strip()
        if mode == "Enforcing": return CheckResult("MAC (SELinux/AppArmor)", "pass", f"SELinux: {mode}", None, 0)
        if mode == "Permissive": return CheckResult("MAC (SELinux/AppArmor)", "warn", f"SELinux: {mode} (только лог)", None, -5)
        return CheckResult("MAC (SELinux/AppArmor)", "fail", f"SELinux: {mode}", None, -10)
    _, out, _ = run_cmd("cat /sys/module/apparmor/parameters/enabled 2>/dev/null")
    if out.strip() == "Y": return CheckResult("MAC (SELinux/AppArmor)", "pass", "AppArmor включён", None, 0)
    return CheckResult("MAC (SELinux/AppArmor)", "warn", "Ни SELinux, ни AppArmor не активны", None, -8)

def linux_check_fail2ban() -> CheckResult:
    code, out, _ = run_cmd("systemctl is-active fail2ban 2>/dev/null")
    if code == 0 and "active" in out:
        _, jails, _ = run_cmd("fail2ban-client status 2>/dev/null | grep 'Number of jail'")
        return CheckResult("Fail2Ban", "pass", f"Fail2Ban активен" + (f" ({jails.strip()})" if jails else ""), None, 0)
    code2, _, _ = run_cmd("which fail2ban-server 2>/dev/null")
    if code2 == 0: return CheckResult("Fail2Ban", "warn", "Fail2Ban установлен, но не запущен", None, -5)
    code3, _, _ = run_cmd("systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null")
    if code3 == 0: return CheckResult("Fail2Ban", "warn", "SSH активен, Fail2Ban не установлен", "apt install fail2ban", -8)
    return CheckResult("Fail2Ban", "info", "Fail2Ban не установлен", None, 0)

def linux_check_disk_encryption() -> CheckResult:
    code, out, _ = run_cmd("lsblk -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null | grep -i crypt")
    if code == 0 and out.strip(): return CheckResult("Шифрование диска", "pass", "LUKS-шифрование обнаружено", out[:150], 0)
    _, dm, _ = run_cmd("dmsetup table --target crypt 2>/dev/null")
    if dm.strip(): return CheckResult("Шифрование диска", "pass", "dm-crypt обнаружен", None, 0)
    return CheckResult("Шифрование диска", "info", "Шифрование не обнаружено", "Рекомендуется LUKS", -5)

def linux_check_suid() -> CheckResult:
    _, out, _ = run_cmd("find / -perm -4000 -type f 2>/dev/null | head -40", timeout=15)
    if not out: return CheckResult("SUID-файлы", "info", "Не удалось проверить")
    known_safe = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/su", "/usr/bin/mount",
        "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/fusermount",
        "/usr/bin/fusermount3", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/openssh/ssh-keysign", "/usr/bin/crontab", "/usr/sbin/pppd",
        "/usr/bin/at", "/usr/lib/snapd/snap-confine",
    }
    files = [l.strip() for l in out.splitlines() if l.strip()]
    unusual = [f for f in files if f not in known_safe]
    if len(unusual) > 5: return CheckResult("SUID-файлы", "warn", f"{len(unusual)} нетипичных", "\n".join(unusual[:8]), -8)
    return CheckResult("SUID-файлы", "pass", f"SUID в норме ({len(files)})", None, 0)

def linux_check_updates() -> CheckResult:
    code, out, _ = run_cmd("apt list --upgradable 2>/dev/null | grep -c upgradable", timeout=15)
    if code == 0 and out.strip().isdigit():
        c = int(out.strip())
        if c > 100: return CheckResult("Обновления", "fail", f"{c} пакетов устарели!", None, -15)
        if c > 50: return CheckResult("Обновления", "warn", f"{c} пакетов устарели", None, -10)
        if c > 0: return CheckResult("Обновления", "info", f"{c} пакетов можно обновить", None, -3)
        return CheckResult("Обновления", "pass", "Все пакеты актуальны", None, 0)
    return CheckResult("Обновления", "info", "Не удалось проверить")

def linux_check_unattended_upgrades() -> CheckResult:
    _, out, _ = run_cmd("dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'")
    if out: return CheckResult("Автообновления", "pass", "unattended-upgrades установлен", None, 0)
    _, out, _ = run_cmd("systemctl is-enabled dnf-automatic.timer 2>/dev/null")
    if "enabled" in (out or ""): return CheckResult("Автообновления", "pass", "dnf-automatic вкл.", None, 0)
    return CheckResult("Автообновления", "warn", "Автообновления не настроены", "apt install unattended-upgrades", -8)

def linux_check_users() -> CheckResult:
    issues = []
    _, out, _ = run_cmd("awk -F: '$3==0 && $1!=\"root\" {print $1}' /etc/passwd 2>/dev/null")
    if out.strip(): issues.append(f"UID 0 (не root): {out.strip()}")
    _, out, _ = run_cmd("awk -F: '$2==\"\" {print $1}' /etc/shadow 2>/dev/null")
    if out.strip(): issues.append(f"Без пароля: {out.strip()}")
    _, out, _ = run_cmd("find /home -maxdepth 1 -type d -perm -o+w 2>/dev/null")
    if out.strip(): issues.append("Домашние каталоги доступны всем")
    _, out, _ = run_cmd("awk -F: '$3>=1000 && $7!~/nologin|false/ {print $1}' /etc/passwd 2>/dev/null")
    if out:
        users = [u.strip() for u in out.splitlines() if u.strip()]
        if len(users) > 10: issues.append(f"Много пользователей с shell: {len(users)}")
    if issues: return CheckResult("Учётные записи", "warn", f"{len(issues)} проблем", "\n".join(issues), -8 * len(issues))
    return CheckResult("Учётные записи", "pass", "Учётные записи в порядке", None, 0)

def linux_check_cron() -> CheckResult:
    suspicious = []
    sus_kw = ["curl.*|.*bash", "wget.*|.*sh", "nc -e", "bash -i >& /dev/tcp", "base64 -d", "eval ", "python -c.*socket"]
    for src in ["crontab -l 2>/dev/null", "cat /etc/crontab 2>/dev/null"]:
        _, out, _ = run_cmd(src)
        if out:
            for line in out.splitlines():
                ll = line.strip()
                if ll.startswith("#") or not ll: continue
                for kw in sus_kw:
                    if re.search(kw, ll, re.IGNORECASE): suspicious.append(ll[:80]); break
    if suspicious: return CheckResult("Задачи cron", "warn", f"{len(suspicious)} подозрительных", "\n".join(suspicious[:5]), -10)
    return CheckResult("Задачи cron", "pass", "Подозрительных задач нет", None, 0)

def linux_check_world_writable() -> CheckResult:
    _, out, _ = run_cmd("find /etc /usr /var -xdev -type f -perm -o+w 2>/dev/null | head -20", timeout=15)
    if not out: return CheckResult("World-writable файлы", "pass", "Не найдено", None, 0)
    files = [l.strip() for l in out.splitlines() if l.strip()]
    if files: return CheckResult("World-writable файлы", "warn", f"Найдено {len(files)} файлов", "\n".join(files[:8]), -5 * min(len(files), 3))
    return CheckResult("World-writable файлы", "pass", "Всё чисто", None, 0)

def linux_check_kernel() -> CheckResult:
    _, kernel, _ = run_cmd("uname -r")
    if not kernel: return CheckResult("Ядро Linux", "info", "Не удалось определить")
    issues = []
    _, aslr, _ = run_cmd("cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
    if aslr.strip() != "2": issues.append(f"ASLR={aslr.strip()} (нужно 2)")
    _, kptr, _ = run_cmd("cat /proc/sys/kernel/kptr_restrict 2>/dev/null")
    if kptr.strip() == "0": issues.append("kptr_restrict=0")
    _, dmesg, _ = run_cmd("cat /proc/sys/kernel/dmesg_restrict 2>/dev/null")
    if dmesg.strip() == "0": issues.append("dmesg доступен всем")
    _, panic, _ = run_cmd("cat /proc/sys/kernel/panic 2>/dev/null")
    if panic.strip() == "0": issues.append("kernel.panic=0 (не перезагрузится)")
    if issues: return CheckResult("Ядро Linux", "warn", f"{len(issues)} проблем", f"Ядро: {kernel}\n" + "\n".join(issues), -4 * len(issues))
    return CheckResult("Ядро Linux", "pass", f"Ядро {kernel} — ОК", None, 0)

def linux_check_kernel_modules() -> CheckResult:
    _, out, _ = run_cmd("lsmod 2>/dev/null")
    if not out: return CheckResult("Модули ядра", "info", "Не удалось получить")
    modules = [l.split()[0] for l in out.splitlines()[1:] if l.strip()]
    suspicious = ["rootkit", "hide", "sniff", "keylog", "backdoor", "diamorphine", "reptile"]
    found = [m for m in modules if any(s in m.lower() for s in suspicious)]
    if found: return CheckResult("Модули ядра", "fail", f"Подозрительные: {', '.join(found)}", None, -20)
    return CheckResult("Модули ядра", "pass", f"{len(modules)} модулей, подозрительных нет", None, 0)

def linux_check_core_dumps() -> CheckResult:
    _, ulimit, _ = run_cmd("ulimit -c 2>/dev/null")
    if ulimit.strip() == "unlimited":
        return CheckResult("Core dumps", "warn", "Без ограничений", "Могут содержать пароли из памяти", -5)
    return CheckResult("Core dumps", "pass", "Core dumps ограничены", None, 0)

def linux_check_tmp_permissions() -> CheckResult:
    _, out, _ = run_cmd("mount | grep ' /tmp '")
    if not out: return CheckResult("Безопасность /tmp", "info", "/tmp не отдельный раздел")
    issues = []
    if "noexec" not in out.lower(): issues.append("Нет noexec")
    if "nosuid" not in out.lower(): issues.append("Нет nosuid")
    if issues: return CheckResult("Безопасность /tmp", "warn", " | ".join(issues), "mount -o remount,noexec,nosuid /tmp", -5 * len(issues))
    return CheckResult("Безопасность /tmp", "pass", "/tmp безопасен", None, 0)

def linux_check_services() -> CheckResult:
    dangerous = {"telnet": "Telnet", "rsh": "RSH", "rlogin": "Rlogin", "tftp": "TFTP",
                 "vsftpd": "FTP", "proftpd": "FTP", "xinetd": "xinetd", "avahi-daemon": "Avahi"}
    found = []
    for svc, desc in dangerous.items():
        code, _, _ = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
        if code == 0: found.append(desc)
    if found: return CheckResult("Опасные сервисы", "warn", f"Запущены: {', '.join(found)}", None, -5 * len(found))
    return CheckResult("Опасные сервисы", "pass", "Опасных сервисов нет", None, 0)

def linux_check_auditd() -> CheckResult:
    code, out, _ = run_cmd("systemctl is-active auditd 2>/dev/null")
    if code == 0 and "active" in out:
        _, rules, _ = run_cmd("auditctl -l 2>/dev/null | wc -l")
        return CheckResult("Аудит (auditd)", "pass", f"auditd активен ({rules.strip()} правил)", None, 0)
    return CheckResult("Аудит (auditd)", "info", "auditd не запущен", None, -3)

def linux_check_sudo_config() -> CheckResult:
    issues = []
    _, out, _ = run_cmd("grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'")
    if out.strip(): issues.append("Найдены NOPASSWD-правила")
    _, out, _ = run_cmd("grep -r 'ALL=(ALL).*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' | grep -v '%sudo' | grep -v '%wheel'")
    if out.strip(): issues.append("Широкие sudo-права")
    if issues: return CheckResult("Конфигурация sudo", "warn", " | ".join(issues), None, -5 * len(issues))
    return CheckResult("Конфигурация sudo", "pass", "sudo настроен корректно", None, 0)

def linux_check_sensitive_permissions() -> CheckResult:
    checks = {"/etc/shadow": "640", "/etc/passwd": "644", "/etc/gshadow": "640", "/etc/ssh/sshd_config": "600"}
    issues = []
    for path, expected in checks.items():
        if not os.path.exists(path): continue
        try:
            mode = oct(os.stat(path).st_mode)[-3:]
            if int(mode, 8) > int(expected, 8):
                issues.append(f"{path}: {mode} (≤{expected})")
        except (PermissionError, OSError): continue
    if issues: return CheckResult("Права на конфиги", "warn", f"{len(issues)} файлов с лишними правами", "\n".join(issues), -5 * len(issues))
    return CheckResult("Права на конфиги", "pass", "Права корректны", None, 0)

def linux_check_bash_history() -> CheckResult:
    hist = os.path.expanduser("~/.bash_history")
    if not os.path.exists(hist): return CheckResult("Bash-история", "info", "Файл не найден")
    try:
        with open(hist, "r", errors="ignore") as f: lines = f.readlines()
    except PermissionError: return CheckResult("Bash-история", "info", "Нет доступа")
    sus_kw = ["curl.*|.*bash", "wget.*|.*sh", "nc -e", "bash -i >& /dev/tcp", "python -c.*socket", "base64 -d", "chmod 777", "rm -rf /"]
    found = []
    for line in lines[-500:]:
        for kw in sus_kw:
            if re.search(kw, line.strip(), re.IGNORECASE): found.append(line.strip()[:80]); break
    if found: return CheckResult("Bash-история", "warn", f"{len(found)} подозрительных команд", "\n".join(found[:5]), -5)
    return CheckResult("Bash-история", "pass", "Подозрительных команд нет", f"Проверено {min(500, len(lines))}", 0)

# ╔═══════════════════════════════════════════════════════════════════════════════╗
# ║  MALWARE DETECTION CHECKS (cross-platform)                                   ║
# ╚═══════════════════════════════════════════════════════════════════════════════╝

# ── VirusTotal API ─────────────────────────────────────────────────────────────

VT_API_KEY = os.environ.get("VT_API_KEY", "")

def _vt_check_hash(sha256: str) -> Optional[dict]:
    """Query VirusTotal for a file hash. Returns None if unavailable."""
    if not VT_API_KEY:
        return None
    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VT_API_KEY}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            name = data.get("data", {}).get("attributes", {}).get("meaningful_name", "")
            return {"malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "name": name}
    except Exception:
        return None

def _sha256_file(path: str) -> Optional[str]:
    """Calculate SHA256 of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError, FileNotFoundError):
        return None

def _collect_files_to_scan() -> list[dict]:
    """Collect suspicious files from autorun, temp, startup paths."""
    files = []

    if CURRENT_OS == "Windows":
        # Autorun executables from registry
        for loc in [
            r'reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul',
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul',
        ]:
            _, out, _ = run_cmd(loc)
            if out:
                for line in out.splitlines():
                    line = line.strip()
                    if "REG_" in line and "HKEY_" not in line:
                        # Extract path from registry value
                        match = re.search(r'REG_\w+\s+(.+)', line)
                        if match:
                            path = match.group(1).strip().strip('"').split('"')[0].split(' /')[0].split(' -')[0]
                            if os.path.isfile(path):
                                files.append({"path": path, "source": "Автозагрузка"})

        # TEMP executables
        temp = os.environ.get("TEMP", "")
        if temp and os.path.isdir(temp):
            try:
                for entry in os.scandir(temp):
                    if entry.is_file() and entry.name.lower().endswith((".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs")):
                        files.append({"path": entry.path, "source": "TEMP"})
            except PermissionError:
                pass

        # Downloads folder
        downloads = os.path.expanduser("~\\Downloads")
        if os.path.isdir(downloads):
            try:
                for entry in os.scandir(downloads):
                    if entry.is_file() and entry.name.lower().endswith((".exe", ".msi", ".scr")):
                        files.append({"path": entry.path, "source": "Загрузки"})
            except PermissionError:
                pass

    else:  # Linux
        for d in ["/tmp", "/var/tmp", "/dev/shm"]:
            if not os.path.isdir(d):
                continue
            try:
                for entry in os.scandir(d):
                    if entry.is_file():
                        try:
                            if entry.stat().st_mode & 0o111:  # executable
                                files.append({"path": entry.path, "source": d})
                        except (PermissionError, OSError):
                            continue
            except PermissionError:
                continue

        # Check /home/*/.local/share for suspicious executables
        for home in glob.glob("/home/*"):
            for subdir in [".local/bin", ".local/share", ".config/autostart"]:
                full = os.path.join(home, subdir)
                if os.path.isdir(full):
                    try:
                        for entry in os.scandir(full):
                            if entry.is_file() and entry.name.endswith((".sh", ".elf", ".bin")):
                                files.append({"path": entry.path, "source": subdir})
                    except PermissionError:
                        continue

    # Deduplicate and limit
    seen = set()
    unique = []
    for f in files:
        if f["path"] not in seen:
            seen.add(f["path"])
            unique.append(f)
    return unique[:50]  # Limit to avoid long scan times

def check_virustotal() -> CheckResult:
    """Check suspicious files against VirusTotal database."""
    if not VT_API_KEY:
        return CheckResult(
            "VirusTotal (хеши)", "info",
            "API-ключ не задан",
            "Установите переменную VT_API_KEY:\n"
            "  Windows: set VT_API_KEY=ваш_ключ\n"
            "  Linux:   export VT_API_KEY=ваш_ключ\n"
            "Бесплатный ключ: https://www.virustotal.com/gui/join-us",
            0
        )

    files = _collect_files_to_scan()
    if not files:
        return CheckResult("VirusTotal (хеши)", "pass", "Нет файлов для проверки", None, 0)

    malicious_files = []
    suspicious_files = []
    clean = 0
    errors = 0
    checked = 0

    import time

    for f in files[:16]:  # VT free = 4 req/min, limit to 16 max
        sha = _sha256_file(f["path"])
        if not sha:
            errors += 1
            continue

        result = _vt_check_hash(sha)
        checked += 1

        if result is None:
            errors += 1
            continue

        if result["malicious"] > 0:
            malicious_files.append(f"🔴 {result['malicious']} AV обнаружили: {os.path.basename(f['path'])} [{f['source']}]")
        elif result["suspicious"] > 0:
            suspicious_files.append(f"🟡 {result['suspicious']} AV подозревают: {os.path.basename(f['path'])} [{f['source']}]")
        else:
            clean += 1

        # Rate limiting: 4 requests per minute for free VT API
        if checked % 4 == 0 and checked < len(files[:16]):
            time.sleep(60)

    details_lines = []
    if malicious_files:
        details_lines.extend(malicious_files)
    if suspicious_files:
        details_lines.extend(suspicious_files)
    details_lines.append(f"\nПроверено: {checked} | Чисто: {clean} | Ошибок: {errors}")
    details = "\n".join(details_lines)

    if malicious_files:
        return CheckResult("VirusTotal (хеши)", "fail",
                           f"Обнаружено {len(malicious_files)} вредоносных файлов!", details, -20)
    if suspicious_files:
        return CheckResult("VirusTotal (хеши)", "warn",
                           f"{len(suspicious_files)} подозрительных файлов", details, -10)
    return CheckResult("VirusTotal (хеши)", "pass",
                       f"Проверено {checked} файлов — всё чисто", details, 0)

# ── Digital Signatures (Windows) ──────────────────────────────────────────────

def win_check_signatures() -> CheckResult:
    """Verify digital signatures of executables in autorun."""
    # Collect autorun executable paths
    exe_paths = []

    for loc in [
        r'reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul',
        r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul',
    ]:
        _, out, _ = run_cmd(loc)
        if out:
            for line in out.splitlines():
                match = re.search(r'REG_\w+\s+(.+)', line.strip())
                if match:
                    raw = match.group(1).strip()
                    # Extract executable path (handle quotes, args)
                    if raw.startswith('"'):
                        end = raw.find('"', 1)
                        path = raw[1:end] if end > 0 else raw.strip('"')
                    else:
                        path = raw.split(' /')[0].split(' -')[0].strip()
                    if path.lower().endswith((".exe", ".dll")) and os.path.isfile(path):
                        exe_paths.append(path)

    # Also check running processes with unusual paths
    code, out, _ = run_ps(
        "Get-Process | Where-Object {$_.Path -ne $null} | "
        "Select-Object -ExpandProperty Path -Unique | "
        "Where-Object {$_ -notlike 'C:\\Windows\\*'}",
        timeout=15
    )
    if code == 0 and out:
        for line in out.splitlines():
            p = line.strip()
            if p and os.path.isfile(p) and p not in exe_paths:
                exe_paths.append(p)

    if not exe_paths:
        return CheckResult("Цифровые подписи", "info", "Нет файлов для проверки")

    unsigned = []
    invalid = []
    signed = 0
    errors = 0

    for exe in exe_paths[:30]:  # Limit
        code, out, _ = run_ps(
            f"(Get-AuthenticodeSignature '{exe}').Status",
            timeout=10
        )
        if code != 0:
            errors += 1
            continue

        status = out.strip()
        if status == "Valid":
            signed += 1
        elif status == "NotSigned":
            unsigned.append(os.path.basename(exe))
        elif status in ("HashMismatch", "Invalid"):
            invalid.append(os.path.basename(exe))
        else:
            # UnknownError, NotTrusted, etc.
            unsigned.append(f"{os.path.basename(exe)} ({status})")

    details_lines = []
    if invalid:
        details_lines.append("🔴 ПОВРЕЖДЁННАЯ ПОДПИСЬ:")
        for f in invalid[:5]:
            details_lines.append(f"  ✘ {f}")
    if unsigned:
        details_lines.append(f"\n🟡 БЕЗ ПОДПИСИ ({len(unsigned)}):")
        for f in unsigned[:10]:
            details_lines.append(f"  ? {f}")
    details_lines.append(f"\nПодписаны: {signed} | Без подписи: {len(unsigned)} | Повреждены: {len(invalid)}")
    details = "\n".join(details_lines)

    if invalid:
        return CheckResult("Цифровые подписи", "fail",
                           f"{len(invalid)} файлов с повреждённой подписью!", details, -15)
    if len(unsigned) > 5:
        return CheckResult("Цифровые подписи", "warn",
                           f"{len(unsigned)} файлов без подписи", details, -8)
    if unsigned:
        return CheckResult("Цифровые подписи", "info",
                           f"{len(unsigned)} без подписи, {signed} подписаны", details, -3)
    return CheckResult("Цифровые подписи", "pass",
                       f"Все {signed} файлов подписаны", details, 0)

# ── Process Anomaly Detection ────────────────────────────────────────────────

def check_process_anomalies() -> CheckResult:
    """Detect suspicious running processes."""
    anomalies = []

    if CURRENT_OS == "Windows":
        # Get process list with paths
        code, out, _ = run_ps(
            "Get-Process | Where-Object {$_.Path -ne $null} | "
            "Select-Object Name,Path,Id | ConvertTo-Json",
            timeout=15
        )
        if code != 0 or not out:
            return CheckResult("Аномалии процессов", "info", "Не удалось получить список процессов")

        try:
            procs = json.loads(out)
            if isinstance(procs, dict): procs = [procs]
        except json.JSONDecodeError:
            return CheckResult("Аномалии процессов", "info", "Ошибка парсинга")

        # System processes that should only run from specific paths
        expected_paths = {
            "svchost": "c:\\windows\\system32\\",
            "csrss": "c:\\windows\\system32\\",
            "lsass": "c:\\windows\\system32\\",
            "services": "c:\\windows\\system32\\",
            "smss": "c:\\windows\\system32\\",
            "wininit": "c:\\windows\\system32\\",
            "winlogon": "c:\\windows\\system32\\",
            "taskhost": "c:\\windows\\system32\\",
            "taskhostw": "c:\\windows\\system32\\",
            "explorer": "c:\\windows\\",
            "dwm": "c:\\windows\\system32\\",
            "conhost": "c:\\windows\\system32\\",
            "spoolsv": "c:\\windows\\system32\\",
            "dllhost": "c:\\windows\\system32\\",
        }

        # Names often mimicked by malware (typosquatting)
        suspicious_names = {
            "svch0st", "scvhost", "svchosl", "svchosts", "svchost32",
            "csrs", "csrrs", "cssrs", "lssas", "lsas", "lsassa",
            "explore", "iexplorer", "explor3r", "exp1orer",
            "svhost", "dwn", "winlogln", "taskhosw",
            "runtime", "systemprocess", "windowsupdate", "securityservice",
        }

        for proc in procs:
            name_lower = proc.get("Name", "").lower()
            path_lower = (proc.get("Path") or "").lower().replace("/", "\\")

            # Check 1: system process running from wrong location
            for sys_proc, expected in expected_paths.items():
                if name_lower == sys_proc and expected not in path_lower:
                    anomalies.append(f"🔴 {proc['Name']} запущен из {proc['Path']} (должен быть в {expected})")

            # Check 2: typosquatting names
            if name_lower in suspicious_names:
                anomalies.append(f"🔴 Имитация системного процесса: {proc['Name']} (PID {proc.get('Id', '?')})")

            # Check 3: executables from suspicious locations
            sus_dirs = ["\\appdata\\local\\temp\\", "\\programdata\\", "\\public\\",
                        "\\downloads\\", "\\desktop\\", "\\recycle"]
            for sd in sus_dirs:
                if sd in path_lower and name_lower not in ("onedrive", "teams", "discord", "slack"):
                    anomalies.append(f"🟡 Процесс из подозрительной папки: {proc['Name']} → {proc['Path'][:60]}")
                    break

        # Check 4: PowerShell with encoded commands
        code2, out2, _ = run_cmd('wmic process where "name=\'powershell.exe\'" get CommandLine 2>nul')
        if out2:
            for line in out2.splitlines():
                ll = line.strip().lower()
                if any(flag in ll for flag in ["-encodedcommand", "-enc ", "-e ", "-ec "]):
                    if len(ll) > 20:  # avoid matching the header
                        anomalies.append(f"🔴 PowerShell с закодированной командой: {line.strip()[:80]}")
                if "-noprofile" in ll and "-windowstyle hidden" in ll:
                    anomalies.append(f"🟡 Скрытый PowerShell: {line.strip()[:80]}")

    else:  # Linux
        _, out, _ = run_cmd("ps aux 2>/dev/null")
        if not out:
            return CheckResult("Аномалии процессов", "info", "Не удалось получить список процессов")

        lines = out.splitlines()[1:]  # skip header

        for line in lines:
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            user, pid, cpu, mem = parts[0], parts[1], parts[2], parts[3]
            cmd = parts[10]
            cmd_lower = cmd.lower()

            # Check 1: processes consuming extreme CPU/memory
            try:
                if float(cpu) > 90:
                    anomalies.append(f"🟡 Высокая загрузка CPU ({cpu}%): {cmd[:60]}")
                if float(mem) > 50:
                    anomalies.append(f"🟡 Высокое потребление RAM ({mem}%): {cmd[:60]}")
            except ValueError:
                pass

            # Check 2: reverse shells / suspicious network commands
            shell_patterns = [
                "bash -i", "/dev/tcp/", "nc -e", "ncat -e",
                "python -c", "perl -e.*socket", "ruby -rsocket",
                "socat", "mkfifo /tmp"
            ]
            for pat in shell_patterns:
                if pat in cmd_lower:
                    anomalies.append(f"🔴 Возможный reverse-shell: {cmd[:80]}")
                    break

            # Check 3: crypto miners
            miner_signs = ["xmrig", "minerd", "cpuminer", "stratum+tcp",
                           "cryptonight", "randomx", "pool.mining", "nicehash"]
            for sign in miner_signs:
                if sign in cmd_lower:
                    anomalies.append(f"🔴 Возможный криптомайнер: {cmd[:80]}")
                    break

            # Check 4: suspicious hidden processes
            if cmd.startswith("./") and "/tmp/" in cmd:
                anomalies.append(f"🟡 Запуск из /tmp: {cmd[:80]}")
            if cmd.startswith(".") and not cmd.startswith("./"):
                # dot-prefixed binary (hidden)
                anomalies.append(f"🟡 Скрытый процесс: {cmd[:80]}")

            # Check 5: base64 encoded commands
            if "base64" in cmd_lower and ("decode" in cmd_lower or "-d" in cmd_lower):
                anomalies.append(f"🟡 Base64-декодирование в процессе: {cmd[:80]}")

    # Deduplicate
    anomalies = list(dict.fromkeys(anomalies))

    details = "\n".join(anomalies[:20]) if anomalies else None

    critical = sum(1 for a in anomalies if "🔴" in a)
    warnings = sum(1 for a in anomalies if "🟡" in a)

    if critical > 0:
        return CheckResult("Аномалии процессов", "fail",
                           f"Обнаружено {critical} критических аномалий!", details, -15)
    if warnings > 3:
        return CheckResult("Аномалии процессов", "warn",
                           f"Обнаружено {warnings} подозрительных процессов", details, -8)
    if warnings > 0:
        return CheckResult("Аномалии процессов", "info",
                           f"{warnings} незначительных аномалий", details, -3)
    return CheckResult("Аномалии процессов", "pass",
                       "Подозрительных процессов не обнаружено", details, 0)

# ── Malware Path Scanner ─────────────────────────────────────────────────────

def check_malware_paths() -> CheckResult:
    """Scan typical malware hiding locations for suspicious files."""
    suspicious_files = []

    if CURRENT_OS == "Windows":
        user_profile = os.environ.get("USERPROFILE", r"C:\Users\Default")

        # Typical malware hiding spots
        scan_dirs = [
            (os.path.join(user_profile, "AppData", "Local", "Temp"), "TEMP"),
            (os.path.join(user_profile, "AppData", "Roaming"), "AppData\\Roaming"),
            (r"C:\ProgramData", "ProgramData"),
            (os.path.join(user_profile, "AppData", "Local"), "AppData\\Local"),
            (r"C:\Windows\Temp", "Windows\\Temp"),
        ]

        # Suspicious patterns
        sus_patterns = {
            "names": [
                # Random-looking names (common for malware droppers)
                r'^[a-f0-9]{8,}\.exe$',         # hex-named exe
                r'^[a-z]{1,3}\d{2,}\.exe$',      # short name + numbers
                r'^tmp[a-f0-9]+\.exe$',           # tmp + hex
                r'^~\$.+\.exe$',                  # ~$ prefix
                r'.*\.exe\.exe$',                 # double extension
                r'.*\.(exe|dll|scr)\.tmp$',       # disguised as tmp
                r'.*\s{2,}\.exe$',                # spaces before extension
                # Known malware names / tools
                r'^mimikatz',
                r'^lazagne',
                r'^procdump',
                r'^psexec',
                r'^netcat',
            ],
            "double_extensions": [
                r'\.(jpg|png|pdf|doc|docx|txt|mp3)\.(exe|scr|bat|cmd|ps1|vbs|js)$',
            ],
        }

        for scan_dir, label in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            try:
                for root, dirs, files in os.walk(scan_dir):
                    # Limit depth to 2
                    depth = root.replace(scan_dir, "").count(os.sep)
                    if depth > 2:
                        dirs.clear()
                        continue

                    for f in files:
                        f_lower = f.lower()

                        # Check double extensions (photo.jpg.exe)
                        for pat in sus_patterns["double_extensions"]:
                            if re.search(pat, f_lower):
                                full = os.path.join(root, f)
                                suspicious_files.append(f"🔴 Двойное расширение: {f} [{label}]")
                                break

                        # Check suspicious names
                        for pat in sus_patterns["names"]:
                            if re.search(pat, f_lower):
                                suspicious_files.append(f"🟡 Подозрительное имя: {f} [{label}]")
                                break

                        # Check hidden executables (dot-prefixed in Windows is unusual)
                        if f.startswith(".") and f_lower.endswith((".exe", ".dll", ".bat", ".ps1")):
                            suspicious_files.append(f"🟡 Скрытый исполняемый: {f} [{label}]")

                        # Very large or very recent executables in TEMP
                        if label == "TEMP" and f_lower.endswith((".exe", ".dll", ".scr")):
                            try:
                                full = os.path.join(root, f)
                                st = os.stat(full)
                                age_hours = (datetime.now().timestamp() - st.st_mtime) / 3600
                                if age_hours < 1:
                                    suspicious_files.append(f"🟡 Свежий .exe в TEMP (<1ч): {f}")
                            except (PermissionError, OSError):
                                pass

            except PermissionError:
                continue

        # Check for suspicious scheduled task files
        tasks_dir = r"C:\Windows\System32\Tasks"
        if os.path.isdir(tasks_dir):
            try:
                for f in os.listdir(tasks_dir):
                    f_lower = f.lower()
                    if any(s in f_lower for s in ["update", "sync", "helper", "service"]):
                        if not any(ok in f_lower for ok in ["microsoft", "google", "adobe", "nvidia", "intel"]):
                            # Could be legit, just flag as info
                            pass  # Too noisy, skip
            except PermissionError:
                pass

    else:  # Linux
        scan_dirs = [
            ("/tmp", "/tmp"),
            ("/var/tmp", "/var/tmp"),
            ("/dev/shm", "/dev/shm"),
        ]

        # Add user dirs
        for home in glob.glob("/home/*"):
            scan_dirs.extend([
                (os.path.join(home, ".local", "share"), "~/.local/share"),
                (os.path.join(home, ".config"), "~/.config"),
                (os.path.join(home, ".cache"), "~/.cache"),
            ])

        for scan_dir, label in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            try:
                for root, dirs, files in os.walk(scan_dir):
                    depth = root.replace(scan_dir, "").count(os.sep)
                    if depth > 2:
                        dirs.clear()
                        continue

                    for f in files:
                        full = os.path.join(root, f)
                        f_lower = f.lower()

                        # Executable in /tmp, /dev/shm
                        if label in ("/tmp", "/var/tmp", "/dev/shm"):
                            try:
                                if os.stat(full).st_mode & 0o111:
                                    # ELF check
                                    try:
                                        with open(full, "rb") as fh:
                                            magic = fh.read(4)
                                        if magic == b'\x7fELF':
                                            suspicious_files.append(f"🔴 ELF-бинарник в {label}: {f}")
                                        elif magic[:2] == b'#!':
                                            suspicious_files.append(f"🟡 Скрипт в {label}: {f}")
                                    except (PermissionError, OSError):
                                        suspicious_files.append(f"🟡 Исполняемый файл в {label}: {f}")
                            except (PermissionError, OSError):
                                continue

                        # Hidden executables in user dirs
                        if f.startswith(".") and not f.startswith(".git"):
                            try:
                                if os.stat(full).st_mode & 0o111:
                                    suspicious_files.append(f"🟡 Скрытый исполняемый: {f} [{label}]")
                            except (PermissionError, OSError):
                                continue

                        # Known miner/backdoor names
                        bad_names = ["xmrig", "kinsing", "kdevtmpfsi", "kthreaddi",
                                     "ksoftirqds", "bioset", ".nspps", "dota3",
                                     "dbused", "solr.sh", "top.sh"]
                        if f_lower in bad_names or any(bn in f_lower for bn in bad_names):
                            suspicious_files.append(f"🔴 Известное имя малвари: {f} [{label}]")

            except PermissionError:
                continue

    # Deduplicate
    suspicious_files = list(dict.fromkeys(suspicious_files))

    details = "\n".join(suspicious_files[:20]) if suspicious_files else None

    critical = sum(1 for s in suspicious_files if "🔴" in s)
    warnings = sum(1 for s in suspicious_files if "🟡" in s)

    if critical > 0:
        return CheckResult("Скан путей малвари", "fail",
                           f"Обнаружено {critical} критических находок!", details, -15)
    if warnings > 5:
        return CheckResult("Скан путей малвари", "warn",
                           f"{warnings} подозрительных файлов", details, -8)
    if warnings > 0:
        return CheckResult("Скан путей малвари", "info",
                           f"{warnings} подозрительных файлов", details, -3)
    return CheckResult("Скан путей малвари", "pass",
                       "Подозрительных файлов не обнаружено", details, 0)

# ╔═══════════════════════════════════════════════════════════════════════════════╗
# ║  SCAN ORCHESTRATOR                                                            ║
# ╚═══════════════════════════════════════════════════════════════════════════════╝

def get_system_info() -> dict:
    info = {
        "os": platform.system(), "os_version": platform.version(),
        "os_release": platform.release(), "hostname": socket.gethostname(),
        "arch": platform.machine(), "python": platform.python_version(),
        "user": os.environ.get("USER") or os.environ.get("USERNAME", "unknown"),
        "admin": is_admin(),
    }
    if CURRENT_OS == "Linux":
        _, out, _ = run_cmd("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
        if out: info["distro"] = out.strip()
    return info

def build_checks(quick: bool = False) -> list[CategoryResult]:
    categories = []

    if CURRENT_OS == "Windows":
        categories.append(CategoryResult("Антивирус и защита", "🛡️", [
            win_check_defender, win_check_defender_exclusions, win_check_firewall,
            win_check_uac,
        ]))
        categories.append(CategoryResult("Сетевая безопасность", "🌐", [
            check_open_ports, check_suspicious_connections,
            win_check_rdp,
        ]))
        categories.append(CategoryResult("Системные настройки", "⚙️", [
            win_check_updates, win_check_autorun, win_check_autorun_bloat,
            win_check_autologon,
        ]))
        categories.append(CategoryResult("Мониторинг и история", "📊", [
            check_temp_suspicious, check_hosts_file, check_uptime,
        ]))
        categories.append(CategoryResult("Поиск вредоносного ПО", "🔬", [
            check_process_anomalies, check_malware_paths,
        ]))

    elif CURRENT_OS == "Linux":
        categories.append(CategoryResult("Защита системы", "🛡️", [
            linux_check_firewall, linux_check_ssh, linux_check_fail2ban,
        ]))
        categories.append(CategoryResult("Сетевая безопасность", "🌐", [
            check_open_ports, check_suspicious_connections,
        ]))
        categories.append(CategoryResult("Система и обновления", "⚙️", [
            linux_check_updates, linux_check_unattended_upgrades,
            linux_check_services, linux_check_users,
        ]))
        categories.append(CategoryResult("Мониторинг и история", "📊", [
            linux_check_cron, linux_check_bash_history,
            check_temp_suspicious, check_hosts_file, check_uptime,
        ]))
        categories.append(CategoryResult("Поиск вредоносного ПО", "🔬", [
            check_process_anomalies, check_malware_paths,
        ]))
    else:
        console.print(f"[red]Неподдерживаемая ОС: {CURRENT_OS}[/]")
        sys.exit(1)

    return categories

# ╔═══════════════════════════════════════════════════════════════════════════════╗
# ║  TUI RENDERING                                                                ║
# ╚═══════════════════════════════════════════════════════════════════════════════╝

BANNER = r"""
[cyan]
   _____ __    _      __    ______                
  / ___// /_  (_)__  / /___/ / __/_________ _____ 
  \__ \/ __ \/ / _ \/ / __  /\__ \/ ___/ __ `/ __ \
 ___/ / / / / /  __/ / /_/ /___/ / /__/ /_/ / / / /
/____/_/ /_/_/\___/_/\__,_//____/\___/\__,_/_/ /_/ 
[/cyan]
[dim]Cross-Platform Security Auditor v2.0 — Extended Edition[/dim]
"""

def render_sysinfo(info: dict):
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="cyan bold", width=16)
    table.add_column()
    os_name = info.get("distro", f"{info['os']} {info['os_release']}")
    table.add_row("ОС", os_name)
    table.add_row("Версия", info["os_version"][:60])
    table.add_row("Хост", info["hostname"])
    table.add_row("Архитектура", info["arch"])
    table.add_row("Пользователь", info["user"])
    table.add_row("Привилегии", "[green]Администратор[/]" if info["admin"] else "[yellow]Обычный пользователь[/]")
    table.add_row("Python", info["python"])
    table.add_row("Время скана", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    console.print(Panel(table, title="[bold]Информация о системе[/]", border_style="cyan", box=box.ROUNDED))

def render_results(categories, results):
    for cat in categories:
        table = Table(box=box.SIMPLE_HEAVY, show_edge=False, padding=(0, 1))
        table.add_column("", width=3)
        table.add_column("Проверка", style="bold", min_width=32)
        table.add_column("Результат", min_width=50)
        for fn in cat.checks:
            r = results[fn.__name__]
            table.add_row(status_icon(r.status), r.name, r.message)
            if r.details:
                for line in r.details.split("\n")[:15]:
                    table.add_row("", "", f"[dim]{line}[/dim]")
        console.print(Panel(table, title=f"[bold]{cat.icon}  {cat.name}[/]", border_style="blue", box=box.ROUNDED))
        console.print()

def render_score(score, results):
    color = score_color(score)
    filled = int(score / 2)
    bar = f"[{color}]{'█' * filled}[/][dim]{'░' * (50 - filled)}[/]"
    if score >= 80: grade, comment = "A — Отлично", "Система хорошо защищена!"
    elif score >= 60: grade, comment = "B — Хорошо", "Есть моменты для улучшения."
    elif score >= 40: grade, comment = "C — Удовлетворительно", "Устраните проблемы."
    else: grade, comment = "D — Критично", "Серьёзные уязвимости!"
    fails = sum(1 for r in results.values() if r.status == "fail")
    warns = sum(1 for r in results.values() if r.status == "warn")
    passes = sum(1 for r in results.values() if r.status == "pass")
    infos = sum(1 for r in results.values() if r.status == "info")
    content = f"\n  {bar}\n\n  [bold]Оценка:[/] [bold {color}]{score}/100[/]  [{color}]({grade})[/]\n  [dim]{comment}[/]\n\n  [green]✔ {passes}[/]  [yellow]⚠ {warns}[/]  [red]✘ {fails}[/]  [blue]ℹ {infos}[/]\n"
    console.print(Panel(content, title="[bold]Итоговая оценка безопасности[/]", border_style=color, box=box.DOUBLE))

def render_recommendations(results):
    recs = []
    for r in results.values():
        if r.status == "fail": recs.append(("🔴 КРИТИЧНО", r.name, r.message, r.details))
        elif r.status == "warn": recs.append(("🟡 ВНИМАНИЕ", r.name, r.message, r.details))
    if not recs:
        console.print(Panel("[green]Проблем не обнаружено! 🎉[/]", border_style="green"))
        return
    table = Table(box=box.SIMPLE, show_edge=False)
    table.add_column("Уровень", width=12)
    table.add_column("Проблема", style="bold", min_width=25)
    table.add_column("Описание")
    for level, name, msg, details in sorted(recs, key=lambda x: x[0]):
        table.add_row(level, name, msg)
        if details:
            first = details.split("\n")[0][:80]
            if any(first.startswith(p) for p in ("Рекомендация", "apt", "Включите", "mount", "Stop", "Disable")):
                table.add_row("", "", f"[dim cyan]→ {first}[/]")
    console.print(Panel(table, title=f"[bold]Рекомендации ({len(recs)} проблем)[/]", border_style="yellow", box=box.ROUNDED))

def export_results(results, info):
    export = {
        "scan_time": datetime.now().isoformat(), "system": info,
        "results": {n: {"name": r.name, "status": r.status, "message": r.message,
                        "details": r.details, "score_impact": r.score_impact} for n, r in results.items()},
        "score": max(0, min(100, 100 + sum(r.score_impact for r in results.values())))
    }
    fn = f"shieldscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(export, f, ensure_ascii=False, indent=2)
    console.print(f"\n[green]✔ Отчёт сохранён: {fn}[/]")

# ╔═══════════════════════════════════════════════════════════════════════════════╗
# ║  MAIN                                                                         ║
# ╚═══════════════════════════════════════════════════════════════════════════════╝

def main():
    parser = argparse.ArgumentParser(description="ShieldScan v2.0")
    parser.add_argument("--quick", action="store_true", help="Quick scan")
    parser.add_argument("--export", action="store_true", help="Export to JSON")
    args = parser.parse_args()

    console.clear()
    console.print(BANNER)
    info = get_system_info()
    render_sysinfo(info)
    console.print()
    if not info["admin"]:
        console.print("[yellow]⚠  Без прав администратора — часть проверок неполна.[/]")
        console.print("[dim]   Рекомендуется: sudo python security_auditor.py[/]\n")
    categories = build_checks(args.quick)
    total = sum(len(c.checks) for c in categories)
    results = {}
    with Progress(
        SpinnerColumn(style="cyan"), TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
        TextColumn("[dim]{task.completed}/{task.total}[/]"), console=console,
    ) as progress:
        task = progress.add_task("Сканирование...", total=total)
        for cat in categories:
            for fn in cat.checks:
                label = fn.__name__.replace("_", " ").replace("check ", "").replace("win ", "").replace("linux ", "")
                progress.update(task, description=f"Проверка: {label}")
                try:
                    results[fn.__name__] = fn()
                except Exception as e:
                    results[fn.__name__] = CheckResult(fn.__name__, "info", f"Ошибка: {str(e)[:60]}")
                progress.advance(task)
    console.print()
    render_results(categories, results)
    score = max(0, min(100, 100 + sum(r.score_impact for r in results.values())))
    render_score(score, results)
    console.print()
    render_recommendations(results)
    if args.export:
        export_results(results, info)
    console.print(f"\n[dim]ShieldScan v2.0 • {datetime.now().strftime('%H:%M:%S')} • {CURRENT_OS} • {total} проверок[/]\n")

    # Self-cleanup: remove all traces after scan
    if getattr(sys, 'frozen', False):
        exe_path = sys.executable
        mei_dir = getattr(sys, '_MEIPASS', None)
        console.print("[dim]Нажмите Enter для выхода (все следы будут удалены)...[/]")
        input()
        if sys.platform == "win32":
            import subprocess
            # Build cleanup command: wait for process exit, delete exe, delete _MEI folder, close window
            cmds = ['ping 127.0.0.1 -n 2 >nul']
            cmds.append(f'del /f /q "{exe_path}"')
            if mei_dir and os.path.isdir(mei_dir):
                cmds.append(f'rmdir /s /q "{mei_dir}"')
            # Also clean any _MEI* leftovers in TEMP
            temp_dir = os.environ.get("TEMP", os.environ.get("TMP", ""))
            if temp_dir:
                cmds.append(f'for /d %i in ("{temp_dir}\\_MEI*") do rmdir /s /q "%i" 2>nul')
            # Delete Prefetch trace (admin required)
            exe_name = os.path.basename(exe_path).upper().replace(".EXE", "")
            cmds.append(f'del /f /q "C:\\Windows\\Prefetch\\{exe_name}.EXE-*.pf" 2>nul')
            cmds.append('exit')
            cleanup_cmd = ' & '.join(cmds)
            subprocess.Popen(
                f'cmd /C {cleanup_cmd}',
                shell=True, creationflags=0x08000000  # CREATE_NO_WINDOW
            )
        else:
            try:
                os.unlink(exe_path)
                if mei_dir and os.path.isdir(mei_dir):
                    import shutil
                    shutil.rmtree(mei_dir, ignore_errors=True)
            except OSError:
                pass
    else:
        input("\nНажмите Enter для выхода...")

if __name__ == "__main__":
    main()
