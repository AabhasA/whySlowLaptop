#!/usr/bin/env python3
"""
win_optimizer.py — World-class local dashboard for Windows health, cleanup, security.

Single file. Pure Python stdlib. No installs. Works on Windows 10 / 11.

Run:    python win_optimizer.py
        python win_optimizer.py --watch 10
Open:   http://localhost:8765

Requirements: Python 3.8+ (install free from Microsoft Store: search "Python 3").
PowerShell is built into Windows — used internally for system queries.

WHAT IT DOES
  • Health snapshot: CPU, memory, page file, disk, boot time
  • Top processes (with kill button)
  • Disk hogs (Downloads, Temp, Recycle Bin)
  • Unused apps (1+ year), largest apps
  • Threat scan: Defender status, startup items, scheduled tasks,
    hosts file integrity, suspicious processes from %TEMP%/%APPDATA%
  • Network: established outbound connections per process
  • Browser extensions audit (Chrome)
  • Recurring offenders (when run with --watch): processes that
    repeatedly hog CPU across snapshots
  • One-click cleanup: Clean %TEMP%, Empty Recycle Bin, Kill process
"""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

PORT = 8765
HOME = Path.home()
USER = os.environ.get("USERNAME", "")
APPDATA = Path(os.environ.get("APPDATA", str(HOME / "AppData/Roaming")))
LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", str(HOME / "AppData/Local")))
TEMP = Path(os.environ.get("TEMP", str(LOCALAPPDATA / "Temp")))
HIST_FILE = HOME / ".win_optimizer_history.json"
HIST_LOCK = threading.Lock()
MAX_SNAPSHOTS = 200

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def ps(cmd, timeout=20):
    """Run a PowerShell command and return stdout."""
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return r.stdout.strip()
    except Exception as e:
        return f"ERR: {e}"

def ps_json(cmd, timeout=20):
    """Run a PowerShell command, parse JSON output."""
    out = ps(cmd + " | ConvertTo-Json -Depth 4 -Compress", timeout)
    if not out or out.startswith("ERR"):
        return None
    try:
        data = json.loads(out)
        # Single objects come back as dict; wrap in list for uniform handling
        return data if isinstance(data, list) else [data]
    except Exception:
        return None

def cmd(cmd_str, timeout=15):
    try:
        r = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.stdout.strip()
    except Exception as e:
        return f"ERR: {e}"

def human(n):
    if n is None or n < 0:
        return "?"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def du_path(path, timeout=120):
    """Recursive folder size in bytes via PowerShell (fast: uses .NET)."""
    if not Path(path).exists():
        return -1
    out = ps(
        f'(Get-ChildItem -LiteralPath "{path}" -Recurse -Force -ErrorAction SilentlyContinue '
        f'| Measure-Object -Property Length -Sum).Sum', timeout=timeout)
    try:
        return int(float(out)) if out and not out.startswith("ERR") else -1
    except Exception:
        return -1

# ─────────────────────────────────────────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────────────────────────────────────────
def get_health():
    info = ps_json(
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object TotalVisibleMemorySize, FreePhysicalMemory, "
        "TotalVirtualMemorySize, FreeVirtualMemory, LastBootUpTime")
    cpu_load = ps("(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average")
    cores = ps("(Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum")
    cpu_name = ps("(Get-CimInstance Win32_Processor).Name")
    cpu_max = ps("(Get-CimInstance Win32_Processor).MaxClockSpeed")
    cpu_cur = ps("(Get-CimInstance Win32_Processor).CurrentClockSpeed")

    total_mb = free_mb = vtotal_mb = vfree_mb = 0
    boot = ""
    if info:
        d = info[0]
        total_mb = int(d.get("TotalVisibleMemorySize", 0) or 0) / 1024
        free_mb = int(d.get("FreePhysicalMemory", 0) or 0) / 1024
        vtotal_mb = int(d.get("TotalVirtualMemorySize", 0) or 0) / 1024
        vfree_mb = int(d.get("FreeVirtualMemory", 0) or 0) / 1024
        boot = str(d.get("LastBootUpTime", ""))

    mem_used_pct = int(100 * (total_mb - free_mb) / total_mb) if total_mb else 0
    mem_free_pct = 100 - mem_used_pct
    page_used_mb = max(0, (vtotal_mb - vfree_mb) - (total_mb - free_mb))

    # CPU throttle: current vs max clock
    speed_pct = 100
    try:
        if cpu_max and cpu_cur:
            speed_pct = int(100 * float(cpu_cur) / float(cpu_max))
    except Exception:
        pass

    # Disk (system drive)
    disks = ps_json("Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free")
    disk_used_pct = disk_free_gb = disk_total_gb = 0
    if disks:
        sysd = next((d for d in disks if d.get("Name") == "C"), disks[0])
        used = int(sysd.get("Used") or 0)
        free = int(sysd.get("Free") or 0)
        total = used + free
        if total:
            disk_used_pct = int(used * 100 / total)
            disk_free_gb = free / 1024**3
            disk_total_gb = total / 1024**3

    try:
        load1 = float(cpu_load) / 100 * int(cores or 1)
    except Exception:
        load1 = 0

    issues = []
    score = 100
    if speed_pct < 80:
        issues.append({"sev": "warn", "msg": f"CPU clocked at {speed_pct}% of max",
                       "fix": "Plug in charger. Power Plan → 'High Performance'."})
        score -= 15
    if disk_used_pct > 90:
        issues.append({"sev": "critical", "msg": f"Disk {disk_used_pct}% full",
                       "fix": "Empty Recycle Bin, clean Downloads, run cleanup."})
        score -= 25
    elif disk_used_pct > 85:
        issues.append({"sev": "warn", "msg": f"Disk {disk_used_pct}% full",
                       "fix": "Run Clean %TEMP% and empty Recycle Bin."})
        score -= 10
    if mem_free_pct < 15:
        issues.append({"sev": "warn", "msg": f"Memory free only {mem_free_pct}%",
                       "fix": "Close unused apps and Chrome tabs."})
        score -= 10
    if try_int(cpu_load) > 80:
        issues.append({"sev": "warn", "msg": f"CPU at {cpu_load}% — sustained load",
                       "fix": "Check Top Processes panel."})
        score -= 10

    return {
        "cpu_name": cpu_name or "?",
        "cpu_load": try_int(cpu_load),
        "speed_limit": speed_pct,
        "cpu_max_mhz": try_int(cpu_max),
        "cpu_cur_mhz": try_int(cpu_cur),
        "load1": load1, "cores": try_int(cores),
        "mem_total_gb": total_mb / 1024,
        "mem_used_pct": mem_used_pct,
        "mem_free_pct": mem_free_pct,
        "page_used_mb": page_used_mb,
        "disk_used_pct": disk_used_pct,
        "disk_free_gb": disk_free_gb,
        "disk_total_gb": disk_total_gb,
        "boot": boot,
        "issues": issues,
        "score": max(0, score),
    }

def try_int(v):
    try: return int(float(v))
    except Exception: return 0

def get_processes():
    """Top 30 processes by CPU."""
    rows = ps_json(
        "Get-Process | Where-Object { $_.CPU } | Sort-Object CPU -Descending | "
        "Select-Object -First 30 Id, ProcessName, CPU, WorkingSet64, Path")
    out = []
    if not rows:
        return out
    for r in rows:
        try:
            out.append({
                "pid": int(r.get("Id") or 0),
                "name": r.get("ProcessName") or "",
                "cpu": float(r.get("CPU") or 0),  # Total CPU seconds — sort proxy
                "rss_mb": int(r.get("WorkingSet64") or 0) / 1024 / 1024,
                "path": r.get("Path") or "",
            })
        except Exception:
            pass
    # Now also get instantaneous CPU% via WMI
    inst = ps_json(
        "Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | "
        "Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' } | "
        "Sort-Object PercentProcessorTime -Descending | Select-Object -First 20 Name, IDProcess, PercentProcessorTime")
    inst_map = {}
    if inst:
        for r in inst:
            try:
                inst_map[int(r.get("IDProcess") or 0)] = float(r.get("PercentProcessorTime") or 0)
            except Exception:
                pass
    for p in out:
        p["cpu_pct"] = inst_map.get(p["pid"], 0)
    out.sort(key=lambda x: x["cpu_pct"], reverse=True)
    return out

# ─────────────────────────────────────────────────────────────────────────────
# Process intelligence — what each process is, in plain English
# ─────────────────────────────────────────────────────────────────────────────
# verdict:  safe    = killing is fine, system unaffected or auto-restart
#           caution = killing may close an app or interrupt work
#           never   = killing will hang, crash, or BSOD Windows
#           unknown = unrecognised — judge by signature + path
PROCESS_INFO_WIN = {
    # ── Critical Windows core (NEVER kill — most cause instant BSOD/reboot) ─
    "System":                 ("Windows kernel", "The Windows kernel itself. High CPU here usually means a driver problem (Wi-Fi, GPU, antivirus). Update drivers, don't kill this.", "never"),
    "System Idle Process":    ("Idle CPU", "Not a real process — it represents unused CPU. 95% here is GOOD, it means your CPU is mostly free.", "never"),
    "Registry":               ("Registry", "The Windows registry process. Critical.", "never"),
    "Memory Compression":     ("Memory Compression", "Compresses idle RAM so Windows doesn't need to swap to disk. High here is normal on low-RAM machines.", "never"),
    "smss.exe":               ("Session Manager", "Starts every Windows session. Killing it BSODs Windows.", "never"),
    "csrss.exe":              ("Client/Server runtime", "Windows subsystem manager. Killing it BSODs Windows.", "never"),
    "wininit.exe":            ("Windows init", "Boots core Windows services. Killing it BSODs.", "never"),
    "services.exe":           ("Service Control Manager", "Starts every Windows service. Killing it BSODs.", "never"),
    "lsass.exe":              ("Local Security Authority", "Manages logins, passwords, and security tokens. Killing it logs you out.", "never"),
    "winlogon.exe":           ("Windows Logon", "Owns your interactive session. Killing it logs you out.", "never"),
    "fontdrvhost.exe":        ("Font driver host", "Renders fonts. Killing it crashes the desktop.", "never"),
    "dwm.exe":                ("Desktop Window Manager", "Draws every window, animation, and shadow on the desktop. High CPU usually = a graphics-heavy app or bad GPU driver. Killing it briefly blanks the screen.", "never"),

    # ── Shell (caution) ────────────────────────────────────────────────────
    "explorer.exe":           ("Windows Explorer", "The taskbar, Start menu, and File Explorer. Killing it makes the taskbar disappear briefly then auto-restart — a common fix for a stuck taskbar.", "caution"),
    "ApplicationFrameHost.exe": ("App Frame Host", "Hosts the window frames of UWP/Store apps. Killing it closes those apps.", "caution"),
    "RuntimeBroker.exe":      ("Runtime Broker", "Mediates permissions for Microsoft Store apps. Multiple instances are normal.", "safe"),
    "ShellExperienceHost.exe": ("Start Menu / Action Center", "Renders the Start menu and notification area. Killing it auto-restarts.", "safe"),
    "StartMenuExperienceHost.exe": ("Start Menu", "The Start menu UI. Killing it auto-restarts.", "safe"),
    "SearchHost.exe":         ("Windows Search UI", "The search box on the taskbar.", "safe"),
    "SearchApp.exe":          ("Windows Search UI", "The search box on the taskbar.", "safe"),
    "TextInputHost.exe":      ("Text Input Host", "Touch keyboard / IME host. Safe to kill.", "safe"),
    "ctfmon.exe":             ("Text input services", "Language bar and text-input switcher. Auto-restarts.", "safe"),
    "sihost.exe":             ("Shell Infrastructure Host", "Hosts shell components (action center, etc.).", "caution"),
    "taskhostw.exe":          ("Task host", "Generic host for scheduled tasks.", "safe"),

    # ── Windows Search & indexing ──────────────────────────────────────────
    "SearchIndexer.exe":      ("Windows Search Indexer", "Builds the search index for File Explorer and Outlook. Heavy CPU after a big file change is normal — let it finish overnight. If it's chronic, rebuild the index in Indexing Options.", "safe"),
    "SearchProtocolHost.exe": ("Search protocol host", "Reads files for the search indexer.", "safe"),
    "SearchFilterHost.exe":   ("Search filter host", "Extracts text from documents for the indexer.", "safe"),

    # ── Windows Defender ───────────────────────────────────────────────────
    "MsMpEng.exe":            ("Microsoft Defender", "The Defender antivirus scanning engine. The #1 cause of mysterious high CPU on Windows. It scans every file you touch. Don't kill it — but you can add trusted folders to Defender exclusions to calm it down.", "never"),
    "NisSrv.exe":             ("Defender network inspection", "Defender's network protection.", "caution"),
    "SecurityHealthService.exe": ("Security Health", "Reports security status to Windows Security center.", "caution"),
    "SecurityHealthSystray.exe": ("Security Health tray icon", "The shield icon in your system tray.", "safe"),
    "MpDefenderCoreService.exe": ("Defender core service", "Newer Defender component.", "never"),

    # ── Windows Update ─────────────────────────────────────────────────────
    "TiWorker.exe":           ("Windows Update worker", "Installs Windows updates. High CPU/disk is normal during an update — let it finish.", "caution"),
    "TrustedInstaller.exe":   ("Windows Module Installer", "Installs Windows updates and components. Same as TiWorker — let it finish.", "caution"),
    "wuauclt.exe":            ("Windows Update client", "The Windows Update background client.", "safe"),
    "MoUsoCoreWorker.exe":    ("Update Orchestrator", "Coordinates Windows Update.", "safe"),
    "usoclient.exe":          ("Update Orchestrator client", "Helper for Windows Update.", "safe"),

    # ── Generic service hosts ──────────────────────────────────────────────
    "svchost.exe":            ("Service Host", "Generic host for Windows services. There are normally many svchost.exe processes — each runs a different group of services. High CPU here usually means one specific service inside is the culprit (open Task Manager → right-click → Go to details to find which).", "caution"),
    "WmiPrvSE.exe":           ("WMI Provider Host", "Answers system info queries. Spikes when management tools query the system.", "safe"),
    "conhost.exe":            ("Console Host", "Hosts a Command Prompt or PowerShell window. Killing it closes that console.", "safe"),
    "dllhost.exe":            ("COM Surrogate", "Hosts COM components (often thumbnail generation). Killing it usually just stops a thumbnail preview.", "safe"),
    "spoolsv.exe":            ("Print Spooler", "Manages print jobs. Killing it cancels any pending prints.", "safe"),
    "audiodg.exe":            ("Audio Device Graph", "Audio mixing and effects. Killing it briefly stops sound and auto-restarts.", "safe"),

    # ── OneDrive / cloud ───────────────────────────────────────────────────
    "OneDrive.exe":           ("OneDrive", "OneDrive sync. Heavy CPU/network usually means a large upload/download.", "safe"),
    "Dropbox.exe":            ("Dropbox", "Dropbox sync.", "safe"),
    "GoogleDriveFS.exe":      ("Google Drive", "Google Drive sync.", "safe"),

    # ── Browsers ───────────────────────────────────────────────────────────
    "chrome.exe":             ("Chrome / tab", "Google Chrome. Each tab and extension also runs as chrome.exe — the biggest CPU one is usually a runaway tab. Killing the helper just closes that tab; killing the main process closes the whole browser.", "caution"),
    "msedge.exe":             ("Microsoft Edge / tab", "Microsoft Edge. Like Chrome, each tab is its own msedge.exe.", "caution"),
    "msedgewebview2.exe":     ("Edge WebView2", "Embedded Edge browser used by many apps (Office, Teams, Outlook). Heavy CPU often means an Office add-in or Teams call.", "caution"),
    "firefox.exe":            ("Firefox", "Mozilla Firefox.", "caution"),
    "brave.exe":              ("Brave", "Brave browser.", "caution"),
    "opera.exe":              ("Opera", "Opera browser.", "caution"),

    # ── Communication apps ─────────────────────────────────────────────────
    "Slack.exe":              ("Slack", "Slack chat. Notoriously memory-heavy because it's Electron. Quitting and reopening can free a lot of RAM.", "caution"),
    "Teams.exe":              ("Microsoft Teams (classic)", "Old Teams client — extremely heavy. Microsoft replaced it with the new Teams in 2024.", "caution"),
    "ms-teams.exe":           ("Microsoft Teams", "The new Teams client. Lighter than the old one but still heavy in calls.", "caution"),
    "Discord.exe":            ("Discord", "Discord chat. Electron — memory hungry.", "caution"),
    "Zoom.exe":               ("Zoom", "Zoom video calls. Heavy CPU during a call is normal.", "caution"),
    "WhatsApp.exe":           ("WhatsApp", "WhatsApp desktop.", "caution"),
    "Telegram.exe":           ("Telegram", "Telegram desktop.", "caution"),
    "Spotify.exe":            ("Spotify", "Spotify music. Surprisingly heavy when left running for days.", "caution"),

    # ── Dev tools ──────────────────────────────────────────────────────────
    "Code.exe":               ("VS Code", "Visual Studio Code. Each extension and window may show as a separate Code.exe.", "caution"),
    "Cursor.exe":             ("Cursor (AI editor)", "The Cursor code editor.", "caution"),
    "devenv.exe":             ("Visual Studio", "Visual Studio IDE.", "caution"),
    "node.exe":               ("Node.js", "A Node.js script — usually a dev server, build watcher, or LSP.", "caution"),
    "python.exe":             ("Python script", "A running Python script.", "caution"),
    "java.exe":               ("Java app", "A Java program — often an IDE (IntelliJ) or build tool.", "caution"),
    "Docker Desktop.exe":     ("Docker Desktop", "Docker Desktop UI. Killing it stops Docker.", "caution"),
    "vmmem":                  ("WSL / VM memory", "Memory used by WSL2 or a Hyper-V VM (Docker, Android emulator). High CPU means a Linux process inside WSL is busy.", "caution"),
    "wslservice.exe":         ("WSL service", "Windows Subsystem for Linux service.", "caution"),

    # ── Misc background ───────────────────────────────────────────────────
    "AggregatorHost.exe":     ("Aggregator host", "Generic host. Safe.", "safe"),
    "GameBarPresenceWriter.exe": ("Xbox Game Bar", "Tracks game activity for Xbox Game Bar. Disable in Settings if you don't game.", "safe"),
    "GameBar.exe":            ("Xbox Game Bar UI", "Xbox Game Bar overlay.", "safe"),
    "YourPhone.exe":          ("Phone Link", "Microsoft Phone Link (formerly Your Phone).", "safe"),
    "PhoneExperienceHost.exe": ("Phone Link", "Microsoft Phone Link.", "safe"),
}

def classify_process_win(name, path=""):
    base = (name or "").strip()
    if not base.lower().endswith(".exe") and base + ".exe" in PROCESS_INFO_WIN:
        base = base + ".exe"
    if base in PROCESS_INFO_WIN:
        return PROCESS_INFO_WIN[base]
    # Strip .exe and try without
    if base.endswith(".exe") and base[:-4] in PROCESS_INFO_WIN:
        return PROCESS_INFO_WIN[base[:-4]]
    pl = (path or "").lower()
    if pl.startswith("c:\\windows\\system32") or pl.startswith("c:\\windows\\syswow64"):
        return (base, "A Windows system service. Usually safe to leave alone — it'll restart if killed.", "caution")
    if "\\program files" in pl:
        return (base, "Part of an installed application. Killing it usually just closes that app.", "caution")
    if "\\appdata\\local\\temp\\" in pl or "\\downloads\\" in pl:
        return (base, "Running from a temp/downloads folder — unusual location. Worth investigating.", "caution")
    if "\\appdata\\" in pl:
        return (base, "Per-user app installed in AppData. Common for Slack/Discord/Spotify, but worth checking if unfamiliar.", "caution")
    return (base, "Unrecognised process. If signed and from Program Files, probably fine; otherwise investigate.", "unknown")


def compute_harm_win(proc, recurring_names=None):
    cpu = proc.get("cpu_pct", 0)
    rss_mb = proc.get("rss_mb", 0)
    score = 0
    reasons = []
    if cpu >= 80:
        score += 60; reasons.append(f"{cpu:.0f}% CPU (pegged)")
    elif cpu >= 50:
        score += 45; reasons.append(f"{cpu:.0f}% CPU sustained")
    elif cpu >= 25:
        score += 25; reasons.append(f"{cpu:.0f}% CPU")
    elif cpu >= 10:
        score += 10
    if rss_mb >= 4000:
        score += 25; reasons.append(f"{rss_mb/1024:.1f} GB of RAM")
    elif rss_mb >= 1500:
        score += 15; reasons.append(f"{rss_mb/1024:.1f} GB of RAM")
    elif rss_mb >= 500:
        score += 6
    if recurring_names and proc.get("name") in recurring_names:
        score += 15; reasons.append("repeat offender across snapshots")
    pl = (proc.get("path") or "").lower()
    if "\\appdata\\local\\temp\\" in pl or "\\downloads\\" in pl:
        score += 30; reasons.append("running from temp/downloads (suspicious)")
    return min(100, score), reasons


def get_process_intel(top=20):
    procs = get_processes()
    recurring = {o["name"] for o in get_recurring_offenders()}
    out = []
    for p in procs[:top]:
        friendly, explanation, verdict = classify_process_win(p["name"], p.get("path", ""))
        harm, reasons = compute_harm_win(p, recurring_names=recurring)
        out.append({
            **p,
            "friendly": friendly,
            "explanation": explanation,
            "verdict": verdict,
            "harm": harm,
            "harm_band": ("severe" if harm >= 80 else "heavy" if harm >= 50
                          else "noticeable" if harm >= 20 else "idle"),
            "reasons": reasons,
        })
    out.sort(key=lambda x: x["harm"], reverse=True)
    return out


def get_heal_recommendations():
    h = get_health()
    intel = get_process_intel(top=15)
    recs = []
    for issue in h["issues"]:
        if issue["sev"] == "critical":
            recs.append({"severity": "critical", "title": issue["msg"],
                         "why": issue["fix"], "action_label": None})
    for p in [x for x in intel if x["harm"] >= 50 and x["verdict"] == "safe"][:3]:
        recs.append({
            "severity": "high" if p["harm"] >= 80 else "medium",
            "title": f"Kill {p['friendly']} — {', '.join(p['reasons']) or 'heavy resource use'}",
            "why": p["explanation"],
            "action_label": f"Kill PID {p['pid']}",
            "action_url": "/api/kill",
            "action_body": {"pid": p["pid"]},
        })
    for p in [x for x in intel if x["harm"] >= 50 and x["verdict"] == "caution"][:3]:
        recs.append({
            "severity": "medium",
            "title": f"{p['friendly']} is heavy ({', '.join(p['reasons']) or 'high CPU/RAM'})",
            "why": p["explanation"] + " Quitting and re-opening it usually frees a lot of memory.",
            "action_label": f"Force-quit PID {p['pid']}",
            "action_url": "/api/kill",
            "action_body": {"pid": p["pid"]},
        })
    if h["disk_used_pct"] >= 80:
        recs.append({
            "severity": "high" if h["disk_used_pct"] >= 90 else "medium",
            "title": f"Free up disk space — {h['disk_used_pct']}% full",
            "why": "Windows slows down when the C: drive is nearly full. Clearing %TEMP% is safe and often frees several GB instantly.",
            "action_label": "Clean %TEMP%",
            "action_url": "/api/clean-temp",
            "action_body": {},
        })
    if h.get("mem_free_pct", 100) < 15:
        recs.append({
            "severity": "high",
            "title": f"Memory almost full ({h['mem_free_pct']}% free)",
            "why": "Windows is about to start heavy paging to disk, which makes everything crawl. Close some heavy apps (check the Process Inspector below).",
            "action_label": None,
        })
    if not recs:
        recs.append({"severity": "ok", "title": "Your PC looks healthy ✓",
                     "why": f"Health score {h['score']}/100. Nothing urgent.",
                     "action_label": None})
    return {
        "score": h["score"],
        "recommendations": recs,
        "summary": f"{len([r for r in recs if r['severity'] in ('critical','high')])} urgent, "
                   f"{len([r for r in recs if r['severity'] == 'medium'])} suggested",
    }


def get_disk_hogs():
    targets = [
        (HOME / "Downloads", "Downloads", "Manually review. Sort by size."),
        (HOME / "Desktop", "Desktop", "Files cluttering Desktop slow Explorer."),
        (HOME / "Documents", "Documents", "Manual review."),
        (HOME / "Videos", "Videos", "Manual review."),
        (HOME / "Pictures", "Pictures", "Manual review."),
        (TEMP, "User TEMP", "Safe to clear; Windows recreates."),
        (LOCALAPPDATA / "Temp", "Local Temp", "Safe to clear."),
        (LOCALAPPDATA / "Microsoft/Windows/INetCache", "IE/Edge cache", "Safe to clear."),
        (LOCALAPPDATA / "Google/Chrome/User Data/Default/Cache", "Chrome cache", "Safe (Chrome rebuilds)."),
        (Path("C:/Windows/Temp"), "System TEMP", "Needs admin to fully clear."),
        (Path("C:/Windows/SoftwareDistribution/Download"), "Windows Update cache", "Needs admin."),
    ]
    out = []
    for path, name, note in targets:
        if path.exists():
            sz = du_path(path, timeout=180)
            out.append({"path": str(path), "name": name, "bytes": sz,
                        "human": human(sz), "note": note,
                        "cleanable": name in ("User TEMP", "Local Temp", "IE/Edge cache", "Chrome cache")})
    # Recycle bin size
    rb_size = ps("(New-Object -ComObject Shell.Application).NameSpace(10).Items() "
                 "| Measure-Object -Property Size -Sum | Select-Object -ExpandProperty Sum")
    try:
        rb = int(float(rb_size)) if rb_size and not rb_size.startswith("ERR") else 0
    except Exception:
        rb = 0
    out.append({"path": "shell:RecycleBinFolder", "name": "Recycle Bin",
                "bytes": rb, "human": human(rb),
                "note": "Empty to actually free space.", "cleanable": True})
    out.sort(key=lambda x: x["bytes"], reverse=True)
    return out

def get_apps_with_dates():
    """Installed programs from registry uninstall keys + UWP apps."""
    out = ps_json(
        r"$paths = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',"
        r"'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',"
        r"'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*';"
        r"Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        r"Where-Object { $_.DisplayName } | "
        r"Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, "
        r"InstallLocation, EstimatedSize, UninstallString")
    apps = []
    if not out:
        return apps
    for r in out:
        loc = r.get("InstallLocation") or ""
        # Try to get last-modified time of install location
        latest = 0
        if loc and Path(loc).exists():
            try:
                latest = int(Path(loc).stat().st_mtime)
            except Exception:
                pass
        idate = str(r.get("InstallDate") or "")
        # InstallDate is YYYYMMDD
        m = re.match(r"(\d{4})(\d{2})(\d{2})", idate)
        install_ts = 0
        if m:
            try:
                install_ts = int(time.mktime(time.strptime("-".join(m.groups()), "%Y-%m-%d")))
            except Exception:
                pass
        size_kb = try_int(r.get("EstimatedSize"))
        apps.append({
            "name": r.get("DisplayName"),
            "publisher": r.get("Publisher") or "",
            "version": r.get("DisplayVersion") or "",
            "install_date": install_ts,
            "last_used": latest or install_ts,
            "size_bytes": size_kb * 1024 if size_kb else -1,
            "uninstall": r.get("UninstallString") or "",
            "location": loc,
        })
    return apps

def get_unused_apps(days=365):
    cutoff = time.time() - days * 86400
    apps = get_apps_with_dates()
    out = []
    for a in apps:
        ts = a["last_used"] or a["install_date"]
        if ts and ts < cutoff:
            out.append({
                "name": a["name"],
                "last_used": time.strftime("%Y-%m-%d", time.localtime(ts)),
                "size_human": human(a["size_bytes"]),
                "size_bytes": a["size_bytes"],
                "uninstall": a["uninstall"],
                "publisher": a["publisher"],
            })
    out.sort(key=lambda x: x["last_used"])
    return out

def get_largest_apps(top=15):
    apps = [a for a in get_apps_with_dates() if a["size_bytes"] > 0]
    apps.sort(key=lambda x: x["size_bytes"], reverse=True)
    return [{
        "name": a["name"],
        "publisher": a["publisher"],
        "size_human": human(a["size_bytes"]),
        "uninstall": a["uninstall"],
        "last_used": time.strftime("%Y-%m-%d", time.localtime(a["last_used"])) if a["last_used"] else "?",
    } for a in apps[:top]]

# ─────────────────────────────────────────────────────────────────────────────
# History / recurring offenders
# ─────────────────────────────────────────────────────────────────────────────
def load_history():
    if not HIST_FILE.exists():
        return {"snapshots": []}
    try:
        return json.loads(HIST_FILE.read_text())
    except Exception:
        return {"snapshots": []}

def save_history(h):
    with HIST_LOCK:
        try:
            HIST_FILE.write_text(json.dumps(h))
        except Exception:
            pass

def take_snapshot():
    h = get_health()
    procs = get_processes()[:15]
    snap = {
        "ts": int(time.time()),
        "score": h["score"],
        "speed_limit": h["speed_limit"],
        "mem_free": h["mem_free_pct"],
        "page_used_mb": h["page_used_mb"],
        "disk_used": h["disk_used_pct"],
        "top_procs": [{"name": p["name"], "cpu": p["cpu_pct"], "rss": round(p["rss_mb"])} for p in procs],
    }
    hist = load_history()
    hist["snapshots"].append(snap)
    hist["snapshots"] = hist["snapshots"][-MAX_SNAPSHOTS:]
    save_history(hist)
    return snap

def get_recurring_offenders(min_appearances=3, cpu_threshold=15):
    hist = load_history()
    counts = {}
    for snap in hist["snapshots"][-30:]:
        for p in snap.get("top_procs", []):
            if p["cpu"] >= cpu_threshold:
                k = p["name"]
                if k not in counts:
                    counts[k] = {"name": k, "appearances": 0, "max_cpu": 0, "total": 0}
                counts[k]["appearances"] += 1
                counts[k]["max_cpu"] = max(counts[k]["max_cpu"], p["cpu"])
                counts[k]["total"] += p["cpu"]
    out = []
    for k, v in counts.items():
        if v["appearances"] >= min_appearances:
            v["avg_cpu"] = round(v["total"] / v["appearances"], 1)
            v.pop("total")
            out.append(v)
    out.sort(key=lambda x: x["appearances"], reverse=True)
    return out

def get_history_summary():
    hist = load_history()
    return {
        "count": len(hist["snapshots"]),
        "recent": [{"ts": s["ts"], "score": s["score"], "speed_limit": s["speed_limit"]}
                   for s in hist["snapshots"][-50:]],
        "offenders": get_recurring_offenders(),
    }

# ─────────────────────────────────────────────────────────────────────────────
# Security
# ─────────────────────────────────────────────────────────────────────────────
def get_defender_status():
    out = ps_json("Get-MpComputerStatus | Select-Object AntivirusEnabled, "
                  "RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, "
                  "AMServiceEnabled, IsTamperProtected")
    if not out:
        return {"available": False}
    d = out[0]
    return {
        "available": True,
        "antivirus": bool(d.get("AntivirusEnabled")),
        "realtime": bool(d.get("RealTimeProtectionEnabled")),
        "tamper": bool(d.get("IsTamperProtected")),
        "signatures": str(d.get("AntivirusSignatureLastUpdated") or ""),
    }

def get_startup_items():
    """Programs that auto-start: registry Run keys + Startup folder + scheduled tasks."""
    items = []
    # Registry Run keys
    reg = ps_json(
        r"$keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',"
        r"'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',"
        r"'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',"
        r"'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',"
        r"'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';"
        r"$keys | ForEach-Object { "
        r"  if (Test-Path $_) { "
        r"    Get-ItemProperty $_ | Select-Object -Property * | ForEach-Object {"
        r"      $obj = $_; $obj.PSObject.Properties | Where-Object {"
        r"        $_.Name -notlike 'PS*' "
        r"      } | ForEach-Object { [PSCustomObject]@{ Source = ($obj.PSPath -replace '.*::',''); Name = $_.Name; Value = $_.Value } }"
        r"    }"
        r"  }"
        r"}")
    if reg:
        for r in reg:
            items.append({
                "kind": "registry",
                "name": r.get("Name") or "?",
                "value": r.get("Value") or "",
                "source": r.get("Source") or "",
            })
    # Startup folder
    for sp in [APPDATA / "Microsoft/Windows/Start Menu/Programs/Startup",
               Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup")]:
        if sp.exists():
            for f in sp.iterdir():
                items.append({"kind": "startup-folder", "name": f.name, "value": str(f), "source": str(sp)})
    return items

def get_scheduled_tasks():
    """Non-Microsoft scheduled tasks (suspicious vector)."""
    out = ps_json(
        "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and "
        "$_.TaskPath -notlike '\\Microsoft\\*' } | "
        "Select-Object TaskName, TaskPath, State, Author")
    return out or []

def get_hosts_check():
    paths = [Path("C:/Windows/System32/drivers/etc/hosts")]
    for p in paths:
        if p.exists():
            try:
                content = p.read_text(errors="ignore")
            except Exception:
                continue
            sus, normal = [], []
            for line in content.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                normal.append(s)
                if any(d in s for d in ["google.com", "microsoft.com", "facebook.com", "github.com", "windowsupdate", "anthropic.com"]):
                    if not s.startswith(("127.", "::1", "0.0.0.0")):
                        sus.append(s)
            return {"total_entries": len(normal), "suspicious": sus, "samples": normal[:10]}
    return {"total_entries": 0, "suspicious": [], "samples": []}

def get_network_connections():
    out = cmd("netstat -ano -p TCP", timeout=10)
    by_pid = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("TCP") or "ESTABLISHED" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        remote = parts[2]
        pid = parts[-1]
        if pid not in by_pid:
            by_pid[pid] = {"pid": pid, "conns": []}
        if remote not in by_pid[pid]["conns"]:
            by_pid[pid]["conns"].append(remote)
    # Resolve PID → process name
    name_map = {}
    procs = ps_json("Get-Process | Select-Object Id, ProcessName")
    if procs:
        for p in procs:
            name_map[str(p.get("Id"))] = p.get("ProcessName")
    out_list = []
    for pid, v in sorted(by_pid.items(), key=lambda x: -len(x[1]["conns"]))[:20]:
        out_list.append({
            "proc": name_map.get(pid, "?"),
            "pid": pid,
            "count": len(v["conns"]),
            "samples": v["conns"][:3],
        })
    return out_list

def get_browser_extensions():
    out = []
    chrome_ext = LOCALAPPDATA / "Google/Chrome/User Data/Default/Extensions"
    if chrome_ext.exists():
        for ext_id in chrome_ext.iterdir():
            if not ext_id.is_dir():
                continue
            versions = sorted([v for v in ext_id.iterdir() if v.is_dir()])
            if not versions:
                continue
            manifest = versions[-1] / "manifest.json"
            name = ext_id.name
            perms = []
            if manifest.exists():
                try:
                    m = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
                    n = m.get("name", "")
                    if n and not n.startswith("__MSG_"):
                        name = n
                    perms = (m.get("permissions") or []) + (m.get("host_permissions") or [])
                except Exception:
                    pass
            risky = any(p in str(perms) for p in ["<all_urls>", "tabs", "cookies", "webRequest", "history"])
            out.append({"browser": "Chrome", "id": ext_id.name, "name": name,
                        "perms": len(perms), "risky": risky})
    edge_ext = LOCALAPPDATA / "Microsoft/Edge/User Data/Default/Extensions"
    if edge_ext.exists():
        for ext_id in edge_ext.iterdir():
            if ext_id.is_dir():
                out.append({"browser": "Edge", "id": ext_id.name, "name": ext_id.name,
                            "perms": 0, "risky": False})
    return out

def get_suspicious_processes():
    """Processes whose binary lives in TEMP/AppData (classic malware hideouts)."""
    procs = get_processes()
    flagged = []
    for p in procs:
        path = (p["path"] or "").lower()
        if not path:
            continue
        if any(seg in path for seg in ["\\temp\\", "\\appdata\\local\\temp\\",
                                       "\\downloads\\", "\\public\\"]):
            flagged.append({**p, "reason": "runs from temp/downloads"})
        elif "\\appdata\\" in path and "\\microsoft\\" not in path and "\\google\\" not in path:
            # AppData is normal for some apps, but flag unusual ones
            if not any(safe in path for safe in ["\\programs\\", "\\local\\slack\\",
                                                 "\\local\\discord\\", "\\local\\spotify\\"]):
                flagged.append({**p, "reason": "runs from AppData"})
    return flagged

def get_security_audit():
    findings = []
    d = get_defender_status()
    if d.get("available"):
        if not d["antivirus"]:
            findings.append({"sev": "critical", "msg": "Defender Antivirus DISABLED",
                             "fix": "Settings → Privacy & Security → Windows Security → Virus & threat protection → turn ON."})
        if not d["realtime"]:
            findings.append({"sev": "critical", "msg": "Defender Real-Time Protection OFF",
                             "fix": "Same path as above. Real-time scanning is critical."})
        if not d["tamper"]:
            findings.append({"sev": "warn", "msg": "Tamper Protection OFF",
                             "fix": "Enable Tamper Protection in Windows Security settings."})
    sus = get_suspicious_processes()
    for p in sus:
        findings.append({"sev": "warn",
                         "msg": f"Process from suspicious path: {p['name']} ({p['reason']})",
                         "fix": f"Path: {p['path']}  PID {p['pid']}"})
    h = get_hosts_check()
    for s in h["suspicious"]:
        findings.append({"sev": "critical",
                         "msg": f"Hosts file redirect: {s}",
                         "fix": "Edit C:\\Windows\\System32\\drivers\\etc\\hosts as Administrator."})
    return {"findings": findings, "defender": d, "hosts": h}

# ─────────────────────────────────────────────────────────────────────────────
# Actions
# ─────────────────────────────────────────────────────────────────────────────
def act_kill(pid):
    out = cmd(f'taskkill /F /PID {int(pid)}', timeout=5)
    if "SUCCESS" in out.upper():
        return {"ok": True, "msg": f"Killed PID {pid}"}
    return {"ok": False, "msg": out or "kill failed (may need admin)"}

def act_clean_temp():
    target = TEMP
    if not target.exists():
        return {"ok": False, "msg": "TEMP not found"}
    freed = 0
    errors = 0
    for child in target.iterdir():
        try:
            if child.is_dir():
                sz = du_path(child, timeout=30)
                shutil.rmtree(child, ignore_errors=True)
                if sz > 0: freed += sz
            else:
                sz = child.stat().st_size
                child.unlink()
                freed += sz
        except Exception:
            errors += 1
    return {"ok": True, "msg": f"Freed {human(freed)} from %TEMP% ({errors} files in use)"}

def act_empty_recycle_bin():
    out = ps("Clear-RecycleBin -Force -ErrorAction SilentlyContinue", timeout=30)
    if out.startswith("ERR"):
        return {"ok": False, "msg": out}
    return {"ok": True, "msg": "Recycle Bin emptied"}

def act_uninstall_app(uninstall_string):
    """Run an app's UninstallString. User must confirm in any GUI prompt."""
    if not uninstall_string:
        return {"ok": False, "msg": "No uninstaller for this app"}
    try:
        subprocess.Popen(uninstall_string, shell=True)
        return {"ok": True, "msg": "Uninstaller launched — follow prompts"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def act_disable_startup(name, source):
    """Remove a registry Run entry."""
    if "registry" not in (source or "").lower() and "Software\\Microsoft" not in (source or ""):
        return {"ok": False, "msg": "Only registry startup items can be disabled here. For folder items, delete the shortcut manually."}
    out = ps(f'Remove-ItemProperty -Path "{source}" -Name "{name}" -ErrorAction Stop', timeout=10)
    if out.startswith("ERR"):
        return {"ok": False, "msg": out}
    return {"ok": True, "msg": f"Removed startup entry: {name}"}

# ─────────────────────────────────────────────────────────────────────────────
# HTTP server (HTML embedded inline; same look as Mac version)
# ─────────────────────────────────────────────────────────────────────────────
HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Win Optimizer</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{
  --bg:#0b0e14; --panel:#141923; --panel2:#1b2230; --border:#272f3f;
  --text:#e6edf3; --dim:#8b96a8; --accent:#5eead4; --warn:#fbbf24;
  --bad:#f87171; --good:#4ade80; --link:#60a5fa;
}
*{box-sizing:border-box}
body{margin:0;font:14px -apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--text)}
header{padding:18px 24px;border-bottom:1px solid var(--border);display:flex;
       align-items:center;justify-content:space-between;background:linear-gradient(180deg,#101521,#0b0e14)}
h1{margin:0;font-size:18px;font-weight:600}
h1 span{color:var(--accent)}
.score{font-size:42px;font-weight:700;margin:0 14px}
.score.good{color:var(--good)} .score.warn{color:var(--warn)} .score.bad{color:var(--bad)}
button{background:var(--panel2);color:var(--text);border:1px solid var(--border);
       padding:6px 12px;border-radius:6px;cursor:pointer;font-size:13px}
button:hover{background:#252d3f;border-color:#3a4456}
button.primary{background:var(--accent);color:#0b0e14;border-color:var(--accent);font-weight:600}
button.danger{background:#3b1a1f;color:var(--bad);border-color:#5c2630}
button.danger:hover{background:#5c2630}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px;padding:16px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;overflow:hidden}
.card h2{margin:0 0 14px;font-size:14px;letter-spacing:.5px;text-transform:uppercase;
         color:var(--dim);font-weight:600;display:flex;justify-content:space-between;align-items:center}
.card h2 .count{background:var(--panel2);padding:2px 8px;border-radius:10px;font-size:11px;color:var(--text)}
.metric{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px}
.metric:last-child{border:0}
.metric .v{color:var(--accent);font-weight:600}
.metric .v.warn{color:var(--warn)} .metric .v.bad{color:var(--bad)} .metric .v.good{color:var(--good)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:6px 8px;color:var(--dim);font-weight:600;border-bottom:1px solid var(--border);
   text-transform:uppercase;font-size:10px;letter-spacing:.5px}
td{padding:6px 8px;border-bottom:1px solid var(--border)}
tr:hover{background:var(--panel2)}
.tag{display:inline-block;padding:1px 7px;border-radius:8px;font-size:10px;background:var(--panel2);color:var(--dim)}
.tag.bad{background:#3b1a1f;color:var(--bad)}
.tag.warn{background:#3b2f1a;color:var(--warn)}
.tag.good{background:#1a3b2a;color:var(--good)}
.issue{padding:10px;border-radius:6px;margin-bottom:8px;border-left:3px solid var(--dim)}
.issue.critical{border-left-color:var(--bad);background:rgba(248,113,113,.06)}
.issue.warn{border-left-color:var(--warn);background:rgba(251,191,36,.06)}
.issue.info{border-left-color:var(--link);background:rgba(96,165,250,.06)}
.issue .msg{font-weight:600;margin-bottom:4px}
.issue .fix{font-size:12px;color:var(--dim)}
.toast{position:fixed;bottom:20px;right:20px;background:var(--panel);border:1px solid var(--border);
       border-radius:8px;padding:12px 18px;box-shadow:0 8px 24px rgba(0,0,0,.4);max-width:380px;z-index:999}
.toast.ok{border-left:3px solid var(--good)}
.toast.err{border-left:3px solid var(--bad)}
.path{font-family:Consolas,Menlo,monospace;font-size:11px;color:var(--dim)}
.btn-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}

/* Heal banner */
.heal{grid-column:1/-1;background:linear-gradient(135deg,#10202a,#0e1822);
      border:1px solid #1f3344;border-radius:12px;padding:22px}
.heal h2{margin:0 0 4px;font-size:20px;color:var(--text);text-transform:none;letter-spacing:0}
.heal .sub{color:var(--dim);font-size:13px;margin-bottom:14px}
.rec{display:flex;gap:14px;align-items:flex-start;padding:12px 14px;
     background:rgba(255,255,255,.02);border:1px solid var(--border);
     border-radius:8px;margin-bottom:8px;border-left:3px solid var(--dim)}
.rec.critical{border-left-color:var(--bad);background:rgba(248,113,113,.05)}
.rec.high{border-left-color:#fb923c;background:rgba(251,146,60,.05)}
.rec.medium{border-left-color:var(--warn);background:rgba(251,191,36,.04)}
.rec.low{border-left-color:var(--link);background:rgba(96,165,250,.04)}
.rec.ok{border-left-color:var(--good);background:rgba(74,222,128,.05)}
.rec .body{flex:1;min-width:0}
.rec .title{font-weight:600;margin-bottom:3px}
.rec .why{font-size:12px;color:var(--dim);line-height:1.5}
.rec .cta{flex-shrink:0}

/* Process inspector */
.proc{display:grid;grid-template-columns:1fr auto auto;gap:10px 14px;
      align-items:center;padding:11px 0;border-bottom:1px solid var(--border)}
.proc:last-child{border:0}
.proc .left{min-width:0}
.proc .friendly{font-weight:600;font-size:13px;display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.proc .raw{font-family:Consolas,Menlo,monospace;font-size:10px;color:var(--dim)}
.proc .why{font-size:11px;color:var(--dim);margin-top:3px;line-height:1.45}
.harm-pill{font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;
           text-transform:uppercase;letter-spacing:.4px}
.harm-pill.severe{background:#3b1a1f;color:var(--bad)}
.harm-pill.heavy{background:#3b2614;color:#fb923c}
.harm-pill.noticeable{background:#3b2f1a;color:var(--warn)}
.harm-pill.idle{background:#1a2b3b;color:var(--dim)}
.verdict{font-size:10px;padding:1px 7px;border-radius:8px;font-weight:600}
.verdict.safe{background:#1a3b2a;color:var(--good)}
.verdict.caution{background:#3b2f1a;color:var(--warn)}
.verdict.never{background:#3b1a1f;color:var(--bad)}
.verdict.unknown{background:#2a2f3b;color:var(--dim)}
.proc .nums{font-size:11px;color:var(--dim);text-align:right;line-height:1.4}
.proc .nums b{color:var(--text);font-size:13px}
button.kill-safe{background:#1a3b2a;color:var(--good);border-color:#2a5b40}
button.kill-safe:hover{background:#2a5b40}
button.kill-caution{background:#3b2f1a;color:var(--warn);border-color:#5b4920}
button.kill-never{background:#1b2230;color:#5a6478;border-color:#272f3f;cursor:not-allowed}
</style></head><body>
<header>
  <h1>Win<span>Optimizer</span> &nbsp;·&nbsp; <span id="cpuname" style="color:var(--dim);font-weight:400"></span></h1>
  <div style="display:flex;align-items:center;gap:14px">
    <div>Health: <span id="score" class="score">--</span></div>
    <button class="primary" onclick="loadAll()">↻ Refresh</button>
  </div>
</header>
<div class="grid">

  <div class="card heal" id="heal-card">
    <h2>🩺 Heal My PC</h2>
    <div class="sub" id="heal-sub">Scanning…</div>
    <div id="heal-list"></div>
  </div>

  <div class="card">
    <h2>System Health <span class="count" id="health-count"></span></h2>
    <div id="health-metrics"></div>
    <div id="health-issues" style="margin-top:14px"></div>
  </div>

  <div class="card">
    <h2>Process Inspector <span class="count" id="intel-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      Ranked by how much each process is hurting your PC right now.
      The verdict tag tells you whether it's safe to kill.
    </p>
    <div id="intel-list"></div>
  </div>

  <div class="card">
    <h2>Disk Hogs</h2>
    <table id="disk-table"><thead>
      <tr><th>Folder</th><th>Size</th><th>Note</th><th></th></tr>
    </thead><tbody></tbody></table>
    <div class="btn-row">
      <button class="primary" onclick="action('/api/clean-temp','Clear %TEMP% folder?')">Clean %TEMP%</button>
      <button onclick="action('/api/empty-recycle','Empty Recycle Bin permanently?')">Empty Recycle Bin</button>
    </div>
  </div>

  <div class="card">
    <h2>Unused Apps (1+ year) <span class="count" id="unused-count"></span></h2>
    <table id="unused-table"><thead>
      <tr><th>App</th><th>Last Used</th><th>Size</th><th></th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Largest Apps</h2>
    <table id="large-table"><thead>
      <tr><th>App</th><th>Size</th><th>Last Used</th><th></th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Recurring Offenders <span class="count" id="off-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">Run with <code>--watch</code> to populate.</p>
    <table id="off-table"><thead>
      <tr><th>Process</th><th>Times</th><th>Avg CPU</th><th>Peak</th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Security Audit <span class="count" id="sec-count"></span></h2>
    <div id="sec-findings"></div>
    <h3 style="font-size:12px;color:var(--dim);margin:14px 0 6px">Windows Defender</h3>
    <div id="defender-info"></div>
    <h3 style="font-size:12px;color:var(--dim);margin:14px 0 6px">/etc/hosts</h3>
    <div id="hosts-info" class="path"></div>
  </div>

  <div class="card">
    <h2>Startup Items <span class="count" id="start-count"></span></h2>
    <table id="start-table"><thead>
      <tr><th>Name</th><th>Source</th><th></th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Scheduled Tasks (non-Microsoft)</h2>
    <table id="task-table"><thead>
      <tr><th>Name</th><th>Path</th><th>Author</th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Network Activity <span class="count" id="net-count"></span></h2>
    <table id="net-table"><thead>
      <tr><th>Process</th><th>PID</th><th>Conns</th><th>Sample remote</th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Browser Extensions <span class="count" id="ext-count"></span></h2>
    <table id="ext-table"><thead>
      <tr><th>Browser</th><th>Name</th><th>Permissions</th><th>Risk</th></tr>
    </thead><tbody></tbody></table>
  </div>

</div>

<script>
function toast(msg, ok=true){
  const t=document.createElement('div');
  t.className='toast '+(ok?'ok':'err'); t.textContent=msg;
  document.body.appendChild(t); setTimeout(()=>t.remove(),4000);
}
async function api(path, body){
  const r = await fetch(path,{
    method: body?'POST':'GET',
    headers: body?{'Content-Type':'application/json'}:{},
    body: body?JSON.stringify(body):undefined});
  return r.json();
}
async function action(path, msg, body){
  if(msg && !confirm(msg)) return;
  const r = await api(path, body||{});
  toast(r.msg, r.ok);
  if(r.ok) setTimeout(loadAll, 500);
}
async function loadHealth(){
  const h = await api('/api/health');
  document.getElementById('cpuname').textContent = h.cpu_name+' · '+h.cores+' cores';
  document.getElementById('score').textContent = h.score;
  document.getElementById('score').className = 'score '+(h.score>=80?'good':h.score>=60?'warn':'bad');
  document.getElementById('health-metrics').innerHTML = `
    <div class="metric"><span>CPU Load</span><span class="v ${h.cpu_load>80?'bad':h.cpu_load>50?'warn':'good'}">${h.cpu_load}%</span></div>
    <div class="metric"><span>CPU Clock</span><span class="v ${h.speed_limit<80?'warn':'good'}">${h.cpu_cur_mhz} / ${h.cpu_max_mhz} MHz (${h.speed_limit}%)</span></div>
    <div class="metric"><span>Disk Used</span><span class="v ${h.disk_used_pct>90?'bad':h.disk_used_pct>80?'warn':'good'}">${h.disk_used_pct}%</span> <span class="path">(${h.disk_free_gb.toFixed(0)} GB free / ${h.disk_total_gb.toFixed(0)} GB)</span></div>
    <div class="metric"><span>Memory Used</span><span class="v ${h.mem_used_pct>85?'bad':h.mem_used_pct>70?'warn':'good'}">${h.mem_used_pct}%</span> <span class="path">(${h.mem_total_gb.toFixed(1)} GB total)</span></div>
    <div class="metric"><span>Page File Used</span><span class="v">${h.page_used_mb.toFixed(0)} MB</span></div>
    <div class="metric"><span>Last Boot</span><span class="path">${h.boot}</span></div>
  `;
  document.getElementById('health-issues').innerHTML = h.issues.length
    ? h.issues.map(i=>`<div class="issue ${i.sev}"><div class="msg">${i.msg}</div><div class="fix">→ ${i.fix}</div></div>`).join('')
    : '<div class="issue info"><div class="msg">No critical issues ✓</div></div>';
  document.getElementById('health-count').textContent = h.issues.length+' issues';
}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
async function loadIntel(){
  const p = await api('/api/intel');
  document.getElementById('intel-count').textContent = p.length+' processes';
  document.getElementById('intel-list').innerHTML = p.map(x=>{
    const killClass = x.verdict==='safe'?'kill-safe':x.verdict==='caution'?'kill-caution':x.verdict==='never'?'kill-never':'danger';
    const killDisabled = x.verdict==='never'?'disabled':'';
    const reasons = (x.reasons && x.reasons.length) ? x.reasons.join(' · ') : 'using few resources';
    return `
      <div class="proc">
        <div class="left">
          <div class="friendly">
            ${esc(x.friendly)}
            <span class="harm-pill ${x.harm_band}">${x.harm_band} ${x.harm}</span>
            <span class="verdict ${x.verdict}">${x.verdict==='never'?'do not kill':x.verdict}</span>
          </div>
          <div class="raw">${esc(x.name)} · pid ${x.pid} · ${esc(x.path||'')}</div>
          <div class="why">${esc(x.explanation)}<br><b style="color:#9aa6ba">Why flagged:</b> ${esc(reasons)}</div>
        </div>
        <div class="nums"><b>${(x.cpu_pct||0).toFixed(0)}%</b> CPU<br>${x.rss_mb<1024?x.rss_mb.toFixed(0)+' MB':(x.rss_mb/1024).toFixed(1)+' GB'}</div>
        <div><button class="${killClass}" ${killDisabled}
          onclick="action('/api/kill','Kill ${esc(x.friendly)} (PID ${x.pid})?\\n\\n${esc(x.explanation)}',{pid:${x.pid}})">
          ${x.verdict==='never'?'Protected':'Kill'}
        </button></div>
      </div>`;
  }).join('');
}
async function loadHeal(){
  const h = await api('/api/heal');
  document.getElementById('heal-sub').textContent = `Health ${h.score}/100 · ${h.summary}`;
  document.getElementById('heal-list').innerHTML = h.recommendations.map(r=>{
    const btn = r.action_label
      ? `<button class="primary" onclick='action(${JSON.stringify(r.action_url)},${JSON.stringify("Run: "+r.action_label+"?")},${JSON.stringify(r.action_body||{})})'>${esc(r.action_label)}</button>`
      : '';
    return `<div class="rec ${r.severity}">
      <div class="body">
        <div class="title">${esc(r.title)}</div>
        <div class="why">${esc(r.why)}</div>
      </div>
      <div class="cta">${btn}</div>
    </div>`;
  }).join('');
}
async function loadDisk(){
  const d = await api('/api/disk');
  document.querySelector('#disk-table tbody').innerHTML = d.map(x=>`
    <tr><td>${x.name}</td><td><b>${x.human}</b></td><td class="path">${x.note}</td>
        <td>${x.cleanable?'<span class="tag good">cleanable</span>':''}</td></tr>`).join('');
}
async function loadUnused(){
  const u = await api('/api/unused');
  document.getElementById('unused-count').textContent = u.length;
  document.querySelector('#unused-table tbody').innerHTML = u.map(x=>`
    <tr><td title="${x.publisher}">${x.name}</td><td class="path">${x.last_used}</td>
        <td>${x.size_human}</td>
        <td><button class="danger" onclick="action('/api/uninstall','Run uninstaller for ${x.name}?',{uninstall:${JSON.stringify(x.uninstall)}})">Uninstall</button></td>
    </tr>`).join('');
}
async function loadLarge(){
  const l = await api('/api/large');
  document.querySelector('#large-table tbody').innerHTML = l.map(x=>`
    <tr><td title="${x.publisher}">${x.name}</td><td><b>${x.size_human}</b></td>
        <td class="path">${x.last_used}</td>
        <td><button class="danger" onclick="action('/api/uninstall','Run uninstaller for ${x.name}?',{uninstall:${JSON.stringify(x.uninstall)}})">Uninstall</button></td>
    </tr>`).join('');
}
async function loadSec(){
  const s = await api('/api/security');
  document.getElementById('sec-count').textContent = s.findings.length+' findings';
  document.getElementById('sec-findings').innerHTML = s.findings.length
    ? s.findings.map(f=>`<div class="issue ${f.sev}"><div class="msg">${f.msg}</div><div class="fix">→ ${f.fix}</div></div>`).join('')
    : '<div class="issue info"><div class="msg">No threats detected ✓</div></div>';
  const d = s.defender;
  document.getElementById('defender-info').innerHTML = d.available
    ? `<div class="metric"><span>Antivirus</span><span class="v ${d.antivirus?'good':'bad'}">${d.antivirus?'ON':'OFF'}</span></div>
       <div class="metric"><span>Real-Time</span><span class="v ${d.realtime?'good':'bad'}">${d.realtime?'ON':'OFF'}</span></div>
       <div class="metric"><span>Tamper Protection</span><span class="v ${d.tamper?'good':'warn'}">${d.tamper?'ON':'OFF'}</span></div>
       <div class="metric"><span>Signatures</span><span class="path">${d.signatures}</span></div>`
    : '<div class="path">Defender status unavailable</div>';
  const h = s.hosts;
  document.getElementById('hosts-info').innerHTML = h.suspicious.length
    ? '<span class="tag bad">SUSPICIOUS</span><br>'+h.suspicious.map(s=>'• '+s).join('<br>')
    : `✓ ${h.total_entries} entries, none suspicious`;
}
async function loadStartup(){
  const s = await api('/api/startup');
  document.getElementById('start-count').textContent = s.length;
  document.querySelector('#start-table tbody').innerHTML = s.map(x=>`
    <tr><td>${x.name}<br><span class="path">${(x.value||'').slice(0,80)}</span></td>
        <td class="path">${x.kind}</td>
        <td>${x.kind==='registry'?`<button class="danger" onclick="action('/api/disable-startup','Disable ${x.name}?',{name:${JSON.stringify(x.name)},source:${JSON.stringify(x.source)}})">Disable</button>`:''}</td>
    </tr>`).join('');
}
async function loadTasks(){
  const t = await api('/api/tasks');
  document.querySelector('#task-table tbody').innerHTML = (t||[]).map(x=>`
    <tr><td>${x.TaskName||x.taskname||''}</td><td class="path">${x.TaskPath||x.taskpath||''}</td><td class="path">${x.Author||x.author||''}</td></tr>`).join('');
}
async function loadNet(){
  const n = await api('/api/network');
  document.getElementById('net-count').textContent = n.length;
  document.querySelector('#net-table tbody').innerHTML = n.map(x=>`
    <tr><td>${x.proc}</td><td class="path">${x.pid}</td><td><b>${x.count}</b></td>
        <td class="path">${x.samples.join('<br>')}</td></tr>`).join('');
}
async function loadExt(){
  const e = await api('/api/extensions');
  document.getElementById('ext-count').textContent = e.length;
  document.querySelector('#ext-table tbody').innerHTML = e.map(x=>`
    <tr><td>${x.browser}</td><td>${x.name}</td><td>${x.perms}</td>
        <td>${x.risky?'<span class="tag warn">broad perms</span>':'<span class="tag good">low</span>'}</td></tr>`).join('') || '<tr><td colspan="4" class="path">none</td></tr>';
}
async function loadHistory(){
  const h = await api('/api/history');
  document.getElementById('off-count').textContent = h.offenders.length;
  document.querySelector('#off-table tbody').innerHTML = h.offenders.length
    ? h.offenders.map(o=>`<tr><td>${o.name}</td><td><b>${o.appearances}</b></td><td>${o.avg_cpu}%</td><td>${o.max_cpu.toFixed(0)}%</td></tr>`).join('')
    : `<tr><td colspan="4" class="path">${h.count} snapshots stored. Run with --watch.</td></tr>`;
}
async function loadAll(){
  document.getElementById('score').textContent='…';
  await Promise.all([loadHealth(),loadHeal(),loadIntel(),loadDisk(),loadUnused(),loadLarge(),
                     loadSec(),loadStartup(),loadTasks(),loadNet(),loadExt(),loadHistory()]);
}
loadAll();
setInterval(loadHealth, 15000);
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path in ("/", "/index.html"):
                return self._send(200, HTML, "text/html; charset=utf-8")
            if path == "/api/health":      return self._send(200, get_health())
            if path == "/api/processes":   return self._send(200, get_processes())
            if path == "/api/intel":       return self._send(200, get_process_intel())
            if path == "/api/heal":        return self._send(200, get_heal_recommendations())
            if path == "/api/disk":        return self._send(200, get_disk_hogs())
            if path == "/api/unused":      return self._send(200, get_unused_apps())
            if path == "/api/large":       return self._send(200, get_largest_apps())
            if path == "/api/security":    return self._send(200, get_security_audit())
            if path == "/api/startup":     return self._send(200, get_startup_items())
            if path == "/api/tasks":       return self._send(200, get_scheduled_tasks())
            if path == "/api/network":     return self._send(200, get_network_connections())
            if path == "/api/extensions":  return self._send(200, get_browser_extensions())
            if path == "/api/history":     return self._send(200, get_history_summary())
            if path == "/api/snapshot":    return self._send(200, take_snapshot())
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        path = urlparse(self.path).path
        ln = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(ln) or b"{}")
        try:
            if path == "/api/kill":            return self._send(200, act_kill(body.get("pid")))
            if path == "/api/clean-temp":      return self._send(200, act_clean_temp())
            if path == "/api/empty-recycle":   return self._send(200, act_empty_recycle_bin())
            if path == "/api/uninstall":       return self._send(200, act_uninstall_app(body.get("uninstall")))
            if path == "/api/disable-startup": return self._send(200, act_disable_startup(body.get("name"), body.get("source")))
            return self._send(404, {"ok": False, "msg": "unknown action"})
        except Exception as e:
            return self._send(500, {"ok": False, "msg": str(e)})

def watcher_loop(interval_min=10):
    print(f"[watcher] sampling every {interval_min} min → {HIST_FILE}")
    take_snapshot()
    while True:
        time.sleep(interval_min * 60)
        try:
            snap = take_snapshot()
            ts = time.strftime("%H:%M", time.localtime(snap["ts"]))
            top = snap["top_procs"][0] if snap["top_procs"] else {}
            print(f"[watcher {ts}] score={snap['score']} top={top.get('name','?')}@{top.get('cpu',0):.0f}%")
        except Exception as e:
            print(f"[watcher] error: {e}")

def main():
    args = sys.argv[1:]
    if "--watch-only" in args:
        idx = args.index("--watch-only")
        interval = int(args[idx+1]) if idx+1 < len(args) and args[idx+1].isdigit() else 10
        watcher_loop(interval)
        return
    if "--watch" in args:
        idx = args.index("--watch")
        interval = int(args[idx+1]) if idx+1 < len(args) and args[idx+1].isdigit() else 10
        threading.Thread(target=watcher_loop, args=(interval,), daemon=True).start()

    server = HTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://localhost:{PORT}"
    print(f"\n  Win Optimizer running at {url}")
    print(f"  Press Ctrl+C to stop.\n")
    try:
        os.startfile(url)  # Windows-native open
    except Exception:
        try:
            subprocess.Popen(["cmd", "/c", "start", "", url])
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBye!")

if __name__ == "__main__":
    main()
