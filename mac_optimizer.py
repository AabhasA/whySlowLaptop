#!/usr/bin/env python3
"""
mac_optimizer.py — World-class local dashboard for macOS health, cleanup, security.

Run:    python3 mac_optimizer.py
Open:   http://localhost:8765

Pure Python stdlib. No installs. Read-only by default; destructive
actions require explicit button-click confirmation in the UI.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, unquote

PORT = 8765
HOME = Path.home()
TRASH = HOME / ".Trash"
HIST_FILE = HOME / ".mac_optimizer_history.json"
HIST_LOCK = threading.Lock()
MAX_SNAPSHOTS = 200  # ~33h at 10-min intervals

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def sh(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception as e:
        return f"ERR: {e}"

def sh_lines(cmd, timeout=15):
    out = sh(cmd, timeout)
    return [l for l in out.splitlines() if l.strip()]

def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def du_path(path, timeout=60):
    """Return size in bytes. -1 on error."""
    try:
        out = subprocess.run(["du", "-sk", str(path)], capture_output=True,
                             text=True, timeout=timeout)
        if out.returncode == 0:
            return int(out.stdout.split()[0]) * 1024
    except Exception:
        pass
    return -1

# ─────────────────────────────────────────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────────────────────────────────────────
def _parse_uptime(raw):
    """Extract just 'X days, HH:MM' from `uptime` output, dropping user count + load."""
    if "up" not in raw:
        return ""
    after = raw.split("up", 1)[-1]
    after = after.split(", load")[0].strip()
    # Drop trailing ", N user(s)"
    after = re.sub(r",\s*\d+\s*users?\s*$", "", after).strip().rstrip(",")
    return after

def get_health():
    therm = sh("pmset -g therm")
    speed_limit = 100
    m = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", therm)
    if m:
        speed_limit = int(m.group(1))

    # CPU load
    load = sh("sysctl -n vm.loadavg").split()
    load1 = float(load[1]) if len(load) > 1 else 0
    cores = int(sh("sysctl -n hw.ncpu") or 1)

    # Memory
    mp = sh("memory_pressure")
    free_pct = 0
    m = re.search(r"System-wide memory free percentage:\s*(\d+)%", mp)
    if m:
        free_pct = int(m.group(1))

    # Swap
    swap = sh("sysctl -n vm.swapusage")
    swap_used = 0
    m = re.search(r"used\s*=\s*([\d.]+)M", swap)
    if m:
        swap_used = float(m.group(1))

    # Disk
    df = sh("df -k /System/Volumes/Data")
    disk_used_pct = 0
    disk_free_gb = 0
    disk_total_gb = 0
    for line in df.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            try:
                total_kb = int(parts[1])
                used_kb = int(parts[2])
                avail_kb = int(parts[3])
                disk_total_gb = total_kb / 1024 / 1024
                disk_free_gb = avail_kb / 1024 / 1024
                disk_used_pct = int(used_kb * 100 / total_kb)
            except Exception:
                pass
            break

    # Wired memory
    vm = sh("vm_stat")
    wired_gb = 0
    m = re.search(r"Pages wired down:\s+(\d+)", vm)
    if m:
        wired_gb = int(m.group(1)) * 4096 / 1024 / 1024 / 1024

    # Battery
    batt = sh("pmset -g batt")
    battery = batt.splitlines()[1] if len(batt.splitlines()) > 1 else ""

    # Uptime
    uptime = sh("uptime")

    # Verdicts
    issues = []
    score = 100
    if speed_limit < 100:
        sev = 30 if speed_limit < 50 else 15
        # Don't guess the cause here — diagnose_slowness() inspects battery
        # cycles, AC state, charger wattage, and top processes to figure out
        # whether it's thermal, power, charger, or worn battery. The Heal
        # banner reuses that diagnosis. Keep this short + point at the button.
        issues.append({"sev": "critical" if speed_limit < 50 else "warn",
                       "msg": f"CPU clock limited to {speed_limit}% of normal",
                       "fix": "Click 'Why is my Mac slow right now?' in the Heal banner — it pinpoints whether it's battery, charger, or heat."})
        score -= sev
    if disk_used_pct > 90:
        issues.append({"sev": "critical", "msg": f"Disk {disk_used_pct}% full — APFS slows below 10% free",
                       "fix": "Clean Downloads folder and trash unused apps."})
        score -= 25
    elif disk_used_pct > 85:
        issues.append({"sev": "warn", "msg": f"Disk {disk_used_pct}% full",
                       "fix": "Clean Downloads folder."})
        score -= 10
    if free_pct < 20:
        issues.append({"sev": "warn", "msg": f"Memory free only {free_pct}%",
                       "fix": "Quit unused apps and Chrome tabs."})
        score -= 10
    # Swap is sticky on macOS — once pages are written out they stay in the
    # swapfile until the owning process touches them again, terminates, or
    # reboot. So a high swap number alone is *historical*, not a current
    # problem. Only flag when memory is *also* under pressure right now.
    # If free% is healthy, the swap is just leftover from a past spike.
    if swap_used > 1500 and free_pct < 30:
        issues.append({"sev": "warn", "msg": f"Active swap pressure ({swap_used:.0f}M with {free_pct}% free)",
                       "fix": "Quit memory-hungry apps. Reboot to clear stale swap."})
        score -= 10
    # Wired memory is only a problem if it's *also* causing pressure.
    # 2-4 GB wired is normal baseline on Apple Silicon (kernel, GPU, Photos
    # framework). Only flag when it's both large AND the system is squeezed.
    if wired_gb > 4 and (free_pct < 30 or swap_used > 1000):
        issues.append({"sev": "warn", "msg": f"Wired memory high ({wired_gb:.1f} GB) with memory pressure",
                       "fix": "Quit memory-hungry apps; if it persists across a full shutdown, suspect a kext or driver leak."})
        score -= 10
    if load1 > cores:
        issues.append({"sev": "warn", "msg": f"CPU load ({load1}) exceeds core count ({cores})",
                       "fix": "Check Top Processes panel for CPU hog."})
        score -= 5

    return {
        "speed_limit": speed_limit,
        "load1": load1, "cores": cores,
        "mem_free_pct": free_pct,
        "swap_used_mb": swap_used,
        "disk_used_pct": disk_used_pct,
        "disk_free_gb": disk_free_gb,
        "disk_total_gb": disk_total_gb,
        "wired_gb": wired_gb,
        "battery": battery,
        "uptime": _parse_uptime(uptime),
        "issues": issues,
        "score": max(0, score),
    }

def get_processes():
    out = sh("ps -Ao pid,pcpu,pmem,rss,user,comm -r")
    rows = []
    for line in out.splitlines()[1:31]:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        try:
            rows.append({
                "pid": int(parts[0]),
                "cpu": float(parts[1]),
                "mem": float(parts[2]),
                "rss_mb": int(parts[3]) / 1024,
                "user": parts[4],
                "name": Path(parts[5]).name,
                "path": parts[5],
            })
        except Exception:
            pass
    return rows

# ─────────────────────────────────────────────────────────────────────────────
# Process intelligence — what each process is, in plain English
# ─────────────────────────────────────────────────────────────────────────────
# verdict:  safe    = killing is fine, system will be unaffected or auto-restart
#           caution = killing may close an app or interrupt work
#           never   = killing will hang, crash, or reboot the Mac
#           unknown = unrecognised, judge by signature + path
PROCESS_INFO = {
    # ── Core kernel / window server (NEVER kill) ────────────────────────────
    "kernel_task":     ("macOS kernel", "The heart of macOS itself. High CPU here usually means the Mac is HOT — it's deliberately stealing CPU to cool down. Fix the heat (clean fans, unplug hub, give airflow), don't kill this.", "never"),
    "launchd":         ("Launchd (PID 1)", "Starts and supervises every other process on the Mac. Killing it instantly reboots the machine.", "never"),
    "WindowServer":    ("Window Server", "Draws every pixel on every screen. High CPU usually means too many windows, a busy animation, or an external display issue. Killing it logs you out.", "never"),
    "loginwindow":     ("Login Window", "Owns your user session. Killing it logs you out and you'll lose unsaved work.", "never"),
    "SystemUIServer":  ("System UI Server", "Runs the menu bar and status icons. Killing it makes the menu bar disappear briefly then auto-restart — usually safe but unnecessary.", "caution"),
    "Dock":            ("Dock", "The Dock at the bottom of the screen, plus Mission Control and Launchpad. Killing it relaunches automatically — sometimes used to fix a stuck Dock.", "safe"),
    "Finder":          ("Finder", "The file browser. Killing it relaunches automatically — a common fix for a stuck Finder window.", "safe"),

    # ── Spotlight / metadata ───────────────────────────────────────────────
    "mds":             ("Spotlight indexer", "Builds the search index for Spotlight. Heavy CPU after a big file copy or upgrade is normal and finishes within an hour. Killing it just makes it restart.", "safe"),
    "mds_stores":      ("Spotlight store writer", "Same as Spotlight. If it's been busy for >1 day, the index is stuck — disable then re-enable Spotlight for that disk.", "safe"),
    "mdworker":        ("Spotlight worker", "Reads individual files for Spotlight. Many of these are normal during indexing.", "safe"),
    "mdworker_shared": ("Spotlight worker", "Same as mdworker.", "safe"),
    "corespotlightd":  ("Spotlight (CoreSpotlight)", "Indexes app content (Mail, Messages, Notes) for Spotlight. Restart safe.", "safe"),

    # ── Photos / iCloud ────────────────────────────────────────────────────
    "photoanalysisd":  ("Photos analysis", "Scans your photo library for faces, scenes, and objects. Famously CPU-hungry. It only runs while the Mac is idle and plugged in — letting it finish overnight is the right move.", "safe"),
    "photolibraryd":   ("Photos library", "Manages your Photos library database. Killing it closes Photos.", "caution"),
    "mediaanalysisd":  ("Media analysis", "Analyses photos and videos for the Photos app's Memories and search.", "safe"),
    "cloudd":          ("iCloud daemon", "Syncs iCloud Drive, Photos, and app data. Killing it just delays sync.", "safe"),
    "bird":            ("iCloud Drive sync", "The iCloud Drive file syncer. Heavy CPU usually means a large upload/download is in progress.", "safe"),
    "rapportd":        ("Rapport (Continuity)", "Apple's Continuity / AirDrop / Handoff bridge. Restart safe.", "safe"),
    "nsurlsessiond":   ("Background downloads", "iCloud and App Store background transfers. Heavy network usually means a sync is happening.", "safe"),

    # ── Backup / Time Machine ──────────────────────────────────────────────
    "backupd":         ("Time Machine", "The Time Machine backup engine. Killing it cancels the current backup; the next one resumes from the same point.", "safe"),
    "backupd-helper":  ("Time Machine helper", "Helper for Time Machine backups.", "safe"),

    # ── Browsers (always many helper processes) ────────────────────────────
    "Google Chrome":             ("Google Chrome", "The browser. Each tab and extension also runs as a 'Chrome Helper'. Killing this closes the whole browser.", "caution"),
    "Google Chrome Helper":      ("Chrome tab/extension", "One Chrome tab, extension, or plugin. The biggest CPU hog here is usually a runaway tab — killing it just closes that tab.", "safe"),
    "Google Chrome Helper (Renderer)": ("Chrome tab", "A single Chrome tab. Killing it closes that one tab.", "safe"),
    "Google Chrome Helper (GPU)":      ("Chrome GPU process", "Chrome's GPU compositor. Killing it makes Chrome auto-restart it.", "safe"),
    "Google Chrome Helper (Plugin)":   ("Chrome plugin", "An old-style Chrome plugin or extension worker.", "safe"),
    "Safari":                    ("Safari", "Apple's browser. Each tab is a separate 'Safari Web Content' process.", "caution"),
    "Safari Web Content":        ("Safari tab", "One Safari tab. Killing it closes that tab.", "safe"),
    "com.apple.WebKit.WebContent": ("Safari tab (WebKit)", "One Safari tab. Killing it closes that tab.", "safe"),
    "firefox":                   ("Firefox", "The Firefox browser.", "caution"),
    "Microsoft Edge":            ("Microsoft Edge", "The Edge browser. Like Chrome, has many helper processes.", "caution"),
    "Arc":                       ("Arc Browser", "The Arc browser by The Browser Company.", "caution"),
    "Brave Browser":             ("Brave Browser", "The Brave browser.", "caution"),

    # ── Communication / collaboration apps ─────────────────────────────────
    "Slack":           ("Slack", "Slack chat. Notoriously memory-heavy because it's an Electron app. Quitting and reopening can free a lot of RAM.", "caution"),
    "Slack Helper":    ("Slack helper", "Slack background worker.", "safe"),
    "zoom.us":         ("Zoom", "The Zoom video-call app. Heavy CPU is normal during a call.", "caution"),
    "ZoomOpener":      ("Zoom helper", "Zoom's background helper that lets browser links open Zoom.", "safe"),
    "Microsoft Teams": ("Microsoft Teams", "Teams chat and calls. Like Slack, Electron-based and memory-heavy.", "caution"),
    "Discord":         ("Discord", "Discord chat. Electron app — memory hungry.", "caution"),
    "WhatsApp":        ("WhatsApp", "WhatsApp desktop client.", "caution"),
    "Telegram":        ("Telegram", "Telegram desktop client.", "caution"),
    "Spotify":         ("Spotify", "Music player. Surprisingly memory-heavy when left running for days.", "caution"),
    "Spotify Helper":  ("Spotify helper", "Spotify background worker.", "safe"),

    # ── Dev tools / editors ────────────────────────────────────────────────
    "Cursor":          ("Cursor (AI editor)", "The Cursor code editor. Heavy CPU usually means an AI request or a large project is being indexed.", "caution"),
    "Cursor Helper":   ("Cursor helper", "A Cursor renderer or worker process.", "safe"),
    "Code Helper":     ("VS Code helper", "VS Code renderer / extension host. Killing one usually just closes a tab or extension.", "safe"),
    "Electron":        ("Electron app", "An app built on Electron (Slack, VS Code, Discord, etc.). Check the path to see which one.", "caution"),
    "Visual Studio Code": ("VS Code", "The main VS Code window.", "caution"),
    "node":            ("Node.js", "A Node.js script. Often a dev server, build watcher, or LSP. Killing it stops that script.", "caution"),
    "python":          ("Python script", "A running Python script.", "caution"),
    "python3":         ("Python script", "A running Python script.", "caution"),
    "ruby":            ("Ruby script", "A running Ruby script.", "caution"),
    "java":            ("Java app", "A Java program — often an IDE (IntelliJ, Eclipse) or build tool (Gradle, Maven).", "caution"),
    "Docker":          ("Docker Desktop", "Docker Desktop UI. Killing this stops Docker entirely.", "caution"),
    "com.docker.hyperkit": ("Docker VM", "The Linux VM that Docker runs containers inside. High CPU here = a container is busy.", "caution"),
    "com.docker.backend":  ("Docker backend", "Docker Desktop's backend service.", "caution"),
    "git":             ("Git", "A git command — usually finishes quickly.", "safe"),
    "claude":          ("Claude Code CLI", "The Claude Code AI coding assistant running in your Terminal. Killing it ends the current conversation — you'll lose any unsaved chat context.", "caution"),
    "codex":           ("Codex CLI", "An AI coding CLI session. Killing it ends the current conversation.", "caution"),
    "ollama":          ("Ollama", "Local LLM runtime. High CPU/GPU during model inference is expected.", "caution"),
    "gh":              ("GitHub CLI", "A `gh` command — usually finishes quickly.", "safe"),

    # ── Apple background services (mostly safe to kill) ────────────────────
    "syslogd":         ("System log", "Writes system logs. Restarts automatically.", "safe"),
    "logd":            ("Unified logger", "Apple's unified logging system. Restarts automatically.", "safe"),
    "coreaudiod":      ("Core Audio", "Audio mixing and routing. Killing it interrupts any sound playback briefly then auto-restarts.", "caution"),
    "bluetoothd":      ("Bluetooth", "Bluetooth radio control. Killing it disconnects any Bluetooth devices briefly.", "caution"),
    "wirelessproxd":   ("AirDrop / Bluetooth proximity", "Discovers nearby Apple devices over Bluetooth.", "safe"),
    "airportd":        ("Wi-Fi", "The Wi-Fi radio service. Killing it briefly drops Wi-Fi.", "caution"),
    "trustd":          ("Certificate trust", "Validates SSL/TLS certificates for the whole system.", "caution"),
    "secd":            ("Keychain sync", "Syncs your keychain (passwords) with iCloud.", "caution"),
    "securityd":       ("Security daemon", "Manages keychain access. Killing it forces every app to re-prompt for keychain.", "never"),
    "powerd":          ("Power management", "Battery and sleep management.", "never"),
    "configd":         ("Network config", "Manages all network interfaces. Killing it can drop the network.", "never"),
    "mDNSResponder":   ("Bonjour / DNS", "Local DNS and Bonjour discovery. Killing it briefly breaks DNS lookups.", "caution"),
    "notifyd":         ("Notification dispatch", "Internal notification bus. Restarts automatically.", "safe"),
    "distnoted":       ("Distributed notifications", "Notification bus between apps. Restarts automatically.", "safe"),
    "cfprefsd":        ("Preferences daemon", "Reads/writes app preferences. Restarts automatically.", "safe"),
    "useractivityd":   ("Handoff / Activities", "Handoff and Continuity activities.", "safe"),
    "knowledge-agent": ("Suggestions agent", "Learns your usage patterns for Siri Suggestions.", "safe"),
    "suggestd":        ("Spotlight suggestions", "Generates Siri/Spotlight suggestions.", "safe"),
    "parsecd":         ("Spotlight web search", "Fetches web suggestions for Spotlight.", "safe"),
    "assistantd":      ("Siri", "Siri's main daemon.", "safe"),
    "Siri":            ("Siri", "Siri's main daemon.", "safe"),
    "spindump":        ("Spindump", "Apple's slow-process diagnostic tool. If this is busy, some app is hanging — find it in the report at /Library/Logs/DiagnosticReports.", "safe"),
    "ReportCrash":     ("Crash reporter", "Writes a crash report. Means another app just crashed.", "safe"),
    "fseventsd":       ("File events", "Tracks file changes for Time Machine, Spotlight, Dropbox, etc. Killing it forces a full re-index later.", "caution"),
    "lsd":             ("LaunchServices", "App registration database. Restarts automatically.", "safe"),
    "diskimages-helper": ("Disk image helper", "Mounts/unmounts disk images.", "safe"),
    "AMPDeviceDiscoveryAgent": ("iPhone/iPad sync", "Detects connected iPhones and iPads for Finder/Music sync.", "safe"),
    "AMPLibraryAgent": ("Music library", "The Apple Music library agent.", "safe"),
    "Music":           ("Apple Music", "The Music app.", "caution"),
    "TV":              ("Apple TV", "The TV app.", "caution"),
    "Terminal":        ("Terminal", "macOS's built-in terminal app — you're probably looking at it right now. Killing it closes every open Terminal window and any commands running inside them.", "caution"),
    "iTerm2":          ("iTerm2", "Third-party terminal app. Killing it closes every tab and any commands running inside.", "caution"),
    "Warp":            ("Warp", "Third-party terminal app. Killing it closes every tab and any commands running inside.", "caution"),
}

# Aliases for processes whose path-leaf differs
PROCESS_ALIASES = {
    "Google Chrome Helper (Renderer)": "Google Chrome Helper",
    "Google Chrome Helper (GPU)":      "Google Chrome Helper",
    "Google Chrome Helper (Plugin)":   "Google Chrome Helper",
}

def classify_process(name, path=""):
    """Return (friendly_name, explanation, verdict)."""
    base = name.split(" --")[0].strip()
    if base in PROCESS_INFO:
        return PROCESS_INFO[base]
    if base in PROCESS_ALIASES:
        return PROCESS_INFO[PROCESS_ALIASES[base]]
    # Heuristic fallbacks
    if "Helper" in base and "(" in base:
        # e.g. "Foo Helper (Renderer)" — strip the parenthetical
        parent = base.split(" (")[0]
        if parent in PROCESS_INFO:
            return PROCESS_INFO[parent]
    if path.startswith("/System/") or path.startswith("/usr/libexec/"):
        return (base, "Apple system service. Usually safe to leave alone — it'll restart on its own if killed.", "caution")
    if path.startswith("/Applications/"):
        app = path.split("/Applications/", 1)[1].split(".app", 1)[0]
        return (app, f"A part of the {app} app. Killing it usually just closes that app.", "caution")
    if "/Library/" in path:
        return (base, "A background helper installed by an app. Usually restarted automatically.", "caution")
    if path.startswith(str(HOME)) and "/Library/" not in path:
        return (base, "Runs from your home folder — unusual location for a system process. Worth investigating.", "caution")
    return (base, "Unrecognised process. If signed and from /Applications, probably fine; otherwise investigate.", "unknown")


def compute_harm(proc, recurring_names=None, signature=None):
    """
    Score 0–100 estimating how much harm a process is doing right now.
    Higher = more disruptive. Bands:
       0–19 idle, 20–49 noticeable, 50–79 heavy, 80–100 severe
    """
    cpu = proc.get("cpu", 0)
    mem = proc.get("mem", 0)
    rss_mb = proc.get("rss_mb", 0)
    score = 0
    reasons = []

    # CPU contribution — the biggest factor for "computer feels slow"
    if cpu >= 200:
        score += 60; reasons.append(f"using {cpu:.0f}% CPU (multi-core pegged)")
    elif cpu >= 100:
        score += 50; reasons.append(f"using {cpu:.0f}% CPU (one full core)")
    elif cpu >= 50:
        score += 35; reasons.append(f"using {cpu:.0f}% CPU sustained")
    elif cpu >= 20:
        score += 18; reasons.append(f"using {cpu:.0f}% CPU")
    elif cpu >= 8:
        score += 5; reasons.append(f"using {cpu:.0f}% CPU")
    elif cpu >= 5:
        score += 5

    # Memory contribution
    if rss_mb >= 4000:
        score += 25; reasons.append(f"holding {rss_mb/1024:.1f} GB of RAM")
    elif rss_mb >= 1500:
        score += 15; reasons.append(f"holding {rss_mb/1024:.1f} GB of RAM")
    elif rss_mb >= 1024:
        score += 8; reasons.append(f"holding {rss_mb/1024:.1f} GB of RAM")
    elif rss_mb >= 500:
        score += 6
    if mem >= 25:
        score += 10

    # Recurring offender — has spiked across multiple snapshots
    if recurring_names and proc.get("name") in recurring_names:
        score += 15; reasons.append("repeat offender across recent snapshots")

    # Unsigned / suspicious binary
    if signature in ("unsigned", "missing", "unknown"):
        score += 10; reasons.append(f"binary {signature}")

    # Suspicious path
    path = proc.get("path", "")
    if any(path.startswith(p) for p in ("/tmp/", "/var/tmp/", "/private/tmp/")):
        score += 30; reasons.append("running from temp folder (very suspicious)")

    return min(100, score), reasons


def get_process_intel(top=25):
    """
    Top processes annotated with friendly info, harm score, and verdict.

    The raw `ps` snapshot is wide (~25 procs) so we have headroom, but we
    only return entries that are actually doing something noticeable.
    Idle and near-idle processes are dropped — novices don't need to see
    a TouchBarServer at 0% CPU in their 'what to fix' list.
    """
    procs = get_processes()
    recurring = {o["name"] for o in get_recurring_offenders()}
    self_pid = os.getpid()
    # Drop the dashboard's own process so it never shows up as a kill candidate
    procs = [p for p in procs if p.get("pid") != self_pid]
    # Drop things the user is actively using (browsers, terminals, AI CLIs,
    # WindowServer). Same denylist Recurring Offenders uses — Aby reads
    # "presence in this list" as "I should act on this", so showing apps
    # he's actively using just creates anxiety with no action to take.
    # Exception: keep them if they're truly extreme (>=80% CPU or >=4 GB RAM),
    # because at that point it IS worth knowing even if it's a foreground app.
    procs = [p for p in procs
             if p.get("name") not in _OFFENDER_DENYLIST
             or p.get("cpu", 0) >= 80
             or p.get("rss_mb", 0) >= 4096]
    out = []
    for p in procs[:top]:
        friendly, explanation, verdict = classify_process(p["name"], p.get("path", ""))
        sig = None  # signature lookup is expensive; only the threats panel does it
        harm, reasons = compute_harm(p, recurring_names=recurring, signature=sig)
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

    # Filter: only keep things that are actually impacting the Mac.
    # Threshold: harm >= 10 OR using >= 8% CPU OR >= 1 GB of RAM.
    filtered = [p for p in out
                if p["harm"] >= 10 or p["cpu"] >= 8 or p["rss_mb"] >= 1024]

    # Always keep at least the top 3 so the panel isn't empty when the Mac is calm.
    if len(filtered) < 3:
        filtered = out[:3]

    # Cap at 10 visible — beyond that it's noise for novices.
    return filtered[:10]


# ─── "Why is my Mac slow right now?" — root-cause diagnosis ─────────────────
#
# The Heal banner says *what* to do but doesn't always say *why* the Mac is
# slow at this moment. This function combines power state, battery health,
# thermal throttle level, top heat-producing process, and memory pressure
# into a ranked diagnosis. Each cause has confidence + a one-line fix the
# user can act on without knowing macOS internals.
#
# All data sources are zero-sudo and zero-network: pmset, system_profiler,
# and our existing process scanner.

def _battery_info():
    """Cycle count, condition, max-capacity, charging state from system_profiler.
    Returns dict; missing fields are None on desktops without batteries."""
    out = sh("system_profiler SPPowerDataType 2>/dev/null", timeout=10)
    info = {"cycle_count": None, "condition": None, "max_capacity_pct": None,
            "charging": None, "ac_connected": None, "wattage": None,
            "adapter_name": None, "charge_remaining_pct": None,
            "fully_charged": None}
    if not out:
        return info
    in_battery = False
    for line in out.splitlines():
        s = line.strip()
        if "Battery Information:" in line:
            in_battery = True
        if "AC Charger Information:" in line:
            in_battery = False
        if "Cycle Count:" in s:
            try: info["cycle_count"] = int(s.split(":",1)[1].strip())
            except: pass
        elif "Condition:" in s:
            info["condition"] = s.split(":",1)[1].strip()
        elif "Maximum Capacity:" in s:
            v = s.split(":",1)[1].strip().rstrip("%")
            try: info["max_capacity_pct"] = int(v)
            except: pass
        elif "Charging:" in s and in_battery:
            info["charging"] = s.split(":",1)[1].strip().lower() == "yes"
        elif "Connected:" in s:
            info["ac_connected"] = s.split(":",1)[1].strip().lower() == "yes"
        elif "Wattage" in s and "(W)" in s:
            try: info["wattage"] = int(s.split(":",1)[1].strip())
            except: pass
        elif "Name:" in s and "Charger" not in s and not in_battery:
            info["adapter_name"] = s.split(":",1)[1].strip()
        elif "State of Charge" in s:
            v = s.split(":",1)[1].strip().rstrip("%")
            try: info["charge_remaining_pct"] = int(v)
            except: pass
        elif "Fully Charged:" in s:
            info["fully_charged"] = s.split(":",1)[1].strip().lower() == "yes"
    return info

def _thermal_info():
    """CPU speed limit + scheduler limit from pmset -g therm. The CPU speed
    limit is the % of full clock the kernel is allowing — anything below 100
    means the user is feeling slowness from throttling."""
    out = sh("pmset -g therm", timeout=5)
    info = {"cpu_speed_limit": 100, "scheduler_limit": 100, "raw": out}
    m = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", out)
    if m: info["cpu_speed_limit"] = int(m.group(1))
    m = re.search(r"CPU_Scheduler_Limit\s*=\s*(\d+)", out)
    if m: info["scheduler_limit"] = int(m.group(1))
    return info

def _power_source():
    """Whether we're on AC or battery, plus time-remaining if on battery."""
    out = sh("pmset -g batt", timeout=5)
    info = {"on_ac": False, "charge_pct": None, "time_remaining": None, "raw": out}
    if "AC Power" in out:
        info["on_ac"] = True
    m = re.search(r"(\d+)%", out)
    if m: info["charge_pct"] = int(m.group(1))
    m = re.search(r"(\d+:\d+)\s+remaining", out)
    if m: info["time_remaining"] = m.group(1)
    return info

# Things a user can do RIGHT NOW to ease CPU throttle when stuck on a worn
# battery without a charger. Each tip is ranked by realistic wattage savings —
# every freed watt is a watt the CPU is allowed to use within the same
# battery budget. Aby learned this the hard way: when his battery hit
# "Service Recommended" macOS clamped his CPU to 33% and there was no
# software override. These are the only legit workarounds short of a
# replacement.
_BATTERY_WORKAROUND_TIPS = [
    {"tip": "Plug in ANY USB-C charger — even a 20W iPhone brick or a power bank works",
     "saves": "biggest win: every external watt supplements the battery, throttle eases within ~30 seconds"},
    {"tip": "Drop screen brightness to ~30%",
     "saves": "5-8W (the display is one of the biggest drains on a laptop)"},
    {"tip": "Quit Chrome / Slack / Spotify / any heavy background app",
     "saves": "5-10W of sustained CPU heat — see Process Inspector for the worst offender"},
    {"tip": "Turn off keyboard backlight (F5 / Touch Bar)",
     "saves": "1-2W"},
    {"tip": "Disable Bluetooth if you don't need it",
     "saves": "~1W"},
    {"tip": "Avoid Low Power Mode — it makes throttling worse, not better, in this scenario",
     "saves": "(it caps the CPU more aggressively instead of letting it run at battery max)"},
]

def diagnose_slowness():
    """
    Run a top-to-bottom 'why is my Mac slow right now?' diagnosis. Returns a
    structured report with a list of *causes* (each with confidence + fix) and
    a single headline verdict. The user wants ONE clear answer plus the
    backing evidence, not a wall of metrics.
    """
    h = get_health()
    therm = _thermal_info()
    power = _power_source()
    batt = _battery_info()
    procs = get_processes()[:5]

    causes = []  # list of {severity, title, evidence, fix, confidence}

    # 1. CPU is being clamped by the kernel — biggest single cause of perceived
    #    slowness on Apple Silicon laptops. Figure out *why* it's clamped.
    if therm["cpu_speed_limit"] < 100:
        # Sub-cause A: running on a degraded battery WITHOUT charger.
        # Apple Silicon Macs throttle to whatever wattage the battery can
        # currently deliver — a worn battery (high cycles, "Service
        # Recommended") simply can't push the CPU at full clock.
        deg_battery = (
            (batt.get("cycle_count") or 0) > 800 or
            (batt.get("condition") and "service" in batt["condition"].lower()) or
            ((batt.get("max_capacity_pct") or 100) < 80)
        )
        if not power["on_ac"] and deg_battery:
            ev = []
            if batt.get("cycle_count"): ev.append(f"{batt['cycle_count']} battery cycles")
            if batt.get("condition"): ev.append(f"battery condition: {batt['condition']}")
            if batt.get("max_capacity_pct"): ev.append(f"battery max capacity: {batt['max_capacity_pct']}%")
            ev.append(f"CPU clamped to {therm['cpu_speed_limit']}%")
            ev.append("no charger plugged in")
            causes.append({
                "severity": "critical",
                "title": "Worn battery + no charger → kernel is throttling your CPU to prevent shutdown",
                "evidence": ev,
                "fix": "Plug in your original Apple charger directly to the wall (no hub). Long-term: Apple is recommending battery service — book a Genius Bar appointment.",
                "confidence": "high",
            })
        elif not power["on_ac"]:
            causes.append({
                "severity": "warn",
                "title": f"Running on battery — kernel clamped CPU to {therm['cpu_speed_limit']}%",
                "evidence": [
                    f"CPU speed limit: {therm['cpu_speed_limit']}%",
                    "no charger plugged in",
                    f"battery: {power['charge_pct']}% / {power['time_remaining']} remaining" if power['charge_pct'] else "",
                ],
                "fix": "Plug in the charger. macOS will release the throttle within 30 seconds.",
                "confidence": "high",
            })
        elif power["on_ac"] and (batt.get("wattage") or 0) and batt["wattage"] < 60:
            causes.append({
                "severity": "warn",
                "title": f"Underpowered charger ({batt['wattage']}W) — can't keep up with CPU demand",
                "evidence": [
                    f"adapter wattage: {batt['wattage']}W",
                    f"CPU clamped to {therm['cpu_speed_limit']}%",
                    "this Mac wants 67W or more under load",
                ],
                "fix": "Switch to a 67W+ Apple-branded charger. iPad/iPhone chargers will charge but won't deliver enough power for full CPU.",
                "confidence": "high",
            })
        elif power["on_ac"]:
            # On AC + healthy charger but still throttled = thermal
            top = procs[0] if procs else {}
            causes.append({
                "severity": "warn",
                "title": "Thermal throttle — your Mac is hot",
                "evidence": [
                    f"CPU clamped to {therm['cpu_speed_limit']}%",
                    "on AC power (so it's not a power issue)",
                    f"top heat producer: {top.get('name','?')} at {top.get('cpu',0):.0f}% CPU" if top else "",
                ],
                "fix": "Quit the heaviest process (see Process Inspector). Make sure no vents are blocked. Hot ambient room? Move to a cooler spot.",
                "confidence": "medium",
            })

    # 2. Memory pressure
    if h["swap_used_mb"] > 1500 and h["mem_free_pct"] < 30:
        top_mem = max(procs, key=lambda p: p.get("rss_mb",0)) if procs else {}
        causes.append({
            "severity": "critical",
            "title": "RAM exhausted — macOS is paging to disk (this is what beach-balling feels like)",
            "evidence": [
                f"swap used: {h['swap_used_mb']:.0f} MB",
                f"free memory: {h['mem_free_pct']}%",
                f"biggest memory user: {top_mem.get('name','?')} ({top_mem.get('rss_mb',0):.0f} MB)" if top_mem else "",
            ],
            "fix": f"Quit {top_mem.get('name','the biggest memory hog')} from Process Inspector, then close idle browser tabs.",
            "confidence": "high",
        })
    elif h["swap_used_mb"] > 500:
        causes.append({
            "severity": "info",
            "title": "Mild memory pressure — some swapping happening",
            "evidence": [f"swap used: {h['swap_used_mb']:.0f} MB", f"free memory: {h['mem_free_pct']}%"],
            "fix": "Not urgent yet. Quit apps you're not using if it grows.",
            "confidence": "medium",
        })

    # 3. A single process pinning the CPU
    if procs:
        top = procs[0]
        if top.get("cpu", 0) > 80:
            causes.append({
                "severity": "warn",
                "title": f"{top['name']} is pinning the CPU at {top['cpu']:.0f}%",
                "evidence": [f"PID {top['pid']}", f"CPU: {top['cpu']:.0f}%", f"RSS: {top.get('rss_mb',0):.0f} MB"],
                "fix": f"Open Process Inspector and use the Kill button on {top['name']}. If it comes back, that process is broken — quit its parent app and reopen.",
                "confidence": "high",
            })

    # 4. Disk almost full — slows everything from app launch to swap
    if h["disk_used_pct"] > 90:
        causes.append({
            "severity": "critical",
            "title": "Disk is almost full — macOS slows down dramatically below 10% free",
            "evidence": [f"disk used: {h['disk_used_pct']}%", f"free: {h['disk_free_gb']:.0f} GB"],
            "fix": "Use Stale Files / File Organizer / Duplicate Finder cards below to free space. Aim for ≥15% free.",
            "confidence": "high",
        })

    # Headline = the highest-severity cause, ordered critical > warn > info.
    rank = {"critical": 0, "warn": 1, "info": 2}
    causes.sort(key=lambda c: (rank.get(c["severity"], 9), -len(c["evidence"])))
    if causes:
        headline = causes[0]["title"]
    elif h["score"] >= 80:
        headline = "Your Mac looks healthy right now — no slowness root cause detected."
    else:
        headline = "Health score is low but no single root cause stands out — check Heal banner for general suggestions."

    # If the top cause is the battery+no-charger case, attach the workaround
    # tips. They're useless in any other diagnosis context, so we don't always
    # surface them — Aby's "filter aggressively" rule.
    workarounds = []
    if causes and causes[0]["title"].startswith("Worn battery + no charger"):
        workarounds = _BATTERY_WORKAROUND_TIPS
    elif causes and "Running on battery" in causes[0]["title"]:
        workarounds = _BATTERY_WORKAROUND_TIPS

    return {
        "headline": headline,
        "score": h["score"],
        "cpu_speed_limit": therm["cpu_speed_limit"],
        "on_ac": power["on_ac"],
        "battery": batt,
        "causes": causes,
        "workarounds": workarounds,
    }

def get_heal_recommendations():
    """
    Build a single 'Heal My Mac' report: what's wrong, what to do, in plain English.
    Each recommendation has: title, why, action_label, action_url, action_body, severity.
    """
    h = get_health()
    intel = get_process_intel(top=15)
    recs = []

    # 1. Critical health issues first
    for issue in h["issues"]:
        if issue["sev"] == "critical":
            recs.append({
                "severity": "critical",
                "title": issue["msg"],
                "why": issue["fix"],
                "action_label": None,
            })

    # 2. Top harmful processes that are SAFE to kill
    safe_kills = [p for p in intel if p["harm"] >= 50 and p["verdict"] == "safe"][:3]
    for p in safe_kills:
        recs.append({
            "severity": "high" if p["harm"] >= 80 else "medium",
            "title": f"Kill {p['friendly']} — {', '.join(p['reasons']) or 'heavy resource use'}",
            "why": p["explanation"],
            "action_label": f"Kill PID {p['pid']}",
            "action_url": "/api/kill",
            "action_body": {"pid": p["pid"]},
            "process": {"name": p["name"], "pid": p["pid"], "harm": p["harm"]},
        })

    # 3. Heavy processes that need user judgement (caution)
    caution = [p for p in intel if p["harm"] >= 50 and p["verdict"] == "caution"][:3]
    for p in caution:
        recs.append({
            "severity": "medium",
            "title": f"{p['friendly']} is heavy ({', '.join(p['reasons']) or 'high CPU/RAM'})",
            "why": p["explanation"] + " Quitting and re-opening it from the Dock usually frees a lot of memory.",
            "action_label": f"Force-quit PID {p['pid']}",
            "action_url": "/api/kill",
            "action_body": {"pid": p["pid"]},
            "process": {"name": p["name"], "pid": p["pid"], "harm": p["harm"]},
        })

    # 4. Disk hygiene if low
    if h["disk_used_pct"] >= 80:
        recs.append({
            "severity": "high" if h["disk_used_pct"] >= 90 else "medium",
            "title": f"Free up disk space — {h['disk_used_pct']}% full",
            "why": "macOS slows down dramatically below 10% free disk. Clearing user caches is safe and often frees several GB instantly.",
            "action_label": "Clean User Caches",
            "action_url": "/api/clean-caches",
            "action_body": {},
        })

    # 5. Trash if non-empty
    trash_size = du_path(TRASH, timeout=15)
    if trash_size > 100 * 1024 * 1024:  # >100 MB
        recs.append({
            "severity": "low",
            "title": f"Empty Trash to free {human(trash_size)}",
            "why": "Files in Trash still occupy disk until Trash is emptied.",
            "action_label": "Empty Trash",
            "action_url": "/api/empty-trash",
            "action_body": {},
        })

    # 6. Wired-memory / swap leak suggestion (only when actually under pressure).
    # Same logic as the health-issue gate: swap and wired in isolation are not
    # problems — only when they coincide with low free memory does it matter.
    if (h["swap_used_mb"] > 1500 and h["mem_free_pct"] < 30) or (h["wired_gb"] > 4 and h["mem_free_pct"] < 30):
        recs.append({
            "severity": "medium",
            "title": "Memory leak suspected — full shutdown recommended",
            "why": "Wired memory and swap don't clear with a normal restart. A full shutdown for 30 seconds clears everything and is the single most effective fix for a slow Mac that's been running for weeks.",
            "action_label": None,
        })

    # 7. CPU throttled — pull the actual root cause from the diagnose function
    # so the Heal banner doesn't show a stale "too hot or charger" message
    # when the real reason is a worn battery, underpowered charger, etc.
    # This used to be a hardcoded thermal message that confused users on
    # battery power with degraded batteries (Aby's case: 917 cycles, no AC).
    if h["speed_limit"] < 100:
        try:
            diag = diagnose_slowness()
            top_cause = diag["causes"][0] if diag.get("causes") else None
        except Exception:
            top_cause = None
        if top_cause:
            recs.append({
                "severity": "critical" if top_cause["severity"] == "critical" else "warn",
                "title": f"CPU throttled to {h['speed_limit']}% — {top_cause['title']}",
                "why": top_cause["fix"],
                "action_label": None,
            })
        else:
            recs.append({
                "severity": "critical",
                "title": f"CPU throttled to {h['speed_limit']}% speed",
                "why": "Click 'Why is my Mac slow right now?' below for the root cause.",
                "action_label": None,
            })

    if not recs:
        recs.append({
            "severity": "ok",
            "title": "Your Mac looks healthy ✓",
            "why": f"Health score {h['score']}/100. Nothing urgent to fix right now.",
            "action_label": None,
        })

    return {
        "score": h["score"],
        "recommendations": recs,
        "summary": f"{len([r for r in recs if r['severity'] in ('critical','high')])} urgent, "
                   f"{len([r for r in recs if r['severity'] == 'medium'])} suggested",
    }

# ─── PERMISSIONS / ONBOARDING ────────────────────────────────────────────────
def _check_fda():
    """Detect Full Disk Access by probing protected paths. Returns dict."""
    mail_dir = HOME / "Library/Mail"
    safari_hist = HOME / "Library/Safari/History.db"
    try:
        if mail_dir.exists():
            try:
                os.listdir(mail_dir)
            except PermissionError:
                return {"granted": False, "tested_path": str(mail_dir)}
        if safari_hist.exists():
            try:
                os.stat(safari_hist)
                return {"granted": True, "tested_path": str(safari_hist)}
            except PermissionError:
                return {"granted": False, "tested_path": str(safari_hist)}
        if mail_dir.exists():
            # Mail existed and we listed it fine
            return {"granted": True, "tested_path": str(mail_dir)}
        # Fallback: neither target exists — probe Safari container
        container = HOME / "Library/Containers/com.apple.Safari"
        if container.exists():
            try:
                os.listdir(container)
                return {"granted": True, "tested_path": str(container)}
            except PermissionError:
                return {"granted": False, "tested_path": str(container)}
        return {"granted": False, "tested_path": str(container)}
    except Exception as e:
        return {"granted": False, "tested_path": f"error: {e}"}

def _check_automation():
    """Detect Automation permission via System Events osascript probe."""
    try:
        r = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to return name of first process'],
            capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return {"granted": False}
        err = (r.stderr or "").lower()
        if "-1743" in err or "not authorized" in err:
            return {"granted": False}
        return {"granted": True}
    except Exception:
        return {"granted": False}

def get_permissions_status():
    fda = _check_fda()
    autom = _check_automation()
    return {
        "fda": fda,
        "automation": autom,
        "all_granted": bool(fda.get("granted") and autom.get("granted")),
    }

# Whitelist: pane name -> x-apple.systempreferences URL.
# IMPORTANT: this dict is the SINGLE source of truth for both the Permissions
# card (Agent 1) and the System Health Quick-Check card (Agent 2) — they used
# to define separate _SETTINGS_PANES dicts, and the second one silently wiped
# the first at module-load time, which is why "Open System Settings → Full
# Disk Access" did nothing for the user. Both code paths now look up here.
_PERM_SETTINGS_PANES = {
    "fda":         "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
    "automation":  "x-apple.systempreferences:com.apple.preference.security?Privacy_Automation",
    "filevault":   "x-apple.systempreferences:com.apple.preference.security?FileVault",
    "gatekeeper":  "x-apple.systempreferences:com.apple.preference.security",
    "firewall":    "x-apple.systempreferences:com.apple.preference.security",
    "auto_update": "x-apple.systempreferences:com.apple.preferences.softwareupdate",
    "sw_update":   "x-apple.systempreferences:com.apple.preferences.softwareupdate",
}

def _open_settings_url(url, friendly):
    """Open a System Settings deep-link and force the app to the foreground.
    On macOS 13+ the URL alone sometimes opens System Settings behind other
    windows, which is why the user thought 'nothing happened'. Activating via
    osascript guarantees it pops to front."""
    try:
        subprocess.Popen(["open", url])
    except Exception as e:
        return {"ok": False, "msg": f"open failed: {e}"}
    # Best-effort: force System Settings (or System Preferences on legacy
    # systems) to the front. Ignore errors — the URL still worked.
    try:
        subprocess.Popen(["osascript", "-e",
                          'tell application "System Settings" to activate'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    return {"ok": True, "msg": f"Opened System Settings → {friendly}. If you don't see it, check Mission Control."}

def act_open_settings(pane):
    """Permissions card variant — same backend as the Quick-Check version."""
    if pane not in _PERM_SETTINGS_PANES:
        return {"ok": False, "msg": f"unknown pane: {pane}"}
    friendly = {"fda": "Full Disk Access", "automation": "Automation"}.get(pane, pane)
    return _open_settings_url(_PERM_SETTINGS_PANES[pane], friendly)
# ─── END PERMISSIONS / ONBOARDING ────────────────────────────────────────────

def get_disk_hogs():
    """Show biggest folders in user dir + cleanable items."""
    targets = [
        (HOME / "Downloads", "Downloads", "Manually review. Sort by size in Finder."),
        (HOME / "Desktop", "Desktop", "Files cluttering Desktop slow Finder + WindowServer."),
        (HOME / "Library/Caches", "User Caches", "Safe to clear; apps regenerate."),
        (HOME / "Library/Application Support", "App Support", "Often hides Docker/Cursor/Slack data."),
        (HOME / "Library/Containers", "Containers (sandboxed apps)", "Rarely safe to delete."),
        (HOME / "Movies", "Movies", "Manual review."),
        (HOME / "Pictures", "Pictures", "Manual review."),
        (HOME / "Documents", "Documents", "Manual review."),
        (HOME / ".Trash", "Trash", "Empty to actually free space."),
        (Path("/Library/Caches"), "System Caches", "Needs sudo to clear."),
    ]
    out = []
    for path, name, note in targets:
        if path.exists():
            sz = du_path(path, timeout=120)
            out.append({"path": str(path), "name": name, "bytes": sz,
                        "human": human(sz) if sz >= 0 else "?", "note": note,
                        "cleanable": name in ("User Caches", "Trash")})
    out.sort(key=lambda x: x["bytes"], reverse=True)
    return out

# ─────────────────────────────────────────────────────────────────────────────
# App intelligence — friendly name + plain-English explanation per app.
# Matched on the .app filename (without extension). The "needed_if" line tells
# a novice the *one specific reason* they might want to keep the app, so they
# can make a Trash decision without having to ask Claude or Google it.
# ─────────────────────────────────────────────────────────────────────────────
APP_INFO = {
    # ── Drivers / hardware helpers ────────────────────────────────────────────
    "DisplayLink Manager": ("Driver for cheap USB docking stations and USB-to-HDMI adapters that use DisplayLink chips instead of native DisplayPort.",
                            "you currently use a USB hub or dock that requires DisplayLink to drive an external monitor."),
    "Logi Options+": ("Logitech's settings app for their mice and keyboards (button mapping, scroll speed, Flow).",
                      "you currently use a Logitech mouse or keyboard and want custom button bindings."),
    "Logitech Options": ("Older version of Logi Options+ for Logitech peripherals.",
                         "you have a Logitech mouse/keyboard and haven't upgraded to Options+."),
    "Logi Tune": ("Logitech's app for their webcams and headsets.",
                  "you use a Logitech webcam or headset that needs firmware updates or settings tweaks."),
    "Bose Connect": ("Companion app for Bose Bluetooth headphones.",
                     "you have Bose Bluetooth headphones and want firmware updates."),
    "JBL Headphones": ("Companion app for JBL Bluetooth headphones.",
                       "you have JBL Bluetooth headphones."),

    # ── Dev tools ─────────────────────────────────────────────────────────────
    "Python Launcher": ("A Finder helper from python.org — it lets you double-click .py files in Finder to run them. Does NOT contain Python itself.",
                        "you launch Python scripts by double-clicking them in Finder. If you use Terminal, you don't need this."),
    "Xcode": ("Apple's IDE for building macOS, iOS, watchOS, and tvOS apps. ~15 GB.",
              "you build apps for Apple platforms or use Simulator. Otherwise it's just disk weight."),
    "Android Studio": ("Google's IDE for building Android apps. Heavy.",
                       "you build Android apps."),
    "IntelliJ IDEA": ("JetBrains' Java/Kotlin IDE.",
                      "you write Java, Kotlin, or Android backend code."),
    "PyCharm": ("JetBrains' Python IDE.",
                "you prefer a full IDE for Python over a text editor."),
    "Docker": ("Container runtime that ships with a Linux VM. The VM pre-allocates 4-8 GB of RAM whether containers are running or not.",
               "you currently develop or run software inside containers."),

    # ── Utilities ─────────────────────────────────────────────────────────────
    "The Unarchiver": ("Free utility that opens .rar, .7z, .iso, .sit, .ace and other compressed formats macOS doesn't handle natively. macOS only handles .zip and .tar.gz on its own.",
                       "you sometimes download .rar or .7z files (game mods, leaked archives, software downloads). If you only handle .zip and .pdf, you don't need it."),
    "Keka": ("Another archive tool, similar to The Unarchiver. Handles .rar/.7z/.zip/.tar/.iso.",
             "you compress or extract non-zip archives. If you have The Unarchiver too, you only need one."),
    "Stuffit Expander": ("Very old archive tool — opens .sit, .sea, .sitx (StuffIt format from the 1990s/2000s).",
                         "you have to open archives from very old Mac software. Otherwise this is dead weight."),
    "VLC": ("The famously bulletproof video/audio player. Plays anything QuickTime can't.",
            "you watch video files in formats QuickTime doesn't support (.mkv, .avi, .flv, etc)."),
    "Handbrake": ("Free video transcoder — converts videos between formats and re-encodes for size.",
                  "you re-encode video files (e.g. ripping DVDs, shrinking phone footage, converting to mp4)."),
    "OBS": ("Free streaming and screen recording software (Twitch, YouTube Live, recording tutorials).",
            "you stream or record video content."),

    # ── Office / writing ──────────────────────────────────────────────────────
    "Microsoft Word": ("Microsoft's word processor.", "you need to open .doc/.docx files Apple Pages can't handle perfectly."),
    "Microsoft Excel": ("Microsoft's spreadsheet.", "you work with .xlsx files with macros or complex formulas."),
    "Microsoft PowerPoint": ("Microsoft's presentation tool.", "you exchange .pptx files with people who use PowerPoint."),
    "Pages": ("Apple's free word processor.", "you write documents on Mac. Comes free."),
    "Numbers": ("Apple's free spreadsheet.", "you do simple spreadsheets. Comes free."),
    "Keynote": ("Apple's free presentation tool.", "you make presentations on Mac. Comes free."),
    "GarageBand": ("Apple's free music creation tool. Often 1-2 GB.",
                   "you make music. If you don't, it's purely disk weight."),
    "iMovie": ("Apple's free video editor. Often 2-3 GB.",
               "you edit home videos on Mac. If not, it's purely disk weight."),

    # ── Communication ────────────────────────────────────────────────────────
    "Slack": ("Team chat. Each Slack workspace is one Electron process holding 500-1000 MB of RAM.",
              "you use Slack for work. Web version (slack.com in browser) does the same thing for less RAM."),
    "Microsoft Teams": ("Microsoft's chat / video calling app.",
                        "your work uses Teams for meetings or chat."),
    "Zoom": ("Zoom Meetings client.",
             "you take Zoom calls. Browser-based Zoom works for many calls if you don't want the app."),
    "Discord": ("Gaming/community chat app. Heavy Electron app.",
                "you're in Discord servers. Web version works too."),
    "WhatsApp": ("Meta's messaging app.",
                 "you message via WhatsApp. WhatsApp Web works in any browser."),
    "Skype": ("Microsoft's old video/voice calling app. Largely abandoned in favor of Teams.",
              "you have a specific contact who only uses Skype. Otherwise dead."),
    "TeamViewer": ("Remote access / remote desktop tool.",
                   "you remote into other people's computers (e.g. helping family debug)."),
    "AnyDesk": ("Another remote access tool, similar to TeamViewer.",
                "you remote into other machines."),

    # ── Apple ────────────────────────────────────────────────────────────────
    "Migration Assistant": ("Apple's tool for transferring data when you set up a new Mac.",
                            "you're setting up a new Mac. Otherwise unused — but it's part of macOS, NOT safe to remove."),
    "Boot Camp Assistant": ("Apple's helper for installing Windows on Intel Macs (does not work on Apple Silicon).",
                            "you have an Intel Mac and want a Windows partition."),
    "Audio MIDI Setup": ("macOS's built-in audio routing utility.",
                         "you configure pro audio interfaces or aggregate sound devices. Part of macOS, don't remove."),
    "Console": ("macOS's log viewer.", "you debug system issues. Part of macOS, don't remove."),
    "Activity Monitor": ("macOS's built-in process monitor.", "you check what's hogging CPU/RAM. Part of macOS, don't remove."),
    "Disk Utility": ("macOS's built-in disk management tool.", "you format drives or repair disks. Part of macOS, don't remove."),
    "Terminal": ("macOS's command-line. You're using it right now if you launched the dashboard from a terminal.",
                 "you ever use the command line. Part of macOS, don't remove."),
}

def classify_app(name):
    """Return (description, needed_if) for an .app filename. None if unknown."""
    base = name.replace(".app", "")
    if base in APP_INFO:
        return APP_INFO[base]
    # Soft match: case-insensitive prefix
    low = base.lower()
    for key, val in APP_INFO.items():
        if low == key.lower() or low.startswith(key.lower() + " "):
            return val
    return None


def _mdls_last_used(path):
    """
    Return Unix timestamp of an app's real 'last opened' date via Spotlight
    metadata (kMDItemLastUsedDate). This is what Finder shows in column view
    under 'Date Last Opened' and is the only reliable signal on macOS — the
    .app bundle's filesystem atime/mtime do NOT update when an app launches.
    Returns 0 if Spotlight has no record (app never opened or not indexed).
    """
    try:
        out = subprocess.run(
            ["mdls", "-name", "kMDItemLastUsedDate", "-raw", str(path)],
            capture_output=True, text=True, timeout=5)
        s = (out.stdout or "").strip()
        if not s or s == "(null)":
            return 0
        # Format: "2026-04-08 18:51:20 +0000"
        return int(time.mktime(time.strptime(s.split(" +")[0], "%Y-%m-%d %H:%M:%S")))
    except Exception:
        return 0


def get_apps_with_dates():
    apps = []
    roots = [Path("/Applications"), HOME / "Applications"]

    def _record(app):
        try:
            st = app.stat()
            last_used = _mdls_last_used(app)
            # Fall back to mtime ONLY when Spotlight has no record at all
            # (rare — usually a brand-new install that's never been opened).
            if last_used == 0:
                last_used = int(st.st_mtime)
            apps.append({
                "name": app.name,
                "path": str(app),
                "last_used": last_used,
                "mtime": st.st_mtime,
                "size": du_path(app, timeout=30),
            })
        except Exception:
            pass

    for root in roots:
        if not root.exists():
            continue
        for app in root.glob("*.app"):
            _record(app)
        # Nested one level (e.g. /Applications/Adobe Photoshop 2025/foo.app)
        for sub in root.iterdir():
            if sub.is_dir() and not sub.name.endswith(".app"):
                for app in sub.glob("*.app"):
                    _record(app)
    return apps

def _annotate_app(a):
    info = classify_app(a["name"])
    return {
        "description": info[0] if info else None,
        "needed_if": info[1] if info else None,
    }

def get_unused_apps(days=365):
    cutoff = time.time() - days * 86400
    apps = get_apps_with_dates()
    out = []
    for a in apps:
        if a["last_used"] and a["last_used"] < cutoff:
            out.append({
                "name": a["name"],
                "path": a["path"],
                "last_used": time.strftime("%Y-%m-%d", time.localtime(a["last_used"])),
                "size_bytes": a["size"],
                "size_human": human(a["size"]) if a["size"] > 0 else "?",
                **_annotate_app(a),
            })
    out.sort(key=lambda x: x["last_used"])
    return out

def get_largest_apps(top=15):
    apps = get_apps_with_dates()
    apps.sort(key=lambda x: x["size"], reverse=True)
    return [{
        "name": a["name"],
        "path": a["path"],
        "size_bytes": a["size"],
        "size_human": human(a["size"]) if a["size"] > 0 else "?",
        "last_used": time.strftime("%Y-%m-%d", time.localtime(a["last_used"])) if a["last_used"] else "never",
        **_annotate_app(a),
    } for a in apps[:top]]

# ─────────────────────────────────────────────────────────────────────────────
# Stale-file scan — Downloads / Documents / Desktop files untouched for years
# ─────────────────────────────────────────────────────────────────────────────
_STALE_FILE_ROOTS = [HOME / "Downloads", HOME / "Documents", HOME / "Desktop"]
_STALE_MAX_DEPTH  = 4
_STALE_MIN_BYTES  = 1 * 1024 * 1024   # ignore anything under 1 MB
_STALE_MIN_DAYS   = 900               # ~2.5 years
_STALE_SKIP_DIRS  = {".git", "node_modules", ".venv", "venv", "__pycache__",
                     ".cache", ".Trash", "Library", ".npm", ".gradle"}

_STALE_CACHE = {"data": None, "ts": 0}
_STALE_CACHE_TTL = 300  # 5 minutes

def get_stale_files(min_days=_STALE_MIN_DAYS, min_bytes=_STALE_MIN_BYTES, limit=200):
    # Cached: a full ~/Documents walk can take 10+ seconds. The contents of
    # Downloads/Documents/Desktop don't change second-to-second, so a 5-minute
    # cache makes the dashboard snappy without going stale.
    now = time.time()
    if _STALE_CACHE["data"] is not None and (now - _STALE_CACHE["ts"]) < _STALE_CACHE_TTL:
        return _STALE_CACHE["data"]
    data = _scan_stale_files(min_days, min_bytes, limit)
    _STALE_CACHE["data"] = data
    _STALE_CACHE["ts"] = now
    return data

def _scan_stale_files(min_days=_STALE_MIN_DAYS, min_bytes=_STALE_MIN_BYTES, limit=200):
    """Files in Downloads/Documents/Desktop not opened OR modified in `min_days`
    days. Filters aggressively per Aby's 'hide noise' rule: tiny files, hidden
    files, .app contents, dependency dirs, and the optimizer itself are skipped.
    Sorted largest-first so the biggest reclaimable items are at the top."""
    cutoff = time.time() - min_days * 86400
    out = []
    for root in _STALE_FILE_ROOTS:
        if not root.exists():
            continue
        root_str = str(root)
        for dirpath, dirnames, filenames in os.walk(root_str):
            # Depth-limit the walk so a giant ~/Documents tree doesn't stall.
            depth = dirpath[len(root_str):].count(os.sep)
            if depth >= _STALE_MAX_DEPTH:
                dirnames[:] = []
            # Don't recurse into .app bundles, hidden dirs, or dep caches.
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".")
                           and not d.endswith(".app")
                           and d not in _STALE_SKIP_DIRS]
            for fn in filenames:
                if fn.startswith(".") or fn == "Icon\r":
                    continue
                fp = os.path.join(dirpath, fn)
                if "mac_optimizer" in fp.lower():
                    continue
                try:
                    st = os.stat(fp)
                except Exception:
                    continue
                if st.st_size < min_bytes:
                    continue
                # Use the most recent of mtime/atime — if either is recent
                # the file was touched recently and should be left alone.
                last = max(st.st_mtime, st.st_atime)
                if last >= cutoff:
                    continue
                age_days = int((time.time() - last) / 86400)
                age_years = age_days / 365.25
                # Bucket the age so the UI can group by 'oldest first'.
                # Boundaries chosen so each bucket contains roughly meaningful
                # cohorts: ancient, very old, old, recently-stale.
                if   age_years >= 5: bucket, bucket_order = "5+ years",        0
                elif age_years >= 4: bucket, bucket_order = "4–5 years",       1
                elif age_years >= 3: bucket, bucket_order = "3–4 years",       2
                else:                bucket, bucket_order = "2.5–3 years",     3
                out.append({
                    "path": fp,
                    "name": fn,
                    "size_bytes": st.st_size,
                    "size_human": human(st.st_size),
                    "last_used": time.strftime("%Y-%m-%d", time.localtime(last)),
                    "age_days": age_days,
                    "age_years": round(age_years, 1),
                    "bucket": bucket,
                    "bucket_order": bucket_order,
                    "root": root.name,
                })
    # Oldest first (bucket asc), then largest first within each bucket so the
    # most reclaimable items in each cohort float to the top of their group.
    out.sort(key=lambda x: (x["bucket_order"], -x["size_bytes"]))
    # Cap per bucket so a huge 5+yr backlog can't crowd out the newer buckets —
    # the user wants to see *every* age cohort represented, not 200 items
    # from a single one.
    per_bucket = max(25, limit // 4)
    bucket_counts = {}
    capped = []
    for item in out:
        b = item["bucket_order"]
        bucket_counts[b] = bucket_counts.get(b, 0) + 1
        if bucket_counts[b] <= per_bucket:
            capped.append(item)
    return capped

# ─────────────────────────────────────────────────────────────────────────────
# File Organizer — bucket every ≥1 MB file in Downloads/Documents/Desktop by
# AGE first (Aby's explicit preference), then by CATEGORY (images, videos,
# documents, installers, other). Feeds a 5×5 grid in the dashboard. Drilldowns
# return the actual files for one (age, category) cell on demand.
# ─────────────────────────────────────────────────────────────────────────────

_ORG_ROOTS = _STALE_FILE_ROOTS  # same three roots as stale-files
_ORG_MAX_DEPTH = 4
_ORG_MIN_BYTES = 1 * 1024 * 1024

_ORG_AGE_LABELS = ["Last 1 year", "1–2 years", "2–3 years", "3–5 years", "5+ years"]
_ORG_CAT_NAMES  = ["Images", "Videos", "Documents", "Installers", "Other"]

_ORG_EXT_MAP = {
    "Images":     {".jpg",".jpeg",".png",".gif",".heic",".webp",".raw",".tif",".tiff",".bmp",".svg"},
    "Videos":     {".mp4",".mov",".avi",".mkv",".webm",".wmv",".m4v",".flv",".mpeg",".mpg"},
    "Documents":  {".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".txt",".md",".pages",".numbers",".key",".rtf",".odt",".csv"},
    "Installers": {".dmg",".pkg",".zip",".tar",".gz",".tgz",".bz2",".7z",".iso",".deb",".rpm"},
}

def _org_classify_ext(fn):
    ext = os.path.splitext(fn)[1].lower()
    for cat, exts in _ORG_EXT_MAP.items():
        if ext in exts:
            return cat
    return "Other"

def _org_age_index(age_years):
    if age_years < 1: return 0
    if age_years < 2: return 1
    if age_years < 3: return 2
    if age_years < 5: return 3
    return 4

_ORG_CACHE = {"summary": None, "files": None, "ts": 0}
_ORG_CACHE_TTL = 300  # 5 minutes

def _scan_organizer():
    """Walk the three roots, bucket every file ≥1 MB by (age, category).
    Returns (summary, files_by_cell) where files_by_cell is a dict
    keyed by (age_idx, cat_name) → list of file dicts sorted largest-first."""
    now = time.time()
    # age_idx → cat_name → list
    files_by_cell = {i: {c: [] for c in _ORG_CAT_NAMES} for i in range(5)}
    for root in _ORG_ROOTS:
        if not root.exists():
            continue
        root_str = str(root)
        for dirpath, dirnames, filenames in os.walk(root_str):
            depth = dirpath[len(root_str):].count(os.sep)
            if depth >= _ORG_MAX_DEPTH:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".")
                           and not d.endswith(".app")
                           and d not in _STALE_SKIP_DIRS]
            for fn in filenames:
                if fn.startswith(".") or fn == "Icon\r":
                    continue
                fp = os.path.join(dirpath, fn)
                if "mac_optimizer" in fp.lower():
                    continue
                try:
                    st = os.stat(fp)
                except Exception:
                    continue
                if st.st_size < _ORG_MIN_BYTES:
                    continue
                last = max(st.st_mtime, st.st_atime)
                age_days = max(0, int((now - last) / 86400))
                age_years = age_days / 365.25
                age_idx = _org_age_index(age_years)
                cat = _org_classify_ext(fn)
                files_by_cell[age_idx][cat].append({
                    "path": fp,
                    "name": fn,
                    "size_bytes": st.st_size,
                    "size_human": human(st.st_size),
                    "last_used": time.strftime("%Y-%m-%d", time.localtime(last)),
                    "age_days": age_days,
                    "age_years": round(age_years, 1),
                    "root": root.name,
                })
    # Sort each cell's files largest-first
    for i in range(5):
        for c in _ORG_CAT_NAMES:
            files_by_cell[i][c].sort(key=lambda x: -x["size_bytes"])
    # Build the summary grid — always 5 age rows, always 5 categories each.
    summary = []
    for i, label in enumerate(_ORG_AGE_LABELS):
        cats = []
        total_count = 0
        total_bytes = 0
        for c in _ORG_CAT_NAMES:
            lst = files_by_cell[i][c]
            cnt = len(lst)
            bts = sum(f["size_bytes"] for f in lst)
            total_count += cnt
            total_bytes += bts
            cats.append({
                "name": c,
                "count": cnt,
                "size_bytes": bts,
                "size_human": human(bts) if bts else "—",
            })
        summary.append({
            "age": label,
            "age_order": i,
            "is_current": i == 0,
            "categories": cats,
            "total_count": total_count,
            "total_human": human(total_bytes) if total_bytes else "—",
        })
    return summary, files_by_cell

def get_file_organizer():
    now = time.time()
    if _ORG_CACHE["summary"] is not None and (now - _ORG_CACHE["ts"]) < _ORG_CACHE_TTL:
        return _ORG_CACHE["summary"]
    summary, files = _scan_organizer()
    _ORG_CACHE["summary"] = summary
    _ORG_CACHE["files"]   = files
    _ORG_CACHE["ts"]      = now
    return summary

def get_organizer_drill(age_order, category, cap=100):
    # Ensure the cache is warm — reuses the same walk as the summary so
    # drilldown is basically free.
    if _ORG_CACHE["files"] is None or (time.time() - _ORG_CACHE["ts"]) >= _ORG_CACHE_TTL:
        get_file_organizer()
    try:
        ai = int(age_order)
    except Exception:
        return []
    if ai < 0 or ai > 4:
        return []
    if category not in _ORG_CAT_NAMES:
        return []
    cell = _ORG_CACHE["files"].get(ai, {}).get(category, [])
    return cell[:cap]

# ─────────────────────────────────────────────────────────────────────────────
# Duplicate File Finder — pure-stdlib sha1 dedupe across user content roots.
# Three-stage pipeline (size → first-64k hash → full hash) so we only fully
# read files that already share a size AND a partial hash. Read-only: this
# module never deletes anything; trashing a single copy goes through the
# dedicated act_trash_one_duplicate() endpoint which re-validates the path.
# ─────────────────────────────────────────────────────────────────────────────

_DUP_ROOTS = [HOME / "Downloads", HOME / "Documents", HOME / "Desktop",
              HOME / "Movies", HOME / "Music"]
_DUP_MAX_DEPTH = 5
_DUP_MIN_BYTES = 10 * 1024 * 1024  # 10 MB — cheap wins only
_DUP_CAP       = 50
_DUP_SKIP_DIRS = set(_STALE_SKIP_DIRS) | {"Photos Library.photoslibrary"}

_DUP_CACHE = {"data": None, "ts": 0}
_DUP_CACHE_TTL = 600  # 10 minutes

# Priority for "keep one" convenience button — higher wins.
_DUP_ROOT_KEEP_PRIORITY = {"Documents": 5, "Desktop": 4, "Downloads": 3,
                           "Movies": 2, "Music": 1}

def _dup_hash_partial(path, n=64*1024):
    import hashlib
    h = hashlib.sha1()
    try:
        with open(path, "rb") as f:
            h.update(f.read(n))
    except Exception:
        return None
    return h.hexdigest()

def _dup_hash_full(path):
    import hashlib
    h = hashlib.sha1()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
    except Exception:
        return None
    return h.hexdigest()

def _scan_duplicates(min_bytes=_DUP_MIN_BYTES):
    # Stage 1: walk + collect (path, size)
    by_size = {}
    for root in _DUP_ROOTS:
        if not root.exists():
            continue
        root_str = str(root)
        for dirpath, dirnames, filenames in os.walk(root_str):
            depth = dirpath[len(root_str):].count(os.sep)
            if depth >= _DUP_MAX_DEPTH:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".")
                           and not d.endswith(".app")
                           and not d.endswith(".photoslibrary")
                           and d not in _DUP_SKIP_DIRS]
            for fn in filenames:
                if fn.startswith(".") or fn == "Icon\r":
                    continue
                fp = os.path.join(dirpath, fn)
                try:
                    st = os.stat(fp)
                except Exception:
                    continue
                if st.st_size < min_bytes:
                    continue
                by_size.setdefault(st.st_size, []).append((fp, st.st_mtime, root.name))
    # Drop singletons
    candidates = {sz: lst for sz, lst in by_size.items() if len(lst) > 1}
    # Stage 2: partial hash
    by_partial = {}
    for sz, lst in candidates.items():
        sub = {}
        for fp, mt, rn in lst:
            ph = _dup_hash_partial(fp)
            if ph is None:
                continue
            sub.setdefault((sz, ph), []).append((fp, mt, rn))
        for key, items in sub.items():
            if len(items) > 1:
                by_partial[key] = items
    # Stage 3: full hash
    dup_sets = []
    for (sz, _ph), items in by_partial.items():
        sub = {}
        for fp, mt, rn in items:
            fh = _dup_hash_full(fp)
            if fh is None:
                continue
            sub.setdefault(fh, []).append((fp, mt, rn))
        for fh, group in sub.items():
            if len(group) < 2:
                continue
            files = []
            for fp, mt, rn in group:
                files.append({
                    "path": fp,
                    "name": os.path.basename(fp),
                    "root": rn,
                    "last_used": time.strftime("%Y-%m-%d", time.localtime(mt)),
                })
            wasted = (len(group) - 1) * sz
            dup_sets.append({
                "hash": fh,
                "size_bytes": sz,
                "size_human": human(sz),
                "count": len(group),
                "wasted_bytes": wasted,
                "wasted_human": human(wasted),
                "files": files,
            })
    dup_sets.sort(key=lambda d: -d["wasted_bytes"])
    return dup_sets[:_DUP_CAP]

def get_duplicates():
    now = time.time()
    if _DUP_CACHE["data"] is not None and (now - _DUP_CACHE["ts"]) < _DUP_CACHE_TTL:
        return _DUP_CACHE["data"]
    data = _scan_duplicates()
    _DUP_CACHE["data"] = data
    _DUP_CACHE["ts"] = now
    return data

# ─────────────────────────────────────────────────────────────────────────────
# History / recurring-offender detection
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
    """Compact snapshot for trend tracking."""
    h = get_health()
    procs = get_processes()[:15]
    snap = {
        "ts": int(time.time()),
        "score": h["score"],
        "speed_limit": h["speed_limit"],
        "mem_free": h["mem_free_pct"],
        "swap_mb": h["swap_used_mb"],
        "wired_gb": round(h["wired_gb"], 2),
        "disk_used": h["disk_used_pct"],
        "top_procs": [{"name": p["name"], "cpu": p["cpu"], "rss": round(p["rss_mb"])} for p in procs],
    }
    hist = load_history()
    hist["snapshots"].append(snap)
    hist["snapshots"] = hist["snapshots"][-MAX_SNAPSHOTS:]
    save_history(hist)
    return snap

# Names to never flag as recurring offenders. These are either: the optimizer
# itself (python3, polluting old snapshots from before the self-PID filter),
# or processes whose 'high CPU' is normal/expected because the user is actively
# using them. Flagging them just creates noise.
_OFFENDER_DENYLIST = {
    "python3", "python",          # often the optimizer or the user's dev work
    "claude", "codex",            # AI CLI sessions the user is actively using
    "WindowServer",               # graphics — spikes are expected with animations
    "Terminal", "iTerm2", "Warp", # terminal emulators
    "Safari", "Google Chrome",    # browsers — high CPU is normal while browsing
    "Microsoft Edge", "firefox",
    "signpost_reporter",          # macOS perf telemetry — bursts are routine
}

def get_recurring_offenders(min_appearances=5, cpu_threshold=30):
    """
    Processes that have repeatedly pegged CPU across recent snapshots —
    intended to catch *chronically* misbehaving things (leaking daemons,
    runaway helpers), NOT stuff the user is actively using.

    Thresholds tuned to be strict: must be ≥30% CPU in ≥5 of the last
    30 snapshots, and we drop a denylist of names that are almost always
    legitimate user activity (browsers, terminals, AI CLIs, the optimizer).
    """
    hist = load_history()
    counts = {}
    for snap in hist["snapshots"][-30:]:
        for p in snap.get("top_procs", []):
            if p["cpu"] < cpu_threshold:
                continue
            k = p["name"]
            if k in _OFFENDER_DENYLIST:
                continue
            if k not in counts:
                counts[k] = {"name": k, "appearances": 0, "max_cpu": 0, "avg_cpu": 0, "total": 0}
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
    snaps = hist["snapshots"][-50:]
    return {
        "count": len(hist["snapshots"]),
        "recent": [{"ts": s["ts"], "score": s["score"], "speed_limit": s["speed_limit"],
                    "mem_free": s["mem_free"], "swap_mb": s["swap_mb"]} for s in snaps],
        "offenders": get_recurring_offenders(),
    }

def get_session_summary(since_ts):
    """Compare the snapshot at-or-just-before `since_ts` with the latest snapshot
    and return per-metric deltas for the Story-mode modal. If `since_ts` is
    older than the oldest snapshot, use the oldest snapshot instead."""
    hist = load_history()
    snaps = hist.get("snapshots", [])
    if not snaps:
        return {"error": "no snapshots yet"}
    try:
        since_ts = int(since_ts)
    except (TypeError, ValueError):
        since_ts = 0
    # Find the latest snapshot at-or-before since_ts; fall back to oldest.
    old = None
    for s in snaps:
        if s["ts"] <= since_ts:
            old = s
        else:
            break
    if old is None:
        old = snaps[0]
    new = snaps[-1]
    def _d(a, b):
        try:
            return round(b - a, 2)
        except Exception:
            return 0
    return {
        "since": since_ts,
        "snapshots_compared": {"old_ts": old["ts"], "new_ts": new["ts"]},
        "deltas": {
            "score":         {"old": old.get("score", 0),    "new": new.get("score", 0),
                              "delta": _d(old.get("score", 0), new.get("score", 0))},
            "wired_gb":      {"old": old.get("wired_gb", 0), "new": new.get("wired_gb", 0),
                              "delta": _d(old.get("wired_gb", 0), new.get("wired_gb", 0))},
            "mem_free_pct":  {"old": old.get("mem_free", 0), "new": new.get("mem_free", 0),
                              "delta": _d(old.get("mem_free", 0), new.get("mem_free", 0))},
            "swap_mb":       {"old": old.get("swap_mb", 0),  "new": new.get("swap_mb", 0),
                              "delta": _d(old.get("swap_mb", 0), new.get("swap_mb", 0))},
            "disk_used_pct": {"old": old.get("disk_used", 0),"new": new.get("disk_used", 0),
                              "delta": _d(old.get("disk_used", 0), new.get("disk_used", 0))},
        },
    }

# ─────────────────────────────────────────────────────────────────────────────
# Security audit
# ─────────────────────────────────────────────────────────────────────────────
def get_login_items():
    out = sh('osascript -e \'tell application "System Events" to get the name of every login item\'')
    return [x.strip() for x in out.split(",") if x.strip()] if out and not out.startswith("ERR") else []

def get_launch_agents():
    """Find launch agents/daemons, flag suspicious ones."""
    locations = [
        ("/Library/LaunchAgents", "system-agent"),
        ("/Library/LaunchDaemons", "system-daemon"),
        (str(HOME / "Library/LaunchAgents"), "user-agent"),
    ]
    items = []
    for loc, kind in locations:
        p = Path(loc)
        if not p.exists():
            continue
        for f in p.glob("*.plist"):
            try:
                content = f.read_text(errors="ignore")
            except Exception:
                content = ""
            label = ""
            program = ""
            m = re.search(r"<key>Label</key>\s*<string>([^<]+)</string>", content)
            if m: label = m.group(1)
            m = re.search(r"<key>Program(?:Arguments)?</key>\s*<string>([^<]+)</string>", content)
            if m: program = m.group(1)
            else:
                m = re.search(r"<key>ProgramArguments</key>\s*<array>\s*<string>([^<]+)</string>", content)
                if m: program = m.group(1)

            # Suspicion checks
            sus = []
            if program:
                if any(s in program for s in ["/tmp/", "/var/tmp/", "/private/tmp/"]):
                    sus.append("runs from /tmp")
                if program and not Path(program).exists():
                    sus.append("binary missing")
                if "/Users/" in program and "/Library/" not in program:
                    sus.append("runs from user home")
            if label:
                if re.search(r"^[a-z0-9]{20,}$", label, re.I):
                    sus.append("random-looking label")

            mtime = f.stat().st_mtime
            recent = (time.time() - mtime) < 14 * 86400
            # The dashboard's own auto-start agent is benign by definition.
            # Strip its suspicious flags so neither the Security Audit nor the
            # Launch Agents table shows it as a threat.
            label_v = label or f.stem
            if "aby.macoptimizer" in label_v.lower() or "mac_optimizer" in str(f).lower():
                sus = []
                is_self = True
            else:
                is_self = False
            items.append({
                "path": str(f),
                "kind": kind,
                "label": label_v,
                "program": program,
                "modified": time.strftime("%Y-%m-%d", time.localtime(mtime)),
                "recent": recent,
                "suspicious": sus,
                "is_self": is_self,
            })
    items.sort(key=lambda x: (not x["suspicious"], not x["recent"], x["modified"]), reverse=False)
    return items

def codesign_check(path):
    """Return signing status of an executable. Quick & cached."""
    if not path or not Path(path).exists():
        return "missing"
    out = subprocess.run(["codesign", "-dv", "--verbose=2", path],
                         capture_output=True, text=True, timeout=5)
    err = (out.stderr or "") + (out.stdout or "")
    if "code object is not signed" in err.lower():
        return "unsigned"
    if "Authority=Apple" in err or "Apple Root CA" in err:
        return "apple"
    if "Authority=Developer ID" in err:
        return "developer-id"
    if "Authority=" in err:
        return "signed"
    return "unknown"

_SIG_CACHE = {}
def codesign_cached(path):
    if path not in _SIG_CACHE:
        try:
            _SIG_CACHE[path] = codesign_check(path)
        except Exception:
            _SIG_CACHE[path] = "error"
    return _SIG_CACHE[path]

def get_unsigned_processes():
    """Top processes whose binary is not Apple/Developer-ID signed."""
    procs = get_processes()
    self_pid = os.getpid()
    flagged = []
    for p in procs[:25]:
        # Don't flag the dashboard itself — it's a python3 script the user
        # just launched, of course it's "unsigned". Same logic as Process
        # Inspector. Without this filter the panel always shows itself.
        if p.get("pid") == self_pid:
            continue
        sig = codesign_cached(p["path"])
        if sig in ("unsigned", "missing", "unknown"):
            # Skip kernel/short paths and common false positives
            if p["path"] in ("kernel_task",) or not p["path"].startswith("/"):
                continue
            flagged.append({**p, "signature": sig})
    return flagged

def get_network_connections():
    """Established outbound TCP connections grouped by process."""
    out = sh("lsof -nP -iTCP -sTCP:ESTABLISHED", timeout=10)
    by_proc = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        proc, pid = parts[0], parts[1]
        remote = parts[8].split("->")[-1] if "->" in parts[8] else ""
        k = f"{proc} ({pid})"
        if k not in by_proc:
            by_proc[k] = {"proc": proc, "pid": pid, "conns": []}
        if remote and remote not in by_proc[k]["conns"]:
            by_proc[k]["conns"].append(remote)
    return [{"proc": v["proc"], "pid": v["pid"], "count": len(v["conns"]),
             "samples": v["conns"][:3]}
            for v in sorted(by_proc.values(), key=lambda x: -len(x["conns"]))[:20]]

def get_kernel_extensions():
    """Third-party kernel extensions (kexts) — common slowdown vector."""
    out = sh("kmutil showloaded --list-only --variant-suffix release 2>/dev/null", timeout=10)
    if not out or "ERR" in out:
        out = sh("kextstat -l 2>/dev/null", timeout=10)
    third_party = []
    for line in out.splitlines():
        if not line.strip() or "com.apple" in line:
            continue
        parts = line.split()
        if len(parts) >= 6:
            third_party.append(line.strip()[:200])
    return third_party[:30]

def get_hosts_file_check():
    """Inspect /etc/hosts for unusual entries (malware redirect indicator)."""
    try:
        content = Path("/etc/hosts").read_text()
    except Exception:
        return {"ok": False, "msg": "Could not read /etc/hosts", "entries": []}
    sus = []
    normal = []
    for line in content.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        normal.append(s)
        # Suspicious: redirecting common domains to non-localhost
        if any(d in s for d in ["google.com", "apple.com", "facebook.com", "icloud.com", "github.com", "anthropic.com"]):
            if not s.startswith(("127.", "::1", "0.0.0.0")):
                sus.append(s)
    return {"total_entries": len(normal), "suspicious": sus, "samples": normal[:10]}

def get_cron_jobs():
    """User crontab + system /etc/cron* + /etc/periodic."""
    user_cron = sh("crontab -l 2>/dev/null", timeout=5)
    items = []
    if user_cron and "no crontab" not in user_cron.lower() and not user_cron.startswith("ERR"):
        for line in user_cron.splitlines():
            if line.strip() and not line.startswith("#"):
                items.append({"src": "user crontab", "entry": line.strip()})
    for d in ["/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/periodic/daily",
              "/etc/periodic/weekly", "/etc/periodic/monthly"]:
        p = Path(d)
        if p.exists():
            for f in p.iterdir():
                if f.name not in ("999.local", ".DS_Store"):
                    items.append({"src": d, "entry": f.name})
    return items

# Well-known Google component extension IDs whose folders have no _locales
# directory because the real name lives inside the Chrome binary itself.
# Without this lookup, these extensions show up as 32-character random IDs
# in the dashboard, which is exactly the noise Aby flagged in the screenshot.
_KNOWN_EXT_IDS = {
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Google Docs Offline",
    "knipolnnllmklapflnccelgolnpehhpl": "Google Input Tools",
    "lpcaedmchfhocbbapmcbpinfpgnhiddi": "Google Hangouts",
    "nmmhkkegccagdldgiimedpiccmgmieda": "Chrome Web Store Payments",
    "blkboeaihdlecgdjjgkcabbacndbjibc": "Google Voice Search (built-in)",
    "bfbmjmiodbnnpllbbbfblcplfjjepjdn": "Google Network Speech",
    "mhjfbmdgcfjbbpaeojofohoefgiehjai": "Chrome PDF Viewer",
    "neajdppkdcdipfabeoofebfddakdcjhd": "Google Network Speech",
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm": "Chromecast",
    "aohghmighlieiainnegkcijnfilokake": "Google Docs",
    "aapocclcgogkmnckokdopfmhonfmgoek": "Google Slides",
    "felcaaldnbdncclmgdcncolpebgiejap": "Google Sheets",
    "apdfllckaahabafndbhieahigkjlhalf": "Google Drive",
}

def _resolve_ext_msg_name(version_dir, raw_name, default_locale):
    """Chrome stores extension names as `__MSG_appName__` placeholders that get
    resolved at runtime from `_locales/<locale>/messages.json`. Without this
    resolution the dashboard would display the placeholder as the name."""
    if not raw_name or not (raw_name.startswith("__MSG_") and raw_name.endswith("__")):
        return raw_name or ""
    key = raw_name[6:-2]
    locales_dir = version_dir / "_locales"
    if not locales_dir.exists():
        return raw_name
    tried = []
    candidates = [default_locale, "en", "en_US", "en_GB"]
    if locales_dir.exists():
        try:
            for d in locales_dir.iterdir():
                if d.is_dir():
                    candidates.append(d.name)
        except Exception:
            pass
    for loc in candidates:
        if not loc or loc in tried:
            continue
        tried.append(loc)
        msg_file = locales_dir / loc / "messages.json"
        if not msg_file.exists():
            continue
        try:
            msgs = json.loads(msg_file.read_text(errors="ignore"))
        except Exception:
            continue
        # JSON message keys are case-insensitive per Chrome i18n spec
        for k, v in msgs.items():
            if k.lower() == key.lower() and isinstance(v, dict) and v.get("message"):
                return v["message"]
    return raw_name

def get_browser_extensions():
    """Enumerate Chrome/Brave/Edge (all profiles) and Safari extensions, with
    real names resolved from manifest + _locales. Each entry includes the
    on-disk path so the UI can offer a Remove button."""
    out = []
    chromium_browsers = [
        ("Chrome", HOME / "Library/Application Support/Google/Chrome"),
        ("Brave",  HOME / "Library/Application Support/BraveSoftware/Brave-Browser"),
        ("Edge",   HOME / "Library/Application Support/Microsoft Edge"),
    ]
    for browser_name, root in chromium_browsers:
        if not root.exists():
            continue
        try:
            profiles = [c for c in root.iterdir()
                        if c.is_dir() and (c / "Extensions").is_dir()]
        except Exception:
            profiles = []
        for profile in profiles:
            ext_dir = profile / "Extensions"
            try:
                ids = [d for d in ext_dir.iterdir() if d.is_dir()]
            except Exception:
                continue
            for ext_id_dir in ids:
                try:
                    versions = sorted([v for v in ext_id_dir.iterdir() if v.is_dir()],
                                      key=lambda v: v.name)
                except Exception:
                    versions = []
                if not versions:
                    continue
                version_dir = versions[-1]
                manifest = version_dir / "manifest.json"
                name = _KNOWN_EXT_IDS.get(ext_id_dir.name, ext_id_dir.name)
                perms_count = 0
                risky = False
                if manifest.exists():
                    try:
                        m = json.loads(manifest.read_text(errors="ignore"))
                        raw = m.get("name") or ""
                        resolved = _resolve_ext_msg_name(version_dir, raw, m.get("default_locale"))
                        if resolved and not resolved.startswith("__MSG_"):
                            name = resolved
                        all_perms = ((m.get("permissions") or [])
                                     + (m.get("host_permissions") or [])
                                     + (m.get("optional_permissions") or []))
                        perms_count = len(all_perms)
                        risky_terms = ("<all_urls>", "tabs", "cookies",
                                       "webRequest", "history", "debugger",
                                       "*://*/*")
                        risky = any(any(t in str(p) for t in risky_terms)
                                    for p in all_perms)
                    except Exception:
                        pass
                try:
                    last_mod = max(v.stat().st_mtime for v in versions)
                except Exception:
                    last_mod = 0
                profile_label = "" if profile.name == "Default" else f" ({profile.name})"
                out.append({
                    "browser": browser_name + profile_label,
                    "id": ext_id_dir.name,
                    "name": name,
                    "perms": perms_count,
                    "risky": risky,
                    "path": str(ext_id_dir),
                    "last_modified": time.strftime("%Y-%m-%d", time.localtime(last_mod)) if last_mod else "?",
                })
    safari_ext = HOME / "Library/Safari/Extensions"
    if safari_ext.exists():
        for f in safari_ext.glob("*.safariextz"):
            out.append({"browser": "Safari", "id": f.name, "name": f.stem,
                        "perms": 0, "risky": False, "path": str(f),
                        "last_modified": "?"})
    # Risky / high-permission extensions float to the top so the user can see
    # the things actually worth reviewing without scrolling.
    out.sort(key=lambda x: (not x["risky"], -x["perms"], x["name"].lower()))
    return out

def get_profiles():
    """Configuration profiles installed (often used by MDM/malware)."""
    out = sh("profiles list -all 2>/dev/null", timeout=10)
    if "There are no" in out or not out:
        return []
    profiles = []
    for line in out.splitlines():
        line = line.strip()
        if line and "attribute:" in line.lower():
            profiles.append(line)
    return profiles[:20]

def get_security_audit():
    findings = []
    # 1. mds_stores reindexing
    procs = sh("ps -Ao pcpu,comm | grep mds_stores | grep -v grep")
    if procs:
        for line in procs.splitlines():
            parts = line.split(None, 1)
            try:
                if float(parts[0]) > 30:
                    findings.append({"sev": "info",
                                     "msg": f"Spotlight reindexing ({parts[0]}% CPU) — usually finishes within an hour",
                                     "fix": "Wait, or: sudo mdutil -i off /  then  sudo mdutil -i on /"})
            except Exception:
                pass

    # 2. Unsigned/suspicious launch agents.
    # Skip the dashboard's own auto-start agent — its Program path is under
    # the user's home, which would otherwise trip the "runs from user home"
    # rule. Same self-filter as Process Inspector and Threat Scan.
    agents = get_launch_agents()
    for a in agents:
        if not a["suspicious"]:
            continue
        label_low = (a.get("label") or "").lower()
        path_low = (a.get("path") or "").lower()
        if "aby.macoptimizer" in label_low or "mac_optimizer" in path_low:
            continue
        findings.append({"sev": "warn",
                         "msg": f"Suspicious launch agent: {a['label']} ({', '.join(a['suspicious'])})",
                         "fix": f"Review: {a['path']}"})

    # 3. Processes from suspicious paths
    ps_out = sh("ps -Ao pid,user,comm")
    for line in ps_out.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        path = parts[2]
        if path.startswith("/tmp/") or path.startswith("/var/tmp/") or path.startswith("/private/tmp/"):
            findings.append({"sev": "critical",
                             "msg": f"Process running from temp dir: {path} (PID {parts[0]})",
                             "fix": f"Investigate immediately. kill {parts[0]} if confirmed bad."})

    # 4. Login items
    li = get_login_items()
    for item in li:
        if any(c in item.lower() for c in [".mp4", ".mov", ".jpg", ".png", "downloader", "helper"]):
            if "google" not in item.lower() and "samsung dex" not in item.lower():
                findings.append({"sev": "warn",
                                 "msg": f"Unusual login item: {item}",
                                 "fix": "System Settings → General → Login Items, or use Remove button."})

    # 5. XProtect status
    xp = sh("system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A1 XProtect | tail -2")
    return {"findings": findings, "login_items": li, "launch_agents": agents}

# ─────────────────────────────────────────────────────────────────────────────
# Actions (destructive — gated by UI confirmation)
# ─────────────────────────────────────────────────────────────────────────────
def act_kill(pid):
    try:
        os.kill(int(pid), 15)  # SIGTERM
        return {"ok": True, "msg": f"Sent SIGTERM to PID {pid}"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def act_trash(path):
    p = Path(path)
    if not p.exists():
        return {"ok": False, "msg": "Path not found"}
    # System-protected paths — refuse anything UNDER these.
    forbidden = ["/System/", "/usr/", "/bin/", "/sbin/", "/private/var/db/"]
    sp = str(p.resolve())
    if any(sp.startswith(f) for f in forbidden):
        return {"ok": False, "msg": "Refused: system-protected path"}

    # Defense-in-depth: refuse to trash the user's HOME or any top-level
    # data folder under it. The current UI cannot pass these (it only finds
    # `.app` bundles in /Applications and ~/Applications), but this catches
    # any future bug or hand-crafted API call before it deletes user data.
    home_str = str(HOME)
    forbidden_exact = {
        home_str,
        str(HOME / "Cursor"),
        str(HOME / "Documents"),
        str(HOME / "Desktop"),
        str(HOME / "Downloads"),
        str(HOME / "Pictures"),
        str(HOME / "Movies"),
        str(HOME / "Music"),
        str(HOME / "Public"),
        str(HOME / "Library"),
        str(HOME / "Applications"),
        "/Applications",
    }
    if sp in forbidden_exact:
        return {"ok": False, "msg": "Refused: top-level user/system folder"}

    # Also refuse to trash anything that isn't an .app bundle if it lives
    # outside the standard app locations. The Trash button is wired up
    # exclusively for app uninstalls — anything else is a bug.
    in_app_dir = sp.startswith("/Applications/") or sp.startswith(str(HOME / "Applications") + "/")
    if not (sp.endswith(".app") and in_app_dir):
        return {"ok": False, "msg": "Refused: only .app bundles in /Applications can be trashed via this button"}

    # First try a plain move to ~/.Trash — works for anything under $HOME
    try:
        TRASH.mkdir(exist_ok=True)
        ts = int(time.time())
        dest = TRASH / f"{p.name}__{ts}"
        shutil.move(str(p), str(dest))
        return {"ok": True, "msg": f"Moved to Trash: {dest.name}"}
    except PermissionError:
        pass
    except Exception as e:
        return {"ok": False, "msg": str(e)}

    # Fallback: move via `mv` inside an admin shell script. This gives the
    # user the standard macOS authorisation dialog and works for paths
    # under /Applications without needing Finder automation permission.
    TRASH.mkdir(exist_ok=True)
    ts = int(time.time())
    dest = TRASH / f"{p.name}__{ts}"
    # Escape any double quotes for AppleScript's "do shell script" string,
    # and escape backslashes too (AppleScript reads the string before the shell does).
    def _esc(s):
        return s.replace("\\", "\\\\").replace('"', '\\"')
    inner = f'mv "{_esc(sp)}" "{_esc(str(dest))}"'
    script = f'do shell script "{_esc(inner)}" with administrator privileges'
    r = subprocess.run(["osascript", "-e", script],
                       capture_output=True, text=True, timeout=120)
    if r.returncode == 0:
        return {"ok": True, "msg": f"Moved to Trash (with admin): {p.name}"}
    err = (r.stderr or r.stdout or "").strip()
    if "User canceled" in err or "-128" in err:
        return {"ok": False, "msg": "Cancelled in password dialog"}
    return {"ok": False, "msg": f"Move failed: {err[:160]}"}


def act_remove_launch_agent(path):
    """Unload and delete a launch agent/daemon plist. Uses admin auth for /Library."""
    p = Path(path)
    if not p.exists():
        # If the file is already gone but you want to clean up, that's still fine
        return {"ok": True, "msg": "Already removed"}
    if not str(p).endswith(".plist"):
        return {"ok": False, "msg": "Refused: not a .plist file"}
    sp = str(p.resolve())
    if not (sp.startswith("/Library/Launch") or
            sp.startswith(str(HOME / "Library/LaunchAgents"))):
        return {"ok": False, "msg": "Refused: not in a Launch* directory"}

    needs_sudo = sp.startswith("/Library/")
    # Try to unload first (best effort — ignore errors)
    if needs_sudo:
        # Unload + delete in a single privileged shell so user only auths once.
        # The path goes through TWO parsers: AppleScript reads the outer "..." string,
        # then the shell parses the resulting command. shlex.quote handles the shell
        # layer; _esc handles the AppleScript layer. Skipping either causes -2740.
        def _esc(s):
            return s.replace("\\", "\\\\").replace('"', '\\"')
        qp = shlex.quote(sp)
        inner = f'launchctl unload {qp} 2>/dev/null; rm {qp}'
        script = f'do shell script "{_esc(inner)}" with administrator privileges'
        r = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            return {"ok": True, "msg": f"Unloaded and removed {p.name}"}
        err = (r.stderr or r.stdout or "").strip()
        if "User canceled" in err or "-128" in err:
            return {"ok": False, "msg": "Cancelled in password dialog"}
        return {"ok": False, "msg": f"Failed: {err[:160]}"}
    else:
        sh(f'launchctl unload "{sp}" 2>/dev/null', timeout=10)
        try:
            p.unlink()
            return {"ok": True, "msg": f"Unloaded and removed {p.name}"}
        except Exception as e:
            return {"ok": False, "msg": str(e)}

# Allowed roots for the Remove Extension button. Anything outside these is
# rejected even if the path looks plausible.
_EXTENSION_ROOTS = [
    HOME / "Library/Application Support/Google/Chrome",
    HOME / "Library/Application Support/BraveSoftware/Brave-Browser",
    HOME / "Library/Application Support/Microsoft Edge",
    HOME / "Library/Safari/Extensions",
]

def act_remove_extension(path):
    """Delete a browser extension folder. Validates the path is under a known
    browser data directory and is *inside* an `Extensions/<id>` folder (so we
    can never wipe the parent profile). Chrome should be quit first, otherwise
    it will recreate the directory from its sync state on next launch."""
    if not path or not isinstance(path, str):
        return {"ok": False, "msg": "No path given"}
    try:
        sp = str(Path(path).resolve())
    except Exception:
        return {"ok": False, "msg": "Invalid path"}
    in_root = any(sp.startswith(str(r) + "/") for r in _EXTENSION_ROOTS)
    if not in_root:
        return {"ok": False, "msg": "Refused: not under a browser extension directory"}
    # Must look like an extension folder, not a profile or root
    if not (("/Extensions/" in sp and sp.count("/") >
             len(str(_EXTENSION_ROOTS[0])) // 1)
            or sp.endswith(".safariextz")):
        return {"ok": False, "msg": "Refused: not an extension folder"}
    p = Path(sp)
    if not p.exists():
        return {"ok": True, "msg": "Already removed"}
    try:
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        return {"ok": True, "msg": f"Removed extension. Quit & reopen the browser for the change to take effect."}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def act_reveal_path(path):
    """Show a file/folder in Finder via `open -R`. Read-only — no deletion.
    Restricted to the same roots that the Stale Files and Extensions panels
    surface, so this can never be used to probe arbitrary system locations."""
    if not path or not isinstance(path, str):
        return {"ok": False, "msg": "No path given"}
    try:
        sp = str(Path(path).resolve())
    except Exception:
        return {"ok": False, "msg": "Invalid path"}
    allowed = [str(r) + "/" for r in _STALE_FILE_ROOTS] \
            + [str(r) + "/" for r in _EXTENSION_ROOTS] \
            + ["/Applications/", str(HOME / "Applications") + "/"]
    if not any(sp.startswith(pref) for pref in allowed):
        return {"ok": False, "msg": "Refused: path not in an allowed root"}
    if not Path(sp).exists():
        return {"ok": False, "msg": "Path no longer exists"}
    try:
        subprocess.Popen(["open", "-R", sp])
        return {"ok": True, "msg": f"Revealing {Path(sp).name} in Finder"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def act_trash_files(paths):
    """Move a list of stale files (from Downloads/Documents/Desktop only) to
    ~/.Trash. Each path is re-validated against the allowed roots before being
    touched, so a hand-crafted API call can never escape into the wider home
    directory or system locations."""
    if not paths:
        return {"ok": True, "msg": "Nothing to trash"}
    allowed_prefixes = [str(r) + "/" for r in _STALE_FILE_ROOTS]
    TRASH.mkdir(exist_ok=True)
    moved = 0
    rejected = 0
    failed = 0
    for raw in paths:
        if not isinstance(raw, str):
            rejected += 1; continue
        try:
            sp = str(Path(raw).resolve())
        except Exception:
            rejected += 1; continue
        if not any(sp.startswith(pref) for pref in allowed_prefixes):
            rejected += 1; continue
        if "mac_optimizer" in sp.lower():
            rejected += 1; continue
        p = Path(sp)
        if not p.exists():
            rejected += 1; continue
        try:
            ts = int(time.time())
            dest = TRASH / f"{p.name}__{ts}"
            shutil.move(str(p), str(dest))
            moved += 1
        except Exception:
            failed += 1
    parts = [f"Trashed {moved} file{'s' if moved != 1 else ''}"]
    if rejected: parts.append(f"{rejected} rejected")
    if failed:   parts.append(f"{failed} failed")
    # Invalidate the stale-files cache so the next /api/stale-files call
    # doesn't return entries we just moved to Trash.
    if moved:
        _STALE_CACHE["data"] = None
        _STALE_CACHE["ts"] = 0
    return {"ok": moved > 0, "msg": " · ".join(parts), "removed": moved}

def act_trash_one_duplicate(path):
    """Move a single duplicate-file copy to ~/.Trash. Unlike act_trash_files,
    this validates against the duplicate-scan roots (which include ~/Movies
    and ~/Music), not the stale-files roots. Re-validates every time — a
    hand-crafted API call can never escape into /Library or system dirs."""
    if not path or not isinstance(path, str):
        return {"ok": False, "msg": "No path given"}
    try:
        sp = str(Path(path).resolve())
    except Exception:
        return {"ok": False, "msg": "Invalid path"}
    allowed_prefixes = [str(r) + "/" for r in _DUP_ROOTS]
    if not any(sp.startswith(pref) for pref in allowed_prefixes):
        return {"ok": False, "msg": "Refused: path not in an allowed root"}
    if "mac_optimizer" in sp.lower():
        return {"ok": False, "msg": "Refused: optimizer file"}
    p = Path(sp)
    if not p.exists():
        return {"ok": False, "msg": "Path no longer exists"}
    TRASH.mkdir(exist_ok=True)
    try:
        ts = int(time.time())
        dest = TRASH / f"{p.name}__{ts}"
        shutil.move(str(p), str(dest))
    except Exception as e:
        return {"ok": False, "msg": str(e)}
    # Invalidate duplicates cache so it reflects the move.
    _DUP_CACHE["data"] = None
    _DUP_CACHE["ts"] = 0
    return {"ok": True, "msg": f"Trashed {p.name}", "removed": 1}

# ─────────────────────────────────────────────────────────────────────────────
# Vendor cleanup — find and bulk-remove every trace of an uninstalled app.
#
# This is the "remove Adobe / TeamViewer / ExpressVPN" feature. A novice user
# can't be expected to know that uninstalling Adobe leaves behind 13+ folders
# across /Library, ~/Library/Application Support, caches, logs, prefs, and
# privileged helpers. This module finds them all and removes them in one
# privileged shell call (one password prompt).
#
# Safety model:
#   1. Vendor token must match _VENDOR_RX (alnum + dot/dash, 2-40 chars)
#   2. Vendor token cannot be in _VENDOR_DENYLIST (apple, the optimizer itself)
#   3. Sweeps only happen inside _SWEEP_ROOTS — anything resolving outside
#      those roots is rejected even if matched
#   4. The sweep roots themselves cannot be deleted (only their children)
#   5. Anything containing "aby.macoptimizer" or "mac_optimizer" is rejected
# ─────────────────────────────────────────────────────────────────────────────

# Vendor tokens that must never be wiped, even if asked.
_VENDOR_DENYLIST = {
    "apple", "com.apple", "system", "macosx", "darwin",
    "aby.macoptimizer", "aby", "macoptimizer",
}

# Top-level directories a sweep is allowed to touch. The sweep walks each
# root's *immediate children* and matches them against the vendor token.
# It never recurses into them — that could match unrelated nested folders.
def _sweep_roots():
    return [
        "/Applications",
        "/Applications/Utilities",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/Library/PrivilegedHelperTools",
        "/Library/Application Support",
        "/Library/Preferences",
        "/Library/Logs",
        str(HOME / "Library/Application Support"),
        str(HOME / "Library/Caches"),
        str(HOME / "Library/Logs"),
        str(HOME / "Library/Preferences"),
        str(HOME / "Library/LaunchAgents"),
    ]

_VENDOR_RX = re.compile(r"^[a-zA-Z0-9._-]{2,40}$")

def _is_safe_to_delete(path_str):
    """Return True only if `path_str` is safely inside a sweep root and not
    one of the sweep roots themselves. The single safety gate for all
    bulk delete operations."""
    roots = _sweep_roots()
    if path_str in roots:
        return False  # never delete a sweep root itself
    # Block the dashboard's own files
    low = path_str.lower()
    if "aby.macoptimizer" in low or "mac_optimizer" in low:
        return False
    # Must be strictly inside one of the roots
    for root in roots:
        prefix = root.rstrip("/") + "/"
        if path_str.startswith(prefix):
            return True
    return False

def get_vendor_footprint(vendor):
    """Find every file/folder under the sweep roots whose name matches `vendor`
    (case-insensitive substring). Returns the list with sizes for preview."""
    if not vendor or not _VENDOR_RX.match(vendor):
        return {"vendor": vendor, "items": [], "total_bytes": 0,
                "total_human": "0 B", "count": 0, "error": "invalid vendor token"}
    if vendor.lower() in _VENDOR_DENYLIST:
        return {"vendor": vendor, "items": [], "total_bytes": 0,
                "total_human": "0 B", "count": 0, "error": "vendor is protected"}

    needle = vendor.lower()
    items = []
    seen = set()
    for root in _sweep_roots():
        rp = Path(root)
        if not rp.exists():
            continue
        try:
            children = list(rp.iterdir())
        except (PermissionError, OSError):
            continue
        for child in children:
            if needle not in child.name.lower():
                continue
            sp = str(child)
            if not _is_safe_to_delete(sp):
                continue
            if sp in seen:
                continue
            seen.add(sp)
            size = du_path(child, timeout=15)
            if size < 0:
                size = 0
            items.append({
                "path": sp,
                "name": child.name,
                "size": size,
                "size_human": human(size),
                "kind": "dir" if child.is_dir() else "file",
                "root": root,
            })
    items.sort(key=lambda x: x["size"], reverse=True)
    total = sum(i["size"] for i in items)
    return {
        "vendor": vendor,
        "items": items,
        "total_bytes": total,
        "total_human": human(total),
        "count": len(items),
    }

def act_remove_paths(paths):
    """Bulk-delete a list of paths after re-validating each one against the
    safety gate. Splits sudo and user paths so we only show the password
    prompt when actually needed."""
    if not paths:
        return {"ok": True, "msg": "Nothing to remove", "removed": 0, "rejected": 0}

    validated = []
    rejected = []
    for raw in paths:
        if not isinstance(raw, str):
            rejected.append(str(raw)); continue
        try:
            sp = str(Path(raw).resolve(strict=False))
        except Exception:
            rejected.append(raw); continue
        if not _is_safe_to_delete(sp):
            rejected.append(raw); continue
        # Path must actually exist (resolve doesn't require existence)
        if not Path(sp).exists() and not Path(sp).is_symlink():
            rejected.append(raw); continue
        validated.append(sp)

    if not validated:
        return {"ok": False, "msg": f"All {len(paths)} paths rejected by safety check"}

    # Best-effort: unload any launch plists in the list before deleting
    for p in validated:
        if p.endswith(".plist") and "/Launch" in p:
            sh(f'launchctl unload {shlex.quote(p)} 2>/dev/null', timeout=5)

    home_str = str(HOME)
    needs_sudo = [p for p in validated if not p.startswith(home_str + "/")]
    user_paths = [p for p in validated if p.startswith(home_str + "/")]

    sudo_removed = 0
    sudo_err = ""
    if needs_sudo:
        rm_cmd = "; ".join(f"rm -rf {shlex.quote(p)}" for p in needs_sudo)
        def _esc(s):
            return s.replace("\\", "\\\\").replace('"', '\\"')
        script = f'do shell script "{_esc(rm_cmd)}" with administrator privileges'
        r = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, timeout=180)
        if r.returncode == 0:
            sudo_removed = len(needs_sudo)
        else:
            sudo_err = (r.stderr or r.stdout or "").strip()
            if "User canceled" in sudo_err or "-128" in sudo_err:
                return {"ok": False, "msg": "Cancelled in password dialog"}
            return {"ok": False, "msg": f"Sudo step failed: {sudo_err[:160]}"}

    user_removed = 0
    user_failed = 0
    for p in user_paths:
        try:
            rp = Path(p)
            if rp.is_dir() and not rp.is_symlink():
                shutil.rmtree(rp, ignore_errors=True)
            elif rp.exists() or rp.is_symlink():
                rp.unlink()
            user_removed += 1
        except Exception:
            user_failed += 1

    total = sudo_removed + user_removed
    parts = [f"Removed {total} item{'s' if total != 1 else ''}"]
    if rejected:
        parts.append(f"{len(rejected)} rejected")
    if user_failed:
        parts.append(f"{user_failed} failed")
    return {"ok": True, "msg": " · ".join(parts), "removed": total,
            "rejected": len(rejected), "failed": user_failed}

def act_remove_vendor(vendor):
    """Public action: preview-then-delete a vendor's entire footprint."""
    fp = get_vendor_footprint(vendor)
    if fp.get("error"):
        return {"ok": False, "msg": fp["error"]}
    if not fp["items"]:
        return {"ok": True, "msg": f"Nothing matching '{vendor}' to remove"}
    result = act_remove_paths([i["path"] for i in fp["items"]])
    if result.get("ok"):
        result["msg"] = f"{vendor}: {result['msg']} ({fp['total_human']} reclaimed)"
        result["bytes_freed"] = fp["total_bytes"]
    return result

def detect_dead_vendors():
    """Find vendors whose launch agents reference a missing binary, and
    bundle them up as suggested vendor cleanups. This is what makes the
    'binary missing' tag actionable: instead of removing one orphan plist,
    we offer to sweep the entire vendor."""
    agents = get_launch_agents()
    by_vendor = {}
    for a in agents:
        if "binary missing" not in a.get("suspicious", []):
            continue
        label = a.get("label", "") or ""
        # Extract vendor token from labels like com.adobe.GC.Invoker-1.0
        m = re.match(r"^(?:com|org|net|io|co)\.([a-zA-Z0-9_-]{2,40})\.", label)
        if not m:
            continue
        token = m.group(1).lower()
        if token in _VENDOR_DENYLIST:
            continue
        by_vendor.setdefault(token, []).append(a)

    out = []
    for token, plists in by_vendor.items():
        fp = get_vendor_footprint(token)
        if not fp["items"]:
            # No broader footprint — but the orphan plists themselves are
            # still worth surfacing. Offer to remove just those.
            out.append({
                "vendor": token,
                "plist_count": len(plists),
                "item_count": len(plists),
                "total_bytes": 0,
                "total_human": "0 B",
                "preview": [a["path"] for a in plists[:6]],
                "plists_only": True,
            })
            continue
        out.append({
            "vendor": token,
            "plist_count": len(plists),
            "item_count": fp["count"],
            "total_bytes": fp["total_bytes"],
            "total_human": fp["total_human"],
            "preview": [i["path"] for i in fp["items"][:6]],
            "plists_only": False,
        })
    out.sort(key=lambda x: (-x["total_bytes"], -x["plist_count"]))
    return out

def get_orphan_app_support():
    """List Application Support folders whose owning app is gone AND which
    haven't been touched recently. False positives are expensive here — if
    we flag something the user actively uses, they could lose extension data,
    chat history, IDE settings, etc. So we combine multiple signals before
    surfacing anything: no matching installed app, not modified in the last
    90 days, not a running process, not Apple-owned."""
    # 1. Build a set of installed app tokens across every common location
    installed = set()
    for apps_dir in (Path("/Applications"), Path("/Applications/Utilities"),
                     Path("/System/Applications"), Path("/System/Applications/Utilities"),
                     HOME / "Applications"):
        if not apps_dir.exists():
            continue
        try:
            for child in apps_dir.iterdir():
                t = child.name.replace(".app", "").replace(" ", "").lower()
                if len(t) >= 3:
                    installed.add(t)
        except (PermissionError, OSError):
            continue

    # 2. Also collect names of currently-running processes — if a folder name
    # matches something that's running, the folder is in use even if the .app
    # is in some non-standard location.
    running = set()
    try:
        ps_out = sh("ps -Axo comm")
        for line in ps_out.splitlines()[1:]:
            name = Path(line.strip()).name.replace(".app", "").replace(" ", "").lower()
            if len(name) >= 3:
                running.add(name)
    except Exception:
        pass

    # 3. Folders we should never flag regardless of match status. Apple's
    # /Library/Application Support is full of these.
    hardcoded_skip = {
        "apple", "appstore", "applepay", "audio", "callhistorydb",
        "captivenetworkassistant", "crashreporter", "icdd", "instruments",
        "iphone simulator", "knowledge", "mobiledevices", "mobilesync",
        "photolibraryd", "screen sharing", "siri", "spotlight",
        "softwareupdate", "icloud", "syncservices", "coreparsec",
        "applemobiledevice", "betaaccessutility", "accessibility",
        "appleaccount", "wallpaper", "calendar", "fileprovider",
        "languagemodeling", "imagecapture", "captureone",  # photo workflow
    }

    # 4. Recency cutoff: if it was touched in the last 90 days, the user is
    # probably still using it even if we can't find the app.
    recent_cutoff = time.time() - (90 * 86400)

    orphans = []
    seen = set()
    for root in ("/Library/Application Support", str(HOME / "Library/Application Support")):
        rp = Path(root)
        if not rp.exists():
            continue
        try:
            children = list(rp.iterdir())
        except (PermissionError, OSError):
            continue
        for child in children:
            name = child.name
            if name.startswith("."):
                continue
            # Catch every com.apple.* / org.apple.* folder regardless of suffix
            if re.match(r"^(?:com|org)\.apple\.", name, re.I):
                continue
            # Derive a comparable token: strip "com.vendor." prefix
            token = name
            if re.match(r"^(?:com|org|net|io|co)\.[^.]+\.", token):
                token = token.split(".", 2)[-1]
            token_norm = token.replace(" ", "").lower()
            if token_norm in hardcoded_skip:
                continue
            if "aby" in token_norm or "macoptimizer" in token_norm:
                continue
            # Match against installed apps (substring either direction, min 4 chars
            # to avoid spurious 3-char matches like "git" matching "digital")
            matched = any((len(token_norm) >= 4 and token_norm in app)
                          or (len(app) >= 4 and app in token_norm)
                          for app in installed)
            if matched:
                continue
            # Match against running processes too
            if any((len(token_norm) >= 4 and token_norm in r)
                   or (len(r) >= 4 and r in token_norm)
                   for r in running):
                continue
            sp = str(child)
            if sp in seen or not _is_safe_to_delete(sp):
                continue
            seen.add(sp)
            try:
                mtime = child.stat().st_mtime
            except Exception:
                mtime = 0
            # Recency gate: if it was touched in the last 90 days, skip it
            if mtime > recent_cutoff:
                continue
            size = du_path(child, timeout=15)
            if size < 1024 * 1024:  # ignore folders under 1 MB
                continue
            orphans.append({
                "path": sp,
                "name": name,
                "size": size,
                "size_human": human(size),
                "last_modified": time.strftime("%Y-%m-%d", time.localtime(mtime)) if mtime else "?",
                "root": root,
            })
    orphans.sort(key=lambda x: x["size"], reverse=True)
    return orphans[:25]

def act_clean_user_caches():
    target = HOME / "Library/Caches"
    freed = 0
    errors = 0
    if not target.exists():
        return {"ok": False, "msg": "No caches dir"}
    for child in target.iterdir():
        try:
            sz = du_path(child, timeout=30)
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()
            if sz > 0:
                freed += sz
        except Exception:
            errors += 1
    return {"ok": True, "msg": f"Freed {human(freed)} ({errors} skipped)"}

def act_empty_trash():
    if not TRASH.exists():
        return {"ok": True, "msg": "Trash already empty"}
    freed = du_path(TRASH, timeout=120)
    for child in TRASH.iterdir():
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()
        except Exception:
            pass
    return {"ok": True, "msg": f"Freed {human(freed)} from Trash"}

def act_remove_login_item(name):
    out = sh(f'osascript -e \'tell application "System Events" to delete login item "{name}"\'')
    if out.startswith("ERR") or "error" in out.lower():
        return {"ok": False, "msg": out}
    return {"ok": True, "msg": f"Removed login item: {name}"}

# ─────────────────────────────────────────────────────────────────────────────
# System Health Quick-Check (Time Machine snapshots, SW updates, security posture)
# ─────────────────────────────────────────────────────────────────────────────
_TM_SNAPSHOT_RE = re.compile(r"(\d{4}-\d{2}-\d{2}-\d{6})")
_TM_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}-\d{6}$")

def _parse_purgeable():
    """Best-effort: return a human string for purgeable/reclaimable space on /, or None."""
    # Try diskutil apfs list first
    out = sh("diskutil apfs list /", timeout=8)
    if out and not out.startswith("ERR"):
        for line in out.splitlines():
            low = line.lower()
            if "purgeable" in low:
                m = re.search(r"([\d.]+\s*[KMGT]?B)", line)
                if m:
                    return m.group(1).strip()
    # Fallback: df -h / doesn't show purgeable, but try anyway
    return None

def get_tm_snapshots():
    """List Time Machine local snapshots on /. Returns count, optional purgeable
    size, and parsed snapshot dates. Aby's rule: caller hides UI if count==0."""
    out = sh("tmutil listlocalsnapshots /", timeout=10)
    snapshots = []
    if out and not out.startswith("ERR"):
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _TM_SNAPSHOT_RE.search(line)
            if m:
                snapshots.append({"date": m.group(1), "raw": line})
    return {
        "count": len(snapshots),
        "purgeable_human": _parse_purgeable(),
        "snapshots": snapshots,
    }

_SWUPDATE_CACHE = {"data": None, "ts": 0}
_SWUPDATE_CACHE_TTL = 1800  # 30 minutes

def get_software_updates():
    """Parse `softwareupdate -l`. Slow (hits Apple servers) — cached 30 min.
    Severity: contains 'Security' => critical, [Recommended] => warn, else info."""
    now = time.time()
    if _SWUPDATE_CACHE["data"] is not None and (now - _SWUPDATE_CACHE["ts"]) < _SWUPDATE_CACHE_TTL:
        return _SWUPDATE_CACHE["data"]
    out = sh("softwareupdate -l 2>&1", timeout=60)
    items = []
    if out and not out.startswith("ERR"):
        lines = out.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            m = re.match(r"^\s*\*\s*(?:Label:\s*)?(.+?)\s*$", line)
            if m and "No new software" not in line and "Software Update Tool" not in line:
                label = m.group(1).strip()
                title = label
                # Look at next line for Title:
                if i + 1 < len(lines):
                    nxt = lines[i + 1]
                    tm = re.search(r"Title:\s*(.+?)(?:,\s*Version|,\s*Size|$)", nxt)
                    if tm:
                        title = tm.group(1).strip()
                recommended = "[Recommended]" in (lines[i] + (lines[i+1] if i+1 < len(lines) else ""))
                is_security = "security" in title.lower() or "security" in label.lower()
                if is_security:
                    sev = "critical"
                elif recommended:
                    sev = "warn"
                else:
                    sev = "info"
                items.append({"label": label, "title": title, "severity": sev})
            i += 1
    data = {
        "count": len(items),
        "critical_count": sum(1 for x in items if x["severity"] == "critical"),
        "items": items,
    }
    _SWUPDATE_CACHE["data"] = data
    _SWUPDATE_CACHE["ts"] = now
    return data

def _posture_state(val):
    return "on" if val is True else ("off" if val is False else "unknown")

def get_security_posture():
    """Read-only check of five security toggles. Never changes anything."""
    # FileVault
    fv = sh("fdesetup status", timeout=5)
    if fv.startswith("ERR"):
        filevault = "unknown"
    else:
        filevault = _posture_state("FileVault is On" in fv)

    # Gatekeeper
    gk = sh("spctl --status 2>&1", timeout=5)
    if gk.startswith("ERR"):
        gatekeeper = "unknown"
    else:
        gatekeeper = _posture_state("assessments enabled" in gk)

    # SIP
    sipo = sh("csrutil status", timeout=5)
    if sipo.startswith("ERR"):
        sip = "unknown"
    else:
        sip = _posture_state("enabled" in sipo.lower() and "disabled" not in sipo.lower())

    # Firewall (no sudo via defaults read)
    fw_raw = sh("defaults read /Library/Preferences/com.apple.alf globalstate 2>&1", timeout=5)
    firewall = "unknown"
    try:
        fw_int = int(fw_raw.strip())
        firewall = "on" if fw_int >= 1 else "off"
    except Exception:
        # Fallback to socketfilterfw
        fw2 = sh("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1", timeout=5)
        if not fw2.startswith("ERR"):
            if "enabled" in fw2.lower():
                firewall = "on"
            elif "disabled" in fw2.lower():
                firewall = "off"

    # Auto-update
    au_raw = sh("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>&1", timeout=5)
    auto_update = "unknown"
    try:
        auto_update = "on" if int(au_raw.strip()) == 1 else "off"
    except Exception:
        pass

    score = sum(1 for v in (filevault, gatekeeper, sip, firewall, auto_update) if v == "on")
    return {
        "filevault": filevault,
        "gatekeeper": gatekeeper,
        "sip": sip,
        "firewall": firewall,
        "auto_update": auto_update,
        "score": score,
    }

def get_quickcheck():
    return {
        "posture": get_security_posture(),
        "updates": get_software_updates(),
        "snapshots": get_tm_snapshots(),
    }

# NOTE: this function shares the _PERM_SETTINGS_PANES whitelist defined near
# get_permissions_status() above. The two used to define separate dicts which
# silently overwrote each other at module-load time, breaking the FDA button.
def act_open_settings_pane(pane):
    if pane not in _PERM_SETTINGS_PANES:
        return {"ok": False, "msg": f"unknown pane: {pane}"}
    friendly = {"filevault": "FileVault", "gatekeeper": "Gatekeeper",
                "firewall": "Firewall", "auto_update": "Software Update",
                "sw_update": "Software Update"}.get(pane, pane)
    return _open_settings_url(_PERM_SETTINGS_PANES[pane], friendly)

def act_delete_tm_snapshots(dates):
    if not isinstance(dates, list) or not dates:
        return {"ok": False, "msg": "no snapshot dates provided"}
    valid = [d for d in dates if isinstance(d, str) and _TM_DATE_RE.match(d)]
    if not valid:
        return {"ok": False, "msg": "no valid snapshot dates (expected YYYY-MM-DD-HHMMSS)"}
    # Build a single shell script that deletes each one. tmutil deletelocalsnapshots
    # accepts the date portion. Run whole thing under one admin prompt.
    cmds = " && ".join(f"/usr/bin/tmutil deletelocalsnapshots {shlex.quote(d)}" for d in valid)
    script = f'do shell script "{cmds}" with administrator privileges'
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True,
                           text=True, timeout=120)
        if r.returncode == 0:
            return {"ok": True, "msg": f"Deleted {len(valid)} snapshot(s)"}
        return {"ok": False, "msg": (r.stderr or r.stdout or "osascript failed").strip()}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

# ─────────────────────────────────────────────────────────────────────────────
# HTTP server
# ─────────────────────────────────────────────────────────────────────────────
HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Mac Optimizer</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{
  --bg:#0b0e14; --panel:#141923; --panel2:#1b2230; --border:#272f3f;
  --text:#e6edf3; --dim:#8b96a8; --accent:#5eead4; --warn:#fbbf24;
  --bad:#f87171; --good:#4ade80; --link:#60a5fa;
}
*{box-sizing:border-box}
body{margin:0;font:14px -apple-system,BlinkMacSystemFont,sans-serif;
     background:var(--bg);color:var(--text)}
header{padding:18px 24px;border-bottom:1px solid var(--border);
       display:flex;align-items:center;justify-content:space-between;
       background:linear-gradient(180deg,#101521,#0b0e14)}
h1{margin:0;font-size:18px;font-weight:600;letter-spacing:.3px}
h1 span{color:var(--accent)}
.score{font-size:42px;font-weight:700;margin:0 14px}
.score.good{color:var(--good)} .score.warn{color:var(--warn)} .score.bad{color:var(--bad)}
button{background:var(--panel2);color:var(--text);border:1px solid var(--border);
       padding:6px 12px;border-radius:6px;cursor:pointer;font-size:13px;
       transition:all .15s}
button:hover{background:#252d3f;border-color:#3a4456}
button.primary{background:var(--accent);color:#0b0e14;border-color:var(--accent);font-weight:600}
button.danger{background:#3b1a1f;color:var(--bad);border-color:#5c2630}
button.danger:hover{background:#5c2630}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));
      gap:16px;padding:16px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;
      padding:18px;overflow:hidden}
.card h2{margin:0 0 14px;font-size:14px;letter-spacing:.5px;text-transform:uppercase;
         color:var(--dim);font-weight:600;display:flex;justify-content:space-between;align-items:center}
.card h2 .count{background:var(--panel2);padding:2px 8px;border-radius:10px;
                font-size:11px;color:var(--text)}
.metric{display:flex;justify-content:space-between;padding:6px 0;
        border-bottom:1px solid var(--border);font-size:13px}
.metric:last-child{border:0}
.metric .v{color:var(--accent);font-weight:600}
.metric .v.warn{color:var(--warn)} .metric .v.bad{color:var(--bad)} .metric .v.good{color:var(--good)}
.bar{height:6px;background:#1b2230;border-radius:3px;margin-top:4px;overflow:hidden}
.bar-fill{height:100%;background:var(--accent);border-radius:3px;transition:width .3s}
.bar-fill.warn{background:var(--warn)} .bar-fill.bad{background:var(--bad)}
.table-wrap{overflow-x:auto;margin:0 -4px;padding:0 4px}
.table-wrap table{min-width:100%}
table{width:100%;border-collapse:collapse;font-size:12px;table-layout:auto}
.btn-row{display:flex;gap:6px;justify-content:flex-end;flex-wrap:nowrap}
.btn-sm{padding:4px 10px;font-size:11px;white-space:nowrap}
.pager{display:flex;align-items:center;gap:8px;margin-top:10px;
       justify-content:flex-end;font-size:12px;color:var(--dim)}
.pager button{padding:4px 10px;font-size:11px}
.pager button:disabled{opacity:.4;cursor:not-allowed}
.bucket-header{display:flex;justify-content:space-between;align-items:baseline;
               margin:14px 0 6px;padding:6px 10px;border-radius:6px;
               background:linear-gradient(90deg,#3b1a1f 0%,#1b2230 60%);
               border-left:3px solid var(--bad)}
.bucket-header:first-child{margin-top:0}
.bucket-title{font-size:12px;font-weight:700;letter-spacing:.4px;
              text-transform:uppercase;color:var(--bad)}
.bucket-meta{font-size:11px;color:var(--dim)}
.org-row{display:block;margin:10px 0;padding:8px;
         border-radius:6px;background:#0e1218;border-left:3px solid #2a3140}
.org-row.current{border-left-color:var(--good);background:rgba(74,222,128,.04)}
.org-row-label{display:flex;justify-content:space-between;align-items:baseline;
               padding:2px 4px 8px;font-size:13px;font-weight:700;color:var(--fg);
               border-bottom:1px solid #1f2530;margin-bottom:8px}
.org-row-label .sub{font-size:11px;font-weight:400;color:var(--dim)}
.org-row.current .org-row-label{color:var(--good)}
.org-cells{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:6px}
.org-cell{padding:8px;border-radius:5px;background:#161b23;cursor:pointer;
          border:1px solid #1f2530;transition:background .15s, border-color .15s;
          display:flex;flex-direction:column;gap:3px}
.org-cell:hover{background:#1c2230;border-color:#3a4558}
.org-cell.empty{opacity:.35;cursor:default}
.org-cell.empty:hover{background:#161b23;border-color:#1f2530}
.org-cell.active{border-color:var(--warn);background:#1e2330}
.org-cell .cat{font-size:11px;font-weight:600;color:var(--fg)}
.org-cell .cnt{font-size:12px;color:var(--dim)}
.org-cell .sz {font-size:11px;color:var(--warn)}
.org-drill{margin:6px 0 10px;padding:10px;background:#0b0f15;
           border-radius:6px;border:1px solid #1f2530}
.org-drill .drill-head{display:flex;justify-content:space-between;align-items:center;
                       margin-bottom:8px;font-size:12px;color:var(--dim)}
.dup-group{margin:10px 0;padding:10px;background:#0e1218;border-radius:6px;
           border-left:3px solid var(--warn)}
.dup-group .dup-head{display:flex;justify-content:space-between;align-items:center;
                     cursor:pointer;gap:10px;flex-wrap:wrap}
.dup-group .dup-title{font-size:13px;font-weight:600;color:var(--fg)}
.dup-group .dup-meta{font-size:11px;color:var(--dim)}
.dup-group .dup-body{margin-top:10px;display:none}
.dup-group.open .dup-body{display:block}
th{text-align:left;padding:6px 8px;color:var(--dim);font-weight:600;
   border-bottom:1px solid var(--border);text-transform:uppercase;font-size:10px;letter-spacing:.5px}
td{padding:6px 8px;border-bottom:1px solid var(--border)}
tr:last-child td{border:0}
tr:hover{background:var(--panel2)}
.tag{display:inline-block;padding:1px 7px;border-radius:8px;font-size:10px;
     background:var(--panel2);color:var(--dim)}
.tag.bad{background:#3b1a1f;color:var(--bad)}
.tag.warn{background:#3b2f1a;color:var(--warn)}
.tag.good{background:#1a3b2a;color:var(--good)}
.issue{padding:10px;border-radius:6px;margin-bottom:8px;border-left:3px solid var(--dim)}
.issue.critical{border-left-color:var(--bad);background:rgba(248,113,113,.06)}
.issue.warn{border-left-color:var(--warn);background:rgba(251,191,36,.06)}
.issue.info{border-left-color:var(--link);background:rgba(96,165,250,.06)}
.issue .msg{font-weight:600;margin-bottom:4px}
.issue .fix{font-size:12px;color:var(--dim)}
.toast{position:fixed;bottom:20px;right:20px;background:var(--panel);
       border:1px solid var(--border);border-radius:8px;padding:12px 18px;
       box-shadow:0 8px 24px rgba(0,0,0,.4);max-width:380px;z-index:999;
       animation:slide .2s}
.toast.ok{border-left:3px solid var(--good)}
.toast.err{border-left:3px solid var(--bad)}
@keyframes slide{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
.path{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--dim)}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);
         border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
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

/* Process inspector rows */
.proc{display:grid;grid-template-columns:1fr auto auto;gap:10px 14px;
      align-items:center;padding:11px 0;border-bottom:1px solid var(--border)}
.proc:last-child{border:0}
.proc .left{min-width:0}
.proc .friendly{font-weight:600;font-size:13px;display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.proc .raw{font-family:ui-monospace,Menlo,monospace;font-size:10px;color:var(--dim)}
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

/* Onboarding: permissions card, first-run overlay, help tips */
#permissions-card{grid-column:1/-1;border:1px solid #5c2630;background:linear-gradient(135deg,#2a1216,#1a0d10)}
#permissions-card h2{color:var(--bad);text-transform:none;font-size:16px;letter-spacing:0}
#permissions-card .perm-sub{color:var(--dim);font-size:12px;margin-bottom:12px}
.help-tip{display:inline-block;width:15px;height:15px;line-height:15px;text-align:center;
          border-radius:50%;background:var(--panel2);color:var(--dim);font-size:10px;
          font-weight:700;margin-left:6px;cursor:help;font-family:sans-serif;
          border:1px solid var(--border);text-transform:none;letter-spacing:0}
.help-tip:hover{background:var(--accent);color:#0b0e14}
#first-run-overlay{position:fixed;inset:0;background:rgba(6,9,14,.92);z-index:9998;
                   display:flex;flex-direction:column;align-items:center;justify-content:center;
                   backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px)}
#first-run-overlay .fr-title{font-size:28px;font-weight:700;color:var(--text);margin-bottom:10px}
#first-run-overlay .fr-sub{font-size:14px;color:var(--dim);max-width:520px;text-align:center;line-height:1.6;margin-bottom:26px;padding:0 20px}
#first-run-overlay .fr-bar{width:360px;height:10px;background:#1b2230;border-radius:5px;overflow:hidden;border:1px solid var(--border)}
#first-run-overlay .fr-bar-fill{height:100%;background:var(--accent);width:0%;transition:width .4s ease}
#first-run-overlay .fr-count{margin-top:10px;font-size:11px;color:var(--dim);font-family:ui-monospace,Menlo,monospace}
/* Story mode modal */
.modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,.7); display:flex; align-items:center; justify-content:center; z-index:1000; }
.modal { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:24px; max-width:560px; width:90%; max-height:80vh; overflow-y:auto; position:relative; }
.modal h2 { margin-top:0; }
.modal-close { position:absolute; top:16px; right:20px; cursor:pointer; font-size:24px; color:var(--dim); background:none; border:none; }
.delta-row { display:flex; justify-content:space-between; padding:10px 0; border-bottom:1px solid var(--border); }
.delta-arrow { font-weight:700; }
.delta-arrow.good { color:var(--good); }
.delta-arrow.bad { color:var(--bad); }
.delta-arrow.neutral { color:var(--dim); }
.story-big { font-size:20px; font-weight:700; margin:6px 0 14px; color:var(--accent); }
.story-section { margin-top:18px; }
.story-section h3 { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--dim); margin:0 0 8px; }
.story-actions-list { list-style:none; padding:0; margin:0; font-size:13px; }
.story-actions-list li { padding:6px 0; border-bottom:1px solid var(--border); color:var(--text); }
.story-actions-list li:last-child { border-bottom:none; }
.story-why { font-size:13px; line-height:1.55; color:var(--text); }
.story-footer { margin-top:18px; padding-top:14px; border-top:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; gap:10px; }
.story-reset { color:var(--link); background:none; border:none; cursor:pointer; font-size:12px; padding:0; }
</style>
</head><body>
<header>
  <h1>Mac<span>Optimizer</span> &nbsp;·&nbsp; <span id="hostname" style="color:var(--dim);font-weight:400"></span></h1>
  <div style="display:flex;align-items:center;gap:14px">
    <div>Health: <span id="score" class="score">--</span></div>
    <button id="story-btn" class="primary" onclick="openStoryModal()">What did I just fix?</button>
    <button class="primary" onclick="loadAll()">↻ Refresh</button>
  </div>
</header>

<div id="first-run-overlay" style="display:none">
  <div class="fr-title">Scanning your Mac…</div>
  <div class="fr-sub">First scan takes 60–90 seconds because we're reading every folder in your home directory. After this, refreshes are instant.</div>
  <div class="fr-bar"><div class="fr-bar-fill" id="fr-bar-fill"></div></div>
  <div class="fr-count" id="fr-count">0 / 13</div>
</div>

<div class="grid">

  <div class="card heal" id="heal-card">
    <h2>🩺 Heal My Mac<span class="help-tip" title="A plain-English summary of what's wrong and what to do next. Start here.">?</span></h2>
    <div class="sub" id="heal-sub">Scanning…</div>
    <div id="heal-list"></div>
    <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border)">
      <button class="primary" onclick="openDiagnoseModal()">Why is my Mac slow right now?</button>
      <span class="path" style="margin-left:10px;font-size:11px">Pinpoints the single root cause + the exact fix.</span>
    </div>
  </div>

  <div class="card" id="permissions-card" style="display:none">
    <h2>Permissions Needed<span class="help-tip" title="macOS won't let this dashboard see some files until you grant permission. Click the buttons below to open System Settings.">?</span></h2>
    <div class="perm-sub">macOS needs your OK before this dashboard can see some things. Grant these once and you're done.</div>
    <div id="permissions-list"></div>
    <div style="margin-top:10px"><button onclick="loadPermissions()">Re-check</button></div>
  </div>

  <div class="card" id="health-card">
    <h2>System Health<span class="help-tip" title="CPU, memory, thermal, and battery stats at a glance. Green is good, red needs attention.">?</span> <span class="count" id="health-count"></span></h2>
    <div id="health-metrics"></div>
    <div id="health-issues" style="margin-top:14px"></div>
  </div>

  <div class="card">
    <h2>Process Inspector<span class="help-tip" title="Apps using a lot of CPU right now. The 'verdict' tag tells you if it's safe to kill.">?</span> <span class="count" id="intel-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      Only processes that are actually impacting your Mac are shown here. If this list is short, your Mac is calm.
      Rows with a <b style="color:#fb923c">heavy</b> or <b style="color:var(--bad)">severe</b> badge are the ones worth killing.
      The verdict tag tells you whether killing is safe.
    </p>
    <div id="intel-list"></div>
  </div>

  <div class="card" id="quickcheck-card">
    <h2>System Health Quick-Check <span class="count" id="qc-score"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      Three things every Mac should have squared away: security toggles, pending updates, and Time Machine snapshots eating disk.
    </p>
    <div id="qc-posture" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px"></div>
    <div id="qc-updates-section" style="display:none;margin-top:8px;padding-top:12px;border-top:1px solid #1f2530">
      <h3 style="font-size:12px;color:var(--dim);margin:0 0 8px">Pending software updates <span id="qc-updates-count"></span></h3>
      <div id="qc-updates-list"></div>
      <div class="btn-row" style="margin-top:8px">
        <button onclick='openSettingsPane(this,"sw_update")'>Open Software Update settings</button>
      </div>
    </div>
    <div id="qc-tm-section" style="display:none;margin-top:8px;padding-top:12px;border-top:1px solid #1f2530">
      <h3 style="font-size:12px;color:var(--dim);margin:0 0 8px">Time Machine local snapshots</h3>
      <div id="qc-tm-summary" class="path"></div>
      <div class="btn-row" style="margin-top:8px">
        <button class="danger" onclick="deleteAllTmSnapshots(this)">Delete all snapshots</button>
      </div>
    </div>
    <div id="qc-allgood" style="display:none;color:var(--good);font-size:12px;margin-top:6px">All clear. Nothing to fix here.</div>
  </div>

  <div class="card">
    <h2>Disk Hogs<span class="help-tip" title="The biggest folders on your Mac, with notes on which are safe to clean.">?</span></h2>
    <table id="disk-table"><thead>
      <tr><th>Folder</th><th>Size</th><th>Note</th><th></th></tr>
    </thead><tbody></tbody></table>
    <div class="btn-row">
      <button class="primary" onclick="action('/api/clean-caches','Clear ~/Library/Caches?')">Clean User Caches</button>
      <button onclick="action('/api/empty-trash','Empty Trash permanently?')">Empty Trash</button>
    </div>
  </div>

  <div class="card">
    <h2>Unused Apps (1+ year)<span class="help-tip" title="Apps you haven't opened in over a year. Usually safe to delete to reclaim disk space.">?</span> <span class="count" id="unused-count"></span></h2>
    <table id="unused-table"><thead>
      <tr><th>App</th><th>Last Used</th><th>Size</th><th></th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Largest Apps<span class="help-tip" title="Apps taking up the most disk space, so you can decide what's worth keeping.">?</span></h2>
    <table id="large-table"><thead>
      <tr><th>App</th><th>Size</th><th>Last Used</th><th></th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Recurring Offenders<span class="help-tip" title="Processes that keep pegging your CPU over time. If this list is empty, nothing chronic is wrong.">?</span> <span class="count" id="off-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      Processes that have repeatedly pegged ≥30% CPU across the last 30 ten-minute snapshots.
      This panel hides things you're actively using (browsers, terminals, AI CLIs) —
      what's left is stuff that <i>shouldn't</i> be that busy. If this list is empty, nothing chronic is wrong.
    </p>
    <table id="off-table"><thead>
      <tr><th>Process</th><th>Times</th><th>Avg CPU</th><th>Peak</th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Threat Scan<span class="help-tip" title="Looks for unsigned processes, weird kernel extensions, modified hosts files, and other signs of trouble.">?</span> <span class="count" id="threat-count"></span></h2>
    <h3 style="font-size:12px;color:var(--dim);margin:0 0 6px">Unsigned / suspicious processes</h3>
    <table id="unsigned-table"><thead>
      <tr><th>Process</th><th>Sig</th><th>PID</th><th></th></tr>
    </thead><tbody></tbody></table>
    <h3 style="font-size:12px;color:var(--dim);margin:14px 0 6px">/etc/hosts integrity</h3>
    <div id="hosts-info" class="path"></div>
    <h3 style="font-size:12px;color:var(--dim);margin:14px 0 6px">Third-party kernel extensions</h3>
    <div id="kexts-info" class="path"></div>
    <h3 style="font-size:12px;color:var(--dim);margin:14px 0 6px">Cron / periodic jobs</h3>
    <div id="cron-info" class="path"></div>
    <h3 style="font-size:12px;color:var(--dim);margin:14px 0 6px">Configuration profiles</h3>
    <div id="profile-info" class="path"></div>
  </div>

  <div class="card">
    <h2>Network Activity<span class="help-tip" title="Shows which apps are currently talking to the internet and to whom. Unexpected traffic means investigate.">?</span> <span class="count" id="net-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">Established outbound TCP connections. Lots of conns from unexpected processes = investigate.</p>
    <table id="net-table"><thead>
      <tr><th>Process</th><th>PID</th><th>Conns</th><th>Sample remote</th></tr>
    </thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Browser Extensions<span class="help-tip" title="Add-ons installed in your browsers. Risky ones (broad permissions) are flagged first.">?</span> <span class="count" id="ext-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      <b>Quit your browser before removing</b>, otherwise it will recreate the folder from sync.
      Risky extensions (broad permissions) are listed first — they can read everything you do in the browser.
    </p>
    <div id="ext-list"></div>
  </div>

  <div class="card">
    <h2>Stale Files<span class="help-tip" title="Files in Downloads/Documents/Desktop you haven't opened in 2.5+ years.">?</span> <span class="count" id="stale-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      Files in <code>~/Downloads</code>, <code>~/Documents</code>, and <code>~/Desktop</code> not opened
      or modified in <b>2.5+ years</b>. Largest first. <b>Reveal</b> opens the file in Finder so you can
      check what it is. <b>Trash</b> is recoverable — nothing is permanently deleted. Files under 1 MB are hidden.
    </p>
    <div id="stale-bulk-actions" style="margin-bottom:8px;display:none">
      <button class="danger" onclick="trashSelectedStale()">Move selected to Trash</button>
      <span id="stale-selected-info" class="path" style="margin-left:10px"></span>
    </div>
    <div id="stale-list"></div>
    <div class="pager" id="stale-pager" style="display:none">
      <span id="stale-page-info"></span>
      <button onclick="stalePage(-1)" id="stale-prev">‹ Prev</button>
      <button onclick="stalePage(1)"  id="stale-next">Next ›</button>
    </div>
  </div>

  <div class="card" id="organizer-card">
    <h2>File Organizer (by age &amp; type) <span class="count" id="org-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      Every file ≥1 MB in <code>~/Downloads</code>, <code>~/Documents</code>, and <code>~/Desktop</code>,
      grouped by how old it is and what kind it is. Click any cell to see the actual files.
      The <b>Last 1 year</b> row is your recent stuff — leave it alone.
    </p>
    <div id="org-grid"></div>
  </div>

  <div class="card" id="duplicates-card" style="display:none">
    <h2>Duplicate Files <span class="count" id="dup-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      Identical files (same content, verified by hash) ≥10 MB across
      <code>~/Downloads</code>, <code>~/Documents</code>, <code>~/Desktop</code>, <code>~/Movies</code>,
      <code>~/Music</code>. Sorted by wasted space. <b>Trash this copy</b> is recoverable.
    </p>
    <div id="dup-list"></div>
  </div>

  <div class="card">
    <h2>Vendor Cleanup<span class="help-tip" title="Finds every leftover folder an uninstalled app left behind in /Library and ~/Library.">?</span> <span class="count" id="vendor-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      Apps you've uninstalled often leave behind launch agents, support folders, caches, prefs, and helpers
      scattered across <code>/Library</code> and <code>~/Library</code>. This panel finds vendors whose stuff is
      <i>still on disk after the app is gone</i> and removes everything in one click. One password prompt per vendor.
    </p>
    <div id="vendor-list"></div>
    <div style="margin-top:14px;padding-top:12px;border-top:1px solid #1f2530">
      <div style="font-size:12px;color:var(--dim);margin-bottom:6px">Manually clean a vendor by name:</div>
      <input id="vendor-input" type="text" placeholder="e.g. dropbox, zoom, skype"
             style="background:#0e1218;border:1px solid #2a3140;color:var(--fg);padding:6px 10px;border-radius:6px;width:200px;font-family:inherit;font-size:13px">
      <button class="kill-caution" onclick="previewVendor()" style="padding:6px 14px">Preview</button>
      <div id="vendor-preview" style="margin-top:10px"></div>
    </div>
  </div>

  <div class="card">
    <h2>Stale Vendor Folders<span class="help-tip" title="Folders in Application Support whose owning app is no longer installed. Usually leftover crud.">?</span> <span class="count" id="orphan-count"></span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 10px">
      Folders in <code>Application Support</code> whose owning app is no longer installed in <code>/Applications</code>.
      These are usually leftover crud from uninstalled software. Tick the ones you don't need and remove together.
    </p>
    <div id="orphan-list"></div>
    <div id="orphan-actions" style="margin-top:10px;display:none">
      <button class="danger" onclick="removeSelectedOrphans()">Remove selected</button>
      <span id="orphan-selected-info" class="path" style="margin-left:10px"></span>
    </div>
  </div>

  <div class="card">
    <h2>Security Audit<span class="help-tip" title="Checks your firewall, FileVault, Gatekeeper, login items, and background launch agents.">?</span> <span class="count" id="sec-count"></span></h2>
    <div id="sec-findings"></div>
    <h2 style="margin-top:18px">Startup Apps (Login Items)</h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 8px">
      Apps that launch automatically when you log in. Removing one here just
      stops it from auto-starting — the app itself stays installed.
    </p>
    <div id="login-items"></div>
    <h2 style="margin-top:18px">Launch Agents <span style="color:var(--dim);font-weight:400;font-size:12px">(background auto-starters)</span></h2>
    <p style="color:var(--dim);font-size:12px;margin:0 0 8px">
      Tick multiple to remove in one password prompt. <span class="tag bad">binary missing</span>
      tags mean the owning app is gone — those are always safe to remove.
    </p>
    <div id="agents-bulk-actions" style="margin-bottom:8px;display:none">
      <button class="danger" onclick="removeSelectedAgents()">Remove selected</button>
      <span id="agents-selected-info" class="path" style="margin-left:10px"></span>
    </div>
    <div class="table-wrap">
      <table id="agents-table"><thead>
        <tr><th style="width:24px"><input type="checkbox" id="agents-select-all" onclick="toggleAllAgents(this)"></th>
            <th>Label</th><th>Kind</th><th>Modified</th><th></th></tr>
      </thead><tbody></tbody></table>
    </div>
  </div>

</div>

<div id="story-modal" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeStoryModal()">
  <div class="modal" role="dialog" aria-modal="true">
    <button class="modal-close" onclick="closeStoryModal()" aria-label="Close">×</button>
    <h2>What did I just fix?</h2>
    <div id="story-body">Loading…</div>
    <div class="story-footer">
      <button class="story-reset" onclick="resetStorySession()">Reset session</button>
      <button class="primary" onclick="storyTakeSnapshot(this)">Take a fresh snapshot</button>
    </div>
  </div>
</div>

<div id="diagnose-modal" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeDiagnoseModal()">
  <div class="modal" role="dialog" aria-modal="true">
    <button class="modal-close" onclick="closeDiagnoseModal()" aria-label="Close">×</button>
    <h2>Why is my Mac slow right now?</h2>
    <div id="diagnose-body">Diagnosing…</div>
    <div class="story-footer">
      <span class="path" style="font-size:11px">Re-runs every time you open this — current data only.</span>
      <button class="primary" onclick="openDiagnoseModal()">Re-run diagnosis</button>
    </div>
  </div>
</div>

<script>
function toast(msg, ok=true){
  const t=document.createElement('div');
  t.className='toast '+(ok?'ok':'err');
  t.textContent=msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(),4000);
}
async function api(path, body){
  const r = await fetch(path,{
    method: body?'POST':'GET',
    headers: body?{'Content-Type':'application/json'}:{},
    body: body?JSON.stringify(body):undefined
  });
  return r.json();
}
async function action(path, confirmMsg, body){
  if(confirmMsg && !confirm(confirmMsg)) return;
  const r = await api(path, body||{});
  toast(r.msg, r.ok);
  if(r.ok) setTimeout(loadAll,500);
}
// Safe button helpers — receive raw values as function args, never via string-built onclick.
// Each takes the clicked button as first arg so we can disable it, show progress, and
// optimistically remove its row from the DOM the moment the action succeeds.
function _runAction(btn, busyLabel, path, body, confirmMsg, logEntry){
  if(confirmMsg && !confirm(confirmMsg)) return;
  const originalLabel = btn.textContent;
  btn.disabled = true;
  btn.textContent = busyLabel;
  api(path, body).then(r=>{
    toast(r.msg, r.ok);
    if(r.ok){
      if(logEntry) logSessionAction(logEntry);
      // Optimistically fade + remove the row container so the user sees the
      // change immediately instead of waiting ~10s for /api/unused to re-scan.
      const row = btn.closest('tr, .proc, .metric');
      if(row){
        row.style.transition = 'opacity .25s, transform .25s';
        row.style.opacity = '0';
        row.style.transform = 'translateX(20px)';
        setTimeout(()=>row.remove(), 260);
      }
      // Then trigger a background refresh so other panels (e.g. health, heal) update.
      setTimeout(loadAll, 1500);
    } else {
      btn.disabled = false;
      btn.textContent = originalLabel;
    }
  }).catch(e=>{
    toast('Error: '+e, false);
    btn.disabled = false;
    btn.textContent = originalLabel;
  });
}
// ── Story-mode session log (localStorage) ─────────────────────────────────
function logSessionAction(entry){
  try {
    const key = 'macopt_session_actions';
    const arr = JSON.parse(localStorage.getItem(key) || '[]');
    arr.push(Object.assign({ts: Date.now()}, entry));
    // Cap to last 500 to keep localStorage sane
    localStorage.setItem(key, JSON.stringify(arr.slice(-500)));
  } catch(e) {}
}
function killProc(btn, pid, friendly, explanation){
  _runAction(btn, 'Killing…', '/api/kill', {pid:pid},
             'Kill '+friendly+' (PID '+pid+')?\n\n'+(explanation||''),
             {kind:'kill', label:friendly, bytes_freed:0, source:'process'});
}
function trashPath(btn, path, name, bytes){
  _runAction(btn, 'Moving…', '/api/trash', {path:path},
             'Move '+name+' to Trash?\n\n'+path,
             {kind:'trash', label:name, bytes_freed:(bytes||0), source:'unused'});
}
function removeLogin(btn, name){
  _runAction(btn, 'Removing…', '/api/remove-login', {name:name},
             'Remove login item: '+name+'?',
             {kind:'remove', label:name, bytes_freed:0, source:'launch_agent'});
}
function removeLaunchAgent(btn, path){
  _runAction(btn, 'Removing…', '/api/remove-launch-agent', {path:path},
             'Unload and DELETE this launch agent?\n\n'+path,
             {kind:'remove', label:(path.split('/').pop()||path), bytes_freed:0, source:'launch_agent'});
}
function pct(v,max=100,warn=70,bad=90){
  const cls = v>=bad?'bad':v>=warn?'warn':'good';
  return `<span class="v ${cls}">${v}${max==100?'%':''}</span>`;
}
async function loadHealth(){
  const h = await api('/api/health');
  // Seed the Story-mode session-start snapshot once per page load (or after 4h).
  try {
    const raw = localStorage.getItem('macopt_session_start');
    const prev = raw ? JSON.parse(raw) : null;
    const now = Date.now();
    if(!prev || !prev.ts || (now - prev.ts) > 4*60*60*1000){
      localStorage.setItem('macopt_session_start', JSON.stringify({ts: now, health: h}));
    }
  } catch(e) {}
  document.getElementById('hostname').textContent = h.uptime?'uptime '+h.uptime:'';
  const score = h.score;
  const sEl = document.getElementById('score');
  sEl.textContent = score;
  sEl.className = 'score '+(score>=80?'good':score>=60?'warn':'bad');
  const m = document.getElementById('health-metrics');
  m.innerHTML = `
    <div class="metric"><span>CPU Speed Limit</span><span class="v ${h.speed_limit>=100?'good':h.speed_limit>=80?'warn':'bad'}">${h.speed_limit}%${h.speed_limit>=100?' (no throttling)':' (thermal throttle)'}</span></div>
    <div class="metric"><span>Disk Used</span>${pct(h.disk_used_pct,100,80,90)} <span class="path">(${h.disk_free_gb.toFixed(0)} GB free / ${h.disk_total_gb.toFixed(0)} GB)</span></div>
    <div class="metric"><span>Memory Free</span><span class="v ${h.mem_free_pct<20?'bad':h.mem_free_pct<40?'warn':'good'}">${h.mem_free_pct}%</span></div>
    <div class="metric"><span>Wired Memory</span><span class="v ${h.wired_gb>4?'warn':'good'}">${h.wired_gb.toFixed(1)} GB</span></div>
    <div class="metric"><span>Swap Used</span><span class="v ${(h.swap_used_mb>1500&&h.mem_free_pct<30)?'bad':h.swap_used_mb>500?'warn':'good'}">${h.swap_used_mb.toFixed(0)} MB</span></div>
    <div class="metric"><span>Load (1m / cores)</span><span class="v">${h.load1.toFixed(2)} / ${h.cores}</span></div>
    <div class="metric"><span>Battery</span><span class="path">${h.battery||'?'}</span></div>
  `;
  const iv = document.getElementById('health-issues');
  iv.innerHTML = h.issues.length ?
    h.issues.map(i=>`<div class="issue ${i.sev}"><div class="msg">${i.msg}</div><div class="fix">→ ${i.fix}</div></div>`).join('')
    : '<div class="issue info"><div class="msg">No critical issues detected ✓</div></div>';
  document.getElementById('health-count').textContent = h.issues.length+' issues';
}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function humanBytes(n){
  const units=['B','KB','MB','GB','TB'];
  let i=0; while(n>=1024 && i<units.length-1){n/=1024;i++;}
  return n.toFixed(1)+' '+units[i];
}
async function loadIntel(){
  const p = await api('/api/intel');
  document.getElementById('intel-count').textContent =
    p.length===0 ? 'all calm' : p.length+(p.length===1?' process':' processes');
  const list = document.getElementById('intel-list');
  list.innerHTML = p.map(x=>{
    const killClass = x.verdict==='safe'?'kill-safe':x.verdict==='caution'?'kill-caution':x.verdict==='never'?'kill-never':'danger';
    const killDisabled = x.verdict==='never'?'disabled':'';
    const reasons = (x.reasons && x.reasons.length) ? x.reasons.join(' · ') : '';
    return `
      <div class="proc">
        <div class="left">
          <div class="friendly">
            ${esc(x.friendly)}
            <span class="harm-pill ${x.harm_band}">${x.harm_band} ${x.harm}</span>
            <span class="verdict ${x.verdict}">${x.verdict==='never'?'do not kill':x.verdict}</span>
          </div>
          <div class="raw">${esc(x.name)} · pid ${x.pid} · ${esc(x.path||'')}</div>
          <div class="why">${esc(x.explanation)}${reasons?'<br><b style="color:#9aa6ba">Why flagged:</b> '+esc(reasons):''}</div>
        </div>
        <div class="nums"><b>${x.cpu.toFixed(0)}%</b> CPU<br>${x.rss_mb<1024?x.rss_mb.toFixed(0)+' MB':(x.rss_mb/1024).toFixed(1)+' GB'}</div>
        <div><button class="${killClass}" ${killDisabled}
          onclick="killProc(this,${x.pid},${JSON.stringify(x.friendly)},${JSON.stringify(x.explanation)})">
          ${x.verdict==='never'?'Protected':'Kill'}
        </button></div>
      </div>`;
  }).join('');
}
async function loadHeal(){
  const h = await api('/api/heal');
  document.getElementById('heal-sub').textContent =
    `Health ${h.score}/100 · ${h.summary}`;
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
    <tr><td>${x.name}</td><td><b>${x.human}</b></td>
        <td class="path">${x.note}</td>
        <td>${x.cleanable?'<span class="tag good">cleanable</span>':''}</td></tr>`).join('');
}
function _appDescBlock(x){
  if(!x.description) return '';
  return `<div class="why" style="margin-top:4px;font-size:11px;line-height:1.45">
            ${esc(x.description)}
            ${x.needed_if?'<br><b style="color:#9aa6ba">You need this if:</b> '+esc(x.needed_if):''}
          </div>`;
}
async function loadUnused(){
  const u = await api('/api/unused');
  document.getElementById('unused-count').textContent = u.length;
  document.querySelector('#unused-table tbody').innerHTML = u.map(x=>`
    <tr><td><div><b>${esc(x.name)}</b></div>${_appDescBlock(x)}</td>
        <td class="path">${x.last_used}</td>
        <td>${x.size_human}</td>
        <td><button class="danger" onclick='trashPath(this,${JSON.stringify(x.path)},${JSON.stringify(x.name)},${x.size_bytes||0})'>Trash</button></td>
    </tr>`).join('');
}
async function loadLarge(){
  const l = await api('/api/large');
  document.querySelector('#large-table tbody').innerHTML = l.map(x=>`
    <tr><td><div><b>${esc(x.name)}</b></div>${_appDescBlock(x)}</td>
        <td><b>${x.size_human}</b></td>
        <td class="path">${x.last_used}</td>
        <td><button class="danger" onclick='trashPath(this,${JSON.stringify(x.path)},${JSON.stringify(x.name)},${x.size_bytes||0})'>Trash</button></td>
    </tr>`).join('');
}
async function loadSec(){
  const s = await api('/api/security');
  document.getElementById('sec-count').textContent = s.findings.length+' findings';
  document.getElementById('sec-findings').innerHTML = s.findings.length ?
    s.findings.map(f=>`<div class="issue ${f.sev}"><div class="msg">${f.msg}</div><div class="fix">→ ${f.fix}</div></div>`).join('')
    : '<div class="issue info"><div class="msg">No suspicious processes or agents found ✓</div></div>';
  document.getElementById('login-items').innerHTML = s.login_items.map(li=>`
    <div class="metric"><span>${esc(li)}</span>
      <button class="danger" onclick='removeLogin(this,${JSON.stringify(li)})'>Remove</button>
    </div>`).join('') || '<div class="path">none</div>';
  document.querySelector('#agents-table tbody').innerHTML = s.launch_agents.slice(0,30).map(a=>`
    <tr data-path='${JSON.stringify(a.path)}' ${a.is_self?'style="background:#0e1a14"':''}>
        <td>${a.is_self?'':'<input type="checkbox" class="agent-cb" onclick="updateAgentSelection()">'}</td>
        <td title="${esc(a.path)}">${esc(a.label)} ${a.is_self?'<span class="tag good">this dashboard</span>':''} ${a.suspicious.length?'<span class="tag bad">'+esc(a.suspicious.join(','))+'</span>':''} ${a.recent && !a.is_self?'<span class="tag warn">new</span>':''}</td>
        <td>${esc(a.kind)}</td><td class="path">${esc(a.modified)}</td>
        <td><button class="danger" onclick='removeLaunchAgent(this,${JSON.stringify(a.path)})'>Remove</button></td>
    </tr>`).join('');
  updateAgentSelection();
}
function toggleAllAgents(box){
  document.querySelectorAll('.agent-cb').forEach(cb=>cb.checked = box.checked);
  updateAgentSelection();
}
function updateAgentSelection(){
  const checked = document.querySelectorAll('.agent-cb:checked');
  const bar = document.getElementById('agents-bulk-actions');
  if(checked.length===0){ bar.style.display='none'; return; }
  bar.style.display='block';
  document.getElementById('agents-selected-info').textContent =
    checked.length+' selected';
}
function removeSelectedAgents(){
  const rows = Array.from(document.querySelectorAll('.agent-cb:checked'))
                    .map(cb=>cb.closest('tr'));
  const paths = rows.map(r=>JSON.parse(r.getAttribute('data-path')));
  if(paths.length===0) return;
  if(!confirm('Unload and DELETE '+paths.length+' launch agent plist'+(paths.length>1?'s':'')+'?\\n\\nOne password prompt covers all of them.')) return;
  api('/api/remove-paths',{paths}).then(r=>{
    toast(r.msg, r.ok);
    if(r.ok){
      rows.forEach(row=>{
        row.style.transition='opacity .25s';
        row.style.opacity='0';
        setTimeout(()=>row.remove(),260);
      });
      setTimeout(loadAll,1500);
    }
  });
}
async function loadVendors(){
  const v = await api('/api/dead-vendors');
  document.getElementById('vendor-count').textContent =
    v.length===0 ? 'all clean' : v.length+(v.length===1?' vendor':' vendors');
  const list = document.getElementById('vendor-list');
  if(v.length===0){
    list.innerHTML = '<div class="issue info"><div class="msg">No dead vendors detected — every launch agent has a working binary ✓</div></div>';
    return;
  }
  list.innerHTML = v.map(d=>`
    <div class="issue warn" style="margin-bottom:8px">
      <div class="msg" style="display:flex;justify-content:space-between;align-items:center;gap:10px">
        <span><b>${esc(d.vendor)}</b> &middot; ${d.plist_count} orphan plist${d.plist_count!==1?'s':''} &middot; ${d.item_count} item${d.item_count!==1?'s':''} &middot; <b>${d.total_human}</b></span>
        <button class="danger" onclick="removeVendor(this,${JSON.stringify(d.vendor)},${d.item_count},${JSON.stringify(d.total_human)})">Remove all</button>
      </div>
      <div class="fix" style="font-family:ui-monospace,Menlo,monospace;font-size:11px;line-height:1.5">
        ${d.preview.map(p=>'• '+esc(p)).join('<br>')}${d.item_count>d.preview.length?'<br>… and '+(d.item_count-d.preview.length)+' more':''}
      </div>
    </div>`).join('');
}
function removeVendor(btn, vendor, count, sizeHuman){
  if(!confirm('Remove ALL '+count+' '+vendor+' files/folders ('+sizeHuman+')?\\n\\nThis deletes apps, launch plists, helpers, support folders, caches, logs, and prefs in one shot. One password prompt.')) return;
  const orig = btn.textContent;
  btn.disabled=true; btn.textContent='Removing…';
  api('/api/remove-vendor',{vendor}).then(r=>{
    toast(r.msg, r.ok);
    if(r.ok){
      logSessionAction({kind:'remove', label:vendor+' (vendor cleanup)',
                        bytes_freed:(r.bytes_freed||parseHumanBytes(sizeHuman)||0), source:'vendor'});
      const card = btn.closest('.issue');
      if(card){ card.style.transition='opacity .3s'; card.style.opacity='0'; setTimeout(()=>card.remove(),320); }
      setTimeout(loadAll,1500);
    } else {
      btn.disabled=false; btn.textContent=orig;
    }
  });
}
function parseHumanBytes(s){
  if(!s) return 0;
  const m = String(s).trim().match(/^([\d.]+)\s*(B|KB|MB|GB|TB|PB)$/i);
  if(!m) return 0;
  const n = parseFloat(m[1]);
  const u = m[2].toUpperCase();
  const mult = {B:1, KB:1024, MB:1024**2, GB:1024**3, TB:1024**4, PB:1024**5}[u] || 1;
  return Math.round(n*mult);
}
async function previewVendor(){
  const v = document.getElementById('vendor-input').value.trim();
  const out = document.getElementById('vendor-preview');
  if(!v){ out.innerHTML=''; return; }
  out.innerHTML = '<div class="path">Scanning…</div>';
  const fp = await api('/api/vendor-footprint?vendor='+encodeURIComponent(v));
  if(fp.error){ out.innerHTML='<div class="path" style="color:var(--bad)">'+esc(fp.error)+'</div>'; return; }
  if(!fp.items || fp.items.length===0){
    out.innerHTML = '<div class="path">Nothing matching <b>'+esc(v)+'</b> found.</div>';
    return;
  }
  out.innerHTML = `
    <div class="issue warn">
      <div class="msg" style="display:flex;justify-content:space-between;align-items:center;gap:10px">
        <span><b>${esc(fp.vendor)}</b> &middot; ${fp.count} item${fp.count!==1?'s':''} &middot; <b>${fp.total_human}</b></span>
        <button class="danger" onclick="removeVendor(this,${JSON.stringify(fp.vendor)},${fp.count},${JSON.stringify(fp.total_human)})">Remove all</button>
      </div>
      <div class="fix" style="font-family:ui-monospace,Menlo,monospace;font-size:11px;line-height:1.5;max-height:240px;overflow:auto">
        ${fp.items.map(i=>'• '+esc(i.path)+' &nbsp;<span style="color:var(--dim)">'+i.size_human+'</span>').join('<br>')}
      </div>
    </div>`;
}
async function loadOrphans(){
  const o = await api('/api/orphan-folders');
  document.getElementById('orphan-count').textContent =
    o.length===0 ? 'none' : o.length+(o.length===1?' folder':' folders');
  const list = document.getElementById('orphan-list');
  if(o.length===0){
    list.innerHTML = '<div class="issue info"><div class="msg">No orphan support folders ≥1 MB found ✓</div></div>';
    document.getElementById('orphan-actions').style.display='none';
    return;
  }
  list.innerHTML = '<div class="table-wrap"><table style="width:100%"><thead><tr><th style="width:24px"></th><th>Folder</th><th>Size</th><th>Last modified</th><th></th></tr></thead><tbody>'+
    o.map(x=>`
    <tr data-path='${JSON.stringify(x.path)}'>
      <td><input type="checkbox" class="orphan-cb" onclick="updateOrphanSelection()"></td>
      <td title="${esc(x.path)}">${esc(x.name)}<div class="path" style="font-size:10px">${esc(x.root)}</div></td>
      <td><b>${x.size_human}</b></td>
      <td class="path">${x.last_modified}</td>
      <td><button class="danger" onclick='removeOnePath(this,${JSON.stringify(x.path)},${JSON.stringify(x.name)})'>Remove</button></td>
    </tr>`).join('')+'</tbody></table></div>';
  updateOrphanSelection();
}
function updateOrphanSelection(){
  const checked = document.querySelectorAll('.orphan-cb:checked');
  const bar = document.getElementById('orphan-actions');
  if(checked.length===0){ bar.style.display='none'; return; }
  bar.style.display='block';
  document.getElementById('orphan-selected-info').textContent =
    checked.length+' selected';
}
function removeSelectedOrphans(){
  const rows = Array.from(document.querySelectorAll('.orphan-cb:checked'))
                    .map(cb=>cb.closest('tr'));
  const paths = rows.map(r=>JSON.parse(r.getAttribute('data-path')));
  if(paths.length===0) return;
  if(!confirm('Delete '+paths.length+' orphan folder'+(paths.length>1?'s':'')+'?')) return;
  api('/api/remove-paths',{paths}).then(r=>{
    toast(r.msg, r.ok);
    if(r.ok){
      rows.forEach(row=>{
        row.style.transition='opacity .25s';
        row.style.opacity='0';
        setTimeout(()=>row.remove(),260);
      });
      setTimeout(loadAll,1500);
    }
  });
}
function removeOnePath(btn, path, name){
  if(!confirm('Delete '+name+'?\\n\\n'+path)) return;
  const orig = btn.textContent;
  btn.disabled=true; btn.textContent='Removing…';
  // Try to pull the row's size cell text as a fallback bytes estimate.
  let bytes = 0;
  const row = btn.closest('tr');
  if(row){
    const sizeCell = row.querySelector('td:nth-child(3) b, td:nth-child(3)');
    if(sizeCell) bytes = parseHumanBytes(sizeCell.textContent) || 0;
  }
  api('/api/remove-paths',{paths:[path]}).then(r=>{
    toast(r.msg, r.ok);
    if(r.ok){
      logSessionAction({kind:'remove', label:name, bytes_freed:bytes, source:'orphan'});
      if(row){ row.style.transition='opacity .25s'; row.style.opacity='0'; setTimeout(()=>row.remove(),260); }
      setTimeout(loadAll,1500);
    } else {
      btn.disabled=false; btn.textContent=orig;
    }
  });
}
async function loadThreats(){
  const t = await api('/api/threats');
  const flagged = (t.unsigned||[]).length + (t.hosts.suspicious||[]).length;
  document.getElementById('threat-count').textContent = flagged+' flagged';
  document.querySelector('#unsigned-table tbody').innerHTML = (t.unsigned||[]).map(p=>`
    <tr><td title="${p.path}">${p.name}</td>
        <td><span class="tag ${p.signature==='unsigned'?'bad':'warn'}">${p.signature}</span></td>
        <td class="path">${p.pid}</td>
        <td><button class="danger" onclick="action('/api/kill','Kill ${p.name} (PID ${p.pid})?',{pid:${p.pid}})">Kill</button></td>
    </tr>`).join('') || '<tr><td colspan="4" class="path">All top processes are signed ✓</td></tr>';
  const h = t.hosts;
  document.getElementById('hosts-info').innerHTML =
    h.suspicious.length
      ? '<span class="tag bad">SUSPICIOUS REDIRECTS</span><br>'+h.suspicious.map(s=>'• '+s).join('<br>')
      : `✓ ${h.total_entries} entries, none suspicious`;
  document.getElementById('kexts-info').innerHTML = (t.kexts||[]).length
    ? (t.kexts).slice(0,8).map(k=>'• '+k).join('<br>')
    : '✓ No third-party kernel extensions';
  document.getElementById('cron-info').innerHTML = (t.cron||[]).length
    ? (t.cron).slice(0,10).map(c=>'• ['+c.src+'] '+c.entry).join('<br>')
    : '✓ No user cron jobs';
  document.getElementById('profile-info').innerHTML = (t.profiles||[]).length
    ? (t.profiles).join('<br>')
    : '✓ No configuration profiles installed';
  const exts = t.extensions||[];
  document.getElementById('ext-count').textContent = exts.length;
  const list = document.getElementById('ext-list');
  if(exts.length===0){ list.innerHTML = '<div class="path">no extensions found</div>'; return; }
  list.innerHTML = exts.map(e=>{
    const riskTag = e.risky
      ? '<span class="tag warn">broad perms · '+e.perms+'</span>'
      : '<span class="tag good">low · '+e.perms+'</span>';
    return `<div class="proc">
      <div class="left">
        <div class="friendly">${esc(e.name)} ${riskTag}</div>
        <div class="raw">${esc(e.browser)} · updated ${esc(e.last_modified||'?')} · <span title="${esc(e.id)}">${esc(e.id.slice(0,12))}…</span></div>
      </div>
      <div class="btn-row">
        <button class="btn-sm" onclick='revealPath(this,${JSON.stringify(e.path||"")})'>Reveal</button>
        <button class="danger btn-sm" onclick='removeExtension(this,${JSON.stringify(e.path||"")},${JSON.stringify(e.name||e.id)})'>Remove</button>
      </div>
    </div>`;
  }).join('');
}
function removeExtension(btn, path, name){
  if(!path){ toast('No path for this extension', false); return; }
  if(!confirm('Remove extension "'+name+'"?\n\nQuit your browser FIRST or it will recreate the folder from sync.\n\n'+path)) return;
  _runAction(btn, 'Removing…', '/api/remove-extension', {path:path}, null,
             {kind:'remove', label:name, bytes_freed:0, source:'extension'});
}
function revealPath(btn, path){
  if(!path){ toast('No path', false); return; }
  api('/api/reveal',{path:path}).then(r=>toast(r.msg, r.ok));
}
let _staleAll = [];
let _stalePage = 0;
const STALE_PER_PAGE = 25;
async function loadStale(){
  _staleAll = await api('/api/stale-files');
  _stalePage = 0;
  renderStale();
}
function renderStale(){
  const s = _staleAll;
  const total = s.length;
  document.getElementById('stale-count').textContent =
    total===0 ? 'all clean' : total+' file'+(total===1?'':'s');
  const list = document.getElementById('stale-list');
  if(total===0){
    list.innerHTML = '<div class="issue info"><div class="msg">No files ≥1 MB untouched for 2.5+ years ✓</div></div>';
    document.getElementById('stale-bulk-actions').style.display='none';
    document.getElementById('stale-pager').style.display='none';
    return;
  }
  const pages = Math.ceil(total / STALE_PER_PAGE);
  if(_stalePage >= pages) _stalePage = pages-1;
  if(_stalePage < 0) _stalePage = 0;
  const start = _stalePage * STALE_PER_PAGE;
  const slice = s.slice(start, start + STALE_PER_PAGE);
  // Walk the slice and inject a section header whenever the bucket changes.
  // Always emit the header for the first row of the page so the user knows
  // which cohort they're looking at after paging.
  let html = '';
  let lastBucket = null;
  for(const x of slice){
    if(x.bucket !== lastBucket){
      // Count how many in this bucket overall, so the header is informative
      const totalInBucket = s.filter(y=>y.bucket===x.bucket).length;
      const bucketBytes = s.filter(y=>y.bucket===x.bucket).reduce((a,y)=>a+y.size_bytes,0);
      html += `<div class="bucket-header">
        <span class="bucket-title">${esc(x.bucket)}</span>
        <span class="bucket-meta">${totalInBucket} file${totalInBucket===1?'':'s'} · ${humanBytes(bucketBytes)}</span>
      </div>`;
      lastBucket = x.bucket;
    }
    html += `
    <div class="proc" data-path='${JSON.stringify(x.path)}'>
      <div style="display:flex;align-items:flex-start;gap:10px;flex:1;min-width:0">
        <input type="checkbox" class="stale-cb" onclick="updateStaleSelection()" style="margin-top:4px;flex-shrink:0">
        <div class="left" style="min-width:0">
          <div class="friendly" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <span style="word-break:break-word">${esc(x.name)}</span>
            <span class="tag bad">${x.age_years}y old</span>
            <span class="tag warn">${x.size_human}</span>
            <span class="tag" style="background:#1b2230;color:var(--dim)">~/${esc(x.root)}</span>
          </div>
          <div class="raw">last touched ${esc(x.last_used)} · <span title="${esc(x.path)}">${esc(x.path)}</span></div>
        </div>
      </div>
      <div class="btn-row">
        <button class="btn-sm" onclick='revealPath(this,${JSON.stringify(x.path)})'>Reveal</button>
        <button class="danger btn-sm" onclick='trashOneStale(this,${JSON.stringify(x.path)},${JSON.stringify(x.name)},${x.size_bytes||0})'>Trash</button>
      </div>
    </div>`;
  }
  list.innerHTML = html;
  // Pager
  const pager = document.getElementById('stale-pager');
  if(pages > 1){
    pager.style.display='flex';
    document.getElementById('stale-page-info').textContent =
      `Showing ${start+1}–${Math.min(start+STALE_PER_PAGE, total)} of ${total}`;
    document.getElementById('stale-prev').disabled = _stalePage === 0;
    document.getElementById('stale-next').disabled = _stalePage >= pages-1;
  } else {
    pager.style.display='none';
  }
  updateStaleSelection();
}
function stalePage(delta){
  _stalePage += delta;
  renderStale();
  // Scroll the card back to the top of the list so the user sees row 1 of the page
  document.getElementById('stale-list').scrollIntoView({behavior:'smooth', block:'nearest'});
}
function toggleAllStale(box){
  document.querySelectorAll('.stale-cb').forEach(cb=>cb.checked = box.checked);
  updateStaleSelection();
}
function updateStaleSelection(){
  const checked = document.querySelectorAll('.stale-cb:checked');
  const bar = document.getElementById('stale-bulk-actions');
  if(checked.length===0){ bar.style.display='none'; return; }
  bar.style.display='block';
  document.getElementById('stale-selected-info').textContent =
    checked.length+' selected';
}
function trashSelectedStale(){
  const rows = Array.from(document.querySelectorAll('.stale-cb:checked'))
                    .map(cb=>cb.closest('[data-path]'));
  const paths = rows.map(r=>JSON.parse(r.getAttribute('data-path')));
  if(paths.length===0) return;
  if(!confirm('Move '+paths.length+' file'+(paths.length>1?'s':'')+' to Trash?\n\nYou can recover them from Trash if you change your mind.')) return;
  api('/api/trash-files',{paths}).then(r=>{
    toast(r.msg, r.ok);
    if(r.ok){
      // Drop trashed entries from the cached list and re-render the page
      const trashedSet = new Set(paths);
      _staleAll = _staleAll.filter(x=>!trashedSet.has(x.path));
      renderStale();
      setTimeout(loadHealth, 1500);
    }
  });
}
function trashOneStale(btn, path, name, bytes){
  if(!confirm('Move "'+name+'" to Trash?\\n\\n'+path)) return;
  _runAction(btn, 'Trashing…', '/api/trash-files', {paths:[path]}, null,
             {kind:'trash', label:name, bytes_freed:(bytes||0), source:'stale'});
}
// ── File Organizer ──────────────────────────────────────────────────────
let _orgData = [];
async function loadOrganizer(){
  _orgData = await api('/api/organizer');
  renderOrganizer();
}
function renderOrganizer(){
  const grid = document.getElementById('org-grid');
  const totalFiles = _orgData.reduce((a,b)=>a+b.total_count,0);
  document.getElementById('org-count').textContent =
    totalFiles===0 ? 'nothing ≥1 MB' : totalFiles+' file'+(totalFiles===1?'':'s');
  if(!_orgData.length){ grid.innerHTML=''; return; }
  let html = '';
  for(const row of _orgData){
    const cls = row.is_current ? 'org-row current' : 'org-row';
    const sub = row.is_current
      ? 'Current — leave alone'
      : (row.total_count+' · '+row.total_human);
    html += `<div class="${cls}">
      <div class="org-row-label">
        <div>${esc(row.age)}</div>
        <div class="sub">${esc(sub)}</div>
      </div>
      <div class="org-cells">`;
    for(const c of row.categories){
      const empty = c.count === 0 ? ' empty' : '';
      const clickAttr = c.count === 0
        ? ''
        : ` onclick="toggleOrgDrill(this,${row.age_order},${JSON.stringify(c.name)})"`;
      html += `<div class="org-cell${empty}" data-age="${row.age_order}" data-cat="${esc(c.name)}"${clickAttr}>
        <div class="cat">${esc(c.name)}</div>
        <div class="cnt">${c.count} file${c.count===1?'':'s'}</div>
        <div class="sz">${esc(c.size_human)}</div>
      </div>`;
    }
    html += `</div></div>
    <div class="org-drill" id="org-drill-${row.age_order}" style="display:none"></div>`;
  }
  grid.innerHTML = html;
}
async function toggleOrgDrill(cell, ageOrder, cat){
  const drill = document.getElementById('org-drill-'+ageOrder);
  // Close if re-clicking the same active cell
  if(cell.classList.contains('active')){
    cell.classList.remove('active');
    drill.style.display='none';
    drill.innerHTML='';
    return;
  }
  // Clear other active cells in this row
  cell.parentElement.querySelectorAll('.org-cell.active').forEach(c=>c.classList.remove('active'));
  cell.classList.add('active');
  drill.style.display='block';
  drill.innerHTML = '<div class="drill-head"><span>Loading…</span></div>';
  const rows = await api('/api/organizer-drill?age='+encodeURIComponent(ageOrder)+'&cat='+encodeURIComponent(cat));
  renderOrgDrill(drill, rows, ageOrder, cat);
}
function renderOrgDrill(drill, rows, ageOrder, cat){
  if(!rows || rows.length === 0){
    drill.innerHTML = '<div class="drill-head"><span>No files in this cell.</span></div>';
    return;
  }
  const isCurrent = ageOrder === 0;
  const totalBytes = rows.reduce((a,x)=>a+x.size_bytes,0);
  let html = `<div class="drill-head">
    <span><b>${esc(cat)}</b> · ${rows.length} file${rows.length===1?'':'s'} · ${humanBytes(totalBytes)}${rows.length>=100?' (top 100)':''}</span>`;
  if(!isCurrent){
    html += `<button class="danger btn-sm" onclick="trashSelectedOrg(this,${ageOrder},${JSON.stringify(cat)})">Move selected to Trash</button>`;
  } else {
    html += `<span class="tag good">Current — read-only</span>`;
  }
  html += `</div>`;
  for(const x of rows){
    html += `<div class="proc" data-path='${JSON.stringify(x.path)}'>
      <div style="display:flex;align-items:flex-start;gap:10px;flex:1;min-width:0">`;
    if(!isCurrent){
      html += `<input type="checkbox" class="org-cb" style="margin-top:4px;flex-shrink:0">`;
    }
    html += `<div class="left" style="min-width:0">
          <div class="friendly" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <span style="word-break:break-word">${esc(x.name)}</span>
            <span class="tag bad">${x.age_years}y old</span>
            <span class="tag warn">${x.size_human}</span>
            <span class="tag" style="background:#1b2230;color:var(--dim)">~/${esc(x.root)}</span>
          </div>
          <div class="raw">last touched ${esc(x.last_used)} · <span title="${esc(x.path)}">${esc(x.path)}</span></div>
        </div>
      </div>
      <div class="btn-row">
        <button class="btn-sm" onclick='revealPath(this,${JSON.stringify(x.path)})'>Reveal</button>`;
    if(!isCurrent){
      html += `<button class="danger btn-sm" onclick='trashOneStale(this,${JSON.stringify(x.path)},${JSON.stringify(x.name)})'>Trash</button>`;
    }
    html += `</div></div>`;
  }
  drill.innerHTML = html;
}
function trashSelectedOrg(btn, ageOrder, cat){
  const drill = btn.closest('.org-drill');
  const checked = drill.querySelectorAll('.org-cb:checked');
  const paths = Array.from(checked).map(cb=>JSON.parse(cb.closest('[data-path]').getAttribute('data-path')));
  if(paths.length === 0){ toast('Nothing selected', false); return; }
  if(!confirm('Move '+paths.length+' file'+(paths.length>1?'s':'')+' to Trash?\n\nYou can recover them from Trash if you change your mind.')) return;
  api('/api/trash-files',{paths}).then(r=>{
    toast(r.msg, r.ok);
    if(r.ok){
      setTimeout(()=>{ loadOrganizer(); loadStale(); loadHealth(); }, 800);
    }
  });
}

// ── Duplicate Files ─────────────────────────────────────────────────────
let _dupSets = [];
async function loadDuplicates(){
  _dupSets = await api('/api/duplicates');
  renderDuplicates();
}
function renderDuplicates(){
  const card = document.getElementById('duplicates-card');
  const list = document.getElementById('dup-list');
  if(!_dupSets || _dupSets.length === 0){
    card.style.display='none';
    return;
  }
  card.style.display='';
  const totalWasted = _dupSets.reduce((a,d)=>a+d.wasted_bytes,0);
  document.getElementById('dup-count').textContent =
    _dupSets.length+' set'+(_dupSets.length===1?'':'s')+' · '+humanBytes(totalWasted)+' wasted';
  let html = '';
  _dupSets.forEach((d, idx)=>{
    html += `<div class="dup-group" id="dup-g-${idx}">
      <div class="dup-head" onclick="toggleDup(${idx})">
        <div class="dup-title">${d.count} copies × ${esc(d.size_human)}
          <span class="tag warn">${esc(d.wasted_human)} wasted</span></div>
        <div class="dup-meta">
          <span>${esc(d.files[0].name)}</span>
          <button class="btn-sm" onclick="event.stopPropagation();trashAllButOne(this,${idx})">Trash all but one</button>
          <button class="btn-sm" onclick="event.stopPropagation();toggleDup(${idx})">Show files</button>
        </div>
      </div>
      <div class="dup-body">`;
    for(const f of d.files){
      html += `<div class="proc" data-path='${JSON.stringify(f.path)}'>
        <div class="left" style="min-width:0">
          <div class="friendly" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <span style="word-break:break-word">${esc(f.name)}</span>
            <span class="tag" style="background:#1b2230;color:var(--dim)">~/${esc(f.root)}</span>
          </div>
          <div class="raw">last touched ${esc(f.last_used)} · <span title="${esc(f.path)}">${esc(f.path)}</span></div>
        </div>
        <div class="btn-row">
          <button class="btn-sm" onclick='revealPath(this,${JSON.stringify(f.path)})'>Reveal</button>
          <button class="danger btn-sm" onclick='trashOneDuplicate(this,${JSON.stringify(f.path)},${JSON.stringify(f.name)})'>Trash this copy</button>
        </div>
      </div>`;
    }
    html += `</div></div>`;
  });
  list.innerHTML = html;
}
function toggleDup(idx){
  const g = document.getElementById('dup-g-'+idx);
  if(g) g.classList.toggle('open');
}
function trashOneDuplicate(btn, path, name){
  if(!confirm('Move this copy of "'+name+'" to Trash?\n\n'+path)) return;
  btn.disabled = true;
  btn.textContent = 'Trashing…';
  api('/api/trash-duplicate',{path:path}).then(r=>{
    toast(r.msg, r.ok);
    if(r.ok){
      const row = btn.closest('.proc');
      if(row){
        row.style.transition='opacity .25s';
        row.style.opacity='0';
        setTimeout(()=>row.remove(), 260);
      }
      setTimeout(loadDuplicates, 1500);
    } else {
      btn.disabled = false;
      btn.textContent = 'Trash this copy';
    }
  });
}
const _DUP_ROOT_PRIORITY = {"Documents":5,"Desktop":4,"Downloads":3,"Movies":2,"Music":1};
function trashAllButOne(btn, idx){
  const d = _dupSets[idx];
  if(!d || d.files.length < 2) return;
  // Pick the keeper — highest priority root, tiebreak by path length (shorter = probably the "real" copy)
  let keepIdx = 0;
  let bestScore = -1;
  d.files.forEach((f,i)=>{
    const score = (_DUP_ROOT_PRIORITY[f.root]||0)*10000 - f.path.length;
    if(score > bestScore){ bestScore = score; keepIdx = i; }
  });
  const keep = d.files[keepIdx];
  const toDelete = d.files.filter((_,i)=>i!==keepIdx);
  if(!confirm('Keep:\n  '+keep.path+'\n\nMove these '+toDelete.length+' copies to Trash?\n\n'
              + toDelete.map(f=>'  '+f.path).join('\n'))) return;
  btn.disabled = true;
  btn.textContent = 'Trashing…';
  // Sequential so we get a clear error if one fails.
  (async ()=>{
    let ok = 0, fail = 0;
    for(const f of toDelete){
      const r = await api('/api/trash-duplicate',{path:f.path});
      if(r.ok) ok++; else fail++;
    }
    toast('Trashed '+ok+(fail?' · '+fail+' failed':''), ok>0);
    setTimeout(loadDuplicates, 800);
  })();
}

async function loadNetwork(){
  const n = await api('/api/network');
  document.getElementById('net-count').textContent = n.length;
  document.querySelector('#net-table tbody').innerHTML = n.map(x=>`
    <tr><td>${x.proc}</td><td class="path">${x.pid}</td>
        <td><b>${x.count}</b></td>
        <td class="path">${x.samples.join('<br>')}</td>
    </tr>`).join('');
}
async function loadHistory(){
  const h = await api('/api/history');
  document.getElementById('off-count').textContent = h.offenders.length;
  document.querySelector('#off-table tbody').innerHTML = h.offenders.length
    ? h.offenders.map(o=>`
      <tr><td>${o.name}</td><td><b>${o.appearances}</b></td>
          <td>${o.avg_cpu}%</td><td>${o.max_cpu.toFixed(0)}%</td></tr>`).join('')
    : `<tr><td colspan="4" class="path">No data yet. ${h.count} snapshots stored. Run with <code>--watch</code> for trends.</td></tr>`;
}
// ─── PERMISSIONS / ONBOARDING (JS) ───
async function loadPermissions(){
  try{
    const p = await api('/api/permissions');
    const card = document.getElementById('permissions-card');
    const list = document.getElementById('permissions-list');
    if(!card || !list) return;
    if(p.all_granted){
      card.style.display = 'none';
      list.innerHTML = '';
      return;
    }
    card.style.display = '';
    const items = [];
    if(!p.fda || !p.fda.granted){
      items.push(`<div class="issue critical">
        <div class="msg">Full Disk Access missing</div>
        <div class="fix">Without Full Disk Access I can't see how much space your Mail and Safari are using — your scan will be incomplete.</div>
        <div style="margin-top:8px"><button class="danger" onclick="openPermsSettingsPane('fda', this)">Open System Settings → Full Disk Access</button></div>
      </div>`);
    }
    if(!p.automation || !p.automation.granted){
      items.push(`<div class="issue critical">
        <div class="msg">Automation (System Events) missing</div>
        <div class="fix">Without Automation I can't ask macOS which apps are actually running — some panels will be empty.</div>
        <div style="margin-top:8px"><button class="danger" onclick="openPermsSettingsPane('automation', this)">Open System Settings → Automation</button></div>
      </div>`);
    }
    list.innerHTML = items.join('');
  }catch(e){ /* non-fatal */ }
}
async function openPermsSettingsPane(pane, btn){
  const orig = btn ? btn.textContent : '';
  if(btn){ btn.disabled = true; btn.textContent = 'Opening…'; }
  try{
    const r = await api('/api/open-settings', {pane: pane});
    toast(r.msg, r.ok);
    if(btn){
      btn.textContent = r.ok ? '✓ Opened' : 'Failed — try manually';
      setTimeout(()=>{ btn.disabled=false; btn.textContent=orig; }, 3500);
    }
  }catch(e){
    toast('Could not reach the server', false);
    if(btn){ btn.disabled=false; btn.textContent=orig; }
  }
}

// ─── FIRST-RUN OVERLAY + PROGRESS ───
function _showFirstRunOverlay(total){
  if(localStorage.getItem('macopt_first_run')) return null;
  const ov = document.getElementById('first-run-overlay');
  if(!ov) return null;
  ov.style.display = 'flex';
  const fill = document.getElementById('fr-bar-fill');
  const count = document.getElementById('fr-count');
  let done = 0, dismissed = false;
  const autoDismissAt = Math.min(10, total);
  return {
    tick(){
      done++;
      if(fill) fill.style.width = Math.round((done/total)*100) + '%';
      if(count) count.textContent = done + ' / ' + total;
      if(!dismissed && done >= autoDismissAt){
        dismissed = true;
        setTimeout(()=>{ ov.style.display = 'none'; }, 250);
      }
    },
    finish(){
      localStorage.setItem('macopt_first_run', '1');
      ov.style.display = 'none';
    }
  };
}

// ─── System Health Quick-Check ────────────────────────────────────────────
function openSettingsPane(btn, pane){
  _runAction(btn, 'Opening…', '/api/open-settings-pane', {pane:pane});
}
function deleteAllTmSnapshots(btn){
  const dates = (window._qcTmDates||[]);
  if(!dates.length){ toast('No snapshots to delete', false); return; }
  _runAction(btn, 'Deleting…', '/api/delete-tm-snapshots', {dates:dates},
    'Delete '+dates.length+' Time Machine local snapshot(s)? Admin password required.');
}
async function loadQuickCheck(){
  let q;
  try { q = await api('/api/quickcheck'); } catch(e){ return; }
  const p = q.posture||{}, u = q.updates||{}, s = q.snapshots||{};

  // Score badge
  const scoreEl = document.getElementById('qc-score');
  scoreEl.textContent = (p.score||0) + '/5';

  // Posture pills
  const labels = {filevault:'FileVault', gatekeeper:'Gatekeeper', sip:'SIP',
                  firewall:'Firewall', auto_update:'Auto-Update'};
  const paneMap = {filevault:'filevault', gatekeeper:'gatekeeper', sip:null,
                   firewall:'firewall', auto_update:'auto_update'};
  const order = ['filevault','gatekeeper','sip','firewall','auto_update'];
  const pp = document.getElementById('qc-posture');
  pp.innerHTML = order.map(k=>{
    const v = p[k]||'unknown';
    const cls = v==='on'?'good':(v==='off'?'bad':'warn');
    const pane = paneMap[k];
    const clickable = (v!=='on' && pane);
    const onclk = clickable ? `onclick='openSettingsPane(this,${JSON.stringify(pane)})'` : '';
    const cursor = clickable ? 'cursor:pointer;' : '';
    const title = clickable ? `title="Click to open ${labels[k]} settings"` : '';
    return `<span class="tag ${cls}" style="padding:4px 10px;font-size:11px;${cursor}" ${title} ${onclk}>${labels[k]}: ${v}</span>`;
  }).join('');

  // Updates section — hide if 0
  const usec = document.getElementById('qc-updates-section');
  if((u.count||0) > 0){
    usec.style.display='';
    document.getElementById('qc-updates-count').textContent =
      '('+u.count+(u.critical_count?', '+u.critical_count+' security':'')+')';
    const list = document.getElementById('qc-updates-list');
    list.innerHTML = (u.items||[]).map(it=>{
      const cls = it.severity==='critical'?'bad':(it.severity==='warn'?'warn':'good');
      return `<div style="padding:4px 0;font-size:12px">
        <span class="tag ${cls}">${esc(it.severity)}</span>
        ${esc(it.title)} <span class="path">${esc(it.label)}</span></div>`;
    }).join('') || '<div class="path">No details parsed.</div>';
  } else {
    usec.style.display='none';
  }

  // Time Machine section — hide if 0
  const tsec = document.getElementById('qc-tm-section');
  if((s.count||0) > 0){
    tsec.style.display='';
    const sum = 'Local snapshots: '+s.count+
      (s.purgeable_human ? ' · purgeable: '+s.purgeable_human
                         : ' · size hidden by macOS — use Storage Settings to see exact reclaimable amount.');
    document.getElementById('qc-tm-summary').textContent = sum;
    window._qcTmDates = (s.snapshots||[]).map(x=>x.date);
  } else {
    tsec.style.display='none';
    window._qcTmDates = [];
  }

  // All-green hint
  const allGood = (p.score===5) && (u.count||0)===0 && (s.count||0)===0;
  document.getElementById('qc-allgood').style.display = allGood ? '' : 'none';
}

// ── Story Mode modal ──────────────────────────────────────────────────────
// "good direction" per metric: score up, wired down, free up, swap down, disk down.
const STORY_METRICS = [
  {key:'score',        label:'Health score',  unit:'',     good:'up',   fmt:v=>Math.round(v)},
  {key:'wired_gb',     label:'Wired memory',  unit:' GB',  good:'down', fmt:v=>Number(v).toFixed(1)},
  {key:'mem_free_pct', label:'Free memory',   unit:'%',    good:'up',   fmt:v=>Math.round(v)},
  {key:'swap_mb',      label:'Swap used',     unit:' MB',  good:'down', fmt:v=>Math.round(v)},
  {key:'disk_used_pct',label:'Disk used',     unit:'%',    good:'down', fmt:v=>Math.round(v)},
];
function openStoryModal(){
  document.getElementById('story-modal').style.display='flex';
  renderStoryModal();
}
function closeStoryModal(){
  document.getElementById('story-modal').style.display='none';
}
document.addEventListener('keydown', e=>{
  if(e.key==='Escape' && document.getElementById('story-modal').style.display==='flex'){
    closeStoryModal();
  }
});
async function renderStoryModal(){
  const body = document.getElementById('story-body');
  body.innerHTML = '<div class="path">Loading…</div>';
  const actions = JSON.parse(localStorage.getItem('macopt_session_actions') || '[]');
  const start = JSON.parse(localStorage.getItem('macopt_session_start') || 'null');
  const totalBytes = actions.reduce((a,x)=>a+(x.bytes_freed||0), 0);
  // Top-line metric
  let html = '';
  if(totalBytes > 0){
    html += `<div class="story-big">You reclaimed ${humanBytes(totalBytes)} this session.</div>`;
  } else {
    html += `<div class="story-big">You haven't trashed anything yet — but here's how your Mac is doing right now.</div>`;
  }
  // Fetch server deltas
  let summary = null;
  try {
    const sinceTs = start && start.ts ? Math.floor(start.ts/1000) : 0;
    summary = await api('/api/session-summary?since='+sinceTs);
  } catch(e) {}
  const deltas = (summary && summary.deltas) ? summary.deltas : null;
  if(deltas){
    html += '<div class="story-section"><h3>What changed</h3>';
    let rows = '';
    for(const m of STORY_METRICS){
      const d = deltas[m.key];
      if(!d) continue;
      if(d.delta === 0) continue; // Aby's filter rule
      const direction = d.delta > 0 ? 'up' : 'down';
      const isGood = (direction === m.good);
      const cls = isGood ? 'good' : 'bad';
      const arrow = direction === 'up' ? '▲' : '▼';
      rows += `<div class="delta-row">
        <span>${m.label}</span>
        <span><span class="delta-arrow ${cls}">${arrow}</span> ${m.fmt(d.old)}${m.unit} → ${m.fmt(d.new)}${m.unit}</span>
      </div>`;
    }
    if(!rows) rows = '<div class="path">No measurable change since session start.</div>';
    html += rows + '</div>';
  } else if(summary && summary.error){
    html += `<div class="story-section"><div class="path">${esc(summary.error)}</div></div>`;
  }
  // Action list — newest first, capped at 20
  if(actions.length){
    const sorted = actions.slice().sort((a,b)=>b.ts-a.ts).slice(0,20);
    html += '<div class="story-section"><h3>What you did</h3><ul class="story-actions-list">';
    for(const a of sorted){
      const sizePart = a.bytes_freed > 0 ? ' ('+humanBytes(a.bytes_freed)+')' : '';
      const verb = a.kind==='trash' ? 'Trashed'
                 : a.kind==='kill'  ? 'Killed'
                 : a.kind==='clean' ? 'Cleaned'
                 : 'Removed';
      html += `<li>${verb} ${esc(a.label||'item')}${sizePart}</li>`;
    }
    html += '</ul></div>';
  }
  // Why this matters
  html += '<div class="story-section"><h3>Why this matters</h3><div class="story-why">';
  const reasons = [];
  if(deltas){
    if(deltas.mem_free_pct && deltas.mem_free_pct.delta >= 15)
      reasons.push('Your apps will open faster and Safari tabs will stop reloading.');
    if(deltas.wired_gb && deltas.wired_gb.delta <= -1)
      reasons.push('Your Mac will run cooler — fans should spin down.');
    if(deltas.swap_mb && deltas.swap_mb.delta <= -500)
      reasons.push('Stuttering and beach-balls should be gone.');
    if(deltas.disk_used_pct && deltas.disk_used_pct.delta <= -2)
      reasons.push('Time Machine backups will finish again, and macOS will stop warning you about disk space.');
    if(deltas.score && deltas.score.delta >= 10)
      reasons.push("You moved from 'struggling' to 'healthy.'");
  }
  if(reasons.length === 0){
    html += 'Your Mac was already in good shape — most of these actions were preventive.';
  } else {
    html += reasons.map(r=>'• '+esc(r)).join('<br>');
  }
  html += '</div></div>';
  body.innerHTML = html;
}
function resetStorySession(){
  if(!confirm('Clear this session log and start fresh?')) return;
  localStorage.removeItem('macopt_session_actions');
  localStorage.removeItem('macopt_session_start');
  // Re-seed a new start snapshot immediately from current health
  api('/api/snapshot').then(()=>{
    api('/api/health').then(h=>{
      localStorage.setItem('macopt_session_start', JSON.stringify({ts: Date.now(), health: h}));
      renderStoryModal();
    });
  });
}
function storyTakeSnapshot(btn){
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = 'Snapshotting…';
  api('/api/snapshot').then(()=>{
    btn.disabled = false; btn.textContent = orig;
    renderStoryModal();
  }).catch(()=>{ btn.disabled=false; btn.textContent=orig; });
}

// ── "Why is my Mac slow?" diagnosis modal ────────────────────────────────
async function openDiagnoseModal(){
  const m = document.getElementById('diagnose-modal');
  m.style.display='flex';
  const body = document.getElementById('diagnose-body');
  body.innerHTML = '<div class="path">Diagnosing… reading pmset, battery, processes…</div>';
  let d;
  try { d = await api('/api/diagnose'); }
  catch(e){ body.innerHTML = '<div class="issue critical"><div class="msg">Could not run diagnosis</div><div class="fix">'+esc(String(e))+'</div></div>'; return; }
  let html = '';
  // Big headline
  const sevClass = (d.causes && d.causes.length && d.causes[0].severity==='critical') ? 'bad'
                 : (d.causes && d.causes.length && d.causes[0].severity==='warn') ? 'warn'
                 : 'good';
  html += `<div class="story-big" style="color:var(--${sevClass})">${esc(d.headline)}</div>`;
  // One-line summary of the system state right now
  const stateBits = [];
  stateBits.push(`Health ${d.score}/100`);
  stateBits.push(`CPU clock ${d.cpu_speed_limit}%`);
  stateBits.push(d.on_ac ? 'plugged in' : 'on battery');
  if(d.battery && d.battery.cycle_count) stateBits.push(d.battery.cycle_count + ' battery cycles');
  if(d.battery && d.battery.condition) stateBits.push('battery: ' + d.battery.condition);
  html += '<div class="path" style="margin:-8px 0 14px;font-size:11px">'+esc(stateBits.join(' · '))+'</div>';
  // Each cause as an issue card
  if(d.causes && d.causes.length){
    html += '<div class="story-section"><h3>Root causes (most likely first)</h3>';
    for(const c of d.causes){
      const cls = c.severity==='critical' ? 'critical' : (c.severity==='warn' ? 'warn' : 'info');
      html += `<div class="issue ${cls}" style="margin-bottom:10px">
        <div class="msg">${esc(c.title)}</div>
        <div class="fix" style="margin-top:6px"><b>What to do:</b> ${esc(c.fix)}</div>`;
      if(c.evidence && c.evidence.length){
        html += '<div class="path" style="margin-top:6px;font-size:10px">Evidence: '+c.evidence.filter(e=>e).map(e=>esc(e)).join(' · ')+'</div>';
      }
      html += '</div>';
    }
    html += '</div>';
  } else {
    html += '<div class="issue info"><div class="msg">No active slowdown root causes detected.</div><div class="fix">Your Mac is performing within normal limits right now.</div></div>';
  }
  // Battery+no-charger workaround tips — only when actually relevant.
  if(d.workarounds && d.workarounds.length){
    html += '<div class="story-section"><h3>Things to try right now (no charger needed)</h3>';
    html += '<ul class="story-actions-list" style="font-size:12px">';
    for(const w of d.workarounds){
      html += `<li><b>${esc(w.tip)}</b><div class="path" style="font-size:11px;margin-top:2px">${esc(w.saves)}</div></li>`;
    }
    html += '</ul></div>';
  }
  body.innerHTML = html;
}
function closeDiagnoseModal(){
  document.getElementById('diagnose-modal').style.display='none';
}
document.addEventListener('keydown', e=>{
  if(e.key==='Escape' && document.getElementById('diagnose-modal').style.display==='flex'){
    closeDiagnoseModal();
  }
});
async function loadAll(){
  document.getElementById('score').textContent='…';
  // Fire permissions check FIRST so the prompt appears before slow scans.
  loadPermissions();
  const loaders = [loadHealth,loadHeal,loadIntel,loadDisk,loadUnused,loadLarge,
                   loadSec,loadThreats,loadNetwork,loadHistory,
                   loadVendors,loadOrphans,loadStale,loadQuickCheck,
                   loadOrganizer,loadDuplicates];
  const overlay = _showFirstRunOverlay(loaders.length);
  const wrapped = loaders.map(fn => Promise.resolve().then(fn).finally(()=>{
    if(overlay) overlay.tick();
  }));
  await Promise.allSettled(wrapped);
  if(overlay) overlay.finish();
}
loadAll();
setInterval(loadHealth, 15000);
</script>
</body></html>"""

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
            body = body.encode()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == "/" or path == "/index.html":
                return self._send(200, HTML, "text/html; charset=utf-8")
            if path == "/api/health":
                return self._send(200, get_health())
            if path == "/api/processes":
                return self._send(200, get_processes())
            if path == "/api/intel":
                return self._send(200, get_process_intel())
            if path == "/api/heal":
                return self._send(200, get_heal_recommendations())
            if path == "/api/disk":
                return self._send(200, get_disk_hogs())
            if path == "/api/unused":
                return self._send(200, get_unused_apps())
            if path == "/api/large":
                return self._send(200, get_largest_apps())
            if path == "/api/security":
                return self._send(200, get_security_audit())
            if path == "/api/threats":
                return self._send(200, {
                    "unsigned": get_unsigned_processes(),
                    "kexts": get_kernel_extensions(),
                    "hosts": get_hosts_file_check(),
                    "cron": get_cron_jobs(),
                    "extensions": get_browser_extensions(),
                    "profiles": get_profiles(),
                })
            if path == "/api/network":
                return self._send(200, get_network_connections())
            if path == "/api/history":
                return self._send(200, get_history_summary())
            if path == "/api/snapshot":
                return self._send(200, take_snapshot())
            if path == "/api/session-summary":
                q = urlparse(self.path).query
                since = 0
                for kv in q.split("&"):
                    if kv.startswith("since="):
                        try:
                            since = int(kv[6:])
                        except ValueError:
                            since = 0
                        break
                return self._send(200, get_session_summary(since))
            if path == "/api/dead-vendors":
                return self._send(200, detect_dead_vendors())
            if path == "/api/orphan-folders":
                return self._send(200, get_orphan_app_support())
            if path == "/api/stale-files":
                return self._send(200, get_stale_files())
            if path == "/api/permissions":
                return self._send(200, get_permissions_status())
            if path == "/api/quickcheck":
                return self._send(200, get_quickcheck())
            if path == "/api/diagnose":
                return self._send(200, diagnose_slowness())
            if path == "/api/organizer":
                return self._send(200, get_file_organizer())
            if path == "/api/organizer-drill":
                q = urlparse(self.path).query
                age_raw = ""
                cat_raw = ""
                for kv in q.split("&"):
                    if kv.startswith("age="):
                        age_raw = kv[4:]
                    elif kv.startswith("cat="):
                        cat_raw = unquote(kv[4:])
                try:
                    ai = int(age_raw)
                except Exception:
                    return self._send(400, {"error": "bad age"})
                if ai < 0 or ai > 4:
                    return self._send(400, {"error": "age out of range"})
                if cat_raw not in _ORG_CAT_NAMES:
                    return self._send(400, {"error": "bad category"})
                return self._send(200, get_organizer_drill(ai, cat_raw))
            if path == "/api/duplicates":
                return self._send(200, get_duplicates())
            if path == "/api/vendor-footprint":
                vendor = urlparse(self.path).query
                # Parse ?vendor=adobe
                v = ""
                for kv in vendor.split("&"):
                    if kv.startswith("vendor="):
                        v = kv[7:]
                        break
                return self._send(200, get_vendor_footprint(v))
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        path = urlparse(self.path).path
        ln = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(ln) or b"{}")
        try:
            if path == "/api/kill":
                return self._send(200, act_kill(body.get("pid")))
            if path == "/api/trash":
                return self._send(200, act_trash(body.get("path")))
            if path == "/api/clean-caches":
                return self._send(200, act_clean_user_caches())
            if path == "/api/empty-trash":
                return self._send(200, act_empty_trash())
            if path == "/api/remove-login":
                return self._send(200, act_remove_login_item(body.get("name")))
            if path == "/api/remove-launch-agent":
                return self._send(200, act_remove_launch_agent(body.get("path")))
            if path == "/api/remove-vendor":
                return self._send(200, act_remove_vendor(body.get("vendor")))
            if path == "/api/remove-paths":
                return self._send(200, act_remove_paths(body.get("paths") or []))
            if path == "/api/remove-extension":
                return self._send(200, act_remove_extension(body.get("path")))
            if path == "/api/trash-files":
                return self._send(200, act_trash_files(body.get("paths") or []))
            if path == "/api/trash-duplicate":
                return self._send(200, act_trash_one_duplicate(body.get("path")))
            if path == "/api/reveal":
                return self._send(200, act_reveal_path(body.get("path")))
            if path == "/api/open-settings":
                return self._send(200, act_open_settings(body.get("pane")))
            if path == "/api/open-settings-pane":
                return self._send(200, act_open_settings_pane(body.get("pane")))
            if path == "/api/delete-tm-snapshots":
                return self._send(200, act_delete_tm_snapshots(body.get("dates") or []))
            return self._send(404, {"ok": False, "msg": "unknown action"})
        except Exception as e:
            return self._send(500, {"ok": False, "msg": str(e)})

def watcher_loop(interval_min=10):
    """Background thread: snapshot every N minutes, log spikes."""
    print(f"[watcher] sampling every {interval_min} min")
    # Initial snapshot
    take_snapshot()
    while True:
        time.sleep(interval_min * 60)
        try:
            snap = take_snapshot()
            ts = time.strftime("%H:%M", time.localtime(snap["ts"]))
            top = snap["top_procs"][0] if snap["top_procs"] else {}
            print(f"[watcher {ts}] score={snap['score']} cpu_limit={snap['speed_limit']}% "
                  f"mem_free={snap['mem_free']}% top={top.get('name','?')}@{top.get('cpu',0):.0f}%")
        except Exception as e:
            print(f"[watcher] error: {e}")

def main():
    args = sys.argv[1:]
    if "--watch-only" in args:
        # Headless mode: just take snapshots, no server.
        idx = args.index("--watch-only")
        interval = int(args[idx+1]) if idx+1 < len(args) and args[idx+1].isdigit() else 10
        watcher_loop(interval)
        return

    interval = 10
    if "--watch" in args:
        idx = args.index("--watch")
        if idx+1 < len(args) and args[idx+1].isdigit():
            interval = int(args[idx+1])
        t = threading.Thread(target=watcher_loop, args=(interval,), daemon=True)
        t.start()

    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    # Warm the stale-files cache in the background — the initial walk of
    # ~/Documents can take 20-30 seconds, and we don't want the first page
    # load to block on it. By the time the user clicks around, it's ready.
    threading.Thread(target=get_stale_files, daemon=True).start()
    # Pre-warm software updates cache — `softwareupdate -l` hits Apple servers
    # and can take 10-30 seconds, so we do it off the first request path.
    threading.Thread(target=get_software_updates, daemon=True).start()
    # Also pre-warm the organizer and duplicate-finder caches — both walk
    # large trees and can take 10-60s, so a cold first-click would otherwise
    # block the dashboard.
    threading.Thread(target=get_file_organizer, daemon=True).start()
    threading.Thread(target=get_duplicates, daemon=True).start()
    url = f"http://localhost:{PORT}"
    print(f"\n🔧 Mac Optimizer running at {url}")
    if "--watch" in args:
        print(f"   Watcher: sampling every {interval} min → {HIST_FILE}")
    print(f"   Press Ctrl+C to stop.\n")
    try:
        subprocess.Popen(["open", url])
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBye!")

if __name__ == "__main__":
    main()
