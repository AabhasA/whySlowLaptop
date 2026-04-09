# whySlowLaptop

> Make your laptop fast locally — know what's eating it up.

**A single-file local dashboard that tells you, in plain English, why your laptop is slow — and gives you one-click buttons to fix it.**

No installer. No login. No telemetry. No cloud. No subscription. Clone it, double-click, a dashboard opens in your browser at `http://localhost:8765`.

Built because my 9-year-old MacBook had been crawling for 3 days, Activity Monitor was useless, and I almost ordered a new laptop. The tool found the cause in 5 minutes (worn battery silently throttling the CPU to 33% on battery power) and fixed it with one cable. Then I cleaned up 260 GB of files older than 5 years I'd forgotten about.

---

## What it does

- **Heal banner** — one plain-English summary of what's wrong right now and what to do about it
- **Why is my Mac slow right now?** — root-cause diagnosis with evidence (battery wear, charger wattage, thermal, memory pressure, runaway processes)
- **Process Inspector** — every CPU hog explained in plain English with a "safe to kill?" verdict
- **Stale Files** — files in Downloads/Documents/Desktop you haven't opened in 2.5+ years, grouped by age, largest first
- **File Organizer** — every file ≥1 MB bucketed by age (Last 1y / 1–2y / 2–3y / 3–5y / 5+y) AND by type (Images, Videos, Documents, Installers, Other)
- **Duplicate Finder** — finds files with identical contents across Downloads/Documents/Desktop/Movies/Music using stdlib hashing
- **Vendor Cleanup** — finds every leftover folder a long-uninstalled app left behind in `/Library` and `~/Library`
- **Browser Extensions** — every Chrome/Brave/Edge extension with real names, permissions, and a Remove button
- **Permissions card** — detects missing Full Disk Access / Automation and links you straight into the right System Settings pane
- **System Health Quick-Check** — FileVault, Gatekeeper, SIP, Firewall, Auto-update status + Time Machine local snapshots + pending Software Updates
- **Story mode** — "What did I just fix?" modal that shows reclaimed bytes, score delta, wired-memory delta, and explains in plain English why your Mac feels faster

Everything is **read-only by default**. Destructive actions (Trash, Remove, Kill) require a confirm-button click. System paths and the dashboard's own files are protected from deletion at the safety-gate level.

## Status

| Platform | Version | Status |
|---|---|---|
| **macOS** | v1.0 | **Production** — tested by the author daily on macOS 26.4, Apple Silicon |
| **Windows** | v0.5 | **Experimental** — has the basics (health, processes, cleanup) but lacks the v1.0 features (File Organizer, Duplicates, Story Mode, Slowness Diagnosis). **Looking for a Windows tester** — file an issue if you try it. |

If you have a Windows laptop and want to help test/port the new features, please [open an issue](https://github.com/AabhasA/whySlowLaptop/issues) — that's the single biggest contribution right now.

## Install — macOS

**Option 1: Run it directly (the easiest, zero install)**

```bash
git clone https://github.com/AabhasA/whySlowLaptop.git
cd whySlowLaptop
python3 mac_optimizer.py
```

Your browser opens automatically. That's it. No `pip install` — Apple's preinstalled `python3` works on every Mac since 2019.

**Option 2: Persistent install (auto-starts at login)**

Double-click `install_mac.command`. It installs a launchd agent that keeps the dashboard running in the background, takes a health snapshot every 10 minutes for trend tracking, and survives reboots. To remove, double-click `uninstall_mac.command`.

If macOS shows "unidentified developer" when you double-click, **right-click → Open** instead. This is normal for any unsigned script downloaded from the internet — the file is the same one you can read in this repo.

## Permissions you'll be asked for

The dashboard works without these but is more accurate with them:

- **Full Disk Access** — needed to see how much space your Mail, Safari, Photos, and other Apple-app data is using. Without it, the disk-usage scan undercounts.
- **Automation (System Events)** — needed to list and remove Login Items.

The first time you run a feature that needs one of these, the dashboard's **Permissions card** will appear at the top with a button that opens System Settings to the exact pane. Grant once and you're done.

## Privacy

- Nothing leaves your machine. There is no network call to anything except (a) Apple's own software-update servers, when you click "check for updates," and (b) `localhost`. No analytics, no telemetry, no remote logging, no error reporting.
- All 4,700+ lines of `mac_optimizer.py` are in this repo. Read it before running it. It uses Python standard library only — no third-party dependencies that could change under you.
- Health snapshots are stored locally at `~/.mac_optimizer_history.json` for trend tracking. Delete that file any time.

## Install — Windows (experimental)

```cmd
git clone https://github.com/AabhasA/whySlowLaptop.git
cd whySlowLaptop
python win_optimizer.py
```

You'll need Python 3.9+ from python.org or the Microsoft Store. The Windows version has the core health/process/cleanup features but is missing the v1.0 additions. **Reports of what works and what breaks are very welcome** in the issue tracker.

## Uninstall

- **Mac (persistent install)**: double-click `uninstall_mac.command`
- **Mac (one-shot run)**: nothing to uninstall — just close the terminal window
- **Files left behind**: `~/.mac_optimizer_history.json` (the snapshot history). Delete manually if you want.

## Support / Feedback / Hire

- **Bug reports & feature requests**: [GitHub Issues](https://github.com/AabhasA/whySlowLaptop/issues)
- **Want to support the project**: [GitHub Sponsors](https://github.com/sponsors/AabhasA) (coming soon)
- **Available for hire**: I build local-first tools and dashboards like this one. Reach me on [LinkedIn](https://www.linkedin.com/in/aabhasagarwal/).

## License

[MIT](LICENSE) — do whatever you want with it, including using it commercially. A credit link back to this repo is appreciated but not required.
