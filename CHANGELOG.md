# Changelog

All notable changes to whySlowLaptop will be documented in this file.

## [v1.0] — 2026-04-09 — first public release

### macOS dashboard (production)

**The story**: built because my 9-year-old MacBook had been crawling for 3
days, Activity Monitor wasn't helping, and I almost ordered a new one. The
tool found the cause in 5 minutes (worn battery silently throttling the
CPU on battery power) and fixed it with one cable.

### Added
- **Heal banner** — plain-English summary of what's wrong + recommended actions
- **"Why is my Mac slow right now?"** modal — root-cause analysis combining
  battery health, charger state, thermal throttle, memory pressure, and the
  top RAM/CPU consumers into one ranked diagnosis with specific fixes
- **Memory Hogs** card — top RAM consumers grouped by app (so all 49 Chrome
  helper processes collapse into one "Google Chrome (incl. tabs) — 6.5 GB"
  row) with per-app Kill button
- **Process Inspector** — top CPU users explained in plain English with
  "safe to kill?" verdicts
- **System Health Quick-Check** — FileVault, Gatekeeper, SIP, Firewall,
  Auto-update status + Time Machine local snapshots + pending macOS updates
- **Permissions card** — auto-detects missing Full Disk Access / Automation
  and links straight into the right System Settings pane (also fixes the
  silent open-settings bug from earlier sessions where two _SETTINGS_PANES
  dicts collided at module import)
- **Stale Files** — files in Downloads/Documents/Desktop not opened for
  2.5+ years, grouped by age, largest first, with bulk-trash and pagination
- **File Organizer** — every file ≥1 MB grouped by age (Last 1y / 1–2y /
  2–3y / 3–5y / 5+y) and category (Images / Videos / Documents / Installers
  / Other). Click any cell to drill down to the actual files with Reveal
  and Trash buttons.
- **Duplicate File Finder** — pure-stdlib size-then-partial-hash-then-full-hash
  algorithm finds identical files across ~/Downloads, Documents, Desktop,
  Movies, Music. Per-set "trash all but the most-protected copy" button.
- **Vendor Cleanup** — finds every leftover folder long-uninstalled apps
  left behind in /Library and ~/Library, removes them in one password prompt
- **Stale Vendor Folders** — orphan Application Support folders whose
  owning app is no longer installed
- **Browser Extensions** — every Chrome / Brave / Edge extension across all
  profiles, with real names resolved from manifests + _locales, permissions
  count, risk badge, and Remove button
- **Story mode** — "What did I just fix?" header button opens a modal that
  diffs HIST_FILE snapshots to show reclaimed bytes, score delta, wired-mem
  delta, and translates each delta into plain-English felt symptoms
- **First-run scanning overlay** with progress bar so novices don't think
  the slow first scan means it's broken
- **`?`-tooltip** on every card title with a one-sentence plain-English
  explanation of what that card shows
- **Auto-warm caches** for the slow scans (organizer, duplicates, stale
  files, software updates) so the first dashboard load is under 1 second

### Fixed
- ThreadingHTTPServer instead of single-threaded HTTPServer — fixed the
  wedge where parallel API calls would block the queue
- 5-minute cache on `get_stale_files()`, 10-minute on duplicates, 30-minute
  on software updates
- File Organizer rows now stack vertically and use a responsive grid so
  the 5×5 cells are never clipped on narrow cards
- Stale Vendor Folders + Launch Agents tables wrapped in horizontal-scroll
  containers so the right-most columns are no longer cut off
- The Heal banner no longer shows a generic "thermal/power" CPU-throttle
  message — it now uses `diagnose_slowness()` to surface the real reason
  (worn battery, underpowered charger, thermal, memory exhaustion, or
  CPU-pinning process) with specific evidence

### Windows dashboard (experimental)
- `win_optimizer.py` v0.5 has the original health/process/cleanup features
  but lacks every v1.0 addition above. **Looking for a Windows tester** —
  please file a `[WINDOWS]` issue if you try it.
