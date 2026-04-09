# comp1 — where we left off (2026-04-09)

## What's in this folder

| File | What it is |
|---|---|
| `mac_optimizer.py` | The macOS dashboard. Run with `python3 mac_optimizer.py --watch 10`. Opens at http://localhost:8765. |
| `win_optimizer.py` | The Windows version (same UX, Windows-specific internals). |
| `install_mac.command` | **Double-click in Finder** to install the LaunchAgent so the dashboard auto-starts on every login. |
| `uninstall_mac.command` | Double-click to remove the LaunchAgent. |
| `mac_slowdown_analyzer.sh` | Original shell-script analyzer (kept around). |

## What we built / fixed in the last session

- **Process Inspector** — replaces "Top Processes". Each process gets a friendly name, plain-English explanation, harm score (0–100, banded idle/noticeable/heavy/severe), and a verdict (`safe`/`caution`/`never`). Kill button is colour-coded and disabled for `never`-kill processes.
- **Heal banner** at the top — single-pane recommendations in plain English, severity-sorted, with one-click action buttons.
- **Filtering**: Process Inspector hides idle processes, hides itself (own PID), hides Chrome from "unused apps" (uses Spotlight `kMDItemLastUsedDate` instead of broken filesystem mtime), and Recurring Offenders ignores browsers/terminals/AI CLIs.
- **Buttons that actually work**: Trash on `/Applications` apps now uses an admin-shell-script fallback (password prompt instead of silent failure). Launch Agents got a Remove button. All buttons fade their row out immediately on success and re-enable on failure.
- **Header fixes**: "6 users" tty count removed; CPU Speed Limit now shows green at 100% with "(no throttling)" instead of red.
- **No more SyntaxErrors** in button onclicks — all four button types use named JS helpers that take `this` and pass values via `JSON.stringify`, eliminating quote-injection bugs.

## The actual lead — `mediaanalysisd`

After tightening the Recurring Offenders thresholds, **only one entry remains**:

> `mediaanalysisd` — 8 appearances, 94.3% avg CPU, 167% peak

That's Apple's Photos library analyzer (face recognition, scene tagging, Memories). On older Macs it can pin a core for days and is the most likely cause of the 3.2 GB wired-memory bloat we saw. After the reboot, watch the Process Inspector for ~15 minutes — if it reappears, let Photos finish analyzing (open the app, plug in, leave it idle for a few hours).

## What to do after the full shutdown

1. **Power on. Open a terminal once.**
2. **Pick one:**
   - **One-time setup (recommended):** double-click `install_mac.command` in Finder. macOS will say "unidentified developer" — right-click → Open → Open. After this, the dashboard auto-starts on every login forever and you never have to think about it again.
   - **Or just for now:** `python3 ~/Cursor/comp1/mac_optimizer.py --watch 10` from a Terminal.
3. **Open http://localhost:8765** and check:
   - **Wired Memory** in the Health card — should be well under 2 GB now (was 3.2 GB pre-shutdown). If it dropped, the leak source was something that auto-launched and the shutdown cleared it.
   - **Security Audit** — `com.expressvpn.expressvpnd` should be gone if you clicked Remove on it before shutting down.
   - **Process Inspector** — should be short (3–6 entries max) and "all calm" if nothing's wrong.
   - **Recurring Offenders** — empty after a fresh boot until the watcher has time to gather snapshots. Check back in ~30 min.

## How to talk to me when you're back

Just say "back from reboot" or paste a screenshot. The full session state is saved in my memory and in this file — I'll know exactly where we left off.

## Things still on the backlog (not blocking)

- `install_win.bat` equivalent for Windows (Task Scheduler entry).
- Per-process "explain in detail" expand button (long-form info for the curious).
- A `git init` here so we can actually track changes.
