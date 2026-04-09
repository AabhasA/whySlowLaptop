#!/bin/bash
# mac_slowdown_analyzer.sh — diagnose sudden macOS slowdowns
# Usage: bash mac_slowdown_analyzer.sh

set -u
BOLD=$(tput bold 2>/dev/null || echo "")
RESET=$(tput sgr0 2>/dev/null || echo "")
RED=$(tput setaf 1 2>/dev/null || echo "")
YEL=$(tput setaf 3 2>/dev/null || echo "")
GRN=$(tput setaf 2 2>/dev/null || echo "")
CYA=$(tput setaf 6 2>/dev/null || echo "")

section() { printf "\n${BOLD}${CYA}══ %s ══${RESET}\n" "$1"; }
warn()    { printf "${YEL}⚠  %s${RESET}\n" "$1"; }
bad()     { printf "${RED}✗  %s${RESET}\n" "$1"; }
ok()      { printf "${GRN}✓  %s${RESET}\n" "$1"; }

printf "${BOLD}Mac Slowdown Analyzer${RESET}  —  $(date)\n"
printf "Host: $(hostname)   macOS: $(sw_vers -productVersion)   Uptime: $(uptime | sed 's/.*up //;s/, load.*//')\n"

# ─────────────────────────────────────────────────────────────
section "1. CPU LOAD & TOP CPU PROCESSES"
load=$(sysctl -n vm.loadavg | awk '{print $2}')
cores=$(sysctl -n hw.ncpu)
printf "Load avg (1m): %s   Cores: %s\n" "$load" "$cores"
awk -v l="$load" -v c="$cores" 'BEGIN{ if (l+0 > c+0) exit 1 }' \
  && ok "Load is below core count" \
  || bad "Load exceeds CPU core count — system is CPU-saturated"

printf "\n${BOLD}Top 10 CPU consumers:${RESET}\n"
ps -Ao pid,pcpu,pmem,comm -r | head -n 11

# ─────────────────────────────────────────────────────────────
section "2. MEMORY PRESSURE & SWAP"
vm_stat | head -n 20
echo
swap=$(sysctl -n vm.swapusage 2>/dev/null)
printf "Swap: %s\n" "$swap"
swap_used=$(echo "$swap" | sed -n 's/.*used = \([0-9.]*\)M.*/\1/p')
if [ -n "$swap_used" ]; then
  awk -v s="$swap_used" 'BEGIN{ if (s+0 > 2000) exit 1 }' \
    && ok "Swap usage is reasonable" \
    || bad "Heavy swap usage (${swap_used}M) — RAM is overcommitted"
fi

mem_pressure=$(memory_pressure 2>/dev/null | tail -n 5)
echo "$mem_pressure"

printf "\n${BOLD}Top 10 memory consumers:${RESET}\n"
ps -Ao pid,pcpu,pmem,rss,comm -m | head -n 11

# ─────────────────────────────────────────────────────────────
section "3. DISK SPACE & I/O"
df -h / /System/Volumes/Data 2>/dev/null | grep -v "^map"
free_pct=$(df / | awk 'NR==2 {gsub("%","",$5); print 100-$5}')
if [ "$free_pct" -lt 10 ]; then
  bad "Less than 10% free disk space (${free_pct}% free) — this WILL slow you down"
elif [ "$free_pct" -lt 20 ]; then
  warn "Only ${free_pct}% disk free"
else
  ok "Disk space OK (${free_pct}% free)"
fi

printf "\n${BOLD}Disk I/O snapshot (5s sample):${RESET}\n"
iostat -d -w 1 -c 5 2>/dev/null | tail -n 7

# ─────────────────────────────────────────────────────────────
section "4. THERMAL / POWER THROTTLING"
if command -v pmset >/dev/null; then
  therm=$(pmset -g therm 2>/dev/null)
  echo "$therm"
  if echo "$therm" | grep -qE "CPU_Speed_Limit *= *[1-9][0-9]?$"; then
    bad "CPU is being thermally throttled"
  elif echo "$therm" | grep -q "CPU_Speed_Limit 	= 100"; then
    ok "No thermal throttling detected"
  fi
fi
pmset -g batt 2>/dev/null | head -n 3

# ─────────────────────────────────────────────────────────────
section "5. RECENTLY INSTALLED / MODIFIED APPS (last 7 days)"
printf "${BOLD}/Applications:${RESET}\n"
find /Applications -maxdepth 2 -name "*.app" -mtime -7 2>/dev/null | head -n 30 \
  || echo "(none)"

printf "\n${BOLD}~/Applications:${RESET}\n"
find ~/Applications -maxdepth 2 -name "*.app" -mtime -7 2>/dev/null | head -n 30
echo "(empty if no user-level apps)"

# ─────────────────────────────────────────────────────────────
section "6. LAUNCH AGENTS / DAEMONS (recently added — last 14 days)"
for d in \
  /Library/LaunchAgents \
  /Library/LaunchDaemons \
  ~/Library/LaunchAgents \
  /Library/StartupItems
do
  if [ -d "$d" ]; then
    recent=$(find "$d" -maxdepth 2 -type f -mtime -14 2>/dev/null)
    if [ -n "$recent" ]; then
      printf "${BOLD}%s${RESET}\n" "$d"
      echo "$recent"
      echo
    fi
  fi
done

# ─────────────────────────────────────────────────────────────
section "7. RUNNING LAUNCHD JOBS (top 15 by PID — newest)"
launchctl list 2>/dev/null | awk 'NR==1 || $1!="-"' | sort -rn | head -n 16

# ─────────────────────────────────────────────────────────────
section "8. LOGIN ITEMS"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null \
  || echo "(could not query — may need accessibility permission)"

# ─────────────────────────────────────────────────────────────
section "9. SPOTLIGHT INDEXING STATUS"
mdutil -s / 2>/dev/null
# active reindexing is a very common cause of sudden slowdowns
if mdutil -s / 2>/dev/null | grep -qi "Indexing enabled"; then
  if pgrep -x mds_stores >/dev/null; then
    cpu=$(ps -o %cpu= -p "$(pgrep -x mds_stores | head -1)" 2>/dev/null | tr -d ' ')
    if [ -n "$cpu" ] && awk -v c="$cpu" 'BEGIN{ exit !(c+0 > 30) }'; then
      bad "mds_stores is using ${cpu}% CPU — Spotlight is reindexing (often the culprit after updates)"
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────
section "10. TIME MACHINE / BACKUP ACTIVITY"
tmutil status 2>/dev/null | head -n 12

# ─────────────────────────────────────────────────────────────
section "11. WINDOWSERVER / KERNEL_TASK CHECK"
for proc in WindowServer kernel_task mds mds_stores mdworker_shared cloudd bird coreaudiod; do
  line=$(ps -Ao pid,pcpu,pmem,comm | awk -v p="$proc" '$4 ~ p {print; exit}')
  [ -n "$line" ] && printf "  %s\n" "$line"
done
warn "kernel_task hogging CPU is macOS's way of cooling — usually means thermal issue"

# ─────────────────────────────────────────────────────────────
section "12. NETWORK-HEAVY PROCESSES"
nettop -P -l 1 -n -k state,interface,bytes_in,bytes_out 2>/dev/null \
  | sort -k4 -rn | head -n 11 \
  || echo "(nettop unavailable)"

# ─────────────────────────────────────────────────────────────
section "13. RECENT KERNEL / SYSTEM LOG ERRORS (last 1h)"
log show --last 1h --predicate 'eventMessage CONTAINS "error" OR eventMessage CONTAINS "fail"' \
  --style compact 2>/dev/null | tail -n 20 \
  || echo "(log show unavailable)"

# ─────────────────────────────────────────────────────────────
section "SUMMARY HINTS"
cat <<'EOF'
Common sudden-slowdown causes to check above:
  • Spotlight reindexing (mds_stores high CPU)        → §1, §9
  • Time Machine running                              → §10
  • Disk almost full (<10–15% free)                   → §3
  • Memory pressure forcing swap                      → §2
  • Thermal throttling (kernel_task hot)              → §4, §11
  • Newly installed app / launch agent misbehaving    → §5, §6, §7
  • A single runaway process (browser tab, Electron)  → §1, §2
  • iCloud sync / cloudd / bird                       → §11
  • Background updates (softwareupdated)              → §1, §13

Next steps if a culprit is unclear:
  sudo fs_usage -w -f filesys | head        # who is hammering disk
  sudo opensnoop                            # who is opening files
  sudo powermetrics --samplers smc -n 1     # detailed thermal
EOF

printf "\n${BOLD}${GRN}Done.${RESET}\n"
