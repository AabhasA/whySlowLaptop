#!/bin/bash
#
# uninstall_mac.command — double-click in Finder to remove the Mac Optimizer
# LaunchAgent and stop the background service.
#
# This does NOT delete mac_optimizer.py itself or the snapshot history file.
#

set -e
LABEL="com.aby.macoptimizer"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

echo ""
echo "  Mac Optimizer — uninstaller"
echo "  ───────────────────────────"

if [ -f "$PLIST" ]; then
  launchctl unload "$PLIST" 2>/dev/null || true
  rm "$PLIST"
  echo "  ✓ LaunchAgent removed:  $PLIST"
else
  echo "  (no LaunchAgent installed)"
fi

# Best-effort kill of any leftover dashboard process on the standard port
PIDS="$(lsof -t -iTCP:8765 -sTCP:LISTEN 2>/dev/null || true)"
if [ -n "$PIDS" ]; then
  kill $PIDS 2>/dev/null || true
  echo "  ✓ Stopped dashboard process(es): $PIDS"
fi

echo ""
echo "  Mac Optimizer will no longer start at login."
echo "  mac_optimizer.py and your snapshot history are still on disk."
echo ""
read -n 1 -s -r -p "Press any key to close…"
echo ""
