#!/bin/bash
#
# install_mac.command — double-click in Finder to install Mac Optimizer
# as a LaunchAgent that starts at login and keeps the dashboard running
# at http://localhost:8765.
#
# Re-running this safely reinstalls. To remove, run uninstall_mac.command.
#

set -e
cd "$(dirname "$0")"
HERE="$(pwd -P)"
OPTIMIZER="$HERE/mac_optimizer.py"
LABEL="com.aby.macoptimizer"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOGDIR="$HOME/Library/Logs/MacOptimizer"
PYTHON="$(/usr/bin/which python3 || echo /usr/bin/python3)"

echo ""
echo "  Mac Optimizer — installer"
echo "  ─────────────────────────"
echo "  optimizer : $OPTIMIZER"
echo "  python    : $PYTHON"
echo "  plist     : $PLIST"
echo "  logs      : $LOGDIR"
echo ""

if [ ! -f "$OPTIMIZER" ]; then
  echo "  ERROR: mac_optimizer.py not found next to this installer."
  echo "  Keep install_mac.command in the same folder as mac_optimizer.py."
  echo ""
  read -n 1 -s -r -p "Press any key to close…"
  exit 1
fi

mkdir -p "$LOGDIR"
mkdir -p "$HOME/Library/LaunchAgents"

# If already installed, unload first so we can rewrite cleanly.
if [ -f "$PLIST" ]; then
  echo "  Existing install found — reloading…"
  launchctl unload "$PLIST" 2>/dev/null || true
fi

cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON</string>
    <string>$OPTIMIZER</string>
    <string>--watch</string>
    <string>10</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$HERE</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOGDIR/stdout.log</string>
  <key>StandardErrorPath</key>
  <string>$LOGDIR/stderr.log</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
PLISTEOF

launchctl load "$PLIST"

# Give the server a moment, then open the dashboard.
sleep 1
open "http://localhost:8765" || true

echo ""
echo "  ✓ Installed. Mac Optimizer will now:"
echo "      • start automatically every time you log in"
echo "      • stay running in the background (auto-restart if it crashes)"
echo "      • take a snapshot every 10 minutes for trend tracking"
echo ""
echo "  Open the dashboard any time at:  http://localhost:8765"
echo "  Logs:                            $LOGDIR/"
echo "  Uninstall:                       double-click uninstall_mac.command"
echo ""
read -n 1 -s -r -p "Press any key to close…"
echo ""
