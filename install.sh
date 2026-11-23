#!/usr/bin/env bash
# Neuro-Wolf worker: one-time setup on Linux or macOS.
#   curl -fsSL https://raw.githubusercontent.com/ori-liloss/neuro-wolf-worker/main/install.sh | bash -s 2
# Downloads the repo once to ~/neuro-wolf-worker, starts the work now, and starts it again by itself after every
# restart (launchd on macOS, cron @reboot or a systemd user service on Linux). Each start does `git pull` first.
set -euo pipefail
SHARE="${1:?usage: install.sh SHARE (1, 2 or 3)}"
case "$SHARE" in 1|2|3) ;; *) echo "share must be 1, 2 or 3"; exit 1 ;; esac
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"
DIR="$HOME/neuro-wolf-worker"
command -v git >/dev/null || { echo "git is not installed (macOS: xcode-select --install, Linux: sudo apt install git)"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is not installed"; exit 1; }
if [ -d "$DIR/.git" ]; then
  echo "already downloaded: $DIR (updating)"
  git -C "$DIR" pull --ff-only
else
  git clone https://github.com/ori-liloss/neuro-wolf-worker.git "$DIR"
fi
START="bash $DIR/start.sh $SHARE"
if [ "$(uname -s)" = Darwin ]; then
  PLIST="$HOME/Library/LaunchAgents/com.neuro.wolf-worker.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.neuro.wolf-worker</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$DIR/start.sh</string><string>$SHARE</string></array>
  <key>RunAtLoad</key><true/>
  <key>AbandonProcessGroup</key><true/>
  <key>StandardOutPath</key><string>/tmp/neuro-wolf-worker.out</string>
  <key>StandardErrorPath</key><string>/tmp/neuro-wolf-worker.err</string>
</dict></plist>
EOF
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST"   # RunAtLoad: this also starts the work now
  echo "autostart: $PLIST"
else
  if command -v crontab >/dev/null; then
    ( crontab -l 2>/dev/null | grep -v 'neuro-wolf-worker/start.sh' || true; echo "@reboot $START" ) | crontab -
    echo "autostart: cron @reboot"
  elif command -v systemctl >/dev/null; then
    mkdir -p "$HOME/.config/systemd/user"
    cat > "$HOME/.config/systemd/user/neuro-wolf-worker.service" <<EOF
[Unit]
Description=Neuro-Wolf worker
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $DIR/start.sh $SHARE
[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload && systemctl --user enable neuro-wolf-worker.service
    loginctl enable-linger "$USER" 2>/dev/null || true
    echo "autostart: systemd user service"
  else
    echo "no cron or systemd: run '$START' after a restart yourself"
  fi
  bash "$DIR/start.sh" "$SHARE"
fi
echo "installed: share $SHARE starts after every restart (git pull first). Status of this start is above (RUNNING or FAILED); full log: $DIR/out/start.log"
