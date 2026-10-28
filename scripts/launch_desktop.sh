#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
APP_NAME="${CODEX_APP_NAME:-Codex}"
URL="${CODEX_APP_SERVER_WS_URL:-ws://127.0.0.1:18765}"
CONNECT_TIMEOUT=30

usage() {
  cat <<'EOF'
Usage: launch_desktop.sh [--python PATH] [--app NAME_OR_PATH] [--url URL] [--connect-timeout SECONDS]

Checks the shared app-server, opens the Codex desktop app, and waits until the
desktop is verified on the loopback connection. It does not install packages,
stop existing processes, or start a second app-server.
EOF
}

while (($#)); do
  case "$1" in
    --python) PYTHON_BIN="$2"; shift 2 ;;
    --app) APP_NAME="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --connect-timeout) CONNECT_TIMEOUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if ! [[ "$CONNECT_TIMEOUT" =~ ^[0-9]+$ ]] || ((CONNECT_TIMEOUT < 1 || CONNECT_TIMEOUT > 120)); then
  echo '--connect-timeout must be between 1 and 120 seconds' >&2
  exit 2
fi
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python interpreter not found: $PYTHON_BIN" >&2
  exit 1
fi
if ! open -Ra "$APP_NAME" >/dev/null 2>&1; then
  echo "Codex desktop app not found: $APP_NAME (use --app with its .app path)" >&2
  exit 1
fi

"$PYTHON_BIN" -X utf8 -I -B "$SCRIPT_DIR/desktop.py" backend --url "$URL"

APP_PATTERN="${APP_NAME##*/}"
APP_PATTERN="${APP_PATTERN%.app}"
if pgrep -f "/${APP_PATTERN}.app/Contents/MacOS/" >/dev/null 2>&1; then
  echo 'Codex desktop is already running; refusing to start another instance.' >&2
  echo 'Quit it normally first if a reconnect is needed.' >&2
  exit 1
fi

open -a "$APP_NAME"
deadline=$((SECONDS + CONNECT_TIMEOUT))
last_report=''
while ((SECONDS < deadline)); do
  if last_report=$("$PYTHON_BIN" -X utf8 -I -B "$SCRIPT_DIR/desktop.py" doctor --url "$URL" 2>/dev/null); then
    printf '%s\n' "$last_report"
    echo 'Codex desktop connected.'
    exit 0
  fi
  sleep 1
done

echo 'Codex desktop connection was not verified before timeout.' >&2
if [[ -n "$last_report" ]]; then printf '%s\n' "$last_report" >&2; fi
exit 1
