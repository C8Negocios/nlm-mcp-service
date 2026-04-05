#!/bin/bash
set -e

COOKIE_ENV_FILE="/root/.notebooklm-mcp-cli/cookie_env.txt"
CHROME_PROFILE="/root/.notebooklm-mcp-cli/chrome-profiles/default"
DISPLAY_NUM=99

echo "[start.sh] Starting NLM Platform Service..."

# ── 1. Virtual display (Xvfb) ─────────────────────────────────────────────────
Xvfb :${DISPLAY_NUM} -screen 0 1366x768x24 -ac +extension GLX &
export DISPLAY=:${DISPLAY_NUM}
echo "[start.sh] Xvfb started on :${DISPLAY_NUM}"
sleep 1

# ── 2. Chromium (hidden, only used for auth sessions) ─────────────────────────
chromium \
    --display=:${DISPLAY_NUM} \
    --no-sandbox \
    --disable-dev-shm-usage \
    --disable-gpu \
    --user-data-dir="${CHROME_PROFILE}" \
    --window-size=1366,768 \
    --start-maximized \
    "https://notebooklm.google.com" &
echo "[start.sh] Chromium started"
sleep 2

# ── 3. VNC server — exposes the virtual display ───────────────────────────────
x11vnc -display :${DISPLAY_NUM} -nopw -listen localhost -xkb -ncache 10 -ncache_cr -forever &
echo "[start.sh] x11vnc started"
sleep 1

# ── 4. WebSocket proxy — noVNC connects via ws://host:6080 ────────────────────
websockify --web /usr/share/novnc 6080 localhost:5900 &
echo "[start.sh] noVNC WebSocket proxy on :6080"

# ── 5. notebooklm-mcp server ──────────────────────────────────────────────────
if [ -f "$COOKIE_ENV_FILE" ]; then
    export NOTEBOOKLM_COOKIES=$(cat "$COOKIE_ENV_FILE")
    echo "[start.sh] NOTEBOOKLM_COOKIES loaded (${#NOTEBOOKLM_COOKIES} chars)"
fi

NOTEBOOKLM_MCP_TRANSPORT=http NOTEBOOKLM_MCP_PORT=8080 notebooklm-mcp &
echo $! > /tmp/nlm.pid
echo "[start.sh] notebooklm-mcp started (PID: $(cat /tmp/nlm.pid))"

# ── 6. Admin UI (foreground — main container process) ─────────────────────────
exec uvicorn admin.main:app --host 0.0.0.0 --port 3000 --log-level info
