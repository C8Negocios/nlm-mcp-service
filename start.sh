#!/bin/bash
set -e

COOKIE_ENV_FILE="/root/.notebooklm-mcp-cli/cookie_env.txt"
DISPLAY_NUM=99

echo "[start.sh] Starting NLM Platform Service..."

# ── 1. Virtual display (Xvfb) — permanente, para o nlm login usar ─────────────
Xvfb :${DISPLAY_NUM} -screen 0 1366x768x24 -ac &
export DISPLAY=:${DISPLAY_NUM}
echo "[start.sh] Xvfb :${DISPLAY_NUM} started"
sleep 1

# Grey background + xterm so VNC shows something visible immediately
xsetroot -solid "#1a1a2e" &
xterm -geometry 120x30+0+0 -e "echo 'NLM Platform - Pronto. Use a UI para fazer login.' && sleep infinity" &

# ── 2. VNC server over the virtual display ────────────────────────────────────
x11vnc -display :${DISPLAY_NUM} -nopw -listen localhost -xkb -forever -shared -bg
echo "[start.sh] x11vnc started on :5900"
sleep 1

# ── 3. WebSocket proxy (pip websockify) — admin proxies at /ws-vnc ─────────────
python3 -m websockify 6081 localhost:5900 &
echo "[start.sh] websockify started on :6081"

# NOTE: Chromium is NOT started here.
# The 'nlm login' command (launched via /api/run-nlm-login) starts its own
# Chrome instance with the correct flags for the automation flow.
# It will appear on the VNC display above when invoked.

# ── 4. notebooklm-mcp server ──────────────────────────────────────────────────
if [ -f "$COOKIE_ENV_FILE" ]; then
    export NOTEBOOKLM_COOKIES=$(cat "$COOKIE_ENV_FILE")
    echo "[start.sh] NOTEBOOKLM_COOKIES loaded (${#NOTEBOOKLM_COOKIES} chars)"
fi

NOTEBOOKLM_MCP_TRANSPORT=http NOTEBOOKLM_MCP_PORT=8080 notebooklm-mcp &
echo $! > /tmp/nlm.pid
echo "[start.sh] notebooklm-mcp started (PID: $(cat /tmp/nlm.pid))"

# ── 5. Admin UI (foreground — main container process) ─────────────────────────
exec uvicorn admin.main:app --host 0.0.0.0 --port 3000 --log-level info
