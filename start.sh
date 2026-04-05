#!/bin/bash
set -e

COOKIE_ENV_FILE="/root/.notebooklm-mcp-cli/cookie_env.txt"

# Load cookie string saved by admin after extension auth
if [ -f "$COOKIE_ENV_FILE" ]; then
    export NOTEBOOKLM_COOKIES=$(cat "$COOKIE_ENV_FILE")
    echo "[start.sh] NOTEBOOKLM_COOKIES loaded (${#NOTEBOOKLM_COOKIES} chars)"
fi

# Start MCP server in background — save PID so admin can restart it after re-auth
NOTEBOOKLM_MCP_TRANSPORT=http NOTEBOOKLM_MCP_PORT=8080 notebooklm-mcp &
echo $! > /tmp/nlm.pid
echo "[start.sh] notebooklm-mcp started (PID: $(cat /tmp/nlm.pid))"

# Admin UI in foreground (main container process)
exec uvicorn admin.main:app --host 0.0.0.0 --port 3000 --log-level info
