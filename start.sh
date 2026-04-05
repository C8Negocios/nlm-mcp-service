#!/bin/bash
set -e

echo "🚀 Starting NLM Platform Service..."

# Start MCP server in background (HTTP/SSE transport on port 8080)
echo "📡 Starting notebooklm-mcp server on port 8080..."
NOTEBOOKLM_MCP_TRANSPORT=http \
NOTEBOOKLM_MCP_PORT=8080 \
notebooklm-mcp &

MCP_PID=$!
echo "✅ MCP server started (PID: $MCP_PID)"

# Start Admin UI in foreground on port 3000
echo "🖥️  Starting Admin UI on port 3000..."
exec uvicorn admin.main:app --host 0.0.0.0 --port 3000 --log-level info
