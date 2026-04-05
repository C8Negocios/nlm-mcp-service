# =============================================================================
# NLM Platform Service — Dockerfile
# Python 3.12 + notebooklm-mcp-cli + Admin UI (bookmarklet/extension auth)
# =============================================================================
FROM python:3.12-slim

# uv — Python package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Minimal system dependencies (no VNC/Chromium needed — auth via Chrome Extension)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN uv pip install --system \
    notebooklm-mcp-cli \
    "fastapi>=0.110" \
    "uvicorn[standard]>=0.29" \
    python-multipart \
    websockets

# Copy admin application
COPY admin/ ./admin/

# Persistent directory for NLM cookies and config
RUN mkdir -p /root/.notebooklm-mcp-cli

# Startup script — strip CRLF (Windows git checkout produces \r\n, Linux needs \n)
COPY start.sh ./start.sh
RUN sed -i 's/\r$//' ./start.sh && chmod +x ./start.sh

# 8080 = MCP Server (internal-only, no public domain)
# 3000 = Admin UI (public via Coolify/Traefik)
EXPOSE 8080 3000

CMD ["./start.sh"]
