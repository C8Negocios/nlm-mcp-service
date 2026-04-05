# =============================================================================
# NLM Platform Service — Dockerfile
# Python 3.12 + notebooklm-mcp-cli + Admin UI
# Auth: Browser-in-browser (Chromium + Xvfb + noVNC) — operator logs in once,
#       nlm auto-refreshes headlessly for 2-4 weeks.
# =============================================================================
FROM python:3.12-slim

# uv — Python package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# System dependencies: Chromium + Xvfb + VNC stack
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Browser
    chromium \
    chromium-driver \
    # Virtual display
    xvfb \
    # VNC server
    x11vnc \
    # X11 utilities (xsetroot for background, xterm for fallback)
    x11-utils \
    xterm \
    # Misc
    curl \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Download noVNC HTML5 client (v1.5.0) into /usr/share/novnc
RUN mkdir -p /usr/share/novnc \
    && curl -fsSL https://github.com/novnc/noVNC/archive/refs/tags/v1.5.0.tar.gz \
    | tar -xz --strip-components=1 -C /usr/share/novnc

# Install Python packages (websockify via pip — avoids apt package web-dir bug)
RUN uv pip install --system \
    notebooklm-mcp-cli \
    "fastapi>=0.110" \
    "uvicorn[standard]>=0.29" \
    python-multipart \
    websockets \
    websockify \
    "httpx>=0.27"

# Copy admin application (includes noVNC static files)
COPY admin/ ./admin/

# Persistent directory for NLM cookies, config and Chrome profile
RUN mkdir -p /root/.notebooklm-mcp-cli/chrome-profiles/default

# Startup script — strip CRLF (Windows line endings → Linux)
COPY start.sh ./start.sh
RUN sed -i 's/\r$//' ./start.sh && chmod +x ./start.sh

# 8080 = MCP Server (internal Docker network only)
# 3000 = Admin UI (public via Coolify/Traefik)
# 5900 = VNC (internal only, accessed via noVNC WebSocket proxy on 6080)
EXPOSE 8080 3000

CMD ["./start.sh"]
