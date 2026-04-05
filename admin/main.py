"""
NLM Admin API — FastAPI backend
Exposes browser-in-browser VNC auth: user just logs into Google, system auto-captures cookies.
"""

import asyncio
import os
import subprocess
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="NLM Auth Manager", docs_url=None, redoc_url=None)

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "c8club-nlm-admin")
NOVNC_DIR = Path("/usr/share/novnc")

# ── Auth Session State ─────────────────────────────────────────────────────────
_auth = {
    "status": "idle",       # idle | authenticating | authenticated | failed
    "account": None,
    "procs": [],
}


def _verify(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Acesso não autorizado")


def _kill_procs():
    for p in _auth["procs"]:
        try:
            p.terminate()
        except Exception:
            pass
    _auth["procs"].clear()


def _run_browser_auth():
    """Background thread: starts Xvfb + VNC + runs `nlm login` (auto mode)."""
    try:
        # 1. Virtual display
        xvfb = subprocess.Popen(
            ["Xvfb", ":99", "-screen", "0", "1280x900x24", "-ac"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _auth["procs"].append(xvfb)
        time.sleep(0.8)

        # 2. VNC server on the virtual display
        vnc = subprocess.Popen(
            ["x11vnc", "-display", ":99", "-forever", "-shared",
             "-rfbport", "5900", "-nopw", "-quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _auth["procs"].append(vnc)
        time.sleep(0.5)

        # 3. WebSocket proxy so browser can connect (port 6080 → VNC 5900)
        ws = subprocess.Popen(
            ["websockify", "6080", "localhost:5900"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _auth["procs"].append(ws)
        time.sleep(0.5)

        # 4. nlm login in auto mode — it opens Chromium on display :99
        #    User sees it via noVNC / WebSocket proxy in the admin page
        env = {**os.environ, "DISPLAY": ":99"}
        result = subprocess.run(
            ["nlm", "login"],
            env=env,
            timeout=300,  # 5 min timeout
        )

        if result.returncode == 0:
            _auth["status"] = "authenticated"
            # Try to extract account email
            check = subprocess.run(
                ["nlm", "login", "--check"],
                capture_output=True, text=True, timeout=10,
            )
            for line in (check.stdout + check.stderr).split("\n"):
                if "@" in line:
                    _auth["account"] = line.strip().split()[-1]
                    break
        else:
            _auth["status"] = "failed"

    except subprocess.TimeoutExpired:
        _auth["status"] = "failed"
    except Exception:
        _auth["status"] = "failed"
    finally:
        time.sleep(2)
        _kill_procs()


# ── API Endpoints ──────────────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status():
    """Current NLM auth status."""
    if _auth["status"] not in ("authenticating",):
        try:
            r = subprocess.run(
                ["nlm", "login", "--check"],
                capture_output=True, text=True, timeout=10,
            )
            out = r.stdout + r.stderr
            if r.returncode == 0 and "authenticated" in out.lower():
                _auth["status"] = "authenticated"
                for line in out.split("\n"):
                    if "@" in line and _auth["account"] is None:
                        _auth["account"] = line.strip().split()[-1]
        except Exception:
            pass
    return {"status": _auth["status"], "account": _auth["account"]}


@app.post("/api/start-auth")
async def start_auth(body: dict):
    """Start browser-based auth session (launches Chromium via VNC)."""
    _verify(body.get("secret", ""))

    if _auth["status"] == "authenticating":
        return {"started": True, "message": "Sessão de autenticação já em andamento"}

    _kill_procs()
    _auth["status"] = "authenticating"
    _auth["account"] = None

    threading.Thread(target=_run_browser_auth, daemon=True).start()
    await asyncio.sleep(2.0)  # Wait for processes to start

    return {"started": True}


@app.post("/api/cancel-auth")
async def cancel_auth(body: dict):
    """Cancel ongoing auth session."""
    _verify(body.get("secret", ""))
    _kill_procs()
    _auth["status"] = "idle"
    return {"cancelled": True}


# ── noVNC WebSocket Proxy ──────────────────────────────────────────────────────
# Proxies browser WebSocket → local websockify (port 6080) → x11vnc → display :99

@app.websocket("/ws-vnc")
async def vnc_proxy(ws: WebSocket):
    """WebSocket proxy: browser ↔ local websockify (VNC)."""
    import websockets as wslib

    await ws.accept(subprotocol="binary")
    try:
        async with wslib.connect(
            "ws://localhost:6080",
            subprotocols=["binary"],
            max_size=None,
        ) as upstream:
            async def up():
                try:
                    async for msg in ws.iter_bytes():
                        await upstream.send(msg)
                except Exception:
                    pass

            async def down():
                try:
                    async for msg in upstream:
                        if isinstance(msg, bytes):
                            await ws.send_bytes(msg)
                        else:
                            await ws.send_text(msg)
                except Exception:
                    pass

            done, pending = await asyncio.wait(
                [asyncio.create_task(up()), asyncio.create_task(down())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
    except Exception:
        pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass


@app.get("/health")
async def health():
    return {"status": "ok", "service": "nlm-admin"}


# ── Static Files ───────────────────────────────────────────────────────────────
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Serve noVNC JS client (needed for browser-in-browser VNC)
if NOVNC_DIR.exists():
    app.mount("/novnc", StaticFiles(directory=str(NOVNC_DIR)), name="novnc")


@app.get("/", response_class=HTMLResponse)
async def root():
    index = static_dir / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return HTMLResponse("<h1>NLM Admin</h1>")
