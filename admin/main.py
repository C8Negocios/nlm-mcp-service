"""
NLM Admin API — FastAPI backend
Browser-in-browser VNC auth: Chromium inicia explicitamente com --no-sandbox (obrigatório em Docker)
VNC permanece ativo durante todo o fluxo de login.
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

app = FastAPI(title="NLM Auth Manager", docs_url=None, redoc_url=None)

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "c8club-nlm-admin")
NOVNC_DIR = Path("/usr/share/novnc")

# ── Auth Session State ─────────────────────────────────────────────────────────
_auth = {
    "status": "idle",       # idle | authenticating | authenticated | failed
    "account": None,
    "procs": {},            # name → Popen (named for selective management)
}


def _verify(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Acesso não autorizado")


def _kill_all():
    """Kill all background processes."""
    for name, proc in list(_auth["procs"].items()):
        try:
            proc.terminate()
        except Exception:
            pass
    _auth["procs"].clear()


def _kill_nlm_only():
    """Kill only the nlm login process, keeping VNC alive."""
    proc = _auth["procs"].pop("nlm", None)
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass


def _run_browser_auth():
    """
    Background thread:
    1. Starts Xvfb virtual display
    2. Starts x11vnc + websockify (VNC stack — stays alive during entire flow)
    3. Starts Chromium with --no-sandbox + CDP on port 9222
    4. Runs `nlm login --provider openclaw --cdp-url http://localhost:9222`
    5. VNC only dies after auth confirmed OR explicit cancel
    """
    env = {**os.environ, "DISPLAY": ":99"}

    try:
        # 1. Virtual display
        xvfb = subprocess.Popen(
            ["Xvfb", ":99", "-screen", "0", "1280x900x24", "-ac"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _auth["procs"]["xvfb"] = xvfb
        time.sleep(1.0)

        # 2. x11vnc — stays alive regardless of Chromium/nlm state
        vnc = subprocess.Popen(
            ["x11vnc", "-display", ":99", "-forever", "-shared",
             "-rfbport", "5900", "-nopw", "-quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _auth["procs"]["vnc"] = vnc
        time.sleep(0.5)

        # 3. Websockify — WebSocket → VNC bridge
        ws = subprocess.Popen(
            ["websockify", "6080", "localhost:5900"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _auth["procs"]["ws"] = ws
        time.sleep(0.5)

        # 4. Chromium with --no-sandbox (REQUIRED in Docker containers)
        #    CDP on port 9222 so nlm login can connect
        chromium = subprocess.Popen(
            [
                "chromium",
                "--no-sandbox",                      # Required in Docker
                "--disable-dev-shm-usage",           # Required in Docker (small /dev/shm)
                "--no-first-run",
                "--disable-sync",
                "--disable-default-apps",
                "--disable-extensions",
                "--disable-background-networking",
                "--remote-debugging-port=9222",
                "--remote-debugging-address=127.0.0.1",
                "--window-size=1280,900",
                "--start-maximized",
                "https://notebooklm.google.com",
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _auth["procs"]["chromium"] = chromium
        time.sleep(8.0)  # Chromium needs more time in Docker containers

        # 5. Wait for Chromium CDP to be actually accessible before calling nlm
        import urllib.request
        cdp_ready = False
        for attempt in range(20):  # up to 20s
            try:
                urllib.request.urlopen("http://localhost:9222/json", timeout=1)
                cdp_ready = True
                break
            except Exception:
                time.sleep(1)

        if not cdp_ready:
            _auth["status"] = "failed"
            return

        # 6. nlm login monitors our Chromium via CDP (auto mode with DISPLAY already set)
        #    Do NOT use --provider openclaw — that starts its own Chromium and conflicts
        nlm = subprocess.Popen(
            ["nlm", "login"],  # pure auto mode — uses DISPLAY :99 (our Chromium is there)
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _auth["procs"]["nlm"] = nlm

        # Wait for nlm to complete (max 5 min)
        try:
            stdout, stderr = nlm.communicate(timeout=300)
            output = stdout.decode() + stderr.decode()

            if nlm.returncode == 0:
                _auth["status"] = "authenticated"
                # Extract account email
                for line in output.split("\n"):
                    if "@" in line:
                        _auth["account"] = line.strip().split()[-1]
                        break
            else:
                _auth["status"] = "failed"

        except subprocess.TimeoutExpired:
            nlm.kill()
            _auth["status"] = "failed"

    except Exception as e:
        _auth["status"] = "failed"
    finally:
        # Keep VNC alive 5 more seconds so user sees result
        time.sleep(5)
        _kill_all()


# ── Fallback: nlm login auto mode (if CDP not available) ──────────────────────

def _run_browser_auth_automode():
    """Fallback: nlm login auto mode with DISPLAY set (no CDP)."""
    env = {**os.environ, "DISPLAY": ":99"}
    try:
        xvfb = subprocess.Popen(
            ["Xvfb", ":99", "-screen", "0", "1280x900x24", "-ac"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _auth["procs"]["xvfb"] = xvfb
        time.sleep(1.0)

        vnc = subprocess.Popen(
            ["x11vnc", "-display", ":99", "-forever", "-shared",
             "-rfbport", "5900", "-nopw", "-quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _auth["procs"]["vnc"] = vnc
        time.sleep(0.5)

        ws = subprocess.Popen(
            ["websockify", "6080", "localhost:5900"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _auth["procs"]["ws"] = ws
        time.sleep(0.5)

        # nlm login auto mode — opens its own Chromium on the display
        nlm = subprocess.Popen(
            ["nlm", "login"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _auth["procs"]["nlm"] = nlm

        try:
            stdout, stderr = nlm.communicate(timeout=300)
            _auth["status"] = "authenticated" if nlm.returncode == 0 else "failed"
        except subprocess.TimeoutExpired:
            nlm.kill()
            _auth["status"] = "failed"
    except Exception:
        _auth["status"] = "failed"
    finally:
        time.sleep(5)
        _kill_all()


# ── API Endpoints ──────────────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status():
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
    _verify(body.get("secret", ""))

    if _auth["status"] == "authenticating":
        return {"started": True, "message": "Sessão já em andamento"}

    _kill_all()
    _auth["status"] = "authenticating"
    _auth["account"] = None

    # Use CDP mode (Chromium with --no-sandbox) — more reliable in Docker
    threading.Thread(target=_run_browser_auth, daemon=True).start()
    await asyncio.sleep(2.5)  # Wait for VNC stack to start before returning

    return {"started": True}


@app.post("/api/cancel-auth")
async def cancel_auth(body: dict):
    _verify(body.get("secret", ""))
    _kill_all()
    _auth["status"] = "idle"
    return {"cancelled": True}


# ── noVNC WebSocket Proxy ──────────────────────────────────────────────────────

@app.websocket("/ws-vnc")
async def vnc_proxy(ws: WebSocket):
    """Bidirectional WebSocket proxy: browser ↔ local websockify (port 6080)."""
    import websockets as wslib

    await ws.accept(subprotocol="binary")
    try:
        async with wslib.connect(
            "ws://localhost:6080",
            subprotocols=["binary"],
            max_size=None,
            ping_interval=20,
            ping_timeout=10,
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

if NOVNC_DIR.exists():
    app.mount("/novnc", StaticFiles(directory=str(NOVNC_DIR)), name="novnc")


@app.get("/", response_class=HTMLResponse)
async def root():
    index = static_dir / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return HTMLResponse("<h1>NLM Admin</h1>")
