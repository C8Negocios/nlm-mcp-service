"""
NLM Admin API — FastAPI backend
Auth flow: operator opens UI → clicks "Iniciar Login" → sees Chrome via noVNC →
           logs into notebooklm.google.com from the SERVER's browser →
           clicks "Confirmar Login" → nlm captures server-side session → done.
Auto-refresh via headless Chrome for 2-4 weeks.
"""

import asyncio
import io
import json
import os
import subprocess
import time
import zipfile
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="NLM Auth Manager", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_SECRET   = os.getenv("ADMIN_SECRET", "c8club-nlm-admin")
COOKIES_DIR    = Path("/root/.notebooklm-mcp-cli")
COOKIES_FILE   = COOKIES_DIR / "cookies.txt"
COOKIE_ENV     = COOKIES_DIR / "cookie_env.txt"
CHROME_PROFILE = COOKIES_DIR / "chrome-profiles/default"
STATIC_DIR     = Path(__file__).parent / "static"
EXTENSION_DIR  = STATIC_DIR / "extension"

_auth   = {"status": "idle", "account": None, "cookie_count": 0, "source": None}
_login  = {"running": False, "pid": None, "started_at": None}


def _verify(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Acesso nao autorizado")


def _write_nlm_profile(cookie_dict: dict) -> tuple[bool, str]:
    """Write cookies directly to nlm's profile JSON — no subprocess needed."""
    try:
        try:
            from notebooklm_tools.utils.config import get_profile_dir  # type: ignore
            profile_dir = get_profile_dir("default")
        except Exception:
            profile_dir = COOKIES_DIR / "profiles" / "default"

        profile_dir.mkdir(parents=True, exist_ok=True)
        profile_dir.chmod(0o700)

        (profile_dir / "cookies.json").write_text(
            json.dumps(cookie_dict, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (profile_dir / "cookies.json").chmod(0o600)

        (profile_dir / "metadata.json").write_text(
            json.dumps({
                "last_validated": datetime.now().isoformat(),
                "email": None, "csrf_token": None, "session_id": None,
            }, indent=2),
            encoding="utf-8"
        )
        (profile_dir / "metadata.json").chmod(0o600)
        return True, str(profile_dir / "cookies.json")
    except Exception as e:
        return False, str(e)


# ── Status ─────────────────────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status():
    # Check if nlm profile exists (server-side Chrome login done)
    try:
        from notebooklm_tools.utils.config import get_profile_dir  # type: ignore
        profile_dir = get_profile_dir("default")
    except Exception:
        profile_dir = COOKIES_DIR / "profiles" / "default"

    profile_exists = (profile_dir / "cookies.json").exists()

    if profile_exists:
        _auth["status"] = "authenticated"
    elif COOKIES_FILE.exists() and COOKIES_FILE.stat().st_size > 50:
        _auth["status"] = "authenticated"

    return {
        "status": _auth["status"],
        "account": _auth["account"],
        "cookie_count": _auth.get("cookie_count", 0),
        "source": _auth.get("source"),
        "profile_exists": profile_exists,
        "login_running": _login["running"],
    }


# ── Server-side browser login ──────────────────────────────────────────────────

@app.post("/api/run-nlm-login")
async def run_nlm_login(body: dict):
    """
    Triggers 'nlm login' inside the container.
    The operator sees the server's Chrome via noVNC, logs into NotebookLM.
    nlm detects the login and saves the server-side session profile.
    """
    _verify(body.get("secret", ""))

    if _login["running"]:
        return {"message": "Login ja em andamento. Use o browser ao lado para logar.", "running": True}

    try:
        proc = subprocess.Popen(
            ["nlm", "login"],
            env={**os.environ, "DISPLAY": ":99"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        _login["running"] = True
        _login["pid"] = proc.pid
        _login["started_at"] = datetime.now().isoformat()

        return {
            "message": f"Login iniciado (PID {proc.pid}). Faca login no browser ao lado.",
            "running": True,
            "pid": proc.pid
        }
    except Exception as e:
        return {"message": f"Erro: {e}", "running": False}


@app.get("/api/login-status")
async def login_status():
    """Check if nlm login process is still running."""
    if _login["pid"]:
        try:
            os.kill(_login["pid"], 0)  # Check if process exists
            running = True
        except ProcessLookupError:
            running = False
            _login["running"] = False

        # Check if profile was created
        try:
            from notebooklm_tools.utils.config import get_profile_dir  # type: ignore
            profile_dir = get_profile_dir("default")
        except Exception:
            profile_dir = COOKIES_DIR / "profiles" / "default"

        profile_done = (profile_dir / "cookies.json").exists()
        if profile_done:
            _auth["status"] = "authenticated"
            _login["running"] = False

        return {
            "running": running,
            "pid": _login["pid"],
            "profile_created": profile_done,
            "started_at": _login.get("started_at"),
        }
    return {"running": False, "pid": None, "profile_created": False}


# ── Fallback: Chrome Extension cookie injection (keeps backward compat) ────────

@app.post("/api/auth-bookmarklet")
async def auth_bookmarklet(body: dict):
    """Fallback: receive cookies from Chrome Extension. Less reliable than browser login."""
    _verify(body.get("secret", ""))

    source         = body.get("source", "bookmarklet")
    cookie_objects = body.get("cookies", [])
    cookie_string  = body.get("cookies_string", "")

    if isinstance(cookie_objects, str):
        cookie_string  = cookie_objects
        cookie_objects = []

    if not cookie_objects and not cookie_string:
        raise HTTPException(status_code=400, detail="Nenhum cookie recebido")

    COOKIES_DIR.mkdir(parents=True, exist_ok=True)

    try:
        lines       = ["# Netscape HTTP Cookie File", "# C8Club NLM Admin"]
        expiry_far  = int(time.time()) + (86400 * 365)
        count       = 0
        cookie_pairs = []

        if cookie_objects and isinstance(cookie_objects, list):
            for c in cookie_objects:
                if not isinstance(c, dict) or not c.get("name"):
                    continue
                name   = c.get("name", "")
                value  = c.get("value", "")
                domain = c.get("domain", ".google.com")
                path   = c.get("path", "/")
                secure = "TRUE" if c.get("secure", False) else "FALSE"
                expiry = int(c.get("expirationDate", expiry_far))
                if not domain.startswith("."):
                    domain = "." + domain
                lines.append(f"{domain}\tTRUE\t{path}\t{secure}\t{expiry}\t{name}\t{value}")
                cookie_pairs.append(f"{name}={value}")
                count += 1
        elif cookie_string:
            for part in cookie_string.split(";"):
                part = part.strip()
                if "=" in part:
                    key, _, val = part.partition("=")
                    key, val = key.strip(), val.strip()
                    lines.append(f".google.com\tTRUE\t/\tFALSE\t{expiry_far}\t{key}\t{val}")
                    cookie_pairs.append(f"{key}={val}")
                    count += 1

        cookie_header = "; ".join(cookie_pairs)
        cookie_dict   = dict(pair.split("=", 1) for pair in cookie_pairs if "=" in pair)

        COOKIES_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        COOKIE_ENV.write_text(cookie_header, encoding="utf-8")
        ok, info = _write_nlm_profile(cookie_dict)

        _auth["status"]       = "authenticated"
        _auth["cookie_count"] = count
        _auth["source"]       = source

        return {
            "message": f"OK {count} cookies via extensao. Nota: pode falhar por validacao Google IP.",
            "count": count,
            "source": source,
            "nlm_ok": ok
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro: {str(e)}")


# ── Extension ZIP ──────────────────────────────────────────────────────────────

@app.get("/api/extension.zip")
async def download_extension():
    if not EXTENSION_DIR.exists():
        raise HTTPException(status_code=404, detail="Extension not found")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in EXTENSION_DIR.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(EXTENSION_DIR))
    buf.seek(0)
    return StreamingResponse(
        buf, media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=nlm-c8club-auth-extension.zip"},
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def root():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return HTMLResponse("<h1>NLM Admin</h1>")
