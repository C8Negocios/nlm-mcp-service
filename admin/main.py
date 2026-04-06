"""
NLM Admin API — FastAPI backend
Auth flow: operator opens UI → clicks "Iniciar Login" → sees Chrome via noVNC →
           logs into notebooklm.google.com from the SERVER's browser →
           clicks "Confirmar Login" → nlm captures server-side session → done.
Auto-refresh via headless Chrome for 2-4 weeks.

MCP Proxy Layer:
  POST /api/source-add   → adiciona source de texto num notebook via MCP
  GET  /api/notebooks    → lista notebooks disponíveis via MCP
  GET  /api/mcp-status   → verifica se MCP está acessível
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

import httpx

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
import websockets
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

# ── Typeform RaioX Sync config ──────────────────────────────────────────────
TYPEFORM_TOKEN    = os.getenv("TYPEFORM_TOKEN", "")
RAIOX_NOTEBOOK_ID = os.getenv("RAIOX_NOTEBOOK_ID", "ee79cded-aaae-4efc-84b0-3d417fa6597d")
SYNC_STATE_FILE   = COOKIES_DIR / "raiox_sync.json"
RAIOX_SYNC_INTERVAL = int(os.getenv("RAIOX_SYNC_INTERVAL_SECONDS", "300"))  # 5 min default

_auth   = {"status": "idle", "account": None, "cookie_count": 0, "source": None}
_login  = {"running": False, "pid": None, "started_at": None}
_raiox_sync_state = {
    "running": False,
    "last_sync": None,
    "total_synced": 0,
    "last_error": None,
    "forms_found": 0,
}


def _verify(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Acesso nao autorizado")


def _write_nlm_profile(cookie_objects: list, email: str | None = None) -> tuple[bool, str]:
    """
    Write cookies to nlm profile in the Playwright LIST format that
    notebooklm-mcp-cli expects. The format is:
      [{"name": ..., "value": ..., "domain": ..., "path": ...,
        "expires": ..., "httpOnly": ..., "secure": ..., "sameSite": "None"}]
    """
    try:
        try:
            from notebooklm_tools.utils.config import get_profile_dir  # type: ignore
            profile_dir = get_profile_dir("default")
        except Exception:
            profile_dir = COOKIES_DIR / "profiles" / "default"

        profile_dir.mkdir(parents=True, exist_ok=True)
        profile_dir.chmod(0o700)

        expiry_far = int(time.time()) + (86400 * 365)

        # Chrome → Playwright sameSite mapping
        SAME_SITE_MAP = {
            "no_restriction": "None",
            "lax":            "Lax",
            "strict":         "Strict",
            "unspecified":    "None",
        }

        # Build Playwright-format cookie list
        playwright_cookies = []
        for c in cookie_objects:
            if not isinstance(c, dict) or not c.get("name"):
                continue
            chrome_ss = (c.get("sameSite") or "no_restriction").lower()
            playwright_cookies.append({
                "name":     c.get("name", ""),
                "value":    c.get("value", ""),
                "domain":   c.get("domain", ".google.com"),
                "path":     c.get("path", "/"),
                "expires":  float(c.get("expirationDate", expiry_far)),
                "httpOnly": bool(c.get("httpOnly", False)),
                "secure":   bool(c.get("secure", True)),
                "sameSite": SAME_SITE_MAP.get(chrome_ss, "None"),
            })

        (profile_dir / "cookies.json").write_text(
            json.dumps(playwright_cookies, ensure_ascii=False), encoding="utf-8"
        )
        (profile_dir / "cookies.json").chmod(0o600)

        (profile_dir / "metadata.json").write_text(
            json.dumps({
                "last_validated": datetime.now().isoformat(),
                "email":       email,
                "csrf_token":  None,
                "session_id":  None,
                "build_label": "manual-auth",
            }, indent=2),
            encoding="utf-8"
        )
        (profile_dir / "metadata.json").chmod(0o600)
        return True, str(profile_dir / "cookies.json")
    except Exception as e:
        return False, str(e)


def _restart_mcp() -> bool:
    """Kill existing MCP process and restart it so it picks up new cookies."""
    try:
        # Kill running MCP instances
        subprocess.run(["pkill", "-f", "notebooklm-mcp"], capture_output=True)
        time.sleep(2)
        # Restart MCP in background
        proc = subprocess.Popen(
            ["notebooklm-mcp"],
            env={**os.environ,
                 "NOTEBOOKLM_MCP_TRANSPORT": "http",
                 "NOTEBOOKLM_MCP_PORT": "8080"},
            stdout=open("/tmp/mcp_restart.log", "w"),
            stderr=subprocess.STDOUT,
        )
        # Reset in-memory MCP session state
        _mcp_session["id"] = None
        _mcp_session["initialized"] = False
        time.sleep(3)
        logger.info(f"[MCP] Reiniciado (PID {proc.pid})")
        return True
    except Exception as e:
        logger.error(f"[MCP] Falha ao reiniciar: {e}")
        return False


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
    Launches Chrome on the server (visible via noVNC).
    User logs into NotebookLM. Then calls /api/confirm-login to extract cookies.
    Uses direct Chrome launch with CDP enabled (--remote-allow-origins=*).
    """
    _verify(body.get("secret", ""))

    if _login["running"]:
        return {"message": "Login ja em andamento. Use o browser ao lado para logar.", "running": True}

    try:
        # Kill existing Chrome instances and clean profile locks
        subprocess.run(["pkill", "-f", "chromium"], capture_output=True)
        time.sleep(1)

        nlm_chrome = COOKIES_DIR / "chrome-profiles" / "default"
        nlm_chrome.mkdir(parents=True, exist_ok=True)
        for lock_name in ["SingletonLock", "SingletonCookie", "SingletonSocket"]:
            lock = nlm_chrome / lock_name
            if lock.exists() or lock.is_symlink():
                lock.unlink(missing_ok=True)

        # Launch Chrome directly with CDP enabled and remote-allow-origins=*
        # This avoids nlm login's Chrome launcher which crashes in Docker
        chrome_args = [
            "/usr/lib/chromium/chromium",
            "--no-sandbox", "--disable-setuid-sandbox", "--no-zygote",
            "--disable-dev-shm-usage", "--disable-gpu",
            "--remote-debugging-port=9222",
            "--remote-debugging-address=127.0.0.1",
            "--remote-allow-origins=*",
            f"--user-data-dir={nlm_chrome}",
            "--start-maximized",
            "https://notebooklm.google.com",
        ]
        proc = subprocess.Popen(
            chrome_args,
            env={**os.environ, "DISPLAY": ":99"},
            stdout=open("/tmp/chrome_login.log", "w"),
            stderr=subprocess.STDOUT,
        )
        _login["running"] = True
        _login["pid"] = proc.pid
        _login["started_at"] = datetime.now().isoformat()

        return {
            "message": f"Chrome aberto (PID {proc.pid}). Faca login no browser ao lado. Depois clique em 'Confirmar'.",
            "running": True,
            "pid": proc.pid,
        }
    except Exception as e:
        return {"message": f"Erro: {e}", "running": False}


@app.get("/api/login-status")
async def login_status():
    """Check if Chrome login process is still running."""
    if _login["pid"]:
        try:
            os.kill(_login["pid"], 0)
            running = True
        except ProcessLookupError:
            running = False
            _login["running"] = False

        try:
            from notebooklm_tools.utils.config import get_profile_dir  # type: ignore
            profile_dir = get_profile_dir("default")
        except Exception:
            profile_dir = COOKIES_DIR / "profiles" / "default"

        profile_done = (profile_dir / "cookies.json").exists()
        if profile_done:
            _auth["status"] = "authenticated"

        return {
            "running": running,
            "pid": _login["pid"],
            "profile_created": profile_done,
            "started_at": _login.get("started_at"),
        }
    return {"running": False, "pid": None, "profile_created": False}


@app.post("/api/confirm-login")
async def confirm_login(body: dict):
    """
    After user logs in via Chrome/noVNC:
    - 100% async: uses websockets library (already installed) for CDP
    - No threads, no blocking, no Traefik timeouts
    """
    _verify(body.get("secret", ""))

    cdp_base = "http://127.0.0.1:9222"

    # Check Chrome and get page WebSocket URL
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            pages_data = (await client.get(f"{cdp_base}/json/list")).json()
        page_ws = next(
            (p.get("webSocketDebuggerUrl") for p in pages_data
             if "notebooklm" in p.get("url", "") or "google" in p.get("url", "")),
            pages_data[0].get("webSocketDebuggerUrl") if pages_data else None,
        )
        if not page_ws:
            return {"success": False, "message": "Chrome aberto mas sem pagina Google. Verifique o VNC."}
    except Exception as e:
        return {"success": False, "message": f"Chrome nao esta rodando na porta 9222: {e}"}

    # Extract cookies using async websockets library (already imported at top of file)
    try:
        cookies_result: list = []
        async with websockets.connect(
            page_ws,
            additional_headers={"Origin": "http://localhost"},
            open_timeout=8,
        ) as ws:
            await ws.send(json.dumps({"id": 1, "method": "Network.enable", "params": {}}))
            await ws.send(json.dumps({"id": 2, "method": "Network.getAllCookies", "params": {}}))
            async for raw_msg in ws:
                d = json.loads(raw_msg)
                if d.get("id") == 2 and "result" in d:
                    cookies_result = d["result"].get("cookies", [])
                    break
    except Exception as e:
        return {"success": False, "message": f"Erro CDP WebSocket: {e}"}

    google_cookies = [c for c in cookies_result
                      if ".google." in c.get("domain", "") or "notebooklm" in c.get("domain", "")]

    if not google_cookies:
        return {"success": False, "message": f"Nenhum cookie Google ({len(cookies_result)} total). Faca login no Chrome antes de confirmar."}

    # Save cookies in Playwright format (async file IO)
    try:
        from notebooklm_tools.utils.config import get_profile_dir  # type: ignore
        profile_dir = Path(get_profile_dir("default"))
    except Exception:
        profile_dir = COOKIES_DIR / "profiles" / "default"
    profile_dir.mkdir(parents=True, exist_ok=True)
    profile_dir.chmod(0o700)

    SS = {"No restriction": "None", "Lax": "Lax", "Strict": "Strict", "": "None", "None": "None"}
    far = time.time() + 86400 * 365
    pw = [{"name": c.get("name", ""), "value": c.get("value", ""),
           "domain": c.get("domain", ".google.com"), "path": c.get("path", "/"),
           "expires": float(c.get("expires", far)),
           "httpOnly": bool(c.get("httpOnly", False)), "secure": bool(c.get("secure", True)),
           "sameSite": SS.get(c.get("sameSite", ""), "None")} for c in google_cookies]

    (profile_dir / "cookies.json").write_text(json.dumps(pw, ensure_ascii=False), encoding="utf-8")
    (profile_dir / "cookies.json").chmod(0o600)
    (profile_dir / "metadata.json").write_text(
        json.dumps({"last_validated": datetime.now().isoformat(),
                    "email": "arquitetomais@gmail.com",
                    "csrf_token": None, "session_id": None, "build_label": "cdp-async"}),
        encoding="utf-8",
    )

    # Restart MCP async (no time.sleep in event loop)
    try:
        subprocess.run(["pkill", "-f", "notebooklm-mcp"], capture_output=True)
        await asyncio.sleep(2)  # async sleep — does NOT block event loop!
        subprocess.Popen(
            ["notebooklm-mcp"],
            env={**os.environ, "NOTEBOOKLM_MCP_TRANSPORT": "http", "NOTEBOOKLM_MCP_PORT": "8080"},
            stdout=open("/tmp/mcp_restart.log", "w"), stderr=subprocess.STDOUT,
        )
        _mcp_session["id"] = None
        _mcp_session["initialized"] = False
        mcp_ok = True
    except Exception:
        mcp_ok = False

    _auth["status"] = "authenticated"
    _auth["cookie_count"] = len(google_cookies)
    _auth["source"] = "cdp-async"
    _login["running"] = False

    return {
        "success": True,
        "message": f"Login confirmado! {len(google_cookies)} cookies salvos. MCP reiniciado: {mcp_ok}.",
        "cookie_count": len(google_cookies),
        "mcp_restarted": mcp_ok,
    }





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

        COOKIES_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        COOKIE_ENV.write_text(cookie_header, encoding="utf-8")

        # Grava no formato Playwright LIST que o MCP espera
        ok, info = _write_nlm_profile(
            cookie_objects if cookie_objects else [
                {"name": k, "value": v, "domain": ".google.com", "path": "/", "secure": True}
                for k, v in (pair.split("=", 1) for pair in cookie_pairs if "=" in pair)
            ]
        )

        # Reinicia MCP para carregar os novos cookies
        mcp_ok = _restart_mcp()

        _auth["status"]       = "authenticated"
        _auth["cookie_count"] = count
        _auth["source"]       = source

        return {
            "message": f"OK {count} cookies via extensao. MCP reiniciado: {mcp_ok}.",
            "count": count,
            "source": source,
            "nlm_ok": ok,
            "mcp_restarted": mcp_ok,
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


# ── MCP Proxy: expõe o MCP interno para outros serviços ───────────────────────
# O worker do blococomercial chama estes endpoints via HTTPS público.
# O admin FastAPI, por sua vez, chama o MCP local em 127.0.0.1:8080.

MCP_URL = "http://127.0.0.1:8080/mcp"
_mcp_session: dict = {"sid": None, "initialized": False}


async def _mcp_call(payload: dict, timeout: int = 60) -> dict | None:
    """Faz uma chamada JSON-RPC ao MCP local e retorna o objeto 'result' ou 'error'."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if _mcp_session["sid"]:
        headers["Mcp-Session-Id"] = _mcp_session["sid"]

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(MCP_URL, json=payload, headers=headers)

    # Captura session ID do header
    new_sid = resp.headers.get("mcp-session-id")
    if new_sid:
        _mcp_session["sid"] = new_sid

    # Parseia SSE ou JSON direto
    body = resp.text
    for line in body.splitlines():
        if line.startswith("data:") and "jsonrpc" in line:
            try:
                return json.loads(line[5:].strip())
            except Exception:
                pass
    try:
        return json.loads(body)
    except Exception:
        return None


async def _mcp_ensure_session():
    """Inicializa a sessão MCP se ainda não estiver ativa."""
    if _mcp_session["initialized"]:
        return
    data = await _mcp_call({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "nlm-admin", "version": "1.0"},
        },
    })
    if data:
        _mcp_session["initialized"] = True


async def _mcp_tool(name: str, arguments: dict, timeout: int = 90) -> dict:
    """Chama uma tool MCP e retorna {'ok': bool, 'text': str, 'data': any}."""
    await _mcp_ensure_session()
    data = await _mcp_call({
        "jsonrpc": "2.0", "id": int(time.time() * 1000) % 999999,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }, timeout=timeout)

    if not data:
        return {"ok": False, "text": "Sem resposta do MCP", "data": None}

    if "error" in data:
        err = data["error"]
        return {"ok": False, "text": err.get("message", str(err)), "data": None}

    result = data.get("result", {})
    content = result.get("content", [])
    text = content[0].get("text", "") if content else ""

    # Tenta parsear JSON embutido no text
    parsed = None
    try:
        parsed = json.loads(text)
    except Exception:
        pass

    return {"ok": True, "text": text, "data": parsed}


@app.get("/api/mcp-status")
async def mcp_status():
    """Verifica se o MCP está respondendo (para debug e health check)."""
    try:
        await _mcp_ensure_session()
        result = await _mcp_tool("notebook_list", {"max_results": 1}, timeout=20)
        return {
            "mcp_ok": result["ok"],
            "session_id": _mcp_session["sid"],
            "initialized": _mcp_session["initialized"],
            "detail": result["text"][:200] if not result["ok"] else "OK",
        }
    except Exception as e:
        return {"mcp_ok": False, "session_id": None, "initialized": False, "detail": str(e)}


@app.get("/api/notebooks")
async def list_notebooks():
    """
    Lista todos os notebooks acessíveis na conta autenticada.
    Usado pelo painel comercial para selecionar o notebook alvo.
    """
    try:
        result = await _mcp_tool("notebook_list", {"max_results": 100}, timeout=60)
        if not result["ok"]:
            # Tenta refresh_auth e retry
            await _mcp_tool("refresh_auth", {}, timeout=30)
            _mcp_session["initialized"] = False
            result = await _mcp_tool("notebook_list", {"max_results": 100}, timeout=60)

        if result["ok"] and result["data"]:
            return {"ok": True, "notebooks": result["data"].get("notebooks", [])}
        return {"ok": result["ok"], "notebooks": [], "detail": result["text"][:300]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro MCP: {str(e)}")


@app.post("/api/source-add")
async def source_add(body: dict):
    """
    Adiciona um source de texto a um notebook NotebookLM.

    Payload esperado:
    {
      "notebook_id": "<UUID do notebook>",
      "title": "Nome Empresa — Nome Pessoa",
      "content": "Pergunta: ...\nResposta: ...\n...",
      "secret": "<ADMIN_SECRET>"     # opcional se em rede interna
    }

    Retorno:
    { "ok": true, "source_id": "...", "detail": "..." }
    """
    # Validação mínima
    notebook_id = body.get("notebook_id", "").strip()
    title = body.get("title", "Lead Sem Título").strip()
    content = body.get("content", "").strip()

    if not notebook_id:
        raise HTTPException(status_code=400, detail="notebook_id é obrigatório")
    if not content:
        raise HTTPException(status_code=400, detail="content é obrigatório")

    try:
        result = await _mcp_tool("source_add", {
            "notebook_id": notebook_id,
            "source_type": "text",
            "text": content,
            "title": title,
            "wait": True,
        }, timeout=120)

        if not result["ok"]:
            # Tenta refresh_auth e retry único
            await _mcp_tool("refresh_auth", {}, timeout=30)
            _mcp_session["initialized"] = False
            result = await _mcp_tool("source_add", {
                "notebook_id": notebook_id,
                "source_type": "text",
                "text": content,
                "title": title,
                "wait": True,
            }, timeout=120)

        source_id = None
        if result["data"]:
            source_id = (
                result["data"].get("source_id")
                or result["data"].get("id")
                or result["data"].get("source", {}).get("id")
            )

        return {
            "ok": result["ok"],
            "source_id": source_id,
            "title": title,
            "notebook_id": notebook_id,
            "detail": result["text"][:500] if not result["ok"] else "Source adicionado com sucesso",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao adicionar source: {str(e)}")



# ══════════════════════════════════════════════════════════════════════════════
# TYPEFORM → NOTEBOOKLM RAIOX SYNC
# Sincroniza todas as respostas dos 16 funis "RAIO-X CULTURAL" automaticamente
# ══════════════════════════════════════════════════════════════════════════════

def _load_sync_state() -> dict:
    """Carrega IDs já sincronizados do arquivo local."""
    if SYNC_STATE_FILE.exists():
        try:
            return json.loads(SYNC_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"synced_ids": []}


def _save_sync_state(state: dict):
    """Persiste IDs sincronizados."""
    SYNC_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SYNC_STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _extract_answer_value(ans: dict) -> str:
    """Extrai o valor legível de um answer do Typeform."""
    atype = ans.get("type", "")
    val = ans.get(atype)
    if val is None:
        val = ans.get("text") or ans.get("number") or ans.get("float") or ""
    if isinstance(val, dict):
        # choice ou choices
        val = val.get("label") or val.get("other") or ", ".join(
            c.get("label", "") for c in val.get("labels", [])
        ) or str(val)
    if isinstance(val, list):
        val = ", ".join(
            (x.get("label", "") if isinstance(x, dict) else str(x)) for x in val
        )
    return str(val).strip()


async def _tf_fetch_form_fields(form_id: str) -> dict:
    """Retorna mapeamento ref → title das perguntas do formulário."""
    if not TYPEFORM_TOKEN:
        return {}
    headers = {"Authorization": f"Bearer {TYPEFORM_TOKEN}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://api.typeform.com/forms/{form_id}",
                headers=headers,
            )
            r.raise_for_status()
            data = r.json()
    except Exception:
        return {}
    return {
        f.get("ref", ""): f.get("title", "")
        for f in data.get("fields", [])
    }


async def _tf_fetch_responses(form_id: str, since_token: str | None = None) -> dict:
    """Busca todas as respostas paginadas de um formulário Typeform."""
    if not TYPEFORM_TOKEN:
        return {"items": [], "total_items": 0}
    headers = {"Authorization": f"Bearer {TYPEFORM_TOKEN}"}
    all_items = []
    before = None
    while True:
        params = {"page_size": 200}
        if before:
            params["before"] = before
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(
                    f"https://api.typeform.com/forms/{form_id}/responses",
                    headers=headers,
                    params=params,
                )
                r.raise_for_status()
                data = r.json()
        except Exception:
            break
        items = data.get("items", [])
        all_items.extend(items)
        # Se veio menos de 200, não há mais páginas
        if len(items) < 200:
            break
        # Paginação reversa: pegar o token do mais antigo
        before = items[-1].get("token")
    return {"items": all_items, "total_items": len(all_items)}


def _format_response_as_text(response: dict, field_map: dict, form_title: str) -> str:
    """Converte uma resposta do Typeform em texto rico para o NotebookLM."""
    submitted = response.get("submitted_at", "")[:10]
    hidden = response.get("hidden", {})

    # Montar linhas de resposta
    lines = [
        f"[DIAGNÓSTICO CULTURAL — RAIO-X C8 CLUB]",
        f"Funil: {form_title}",
        f"Data: {submitted}",
    ]

    # Hidden fields (score, empresa, etc. passados via URL)
    if hidden:
        for k, v in hidden.items():
            lines.append(f"{k.replace('_', ' ').title()}: {v}")

    lines.append("")
    lines.append("=== RESPOSTAS DO DIAGNÓSTICO ===")

    # Answers com título da pergunta
    for ans in response.get("answers", []):
        field = ans.get("field", {})
        ref = field.get("ref", "")
        title = field_map.get(ref, ref) or ref
        # Limpar títulos com variáveis do typeform
        if "{{field:" in title:
            title = title.split("}},")[-1].strip() if "}}" in title else title
        val = _extract_answer_value(ans)
        if val and title and not title.startswith("{{"):
            lines.append(f"{title}: {val}")

    # Variables (score calculado, outcome etc.)
    for var in response.get("variables", []):
        lines.append(f"{var.get('key', 'var')}: {var.get('number', var.get('text', ''))}")

    return "\n".join(lines)


def _get_submission_title(response: dict, field_map: dict) -> str:
    """Gera título curto para o source: 'Empresa — Nome' ou data."""
    hidden = response.get("hidden", {})
    empresa = hidden.get("empresa") or hidden.get("company") or hidden.get("nome_empresa", "")
    nome = hidden.get("nome") or hidden.get("name") or ""

    # Tentar extrair da primeira pergunta (usually nome)
    if not nome and response.get("answers"):
        first_ans = response["answers"][0]
        val = _extract_answer_value(first_ans)
        if val and len(val) < 60:
            nome = val
    if not empresa and len(response.get("answers", [])) > 2:
        # Tentar segunda pergunta como empresa
        second_ans = response["answers"][1]
        val = _extract_answer_value(second_ans)
        if val and len(val) < 80:
            empresa = val

    parts = [e for e in [empresa, nome] if e]
    if parts:
        return " — ".join(parts[:2])
    return f"Diagnóstico {response.get('submitted_at', '')[:10]}"


async def _discover_cultural_forms() -> list[dict]:
    """Descobre todos os forms RAIO-X CULTURAL via Typeform API."""
    if not TYPEFORM_TOKEN:
        return []
    headers = {"Authorization": f"Bearer {TYPEFORM_TOKEN}"}
    all_forms = []
    page = 1
    while True:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    "https://api.typeform.com/forms",
                    headers=headers,
                    params={"page_size": 200, "page": page},
                )
                r.raise_for_status()
                data = r.json()
        except Exception:
            break
        items = data.get("items", [])
        all_forms.extend(items)
        if len(items) < 200:
            break
        page += 1
    return [f for f in all_forms if "RAIO-X CULTURAL" in f.get("title", "").upper()]


async def _sync_raiox_once() -> dict:
    """
    Executa uma rodada completa de sincronização:
    1. Descobre os 16 formulários RAIO-X CULTURAL
    2. Para cada form: busca respostas novas
    3. Formata como texto e adiciona ao notebook via MCP
    4. Persiste IDs sincronizados
    Retorna dict com stats da rodada.
    """
    state = _load_sync_state()
    synced_ids = set(state.get("synced_ids", []))
    added = 0
    errors = []

    forms = await _discover_cultural_forms()
    if not forms:
        return {"added": 0, "errors": ["TYPEFORM_TOKEN ausente ou API inacessível"], "forms": 0}

    _raiox_sync_state["forms_found"] = len(forms)

    for form in forms:
        form_id = form["id"]
        form_title = form.get("title", form_id)

        # Buscar mapeamento de campos e respostas
        field_map, resp_data = await asyncio.gather(
            _tf_fetch_form_fields(form_id),
            _tf_fetch_responses(form_id),
        )

        for response in resp_data.get("items", []):
            uid = f"{form_id}::{response.get('response_id', response.get('token', ''))}"
            if uid in synced_ids:
                continue  # Já sincronizado

            title = _get_submission_title(response, field_map)
            content = _format_response_as_text(response, field_map, form_title)

            # Adicionar ao notebook via MCP
            result = await _mcp_tool("source_add", {
                "notebook_id": RAIOX_NOTEBOOK_ID,
                "source_type": "text",
                "title": title[:200],
                "text": content,
                "wait": True,
            }, timeout=120)

            if result["ok"]:
                synced_ids.add(uid)
                added += 1
            else:
                errors.append(f"{title[:40]}: {result['text'][:80]}")
                # Se autenticação expirou, parar
                if "auth" in result["text"].lower() or "expired" in result["text"].lower():
                    break

        # Breve pausa entre forms para não sobrecarregar MCP
        await asyncio.sleep(1)

    # Persistir state
    state["synced_ids"] = list(synced_ids)
    _save_sync_state(state)

    return {"added": added, "errors": errors, "forms": len(forms), "total_synced": len(synced_ids)}


async def _raiox_sync_loop():
    """Background loop que roda sync a cada RAIOX_SYNC_INTERVAL segundos."""
    # Aguardar MCP inicializar
    await asyncio.sleep(15)
    while True:
        if not _raiox_sync_state["running"]:
            _raiox_sync_state["running"] = True
            try:
                stats = await _sync_raiox_once()
                _raiox_sync_state["last_sync"] = datetime.now().isoformat()
                _raiox_sync_state["total_synced"] += stats.get("added", 0)
                _raiox_sync_state["last_error"] = stats["errors"][0] if stats["errors"] else None
                _raiox_sync_state["forms_found"] = stats.get("forms", 0)
            except Exception as e:
                _raiox_sync_state["last_error"] = str(e)[:200]
            finally:
                _raiox_sync_state["running"] = False
        await asyncio.sleep(RAIOX_SYNC_INTERVAL)


@app.on_event("startup")
async def start_raiox_sync():
    """Inicia o loop de sync em background no startup do servidor."""
    asyncio.create_task(_raiox_sync_loop())


@app.get("/api/raiox-status")
async def raiox_status():
    """Status do sync e quantidade de leads no notebook."""
    state = _load_sync_state()
    synced_ids = state.get("synced_ids", [])
    return {
        "synced_total": len(synced_ids),
        "last_sync": _raiox_sync_state["last_sync"],
        "running": _raiox_sync_state["running"],
        "forms_found": _raiox_sync_state["forms_found"],
        "last_error": _raiox_sync_state["last_error"],
        "sync_interval_seconds": RAIOX_SYNC_INTERVAL,
    }


@app.post("/api/raiox-sync-now")
async def raiox_sync_now(body: dict = {}):
    """Dispara sincronização manual imediata."""
    _verify(body.get("secret", ""))
    if _raiox_sync_state["running"]:
        return {"ok": False, "message": "Sync já está em andamento"}
    # Roda em background para não bloquear a resposta
    asyncio.create_task(_run_sync_now())
    return {"ok": True, "message": "Sincronização iniciada em background"}


async def _run_sync_now():
    _raiox_sync_state["running"] = True
    try:
        stats = await _sync_raiox_once()
        _raiox_sync_state["last_sync"] = datetime.now().isoformat()
        _raiox_sync_state["total_synced"] += stats.get("added", 0)
        _raiox_sync_state["last_error"] = stats["errors"][0] if stats["errors"] else None
        _raiox_sync_state["forms_found"] = stats.get("forms", 0)
    except Exception as e:
        _raiox_sync_state["last_error"] = str(e)[:200]
    finally:
        _raiox_sync_state["running"] = False


@app.post("/api/typeform-webhook")
async def typeform_webhook(body: dict):
    """
    Webhook do Typeform: dispara sync imediato quando um novo formulário é submetido.
    Configurar no painel Typeform:
      URL: https://nlm.codigooito.com.br/api/typeform-webhook
      Event: form_response
    """
    # Typeform envia form_id no payload
    form_id = body.get("form_response", {}).get("form_id", "")
    # Verifica se é um dos forms RAIO-X CULTURAL (ou aceita qualquer, dado que
    # o sync filtra automaticamente)
    if not _raiox_sync_state["running"]:
        asyncio.create_task(_run_sync_now())
    return {"ok": True, "form_id": form_id}



# ── WebSocket proxy: /ws-vnc → localhost:6081 (websockify/VNC) ─────────────────

@app.websocket("/ws-vnc")
async def vnc_proxy(ws_client: WebSocket):
    """
    Proxies the browser's WebSocket connection to the local VNC websockify
    running on localhost:6081. All VNC traffic goes through the admin HTTPS
    endpoint — no extra port exposure needed.
    """
    # Forward any requested subprotocols (VNC uses 'binary')
    proto_header = ws_client.headers.get("sec-websocket-protocol", "")
    subprotocols = [s.strip() for s in proto_header.split(",") if s.strip()]
    subprotocol = subprotocols[0] if subprotocols else None
    await ws_client.accept(subprotocol=subprotocol)

    try:
        ws_kwargs = {}
        if subprotocols:
            ws_kwargs["subprotocols"] = [websockets.Subprotocol(s) for s in subprotocols]

        async with websockets.connect("ws://localhost:6081", **ws_kwargs) as ws_server:
            async def to_server():
                try:
                    while True:
                        data = await ws_client.receive_bytes()
                        await ws_server.send(data)
                except (WebSocketDisconnect, Exception):
                    pass

            async def to_client():
                try:
                    async for msg in ws_server:
                        if isinstance(msg, bytes):
                            await ws_client.send_bytes(msg)
                        else:
                            await ws_client.send_text(msg)
                except Exception:
                    pass

            tasks = [asyncio.create_task(to_server()), asyncio.create_task(to_client())]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
    except Exception:
        pass


STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# noVNC HTML5 client static files (installed via apt novnc → /usr/share/novnc)
NOVNC_DIR = Path("/usr/share/novnc")
if NOVNC_DIR.exists():
    app.mount("/novnc", StaticFiles(directory=str(NOVNC_DIR)), name="novnc")


@app.get("/", response_class=HTMLResponse)
async def root():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return HTMLResponse("<h1>NLM Admin</h1>")
