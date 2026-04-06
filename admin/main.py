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

_auth   = {"status": "idle", "account": None, "cookie_count": 0, "source": None}
_login  = {"running": False, "pid": None, "started_at": None}


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
    1. Gets PAGE-level WebSocket from Chrome CDP (browser-level returns 0 in Chrome 146+)
    2. Calls Network.getAllCookies on the page target
    3. Saves to nlm profile in Playwright format
    4. Restarts MCP
    """
    _verify(body.get("secret", ""))

    cdp_base = "http://127.0.0.1:9222"

    # Get Chrome status and find page-level WebSocket
    try:
        import urllib.request as _req
        # Get list of pages to find the notebooklm page WebSocket
        pages_data = json.loads(_req.urlopen(f"{cdp_base}/json/list", timeout=5).read())
        # Prefer notebooklm page, fallback to first page
        page_ws = next(
            (p.get("webSocketDebuggerUrl") for p in pages_data
             if "notebooklm" in p.get("url", "") or "google" in p.get("url", "")),
            pages_data[0].get("webSocketDebuggerUrl") if pages_data else None
        )
        if not page_ws:
            return {"success": False, "message": "Chrome nao tem paginas abertas. Certifique-se de que o NotebookLM esta carregado."}
    except Exception as e:
        return {"success": False, "message": f"Chrome nao esta acessivel em porta 9222: {e}"}

    # Extract cookies via CDP WebSocket (PAGE level — browser level returns 0 in Chrome 146+)
    try:
        import websocket as _ws  # type: ignore
        import threading as _threading

        cookies_result: list = []
        done_evt = _threading.Event()
        ws_error: list = []

        def _on_open(ws_conn):
            ws_conn.send(json.dumps({"id": 1, "method": "Network.enable", "params": {}}))
            ws_conn.send(json.dumps({"id": 2, "method": "Network.getAllCookies", "params": {}}))

        def _on_message(ws_conn, message):
            data = json.loads(message)
            if data.get("id") == 2 and "result" in data:
                cookies_result.extend(data["result"].get("cookies", []))
                done_evt.set()
                ws_conn.close()

        def _on_error(ws_conn, err):
            ws_error.append(str(err))
            done_evt.set()

        def _on_close(ws_conn, code, msg):
            done_evt.set()

        ws = _ws.WebSocketApp(
            page_ws,
            header=["Origin: http://localhost"],  # list format — compatible with all ws-client versions
            on_open=_on_open,
            on_message=_on_message,
            on_error=_on_error,
            on_close=_on_close,
        )
        t = _threading.Thread(target=ws.run_forever, daemon=True)
        t.start()
        done_evt.wait(timeout=12)

        if ws_error:
            return {"success": False, "message": f"Erro ao conectar ao Chrome: {ws_error[0]}. Chrome foi lancado com --remote-allow-origins=*?"}

    except Exception as e:
        return {"success": False, "message": f"Erro CDP WebSocket: {e}"}

    # Filter Google cookies
    google_cookies = [
        c for c in cookies_result
        if ".google." in c.get("domain", "") or "notebooklm" in c.get("domain", "")
    ]

    if not google_cookies:
        return {"success": False, "message": f"Nenhum cookie Google encontrado ({len(cookies_result)} total). Certifique-se de estar logado no NotebookLM antes de confirmar."}

    # Save in Playwright LIST format
    SAME_SITE_MAP = {"No restriction": "None", "Lax": "Lax", "Strict": "Strict", "": "None", "None": "None"}
    expiry_far = time.time() + (86400 * 365)
    playwright_cookies = [{
        "name":     c.get("name", ""),
        "value":    c.get("value", ""),
        "domain":   c.get("domain", ".google.com"),
        "path":     c.get("path", "/"),
        "expires":  float(c.get("expires", expiry_far)),
        "httpOnly": bool(c.get("httpOnly", False)),
        "secure":   bool(c.get("secure", True)),
        "sameSite": SAME_SITE_MAP.get(c.get("sameSite", ""), "None"),
    } for c in google_cookies]

    ok, info = _write_nlm_profile(
        playwright_cookies,
        email="arquitetomais@gmail.com",
    )
    if not ok:
        return {"success": False, "message": f"Erro ao salvar profile: {info}"}

    # Restart MCP
    mcp_ok = _restart_mcp()

    _auth["status"] = "authenticated"
    _auth["cookie_count"] = len(google_cookies)
    _auth["source"] = "cdp-extract"
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
