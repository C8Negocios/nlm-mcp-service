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
import logging
import os
import subprocess
import time
import zipfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("nlm-admin")

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
        subprocess.run(["pkill", "-f", "notebooklm-mcp"], capture_output=True)
        time.sleep(2)
        mcp_env = {
            **os.environ,
            "NOTEBOOKLM_MCP_TRANSPORT": "http",
            "NOTEBOOKLM_MCP_PORT": "8080",
            "NOTEBOOKLM_HL": "en",   # FIX: hl=pt herdado do container causa 400 na API Google
        }
        # Passar bl atual se disponível (evita usar o fallback stale)
        cached_bl = _auth.get("build_label") or os.environ.get("NOTEBOOKLM_BL", "")
        if cached_bl:
            mcp_env["NOTEBOOKLM_BL"] = cached_bl
        proc = subprocess.Popen(
            ["notebooklm-mcp"],
            env=mcp_env,
            stdout=open("/tmp/mcp_restart.log", "w"),
            stderr=subprocess.STDOUT,
        )
        _mcp_session["sid"] = None
        _mcp_session["initialized"] = False
        time.sleep(3)
        logger.info(f"[MCP] Reiniciado (PID {proc.pid}) bl={cached_bl[:20] if cached_bl else 'fallback'}")
        return True
    except Exception as e:
        logger.error(f"[MCP] Falha ao reiniciar: {e}")
        return False


# ── Direct NotebookLM API (bypassa MCP — necessário pois MCP não envia SAPISIDHASH) ──────────────

import hashlib as _hashlib

def _make_sapisidhash(sapisid: str, origin: str = "https://notebooklm.google.com") -> str:
    """Gera o header Authorization: SAPISIDHASH exigido pelo batchexecute do Google."""
    ts = str(int(time.time()))
    raw = f"{ts} {sapisid} {origin}"
    sha1 = _hashlib.sha1(raw.encode()).hexdigest()
    return f"SAPISIDHASH {ts}_{sha1}"


def _load_nlm_cookies() -> tuple[dict, str]:
    """
    Retorna (cookie_dict, sapisid) lendo do profiles/default/cookies.json.
    """
    profile_dir = COOKIES_DIR / "profiles" / "default"
    raw = json.loads((profile_dir / "cookies.json").read_text())
    cookie_dict = {}
    sapisid = ""
    for ck in raw:
        name = ck.get("name", "")
        value = ck.get("value", "")
        if name:
            cookie_dict[name] = value
        if name == "SAPISID":
            sapisid = value
    return cookie_dict, sapisid


async def _direct_add_text_source(
    notebook_id: str,
    text: str,
    title: str = "Pasted Text",
) -> dict:
    """
    Adiciona uma fonte de texto no NotebookLM via batchexecute DIRETO
    (sem usar a lib MCP que não envia o SAPISIDHASH Authorization header).

    Formato extraído do código-fonte do notebooklm-mcp-cli (sources.py):
      source_data = [None, [title, text], None, 2, None, ..., 1]
      params = [[source_data], notebook_id, [2], [1, None, ..., [1]]]
      RPC ID: izAoDd
    """
    import urllib.parse as _urlparse

    origin = "https://notebooklm.google.com"
    bl = _auth.get("build_label") or os.environ.get("NOTEBOOKLM_BL", "boq_labs-tailwind-frontend_20260405.03_p0")

    # Carregar cookies e metadados
    try:
        profile_dir = COOKIES_DIR / "profiles" / "default"
        meta = json.loads((profile_dir / "metadata.json").read_text())
        csrf_token = meta.get("csrf_token", "")
        cookie_dict, sapisid = _load_nlm_cookies()
    except Exception as e:
        return {"ok": False, "error": f"Leitura de credenciais falhou: {e}"}

    if not sapisid:
        return {"ok": False, "error": "Cookie SAPISID não encontrado"}

    # Construir params conforme sources.py:add_text_source
    source_data = [None, [title, text], None, 2, None, None, None, None, None, None, 1]
    params = [
        [source_data],
        notebook_id,
        [2],
        [1, None, None, None, None, None, None, None, None, None, [1]],
    ]

    # Serializar f.req (igual ao _build_request_body do BaseClient)
    params_json = json.dumps(params, separators=(",", ":"), ensure_ascii=False)
    f_req_inner = [[["izAoDd", params_json, None, "generic"]]]
    f_req_json = json.dumps(f_req_inner, separators=(",", ":"), ensure_ascii=False)
    body_parts = [f"f.req={_urlparse.quote(f_req_json, safe='')}"]
    if csrf_token:
        body_parts.append(f"at={_urlparse.quote(csrf_token, safe='')}")
    body = "&".join(body_parts) + "&"

    # URL de destino (mesma lógica do _build_url)
    source_path = f"/notebook/{notebook_id}"
    qp = _urlparse.urlencode({
        "rpcids": "izAoDd",
        "source-path": source_path,
        "bl": bl,
        "hl": "en",
        "rt": "c",
    })
    url = f"{origin}/_/LabsTailwindUi/data/batchexecute?{qp}"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Authorization": _make_sapisidhash(sapisid, origin),
        "X-Same-Domain": "1",
        "X-Goog-AuthUser": "0",
        "Origin": origin,
        "Referer": f"{origin}/",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    }

    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as cl:
            resp = await cl.post(url, content=body, cookies=cookie_dict, headers=headers)

        if resp.status_code != 200:
            return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

        # Parsear resposta (mesmo formato do _parse_response)
        text_body = resp.text
        if text_body.startswith(")]}'"):
            text_body = text_body[4:]
        lines = text_body.strip().split("\n")
        results = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            try:
                int(line)
                i += 1
                if i < len(lines):
                    try:
                        data = json.loads(lines[i])
                        results.append(data)
                    except Exception:
                        pass
                i += 1
            except ValueError:
                try:
                    results.append(json.loads(line))
                except Exception:
                    pass
                i += 1

        # Extrair source_id da resposta wrb.fr
        source_id = None
        source_title = title
        for chunk in results:
            if isinstance(chunk, list):
                for item in chunk:
                    if isinstance(item, list) and len(item) >= 3 and item[0] == "wrb.fr" and item[1] == "izAoDd":
                        # Verificar erro estrutural (item[5])
                        if len(item) > 5 and isinstance(item[5], list) and item[5]:
                            err_code = item[5][0] if isinstance(item[5][0], int) else None
                            return {"ok": False, "error": f"RPC error code {err_code}"}
                        result_str = item[2]
                        if isinstance(result_str, str):
                            try:
                                inner = json.loads(result_str)
                                # inner[0][0] = [[source_id], title, ...]
                                if inner and isinstance(inner[0], list) and inner[0]:
                                    sd = inner[0][0]
                                    source_id = sd[0][0] if sd[0] else None
                                    source_title = sd[1] if len(sd) > 1 else title
                            except Exception:
                                pass

        if source_id:
            return {"ok": True, "source_id": source_id, "title": source_title}
        else:
            return {"ok": False, "error": "Source ID nao encontrado na resposta", "raw": resp.text[:300]}

    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _direct_studio_create(
    notebook_id: str,
    artifact_type: str,  # "video" | "slide_deck"
    focus_prompt: str = "",
) -> dict:
    """
    Cria um artefato no Studio do NotebookLM via batchexecute DIRETO.
    Bypassa MCP (que não envia SAPISIDHASH).

    Estrutura extraída do notebooklm-mcp-cli/core/studio.py + base.py:
      RPC_CREATE_STUDIO = "R7cb6c"
      STUDIO_TYPE_VIDEO     = 3  VIDEO_FORMAT_CINEMATIC = 3
      STUDIO_TYPE_SLIDE_DECK = 8  SLIDE_DECK_FORMAT_DETAILED = 1
    """
    import urllib.parse as _urlparse

    RPC_CREATE_STUDIO = "R7cb6c"
    STUDIO_TYPE_VIDEO      = 3
    STUDIO_TYPE_SLIDE_DECK = 8
    VIDEO_FORMAT_CINEMATIC = 3
    SLIDE_DECK_FORMAT_DETAILED = 1
    SLIDE_DECK_LENGTH_DEFAULT  = 3

    origin = "https://notebooklm.google.com"
    bl = _auth.get("build_label") or os.environ.get("NOTEBOOKLM_BL", "boq_labs-tailwind-frontend_20260408.12_p0")

    try:
        profile_dir = COOKIES_DIR / "profiles" / "default"
        meta = json.loads((profile_dir / "metadata.json").read_text())
        csrf_token = meta.get("csrf_token", "")
        cookie_dict, sapisid = _load_nlm_cookies()
    except Exception as e:
        return {"ok": False, "error": f"Credenciais nao carregadas: {e}"}

    if not sapisid:
        return {"ok": False, "error": "SAPISID ausente"}

    # 1. Buscar source_ids do notebook (necessário para o payload)
    source_ids: list[str] = []
    try:
        from notebooklm_tools.core.notebooks import NotebookManager  # type: ignore
        from notebooklm_tools.utils.config import get_profile_dir    # type: ignore
        profile = get_profile_dir("default")
        nm = NotebookManager(profile_dir=profile)
        nb = nm.get_notebook(notebook_id)
        if nb and nb.get("sources"):
            source_ids = [s["id"] for s in nb["sources"] if s.get("id")]
    except Exception as e:
        logger.warning(f"[studio_create] nao conseguiu buscar source_ids: {e}")

    # Formatos de source_ids exigidos pela API
    # Se source_ids vazio → passa None para NLM usar todas as fontes do notebook
    sources_nested = [[[sid]] for sid in source_ids] if source_ids else None
    sources_simple = [[sid] for sid in source_ids] if source_ids else None

    # 2. Construir params conforme studio.py
    if artifact_type == "video":
        studio_type = STUDIO_TYPE_VIDEO
        inner_options = [
            sources_simple,
            "en",
            focus_prompt or "",
            None,
            VIDEO_FORMAT_CINEMATIC,  # format_code=3 cinematic → sem visual_style_code
        ]
        video_options = [None, None, inner_options]
        content = [
            None, None,
            studio_type,
            sources_nested,
            None, None, None, None,
            video_options,
        ]
    elif artifact_type == "slide_deck":
        studio_type = STUDIO_TYPE_SLIDE_DECK
        slide_deck_options = [[focus_prompt or None, "en", SLIDE_DECK_FORMAT_DETAILED, SLIDE_DECK_LENGTH_DEFAULT]]
        content = [
            None, None,
            studio_type,
            sources_nested,
            None, None, None, None, None, None, None, None, None, None, None, None,  # 12 nulls pos 4-15
            slide_deck_options,  # pos 16
        ]
    else:
        return {"ok": False, "error": f"artifact_type invalido: {artifact_type}"}

    params = [[2], notebook_id, content]

    # 3. Serializar f.req (mesmo formato do _build_request_body)
    params_json = json.dumps(params, separators=(",", ":"), ensure_ascii=False)
    f_req_inner = [[[RPC_CREATE_STUDIO, params_json, None, "generic"]]]
    f_req_json = json.dumps(f_req_inner, separators=(",", ":"), ensure_ascii=False)
    body_parts = [f"f.req={_urlparse.quote(f_req_json, safe='')}"]
    if csrf_token:
        body_parts.append(f"at={_urlparse.quote(csrf_token, safe='')}")
    body = "&".join(body_parts) + "&"

    # 4. URL
    qp = _urlparse.urlencode({
        "rpcids": RPC_CREATE_STUDIO,
        "source-path": f"/notebook/{notebook_id}",
        "bl": bl,
        "hl": "en",
        "rt": "c",
    })
    url = f"{origin}/_/LabsTailwindUi/data/batchexecute?{qp}"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Authorization": _make_sapisidhash(sapisid, origin),
        "X-Same-Domain": "1",
        "X-Goog-AuthUser": "0",
        "Origin": origin,
        "Referer": f"{origin}/notebook/{notebook_id}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    }

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as cl:
            resp = await cl.post(url, content=body, cookies=cookie_dict, headers=headers)

        if resp.status_code != 200:
            return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:300]}"}

        # Resposta confirma que geração foi iniciada (processo assíncrono no NLM)
        return {"ok": True, "artifact_type": artifact_type, "status": "generating"}

    except Exception as e:
        return {"ok": False, "error": str(e)}



# ── Diretório para artefatos baixados ─────────────────────────────────────────
ARTIFACTS_DIR = Path("/tmp/nlm-artifacts")
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

from fastapi.responses import FileResponse as _FileResponse

@app.get("/artifacts/{filename}")
async def serve_artifact(filename: str):
    """Serve artefatos gerados (MP4, PDF) via HTTPS público."""
    path = ARTIFACTS_DIR / filename
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Artefato não encontrado")
    return _FileResponse(path)


async def _direct_poll_studio_status(
    notebook_id: str,
    artifact_type: str,      # "video" | "slide_deck"
    max_wait: int = 600,
    poll_interval: int = 20,
) -> dict:
    """
    Polling via batchexecute (RPC gArtLc) até o artefato ficar pronto.
    status_code 1=in_progress  3=completed
    Video URL:      artifact_data[8][3]
    Slide deck URL: artifact_data[16][0]
    """
    import urllib.parse as _urlparse

    RPC_POLL_STUDIO    = "gArtLc"
    STUDIO_TYPE_VIDEO      = 3
    STUDIO_TYPE_SLIDE_DECK = 8

    origin = "https://notebooklm.google.com"
    bl = _auth.get("build_label") or os.environ.get("NOTEBOOKLM_BL", "boq_labs-tailwind-frontend_20260408.12_p0")

    try:
        profile_dir = COOKIES_DIR / "profiles" / "default"
        meta = json.loads((profile_dir / "metadata.json").read_text())
        csrf_token = meta.get("csrf_token", "")
        cookie_dict, sapisid = _load_nlm_cookies()
    except Exception as e:
        return {"ok": False, "error": f"Credenciais: {e}"}

    if not sapisid:
        return {"ok": False, "error": "SAPISID ausente"}

    target_type = STUDIO_TYPE_VIDEO if artifact_type == "video" else STUDIO_TYPE_SLIDE_DECK
    params = [[2], notebook_id, 'NOT artifact.status = "ARTIFACT_STATUS_SUGGESTED"']

    elapsed = 0
    while elapsed < max_wait:
        try:
            params_json = json.dumps(params, separators=(",", ":"), ensure_ascii=False)
            f_req_inner = [[[RPC_POLL_STUDIO, params_json, None, "generic"]]]
            f_req_json  = json.dumps(f_req_inner, separators=(",", ":"), ensure_ascii=False)
            body_parts  = [f"f.req={_urlparse.quote(f_req_json, safe='')}"]
            if csrf_token:
                body_parts.append(f"at={_urlparse.quote(csrf_token, safe='')}")
            body = "&".join(body_parts) + "&"

            qp  = _urlparse.urlencode({"rpcids": RPC_POLL_STUDIO, "source-path": f"/notebook/{notebook_id}", "bl": bl, "hl": "en", "rt": "c"})
            rpc_url = f"{origin}/_/LabsTailwindUi/data/batchexecute?{qp}"
            headers = {
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Authorization": _make_sapisidhash(sapisid, origin),
                "X-Same-Domain": "1", "X-Goog-AuthUser": "0",
                "Origin": origin, "Referer": f"{origin}/notebook/{notebook_id}",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            }

            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as cl:
                resp = await cl.post(rpc_url, content=body, cookies=cookie_dict, headers=headers)

            if resp.status_code == 200:
                text_body = resp.text
                if text_body.startswith(")]}{"):
                    text_body = text_body[4:]
                lines_resp = text_body.strip().split("\n")
                results = []
                ridx = 0
                while ridx < len(lines_resp):
                    ln = lines_resp[ridx].strip()
                    if not ln:
                        ridx += 1; continue
                    try:
                        int(ln); ridx += 1
                        if ridx < len(lines_resp):
                            try: results.append(json.loads(lines_resp[ridx]))
                            except Exception: pass
                        ridx += 1
                    except ValueError:
                        try: results.append(json.loads(ln))
                        except Exception: pass
                        ridx += 1

                for chunk in results:
                    if not isinstance(chunk, list): continue
                    for item in chunk:
                        if not (isinstance(item, list) and len(item) >= 3
                                and item[0] == "wrb.fr" and item[1] == RPC_POLL_STUDIO):
                            continue
                        result_str = item[2]
                        if not isinstance(result_str, str): continue
                        try:
                            inner = json.loads(result_str)
                            artifact_list = inner[0] if isinstance(inner[0], list) else inner
                            for ad in artifact_list:
                                if not isinstance(ad, list) or len(ad) < 5: continue
                                artifact_id  = ad[0]
                                type_code    = ad[2]
                                status_code  = ad[4]
                                if type_code != target_type: continue
                                if status_code == 3:  # completed
                                    url_found = None
                                    if type_code == STUDIO_TYPE_VIDEO and len(ad) > 8:
                                        opts = ad[8]
                                        if isinstance(opts, list) and len(opts) > 3 and isinstance(opts[3], str):
                                            url_found = opts[3]
                                    elif type_code == STUDIO_TYPE_SLIDE_DECK and len(ad) > 16:
                                        opts = ad[16]
                                        if isinstance(opts, list):
                                            url_found = (opts[0] if isinstance(opts[0], str)
                                                         else opts[3] if len(opts) > 3 and isinstance(opts[3], str)
                                                         else None)
                                    logger.info(f"[poll_studio] {artifact_type} COMPLETO artifact_id={artifact_id}")
                                    return {"ok": True, "artifact_id": artifact_id, "url": url_found}
                                elif status_code == 1:
                                    logger.info(f"[poll_studio] {artifact_type} em geracao... {elapsed}s")
                        except Exception as pe:
                            logger.warning(f"[poll_studio] parse: {pe}")
            else:
                logger.warning(f"[poll_studio] HTTP {resp.status_code}")

        except Exception as e:
            logger.warning(f"[poll_studio] erro: {e}")

        await asyncio.sleep(poll_interval)
        elapsed += poll_interval

    return {"ok": False, "error": f"Timeout {max_wait}s aguardando {artifact_type}"}


async def _download_and_serve(artifact_type: str, lead_id: str, url: str) -> "str | None":
    """
    Baixa o artefato da URL do NLM (autenticado) e salva em /tmp/nlm-artifacts/.
    Retorna a URL pública servida pelo NLM service.
    """
    ext = "mp4" if artifact_type == "video" else "pdf"
    filename = f"{lead_id}_{artifact_type}.{ext}"
    dest = ARTIFACTS_DIR / filename

    try:
        cookie_dict, sapisid = _load_nlm_cookies()
        origin = "https://notebooklm.google.com"
        dl_headers = {
            "Authorization": _make_sapisidhash(sapisid, origin),
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        }
        async with httpx.AsyncClient(timeout=300, follow_redirects=True) as cl:
            async with cl.stream("GET", url, cookies=cookie_dict, headers=dl_headers) as r:
                if r.status_code != 200:
                    logger.error(f"[download] HTTP {r.status_code} url={url[:80]}")
                    return None
                with open(dest, "wb") as fh:
                    async for chunk in r.aiter_bytes(chunk_size=65536):
                        fh.write(chunk)

        size_kb = dest.stat().st_size // 1024
        logger.info(f"[download] {filename} salvo ({size_kb} KB)")
        public_base = os.environ.get("NLM_PUBLIC_URL", "https://nlm.codigooito.com.br")
        return f"{public_base}/artifacts/{filename}"

    except Exception as e:
        logger.error(f"[download] {artifact_type}: {e}")
        return None


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
    # ── Fetch CSRF token, bl and session_id from NotebookLM page ─────────────
    # Estratégia: tentamos extrair br/csrf, mas MESMO SE FALHAR escrevemos
    # metadata.json SEM csrf_token → o MCP chamará _refresh_auth_tokens() no
    # startup e fará o fetch ele mesmo com os cookies frescos. Isso garante que
    # o bl (cfb2h) sempre vem direto do NotebookLM, não de um regex nosso.
    csrf_token  = ""
    nlm_session = ""
    current_bl  = ""
    html_status = 0
    final_url   = ""
    try:
        import re as _re
        cks = httpx.Cookies()
        for ck in pw:
            if ck.get("name") and ck.get("value"):
                # set sem domínio para que o httpx inclua em todas subdomain requests
                try:
                    cks.set(ck["name"], ck["value"], domain=ck.get("domain", ".google.com"))
                except Exception:
                    pass

        async with httpx.AsyncClient(timeout=25, follow_redirects=True) as cl:
            nlm_resp = await cl.get(
                "https://notebooklm.google.com",
                cookies=cks,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                },
            )
        html_status = nlm_resp.status_code
        final_url   = str(nlm_resp.url)
        html = nlm_resp.text

        csrf_m = _re.search(r'"SNlM0e":"([^"]+)"', html)
        sid_m  = _re.search(r'"FdrFJe":"([^"]+)"', html)

        # Extrai bl (build label) — usa group(1) do padrão cfb2h (grupo capturado)
        # NÃO usar group(0) que retorna a string JSON inteira "cfb2h":"boq_..."
        bl_m1 = _re.search(r'"cfb2h":"([^"]+)"', html)
        bl_m2 = _re.search(r'boq_labs-tailwind-frontend_[\w.]+', html)

        csrf_token  = csrf_m.group(1) if csrf_m else ""
        nlm_session = sid_m.group(1)  if sid_m  else ""
        if bl_m1:
            current_bl = bl_m1.group(1)       # → "boq_labs-tailwind-frontend_20260405.03_p0"
        elif bl_m2:
            current_bl = bl_m2.group(0)       # → "boq_labs-tailwind-frontend_20260405.03_p0"
        else:
            current_bl = ""

        # Sanity check: bl não deve conter aspas nem dois-pontos
        if '"' in current_bl or ':' in current_bl:
            logger.warning(f"[confirm-login] bl extraído parece inválido, ignorando: {current_bl!r}")
            current_bl = ""

        logger.info(
            f"[confirm-login] status={html_status} url={final_url[:60]} "
            f"CSRF={'OK' if csrf_token else 'VAZIO'} bl={current_bl or 'VAZIO'}"
        )

        # Patch base.py fallback SOMENTE se bl parece válido (começa com boq_labs-)
        if current_bl and current_bl.startswith("boq_labs-"):
            for py_path in [
                "/usr/local/lib/python3.12/site-packages/notebooklm_tools/core/base.py",
                "/usr/local/lib/python3.11/site-packages/notebooklm_tools/core/base.py",
            ]:
                base_py = Path(py_path)
                if base_py.exists():
                    orig    = base_py.read_text(encoding="utf-8")
                    patched = _re.sub(
                        r'_BL_FALLBACK\s*=\s*"boq_labs-tailwind-frontend_[^"]+"',
                        f'_BL_FALLBACK = "{current_bl}"',
                        orig,
                    )
                    if patched != orig:
                        base_py.write_text(patched, encoding="utf-8")
                        logger.info(f"[confirm-login] base.py patchado com bl={current_bl}: {py_path}")

        if csrf_token:
            _auth["csrf_ok"] = True
            _auth["build_label"] = current_bl

    except Exception as e:
        logger.warning(f"[confirm-login] Falha ao extrair CSRF/bl: {e}")

    # ── ESTRATÉGIA DE METADATA ──────────────────────────────────────────────
    # Se csrf_token foi extraído COM SUCESSO → salva no metadata.json, MCP usa direto.
    # Se csrf_token VAZIO (página não carregou ou estrutura mudou) → salva null,
    # o MCP chamará _refresh_auth_tokens() no startup e extrairá bl+csrf fresco.
    # Em ambos os casos o MCP terá tokens válidos ao iniciar.
    (profile_dir / "metadata.json").write_text(
        json.dumps({
            "last_validated": datetime.now().isoformat(),
            "email": "arquitetomais@gmail.com",
            "csrf_token": csrf_token or None,   # null → MCP faz fetch próprio
            "session_id": nlm_session or None,
            "build_label": current_bl or None,
            "_debug": {
                "html_status": html_status,
                "final_url": final_url[:100],
                "csrf_found": bool(csrf_token),
                "bl_found": bool(current_bl),
            },
        }, ensure_ascii=False),
        encoding="utf-8",
    )

    # Restart MCP async — CRITICAL: pass NOTEBOOKLM_BL so MCP usa o bl atual
    # sem isso, MCP usa _BL_FALLBACK stale e source_add falha com 400
    try:
        subprocess.run(["pkill", "-f", "notebooklm-mcp"], capture_output=True)
        await asyncio.sleep(2)
        mcp_env = {
            **os.environ,
            "NOTEBOOKLM_MCP_TRANSPORT": "http",
            "NOTEBOOKLM_MCP_PORT": "8080",
            "NOTEBOOKLM_HL": "en",   # FIX: hl=pt herdado do container causa 400 na API Google
        }
        # Injetar bl e csrf extraídos do HTML do NotebookLM
        if current_bl:
            mcp_env["NOTEBOOKLM_BL"] = current_bl
            os.environ["NOTEBOOKLM_BL"] = current_bl  # persiste para syncs futuros
            logger.info(f"[confirm-login] Reiniciando MCP com NOTEBOOKLM_BL={current_bl}")
        subprocess.Popen(
            ["notebooklm-mcp"],
            env=mcp_env,
            stdout=open("/tmp/mcp_restart.log", "w"), stderr=subprocess.STDOUT,
        )
        _mcp_session["sid"] = None
        _mcp_session["initialized"] = False
        mcp_ok = True
    except Exception as e:
        logger.error(f"[confirm-login] Falha ao reiniciar MCP: {e}")
        log_event("error", f"Falha ao reiniciar MCP: {e}", "confirm-login")
        mcp_ok = False

    _auth["status"] = "authenticated"
    _auth["cookie_count"] = len(google_cookies)
    _auth["source"] = "cdp-async"
    _login["running"] = False

    log_event("ok",
        f"{len(google_cookies)} cookies salvos. "
        f"CSRF={'OK' if csrf_token else 'VAZIO'} "
        f"bl={current_bl[:30] if current_bl else 'VAZIO'} | "
        f"html_status={html_status} | MCP reiniciado: {mcp_ok}",
        "confirm-login"
    )

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
        log_event("error", f"MCP sem resposta para tool={name}", "mcp")
        return {"ok": False, "text": "Sem resposta do MCP", "data": None}

    if "error" in data:
        err = data["error"]
        err_msg = err.get("message", str(err))
        # Session not found → reset e tentar uma vez
        if "session" in err_msg.lower() or "not found" in err_msg.lower():
            _mcp_session["sid"] = None
            _mcp_session["initialized"] = False
            await _mcp_ensure_session()
            data = await _mcp_call({
                "jsonrpc": "2.0", "id": int(time.time() * 1000) % 999999,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }, timeout=timeout)
            if not data or "error" in data:
                log_event("error", f"MCP tool={name} falhou mesmo após retry: {err_msg}", "mcp")
                return {"ok": False, "text": err_msg, "data": None}
        else:
            log_event("error", f"MCP tool={name} erro: {err_msg}", "mcp")
            return {"ok": False, "text": err_msg, "data": None}

    result = data.get("result", {})
    content = result.get("content", [])
    text = content[0].get("text", "") if content else ""

    # Tenta parsear JSON embutido no text
    parsed = None
    try:
        parsed = json.loads(text)
    except Exception:
        pass

    # Loga erros retornados pelo MCP no campo "error" do JSON
    if isinstance(parsed, dict) and parsed.get("error"):
        log_event("warn", f"MCP tool={name} retornou erro: {parsed['error']}", "mcp")
    elif name == "source_add" and isinstance(parsed, dict) and parsed.get("status") != "error":
        log_event("ok", f"source_add bem-sucedido", "mcp")

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


@app.get("/api/auth-debug")
async def auth_debug():
    """Expõe metadata.json + env vars para diagnóstico de bl/csrf."""
    try:
        from notebooklm_tools.utils.config import get_profile_dir  # type: ignore
        profile_dir = Path(get_profile_dir("default"))
    except Exception:
        profile_dir = COOKIES_DIR / "profiles" / "default"

    meta = {}
    try:
        raw = (profile_dir / "metadata.json").read_text(encoding="utf-8")
        meta = json.loads(raw)
        # Mascarar o csrf_token mas manter comprimento para diagnóstico
        if meta.get("csrf_token"):
            t = meta["csrf_token"]
            meta["csrf_token"] = f"{t[:6]}...{t[-4:]} (len={len(t)})"
    except Exception as e:
        meta = {"error": str(e)}

    cookies_count = 0
    try:
        raw_ck = (profile_dir / "cookies.json").read_text(encoding="utf-8")
        cookies_count = len(json.loads(raw_ck))
    except Exception:
        pass

    return {
        "metadata": meta,
        "cookies_count": cookies_count,
        "profile_dir": str(profile_dir),
        "NOTEBOOKLM_BL_env": os.environ.get("NOTEBOOKLM_BL", "(não definido)"),
        "mcp_session": _mcp_session,
        "auth_state": {k: v for k, v in _auth.items() if k != "cookies"},
    }


@app.get("/api/raw-batchexecute")
async def raw_batchexecute():
    """
    Faz um batchexecute direto ao NotebookLM SEM passar pelo MCP.
    Testa se os cookies + CSRF estão funcionando corretamente.
    Útil para isolar: problema nos cookies vs problema na lib MCP.
    """
    import hashlib as _hashlib
    import time as _time

    try:
        profile_dir = COOKIES_DIR / "profiles" / "default"
        raw_meta = json.loads((profile_dir / "metadata.json").read_text())
        csrf_token = raw_meta.get("csrf_token", "")
        bl = raw_meta.get("build_label", os.environ.get("NOTEBOOKLM_BL", ""))

        raw_cookies = json.loads((profile_dir / "cookies.json").read_text())
        cookie_dict = {}
        sapisid = ""
        for ck in raw_cookies:
            name = ck.get("name", "")
            value = ck.get("value", "")
            cookie_dict[name] = value
            if name == "SAPISID":
                sapisid = value

        # Gerar SAPISIDHASH  (obrigatório para batchexecute autenticado)
        origin = "https://notebooklm.google.com"
        ts = str(int(_time.time()))
        raw_hash = f"{ts} {sapisid} {origin}"
        sha1 = _hashlib.sha1(raw_hash.encode()).hexdigest()
        sapisidhash = f"SAPISIDHASH {ts}_{sha1}"

        # Payload do notebook_list (rpcids=wXbhsf)
        f_req = json.dumps([[["wXbhsf", "[[1]]", None, "generic"]]])
        data = {
            "f.req": f_req,
            "at": csrf_token,
        }

        url = (
            f"https://notebooklm.google.com/_/LabsTailwindUi/data/batchexecute"
            f"?rpcids=wXbhsf&source-path=%2F&bl={bl}&hl=en&rt=c"
        )

        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as cl:
            resp = await cl.post(
                url,
                data=data,
                cookies=cookie_dict,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                    "Authorization": sapisidhash,
                    "X-Same-Domain": "1",
                    "X-Goog-AuthUser": "0",
                    "Origin": origin,
                    "Referer": "https://notebooklm.google.com/",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                },
            )

        return {
            "http_status": resp.status_code,
            "ok": resp.status_code == 200,
            "sapisidhash_header": sapisidhash[:40] + "...",
            "sapisid_found": bool(sapisid),
            "csrf_len": len(csrf_token),
            "bl": bl,
            "cookies_sent": list(cookie_dict.keys()),
            "response_preview": resp.text[:500] if resp.status_code != 200 else resp.text[:200],
        }

    except Exception as e:
        return {"error": str(e), "ok": False}


@app.get("/api/mcp-logs")
async def mcp_logs():
    """Retorna as últimas 200 linhas dos logs do processo MCP (debug)."""
    logs = {}
    for name, path in [
        ("mcp_restart", "/tmp/mcp_restart.log"),
        ("chrome_login", "/tmp/chrome_login.log"),
    ]:
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            logs[name] = lines[-200:]  # últimas 200 linhas
        except FileNotFoundError:
            logs[name] = [f"[arquivo não encontrado: {path}]"]
        except Exception as e:
            logs[name] = [f"[erro ao ler: {e}]"]
    return logs


@app.post("/api/diagnose-source-add")
async def diagnose_source_add(body: dict = {}):
    """
    Debug completo: testa notebook_list + source_add com conteúdo mínimo.
    Retorna a resposta RAW do MCP para diagnóstico.
    """
    notebook_id = body.get("notebook_id", RAIOX_NOTEBOOK_ID)
    diag: dict = {"notebook_id": notebook_id, "steps": []}

    # Step 1: MCP session
    try:
        _mcp_session["initialized"] = False
        await _mcp_ensure_session()
        diag["steps"].append({
            "step": "mcp_init",
            "ok": _mcp_session["initialized"],
            "session_id": _mcp_session["sid"],
        })
    except Exception as e:
        diag["steps"].append({"step": "mcp_init", "ok": False, "error": str(e)})
        return diag

    # Step 2: refresh_auth
    try:
        rr = await _mcp_tool("refresh_auth", {}, timeout=30)
        diag["steps"].append({
            "step": "refresh_auth",
            "ok": rr["ok"],
            "text": rr["text"][:300],
            "data": rr["data"],
        })
    except Exception as e:
        diag["steps"].append({"step": "refresh_auth", "ok": False, "error": str(e)})

    # Step 3: notebook_list
    try:
        nl = await _mcp_tool("notebook_list", {"max_results": 3}, timeout=30)
        diag["steps"].append({
            "step": "notebook_list",
            "ok": nl["ok"],
            "text": nl["text"][:400],
            "data_keys": list(nl["data"].keys()) if isinstance(nl.get("data"), dict) else None,
            "notebook_count": len(nl["data"].get("notebooks", [])) if isinstance(nl.get("data"), dict) else 0,
        })
    except Exception as e:
        diag["steps"].append({"step": "notebook_list", "ok": False, "error": str(e)})

    # Step 4: source_add com conteúdo mínimo de teste
    test_title = "TESTE DIAGNOSTICO NLM"
    test_content = (
        "# Teste de Diagnostico NotebookLM\n\n"
        "Este source foi adicionado automaticamente pelo diagnóstico do NLM Admin.\n"
        "Pode ser removido após confirmar que o sync funciona.\n"
    )
    try:
        _mcp_session["initialized"] = False  # força nova sessão para isolar o teste
        sa = await _mcp_tool("source_add", {
            "notebook_id": notebook_id,
            "source_type": "text",
            "title": test_title,
            "text": test_content,
            "wait": False,  # sem wait para resposta mais rápida
        }, timeout=60)
        diag["steps"].append({
            "step": "source_add_test",
            "ok": sa["ok"],
            "text_full": sa["text"],   # resposta completa sem truncar
            "data": sa["data"],
        })
    except Exception as e:
        diag["steps"].append({"step": "source_add_test", "ok": False, "error": str(e)})

    # Step 5: source_add com wait=True (se o anterior funcionou sem wait)
    prev_ok = any(s.get("step") == "source_add_test" and s.get("ok") for s in diag["steps"])
    if prev_ok:
        diag["steps"].append({"step": "source_add_wait", "skipped": "source_add sem wait já funcionou"})
    else:
        try:
            _mcp_session["initialized"] = False
            sa2 = await _mcp_tool("source_add", {
                "notebook_id": notebook_id,
                "source_type": "text",
                "title": test_title + " (wait=True)",
                "text": test_content,
                "wait": True,
            }, timeout=120)
            diag["steps"].append({
                "step": "source_add_wait",
                "ok": sa2["ok"],
                "text_full": sa2["text"],
                "data": sa2["data"],
            })
        except Exception as e:
            diag["steps"].append({"step": "source_add_wait", "ok": False, "error": str(e)})

    return diag


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
    # content pode ser simples (só nome/empresa) — NLM usa o notebook completo para gerar
    if not content:
        content = title or "Lead"

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
# GERAÇÃO DE ARTEFATOS POR LEAD (vídeo cinematic + deck de slides)
# Disparado pelo webhook do bloco comercial após cada novo lead.
# ══════════════════════════════════════════════════════════════════════════════

SALES_CALLBACK_URL = os.getenv("SALES_CALLBACK_URL", "https://sales.codigooito.com.br/api/leads/{lead_id}/artifacts")
SALES_CALLBACK_SECRET = os.getenv("SALES_CALLBACK_SECRET", "c8club-nlm-2026")

async def _generate_artifacts_task(
    notebook_id: str,
    lead_id: str,
    title: str,
    content: str,
):
    """
    Pipeline completo de geração de artefatos NLM:
    1. Adiciona source (rawAnswers do lead) ao notebook
    2. Dispara studio_create para video cinematic
    3. Dispara studio_create para slide_deck
    4. Aguarda AMBOS ficarem prontos via poll
    5. Baixa os artefatos e os serve via /artifacts/
    6. Callback ao sales com URLs reais
    """
    logger.info(f"[generate-artifacts] Iniciando lead={lead_id} notebook={notebook_id}")

    # 1. Adicionar source ao notebook
    source_result = await _direct_add_text_source(notebook_id, content, title)
    logger.info(f"[generate-artifacts] source_add ok={source_result['ok']} sid={source_result.get('source_id')} lead={lead_id}")
    if not source_result["ok"]:
        logger.warning(f"[generate-artifacts] source_add falhou: {source_result.get('error')} — continuando")

    # Aguardar indexação
    await asyncio.sleep(10)

    # 2. Disparar video cinematic
    focus = f"Crie uma apresentação em vídeo cinematic para {title}."
    vid_trigger = await _direct_studio_create(notebook_id, "video", focus_prompt=focus)
    logger.info(f"[generate-artifacts] video trigger ok={vid_trigger['ok']} lead={lead_id}")

    # 3. Disparar slide deck
    sld_trigger = await _direct_studio_create(notebook_id, "slide_deck", focus_prompt=focus)
    logger.info(f"[generate-artifacts] slides trigger ok={sld_trigger['ok']} lead={lead_id}")

    # Pequena pausa antes de começar o polling
    await asyncio.sleep(10)

    # 4. Poll até video ficar pronto (max 8 min)
    video_url: str | None = None
    vid_poll = await _direct_poll_studio_status(notebook_id, "video", max_wait=480, poll_interval=20)
    logger.info(f"[generate-artifacts] video poll ok={vid_poll['ok']} lead={lead_id}")
    if vid_poll["ok"] and vid_poll.get("url"):
        # 5a. Baixar e servir video
        video_url = await _download_and_serve("video", lead_id, vid_poll["url"])
        logger.info(f"[generate-artifacts] video servido em {video_url} lead={lead_id}")

    # Poll até slides ficarem prontos (max 8 min)
    slides_url: str | None = None
    sld_poll = await _direct_poll_studio_status(notebook_id, "slide_deck", max_wait=480, poll_interval=20)
    logger.info(f"[generate-artifacts] slides poll ok={sld_poll['ok']} lead={lead_id}")
    if sld_poll["ok"] and sld_poll.get("url"):
        # 5b. Baixar e servir slides
        slides_url = await _download_and_serve("slide_deck", lead_id, sld_poll["url"])
        logger.info(f"[generate-artifacts] slides servidos em {slides_url} lead={lead_id}")

    # 6. Callback ao sales com URLs reais
    nlm_status = "generated" if (video_url or slides_url) else "failed"
    try:
        callback_url = SALES_CALLBACK_URL.format(lead_id=lead_id)
        async with httpx.AsyncClient(timeout=15) as cl:
            resp = await cl.patch(callback_url, json={
                "secret":    SALES_CALLBACK_SECRET,
                "videoUrl":  video_url,
                "slidesUrl": slides_url,
                "nlmStatus": nlm_status,
            })
        logger.info(f"[generate-artifacts] callback status={resp.status_code} nlmStatus={nlm_status} lead={lead_id}")
        if resp.status_code not in (200, 204):
            logger.error(f"[generate-artifacts] callback falhou: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"[generate-artifacts] callback excecao: {e}")


@app.post("/api/generate-artifacts")
async def generate_artifacts(body: dict):
    """
    Dispara geração assíncrona de vídeo + slides para um lead.

    Payload:
    {
      "notebook_id": "<UUID>",
      "lead_id": "<UUID do lead no bloco comercial>",
      "title": "Nome Lead — Empresa",
      "content": "<rawAnswers do Typeform>"
    }

    Retorna imediatamente (202 Accepted).
    Quando os artefatos ficam prontos, faz PATCH /api/leads/:lead_id/artifacts no sales.
    """
    notebook_id = body.get("notebook_id", "").strip()
    lead_id = body.get("lead_id", "").strip()
    title = body.get("title", "Lead Sem Título").strip()
    content = body.get("content", "").strip()

    if not notebook_id or not lead_id:
        raise HTTPException(status_code=400, detail="notebook_id e lead_id são obrigatórios")
    if not content:
        raise HTTPException(status_code=400, detail="content é obrigatório")

    # Dispara background sem bloquear o webhook do typeform
    asyncio.create_task(_generate_artifacts_task(notebook_id, lead_id, title, content))

    logger.info(f"[generate-artifacts] Tarefa enfileirada lead={lead_id}")
    return {"ok": True, "queued": True, "lead_id": lead_id}


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


def _sanitize_text(s: str) -> str:
    """Remove/substitui caracteres que causam rejeição pelo NotebookLM."""
    if not s:
        return ""
    # Manter apenas caracteres imprimíveis Unicode + newlines/tabs
    import unicodedata
    cleaned = []
    for ch in s:
        cat = unicodedata.category(ch)
        if ch in ('\n', '\r', '\t'):
            cleaned.append(ch)
        elif cat.startswith('C'):  # Control chars
            cleaned.append(' ')
        else:
            cleaned.append(ch)
    return ''.join(cleaned).strip()


def _format_response_as_markdown(response: dict, field_map: dict, form_title: str) -> str:
    """Converte resposta do Typeform em Markdown estruturado para o NotebookLM."""
    submitted = response.get("submitted_at", "")[:10]
    hidden = response.get("hidden", {})

    lines = [
        "# Diagnostico Cultural - Raio-X C8 Club",
        "",
        f"**Funil:** {_sanitize_text(form_title)}",
        f"**Data de Submissao:** {submitted}",
    ]

    # Hidden fields (empresa, nome, utm etc. passados via URL)
    meta = []
    for k, v in hidden.items():
        v_str = _sanitize_text(str(v))
        if v_str and not k.startswith("utm_"):
            meta.append(f"**{k.replace('_', ' ').title()}:** {v_str}")
    if meta:
        lines.append("")
        lines.append("## Identificacao")
        lines.extend(meta)

    lines.append("")
    lines.append("## Respostas do Diagnostico")
    lines.append("")

    # Answers com titulo da pergunta como header de nivel 3
    for i, ans in enumerate(response.get("answers", []), 1):
        field = ans.get("field", {})
        ref = field.get("ref", "")
        title = field_map.get(ref, ref) or ref
        # Remover variaveis do typeform ({{field:xxx}})
        if "{{" in title:
            parts = title.split("}},")
            title = parts[-1].strip() if len(parts) > 1 else ""
        title = _sanitize_text(title)
        val = _sanitize_text(_extract_answer_value(ans))
        if val and title and not title.startswith("{"):
            lines.append(f"**{title}**")
            lines.append(val)
            lines.append("")

    # Variables (score calculado, outcome etc.)
    vars_list = response.get("variables", [])
    if vars_list:
        lines.append("## Dados Calculados")
        for var in vars_list:
            key = var.get("key", "var")
            val = str(var.get("number", var.get("text", "")))
            if val:
                lines.append(f"- **{key}:** {val}")

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

    # Refresh auth tokens (CSRF) antes de iniciar o sync
    try:
        refresh_res = await _mcp_tool("refresh_auth", {}, timeout=30)
        logger.info(f"[raiox-sync] refresh_auth: {refresh_res.get('text', 'ok')[:80]}")
    except Exception as e:
        logger.warning(f"[raiox-sync] refresh_auth falhou (continuando): {e}")

    # Invalidar cache de sessão MCP para esta rodada (CSRF pode ter mudado pós-restart)
    _mcp_session["initialized"] = False

    for form in forms:
        form_id = form["id"]
        form_title = form.get("title", form_id)

        field_map, resp_data = await asyncio.gather(
            _tf_fetch_form_fields(form_id),
            _tf_fetch_responses(form_id),
        )

        for response in resp_data.get("items", []):
            uid = f"{form_id}::{response.get('response_id', response.get('token', ''))}"
            if uid in synced_ids:
                continue

            title = _get_submission_title(response, field_map)
            content = _format_response_as_markdown(response, field_map, form_title)

            # Adicionar ao notebook DIRETAMENTE (bypassa MCP — MCP não envia SAPISIDHASH)
            result = await _direct_add_text_source(
                notebook_id=RAIOX_NOTEBOOK_ID,
                text=content,
                title=title[:200],
            )

            log_event("mcp", f"direct_source_add '{title[:30]}': ok={result.get('ok')} sid={result.get('source_id', '')[:20] or result.get('error', '')[:60]}", "sync")

            if result.get("ok") and result.get("source_id"):
                synced_ids.add(uid)
                added += 1
                log_event("sync", f"✅ Adicionado: {title[:50]}", "sync")
            else:
                err_msg = result.get("error", "resposta inesperada")
                errors.append(f"{title[:40]}: {err_msg[:80]}")
                logger.warning(f"[raiox-sync] Falha source_add '{title[:40]}': {err_msg[:120]}")


        await asyncio.sleep(1)

    state["synced_ids"] = list(synced_ids)
    _save_sync_state(state)

    return {"added": added, "errors": errors, "forms": len(forms), "total_synced": len(synced_ids)}


async def _raiox_sync_loop():
    """Background loop que roda sync a cada RAIOX_SYNC_INTERVAL segundos."""
    # Aguardar MCP inicializar
    await asyncio.sleep(15)
    log_event("info", "Loop de sync iniciado", "sync")
    while True:
        if not _raiox_sync_state["running"]:
            _raiox_sync_state["running"] = True
            log_event("info", "Iniciando rodada de sync...", "sync")
            try:
                stats = await _sync_raiox_once()
                _raiox_sync_state["last_sync"] = datetime.now().isoformat()
                _raiox_sync_state["total_synced"] += stats.get("added", 0)
                _raiox_sync_state["last_error"] = stats["errors"][0] if stats["errors"] else None
                _raiox_sync_state["forms_found"] = stats.get("forms", 0)
                if stats["errors"]:
                    log_event("error", f"Sync concluído com erros: {stats['errors']}", "sync")
                else:
                    log_event("ok", f"Sync OK — {stats.get('added', 0)} novos, {stats.get('forms', 0)} funis", "sync")
            except Exception as e:
                _raiox_sync_state["last_error"] = str(e)[:200]
                log_event("error", f"Exceção no sync: {e}", "sync")
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


# ══════════════════════════════════════════════════════════════════════════════
# LOG BUFFER  — captura eventos importantes em memória e serve via SSE
# ══════════════════════════════════════════════════════════════════════════════

import collections as _collections

_LOG_BUFFER: _collections.deque = _collections.deque(maxlen=500)
_log_subscribers: list = []   # asyncio.Queue per connected client


def log_event(level: str, msg: str, source: str = "system") -> None:
    """Registra um evento no buffer de log e notifica clientes SSE."""
    entry = {
        "ts": datetime.now().strftime("%H:%M:%S"),
        "level": level,   # info | ok | warn | error | debug
        "source": source,
        "msg": msg,
    }
    _LOG_BUFFER.append(entry)
    # Notifica todos subscribers (fire-and-forget, não bloqueia)
    dead = []
    for q in _log_subscribers:
        try:
            q.put_nowait(entry)
        except Exception:
            dead.append(q)
    for q in dead:
        try:
            _log_subscribers.remove(q)
        except ValueError:
            pass


@app.get("/api/logs/stream")
async def logs_stream():
    """SSE endpoint — envia eventos de log em tempo real para o browser."""
    from fastapi.responses import StreamingResponse as _SR

    q: asyncio.Queue = asyncio.Queue()
    _log_subscribers.append(q)

    async def generate():
        # Envia histórico imediato (últimas 200 entradas)
        for entry in list(_LOG_BUFFER)[-200:]:
            payload = json.dumps(entry, ensure_ascii=False)
            yield f"data: {payload}\n\n"

        # Streaming em tempo real
        try:
            while True:
                try:
                    entry = await asyncio.wait_for(q.get(), timeout=30)
                    payload = json.dumps(entry, ensure_ascii=False)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            try:
                _log_subscribers.remove(q)
            except ValueError:
                pass

    return _SR(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # desativa buffer do Nginx/Traefik
        },
    )


@app.get("/api/logs/snapshot")
async def logs_snapshot():
    """Retorna snapshot JSON dos últimos 200 eventos (para copiar/colar)."""
    return {"logs": list(_LOG_BUFFER)[-200:]}




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
