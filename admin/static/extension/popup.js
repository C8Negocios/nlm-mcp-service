const API_URL = "https://nlm.codigooito.com.br/api/auth-bookmarklet";
const STATUS_URL = "https://nlm.codigooito.com.br/api/status";
const STORAGE_KEY = "nlm_secret";

// Load saved secret from persistent storage (survives popup close)
chrome.storage.local.get([STORAGE_KEY], (r) => {
  if (r[STORAGE_KEY]) document.getElementById("secret").value = r[STORAGE_KEY];
});

// Save secret on change
document.getElementById("secret").addEventListener("input", (e) => {
  const v = e.target.value;
  if (v) chrome.storage.local.set({ [STORAGE_KEY]: v });
});

async function checkStatus() {
  const badge = document.getElementById("badge");
  const stxt = document.getElementById("stxt");
  try {
    const d = await (await fetch(STATUS_URL, { cache: "no-store" })).json();
    if (d.status === "authenticated") {
      badge.className = "badge ok";
      stxt.textContent = "Autenticado ✓";
    } else {
      badge.className = "badge no";
      stxt.textContent = "Não Autenticado";
    }
  } catch {
    badge.className = "badge no";
    stxt.textContent = "Servidor offline";
  }
}

checkStatus();
// Refresh status every 8s while popup is open
setInterval(checkStatus, 8000);

// Auth button — ALWAYS enabled, always callable
async function doAuth() {
  const secret = document.getElementById("secret").value.trim();
  const btn = document.getElementById("authBtn");
  const msg = document.getElementById("msg");

  if (!secret) {
    msg.textContent = "⚠️ Digite a chave de acesso primeiro.";
    msg.className = "msg err";
    document.getElementById("secret").focus();
    return;
  }

  // Persist secret
  chrome.storage.local.set({ [STORAGE_KEY]: secret });

  // Disable while working
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = "⏳ Capturando cookies...";
  msg.textContent = "";
  msg.className = "msg";

  try {
    // Get current tab URL (needs "tabs" permission in manifest)
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab?.url || "";

    if (!url.includes("google.com")) {
      msg.textContent = "⚠️ Abra notebooklm.google.com antes de autenticar.";
      msg.className = "msg err";
      btn.disabled = false;
      btn.textContent = originalText;
      return;
    }

    btn.textContent = "⏳ Lendo cookies...";

    // Capture ALL Google cookies including HttpOnly via chrome.cookies API
    const googleCookies = await new Promise((res) =>
      chrome.cookies.getAll({ domain: "google.com" }, res)
    );
    const nlmCookies = await new Promise((res) =>
      chrome.cookies.getAll({ domain: "notebooklm.google.com" }, res)
    );

    const allCookies = [...googleCookies, ...nlmCookies];

    if (!allCookies.length) {
      msg.textContent = "❌ Nenhum cookie encontrado. Faça login no Google primeiro.";
      msg.className = "msg err";
      btn.disabled = false;
      btn.textContent = originalText;
      return;
    }

    btn.textContent = `⏳ Enviando ${allCookies.length} cookies...`;

    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        secret,
        cookies: allCookies,
        cookies_string: allCookies.map((c) => `${c.name}=${c.value}`).join("; "),
        url,
        source: "chrome_extension",
        cookie_count: allCookies.length,
      }),
    });

    const data = await response.json();

    if (response.ok) {
      msg.textContent = data.message || `✅ ${allCookies.length} cookies enviados!`;
      msg.className = "msg ok";
      btn.textContent = "✅ Feito! Clique para re-autenticar";
      checkStatus();
    } else {
      msg.textContent = `❌ ${data.detail || "Erro do servidor"}`;
      msg.className = "msg err";
      btn.textContent = originalText;
    }
  } catch (e) {
    msg.textContent = `❌ Erro: ${e.message}`;
    msg.className = "msg err";
    btn.textContent = originalText;
  } finally {
    // ALWAYS re-enable the button
    btn.disabled = false;
  }
}

// Attach event listener (MV3 CSP forbids inline onclick)
document.getElementById("authBtn").addEventListener("click", doAuth);
