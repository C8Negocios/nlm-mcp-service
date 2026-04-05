const API_URL = "http://nlm.codigooito.com.br/api/auth-bookmarklet";
const STORAGE_KEY = "nlm_secret";

// Load saved secret
chrome.storage.local.get([STORAGE_KEY], (r) => {
  if (r[STORAGE_KEY]) document.getElementById("secret").value = r[STORAGE_KEY];
});

// Save secret on change
document.getElementById("secret").addEventListener("change", (e) => {
  chrome.storage.local.set({ [STORAGE_KEY]: e.target.value });
});

// Check current auth status
fetch(API_URL.replace("/api/auth-bookmarklet", "/api/status"))
  .then(r => r.json())
  .then(d => {
    const badge = document.getElementById("badge");
    if (d.status === "authenticated") {
      badge.textContent = "Autenticado ✓";
      badge.className = "badge ok";
    } else {
      badge.textContent = "Não Autenticado";
      badge.className = "badge no";
    }
  })
  .catch(() => {
    document.getElementById("badge").textContent = "Servidor offline";
  });

async function doAuth() {
  const secret = document.getElementById("secret").value.trim();
  const btn = document.getElementById("authBtn");
  const msg = document.getElementById("msg");

  if (!secret) {
    msg.textContent = "Digite a chave de acesso primeiro";
    msg.className = "msg err";
    return;
  }

  btn.disabled = true;
  btn.textContent = "⏳ Capturando cookies...";
  msg.textContent = "";
  msg.className = "msg";

  // Get current active tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || "";

  if (!url.includes("google.com")) {
    document.getElementById("warning").style.display = "block";
    btn.disabled = false;
    btn.textContent = "🔑 Autenticar agora";
    return;
  }

  // Capture ALL cookies for google.com (including HttpOnly via chrome.cookies)
  chrome.cookies.getAll({ domain: "google.com" }, async (googleCookies) => {
    chrome.cookies.getAll({ domain: "notebooklm.google.com" }, async (nlmCookies) => {
      const allCookies = [...googleCookies, ...nlmCookies];

      if (!allCookies.length) {
        msg.textContent = "Nenhum cookie encontrado. Faça login no Google primeiro.";
        msg.className = "msg err";
        btn.disabled = false;
        btn.textContent = "🔑 Autenticar agora";
        return;
      }

      btn.textContent = "⏳ Enviando para servidor...";

      try {
        const response = await fetch(API_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            secret: secret,
            cookies: allCookies,           // Full cookie objects (name, value, domain, path, httpOnly, secure, expirationDate)
            cookies_string: allCookies.map(c => `${c.name}=${c.value}`).join("; "),
            url: url,
            source: "chrome_extension",
            cookie_count: allCookies.length
          })
        });

        const data = await response.json();

        if (response.ok) {
          msg.textContent = data.message || "✅ Autenticado com sucesso!";
          msg.className = "msg ok";
          btn.textContent = "✅ Autenticado!";
          document.getElementById("badge").textContent = "Autenticado ✓";
          document.getElementById("badge").className = "badge ok";
          // Save secret for next time
          chrome.storage.local.set({ [STORAGE_KEY]: secret });
        } else {
          msg.textContent = data.detail || "Erro ao autenticar";
          msg.className = "msg err";
          btn.disabled = false;
          btn.textContent = "🔑 Autenticar agora";
        }
      } catch (e) {
        msg.textContent = "Erro de conexão com o servidor";
        msg.className = "msg err";
        btn.disabled = false;
        btn.textContent = "🔑 Autenticar agora";
      }
    });
  });
}
