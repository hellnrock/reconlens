from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.concurrency import run_in_threadpool
import httpx
import asyncio
import dns.resolver
from datetime import datetime, timezone, timedelta

app = FastAPI(title="ReconLens", version="0.1.0")

# Caché simple para Wayback
CACHE = {}
CACHE_TTL = timedelta(hours=1)

# ---------- MÓDULOS PASIVOS ----------

async def crtsh(domain: str):
    """Certificate Transparency con timeout de 30s + fallback a HackerTarget.
    Siempre devuelve lista (nunca dict)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return await hackertarget(domain)

            subs = set()
            for e in r.json():
                for n in e.get("name_value", "").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith(domain) and "*" not in n:
                        subs.add(n)
            return sorted(subs)[:200] if subs else await hackertarget(domain)
    except Exception:
        return await hackertarget(domain)


async def hackertarget(domain: str):
    """Plan B: HackerTarget. Siempre devuelve lista."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
            if r.status_code != 200 or "error" in r.text.lower():
                return []

            subs = set()
            for line in r.text.strip().split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if sub.endswith(domain):
                        subs.add(sub)
            return sorted(list(subs))[:200]
    except Exception:
        return []


async def shodan_idb(domain: str):
    """InternetDB solo acepta IP. Resolvemos la IP en threadpool para no bloquear."""
    def resolve_ip():
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=5)
            return str(answers[0])
        except Exception:
            return None

    ip = await run_in_threadpool(resolve_ip)
    if not ip:
        return {"status": "no_ip"}

    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"https://internetdb.shodan.io/{ip}")
            if r.status_code != 200:
                return {"status": "not_found", "ip": ip}
            data = r.json()
            data["ip"] = ip
            return data
    except Exception:
        return {"error": "Shodan no disponible", "ip": ip}


async def wayback(domain: str):
    """Wayback con caché de 1h y límite de 100."""
    cache_key = f"wb_{domain}"
    now = datetime.now()

    if cache_key in CACHE:
        data, timestamp = CACHE[cache_key]
        if now - timestamp < CACHE_TTL:
            return data

    try:
        async with httpx.AsyncClient(timeout=25) as c:
            r = await c.get(
                "http://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "100",
                },
            )
            if r.status_code != 200:
                return []
            data = r.json()
            result = [row[0] for row in data[1:]] if len(data) > 1 else []
            CACHE[cache_key] = (result, now)
            return result
    except Exception:
        return []


def dns_records_sync(domain: str):
    """Versión síncrona que se ejecutará en un hilo separado."""
    out = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=5)
            out[rtype] = [str(r) for r in ans]
        except Exception:
            out[rtype] = []
    return out

# ---------- ENDPOINTS ----------

@app.get("/api/passive/domain")
async def passive(domain: str = Query(..., min_length=3)):
    domain = domain.lower().strip().lstrip("*.").rstrip("/")
    if "." not in domain:
        raise HTTPException(400, "invalid domain")

    crt, shodan, wb = await asyncio.gather(
        crtsh(domain), shodan_idb(domain), wayback(domain)
    )
    dns_data = await run_in_threadpool(dns_records_sync, domain)

    return {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dns": dns_data,
        "subdomains": crt,
        "shodan_internetdb": shodan,
        "wayback_urls_sample": wb[:15],
        "disclaimer": "Passive recon only. No packets sent to target.",
    }


@app.get("/healthz")
async def health():
    return {"ok": True}

# ---------- UI ----------
@app.get("/", response_class=HTMLResponse)
async def index():
    return """
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>ReconLens — HellNRock Labs</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://unpkg.com/htmx.org@2.0.3"></script>
<style>
  :root {
    --bg: #0a0b0f;
    --surface: #101010;
    --surface-hover: #161618;
    --text: #C7B182;
    --text-bright: #E5D5B3;
    --cyan: #00D4CE;
    --muted: #7a6c5d;
    --accent: #634F5F;
    --border: #634F5F40;
    --border-focus: #00D4CE;
  }

  * { box-sizing: border-box; }

  body {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    background: var(--bg);
    background-image: radial-gradient(circle at 1px 1px, #1a1b22 1px, transparent 0);
    background-size: 24px 24px;
    color: var(--text);
    margin: 0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 60px 20px 40px;
  }

  .container {
    width: 100%;
    max-width: 720px;
  }

  header {
    text-align: center;
    margin-bottom: 44px;
  }

  .logo {
    width: 64px;
    height: 64px;
    margin: 0 auto 20px;
    position: relative;
  }

  .logo svg {
    width: 100%;
    height: 100%;
    stroke: var(--cyan);
    stroke-width: 1.2;
    fill: none;
    opacity: 0.9;
    animation: float 6s ease-in-out infinite;
  }

  @keyframes float {
    0%, 100% { transform: translateY(0) rotate(0deg); }
    50% { transform: translateY(-5px) rotate(1deg); }
  }

  h1 {
    font-size: 24px;
    font-weight: 600;
    letter-spacing: 0.18em;
    margin: 0 0 8px;
    color: var(--text-bright);
    text-transform: uppercase;
  }

  .subtitle {
    color: var(--muted);
    font-size: 11px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin: 0;
  }

  form {
    display: flex;
    gap: 10px;
    margin-bottom: 28px;
  }

  .input-wrapper {
    position: relative;
    flex: 1;
  }

  input {
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-bright);
    padding: 14px 16px;
    border-radius: 4px;
    font-family: inherit;
    font-size: 13px;
    letter-spacing: 0.03em;
    outline: none;
    transition: all 0.2s ease;
  }

  input:focus {
    border-color: var(--border-focus);
    background: var(--surface-hover);
    box-shadow: 0 0 12px rgba(0, 212, 206, 0.12);
  }

  input::placeholder {
    color: var(--muted);
    opacity: 0.6;
  }

  button {
    background: transparent;
    color: var(--cyan);
    border: 1px solid var(--cyan);
    padding: 14px 24px;
    border-radius: 4px;
    font-family: inherit;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.12em;
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    gap: 8px;
    white-space: nowrap;
  }

  button:hover {
    background: var(--cyan);
    color: var(--bg);
    box-shadow: 0 0 16px rgba(0, 212, 206, 0.25);
  }

  #out {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 20px;
    min-height: 140px;
    font-size: 12px;
    line-height: 1.6;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--text);
  }

  .htmx-indicator {
    display: none;
    color: var(--cyan);
    font-size: 12px;
    letter-spacing: 0.05em;
    animation: pulse 1.5s infinite;
  }

  .htmx-request .htmx-indicator {
    display: inline-block;
  }

  @keyframes pulse {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 1; }
  }

  .note {
    margin-top: 36px;
    text-align: center;
    color: var(--muted);
    font-size: 11px;
    line-height: 1.8;
    letter-spacing: 0.04em;
  }

  .note span {
    color: var(--accent);
  }

  footer {
    margin-top: 48px;
    font-size: 10px;
    letter-spacing: 0.12em;
    color: var(--muted);
    text-transform: uppercase;
    opacity: 0.75;
    text-align: center;
  }

  footer a {
    color: var(--text);
    text-decoration: none;
    transition: color 0.2s;
  }

  footer a:hover {
    color: var(--cyan);
  }
</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
          <polygon points="50,10 85,35 70,80 30,80 15,35" />
          <polygon points="50,10 15,35 50,50" />
          <polygon points="50,10 85,35 50,50" />
          <polygon points="15,35 30,80 50,50" />
          <polygon points="85,35 70,80 50,50" />
          <polygon points="30,80 70,80 50,50" />
          <line x1="50" y1="10" x2="50" y2="50" />
          <line x1="15" y1="35" x2="85" y2="35" />
          <line x1="30" y1="80" x2="70" y2="80" />
        </svg>
      </div>
      <h1>RECONLENS</h1>
      <p class="subtitle">PASSIVE RECONNAISSANCE · NO ACTIVE SCANNING</p>
    </header>

    <form hx-get="/api/passive/domain" 
          hx-target="#out" 
          hx-indicator="#load"
          hx-on::after-request="
            const el = document.getElementById('out');
            if (el) {
              el.innerText = el.innerText
                .replace(/blob:[^\\s\\n"']+/g, '[REDACTED_BLOB]')
                .replace(/(?:api_key|token|secret|auth)[=:]\\s*["']?[a-zA-Z0-9_\\.-]+["']?/gi, '[REDACTED_KEY]');
            }
          ">
      <div class="input-wrapper">
        <input name="domain" placeholder="labs.hellnrock.com" required autocomplete="off" spellcheck="false">
      </div>
      <button type="submit">
        <span>ANALYZE</span>
        <span id="load" class="htmx-indicator">[...]</span>
      </button>
    </form>

    <pre id="out">// Waiting for target domain input...</pre>

    <div class="note">
      Public sources: <span>crt.sh</span> · <span>HackerTarget</span> · <span>Shodan InternetDB</span> · <span>Wayback</span> · <span>DNS</span><br>
      <i>Render Free Tier: first request after idle state may take up to 50s</i>
    </div>
  </div>

  <footer>
    POWERED BY <a href="https://labs.hellnrock.com" target="_blank" rel="noopener">LABS.HELLNROCK.COM</a>
  </footer>
</body>
</html>
"""
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
