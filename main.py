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
<title>ReconLens — passive recon</title>
<script src="https://unpkg.com/htmx.org@2.0.3"></script>
<style>
  /* Branding Hellnrock */
  body {
    font-family: monospace, system-ui; 
    background-color: #101010; 
    color: #C7B182; 
    max-width: 900px; 
    margin: 40px auto; 
    padding: 0 20px;
  }
  h1 { 
    color: #C7B182; 
    border-bottom: 2px solid #634F5F2E; 
    padding-bottom: 10px;
  }
  p { 
    color: #634F5F; 
    font-weight: bold;
  }
  form {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
  }
  input {
    background-color: #0d0d0d; 
    border: 1px solid #634F5F; 
    color: #C7B182; 
    padding: 12px; 
    border-radius: 4px; 
    width: 60%;
    outline: none;
  }
  input:focus {
    border-color: #C7B182;
  }
  button {
    background-color: #634F5F; 
    color: #C7B182; 
    border: 1px solid #C7B182; 
    padding: 10px 20px; 
    border-radius: 4px; 
    cursor: pointer;
    font-weight: bold;
    transition: all 0.3s ease;
  }
  button:hover {
    background-color: #C7B182;
    color: #101010;
  }
  pre {
    background-color: #0d0d0d; 
    border: 1px solid #634F5F2E; 
    color: #C7B182;
    padding: 16px; 
    border-radius: 4px; 
    overflow: auto; 
    font-size: 13px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.3);
  }
  .note {
    color: #634F5F; 
    font-size: 12px; 
    margin-top: 30px;
    border-top: 1px solid #634F5F2E;
    padding-top: 15px;
  }
</style>
</head>
<body>
  <h1>🔍 ReconLens</h1>
  <p>Passive reconnaissance. No active scanning. No payloads.</p>
  
  <form hx-get="/api/passive/domain" hx-target="#out" hx-indicator="#load">
    <input name="domain" placeholder="labs.hellnrock.com" required>
    <button>Analyze</button>
    <span id="load" class="htmx-indicator" style="color: #C7B182;">⏳...</span>
  </form>
  
  <pre id="out"></pre>
  
  <div class="note">
    All data from public sources (crt.sh, HackerTarget, Shodan IDB, Wayback, DNS).<br>
    <i>Nota: Si la app está dormida (Render Free Tier), la primera carga puede tardar hasta 50s.</i>
  </div>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
