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
    html_content = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>ReconLens — HNR Labs</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://unpkg.com/htmx.org@2.0.3" crossorigin="anonymous"></script>
<style>
  :root {
    --bg: #101010;
    --surface: #0d0d0d;
    --surface-hover: #141414;
    --gold: #C7B182;
    --gold-bright: #E5D5B3;
    --brand: #634F5F;
    --brand-glow: rgba(99, 79, 95, 0.4);
    --border: #634F5F40;
    --border-focus: #C7B182;
    --muted: #8a7a6a;
  }
  * { box-sizing: border-box; }
  body {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    background: var(--bg);
    background-image: radial-gradient(circle at 1px 1px, #1a1a1a 1px, transparent 0);
    background-size: 24px 24px;
    color: var(--gold);
    margin: 0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 0 20px 40px;
  }
  .brand-bar {
    width: 100%;
    height: 4px;
    background: var(--brand);
    box-shadow: 0 0 8px var(--brand-glow);
    margin-bottom: 40px;
  }
  .container { width: 100%; max-width: 680px; }
  header { text-align: center; margin-bottom: 32px; }
  .icosahedron-center-wrapper {
    display: flex;
    justify-content: center;
    align-items: center;
    margin: 0 auto 16px;
  }
  .central-icosahedron {
    width: 100px;
    height: 100px;
    display: block;
    touch-action: none;
    filter: drop-shadow(0 0 10px var(--brand-glow));
  }
  h1 {
    font-size: 22px;
    font-weight: 600;
    letter-spacing: 0.2em;
    margin: 0 0 6px;
    color: var(--gold-bright);
    text-transform: uppercase;
  }
  .subtitle {
    color: var(--brand);
    font-size: 10px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    font-weight: 600;
    margin: 0;
  }
  form { display: flex; gap: 10px; margin-bottom: 24px; }
  .input-wrapper { position: relative; flex: 1; }
  input {
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--gold-bright);
    padding: 12px 16px;
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
    box-shadow: 0 0 12px rgba(199, 177, 130, 0.12);
  }
  input::placeholder { color: var(--muted); opacity: 0.6; }
  button {
    background: transparent;
    color: var(--gold);
    border: 1px solid var(--brand);
    padding: 12px 22px;
    border-radius: 4px;
    font-family: inherit;
    font-size: 11px;
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
    background: var(--brand);
    color: var(--gold-bright);
    box-shadow: 0 0 14px var(--brand-glow);
  }
  #out {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 18px;
    min-height: 140px;
    font-size: 12px;
    line-height: 1.6;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--gold);
  }
  .htmx-indicator {
    display: none;
    color: var(--gold-bright);
    font-size: 11px;
    letter-spacing: 0.05em;
    animation: pulse 1.5s infinite;
  }
  .htmx-request .htmx-indicator { display: inline-block; }
  @keyframes pulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
  .note {
    margin-top: 32px;
    text-align: center;
    color: var(--muted);
    font-size: 11px;
    line-height: 1.8;
    letter-spacing: 0.04em;
    border-top: 1px solid var(--border);
    padding-top: 18px;
  }
  .note span { color: var(--brand); font-weight: 600; }
  footer {
    margin-top: 40px;
    font-size: 10px;
    letter-spacing: 0.12em;
    color: var(--muted);
    text-transform: uppercase;
    opacity: 0.85;
    text-align: center;
  }
  footer a { color: var(--gold); text-decoration: none; transition: color 0.2s; }
  footer a:hover { color: var(--gold-bright); }
</style>
</head>
<body>
  <div class="brand-bar"></div>
  <div class="container">
    <header>
      <div class="icosahedron-center-wrapper">
        <canvas id="geo" class="central-icosahedron" height="200" width="200"></canvas>
      </div>
      <h1>RECONLENS</h1>
      <p class="subtitle">PASSIVE RECONNAISSANCE · NO ACTIVE SCANNING</p>
    </header>

    <form hx-get="/api/passive/domain" hx-target="#out" hx-indicator="#load">
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

  <script>
    (function() {
      setTimeout(function() {
        console.clear();
        console.log(
          '%c HNR LABS %c SECURITY RESEARCH LAB ',
          'background: #101010; color: #C7B182; padding: 4px 8px; font-weight: bold; border: 1px solid #634F5F; font-family: monospace;',
          'background: #C7B182; color: #101010; padding: 4px 8px; font-weight: bold; font-family: monospace;'
        );
      }, 200);
    })();

    document.body.addEventListener('htmx:afterRequest', function(e) {
      const el = document.getElementById('out');
      if (el && el.innerText) {
        el.innerText = el.innerText
          .replace(/blob:[^\\s\\n"']+/g, '[REDACTED_BLOB]')
          .replace(/(?:api_key|token|secret|auth)[=:]\\s*["']?[a-zA-Z0-9_\\.-]+["']?/gi, '[REDACTED_KEY]');
      }
    });

    (function() {
      const c = document.getElementById('geo');
      if (!c) return;
      const ctx = c.getContext('2d');
      const t = (1 + Math.sqrt(5)) / 2;
      const v = [[-1,t,0],[1,t,0],[-1,-t,0],[1,-t,0],[0,-1,t],[0,1,t],[0,-1,-t],[0,1,-t],[t,0,-1],[t,0,1],[-t,0,-1],[-t,0,1]];
      const ed = [];
      for(let i=0;i<v.length;i++){
        for(let j=i+1;j<v.length;j++){
          const d = Math.hypot(v[i][0]-v[j][0], v[i][1]-v[j][1], v[i][2]-v[j][2]);
          if(Math.abs(d-2)<0.1) ed.push([i,j]);
        }
      }
      let ax=0, ay=0;
      function render(){
        ctx.clearRect(0,0,c.width,c.height);
        const cx=c.width/2, cy=c.height/2, s=45;
        ax+=0.005; ay+=0.008;
        const cxO=Math.cos(ax), sxO=Math.sin(ax), cyO=Math.cos(ay), syO=Math.sin(ay);
        const pts = v.map(p => {
          let x = p[0]*cyO - p[2]*syO;
          let z = p[0]*syO + p[2]*cyO;
          let y = p[1]*cxO - z*sxO;
          return { x: cx + x*s, y: cy + y*s };
        });
        ctx.strokeStyle = '#C7B182';
        ctx.lineWidth = 1.2;
        ed.forEach(e => {
          ctx.beginPath();
          ctx.moveTo(pts[e[0]].x, pts[e[0]].y);
          ctx.lineTo(pts[e[1]].x, pts[e[1]].y);
          ctx.stroke();
        });
        requestAnimationFrame(render);
      }
      render();
    })();
  </script>
</body>
</html>
"""
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
