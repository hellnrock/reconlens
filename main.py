"""
ReconLens v0.2.0 — reconocimiento pasivo con dos niveles de acceso.

Variables de entorno:
  ADMIN_TOKEN  Token del nivel admin (>= 32 caracteres aleatorios). Si no existe, el nivel admin queda
               deshabilitado (falla cerrado).
  PROXY_HOPS   Cuántos proxies confiables hay delante (default 1). Se toma la IP en la posición
               -PROXY_HOPS de X-Forwarded-For. Verifícalo con el honeypot (ver README del cambio).
  HONEYPOT_MODE  "banner" (default) o "stealth". stealth: responde un 404 genérico, sin revelar que
               hay trampa ni mostrar la IP. banner: página 403 de marca que muestra la IP (útil para
               verificar PROXY_HOPS o como disuasión). En ambos modos se registra el CANARY en el log.
  PORT         Puerto (Render lo define).

Dependencias: fastapi, uvicorn, httpx, dnspython>=2.0
"""

import asyncio
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import unquote

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("reconlens")
canary_log = logging.getLogger("reconlens.canary")

app = FastAPI(title="ReconLens", version="0.2.0", docs_url=None, redoc_url=None, openapi_url=None)

# ---------- CONFIG ----------

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
PROXY_HOPS = int(os.environ.get("PROXY_HOPS", "1"))
HONEYPOT_MODE = os.environ.get("HONEYPOT_MODE", "banner").strip().lower()
if HONEYPOT_MODE not in ("stealth", "banner"):
    log.warning("HONEYPOT_MODE=%r no válido: usando 'banner'.", HONEYPOT_MODE)
    HONEYPOT_MODE = "banner"

if not ADMIN_TOKEN:
    log.warning("ADMIN_TOKEN no definido: nivel admin deshabilitado.")
elif len(ADMIN_TOKEN) < 32:
    log.warning("ADMIN_TOKEN tiene menos de 32 caracteres: usa uno aleatorio y largo.")

USER_LIMITS = {"subs": 200, "wayback": 15, "shodan_ips": 1, "findings": 10}
ADMIN_LIMITS = {"subs": 1000, "wayback": 500, "shodan_ips": 5, "findings": None}

MAX_UPSTREAM_BYTES = 8 * 1024 * 1024  # tope por respuesta externa (crt.sh puede ser enorme)
WB_FETCH_LIMIT = 500
SUBS_FETCH_LIMIT = 1000
CACHE_TTL = 3600.0
CACHE_MAX = 256
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

# ---------- UTILIDADES: IP, LIMITADOR, AUTH ----------


def client_ip(request: Request) -> str:
    fallback = request.client.host if request.client else "unknown"
    xff = request.headers.get("x-forwarded-for")
    if xff and PROXY_HOPS > 0:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if len(parts) >= PROXY_HOPS:
            candidate = parts[-PROXY_HOPS]
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                return fallback
    return fallback


class RateLimiter:
    def __init__(self, limit: int, window: float):
        self.limit = limit
        self.window = window
        self.hits: dict[str, deque] = {}

    def check(self, key: str) -> int:
        """0 si se permite; si no, segundos para reintentar."""
        now = time.monotonic()
        q = self.hits.get(key)
        if q is None:
            if len(self.hits) > 10000:
                self._prune(now)
            q = self.hits[key] = deque()
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return max(1, int(self.window - (now - q[0])))
        q.append(now)
        return 0

    def _prune(self, now: float):
        for k in [k for k, q in self.hits.items() if not q or now - q[-1] > self.window]:
            del self.hits[k]
        if len(self.hits) > 10000:  # bajo ataque: preferible resetear a crecer sin tope
            self.hits.clear()


USER_LIMITER = RateLimiter(limit=10, window=60)
ADMIN_LIMITER = RateLimiter(limit=60, window=60)
FAIL_LIMITER = RateLimiter(limit=5, window=300)  # intentos fallidos de token por IP
SCAN_SEM = asyncio.Semaphore(5)  # escaneos simultáneos (protege memoria/salida)


async def authenticate(request: Request, ip: str) -> bool:
    """False = nivel público. True = admin. Token presente pero inválido => 401."""
    supplied = request.headers.get("x-admin-token")
    if supplied is None:
        return False
    ok = bool(ADMIN_TOKEN) and hmac.compare_digest(supplied.encode("utf-8"), ADMIN_TOKEN.encode("utf-8"))
    if ok:
        return True
    retry = FAIL_LIMITER.check(ip)
    log.warning("intento admin fallido desde %s", ip)
    if retry:
        raise HTTPException(429, "demasiados intentos", headers={"Retry-After": str(retry)})
    await asyncio.sleep(1)
    raise HTTPException(401, "token inválido")


# ---------- VALIDACIÓN DE DOMINIO ----------

DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)
SUB_RE = re.compile(r"^[a-z0-9_.-]+$")


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower().rstrip(".").removeprefix("*.")
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            raise HTTPException(400, "invalid domain")
    if not DOMAIN_RE.fullmatch(d):
        raise HTTPException(400, "invalid domain")
    return d


def in_scope(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


# ---------- REDACCIÓN (solo nivel público) ----------
# Propósito: el nivel público ve QUE existe un parámetro/secreto (nombre, ubicación), nunca el valor.
# El admin recibe los datos crudos.

SENSITIVE_PARAM_RE = re.compile(
    r"^(?:.*[_-])?(?:token|secret|password|passwd|pwd|apikey|api[_-]?key|auth|authorization|"
    r"session|sessionid|sessid|sid|jwt|signature|sig|key|bearer)(?:[_-].*)?$",
    re.I,
)
USERINFO_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#@\s]*)@")

SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED_JWT]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|token|secret|password|passwd|auth)\b(\s*[=:]\s*)[\"']?[^\s\"'&;,]+"
        ),
        r"\1\2[REDACTED]",
    ),
]


def redact_url(url: str):
    """Devuelve (url_redactada, [nombres de parámetros sensibles])."""
    flagged: list[str] = []

    m = USERINFO_RE.match(url)
    if m:
        url = m.group(1) + "[REDACTED]@" + url[m.end():]
        flagged.append("userinfo")

    def redact_part(part: str) -> str:
        out = []
        for piece in part.split("&"):
            name, sep, _ = piece.partition("=")
            if sep and SENSITIVE_PARAM_RE.match(unquote(name)):
                flagged.append(unquote(name)[:64])
                out.append(f"{name}=[REDACTED]")
            else:
                out.append(piece)
        return "&".join(out)

    base, hsep, frag = url.partition("#")
    path, qsep, query = base.partition("?")
    if qsep:
        query = redact_part(query)
    if hsep and "=" in frag:
        frag = redact_part(frag)
    return path + qsep + query + hsep + frag, flagged


def sanitize_data(data):
    """Redacta secretos conocidos en cualquier string anidado. NO es protección contra XSS:
    eso lo resuelve la UI renderizando con textContent."""
    if isinstance(data, dict):
        return {k: sanitize_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_data(i) for i in data]
    if isinstance(data, str):
        for pattern, repl in SECRET_PATTERNS:
            data = pattern.sub(repl, data)
        return data
    return data


# ---------- HTTP con tope de tamaño ----------


class UpstreamError(Exception):
    pass


async def fetch_limited(client: httpx.AsyncClient, url: str, params: dict, max_bytes: int) -> bytes:
    async with client.stream("GET", url, params=params) as r:
        if r.status_code != 200:
            raise UpstreamError(f"http_{r.status_code}")
        buf = bytearray()
        async for chunk in r.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise UpstreamError("too_large")
        return bytes(buf)


# ---------- MÓDULOS PASIVOS ----------


async def crtsh(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as c:
            body = await fetch_limited(
                c,
                "https://crt.sh/",
                {"q": f"%.{domain}", "output": "json", "deduplicate": "Y"},
                MAX_UPSTREAM_BYTES,
            )
        subs = set()
        for e in json.loads(body):
            for n in str(e.get("name_value", "")).split("\n"):
                n = n.strip().lower().removeprefix("*.")
                if SUB_RE.fullmatch(n) and in_scope(n, domain):
                    subs.add(n)
        items = sorted(subs)[:SUBS_FETCH_LIMIT]
        return {"status": "ok" if items else "empty", "source": "crt.sh", "items": items}
    except UpstreamError as e:
        return {"status": "error", "source": "crt.sh", "reason": str(e), "items": []}
    except Exception as e:
        return {"status": "error", "source": "crt.sh", "reason": type(e).__name__, "items": []}


async def hackertarget(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as c:
            body = await fetch_limited(
                c, "https://api.hackertarget.com/hostsearch/", {"q": domain}, MAX_UPSTREAM_BYTES
            )
        text = body.decode("utf-8", errors="replace")
        subs = set()
        for line in text.strip().splitlines():
            if "," not in line:
                continue  # las líneas de error de la API no llevan coma
            sub = line.split(",", 1)[0].strip().lower()
            if SUB_RE.fullmatch(sub) and in_scope(sub, domain):
                subs.add(sub)
        items = sorted(subs)[:SUBS_FETCH_LIMIT]
        if items:
            return {"status": "ok", "source": "hackertarget", "items": items}
        # sin resultados válidos: ¿vacío real o error de API (límite, parámetro)?
        looks_like_error = text.strip().lower().startswith(("error", "api count exceeded"))
        return {
            "status": "error" if looks_like_error else "empty",
            "source": "hackertarget",
            "reason": "api_error" if looks_like_error else None,
            "items": [],
        }
    except UpstreamError as e:
        return {"status": "error", "source": "hackertarget", "reason": str(e), "items": []}
    except Exception as e:
        return {"status": "error", "source": "hackertarget", "reason": type(e).__name__, "items": []}


def _is_error(res: dict) -> bool:
    return res.get("status") == "error"


async def with_retry(fn, domain: str, retry_if=_is_error, pause: float = 2.0) -> dict:
    """Un solo reintento, solo si retry_if(resultado) es verdadero. Los fallos de estas fuentes
    suelen ser intermitentes (timeout, 503), pero más de un reintento haría esperar demasiado."""
    res = await fn(domain)
    if retry_if(res):
        await asyncio.sleep(pause)
        res = await fn(domain)
    return res


def _wayback_retryable(res: dict) -> bool:
    """Reintentar solo errores transitorios de Wayback: HTTP 5xx o timeouts."""
    if res.get("status") != "error":
        return False
    reason = str(res.get("reason", ""))
    return reason.startswith("http_5") or "timeout" in reason.lower()


async def find_subdomains(domain: str) -> dict:
    """crt.sh y HackerTarget en paralelo; se UNEN los resultados (cada fuente ve cosas distintas)."""
    results = await asyncio.gather(with_retry(crtsh, domain), hackertarget(domain))

    merged: set = set()
    attempts = []
    for res in results:
        merged.update(res["items"])
        attempts.append(
            {
                "source": res["source"],
                "status": res["status"],
                "reason": res.get("reason"),
                "count": len(res["items"]),
            }
        )

    items = sorted(merged)[:SUBS_FETCH_LIMIT]
    failed = [a for a in attempts if a["status"] == "error"]
    contributing = [a["source"] for a in attempts if a["count"] > 0]
    if items:
        status = "partial" if failed else "ok"  # partial: hay datos, pero una fuente falló
    else:
        status = "error" if failed else "empty"
    return {
        "status": status,
        "source": "+".join(contributing) if contributing else None,
        "items": items,
        "attempts": attempts,
    }


async def dns_records(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0
    records: dict[str, list] = {}
    errors: dict[str, str] = {}

    async def one(rtype: str):
        try:
            ans = await resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in ans]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            records[rtype] = []
            errors[rtype] = "nxdomain"
        except dns.exception.Timeout:
            errors[rtype] = "timeout"
        except Exception as e:
            errors[rtype] = type(e).__name__

    await asyncio.gather(*(one(t) for t in DNS_TYPES))
    return {"records": {t: records.get(t, []) for t in DNS_TYPES}, "errors": errors}


async def shodan_idb(ips: list, max_ips: int) -> dict:
    if not ips:
        return {"status": "no_ip"}
    public = []
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).is_global:
                public.append(ip)
        except ValueError:
            continue
    public = public[:max_ips]
    if not public:
        return {"status": "no_public_ip"}

    async def one(c: httpx.AsyncClient, ip: str) -> dict:
        try:
            r = await c.get(f"https://internetdb.shodan.io/{ip}")
            if r.status_code == 404:
                return {"ip": ip, "status": "not_found"}
            if r.status_code != 200:
                return {"ip": ip, "status": "error", "reason": f"http_{r.status_code}"}
            data = r.json()
            data["ip"] = ip
            data["status"] = "ok"
            return data
        except Exception as e:
            return {"ip": ip, "status": "error", "reason": type(e).__name__}

    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as c:
        results = await asyncio.gather(*(one(c, ip) for ip in public))
    return {
        "status": "ok",
        "results": results,
        "note": "Los datos describen la IP, no necesariamente al objetivo (CDN / hosting compartido).",
    }


CACHE: dict[str, tuple[float, list]] = {}


def cache_get(key: str):
    item = CACHE.get(key)
    if item and time.monotonic() - item[0] < CACHE_TTL:
        return item[1]
    CACHE.pop(key, None)
    return None


def cache_put(key: str, value: list):
    now = time.monotonic()
    for k in [k for k, (t, _) in CACHE.items() if now - t >= CACHE_TTL]:
        del CACHE[k]
    while len(CACHE) >= CACHE_MAX:
        CACHE.pop(next(iter(CACHE)))
    CACHE[key] = (now, value)


async def wayback(domain: str) -> dict:
    cached = cache_get(f"wb_{domain}")
    if cached is not None:
        capped = len(cached) >= WB_FETCH_LIMIT
        return {
            "status": "partial" if capped else "ok",
            "reason": "limit_reached" if capped else None,
            "urls": cached,
            "cached": True,
        }
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=False) as c:
            body = await fetch_limited(
                c,
                "https://web.archive.org/cdx/search/cdx",
                {
                    "url": domain,
                    "matchType": "domain",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": str(WB_FETCH_LIMIT),
                },
                MAX_UPSTREAM_BYTES,
            )
        if not body.strip():
            return {"status": "empty", "urls": []}
        rows = json.loads(body)
        urls = [str(row[0])[:2048] for row in rows[1:] if row]
        if not urls:
            return {"status": "empty", "urls": []}
        cache_put(f"wb_{domain}", urls)  # solo se cachean resultados con datos
        capped = len(urls) >= WB_FETCH_LIMIT
        return {
            "status": "partial" if capped else "ok",
            "reason": "limit_reached" if capped else None,
            "urls": urls,
        }
    except UpstreamError as e:
        return {"status": "error", "reason": str(e), "urls": []}
    except Exception as e:
        return {"status": "error", "reason": type(e).__name__, "urls": []}


# ---------- SEGURIDAD DE CORREO (solo admin) ----------
# SPF + DMARC + DKIM por selectores comunes. Son consultas DNS al dominio objetivo (visibles para sus
# nameservers), por eso solo corren con token admin. Que un selector DKIM no aparezca NO prueba que no
# haya DKIM: el selector puede tener cualquier nombre.

DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
    "mail", "dkim", "brevo", "hostingermail-a", "hostingermail-b", "hostingermail-c",
)


def parse_tags(text: str) -> dict:
    tags = {}
    for part in text.split(";"):
        key, sep, val = part.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = val.strip()
    return tags


def analyze_spf(txts: list) -> dict:
    records = [t for t in txts if t.lower().startswith("v=spf1")]
    if not records:
        return {"status": "missing"}
    rec = records[0]
    tokens = rec.split()[1:]
    all_tok = next((t for t in reversed(tokens) if re.fullmatch(r"[+\-~?]?all", t.lower())), None)
    mech = {"-all": "fail (strict)", "~all": "softfail", "?all": "neutral", "+all": "pass (open to anyone)", "all": "pass (open to anyone)"}
    lookups = 0
    for t in tokens:
        low = t.lower().lstrip("+-~?")
        if low.startswith(("include:", "exists:", "redirect=")) or low in ("a", "mx", "ptr") or low.startswith(("a:", "a/", "mx:", "mx/", "ptr:")):
            lookups += 1
    return {
        "status": "found",
        "record": rec[:512],
        "multiple_records": len(records) > 1,
        "all": all_tok.lower() if all_tok else None,
        "all_meaning": mech.get(all_tok.lower()) if all_tok else "no 'all' mechanism",
        "includes": [t.split(":", 1)[1] for t in tokens if t.lower().startswith("include:")][:20],
        "dns_lookup_terms_top_level": lookups,  # piso, no total: los includes anidados también cuentan (límite 10)
    }


def analyze_dmarc(txts: list) -> dict:
    records = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not records:
        return {"status": "missing"}
    tags = parse_tags(records[0])
    return {
        "status": "found",
        "record": records[0][:512],
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "pct": tags.get("pct"),
        "rua": tags.get("rua"),
        "adkim": tags.get("adkim"),
        "aspf": tags.get("aspf"),
    }


async def _txt_lookup(resolver, name: str):
    """(lista de TXT, error|None). Une los fragmentos de cada registro; sigue CNAMEs."""
    try:
        ans = await resolver.resolve(name, "TXT")
        return ["".join(s.decode("utf-8", errors="replace") for s in r.strings) for r in ans], None
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], None
    except dns.exception.Timeout:
        return [], "timeout"
    except Exception as e:
        return [], type(e).__name__


async def email_security(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0

    root, dmarc, *dkim = await asyncio.gather(
        _txt_lookup(resolver, domain),
        _txt_lookup(resolver, f"_dmarc.{domain}"),
        *(_txt_lookup(resolver, f"{sel}._domainkey.{domain}") for sel in DKIM_SELECTORS),
    )
    spf = analyze_spf(root[0])
    dm = analyze_dmarc(dmarc[0])
    found = [sel for sel, (txts, _) in zip(DKIM_SELECTORS, dkim) if any("p=" in t.lower() for t in txts)]

    issues = []
    if spf["status"] == "missing":
        issues.append("SPF missing")
    else:
        if spf.get("multiple_records"):
            issues.append("Multiple SPF records (invalid: SPF permits only one)")
        if spf.get("all") in ("+all", "all"):
            issues.append("SPF allows any sender (+all)")
        elif spf.get("all") is None:
            issues.append("SPF has no 'all' mechanism")
        elif spf.get("all") == "?all":
            issues.append("SPF is neutral (?all): offers no protection")
        if spf.get("dns_lookup_terms_top_level", 0) >= 8:
            issues.append("SPF uses many DNS lookups; the limit is 10 including nested includes")
    if dm["status"] == "missing":
        issues.append("DMARC missing")
    elif (dm.get("policy") or "").lower() == "none":
        issues.append("DMARC policy is p=none (monitoring only, no enforcement)")
    errors = sorted({e for _, e in [root, dmarc, *dkim] if e})
    return {
        "status": "ok" if not errors else "partial",
        "spf": spf,
        "dmarc": dm,
        "dkim": {
            "selectors_found": found,
            "selectors_checked": len(DKIM_SELECTORS),
            "note": "Only common selector names are tried; a selector not listed here may still exist.",
        },
        "issues": issues,
        "dns_errors": errors,
    }


async def _admin_only() -> dict:
    return {"status": "admin_only"}


# ---------- ENSAMBLADO POR NIVEL ----------

DISCLAIMER = (
    "Passive recon: consulta fuentes públicas de terceros (crt.sh, HackerTarget, Shodan InternetDB, "
    "Wayback) y resolvers DNS. No se abren conexiones a los hosts del objetivo; las consultas DNS pueden "
    "ser visibles para los nameservers autoritativos del dominio."
)


def build_coverage(dns_res: dict, subs: dict, shodan: dict, wb: dict, email_sec: dict) -> dict:
    def mk(status, reason=None):
        return {"status": status, "reason": reason} if reason else {"status": status}

    # DNS: nxdomain es una respuesta válida; los demás errores dejan el módulo incompleto
    errs = {t: e for t, e in dns_res.get("errors", {}).items() if e != "nxdomain"}
    dns_cov = mk("partial", ", ".join(f"{t}:{e}" for t, e in errs.items())) if errs else mk("completed")

    # Subdominios: según cuántas fuentes fallaron
    atts = subs.get("attempts", [])
    failed = [a for a in atts if a.get("status") == "error"]
    if not atts:
        sub_cov = mk("not_assessed")
    elif len(failed) == len(atts):
        sub_cov = mk("failed", "; ".join(f"{a['source']}: {a['reason']}" for a in failed))
    elif failed:
        sub_cov = mk("partial", "; ".join(f"{a['source']}: {a['reason']}" for a in failed))
    else:
        sub_cov = mk("completed")

    # Shodan
    st = shodan.get("status")
    if st == "ok":
        bad = [r for r in shodan.get("results", []) if r.get("status") == "error"]
        shodan_cov = mk("partial", f"{len(bad)} IP con error") if bad else mk("completed")
    elif st in ("no_ip", "no_public_ip"):
        shodan_cov = mk("not_assessed", st)
    else:
        shodan_cov = mk("failed", st)

    # Correo (solo admin)
    es = email_sec.get("status")
    email_cov = {
        "ok": mk("completed"),
        "partial": mk("partial", "errores DNS"),
        "admin_only": mk("not_assessed", "admin_only"),
    }.get(es, mk("failed", es))

    # Wayback
    wst = wb.get("status")
    if wst == "ok":
        wb_cov = mk("completed")
    elif wst == "empty":
        wb_cov = mk("completed", "empty_result")
    elif wst == "partial":
        wb_cov = mk("partial", wb.get("reason") or "incomplete_results")
    else:
        wb_cov = mk("failed", wb.get("reason") or wst)

    na = mk("not_assessed", "module_not_available")
    return {
        "dns": dns_cov,
        "subdomains": sub_cov,
        "shodan": shodan_cov,
        "email_security": email_cov,
        "wayback": wb_cov,
        "tls": na,
        "http_security": na,
        "technology": na,
    }


def assemble(domain: str, admin: bool, dns_res: dict, subs: dict, shodan: dict, wb: dict, email_sec: dict) -> dict:
    lim = ADMIN_LIMITS if admin else USER_LIMITS

    findings = []
    redacted_urls = []
    for u in wb.get("urls", []):
        red, flagged = redact_url(u)
        redacted_urls.append(red)
        if flagged:
            findings.append(
                {
                    "type": "sensitive_url_param",
                    "params": sorted(set(flagged)),
                    "url": u if admin else red,
                    "source": "wayback",
                }
            )
    shown_urls = (wb.get("urls", []) if admin else redacted_urls)[: lim["wayback"]]
    findings_total = len(findings)
    if lim["findings"] is not None:
        findings = findings[: lim["findings"]]

    # Avisos: que "0 hallazgos" no se confunda con "no revisado".
    warnings = []
    for a in subs.get("attempts", []):
        if a["status"] == "error":
            warnings.append(f"{a['source']} failed ({a['reason']}): subdomain list may be incomplete.")
    if wb.get("status") == "error":
        warnings.append(f"wayback failed ({wb.get('reason')}): archived URLs were NOT checked, so findings=0 means not reviewed.")
    wst = wb.get("status")
    if wst == "partial":
        warnings.append("wayback reached its URL limit: the archived URL list is truncated, so findings may be incomplete.")
    findings_status = (
        "partial" if wst == "partial"
        else "checked" if wst in ("ok", "empty")
        else "not_checked"
    )

    sub_items = subs.get("items", [])
    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tier": "admin" if admin else "public",
        "dns": dns_res,
        "subdomains": {
            "status": subs["status"],
            "source": subs.get("source"),
            "attempts": subs.get("attempts", []),
            "total": len(sub_items),
            "items": sub_items[: lim["subs"]],
        },
        "shodan_internetdb": shodan,
        "email_security": email_sec,
        "wayback": {
            "status": wb["status"],
            "reason": wb.get("reason"),
            "fetched": len(wb.get("urls", [])),
            "shown": len(shown_urls),
            "urls": shown_urls,
        },
        "findings": findings,
        "findings_total": findings_total,
        "findings_status": findings_status,
        "assessment_coverage": build_coverage(dns_res, subs, shodan, wb, email_sec),
        "warnings": warnings,
        "disclaimer": DISCLAIMER,
    }
    return result if admin else sanitize_data(result)


# ---------- ENDPOINTS ----------


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/passive/domain")
async def passive(request: Request, domain: str = Query(..., min_length=3, max_length=253)):
    ip = client_ip(request)
    admin = await authenticate(request, ip)

    retry = (ADMIN_LIMITER if admin else USER_LIMITER).check(ip)
    if retry:
        raise HTTPException(429, "rate limit", headers={"Retry-After": str(retry)})

    domain = normalize_domain(domain)

    try:
        await asyncio.wait_for(SCAN_SEM.acquire(), timeout=10)
    except asyncio.TimeoutError:
        raise HTTPException(503, "busy, retry shortly", headers={"Retry-After": "10"})
    try:
        dns_res, subs, wb = await asyncio.gather(
            dns_records(domain),
            find_subdomains(domain),
            # Wayback devuelve 503 y timeouts con frecuencia: un solo reintento para 5xx o timeout
            with_retry(wayback, domain, retry_if=_wayback_retryable),
        )
        lim = ADMIN_LIMITS if admin else USER_LIMITS
        shodan, email_sec = await asyncio.gather(
            shodan_idb(dns_res["records"]["A"], lim["shodan_ips"]),
            email_security(domain) if admin else _admin_only(),
        )
    finally:
        SCAN_SEM.release()

    return JSONResponse(assemble(domain, admin, dns_res, subs, shodan, wb, email_sec))


@app.get("/healthz")
async def health():
    return {"ok": True}


# ---------- HONEYPOTS ----------
# Es un honeypot con log, no un canary token con alerta externa. Los logs de Render free son efímeros.

CANARY_PATHS = [
    "/.env", "/api/.env", "/admin", "/wp-admin", "/wp-login.php", "/config.php",
    "/xmlrpc.php", "/phpmyadmin", "/.git/config", "/.aws/credentials",
]
TARPIT_SLOTS = asyncio.Semaphore(50)

# Respuesta del modo stealth: un 404 de lo más ordinario, sin marca ni pistas.
NOT_FOUND_HTML = (
    "<!doctype html>\n<html>\n<head><title>404 Not Found</title></head>\n"
    "<body>\n<h1>Not Found</h1>\n"
    "<p>The requested URL was not found on this server.</p>\n</body>\n</html>\n"
)

CANARY_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>403 Access Denied</title>
<style>
  body { background-color: #101010; color: #C7B182; font-family: monospace; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; }
  .container { border: 1px solid #634F5F; padding: 40px; box-shadow: 0 0 20px rgba(99, 79, 95, 0.4); max-width: 500px; }
  h1 { font-size: 48px; margin: 0 0 10px 0; color: #E5D5B3; }
  .terminal { text-align: left; background: #0d0d0d; padding: 15px; border: 1px solid #634F5F40; font-size: 12px; margin-top: 20px; line-height: 1.5; }
  .blink { animation: blinker 1s linear infinite; }
  @keyframes blinker { 50% { opacity: 0; } }
  .brand { color: #634F5F; font-weight: bold; letter-spacing: 2px; }
  .tag { font-size: 10px; margin-top: 20px; color: #8a7a6a; }
</style>
</head>
<body>
  <div class="container">
    <h1>403</h1>
    <p class="brand">ACCESS DENIED</p>
    <div class="terminal">
      &gt; INITIALIZING TRAP... [DONE]<br>
      &gt; IDENTIFYING SOURCE... [LOGGED]<br>
      &gt; IP: {{IP}}<br>
      &gt; <span class="blink">_</span>
    </div>
    <p class="tag">HELLNROCK SECURITY SYSTEMS</p>
  </div>
</body>
</html>"""


async def canary_trap(request: Request):
    ip = client_ip(request)
    ua = request.headers.get("user-agent", "unknown")[:200]
    # %r neutraliza saltos de línea (log injection)
    canary_log.warning(
        "CANARY mode=%s method=%s path=%r ip=%s xff=%r ua=%r",
        HONEYPOT_MODE, request.method, request.url.path, ip,
        request.headers.get("x-forwarded-for", "")[:200], ua,
    )

    # stealth: demora corta, que no destaque; banner: tarpit visible de 3 s
    delay = 1 if HONEYPOT_MODE == "stealth" else 3
    if not TARPIT_SLOTS.locked():  # tarpit acotado: no te conviertas en tu propio DoS
        async with TARPIT_SLOTS:
            await asyncio.sleep(delay)

    if HONEYPOT_MODE == "stealth":
        # HEAD sin cuerpo; el resto, un 404 genérico que no delata nada
        body = "" if request.method == "HEAD" else NOT_FOUND_HTML
        return HTMLResponse(body, status_code=404)

    return HTMLResponse(
        CANARY_HTML.replace("{{IP}}", html.escape(ip)),
        status_code=403,
        headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"},
    )


for _p in CANARY_PATHS:
    app.add_api_route(
        _p, canary_trap,
        methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        include_in_schema=False,
    )

# ---------- UI ----------

INDEX_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>ReconLens — HNR Labs</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style nonce="__NONCE__">
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
    color-scheme: dark;
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
  .brand-bar { width: 100%; height: 4px; background: var(--brand); box-shadow: 0 0 8px var(--brand-glow); margin-bottom: 40px; }
  .container { width: 100%; max-width: 680px; }
  header { text-align: center; margin-bottom: 32px; }
  .icosahedron-center-wrapper { display: flex; justify-content: center; align-items: center; margin: 0 auto 16px; }
  .central-icosahedron { width: 100px; height: 100px; display: block; touch-action: none; filter: drop-shadow(0 0 10px var(--brand-glow)); }
  h1 { font-size: 22px; font-weight: 600; letter-spacing: 0.2em; margin: 0 0 6px; color: var(--gold-bright); text-transform: uppercase; }
  .subtitle { color: var(--brand); font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; font-weight: 600; margin: 0; }
  form { display: flex; gap: 10px; margin-bottom: 12px; }
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
  input:focus { border-color: var(--border-focus); background: var(--surface-hover); box-shadow: 0 0 12px rgba(199, 177, 130, 0.12); }
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
  button:hover { background: var(--brand); color: var(--gold-bright); box-shadow: 0 0 14px var(--brand-glow); }
  details { margin-bottom: 24px; color: var(--muted); font-size: 11px; letter-spacing: 0.06em; }
  summary { cursor: pointer; }
  details .input-wrapper { margin-top: 10px; }
  .code-block {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 8px;
  }
  .code-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 14px;
    background: var(--surface-deep, #0a0a0a);
    border-bottom: 1px solid var(--border);
    font-size: 12px;
    letter-spacing: 0.06em;
    color: var(--muted);
  }
  .code-header button {
    font-family: inherit;
    background: transparent;
    border: 1px solid var(--border);
    color: var(--gold);
    padding: 6px 12px;
    font-size: 11px;
    letter-spacing: 0.08em;
    border-radius: 3px;
    cursor: pointer;
    transition: border-color 0.15s, background 0.15s;
  }
  .code-header button:hover {
    border-color: var(--gold);
    background: color-mix(in srgb, var(--gold) 8%, transparent);
    box-shadow: none;
    color: var(--gold);
  }
  .code-header button:focus-visible {
    outline: 2px solid var(--gold);
    outline-offset: 2px;
  }
  .code-out {
    margin: 0;
    border: none;
    border-radius: 0;
    padding: 16px;
    min-height: 140px;
    max-height: 60vh;
    font-size: 12px;
    line-height: 1.6;
    overflow: auto;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    color: var(--gold);
    scrollbar-width: thin;
    scrollbar-color: var(--brand) var(--surface);
  }
  .code-out::-webkit-scrollbar { width: 10px; height: 10px; }
  .code-out::-webkit-scrollbar-track { background: var(--surface); }
  .code-out::-webkit-scrollbar-thumb { background: var(--brand); border: 2px solid var(--surface); border-radius: 6px; }
  .code-out::-webkit-scrollbar-thumb:hover { background: var(--gold-dim, #8f7f5c); }
  .code-out::-webkit-scrollbar-corner { background: var(--surface); }
  .code-actions { display: flex; gap: 8px; }
  .indicator { display: none; color: var(--gold-bright); font-size: 11px; letter-spacing: 0.05em; animation: pulse 1.5s infinite; }
  .indicator.on { display: inline-block; }
  @keyframes pulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
  .note { margin-top: 32px; text-align: center; color: var(--muted); font-size: 11px; line-height: 1.8; letter-spacing: 0.04em; border-top: 1px solid var(--border); padding-top: 18px; }
  .note span { color: var(--brand); font-weight: 600; }
  footer { margin-top: 40px; font-size: 10px; letter-spacing: 0.12em; color: var(--muted); text-transform: uppercase; opacity: 0.85; text-align: center; }
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

    <form id="f">
      <div class="input-wrapper">
        <input id="domain" name="domain" placeholder="labs.hellnrock.com" required autocomplete="off" spellcheck="false" maxlength="253">
      </div>
      <button type="submit">
        <span>ANALYZE</span>
        <span id="load" class="indicator">[...]</span>
      </button>
    </form>

    <details>
      <summary>ADMIN</summary>
      <div class="input-wrapper">
        <input id="tok" type="password" placeholder="admin token (opcional)" autocomplete="off" spellcheck="false">
      </div>
    </details>

    <div class="code-block">
      <div class="code-header">
        <span>RESULT</span>
        <div class="code-actions">
          <button type="button" id="clear-btn">CLEAR</button>
          <button type="button" id="copy-btn">COPY</button>
        </div>
      </div>
      <pre id="out" class="code-out">// Waiting for target domain input...</pre>
    </div>

    <div class="note">
      Public sources: <span>crt.sh</span> · <span>HackerTarget</span> · <span>Shodan InternetDB</span> · <span>Wayback</span> · <span>DNS</span><br>
      <i>Render Free Tier: first request after idle state may take up to 50s</i>
    </div>
  </div>

  <footer>
    POWERED BY <a href="https://labs.hellnrock.com" target="_blank" rel="noopener">LABS.HELLNROCK.COM</a>
  </footer>

  <script nonce="__NONCE__">
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

    // Los datos de DNS/Wayback/certificados son hostiles: se pintan SIEMPRE con textContent, nunca como HTML.
    (function() {
      const form = document.getElementById('f');
      const out = document.getElementById('out');
      const load = document.getElementById('load');
      form.addEventListener('submit', async function(ev) {
        ev.preventDefault();
        const domain = document.getElementById('domain').value.trim();
        const token = document.getElementById('tok').value;
        const headers = {};
        if (token) headers['X-Admin-Token'] = token;
        load.classList.add('on');
        out.textContent = '// Working...';
        try {
          const r = await fetch('/api/passive/domain?domain=' + encodeURIComponent(domain), { headers: headers });
          const ct = r.headers.get('content-type') || '';
          const body = ct.indexOf('json') !== -1 ? await r.json() : await r.text();
          out.textContent = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
        } catch (e) {
          out.textContent = '// Network error';
        } finally {
          load.classList.remove('on');
        }
      });
    })();

    (function() {
      const c = document.getElementById('geo');
      if (!c) return;
      const ctx = c.getContext('2d');
      const t = (1 + Math.sqrt(5)) / 2;
      const v = [[-1,t,0],[1,t,0],[-1,-t,0],[1,-t,0],[0,-1,t],[0,1,t],[0,-1,-t],[0,1,-t],[t,0,-1],[t,0,1],[-t,0,-1],[-t,0,1]];
      const ed = [];
      for (let i = 0; i < v.length; i++) {
        for (let j = i + 1; j < v.length; j++) {
          const d = Math.hypot(v[i][0]-v[j][0], v[i][1]-v[j][1], v[i][2]-v[j][2]);
          if (Math.abs(d - 2) < 0.1) ed.push([i, j]);
        }
      }
      let ax = 0, ay = 0;
      function render() {
        ctx.clearRect(0, 0, c.width, c.height);
        const cx = c.width / 2, cy = c.height / 2, s = 45;
        ax += 0.005; ay += 0.008;
        const cxO = Math.cos(ax), sxO = Math.sin(ax), cyO = Math.cos(ay), syO = Math.sin(ay);
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
        document.getElementById('clear-btn').addEventListener('click', function() {
      const dom = document.getElementById('domain');
      document.getElementById('out').textContent = '// Waiting for target domain input...';
      dom.value = '';
      dom.focus();
    });

    document.getElementById('copy-btn').addEventListener('click', function() {
      const el = document.getElementById('out');
      const text = el.innerText || el.textContent;
      navigator.clipboard.writeText(text).then(() => {
        this.textContent = 'COPIED';
        setTimeout(() => this.textContent = 'COPY', 1500);
      }).catch(() => {
        const range = document.createRange();
        range.selectNodeContents(el);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        document.execCommand('copy');
        sel.removeAllRanges();
        this.textContent = 'COPIED';
        setTimeout(() => this.textContent = 'COPY', 1500);
      });
    });
  </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    nonce = secrets.token_urlsafe(16)
    csp = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        f"style-src 'nonce-{nonce}'; "
        "connect-src 'self'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    return HTMLResponse(
        INDEX_TEMPLATE.replace("__NONCE__", nonce),
        headers={"Content-Security-Policy": csp},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
