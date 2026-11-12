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

MAX_UPSTREAM_BYTES = 8 * 1024 * 1024
WB_FETCH_LIMIT = 500
SUBS_FETCH_LIMIT = 1000
CACHE_TTL = 3600.0
CACHE_MAX = 256
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


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
        if len(self.hits) > 10000:
            self.hits.clear()


USER_LIMITER = RateLimiter(limit=10, window=60)
ADMIN_LIMITER = RateLimiter(limit=60, window=60)
FAIL_LIMITER = RateLimiter(limit=5, window=300)
SCAN_SEM = asyncio.Semaphore(5)


async def authenticate(request: Request, ip: str) -> bool:
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
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    (
        re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|token|secret|password|passwd|auth)\b(\s*[=:]\s*)[\"']?[^\s\"'&;,]+"),
        r"\1\2[REDACTED]",
    ),
]


def redact_url(url: str):
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
    if isinstance(data, dict):
        return {k: sanitize_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_data(i) for i in data]
    if isinstance(data, str):
        for pattern, repl in SECRET_PATTERNS:
            data = pattern.sub(repl, data)
        return data
    return data


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


async def crtsh(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as c:
            body = await fetch_limited(c, "https://crt.sh/", {"q": f"%.{domain}", "output": "json", "deduplicate": "Y"}, MAX_UPSTREAM_BYTES)
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
            body = await fetch_limited(c, "https://api.hackertarget.com/hostsearch/", {"q": domain}, MAX_UPSTREAM_BYTES)
        text = body.decode("utf-8", errors="replace")
        subs = set()
        for line in text.strip().splitlines():
            if "," not in line:
                continue
            sub = line.split(",", 1)[0].strip().lower()
            if SUB_RE.fullmatch(sub) and in_scope(sub, domain):
                subs.add(sub)
        items = sorted(subs)[:SUBS_FETCH_LIMIT]
        if items:
            return {"status": "ok", "source": "hackertarget", "items": items}
        looks_like_error = text.strip().lower().startswith(("error", "api count exceeded"))
        return {"status": "error" if looks_like_error else "empty", "source": "hackertarget", "reason": "api_error" if looks_like_error else None, "items": []}
    except UpstreamError as e:
        return {"status": "error", "source": "hackertarget", "reason": str(e), "items": []}
    except Exception as e:
        return {"status": "error", "source": "hackertarget", "reason": type(e).__name__, "items": []}


def _is_error(res: dict) -> bool:
    return res.get("status") == "error"


async def with_retry(fn, domain: str, retry_if=_is_error, pause: float = 2.0) -> dict:
    res = await fn(domain)
    if retry_if(res):
        await asyncio.sleep(pause)
        res = await fn(domain)
    return res


def _wayback_retryable(res: dict) -> bool:
    if res.get("status") != "error":
        return False
    reason = str(res.get("reason", ""))
    return reason.startswith("http_5") or "timeout" in reason.lower()


async def find_subdomains(domain: str) -> dict:
    results = await asyncio.gather(with_retry(crtsh, domain), hackertarget(domain))
    merged: set = set()
    attempts = []
    for res in results:
        merged.update(res["items"])
        attempts.append({"source": res["source"], "status": res["status"], "reason": res.get("reason"), "count": len(res["items"])})
    items = sorted(merged)[:SUBS_FETCH_LIMIT]
    failed = [a for a in attempts if a["status"] == "error"]
    contributing = [a["source"] for a in attempts if a["count"] > 0]
    if items:
        status = "partial" if failed else "ok"
    else:
        status = "error" if failed else "empty"
    return {"status": status, "source": "+".join(contributing) if contributing else None, "items": items, "attempts": attempts}


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
    return {"status": "ok", "results": results, "note": "Los datos describen la IP, no necesariamente al objetivo (CDN / hosting compartido)."}


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
        return {"status": "partial" if capped else "ok", "reason": "limit_reached" if capped else None, "urls": cached, "cached": True}
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=False) as c:
            body = await fetch_limited(c, "https://web.archive.org/cdx/search/cdx", {
                "url": domain, "matchType": "domain", "output": "json", "fl": "original",
                "collapse": "urlkey", "limit": str(WB_FETCH_LIMIT),
            }, MAX_UPSTREAM_BYTES)
        if not body.strip():
            return {"status": "empty", "urls": []}
        rows = json.loads(body)
        urls = [str(row[0])[:2048] for row in rows[1:] if row]
        if not urls:
            return {"status": "empty", "urls": []}
        cache_put(f"wb_{domain}", urls)
        capped = len(urls) >= WB_FETCH_LIMIT
        return {"status": "partial" if capped else "ok", "reason": "limit_reached" if capped else None, "urls": urls}
    except UpstreamError as e:
        return {"status": "error", "reason": str(e), "urls": []}
    except Exception as e:
        return {"status": "error", "reason": type(e).__name__, "urls": []}


DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim", "brevo", "hostingermail-a", "hostingermail-b", "hostingermail-c")


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
    lookups = sum(1 for t in tokens if t.lower().lstrip("+-~?").startswith(("include:", "exists:", "redirect=")) or t.lower().lstrip("+-~?") in ("a", "mx", "ptr") or t.lower().lstrip("+-~?").startswith(("a:", "a/", "mx:", "mx/", "ptr:")))
    return {"status": "found", "record": rec[:512], "multiple_records": len(records) > 1, "all": all_tok.lower() if all_tok else None, "all_meaning": mech.get(all_tok.lower()) if all_tok else "no 'all' mechanism", "includes": [t.split(":", 1)[1] for t in tokens if t.lower().startswith("include:")][:20], "dns_lookup_terms_top_level": lookups}


def analyze_dmarc(txts: list) -> dict:
    records = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not records:
        return {"status": "missing"}
    tags = parse_tags(records[0])
    return {"status": "found", "record": records[0][:512], "policy": tags.get("p"), "subdomain_policy": tags.get("sp"), "pct": tags.get("pct"), "rua": tags.get("rua"), "adkim": tags.get("adkim"), "aspf": tags.get("aspf")}


async def _txt_lookup(resolver, name: str):
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
    root, dmarc, *dkim = await asyncio.gather(_txt_lookup(resolver, domain), _txt_lookup(resolver, f"_dmarc.{domain}"), *(_txt_lookup(resolver, f"{sel}._domainkey.{domain}") for sel in DKIM_SELECTORS))
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
    return {"status": "ok" if not errors else "partial", "spf": spf, "dmarc": dm, "dkim": {"selectors_found": found, "selectors_checked": len(DKIM_SELECTORS), "note": "Only common selector names are tried; a selector not listed here may still exist."}, "issues": issues, "dns_errors": errors}


async def _admin_only() -> dict:
    return {"status": "admin_only"}


DISCLAIMER = ("Passive recon: consulta fuentes públicas de terceros (crt.sh, HackerTarget, Shodan InternetDB, Wayback) y resolvers DNS. No se abren conexiones a los hosts del objetivo; las consultas DNS pueden ser visibles para los nameservers autoritativos del dominio.")


def build_coverage(dns_res: dict, subs: dict, shodan: dict, wb: dict, email_sec: dict) -> dict:
    def mk(status, reason=None):
        return {"status": status, "reason": reason} if reason else {"status": status}
    errs = {t: e for t, e in dns_res.get("errors", {}).items() if e != "nxdomain"}
    dns_cov = mk("partial", ", ".join(f"{t}:{e}" for t, e in errs.items())) if errs else mk("completed")
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
    st = shodan.get("status")
    if st == "ok":
        bad = [r for r in shodan.get("results", []) if r.get("status") == "error"]
        shodan_cov = mk("partial", f"{len(bad)} IP con error") if bad else mk("completed")
    elif st in ("no_ip", "no_public_ip"):
        shodan_cov = mk("not_assessed", st)
    else:
        shodan_cov = mk("failed", st)
    es = email_sec.get("status")
    email_cov = {"ok": mk("completed"), "partial": mk("partial", "errores DNS"), "admin_only": mk("not_assessed", "admin_only")}.get(es, mk("failed", es))
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
    return {"dns": dns_cov, "subdomains": sub_cov, "shodan": shodan_cov, "email_security": email_cov, "wayback": wb_cov, "tls": na, "http_security": na, "technology": na}


def assemble(domain: str, admin: bool, dns_res: dict, subs: dict, shodan: dict, wb: dict, email_sec: dict) -> dict:
    lim = ADMIN_LIMITS if admin else USER_LIMITS
    findings = []
    redacted_urls = []
    for u in wb.get("urls", []):
        red, flagged = redact_url(u)
        redacted_urls.append(red)
        if flagged:
            findings.append({"type": "sensitive_url_param", "params": sorted(set(flagged)), "url": u if admin else red, "source": "wayback"})
    shown_urls = (wb.get("urls", []) if admin else redacted_urls)[: lim["wayback"]]
    findings_total = len(findings)
    if lim["findings"] is not None:
        findings = findings[: lim["findings"]]
    warnings = []
    for a in subs.get("attempts", []):
        if a["status"] == "error":
            warnings.append(f"{a['source']} failed ({a['reason']}): subdomain list may be incomplete.")
    if wb.get("status") == "error":
        warnings.append(f"wayback failed ({wb.get('reason')}): archived URLs were NOT checked, so findings=0 means not reviewed.")
    wst = wb.get("status")
    if wst == "partial":
        warnings.append("wayback reached its URL limit: the archived URL list is truncated, so findings may be incomplete.")
    findings_status = "partial" if wst == "partial" else "checked" if wst in ("ok", "empty") else "not_checked"
    sub_items = subs.get("items", [])
    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tier": "admin" if admin else "public",
        "dns": dns_res,
        "subdomains": {"status": subs["status"], "source": subs.get("source"), "attempts": subs.get("attempts", []), "total": len(sub_items), "items": sub_items[: lim["subs"]]},
        "shodan_internetdb": shodan,
        "email_security": email_sec,
        "wayback": {"status": wb["status"], "reason": wb.get("reason"), "fetched": len(wb.get("urls", [])), "shown": len(shown_urls), "urls": shown_urls},
        "findings": findings,
        "findings_total": findings_total,
        "findings_status": findings_status,
        "assessment_coverage": build_coverage(dns_res, subs, shodan, wb, email_sec),
        "warnings": warnings,
        "disclaimer": DISCLAIMER,
    }
    return result if admin else sanitize_data(result)


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


CANARY_PATHS = ["/.env", "/api/.env", "/admin", "/wp-admin", "/wp-login.php", "/config.php", "/xmlrpc.php", "/phpmyadmin", "/.git/config", "/.aws/credentials"]
TARPIT_SLOTS = asyncio.Semaphore(50)
NOT_FOUND_HTML = "<!doctype html>\n<html>\n<head><title>404 Not Found</title></head>\n<body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n</body>\n</html>\n"
CANARY_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>403 Access Denied</title></head>
<body><h1>403 ACCESS DENIED</h1><p>IP: {{IP}}</p></body></html>"""


async def canary_trap(request: Request):
    ip = client_ip(request)
    ua = request.headers.get("user-agent", "unknown")[:200]
    canary_log.warning("CANARY mode=%s method=%s path=%r ip=%s xff=%r ua=%r", HONEYPOT_MODE, request.method, request.url.path, ip, request.headers.get("x-forwarded-for", "")[:200], ua)
    delay = 1 if HONEYPOT_MODE == "stealth" else 3
    if not TARPIT_SLOTS.locked():
        async with TARPIT_SLOTS:
            await asyncio.sleep(delay)
    if HONEYPOT_MODE == "stealth":
        return HTMLResponse("" if request.method == "HEAD" else NOT_FOUND_HTML, status_code=404)
    return HTMLResponse(CANARY_HTML.replace("{{IP}}", html.escape(ip)), status_code=403, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"})


for _p in CANARY_PATHS:
    app.add_api_route(_p, canary_trap, methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"], include_in_schema=False)


INDEX_TEMPLATE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>ReconLens — HNR Labs</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style nonce="__NONCE__">body{font-family:monospace;background:#101010;color:#C7B182;max-width:680px;margin:40px auto;padding:20px}input,button{padding:12px;background:#0d0d0d;color:#E5D5B3;border:1px solid #634F5F}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>
</head><body><h1>RECONLENS</h1><p>PASSIVE RECONNAISSANCE · NO ACTIVE SCANNING</p>
<form id="f"><input id="domain" placeholder="labs.hellnrock.com" required maxlength="253"><button>ANALYZE</button></form>
<details><summary>ADMIN</summary><input id="tok" type="password" placeholder="admin token (opcional)"></details>
<button type="button" id="clear-btn">CLEAR</button><button type="button" id="copy-btn">COPY</button><pre id="out">// Waiting for target domain input...</pre>
<script nonce="__NONCE__">
const form=document.getElementById('f'),out=document.getElementById('out');
form.addEventListener('submit',async e=>{e.preventDefault();try{const headers={},token=document.getElementById('tok').value;if(token)headers['X-Admin-Token']=token;const r=await fetch('/api/passive/domain?domain='+encodeURIComponent(document.getElementById('domain').value.trim()),{headers});const ct=r.headers.get('content-type')||'';const body=ct.includes('json')?await r.json():await r.text();out.textContent=typeof body==='string'?body:JSON.stringify(body,null,2)}catch(_){out.textContent='// Network error'}});
document.getElementById('clear-btn').addEventListener('click',()=>{document.getElementById('domain').value='';out.textContent='// Waiting for target domain input...'});
document.getElementById('copy-btn').addEventListener('click',()=>navigator.clipboard.writeText(out.innerText||out.textContent));
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    nonce = secrets.token_urlsafe(16)
    csp = "default-src 'none'; " + f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; " + "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    return HTMLResponse(INDEX_TEMPLATE.replace("__NONCE__", nonce), headers={"Content-Security-Policy": csp})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
