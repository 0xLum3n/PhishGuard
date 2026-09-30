from __future__ import annotations

import base64
import ipaddress
import os
import re
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv()

APP_NAME = "PhishGuard Live URL Intelligence API"
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "8"))
HACKERTARGET_BASE = "https://api.hackertarget.com"
RDAP_BASE = "https://rdap.org"
IPAPI_BASE = "https://ipapi.co"
URLSCAN_BASE = "https://urlscan.io/api/v1/search/"
PHISHTANK_ENDPOINT = "http://checkurl.phishtank.com/checkurl/"
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "account", "wallet", "update",
    "confirm", "password", "session", "oauth", "token", "auth", "invoice", "security",
    "billing", "payment", "recover", "reset", "unlock", "support", "credential",
}
SENSITIVE_KEYS = {"token", "auth", "pass", "password", "key", "session", "redirect", "url", "return", "code", "secret"}
COMMON_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "firm.in", "net.in",
    "org.in", "gen.in", "ind.in", "com.br", "com.cn", "com.hk", "com.sg", "co.jp", "co.kr", "co.nz",
    "co.za", "com.mx", "com.tr", "com.tw", "com.ar", "com.ua", "com.pl",
}
HOMOGLYPH_MAP = {
    "\u0430": ("a", "Cyrillic"), "\u043e": ("o", "Cyrillic"), "\u0435": ("e", "Cyrillic"),
    "\u0440": ("p", "Cyrillic"), "\u0441": ("c", "Cyrillic"), "\u0443": ("y", "Cyrillic"),
    "\u0445": ("x", "Cyrillic"), "\u0456": ("i", "Cyrillic"), "\u04cf": ("l", "Cyrillic Palochka"),
    "\u03b1": ("a", "Greek"), "\u03bf": ("o", "Greek"), "\u03c1": ("p", "Greek"),
}
TARGET_BRANDS = [
    ("PayPal", "paypal.com"), ("Microsoft", "microsoft.com"), ("Apple", "apple.com"),
    ("Google", "google.com"), ("Amazon", "amazon.com"), ("Netflix", "netflix.com"),
    ("Bank of America", "bankofamerica.com"), ("Chase Bank", "chase.com"), ("Meta / Facebook", "facebook.com"),
]

app = FastAPI(title=APP_NAME, version="1.0.0")
origins = [x.strip() for x in os.getenv("FRONTEND_ORIGINS", "*").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=8192)


def normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("URL is empty")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only HTTP and HTTPS URLs with a hostname are supported")
    return value


def domain_parts(hostname: str) -> tuple[str, str, str]:
    labels = [label for label in hostname.split(".") if label]
    if len(labels) <= 1:
        return "", hostname, ""
    suffix2 = ".".join(labels[-2:]).lower()
    suffix_len = 2 if suffix2 in COMMON_MULTI_LABEL_SUFFIXES else 1
    suffix = ".".join(labels[-suffix_len:])
    domain_index = len(labels) - suffix_len - 1
    domain = ".".join(labels[max(0, domain_index):])
    subdomain = ".".join(labels[:max(0, domain_index)])
    return subdomain, domain, "." + suffix


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    import math
    n = len(value)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


def parse_url(raw: str) -> dict[str, Any]:
    normalized = normalize_url(raw)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    try:
        ipaddress.ip_address(host)
        has_ip_host = True
    except ValueError:
        has_ip_host = False
    if has_ip_host:
        subdomain, domain, tld = "", host, ""
    else:
        subdomain, domain, tld = domain_parts(host)
    explicit_port = str(parsed.port) if parsed.port else ""
    display_port = explicit_port or ("443" if parsed.scheme.lower() == "https" else "80")
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_params = [{"key": k, "value": v, "isSensitive": any(term in k.lower() for term in SENSITIVE_KEYS)} for k, v in query_pairs]
    path = parsed.path or "/"
    fragment = parsed.fragment or ""
    has_ip = has_ip_host
    suspicious = sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in (path + "?" + parsed.query).lower()})
    has_encoded = bool(re.search(r"%[0-9a-f]{2}", normalized, flags=re.I))
    has_obfuscated = len(parsed.query) > 60 or bool(re.search(r"[A-Za-z0-9+/=]{30,}", parsed.query))
    unicode_chars = []
    for char in host:
        if ord(char) > 127:
            lookalike, script = HOMOGLYPH_MAP.get(char.lower(), ("?", "Non-ASCII Unicode"))
            unicode_chars.append({
                "char": char,
                "codePoint": f"U+{ord(char):04X}",
                "lookalike": lookalike,
                "script": script,
            })
    lower_host = host.lower()
    typo = None
    for brand, legit_domain in TARGET_BRANDS:
        if lower_host == legit_domain:
            continue
        brand_key = legit_domain.split(".")[0]
        for candidate in (brand_key.replace("l", "1"), brand_key.replace("o", "0"), brand_key + "-login", brand_key + "-verify"):
            if candidate and candidate in lower_host:
                typo = {
                    "detected": True,
                    "targetBrand": brand,
                    "similarityScore": 90,
                    "patternType": "Brand keyword / character substitution",
                    "explanation": f"Hostname contains the lookalike pattern '{candidate}' associated with {brand} ({legit_domain}).",
                }
                break
        if typo:
            break
    if not typo and re.search(r"[a-z]+[015][a-z]+", host, re.I):
        typo = {
            "detected": True,
            "targetBrand": "Unspecified brand target",
            "similarityScore": 78,
            "patternType": "Leet-speak / numeric substitution",
            "explanation": "Hostname contains a mixed letter/number pattern that can be used in lookalike domains.",
        }
    if not typo:
        typo = {
            "detected": False,
            "similarityScore": None,
            "patternType": None,
            "explanation": "No configured brand-lookalike pattern was found in the hostname.",
        }
    domain_entropy = shannon_entropy(host)
    url_entropy = shannon_entropy(normalized)
    level = "Low"
    if url_entropy > 4.5 or domain_entropy > 3.8:
        level = "Suspiciously High"
    elif url_entropy > 4.0 or domain_entropy > 3.4:
        level = "High"
    elif url_entropy > 3.2:
        level = "Moderate"
    return {
        "normalized": normalized,
        "parsed": parsed,
        "hostname": host,
        "subdomain": subdomain,
        "domain": domain,
        "tld": tld,
        "port": explicit_port,
        "displayPort": display_port,
        "path": path,
        "queryParams": query_params,
        "fragment": fragment,
        "scheme": parsed.scheme.lower(),
        "hasIp": has_ip,
        "suspiciousKeywords": suspicious,
        "hasEncodedChars": has_encoded,
        "hasObfuscatedQuery": has_obfuscated,
        "unicodeChars": unicode_chars,
        "typo": typo,
        "entropy": {"domainEntropy": domain_entropy, "urlEntropy": url_entropy, "level": level},
    }


async def get_json(client: httpx.AsyncClient, url: str, **kwargs: Any) -> tuple[Any | None, str | None]:
    try:
        response = await client.get(url, timeout=HTTP_TIMEOUT, follow_redirects=True, **kwargs)
        response.raise_for_status()
        return response.json(), None
    except Exception as exc:
        return None, str(exc)


async def post_form(client: httpx.AsyncClient, url: str, data: dict[str, Any], headers: dict[str, str] | None = None) -> tuple[Any | None, str | None]:
    try:
        response = await client.post(url, data=data, headers=headers or {}, timeout=HTTP_TIMEOUT, follow_redirects=True)
        response.raise_for_status()
        return response.json(), None
    except Exception as exc:
        return None, str(exc)


def dns_lookup_fallback_text(text: str) -> dict[str, list[str]]:
    out = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [], "SOA": []}
    for line in text.splitlines():
        if "," not in line:
            continue
        kind, value = line.split(",", 1)
        if kind.strip() in out:
            out[kind.strip()].append(value.strip())
    return out


async def hacker_target_lookup(client: httpx.AsyncClient, endpoint: str, target: str) -> tuple[Any | None, str | None]:
    try:
        response = await client.get(f"{HACKERTARGET_BASE}/{endpoint}/", params={"q": target, "output": "json"}, timeout=HTTP_TIMEOUT)
        if response.status_code >= 400:
            return None, f"HTTP {response.status_code}"
        text = response.text.strip()
        try:
            return response.json(), None
        except Exception:
            return text, None
    except Exception as exc:
        return None, str(exc)


def extract_vcard_name(entity: dict[str, Any]) -> str:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and item and item[0] == "fn" and len(item) >= 4:
                return str(item[3])
    return ""


def parse_rdap_domain(data: dict[str, Any]) -> dict[str, Any]:
    registrar = ""
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            registrar = extract_vcard_name(entity)
            if registrar:
                break
    events = {}
    for event in data.get("events", []):
        if isinstance(event, dict) and event.get("eventAction"):
            events[event["eventAction"]] = event.get("eventDate", "")
    statuses = [str(x) for x in data.get("status", [])]
    nameservers = [str(x.get("ldhName")) for x in data.get("nameservers", []) if isinstance(x, dict) and x.get("ldhName")]
    return {
        "registrar": registrar,
        "creationDate": events.get("registration", ""),
        "expirationDate": events.get("expiration", ""),
        "updatedDate": events.get("last changed", "") or events.get("last update of RDAP database", ""),
        "status": statuses,
        "nameservers": nameservers,
        "dnssec": "signed" if data.get("secureDNS", {}).get("delegationSigned") else "unsigned",
        "raw": data,
    }


def format_age(days: int | None) -> str:
    if days is None:
        return "Unavailable"
    if days < 0:
        return "Unavailable"
    if days < 30:
        return f"{days} days (newly registered range)"
    years, remainder = divmod(days, 365)
    months, days2 = divmod(remainder, 30)
    pieces = []
    if years:
        pieces.append(f"{years} years")
    if months:
        pieces.append(f"{months} months")
    if days2 or not pieces:
        pieces.append(f"{days2} days")
    return f"{', '.join(pieces)} ({days} days)"


def age_days_from_date(value: str) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).days)
    except Exception:
        return None


async def rdap_domain(client: httpx.AsyncClient, domain: str) -> tuple[dict[str, Any], str]:
    data, error = await get_json(client, f"{RDAP_BASE}/domain/{domain}")
    if not data:
        return {
            "domain": domain, "registrar": "", "creationDate": "", "expirationDate": "", "updatedDate": "",
            "domainAgeDays": None, "domainAgeFormatted": "Unavailable", "status": [], "nameservers": [],
            "isNewlyRegistered": False, "dnssec": "", "source": "RDAP.org", "error": f"RDAP lookup failed: {error}",
        }, "RDAP.org"
    parsed = parse_rdap_domain(data)
    age = age_days_from_date(parsed["creationDate"])
    return {
        "domain": domain,
        "registrar": parsed["registrar"],
        "creationDate": parsed["creationDate"],
        "expirationDate": parsed["expirationDate"],
        "updatedDate": parsed["updatedDate"],
        "domainAgeDays": age,
        "domainAgeFormatted": format_age(age),
        "status": parsed["status"],
        "nameservers": parsed["nameservers"],
        "isNewlyRegistered": age is not None and age <= 30,
        "dnssec": parsed["dnssec"],
        "source": "RDAP.org",
    }, "RDAP.org"


async def ip_geolocation(client: httpx.AsyncClient, ip: str | None) -> dict[str, Any]:
    if not ip:
        return {"ip": None, "source": "ipapi.co", "error": "No resolved IP address"}
    data, error = await get_json(client, f"{IPAPI_BASE}/{ip}/json/")
    if not data:
        return {"ip": ip, "source": "ipapi.co", "error": f"IP geolocation lookup failed: {error}"}
    return {
        "ip": data.get("ip") or ip,
        "city": data.get("city"), "region": data.get("region"), "country": data.get("country_name"),
        "countryCode": data.get("country_code"), "latitude": data.get("latitude"), "longitude": data.get("longitude"),
        "timezone": data.get("timezone"), "asn": data.get("asn"), "org": data.get("org"), "source": "ipapi.co",
    }


async def resolve_hostname(hostname: str) -> tuple[list[str], str | None]:
    loop = __import__("asyncio").get_running_loop()

    def _resolve() -> list[str]:
        results = set()
        try:
            infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                if addr:
                    results.add(addr)
        except socket.gaierror as exc:
            raise exc
        return sorted(results)

    try:
        ips = await loop.run_in_executor(None, _resolve)
        return ips, None
    except Exception as exc:
        return [], str(exc)


async def optional_osint(client: httpx.AsyncClient, normalized_url: str, domain: str, primary_ip: str | None) -> tuple[dict[str, Any], list[str]]:
    import asyncio

    osint: dict[str, Any] = {
        "subdomains": [], "reverseIpDomains": [], "urlscanSightings": [], "sources": [], "notes": [],
    }

    async def ht(endpoint: str, target: str):
        return await hacker_target_lookup(client, endpoint, target)

    async def urlscan_search():
        return await get_json(client, URLSCAN_BASE, params={"q": f"domain:{domain}", "size": 10})

    async def phishtank_lookup():
        payload = {"url": normalized_url, "format": "json"}
        phish_key = os.getenv("PHISHTANK_APP_KEY")
        if phish_key:
            payload["app_key"] = phish_key
        return await post_form(client, PHISHTANK_ENDPOINT, payload, {"User-Agent": "PhishGuard/1.0 URL analysis"})

    async def reverse_ip_lookup():
        if primary_ip:
            return await ht("reverseiplookup", primary_ip)
        return None, "No resolved IP"

    jobs = [ht("hostsearch", domain), urlscan_search(), reverse_ip_lookup(), phishtank_lookup()]
    host_result, urlscan_result, reverse_result, phish_result = await asyncio.gather(*jobs, return_exceptions=False)

    host_data, host_error = host_result
    if host_data is not None:
        text = host_data if isinstance(host_data, str) else ""
        values = []
        for line in text.splitlines():
            if "," in line:
                _, found_host = line.split(",", 1)
                found_host = found_host.strip()
                if found_host and found_host.endswith(domain):
                    values.append(found_host)
        osint["subdomains"] = sorted(set(values))[:100]
        osint["sources"].append("HackerTarget hostsearch")
    elif host_error:
        osint["notes"].append(f"HackerTarget subdomain lookup unavailable: {host_error}.")

    search_data, search_error = urlscan_result
    if search_data and isinstance(search_data, dict):
        for result in search_data.get("results", []):
            page = result.get("page") or {}
            task = result.get("task") or {}
            osint["urlscanSightings"].append({
                "uuid": result.get("_id"), "pageUrl": page.get("url"), "taskTime": task.get("time"),
                "country": page.get("country"), "ip": page.get("ip"),
            })
        osint["sources"].append("urlscan.io search")
    elif search_error:
        osint["notes"].append(f"urlscan.io search unavailable or rate-limited: {search_error}.")

    reverse_data, reverse_error = reverse_result
    if reverse_data is not None:
        text = reverse_data if isinstance(reverse_data, str) else ""
        osint["reverseIpDomains"] = sorted({x.strip() for x in text.splitlines() if x.strip() and not x.lower().startswith("error")})[:100]
        osint["sources"].append("HackerTarget reverse-IP")
    elif reverse_error:
        osint["notes"].append(f"HackerTarget reverse-IP lookup unavailable: {reverse_error}.")

    phish_data, phish_error = phish_result
    if phish_data and isinstance(phish_data, dict):
        result = phish_data.get("results", {})
        if isinstance(result, dict):
            osint["phishtank"] = {
                "inDatabase": bool(result.get("in_database")) if "in_database" in result else None,
                "verified": str(result.get("verified", "")).lower() in {"true", "y"} if "verified" in result else None,
                "phishId": str(result.get("phish_id")) if result.get("phish_id") else None,
                "submissionUrl": result.get("phish_detail_page"),
                "source": "PhishTank",
            }
            osint["sources"].append("PhishTank")
    elif phish_error:
        osint["notes"].append(f"PhishTank lookup unavailable or rate-limited: {phish_error}.")

    urlhaus_key = os.getenv("URLHAUS_AUTH_KEY")
    if urlhaus_key:
        try:
            response = await client.post(URLHAUS_ENDPOINT, data={"url": normalized_url}, headers={"Auth-Key": urlhaus_key}, timeout=HTTP_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            osint["urlhaus"] = {
                "listed": data.get("query_status") == "listed", "threat": data.get("threat"),
                "urlStatus": data.get("url_status"), "lastSeen": data.get("last_online"), "source": "URLhaus",
            }
            osint["sources"].append("URLhaus")
        except Exception as exc:
            osint["notes"].append(f"URLhaus lookup unavailable: {exc}.")
    else:
        osint["urlhaus"] = {"listed": None, "source": "URLhaus", "error": "URLHAUS_AUTH_KEY not configured"}

    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key:
        try:
            url_id = base64.urlsafe_b64encode(normalized_url.encode()).decode().rstrip("=")
            response = await client.get(f"{VT_BASE}/urls/{url_id}", headers={"x-apikey": vt_key, "Accept": "application/json"}, timeout=HTTP_TIMEOUT)
            response.raise_for_status()
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            osint["virustotal"] = {
                "malicious": stats.get("malicious"), "suspicious": stats.get("suspicious"),
                "harmless": stats.get("harmless"), "undetected": stats.get("undetected"), "source": "VirusTotal",
            }
            osint["sources"].append("VirusTotal")
        except Exception as exc:
            osint["notes"].append(f"VirusTotal lookup unavailable: {exc}.")
    else:
        osint["virustotal"] = {"malicious": None, "suspicious": None, "harmless": None, "undetected": None, "source": "VirusTotal", "error": "VIRUSTOTAL_API_KEY not configured"}

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key and primary_ip:
        try:
            response = await client.get(
                f"{ABUSEIPDB_BASE}/check", params={"ipAddress": primary_ip, "maxAgeInDays": "90"},
                headers={"Key": abuse_key, "Accept": "application/json"}, timeout=HTTP_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            osint["abuseIpdb"] = {
                "confidenceScore": data.get("abuseConfidenceScore"), "totalReports": data.get("totalReports"),
                "lastReportedAt": data.get("lastReportedAt"), "source": "AbuseIPDB",
            }
            osint["sources"].append("AbuseIPDB")
        except Exception as exc:
            osint["notes"].append(f"AbuseIPDB lookup unavailable: {exc}.")
    elif not abuse_key:
        osint["abuseIpdb"] = {"confidenceScore": None, "totalReports": None, "lastReportedAt": None, "source": "AbuseIPDB", "error": "ABUSEIPDB_API_KEY not configured"}

    return osint, sorted(set(osint["sources"]))


def build_reasons(info: dict[str, Any], whois: dict[str, Any], osint: dict[str, Any], primary_ip: str | None) -> tuple[int, list[dict[str, str]], str]:
    score = 0
    reasons: list[dict[str, str]] = []

    def add(points: int, title: str, detail: str, severity: str) -> None:
        nonlocal score
        score += points
        reasons.append({"title": title, "detail": detail, "severity": severity})

    if info["scheme"] != "https":
        add(15, "HTTP transport", "The supplied URL uses HTTP rather than HTTPS.", "medium")
    if info["hasIp"]:
        add(25, "Direct IP hostname", "The hostname is a numeric IP address rather than a DNS name.", "high")
    if info["unicodeChars"]:
        add(30, "Non-ASCII hostname characters", "Unicode characters were detected in the hostname; some can resemble Latin characters.", "high")
    if info["typo"]["detected"]:
        add(30, "Lookalike-domain pattern", info["typo"]["explanation"], "high")
    if info["suspiciousKeywords"]:
        add(10, "Credential-oriented URL terms", f"Sensitive action words found: {', '.join(info['suspiciousKeywords'])}.", "medium")
    if info["hasObfuscatedQuery"]:
        add(8, "High-density query string", "The query string is unusually long or token-like.", "medium")
    if info["hasEncodedChars"]:
        add(6, "Percent-encoded characters", "The URL contains percent-encoded bytes.", "low")
    if info["entropy"]["level"] in {"High", "Suspiciously High"}:
        add(8, "Elevated URL entropy", f"Measured URL entropy is {info['entropy']['urlEntropy']} bits/character.", "medium")
    if whois.get("isNewlyRegistered"):
        add(20, "Recently registered domain", f"RDAP reports a registration age of {whois.get('domainAgeDays')} days.", "medium")

    vt = osint.get("virustotal") or {}
    if isinstance(vt.get("malicious"), int) and vt.get("malicious", 0) > 0:
        add(min(25, vt["malicious"] * 5), "VirusTotal detections", f"VirusTotal reports {vt['malicious']} malicious engine verdict(s).", "high")
    phish = osint.get("phishtank") or {}
    if phish.get("inDatabase"):
        add(25 if phish.get("verified") else 18, "PhishTank listing", "The URL is present in the PhishTank database.", "high")
    urlhaus = osint.get("urlhaus") or {}
    if urlhaus.get("listed"):
        add(30, "URLhaus listing", "The URL is present in URLhaus as a known malware-related URL.", "high")
    abuse = osint.get("abuseIpdb") or {}
    if isinstance(abuse.get("confidenceScore"), int) and abuse["confidenceScore"] >= 25:
        add(min(15, abuse["confidenceScore"] // 10), "IP abuse reports", f"AbuseIPDB reports an abuse confidence score of {abuse['confidenceScore']}% for the resolved IP.", "medium")

    score = min(score, 100)
    # Verdict is a UI risk band, not a claim that the destination is definitively malicious/safe.
    verdict = "SAFE" if score <= 20 else "SUSPICIOUS" if score <= 60 else "MALICIOUS"
    if not reasons:
        reasons.append({"title": "No configured high-signal indicators", "detail": "No score-contributing indicator was returned by the configured checks.", "severity": "info"})
    return score, reasons, verdict


def build_dns_result(data: Any) -> tuple[dict[str, list[str]], str | None]:
    fields = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [], "SOA": []}
    if isinstance(data, dict):
        for key in fields:
            values = data.get(key, [])
            if isinstance(values, list):
                fields[key] = [str(v) for v in values]
            elif values:
                fields[key] = [str(values)]
        return fields, None
    if isinstance(data, str):
        return dns_lookup_fallback_text(data), None
    return fields, "DNS lookup returned no structured data"


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": APP_NAME}


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    try:
        info = parse_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    hostname = info["hostname"]
    is_ip = info["hasIp"]

    async with httpx.AsyncClient(headers={"User-Agent": "PhishGuard/1.0 (+safe metadata inspection)"}) as client:
        if is_ip:
            ips = [hostname]
            resolution_error = None
        else:
            ips, resolution_error = await resolve_hostname(hostname)
        primary_ip = ips[0] if ips else None

        whois_task = rdap_domain(client, info["domain"]) if not is_ip and info["domain"] else None
        if whois_task:
            whois_result, whois_source = await whois_task
        else:
            whois_result = {
                "domain": info["domain"], "registrar": "", "creationDate": "", "expirationDate": "",
                "updatedDate": "", "domainAgeDays": None, "domainAgeFormatted": "Unavailable",
                "status": [], "nameservers": [], "isNewlyRegistered": False, "dnssec": "",
                "source": "RDAP.org", "error": "WHOIS/RDAP domain lookup is not applicable to a raw IP hostname.",
            }
            whois_source = "RDAP.org"

        ip_intel = await ip_geolocation(client, primary_ip)
        dns_data, dns_error = await hacker_target_lookup(client, "dnslookup", info["domain"] if info["domain"] else hostname)
        dns, _ = build_dns_result(dns_data)
        if dns_error:
            dns["source"] = "HackerTarget"
            dns["error"] = dns_error
        else:
            dns["source"] = "HackerTarget"

        osint, _sources = await optional_osint(client, info["normalized"], info["domain"] if info["domain"] else hostname, primary_ip)

    score, reasons, verdict = build_reasons(info, whois_result, osint, primary_ip)
    scheme = info["scheme"]
    query_string = info["parsed"].query
    normalized = info["normalized"]
    hostname_display = hostname
    subdomain = info["subdomain"] or "—"
    query_separator = "?" if query_string else "—"
    generated_at = datetime.now(timezone.utc).isoformat()

    return {
        "url": request.url.strip(),
        "normalizedUrl": normalized,
        "protocol": f"{scheme}:",
        "hostname": hostname_display,
        "domain": info["domain"],
        "tld": info["tld"],
        "path": info["path"],
        "fragment": info["fragment"],
        "port": info["port"],
        "urlParts": {
            "scheme": scheme,
            "subdomain": subdomain,
            "domain": info["domain"],
            "tld": info["tld"],
            "port": info["displayPort"],
            "path": info["path"],
            "queryString": query_string or "—",
            "querySeparator": query_separator,
            "fragment": info["fragment"] or "—",
            "queryParams": info["queryParams"],
        },
        "queryParams": info["queryParams"],
        "entropy": {
            **info["entropy"],
            "explanation": f"URL Shannon entropy is {info['entropy']['urlEntropy']} bits/character; entropy is a heuristic and should not be treated as a standalone detection signal.",
        },
        "typosquatting": info["typo"],
        "homoglyphs": {
            "detected": bool(info["unicodeChars"]),
            "characters": info["unicodeChars"],
            "explanation": "Non-ASCII hostname characters were detected." if info["unicodeChars"] else "No non-ASCII hostname characters were detected.",
        },
        "structure": {
            "hasSuspiciousPath": bool(info["suspiciousKeywords"]),
            "suspiciousKeywords": info["suspiciousKeywords"],
            "hasEncodedChars": info["hasEncodedChars"],
            "hasObfuscatedQuery": info["hasObfuscatedQuery"],
            "hasIpHostname": info["hasIp"],
            "isHttps": scheme == "https",
            "explanation": "Credential-oriented or obfuscation signals were found in the path/query." if info["suspiciousKeywords"] or info["hasObfuscatedQuery"] else "No configured credential-oriented path/query markers were found.",
        },
        "resolution": {"ips": ips, "primaryIp": primary_ip, "lookupError": resolution_error},
        "ipIntel": ip_intel,
        "dns": dns,
        "osint": osint,
        "whois": whois_result,
        "threatScore": score,
        "verdict": verdict,
        "reasons": reasons,
        "generatedAt": generated_at,
        "backendSource": "FastAPI + live external sources",
    }
