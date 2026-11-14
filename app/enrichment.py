"""Lightweight free-source enrichers: breaches, mail/web security, public profiles.

All of these are HTTP or DNS lookups with short timeouts. They are safe to
run alongside each other on a 512 MB instance; they must not overlap the
heavy CLIs (Maigret, Sherlock, dnsrecon, subfinder, theHarvester).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from .adapters import Finding, ToolResult

logger = logging.getLogger("footprint.enrichment")

USER_AGENT = (
    "FootprintAudit/1.3 (educational self-audit; "
    "https://github.com/vishal-1307/footprint-audit)"
)
XON_ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics"
XON_CHECK = "https://api.xposedornot.com/v1/check-email/{email}"
GITHUB_USER = "https://api.github.com/users/{username}"
GRAVATAR_JSON = "https://www.gravatar.com/{digest}.json"
CRTSH_JSON = "https://crt.sh/?q=%25.{domain}&output=json"

SENSITIVE_BREACH_CLASSES = {
    "passwords",
    "password",
    "password hints",
    "phone numbers",
    "phone",
    "physical addresses",
    "address",
    "government issued ids",
    "government issued i ds",
    "social security numbers",
    "national ids",
    "passport",
    "credit cards",
    "bank accounts",
    "dates of birth",
    "date of birth",
}

DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "dkim",
    "mail",
    "smtp",
    "zoho",
    "cm",
    "sig1",
    "s1024",
    "k2",
    "fm1",
    "fm2",
    "fm3",
)

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

SUBDOMAIN_HEAD_CAP = 8
SUBDOMAIN_HEAD_TIMEOUT = 4.0
MAX_BREACH_ROWS = 20


def _raw(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _headers() -> dict[str, str]:
    return {"User-Agent": USER_AGENT, "Accept": "application/json"}


# ---------------------------------------------------------------------------
# XposedOrNot
# ---------------------------------------------------------------------------


def _flatten_breach_names(payload: Any) -> list[str]:
    names: list[str] = []
    if isinstance(payload, dict):
        inner = payload.get("breaches")
        if inner is not None:
            return _flatten_breach_names(inner)
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, str) and item.strip():
                names.append(item.strip())
            elif isinstance(item, list):
                names.extend(_flatten_breach_names(item))
            elif isinstance(item, dict):
                label = item.get("breach") or item.get("name") or item.get("Title")
                if label:
                    names.append(str(label).strip())
    return list(dict.fromkeys(names))


def _split_classes(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            parts.extend(_split_classes(item))
        return parts
    text = str(value)
    bits = re.split(r"[;,|/]+", text)
    return [b.strip() for b in bits if b.strip() and b.strip().lower() not in {"email addresses", "emails"}]


def parse_xposedornot_analytics(payload: dict[str, Any], email: str) -> list[Finding]:
    """Turn a breach-analytics (or check-email) JSON body into findings."""
    findings: list[Finding] = []
    if not isinstance(payload, dict):
        return findings

    exposed = payload.get("ExposedBreaches") or payload.get("exposedBreaches") or []
    if isinstance(exposed, dict):
        exposed = exposed.get("breaches_details") or exposed.get("breaches") or exposed.get("records") or []
    if not isinstance(exposed, list):
        exposed = []

    summary = payload.get("BreachesSummary") or payload.get("breachesSummary") or {}
    site_blob = ""
    if isinstance(summary, dict):
        site_blob = str(summary.get("site") or "")
    summary_names = [s.strip() for s in site_blob.split(";") if s.strip()] if site_blob else []

    names_from_rows: list[str] = []
    classes: list[str] = []
    rows: list[dict[str, Any]] = []
    for item in exposed:
        if not isinstance(item, dict):
            continue
        name = str(item.get("breach") or item.get("name") or "").strip()
        if not name:
            continue
        year = str(item.get("xposed_date") or item.get("breached_date") or item.get("year") or "").strip()
        data = _split_classes(item.get("xposed_data") or item.get("data_classes") or "")
        classes.extend(data)
        names_from_rows.append(name)
        rows.append({"name": name, "year": year, "data_classes": data, "domain": item.get("domain") or ""})

    if not names_from_rows:
        # check-email shape: {"breaches": [["Adobe", "LinkedIn"]], "status": "success"}
        names_from_rows = _flatten_breach_names(payload.get("breaches")) or summary_names

    # Not found / empty
    if not names_from_rows and not rows:
        err = str(payload.get("Error") or payload.get("error") or "")
        if err or payload.get("ExposedBreaches") in (None, []) or not names_from_rows:
            findings.append(
                Finding(
                    source="xposedornot",
                    input_type="email",
                    value="No breaches reported for this email",
                    url="https://xposedornot.com/",
                    status="not_found",
                    confidence="medium",
                    raw=_raw({"count": 0, "email_present": True}),
                )
            )
            return findings

    unique_classes = list(dict.fromkeys(classes))
    count = len(names_from_rows) or len(rows)
    preview = ", ".join(names_from_rows[:8])
    if count > 8:
        preview += f", +{count - 8} more"
    findings.append(
        Finding(
            source="xposedornot",
            input_type="email",
            value=f"{count} breach(es) reported" + (f" — {preview}" if preview else ""),
            url="https://xposedornot.com/",
            status="found",
            confidence="high",
            raw=_raw(
                {
                    "kind": "summary",
                    "count": count,
                    "breaches": names_from_rows,
                    "data_classes": unique_classes,
                }
            ),
        )
    )
    for row in rows[:MAX_BREACH_ROWS]:
        label = row["name"]
        if row.get("year"):
            label = f"{row['name']} ({row['year']})"
        extras = ", ".join(row.get("data_classes") or [])
        if extras:
            label = f"{label} — {extras}"
        findings.append(
            Finding(
                source="xposedornot",
                input_type="email",
                value=label,
                url="",
                status="found",
                confidence="high",
                raw=_raw({"kind": "breach", **row}),
            )
        )
    return findings


async def run_xposedornot(email: str, timeout: int = 20) -> ToolResult:
    started = asyncio.get_event_loop().time()
    params = {"email": email}
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=_headers(), follow_redirects=True) as client:
            response = await client.get(XON_ANALYTICS, params=params)
            if response.status_code == 429:
                return ToolResult(
                    tool="xposedornot",
                    status="blocked",
                    message="XposedOrNot rate-limited this request. Try again later (25 checks/hour per IP).",
                    elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
                )
            if response.status_code in {404, 204}:
                findings = parse_xposedornot_analytics({}, email)
                return ToolResult(
                    tool="xposedornot",
                    status="not_found",
                    message="No breaches reported",
                    findings=findings,
                    elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
                )
            if response.status_code >= 400:
                # Fall back to the lighter check-email endpoint once.
                fallback = await client.get(XON_CHECK.format(email=email))
                if fallback.status_code == 429:
                    return ToolResult(
                        tool="xposedornot",
                        status="blocked",
                        message="XposedOrNot rate-limited this request. Try again later.",
                        elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
                    )
                if fallback.status_code >= 400:
                    return ToolResult(
                        tool="xposedornot",
                        status="error",
                        message=f"XposedOrNot returned HTTP {response.status_code}",
                        elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
                    )
                payload = fallback.json()
            else:
                payload = response.json()
    except httpx.TimeoutException:
        return ToolResult(tool="xposedornot", status="error", message=f"timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001
        logger.warning("xposedornot failed: %s", exc)
        return ToolResult(tool="xposedornot", status="error", message=str(exc)[:240])

    findings = parse_xposedornot_analytics(payload if isinstance(payload, dict) else {}, email)
    found = [f for f in findings if f.status == "found"]
    status = "found" if found else "not_found"
    message = found[0].value if found else "No breaches reported"
    return ToolResult(
        tool="xposedornot",
        status=status,
        message=message,
        findings=findings,
        elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
    )


# ---------------------------------------------------------------------------
# Mail security (SPF / DMARC / DKIM / MX)
# ---------------------------------------------------------------------------


def grade_mail(records: dict[str, Any]) -> dict[str, Any]:
    """Pure grader. `records` has mx, spf, dmarc, dkim (list of selector names)."""
    mx = list(records.get("mx") or [])
    spf = records.get("spf") or ""
    dmarc = records.get("dmarc") or ""
    dkim = list(records.get("dkim") or [])
    issues: list[str] = []
    score = 100
    if not mx:
        score -= 15
        issues.append("No MX records — this domain may not receive mail, or mail is hosted elsewhere.")
    if not spf:
        score -= 25
        issues.append("No SPF record (TXT starting with v=spf1). Spoofed mail is easier to send.")
    elif "v=spf1" in spf.lower() and " -all" not in f" {spf.lower()}" and " ~all" not in f" {spf.lower()}":
        score -= 8
        issues.append("SPF is present but does not end in ~all or -all, so spoofed mail may still pass.")
    if not dmarc:
        score -= 30
        issues.append("No DMARC record at _dmarc. Receivers will not know how to handle failed mail.")
    else:
        policy = ""
        match = re.search(r"\bp=([a-z]+)", dmarc, re.I)
        if match:
            policy = match.group(1).lower()
        if policy == "none":
            score -= 12
            issues.append("DMARC policy is p=none (monitor only). Move to p=quarantine or p=reject when ready.")
        elif policy not in {"quarantine", "reject"}:
            score -= 10
            issues.append("DMARC record is missing a clear p= policy.")
    if mx and not dkim:
        score -= 15
        issues.append("No DKIM key found for common selectors. Add a DKIM TXT record for your mail provider.")
    score = max(0, min(100, score))
    if score >= 90:
        letter = "A"
    elif score >= 75:
        letter = "B"
    elif score >= 60:
        letter = "C"
    elif score >= 40:
        letter = "D"
    else:
        letter = "F"
    return {
        "grade": letter,
        "score": score,
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "issues": issues,
    }


def parse_mail_security(graded: dict[str, Any], domain: str) -> list[Finding]:
    findings = [
        Finding(
            source="mail_security",
            input_type="domain",
            value=f"Mail security grade {graded['grade']}",
            url="",
            status="found",
            confidence="high",
            raw=_raw({"kind": "grade", **graded}),
        )
    ]
    if graded.get("mx"):
        findings.append(
            Finding(
                source="mail_security",
                input_type="domain",
                value="MX: " + ", ".join(graded["mx"][:6]),
                url="",
                status="found",
                confidence="high",
                raw=_raw({"kind": "mx", "mx": graded["mx"]}),
            )
        )
    else:
        findings.append(
            Finding(
                source="mail_security",
                input_type="domain",
                value="No MX records",
                url="",
                status="not_found",
                confidence="medium",
                raw=_raw({"kind": "mx", "mx": []}),
            )
        )
    for key, label in (("spf", "SPF"), ("dmarc", "DMARC")):
        val = graded.get(key) or ""
        findings.append(
            Finding(
                source="mail_security",
                input_type="domain",
                value=f"{label}: {val}" if val else f"No {label} record",
                url="",
                status="found" if val else "not_found",
                confidence="high",
                raw=_raw({"kind": key, key: val}),
            )
        )
    dkim = graded.get("dkim") or []
    findings.append(
        Finding(
            source="mail_security",
            input_type="domain",
            value=("DKIM selectors: " + ", ".join(dkim)) if dkim else "No DKIM key on common selectors",
            url="",
            status="found" if dkim else "not_found",
            confidence="medium" if not dkim else "high",
            raw=_raw({"kind": "dkim", "dkim": dkim}),
        )
    )
    return findings


async def _txt(resolver, name: str, timeout: float) -> list[str]:
    import dns.resolver

    try:
        answer = await asyncio.wait_for(
            asyncio.to_thread(resolver.resolve, name, "TXT"),
            timeout=timeout,
        )
        texts = []
        for rr in answer:
            parts = getattr(rr, "strings", None)
            if parts:
                texts.append("".join(p.decode("utf-8", "replace") if isinstance(p, bytes) else str(p) for p in parts))
            else:
                texts.append(str(rr).strip('"'))
        return texts
    except Exception:
        return []


async def run_mail_security(domain: str, timeout: int = 20) -> ToolResult:
    started = asyncio.get_event_loop().time()
    try:
        import dns.resolver
    except Exception:
        return ToolResult(tool="mail_security", status="unavailable", message="dnspython is not installed")

    resolver = dns.resolver.Resolver()
    resolver.lifetime = min(6, max(2, timeout / 4))
    records: dict[str, Any] = {"mx": [], "spf": "", "dmarc": "", "dkim": []}
    try:
        try:
            mx_ans = await asyncio.wait_for(asyncio.to_thread(resolver.resolve, domain, "MX"), timeout=min(8, timeout))
            records["mx"] = sorted(
                {str(rr.exchange).rstrip(".") for rr in mx_ans if getattr(rr, "exchange", None)},
                key=str,
            )
        except Exception:
            records["mx"] = []

        for txt in await _txt(resolver, domain, min(6, timeout)):
            if txt.lower().startswith("v=spf1"):
                records["spf"] = txt
                break

        dmarc_texts = await _txt(resolver, f"_dmarc.{domain}", min(6, timeout))
        for txt in dmarc_texts:
            if "v=DMARC1" in txt.upper() or "v=dmarc1" in txt.lower():
                records["dmarc"] = txt
                break

        async def one_selector(sel: str) -> str | None:
            texts = await _txt(resolver, f"{sel}._domainkey.{domain}", 3)
            for txt in texts:
                if "v=DKIM1" in txt.upper() or "k=rsa" in txt.lower() or "p=" in txt.lower():
                    return sel
            return None

        found_sel = await asyncio.gather(*(one_selector(s) for s in DKIM_SELECTORS))
        records["dkim"] = [s for s in found_sel if s]
    except Exception as exc:  # noqa: BLE001
        logger.warning("mail_security %s failed: %s", domain, exc)
        return ToolResult(tool="mail_security", status="error", message=str(exc)[:240])

    graded = grade_mail(records)
    findings = parse_mail_security(graded, domain)
    return ToolResult(
        tool="mail_security",
        status="found",
        message=f"Mail grade {graded['grade']}",
        findings=findings,
        elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
    )


# ---------------------------------------------------------------------------
# Website security (TLS, redirect, headers, capped subdomain HEAD)
# ---------------------------------------------------------------------------


def grade_web(
    *,
    https_ok: bool,
    redirect_to_https: bool,
    cert: dict[str, Any] | None,
    headers: dict[str, str],
    open_http_hosts: list[str],
) -> dict[str, Any]:
    issues: list[str] = []
    score = 100
    missing: list[str] = []
    present: list[str] = []
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    if not https_ok:
        score -= 35
        issues.append("HTTPS did not respond on port 443.")
    if not redirect_to_https:
        score -= 15
        issues.append("HTTP does not redirect to HTTPS.")
    days = None
    if cert and cert.get("not_after"):
        days = cert.get("days_left")
        if days is not None and days < 0:
            score -= 25
            issues.append("TLS certificate has expired.")
        elif days is not None and days <= 30:
            score -= 12
            issues.append(f"TLS certificate expires in {days} day(s).")
    elif https_ok:
        score -= 8
        issues.append("Could not read the TLS certificate.")
    for name in SECURITY_HEADERS:
        if lowered.get(name):
            present.append(name)
        else:
            missing.append(name)
            score -= 8 if name == "strict-transport-security" else 4
    if missing:
        issues.append("Missing headers: " + ", ".join(missing) + ".")
    if open_http_hosts:
        score -= min(12, 2 * len(open_http_hosts))
        issues.append(
            f"{len(open_http_hosts)} live host(s) answered HTTP without a reliable HTTPS upgrade: "
            + ", ".join(open_http_hosts[:8])
            + "."
        )
    score = max(0, min(100, score))
    if score >= 90:
        letter = "A"
    elif score >= 75:
        letter = "B"
    elif score >= 60:
        letter = "C"
    elif score >= 40:
        letter = "D"
    else:
        letter = "F"
    return {
        "grade": letter,
        "score": score,
        "https_ok": https_ok,
        "redirect_to_https": redirect_to_https,
        "cert": cert or {},
        "present_headers": present,
        "missing_headers": missing,
        "open_http_hosts": open_http_hosts,
        "issues": issues,
    }


def _issuer_from_cert(cert: dict[str, Any]) -> str:
    issuer = cert.get("issuer") or ()
    bits = []
    for rdn in issuer:
        for key, val in rdn:
            if key in {"organizationName", "commonName"}:
                bits.append(str(val))
    return ", ".join(bits) or "unknown issuer"


def _days_left(not_after: str | None) -> int | None:
    if not not_after:
        return None
    text = not_after.strip()
    parsed = None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(text.replace("GMT", "UTC"), fmt).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue
    if parsed is None:
        try:
            parsed = parsedate_to_datetime(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return int((parsed - datetime.now(timezone.utc)).total_seconds() // 86400)


def read_tls_cert(host: str, timeout: float = 8.0) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert() or {}
    not_after = cert.get("notAfter")
    days = _days_left(not_after)
    return {
        "issuer": _issuer_from_cert(cert),
        "not_after": not_after or "",
        "days_left": days,
        "subject": str(cert.get("subject", "")),
    }


async def _http_probe(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        return await client.get(url)
    except Exception:
        return None


def _hosts_from_crtsh(payload: Any, domain: str, limit: int = 20) -> list[str]:
    domain = domain.lower().rstrip(".")
    names: list[str] = []
    rows = payload if isinstance(payload, list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        value = str(row.get("name_value") or "")
        for part in value.split("\n"):
            host = part.strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if not host.endswith(domain):
                continue
            if host == domain or host == f"www.{domain}":
                continue
            if host not in names:
                names.append(host)
            if len(names) >= limit:
                return names
    return names


async def run_web_security(domain: str, timeout: int = 30) -> ToolResult:
    started = asyncio.get_event_loop().time()
    domain = domain.lower().rstrip(".")
    https_ok = False
    redirect_to_https = False
    headers: dict[str, str] = {}
    cert: dict[str, Any] | None = None
    open_http: list[str] = []

    try:
        cert = await asyncio.wait_for(asyncio.to_thread(read_tls_cert, domain, 8.0), timeout=10)
    except Exception as exc:
        logger.info("tls %s: %s", domain, exc)
        cert = None

    timeout_cfg = httpx.Timeout(min(10, timeout), connect=5)
    async with httpx.AsyncClient(
        timeout=timeout_cfg,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        follow_redirects=False,
        verify=True,
    ) as client:
        https = await _http_probe(client, f"https://{domain}/")
        if https is not None and https.status_code < 500:
            https_ok = True
            headers = {k: v for k, v in https.headers.items()}
        http = await _http_probe(client, f"http://{domain}/")
        if http is not None:
            loc = (http.headers.get("location") or "").strip()
            if http.status_code in {301, 302, 303, 307, 308} and loc.lower().startswith("https://"):
                redirect_to_https = True
            elif http.status_code < 400 and https_ok:
                # Some hosts serve HTTPS only by ignoring HTTP; still flag missing redirect.
                redirect_to_https = False

        hosts: list[str] = []
        try:
            crt = await client.get(CRTSH_JSON.format(domain=domain), timeout=10, follow_redirects=True)
            if crt.status_code == 200 and crt.text:
                try:
                    hosts = _hosts_from_crtsh(crt.json(), domain, limit=16)
                except Exception:
                    hosts = []
        except Exception:
            hosts = []

        async def head_host(host: str) -> str | None:
            try:
                r = await client.head(f"http://{host}/", timeout=SUBDOMAIN_HEAD_TIMEOUT)
            except Exception:
                try:
                    r = await client.get(f"http://{host}/", timeout=SUBDOMAIN_HEAD_TIMEOUT)
                except Exception:
                    return None
            loc = (r.headers.get("location") or "").lower()
            if r.status_code in {301, 302, 303, 307, 308} and loc.startswith("https://"):
                return None
            if r.status_code < 500:
                # Confirm HTTPS; if it fails, flag the host.
                try:
                    h = await client.head(f"https://{host}/", timeout=SUBDOMAIN_HEAD_TIMEOUT)
                    if h.status_code < 500:
                        return None
                except Exception:
                    return host
                return None
            return None

        checked = []
        for host in hosts[:SUBDOMAIN_HEAD_CAP]:
            flagged = await head_host(host)
            checked.append(host)
            if flagged:
                open_http.append(flagged)

    graded = grade_web(
        https_ok=https_ok,
        redirect_to_https=redirect_to_https,
        cert=cert,
        headers=headers,
        open_http_hosts=open_http,
    )
    findings = [
        Finding(
            source="web_security",
            input_type="domain",
            value=f"Website security grade {graded['grade']}",
            url=f"https://{domain}",
            status="found",
            confidence="high",
            raw=_raw({"kind": "grade", **graded}),
        )
    ]
    if cert:
        expiry = cert.get("not_after") or "unknown"
        days = cert.get("days_left")
        day_txt = f", {days} day(s) left" if days is not None else ""
        findings.append(
            Finding(
                source="web_security",
                input_type="domain",
                value=f"TLS: {cert.get('issuer') or 'unknown issuer'} (expires {expiry}{day_txt})",
                url=f"https://{domain}",
                status="found",
                confidence="high",
                raw=_raw({"kind": "cert", **cert}),
            )
        )
    findings.append(
        Finding(
            source="web_security",
            input_type="domain",
            value="HTTP redirects to HTTPS" if redirect_to_https else "HTTP does not redirect to HTTPS",
            url=f"http://{domain}",
            status="found" if redirect_to_https else "not_found",
            confidence="high",
            raw=_raw({"kind": "redirect", "redirect_to_https": redirect_to_https}),
        )
    )
    missing = graded.get("missing_headers") or []
    present = graded.get("present_headers") or []
    findings.append(
        Finding(
            source="web_security",
            input_type="domain",
            value=(
                "Security headers present: " + ", ".join(present)
                if present
                else "No standard security headers observed"
            )
            + (f" (missing {', '.join(missing)})" if missing else ""),
            url=f"https://{domain}",
            status="found",
            confidence="high",
            raw=_raw({"kind": "headers", "present": present, "missing": missing}),
        )
    )
    for host in open_http:
        findings.append(
            Finding(
                source="web_security",
                input_type="domain",
                value=f"Live host without a reliable HTTPS upgrade: {host}",
                url=f"http://{host}",
                status="found",
                confidence="medium",
                raw=_raw({"kind": "open_http", "host": host}),
            )
        )
    return ToolResult(
        tool="web_security",
        status="found",
        message=f"Website grade {graded['grade']}",
        findings=findings,
        elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
    )


# ---------------------------------------------------------------------------
# GitHub public profile
# ---------------------------------------------------------------------------


def parse_github_profile(payload: dict[str, Any], username: str) -> list[Finding]:
    if not payload or payload.get("message") == "Not Found":
        return [
            Finding(
                source="github_profile",
                input_type="username",
                value="No public GitHub user with this handle",
                url=f"https://github.com/{username}",
                status="not_found",
                confidence="high",
                raw=_raw({"kind": "missing"}),
            )
        ]
    login = payload.get("login") or username
    url = payload.get("html_url") or f"https://github.com/{login}"
    fields = {
        "name": payload.get("name") or "",
        "bio": payload.get("bio") or "",
        "location": payload.get("location") or "",
        "company": payload.get("company") or "",
        "blog": payload.get("blog") or "",
        "email": payload.get("email") or "",
        "created_at": payload.get("created_at") or "",
        "public_repos": payload.get("public_repos") if payload.get("public_repos") is not None else "",
        "followers": payload.get("followers") if payload.get("followers") is not None else "",
    }
    pii = [k for k in ("email", "location", "company", "blog", "name") if fields.get(k)]
    created = fields["created_at"]
    age = ""
    if created:
        try:
            start = datetime.fromisoformat(created.replace("Z", "+00:00"))
            days = max(0, int((datetime.now(timezone.utc) - start).total_seconds() // 86400))
            age = f"{days // 365}y" if days >= 365 else f"{days}d"
        except Exception:
            age = created[:10]
    summary = f"GitHub @{login}"
    bits = [fields["name"], f"{fields['public_repos']} public repos" if fields["public_repos"] != "" else "", f"since {age}" if age else ""]
    extra = ", ".join(b for b in bits if b)
    if extra:
        summary = f"{summary} — {extra}"
    findings = [
        Finding(
            source="github_profile",
            input_type="username",
            value=summary,
            url=url,
            status="found",
            confidence="high",
            raw=_raw({"kind": "profile", "pii_fields": pii, **fields}),
        )
    ]
    if fields["email"]:
        findings.append(
            Finding(
                source="github_profile",
                input_type="username",
                value=f"Public email on GitHub: {fields['email']}",
                url=url,
                status="found",
                confidence="high",
                raw=_raw({"kind": "pii", "field": "email"}),
            )
        )
    for key in ("location", "company", "blog", "bio"):
        if fields[key]:
            findings.append(
                Finding(
                    source="github_profile",
                    input_type="username",
                    value=f"GitHub {key}: {fields[key]}",
                    url=url,
                    status="found",
                    confidence="medium",
                    raw=_raw({"kind": "pii", "field": key}),
                )
            )
    return findings


async def run_github_profile(username: str, timeout: int = 15) -> ToolResult:
    started = asyncio.get_event_loop().time()
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=_headers(), follow_redirects=True) as client:
            response = await client.get(GITHUB_USER.format(username=username))
        if response.status_code == 403:
            return ToolResult(
                tool="github_profile",
                status="blocked",
                message="GitHub unauthenticated rate limit (60 requests/hour) was reached.",
                elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
            )
        if response.status_code == 404:
            findings = parse_github_profile({}, username)
            return ToolResult(
                tool="github_profile",
                status="not_found",
                message="No public GitHub user with this handle",
                findings=findings,
                elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
            )
        if response.status_code >= 400:
            return ToolResult(
                tool="github_profile",
                status="error",
                message=f"GitHub returned HTTP {response.status_code}",
                elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
            )
        payload = response.json()
    except httpx.TimeoutException:
        return ToolResult(tool="github_profile", status="error", message=f"timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001
        return ToolResult(tool="github_profile", status="error", message=str(exc)[:240])

    findings = parse_github_profile(payload if isinstance(payload, dict) else {}, username)
    found = any(f.status == "found" for f in findings)
    return ToolResult(
        tool="github_profile",
        status="found" if found else "not_found",
        message=findings[0].value if findings else "No public GitHub profile",
        findings=findings,
        elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
    )


# ---------------------------------------------------------------------------
# Gravatar public profile (email hash only)
# ---------------------------------------------------------------------------


def email_digests(email: str) -> dict[str, str]:
    norm = email.strip().lower().encode("utf-8")
    return {
        "md5": hashlib.md5(norm).hexdigest(),  # noqa: S324 — Gravatar still indexes MD5
        "sha256": hashlib.sha256(norm).hexdigest(),
    }


def parse_gravatar_profile(payload: dict[str, Any], email: str) -> list[Finding]:
    entry = payload.get("entry") if isinstance(payload, dict) else None
    if not entry:
        return [
            Finding(
                source="gravatar",
                input_type="email",
                value="No public Gravatar profile for this email",
                url="https://gravatar.com/",
                status="not_found",
                confidence="medium",
                raw=_raw({"kind": "missing"}),
            )
        ]
    first = entry[0] if isinstance(entry, list) and entry else {}
    display = first.get("displayName") or first.get("preferredUsername") or "Gravatar profile"
    location = ""
    current = first.get("currentLocation") or ""
    if current:
        location = str(current)
    urls = first.get("urls") or []
    about = first.get("aboutMe") or first.get("description") or ""
    profile_url = first.get("profileUrl") or first.get("hash") or "https://gravatar.com/"
    if isinstance(profile_url, str) and profile_url.startswith("/"):
        profile_url = "https://gravatar.com" + profile_url
    pii = []
    if location:
        pii.append("location")
    if about:
        pii.append("about")
    if first.get("name"):
        pii.append("name")
    findings = [
        Finding(
            source="gravatar",
            input_type="email",
            value=f"Gravatar profile: {display}",
            url=str(profile_url),
            status="found",
            confidence="high",
            raw=_raw(
                {
                    "kind": "profile",
                    "display": display,
                    "location": location,
                    "about": (about or "")[:240],
                    "pii_fields": pii,
                }
            ),
        )
    ]
    if location:
        findings.append(
            Finding(
                source="gravatar",
                input_type="email",
                value=f"Gravatar location: {location}",
                url=str(profile_url),
                status="found",
                confidence="medium",
                raw=_raw({"kind": "pii", "field": "location"}),
            )
        )
    return findings


async def run_gravatar(email: str, timeout: int = 15) -> ToolResult:
    started = asyncio.get_event_loop().time()
    digests = email_digests(email)
    payload: dict[str, Any] | None = None
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=_headers(), follow_redirects=True) as client:
            for algo in ("sha256", "md5"):
                response = await client.get(GRAVATAR_JSON.format(digest=digests[algo]))
                if response.status_code == 404:
                    continue
                if response.status_code == 429:
                    return ToolResult(
                        tool="gravatar",
                        status="blocked",
                        message="Gravatar rate-limited this request.",
                        elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
                    )
                if response.status_code >= 400:
                    continue
                try:
                    payload = response.json()
                except Exception:
                    payload = None
                if payload:
                    break
    except httpx.TimeoutException:
        return ToolResult(tool="gravatar", status="error", message=f"timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001
        return ToolResult(tool="gravatar", status="error", message=str(exc)[:240])

    findings = parse_gravatar_profile(payload or {}, email)
    found = any(f.status == "found" for f in findings)
    return ToolResult(
        tool="gravatar",
        status="found" if found else "not_found",
        message=findings[0].value if findings else "No Gravatar profile",
        findings=findings,
        elapsed_s=round(asyncio.get_event_loop().time() - started, 2),
    )


# ---------------------------------------------------------------------------
# Scan history / diff
# ---------------------------------------------------------------------------


def identifier_hash(inputs: dict[str, str] | None) -> str:
    parts = []
    for key in ("username", "email", "domain"):
        val = (inputs or {}).get(key) or ""
        val = val.strip().lower()
        if val:
            parts.append(f"{key}={val}")
    blob = "|".join(parts)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def finding_identity(finding: dict[str, Any]) -> str:
    url = (finding.get("url") or "").rstrip("/").lower()
    value = (finding.get("value") or "").strip().lower()
    source = (finding.get("source") or "").strip().lower()
    kind = (finding.get("input_type") or "").strip().lower()
    return f"{source}|{kind}|{url or value}"


def diff_findings(
    current: list[dict[str, Any]],
    previous: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    current_found = [f for f in current or [] if (f.get("status") or "").lower() == "found"]
    previous_found = [f for f in previous or [] if (f.get("status") or "").lower() == "found"]
    if previous is None:
        return {"new": [], "removed": [], "unchanged": len(current_found), "has_previous": False}
    cur_map = {finding_identity(f): f for f in current_found}
    prev_map = {finding_identity(f): f for f in previous_found}
    new_keys = [k for k in cur_map if k not in prev_map]
    gone_keys = [k for k in prev_map if k not in cur_map]
    return {
        "has_previous": True,
        "new": [cur_map[k] for k in new_keys],
        "removed": [prev_map[k] for k in gone_keys],
        "unchanged": len(current_found) - len(new_keys),
    }
