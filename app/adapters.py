"""Subprocess adapters and output parsers for the Kali OSINT tools used in the MVP.

Flags follow the project research notes (Nov 2026):

- Sherlock: CSV export only. ``--json`` loads a site list; it does *not* export results.
  ``sherlock USER --csv --no-txt --folderoutput DIR``
- Maigret: ``maigret USER --json simple -fo DIR`` → ``*_simple.json``
- holehe: ``holehe EMAIL --only-used --json`` (JSON may be missing; parse text too)
- h8mail: only when HIBP_API_KEY is set: ``h8mail -t EMAIL -j out.json -k hibp:KEY``
- whois: ``whois example.com``
- dnsrecon: ``dnsrecon -d example.com -t std -j out.json``
- subfinder: ``subfinder -d example.com -silent -oJ -o out.jsonl``
- theHarvester: ``theHarvester -d example.com -b crtsh,hackertarget,duckduckgo -l 200 -f out``

Every tool is launched as an argv list (never ``shell=True``). Missing binaries are
marked ``unavailable``. Timeouts and rate-limits are distinct from ``not_found``.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import re
import shutil

import httpx
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

logger = logging.getLogger("footprint.adapters")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# WHOIS privacy / registrar-abuse addresses should not count as a personal email.
WHOIS_PRIVACY_MARKERS = (
    "redacted",
    "privacy",
    "anonymiz",
    "withheld",
    "domainsbyproxy",
    "whoisguard",
    "contact privacy",
    "gdpr",
    "data protected",
    "redacted for privacy",
    "privacyprotect",
    "identity protect",
    "whoisprivacyprotect",
)
WHOIS_ABUSE_MARKERS = ("abuse@", "awregistry", "registrar-abuse", "dnsabuse")

SENSITIVE_HINTS = (
    "github",
    "gitlab",
    "linkedin",
    "instagram",
    "facebook",
    "reddit",
    "tiktok",
    "twitter",
    "youtube",
    "paypal",
    "adobe",
    "apple",
    "google",
)

TOOL_TIMEOUTS = {
    "sherlock": 180,
    "maigret": 180,
    "holehe": 150,
    "h8mail": 120,
    "whois": 120,
    "dns_lookup": 60,
    "crtsh": 45,
    "dnsrecon": 150,
    "subfinder": 150,
    "theharvester": 180,
}

# kind: binary = PATH tool; python = always-on library/API; whois = CLI or python-whois.
# optional binaries stay in the UI as unavailable when not installed (cloud image
# does not ship dnsrecon/subfinder/theHarvester).
TOOL_SPEC = {
    "sherlock": {"binaries": ["sherlock"], "group": "username", "timeout": 180, "kind": "binary"},
    "maigret": {"binaries": ["maigret"], "group": "username", "timeout": 180, "kind": "binary"},
    "holehe": {"binaries": ["holehe"], "group": "email", "timeout": 150, "kind": "binary"},
    "h8mail": {
        "binaries": ["h8mail"],
        "group": "email",
        "timeout": 120,
        "requires_env": "HIBP_API_KEY",
        "kind": "binary",
    },
    "whois": {"binaries": ["whois"], "group": "domain", "timeout": 120, "kind": "whois"},
    "dns_lookup": {"binaries": [], "group": "domain", "timeout": 60, "kind": "python", "module": "dns.resolver"},
    "crtsh": {"binaries": [], "group": "domain", "timeout": 45, "kind": "python", "module": "httpx"},
    "dnsrecon": {"binaries": ["dnsrecon"], "group": "domain", "timeout": 150, "kind": "binary"},
    "subfinder": {"binaries": ["subfinder"], "group": "domain", "timeout": 150, "kind": "binary"},
    "theharvester": {
        "binaries": ["theHarvester", "theharvester"],
        "group": "domain",
        "timeout": 180,
        "kind": "binary",
    },
}

HEAVY_TOOLS = {"maigret", "sherlock"}


def maigret_top_sites() -> int:
    try:
        n = int(os.environ.get("MAIGRET_TOP_SITES", "200"))
    except ValueError:
        n = 200
    return max(20, min(n, 500))


def maigret_max_connections() -> int:
    try:
        n = int(os.environ.get("MAIGRET_MAX_CONNECTIONS", "20"))
    except ValueError:
        n = 20
    return max(5, min(n, 50))

# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    source: str
    input_type: str
    value: str
    url: str = ""
    status: str = "found"  # found | not_found | blocked | error | unavailable
    confidence: str = "medium"  # high | medium | low
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolResult:
    tool: str
    status: str
    message: str = ""
    findings: list[Finding] = field(default_factory=list)
    elapsed_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "message": self.message,
            "findings": [f.to_dict() for f in self.findings],
            "elapsed_s": self.elapsed_s,
        }


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------


def _which_first(names: Iterable[str]) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def _module_available(dotted: str) -> bool:
    if not dotted:
        return False
    try:
        __import__(dotted)
        return True
    except Exception:
        return False


def detect_tools() -> dict[str, dict[str, Any]]:
    """Startup check used by the API and the UI."""
    detected: dict[str, dict[str, Any]] = {}
    for name, spec in TOOL_SPEC.items():
        kind = spec.get("kind") or "binary"
        path = _which_first(spec.get("binaries") or [])
        reason = ""
        backend = "binary" if path else None
        available = bool(path)
        if kind == "python":
            available = _module_available(spec.get("module") or "")
            backend = "python" if available else None
            path = None
            reason = "" if available else f"Python module {spec.get('module')} is not installed"
        elif kind == "whois":
            if path:
                available = True
                backend = "binary"
            elif _module_available("whois"):
                available = True
                backend = "python"
                path = None
                reason = "using python-whois (system whois binary not on PATH)"
            else:
                available = False
                reason = "whois binary and python-whois are both missing"
        elif not available:
            reason = "binary not found on PATH (optional on the cloud image)"
        env_name = spec.get("requires_env")
        if env_name and not os.environ.get(env_name, "").strip():
            if path:
                reason = f"{env_name} is not set — tool will be skipped; a HIBP link is shown instead"
            elif not reason:
                reason = "binary not found on PATH"
            if name == "h8mail":
                available = bool(path) and bool(os.environ.get(env_name, "").strip())
                if path and not os.environ.get(env_name, "").strip():
                    reason = f"{env_name} is not set — skipped; use the Have I Been Pwned link"
                    available = False
        detected[name] = {
            "available": available,
            "path": path,
            "group": spec["group"],
            "timeout": spec["timeout"],
            "reason": reason,
            "backend": backend,
            "kind": kind,
        }
    return detected


def hibp_link(email: str | None = None) -> str:
    return "https://haveibeenpwned.com/"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def _truncate(text: str, limit: int = 400) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _extract_json_blob(text: str) -> Any | None:
    """Best-effort: parse whole text, then the last [...] or {...} block."""
    text = strip_ansi(text).strip()
    if not text:
        return None
    candidates: list[str] = [text]
    # Prefer the last array or object, which is how holehe often prints JSON
    # after coloured progress lines.
    for open_ch, close_ch in (("[", "]"), ("{", "}")):
        start = text.rfind(open_ch)
        end = text.rfind(close_ch)
        if start != -1 and end != -1 and end > start:
            candidates.append(text[start : end + 1])
    for chunk in candidates:
        try:
            return json.loads(chunk)
        except json.JSONDecodeError:
            continue
    return None


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _glob_first(directory: Path, patterns: Iterable[str]) -> Path | None:
    for pattern in patterns:
        matches = sorted(directory.glob(pattern))
        if matches:
            return matches[0]
    return None


def _confidence_for_site(name: str, url: str = "") -> str:
    blob = f"{name} {url}".lower()
    # Platforms that commonly false-positive or block scanners.
    if any(s in blob for s in ("instagram", "facebook", "tiktok", "snapchat")):
        return "low"
    if any(s in blob for s in ("github", "gitlab", "reddit", "linkedin")):
        return "high"
    return "medium"


def _status_from_exists(flag: Any) -> str | None:
    if flag is None:
        return None
    if isinstance(flag, bool):
        return "found" if flag else "not_found"
    text = str(flag).strip().lower()
    if text in {"claimed", "found", "true", "yes", "exists", "used"}:
        return "found"
    if text in {"available", "not found", "false", "no", "not_found", "unknown"}:
        return "not_found"
    if text in {"waf", "blocked", "rate", "ratelimited", "rate-limited", "rate_limit"}:
        return "blocked"
    if text in {"illegal", "illegal username format for this site!"}:
        return None  # skip — username not legal on that site
    return None


# ---------------------------------------------------------------------------
# Parsers (pure functions, unit-tested with fixtures)
# ---------------------------------------------------------------------------


def parse_sherlock_csv(text: str, username: str) -> list[Finding]:
    """Parse Sherlock CSV (columns: username,name,url_main,url_user,exists,http_status,...)."""
    findings: list[Finding] = []
    cleaned = strip_ansi(text).lstrip("\ufeff")
    if not cleaned.strip():
        return findings
    reader = csv.DictReader(io.StringIO(cleaned))
    # Be tolerant of slightly different headers.
    for row in reader:
        if not row:
            continue
        # Some versions write a leading index column; DictReader still works.
        lower = { (k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k is not None }
        site = lower.get("name") or lower.get("platform") or lower.get("site") or ""
        url = lower.get("url_user") or lower.get("url") or lower.get("profile url") or lower.get("profile") or ""
        exists = lower.get("exists") or lower.get("status") or ""
        http_status = lower.get("http_status") or lower.get("http") or ""
        status = _status_from_exists(exists)
        if status is None:
            lowered_exists = exists.lower()
            if not exists or "illegal" in lowered_exists:
                continue
            if "claimed" in lowered_exists:
                status = "found"
            elif "waf" in lowered_exists or "block" in lowered_exists:
                status = "blocked"
            elif "available" in lowered_exists:
                status = "not_found"
            else:
                status = "error"
        if status == "not_found":
            # Do not flood the report with hundreds of negatives.
            continue
        raw = f"exists={exists}; http_status={http_status}"
        confidence = _confidence_for_site(site, url) if status == "found" else "low"
        try:
            code = int(str(http_status).strip()) if str(http_status).strip() else 0
        except ValueError:
            code = 0
        # Soft-404 / WAF: Sherlock may still mark these Claimed.
        if status == "found" and code and code not in {200, 201, 204, 301, 302, 303}:
            confidence = "low"
            raw += "; possible_false_positive"
        findings.append(
            Finding(
                source="sherlock",
                input_type="username",
                value=site or username,
                url=url,
                status=status,
                confidence=confidence,
                raw=_truncate(raw),
            )
        )
    return findings


def parse_maigret_json(text: str, username: str) -> list[Finding]:
    """Parse Maigret ``--json simple`` (object keyed by site name, claimed accounts only).

    Also accepts ndjson (one object per line with a sitename field) and a
    wrapped ``{username: {...}}`` form if a future version adds it.
    """
    findings: list[Finding] = []
    text = strip_ansi(text).strip()
    if not text:
        return findings

    data: Any = None
    # ndjson? try line by line first only if every non-empty line is an object
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if lines and all(ln.strip().startswith("{") for ln in lines) and len(lines) > 1:
        objs = []
        ok = True
        for ln in lines:
            try:
                objs.append(json.loads(ln))
            except json.JSONDecodeError:
                ok = False
                break
        if ok and objs and any("sitename" in o or "url_user" in o for o in objs):
            data = objs

    if data is None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = _extract_json_blob(text)
    if data is None:
        return findings

    sites: dict[str, Any] = {}
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            name = item.get("sitename") or item.get("site") or item.get("name") or ""
            if isinstance(name, dict):
                name = name.get("name") or ""
            sites[str(name) or "unknown"] = item
    elif isinstance(data, dict):
        # If the only keys look like usernames wrapping a site dict, unwrap.
        if (
            username in data
            and isinstance(data[username], dict)
            and any(isinstance(v, dict) for v in data[username].values())
        ):
            sites = data[username]
        else:
            sites = data
    else:
        return findings

    for site_name, payload in sites.items():
        if not isinstance(payload, dict):
            continue
        status_field = payload.get("status")
        status_text = ""
        if isinstance(status_field, dict):
            status_text = str(status_field.get("status") or "")
        elif status_field is not None:
            status_text = str(status_field)
        # simple JSON is supposed to include only claimed accounts, but be safe.
        mapped = _status_from_exists(status_text) if status_text else "found"
        if mapped == "not_found":
            continue
        if mapped is None:
            mapped = "found"
        url = (
            payload.get("url_user")
            or payload.get("url")
            or (status_field.get("url") if isinstance(status_field, dict) else "")
            or ""
        )
        ids = payload.get("ids") or {}
        raw_bits = {
            "status": status_text or "Claimed",
            "http_status": payload.get("http_status"),
            "ids": ids or None,
            "is_similar": payload.get("is_similar"),
        }
        findings.append(
            Finding(
                source="maigret",
                input_type="username",
                value=str(site_name),
                url=str(url),
                status=mapped,
                confidence=_confidence_for_site(str(site_name), str(url)),
                raw=_truncate(json.dumps(raw_bits, ensure_ascii=False, default=str)),
            )
        )
    return findings


def parse_holehe_output(text: str, email: str) -> list[Finding]:
    """Parse holehe ``--only-used --json`` output, or coloured text if JSON is absent."""
    findings: list[Finding] = []
    cleaned = strip_ansi(text)
    blob = _extract_json_blob(cleaned)

    items: list[dict] = []
    if isinstance(blob, list):
        items = [x for x in blob if isinstance(x, dict)]
    elif isinstance(blob, dict) and any(k in blob for k in ("name", "exists", "rateLimit", "domain")):
        items = [blob]
    elif isinstance(blob, dict):
        # Sometimes a mapping of site -> info
        for name, info in blob.items():
            if isinstance(info, dict):
                merged = {"name": name, **info}
                items.append(merged)
            elif info is True:
                items.append({"name": name, "exists": True, "rateLimit": False})

    if items:
        for item in items:
            name = str(item.get("name") or item.get("domain") or "unknown")
            rate_limited = bool(item.get("rateLimit") or item.get("rate_limit") or item.get("frequent_rate_limit") and item.get("rateLimit"))
            if item.get("rateLimit") is True or item.get("rate_limit") is True:
                rate_limited = True
            exists = item.get("exists")
            if rate_limited and not exists:
                status = "blocked"
            elif exists is True or str(exists).lower() in {"true", "yes", "used"}:
                status = "found"
            elif exists is False:
                # --only-used should have filtered these; skip negatives.
                continue
            else:
                if rate_limited:
                    status = "blocked"
                else:
                    continue
            extras = []
            if item.get("emailrecovery"):
                extras.append(f"recovery_email={item['emailrecovery']}")
            if item.get("phoneNumber"):
                extras.append(f"recovery_phone={item['phoneNumber']}")
            if item.get("others"):
                extras.append(f"others={item['others']}")
            if rate_limited:
                extras.append("rateLimit=true")
            domain = item.get("domain") or ""
            url = f"https://{domain}" if domain and not str(domain).startswith("http") else str(domain)
            findings.append(
                Finding(
                    source="holehe",
                    input_type="email",
                    value=name,
                    url=url,
                    status=status,
                    confidence="medium" if status == "found" else "low",
                    raw=_truncate("; ".join(extras) or json.dumps(item, ensure_ascii=False, default=str)[:400]),
                )
            )
        return findings

    # Text fallback: look for [+] used / [x] rate-limit style lines.
    for line in cleaned.splitlines():
        line = line.strip()
        if not line:
            continue
        plus = re.match(r"^\[\+\]\s*(.+)$", line)
        blocked = re.match(r"^\[(?:x|X|!)\]\s*(.+)$", line)
        # Common phrase forms
        used = re.search(r"(?:email\s+)?(?:used|registered)\s+(?:on\s+)?(.+)$", line, re.I)
        if plus:
            name = plus.group(1).strip().strip(":- ")
            # Ignore banner / summary lines
            if len(name) < 2 or "holehe" in name.lower():
                continue
            findings.append(
                Finding(
                    source="holehe",
                    input_type="email",
                    value=name.split()[0],
                    url="",
                    status="found",
                    confidence="medium",
                    raw=_truncate(line),
                )
            )
        elif blocked and re.search(r"rate|limit|block", line, re.I):
            name = blocked.group(1).strip().strip(":- ")
            findings.append(
                Finding(
                    source="holehe",
                    input_type="email",
                    value=name.split()[0],
                    url="",
                    status="blocked",
                    confidence="low",
                    raw=_truncate(line),
                )
            )
        elif used and not line.startswith("[-]"):
            name = used.group(1).strip().strip(":- ")
            if name:
                findings.append(
                    Finding(
                        source="holehe",
                        input_type="email",
                        value=name.split()[0],
                        url="",
                        status="found",
                        confidence="low",
                        raw=_truncate(line),
                    )
                )
    return findings


def parse_holehe_csv(text: str, email: str) -> list[Finding]:
    """Parse holehe ``-C`` CSV (same fields as the per-module dicts)."""
    cleaned = strip_ansi(text).lstrip("\ufeff")
    if not cleaned.strip():
        return []
    reader = csv.DictReader(io.StringIO(cleaned))
    items: list[dict] = []
    for row in reader:
        if not row:
            continue
        item = { (k or "").strip(): v for k, v in row.items() if k is not None }
        # CSV cells are strings; coerce booleans.
        for key in ("exists", "rateLimit", "rate_limit", "frequent_rate_limit"):
            if key in item:
                val = str(item[key]).strip().lower()
                item[key] = val in {"true", "1", "yes"}
        items.append(item)
    return parse_holehe_output(json.dumps(items), email)


def parse_whois_text(text: str, domain: str) -> list[Finding]:
    """Extract registrar, dates, nameservers, and non-redacted contact emails."""
    findings: list[Finding] = []
    cleaned = strip_ansi(text)
    if not cleaned.strip():
        return findings

    def first_match(patterns: Iterable[str]) -> str:
        for pattern in patterns:
            m = re.search(pattern, cleaned, re.I | re.M)
            if m:
                return m.group(1).strip()
        return ""

    registrar = first_match(
        [
            r"^Registrar:\s*(.+)$",
            r"^registrar(?:\s+name)?:\s*(.+)$",
        ]
    )
    created = first_match(
        [
            r"^Creation Date:\s*(.+)$",
            r"^created:\s*(.+)$",
            r"^Created On:\s*(.+)$",
        ]
    )
    expires = first_match(
        [
            r"^Registry Expiry Date:\s*(.+)$",
            r"^Expir(?:y|ation) Date:\s*(.+)$",
            r"^expires:\s*(.+)$",
        ]
    )
    org = first_match(
        [
            r"^Registrant Organization:\s*(.+)$",
            r"^org(?:anization)?:\s*(.+)$",
            r"^Registrant Name:\s*(.+)$",
        ]
    )
    nameservers = re.findall(r"^Name Server:\s*(\S+)", cleaned, re.I | re.M)
    if not nameservers:
        nameservers = re.findall(r"^nserver:\s*(\S+)", cleaned, re.I | re.M)

    summary_parts = [f"domain={domain}"]
    if registrar:
        summary_parts.append(f"registrar={registrar}")
    if created:
        summary_parts.append(f"created={created}")
    if expires:
        summary_parts.append(f"expires={expires}")
    if nameservers:
        summary_parts.append("ns=" + ",".join(nameservers[:6]))
    findings.append(
        Finding(
            source="whois",
            input_type="domain",
            value=registrar or domain,
            url="",
            status="found",
            confidence="high",
            raw=_truncate("; ".join(summary_parts)),
        )
    )

    lowered_full = cleaned.lower()
    redacted_record = any(m in lowered_full for m in ("redacted for privacy", "data protected", "gdpr redacted"))

    if org and not any(m in org.lower() for m in WHOIS_PRIVACY_MARKERS) and org.lower() not in {"n/a", "na", "redacted"}:
        findings.append(
            Finding(
                source="whois",
                input_type="domain",
                value=org,
                url="",
                status="found",
                confidence="medium",
                raw="whois_registrant",
            )
        )

    seen_emails: set[str] = set()
    for match in EMAIL_RE.findall(cleaned):
        addr = match.lower()
        if addr in seen_emails:
            continue
        seen_emails.add(addr)
        context_ok = True
        if any(m in addr for m in WHOIS_ABUSE_MARKERS):
            context_ok = False
        if any(m in addr for m in WHOIS_PRIVACY_MARKERS):
            context_ok = False
        # Look at a short window around the email for privacy words.
        idx = lowered_full.find(addr)
        window = lowered_full[max(0, idx - 80) : idx + len(addr) + 80]
        if any(m in window for m in WHOIS_PRIVACY_MARKERS):
            context_ok = False
        if not context_ok:
            continue
        findings.append(
            Finding(
                source="whois",
                input_type="domain",
                value=addr,
                url="",
                status="found",
                confidence="high",
                raw="whois_email",
            )
        )

    if redacted_record and not any(f.raw == "whois_email" for f in findings):
        findings.append(
            Finding(
                source="whois",
                input_type="domain",
                value="WHOIS privacy / redaction appears active",
                url="",
                status="found",
                confidence="high",
                raw="whois_privacy",
            )
        )
    return findings


def parse_dnsrecon_json(text: str, domain: str) -> list[Finding]:
    """Parse dnsrecon ``-j`` output (a list of records, or an object with records)."""
    findings: list[Finding] = []
    data = _extract_json_blob(text)
    if data is None:
        try:
            data = json.loads(strip_ansi(text))
        except json.JSONDecodeError:
            return findings

    records: list[Any]
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("records") or data.get("data") or data.get("hosts") or []
        if not records and any(k in data for k in ("type", "name", "address")):
            records = [data]
    else:
        return findings

    seen: set[tuple[str, str, str]] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        rtype = str(rec.get("type") or rec.get("rtype") or "record")
        name = str(rec.get("name") or rec.get("hostname") or rec.get("host") or domain)
        address = str(
            rec.get("address")
            or rec.get("exchange")
            or rec.get("target")
            or rec.get("value")
            or rec.get("strings")
            or ""
        )
        key = (rtype.upper(), name.lower(), address.lower())
        if key in seen:
            continue
        seen.add(key)
        value = f"{rtype} {name}"
        if address:
            value = f"{rtype} {name} → {address}"
        findings.append(
            Finding(
                source="dnsrecon",
                input_type="domain",
                value=value,
                url="",
                status="found",
                confidence="high",
                raw=_truncate(json.dumps(rec, ensure_ascii=False, default=str)),
            )
        )
    return findings


def parse_subfinder_jsonl(text: str, domain: str) -> list[Finding]:
    """Parse subfinder ``-oJ`` JSONL (one JSON object per line)."""
    findings: list[Finding] = []
    cleaned = strip_ansi(text).strip()
    if not cleaned:
        return findings

    rows: list[dict] = []
    # JSONL first
    parsed_any = False
    for line in cleaned.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_any = True
        if isinstance(obj, dict):
            rows.append(obj)
        elif isinstance(obj, str):
            rows.append({"host": obj})
    if not parsed_any:
        blob = _extract_json_blob(cleaned)
        if isinstance(blob, list):
            rows = [x if isinstance(x, dict) else {"host": str(x)} for x in blob]
        elif isinstance(blob, dict):
            rows = [blob]
        else:
            # Plain hostnames, one per line (if -oJ was ignored)
            for line in cleaned.splitlines():
                host = line.strip()
                if host and " " not in host:
                    rows.append({"host": host})

    seen: set[str] = set()
    for row in rows:
        host = str(row.get("host") or row.get("fqdn") or row.get("name") or "").strip()
        if not host or host.lower() in seen:
            continue
        seen.add(host.lower())
        source = row.get("source") or row.get("input") or ""
        findings.append(
            Finding(
                source="subfinder",
                input_type="domain",
                value=host,
                url=f"https://{host}",
                status="found",
                confidence="high",
                raw=_truncate(f"source={source}" if source else json.dumps(row, ensure_ascii=False, default=str)),
            )
        )
    return findings


def parse_theharvester_json(text: str, domain: str) -> list[Finding]:
    """Parse theHarvester ``-f`` JSON (emails, hosts, people, ips, interesting_urls)."""
    findings: list[Finding] = []
    data = _extract_json_blob(text)
    if data is None:
        try:
            data = json.loads(strip_ansi(text))
        except json.JSONDecodeError:
            return findings
    if not isinstance(data, dict):
        return findings

    def as_list(key: str) -> list[Any]:
        val = data.get(key) or []
        if isinstance(val, list):
            return val
        if val:
            return [val]
        return []

    for email in as_list("emails"):
        addr = email if isinstance(email, str) else str(email)
        findings.append(
            Finding(
                source="theharvester",
                input_type="domain",
                value=addr,
                url="",
                status="found",
                confidence="medium",
                raw="harvested_email",
            )
        )
    for host in as_list("hosts"):
        name = host if isinstance(host, str) else str(host)
        # theHarvester sometimes emits "host:ip"
        hostname = name.split(":")[0].strip()
        findings.append(
            Finding(
                source="theharvester",
                input_type="domain",
                value=hostname or name,
                url=f"https://{hostname}" if hostname else "",
                status="found",
                confidence="medium",
                raw=_truncate(name),
            )
        )
    for person in as_list("people") + as_list("linkedin_people") + as_list("twitter_people"):
        label = "person"
        if not isinstance(person, str):
            person = str(person)
        findings.append(
            Finding(
                source="theharvester",
                input_type="domain",
                value=person,
                url="",
                status="found",
                confidence="low",
                raw="person",
            )
        )
    for url in as_list("interesting_urls"):
        findings.append(
            Finding(
                source="theharvester",
                input_type="domain",
                value=str(url),
                url=str(url),
                status="found",
                confidence="medium",
                raw="interesting_url",
            )
        )
    for ip in as_list("ips"):
        findings.append(
            Finding(
                source="theharvester",
                input_type="domain",
                value=str(ip),
                url="",
                status="found",
                confidence="medium",
                raw="ip",
            )
        )
    return findings


def parse_h8mail_json(text: str, email: str) -> list[Finding]:
    """Parse h8mail ``-j`` JSON. Shapes vary across versions; be liberal."""
    findings: list[Finding] = []
    data = _extract_json_blob(text)
    if data is None:
        try:
            data = json.loads(strip_ansi(text))
        except json.JSONDecodeError:
            return findings

    targets: list[dict] = []
    if isinstance(data, dict):
        if "targets" in data:
            raw_targets = data["targets"]
            if isinstance(raw_targets, dict):
                for key, val in raw_targets.items():
                    if isinstance(val, dict):
                        targets.append({"target": key, **val})
                    else:
                        targets.append({"target": key, "data": val})
            elif isinstance(raw_targets, list):
                targets = [t for t in raw_targets if isinstance(t, dict)]
        elif "target" in data or "data" in data or "pwn_num" in data:
            targets = [data]
        else:
            # Maybe a mapping of email -> record
            for key, val in data.items():
                if isinstance(val, dict) and ("@" in str(key) or "pwn" in val or "data" in val):
                    targets.append({"target": key, **val})
    elif isinstance(data, list):
        targets = [t for t in data if isinstance(t, dict)]

    for target in targets:
        pwn_num = target.get("pwn_num")
        if pwn_num is None:
            pwn_num = target.get("pwned") or target.get("breach_count")
        data_rows = target.get("data") or target.get("breaches") or target.get("sources") or []
        if isinstance(data_rows, dict):
            data_rows = [data_rows]
        if pwn_num is None:
            pwn_num = len(data_rows) if data_rows else 0
        try:
            pwn_count = int(pwn_num)
        except (TypeError, ValueError):
            pwn_count = len(data_rows) if data_rows else 0

        if pwn_count <= 0 and not data_rows:
            findings.append(
                Finding(
                    source="h8mail",
                    input_type="email",
                    value="No breach records returned",
                    url=hibp_link(email),
                    status="not_found",
                    confidence="medium",
                    raw="pwn_num=0",
                )
            )
            continue

        # Do not include leaked passwords even if the tool returned them.
        labels: list[str] = []
        for row in data_rows:
            if isinstance(row, (list, tuple)) and row:
                # Typical: [email, source, ...sensitive]
                label = str(row[1] if len(row) > 1 else row[0])
                labels.append(label)
            elif isinstance(row, dict):
                label = str(row.get("source") or row.get("Name") or row.get("name") or row.get("breach") or "breach")
                labels.append(label)
            else:
                labels.append(str(row))
        preview = ", ".join(labels[:8])
        if len(labels) > 8:
            preview += f", +{len(labels) - 8} more"
        findings.append(
            Finding(
                source="h8mail",
                input_type="email",
                value=f"{pwn_count} breach source(s)",
                url=hibp_link(email),
                status="found",
                confidence="high",
                raw=_truncate(f"pwn_num={pwn_count}; sources={preview}"),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------


async def run_cmd(argv: list[str], timeout: int, cwd: str | None = None) -> tuple[int, str, str]:
    """Run a command without a shell. Raises asyncio.TimeoutError after kill."""
    logger.info("Running: %s", " ".join(argv))
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:  # noqa: BLE001
            pass
        raise
    return (
        int(proc.returncode or 0),
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def _summarize_blocked(findings: list[Finding], source: str, input_type: str, keep: int = 5) -> list[Finding]:
    """Keep the report readable when a cloud IP rate-limits almost every site."""
    found = [f for f in findings if f.status == "found"]
    blocked = [f for f in findings if f.status == "blocked"]
    other = [f for f in findings if f.status not in {"found", "blocked"}]
    if len(blocked) <= 8:
        return findings
    kept = blocked[:keep]
    rest = len(blocked) - keep
    kept.append(
        Finding(
            source=source,
            input_type=input_type,
            value=f"{len(blocked)} services rate-limited or unreachable",
            url="",
            status="blocked",
            confidence="low",
            raw=_truncate(f"summarized {rest} additional blocked rows (common from cloud IPs)"),
        )
    )
    return found + kept + other


def _tool_status_from_findings(findings: list[Finding], default_if_empty: str = "not_found") -> str:
    if any(f.status == "error" for f in findings) and not any(f.status == "found" for f in findings):
        return "error"
    if any(f.status == "found" for f in findings):
        return "found"
    if any(f.status == "blocked" for f in findings) and not any(f.status == "found" for f in findings):
        return "blocked"
    if any(f.status == "unavailable" for f in findings):
        return "unavailable"
    return default_if_empty


def _unavailable(tool: str, reason: str) -> ToolResult:
    return ToolResult(tool=tool, status="unavailable", message=reason, findings=[])


def _error(tool: str, message: str) -> ToolResult:
    return ToolResult(tool=tool, status="error", message=_truncate(message, 240), findings=[])


# --- individual runners ---


async def run_sherlock(username: str, timeout: int | None = None, binary: str = "sherlock") -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["sherlock"]
    with tempfile.TemporaryDirectory(prefix="sherlock-") as tmp:
        tmp_path = Path(tmp)
        # Sherlock 0.16+: txt is opt-in (--txt). There is no --no-txt flag.
        # --json loads a site list; it does not export results. Parse CSV.
        argv = [
            binary,
            username,
            "--csv",
            "--folderoutput",
            str(tmp_path),
            "--print-found",
            "--timeout",
            "10",
        ]
        try:
            code, out, err = await run_cmd(argv, timeout=timeout, cwd=str(tmp_path))
        except asyncio.TimeoutError:
            return ToolResult(tool="sherlock", status="error", message=f"timed out after {timeout}s")
        csv_path = _glob_first(tmp_path, [f"{username}.csv", "*.csv"])
        text = _read_text(csv_path) if csv_path else ""
        findings = parse_sherlock_csv(text, username) if text else []
        if not findings and code != 0 and not text:
            return _error("sherlock", err or out or f"exit {code}")
        status = _tool_status_from_findings(findings)
        found_n = sum(1 for f in findings if f.status == "found")
        blocked_n = sum(1 for f in findings if f.status == "blocked")
        msg = f"{found_n} profile(s) found"
        if blocked_n:
            msg += f", {blocked_n} blocked"
        return ToolResult(tool="sherlock", status=status, message=msg, findings=findings)


async def run_maigret(username: str, timeout: int | None = None, binary: str = "maigret") -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["maigret"]
    with tempfile.TemporaryDirectory(prefix="maigret-") as tmp:
        tmp_path = Path(tmp)
        argv = [
            binary,
            username,
            "--json",
            "simple",
            "-fo",
            str(tmp_path),
            "--top-sites",
            str(maigret_top_sites()),
            "--max-connections",
            str(maigret_max_connections()),
            "--timeout",
            "10",
        ]
        try:
            code, out, err = await run_cmd(argv, timeout=timeout, cwd=str(tmp_path))
        except asyncio.TimeoutError:
            return ToolResult(tool="maigret", status="error", message=f"timed out after {timeout}s")
        json_path = _glob_first(
            tmp_path,
            [f"{username}_simple.json", f"*{username}*simple*.json", "*simple*.json", "*.json"],
        )
        text = _read_text(json_path) if json_path else out
        findings = parse_maigret_json(text, username) if text.strip() else []
        if not findings and code != 0 and not (json_path and json_path.exists()):
            return _error("maigret", err or out or f"exit {code}")
        status = _tool_status_from_findings(findings)
        found_n = sum(1 for f in findings if f.status == "found")
        return ToolResult(
            tool="maigret",
            status=status,
            message=f"{found_n} profile(s) found",
            findings=findings,
        )


async def run_holehe(email: str, timeout: int | None = None, binary: str = "holehe") -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["holehe"]
    # holehe 1.61 has no --json flag. --only-used + --no-color + optional -C CSV.
    with tempfile.TemporaryDirectory(prefix="holehe-") as tmp:
        argv = [binary, email, "--only-used", "--no-color", "--no-clear", "-C", "-T", "10"]
        try:
            code, out, err = await run_cmd(argv, timeout=timeout, cwd=tmp)
        except asyncio.TimeoutError:
            return ToolResult(tool="holehe", status="error", message=f"timed out after {timeout}s")
        csv_path = _glob_first(Path(tmp), ["holehe_*.csv", "*.csv"])
        if csv_path:
            findings = parse_holehe_csv(_read_text(csv_path), email)
        else:
            findings = parse_holehe_output(out or err, email)
        if not findings and code != 0 and not (out or "").strip() and not csv_path:
            return _error("holehe", err or f"exit {code}")
    findings = _summarize_blocked(findings, source="holehe", input_type="email")
    status = _tool_status_from_findings(findings)
    found_n = sum(1 for f in findings if f.status == "found")
    blocked_n = sum(1 for f in findings if f.status == "blocked")
    msg = f"{found_n} service(s) registered"
    if blocked_n:
        msg += f", {blocked_n} rate-limited"
    return ToolResult(tool="holehe", status=status, message=msg, findings=findings)


async def run_h8mail(email: str, timeout: int | None = None, binary: str = "h8mail") -> ToolResult:
    key = os.environ.get("HIBP_API_KEY", "").strip()
    if not key:
        return _unavailable("h8mail", "HIBP_API_KEY is not set")
    timeout = timeout or TOOL_TIMEOUTS["h8mail"]
    with tempfile.TemporaryDirectory(prefix="h8mail-") as tmp:
        out_json = Path(tmp) / "out.json"
        argv = [binary, "-t", email, "-j", str(out_json), "-k", f"hibp:{key}"]
        try:
            code, out, err = await run_cmd(argv, timeout=timeout, cwd=tmp)
        except asyncio.TimeoutError:
            return ToolResult(tool="h8mail", status="error", message=f"timed out after {timeout}s")
        text = _read_text(out_json) if out_json.exists() else (out or err)
        findings = parse_h8mail_json(text, email) if text.strip() else []
        if not findings and code != 0:
            return _error("h8mail", err or out or f"exit {code}")
        status = _tool_status_from_findings(findings)
        return ToolResult(
            tool="h8mail",
            status=status,
            message="breach check complete" if findings else "no breach records",
            findings=findings,
        )


async def run_whois(domain: str, timeout: int | None = None, binary: str | None = "whois") -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["whois"]
    cli = binary if binary and shutil.which(binary) else _which_first(["whois"])
    if cli:
        argv = [cli, domain]
        try:
            code, out, err = await run_cmd(argv, timeout=timeout)
            text = out or err
            if text.strip():
                findings = parse_whois_text(text, domain)
                if findings:
                    return ToolResult(tool="whois", status="found", message="WHOIS record parsed", findings=findings)
                if re.search(r"no match|not found|no entries", text, re.I):
                    return ToolResult(tool="whois", status="not_found", message="no WHOIS match", findings=[])
        except asyncio.TimeoutError:
            logger.info("whois CLI timed out for %s, trying other backends", domain)
        except Exception as exc:  # noqa: BLE001
            logger.info("whois CLI failed for %s: %s", domain, exc)
    py_result = await run_whois_python(domain, timeout=min(timeout, 25))
    if py_result.status == "found":
        return py_result
    # Port 43 is often blocked from cloud hosts (including Render). RDAP is HTTP.
    rdap = await run_rdap(domain, timeout=min(timeout, 30))
    if rdap.status == "found":
        return rdap
    if py_result.status == "not_found" or rdap.status == "not_found":
        return ToolResult(tool="whois", status="not_found", message="no WHOIS/RDAP match", findings=[])
    # Prefer the RDAP error if python-whois only timed out on port 43.
    if rdap.status != "unavailable":
        return ToolResult(
            tool="whois",
            status=rdap.status if rdap.status != "error" else "error",
            message=rdap.message or py_result.message,
            findings=rdap.findings or py_result.findings,
        )
    return py_result


async def run_dnsrecon(domain: str, timeout: int | None = None, binary: str = "dnsrecon") -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["dnsrecon"]
    with tempfile.TemporaryDirectory(prefix="dnsrecon-") as tmp:
        out_json = Path(tmp) / "out.json"
        argv = [binary, "-d", domain, "-t", "std", "-j", str(out_json)]
        try:
            code, out, err = await run_cmd(argv, timeout=timeout, cwd=tmp)
        except asyncio.TimeoutError:
            return ToolResult(tool="dnsrecon", status="error", message=f"timed out after {timeout}s")
        text = _read_text(out_json) if out_json.exists() else out
        findings = parse_dnsrecon_json(text, domain) if text.strip() else []
        if not findings and code != 0:
            return _error("dnsrecon", err or out or f"exit {code}")
        status = _tool_status_from_findings(findings)
        return ToolResult(
            tool="dnsrecon",
            status=status,
            message=f"{len(findings)} record(s)",
            findings=findings,
        )


async def run_subfinder(domain: str, timeout: int | None = None, binary: str = "subfinder") -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["subfinder"]
    with tempfile.TemporaryDirectory(prefix="subfinder-") as tmp:
        out_jsonl = Path(tmp) / "out.jsonl"
        argv = [binary, "-d", domain, "-silent", "-oJ", "-o", str(out_jsonl)]
        try:
            code, out, err = await run_cmd(argv, timeout=timeout, cwd=tmp)
        except asyncio.TimeoutError:
            return ToolResult(tool="subfinder", status="error", message=f"timed out after {timeout}s")
        text = _read_text(out_jsonl) if out_jsonl.exists() else out
        findings = parse_subfinder_jsonl(text, domain) if text.strip() else []
        if not findings and code != 0:
            return _error("subfinder", err or out or f"exit {code}")
        status = _tool_status_from_findings(findings)
        return ToolResult(
            tool="subfinder",
            status=status,
            message=f"{len(findings)} subdomain(s)",
            findings=findings,
        )


async def run_theharvester(domain: str, timeout: int | None = None, binary: str = "theHarvester") -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["theharvester"]
    with tempfile.TemporaryDirectory(prefix="theharvester-") as tmp:
        out_base = Path(tmp) / "out"
        argv = [
            binary,
            "-d",
            domain,
            "-b",
            "crtsh,hackertarget,duckduckgo",
            "-l",
            "200",
            "-f",
            str(out_base),
        ]
        try:
            code, out, err = await run_cmd(argv, timeout=timeout, cwd=tmp)
        except asyncio.TimeoutError:
            return ToolResult(tool="theharvester", status="error", message=f"timed out after {timeout}s")
        json_path = _glob_first(Path(tmp), ["out.json", "*.json"])
        text = _read_text(json_path) if json_path else out
        findings = parse_theharvester_json(text, domain) if text.strip() else []
        if not findings and code != 0:
            return _error("theharvester", err or out or f"exit {code}")
        status = _tool_status_from_findings(findings)
        return ToolResult(
            tool="theharvester",
            status=status,
            message=f"{len(findings)} item(s)",
            findings=findings,
        )



# ---------------------------------------------------------------------------
# Pure-Python / HTTP domain adapters (no Kali binaries required)
# ---------------------------------------------------------------------------


def whois_record_to_text(record: Any, domain: str) -> str:
    """Flatten a python-whois result into WHOIS-like text for parse_whois_text."""
    lines = [f"Domain Name: {domain}"]

    def add(label: str, value: Any) -> None:
        if value is None or value == "":
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                add(label, item)
            return
        lines.append(f"{label}: {value}")

    def attr(*names: str) -> Any:
        if record is None:
            return None
        if isinstance(record, dict):
            for name in names:
                if record.get(name) not in (None, "", []):
                    return record.get(name)
            return None
        for name in names:
            if hasattr(record, name):
                val = getattr(record, name)
                if val not in (None, "", []):
                    return val
        return None

    add("Registrar", attr("registrar", "registrar_name"))
    add("Creation Date", attr("creation_date", "created"))
    add("Registry Expiry Date", attr("expiration_date", "expiry_date", "expires"))
    add("Registrant Organization", attr("org", "organization", "registrant_organization"))
    add("Registrant Name", attr("name", "registrant_name"))
    emails = attr("emails", "email")
    add("Registrant Email", emails)
    add("Name Server", attr("name_servers", "name_server", "nserver"))
    return "\n".join(lines)


def parse_python_whois(record: Any, domain: str) -> list[Finding]:
    return parse_whois_text(whois_record_to_text(record, domain), domain)


def parse_crtsh_json(text: str, domain: str, limit: int = 200) -> list[Finding]:
    """Parse crt.sh ``?output=json`` certificates into unique hostname findings."""
    findings: list[Finding] = []
    data = _extract_json_blob(text)
    if data is None:
        try:
            data = json.loads(strip_ansi(text))
        except json.JSONDecodeError:
            return findings
    if not isinstance(data, list):
        return findings

    domain_l = domain.lower().rstrip(".")
    seen: set[str] = set()
    names: list[tuple[str, str]] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        raw_names = []
        for key in ("name_value", "common_name"):
            val = row.get(key)
            if not val:
                continue
            raw_names.extend(str(val).split("\n"))
        for raw in raw_names:
            host = raw.strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if not host or host in seen:
                continue
            if host != domain_l and not host.endswith("." + domain_l):
                continue
            seen.add(host)
            names.append((host, str(row.get("issuer_name") or row.get("id") or "crt.sh")))
            if len(names) >= limit:
                break
        if len(names) >= limit:
            break

    for host, issuer in names:
        findings.append(
            Finding(
                source="crtsh",
                input_type="domain",
                value=host,
                url=f"https://{host}",
                status="found",
                confidence="high",
                raw=_truncate(f"source=crt.sh; issuer={issuer}"),
            )
        )
    return findings


def parse_dns_lookup_records(records: list[dict[str, str]], domain: str) -> list[Finding]:
    """Normalize dnspython records to the same shape as dnsrecon findings."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for rec in records:
        rtype = str(rec.get("type") or "record")
        name = str(rec.get("name") or domain)
        address = str(rec.get("address") or rec.get("value") or "")
        key = (rtype.upper(), name.lower(), address.lower())
        if key in seen:
            continue
        seen.add(key)
        value = f"{rtype} {name}"
        if address:
            value = f"{rtype} {name} → {address}"
        findings.append(
            Finding(
                source="dns_lookup",
                input_type="domain",
                value=value,
                url="",
                status="found",
                confidence="high",
                raw=_truncate(json.dumps(rec, ensure_ascii=False, default=str)),
            )
        )
    return findings


def _query_python_whois_sync(domain: str):
    import whois as python_whois  # type: ignore

    return python_whois.whois(domain)


async def run_whois_python(domain: str, timeout: int | None = None) -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["whois"]
    try:
        record = await asyncio.wait_for(
            asyncio.to_thread(_query_python_whois_sync, domain),
            timeout=timeout,
        )
    except TimeoutError:
        # In Python 3.11+ asyncio.TimeoutError is an alias of TimeoutError, so a
        # 10s socket timeout inside python-whois is also caught here.
        return ToolResult(
            tool="whois",
            status="error",
            message="WHOIS port 43 timed out (often blocked from cloud hosts); will try RDAP",
        )
    except ImportError:
        return _unavailable("whois", "python-whois is not installed and no whois binary was found")
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if re.search(r"no match|not found|no whois|unknown", msg, re.I):
            return ToolResult(tool="whois", status="not_found", message="no WHOIS match", findings=[])
        return _error("whois", msg)
    findings = parse_python_whois(record, domain)
    if not findings:
        return ToolResult(tool="whois", status="not_found", message="no WHOIS fields parsed", findings=[])
    return ToolResult(tool="whois", status="found", message="WHOIS record parsed (python-whois)", findings=findings)


async def run_dns_lookup(domain: str, timeout: int | None = None) -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["dns_lookup"]
    try:
        import dns.asyncresolver
        import dns.exception
        import dns.resolver
    except ImportError:
        return _unavailable("dns_lookup", "dnspython is not installed")

    resolver = dns.asyncresolver.Resolver()
    per = max(2.0, min(8.0, timeout / 6))
    resolver.lifetime = per
    types = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME")
    records: list[dict[str, str]] = []
    try:
        async def _one(rtype: str) -> None:
            try:
                answers = await resolver.resolve(domain, rtype)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                return
            except Exception as exc:  # noqa: BLE001
                logger.info("dns_lookup %s %s: %s", domain, rtype, exc)
                return
            for rr in answers:
                address = rr.to_text().strip()
                records.append({"type": rtype, "name": domain, "address": address})

        await asyncio.wait_for(asyncio.gather(*[_one(t) for t in types]), timeout=timeout)
    except asyncio.TimeoutError:
        if not records:
            return ToolResult(tool="dns_lookup", status="error", message=f"timed out after {timeout}s")
    findings = parse_dns_lookup_records(records, domain)
    status = _tool_status_from_findings(findings)
    return ToolResult(
        tool="dns_lookup",
        status=status,
        message=f"{len(findings)} record(s)",
        findings=findings,
    )


async def run_crtsh(domain: str, timeout: int | None = None) -> ToolResult:
    timeout = timeout or TOOL_TIMEOUTS["crtsh"]
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(
                url,
                params=params,
                headers={"User-Agent": "FootprintAudit/1.1 educational-self-audit"},
            )
    except ImportError:
        return _unavailable("crtsh", "httpx is not installed")
    except Exception as exc:  # noqa: BLE001
        return _error("crtsh", str(exc))
    if response.status_code == 429:
        return ToolResult(tool="crtsh", status="blocked", message="crt.sh rate-limited this request", findings=[])
    if response.status_code >= 400:
        return _error("crtsh", f"crt.sh returned HTTP {response.status_code}")
    content_type = (response.headers.get("content-type") or "").lower()
    body = response.text
    if "json" not in content_type and not body.lstrip().startswith("["):
        return ToolResult(
            tool="crtsh",
            status="blocked",
            message="crt.sh returned a non-JSON response (often a temporary block or challenge)",
            findings=[],
        )
    findings = parse_crtsh_json(body, domain)
    status = _tool_status_from_findings(findings)
    return ToolResult(
        tool="crtsh",
        status=status,
        message=f"{len(findings)} hostname(s) from certificate transparency",
        findings=findings,
    )



def parse_rdap_json(text: str, domain: str) -> list[Finding]:
    """Parse an RDAP domain object into the same finding shape as WHOIS."""
    try:
        data = json.loads(strip_ansi(text))
    except json.JSONDecodeError:
        data = _extract_json_blob(text)
    if not isinstance(data, dict):
        return []

    registrar = ""
    emails: list[str] = []
    org = ""
    registrant = ""
    for ent in data.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        vcard = ent.get("vcardArray") or []
        props = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        fn = ""
        org_name = ""
        for prop in props:
            if not isinstance(prop, list) or len(prop) < 4:
                continue
            name, _params, _typ, value = prop[0], prop[1], prop[2], prop[3]
            if name == "fn":
                fn = str(value)
            elif name == "org":
                org_name = value[0] if isinstance(value, list) and value else str(value)
            elif name == "email":
                emails.append(str(value))
        if "registrar" in roles and (fn or org_name):
            registrar = fn or org_name
        if "registrant" in roles:
            registrant = fn or org_name or registrant
            org = org_name or org
        # Nested entities (registrar often wraps a vcard-less org)
        for child in ent.get("entities") or []:
            if not isinstance(child, dict):
                continue
            cv = child.get("vcardArray") or []
            cprops = cv[1] if isinstance(cv, list) and len(cv) > 1 else []
            for prop in cprops:
                if not isinstance(prop, list) or len(prop) < 4:
                    continue
                if prop[0] == "email":
                    emails.append(str(prop[3]))

    created = expires = ""
    for ev in data.get("events") or []:
        if not isinstance(ev, dict):
            continue
        action = str(ev.get("eventAction") or "").lower()
        date = ev.get("eventDate") or ""
        if "registration" in action and not created:
            created = date
        if "expiration" in action:
            expires = date

    nameservers = []
    for ns in data.get("nameservers") or []:
        if isinstance(ns, dict) and ns.get("ldhName"):
            nameservers.append(str(ns["ldhName"]))
        elif isinstance(ns, str):
            nameservers.append(ns)

    lines = [f"Domain Name: {data.get('ldhName') or domain}"]
    if registrar:
        lines.append(f"Registrar: {registrar}")
    if created:
        lines.append(f"Creation Date: {created}")
    if expires:
        lines.append(f"Registry Expiry Date: {expires}")
    if org:
        lines.append(f"Registrant Organization: {org}")
    if registrant:
        lines.append(f"Registrant Name: {registrant}")
    for addr in emails:
        lines.append(f"Registrant Email: {addr}")
    for ns in nameservers:
        lines.append(f"Name Server: {ns}")
    findings = parse_whois_text("\n".join(lines), domain)
    # Tag source as whois so scoring rules still apply, but note RDAP in raw.
    for f in findings:
        if "rdap" not in (f.raw or "").lower():
            f.raw = _truncate((f.raw + "; via=rdap").strip("; "))
    return findings


async def run_rdap(domain: str, timeout: int | None = None) -> ToolResult:
    timeout = timeout or 30
    urls = [
        f"https://rdap.org/domain/{domain}",
        f"https://rdap.verisign.com/com/v1/domain/{domain}",
    ]
    last_error = ""
    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": "FootprintAudit/1.1 educational-self-audit", "Accept": "application/rdap+json, application/json"},
                )
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            continue
        if response.status_code == 404:
            return ToolResult(tool="whois", status="not_found", message="no RDAP match", findings=[])
        if response.status_code == 429:
            last_error = "RDAP rate-limited"
            continue
        if response.status_code >= 400:
            last_error = f"RDAP HTTP {response.status_code}"
            continue
        findings = parse_rdap_json(response.text, domain)
        if findings:
            return ToolResult(tool="whois", status="found", message="WHOIS record parsed (RDAP)", findings=findings)
        last_error = "RDAP response had no parseable fields"
    if last_error:
        return _error("whois", last_error)
    return _unavailable("whois", "RDAP lookup failed")


RUNNERS: dict[str, Callable[..., Any]] = {
    "sherlock": run_sherlock,
    "maigret": run_maigret,
    "holehe": run_holehe,
    "h8mail": run_h8mail,
    "whois": run_whois,
    "dns_lookup": run_dns_lookup,
    "crtsh": run_crtsh,
    "dnsrecon": run_dnsrecon,
    "subfinder": run_subfinder,
    "theharvester": run_theharvester,
}


def select_tools(inputs: dict[str, str], available: dict[str, dict[str, Any]] | None = None) -> list[str]:
    """Return the tools that should run for the given inputs, in a stable order."""
    available = available if available is not None else detect_tools()
    chosen: list[str] = []
    if inputs.get("username"):
        chosen.extend(["maigret", "sherlock"])
    if inputs.get("email"):
        chosen.extend(["holehe", "h8mail"])
    if inputs.get("domain"):
        chosen.extend(["whois", "dns_lookup", "crtsh", "dnsrecon", "subfinder", "theharvester"])
    return chosen


async def run_tool(
    name: str,
    inputs: dict[str, str],
    available: dict[str, dict[str, Any]] | None = None,
) -> ToolResult:
    available = available if available is not None else detect_tools()
    info = available.get(name) or {}
    if not info.get("available"):
        reason = info.get("reason") or "tool is not available"
        return _unavailable(name, reason)
    binary = info.get("path") or name
    timeout = int(info.get("timeout") or TOOL_TIMEOUTS.get(name, 150))
    loop = asyncio.get_event_loop()
    started = loop.time()
    try:
        if name == "sherlock":
            result = await run_sherlock(inputs["username"], timeout=timeout, binary=binary)
        elif name == "maigret":
            result = await run_maigret(inputs["username"], timeout=timeout, binary=binary)
        elif name == "holehe":
            result = await run_holehe(inputs["email"], timeout=timeout, binary=binary)
        elif name == "h8mail":
            result = await run_h8mail(inputs["email"], timeout=timeout, binary=binary)
        elif name == "whois":
            result = await run_whois(inputs["domain"], timeout=timeout, binary=binary)
        elif name == "dns_lookup":
            result = await run_dns_lookup(inputs["domain"], timeout=timeout)
        elif name == "crtsh":
            result = await run_crtsh(inputs["domain"], timeout=timeout)
        elif name == "dnsrecon":
            result = await run_dnsrecon(inputs["domain"], timeout=timeout, binary=binary)
        elif name == "subfinder":
            result = await run_subfinder(inputs["domain"], timeout=timeout, binary=binary)
        elif name == "theharvester":
            result = await run_theharvester(inputs["domain"], timeout=timeout, binary=binary)
        else:
            result = _error(name, f"unknown tool {name}")
    except asyncio.TimeoutError:
        result = ToolResult(tool=name, status="error", message=f"timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001
        logger.exception("Tool %s failed", name)
        result = _error(name, str(exc))
    result.elapsed_s = round(loop.time() - started, 2)
    return result


# Fake adapters used by automated tests (USE_FAKE_TOOLS=1). Never used in class demos
# unless that environment variable is set — the UI demo button loads cached sample
# data instead, so the viva does not depend on this path.
async def run_fake_tool(name: str, inputs: dict[str, str], **_: Any) -> ToolResult:
    username = inputs.get("username") or "test_user_demo"
    email = inputs.get("email") or "demo@example.com"
    domain = inputs.get("domain") or "example.com"
    catalog: dict[str, ToolResult] = {
        "sherlock": ToolResult(
            tool="sherlock",
            status="found",
            message="2 profile(s) found (fake adapter)",
            findings=[
                Finding("sherlock", "username", "GitHub", f"https://github.com/{username}", "found", "high", "exists=Claimed"),
                Finding("sherlock", "username", "Reddit", f"https://reddit.com/user/{username}", "found", "high", "exists=Claimed"),
            ],
        ),
        "maigret": ToolResult(
            tool="maigret",
            status="found",
            message="1 profile(s) found (fake adapter)",
            findings=[
                Finding("maigret", "username", "GitHub", f"https://github.com/{username}", "found", "high", '{"status":"Claimed"}'),
            ],
        ),
        "holehe": ToolResult(
            tool="holehe",
            status="found",
            message="1 service(s) registered (fake adapter)",
            findings=[
                Finding("holehe", "email", "github", "https://github.com", "found", "medium", "exists=true"),
            ],
        ),
        "h8mail": ToolResult(
            tool="h8mail",
            status="not_found",
            message="no breach records (fake adapter)",
            findings=[
                Finding("h8mail", "email", "No breach records returned", hibp_link(email), "not_found", "medium", "pwn_num=0"),
            ],
        ),
        "whois": ToolResult(
            tool="whois",
            status="found",
            message="WHOIS record parsed (fake adapter)",
            findings=[
                Finding("whois", "domain", "RESERVED-Internet Assigned Numbers Authority", "", "found", "high", f"domain={domain}; registrar=RESERVED"),
            ],
        ),
        "dnsrecon": ToolResult(
            tool="dnsrecon",
            status="found",
            message="1 record(s) (fake adapter)",
            findings=[
                Finding("dnsrecon", "domain", f"A {domain} → 93.184.216.34", "", "found", "high", '{"type":"A"}'),
            ],
        ),
        "subfinder": ToolResult(
            tool="subfinder",
            status="found",
            message="1 subdomain(s) (fake adapter)",
            findings=[
                Finding("subfinder", "domain", f"www.{domain}", f"https://www.{domain}", "found", "high", "source=fake"),
            ],
        ),
        "theharvester": ToolResult(
            tool="theharvester",
            status="not_found",
            message="0 item(s) (fake adapter)",
            findings=[],
        ),
        "dns_lookup": ToolResult(
            tool="dns_lookup",
            status="found",
            message="1 record(s) (fake adapter)",
            findings=[
                Finding("dns_lookup", "domain", f"A {domain} → 93.184.216.34", "", "found", "high", '{"type":"A"}'),
            ],
        ),
        "crtsh": ToolResult(
            tool="crtsh",
            status="found",
            message="1 hostname(s) from certificate transparency (fake adapter)",
            findings=[
                Finding("crtsh", "domain", f"www.{domain}", f"https://www.{domain}", "found", "high", "source=crt.sh"),
            ],
        ),
    }
    result = catalog.get(name) or _error(name, "no fake adapter")
    result.elapsed_s = 0.01
    return result


def use_fake_tools() -> bool:
    return os.environ.get("USE_FAKE_TOOLS", "").strip() in {"1", "true", "yes"}
