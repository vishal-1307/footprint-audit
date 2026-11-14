"""Transparent 0–100 exposure score, remediation checklist, and confidence notes.

Every point added to the score maps to a named rule so a viva examiner can
see exactly why a result is "moderate" or "high". The score is a teaching
device, not a scientific risk model.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

SENSITIVE_USERNAME_PLATFORMS = {
    "github",
    "gitlab",
    "bitbucket",
    "linkedin",
    "instagram",
    "facebook",
    "reddit",
    "tiktok",
    "twitter",
    "x",
    "youtube",
    "steam",
    "discord",
    "telegram",
    "snapchat",
    "pinterest",
    "wordpress",
    "dev.to",
    "devto",
}

SENSITIVE_EMAIL_SERVICES = {
    "paypal",
    "venmo",
    "bank",
    "adobe",
    "apple",
    "google",
    "microsoft",
    "icloud",
    "tinder",
    "bumble",
    "okcupid",
    "match",
    "hinge",
    "linkedin",
    "github",
    "instagram",
    "facebook",
    "twitter",
    "x",
    "amazon",
    "ebay",
}


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def _site_name(finding: dict) -> str:
    raw = " ".join(
        [
            _norm(finding.get("value")),
            _norm(finding.get("source")),
            _norm(finding.get("url")),
            _norm(finding.get("raw")),
        ]
    )
    host = ""
    url = finding.get("url") or ""
    try:
        host = urlparse(url).netloc.lower().removeprefix("www.")
    except Exception:
        host = ""
    return f"{raw} {host}"


def _is_found(finding: dict) -> bool:
    return _norm(finding.get("status")) == "found"



def _profile_key(finding: dict) -> str:
    url = _norm(finding.get("url")).rstrip("/")
    if url:
        return url
    return _norm(finding.get("value"))


def _unique_findings(items: list[dict]) -> list[dict]:
    """Dedupe username hits so Sherlock + Maigret overlap is not double-counted."""
    seen: dict[str, dict] = {}
    for item in items:
        key = _profile_key(item)
        if key not in seen:
            seen[key] = item
    return list(seen.values())


def score_label(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Moderate"
    return "Low"


def compute_score(findings: list[dict], tools: dict | None = None) -> tuple[int, list[dict]]:
    """Return (score, breakdown) using documented, capped rules."""
    tools = tools or {}
    breakdown: list[dict] = []
    total = 0

    def add(rule: str, points: int, detail: str) -> None:
        nonlocal total
        if points <= 0:
            return
        total += points
        breakdown.append({"rule": rule, "points": points, "detail": detail})

    found = [f for f in findings if _is_found(f)]
    username_hits = _unique_findings([f for f in found if f.get("input_type") == "username"])
    email_hits = [f for f in found if f.get("input_type") == "email"]
    domain_hits = [f for f in found if f.get("input_type") == "domain"]

    # --- Username rules ---
    profile_points = min(20, 2 * len(username_hits))
    add(
        "username_profiles_found",
        profile_points,
        f"{len(username_hits)} unique public profile(s) found for the username (+2 each, cap 20).",
    )
    if len(username_hits) >= 5:
        add(
            "username_high_reuse",
            15,
            "The same handle was found on 5 or more sites (likely identity reuse).",
        )

    sensitive_user = []
    for f in username_hits:
        blob = _site_name(f)
        for plat in SENSITIVE_USERNAME_PLATFORMS:
            if plat in blob:
                sensitive_user.append(plat)
                break
    sensitive_user = sorted(set(sensitive_user))
    add(
        "sensitive_platforms",
        min(15, 3 * len(sensitive_user)),
        (
            "Handle found on sensitive or high-visibility platforms: "
            + ", ".join(sensitive_user)
            + " (+3 each, cap 15)."
        )
        if sensitive_user
        else "No sensitive-platform username hits.",
    )

    # --- Email rules ---
    registrations = [
        f
        for f in email_hits
        if _norm(f.get("source")) in {"holehe", "h8mail"}
        or "registered" in _norm(f.get("raw"))
        or _norm(f.get("source")) == "holehe"
    ]
    # All holehe found items count as registrations; h8mail breaches are separate.
    holehe_regs = [f for f in email_hits if _norm(f.get("source")) == "holehe"]
    add(
        "email_registrations",
        min(18, 3 * len(holehe_regs)),
        f"Email appears registered on {len(holehe_regs)} service(s) (+3 each, cap 18).",
    )

    sensitive_email = []
    for f in holehe_regs:
        blob = _site_name(f)
        for svc in SENSITIVE_EMAIL_SERVICES:
            if svc in blob:
                sensitive_email.append(svc)
                break
    if sensitive_email:
        add(
            "email_sensitive_services",
            8,
            "Email is tied to at least one sensitive category (identity, finance, or major recovery account): "
            + ", ".join(sorted(set(sensitive_email)))
            + ".",
        )

    breaches = [
        f
        for f in email_hits
        if _norm(f.get("source")) == "h8mail"
        and (
            "breach" in _norm(f.get("raw"))
            or "pwn" in _norm(f.get("raw"))
            or "hibp" in _norm(f.get("value"))
            or _is_found(f)
        )
    ]
    # Only count h8mail findings that represent a confirmed breach, not a "no results" row.
    confirmed = []
    for f in email_hits:
        if _norm(f.get("source")) != "h8mail":
            continue
        blob = _norm(f.get("raw")) + " " + _norm(f.get("value"))
        if any(k in blob for k in ("breach", "pwn", "leaked", "compromised")) or (
            _is_found(f) and "no breach" not in blob and "not found" not in blob
        ):
            # A found h8mail row is treated as a breach record unless clearly negative.
            if "0 pwn" in blob or "pwn_num\": 0" in blob or "pwn_num: 0" in blob:
                continue
            confirmed.append(f)
    if confirmed:
        add(
            "breach_confirmed",
            25,
            "A confirmed breach record was returned for this email (HIBP/h8mail). "
            "Change reused passwords and enable 2FA.",
        )

    # --- Domain rules ---
    whois_hits = [f for f in domain_hits if _norm(f.get("source")) == "whois"]
    whois_email = [
        f
        for f in whois_hits
        if "whois_email" in _norm(f.get("raw")) or "contact email" in _norm(f.get("value")) or (
            "@" in (f.get("value") or "") and "redact" not in _norm(f.get("value")) and "privacy" not in _norm(f.get("raw"))
        )
    ]
    if any("whois_email" in _norm(f.get("raw")) or (
        "@" in (f.get("value") or "") and "privacy" not in _norm(f.get("raw")) and "redact" not in _norm(f.get("raw") + f.get("value", ""))
    ) for f in whois_hits):
        add(
            "whois_public_email",
            12,
            "WHOIS record exposes a public contact email that does not look privacy-redacted.",
        )
    if any("whois_registrant" in _norm(f.get("raw")) for f in whois_hits):
        add(
            "whois_public_org",
            5,
            "WHOIS exposes a registrant or organization name (not clearly redacted).",
        )

    sub_raw = [f for f in domain_hits if _norm(f.get("source")) in {"subfinder", "crtsh"}]
    seen_hosts: set[str] = set()
    subdomains = []
    for f in sub_raw:
        host = _norm(f.get("value") or f.get("url"))
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            subdomains.append(f)
    if len(subdomains) >= 5:
        add(
            "subdomain_exposure",
            8,
            f"{len(subdomains)} public subdomains were discovered via crt.sh and/or subfinder (5+ raises exposure).",
        )

    harvested_emails = [
        f
        for f in domain_hits
        if _norm(f.get("source")) == "theharvester" and "@" in (f.get("value") or "")
    ]
    add(
        "harvested_emails",
        min(16, 4 * len(harvested_emails)),
        f"{len(harvested_emails)} email address(es) harvested from public sources for the domain (+4 each, cap 16).",
    )
    harvested_people = [
        f
        for f in domain_hits
        if _norm(f.get("source")) == "theharvester"
        and "person" in _norm(f.get("raw"))
    ]
    add(
        "harvested_people",
        min(9, 3 * len(harvested_people)),
        f"{len(harvested_people)} people name(s) found in public domain sources (+3 each, cap 9).",
    )

    score = max(0, min(100, total))
    return score, breakdown


def remediation_items(findings: list[dict], score: int, breakdown: list[dict], inputs: dict | None = None) -> list[dict]:
    """Build a checklist that follows from the actual findings."""
    inputs = inputs or {}
    found = [f for f in findings if _is_found(f)]
    rules = {b["rule"] for b in breakdown if b.get("points", 0) > 0}
    items: list[dict] = []

    def add(priority: str, title: str, detail: str) -> None:
        items.append({"priority": priority, "title": title, "detail": detail})

    username_hits = [f for f in found if f.get("input_type") == "username"]
    holehe = [f for f in found if _norm(f.get("source")) == "holehe"]

    if username_hits:
        sites = sorted({(f.get("value") or f.get("url") or "a site") for f in username_hits})
        preview = ", ".join(sites[:8])
        if len(sites) > 8:
            preview += f", +{len(sites) - 8} more"
        add(
            "high",
            "Review privacy settings on accounts that use this handle",
            "Public profiles were found. Tighten privacy, remove unused accounts, and limit what bios and photos show. Sites: "
            + preview
            + ".",
        )
    if "username_high_reuse" in rules:
        add(
            "high",
            "Stop reusing the same username everywhere",
            "A unique handle on banking, email recovery, and school or work accounts makes you harder to correlate across the public internet.",
        )
    if holehe:
        names = sorted({f.get("value") or "a service" for f in holehe})
        add(
            "high",
            "Close or secure forgotten accounts tied to this email",
            "Registration checks suggest this address is on: "
            + ", ".join(names[:12])
            + (f", +{len(names) - 12} more" if len(names) > 12 else "")
            + ". Disable accounts you no longer use.",
        )
        add(
            "medium",
            "Use email aliases for new sign-ups",
            "Plus-addressing (you+site@gmail.com) or a secondary alias limits how easily one leaked email maps to every service you use.",
        )
    if inputs.get("email"):
        add(
            "medium",
            "Check Have I Been Pwned manually if no API key was configured",
            "Visit https://haveibeenpwned.com/ and search your own email. The free public API is not used here without a paid HIBP key.",
        )
    if "breach_confirmed" in rules:
        add(
            "critical",
            "Treat this email as breached",
            "Change the password on every account that shared it, do not reuse that password, and turn on two-factor authentication.",
        )
    if holehe or username_hits:
        add(
            "high",
            "Turn on two-factor authentication",
            "2FA on email, GitHub, Google, Apple, and banking accounts reduces the damage if a password or recovery flow is abused.",
        )
    if "whois_public_email" in rules or "whois_public_org" in rules:
        add(
            "high",
            "Enable WHOIS privacy / redaction on the domain",
            "Registrar privacy or GDPR redaction stops a personal email or name from appearing in public WHOIS.",
        )
    if "subdomain_exposure" in rules:
        add(
            "medium",
            "Review public subdomains you no longer need",
            "Old staging, mail, or dev hosts advertised in public DNS enlarge your attack surface. Remove unused records.",
        )
    if "harvested_emails" in rules or "harvested_people" in rules:
        add(
            "medium",
            "Reduce emails and staff names on public pages",
            "Addresses and names published on websites, certificates, or directories are routinely harvested. Use role inboxes and contact forms where you can.",
        )
    add(
        "medium",
        "Use a search-engine opt-out where it applies",
        "Google's 'Results about you' and similar tools can request removal of some personal results. This is not guaranteed and does not hide public profiles you still publish.",
    )
    add(
        "low",
        "Strip EXIF / GPS from photos before you upload them",
        "Messaging apps often strip metadata, but files shared from a camera or cloud folder may still contain GPS or device information.",
    )
    if score < 25 and not found:
        add(
            "low",
            "A low score can also mean tools were blocked",
            "If scanners were rate-limited, a small footprint is not proven. Re-run later from your own network and review accounts you already know about.",
        )
    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items.sort(key=lambda x: priority_rank.get(x["priority"], 9))
    return items


def confidence_notes(findings: list[dict], inputs: dict | None = None, tools: dict | None = None) -> list[str]:
    """Human-readable caveats an examiner will look for."""
    inputs = inputs or {}
    tools = tools or {}
    notes: list[str] = []
    found = [f for f in findings if _is_found(f)]
    username_hits = _unique_findings([f for f in found if f.get("input_type") == "username"])
    blocked = [f for f in findings if _norm(f.get("status")) == "blocked"]
    tool_blocked = [
        name
        for name, info in tools.items()
        if _norm((info or {}).get("status")) in {"blocked", "timeout"}
    ]

    if len(username_hits) >= 2:
        notes.append(
            f"The same handle appears on {len(username_hits)} sites. This is likely the same person, "
            "but usernames can be coincidentally reused — this is not a verified identity match."
        )
    elif len(username_hits) == 1:
        notes.append(
            "A single username hit is weak evidence. Many sites allow the same handle for different people, "
            "and some checkers have soft-404 false positives."
        )

    sherlock_sites = {(_norm(f.get("value")), _norm(f.get("url"))) for f in username_hits if _norm(f.get("source")) == "sherlock"}
    maigret_sites = {(_norm(f.get("value")), _norm(f.get("url"))) for f in username_hits if _norm(f.get("source")) == "maigret"}
    if sherlock_sites and maigret_sites:
        notes.append(
            "Sherlock and Maigret both ran. Treat overlapping sites as stronger evidence than a hit reported by only one tool; "
            "each tool has different site lists and false-positive rates."
        )

    if any(_norm(f.get("source")) == "holehe" for f in found):
        notes.append(
            "Email registration checks infer that an account exists from public signup or recovery responses. "
            "They do not log in, read a mailbox, or prove who owns the account."
        )

    if blocked or tool_blocked:
        notes.append(
            "Some sites blocked or rate-limited the scanners (common for Instagram, Facebook, and TikTok). "
            "Absence of a result is not proof that an account does not exist."
        )

    if inputs.get("name") or inputs.get("city"):
        name = inputs.get("name") or "the given name"
        city = inputs.get("city")
        extra = f" / city {city}" if city else ""
        notes.append(
            f"The optional name '{name}'{extra} was used only as a display filter note, not as a search query. "
            "A common name is not evidence of a match. Discard hits that clearly belong to someone else."
        )

    if not found:
        notes.append(
            "No public hits were parsed. This may mean a small footprint, a typo in the identifier, "
            "or tools that failed or were blocked. Check the per-tool status before drawing conclusions."
        )

    notes.append(
        "Instagram, Facebook, and other login-walled platforms cannot be scraped reliably without an account. "
        "This platform only uses public, unauthenticated sources and will not attempt to bypass controls."
    )
    return notes


def evaluate(findings: list[dict], inputs: dict | None = None, tools: dict | None = None) -> dict[str, Any]:
    score, breakdown = compute_score(findings, tools)
    return {
        "score": score,
        "score_label": score_label(score),
        "score_breakdown": breakdown,
        "remediation": remediation_items(findings, score, breakdown, inputs),
        "confidence_notes": confidence_notes(findings, inputs, tools),
    }
