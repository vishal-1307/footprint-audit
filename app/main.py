"""FastAPI entry point for the Digital Footprint Self-Audit Platform.

Cloud-hostable dashboard (Render / Docker). Bind 0.0.0.0 and honour $PORT.
POST /api/scan returns a job id; GET /api/jobs/{id} is polled for live per-tool
progress. Pages and APIs require a session except /login and /health.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from . import adapters, ai, auth, db, report, scoring

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("footprint")

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
DATA = ROOT / "data"
DEMO_PATH = DATA / "demo_result.json"

RATE_LIMIT = 5  # live scans per rolling hour
SEMAPHORE_LIMIT = int(os.environ.get("SCAN_CONCURRENCY", "2") or "2")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{0,79}$")

CONSENT_TEXT = (
    "I confirm that I am searching only my own identifiers, or identifiers of a "
    "person who has given informed consent. I understand this tool queries public "
    "sources only, must not be used to stalk, harass, or profile someone without "
    "consent, and that results can be incomplete or wrong."
)

_tool_cache: dict[str, dict[str, Any]] = {}
_jobs_in_flight: set[str] = set()


class ScanRequest(BaseModel):
    username: str | None = Field(default=None, max_length=64)
    email: str | None = Field(default=None, max_length=120)
    domain: str | None = Field(default=None, max_length=120)
    name: str | None = Field(default=None, max_length=80)
    city: str | None = Field(default=None, max_length=80)
    consent: bool = False


def _clean(value: str | None) -> str:
    return (value or "").strip()


def validate_inputs(payload: ScanRequest) -> dict[str, str]:
    username = _clean(payload.username)
    email = _clean(payload.email)
    domain = _clean(payload.domain).lower().rstrip(".")
    name = _clean(payload.name)
    city = _clean(payload.city)

    if not payload.consent:
        raise HTTPException(
            status_code=400,
            detail="Consent is required. Search only yourself or someone who has given consent.",
        )
    if not (username or email or domain):
        raise HTTPException(
            status_code=400,
            detail="Provide at least one of: username, email, or domain.",
        )
    if username and not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username may contain letters, digits, dots, underscores and hyphens only (max 64).",
        )
    if email and not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="That email address does not look valid.")
    if domain:
        if domain.startswith("http://") or domain.startswith("https://"):
            raise HTTPException(status_code=400, detail="Enter a domain like example.com, not a URL.")
        if not DOMAIN_RE.match(domain):
            raise HTTPException(status_code=400, detail="That domain does not look valid.")
    if name and not NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail="Name is a display filter only and may contain letters, spaces, and basic punctuation.",
        )
    if city and not NAME_RE.match(city):
        raise HTTPException(
            status_code=400,
            detail="City is a display filter only and may contain letters, spaces, and basic punctuation.",
        )
    inputs = {
        "username": username,
        "email": email,
        "domain": domain,
        "name": name,
        "city": city,
    }
    return {k: v for k, v in inputs.items() if v}


def input_types_of(inputs: dict[str, str]) -> list[str]:
    return [k for k in ("username", "email", "domain") if inputs.get(k)]


def filter_note(inputs: dict[str, str]) -> str | None:
    if not (inputs.get("name") or inputs.get("city")):
        return None
    bits = [b for b in (inputs.get("name"), inputs.get("city")) if b]
    return (
        "Filter note: results are unfiltered raw hits for the identifiers you entered. "
        "Name/city (" + " / ".join(bits) + ") were NOT searched. Use them only to mentally "
        "discard obvious mismatches — a common name is not a match."
    )


def job_public_view(job: dict[str, Any]) -> dict[str, Any]:
    """Shape the DB row for the frontend / PDF consumers."""
    tools = job.get("tools") or {}
    progress = job.get("progress") or {}
    # Merge progress into a single tools map the UI can render.
    merged = {}
    names = list(dict.fromkeys(list(tools.keys()) + list(progress.keys())))
    for name in names:
        merged[name] = {**(tools.get(name) or {}), **(progress.get(name) or {})}
    view = {
        "id": job["id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "is_demo": bool(job.get("is_demo")),
        "demo_disclaimer": (
            "SAMPLE DATA — fictional person, not a real audit."
            if job.get("is_demo")
            else None
        ),
        "inputs": job.get("inputs") or {},
        "consent": bool(job.get("consent")),
        "consent_text": CONSENT_TEXT,
        "tools": merged,
        "progress": progress,
        "findings": job.get("findings") or [],
        "score": job.get("score"),
        "score_label": scoring.score_label(job["score"]) if job.get("score") is not None else None,
        "score_breakdown": job.get("score_breakdown") or [],
        "remediation": job.get("remediation") or [],
        "confidence_notes": job.get("confidence_notes") or [],
        "ai_summary": job.get("ai_summary") or "",
        "ai_status": job.get("ai_status") or "",
        "error": job.get("error"),
        "hibp_link": adapters.hibp_link((job.get("inputs") or {}).get("email")),
        "filter_note": filter_note(job.get("inputs") or {}),
        "demo_mode_env": os.environ.get("DEMO", "").strip() in {"1", "true", "yes"},
    }
    return view


def load_demo_template() -> dict[str, Any]:
    if not DEMO_PATH.exists():
        raise HTTPException(status_code=500, detail="Bundled demo result is missing (data/demo_result.json).")
    return json.loads(DEMO_PATH.read_text(encoding="utf-8"))


def persist_demo_job() -> dict[str, Any]:
    template = load_demo_template()
    job_id = "demo-" + uuid.uuid4().hex[:8]
    inputs = template.get("inputs") or {}
    tools = template.get("tools") or {}
    db.create_job(job_id, inputs, consent=True, is_demo=True, status="complete")
    evaluated = {
        "score": template.get("score"),
        "score_breakdown": template.get("score_breakdown"),
        "remediation": template.get("remediation"),
        "confidence_notes": template.get("confidence_notes"),
    }
    # Recompute score from findings so the demo stays consistent with current rules,
    # but keep the bundled narrative and allow the file to override if present.
    findings = template.get("findings") or []
    computed = scoring.evaluate(findings, inputs, tools)
    db.update_job(
        job_id,
        status="complete",
        tools=tools,
        progress={
            name: {"status": (info or {}).get("status"), "message": (info or {}).get("message")}
            for name, info in tools.items()
        },
        findings=findings,
        score=computed["score"],
        score_breakdown=computed["score_breakdown"],
        remediation=computed["remediation"],
        confidence_notes=computed["confidence_notes"],
        ai_summary=template.get("ai_summary") or "",
        ai_status=template.get("ai_status") or "skipped_no_key",
        is_demo=True,
    )
    # evaluated kept so a stale template still works if compute changes
    _ = evaluated
    db.add_audit_entry(
        job_id,
        input_types_of(inputs),
        consent=True,
        tools_run=list(tools.keys()),
        is_demo=True,
    )
    job = db.get_job(job_id)
    assert job is not None
    return job


async def execute_job(job_id: str, inputs: dict[str, str]) -> None:
    available = _tool_cache or adapters.detect_tools()
    planned = adapters.select_tools(inputs, available)
    fake = adapters.use_fake_tools()
    progress = {
        name: {
            "status": "queued"
            if fake or (available.get(name) or {}).get("available")
            else "unavailable",
            "message": (
                "waiting (fake adapter)"
                if fake
                else ((available.get(name) or {}).get("reason") or "waiting")
            ),
        }
        for name in planned
    }
    db.update_job(job_id, status="running", tools=progress, progress=progress)

    sem = asyncio.Semaphore(max(1, min(SEMAPHORE_LIMIT, 4)))
    findings: list[dict[str, Any]] = []
    findings_lock = asyncio.Lock()
    heavy_lock = asyncio.Lock()

    async def run_one(name: str) -> None:
        info = available.get(name) or {}
        # USE_FAKE_TOOLS is for automated tests: run canned adapters even if
        # the real binaries are not installed on this machine.
        if adapters.use_fake_tools():
            progress[name] = {"status": "running", "message": "running"}
            db.update_job(job_id, progress=progress, tools=progress)
            result = await adapters.run_fake_tool(name, inputs)
            progress[name] = {
                "status": result.status,
                "message": result.message,
                "elapsed_s": result.elapsed_s,
            }
            async with findings_lock:
                findings.extend(f.to_dict() for f in result.findings)
                db.update_job(job_id, progress=progress, tools=progress, findings=list(findings))
            return
        if not info.get("available"):
            progress[name] = {
                "status": "unavailable",
                "message": info.get("reason") or "unavailable",
            }
            db.update_job(job_id, progress=progress, tools=progress)
            return
        progress[name] = {"status": "running", "message": "running"}
        db.update_job(job_id, progress=progress, tools=progress)
        result = await adapters.run_tool(name, inputs, available)
        progress[name] = {
            "status": result.status,
            "message": result.message,
            "elapsed_s": result.elapsed_s,
        }
        async with findings_lock:
            findings.extend(f.to_dict() for f in result.findings)
            db.update_job(job_id, progress=progress, tools=progress, findings=list(findings))

    try:
        await asyncio.gather(
            *(asyncio.create_task(_guard(sem, heavy_lock, run_one, name)) for name in planned)
        )
        computed = scoring.evaluate(findings, inputs, progress)
        job_so_far = {
            "inputs": inputs,
            "findings": findings,
            "tools": progress,
            "progress": progress,
            "score": computed["score"],
            "score_label": computed["score_label"],
            "score_breakdown": computed["score_breakdown"],
            "remediation": computed["remediation"],
            "confidence_notes": computed["confidence_notes"],
            "is_demo": False,
        }
        ai_result = await ai.summarize_findings_async(job_so_far)
        db.update_job(
            job_id,
            status="complete",
            progress=progress,
            tools=progress,
            findings=findings,
            score=computed["score"],
            score_breakdown=computed["score_breakdown"],
            remediation=computed["remediation"],
            confidence_notes=computed["confidence_notes"],
            ai_summary=ai_result.get("summary") or "",
            ai_status=ai_result.get("status") or "skipped_error",
        )
        db.add_audit_entry(
            job_id,
            input_types_of(inputs),
            consent=True,
            tools_run=planned,
            is_demo=False,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Job %s failed", job_id)
        db.update_job(job_id, status="error", error=str(exc), progress=progress, tools=progress, findings=findings)
    finally:
        _jobs_in_flight.discard(job_id)


async def _guard(sem: asyncio.Semaphore, heavy_lock: asyncio.Lock, fn, name: str) -> None:
    # Maigret and Sherlock are the two memory-heavy CLIs; never overlap them
    # on a 512 MB Render instance. Light tools can still use the other slot.
    if name in adapters.HEAVY_TOOLS:
        async with heavy_lock:
            async with sem:
                await fn(name)
    else:
        async with sem:
            await fn(name)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if auth.is_production() and not auth.app_password():
        raise RuntimeError("APP_PASSWORD must be set when running on Render / production.")
    if auth.is_production() and not os.environ.get("SECRET_KEY", "").strip():
        raise RuntimeError("SECRET_KEY must be set when running on Render / production.")
    if not auth.auth_enabled():
        logger.warning("APP_PASSWORD is not set — the dashboard is not password-protected. Set it before deploying.")
    db_path = os.environ.get("DATABASE_PATH")
    resolved = db.init_db(db_path)
    logger.info("SQLite path: %s (ephemeral on Render free-tier redeploys / sleeps unless you attach a disk)", resolved)
    global _tool_cache
    _tool_cache = adapters.detect_tools()
    logger.info("Tool availability: %s", {k: v.get("available") for k, v in _tool_cache.items()})
    yield


app = FastAPI(
    title="Digital Footprint Self-Audit Platform",
    description="OSINT self-audit dashboard for a cybersecurity class project.",
    version="1.2.0",
    lifespan=lifespan,
)

class AuthGateMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if auth.is_public_path(path) or not auth.auth_enabled():
            return await call_next(request)
        if auth.is_authenticated(request):
            return await call_next(request)
        return auth.unauthorized_response(request)


# Auth gate first (inner), then SessionMiddleware last so it is the outermost
# wrapper and request.session is available inside the gate.
app.add_middleware(AuthGateMiddleware)
auth.install_session_middleware(app)

if STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/audit", response_class=HTMLResponse)
async def audit_page() -> FileResponse:
    return FileResponse(STATIC / "audit.html")


@app.get("/health")
async def public_health() -> dict[str, Any]:
    """Liveness probe for Render. No secrets, no tool inventory."""
    return {"ok": True, "version": app.version}


@app.get("/api/health")
async def health() -> dict[str, Any]:
    tools = adapters.detect_tools()  # re-read env (HIBP / Gemini are request-time)
    used = db.count_scans_in_last_hour()
    gemini_configured = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    gemini_model = ai.configured_model()
    return {
        "ok": True,
        "tools": tools,
        "demo_mode_env": os.environ.get("DEMO", "").strip() in {"1", "true", "yes"},
        "gemini_configured": gemini_configured,
        "gemini_model": gemini_model,
        "gemini": {"configured": gemini_configured, "model": gemini_model},
        "hibp_configured": bool(os.environ.get("HIBP_API_KEY", "").strip()),
        "rate_limit": {
            "max": RATE_LIMIT,
            "window": "1 hour",
            "used": used,
            "remaining": max(0, RATE_LIMIT - used),
        },
        "consent_text": CONSENT_TEXT,
        "bind": os.environ.get("HOST", "0.0.0.0"),
        "fake_tools": adapters.use_fake_tools(),
    }


@app.get("/api/tools")
async def tools() -> dict[str, Any]:
    return {"tools": _tool_cache or adapters.detect_tools()}


@app.post("/api/scan")
async def start_scan(payload: ScanRequest, request: Request) -> dict[str, Any]:
    inputs = validate_inputs(payload)
    used = db.count_scans_in_last_hour()
    if used >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit reached: {RATE_LIMIT} live scans per hour. Use Load demo result, or wait before starting another live scan.",
        )
    job_id = uuid.uuid4().hex
    db.create_job(job_id, inputs, consent=True, is_demo=False, status="queued")
    db.record_rate_event()
    _jobs_in_flight.add(job_id)
    asyncio.create_task(execute_job(job_id, inputs))
    return {"job_id": job_id, "id": job_id, "status": "queued"}


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str) -> dict[str, Any]:
    job = db.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job_public_view(job)


@app.get("/api/jobs/{job_id}/report.pdf")
async def get_report(job_id: str) -> Response:
    job = db.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    if job["status"] not in {"complete", "error"}:
        raise HTTPException(status_code=409, detail="Report is available after the scan finishes.")
    pdf_bytes = report.build_pdf(job_public_view(job))
    filename = f"footprint-audit-{job_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/demo")
async def load_demo() -> dict[str, Any]:
    job = persist_demo_job()
    return {"job_id": job["id"], "id": job["id"], "status": "complete", "is_demo": True}


@app.get("/api/audit")
async def api_audit() -> dict[str, Any]:
    entries = db.list_audit()
    # Belt-and-braces: never return raw identifier values from the audit log.
    for entry in entries:
        if any(ch in (entry.get("input_types") or "") for ch in ("@", " ")):
            entry["input_types"] = ",".join(
                t for t in ("username", "email", "domain") if t in (entry.get("input_types") or "")
            )
    return {"entries": entries, "note": "The audit log stores input types and tools run, not emails or passwords."}


def _login_page(error: str = "", next_path: str = "/") -> HTMLResponse:
    template = (STATIC / "login.html").read_text(encoding="utf-8")
    error_html = f'<div class="error" style="display:block">{html.escape(error)}</div>' if error else ""
    safe_next = next_path if next_path.startswith("/") and not next_path.startswith("//") else "/"
    page = template.replace("<!--ERROR-->", error_html).replace("<!--NEXT-->", html.escape(safe_next, quote=True))
    status = 401 if error else 200
    return HTMLResponse(page, status_code=status)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, next: str = "/") -> HTMLResponse:
    if auth.auth_enabled() and auth.is_authenticated(request):
        return RedirectResponse("/", status_code=302)
    if not auth.auth_enabled():
        return RedirectResponse("/", status_code=302)
    return _login_page("", next)


@app.post("/login")
async def login_submit(
    request: Request,
    password: str = Form(""),
    next: str = Form("/"),
):
    if not auth.auth_enabled():
        return RedirectResponse("/", status_code=302)
    ip = auth.client_ip(request)
    if not auth.login_allowed(ip):
        return _login_page("Too many failed attempts. Try again in a few minutes.", next)
    if not auth.check_password(password):
        auth.record_login_failure(ip)
        return _login_page("That password is not correct.", next)
    auth.clear_login_failures(ip)
    auth.mark_authenticated(request)
    dest = next if next.startswith("/") and not next.startswith("//") else "/"
    return RedirectResponse(dest, status_code=303)


@app.api_route("/logout", methods=["GET", "POST"])
async def logout(request: Request):
    auth.clear_session(request)
    return RedirectResponse("/login", status_code=303)


@app.get("/favicon.ico")
async def favicon() -> Response:
    return Response(status_code=204)
