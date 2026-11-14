"""Password login and signed session cookies.

A single admin password is read from APP_PASSWORD. Sessions are signed with
SECRET_KEY (Starlette SessionMiddleware). Cookie flags: HttpOnly, SameSite=Lax,
and Secure when the app is served over HTTPS (Render).
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import time
from collections import defaultdict

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

logger = logging.getLogger("footprint.auth")

SESSION_COOKIE = "fa_session"
SESSION_MAX_AGE = 60 * 60 * 12  # 12 hours
PUBLIC_PATHS = frozenset({"/login", "/health", "/favicon.ico"})
LOGIN_FAILURE_WINDOW = 15 * 60
LOGIN_FAILURE_LIMIT = 10

_failures: dict[str, list[float]] = defaultdict(list)


def app_password() -> str:
    return os.environ.get("APP_PASSWORD", "").strip()


def auth_enabled() -> bool:
    return bool(app_password())


def is_production() -> bool:
    if os.environ.get("RENDER", "").strip().lower() in {"true", "1", "yes"}:
        return True
    if os.environ.get("RENDER_EXTERNAL_HOSTNAME", "").strip():
        return True
    return os.environ.get("REQUIRE_AUTH", "").strip().lower() in {"1", "true", "yes"}


def secret_key() -> str:
    key = os.environ.get("SECRET_KEY", "").strip()
    if key:
        return key
    generated = os.environ.get("_GENERATED_SECRET_KEY")
    if not generated:
        generated = secrets.token_hex(32)
        os.environ["_GENERATED_SECRET_KEY"] = generated
        logger.warning("SECRET_KEY is not set; a temporary key was generated. Sessions will reset on restart.")
    return generated


def use_secure_cookies() -> bool:
    flag = os.environ.get("SECURE_COOKIES", "").strip().lower()
    if flag in {"1", "true", "yes"}:
        return True
    if flag in {"0", "false", "no"}:
        return False
    return is_production()


def check_password(provided: str) -> bool:
    expected = app_password()
    if not expected:
        return False
    a = (provided or "").encode("utf-8")
    b = expected.encode("utf-8")
    if len(a) != len(b):
        hmac.compare_digest(b, b)
        return False
    return hmac.compare_digest(a, b)


def is_authenticated(request: Request) -> bool:
    if not auth_enabled():
        return True
    return request.session.get("auth") is True


def mark_authenticated(request: Request) -> None:
    request.session["auth"] = True
    request.session["ts"] = int(time.time())


def clear_session(request: Request) -> None:
    request.session.clear()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


def login_allowed(ip: str) -> bool:
    now = time.time()
    window = [t for t in _failures[ip] if now - t < LOGIN_FAILURE_WINDOW]
    _failures[ip] = window
    return len(window) < LOGIN_FAILURE_LIMIT


def record_login_failure(ip: str) -> None:
    _failures[ip].append(time.time())


def clear_login_failures(ip: str) -> None:
    _failures.pop(ip, None)


def is_public_path(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    # Login and other public pages need the shared stylesheet.
    if path == "/static" or path.startswith("/static/"):
        return True
    return False


def unauthorized_response(request: Request):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Not authenticated. Please log in."}, status_code=401)
    next_path = request.url.path
    if next_path in {"/", "/login"}:
        return RedirectResponse("/login", status_code=302)
    return RedirectResponse("/login?next=" + next_path, status_code=302)


def install_session_middleware(app) -> None:
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key(),
        session_cookie=SESSION_COOKIE,
        max_age=SESSION_MAX_AGE,
        same_site="lax",
        https_only=use_secure_cookies(),
    )
