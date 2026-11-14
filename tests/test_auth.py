from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def raw_client(tmp_db, monkeypatch):
    monkeypatch.setenv("USE_FAKE_TOOLS", "1")
    monkeypatch.setenv("APP_PASSWORD", "test-password")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    monkeypatch.setenv("SECURE_COOKIES", "0")
    monkeypatch.delenv("RENDER", raising=False)
    from app.main import app

    with TestClient(app) as c:
        yield c


def test_public_health_and_login_page(raw_client: TestClient):
    res = raw_client.get("/health")
    assert res.status_code == 200
    assert res.json()["ok"] is True
    page = raw_client.get("/login")
    assert page.status_code == 200
    assert "password" in page.text.lower()


def test_pages_and_api_require_login(raw_client: TestClient):
    home = raw_client.get("/", follow_redirects=False)
    assert home.status_code in {302, 303}
    assert "/login" in home.headers["location"]

    api = raw_client.get("/api/health")
    assert api.status_code == 401
    scan = raw_client.post("/api/scan", json={"username": "test_user_demo", "consent": True})
    assert scan.status_code == 401
    audit = raw_client.get("/audit", follow_redirects=False)
    assert audit.status_code in {302, 303, 401}


def test_wrong_password_rejected(raw_client: TestClient):
    res = raw_client.post(
        "/login",
        data={"password": "definitely-wrong", "next": "/"},
        follow_redirects=False,
    )
    assert res.status_code == 401
    assert "not correct" in res.text.lower()
    still = raw_client.get("/api/health")
    assert still.status_code == 401


def test_login_logout_roundtrip(raw_client: TestClient):
    res = raw_client.post(
        "/login",
        data={"password": "test-password", "next": "/"},
        follow_redirects=False,
    )
    assert res.status_code in {302, 303}
    health = raw_client.get("/api/health")
    assert health.status_code == 200
    home = raw_client.get("/")
    assert home.status_code == 200
    assert "consent" in home.text.lower()
    out = raw_client.get("/logout", follow_redirects=False)
    assert out.status_code in {302, 303}
    blocked = raw_client.get("/api/health")
    assert blocked.status_code == 401


def test_static_css_is_public(raw_client: TestClient):
    res = raw_client.get("/static/styles.css")
    assert res.status_code == 200
    assert "font-family" in res.text
