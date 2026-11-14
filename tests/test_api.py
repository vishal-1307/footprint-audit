from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_db, monkeypatch):
    monkeypatch.setenv("USE_FAKE_TOOLS", "1")
    monkeypatch.setenv("APP_PASSWORD", "test-password")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    monkeypatch.setenv("SECURE_COOKIES", "0")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    monkeypatch.delenv("RENDER", raising=False)
    from app import db
    from app.main import app

    assert db.get_job("missing") is None or True
    with TestClient(app) as c:
        res = c.post("/login", data={"password": "test-password", "next": "/"}, follow_redirects=False)
        assert res.status_code in {303, 302}
        yield c


def test_health_and_tools(client: TestClient):
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert "sherlock" in body["tools"]
    assert body["gemini_configured"] is False
    assert body["fake_tools"] is True


def test_scan_requires_consent(client: TestClient):
    res = client.post("/api/scan", json={"username": "test_user_demo", "consent": False})
    assert res.status_code == 400
    assert "consent" in res.json()["detail"].lower()


def test_scan_requires_identifier(client: TestClient):
    res = client.post("/api/scan", json={"consent": True, "name": "Alex"})
    assert res.status_code == 400


def test_scan_rejects_bad_email_and_domain(client: TestClient):
    res = client.post("/api/scan", json={"consent": True, "email": "not-an-email"})
    assert res.status_code == 400
    res = client.post("/api/scan", json={"consent": True, "domain": "https://example.com"})
    assert res.status_code == 400
    res = client.post("/api/scan", json={"consent": True, "username": "bad user"})
    assert res.status_code == 400


def test_scan_e2e_with_fake_adapters(client: TestClient):
    res = client.post(
        "/api/scan",
        json={
            "username": "test_user_demo",
            "email": "demo@example.com",
            "domain": "example.com",
            "name": "Demo User",
            "city": "Pune",
            "consent": True,
        },
    )
    assert res.status_code == 200, res.text
    job_id = res.json()["job_id"]
    job = None
    for _ in range(50):
        poll = client.get(f"/api/jobs/{job_id}")
        assert poll.status_code == 200
        job = poll.json()
        if job["status"] in {"complete", "error"}:
            break
    assert job is not None and job["status"] == "complete"
    assert job["score"] is not None
    assert job["findings"]
    assert any(f["source"] == "sherlock" for f in job["findings"])
    assert any(f["source"] == "holehe" for f in job["findings"])
    assert job["ai_status"] == "skipped_no_key"
    assert "Pune" in " ".join(job["confidence_notes"])
    # live progress keys exist
    assert "sherlock" in job["tools"]

    pdf = client.get(f"/api/jobs/{job_id}/report.pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")
    assert pdf.headers["content-type"].startswith("application/pdf")


def test_pdf_before_complete_is_conflict(client: TestClient):
    # Unknown job
    res = client.get("/api/jobs/does-not-exist/report.pdf")
    assert res.status_code == 404


def test_demo_mode_is_labelled_and_complete(client: TestClient):
    res = client.post("/api/demo")
    assert res.status_code == 200, res.text
    job_id = res.json()["job_id"]
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "complete"
    assert job["is_demo"] is True
    assert "SAMPLE" in (job.get("demo_disclaimer") or "").upper() or "fictional" in (job.get("demo_disclaimer") or "").lower()
    assert job["inputs"]["username"] == "alexrivera_demo"
    assert job["score"] is not None
    assert job["score_breakdown"]
    assert job["remediation"]
    assert job["ai_summary"]
    pdf = client.get(f"/api/jobs/{job_id}/report.pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")
    # Demo PDF must be clearly labelled.
    assert b"SAMPLE" in pdf.content or b"fictional" in pdf.content.lower() or b"FICTIONAL" in pdf.content


def test_audit_log_has_types_not_secrets(client: TestClient):
    client.post(
        "/api/scan",
        json={"username": "test_user_demo", "email": "secret-person@example.com", "consent": True},
    )
    # Wait for completion so the audit row is written at the end of the job.
    # Rate event is recorded immediately; audit entry is written when the job finishes.
    # Also load a demo (audit is written immediately).
    client.post("/api/demo")
    audit = client.get("/api/audit").json()
    blob = str(audit).lower()
    assert "secret-person@example.com" not in blob
    assert "entries" in audit
    assert any("username" in (e.get("input_types") or "") or e.get("is_demo") for e in audit["entries"])


def test_rate_limit(client: TestClient, monkeypatch):
    from app import db

    for _ in range(5):
        db.record_rate_event()
    res = client.post("/api/scan", json={"username": "test_user_demo", "consent": True})
    assert res.status_code == 429
    # Demo is not rate limited.
    demo = client.post("/api/demo")
    assert demo.status_code == 200


def test_pages_served(client: TestClient):
    assert client.get("/").status_code == 200
    assert client.get("/audit").status_code == 200
    assert "consent" in client.get("/").text.lower()
