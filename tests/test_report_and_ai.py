from __future__ import annotations

import json
from pathlib import Path

from app import ai, report, scoring


def test_demo_pdf_contains_expected_labels():
    demo = json.loads((Path(__file__).resolve().parent.parent / "data" / "demo_result.json").read_text())
    computed = scoring.evaluate(demo["findings"], demo["inputs"], demo["tools"])
    job = {
        "id": "demo-test",
        "created_at": "2026-11-11T18:00:00Z",
        "consent": True,
        "is_demo": True,
        "inputs": demo["inputs"],
        "tools": demo["tools"],
        "findings": demo["findings"],
        "score": computed["score"],
        "score_label": computed["score_label"],
        "score_breakdown": computed["score_breakdown"],
        "remediation": computed["remediation"],
        "confidence_notes": computed["confidence_notes"],
        "ai_summary": demo["ai_summary"],
        "ai_status": "skipped_no_key",
    }
    pdf = report.build_pdf(job)
    assert pdf.startswith(b"%PDF")
    # Fonts are embedded; ASCII labels from the header / title should still appear.
    assert b"Digital Footprint" in pdf or b"Self-Audit" in pdf
    assert b"SAMPLE" in pdf
    assert computed["score"] >= 50
    job["diff"] = {"has_previous": True, "previous_at": "2026-11-01T00:00:00Z", "new": [{"source": "xposedornot", "value": "ExampleForum2019"}], "removed": []}
    pdf2 = report.build_pdf(job)
    assert pdf2.startswith(b"%PDF")
    assert len(pdf2) >= len(pdf)


def test_ai_skipped_without_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    result = ai.summarize_findings({"findings": [], "score": 0})
    assert result["status"] == "skipped_no_key"
    assert result["summary"] == ""


def test_ai_prompt_forbids_invention():
    prompt = ai.build_prompt(
        {
            "inputs": {"username": "demo"},
            "findings": [{"source": "sherlock", "value": "GitHub", "status": "found"}],
            "score": 10,
            "remediation": [],
            "confidence_notes": ["not verified"],
            "is_demo": False,
        }
    )
    assert "Never invent" in prompt
    assert "GitHub" in prompt
    # Prompt should not be written as a dossier on a third-party "target".
    assert "SELF-AUDIT" in prompt or "self-audit" in prompt.lower()
    assert "raw secrets" in prompt.lower() or "Never quote raw secrets" in prompt


def test_ai_prompt_strips_raw_secrets():
    prompt = ai.build_prompt(
        {
            "inputs": {"email": "alex.rivera.demo@example.com"},
            "findings": [
                {
                    "source": "xposedornot",
                    "value": "ExampleForum2019 — Passwords",
                    "status": "found",
                    "raw": {"kind": "breach", "password": "should-not-appear", "data_classes": ["Passwords"]},
                }
            ],
            "score": 25,
            "is_demo": False,
        }
    )
    assert "should-not-appear" not in prompt
    assert "ExampleForum2019" in prompt


def test_configured_model_default_and_override(monkeypatch):
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    assert ai.configured_model() == "gemini-2.5-flash-lite"
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    assert ai.configured_model() == "gemini-3.5-flash-lite"
