"""Optional Gemini summary. The app must still work if the key is missing or the API fails."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("footprint.ai")

# Default is conservative and widely available. Recheck the exact free-tier
# model id in Google AI Studio — names change. Research from Nov 2026 also
# mentions gemini-3.5-flash-lite as a higher-cap option.
DEFAULT_MODEL = "gemini-2.5-flash-lite"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def configured_model() -> str:
    return os.environ.get("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def _api_key() -> str | None:
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    return key or None


def build_prompt(job: dict[str, Any]) -> str:
    payload = {
        "inputs_present": {
            "username": bool((job.get("inputs") or {}).get("username")),
            "email": bool((job.get("inputs") or {}).get("email")),
            "domain": bool((job.get("inputs") or {}).get("domain")),
            "name_filter": (job.get("inputs") or {}).get("name") or None,
            "city_filter": (job.get("inputs") or {}).get("city") or None,
        },
        "score": job.get("score"),
        "score_label": job.get("score_label"),
        "score_breakdown": job.get("score_breakdown") or [],
        "findings": job.get("findings") or [],
        "remediation": job.get("remediation") or [],
        "confidence_notes": job.get("confidence_notes") or [],
        "tool_status": {
            name: (info or {}).get("status")
            for name, info in (job.get("tools") or job.get("progress") or {}).items()
        },
        "is_demo": bool(job.get("is_demo")),
    }
    return (
        "You are summarizing a digital-footprint SELF-AUDIT for a cybersecurity class.\n"
        "Rules you must follow:\n"
        "- Summarize ONLY the facts in the JSON below. Never invent profiles, accounts, "
        "breaches, locations, employers, phone numbers, or personal details that are not present.\n"
        "- If a finding is low-confidence, or the same username could belong to different people, say so explicitly.\n"
        "- Do not treat a missing result as proof that an account does not exist, especially if a tool was blocked or unavailable.\n"
        "- Do not address a third party as a 'target'. This is a self-audit of identifiers the user consented to check.\n"
        "- If this is sample/demo data, say clearly that it is fictional sample data.\n"
        "- Write 3–6 short paragraphs or bullet groups covering: what was found, what was not found or blocked, "
        "confidence caveats, and the most important privacy fixes already listed in remediation.\n"
        "- Do not repeat the raw JSON. Do not add a preamble about being an AI.\n\n"
        f"{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )


def _extract_text(body: dict[str, Any]) -> str:
    candidates = body.get("candidates") or []
    parts_text: list[str] = []
    for cand in candidates:
        content = cand.get("content") or {}
        for part in content.get("parts") or []:
            text = part.get("text")
            if text:
                parts_text.append(text)
    return "\n".join(parts_text).strip()


def summarize_findings(job: dict[str, Any], timeout_s: float = 30.0) -> dict[str, str]:
    """Return {status, summary}. status is ok | skipped_no_key | skipped_429 | skipped_error."""
    key = _api_key()
    if not key:
        return {
            "status": "skipped_no_key",
            "summary": "",
        }

    model = configured_model()
    url = GEMINI_URL.format(model=model)
    payload = {
        "contents": [{"parts": [{"text": build_prompt(job)}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024},
    }
    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.post(url, params={"key": key}, json=payload)
        if response.status_code == 429:
            logger.warning("Gemini returned 429 (rate limited); skipping AI summary")
            return {"status": "skipped_429", "summary": ""}
        if response.status_code >= 400:
            logger.warning(
                "Gemini error %s: %s",
                response.status_code,
                response.text[:300],
            )
            return {"status": "skipped_error", "summary": ""}
        text = _extract_text(response.json())
        if not text:
            return {"status": "skipped_error", "summary": ""}
        return {"status": "ok", "summary": text}
    except Exception as exc:  # noqa: BLE001 — must never fail the scan
        logger.warning("Gemini request failed: %s", exc)
        return {"status": "skipped_error", "summary": ""}


async def summarize_findings_async(job: dict[str, Any], timeout_s: float = 30.0) -> dict[str, str]:
    """Async wrapper used by the job runner. Same contract as summarize_findings."""
    key = _api_key()
    if not key:
        return {"status": "skipped_no_key", "summary": ""}

    model = configured_model()
    url = GEMINI_URL.format(model=model)
    payload = {
        "contents": [{"parts": [{"text": build_prompt(job)}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024},
    }
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            response = await client.post(url, params={"key": key}, json=payload)
        if response.status_code == 429:
            logger.warning("Gemini returned 429 (rate limited); skipping AI summary")
            return {"status": "skipped_429", "summary": ""}
        if response.status_code >= 400:
            logger.warning(
                "Gemini error %s: %s",
                response.status_code,
                response.text[:300],
            )
            return {"status": "skipped_error", "summary": ""}
        text = _extract_text(response.json())
        if not text:
            return {"status": "skipped_error", "summary": ""}
        return {"status": "ok", "summary": text}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Gemini request failed: %s", exc)
        return {"status": "skipped_error", "summary": ""}
