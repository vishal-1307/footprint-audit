from __future__ import annotations

import json

from app.enrichment import (
    diff_findings,
    email_digests,
    grade_mail,
    grade_web,
    identifier_hash,
    parse_github_profile,
    parse_gravatar_profile,
    parse_mail_security,
    parse_xposedornot_analytics,
)


def test_xposedornot_not_found():
    findings = parse_xposedornot_analytics(
        {"BreachMetrics": None, "BreachesSummary": {"site": ""}, "ExposedBreaches": None},
        "alex.rivera.demo@example.com",
    )
    assert findings and findings[0].status == "not_found"
    assert "No breaches" in findings[0].value


def test_xposedornot_analytics_and_classes():
    payload = {
        "BreachesSummary": {"site": "ExampleForum2019;SampleShop2022"},
        "ExposedBreaches": [
            {
                "breach": "ExampleForum2019",
                "xposed_date": "2019",
                "xposed_data": "Usernames;Passwords",
                "domain": "exampleforum.example",
            },
            {
                "breach": "SampleShop2022",
                "breached_date": "2022",
                "xposed_data": "Email addresses;Passwords",
                "domain": "sampleshop.example",
            },
        ],
    }
    findings = parse_xposedornot_analytics(payload, "alex.rivera.demo@example.com")
    statuses = [f.status for f in findings]
    assert statuses.count("found") >= 3
    summary = json.loads(findings[0].raw)
    assert summary["count"] == 2
    assert "ExampleForum2019" in summary["breaches"]
    assert any("Passwords" in f.value for f in findings)


def test_xposedornot_check_email_shape():
    payload = {"breaches": [["Adobe", "LinkedIn"]], "email": "a@example.com", "status": "success"}
    findings = parse_xposedornot_analytics(payload, "a@example.com")
    summary = json.loads(findings[0].raw)
    assert summary["count"] == 2
    assert "Adobe" in summary["breaches"]


def test_mail_grade_missing_dmarc():
    graded = grade_mail(
        {
            "mx": ["mail.example.com"],
            "spf": "v=spf1 -all",
            "dmarc": "",
            "dkim": [],
        }
    )
    assert graded["grade"] in {"C", "D", "F"}
    assert any("DMARC" in i for i in graded["issues"])
    findings = parse_mail_security(graded, "example.com")
    assert any("grade" in f.value.lower() for f in findings)


def test_mail_grade_strong():
    graded = grade_mail(
        {
            "mx": ["mail.example.com"],
            "spf": "v=spf1 include:_spf.example.com -all",
            "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            "dkim": ["google"],
        }
    )
    assert graded["grade"] == "A"
    assert graded["score"] >= 90


def test_web_grade_missing_headers_and_redirect():
    graded = grade_web(
        https_ok=True,
        redirect_to_https=False,
        cert={"issuer": "Example CA", "not_after": "Apr 1 00:00:00 2027 GMT", "days_left": 140},
        headers={"X-Content-Type-Options": "nosniff"},
        open_http_hosts=["dev.example.com"],
    )
    assert graded["grade"] in {"C", "D", "F"}
    assert "strict-transport-security" in graded["missing_headers"]
    assert "dev.example.com" in graded["open_http_hosts"]


def test_web_grade_strong():
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    graded = grade_web(
        https_ok=True,
        redirect_to_https=True,
        cert={"issuer": "Let's Encrypt", "not_after": "Apr 1 00:00:00 2027 GMT", "days_left": 140},
        headers=headers,
        open_http_hosts=[],
    )
    assert graded["grade"] == "A"
    assert not graded["missing_headers"]


def test_github_profile_pii_and_missing():
    missing = parse_github_profile({}, "alexrivera_demo")
    assert missing[0].status == "not_found"
    found = parse_github_profile(
        {
            "login": "alexrivera_demo",
            "html_url": "https://github.com/alexrivera_demo",
            "name": "Alex Rivera",
            "bio": "Demo",
            "location": "Pune",
            "company": "Demo Labs",
            "blog": "https://rivera-demo.example",
            "email": "alex.rivera.demo@example.com",
            "created_at": "2022-01-15T10:00:00Z",
            "public_repos": 7,
            "followers": 12,
        },
        "alexrivera_demo",
    )
    assert any(f.status == "found" and "GitHub @alexrivera_demo" in f.value for f in found)
    assert any("Public email" in f.value for f in found)
    assert any("location: Pune" in f.value for f in found)


def test_gravatar_profile_and_hash():
    digests = email_digests("Alex.Rivera.Demo@example.com")
    assert digests["md5"] == email_digests("alex.rivera.demo@example.com")["md5"]
    assert len(digests["sha256"]) == 64
    missing = parse_gravatar_profile({}, "alex.rivera.demo@example.com")
    assert missing[0].status == "not_found"
    found = parse_gravatar_profile(
        {"entry": [{"displayName": "Alex Rivera", "currentLocation": "Pune", "profileUrl": "https://gravatar.com/alexrivera_demo"}]},
        "alex.rivera.demo@example.com",
    )
    assert found[0].status == "found"
    assert any("location: Pune" in f.value for f in found)


def test_identifier_hash_and_diff():
    a = identifier_hash({"username": "Alex", "email": "A@example.com", "domain": "Example.com"})
    b = identifier_hash({"username": "alex", "email": "a@example.com", "domain": "example.com"})
    assert a == b
    assert identifier_hash({"username": "other"}) != a
    current = [
        {"source": "sherlock", "input_type": "username", "value": "GitHub", "url": "https://github.com/demo", "status": "found"},
        {"source": "xposedornot", "input_type": "email", "value": "ExampleForum2019", "url": "", "status": "found"},
    ]
    previous = [
        {"source": "sherlock", "input_type": "username", "value": "GitHub", "url": "https://github.com/demo", "status": "found"},
        {"source": "sherlock", "input_type": "username", "value": "Tumblr", "url": "https://demo.tumblr.com", "status": "found"},
    ]
    first = diff_findings(current, None)
    assert first["has_previous"] is False
    diff = diff_findings(current, previous)
    assert diff["has_previous"] is True
    assert any(f["value"] == "ExampleForum2019" for f in diff["new"])
    assert any(f["value"] == "Tumblr" for f in diff["removed"])
    assert diff["unchanged"] == 1
