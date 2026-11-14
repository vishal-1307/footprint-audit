from __future__ import annotations

from app.scoring import compute_score, evaluate, score_label


def _f(**kwargs):
    base = {
        "source": "sherlock",
        "input_type": "username",
        "value": "GitHub",
        "url": "",
        "status": "found",
        "confidence": "high",
        "raw": "",
    }
    base.update(kwargs)
    return base


def test_score_zero_when_empty():
    score, breakdown = compute_score([])
    assert score == 0
    assert breakdown == []
    assert score_label(0) == "Low"


def test_username_reuse_and_dedupe():
    findings = [
        _f(source="sherlock", value="GitHub", url="https://github.com/demo"),
        _f(source="maigret", value="GitHub", url="https://github.com/demo"),
        _f(source="sherlock", value="Reddit", url="https://reddit.com/user/demo"),
        _f(source="sherlock", value="WordPress", url="https://demo.wordpress.com"),
        _f(source="sherlock", value="Pinterest", url="https://pinterest.com/demo"),
        _f(source="sherlock", value="Steam", url="https://steamcommunity.com/id/demo"),
    ]
    score, breakdown = compute_score(findings)
    rules = {b["rule"]: b["points"] for b in breakdown}
    assert rules["username_profiles_found"] == 10  # 5 unique * 2, not 6
    assert rules["username_high_reuse"] == 15
    assert "sensitive_platforms" in rules
    assert score >= 25
    assert score <= 100


def test_email_and_breach_points():
    findings = [
        _f(source="holehe", input_type="email", value="github"),
        _f(source="holehe", input_type="email", value="adobe"),
        _f(
            source="h8mail",
            input_type="email",
            value="2 breach source(s)",
            raw="pwn_num=2; sources=ExampleBreach2019",
        ),
    ]
    score, breakdown = compute_score(findings)
    rules = {b["rule"]: b["points"] for b in breakdown}
    assert rules["email_registrations"] == 6
    assert rules["email_sensitive_services"] == 8
    assert rules["breach_confirmed"] == 25
    assert score == 39


def test_whois_privacy_does_not_add_email_points():
    findings = [
        _f(source="whois", input_type="domain", value="REDACTED", raw="whois_privacy"),
    ]
    score, breakdown = compute_score(findings)
    rules = {b["rule"] for b in breakdown}
    assert "whois_public_email" not in rules
    assert score == 0


def test_whois_public_email_and_harvest():
    findings = [
        _f(source="whois", input_type="domain", value="alex@example.com", raw="whois_email"),
        _f(source="whois", input_type="domain", value="Alex Rivera", raw="whois_registrant"),
        _f(source="theharvester", input_type="domain", value="hello@example.com", raw="harvested_email"),
        _f(source="theharvester", input_type="domain", value="Alex Rivera", raw="person"),
    ]
    findings.extend(
        _f(source="subfinder", input_type="domain", value=f"h{i}.example.com") for i in range(5)
    )
    score, breakdown = compute_score(findings)
    rules = {b["rule"]: b["points"] for b in breakdown}
    assert rules["whois_public_email"] == 12
    assert rules["whois_public_org"] == 5
    assert rules["harvested_emails"] == 4
    assert rules["harvested_people"] == 3
    assert rules["subdomain_exposure"] == 8
    assert score == 32


def test_score_capped_at_100():
    findings = []
    for i in range(20):
        findings.append(
            _f(
                source="sherlock",
                value=f"Site{i}",
                url=f"https://github.com/u{i}" if i < 8 else f"https://site{i}.example/u",
            )
        )
    for i in range(10):
        findings.append(_f(source="holehe", input_type="email", value="adobe" if i == 0 else f"svc{i}"))
    findings.append(
        _f(source="h8mail", input_type="email", value="9 breach source(s)", raw="pwn_num=9; sources=a,b,c")
    )
    findings.append(_f(source="whois", input_type="domain", value="a@b.com", raw="whois_email"))
    score, _ = compute_score(findings)
    assert score == 100


def test_evaluate_includes_remediation_and_notes():
    findings = [
        _f(value="GitHub", url="https://github.com/demo"),
        _f(source="sherlock", value="Reddit", url="https://reddit.com/user/demo"),
        _f(source="holehe", input_type="email", value="github"),
        _f(source="sherlock", value="Instagram", url="https://instagram.com/demo", status="blocked"),
    ]
    result = evaluate(findings, inputs={"name": "Alex Rivera", "city": "Pune", "username": "demo"})
    assert "score" in result and "remediation" in result and "confidence_notes" in result
    titles = " ".join(item["title"] for item in result["remediation"]).lower()
    assert "privacy" in titles or "2fa" in titles or "two-factor" in titles or "forgotten" in titles
    notes = " ".join(result["confidence_notes"]).lower()
    assert "name" in notes and "pune" in notes
    assert "instagram" in notes or "blocked" in notes
    assert "verified identity" in notes or "same handle" in notes or "single username" in notes


def test_labels():
    assert score_label(0) == "Low"
    assert score_label(24) == "Low"
    assert score_label(25) == "Moderate"
    assert score_label(49) == "Moderate"
    assert score_label(50) == "High"
    assert score_label(74) == "High"
    assert score_label(75) == "Critical"
    assert score_label(100) == "Critical"


def test_xposedornot_and_mail_web_points():
    import json
    findings = [
        _f(
            source="xposedornot",
            input_type="email",
            value="2 breach(es) reported — ExampleForum2019, SampleShop2022",
            raw=json.dumps({"kind": "summary", "count": 2, "breaches": ["ExampleForum2019", "SampleShop2022"], "data_classes": ["Passwords"]}),
        ),
        _f(
            source="mail_security",
            input_type="domain",
            value="Mail security grade D",
            raw=json.dumps({"kind": "grade", "grade": "D", "score": 40}),
        ),
        _f(
            source="web_security",
            input_type="domain",
            value="Website security grade C",
            raw=json.dumps({"kind": "grade", "grade": "C", "score": 64}),
        ),
        _f(source="github_profile", input_type="username", value="Public email on GitHub: alex.rivera.demo@example.com"),
        _f(source="gravatar", input_type="email", value="Gravatar profile: Alex Rivera"),
    ]
    result = evaluate(findings, {"email": "alex.rivera.demo@example.com", "domain": "rivera-demo.example", "username": "alexrivera_demo"})
    rules = {b["rule"]: b["points"] for b in result["score_breakdown"]}
    assert rules["breach_confirmed"] == 25
    assert rules["breach_sensitive_data"] == 8
    assert rules["mail_security_weak"] == 12
    assert rules["web_security_weak"] == 6
    assert rules["github_public_email"] == 6
    assert rules["gravatar_profile"] == 4
    assert result["score"] <= 100
    titles = [i["title"].lower() for i in result["remediation"]]
    assert any("breached" in t for t in titles)
    assert any("spf" in t or "dmarc" in t for t in titles)
