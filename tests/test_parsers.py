from __future__ import annotations

from pathlib import Path

from app.adapters import (
    parse_dnsrecon_json,
    parse_h8mail_json,
    parse_holehe_output,
    parse_maigret_json,
    parse_sherlock_csv,
    parse_subfinder_jsonl,
    parse_theharvester_json,
    parse_whois_text,
)


def _read(fixtures: Path, name: str) -> str:
    return (fixtures / name).read_text(encoding="utf-8")


def test_sherlock_csv_claimed_waf_and_skips_available(fixtures: Path):
    findings = parse_sherlock_csv(_read(fixtures, "sherlock.csv"), "alexrivera_demo")
    by_site = {f.value: f for f in findings}
    assert "GitHub" in by_site and by_site["GitHub"].status == "found"
    assert by_site["GitHub"].url.endswith("alexrivera_demo")
    assert by_site["Instagram"].status == "blocked"
    assert "Twitter" not in by_site  # Available / not_found omitted
    assert "SomeSite" not in by_site  # illegal username skipped
    assert all(f.source == "sherlock" and f.input_type == "username" for f in findings)


def test_maigret_simple_json(fixtures: Path):
    findings = parse_maigret_json(_read(fixtures, "maigret_simple.json"), "alexrivera_demo")
    names = {f.value for f in findings}
    assert names == {"GitHub", "Reddit"}
    assert all(f.status == "found" for f in findings)
    github = next(f for f in findings if f.value == "GitHub")
    assert "github.com" in github.url


def test_maigret_ndjson():
    text = (
        '{"sitename":"GitHub","url_user":"https://github.com/demo","status":{"status":"Claimed"}}\n'
        '{"sitename":"GitLab","url_user":"https://gitlab.com/demo","status":"Claimed"}\n'
    )
    findings = parse_maigret_json(text, "demo")
    assert {f.value for f in findings} == {"GitHub", "GitLab"}


def test_holehe_json_used_and_ratelimit(fixtures: Path):
    findings = parse_holehe_output(_read(fixtures, "holehe.json"), "a@example.com")
    by_name = {f.value: f for f in findings}
    assert by_name["twitter"].status == "found"
    assert by_name["github"].status == "found"
    assert by_name["instagram"].status == "blocked"
    assert "facebook" not in by_name
    github = by_name["github"]
    assert "github.com" in github.url


def test_holehe_text_fallback_with_ansi(fixtures: Path):
    findings = parse_holehe_output(_read(fixtures, "holehe_text.txt"), "a@example.com")
    values = {f.value.lower(): f.status for f in findings}
    assert values["twitter"] == "found"
    assert values["github"] == "found"
    assert values.get("instagram") == "blocked"
    assert "facebook" not in values
    assert values["adobe"] == "found"


def test_holehe_tolerates_absent_json():
    assert parse_holehe_output("", "a@example.com") == []
    assert parse_holehe_output("not json at all\nrandom banner", "a@example.com") == []


def test_whois_public_email_and_registrant(fixtures: Path):
    findings = parse_whois_text(_read(fixtures, "whois_public.txt"), "rivera-demo.example")
    raws = {f.raw for f in findings}
    assert "whois_email" in raws
    assert "whois_registrant" in raws
    email = next(f for f in findings if f.raw == "whois_email")
    assert email.value == "alex.rivera.demo@example.com"


def test_whois_privacy_not_counted_as_personal_email(fixtures: Path):
    findings = parse_whois_text(_read(fixtures, "whois_privacy.txt"), "example.com")
    emails = [f for f in findings if f.raw == "whois_email"]
    assert emails == []
    assert any("privacy" in (f.raw + f.value).lower() or "redact" in (f.value + f.raw).lower() for f in findings)


def test_dnsrecon_json(fixtures: Path):
    findings = parse_dnsrecon_json(_read(fixtures, "dnsrecon.json"), "example.com")
    types = {f.value.split()[0] for f in findings}
    assert {"A", "MX", "NS"} <= types
    assert all(f.source == "dnsrecon" for f in findings)


def test_subfinder_jsonl_dedupes(fixtures: Path):
    findings = parse_subfinder_jsonl(_read(fixtures, "subfinder.jsonl"), "example.com")
    hosts = [f.value for f in findings]
    assert hosts.count("www.example.com") == 1
    assert "mail.example.com" in hosts


def test_theharvester_json(fixtures: Path):
    findings = parse_theharvester_json(_read(fixtures, "theharvester.json"), "example.com")
    values = {f.value for f in findings}
    assert "admin@example.com" in values
    assert "hello@example.com" in values
    assert "www.example.com" in values
    assert "mail.example.com" in values  # host:ip split
    assert "Jane Example" in values
    people = [f for f in findings if f.raw == "person"]
    assert people and people[0].confidence == "low"


def test_h8mail_pwned_does_not_include_password(fixtures: Path):
    findings = parse_h8mail_json(_read(fixtures, "h8mail_pwned.json"), "alex.rivera.demo@example.com")
    assert findings and findings[0].status == "found"
    assert "2 breach" in findings[0].value
    blob = findings[0].raw + findings[0].value
    assert "DO-NOT-STORE-PASSWORD" not in blob
    assert "ExampleBreach2019" in findings[0].raw


def test_h8mail_clean(fixtures: Path):
    findings = parse_h8mail_json(_read(fixtures, "h8mail_clean.json"), "clean@example.com")
    assert findings and findings[0].status == "not_found"


def test_crtsh_json_filters_and_dedupes(fixtures: Path):
    from app.adapters import parse_crtsh_json

    findings = parse_crtsh_json(_read(fixtures, "crtsh.json"), "example.com")
    hosts = [f.value for f in findings]
    assert "www.example.com" in hosts
    assert "example.com" in hosts
    assert "mail.example.com" in hosts
    assert hosts.count("www.example.com") == 1
    assert "unrelated.example.net" not in hosts
    assert all(f.source == "crtsh" for f in findings)


def test_python_whois_record_flattens_to_same_parser():
    from app.adapters import parse_python_whois

    record = {
        "registrar": "Example Registrar, Inc.",
        "creation_date": "2020-04-01",
        "expiration_date": "2027-04-01",
        "org": "Alex Rivera Labs",
        "emails": "alex.rivera.demo@example.com",
        "name_servers": ["ns1.rivera-demo.example", "ns2.rivera-demo.example"],
    }
    findings = parse_python_whois(record, "rivera-demo.example")
    raws = {f.raw for f in findings}
    assert "whois_email" in raws
    assert "whois_registrant" in raws


def test_dns_lookup_records_normalize():
    from app.adapters import parse_dns_lookup_records

    findings = parse_dns_lookup_records(
        [
            {"type": "A", "name": "example.com", "address": "93.184.216.34"},
            {"type": "A", "name": "example.com", "address": "93.184.216.34"},
            {"type": "MX", "name": "example.com", "address": "10 mail.example.com."},
        ],
        "example.com",
    )
    assert len(findings) == 2
    assert all(f.source == "dns_lookup" for f in findings)


def test_holehe_csv(fixtures: Path):
    from app.adapters import parse_holehe_csv

    findings = parse_holehe_csv(_read(fixtures, "holehe.csv"), "a@example.com")
    by_name = {f.value: f for f in findings}
    assert by_name["twitter"].status == "found"
    assert by_name["github"].status == "found"
    assert by_name["instagram"].status == "blocked"
    assert "facebook" not in by_name


def test_rdap_json(fixtures: Path):
    from app.adapters import parse_rdap_json

    findings = parse_rdap_json(_read(fixtures, "rdap_example.json"), "example.com")
    assert findings
    assert any("registrar" in (f.raw or "").lower() or "RESERVED" in (f.value or "") or "IANA" in (f.value or "") or f.status == "found" for f in findings)
    assert any("ns=" in (f.raw or "") or "IANA-SERVERS" in (f.raw or "") or "A.IANA" in (f.value or f.raw or "") for f in findings) or any("whois" == f.source for f in findings)
    assert all(f.source == "whois" for f in findings)
    assert any("rdap" in (f.raw or "").lower() for f in findings)


def test_sherlock_claimed_non_200_is_low_confidence():
    from app.adapters import parse_sherlock_csv
    csv = (
        "username,name,url_main,url_user,exists,http_status,response_time_s\n"
        "u,Wikidot,https://wikidot.com/,http://wikidot.com/user:info/u,Claimed,500,0.2\n"
    )
    findings = parse_sherlock_csv(csv, "u")
    assert findings[0].status == "found"
    assert findings[0].confidence == "low"
    assert "possible_false_positive" in findings[0].raw
