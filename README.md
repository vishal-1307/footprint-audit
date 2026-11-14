# Digital Footprint Self-Audit Platform

A class-project web dashboard for a BCA cybersecurity course. Enter a username, email, or domain you are allowed to check; the app runs public OSINT tools and returns an exposure score, confidence notes, a remediation checklist, and a PDF.

**You do not need a Kali VM.** The supported way to run this is a password-protected website on [Render](https://render.com)’s free tier (Docker), or Docker on your own machine. A local Python virtualenv also works.

It is **not** a people-finder. It cannot reliably pull “all public details of any person,” and it will not scrape Instagram or Facebook behind a login wall. The honest scope is: *given a username, an email, and optionally a domain, show what selected public sources already reveal.*

## What it does

1. You log in with the single dashboard password (`APP_PASSWORD`).
2. You tick a consent box and enter at least one of: **username**, **email**, **domain**.
3. Optional **name** and **city** are display-filter notes only. They are never sent to OSINT tools.
4. The backend runs only the tools that match those inputs (at most two at a time; Maigret and Sherlock never overlap, to stay inside 512 MB).
5. Each tool is marked `found`, `not_found`, `blocked`, `error`, or `unavailable`.
6. Findings are normalized to `{source, input_type, value, url, status, confidence, raw}`.
7. A transparent 0–100 exposure score, a remediation checklist, and confidence notes are generated from the findings.
8. If `GEMINI_API_KEY` is set, Gemini writes a short summary of *only those facts*. If the key is missing or the API returns 429, the rest of the report still works.
9. You can download a PDF report. Every scan is written to an **audit log** (input *types* and tools run, not passwords or raw secrets).
10. Live scans are rate-limited to **5 per hour**. **Load demo result** loads bundled sample data for a fictional person so a viva still works if live tools fail.

## Inputs: what actually works

| Input | Used? | Why |
| --- | --- | --- |
| Username | Yes (best signal) | Maigret (`--top-sites 200`) + Sherlock. |
| Email | Yes | holehe infers whether an address is registered. h8mail runs only with a paid HIBP key; otherwise the UI links out to haveibeenpwned.com. |
| Domain | Optional | **whois** (system `whois` if present, otherwise `python-whois`), **dns_lookup** (dnspython, standard records only), **crt.sh** (certificate-transparency hostnames via HTTP). Optional extras if you install the binaries: dnsrecon, subfinder, theHarvester. |
| Name only | No | A common name matches thousands of people. Name is a filter note only. |
| Instagram / Facebook scrape | Not offered | Login-walled platforms block unauthenticated automation. A miss is not proof the account is absent. |

## Deploy on Render (free tier)

1. Push this folder to a GitHub repository (the `Dockerfile`, `render.yaml`, `app/`, `static/`, and `data/demo_result.json` must be in the repo root, or adjust paths if you nest them).
2. Open [Render](https://dashboard.render.com/) and sign in with GitHub.
3. Click **New → Blueprint**, pick the repo, and apply `render.yaml`.
   - Or **New → Web Service**, connect the repo, set **Language** to **Docker**, and use the free instance type.
4. Set environment variables (Blueprint will ask you to fill the ones marked `sync: false`):

   | Variable | Required | What to put |
   | --- | --- | --- |
   | `APP_PASSWORD` | Yes | The password you will type on the login page. |
   | `SECRET_KEY` | Yes | A long random string (Blueprint can generate this). Used to sign the session cookie. |
   | `GEMINI_API_KEY` | No | Free-tier key from [Google AI Studio](https://aistudio.google.com/). |
   | `GEMINI_MODEL` | No | Default `gemini-2.5-flash-lite`. Recheck the current free-tier id in AI Studio. |
   | `HIBP_API_KEY` | No | Paid Have I Been Pwned key. Without it, the UI shows a manual link. |

   `DATABASE_PATH`, `MAIGRET_TOP_SITES=200`, `SCAN_CONCURRENCY=2`, and `SECURE_COOKIES=1` are already set in `render.yaml`.
5. Wait for the build to finish, open the `onrender.com` URL, log in, tick consent, and either run a **self-audit** of your own identifiers or click **Load demo result**.
6. Health check: `https://YOUR-SERVICE.onrender.com/health` should return `{"ok": true}` without logging in.

**Free-tier limits you should expect**

- The service **sleeps** after idle time. The first request after a sleep can take a minute to wake.
- The SQLite file lives at `/var/data/footprint.db` on the instance disk. **It is wiped on a free-tier redeploy or when the instance is replaced.** The audit log and past jobs are not a permanent archive unless you attach a paid disk.
- Cloud datacenter IPs are often **rate-limited or blocked** by social sites. Instagram, Facebook, and sometimes even Sherlock/Maigret/holehe will come back `blocked` or empty more often than they would from a home network. That is a platform limitation, not a broken install. Use **Load demo result** if a live scan is thin.
- RAM is 512 MB. Maigret is capped at the top 200 sites, connection count is limited, and Maigret never runs at the same time as Sherlock.

## Run locally with Docker

```bash
docker build -t footprint-audit .
docker run --rm -p 8000:8000 \
  -e APP_PASSWORD='choose-a-strong-password' \
  -e SECRET_KEY='a-long-random-string' \
  -e SECURE_COOKIES=0 \
  footprint-audit
# open http://127.0.0.1:8000/ and log in
```

`SECURE_COOKIES=0` is required on plain HTTP so the session cookie is stored. On Render (HTTPS) leave it at `1`.

## Run locally with Python (no Docker)

Needs Python 3.11+ (3.12 is what the image uses).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit APP_PASSWORD and SECRET_KEY
./run.sh
# open http://127.0.0.1:8000/
```

`run.sh` binds `0.0.0.0` and honours `$PORT`. Optional Kali helper: `./setup_kali.sh` still installs apt CLIs if you happen to be on Kali, but it is **not required**.

```bash
source .venv/bin/activate
python -m pytest -q
```

## Tools and flags

| Tool | How it is installed | Command / API | Output |
| --- | --- | --- | --- |
| Maigret | `pip install maigret` | `maigret USER --json simple -fo DIR --top-sites 200 --max-connections 20 --timeout 10` | `*_simple.json` |
| Sherlock | `pip install sherlock-project` | `sherlock USER --csv --folderoutput DIR --print-found --timeout 10` | CSV. **Do not use `--json`** — that flag loads a site list, it does not export results. Sherlock 0.16 has no `--no-txt` (txt is opt-in). |
| holehe | `pip install holehe` | `holehe EMAIL --only-used --no-color --no-clear -C` (v1.61 has no `--json`) | CSV and/or `[+] domain` text. |
| whois | `apt install whois` in the image, else `python-whois`, then RDAP | `whois example.com`, python-whois, or `https://rdap.org/domain/{domain}` | Registrar, dates, non-redacted emails. Port 43 often fails from cloud IPs; RDAP is the HTTP fallback. |
| dns_lookup | `dnspython` | Standard A/AAAA/MX/NS/TXT/SOA/CNAME | Same shape as dnsrecon records. |
| crtsh | `httpx` to `https://crt.sh/?q=%.domain&output=json` | Certificate-transparency hostnames | Deduped, apex + subdomains only. |
| h8mail | Optional binary + `HIBP_API_KEY` | `h8mail -t EMAIL -j out.json -k hibp:$KEY` | Breach *source names* only; passwords are discarded. |
| dnsrecon / subfinder / theHarvester | Installed in the Docker image: PyPI `dnsrecon==0.10.1`, `theHarvester` 4.6.0 from git (no FastAPI/Playwright extras), official `subfinder` v2.17.0 linux amd64 binary | `dnsrecon -d DOMAIN -t std -j FILE`; `theHarvester -d DOMAIN -b crtsh,hackertarget,duckduckgo -l 100 -f FILE`; `subfinder -d DOMAIN -silent -oJ -o FILE -duc` | Run under the heavy-tool lock so they never overlap Maigret or Sherlock (512 MB cap). Python dns_lookup / crt.sh still run as well. |
| XposedOrNot | Free HTTP API, no key | `GET https://api.xposedornot.com/v1/breach-analytics?email=` (fallback `/v1/check-email/{email}`) | Breach names, years, data classes. 429s are reported as blocked. |
| mail_security | `dnspython` | MX, SPF TXT, `_dmarc`, common DKIM selectors | Letter grade and fix list. |
| web_security | `httpx` + stdlib `ssl` | HTTPS, HTTP→HTTPS redirect, cert issuer/expiry, security headers; capped HEAD of crt.sh hosts | Letter grade. Max 8 live-host checks. |
| github_profile | GitHub public API, unauthenticated (60/hr) | `GET https://api.github.com/users/{username}` | Name, bio, location, company, blog, public email, account age, repo count. |
| gravatar | Gravatar profile JSON | SHA-256 then MD5 of the lowercased email | Public display name / location if a profile exists. |
| Password leak check | Browser-only, HIBP Pwned Passwords k-anonymity | `https://api.pwnedpasswords.com/range/{5-char SHA-1 prefix}` | The password never reaches this server. |

Missing binaries are marked `unavailable`; the rest of the scan continues.

## Architecture

```
Browser  --login cookie-->  FastAPI (0.0.0.0:$PORT)
   |  polls GET /api/jobs/{id}        |
   v                                  v
on-screen report + PDF         asyncio adapters (concurrency 2)
                                      |
                    SQLite (DATABASE_PATH)  <----+
                    Gemini (optional httpx REST)
```

| File | Role |
| --- | --- |
| `app/main.py` | Routes, consent, rate limit, job orchestration, auth gate |
| `app/auth.py` | Password check, signed session cookie, login rate limit |
| `app/adapters.py` | CLI + Python adapters and parsers |
| `app/scoring.py` | 0–100 score, remediation, confidence notes |
| `app/ai.py` | Gemini REST call |
| `app/report.py` | PDF via fpdf2 |
| `app/db.py` | SQLite jobs and audit log |
| `static/index.html` | Dashboard (no build step) |
| `static/login.html` | Password page |
| `static/audit.html` | Audit log |
| `data/demo_result.json` | Fictional sample |
| `Dockerfile`, `render.yaml` | Cloud deploy |

### Exposure score (transparent rules)

The score starts at 0 and is capped at 100. Overlapping Sherlock and Maigret hits for the same URL are counted once. crt.sh and subfinder hostnames are unioned for the subdomain rule.

- **+2** per unique public username profile (cap 20)
- **+15** if the same handle is found on 5 or more sites
- **+3** per sensitive/high-visibility platform (cap 15)
- **+3** per holehe email registration (cap 18)
- **+8** if the email is tied to a sensitive category
- **+25** if h8mail / HIBP confirms a breach
- **+12** if WHOIS exposes a non-redacted contact email
- **+5** if WHOIS exposes a registrant / organization name
- **+8** if 5 or more public subdomains are found
- **+4** per harvested domain email (cap 16)
- **+3** per harvested person name (cap 9)

This is a teaching device, not a scientific risk model. Every rule that fired is listed in the report.

## Known limitations

- Username and email work reasonably well. Name-only search does not, and is not a primary input.
- Instagram, Facebook, and TikTok usually block unauthenticated scanners. A miss is not proof that an account does not exist.
- Sherlock can produce soft-404 false positives. A single hit is weak evidence.
- holehe modules often rate-limit or break, especially from a cloud IP.
- HIBP v3 email search needs a paid API key. Breach dumps are never downloaded.
- WHOIS is often privacy-redacted.
- Gemini may be rate-limited. The app skips the summary and still shows findings.
- Render free tier sleeps; SQLite does not survive a free-tier redeploy.
- This is a single-password class dashboard, not a multi-user production service.

## Legal and ethics note (India) — not legal advice

Public-source OSINT can be lawful, but aggregating personal data is still sensitive.

- The **Digital Personal Data Protection Act, 2023**, section 3(c)(ii), excludes personal data that the **Data Principal themselves** (or a person legally required to make it public) has made publicly available. That is a narrow exception, not a licence to collect “anything on Google.” Text: [DPDP Act 2023 (PDF)](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf).
- The **Information Technology Act, 2000**, sections 43 and 66 cover unauthorized access and bypassing controls; section 66C covers identity misuse.
- Unofficial recovery-flow checks (holehe) and any login-walled scraping may violate a platform’s terms of service. This app does not log in, does not bypass access controls, and does not ingest leaked or dark-web dumps.
- Use it only on **your own** identifiers, or on a willing classmate who has ticked the same consent understanding. Keep the dashboard password private.

## 5-minute demo script (viva)

Prep: have the Render URL (or local Docker) already running and the password ready. Prefer a live scan of **your own** handle. Keep **Load demo result** as a fallback.

1. **0:00–0:40 — Frame the project.** Open the site, log in, and say: *this is a digital-footprint self-audit, not a people-finder. Public sources only, consent required, password-protected.* Point at the consent box, tool-availability chips, and known limitations.
2. **0:40–1:00 — Inputs.** Explain why username and email come first, why domain is optional, and why name/city are “not searched.”
3. **1:00–3:00 — Live scan or demo.** Tick consent, enter your own username (and email if you are comfortable). Talk over per-tool statuses. If a cloud IP is blocked or a tool is thin, click **Load demo result** and say the bundled dataset is a fictional person, clearly labelled.
4. **3:00–4:20 — Report.** Walk through the score and the rules that fired, one confidence note (same handle ≠ verified identity), the AI summary or “skipped, no API key,” two remediation items, and download the PDF.
5. **4:20–5:00 — Accountability.** Open `/audit`. Show that the log stores input *types* and tools, not the email itself. Close with the legal line: DPDP’s public-data exception is narrow; we do not scrape login-walled sites or ingest dumps.

## Ten viva questions (with short answers)

**1. Why can’t this tool take any name and return someone’s Instagram?**
A common name matches too many people. Instagram and Facebook also block unauthenticated automation. Username and email are the high-signal inputs; name is only a display filter.

**2. Why did you not just run every OSINT tool in Kali?**
Most Kali OSINT tools are for domains and networks, not people. This dashboard is meant to run in the cloud without a VM, so it uses pip-installable CLIs plus pure-Python WHOIS, DNS, and crt.sh. Optional Kali binaries are used only if present.

**3. Is holehe “hacking” someone’s email?**
No. It probes public signup or password-recovery endpoints to infer whether an account exists. It does not log in or read a mailbox. It may still violate a site’s terms of service, which is why we require consent and use it only for a self-audit.

**4. Why do you parse Sherlock’s CSV and refuse `--json`?**
In current Sherlock, `--json` loads a site-list file. It does not export results. The documented export is `--csv`. `exists=Claimed` is a hit.

**5. How is the exposure score calculated?**
It is a transparent sum of documented rules, capped at 100. Overlapping Sherlock and Maigret hits count once. crt.sh and subfinder hostnames are unioned. Every point is listed in the report. It is a teaching score, not a scientific risk model.

**6. What is the difference between `not_found`, `blocked`, `unavailable`, and `error`?**
`not_found` means the tool ran and reported no hit. `blocked` means the site rate-limited or served a WAF page — the account may still exist. `unavailable` means the binary or key is missing. `error` means a timeout or a crash. A miss after a block is not proof of absence.

**7. Is this legal in India?**
We are not giving legal advice. Public-source collection can be lawful, but DPDP Act 2023 s.3(c)(ii) is a narrow exception for data the person themselves made public. IT Act ss.43/66 cover unauthorized access and bypassing controls. We require consent, a login password, no login-wall bypass, and no dumps.

**8. What happens if Gemini is missing or rate-limited?**
The scan still finishes. The AI box explains `skipped_no_key`, `skipped_429`, or `skipped_error`. The model is prompted to summarize only the given facts and never invent profiles.

**9. Why a password, and why can the audit log disappear on Render?**
The dashboard is on the public internet, so a signed session cookie protects it. The audit log still records consent and input *types*, not raw secrets. On Render’s free tier the disk is ephemeral: a redeploy can wipe SQLite. That is a hosting limit, not a feature to rely on for evidence.

**10. Your live scan failed in the viva. Now what?**
Click **Load demo result**. It loads bundled sample findings for a fictional person (`Alex Rivera` / `alexrivera_demo`), clearly labelled “SAMPLE DATA.” Then explain *why* the live tool failed (cloud IP blocked, sleep, rate limit, missing key) — that answer is part of the design.

## Project layout

```
footprint-audit/
  Dockerfile              # python:3.12-slim image for Render
  render.yaml             # free web service blueprint
  app/                    # FastAPI backend
  static/                 # login, dashboard, audit pages
  data/demo_result.json
  tests/
  requirements.txt
  run.sh
  setup_kali.sh           # optional, Kali only
  .env.example
  README.md
```

## License and notice

Written as an educational coursework project. The bundled demo dataset is fictional. The authors of Sherlock, Maigret, holehe, theHarvester, dnsrecon, subfinder, h8mail, Have I Been Pwned, and crt.sh own their respective tools and trademarks. This project is not affiliated with them.
