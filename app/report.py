"""PDF report export using fpdf2."""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from fpdf import FPDF

FONT_DIR_CANDIDATES = [
    Path("/usr/share/fonts/truetype/dejavu"),
    Path("/usr/share/fonts/truetype/liberation"),
    Path("/usr/share/fonts/truetype/freefont"),
]


def _find_fonts() -> tuple[Path, Path] | None:
    pairs = [
        ("DejaVuSans.ttf", "DejaVuSans-Bold.ttf"),
        ("LiberationSans-Regular.ttf", "LiberationSans-Bold.ttf"),
        ("FreeSans.ttf", "FreeSansBold.ttf"),
    ]
    for directory in FONT_DIR_CANDIDATES:
        if not directory.is_dir():
            continue
        for regular, bold in pairs:
            r = directory / regular
            b = directory / bold
            if r.exists() and b.exists():
                return r, b
    return None


def _parse_created(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    text = value.replace("T", " ").replace("Z", " UTC")
    return text


class AuditPDF(FPDF):
    def __init__(self) -> None:
        super().__init__(format="A4", unit="mm")
        self.is_demo = False
        fonts = _find_fonts()
        if fonts:
            self.add_font("Body", "", str(fonts[0]))
            self.add_font("Body", "B", str(fonts[1]))
            self.font_family_name = "Body"
            self.unicode_ok = True
        else:
            self.font_family_name = "Helvetica"
            self.unicode_ok = False
        self.set_auto_page_break(auto=True, margin=18)
        self.set_title("Digital Footprint Self-Audit Report")
        self.set_author("Digital Footprint Self-Audit Platform")
        # Subject/keywords stay in the PDF Info dict as plain ASCII so a
        # demo report can be identified even when body text is in a compressed
        # or custom-encoded font stream.
        self.set_subject("Self-audit report")
        self.set_keywords("digital footprint self-audit")

    def header(self) -> None:
        self.set_font(self.font_family_name, "B", 9)
        self.set_text_color(40, 55, 70)
        label = "SAMPLE DATA — fictional demo" if self.is_demo else "Self-audit report"
        mid = self.epw / 2
        self.cell(mid, 6, "Digital Footprint Self-Audit Platform", align="L")
        self.set_font(self.font_family_name, "", 8)
        self.cell(mid, 6, label, align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(46, 224, 180)
        self.set_line_width(0.5)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)
        self.set_x(self.l_margin)

    def footer(self) -> None:
        self.set_y(-14)
        self.set_draw_color(200, 210, 220)
        self.set_line_width(0.2)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)
        self.set_font(self.font_family_name, "", 7)
        self.set_text_color(100, 110, 120)
        self.cell(
            0,
            4,
            "For educational self-audit use only. Public sources. Not legal advice.  |  Page "
            + str(self.page_no()),
            align="C",
        )

    def _safe(self, text: Any) -> str:
        value = "" if text is None else str(text)
        if self.unicode_ok:
            return value
        return value.encode("latin-1", "replace").decode("latin-1")

    def heading(self, text: str) -> None:
        self.ln(2)
        self.set_font(self.font_family_name, "B", 13)
        self.set_text_color(16, 32, 48)
        self.cell(0, 8, self._safe(text), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(180, 200, 210)
        self.set_line_width(0.2)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def _write(self, text: str, size: int, bold: bool, color: tuple[int, int, int], leading: float) -> None:
        self.set_x(self.l_margin)
        self.set_font(self.font_family_name, "B" if bold else "", size)
        self.set_text_color(*color)
        # Width must be the usable page width. A leftover x at the right margin
        # makes multi_cell(0, ...) raise "not enough horizontal space".
        self.multi_cell(self.epw, leading, self._safe(text))
        self.set_x(self.l_margin)
        self.ln(1)

    def body(self, text: str, size: int = 10, bold: bool = False) -> None:
        self._write(text, size, bold, (30, 40, 50), 5)

    def muted(self, text: str) -> None:
        self._write(text, 9, False, (90, 100, 110), 4.5)

    def bullet(self, text: str) -> None:
        self._write("- " + text, 10, False, (30, 40, 50), 5)


def build_pdf(job: dict[str, Any]) -> bytes:
    pdf = AuditPDF()
    pdf.is_demo = bool(job.get("is_demo"))
    if pdf.is_demo:
        pdf.set_title("SAMPLE DATA - Digital Footprint Self-Audit (fictional demo)")
        pdf.set_subject("SAMPLE DATA - fictional person, not a real audit")
        pdf.set_keywords("SAMPLE DATA fictional demo")
    pdf.add_page()

    if job.get("is_demo"):
        pdf.set_fill_color(255, 243, 200)
        pdf.set_text_color(120, 80, 0)
        pdf.set_font(pdf.font_family_name, "B", 11)
        pdf.multi_cell(
            0,
            7,
            pdf._safe(
                "SAMPLE DATA — This report uses a bundled fictional person "
                "(Alex Rivera / alexrivera_demo). It is not a real audit."
            ),
            fill=True,
        )
        pdf.ln(3)

    pdf.set_font(pdf.font_family_name, "B", 20)
    pdf.set_text_color(16, 32, 48)
    pdf.cell(0, 10, "Digital Footprint Self-Audit", new_x="LMARGIN", new_y="NEXT")
    pdf.muted(f"Generated {_parse_created(job.get('created_at'))}  •  Job {job.get('id', '')}")

    inputs = job.get("inputs") or {}
    present = []
    if inputs.get("username"):
        present.append(f"Username: {inputs['username']}")
    if inputs.get("email"):
        present.append(f"Email: {inputs['email']}")
    if inputs.get("domain"):
        present.append(f"Domain: {inputs['domain']}")
    pdf.body("  |  ".join(present) or "No identifiers recorded.", bold=True)
    if inputs.get("name") or inputs.get("city"):
        pdf.muted(
            "Display filter only (not searched): "
            + ", ".join(x for x in [inputs.get("name"), inputs.get("city")] if x)
        )
    pdf.muted(
        "Consent recorded: "
        + ("yes — search limited to self or a person who has given consent, public sources only."
           if job.get("consent")
           else "no")
    )

    score = job.get("score")
    label = job.get("score_label") or ""
    pdf.heading("Exposure score")
    if score is None:
        pdf.body("Score not yet available (scan still running).")
    else:
        pdf.body(f"{score} / 100  —  {label}", bold=True, size=16)
        pdf.muted(
            "This is a transparent teaching score, not a scientific risk rating. "
            "Points come only from the rules below."
        )
        for item in job.get("score_breakdown") or []:
            pdf.bullet(f"+{item.get('points', 0)}  {item.get('rule')}: {item.get('detail')}")
        if not job.get("score_breakdown"):
            pdf.muted("No scoring rules fired (small public footprint, or tools found nothing).")

    pdf.heading("AI summary")
    ai_status = job.get("ai_status") or ""
    if job.get("is_demo") and job.get("ai_summary"):
        pdf.body(job["ai_summary"])
        pdf.muted("Sample narrative bundled with the demo dataset (not generated live unless a key was used).")
    elif ai_status == "ok" and job.get("ai_summary"):
        pdf.body(job["ai_summary"])
        pdf.muted("Generated from the structured findings only; the model was instructed not to invent facts.")
    elif ai_status == "skipped_no_key":
        pdf.muted("No GEMINI_API_KEY configured. Findings and the score below still stand.")
    elif ai_status == "skipped_429":
        pdf.muted("Gemini rate-limited this request (HTTP 429). The rest of the report is complete.")
    elif ai_status == "skipped_error":
        pdf.muted("Gemini was unreachable or returned an error. The rest of the report is complete.")
    else:
        pdf.muted("AI summary was not produced.")

    diff = job.get("diff") or {}
    if diff.get("has_previous"):
        pdf.heading("Changes since last scan")
        when = diff.get("previous_at") or "an earlier scan"
        pdf.muted(f"Compared with the previous complete scan at {when}.")
        new_items = diff.get("new") or []
        removed = diff.get("removed") or []
        if new_items:
            pdf.body(f"{len(new_items)} new finding(s):", bold=True)
            for item in new_items[:20]:
                pdf.bullet(f"[{item.get('source')}] {item.get('value') or item.get('url') or ''}")
        if removed:
            pdf.body(f"{len(removed)} finding(s) no longer present:", bold=True)
            for item in removed[:20]:
                pdf.bullet(f"[{item.get('source')}] {item.get('value') or item.get('url') or ''}")
        if not new_items and not removed:
            pdf.muted("No added or removed findings since the last scan of these identifiers.")

    pdf.heading("Confidence notes")
    notes = job.get("confidence_notes") or []
    if notes:
        for note in notes:
            pdf.bullet(note)
    else:
        pdf.muted("No additional confidence notes.")

    pdf.heading("Tool status")
    tools = job.get("tools") or job.get("progress") or {}
    if tools:
        for name, info in tools.items():
            info = info or {}
            status = info.get("status") or "unknown"
            message = info.get("message") or ""
            pdf.bullet(f"{name}: {status}" + (f" — {message}" if message else ""))
    else:
        pdf.muted("No tools recorded.")

    pdf.heading("Findings")
    findings = job.get("findings") or []
    found = [f for f in findings if (f.get("status") == "found")]
    blocked = [f for f in findings if (f.get("status") == "blocked")]
    if not findings:
        pdf.muted("No findings were parsed.")
    else:
        pdf.muted(f"{len(found)} found, {len(blocked)} blocked, {len(findings)} rows total (negatives omitted where possible).")
        for f in findings:
            if f.get("status") not in {"found", "blocked", "error"}:
                # Skip not_found rows in the PDF to keep it readable.
                continue
            line = f"[{f.get('source')}] ({f.get('input_type')}) {f.get('value') or ''}  [{f.get('status')}]"
            if f.get("url"):
                line += f"  {f.get('url')}"
            if f.get("confidence"):
                line += f"  (confidence: {f.get('confidence')})"
            pdf.bullet(line)

    pdf.heading("Remediation checklist")
    rem = job.get("remediation") or []
    if rem:
        for item in rem:
            title = item.get("title") or ""
            detail = item.get("detail") or ""
            priority = (item.get("priority") or "").upper()
            pdf.body(f"[{priority}] {title}", bold=True)
            if detail:
                pdf.muted(detail)
    else:
        pdf.muted("No remediation items.")

    pdf.heading("Legal and ethics (India) — not legal advice")
    pdf.body(
        "This tool searches only public sources and is intended for a self-audit, "
        "or for a classmate who has given informed consent. The Digital Personal "
        "Data Protection Act, 2023, section 3(c)(ii) has a narrow exception for "
        "data that the Data Principal themselves (or someone legally required to) "
        "made publicly available — it is not a licence to collect 'anything on Google'. "
        "The Information Technology Act, 2000, sections 43 and 66 cover unauthorized "
        "access and bypassing controls; section 66C covers identity misuse. This app "
        "does not log in to third-party accounts, does not ingest breach dumps, and "
        "is intended only for consented self-audits of identifiers you own. Platform terms of service may still prohibit some "
        "automated checks. When in doubt, search only your own identifiers."
    )

    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()
