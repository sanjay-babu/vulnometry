"""Annotated Excel output: one row per scanner row, plus the lists to act on.

Findings has one row per row of the scanner export, each judged Fix, Schedule, Accept or Not
analysed. Manual review, Engineering - fix, DevSecOps - suppress and Accepted are filters of it; Action Plan and By Owner
summarise it; Method explains it.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from ..assessment import JUDGMENT_ORDER, NOT_ANALYSED, export_rows, suppression
from ..schema import Assessment

VERDICT_FILL = {
    "Contain": PatternFill("solid", fgColor="C0392B"),
    "Remediate": PatternFill("solid", fgColor="E67E22"),
    "Schedule": PatternFill("solid", fgColor="F1C40F"),
    "Accept": PatternFill("solid", fgColor="BDC3C7"),
    "Fix": PatternFill("solid", fgColor="C0392B"),
}
VERDICT_FONT = {
    "Contain": Font(color="FFFFFF", bold=True),
    "Remediate": Font(color="FFFFFF", bold=True),
    "Schedule": Font(color="4A3B00"),
    "Accept": Font(color="4A4A4A"),
    "Fix": Font(color="FFFFFF", bold=True),
}
NOT_ANALYSED_FILL = PatternFill("solid", fgColor="D6EAF8")
NOT_ANALYSED_FONT = Font(color="1B4F72", bold=True)

HEADER_FILL = PatternFill("solid", fgColor="1F3A53")
HEADER_FONT = Font(color="FFFFFF", bold=True, size=11)
TITLE_FONT = Font(bold=True, size=14)
NOTE_FONT = Font(color="7F8C8D", size=10)
THIN = Side(style="thin", color="D5D8DC")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

_CODE_PATH_SHORT = {"reachable": "Reachable", "unreachable": "No path"}
_FACING_SHORT = {"internet-facing": "External", "internal-only": "Internal", "exposure unknown": "Unknown"}
_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_BANDS = ["Critical", "High", "Medium", "Low", "Other"]
_URL_COLUMNS = {"Project URL", "Issue URL"}
_PAINTED = {"Judgment", "Verdict"}
_WRAPPED = {"Reason", "Rationale", "Directive", "Evidence gaps", "Reopen triggers"}

REOPEN_DEFAULT = ("EPSS >= 0.10  |  added to CISA KEV  |  a working public exploit appears  |  "
                  "the asset's internet exposure or tier changes  |  review-by date reached")


def _item(rec: dict, fn, default=""):
    item = rec["item"]
    if item is None:
        return default
    value = fn(item)
    return default if value is None else value


def _epss(item: Assessment):
    p = item.probability.probability
    return round(p * 100, 2) if p is not None else ""


def _cvss(item: Assessment):
    severity = item.weakness.primary_severity()
    return severity.base_score if severity and severity.base_score is not None else ""


# Every column any sheet can show, by name. A sheet is a list of (name, width).
FIELDS = {
    "Export row": lambda r: r["row"] or "",
    "Judgment": lambda r: r["judgment"],
    "Verdict": lambda r: r["verdict"],
    "BEI": lambda r: _item(r, lambda i: i.exposure.index),
    "Due by": lambda r: _item(r, lambda i: i.due_by) if r["analysed"] else "",
    "SLA days": lambda r: _item(r, lambda i: i.sla_days) if r["analysed"] else "",
    "Scanner severity": lambda r: r["scanner_severity"],
    "CVE": lambda r: ", ".join(r["cves"]),
    "Issue ID": lambda r: r["issue_id"],
    "Issue type": lambda r: r.get("issue_type", ""),
    "Title": lambda r: r["title"],
    "Project": lambda r: r["project"],
    "Target": lambda r: r["target"],
    "Asset": lambda r: _item(r, lambda i: i.asset),
    "Owner": lambda r: _item(r, lambda i: i.owner),
    "Business unit": lambda r: _item(r, lambda i: i.business_unit),
    "Environment": lambda r: _item(r, lambda i: i.environment),
    "Internet": lambda r: _item(r, lambda i: _FACING_SHORT.get(i.exposure_facing(), "")),
    "Tier": lambda r: _item(r, lambda i: i.tier),
    "Data class": lambda r: _item(r, lambda i: i.data_classification),
    "Analysis": lambda r: "Analysed" if r["analysed"] else NOT_ANALYSED,
    "Not analysed because": lambda r: r["why_not"],
    "Duplicate of row": lambda r: r["duplicate_of"] or "",
    "Project URL": lambda r: r["project_url"],
    "Issue URL": lambda r: r["issue_url"],
    "Threat": lambda r: _item(r, lambda i: i.exposure.threat),
    "Reach": lambda r: _item(r, lambda i: i.exposure.reachability),
    "Code path": lambda r: _item(r, lambda i: _CODE_PATH_SHORT.get(i.code_reachability, "")),
    "Consequence": lambda r: _item(r, lambda i: i.exposure.consequence),
    "CVSS": lambda r: _item(r, _cvss),
    "EPSS %": lambda r: _item(r, _epss),
    "EPSS date": lambda r: _item(r, lambda i: i.probability.as_of),
    "KEV": lambda r: _item(r, lambda i: "Yes" if i.exploitation.confirmed else ""),
    "Ransomware": lambda r: _item(r, lambda i: "Yes" if i.exploitation.ransomware_linked else ""),
    "Component": lambda r: _item(r, lambda i: i.source_component),
    "Fixed in": lambda r: _item(r, lambda i: ", ".join(i.fixes[:3])),
    "Scanner fixability": lambda r: _item(r, lambda i: i.scanner_fixability),
    "Scanner exploit maturity": lambda r: _item(r, lambda i: i.scanner_exploit_maturity),
    "Confidence": lambda r: _item(r, lambda i: i.exposure.confidence),
    "Evidence gaps": lambda r: _item(r, lambda i: " | ".join(i.gaps) or "none"),
    "Model": lambda r: _item(r, lambda i: i.exposure.model_version),
    "Assessed (UTC)": lambda r: _item(r, lambda i: i.measured_at),
    "Rationale": lambda r: r["reason"],
    "Reason": lambda r: r["reason"],
    "Directive": lambda r: _item(r, lambda i: i.directive) if r["analysed"] else (
        "Map this project to an asset in the inventory and re-run for a real verdict. Until then, "
        "triage it on the scanner's severity." if r["item"] is not None else "Triage on the scanner's severity."),
    "Decision": lambda r: ("Accept risk; suppress in scanner" if suppression(r)[0]
                           else f"Accept risk; {suppression(r)[1]}"),
    "Suppress in scanner": lambda r: "Yes" if suppression(r)[0] else suppression(r)[1][:1].upper() + suppression(r)[1][1:],
    "Suppress until": lambda r: r.get("suppress_until", ""),
    "Ignore reason": lambda r: r.get("ignore_reason", ""),
    "Ignore type": lambda r: "temporary-ignore",
    "Decided by": lambda r: "",
    "Decision date": lambda r: "",
    "Review by": lambda r: "",
    "Reopen triggers": lambda r: REOPEN_DEFAULT,
    "Ticket": lambda r: "",
}

IDENTITY = [("Export row", 8), ("Judgment", 13), ("Verdict", 13), ("BEI", 8), ("Due by", 12),
            ("Scanner severity", 11), ("Issue type", 13), ("CVE", 18), ("Issue ID", 30), ("Title", 32),
            ("Project", 30),
            ("Target", 24), ("Asset", 24), ("Owner", 26)]
LINKS = [("Project URL", 30), ("Issue URL", 30)]

FINDINGS_COLUMNS = [
    *IDENTITY, ("Internet", 10), ("Analysis", 13), ("Not analysed because", 18), ("Duplicate of row", 9),
    *LINKS, ("SLA days", 9), ("Threat", 9), ("Reach", 9), ("Code path", 11), ("Consequence", 12),
    ("CVSS", 7), ("EPSS %", 9), ("EPSS date", 12), ("KEV", 6), ("Ransomware", 11), ("Component", 22),
    ("Fixed in", 28), ("Scanner fixability", 14), ("Scanner exploit maturity", 14), ("Confidence", 11),
    ("Business unit", 18),
    ("Environment", 13),
    ("Rationale", 90), ("Directive", 60),
]
REVIEW_COLUMNS = [*IDENTITY, ("Not analysed because", 18), *LINKS, ("Reason", 90), ("Directive", 60)]
FIX_COLUMNS = [*IDENTITY, ("Fixed in", 30), ("Scanner fixability", 14), *LINKS, ("Reason", 90),
               ("Directive", 60)]
ENGINEERING_COLUMNS = [*IDENTITY, ("Not analysed because", 18), ("Fixed in", 30), ("Scanner fixability", 14),
                       *LINKS, ("Reason", 90), ("Directive", 60)]
SUPPRESS_COLUMNS = [
    ("Export row", 8), ("Issue ID", 32), ("Issue URL", 34), ("Project", 30), ("Target", 24), ("Project URL", 30),
    ("Scanner severity", 11), ("Issue type", 13), ("CVE", 18), ("BEI", 8), ("Asset", 24), ("Owner", 26),
    ("Ignore type", 15), ("Suppress until", 13), ("Ignore reason", 70), ("Rationale", 90),
    ("Decided by", 16), ("Decision date", 14), ("Ticket", 16),
]
ACCEPT_COLUMNS = [
    *IDENTITY, ("Suppress in scanner", 26), *LINKS, ("Threat", 8), ("Reach", 8), ("Code path", 10), ("Consequence", 9), ("Internet", 11),
    ("Tier", 6), ("Data class", 14), ("EPSS %", 9), ("EPSS date", 12), ("KEV", 9), ("CVSS", 7),
    ("Fixed in", 22), ("Scanner fixability", 14), ("Scanner exploit maturity", 14), ("Confidence", 11),
    ("Rationale", 95), ("Evidence gaps", 40), ("Model", 10),
    ("Assessed (UTC)", 22), ("Decision", 26), ("Decided by", 16), ("Decision date", 14), ("Review by", 14),
    ("Reopen triggers", 60), ("Ticket", 16),
]


def _style_header(sheet, row_index: int, count: int) -> None:
    for column in range(1, count + 1):
        cell = sheet.cell(row=row_index, column=column)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(vertical="center", wrap_text=True)
        cell.border = BORDER


def _widths(sheet, columns) -> None:
    for index, (_, width) in enumerate(columns, start=1):
        sheet.column_dimensions[get_column_letter(index)].width = width


def _paint(cell, label: str) -> None:
    if label in VERDICT_FILL:
        cell.fill, cell.font = VERDICT_FILL[label], VERDICT_FONT[label]
    elif label == NOT_ANALYSED:
        cell.fill, cell.font = NOT_ANALYSED_FILL, NOT_ANALYSED_FONT


def _write_records(sheet, header_row: int, columns, records: list[dict]) -> None:
    names = [name for name, _ in columns]
    for index, name in enumerate(names, start=1):
        sheet.cell(row=header_row, column=index, value=name)
    _style_header(sheet, header_row, len(names))
    getters = [FIELDS[name] for name in names]
    for offset, rec in enumerate(records, start=1):
        r = header_row + offset
        for column, (name, get) in enumerate(zip(names, getters, strict=True), start=1):
            value = get(rec)
            cell = sheet.cell(row=r, column=column, value=value)
            cell.border = BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=name in _WRAPPED)
            if name in _PAINTED:
                _paint(cell, value)
            elif name in _URL_COLUMNS and isinstance(value, str) and value.startswith(("http://", "https://")):
                cell.hyperlink = value
                cell.font = Font(color="1F5FAD", underline="single")
    _widths(sheet, columns)
    sheet.freeze_panes = sheet.cell(row=header_row + 1, column=2)
    if records:
        sheet.auto_filter.ref = f"A{header_row}:{get_column_letter(len(names))}{header_row + len(records)}"


def _band(value: str) -> str:
    return value if value in _SEVERITY_ORDER else "Other"


def _count_table(sheet, top: int, groups: list[tuple[str, list[dict]]]) -> int:
    """Group x scanner severity, with a total that reconciles to the rows listed. Returns the next free row."""
    for col, name in enumerate(["", *_BANDS, "Total"], start=1):
        sheet.cell(row=top, column=col, value=name)
    _style_header(sheet, top, len(_BANDS) + 2)
    for offset, (label, recs) in enumerate(groups, start=1):
        r = top + offset
        bands = [_band(rec["scanner_severity"]) for rec in recs]
        for col, value in enumerate([label, *[bands.count(b) for b in _BANDS], len(bands)], start=1):
            sheet.cell(row=r, column=col, value=value).border = BORDER
        _paint(sheet.cell(row=r, column=1), label.split(" (")[0])
    r = top + len(groups) + 1
    every = [rec for _, recs in groups for rec in recs]
    sheet.cell(row=r, column=1, value="Total").font = Font(bold=True)
    for col, band in enumerate(_BANDS, start=2):
        sheet.cell(row=r, column=col, value=sum(1 for rec in every if _band(rec["scanner_severity"]) == band)
                   ).font = Font(bold=True)
    sheet.cell(row=r, column=len(_BANDS) + 2, value=len(every)).font = Font(bold=True)
    return r + 2


def _order(records: list[dict]) -> list[dict]:
    rank = {j: n for n, j in enumerate(JUDGMENT_ORDER)}
    return sorted(records, key=lambda r: (rank.get(r["judgment"], 9), -(_item(r, lambda i: i.exposure.index, 0)),
                                          _SEVERITY_ORDER.get(r["scanner_severity"], 4), r["row"] or 0))


def _title(sheet, title: str, note: str) -> None:
    sheet.cell(row=1, column=1, value=title).font = TITLE_FONT
    sheet.cell(row=2, column=1, value=note).font = NOTE_FONT


def _verdict_groups(records: list[dict]) -> list[tuple[str, list[dict]]]:
    return [
        ("Contain", [r for r in records if r["verdict"] == "Contain"]),
        ("Remediate", [r for r in records if r["verdict"] == "Remediate"]),
        ("Schedule", [r for r in records if r["verdict"] == "Schedule"]),
        ("Accept", [r for r in records if r["verdict"] == "Accept"]),
        ("Not analysed (no inventory match)", [r for r in records if r["why_not"] == "No inventory match"]),
        ("Not analysed (insufficient data)", [r for r in records if r["why_not"] == "Insufficient data"]),
        ("Not analysed (licence issue)", [r for r in records if r["why_not"] == "Licence issue"]),
        ("Not analysed (no CVE)", [r for r in records if r["why_not"] == "No CVE identifier"]),
    ]


def _findings_sheet(workbook: Workbook, records: list[dict]) -> None:
    sheet = workbook.active
    sheet.title = "Findings"
    _title(sheet, "Exposure assessment: one row per scanner row",
           f"Generated {date.today().isoformat()} · {len(records)} rows · judgment per row: Fix, Schedule, Accept "
           "or Not analysed · Business Exposure Index 0-1000, higher means act sooner")
    header_row = _count_table(sheet, 4, _verdict_groups(records)) + 1
    _write_records(sheet, header_row, FINDINGS_COLUMNS, _order(records))


def _manual_review_sheet(workbook: Workbook, records: list[dict]) -> None:
    review = [r for r in records if r["judgment"] == NOT_ANALYSED]
    sheet = workbook.create_sheet("Manual review", 1)
    _title(sheet, "Manual review: rows there was not enough context to judge",
           f"{len(review)} row(s): the project matched no asset in the inventory, the data was too thin to "
           "accept the risk, the row is a licence issue, or it has no CVE. "
           "Each keeps the scanner's severity and links. Filter and hand over.")
    groups = [g for g in _verdict_groups(records) if g[0].startswith(NOT_ANALYSED)]
    header_row = _count_table(sheet, 4, groups) + 1
    _write_records(sheet, header_row, REVIEW_COLUMNS, _order(review))


def _engineering_sheet(workbook: Workbook, records: list[dict]) -> None:
    """For engineering: everything that is not an accepted risk. Rows to fix by due date first, then the
    rows vulnometry could not judge, by scanner severity, so nothing unreviewed drops out of sight."""
    fix = [r for r in records if r["judgment"] in ("Fix", "Schedule")]
    unjudged = [r for r in records if r["judgment"] == NOT_ANALYSED]
    sheet = workbook.create_sheet("Engineering - fix", 2)
    _title(sheet, "Engineering: rows to fix, and rows not analysed",
           f"{len(fix)} row(s) to fix, by due date: Fix = Contain or Remediate (ahead of the routine cycle), "
           "Schedule = the next planned maintenance window. Then "
           f"{len(unjudged)} row(s) vulnometry could not judge (no inventory match, too little data, a licence "
           "issue, or no CVE): treat these on the scanner's severity until they are analysed. 'Fixed in' is the "
           "version to upgrade to for the package this scanner issue is about.")
    groups = [g for g in _verdict_groups(records) if g[0] in ("Contain", "Remediate", "Schedule")
              or g[0].startswith(NOT_ANALYSED)]
    header_row = _count_table(sheet, 4, groups) + 1
    ordered = sorted(fix, key=lambda r: (_item(r, lambda i: i.due_by) or "9999-12-31",
                                         -_item(r, lambda i: i.exposure.index, 0)))
    ordered += sorted(unjudged, key=lambda r: (_SEVERITY_ORDER.get(r["scanner_severity"], 4), r["row"] or 0))
    _write_records(sheet, header_row, ENGINEERING_COLUMNS, ordered)


def _devsecops_sheet(workbook: Workbook, records: list[dict], review_days: int) -> None:
    """For DevSecOps: the accepted rows to suppress in the scanner, each with its expiry and reason."""
    accepted = [r for r in records if r["judgment"] == "Accept"]
    rows = [r for r in accepted if suppression(r)[0]]
    for rec in rows:
        item = rec["item"]
        assessed = (item.measured_at or date.today().isoformat())[:10]
        until = (date.fromisoformat(assessed) + timedelta(days=review_days)).isoformat()
        rec["suppress_until"] = until
        why = rec["reason"].split(" — ", 1)[-1].split(" Context:")[0].rstrip(".")
        rec["ignore_reason"] = (f"Risk accepted: vulnometry {item.exposure.model_version} Accept "
                                f"(BEI {item.exposure.index:.0f}) on {assessed}: {why}. Re-review by {until}.")[:500]
    kept_open = len(accepted) - len(rows)
    sheet = workbook.create_sheet("DevSecOps - suppress", 3)
    _title(sheet, "DevSecOps: accepted rows to suppress in the scanner",
           f"{len(rows)} row(s) to suppress as a temporary ignore until the date shown ({review_days} days, the "
           f"next review). {kept_open} more accepted row(s) stay open in the scanner because its own evidence "
           "argues against hiding them (call path found, mature exploit, or CISA KEV); see 'Accepted'. Rows "
           "judged Not analysed are never suppressed. Fill 'Decided by' and 'Decision date' when signed off.")
    _write_records(sheet, 4, SUPPRESS_COLUMNS, _order(rows))


def _accepted_sheet(workbook: Workbook, records: list[dict]) -> None:
    accepted = [r for r in records if r["judgment"] == "Accept"]
    held = [r for r in records if r["item"] is not None and not r["analysed"]
            and r["item"].exposure.verdict == "Accept"]
    no_match = sum(1 for r in held if r["why_not"] == "No inventory match")
    thin = sum(1 for r in held if r["why_not"] == "Insufficient data")
    sheet = workbook.create_sheet("Accepted")
    _title(sheet, "Accepted risk — rationale and sign-off",
           f"{len(accepted)} row(s) judged Accept. The rationale columns are produced by the model; fill the "
           "Decision..Ticket columns and keep this as the audit record."
           + (f" {len(held)} more scored Accept but are left off (Not analysed: {no_match} with no inventory "
              f"match, {thin} with too little data to accept), so they cannot be signed off or suppressed "
              "by mistake." if held else ""))
    _write_records(sheet, 4, ACCEPT_COLUMNS, _order(accepted))


def _action_sheet(workbook: Workbook, records: list[dict]) -> None:
    actionable = [r for r in records if r["judgment"] == "Fix"]
    sheet = workbook.create_sheet("Action Plan")
    _title(sheet, "What has to happen, and by when",
           f"{len(actionable)} of {len(records)} rows judged Fix (Contain or Remediate). Sorted by due date.")
    columns = [("Due by", 12), ("Verdict", 12), ("CVE", 18), ("Scanner severity", 11), ("Asset", 24),
               ("Project", 30), ("Owner", 28), ("Issue URL", 30), ("Directive", 70)]
    ordered = sorted(actionable, key=lambda r: (_item(r, lambda i: i.due_by) or "9999-12-31",
                                                -_item(r, lambda i: i.exposure.index, 0)))
    _write_records(sheet, 4, columns, ordered)


def _owner_sheet(workbook: Workbook, records: list[dict]) -> None:
    sheet = workbook.create_sheet("By Owner")
    _title(sheet, "Workload by owner", "Rows per owner and judgment, and how urgent their share is.")
    tally: dict[str, dict] = {}
    for rec in records:
        owner = _item(rec, lambda i: i.owner) or "unassigned"
        bucket = tally.setdefault(owner, {"Contain": 0, "Remediate": 0, "Schedule": 0, "Accept": 0,
                                          NOT_ANALYSED: 0, "exposure": 0.0, "soonest": ""})
        bucket[rec["verdict"]] = bucket.get(rec["verdict"], 0) + 1
        if rec["analysed"]:
            bucket["exposure"] += _item(rec, lambda i: i.exposure.index, 0)
            due = _item(rec, lambda i: i.due_by)
            if due and (not bucket["soonest"] or due < bucket["soonest"]):
                bucket["soonest"] = due
    columns = [("Owner", 32), ("Contain", 10), ("Remediate", 11), ("Schedule", 10), ("Accept", 9),
               (NOT_ANALYSED, 13), ("Total exposure", 15), ("Earliest due", 13)]
    header_row = 4
    for index, (name, _) in enumerate(columns, start=1):
        sheet.cell(row=header_row, column=index, value=name)
    _style_header(sheet, header_row, len(columns))
    ordered = sorted(tally.items(), key=lambda kv: (-kv[1]["Contain"], -kv[1]["exposure"]))
    for offset, (owner, bucket) in enumerate(ordered):
        row = header_row + 1 + offset
        for column, value in enumerate(
            [owner, bucket["Contain"], bucket["Remediate"], bucket["Schedule"], bucket["Accept"],
             bucket[NOT_ANALYSED], round(bucket["exposure"], 1), bucket["soonest"] or ""], start=1):
            sheet.cell(row=row, column=column, value=value).border = BORDER
        if bucket["Contain"]:
            _paint(sheet.cell(row=row, column=2), "Contain")
    _widths(sheet, columns)


def _lens(items: list[Assessment]) -> str:
    return items[0].lens if items else "signal"


def _sources(items: list[Assessment]) -> str:
    lens = _lens(items)
    used = "NIST NVD (CVE Program as fallback), FIRST EPSS, CISA KEV"
    if lens in ("full", "forensic"):
        used += ", OSV.dev and GitHub Security Advisories (fixed versions)"
    if lens == "forensic":
        used += ", GitHub repository search (exploit material)"
    note = ("" if lens != "signal" else
            " This run used the 'signal' lens, which does not look up fixed versions; where the scanner reports "
            "fixability it is shown in 'Scanner fixability'.")
    return used + "." + note


def _exploit_evidence(items: list[Assessment]) -> str:
    text = ("CISA KEV (observed exploitation), FIRST EPSS (probability of exploitation in the next 30 days), and "
            "references that NVD labels as exploit code.")
    if _lens(items) == "forensic":
        text += (" A heuristic GitHub search adds public exploit repositories; a match means code claims to "
                 "exploit the CVE, not that it works.")
    return text


def _call_path(items: list[Assessment]) -> str:
    analysed = sum(1 for i in items if i.code_reachability)
    if not analysed:
        return ("No call-path analysis was supplied, so reachability is judged from the CVSS vector and the "
                "inventory, not from your code.")
    return (f"The scanner's call-path analysis was used for {analysed} of {len(items)} finding(s): 'no call path' "
            "lowers Reachability (x0.4) unless the CVE is in CISA KEV; the rest are judged from the CVSS vector "
            "and the inventory.")


def _method_sheet(workbook: Workbook, items: list[Assessment], summary: dict | None) -> None:
    sheet = workbook.create_sheet("Method")
    sheet.column_dimensions["A"].width = 24
    sheet.column_dimensions["B"].width = 96

    rows = [
        ("Business Exposure Index", "BEI = 1000 x Threat^0.8 x Reachability^0.7 x Consequence^0.6"),
        ("", "Multiplicative, so any factor can veto. If nobody can reach it, exposure collapses regardless of CVSS."),
        ("Threat", "Will anyone try? CISA KEV listing = 1.0. Otherwise the stronger of EPSS (concave) and exploit maturity."),
        ("Reachability", "Can they get to it here? CVSS attack vector, complexity, privileges and user interaction, "
                         "adjusted by internet exposure, deployment status and compensating controls."),
        ("Consequence", "What does it cost us? CVSS impact sub-metrics, scaled by asset tier, data classification, "
                        "regulatory scope and environment."),
        ("", ""),
        ("Verdict thresholds", "Contain >= 700 · Remediate >= 400 · Schedule >= 150 · Accept < 150"),
        ("Contain", "Act now, outside the normal change process."),
        ("Remediate", "Fix within this sprint, ahead of the routine cycle."),
        ("Schedule", "Queue for the next planned maintenance window."),
        ("Accept", "No action warranted. Record the decision and move on."),
        ("Judgment", "Per scanner row: Fix (Contain or Remediate), Schedule, Accept, or Not analysed when there was "
                     "not enough context to judge it (no inventory match, or no CVE)."),
        ("", ""),
        ("Due dates", (f"From the verdict: {summary['sla_policy']} Set in the inventory's 'sla' block."
                       if summary and summary.get("sla_policy") else
                       "Derived from the verdict and the asset: tier 1 halves the window, regulated systems take 60% "
                       "of it, production takes 80%. Set your own windows in the inventory's 'sla' block.")),
        ("Confidence", "high = CVE record, EPSS and asset context all present. low = at least two are missing; "
                       "treat the number as provisional."),
        ("", ""),
        ("Data sources", _sources(items)),
        ("Exploit evidence", _exploit_evidence(items)),
        ("Call path", _call_path(items)),
        ("Caveat", "Asset context (tier, internet exposure, data class, owner) comes from your inventory and is "
                   "only as current as it is."),
    ]
    if items:
        rows += [
            ("", ""),
            ("Run", f"Assessed {items[0].measured_at or 'n/a'} · exposure model {items[0].exposure.model_version} · "
                    f"lens '{items[0].lens}'. Re-running with the same inputs reproduces these numbers."),
        ]
    if summary:
        rows += [
            ("This assessment", f"{summary['assessed']} findings · {summary['actionable']} actionable · "
                                f"{summary['suppressed_by_context']} suppressed by business context · "
                                f"{summary['unattributed']} not matched to a known asset"
                                + (f" · {summary['not_scored']['count']} row(s) not scored (no CVE identifier; "
                                   "see 'Manual review')" if summary.get("not_scored") else "")),
        ]
        if summary.get("not_analysed"):
            rows.append(("Not analysed",
                         f"{summary['not_analysed']} finding(s) name a project or host that matched nothing in the "
                         "inventory. They are scored on worst-case defaults, but their judgment is "
                         "'Not analysed' instead of that provisional result, and none of them appear on the "
                         "Accepted sheet. Map them to an asset to get a real verdict."))
        intake = summary.get("intake")
        if intake:
            rows += [
                ("", ""),
                ("Every row accounted for",
                 "Findings has one row per row of the scanner export: two scanner issues are never merged, "
                 "even when they share a CVE and a project."
                 + (" This run was limited (--limit), so only part of the export was scored."
                    if intake.get("limited") else "")),
                ("  Rows in the export", intake["export_rows"]),
                ("  Rows on Findings", intake.get("rows_on_findings", intake["export_rows"])),
                ("  No CVE identifier", f"{intake['rows_without_cve']}  (Not analysed; on Manual review)"),
                ("  Rows listing several CVEs",
                 f"{intake.get('rows_with_several_cves', 0)}  (judged on the worst of their CVEs)"),
            ]
            by_judgment = summary.get("by_judgment") or {}
            if by_judgment:
                rows.append(("  Judgment per row", " · ".join(f"{k} {v}" for k, v in by_judgment.items())))
        reduction = summary.get("reduction") or {}
        if reduction.get("findings_assessed"):
            r = reduction
            rows += [
                ("", ""),
                ("What the analysis removed",
                 "Two separate reductions. Scanner duplication is bookkeeping: one row per "
                 "(CVE, project, manifest) inflates the count before anyone judges anything. The "
                 "reduction that is the analysis is measured against the counterfactual - how many "
                 f"a severity-driven queue would call urgent (CVSS >= {r['severity_floor']:g}) versus "
                 "how many this model says to act on."),
                ("  Scanner findings in", r["findings_assessed"]),
                ("  Unique CVEs", r["unique_cves"]),
                ("  CVE x asset decisions",
                 f"{r['cve_asset_pairs']}  ({r['deduplication_pct']}% scanner duplication removed)"),
                (f"  Urgent on CVSS alone (>= {r['severity_floor']:g})", r["urgent_on_severity_alone"]),
                ("  Actionable after exposure analysis",
                 f"{r['actionable_findings']}  Contain or Remediate ({r['analysis_reduction_pct']}% of the "
                 "severity queue moved off the urgent path). Schedule findings are not counted here: they are "
                 "still fixed, on the planned cycle."),
                ("  Collapsed to nil by business context", r["collapsed_by_business_context"]),
                ("  Upgrades to perform",
                 f"{r['actionable_work_items']} across {r['actionable_work_assets']} asset(s). "
                 "One upgrade is one package on one asset; bumping it clears every CVE that "
                 "package carries there."),
                ("  Findings per upgrade", r["findings_per_work_item"]),
                ("  Analyst hours not spent",
                 f"~{r['analyst_hours_saved_low']:,g}-{r['analyst_hours_saved_high']:,g}  "
                 f"({r['findings_not_triaged']} findings never hand-triaged, at "
                 f"{r['triage_minutes_assumed'][0]:g}-{r['triage_minutes_assumed'][1]:g} minutes each). "
                 "An assumption, not a measurement: set VULNOMETRY_TRIAGE_MINUTES_LOW / _HIGH to "
                 "your own figures."),
            ]

    sheet.cell(row=1, column=1, value="How these numbers were produced").font = TITLE_FONT
    for offset, (label, text) in enumerate(rows, start=3):
        sheet.cell(row=offset, column=1, value=label).font = Font(bold=bool(label))
        cell = sheet.cell(row=offset, column=2, value=text)
        cell.alignment = Alignment(wrap_text=True, vertical="top")


def build_workbook(items: list[Assessment], path: str | Path, summary: dict | None = None) -> Path:
    path = Path(path)
    records = export_rows(items, ((summary or {}).get("not_scored") or {}).get("rows"))
    workbook = Workbook()
    _findings_sheet(workbook, records)
    _manual_review_sheet(workbook, records)
    _engineering_sheet(workbook, records)
    _devsecops_sheet(workbook, records, (summary or {}).get("review_days", 90))
    _action_sheet(workbook, records)
    _accepted_sheet(workbook, records)
    _owner_sheet(workbook, records)
    _method_sheet(workbook, items, summary)
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)
    return path
