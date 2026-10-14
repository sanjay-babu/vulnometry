"""Annotated Excel output: Findings, Manual review, To fix, Duplicates, Action Plan, Accepted, By Owner, Method."""

from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from ..assessment import scanner_band
from ..schema import Assessment

VERDICT_FILL = {
    "Contain": PatternFill("solid", fgColor="C0392B"),
    "Remediate": PatternFill("solid", fgColor="E67E22"),
    "Schedule": PatternFill("solid", fgColor="F1C40F"),
    "Accept": PatternFill("solid", fgColor="BDC3C7"),
}
NOT_ANALYSED = "Not analysed"
NOT_ANALYSED_FILL = PatternFill("solid", fgColor="D6EAF8")
NOT_ANALYSED_FONT = Font(color="1B4F72", bold=True)


def _verdict_label(item: Assessment) -> str:
    """The verdict to show. A finding judged without business context has none worth acting on."""
    return item.exposure.verdict if item.analysed() else NOT_ANALYSED


def _paint_verdict(cell, item: Assessment) -> None:
    if item.analysed():
        cell.fill = VERDICT_FILL.get(item.exposure.verdict, VERDICT_FILL["Accept"])
        cell.font = VERDICT_FONT.get(item.exposure.verdict, VERDICT_FONT["Accept"])
    else:
        cell.fill = NOT_ANALYSED_FILL
        cell.font = NOT_ANALYSED_FONT


VERDICT_FONT = {
    "Contain": Font(color="FFFFFF", bold=True),
    "Remediate": Font(color="FFFFFF", bold=True),
    "Schedule": Font(color="4A3B00"),
    "Accept": Font(color="4A4A4A"),
}

HEADER_FILL = PatternFill("solid", fgColor="1F3A53")
HEADER_FONT = Font(color="FFFFFF", bold=True, size=11)
TITLE_FONT = Font(bold=True, size=14)
THIN = Side(style="thin", color="D5D8DC")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

FINDINGS_COLUMNS = [
    ("CVE", 16), ("BEI", 8), ("Verdict", 12), ("Scanner severity", 11), ("Asset", 22),
    ("Project", 28), ("Target", 22), ("Project URL", 30), ("Issue URL", 30),
    ("Analysis", 15), ("Scanner rows", 9), ("Owner", 26),
    ("Business unit", 18), ("Environment", 13), ("Internet", 12), ("Due by", 12), ("SLA days", 9),
    ("Threat", 9), ("Reach", 9), ("Code path", 11), ("Consequence", 12),
    ("CVSS", 7), ("EPSS %", 9), ("EPSS date", 12), ("KEV", 6), ("Ransomware", 11),
    ("Component", 22), ("Fixed in", 28), ("Confidence", 11),
    ("Rationale", 90), ("Directive", 60),
]

_RATIONALE_COLUMN = [name for name, _ in FINDINGS_COLUMNS].index("Rationale") + 1

_CODE_PATH_SHORT = {"reachable": "Reachable", "unreachable": "No path"}

_FACING_SHORT = {"internet-facing": "External", "internal-only": "Internal", "exposure unknown": "Unknown"}


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


def _primary_driver(item: Assessment) -> str:
    if item.exposure.collapsed_by == "not-deployed":
        return "Suppressed: component not deployed on this asset"
    for basis in (item.exposure.threat_basis, item.exposure.reachability_basis):
        if basis:
            return basis[0]
    return ""


ACCEPT_COLUMNS = [
    ("CVE", 16), ("Location", 30), ("Project", 28), ("Target", 22), ("Project URL", 30), ("Issue URL", 30),
    ("Analysis", 15), ("Package", 26), ("Scanner severity", 11),
    ("BEI", 7), ("Threat", 8), ("Reach", 8), ("Code path", 10), ("Conseq.", 9),
    ("Internet", 11), ("Tier", 6), ("Data class", 14),
    ("EPSS %", 9), ("EPSS date", 12), ("CISA KEV", 9), ("CVSS", 7),
    ("Fix available", 22), ("Confidence", 11),
    ("Rationale", 95), ("Evidence gaps", 40),
    ("Model", 10), ("Assessed (UTC)", 22),
    ("Decision", 26), ("Decided by", 16), ("Decision date", 14),
    ("Review by", 14), ("Reopen triggers", 60), ("Snyk ignore ID", 18), ("Ticket", 16),
]

_ACCEPT_WRAP = {i for i, (name, _) in enumerate(ACCEPT_COLUMNS, start=1)
                if name in ("Rationale", "Evidence gaps", "Reopen triggers")}
_URL_COLUMNS = {"Project URL", "Issue URL", "Duplicate: issue URL", "Kept: issue URL"}


def _link(cell, value, column_name: str) -> None:
    """Make a URL column clickable."""
    if column_name in _URL_COLUMNS and isinstance(value, str) and value.startswith(("http://", "https://")):
        cell.hyperlink = value
        cell.font = Font(color="1F5FAD", underline="single")


REOPEN_DEFAULT = ("EPSS >= 0.10  |  added to CISA KEV  |  a working public exploit appears  |  "
                  "the asset's internet exposure or tier changes  |  review-by date reached")


def _accepted_sheet(workbook: Workbook, items: list[Assessment]) -> None:
    accepted = [i for i in items if i.exposure.verdict == "Accept" and i.analysed()]
    held_back = sum(1 for i in items if i.exposure.verdict == "Accept" and not i.analysed())
    sheet = workbook.create_sheet("Accepted")

    sheet.cell(row=1, column=1, value="Accepted risk — rationale and sign-off").font = TITLE_FONT
    sheet.cell(
        row=2, column=1,
        value=(f"{len(accepted)} finding(s) scored below the action threshold. The rationale columns are "
               "produced by the model; fill the Decision..Ticket columns and keep this as the audit record."
               + (f" {held_back} more scored Accept only on worst-case defaults (Not analysed: no inventory "
                  "match) and are left off, so they cannot be signed off or suppressed by mistake."
                  if held_back else "")),
    ).font = Font(color="7F8C8D", size=10)

    header_row = 4
    for index, (name, _) in enumerate(ACCEPT_COLUMNS, start=1):
        sheet.cell(row=header_row, column=index, value=name)
    _style_header(sheet, header_row, len(ACCEPT_COLUMNS))

    for offset, item in enumerate(sorted(accepted, key=lambda i: -i.exposure.index)):
        row = header_row + 1 + offset
        severity = item.weakness.primary_severity()
        values = [
            item.cve_id,
            item.where() or "",
            item.source_asset or "",
            item.source_host or "",
            item.source_url or "",
            item.issue_url or "",
            "Analysed" if item.analysed() else "Not analysed",
            item.source_component or "",
            scanner_band(item.scanner_severity),
            item.exposure.index,
            item.exposure.threat,
            item.exposure.reachability,
            _CODE_PATH_SHORT.get(item.code_reachability, ""),
            item.exposure.consequence,
            _FACING_SHORT.get(item.exposure_facing(), ""),
            item.tier or "",
            item.data_classification or "",
            round(item.probability.probability * 100, 2) if item.probability.probability is not None else "no score",
            item.probability.as_of or "",
            "Yes" if item.exploitation.confirmed else "No",
            severity.base_score if severity and severity.base_score is not None else "",
            ", ".join(item.fixes[:3]) or "none published",
            item.exposure.confidence,
            item.rationale(),
            " | ".join(item.gaps) or "none",
            item.exposure.model_version,
            item.measured_at or "",
            "Accept risk / suppress in scanner",
            "", "", "",
            REOPEN_DEFAULT,
            "", "",
        ]
        for column, value in enumerate(values, start=1):
            cell = sheet.cell(row=row, column=column, value=value)
            cell.border = BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=column in _ACCEPT_WRAP)
            _link(cell, value, ACCEPT_COLUMNS[column - 1][0])
        sheet.cell(row=row, column=1).font = Font(bold=True)

    _widths(sheet, ACCEPT_COLUMNS)
    sheet.freeze_panes = sheet.cell(row=header_row + 1, column=2)
    if accepted:
        sheet.auto_filter.ref = f"A{header_row}:{get_column_letter(len(ACCEPT_COLUMNS))}{header_row + len(accepted)}"


def _findings_sheet(workbook: Workbook, items: list[Assessment]) -> None:
    sheet = workbook.active
    sheet.title = "Findings"

    sheet.cell(row=1, column=1, value="Exposure assessment").font = TITLE_FONT
    sheet.cell(row=2, column=1, value=f"Generated {date.today().isoformat()} · Business Exposure Index 0-1000 · higher means act sooner")
    sheet.cell(row=2, column=1).font = Font(color="7F8C8D", size=10)

    header_row = 4
    for index, (name, _) in enumerate(FINDINGS_COLUMNS, start=1):
        sheet.cell(row=header_row, column=index, value=name)
    _style_header(sheet, header_row, len(FINDINGS_COLUMNS))

    for offset, item in enumerate(items):
        row = header_row + 1 + offset
        severity = item.weakness.primary_severity()
        values = [
            item.cve_id,
            item.exposure.index,
            _verdict_label(item),
            scanner_band(item.scanner_severity),
            item.asset or "",
            item.source_asset or "",
            item.source_host or "",
            item.source_url or "",
            item.issue_url or "",
            "Analysed" if item.analysed() else NOT_ANALYSED,
            item.source_rows or 1,
            item.owner or "",
            item.business_unit or "",
            item.environment or "",
            _FACING_SHORT.get(item.exposure_facing(), ""),
            item.due_by or "",
            item.sla_days or "",
            item.exposure.threat,
            item.exposure.reachability,
            _CODE_PATH_SHORT.get(item.code_reachability, ""),
            item.exposure.consequence,
            severity.base_score if severity and severity.base_score is not None else "",
            round(item.probability.probability * 100, 2) if item.probability.probability is not None else "",
            item.probability.as_of or "",
            "Yes" if item.exploitation.confirmed else "",
            "Yes" if item.exploitation.ransomware_linked else "",
            (item.bulletins[0].remedies[0].component if item.bulletins and item.bulletins[0].remedies else ""),
            ", ".join(item.fixes[:3]),
            item.exposure.confidence,
            item.rationale(),
            item.directive,
        ]
        for column, value in enumerate(values, start=1):
            cell = sheet.cell(row=row, column=column, value=value)
            cell.border = BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=column >= _RATIONALE_COLUMN)
            _link(cell, value, FINDINGS_COLUMNS[column - 1][0])

        verdict_cell = sheet.cell(row=row, column=3)
        _paint_verdict(verdict_cell, item)
        verdict_cell.alignment = Alignment(horizontal="center", vertical="center")
        sheet.cell(row=row, column=2).font = Font(bold=True)

    _widths(sheet, FINDINGS_COLUMNS)
    sheet.freeze_panes = sheet.cell(row=header_row + 1, column=2)
    if items:
        sheet.auto_filter.ref = f"A{header_row}:{get_column_letter(len(FINDINGS_COLUMNS))}{header_row + len(items)}"


def _action_sheet(workbook: Workbook, items: list[Assessment]) -> None:
    actionable = [i for i in items if i.exposure.verdict in ("Contain", "Remediate")]
    sheet = workbook.create_sheet("Action Plan")

    sheet.cell(row=1, column=1, value="What has to happen, and by when").font = TITLE_FONT
    sheet.cell(row=2, column=1, value=f"{len(actionable)} of {len(items)} findings need action. Sorted by due date.")
    sheet.cell(row=2, column=1).font = Font(color="7F8C8D", size=10)

    columns = [("Due by", 12), ("CVE", 16), ("Verdict", 12), ("Scanner severity", 11), ("Asset", 24),
               ("Owner", 28), ("Action", 70)]
    header_row = 4
    for index, (name, _) in enumerate(columns, start=1):
        sheet.cell(row=header_row, column=index, value=name)
    _style_header(sheet, header_row, len(columns))

    ordered = sorted(actionable, key=lambda i: (i.due_by or "9999-12-31", -i.exposure.index))
    for offset, item in enumerate(ordered):
        row = header_row + 1 + offset
        for column, value in enumerate(
            [item.due_by or "unscheduled", item.cve_id, _verdict_label(item),
             scanner_band(item.scanner_severity),
             item.where() or "unattributed", item.owner or "unassigned", item.directive],
            start=1,
        ):
            cell = sheet.cell(row=row, column=column, value=value)
            cell.border = BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=column == 7)
        _paint_verdict(sheet.cell(row=row, column=3), item)

    _widths(sheet, columns)
    sheet.freeze_panes = sheet.cell(row=header_row + 1, column=1)


REVIEW_COLUMNS = [
    ("Why on this list", 24), ("Scanner severity", 11), ("Verdict", 13), ("BEI", 8), ("Due by", 12),
    ("CVE", 16), ("Asset", 24), ("Project", 28), ("Target", 22), ("Project URL", 30), ("Issue URL", 30),
    ("Owner", 26), ("Export row", 9),
    ("Title / component", 30), ("Reason", 90), ("Next step", 60),
]
_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_BANDS = ["Critical", "High", "Medium", "Low", "Other"]
REVIEW_NOT_ANALYSED = "Not analysed"
REVIEW_DUPLICATE = "Duplicate row"
REVIEW_NOT_SCORED = "Not scored (no CVE)"


def _band(value: str) -> str:
    band = scanner_band(value)
    return band if band in _SEVERITY_ORDER else "Other"


def _severity_key(value: str) -> int:
    return _SEVERITY_ORDER.get(scanner_band(value), 4)


def _list_rows(sheet, header_row: int, columns, rows: list[list], verdict_column: int = 3) -> None:
    names = [name for name, _ in columns]
    wrap_from = next((i for i, n in enumerate(names, start=1) if n in ("Reason", "Directive")), len(names) + 1)
    for index, (name, _) in enumerate(columns, start=1):
        sheet.cell(row=header_row, column=index, value=name)
    _style_header(sheet, header_row, len(columns))
    for offset, values in enumerate(rows, start=1):
        r = header_row + offset
        for column, value in enumerate(values, start=1):
            cell = sheet.cell(row=r, column=column, value=value)
            cell.border = BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=column >= wrap_from)
            _link(cell, value, names[column - 1])
        verdict = sheet.cell(row=r, column=verdict_column)
        label = values[verdict_column - 1]
        if label in VERDICT_FILL:
            verdict.fill, verdict.font = VERDICT_FILL[label], VERDICT_FONT[label]
        else:
            verdict.fill, verdict.font = NOT_ANALYSED_FILL, NOT_ANALYSED_FONT
    _widths(sheet, columns)
    sheet.freeze_panes = sheet.cell(row=header_row + 1, column=1)
    if rows:
        sheet.auto_filter.ref = f"A{header_row}:{get_column_letter(len(columns))}{header_row + len(rows)}"


def _count_table(sheet, top: int, groups: list[tuple[str, list[str]]]) -> int:
    """Group x scanner severity. Returns the next free row."""
    for col, name in enumerate(["", *_BANDS, "Total"], start=1):
        sheet.cell(row=top, column=col, value=name)
    _style_header(sheet, top, len(_BANDS) + 2)
    for offset, (label, bands) in enumerate(groups, start=1):
        r = top + offset
        for col, value in enumerate([label, *[bands.count(b) for b in _BANDS], len(bands)], start=1):
            sheet.cell(row=r, column=col, value=value).border = BORDER
        if label in VERDICT_FILL:
            sheet.cell(row=r, column=1).fill = VERDICT_FILL[label]
            sheet.cell(row=r, column=1).font = VERDICT_FONT[label]
        elif label.startswith(("Not analysed", "Not scored", "Duplicate")):
            sheet.cell(row=r, column=1).fill = NOT_ANALYSED_FILL
            sheet.cell(row=r, column=1).font = NOT_ANALYSED_FONT
    r = top + len(groups) + 1
    sheet.cell(row=r, column=1, value="Total").font = Font(bold=True)
    for col, b in enumerate(_BANDS, start=2):
        sheet.cell(row=r, column=col, value=sum(bands.count(b) for _, bands in groups)).font = Font(bold=True)
    sheet.cell(row=r, column=len(_BANDS) + 2, value=sum(len(b) for _, b in groups)).font = Font(bold=True)
    return r + 2


def _manual_review_sheet(workbook: Workbook, items: list[Assessment], not_scored: dict | None) -> None:
    """Every export row that has no trustworthy verdict of its own, one row each.

    Findings that could not be analysed (no inventory match), scanner rows with no CVE, and
    duplicate rows: further rows for the same CVE on the same project, merged into one finding
    and so never judged on their own. The count table at the top accounts for every row of the
    export, including the ones that are not on this list.
    """
    sheet = workbook.create_sheet("Manual review", 1)
    unanalysed = [i for i in items if not i.analysed()]
    unscored = list((not_scored or {}).get("rows") or [])
    duplicates = [(i, d) for i in items for d in i.duplicate_rows]

    sheet.cell(row=1, column=1, value="Manual review: rows with no verdict of their own").font = TITLE_FONT
    sheet.cell(
        row=2, column=1,
        value=(f"{len(unanalysed)} not analysed, {len(unscored)} not scored. The table counts every row of the "
               "scanner export by scanner severity, so it reconciles to the export; duplicate rows are on "
               f"'{_duplicates_title(items)}'. Filter 'Why on this list' and hand the rows over."),
    ).font = Font(color="7F8C8D", size=10)

    analysed = [i for i in items if i.analysed()]
    groups = [(v, [_band(i.scanner_severity) for i in analysed if i.exposure.verdict == v])
              for v in ("Contain", "Remediate", "Schedule", "Accept")]
    groups += [
        ("Not analysed (on this list)", [_band(i.scanner_severity) for i in unanalysed]),
        (f"Duplicate rows ({_duplicates_title(items)})", [_band(d.get("scanner_severity", "")) for _, d in duplicates]),
        ("Not scored (on this list)", [_band(r.get("scanner_severity", "")) for r in unscored]),
    ]
    header_row = _count_table(sheet, 4, groups) + 1

    rows: list[list] = []
    for item in sorted(unanalysed, key=lambda i: (_severity_key(i.scanner_severity), -i.exposure.index)):
        rows.append([REVIEW_NOT_ANALYSED, scanner_band(item.scanner_severity), NOT_ANALYSED,
                     item.exposure.index, "", item.cve_id, "", item.source_asset or "", item.source_host or "",
                     item.source_url or "", item.issue_url or "", item.owner or "",
                     item.source_row or "", item.source_component or "", item.rationale(),
                     "Map this project to an asset in the inventory and re-run for a real verdict. "
                     "Until then, triage it on the scanner's severity."])
    for row in sorted(unscored, key=lambda r: _severity_key(r.get("scanner_severity", ""))):
        rows.append([REVIEW_NOT_SCORED, row.get("scanner_severity", ""), NOT_ANALYSED, "", "", "",
                     "", row.get("asset", ""), row.get("host", ""), row.get("project_url", ""),
                     row.get("issue_url", ""), "", row.get("row") or "",
                     row.get("title", ""),
                     "No CVE identifier: exposure is scored per CVE, so only the scanner's severity applies.",
                     "Triage on the scanner's severity."])
    _list_rows(sheet, header_row, REVIEW_COLUMNS, rows)


def _to_fix_sheet(workbook: Workbook, items: list[Assessment]) -> None:
    """Analysed findings that need fixing, Contain to Schedule, by due date."""
    sheet = workbook.create_sheet("To fix", 2)
    fix = [i for i in items if i.analysed() and i.exposure.verdict != "Accept"]
    sheet.cell(row=1, column=1, value="To fix: analysed findings that need work, by due date").font = TITLE_FONT
    sheet.cell(row=2, column=1,
               value=(f"{len(fix)} finding(s): Contain, Remediate and Schedule. Not analysed findings are on "
                      "'Manual review', accepted ones on 'Accepted'.")).font = Font(color="7F8C8D", size=10)
    header_row = _count_table(sheet, 4, [(v, [_band(i.scanner_severity) for i in fix if i.exposure.verdict == v])
                                         for v in ("Contain", "Remediate", "Schedule")]) + 1
    rows = [["Fix", scanner_band(i.scanner_severity), i.exposure.verdict, i.exposure.index, i.due_by or "",
             i.cve_id, i.asset, i.source_asset or "", i.source_host or "", i.source_url or "",
             i.issue_url or "", i.owner or "", i.source_row or "",
             i.source_component or "", i.rationale(), i.directive]
            for i in sorted(fix, key=lambda i: (i.due_by or "9999-12-31", -i.exposure.index))]
    columns = [("Why on this list", 10), *REVIEW_COLUMNS[1:-1], ("Directive", 60)]
    _list_rows(sheet, header_row, columns, rows)


DUPLICATE_COLUMNS = [
    ("Scanner severity", 11), ("CVE", 16), ("Title", 30), ("Project", 28), ("Target", 22),
    ("Duplicate: export row", 10), ("Duplicate: issue URL", 34), ("Kept: export row", 10),
    ("Kept: issue URL", 34), ("Verdict", 13), ("BEI", 8), ("Due by", 12), ("Asset", 24), ("Owner", 26),
    ("Project URL", 34),
]


def _duplicates_title(items: list[Assessment]) -> str:
    names = Counter(i.scanner for i in items if i.scanner)
    return f"Duplicates from {names.most_common(1)[0][0] if names else 'scanner'}"[:31]


def _duplicates_sheet(workbook: Workbook, items: list[Assessment]) -> None:
    """Rows the scanner listed more than once for the same CVE on the same project and target.

    Each sits beside the row it was merged into. Typically the scanner carries two advisories
    for one vulnerability in one package, so the issue links differ and nothing else does.
    """
    pairs = [(i, d) for i in items for d in i.duplicate_rows]
    sheet = workbook.create_sheet(_duplicates_title(items), 3)
    sheet.cell(row=1, column=1, value="Duplicate rows: the same CVE listed again on the same project").font = TITLE_FONT
    sheet.cell(
        row=2, column=1,
        value=(f"{len(pairs)} row(s) repeat a CVE already listed for the same project and target, usually a second "
               "advisory for the same vulnerability in the same package. Each was merged into the kept row's "
               "finding and judged once; its verdict is shown. Compare the two issue links to confirm."),
    ).font = Font(color="7F8C8D", size=10)
    rows = []
    for item, dup in sorted(pairs, key=lambda p: (_severity_key(p[1].get("scanner_severity", "")),
                                                  p[0].cve_id, p[0].source_asset, p[1].get("row", 0))):
        rows.append([scanner_band(dup.get("scanner_severity", "")), item.cve_id, dup.get("title", ""),
                     item.source_asset or "", item.source_host or "", dup.get("row") or "",
                     dup.get("issue_url", ""), item.source_row or "", item.issue_url or "",
                     _verdict_label(item), item.exposure.index, item.due_by or "", item.asset or "",
                     item.owner or "", item.source_url or ""])
    _list_rows(sheet, 4, DUPLICATE_COLUMNS, rows, verdict_column=10)


def _owner_sheet(workbook: Workbook, items: list[Assessment]) -> None:
    sheet = workbook.create_sheet("By Owner")
    sheet.cell(row=1, column=1, value="Workload by owner").font = TITLE_FONT
    sheet.cell(row=2, column=1, value="Who is carrying the queue, and how urgent their share is.").font = Font(color="7F8C8D", size=10)

    tally: dict[str, dict] = {}
    for item in items:
        owner = item.owner or "unassigned"
        bucket = tally.setdefault(owner, {"Contain": 0, "Remediate": 0, "Schedule": 0, "Accept": 0, "exposure": 0.0, "soonest": ""})
        bucket[item.exposure.verdict] = bucket.get(item.exposure.verdict, 0) + 1
        bucket["exposure"] += item.exposure.index
        if item.due_by and (not bucket["soonest"] or item.due_by < bucket["soonest"]):
            bucket["soonest"] = item.due_by

    columns = [("Owner", 32), ("Contain", 10), ("Remediate", 11), ("Schedule", 10), ("Accept", 9), ("Total exposure", 15), ("Earliest due", 13)]
    header_row = 4
    for index, (name, _) in enumerate(columns, start=1):
        sheet.cell(row=header_row, column=index, value=name)
    _style_header(sheet, header_row, len(columns))

    ordered = sorted(tally.items(), key=lambda kv: (-kv[1]["Contain"], -kv[1]["exposure"]))
    for offset, (owner, bucket) in enumerate(ordered):
        row = header_row + 1 + offset
        for column, value in enumerate(
            [owner, bucket["Contain"], bucket["Remediate"], bucket["Schedule"],
             bucket["Accept"], round(bucket["exposure"], 1), bucket["soonest"] or ""],
            start=1,
        ):
            cell = sheet.cell(row=row, column=column, value=value)
            cell.border = BORDER
        if bucket["Contain"]:
            sheet.cell(row=row, column=2).fill = VERDICT_FILL["Contain"]
            sheet.cell(row=row, column=2).font = VERDICT_FONT["Contain"]

    _widths(sheet, columns)


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
        ("", ""),
        ("Due dates", (f"From the verdict: {summary['sla_policy']} Set in the inventory's 'sla' block."
                       if summary and summary.get("sla_policy") else
                       "Derived from the verdict and the asset: tier 1 halves the window, regulated systems take 60% "
                       "of it, production takes 80%. Set your own windows in the inventory's 'sla' block.")),
        ("Confidence", "high = CVE record, EPSS and asset context all present. low = at least two are missing; "
                       "treat the number as provisional."),
        ("", ""),
        ("Data sources", "NIST NVD, CVE Program (fallback), FIRST EPSS, CISA KEV, OSV.dev, GitHub Security Advisories."),
        ("Caveat", "Exploit-artifact discovery is a heuristic GitHub search. A match means public code claims to "
                   "exploit the CVE, not that it works."),
        ("Caveat", "Asset context comes from your inventory. Nothing here can verify that the vulnerable code path "
                   "is actually reachable in your deployment."),
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
                         "inventory. They are scored on worst-case defaults, but the Verdict column says "
                         "'Not analysed' instead of that provisional result, and none of them appear on the "
                         "Accepted sheet. Map them to an asset to get a real verdict."))
        intake = summary.get("intake")
        if intake:
            rows += [
                ("", ""),
                ("Every row accounted for",
                 "How the rows in the scanner export become the findings in this workbook."
                 + (" This run was limited (--limit), so only part of the export was scored."
                    if intake.get("limited") else "")),
                ("  Rows in the export", intake["export_rows"]),
                ("  No CVE identifier", f"{intake['rows_without_cve']}  (Manual review)"),
                ("  With a CVE", f"{intake['rows_with_cve']}  ({intake['cve_entries']} CVE entries: a row "
                                 "listing several CVEs counts once per CVE)"),
                ("  Merged duplicates",
                 f"{intake['merged_duplicates']}  (the same CVE on the same project and host, listed more "
                 "than once by the scanner, e.g. once per advisory. Each is listed on the Duplicates sheet; "
                 "'Scanner rows' on Findings says how many each finding stands for)"),
                ("  Findings", intake["findings"]),
            ]
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
                 f"{r['actionable_findings']}  ({r['analysis_reduction_pct']}% of the severity queue removed)"),
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
    workbook = Workbook()
    _findings_sheet(workbook, items)
    _action_sheet(workbook, items)
    _accepted_sheet(workbook, items)
    _manual_review_sheet(workbook, items, (summary or {}).get("not_scored"))
    _to_fix_sheet(workbook, items)
    _duplicates_sheet(workbook, items)
    _owner_sheet(workbook, items)
    _method_sheet(workbook, items, summary)
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)
    return path
