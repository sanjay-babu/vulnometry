"""Registry, reports, providers and the analyst loop."""

import asyncio
import json

from vulnometry.analyst import run_analysis
from vulnometry.exposure import MODEL_VERSION
from vulnometry.providers import parse_spec
from vulnometry.providers.base import ChatResponse, Message, ProviderError, ToolCall, parse_arguments
from vulnometry.registry import ACTIONS, invoke
from vulnometry.report import build_dashboard, build_workbook, to_csv, to_json, to_markdown
from vulnometry.schema import (
    Assessment,
    ConfirmedExploitation,
    ExploitProbability,
    ExposureMeasure,
    Weakness,
)
from vulnometry.surfaces.schemas import DIALECTS


def test_every_action_schema_is_well_formed():
    for action in ACTIONS:
        schema = action.json_schema()
        assert schema["type"] == "object"
        assert isinstance(schema["properties"], dict)
        for required in schema.get("required", []):
            assert required in schema["properties"], f"{action.name}: {required} undeclared"
        assert len(action.description) > 40, f"{action.name} needs a usable description"


def test_every_dialect_exports_all_actions():
    count = len(ACTIONS)
    assert len(DIALECTS["openai"]()) == count
    assert len(DIALECTS["anthropic"]()) == count
    assert len(DIALECTS["bedrock"]()["tools"]) == count
    assert len(DIALECTS["gemini"]()[0]["function_declarations"]) == count


def test_gemini_schema_drops_unsupported_keywords():
    blob = json.dumps(DIALECTS["gemini"]())
    assert "additionalProperties" not in blob, "Gemini rejects this keyword"


def test_unknown_action_returns_data_not_an_exception():
    result = asyncio.run(invoke("no_such_action", {}))
    assert "error" in result
    assert "measure_exposure" in result["available"]


def test_bad_arguments_return_data_not_an_exception():
    result = asyncio.run(invoke("measure_exposure", {"cve_id": "banana"}))
    assert "error" in result and "banana" in result["error"]


def test_unexpected_arguments_are_ignored_with_a_warning():
    result = asyncio.run(invoke("harvest_cve_ids", {"text": "CVE-2021-44228", "nonsense": 1}))
    assert result["cve_ids"] == ["CVE-2021-44228"]
    assert "nonsense" in result["_warning"]


def test_offline_action_needs_no_network():
    result = asyncio.run(invoke("harvest_cve_ids", {"text": "saw CVE-2021-44228 in prod"}))
    assert result == {"count": 1, "cve_ids": ["CVE-2021-44228"]}


def test_model_spec_parsing_survives_colons_in_model_ids():
    assert parse_spec("bedrock:us.anthropic.claude-sonnet-4-20250514-v1:0") == (
        "bedrock", "us.anthropic.claude-sonnet-4-20250514-v1:0")
    assert parse_spec("ollama:qwen3:8b") == ("ollama", "qwen3:8b")
    assert parse_spec("azure:my-deployment") == ("azure", "my-deployment")
    assert parse_spec("llama3.1")[0] == "ollama", "a bare name defaults to Ollama"


def test_tool_argument_parsing_is_forgiving():
    assert parse_arguments('{"cve_id": "CVE-2021-44228"}') == {"cve_id": "CVE-2021-44228"}
    assert parse_arguments('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_arguments("total garbage") == {}
    assert parse_arguments({"already": "a dict"}) == {"already": "a dict"}


def test_each_provider_builds_its_own_wire_format():
    from vulnometry.providers import anthropic, bedrock, gemini, openai_compat

    convo = [
        Message(role="system", content="brief"),
        Message(role="user", content="is it urgent?"),
        Message(role="assistant", tool_calls=[ToolCall(id="c1", name="measure_exposure", arguments={"cve_id": "CVE-1"})]),
        Message(role="tool", name="measure_exposure", tool_call_id="c1", content='{"index": 900}'),
    ]

    openai_wire = openai_compat._to_wire(convo)
    assert openai_wire[2]["tool_calls"][0]["function"]["name"] == "measure_exposure"
    assert openai_wire[3] == {"role": "tool", "tool_call_id": "c1", "content": '{"index": 900}'}

    system, anthropic_wire = anthropic._to_wire(convo)
    assert system == "brief"
    assert anthropic_wire[1]["content"][0]["type"] == "tool_use"
    assert anthropic_wire[2]["content"][0]["type"] == "tool_result"

    bedrock_system, bedrock_wire = bedrock._to_wire(convo)
    assert bedrock_system == [{"text": "brief"}]
    assert "toolUse" in bedrock_wire[1]["content"][0]
    assert "toolResult" in bedrock_wire[2]["content"][0]

    instruction, contents = gemini._to_wire(convo)
    assert instruction["parts"][0]["text"] == "brief"
    assert "functionCall" in contents[1]["parts"][0]
    assert "functionResponse" in contents[2]["parts"][0]


class Scripted:
    name = "fake"
    model = "scripted"

    def __init__(self, script):
        self.script = list(script)
        self.received = []

    async def chat(self, messages, tools=None, **kwargs):
        self.received.append((list(messages), tools))
        return self.script.pop(0)

    async def check(self):
        return {"ok": True}

    async def aclose(self):
        pass


def test_analyst_calls_an_action_then_answers():
    provider = Scripted([
        ChatResponse(tool_calls=[ToolCall(id="c1", name="harvest_cve_ids",
                                          arguments={"text": "we saw CVE-2021-44228"})]),
        ChatResponse(text="One CVE: CVE-2021-44228."),
    ])
    run = asyncio.run(run_analysis("what is in this?", provider=provider))

    assert run.calls == 1
    assert run.actions_used() == ["harvest_cve_ids"]
    tool_messages = [m for m in provider.received[-1][0] if m.role == "tool"]
    assert tool_messages[0].tool_call_id == "c1"
    assert "CVE-2021-44228" in tool_messages[0].content


def test_analyst_survives_a_hallucinated_action():
    provider = Scripted([
        ChatResponse(tool_calls=[ToolCall(id="c1", name="does_not_exist", arguments={})]),
        ChatResponse(text="That action is unavailable."),
    ])
    run = asyncio.run(run_analysis("go", provider=provider))
    assert run.answer.startswith("That action is unavailable")
    assert "unknown action" in [m for m in provider.received[-1][0] if m.role == "tool"][0].content


def test_analyst_stops_looping_and_withholds_actions_on_the_last_call():
    loop = ChatResponse(tool_calls=[ToolCall(id="c", name="harvest_cve_ids", arguments={"text": "x"})])
    provider = Scripted([loop] * 3 + [ChatResponse(text="Final answer.")])
    run = asyncio.run(run_analysis("go", provider=provider, max_turns=3))
    assert run.turns == 3
    assert run.answer == "Final answer."
    assert provider.received[-1][1] is None


def test_provider_failure_becomes_an_answer_not_a_crash():
    class Broken(Scripted):
        async def chat(self, messages, tools=None, **kwargs):
            raise ProviderError("ollama", "connection refused", "run `ollama serve`")

    run = asyncio.run(run_analysis("go", provider=Broken([])))
    assert "Inference failed" in run.answer and "ollama serve" in run.answer


def _sample() -> list[Assessment]:
    return [
        Assessment(cve_id="CVE-2021-44228", asset="checkout-api", owner="pay@x.com",
                   business_unit="Commerce", due_by="2026-09-04", sla_days=2,
                   directive="Act now.", fixes=["log4j-core 2.15.0"],
                   weakness=Weakness(cve_id="CVE-2021-44228", summary="RCE", resolved=True),
                   exposure=ExposureMeasure(index=928.9, verdict="Contain", threat=1.0,
                                            reachability=0.9, consequence=1.0,
                                            threat_basis=["CISA KEV lists this as exploited"])),
        Assessment(cve_id="CVE-2023-40000", asset="ml-sandbox", directive="No action.",
                   exposure=ExposureMeasure(index=0.0, verdict="Accept", threat=0.26,
                                            reachability=0.0, consequence=0.2,
                                            collapsed_by="not-deployed")),
    ]


def test_accepted_sheet_carries_rationale_and_signoff_columns(tmp_path):
    from openpyxl import load_workbook

    accepted = Assessment(
        cve_id="CVE-2024-9999", asset="reporting-svc", tier=3,
        internet_exposed=False, data_classification="internal",
        weakness=Weakness(cve_id="CVE-2024-9999", summary="XSS", resolved=True),
        probability=ExploitProbability(cve_id="CVE-2024-9999", probability=0.004,
                                       as_of="2026-09-08", resolved=True),
        exposure=ExposureMeasure(index=96, verdict="Accept", threat=0.13, reachability=0.7,
                                 consequence=0.5, confidence="high",
                                 threat_basis=["EPSS puts exploitation within 30 days at 0.40%"],
                                 reachability_basis=["Attack vector is network"],
                                 consequence_basis=["CVSS impact C:LOW I:LOW A:NONE"]),
        measured_at="2026-09-09T12:00:00+00:00",
    )
    path = build_workbook([accepted], tmp_path / "out.xlsx", None)
    sheet = load_workbook(path)["Accepted"]
    header = [c.value for c in sheet[4]]
    for col in ("Rationale", "Internet", "EPSS %", "EPSS date", "Reopen triggers", "Decision", "Model"):
        assert col in header, col

    row = {header[i]: sheet.cell(row=5, column=i + 1).value for i in range(len(header))}
    assert row["CVE"] == "CVE-2024-9999"
    assert row["Internet"] == "Internal"
    assert row["EPSS date"] == "2026-09-08"
    assert row["Model"] == MODEL_VERSION
    assert "exploitation unlikely in the next 30 days" in row["Rationale"]
    assert "EPSS 0.40% (as of 2026-09-08)" in row["Rationale"]
    assert row["Decision"] == "Accept risk; suppress in scanner"
    assert "EPSS >= 0.10" in row["Reopen triggers"]
    assert "CISA KEV" in row["Reopen triggers"]


def test_rows_the_model_could_not_score_are_summarised(tmp_path):
    from openpyxl import load_workbook

    from vulnometry.assessment import not_scored_summary

    not_scored = not_scored_summary([
        {"raw_severity": "Low", "asset": "web", "title": "MIT licence", "reason": "no CVE identifier"},
        {"raw_severity": "HIGH", "asset": "api", "title": "Prototype pollution", "reason": "no CVE identifier"},
    ])
    assert not_scored["count"] == 2
    assert list(not_scored["by_scanner_severity"]) == ["High", "Low"], "ordered by severity"

    summary = {"assessed": 2, "actionable": 1, "suppressed_by_context": 1, "unattributed": 0,
               "not_scored": not_scored}
    workbook = load_workbook(build_workbook(_sample(), tmp_path / "out.xlsx", summary))
    assert "Not scored" not in workbook.sheetnames, "they live on Manual review"
    method = " ".join(str(c.value) for row in workbook["Method"].iter_rows() for c in row if c.value)
    assert "2 row(s) not scored" in method
    assert json.loads(to_json(_sample(), summary))["summary"]["not_scored"]["count"] == 2


def test_rationale_leads_with_the_driving_factor():
    urgent = Assessment(
        cve_id="CVE-1", internet_exposed=True, tier=1,
        exploitation=ConfirmedExploitation(cve_id="CVE-1", confirmed=True),
        exposure=ExposureMeasure(index=800, verdict="Contain", threat=1.0, reachability=0.9,
                                 consequence=0.9, confidence="high",
                                 threat_basis=["CISA KEV lists this as exploited in the wild"]),
    )
    assert urgent.rationale().startswith("Contain: exploitation is likely or under way")
    assert "internet-facing" in urgent.rationale()
    assert "in CISA KEV" in urgent.rationale()


def test_dashboard_is_self_contained(tmp_path):
    path = build_dashboard(_sample(), tmp_path / "out.html",
                           {"assessed": 2, "actionable": 1, "suppressed_by_context": 1,
                            "unattributed": 0, "confirmed_exploited": ["CVE-2021-44228"],
                            "load_by_owner": {"pay@x.com": 1},
                            "exposure_by_business_unit": {"Commerce": 928.9}})
    document = path.read_text()
    assert "<script" not in document, "no JavaScript: it must open from file:// and survive email"
    assert "cdn" not in document.lower()
    assert document.count("https://") == document.count("http://www.w3.org")
    assert "CVE-2021-44228" in document and "Contain" in document
    assert "<svg" in document


def test_html_escaping_in_the_dashboard(tmp_path):
    items = _sample()
    items[0].asset = "<script>alert(1)</script>"
    document = build_dashboard(items, tmp_path / "x.html", {}).read_text()
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;" in document


def test_text_formats_render():
    items = _sample()
    assert json.loads(to_json(items, {"assessed": 2}))["summary"]["assessed"] == 2
    markdown = to_markdown(items, {"assessed": 2, "actionable": 1, "deferrable": 1,
                                   "contain_now": ["CVE-2021-44228"], "suppressed_by_context": 1})
    assert "| CVE-2021-44228 | 928.9 | Contain" in markdown
    assert "## CVE-2021-44228" in markdown
    csv_text = to_csv(items)
    assert csv_text.splitlines()[0].startswith("cve,bei,verdict")
    assert "CVE-2021-44228,928.9,Contain" in csv_text


def test_the_package_version_matches_pyproject():
    """__version__ reaches users through `vulnometry --version`, the MCP
    serverInfo handshake and the OpenAPI document, and it is a second copy of a
    number that lives in pyproject.toml. The 0.2.0 release bumped one and not
    the other, so every one of those three reported 0.1.0.
    """
    import re
    from pathlib import Path

    import vulnometry

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    declared = re.search(r'^version = "([^"]+)"', pyproject.read_text(), re.M)
    assert declared, "pyproject.toml has no top-level version"
    assert vulnometry.__version__ == declared.group(1)


def _header_row(sheet):
    return next(r for r in range(1, 40) if sheet.cell(row=r, column=1).value == "Export row")


def _table(sheet, columns):
    """The listed rows of a sheet as dicts of the named columns."""
    header_row = _header_row(sheet)
    header = [c.value for c in sheet[header_row]]
    return [{c: sheet.cell(row=r, column=header.index(c) + 1).value for c in columns}
            for r in range(header_row + 1, sheet.max_row + 1)]


def _counts(sheet):
    """The count table at the top: label -> total."""
    return {sheet.cell(row=r, column=1).value: sheet.cell(row=r, column=7).value
            for r in range(5, _header_row(sheet) - 1) if sheet.cell(row=r, column=1).value}


def test_workbook_has_the_expected_sheets_and_survives_a_round_trip(tmp_path):
    from openpyxl import load_workbook

    path = build_workbook(_sample(), tmp_path / "out.xlsx",
                          {"assessed": 2, "actionable": 1, "suppressed_by_context": 1, "unattributed": 0})
    workbook = load_workbook(path)
    assert workbook.sheetnames == ["Findings", "Manual review", "Engineering - fix", "DevSecOps - suppress",
                                   "DevSecOps - until fixable", "Action Plan", "Accepted", "By Owner", "Method"]
    rows = _table(workbook["Findings"], ["CVE", "Verdict", "Judgment"])
    assert rows[0] == {"CVE": "CVE-2021-44228", "Verdict": "Contain", "Judgment": "Fix"}
    assert workbook["Findings"].auto_filter.ref
    action = workbook["Action Plan"]
    assert action.cell(row=5, column=3).value == "CVE-2021-44228"
    assert action.cell(row=6, column=3).value is None


def _snyk_like_rows():
    """Two scanner rows that share a CVE and a project but are different issues, one row with two
    CVEs, one unmatched project, and one row with no CVE."""
    from vulnometry.assessment import not_scored_summary

    url = "https://scanner.example/org/o/project/p1"
    items = [
        Assessment(cve_id="CVE-2026-1001", asset="checkout-api", scanner="Snyk", scanner_severity="High",
                   due_by="2026-11-01", source_asset="checkout-svc", source_host="checkout_ci",
                   source_url=url, issue_url=url + "#issue-SNYK-JS-AXIOS-1", issue_id="SNYK-JS-AXIOS-1",
                   source_title="Improper validation", source_row=2,
                   exposure=ExposureMeasure(index=500, verdict="Remediate")),
        Assessment(cve_id="CVE-2026-1001", asset="checkout-api", scanner="Snyk", scanner_severity="High",
                   due_by="2026-11-01", source_asset="checkout-svc", source_host="checkout_ci",
                   source_url=url, issue_url=url + "#issue-SNYK-JS-AXIOS-2", issue_id="SNYK-JS-AXIOS-2",
                   source_title="Improper validation", source_row=3,
                   exposure=ExposureMeasure(index=500, verdict="Remediate")),
        Assessment(cve_id="CVE-2026-2001", asset="checkout-api", scanner="Snyk", scanner_severity="Medium",
                   source_row=4, exposure=ExposureMeasure(index=100, verdict="Accept", confidence="high")),
        Assessment(cve_id="CVE-2026-2002", asset="checkout-api", scanner="Snyk", scanner_severity="Medium",
                   due_by="2027-02-01", source_row=4, exposure=ExposureMeasure(index=200, verdict="Schedule")),
        Assessment(cve_id="CVE-2026-3001", source_asset="orphan", scanner="Snyk", scanner_severity="Critical",
                   source_row=5, exposure=ExposureMeasure(index=60, verdict="Accept", confidence="high")),
        Assessment(cve_id="CVE-2026-4001", asset="checkout-api", scanner="Snyk", scanner_severity="Low",
                   source_row=6, exposure=ExposureMeasure(index=40, verdict="Accept", confidence="high")),
    ]
    not_scored = not_scored_summary([{"raw_severity": "Low", "asset": "web", "title": "GPL-3.0 license",
                                      "row": 7, "issue_url": "https://scanner.example/p2#issue-snyk:lic:gpl"}])
    summary = {"assessed": 6, "actionable": 2, "suppressed_by_context": 0, "unattributed": 1,
               "not_scored": not_scored}
    return items, summary


def test_findings_has_one_row_per_scanner_row_and_a_judgment_for_each(tmp_path):
    from openpyxl import load_workbook

    items, summary = _snyk_like_rows()
    workbook = load_workbook(build_workbook(items, tmp_path / "out.xlsx", summary))
    findings = _table(workbook["Findings"], ["Export row", "Judgment", "Verdict", "CVE", "Issue ID",
                                             "Scanner severity", "Project URL", "Issue URL", "Rationale"])
    by_row = {r["Export row"]: r for r in findings}
    assert sorted(by_row) == [2, 3, 4, 5, 6, 7], "one row per scanner row, nothing merged or lost"
    assert by_row[2]["Issue ID"] == "SNYK-JS-AXIOS-1" and by_row[3]["Issue ID"] == "SNYK-JS-AXIOS-2", \
        "two scanner issues sharing a CVE and project stay two rows"
    assert by_row[2]["Judgment"] == by_row[3]["Judgment"] == "Fix"
    assert by_row[4]["CVE"] == "CVE-2026-2001, CVE-2026-2002"
    assert by_row[4]["Verdict"] == "Schedule", "a row with several CVEs takes the worst"
    assert by_row[5]["Judgment"] == "Not analysed" and "matched no asset" in by_row[5]["Rationale"]
    assert by_row[6]["Judgment"] == "Accept"
    assert by_row[7]["Judgment"] == "Not analysed" and by_row[7]["Scanner severity"] == "Low"
    assert by_row[7]["Issue ID"] == "snyk:lic:gpl", "the id comes from the issue link"
    assert by_row[2]["Issue URL"].endswith("#issue-SNYK-JS-AXIOS-1")

    counts = _counts(workbook["Findings"])
    assert counts["Total"] == 6
    assert counts["Remediate"] == 2 and counts["Schedule"] == 1 and counts["Accept"] == 1
    assert counts["Not analysed (no inventory match)"] == 1 and counts["Not analysed (no CVE)"] == 1

    sheet = workbook["Findings"]
    header = [c.value for c in sheet[_header_row(sheet)]]
    link = sheet.cell(row=_header_row(sheet) + 1, column=header.index("Issue URL") + 1).hyperlink
    assert link is not None and "#issue-" in link.target, "links are clickable"


def test_the_lists_are_filters_of_findings(tmp_path):
    from openpyxl import load_workbook

    items, summary = _snyk_like_rows()
    workbook = load_workbook(build_workbook(items, tmp_path / "out.xlsx", summary))
    review = sorted(r["Export row"] for r in _table(workbook["Manual review"], ["Export row"]))
    engineering = sorted(r["Export row"] for r in _table(workbook["Engineering - fix"], ["Export row"]))
    assert engineering == [2, 3, 4, 5, 7], "everything that is not an accepted risk, unreviewed rows included"
    to_fix = [r for r in engineering if r not in review]
    accepted = sorted(r["Export row"] for r in _table(workbook["Accepted"], ["Export row"]))
    assert review == [5, 7]
    assert to_fix == [2, 3, 4]
    assert accepted == [6], "a worst-case Accept on an unmatched project is never on Accepted"
    assert sorted(review + to_fix + accepted) == [2, 3, 4, 5, 6, 7]
    assert "1 more scored Accept but are left off (Not analysed: 1 with no inventory match, 0 with too little" \
        in workbook["Accepted"].cell(row=2, column=1).value
    assert _counts(workbook["Manual review"])["Total"] == 2


def test_the_same_issue_link_twice_is_flagged_not_merged(tmp_path):
    from openpyxl import load_workbook

    items, summary = _snyk_like_rows()
    items[1].issue_url = items[0].issue_url
    items[1].issue_id = items[0].issue_id
    workbook = load_workbook(build_workbook(items, tmp_path / "out.xlsx", summary))
    rows = {r["Export row"]: r for r in _table(workbook["Findings"], ["Export row", "Duplicate of row"])}
    assert rows[3]["Duplicate of row"] == 2 and rows[2]["Duplicate of row"] is None
    assert len(rows) == 6


def test_scanner_severity_and_analysed_flag_in_csv():
    items = _sample()
    items[0].scanner_severity = "CRITICAL"
    items[1].asset = ""
    items[1].source_asset = "legacy-batch-job"
    csv_lines = to_csv(items).splitlines()
    assert csv_lines[0].startswith("cve,bei,verdict,analysed,scanner_severity,")
    assert csv_lines[1].startswith("CVE-2021-44228,928.9,Contain,yes,CRITICAL,")
    assert csv_lines[2].split(",")[3] == "no"
    assert json.loads(to_json(items, {"assessed": 2}))["findings"][1]["analysed"] is False



def test_no_fix_is_only_claimed_when_fixes_were_looked_up():
    from vulnometry.exposure import directive_for
    from vulnometry.inventory import AssetProfile
    from vulnometry.schema import ConfirmedExploitation as Kev

    def item(**kw):
        return Assessment(cve_id="CVE-2026-1001", asset="api", exposure=ExposureMeasure(index=100, verdict="Accept"),
                          **kw)

    assert "No fixed version published" not in item(fixes_checked=False).rationale(), \
        "the signal lens never looks fixes up, so it must not say there are none"
    assert "No fixed version published" in item(fixes_checked=True).rationale()
    assert "Scanner fixability: Fixable." in item(fixes_checked=False, scanner_fixability="Fixable").rationale()

    urgent = ExposureMeasure(index=500, verdict="Remediate")
    unchecked = directive_for(urgent, Kev(cve_id="x"), [], AssetProfile(name="api"), fixes_checked=False)
    assert "No fixed version published" not in unchecked
    with_scanner = directive_for(urgent, Kev(cve_id="x"), [], AssetProfile(name="api"), fixes_checked=False,
                                 scanner_fixability="Fixable")
    assert "Scanner fixability: Fixable" in with_scanner
    assert "Upgrade to axios 1.15.1" in directive_for(urgent, Kev(cve_id="x"), ["axios 1.15.1"],
                                                       AssetProfile(name="api"))


def test_accept_rationale_cites_what_lowered_the_score():
    item = Assessment(
        cve_id="CVE-2026-5001", asset="billing", internet_exposed=False, tier=2,
        exposure=ExposureMeasure(
            index=60, verdict="Accept", threat=0.3, reachability=0.1, consequence=0.8, confidence="high",
            threat_basis=["EPSS puts exploitation within 30 days at 0.40%, ahead of 30% of all CVEs"],
            reachability_basis=["Attack vector is network", "billing is not internet-reachable",
                                "Scanner's reachability analysis found no call path to the vulnerable function"],
            consequence_basis=["CVSS impact C:HIGH I:HIGH A:HIGH"]))
    text = item.rationale()
    assert text.startswith("Accept: hard to reach in this environment — scanner's reachability analysis found no "
                           "call path to the vulnerable function; billing is not internet-reachable.")
    assert "Attack vector is network" not in text.split("Context:")[0], "a reason to reach is not a reason not to"
    assert "Also: EPSS puts exploitation within 30 days at 0.40%" in text

    item.exposure.threat_basis = ["No EPSS score, usually a very new CVE, so treat as unresolved rather than safe"]
    item.exposure.threat, item.exposure.reachability = 0.1, 0.5
    assert item.rationale().startswith("Accept: no exploitation data yet"), "never 'little sign anyone will try'"


def test_an_accept_without_enough_data_is_not_analysed(tmp_path):
    from openpyxl import load_workbook

    items = [Assessment(cve_id="CVE-2026-6001", asset="api", source_row=2, scanner_severity="High",
                        gaps=["No EPSS score retrieved"],
                        exposure=ExposureMeasure(index=50, verdict="Accept", confidence="medium")),
             Assessment(cve_id="CVE-2026-6002", asset="api", source_row=3, scanner_severity="High",
                        exposure=ExposureMeasure(index=50, verdict="Accept", confidence="high"))]
    workbook = load_workbook(build_workbook(items, tmp_path / "out.xlsx", None))
    rows = {r["Export row"]: r for r in _table(workbook["Findings"], ["Export row", "Judgment",
                                                                      "Not analysed because", "Rationale"])}
    assert rows[2]["Judgment"] == "Not analysed" and rows[2]["Not analysed because"] == "Insufficient data"
    assert "not enough data to accept this risk (No EPSS score retrieved; confidence medium)" in rows[2]["Rationale"]
    assert rows[3]["Judgment"] == "Accept"
    assert [r["Export row"] for r in _table(workbook["Accepted"], ["Export row"])] == [3]


def test_licence_rows_say_so_and_issue_type_is_shown(tmp_path):
    from openpyxl import load_workbook

    from vulnometry.assessment import not_scored_summary

    not_scored = not_scored_summary([
        {"raw_severity": "Medium", "asset": "web", "title": "GPL-3.0 license", "row": 2, "issue_type": "License"},
        {"raw_severity": "High", "asset": "web", "title": "Prototype pollution", "row": 3,
         "issue_type": "Vulnerability"},
    ])
    workbook = load_workbook(build_workbook([], tmp_path / "out.xlsx", {"not_scored": not_scored, "assessed": 0,
                                                                        "actionable": 0, "suppressed_by_context": 0,
                                                                        "unattributed": 0}))
    rows = {r["Export row"]: r for r in _table(workbook["Findings"], ["Export row", "Issue type",
                                                                      "Not analysed because", "Rationale"])}
    assert rows[2]["Issue type"] == "License" and rows[2]["Not analysed because"] == "Licence issue"
    assert "a licence issue, not a vulnerability" in rows[2]["Rationale"]
    assert rows[3]["Issue type"] == "Vulnerability" and rows[3]["Not analysed because"] == "No CVE identifier"


def test_scanner_exploit_maturity_is_stated_in_the_rationale():
    item = Assessment(cve_id="CVE-2026-7001", asset="api", scanner_exploit_maturity="Proof of Concept",
                      exposure=ExposureMeasure(index=80, verdict="Accept", threat=0.2, reachability=0.5,
                                               consequence=0.8, confidence="high",
                                               threat_basis=["EPSS puts exploitation within 30 days at 0.30%"]))
    text = item.rationale()
    assert text.startswith("Accept: exploitation unlikely in the next 30 days")
    assert "scanner exploit maturity: Proof of Concept" in text, "a known exploit is never left unsaid"


def test_devsecops_gets_only_what_is_safe_to_suppress(tmp_path):
    from openpyxl import load_workbook

    def accept(row, **kw):
        return Assessment(cve_id=f"CVE-2026-{8000 + row}", asset="api", source_row=row, scanner_severity="High",
                          issue_id=f"SNYK-JS-X-{row}", issue_url=f"https://s.example/p#issue-SNYK-JS-X-{row}",
                          measured_at="2026-10-14T20:00:00+00:00",
                          exposure=ExposureMeasure(index=60, verdict="Accept", confidence="high", threat=0.2,
                                                   reachability=0.1, consequence=0.8, model_version="bei-1.1",
                                                   reachability_basis=["api is not internet-reachable"]),
                          **kw)

    items = [accept(2), accept(3, code_reachability="reachable"), accept(4, scanner_exploit_maturity="Mature"),
             accept(5, exploitation=ConfirmedExploitation(cve_id="x", confirmed=True)),
             Assessment(cve_id="CVE-2026-9000", asset="api", source_row=6, due_by="2027-02-11",
                        fixes=["axios 1.15.1"], exposure=ExposureMeasure(index=200, verdict="Schedule"))]
    summary = {"assessed": 5, "actionable": 0, "suppressed_by_context": 0, "unattributed": 0, "review_days": 182}
    workbook = load_workbook(build_workbook(items, tmp_path / "out.xlsx", summary))

    suppress = _table(workbook["DevSecOps - suppress"], ["Export row", "Issue ID", "Suppress until", "Ignore type",
                                                         "Ignore reason"])
    assert [r["Export row"] for r in suppress] == [2]
    assert suppress[0]["Suppress until"] == "2027-04-14", "182 days after the assessment"
    assert suppress[0]["Ignore type"] == "temporary-ignore"
    assert suppress[0]["Ignore reason"].startswith("Risk accepted: vulnometry bei-1.1 Accept (BEI 60.0) on 2026-10-14")
    assert "Re-review by 2027-04-14" in suppress[0]["Ignore reason"]

    accepted = {r["Export row"]: r["Suppress in scanner"]
                for r in _table(workbook["Accepted"], ["Export row", "Suppress in scanner"])}
    assert accepted[2] == "Yes"
    assert "call path" in accepted[3] and "mature exploit" in accepted[4] and "CISA KEV" in accepted[5]

    fix = _table(workbook["Engineering - fix"], ["Export row", "Fixed in", "Due by"])
    assert fix == [{"Export row": 6, "Fixed in": "axios 1.15.1", "Due by": "2027-02-11"}], \
        "accepted rows, suppressed or kept open, are not engineering's"


def test_rationale_keeps_names_as_written():
    item = Assessment(cve_id="CVE-2026-5002", asset="bridger Search", internet_exposed=False,
                      exposure=ExposureMeasure(index=60, verdict="Accept", threat=0.5, reachability=0.1,
                                               consequence=0.8, confidence="high",
                                               reachability_basis=["Attack vector is network",
                                                                   "Bridger Search is not internet-reachable"]))
    assert "— Bridger Search is not internet-reachable." in item.rationale()


def test_an_accept_mentions_its_fix_without_demanding_it():
    from vulnometry.exposure import directive_for
    from vulnometry.inventory import AssetProfile

    text = directive_for(ExposureMeasure(index=80, verdict="Accept"), ConfirmedExploitation(cve_id="x"),
                         ["js-yaml 4.2.0"], AssetProfile(name="api"))
    assert text.startswith("No action warranted.")
    assert "A fix exists (js-yaml 4.2.0); take it with routine dependency upgrades." in text
    assert "Upgrade to" not in text


def test_policy_puts_licence_rows_out_of_scope_and_still_judges_low_severity(tmp_path):
    from openpyxl import load_workbook

    from vulnometry.assessment import not_scored_summary
    from vulnometry.schema import ConfirmedExploitation

    items, summary = _snyk_like_rows()
    items += [
        Assessment(cve_id="CVE-2026-5001", asset="checkout-api", scanner="Snyk", scanner_severity="Low",
                   due_by="2026-10-20", source_row=8, exposure=ExposureMeasure(index=200, verdict="Schedule")),
        Assessment(cve_id="CVE-2026-5002", asset="checkout-api", scanner="Snyk", scanner_severity="Low",
                   due_by="2027-02-01", source_row=9, exploitation=ConfirmedExploitation(confirmed=True),
                   exposure=ExposureMeasure(index=300, verdict="Schedule")),
    ]
    summary["not_scored"] = not_scored_summary([
        {"raw_severity": "Low", "asset": "web", "title": "GPL-3.0 license", "row": 7, "issue_type": "License",
         "issue_url": "https://scanner.example/p2#issue-snyk:lic:gpl"}])
    summary["policy"] = {"issue_types": ["vulnerability"], "priority_severities": ["critical", "high", "medium"]}
    workbook = load_workbook(build_workbook(items, tmp_path / "out.xlsx", summary))
    by_row = {r["Export row"]: r for r in _table(workbook["Findings"], ["Export row", "Judgment", "Priority",
                                                                         "Due by", "Rationale"])}
    assert by_row[7]["Judgment"] == "Out of scope" and "license issue, not a vulnerability" in by_row[7]["Rationale"]
    assert by_row[8]["Judgment"] == "Schedule", "a Low is judged on exposure, not accepted on severity"
    assert by_row[8]["Priority"] == "Not prioritised (Low)" and by_row[8]["Due by"] == "2026-10-20"
    assert by_row[6]["Judgment"] == "Accept" and by_row[6]["Priority"] == "Not prioritised (Low)"
    assert by_row[9]["Priority"] == "Priority" and "CISA KEV" in by_row[9]["Rationale"], \
        "exploited in the wild is always a priority"
    assert by_row[2]["Priority"] == "Priority"

    engineering = [r["Export row"] for r in _table(workbook["Engineering - fix"], ["Export row"])]
    assert 7 not in engineering, "out of scope rows go to nobody"
    fixes = [r for r in engineering if r in (2, 3, 4, 8, 9)]
    assert fixes[-1] == 8, "a Low comes after every priority row, even with an earlier due date"
    counts = _counts(workbook["Findings"])
    assert counts["Out of scope (issue type)"] == 1 and counts["Total"] == 8


def test_a_raised_verdict_says_why_and_a_high_epss_is_never_a_reason_for_low_risk():
    from vulnometry.schema import ExploitProbability

    measure = ExposureMeasure(index=147, verdict="Schedule", scored_verdict="Accept", threat=0.8, reachability=0.1,
                              consequence=0.9, floor_reason="EPSS puts exploitation within 30 days at 64.41%",
                              reachability_basis=["Scanner's reachability analysis found no call path to the "
                                                  "vulnerable function"],
                              threat_basis=["EPSS puts exploitation within 30 days at 64.41%"], confidence="high")
    item = Assessment(cve_id="CVE-2026-1", asset="portal", exposure=measure,
                      probability=ExploitProbability(probability=0.6441, resolved=True))
    text = item.rationale()
    assert text.startswith("Schedule: EPSS puts exploitation within 30 days at 64.41%, so it is not left at Accept.")
    assert "the exposure index alone (147.0) gives Accept, on scanner's reachability analysis found no call path" in text

    accepted = Assessment(cve_id="CVE-2026-2", asset="portal", exposure=ExposureMeasure(
        index=90, verdict="Accept", threat=0.9, reachability=0.05, consequence=0.5, confidence="high",
        threat_basis=["EPSS puts exploitation within 30 days at 61.32%"],
        reachability_basis=["portal is not internet-reachable"]))
    assert "61.32%" not in accepted.rationale().split("Context:")[0], "a 61% EPSS cannot explain a low score"


def test_a_git_commit_is_not_offered_as_a_fixed_version():
    from vulnometry.assessment import _fix_versions
    from vulnometry.schema import Bulletin, Remedy

    bulletins = [Bulletin(remedies=[Remedy(component="", fixed_in="74b2db2938fad48a2ea54a9c8bf27a37a62c350d"),
                                    Remedy(component="lodash", fixed_in="4.17.21")])]
    assert _fix_versions(bulletins) == ["lodash 4.17.21"]


def test_several_fixes_in_one_range_drop_only_the_commits():
    from vulnometry.assessment import _fix_versions
    from vulnometry.schema import Bulletin, Remedy

    joined = Remedy(component="", fixed_in="4007498b13582d90ee1eda5d9920c324428b98b3, 986fb4892bb39f292ba0fd82eba11d2cbc503217")
    mixed = Remedy(component="yaml", fixed_in="abc1234def, 2.4.1")
    assert _fix_versions([Bulletin(remedies=[joined, mixed])]) == ["yaml 2.4.1"]


def test_a_directive_names_the_upgrade_once():
    from vulnometry.exposure import directive_for
    from vulnometry.inventory import AssetProfile
    from vulnometry.schema import ConfirmedExploitation

    asset = AssetProfile(name="portal")
    text = directive_for(ExposureMeasure(verdict="Schedule"), ConfirmedExploitation(), ["axios 1.15.1"], asset,
                         scanner_fixability="Fixable")
    assert "Upgrade to axios 1.15.1." in text and "see the scanner issue" not in text
    text = directive_for(ExposureMeasure(verdict="Accept"), ConfirmedExploitation(), [], asset,
                         scanner_fixability="Fixable")
    assert "The scanner reports a fix (Fixable)" in text
    text = directive_for(ExposureMeasure(verdict="Schedule"), ConfirmedExploitation(), ["x 1.0"], asset,
                         scanner_fixability="No Fix Supported")
    assert "parent that pulls it in" in text


def test_a_score_just_under_a_threshold_is_never_shown_rounded_up_to_it():
    measure = ExposureMeasure(index=149.8, verdict="Accept", threat=0.1, reachability=0.3, consequence=0.9,
                              confidence="high")
    assert "BEI 149.8" in Assessment(cve_id="CVE-2026-1", exposure=measure).one_line()


def test_a_schedule_row_with_no_fix_anywhere_waits_in_the_scanner_instead_of_the_engineering_queue(tmp_path):
    from openpyxl import load_workbook

    from vulnometry.schema import ConfirmedExploitation

    items, summary = _snyk_like_rows()
    url = "https://scanner.example/org/o/project/p9"
    items += [
        Assessment(cve_id="CVE-2026-6001", asset="checkout-api", scanner_severity="High", due_by="2027-02-01",
                   source_row=8, issue_url=url + "#issue-SNYK-JS-X-1", issue_id="SNYK-JS-X-1",
                   scanner_fixability="No Fix Supported", fixes_checked=True,
                   exposure=ExposureMeasure(index=200, verdict="Schedule", confidence="high")),
        Assessment(cve_id="CVE-2026-6002", asset="checkout-api", scanner_severity="High", due_by="2027-02-01",
                   source_row=9, scanner_fixability="No Fix Supported", fixes_checked=True,
                   exploitation=ConfirmedExploitation(confirmed=True),
                   exposure=ExposureMeasure(index=200, verdict="Schedule", confidence="high")),
        Assessment(cve_id="CVE-2026-6003", asset="checkout-api", scanner_severity="High", due_by="2027-02-01",
                   source_row=10, scanner_fixability="No Fix Supported", fixes=["x 1.2"], fixes_checked=True,
                   exposure=ExposureMeasure(index=200, verdict="Schedule", confidence="high")),
    ]
    workbook = load_workbook(build_workbook(items, tmp_path / "out.xlsx", summary))
    parked = {r["Export row"]: r for r in _table(workbook["DevSecOps - until fixable"],
                                                 ["Export row", "Ignore type", "Ignore reason"])}
    assert set(parked) == {8}, "KEV is never parked, and a published fixed version means upgrade"
    assert parked[8]["Ignore type"] == "temporary-ignore, until fixable"
    assert parked[8]["Ignore reason"].startswith("No fix available on")
    engineering = {r["Export row"] for r in _table(workbook["Engineering - fix"], ["Export row"])}
    assert 8 not in engineering and {9, 10, 4} <= engineering, "missing fix data alone never parks a row"
    by_row = {r["Export row"]: r for r in _table(workbook["Findings"], ["Export row", "Judgment"])}
    assert by_row[8]["Judgment"] == "Schedule", "parking it does not change the judgment"
