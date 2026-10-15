# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/), with the addition
that any change to the exposure model bumps `MODEL_VERSION` independently.

## [Unreleased]

Exposure model `bei-1.3`.

### Changed

- A WAF (or other network control) is credited only for weaknesses it can filter: injection,
  cross-site scripting, path traversal, SSRF, XXE, deserialization payloads, request smuggling,
  header injection, and denial of service. Authentication, cryptography, authorisation, data
  exposure, prototype pollution and unclassified weaknesses get no credit, and the rationale says
  the control was not counted. The weakness class comes from the scanner's CWE column when the
  export has one (new intake alias `cwe`), otherwise from the CVE record.

- Fixed versions no longer include git commit hashes from source-repository ranges, and an EPSS of
  10% or more is never cited as a reason for a low score. Directives name the upgrade once and,
  when the scanner offers no fix path, point at the parent dependency.

- Denial of service against an internal asset: when the CVSS impact is to availability alone
  (C:N/I:N) and the asset is not internet-exposed, Consequence is halved. The attacker has to be
  inside the network already and the worst case is a recoverable outage, not a breach. The
  rationale says so.
- Network controls (a WAF, firewall, CDN or DDoS service) no longer discount a CVE whose attack
  vector is local or physical, since they are not in that path; the rationale records that they
  were not counted. For a denial-of-service-only CVE they are credited with rate limiting and
  request filtering.

### Added

- Acceptance guardrails, both about exploitation. The index is unchanged, but the verdict is raised
  to a floor, and the rationale states why and what the index alone gave: CISA KEV is at least
  Remediate, and EPSS of 10% or more (the level at which an accepted risk is reopened) is at least
  Schedule. Every other factor, the scanner's call path included, is weighed in the index and
  overrides nothing on its own. Nothing is raised where the component is not deployed.
- Reproducible runs. `VULNOMETRY_EVIDENCE_RECORD=path` writes every feed response a run used
  (NVD, EPSS, KEV, OSV, GitHub) to a SQLite evidence file with the run's timestamp;
  `VULNOMETRY_EVIDENCE_REPLAY=path` answers every request from that file, never touches the
  network, and dates findings and due dates from the recorded run. Same export, inventory,
  model version and evidence give the same workbook. A request missing from the file is a gap,
  as it was in the recorded run.
- Inventory `policy` block: `issue_types` puts other issue types (licence) Out of scope, and
  `priority_severities` marks rows of other scanner severities 'Not prioritised' while still
  judging them. A Priority column appears on every sheet, Engineering - fix lists non-priority
  rows last, and the JSON summary has `by_judgment_priority`.

- Reachability now uses the scanner's own call-graph analysis when the export carries
  it, such as Snyk's `REACHABILITY` column. It is detected automatically, with no flag. "No path found" discounts
  the Reachability factor ×0.4, roughly one verdict band, unless the CVE is in CISA KEV,
  where observed exploitation outweighs a static call graph and the result is recorded
  but not applied. "Reachable" is recorded and changes nothing; "Not Applicable" and
  anything undecided are ignored. When duplicate rows disagree, the least favourable
  verdict wins. `Assessment.code_reachability` carries the normalised value; the
  workbook's Findings and Accepted sheets gain a **Code path** column, the CSV a
  `code_reachability` column, and the rationale mentions it.
- The scanner's own severity now appears in every output. The workbook has a Scanner
  severity column on Findings, Action Plan and Accepted, and `--format csv` has a
  `scanner_severity` column. The value was already read and used for the severity crosstab,
  but a reader could not see it against each verdict.
- Findings and Accepted have an Analysis column: `Not analysed` when the scan named a project
  or host that matched nothing in the inventory, so the verdict was reached on worst-case
  defaults. The rationale of such a finding opens with `Not analysed:` and says why.
  `Assessment.analysed()` exposes the same test.
- Rows in a spreadsheet or CSV export that carry no CVE identifier, such as licence issues and
  scanner-only advisories, are no longer dropped silently. `vulnometry import` says how many
  there are and lists them on the Manual review sheet with their scanner severity; JSON output
  carries them as `summary.not_scored`. `parse_tabular` and `load_findings` take an optional
  `unscored` list to collect them; callers that pass nothing see no change.

- Due-date windows can be set in the inventory with an `sla` block: `days` per verdict, and
  `scale: false` to give every asset the same window instead of scaling by tier, regime and
  environment. Unmatched findings use it too. Without the block nothing changes. The
  workbook's Method sheet states the policy that was applied.

- A finding that matched no inventory asset shows `Not analysed` in the Verdict column of the
  workbook instead of its worst-case result, and is left off the Accepted sheet, so it cannot be
  signed off or suppressed by mistake. The rationale still gives the provisional result. JSON
  findings carry `analysed`, CSV an `analysed` column, and the summary `not_analysed` and
  `by_verdict_analysed`.
- **One row per scanner row.** Rows of a spreadsheet export are no longer merged: two scanner
  issues that share a CVE and a project are two rows, each judged on its own. Findings has
  exactly one row per export row, including rows with no CVE, and a count table at the top that
  totals to the export. A row listing several CVEs is judged on the worst of them. Each row
  carries a **Judgment**: Fix (Contain or Remediate), Schedule, Accept, or Not analysed (no
  inventory match, or no CVE), with the reason. `export_rows()` builds these records; the JSON
  summary carries `by_judgment` and `intake`.
- Every list shows the scanner's Export row, Issue ID, Title, Project, Target, Project URL and
  Issue URL (read from columns such as `PROJECT_URL`, `ISSUE_URL`, `PROBLEM_TITLE`; the issue ID
  from an `ISSUE_ID`-style column or the issue link). Links are clickable. A row whose issue link
  already appeared on an earlier row says so in *Duplicate of row*; it is still listed.
- Manual review lists the Not analysed rows, To fix the Fix and Schedule rows by due date, and
  Accepted the Accept rows with sign-off columns: all filters of Findings. The separate Not
  scored sheet is gone; those rows are on Findings and Manual review.

- The scanner's fixability (e.g. Snyk `COMPUTED_FIXABILITY`: Fixable / Partially fixable / No
  supported fix) is read, shown in a Scanner fixability column, and used in the rationale and
  directive when no fixed version was looked up.

- An **Issue type** column (the scanner's Vulnerability / License classification) on every list, so
  rows can be filtered as in the scanner. Licence rows say so: "a licence issue, not a
  vulnerability, so exposure scoring does not apply".
- A **Scanner exploit maturity** column (e.g. Snyk `EXPLOIT_MATURITY`), also stated in the
  rationale's context, so a known exploit is never left unsaid next to an Accept.
- An Accept with confidence below high (CVE record, EPSS score or asset context missing) is
  judged **Not analysed (insufficient data)** instead, with the gaps named: the low score may
  only reflect missing data. It is kept off the Accepted sheet.

- **Engineering - fix** sheet (replaces To fix): every row that is not an accepted risk. Rows to
  fix (Contain, Remediate, Schedule) by due date with the fixed version to move to, then the rows
  that could not be judged, by scanner severity.
- **DevSecOps - suppress** sheet: the accepted rows that are safe to suppress in the scanner, each
  with its issue link, an ignore reason and a "Suppress until" date. An accepted row stays open
  in the scanner, and says why on the Accepted sheet, when the CVE is in CISA KEV, the scanner
  found a call path, or the scanner reports a mature exploit. `suppression()` holds the rule.
- `sla.review_days` in the inventory (default 90): how long an accepted risk stands before it is
  re-reviewed, and so when a suppression expires.
- Fixed versions follow the package the scanner issue names (Snyk `SNYK-JAVA-<PACKAGE>-n`): one
  CVE can span several packages, and a row is about one of them.
- An Accept with any evidence gap (a feed that failed) is judged Not analysed (insufficient
  data), as one with confidence below high already is.

### Fixed

- The GitHub exploit search matched any repository whose README mentioned the CVE, which is
  mostly projects recording a dependency upgrade: on a real Snyk export, 65 of 78 CVEs came back
  with "public exploit material", raising Threat and pushing findings up a verdict on the strength
  of a changelog. A repository now counts only when its name carries the CVE ID, or its
  description names the CVE and describes exploit material (exploit, PoC, payload, RCE, ...).
- An Accept's directive said "Upgrade to ..." after "No action warranted". It now says a fix
  exists and can be taken with routine dependency upgrades.
- GitHub's search API allows 30 requests a minute; searches were paced like the rest of the API
  (60 a minute), and the 403 GitHub sends when a limit is hit was not retried. Most exploit
  searches on a large run were refused, and a refused search returned "nothing found": a false
  negative that lowered Threat. Search now has its own pace, rate-limit responses are waited out,
  and a search that still fails is recorded as an evidence gap rather than as no exploit.
- The rationale of an Accept or Schedule cited the first evidence line recorded, not the one
  that lowered the score: "hard to reach in this environment — Attack vector is network" gives
  a reason something *is* reachable. It now cites the evidence that lowered the weakest factor
  (no call path, not internet-reachable, compensating controls, local vector, ...) and adds the
  strongest from the other factors under "Also".
- "Little sign anyone will try" overstated what a low EPSS score means, and was used even when
  public exploit code exists. The lead is now "exploitation unlikely in the next 30 days", and
  "no exploitation data yet" when there is no EPSS score.
- The Method sheet listed OSV, GitHub Security Advisories and a GitHub exploit search as data
  sources and said the code path could not be verified, whichever lens ran. It now states the
  sources the run's lens actually used, where exploit evidence came from, and how many findings
  had the scanner's call-path analysis applied.

- The rationale and directive said "No fixed version published" whenever no fix was known, but
  the signal lens never looks fixed versions up (only full and forensic query OSV and GitHub
  advisories), so the claim was made without checking. It is now made only when fixes were
  looked up; otherwise the scanner's fixability is reported, or nothing.

### Changed

- `MODEL_VERSION` is `bei-1.1`. Findings without call-graph data score exactly as
  under `bei-1.0`.

## [0.3.1] - 2026-09-10

### Fixed

- Every feed failed with `CERTIFICATE_VERIFY_FAILED` on a corporate network. httpx verifies
  against certifi, which does not know the private root that a TLS-inspecting proxy re-signs
  traffic with, so `curl` succeeded where vulnometry could not reach anything. Verification now
  goes through the operating system's own trust store via `truststore`, which is a dependency.
  Python 3.13 made this worse by enabling `VERIFY_X509_STRICT`, which rejects enterprise roots
  that omit the critical flag on `basicConstraints`; macOS and Windows tolerate those, so asking
  the OS fixes both halves. An explicit `SSL_CERT_FILE` or `SSL_CERT_DIR` still wins, and
  `VULNOMETRY_SYSTEM_TRUST=0` restores the old behaviour. `SSL_CERT_FILE` and
  `SSL_CERT_DIR` are added to the system store rather than swapped for it, because a
  corporate image commonly sets them to the company bundle, and treating that as
  "use this instead" reintroduces the failure on exactly the machines this fixes.
- A rejected certificate was retried four times and then reported as a raw OpenSSL string, which
  reads like a network fault and sends people looking for a CA bundle to download. It now fails
  on the first attempt and names the likely cause, the one-command way to confirm it, and the fix.


## [0.3.0] - 2026-09-10

### Added

- `summary.severity_crosstab`: how each severity band was judged, on both axes — what the
  scanner called it and what NVD's CVSS calls it — against the verdict. "You accepted 40
  Critical findings" is the first challenge any report of this kind meets, so it is stated
  rather than left to be discovered. `Assessment` now carries `scanner_severity`, the
  scanner's own rating verbatim; it is kept for comparison and never used in the score.
  Shown on the dashboard as three rankings of the same findings — what the scanner called
  Critical and High, what CVSS calls them, and what the model decided — with a
  plain-language summary, since the three routinely disagree.

### Changed

- Dashboard names the tool that produced the export rather than saying "the scanner".
  `sniff_tabular_scanner()` recognises Snyk, Tenable Nessus, Qualys, Rapid7 InsightVM, Wiz,
  Prisma Cloud, Trivy and Dependabot exports by the columns only that tool emits, and every
  signature needs at least two of them so a stray "Plugin ID" in a hand-made spreadsheet
  cannot make a report claim the data came from Nessus. Unrecognised exports still read
  "Scanner". Purely cosmetic: nothing in the model branches on it.
- Dashboard: dropped the "Highest exposure" findings table. It grew with the scan and on a
  real run pushed the page past 40 KB while duplicating the workbook's Findings and Action
  Plan sheets, which are the right place to read individual rows. The page is now a fixed
  size regardless of scan volume.

### Fixed

- Dashboard escaped everything except the scanner name, which reaches the page from the
  export and so could carry markup. Escaped, with a test that drives hostile strings through
  the real path: asset name, owner, business unit, title and scanner name all sourced from
  untrusted input.
- `scanner_band()` bucketed values that `float()` accepts but CVSS does not. `nan` compares
  False against every threshold and fell through to "None"; `inf` cleared the Critical
  threshold; negatives were silently swallowed. Only a score between 0 and 10 becomes a
  band now, so an odd value surfaces instead of being hidden, which is what the function
  already claimed to do.
- Tabular intake mapped `raw_severity` to the wrong column whenever an export carried both
  a finding severity and an asset criticality. `criticality` was a severity alias and the
  longest-alias-first tiebreak made it beat `severity`, so a Snyk export recorded
  `PROJECT_CRITICALITY` — the project's business-criticality tag — as the finding's
  severity. `criticality` is no longer a severity alias (asset criticality is modelled
  separately as tier) and the common explicit spellings are matched first.
- `vulnometry --version`, the MCP `serverInfo` handshake and the OpenAPI document all
  reported 0.1.0 on a 0.2.0 install: `__version__` is a second copy of the number in
  `pyproject.toml`, and the 0.2.0 release bumped one and not the other. A test now fails
  the build when the two disagree.
- Dashboard: the Critical/High/Other headers on the rankings table were centred over
  right-aligned counts, so no column lined up.

## [0.2.0] - 2026-09-10

### Added

- Every bulk report states how much the analysis narrowed the pile, under
  `summary.reduction`: scanner findings, unique CVEs, CVE-by-asset decisions, how many a
  severity-driven queue would call urgent (CVSS >= 7), how many are actionable, and finally
  the distinct (asset, package) upgrades to perform, since one dependency bump closes every
  CVE that package carries. `analysis_reduction_pct` is measured against the severity queue
  rather than the row count, so scanner duplication is not counted as the tool's work.
  Effort avoided is reported as a band with the per-finding triage assumption beside it
  (`VULNOMETRY_TRIAGE_MINUTES_LOW` / `_HIGH`) and never feeds a score. Rendered as a tree in
  the console, a numbered list in Markdown, a bar chart on the dashboard and a block in the
  workbook's Method sheet.
- Dashboard: a leadership view — a verdict KPI row that now includes **Accept**, each card
  carrying a plain-language subtitle; a second row with the severity-queue reduction, the
  upgrades left, the analyst hours avoided and what matched no asset; and a business-unit
  (or owner, or asset) by verdict heat map ordered by total exposure.
- Every assessment carries a one-sentence `rationale()`: what drove the verdict (the deciding
  factor and its evidence) plus the context it was judged in — internet exposure, tier, data
  class, EPSS score and its date, KEV status, confidence. `Assessment` now also keeps `tier`,
  `internet_exposed` and `data_classification` from the matched asset.
- Workbook: a new **Accepted** sheet — an audit-ready register of every finding below the
  action threshold, with the rationale, inputs, evidence gaps, model version and run timestamp,
  and blank columns for the human decision (who, when, review-by date, reopen triggers). The
  Findings sheet gains **Internet**, **EPSS date** and **Rationale** columns; the Method sheet
  records the run timestamp and model version. The Markdown report now lists Accepted findings
  with their rationale instead of dropping them.
- Findings keep the identifier the scan gave them (`source_asset`, `source_host`,
  `source_component` on `Assessment`) even when nothing in the inventory matches, so a
  bulk import no longer produces anonymous rows. The workbook gains a **Scanner ref**
  column; the Action Plan, terminal table, Markdown, CSV and dashboard fall back to the
  scan's own label (shown as `~name`) when there is no matched asset.
- `vulnometry inventory import EXPORT --map MAPPING.yaml`: build the business inventory
  from an arbitrary CSV/XLSX asset export (a CMDB extract, an application register). The
  mapping file names the columns and the value translations; built-in transforms cover
  multi-value cells, host extraction from URLs and tri-state booleans. Re-running merges,
  keeping fields added by hand. Also usable inline: `--inventory EXPORT --inventory-map MAPPING`.
- `docs/INVENTORY-IMPORT.md`: full reference and a runnable worked example
  (`examples/asset-export.csv`, `examples/inventory-mapping.yaml`,
  `examples/inventory-from-export.yaml`) with a line-by-line account of how each column is read.
- `aliases` on an asset: other names a scan might use for it (a scanner project, a code
  name, a ticket key). `Inventory.by_name()` resolves them, with glob support.
- CSV intake now decodes cp1252 / latin-1 exports, not just UTF-8.
- Dashboard screenshot in the README, with the sample export
  (`examples/scan-export.csv`) and generated page (`examples/exposure.html`) that produced it.

### Changed

- Dashboard cards centre their chart vertically, so a short chart no longer leaves
  a band of empty space when the card next to it is taller.

## [0.1.0] - 2026-09-02

First release. Exposure model `bei-1.0`.

### Added

- **Business Exposure Index.** `BEI = 1000 · Threat^0.8 · Reachability^0.7 ·
  Consequence^0.6`. Multiplicative, so any factor can veto; every factor carries
  its reasoning. Verdicts: Contain, Remediate, Schedule, Accept.
- **Business inventory** (`vulnometry.yaml`): asset tiers, owners, business units,
  environments, internet exposure, data classification, regulatory scope,
  compensating controls, component and hostname globs. Due dates derived from
  verdict plus asset policy.
- **Feeds:** NIST NVD with automatic CVE Program fallback, FIRST EPSS, CISA KEV,
  OSV.dev, GitHub Security Advisories, and heuristic exploit-artifact discovery.
- **Intake:** Excel and CSV with header-row detection and column alias matching;
  native JSON from Trivy, Grype, Snyk, OSV-Scanner, Dependabot and SARIF;
  lockfiles and SBOMs (requirements.txt, poetry.lock, package-lock.json, go.mod,
  Gemfile.lock, Cargo.lock, pom.xml, CycloneDX, SPDX).
- **Reporting:** annotated four-sheet Excel workbook (Findings, Action Plan, By
  Owner, Method); self-contained HTML dashboard with inline SVG and no
  JavaScript; terminal, JSON, Markdown and CSV output.
- **Commands:** `measure`, `import`, `sweep`, `compare`, `inventory`, `watch`,
  `ask`, `providers`, `doctor`, `actions`, `run`, `serve`, `cache`.
- **Surfaces:** MCP over stdio with no SDK dependency; OpenAI, Anthropic,
  Bedrock and Gemini tool schemas; FastAPI service with OpenAPI.
- **Providers:** Ollama, any OpenAI-compatible server, OpenAI/Codex, Azure AI
  Foundry and Azure OpenAI, AWS Bedrock, Anthropic, Google Gemini.
- Client-side per-host rate limiting and a SQLite feed cache.
- 58 offline tests.
