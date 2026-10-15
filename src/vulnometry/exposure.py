"""Business Exposure Index: 1000 * Threat**0.8 * Reachability**0.7 * Consequence**0.6."""

from __future__ import annotations

from .inventory import UNKNOWN_ASSET, AssetProfile
from .schema import (
    ConfirmedExploitation,
    ExploitArtifact,
    ExploitProbability,
    ExposureMeasure,
    Weakness,
)

MODEL_VERSION = "bei-1.2"

THREAT_EXPONENT = 0.8
REACH_EXPONENT = 0.7
CONSEQUENCE_EXPONENT = 0.6

THRESHOLDS = [(700, "Contain"), (400, "Remediate"), (150, "Schedule"), (0, "Accept")]

VERDICT_MEANING = {
    "Contain": "Act now, outside the normal change process.",
    "Remediate": "Fix within this sprint, ahead of the routine cycle.",
    "Schedule": "Queue for the next planned maintenance window.",
    "Accept": "No action warranted. Record the decision and move on.",
}

VECTOR_REACH = {"N": 1.0, "A": 0.45, "L": 0.2, "P": 0.05}

MATURITY_THREAT = {"weaponised": 0.78, "proof-of-concept": 0.55, "referenced": 0.35}

# A scanner's call-graph analysis found no path from this code to the vulnerable
# function. Strong evidence, not proof: reflection, dynamic dispatch and
# deserialisation hide call paths from static analysis, so it discounts rather
# than zeroes. 0.4 is the same weight as "not internet-reachable", and after the
# 0.7 exponent it roughly halves the index: about one verdict band.
CODE_UNREACHABLE_REACH = 0.4

# Controls that sit in the network path (a WAF, a firewall, a DDoS or rate-limiting service).
# They filter traffic, so they do nothing against an attack that needs local or physical access.
_NETWORK_CONTROL_WORDS = ("waf", "firewall", "ddos", "rate limit", "rate-limit", "rate limiting", "cdn",
                          "web application firewall", "intrusion prevention")

# Denial of service only (no confidentiality or integrity impact) against an internal asset: an
# attacker must already be on the internal network, and the worst case is a recoverable outage of
# one internal system, not a breach. Halves the consequence.
INTERNAL_DOS_CONSEQUENCE = 0.5


def _network_control(name: str) -> bool:
    text = name.lower()
    return any(word in text for word in _NETWORK_CONTROL_WORDS)


def availability_only(severity) -> bool:
    """CVSS impact is to availability alone: the flaw can take the service down but not read or change data."""
    if severity is None:
        return False
    c, i, a = (_first_letter(severity.confidentiality), _first_letter(severity.integrity),
               _first_letter(severity.availability))
    return c == "N" and i == "N" and a in ("H", "L")


def _first_letter(value: str) -> str:
    return (value or "").upper()[:1]


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def compute_threat(
    probability: ExploitProbability,
    exploitation: ConfirmedExploitation,
    artifacts: list[ExploitArtifact],
) -> tuple[float, list[str]]:
    basis: list[str] = []

    if exploitation.confirmed:
        basis.append("CISA KEV lists this as exploited in the wild: observed, not predicted")
        if exploitation.ransomware_linked:
            basis.append("Associated with known ransomware campaigns")
        if exploitation.federal_deadline:
            basis.append(f"US federal remediation deadline {exploitation.federal_deadline}")
        return 1.0, basis

    candidates: list[float] = []

    if probability.probability is not None:
        epss_threat = probability.probability ** 0.35
        candidates.append(epss_threat)
        percentile = (
            f", ahead of {probability.percentile * 100:.0f}% of all CVEs"
            if probability.percentile is not None
            else ""
        )
        basis.append(
            f"EPSS puts exploitation within 30 days at "
            f"{probability.probability * 100:.2f}%{percentile}"
        )
    else:
        basis.append("No EPSS score, usually a very new CVE, so treat as unresolved rather than safe")

    if artifacts:
        best = max(MATURITY_THREAT.get(a.maturity, 0.3) for a in artifacts)
        popularity = max((a.popularity or 0) for a in artifacts)
        if popularity > 200:
            best = min(0.85, best + 0.07)
        candidates.append(best)
        kinds = sorted({a.maturity for a in artifacts})
        basis.append(f"Public exploit material found ({', '.join(kinds)}; {len(artifacts)} item(s))")

    if not candidates:
        return 0.08, basis + ["No evidence of exploitation activity"]

    threat = max(candidates)
    return _clamp(threat, 0.02, 1.0), basis


def compute_reachability(
    weakness: Weakness,
    asset: AssetProfile,
    code_reachability: str = "",
    exploited: bool = False,
) -> tuple[float, list[str], str]:
    basis: list[str] = []
    severity = weakness.primary_severity()

    if asset.deployed is False:
        return 0.0, [f"{asset.name} does not run the affected component"], "not-deployed"

    if severity and severity.attack_vector:
        letter = _first_letter(severity.attack_vector)
        reach = VECTOR_REACH.get(letter, 0.5)
        basis.append(f"Attack vector is {severity.attack_vector.lower()}")
    else:
        reach = 0.6
        basis.append("Attack vector unpublished, assumed partially reachable")

    if severity:
        if _first_letter(severity.attack_complexity) == "H":
            reach *= 0.7
            basis.append("High attack complexity narrows who can pull it off")
        privileges = _first_letter(severity.privileges_required)
        if privileges == "L":
            reach *= 0.8
            basis.append("Requires some level of authenticated access")
        elif privileges == "H":
            reach *= 0.55
            basis.append("Requires privileged access already")
        if _first_letter(severity.user_interaction) == "R":
            reach *= 0.75
            basis.append("Needs a user to be tricked into acting")

    if asset.internet_exposed is True:
        basis.append(f"{asset.name} is reachable from the internet")
    elif asset.internet_exposed is False:
        reach *= 0.4
        basis.append(f"{asset.name} is not internet-reachable")
    else:
        reach *= 0.7
        basis.append("Internet exposure unknown: discounted, not dismissed")

    if asset.deployed is None and asset.name != UNKNOWN_ASSET.name:
        reach *= 0.9
        basis.append("Deployment status unconfirmed")

    if asset.has_controls:
        local = severity is not None and _first_letter(severity.attack_vector) in ("L", "P")
        applicable = [c for c in asset.compensating_controls if not (local and _network_control(c))]
        if applicable:
            reach *= 0.45
            line = f"Compensating controls in place: {', '.join(applicable[:3])}"
            if availability_only(severity) and any(_network_control(c) for c in applicable):
                line += " (rate limiting and request filtering in front of the app blunt denial-of-service traffic)"
            basis.append(line)
        else:
            basis.append(f"{', '.join(asset.compensating_controls[:3])} not counted: a network control is not "
                         "in the path of a local attack")

    if code_reachability == "reachable":
        basis.append("Scanner's reachability analysis found a call path to the vulnerable function")
    elif code_reachability == "unreachable":
        if exploited:
            # Exploited in the wild is observed fact; a static call graph that
            # says otherwise is the weaker evidence. Recorded, not applied.
            basis.append(
                "Scanner found no call path to the vulnerable function, "
                "not discounted because it is exploited in the wild"
            )
        else:
            reach *= CODE_UNREACHABLE_REACH
            basis.append("Scanner's reachability analysis found no call path to the vulnerable function")

    collapsed = "reachability" if reach < 0.05 else ""
    return _clamp(reach), basis, collapsed


def compute_consequence(weakness: Weakness, asset: AssetProfile) -> tuple[float, list[str]]:
    basis: list[str] = []
    severity = weakness.primary_severity()

    if severity:
        impact = severity.impact_fraction
        if severity.confidentiality or severity.integrity or severity.availability:
            basis.append(
                f"CVSS impact C:{severity.confidentiality or '?'} "
                f"I:{severity.integrity or '?'} A:{severity.availability or '?'}"
            )
        elif severity.base_score is not None:
            basis.append(f"CVSS {severity.version} base score {severity.base_score:g} used as an impact proxy")
    else:
        impact = 0.5
        basis.append("No CVSS published, impact assumed moderate pending analysis")

    consequence = impact * asset.tier_weight
    if availability_only(severity) and asset.internet_exposed is False:
        consequence *= INTERNAL_DOS_CONSEQUENCE
        basis.append("Denial of service only, no data read or changed, on an internal app: an attacker must "
                     "already be inside the network, and the worst case is a recoverable outage")
    basis.append(f"{asset.name} is {asset.tier_label} (tier weight {asset.tier_weight:g})")

    consequence *= asset.data_weight
    if asset.data_classification:
        basis.append(f"Holds {asset.data_classification} data (weight {asset.data_weight:g})")

    if asset.regulated:
        consequence *= 1.12
        basis.append(f"In scope for {', '.join(asset.regimes)}, breach carries reporting duties")

    if asset.is_production:
        consequence *= 1.08
        basis.append("Production environment")
    elif (asset.environment or "").lower().startswith("dev"):
        consequence *= 0.7
        basis.append("Development environment")

    return _clamp(consequence, 0.02, 1.0), basis


def verdict_for(index: float) -> str:
    for threshold, label in THRESHOLDS:
        if index >= threshold:
            return label
    return "Accept"


def _confidence(weakness: Weakness, probability: ExploitProbability, asset: AssetProfile) -> str:
    known = 0
    if weakness.resolved and weakness.primary_severity():
        known += 1
    if probability.resolved:
        known += 1
    if asset.tier is not None and asset.internet_exposed is not None:
        known += 1
    return {0: "low", 1: "low", 2: "medium", 3: "high"}[known]


def measure_exposure(
    weakness: Weakness,
    probability: ExploitProbability,
    exploitation: ConfirmedExploitation,
    artifacts: list[ExploitArtifact] | None = None,
    asset: AssetProfile | None = None,
    code_reachability: str = "",
) -> ExposureMeasure:
    artifacts = artifacts or []
    asset = asset or UNKNOWN_ASSET

    threat, threat_basis = compute_threat(probability, exploitation, artifacts)
    reach, reach_basis, collapsed = compute_reachability(
        weakness, asset, code_reachability, exploited=exploitation.confirmed
    )
    consequence, consequence_basis = compute_consequence(weakness, asset)

    index = 1000.0 * (
        (threat ** THREAT_EXPONENT)
        * (reach ** REACH_EXPONENT)
        * (consequence ** CONSEQUENCE_EXPONENT)
    )
    index = round(_clamp(index, 0.0, 1000.0), 1)

    return ExposureMeasure(
        index=index,
        verdict=verdict_for(index),
        model_version=MODEL_VERSION,
        threat=round(threat, 3),
        reachability=round(reach, 3),
        consequence=round(consequence, 3),
        threat_basis=threat_basis,
        reachability_basis=reach_basis,
        consequence_basis=consequence_basis,
        collapsed_by=collapsed,
        confidence=_confidence(weakness, probability, asset),
    )


# Guardrails: evidence that rules out accepting a risk, whatever the index says. They raise the
# verdict to a floor and say why; the index is left as computed, so the arithmetic stays auditable.
EPSS_FLOOR = 0.10            # the same level at which an accepted risk is reopened
_RANK = {"Accept": 0, "Schedule": 1, "Remediate": 2, "Contain": 3}


def apply_floors(
    measure: ExposureMeasure,
    exploitation: ConfirmedExploitation,
    probability: ExploitProbability,
    asset: AssetProfile,
    code_reachability: str = "",
    scanner_exploit_maturity: str = "",
    critical: bool = False,
) -> ExposureMeasure:
    """``critical``: the finding is rated critical (by the scanner, or CVSS 9.0+ without one)."""
    if measure.collapsed_by == "not-deployed":
        return measure
    floors: list[tuple[str, str]] = []
    if exploitation.confirmed:
        floors.append(("Remediate", "it is exploited in the wild (CISA KEV), which rules out accepting or "
                                    "deferring it"))
    if probability.probability is not None and probability.probability >= EPSS_FLOOR:
        floors.append(("Schedule", f"EPSS puts exploitation within 30 days at {probability.probability * 100:.2f}%, "
                                   f"at or above the {EPSS_FLOOR * 100:.0f}% level at which an accepted risk is "
                                   "reopened"))
    facing = asset.internet_exposed is True
    if facing and code_reachability == "reachable":
        floors.append(("Schedule", "the scanner found a call path to the vulnerable function on an "
                                   "internet-facing asset"))
    if facing and (scanner_exploit_maturity or "").strip().lower() == "mature":
        floors.append(("Schedule", "the scanner reports a mature exploit and the asset is internet-facing"))
    if facing and critical and code_reachability != "unreachable":
        # A low EPSS is a forecast and a WAF is not a fix; accepting a critical flaw on an internet-facing
        # asset needs evidence that the vulnerable code is not reached.
        floors.append(("Schedule", "a critical finding on an internet-facing asset is accepted only with the "
                                   "scanner's evidence that the vulnerable code is not called, and there is none"))
    raising = [(v, why) for v, why in floors if _RANK[v] > _RANK.get(measure.verdict, 0)]
    if not raising:
        return measure
    top = max(_RANK[v] for v, _ in raising)
    verdict = next(v for v, r in _RANK.items() if r == top)
    measure.scored_verdict = measure.verdict
    measure.verdict = verdict
    measure.floor_reason = "; and ".join(why for _, why in raising)
    return measure


def directive_for(
    measure: ExposureMeasure,
    exploitation: ConfirmedExploitation,
    fixes: list[str],
    asset: AssetProfile,
    due_by: str = "",
    fixes_checked: bool = True,
    scanner_fixability: str = "",
) -> str:
    """The action sentence that goes in the ticket.

    Only says no fix exists when fix versions were actually looked up (the full and forensic
    lenses query OSV and GitHub advisories; signal does not). The scanner's own fixability is
    reported when that is all there is.
    """
    parts = [VERDICT_MEANING.get(measure.verdict, "Review.")]

    if measure.collapsed_by == "not-deployed":
        return (
            f"{asset.name} does not run the affected component, so there is nothing to fix here. "
            "Confirm the inventory entry is current, then close."
        )

    if due_by:
        parts.append(f"Target date {due_by}.")
    if exploitation.confirmed and exploitation.federal_deadline:
        parts.append(f"CISA deadline for federal agencies was {exploitation.federal_deadline}.")
    scanner_has_fix = scanner_fixability.strip().lower() in ("fixable", "partially fixable")
    if fixes:
        parts.append(f"A fix exists ({', '.join(fixes[:3])}); take it with routine dependency upgrades."
                     if measure.verdict == "Accept" else f"Upgrade to {', '.join(fixes[:3])}.")
        if "no fix" in scanner_fixability.lower():
            parts.append("The scanner offers no automatic fix path, which usually means the package arrives "
                         "through another dependency: upgrade the parent that pulls it in, or pin the fixed version.")
    elif scanner_has_fix and measure.verdict == "Accept":
        parts.append(f"The scanner reports a fix ({scanner_fixability}); take it with routine dependency upgrades.")
    elif scanner_fixability and measure.verdict in ("Contain", "Remediate", "Schedule"):
        parts.append(f"Scanner fixability: {scanner_fixability}; see the scanner issue for the fixed version.")
    elif fixes_checked and measure.verdict in ("Contain", "Remediate"):
        parts.append("No fixed version published. Apply the vendor mitigation or isolate the service.")
    if measure.confidence == "low":
        parts.append("Confidence is low; the inventory entry or the CVE record is incomplete.")

    return " ".join(parts)
