"""The exposure model is the product. It gets the most tests."""

from vulnometry.exposure import measure_exposure, verdict_for
from vulnometry.inventory import UNKNOWN_ASSET, AssetProfile
from vulnometry.schema import (
    ConfirmedExploitation,
    ExploitArtifact,
    ExploitProbability,
    Severity,
    Weakness,
)


def wormable(score: float = 9.8) -> Weakness:
    return Weakness(
        cve_id="CVE-2024-1",
        resolved=True,
        severities=[Severity(
            version="3.1", base_score=score, rating="CRITICAL",
            attack_vector="NETWORK", attack_complexity="LOW",
            privileges_required="NONE", user_interaction="NONE",
            confidentiality="HIGH", integrity="HIGH", availability="HIGH",
        )],
    )


def local_nuisance() -> Weakness:
    return Weakness(
        cve_id="CVE-2024-2",
        resolved=True,
        severities=[Severity(
            version="3.1", base_score=3.3, rating="LOW",
            attack_vector="LOCAL", attack_complexity="HIGH",
            privileges_required="HIGH", user_interaction="REQUIRED",
            confidentiality="NONE", integrity="NONE", availability="LOW",
        )],
    )


CROWN_JEWEL = AssetProfile(name="checkout", tier=1, internet_exposed=True,
                           environment="production", data_classification="restricted",
                           regimes=["pci-dss"], deployed=True)
LAB_BOX = AssetProfile(name="lab", tier=3, internet_exposed=False,
                       environment="development", data_classification="public", deployed=True)


def test_not_deployed_collapses_exposure_to_zero():
    """The headline claim: context can veto, with no override rule involved."""
    shelved = AssetProfile(name="decommissioned", tier=1, internet_exposed=True, deployed=False)
    measure = measure_exposure(
        wormable(10.0),
        ExploitProbability(probability=0.97, resolved=True),
        ConfirmedExploitation(confirmed=True, ransomware_linked=True),
        [ExploitArtifact(maturity="weaponised", popularity=5000)],
        shelved,
    )
    assert measure.index == 0.0
    assert measure.verdict == "Accept"
    assert measure.collapsed_by == "not-deployed"
    assert measure.threat == 1.0, "threat is still maximal, only reachability vetoed"


def test_same_cve_lands_differently_by_context():
    args = (wormable(10.0), ExploitProbability(probability=0.94, resolved=True),
            ConfirmedExploitation(confirmed=True), [])
    critical = measure_exposure(*args, CROWN_JEWEL)
    lab = measure_exposure(*args, LAB_BOX)

    assert critical.verdict == "Contain"
    assert critical.index > lab.index * 3
    assert critical.threat == lab.threat, "threat must be context-independent"
    assert critical.reachability > lab.reachability
    assert critical.consequence > lab.consequence


def test_severe_but_unreachable_ranks_below_mild_and_exploited():
    """The failure mode this whole tool exists to prevent."""
    severe_unreachable = measure_exposure(
        wormable(9.8), ExploitProbability(probability=0.02, resolved=True),
        ConfirmedExploitation(), [],
        AssetProfile(name="lab", tier=3, internet_exposed=False, deployed=True,
                     environment="development", data_classification="public"),
    )
    mild_exploited = measure_exposure(
        Weakness(cve_id="CVE-2024-3", resolved=True, severities=[Severity(
            version="3.1", base_score=6.1, attack_vector="NETWORK", attack_complexity="LOW",
            privileges_required="NONE", user_interaction="NONE",
            confidentiality="HIGH", integrity="LOW", availability="NONE")]),
        ExploitProbability(probability=0.6, resolved=True),
        ConfirmedExploitation(confirmed=True), [], CROWN_JEWEL,
    )
    assert mild_exploited.index > severe_unreachable.index
    assert mild_exploited.verdict == "Contain"


def test_confirmed_exploitation_maxes_threat():
    measure = measure_exposure(
        wormable(), ExploitProbability(probability=0.001, resolved=True),
        ConfirmedExploitation(confirmed=True, federal_deadline="2025-01-01"), [], CROWN_JEWEL,
    )
    assert measure.threat == 1.0, "observation beats prediction"
    assert any("KEV" in b for b in measure.threat_basis)


def test_compensating_controls_reduce_reachability_only():
    base = measure_exposure(wormable(), ExploitProbability(probability=0.5, resolved=True),
                            ConfirmedExploitation(), [], CROWN_JEWEL)
    guarded = AssetProfile(**{**CROWN_JEWEL.__dict__, "compensating_controls": ["WAF virtual patch"]})
    with_controls = measure_exposure(wormable(), ExploitProbability(probability=0.5, resolved=True),
                                     ConfirmedExploitation(), [], guarded, cwe_ids=["CWE-89"])
    assert with_controls.reachability < base.reachability
    assert with_controls.consequence == base.consequence
    assert with_controls.threat == base.threat


def test_unknown_context_is_pessimistic_not_optimistic():
    args = (wormable(), ExploitProbability(probability=0.4, resolved=True), ConfirmedExploitation(), [])
    unknown = measure_exposure(*args, UNKNOWN_ASSET)
    known_safe = measure_exposure(*args, AssetProfile(name="x", tier=3, internet_exposed=False, deployed=True))
    assert unknown.reachability > known_safe.reachability


def test_regulated_scope_raises_consequence():
    plain = AssetProfile(name="a", tier=2, deployed=True, data_classification="confidential")
    regulated = AssetProfile(name="a", tier=2, deployed=True, data_classification="confidential",
                             regimes=["hipaa"])
    args = (wormable(), ExploitProbability(probability=0.3, resolved=True), ConfirmedExploitation(), [])
    assert measure_exposure(*args, regulated).consequence > measure_exposure(*args, plain).consequence


def test_local_nuisance_on_a_lab_box_is_accepted():
    measure = measure_exposure(local_nuisance(), ExploitProbability(probability=0.0004, resolved=True),
                               ConfirmedExploitation(), [], LAB_BOX)
    assert measure.verdict == "Accept"
    assert measure.index < 20


def test_weaponised_artifacts_outrank_a_bare_poc():
    args = (wormable(), ExploitProbability(probability=0.05, resolved=True), ConfirmedExploitation())
    poc = measure_exposure(*args, [ExploitArtifact(maturity="proof-of-concept")], CROWN_JEWEL)
    armed = measure_exposure(*args, [ExploitArtifact(maturity="weaponised")], CROWN_JEWEL)
    assert armed.threat > poc.threat


def test_every_factor_carries_its_reasoning():
    measure = measure_exposure(wormable(), ExploitProbability(probability=0.5, resolved=True),
                               ConfirmedExploitation(), [], CROWN_JEWEL)
    assert measure.threat_basis and measure.reachability_basis and measure.consequence_basis


def test_confidence_degrades_with_missing_evidence():
    complete = measure_exposure(wormable(), ExploitProbability(probability=0.5, resolved=True),
                                ConfirmedExploitation(), [], CROWN_JEWEL)
    sparse = measure_exposure(Weakness(cve_id="CVE-2024-9"), ExploitProbability(), ConfirmedExploitation(),
                              [], UNKNOWN_ASSET)
    assert complete.confidence == "high"
    assert sparse.confidence == "low"


def test_verdict_thresholds():
    assert verdict_for(950) == "Contain"
    assert verdict_for(700) == "Contain"
    assert verdict_for(699) == "Remediate"
    assert verdict_for(400) == "Remediate"
    assert verdict_for(399) == "Schedule"
    assert verdict_for(150) == "Schedule"
    assert verdict_for(149) == "Accept"


def test_index_stays_in_range_across_extremes():
    for probability in (None, 0.0, 0.5, 1.0):
        for asset in (UNKNOWN_ASSET, CROWN_JEWEL, LAB_BOX):
            measure = measure_exposure(
                wormable(10.0),
                ExploitProbability(probability=probability, resolved=probability is not None),
                ConfirmedExploitation(confirmed=True), [], asset,
            )
            assert 0.0 <= measure.index <= 1000.0


def test_no_call_path_discounts_reachability_by_about_one_band():
    args = (wormable(), ExploitProbability(probability=0.5, resolved=True), ConfirmedExploitation(), [], CROWN_JEWEL)
    base = measure_exposure(*args)
    no_path = measure_exposure(*args, code_reachability="unreachable")

    assert no_path.reachability < base.reachability
    assert no_path.threat == base.threat and no_path.consequence == base.consequence
    assert abs(no_path.index / base.index - 0.4 ** 0.7) < 0.01
    assert any("no call path" in b for b in no_path.reachability_basis)


def test_confirmed_call_path_is_recorded_not_scored():
    args = (wormable(), ExploitProbability(probability=0.5, resolved=True), ConfirmedExploitation(), [], CROWN_JEWEL)
    base = measure_exposure(*args)
    reachable = measure_exposure(*args, code_reachability="reachable")

    assert reachable.index == base.index
    assert any("found a call path" in b for b in reachable.reachability_basis)


def test_exploited_in_the_wild_outranks_a_static_call_graph():
    kev = ConfirmedExploitation(confirmed=True)
    args = (wormable(), ExploitProbability(probability=0.5, resolved=True), kev, [], CROWN_JEWEL)
    base = measure_exposure(*args)
    no_path = measure_exposure(*args, code_reachability="unreachable")

    assert no_path.index == base.index, "KEV findings are never discounted on call-graph evidence"
    assert any("not discounted" in b for b in no_path.reachability_basis)


def test_model_version_default_matches_the_model():
    from vulnometry.exposure import MODEL_VERSION
    from vulnometry.schema import ExposureMeasure

    assert ExposureMeasure().model_version == MODEL_VERSION


def dos_only(vector: str = "NETWORK") -> Weakness:
    return Weakness(
        cve_id="CVE-2024-3",
        resolved=True,
        severities=[Severity(
            version="3.1", base_score=7.5, rating="HIGH",
            attack_vector=vector, attack_complexity="LOW",
            privileges_required="NONE", user_interaction="NONE",
            confidentiality="NONE", integrity="NONE", availability="HIGH",
        )],
    )


def _internal(**extra) -> AssetProfile:
    return AssetProfile(name="ledger", tier=1, internet_exposed=False, environment="production",
                        data_classification="confidential", deployed=True, **extra)


def test_denial_of_service_on_an_internal_app_halves_the_consequence():
    probability = ExploitProbability(probability=0.01, resolved=True)
    internal_dos = measure_exposure(dos_only(), probability, ConfirmedExploitation(), [], _internal())
    external = AssetProfile(name="portal", tier=1, internet_exposed=True, environment="production",
                            data_classification="confidential", deployed=True)
    external_dos = measure_exposure(dos_only(), probability, ConfirmedExploitation(), [], external)
    assert round(internal_dos.consequence * 2, 3) == round(external_dos.consequence, 3)
    assert any("Denial of service only" in b and "inside the network" in b for b in internal_dos.consequence_basis)
    assert not any("Denial of service only" in b for b in external_dos.consequence_basis)
    full_impact = measure_exposure(wormable(7.5), probability, ConfirmedExploitation(), [], _internal())
    assert not any("Denial of service only" in b for b in full_impact.consequence_basis), \
        "a flaw that can read or change data is not discounted as an outage"


def test_a_waf_is_credited_against_floods_but_not_against_a_local_attack():
    probability = ExploitProbability(probability=0.01, resolved=True)
    behind_waf = AssetProfile(name="portal", tier=1, internet_exposed=True, deployed=True,
                              compensating_controls=["Edge WAF"])
    remote = measure_exposure(dos_only(), probability, ConfirmedExploitation(), [], behind_waf)
    assert any("Edge WAF" in b and "denial-of-service traffic" in b for b in remote.reachability_basis)
    bare = AssetProfile(name="portal", tier=1, internet_exposed=True, deployed=True)
    local_bare = measure_exposure(dos_only("LOCAL"), probability, ConfirmedExploitation(), [], bare)
    local_waf = measure_exposure(dos_only("LOCAL"), probability, ConfirmedExploitation(), [], behind_waf)
    assert local_waf.reachability == local_bare.reachability, "a WAF is not in the path of a local attack"
    assert any("not counted" in b for b in local_waf.reachability_basis)


def _accepted(asset: AssetProfile, epss: float = 0.002):
    from vulnometry.exposure import apply_floors

    probability = ExploitProbability(probability=epss, resolved=True)
    measure = measure_exposure(local_nuisance(), probability, ConfirmedExploitation(), [], asset)
    assert measure.verdict == "Accept"
    return measure, probability, apply_floors


def test_guardrails_raise_an_accept_but_never_change_the_index():
    exposed = AssetProfile(name="portal", tier=3, internet_exposed=True, deployed=True)
    measure, probability, apply_floors = _accepted(exposed, epss=0.64)
    index = measure.index
    raised = apply_floors(measure, ConfirmedExploitation(), probability, exposed)
    assert raised.verdict == "Schedule" and raised.scored_verdict == "Accept" and raised.index == index
    assert "64.00%" in raised.floor_reason and "reopened" in raised.floor_reason

    measure, probability, _ = _accepted(exposed)
    kev = apply_floors(measure, ConfirmedExploitation(confirmed=True), probability, exposed)
    assert kev.verdict == "Remediate" and "CISA KEV" in kev.floor_reason



def test_guardrails_leave_a_well_founded_accept_alone():
    exposed = AssetProfile(name="portal", tier=3, internet_exposed=True, deployed=True)
    measure, probability, apply_floors = _accepted(exposed)
    kept = apply_floors(measure, ConfirmedExploitation(), probability, exposed)
    assert kept.verdict == "Accept" and not kept.floor_reason, \
        "no single scanner flag overrides the index; only exploitation evidence does"
    gone = AssetProfile(name="old", tier=1, internet_exposed=True, deployed=False)
    measure = measure_exposure(wormable(), ExploitProbability(probability=0.9, resolved=True),
                               ConfirmedExploitation(confirmed=True), [], gone)
    assert apply_floors(measure, ConfirmedExploitation(confirmed=True), ExploitProbability(probability=0.9),
                        gone).verdict == "Accept", "nothing to fix where the component is not deployed"


def test_a_waf_is_credited_only_against_what_it_filters():
    probability = ExploitProbability(probability=0.01, resolved=True)
    guarded = AssetProfile(name="login", tier=1, internet_exposed=True, deployed=True,
                           compensating_controls=["Edge WAF"])
    bare = AssetProfile(name="login", tier=1, internet_exposed=True, deployed=True)
    plain = measure_exposure(wormable(), probability, ConfirmedExploitation(), [], bare, cwe_ids=["CWE-79"])
    xss = measure_exposure(wormable(), probability, ConfirmedExploitation(), [], guarded, cwe_ids=["CWE-79"])
    assert xss.reachability < plain.reachability
    assert any("inspect requests for cross-site scripting" in b for b in xss.reachability_basis)
    for cwe in (["CWE-287"], ["CWE-1321"], ["CWE-295"], []):
        flaw = measure_exposure(wormable(), probability, ConfirmedExploitation(), [], guarded, cwe_ids=cwe)
        assert flaw.reachability == plain.reachability, f"a WAF does nothing for {cwe or 'unknown'}"
        assert any("not counted: a WAF does not filter this kind of weakness" in b for b in flaw.reachability_basis)


def test_the_rationale_says_when_a_waf_was_not_counted():
    from vulnometry.schema import Assessment

    guarded = AssetProfile(name="login", tier=1, internet_exposed=True, deployed=True,
                           compensating_controls=["Edge WAF"])
    measure = measure_exposure(wormable(), ExploitProbability(probability=0.01, resolved=True),
                               ConfirmedExploitation(), [], guarded, cwe_ids=["CWE-287"])
    text = Assessment(cve_id="CVE-2024-1", asset="login", exposure=measure).rationale()
    assert "Edge WAF not counted: a WAF does not filter this kind of weakness (CWE-287)." in text
