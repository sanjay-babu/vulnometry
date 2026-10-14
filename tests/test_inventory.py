import pytest

from vulnometry.inventory import TEMPLATE, AssetProfile, Inventory, SlaPolicy


def test_template_parses(tmp_path):
    path = tmp_path / "vulnometry.yaml"
    path.write_text(TEMPLATE)
    inventory = Inventory.load(path)
    assert len(inventory.assets) == 3
    checkout = inventory.by_name("checkout-api")
    assert checkout.tier == 1
    assert checkout.internet_exposed is True
    assert "pci-dss" in checkout.regimes
    assert checkout.regulated


def test_friendly_aliases_are_accepted():
    inventory = Inventory.from_dict({"assets": [
        {"name": "api", "criticality": 1, "team": "sre@x.com", "packages": ["log4j*"]}
    ]})
    asset = inventory.assets[0]
    assert asset.tier == 1
    assert asset.owner == "sre@x.com"
    assert asset.components == ["log4j*"]


def test_host_and_component_globs():
    asset = AssetProfile(name="api", hosts=["web-*.prod.example.com"],
                         components=["org.apache.logging.log4j*"])
    assert asset.matches_host("web-03.prod.example.com")
    assert not asset.matches_host("db-01.prod.example.com")
    assert asset.matches_component("org.apache.logging.log4j:log4j-core")
    assert not asset.matches_component("requests")


def test_resolution_precedence():
    inventory = Inventory.from_dict({"assets": [
        {"name": "api", "tier": 1, "hosts": ["web-*"]},
        {"name": "batch", "tier": 3, "components": ["log4j*"]},
        {"name": "gateway", "tier": 1, "components": ["log4j*"]},
    ]})
    assert inventory.resolve(asset_name="api").name == "api"
    assert inventory.resolve(host="web-07").name == "api"
    assert inventory.resolve(component="log4j-core").name == "gateway"
    assert inventory.resolve().name == "(unspecified)"


def test_sla_shortens_for_tier_and_regulation():
    tier3 = AssetProfile(name="lab", tier=3)
    tier1_regulated = AssetProfile(name="pay", tier=1, regimes=["pci-dss"], environment="production")
    assert tier1_regulated.sla_days("Contain") < tier3.sla_days("Contain")
    assert tier3.sla_days("Accept") == 0
    assert tier1_regulated.due_date("Contain")


def test_unknown_tier_sits_between_known_values():
    assert AssetProfile(tier=3).tier_weight < AssetProfile().tier_weight < AssetProfile(tier=1).tier_weight


def test_inventory_can_set_its_own_flat_sla():
    inventory = Inventory.from_dict({
        "sla": {"days": {"Contain": 10, "Remediate": 45, "Schedule": 100}, "scale": False},
        "assets": [{"name": "gold", "tier": 1, "regimes": ["sox"], "environment": "production"},
                   {"name": "bronze", "tier": 3}],
    })
    gold, bronze = inventory.assets
    for asset in (gold, bronze):
        assert asset.sla_days("Contain", inventory.sla) == 10
        assert asset.sla_days("Remediate", inventory.sla) == 45
        assert asset.sla_days("Schedule", inventory.sla) == 100
        assert asset.sla_days("Accept", inventory.sla) == 0
    assert gold.due_date("Contain", policy=inventory.sla) != ""
    assert "the same for every asset" in inventory.sla.describe()


def test_sla_days_can_be_set_and_still_scale():
    policy = SlaPolicy.from_dict({"days": {"remediate": 50}})
    assert policy.days["Contain"] == 7, "verdicts not named keep the built-in window"
    assert AssetProfile(tier=1).sla_days("Remediate", policy) == 25


def test_no_sla_block_keeps_the_built_in_policy():
    inventory = Inventory.from_dict({"assets": []})
    assert inventory.sla.is_default
    assert AssetProfile(tier=1).sla_days("Contain", inventory.sla) == AssetProfile(tier=1).sla_days("Contain")


@pytest.mark.parametrize("bad", [{"days": {"Accept": 5}}, {"days": {"Contain": 0}},
                                 {"days": {"Contain": "soon"}}, "two weeks"])
def test_a_bad_sla_block_is_refused(bad):
    with pytest.raises(ValueError):
        SlaPolicy.from_dict(bad)
