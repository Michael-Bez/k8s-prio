""" Tests for the heuristic scorer """

import os

from k8s_prio.findings import Finding
from k8s_prio.scoring.heuristic import RULE_FACTORS, WEIGHTS, band_for, load_weights, score_finding

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

ALL_RULE_IDS = ["K8S-NET-001", "K8S-NET-002", "K8S-SEC-001", "K8S-SEC-002",
                "K8S-SEC-003", "K8S-SEC-004", "K8S-SEC-005", "K8S-SEC-006",
                "K8S-WKL-001", "K8S-WKL-002", "K8S-RBC-001", "K8S-RBC-002"]


def fake_finding(rule_id):
    """ a minimal Finding for scoring tests, scoring only reads rule_id """
    return Finding(rule_id, "test", None, "test", "test", {})


def test_score_arithmetic_worked_by_hand():
    # K8S-SEC-001 has factors 9, 10, 6, 9. With the default weights:
    # 0.30*9 + 0.35*10 + 0.25*6 + 0.10*9 = 2.7 + 3.5 + 1.5 + 0.9 = 8.6

    finding = fake_finding("K8S-SEC-001")
    score = score_finding(finding, WEIGHTS)
    assert score == 8.6
    assert finding.score == 8.6
    assert finding.band == "Act"


def test_low_end_score_worked_by_hand():
    # K8S-WKL-002 has factors 7, 4, 6, 8:
    # 0.30*7 + 0.35*4 + 0.25*6 + 0.10*8 = 2.1 + 1.4 + 1.5 + 0.8 = 5.8
    # impact 4 is the lowest in the table because its anchor CVE-2020-8557
    # scores C:N/I:N/A:H, - availability only

    finding = fake_finding("K8S-WKL-002")
    assert score_finding(finding, WEIGHTS) == 5.8
    assert finding.band == "Track*"


def test_score_inputs_are_kept_on_the_finding():
    # --report has to be able to show how the score was built, so the inputs
    # are kept on the finding and not thrown away
    
    finding = fake_finding("K8S-NET-001")
    score_finding(finding, WEIGHTS)
    assert finding.factors == RULE_FACTORS["K8S-NET-001"]
    assert finding.weights == WEIGHTS


def test_every_rule_id_has_factors():
    assert len(RULE_FACTORS) == 12
    for rule_id in ALL_RULE_IDS:
        assert rule_id in RULE_FACTORS
        for name in ["exploitability", "impact", "exposure", "remediation_ease"]:
            assert 1 <= RULE_FACTORS[rule_id][name] <= 10


def test_scores_spread_across_at_least_three_bands():
    bands = []
    for rule_id in ALL_RULE_IDS:
        finding = fake_finding(rule_id)
        score_finding(finding, WEIGHTS)
        if finding.band not in bands:
            bands.append(finding.band)
    assert len(bands) >= 3


def test_band_boundaries():
    assert band_for(8.0) == "Act"
    assert band_for(7.9) == "Attend"
    assert band_for(6.0) == "Attend"
    assert band_for(5.9) == "Track*"
    assert band_for(4.0) == "Track*"
    assert band_for(3.9) == "Track"


def test_load_weights_full_file():
    weights = load_weights(os.path.join(FIXTURES, "weights_custom.yaml"))
    assert weights["exploitability"] == 0.40
    assert weights["remediation_ease"] == 0.10


def test_load_weights_fills_missing_keys_from_default():
    weights = load_weights(os.path.join(FIXTURES, "weights_partial.yaml"))
    assert weights["impact"] == WEIGHTS["impact"]
    assert weights["exposure"] == WEIGHTS["exposure"]


def test_load_weights_rejects_negative_value():
    caught = False
    try:
        load_weights(os.path.join(FIXTURES, "weights_negative.yaml"))
    except ValueError:
        caught = True
    assert caught


def test_load_weights_rejects_bad_sum():
    caught = False
    try:
        load_weights(os.path.join(FIXTURES, "weights_bad_sum.yaml"))
    except ValueError:
        caught = True
    assert caught
