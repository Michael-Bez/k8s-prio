""" Tests for the SSVC router """

from k8s_prio.findings import Finding
from k8s_prio.scoring.ssvc import CISA_TREE, RULE_SSVC, route

ALL_RULE_IDS = ["K8S-NET-001", "K8S-NET-002", "K8S-SEC-001", "K8S-SEC-002",
                "K8S-SEC-003", "K8S-SEC-004", "K8S-SEC-005", "K8S-SEC-006",
                "K8S-WKL-001", "K8S-WKL-002", "K8S-RBC-001", "K8S-RBC-002"]


def fake_finding(rule_id):
    """ a minimal Finding; routing only reads rule_id  """
    return Finding(rule_id, "test", None, "test", "test", {})


def test_every_rule_id_has_ssvc_values():
    
    # the four CISA Coordinator decision points, with only the published values
    assert len(RULE_SSVC) == 12
    for rule_id in ALL_RULE_IDS:
        assert rule_id in RULE_SSVC
        values = RULE_SSVC[rule_id]
        assert values["exploitation"] in ["none", "poc", "active"]
        assert values["automatable"] in ["no", "yes"]
        assert values["impact"] in ["partial", "total"]
        assert values["mission"] in ["low", "medium", "high"]


def test_tree_has_all_thirty_six_published_rows():
    # 3 exploitation x 2 automatable x 2 impact = 12 branches, each holding
    # the three mission values, so 36 outcomes in total
    assert len(CISA_TREE) == 12
    outcomes = 0
    for branch in CISA_TREE:
        for mission in ["low", "medium", "high"]:
            assert CISA_TREE[branch][mission] in ["Track", "Track*", "Attend", "Act"]
            outcomes = outcomes + 1
    assert outcomes == 36


def test_tree_corners_match_the_published_matrix():
    # spot checks against the CISA SSVC Guide matrix
    assert CISA_TREE[("none", "no", "partial")]["low"] == "Track"
    assert CISA_TREE[("active", "yes", "total")]["high"] == "Act"
    # and one row that is easy to get wrong: poc + not automatable + total
    assert CISA_TREE[("poc", "no", "total")]["medium"] == "Track*"


def test_all_four_outcomes_are_reachable():
    outcomes = []
    for rule_id in ALL_RULE_IDS:
        outcome = route(fake_finding(rule_id))
        if outcome not in outcomes:
            outcomes.append(outcome)
    assert sorted(outcomes) == ["Act", "Attend", "Track", "Track*"]


def test_privileged_routes_to_act():
    # active + automatable + total + high mission is the worst corner
    finding = fake_finding("K8S-SEC-001")
    assert route(finding) == "Act"
    assert finding.ssvc_outcome == "Act"


def test_missing_netpol_routes_to_track():
    # nothing to exploit and only partial impact keeps it at routine tracking
    assert route(fake_finding("K8S-NET-002")) == "Track"


def test_wildcard_role_routes_to_track_star():
    # not exploited on its own but the grant is total and mission is high,
    # which is exactly the published none/no/total/high row
    assert route(fake_finding("K8S-RBC-001")) == "Track*"


def test_capabilities_route_to_attend():
    assert route(fake_finding("K8S-SEC-005")) == "Attend"


def test_path_is_recorded_for_the_report():
    finding = fake_finding("K8S-SEC-001")
    route(finding)
    assert finding.ssvc_path == ["exploitation=active", "automatable=yes",
                                 "impact=total", "mission=high"]
