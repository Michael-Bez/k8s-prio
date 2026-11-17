""" Tests for the rule engine """

import os

from k8s_prio.engine import run_rules
from k8s_prio.parser import parse_file, parse_dir

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_no_resources_means_no_findings():
    assert run_rules([]) == []


def test_engine_calls_the_network_policy_rule_separately():
    # check_missing_network_policy is not in ALL_RULES, but run_rules must
    # still produce its findings via the separate whole list call
    resources = parse_file(os.path.join(FIXTURES, "netpol_missing_bad.yaml"))
    findings = run_rules(resources)
    rule_ids = [f.rule_id for f in findings]
    assert "K8S-NET-002" in rule_ids


def test_clean_resources_produce_no_findings():
    resources = parse_file(os.path.join(FIXTURES, "clean.yaml"))
    assert run_rules(resources) == []


def test_every_finding_fills_all_six_feature_keys():
    # both scoring engines depend on these six keys, so
    # run everything over all fixtures and check no rule forgets one
    resources = parse_dir(FIXTURES)
    findings = run_rules(resources)
    assert len(findings) > 0
    keys = ["category", "owasp_top10_ref", "cis_benchmark_ref",
            "is_workload", "affects_node_resources", "scope"]
    for finding in findings:
        for key in keys:
            assert key in finding.features
