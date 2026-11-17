""" Runs the rules over the parsed resources and collects the findings """

from k8s_prio.rules import ALL_RULES
from k8s_prio.rules.network import check_missing_network_policy


def run_rules(resources):
    """ Run every rule against every resource, return the list of findings """
    findings = []
    for resource in resources:
        for rule in ALL_RULES:
            # every rule returns a list, empty when nothing is wrong, so
            # extend works whatever it found
            findings.extend(rule(resource))

    # the missing NetworkPolicy rule is the exception to the loop above, to
    # know whether a namespace needs flagging you have to see two things at
    # once: does it run workloads and does it have a NetworkPolicy? Those are
    # usually different objects in different files so a rule that only ever
    # sees one resource cannot answer it, it gets the whole list once
    findings.extend(check_missing_network_policy(resources))
    return findings
