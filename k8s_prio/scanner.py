""" ties the pipeline together: parse, run rules, score both ways, sort """

from k8s_prio.engine import run_rules
from k8s_prio.parser import parse_dir
from k8s_prio.scoring.heuristic import score_finding
from k8s_prio.scoring.ssvc import route


def get_score(finding):
    """ Sort key: the heuristic score of a finding """
    return finding.score


def scan_directory(directory, weights):
    """Parse a directory, detect and then score every finding with both methods

    both engines always run and neither one feeds the other, that is the
    whole point of the project: two independent opinions on the same finding.
    Returns the resources as well as the findings because the CLI wants the
    resource count for its summary line

    note the sort is by the heuristic score, something had to decide the
    display order and that is the engine that produces a number
    """
    
    resources = parse_dir(directory)
    findings = run_rules(resources)
    for finding in findings:
        score_finding(finding, weights)
        route(finding)
    findings.sort(key=get_score, reverse=True)
    return resources, findings
