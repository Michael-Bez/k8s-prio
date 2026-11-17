""" The corpus scale evaluation: how much do the two engines agree and does
that survive changing the heuristic weights?

This module only measures agreement. It never asks whether a finding is
correct which is a different question needing hand labelled ground truth and
is not part of this code """

from k8s_prio.comparison import (LABELS, agreement_parts, bootstrap_interval,
                                 bootstrap_interval_by_group,
                                 bootstrap_paired_difference, cohens_kappa,
                                 compare_findings, steps_apart, weighted_kappa)
from k8s_prio.corpus import add_one, findings_per_rule, profile_dir, timing_stats
from k8s_prio.divergence import explain_divergence, heuristic_floor
from k8s_prio.engine import run_rules
from k8s_prio.scoring.heuristic import RULE_FACTORS, score_finding
from k8s_prio.scoring.ssvc import route

# how many bootstrap resamples and the fixed seed that makes a run repeatable
BOOTSTRAP_ROUNDS = 2000
BOOTSTRAP_SEED = 20260802

# The weight profiles for the sensitivity run. Three of them are just sanity
# checks: would the conclusions survive someone reasonably picking different
# weights? no-remediation is the one that carries weight because
# remediation_ease is the only factor the SSVC tree has no equivalent of so
# zeroing it tests whether that is what the disagreement is actually made of
# on the Goat corpus it takes kappa from 0.112 to 0.603
PROFILES = [
    ("default", {"exploitability": 0.30, "impact": 0.35, "exposure": 0.25, "remediation_ease": 0.10}),
    ("equal", {"exploitability": 0.25, "impact": 0.25, "exposure": 0.25, "remediation_ease": 0.25}),
    ("impact-heavy", {"exploitability": 0.20, "impact": 0.50, "exposure": 0.20, "remediation_ease": 0.10}),
    ("exploit-heavy", {"exploitability": 0.50, "impact": 0.20, "exposure": 0.20, "remediation_ease": 0.10}),
    ("no-remediation", {"exploitability": 0.33, "impact": 0.37, "exposure": 0.30, "remediation_ease": 0.00}),
]


def label_counts(labels):
    """ count each label and work out its percentage of the total """
    counts = {}
    for label in LABELS:
        counts[label] = 0
    for label in labels:
        counts[label] = counts[label] + 1
    percentages = {}
    for label in LABELS:
        if len(labels) == 0:
            percentages[label] = 0.0
        else:
            percentages[label] = 100.0 * counts[label] / len(labels)
    return counts, percentages


def divergence_analysis(findings):
    """ who ranked higher, by how many bands, and which rules disagree most
    labels runs most urgent first so a lower index means ranked higher """
    heuristic_higher = 0
    ssvc_higher = 0
    step_sizes = {1: 0, 2: 0, 3: 0}
    #  start every rule at zero so a rule that never fires on this corpus
    #   still shows up in the table as an observation rather than vanishing
    per_rule = {}
    for rule_id in RULE_FACTORS:
        per_rule[rule_id] = {"findings": 0, "diverged": 0,
                             "heuristic_higher": 0, "ssvc_higher": 0}
    for finding in findings:
        per_rule[finding.rule_id]["findings"] = per_rule[finding.rule_id]["findings"] + 1
        if finding.band == finding.ssvc_outcome:
            continue
        per_rule[finding.rule_id]["diverged"] = per_rule[finding.rule_id]["diverged"] + 1
        steps = steps_apart(finding.band, finding.ssvc_outcome)
        add_one(step_sizes, steps)
        if LABELS.index(finding.band) < LABELS.index(finding.ssvc_outcome):
            heuristic_higher = heuristic_higher + 1
            per_rule[finding.rule_id]["heuristic_higher"] = per_rule[finding.rule_id]["heuristic_higher"] + 1
        else:
            ssvc_higher = ssvc_higher + 1
            per_rule[finding.rule_id]["ssvc_higher"] = per_rule[finding.rule_id]["ssvc_higher"] + 1
    return {"heuristic_higher": heuristic_higher, "ssvc_higher": ssvc_higher,
            "step_sizes": step_sizes, "per_rule": per_rule}


def profile_weights(name):
    """ look one weight profile up by name  """
    for profile_name, weights in PROFILES:
        if profile_name == name:
            return weights
    return None


def divergence_cause_table(findings):
    """ for every divergent finding which structural cause dominates and
    whether the gap is one band or wider, assume default scoring """
    table = {}
    weights = profile_weights("no-remediation")
    # the floor is a corpus level fact so it is measured once over all the
    # findings and handed to every per finding explanation
    floor = heuristic_floor(findings)
    for finding in findings:
        if finding.band == finding.ssvc_outcome:
            continue
        explained = explain_divergence(finding, weights, floor)
        cause = explained["cause"]
        if cause not in table:
            table[cause] = {"findings": 0, "one_band": 0, "multi_band": 0}
        table[cause]["findings"] = table[cause]["findings"] + 1
        if steps_apart(finding.band, finding.ssvc_outcome) == 1:
            table[cause]["one_band"] = table[cause]["one_band"] + 1
        else:
            table[cause]["multi_band"] = table[cause]["multi_band"] + 1
    return table


def rule_level_labels(findings):
    """ One (band, outcome) pair per rule that fired ignoring how many findings
    that rule produced """
    pairs = {}
    for finding in findings:
        if finding.rule_id not in pairs:
            pairs[finding.rule_id] = [finding.band, finding.ssvc_outcome]
    heuristic_labels = []
    ssvc_labels = []
    for rule_id in sorted(pairs):
        heuristic_labels.append(pairs[rule_id][0])
        ssvc_labels.append(pairs[rule_id][1])
    return heuristic_labels, ssvc_labels


def rule_groups(findings):
    """ The (band, outcome) label pairs grouped by rule, one group per rule
    that fired in sorted rule id order so the grouping is deterministic """
    pairs_by_rule = {}
    for finding in findings:
        if finding.rule_id not in pairs_by_rule:
            pairs_by_rule[finding.rule_id] = []
        pairs_by_rule[finding.rule_id].append((finding.band, finding.ssvc_outcome))
    groups = []
    for rule_id in sorted(pairs_by_rule):
        groups.append(pairs_by_rule[rule_id])
    return groups


def paired_profile_difference(findings, name_first, name_second):
    """ The paired rule level bootstrap between two weight profiles: one draw of
    rules is scored under both profiles and the kappa difference recorded """
    weights_first = profile_weights(name_first)
    weights_second = profile_weights(name_second)
    score_all(findings, weights_first)
    groups_first = rule_groups(findings)
    score_all(findings, weights_second)
    groups_second = rule_groups(findings)
    return bootstrap_paired_difference(groups_first, groups_second,
                                       BOOTSTRAP_ROUNDS, BOOTSTRAP_SEED)


def score_all(findings, weights):
    """ Re score every finding with a given weight profile, both engines"""
    for finding in findings:
        score_finding(finding, weights)
        route(finding)


def analyse(findings):
    """ the part for findings that are already scored """
    heuristic_labels = []
    ssvc_labels = []
    for finding in findings:
        heuristic_labels.append(finding.band)
        ssvc_labels.append(finding.ssvc_outcome)

    observed, expected = agreement_parts(heuristic_labels, ssvc_labels)
    low, high = bootstrap_interval(heuristic_labels, ssvc_labels,
                                   BOOTSTRAP_ROUNDS, BOOTSTRAP_SEED)
    result = compare_findings(findings)
    result["observed"] = observed
    result["expected"] = expected
    result["kappa_low"] = low
    result["kappa_high"] = high
    # the rule level bootstrap: group the pairs by rule so one draw takes a
    # whole rule with all its findings, the findings inside a rule are copies
    # of each other not independent observations which is why this interval
    # is much wider than the finding level one and is the honest one to quote
    rule_low, rule_high, rule_discarded = bootstrap_interval_by_group(
        rule_groups(findings), BOOTSTRAP_ROUNDS, BOOTSTRAP_SEED)
    result["rule_kappa_low"] = rule_low
    result["rule_kappa_high"] = rule_high
    result["rule_discarded"] = rule_discarded
    result["weighted_kappa"] = weighted_kappa(heuristic_labels, ssvc_labels)
    # agreement over the rule set: one row per rule, with corpus composition removed
    rule_set_a, rule_set_b = rule_level_labels(findings)
    result["rules_fired"] = len(rule_set_a)
    result["rule_set_kappa"] = cohens_kappa(rule_set_a, rule_set_b)
    result["rule_set_weighted_kappa"] = weighted_kappa(rule_set_a, rule_set_b)
    result["divergence"] = divergence_analysis(findings)
    result["heuristic_counts"], result["heuristic_pct"] = label_counts(heuristic_labels)
    result["ssvc_counts"], result["ssvc_pct"] = label_counts(ssvc_labels)
    result["per_rule_findings"] = findings_per_rule(findings)
    return result


def run_evaluation(directory, weights, timing_runs=0):
    """ Walk the corpus, detect, score with one profile and analyse

    with timing_runs >= 2 the walk is repeated and the profile reports the
    median so one cold cache run cannot end up in the record of time """
    resources, profile = profile_dir(directory)
    if timing_runs >= 2:
        times = [profile["seconds"]]
        for extra in range(timing_runs - 1):
            resources, profile = profile_dir(directory)
            times.append(profile["seconds"])
        profile["timing"] = timing_stats(times)
        profile["seconds"] = profile["timing"]["median"]
    findings = run_rules(resources)
    score_all(findings, weights)
    return resources, findings, profile, analyse(findings)


def bands_by_rule(findings):
    """ which heuristic band each rule landed in for the sensitivity table"""
    bands = {}
    for finding in findings:
        bands[finding.rule_id] = finding.band
    return bands


def run_sensitivity(findings):
    """ Re score the same findings under every weight profile and collect
    kappa, weighted kappa and the divergence count for each """
    rows = []
    default_bands = {}
    for name, weights in PROFILES:
        score_all(findings, weights)
        result = analyse(findings)
        bands = bands_by_rule(findings)
        if name == "default":
            default_bands = bands
        moved = []
        for rule_id in sorted(bands):
            if rule_id in default_bands and bands[rule_id] != default_bands[rule_id]:
                moved.append(f"{rule_id} {default_bands[rule_id]}->{bands[rule_id]}")
        rows.append({"profile": name, "weights": weights,
                     "kappa": result["kappa"],
                     "weighted_kappa": result["weighted_kappa"],
                     "kappa_low": result["kappa_low"], "kappa_high": result["kappa_high"],
                     "rule_kappa_low": result["rule_kappa_low"],
                     "rule_kappa_high": result["rule_kappa_high"],
                     "divergent": len(result["divergent"]), "n": result["n"],
                     "moved": moved})
    return rows
