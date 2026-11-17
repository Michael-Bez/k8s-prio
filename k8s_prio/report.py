""" prints the evaluation report and writes the results/ files

all the printing lives here so evaluate.py only does arithmetic, every print_*
function takes a lines list and goes through add() which prints and appends
so the terminal output and the saved report are the same text by design
rather than two code paths that have to be kept in step """

import os
import platform

from k8s_prio.comparison import LABELS, kappa_word
from k8s_prio.corpus import corpus_identity, objects_per_second

# below this many findings the kappa cannot carry much weight and the report
# should say so out loud rather than quietly presenting a number
SMALL_CORPUS = 100


def print_profile(directory, profile, findings, lines):
    """ the corpus profile: what was seen, parsed, skipped and found """
    identity = corpus_identity(directory)
    add(lines, f"corpus:   {identity['title']}")
    add(lines, f"source:   {identity['url']}")
    add(lines, f"release:  {identity['tag']} (commit {identity['commit']})")
    add(lines, f"corpus-id: {identity['name']}")
    add(lines, f"directory: {directory}")
    # the timing further down depends heavily on the machine: a cold Windows
    # run came out 54x slower than a warm Fedora one so the report has to say
    # where the number came from
    add(lines, f"platform: {platform.system()} {platform.release()}, "
               f"Python {platform.python_version()}")
    add(lines, "")
    add(lines, "--- corpus profile ---")
    add(lines, f"files seen:    {profile['files_seen']}")
    add(lines, f"files parsed:  {profile['files_parsed']}")
    add(lines, f"files skipped: {profile['files_skipped']}")
    if profile["skip_reasons"] != {}:
        add(lines, "skipped documents by reason:")
        for reason in sorted(profile["skip_reasons"]):
            add(lines, f"    {profile['skip_reasons'][reason]:>4}  {reason}")
    add(lines, "")
    add(lines, f"objects parsed: {profile['objects']}"
               f"   (workloads {profile['workloads']}, "
               f"non-workloads {profile['non_workloads']})")
    add(lines, "objects by kind:")
    for kind in sorted(profile["kinds"]):
        add(lines, f"    {profile['kinds'][kind]:>4}  {kind}")
    add(lines, "")
    if "timing" in profile:
        timing = profile["timing"]
        add(lines, f"scan time: {round(timing['median'], 3)} s "
                   f"({round(objects_per_second(profile), 1)} objects/second)")
        add(lines, f"    median of {timing['runs_timed']} timed runs, first of "
                   f"{timing['runs_total']} discarded as warm-up "
                   f"(min {round(timing['min'], 3)} s, mean {round(timing['mean'], 3)} s)")
    else:
        add(lines, f"scan time: {round(profile['seconds'], 3)} s "
                   f"({round(objects_per_second(profile), 1)} objects/second) - single run")
    add(lines, f"total findings: {len(findings)}")
    if len(findings) < SMALL_CORPUS:
        add(lines, f"NOTE: fewer than {SMALL_CORPUS} findings. This is a small sample, "
                   "so the kappa below carries limited weight and its confidence "
                   "interval will be wide. Reported as measured; the corpus was not "
                   "padded and no rule was loosened.")


def print_per_rule(result, lines):
    """ Findings per rule and how often each rules two labels disagree """
    add(lines, "")
    add(lines, "--- findings per rule, with divergence ---")
    add(lines, f"{'rule':<14}{'findings':>9}{'diverged':>10}{'heur higher':>13}{'ssvc higher':>13}")
    per_rule = result["divergence"]["per_rule"]
    for rule_id in sorted(per_rule):
        row = per_rule[rule_id]
        add(lines, f"{rule_id:<14}{row['findings']:>9}{row['diverged']:>10}"
                   f"{row['heuristic_higher']:>13}{row['ssvc_higher']:>13}")


def print_analysis(result, lines):
    """ Matrix, kappa with its parts and interval and divergence """
    add(lines, "")
    add(lines, f"--- agreement over {result['n']} findings ---")
    add(lines, "")
    # the corner label is built outside the f-string on purpose: a backslash
    # inside an f-string expression is a syntax error before python 3.12, and
    # one line like this quietly made the whole project 3.12-only once
    corner = "heuristic \\ ssvc"
    header = f"{corner:<17}"
    for label in LABELS:
        header = header + f"{label:>8}"
    add(lines, header)
    for band in LABELS:
        line = f"{band:<17}"
        for outcome in LABELS:
            line = line + f"{result['matrix'][band][outcome]:>8}"
        add(lines, line)

    add(lines, "")
    if result["kappa"] is None:
        add(lines, "not enough data for kappa")
    else:
        add(lines, f"observed agreement (po): {round(result['observed'], 4)}")
        add(lines, f"expected agreement (pe): {round(result['expected'], 4)}")
        add(lines, f"Cohen's kappa:           {round(result['kappa'], 3)} "
                   f"({kappa_word(result['kappa'])} agreement)")
        if result["kappa_low"] is not None:
            add(lines, f"95% bootstrap interval (finding-level):  {result['kappa_low']:.3f} "
                       f"to {result['kappa_high']:.3f}")
        if result["rule_kappa_low"] is not None:
            add(lines, f"95% bootstrap interval (rule-level):    {result['rule_kappa_low']:.3f} "
                       f"to {result['rule_kappa_high']:.3f}   "
                       f"({result['rule_discarded']} undefined resamples discarded)")
            add(lines, "    the rule-level interval is the defensible one: findings within "
                       "a rule share one score and one outcome by construction, so they "
                       "are not independent observations")
        add(lines, f"linear weighted kappa:   {round(result['weighted_kappa'], 3)}"
                   "   (Cohen 1968; counts a three band gap as worse than one)")
    if result["rule_set_kappa"] is not None:
        add(lines, "")
        add(lines, f"--- agreement over the rule set ({result['rules_fired']} rules that fired) ---")
        add(lines, "one row per rule, ignoring how many findings it produced:")
        add(lines, f"    rule-set kappa:          {result['rule_set_kappa']:.3f} "
                   f"({kappa_word(result['rule_set_kappa'])} agreement)")
        add(lines, f"    rule-set weighted kappa: {result['rule_set_weighted_kappa']:.3f}")
        add(lines, "    This is agreement between the two METHODS. The finding-level kappa")
        add(lines, "    above also reflects corpus composition, because a rule that fires")
        add(lines, "    24 times counts 24 times there and once here.")
        add(lines, f"    Descriptive only: it is computed from {result['rules_fired']} rows, so it is")
        add(lines, "    stable across corpora but NOT more precise than the finding-level")
        add(lines, "    figure. Neither number supersedes the other.")

    add(lines, "")
    add(lines, "marginal distributions:")
    add(lines, f"{'label':<10}{'heuristic':>12}{'%':>8}{'ssvc':>10}{'%':>8}")
    for label in LABELS:
        add(lines, f"{label:<10}{result['heuristic_counts'][label]:>12}"
                   f"{round(result['heuristic_pct'][label], 1):>8}"
                   f"{result['ssvc_counts'][label]:>10}"
                   f"{round(result['ssvc_pct'][label], 1):>8}")

    divergence = result["divergence"]
    total = len(result["divergent"])
    add(lines, "")
    if result["n"] > 0:
        rate = round(100.0 * total / result["n"], 1)
    else:
        rate = 0.0
    add(lines, f"divergent findings: {total} of {result['n']} ({rate}%)")
    add(lines, f"    heuristic ranked higher: {divergence['heuristic_higher']}")
    add(lines, f"    ssvc ranked higher:      {divergence['ssvc_higher']}")
    add(lines, "disagreement size:")
    for steps in [1, 2, 3]:
        add(lines, f"    {steps} band(s) apart: {divergence['step_sizes'].get(steps, 0)}")
    print_per_rule(result, lines)


def print_sensitivity(rows, lines):
    """ the same analysis under each weight profile """
    add(lines, "")
    add(lines, "--- weight sensitivity ---")
    add(lines, f"{'profile':<16}{'kappa':>8}{'weighted':>10}{'95% interval':>18}{'divergent':>11}")
    for row in rows:
        if row["kappa"] is None:
            add(lines, f"{row['profile']:<16}{'n/a':>8}")
            continue
        #  fixed decimal places, otherwise round() drops trailing zeros and
        # the columns come out ragged on screen
        interval = f"{row['kappa_low']:.2f} to {row['kappa_high']:.2f}"
        add(lines, f"{row['profile']:<16}{row['kappa']:>8.3f}"
                   f"{row['weighted_kappa']:>10.3f}{interval:>18}"
                   f"{row['divergent']:>11}")
    add(lines, "")
    add(lines, "rules whose heuristic band moved compared with the default profile:")
    for row in rows:
        if row["profile"] == "default":
            continue
        if row["moved"] == []:
            add(lines, f"    {row['profile']}: none")
        else:
            add(lines, f"    {row['profile']}: {', '.join(row['moved'])}")


# fixed print order for the divergence causes, absent causes are skipped
CAUSE_ORDER = ["remediation-pricing", "exploitation-gating", "impact-granularity",
               "mission-weighting", "band-floor-mismatch", "no-single-cause"]


def print_divergence_causes(table, result, floor, lines):
    """Why the divergences exist. Keeps two things apart on purpose: the
    general mechanism (four structural causes, true on any corpus) and the
    pattern this particular corpus happens to produce """
    add(lines, "")
    add(lines, "--- why the divergences happen ---")
    add(lines, "general mechanism: the first four causes are structural differences between")
    add(lines, "CVSS-style scoring and the SSVC tree, and exist on any corpus. The fifth,")
    add(lines, "band-floor mismatch, is a range mismatch specific to what a corpus produces.")
    add(lines, f"{'dominant cause':<22}{'findings':>9}{'one-band':>10}{'multi-band':>12}")
    for cause in CAUSE_ORDER:
        if cause not in table:
            continue
        row = table[cause]
        add(lines, f"{cause:<22}{row['findings']:>9}{row['one_band']:>10}{row['multi_band']:>12}")
    # the corpus-specific half: which rules actually produced the divergences
    per_rule = result["divergence"]["per_rule"]
    contributors = 0
    top_rule = None
    top_count = 0
    for rule_id in sorted(per_rule):
        diverged = per_rule[rule_id]["diverged"]
        if diverged > 0:
            contributors = contributors + 1
            if diverged > top_count:
                top_count = diverged
                top_rule = rule_id
    if top_rule is not None:
        add(lines, "")
        add(lines, f"corpus pattern: the divergent findings come from {contributors} rules; "
                   f"the largest single contributor is {top_rule} ({top_count} findings).")
        add(lines, "Both engines score on the rule id alone, so all of a rule's findings "
                   "diverge together - rules that fire in bulk dominate the pattern.")
    # the band floor findings and the empty row in the agreement matrix are the
    # same fact seen from two directions
    if "band-floor-mismatch" in table and floor is not None:
        floor_count = table["band-floor-mismatch"]["findings"]
        empty = []
        for label in LABELS:
            if result["heuristic_counts"][label] == 0:
                empty.append(label)
        if empty != []:
            add(lines, f"The {floor_count} band-floor-mismatch findings above and the empty "
                       f"{'/'.join(empty)} row of the agreement matrix are the same fact "
                       f"seen twice: the heuristic's lowest score on this corpus is "
                       f"{floor:.2f}, so it never uses {'/'.join(empty)} at all, while SSVC "
                       f"assigns it freely. Those findings could not have agreed no matter "
                       f"what any single factor said.")


def print_paired(paired, lines):
    """ the paired default vs no-remediation test """
    add(lines, "")
    add(lines, "--- paired test: no-remediation minus default (rule-level) ---")
    if paired is None:
        add(lines, "not enough data for the paired test")
        return
    no_improvement_pct = 100.0 * paired["no_improvement"] / paired["usable"]
    improvement_pct = 100.0 - no_improvement_pct
    add(lines, f"95% interval on the kappa difference: {paired['low']:.3f} to "
               f"{paired['high']:.3f}   (median {paired['median']:.3f})")
    add(lines, f"resamples showing no improvement (difference <= 0): "
               f"{paired['no_improvement']} of {paired['usable']} "
               f"({no_improvement_pct:.1f}%)")
    if paired["discarded"] > 0:
        add(lines, f"({paired['discarded']} undefined resamples discarded)")
    add(lines, f"reading: removing remediation pricing raises kappa in about "
               f"{round(improvement_pct)} of 100 rule-level resamples.")
    if paired["low"] <= 0:
        add(lines, "This is NOT claimed as statistically significant: the interval's "
                   "lower bound does not exclude zero, and the share of resamples "
                   "showing no improvement is above the usual 5% threshold. Both "
                   "facts stand together: the effect is consistent but the corpus "
                   "is too small to establish it formally.")


def add(lines, text):
    """ Print a line and keep a copy for the results file """
    print(text)
    lines.append(text)


def write_text(lines, directory):
    """ Save the printed report """
    path = os.path.join(directory, "evaluation_report.txt")
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    return path


def write_matrix_csv(result, directory):
    """ The agreement matrix for the figure """
    path = os.path.join(directory, "agreement_matrix.csv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("heuristic_band," + ",".join(LABELS) + "\n")
        for band in LABELS:
            counts = []
            for outcome in LABELS:
                counts.append(str(result["matrix"][band][outcome]))
            f.write(band + "," + ",".join(counts) + "\n")
    return path


def write_per_rule_csv(result, directory):
    """ The per rule divergence table for the figure """
    path = os.path.join(directory, "per_rule_divergence.csv")
    per_rule = result["divergence"]["per_rule"]
    with open(path, "w", encoding="utf-8") as f:
        f.write("rule_id,findings,diverged,heuristic_higher,ssvc_higher\n")
        for rule_id in sorted(per_rule):
            row = per_rule[rule_id]
            f.write(f"{rule_id},{row['findings']},{row['diverged']},"
                    f"{row['heuristic_higher']},{row['ssvc_higher']}\n")
    return path


def write_causes_csv(table, directory):
    """ The divergence cause table for the figure """
    path = os.path.join(directory, "divergence_causes.csv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("cause,findings,one_band,multi_band\n")
        for cause in CAUSE_ORDER:
            if cause not in table:
                continue
            row = table[cause]
            f.write(f"{cause},{row['findings']},{row['one_band']},{row['multi_band']}\n")
    return path


def write_sensitivity_csv(rows, directory):
    """ The sensitivity table for the figure """
    path = os.path.join(directory, "sensitivity.csv")
    with open(path, "w", encoding="utf-8") as f:
        # kappa_low/high resample findings; rule_kappa_low/high resample whole
        # rules. Both columns are kept so the gap between them stays visible,
        # because that gap is itself a result.
        f.write("profile,exploitability,impact,exposure,remediation_ease,"
                "kappa,weighted_kappa,kappa_low,kappa_high,"
                "rule_kappa_low,rule_kappa_high,divergent,n\n")
        for row in rows:
            w = row["weights"]
            f.write(f"{row['profile']},{w['exploitability']},{w['impact']},"
                    f"{w['exposure']},{w['remediation_ease']},"
                    f"{row['kappa']},{row['weighted_kappa']},"
                    f"{row['kappa_low']},{row['kappa_high']},"
                    f"{row['rule_kappa_low']},{row['rule_kappa_high']},"
                    f"{row['divergent']},{row['n']}\n")
    return path
