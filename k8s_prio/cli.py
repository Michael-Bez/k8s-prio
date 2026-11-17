""" Command line interface, argument parsing, the text output format, the merge
gates. The GitHub annotation format is in
formats.py - the evaluation report is in report.py """

import argparse
import os
import sys

import yaml

from k8s_prio.comparison import LABELS, compare_findings, kappa_word, steps_apart
from k8s_prio.divergence import explain_divergence, guidance_for, heuristic_floor
from k8s_prio.evaluate import (BOOTSTRAP_ROUNDS, BOOTSTRAP_SEED,
                               divergence_cause_table,
                               paired_profile_difference, profile_weights,
                               run_evaluation, run_sensitivity, score_all)
from k8s_prio.formats import effective_band, finding_source, github_lines
from k8s_prio.report import (print_analysis, print_divergence_causes,
                             print_paired, print_profile, print_sensitivity,
                             write_causes_csv, write_matrix_csv,
                             write_per_rule_csv, write_sensitivity_csv,
                             write_text)
from k8s_prio.scanner import scan_directory
from k8s_prio.scoring.heuristic import WEIGHTS, load_weights


def print_finding(finding, report, floor=None):
    """ One line per finding: score, both verdicts, rule, object, file and line
    With report=True it adds the detail block underneath """
    resource = finding.resource
    print(f"{finding.score:>4}  {finding.band:<7} {finding.ssvc_outcome:<7} "
          f"{finding.rule_id}  {finding.rule_name}: "
          f"{resource.kind} {resource.namespace}/{resource.name}  "
          f"[{resource.source_file}:{finding.line}]")
    if report:
        print(f"    problem: {finding.description}")
        print(f"    fix:     {finding.remediation_hint}")
        print(f"    source:  {finding_source(finding)}")
        # show exactly how both results were reached
        factors = finding.factors
        weights = finding.weights
        print(f"    factors: exploitability={factors['exploitability']} impact={factors['impact']} "
              f"exposure={factors['exposure']} remediation_ease={factors['remediation_ease']}")
        print(f"    weights: exploitability={weights['exploitability']} impact={weights['impact']} "
              f"exposure={weights['exposure']} remediation_ease={weights['remediation_ease']}")
        print(f"    ssvc:    {' -> '.join(finding.ssvc_path)} -> {finding.ssvc_outcome}")
        # when the two engines disagree explain it and give the advice from
        # the policy in divergence.py, neither verdict is overwritten: both are
        # still printed on the summary line above
        if finding.band != finding.ssvc_outcome:
            steps = steps_apart(finding.band, finding.ssvc_outcome)
            if LABELS.index(finding.band) < LABELS.index(finding.ssvc_outcome):
                who = "heuristic"
            else:
                who = "ssvc"
            if steps == 1:
                band_word = "band"
            else:
                band_word = "bands"
            explained = explain_divergence(finding, profile_weights("no-remediation"), floor)
            print(f"    diverge: heuristic {finding.band} vs ssvc {finding.ssvc_outcome} "
                  f"({steps} {band_word}, {who} higher)")
            print(f"    because: {explained['sentence']}")
            print(f"    advice:  {guidance_for(finding, explained)}")
        print()


def print_comparison(result):
    """The agreement matrix, the kappa and the divergent findings """
    print(f"heuristic bands vs SSVC outcomes for {result['n']} findings")
    print()
    # the corner label is built outside the f-string: a backslash inside an
    # f-string expression is a syntax error before python 3.12
    corner = "heuristic \\ ssvc"
    header = f"{corner:<17}"
    for label in LABELS:
        header = header + f"{label:>8}"
    print(header)
    for band in LABELS:
        line = f"{band:<17}"
        for outcome in LABELS:
            line = line + f"{result['matrix'][band][outcome]:>8}"
        print(line)
    print()
    kappa = result["kappa"]
    if kappa is None:
        print("not enough data for kappa")
    else:
        print(f"Cohen's kappa: {round(kappa, 3)} ({kappa_word(kappa)} agreement)")
    print()
    if result["divergent"] == []:
        print("no divergent findings - the two methods agree everywhere")
    else:
        print(f"{len(result['divergent'])} divergent findings (heuristic vs ssvc):")
        for finding in result["divergent"]:
            resource = finding.resource
            print(f"  {finding.band:<7} vs {finding.ssvc_outcome:<7} {finding.rule_id}  "
                  f"{resource.kind} {resource.namespace}/{resource.name}")


def count_phrase(count, word):
    """'1 finding' rather than '1 findings' """
    if count == 1:
        return f"{count} {word}"
    return f"{count} {word}s"


def at_or_above(band, threshold):
    """ is this band at least as urgent as the threshold? labels runs most
    urgent first so a lower index means more urgent """
    return LABELS.index(band) <= LABELS.index(threshold)


def gating_decision(findings, fail_on, fail_on_divergence):
    """ work out the exit code for a scan and one sentence saying why

    With no flags any finding at all fails, with a threshold only findings
    that reach it fail so a team can let the small stuff through and still
    block on the serious things

    --fail-on uses the more urgent of the two verdicts, through the same
    effective_band() the annotation level uses, Two reasons: a blocker must not slip
    through just because one engine ranked it lower and the severity shown in
    the pull request must not contradict the gate

    Returns (exit_code, reason)."""

    if fail_on is None and fail_on_divergence is None:
        if findings == []:
            return 0, "no findings"
        return 1, (count_phrase(len(findings), "finding")
                   + "; failing (no threshold set, any finding fails)")

    if findings == []:
        # "0 findings but none at or above Act" reads strangely so just say the simple thing
        return 0, "no findings; passing"

    reasons = []
    blocking = 0
    if fail_on is not None:
        over = []
        for finding in findings:
            if at_or_above(effective_band(finding), fail_on):
                over.append(finding)
        blocking = blocking + len(over)
        if over == []:
            reasons.append(count_phrase(len(findings), "finding")
                           + f" but none at or above {fail_on} (--fail-on {fail_on})")
        else:
            reasons.append(count_phrase(len(over), "finding")
                           + f" at or above {fail_on} (--fail-on {fail_on})")
    if fail_on_divergence is not None:
        apart = []
        for finding in findings:
            if steps_apart(finding.band, finding.ssvc_outcome) >= fail_on_divergence:
                apart.append(finding)
        blocking = blocking + len(apart)
        if apart == []:
            reasons.append(f"no findings {fail_on_divergence} or more bands apart "
                           f"(--fail-on-divergence {fail_on_divergence})")
        else:
            reasons.append(count_phrase(len(apart), "finding")
                           + f" {fail_on_divergence} or more bands apart "
                           + f"(--fail-on-divergence {fail_on_divergence})")

    joined = "; ".join(reasons)
    if blocking > 0:
        return 1, joined + "; failing"
    return 0, joined + "; passing"


def divergence_map(findings, floor):
    """ the explanation and advice for each divergent finding keyed by its
    position in the list, findings where the two engines agree are simply
    absent which is how the output formats know to say nothing """
    weights = profile_weights("no-remediation")
    explained = {}
    position = -1
    for finding in findings:
        position = position + 1
        if finding.band == finding.ssvc_outcome:
            continue
        detail = explain_divergence(finding, weights, floor)
        detail["advice"] = guidance_for(finding, detail)
        explained[position] = detail
    return explained


def write_out(text, destination):
    """ send output to a file when asked otherwise to stdout """
    if destination is None:
        print(text)
        return
    with open(destination, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(f"wrote {destination}")


def run_scan_output(args, resources, findings):
    """ print the scan in whichever format was asked for """
    # the band floor is a fact about the whole scan not about one finding so
    #  i measure it once here and hand it down
    floor = heuristic_floor(findings)
    if args.format == "text":
        for finding in findings:
            print_finding(finding, args.report, floor)
        print(f"{len(findings)} findings across {len(resources)} resources")
        return
    divergences = divergence_map(findings, floor)
    # paths go out relative to the working directory not the scan directory
    # CI runs from the repository root and GitHub resolves an annotation path
    # against the repository root so this is what makes the annotations land on
    # real files, see relative_uri in formats.py
    root = os.getcwd()
    write_out("\n".join(github_lines(findings, root, divergences)), args.output)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="k8s-prio",
        description="Scans Kubernetes YAML manifests for security misconfigurations "
                    "and prioritises the findings two ways (heuristic score and SSVC).",
        epilog="exit codes: 0 = scan ran and found nothing, "
               "1 = scan ran and found misconfigurations, "
               "2 = the scanner itself failed (e.g. missing directory). "
               "Scores do not change the exit code; a score-aware exit mode may come later.")
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", help="scan a directory of .yaml/.yml files")
    scan_parser.add_argument("directory", help="directory to scan (searched recursively)")
    scan_parser.add_argument("--report", action="store_true",
                             help="also print each finding's details, score factors and SSVC path")
    scan_parser.add_argument("--config", help="YAML file with custom heuristic weights")
    scan_parser.add_argument("--format", default="text", choices=["text", "github"],
                             help="text (default), or github for workflow "
                                  "annotations on a pull request")
    scan_parser.add_argument("--output", help="write to this file instead of stdout")
    scan_parser.add_argument("--fail-on", choices=LABELS,
                             help="exit 1 only when a finding reaches this band. A finding "
                                  "counts if EITHER the heuristic band OR the SSVC outcome "
                                  "is at or above it, so a blocker cannot slip through "
                                  "because one engine ranked it lower")
    scan_parser.add_argument("--fail-on-divergence", type=int, metavar="N",
                             help="exit 1 when any finding's two verdicts are N or more "
                                  "bands apart, routing big disagreements to a human")
    
    compare_parser = subparsers.add_parser(
        "compare", help="compare the two scoring methods on a directory of manifests")
    compare_parser.add_argument("directory", help="directory to scan (searched recursively)")

    evaluate_parser = subparsers.add_parser(
        "evaluate", help="run the full corpus evaluation: profile, agreement, divergence")
    evaluate_parser.add_argument("directory", help="corpus directory (searched recursively)")
    evaluate_parser.add_argument("--sensitivity", action="store_true",
                                 help="also re-run the analysis under every weight profile")
    evaluate_parser.add_argument("--results", default="results",
                                 help="directory for the report and CSV files (default: results)")
    evaluate_parser.add_argument("--timing-runs", type=int, default=0,
                                 help="repeat the scan N times and report min/median/mean, "
                                      "discarding the first run as warm-up (default: off, single run)")
    args = parser.parse_args(argv)

    if args.command is None:
        # no subcommand given, show the help and exit 2, because the tool did
        # not run rather than ran and found nothing
        parser.print_help()
        sys.exit(2)

    if not os.path.isdir(args.directory):
        print(f"error: '{args.directory}' is not a directory")
        sys.exit(2)

    weights = WEIGHTS
    if args.command == "scan" and args.config is not None:
        # a bad weights file means the scanner could not run so exit 2 and not
        # 1. exiting 1 would make it look like findings
        try:
            weights = load_weights(args.config)
        except OSError:
            print(f"error: could not read weights file '{args.config}'")
            sys.exit(2)
        except yaml.YAMLError:
            print(f"error: '{args.config}' is not valid YAML")
            sys.exit(2)
        except ValueError as problem:
            print(f"error: bad weights in '{args.config}': {problem}")
            sys.exit(2)

    if args.command == "evaluate":
        # timing_stats throws the first run away as warm up so 1 would leave
        # nothing to average
        if args.timing_runs != 0 and args.timing_runs < 2:
            print("error: --timing-runs needs at least 2 (first run is discarded as warm-up)")
            sys.exit(2)
        run_evaluate(args)
        return

    resources, findings = scan_directory(args.directory, weights)

    if args.command == "scan":
        run_scan_output(args, resources, findings)
        code, reason = gating_decision(findings, args.fail_on, args.fail_on_divergence)
        # the reason goes to stderr because stdout may be carrying the
        # annotation stream and a loose English sentence in the middle of it
        # would break whatever is reading it
        print(f"k8s-prio: {reason}", file=sys.stderr)
        sys.exit(code)
    else:
        print_comparison(compare_findings(findings))

    if len(findings) > 0:
        sys.exit(1)
    sys.exit(0)


def run_evaluate(args):
    """ The evaluate subcommand: profile the corpus, measure agreement and with
    --sensitivity repeat the whole thing under every weight profile  """
    lines = []
    resources, findings, profile, result = run_evaluation(args.directory, WEIGHTS,
                                                          args.timing_runs)
    print_profile(args.directory, profile, findings, lines)
    print_analysis(result, lines)
    causes = divergence_cause_table(findings)
    print_divergence_causes(causes, result, heuristic_floor(findings), lines)

    rows = []
    if args.sensitivity:
        rows = run_sensitivity(findings)
        print_sensitivity(rows, lines)
        
        paired = paired_profile_difference(findings, "default", "no-remediation")
        print_paired(paired, lines)
        # run_sensitivity leaves the findings scored with the last profile so
        # put the defaults back before anything else reads .band
        score_all(findings, WEIGHTS)

    lines.append("")
    lines.append(f"bootstrap: {BOOTSTRAP_ROUNDS} resamples, seed {BOOTSTRAP_SEED}")

    if not os.path.isdir(args.results):
        os.makedirs(args.results)
    written = [write_text(lines, args.results),
               write_matrix_csv(result, args.results),
               write_per_rule_csv(result, args.results),
               write_causes_csv(causes, args.results)]
    if rows != []:
        written.append(write_sensitivity_csv(rows, args.results))
    print("")
    for path in written:
        print(f"wrote {path}")

    if len(findings) > 0:
        sys.exit(1)
    sys.exit(0)
