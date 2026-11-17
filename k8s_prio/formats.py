""" output format for the scan subcommand: GitHub workflow annotations
text output stays in cli.py

an annotation is one line printed to stdout in a format the GitHub runner
recognises, it needs no upload step and no extra permissions so it works on a
private repository: findings show up on the changed lines of a pull request and
the check fails when something reaches the threshold """

import os

from k8s_prio.comparison import LABELS, steps_apart

# The OWASP Kubernetes Top Ten was renumbered after the 2022 edition these rules cite
CIS_EDITION = "CIS Kubernetes Benchmark v1.8"
OWASP_EDITION = "OWASP K8s Top 10 (2022)"

# how a band maps to a GitHub annotation command, Four bands collapse into
# three levels because that is all GitHub offers so Track* and Track share
# the mildest one
GITHUB_LEVELS = {"Act": "error", "Attend": "warning", "Track*": "notice", "Track": "notice"}


def source_text(cis_ref, owasp_ref):
    """ the citation line with both editions named in full"""
    refs = []
    if cis_ref is not None:
        refs.append(f"{CIS_EDITION} {cis_ref}")
    if owasp_ref is not None:
        refs.append(f"{OWASP_EDITION} {owasp_ref}")
    if refs == []:
        return "best practice"
    return ", ".join(refs)


def finding_source(finding):
    """ The citation line for one finding, read from its features """
    return source_text(finding.features["cis_benchmark_ref"],
                       finding.features["owasp_top10_ref"])


def relative_uri(source_file, root):
    """ The file path relative to root always with forward slashes """
    path = os.path.relpath(source_file, root)
    # os.sep is a backslash on Windows and a backslash path matches nothing
    path = path.replace(os.sep, "/")
    path = path.replace("\\", "/")
    # a path above the root starts with ../, which is not a valid
    # repository relative uri
    while path.startswith("../"):
        path = path[3:]
    return path


def effective_band(finding):
    """ the more urgent of the two verdicts """
    if LABELS.index(finding.band) <= LABELS.index(finding.ssvc_outcome):
        return finding.band
    return finding.ssvc_outcome


def message_for(finding, divergence):
    """ The human meant sentence an annotation carries """
    text = (f"{finding.score} {finding.band} "
            f"(heuristic {finding.band}, SSVC {finding.ssvc_outcome}). "
            f"{finding.description} Fix: {finding.remediation_hint}")
    if divergence is not None:
        steps = steps_apart(finding.band, finding.ssvc_outcome)
        if steps == 1:
            band_word = "band"
        else:
            band_word = "bands"
        text = text + (f" Divergence: heuristic {finding.band} vs SSVC "
                       f"{finding.ssvc_outcome} ({steps} {band_word}). "
                       f"Because: {divergence['sentence']} "
                       f"Advice: {divergence['advice']}")
    return text


def github_lines(findings, root, divergences):
    """ GitHub workflow commands, one per finding

    The runner reads these straight out of the job log so there is no upload
    step and no extra permission to grant which is what makes this work on a
    private repository """
    lines = []
    position = -1
    for finding in findings:
        position = position + 1
        divergence = divergences.get(position)
        level = GITHUB_LEVELS[effective_band(finding)]
        title = f"{finding.rule_id} {finding.rule_name}"
        # a newline inside a workflow command would break the runner's parsing
        message = message_for(finding, divergence).replace("\n", " ")
        lines.append(f"::{level} file={relative_uri(finding.resource.source_file, root)},"
                     f"line={finding.line},title={title}::{message}")
    return lines
