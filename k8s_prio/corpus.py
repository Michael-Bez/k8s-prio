""" walks a real corpus and reports what it found and what it had to skip
demo/ was three clean files, a real repository is full of Helm templates,
CI config and values files, so this counts the skips by reason instead of
letting them disappear into warnings """

import os
import time

from k8s_prio.parser import WORKLOAD_KINDS, parse_file_with_reasons


# corpus identity comes from a manifest file rather than being hardcoded so
# every report says which corpus produced it, a corpus with no manifest entry
# still scans it is just reported as unrecorded: a missing manifest is a
# reason to say so not a reason to invent a name
#
# It lives in this module rather than in report.py so that anything needing a
# corpus name can have it without pulling in the whole reporting layer
UNKNOWN_CORPUS = "unrecorded corpus"


def corpus_identity(directory):
    """ Name, url, tag and commit for the corpus in this directory """
    folder = os.path.basename(os.path.abspath(directory).rstrip(os.sep))
    manifest = os.path.join(os.path.dirname(os.path.abspath(directory)),
                            "corpus_manifest.txt")
    identity = {"name": UNKNOWN_CORPUS, "title": UNKNOWN_CORPUS,
                "url": "-", "tag": "-", "commit": "-"}
    if not os.path.isfile(manifest):
        return identity
    with open(manifest, encoding="utf-8") as f:
        lines = f.read().split("\n")
    # the file is a flat list of "corpus: name" blocks with indented fields
    current = {}
    blocks = []
    for line in lines:
        if line.startswith("corpus: "):
            current = {"name": line[len("corpus: "):].strip()}
            blocks.append(current)
        elif line.startswith("  ") and ": " in line and current != {}:
            key, value = line.strip().split(": ", 1)
            current[key] = value
    # match on the folder name so moving the corpus somewhere else still works
    for block in blocks:
        if block.get("directory") == folder:
            identity["name"] = block.get("name", UNKNOWN_CORPUS)
            identity["title"] = block.get("title", block.get("name", UNKNOWN_CORPUS))
            identity["url"] = block.get("url", "-")
            identity["tag"] = block.get("tag", "-")
            identity["commit"] = block.get("commit", "-")
    return identity


def add_one(counts, key):
    """  bump a counter in a plain dict starting it at zero if it is new """
    if key not in counts:
        counts[key] = 0
    counts[key] = counts[key] + 1


def profile_dir(path):
    """ walk a directory, parse everything scannable and record a profile
    returns the resources plus a dict describing the corpus """
    started = time.time()
    resources = []
    files_seen = 0
    files_parsed = 0
    files_skipped = 0
    skip_reasons = {}
    kinds = {}

    for root, dirs, files in os.walk(path):
        for filename in sorted(files):
            if not (filename.endswith(".yaml") or filename.endswith(".yml")):
                continue
            files_seen = files_seen + 1
            found, reasons = parse_file_with_reasons(os.path.join(root, filename))
            for reason in reasons:
                add_one(skip_reasons, reason)
            # a file counts as parsed if it gave us at least one object
            # a file that gave nothing at all is a skipped file
            if found == []:
                files_skipped = files_skipped + 1
            else:
                files_parsed = files_parsed + 1
            for resource in found:
                resources.append(resource)
                add_one(kinds, resource.kind)

    workloads = 0
    for resource in resources:
        if resource.kind in WORKLOAD_KINDS:
            workloads = workloads + 1

    elapsed = time.time() - started
    profile = {"files_seen": files_seen,
               "files_parsed": files_parsed,
               "files_skipped": files_skipped,
               "skip_reasons": skip_reasons,
               "objects": len(resources),
               "kinds": kinds,
               "workloads": workloads,
               "non_workloads": len(resources) - workloads,
               "seconds": elapsed}
    return resources, profile


def findings_per_rule(findings):
    """ count how many findings each rule produced """
    counts = {}
    for finding in findings:
        add_one(counts, finding.rule_id)
    return counts


def objects_per_second(profile):
    """ scan speed guarding against a divide by zero on a tiny corpus"""
    if profile["seconds"] <= 0:
        return 0.0
    return profile["objects"] / profile["seconds"]


def timing_stats(times):
    """ min / median / mean over repeated scan timings discarding the first
    run as warm up (the first walk pays the "cold-cache" cost so counting it
    would mix two different things into one number)  """
    timed = times[1:]
    ordered = sorted(timed)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        median = ordered[middle]
    else:
        median = (ordered[middle - 1] + ordered[middle]) / 2
    return {"runs_total": len(times), "runs_timed": len(timed),
            "min": ordered[0], "median": median,
            "mean": sum(timed) / len(timed)}
