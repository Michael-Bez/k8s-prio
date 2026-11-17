""" The heuristic scorer: a weighted average that turns a finding into a 1.0-10.0 score """

import yaml

# WHERE THE FOUR FACTOR VALUES COME FROM
#
# My anchor is CVSS v3.1 (FIRST.org). Where a representative CVE exists for
# the kind of misconfiguration a rule finds its published NVD vector fixes the
# values. Where there is no clean CVE the same rubric is applied to the rules
# CWE class instead and the comment says so. Seven rules are CVE-anchored five
# are CWE-derived
#
# The rubric itself is mine. CVSS has no "exposure" metric and no 1-10
# sub score per dimension, so what this does is take real CVSS metric groups
# and lay a consistent scale over them. The anchors are published and
# checkable, the mapping from anchor to number is not, and that is worth being
# honest about
#
#   exploitability   <- Attack Vector, Attack Complexity, Privileges Required
#                       AV:L/AC:L with PR:L or PR:N is near the top (8-10);
#                       needing a foothold or a second condition drops it to
#                       the middle (5-7); enabling-only issues sit low (2-4)
#   impact           <- the C/I/A triad, raised when Scope:Changed applies
#                       Container-to-node breakout IS Scope:Changed, so those
#                       take 9-10. C:H/I:H/A:H without a scope change is 7-8;
#                       one namespace or workload is 5-6; availability only 3-4
#   exposure         <- Attack Vector plus Scope: how reachable it is and how
#                       far the blast travels. Present by default and broadly
#                       reachable 8-10; common but deliberate config 4-7;
#                       rare 1-3
#   remediation_ease <- CVSS Remediation Level One line flip or delete 9-10;
#                       one line needing the right value or testing 7-8;
#                       design or coordination 5-6; architectural 1-4.
#
# Watch the direction of remediation_ease: 1 = hard to fix, 10 = trivial and
# because the weight is positive an EASY fix RAISES the score, that looks
# backwards at first. The reason is that this is a work queue not a severity
# rating: two equally dangerous problems are not equally urgent if one is a
# one line change and the other is a storage redesign, so cheap dangerous
# things should float to the top

RULE_FACTORS = {
    # privileged container. Anchor: CVE-2019-5736 (runc host binary overwrite),
    # CVSS v3.1 8.6, AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H. Rule class CWE-250.
    # S:C plus the full triad is the breakout case so impact takes the top
    "K8S-SEC-001": {"exploitability": 9, "impact": 10, "exposure": 6, "remediation_ease": 9},

    # hostPath volume. Anchor: CVE-2021-25741 (subpath symlink reaches host
    # files), CVSS v3.1 8.1, AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N. Rule class
    # CWE-668. Ease is low because replacing a hostPath means redesigning storage
    "K8S-SEC-006": {"exploitability": 8, "impact": 9, "exposure": 7, "remediation_ease": 6},

    # dangerous capabilities. Anchor: CVE-2022-0492 (cgroups v1 release_agent
    # escape, reachable with SYS_ADMIN), CVSS v3.1 7.8,
    # AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H. Rule class CWE-250
    "K8S-SEC-005": {"exploitability": 8, "impact": 9, "exposure": 5, "remediation_ease": 8},

    # cluster-admin binding. Anchor: CVE-2018-1002105 (API server escalation to
    # full cluster control), CVSS v3.0 9.8, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    # (NVD has no v3.1 for it). Rule class CWE-269. Exploitability is a step
    # down because the bound credential has to be obtained first
    "K8S-RBC-002": {"exploitability": 7, "impact": 10, "exposure": 4, "remediation_ease": 9},

    # hostPID/hostIPC. No clean CVE: this is a configuration exposure, not a
    # software flaw so the values are CWE-rubric derived from CWE-668
    # (exposure of resource to wrong sphere), CIS v1.8 5.2.3/5.2.4, OWASP K01
    "K8S-SEC-004": {"exploitability": 7, "impact": 9, "exposure": 5, "remediation_ease": 9},

    # hostNetwork. Anchor: CVE-2020-8558 (node localhost boundary bypass),
    # CVSS v3.1 8.8, AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Rule class CWE-668.
    # AV:A rather than AV:L, but S:U keeps impact below the breakout rules
    "K8S-NET-001": {"exploitability": 7, "impact": 8, "exposure": 6, "remediation_ease": 8},

    # running as root. Anchor: CVE-2019-11245 (containers run as uid 0 when
    # runAsUser is unset), CVSS v3.0 7.8, AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
    # (no v3.1 in NVD). Rule class CWE-250. Exploitability sits at the top of
    # the middle band: a foothold is still needed and S:U caps the impact
    "K8S-SEC-003": {"exploitability": 7, "impact": 7, "exposure": 7, "remediation_ease": 7},

    # allowPrivilegeEscalation. No clean CVE: it is a control that permits
    # setuid escalation rather than a flaw. CWE-rubric derived from CWE-269,
    # CIS v1.8 5.2.6, OWASP K01. Two conditions needed so exploitability 6
    "K8S-SEC-002": {"exploitability": 6, "impact": 7, "exposure": 5, "remediation_ease": 9},

    # wildcard RBAC. No clean CVE: over-broad permissions are intended
    # behaviour until a token leaks. CWE-rubric derived from CWE-269,
    # CIS v1.8 5.1.3, OWASP K03
    "K8S-RBC-001": {"exploitability": 5, "impact": 8, "exposure": 4, "remediation_ease": 7},

    # missing NetworkPolicy. No CVE by nature: an absent control. CWE-rubric
    # derived from CWE-923 (improper restriction of communication channel),
    # CIS 5.3.2, OWASP K07. Exposure is the highest here because Kubernetes
    # ships with no default-deny so every namespace without a policy fires
    "K8S-NET-002": {"exploitability": 4, "impact": 6, "exposure": 8, "remediation_ease": 5},

    # :latest tag. No CVE: it is a practice, not a flaw. CWE-rubric derived
    # from CWE-494 (download of code without integrity check), OWASP K02
    # Enabling-only so exploitability sits in the low band
    "K8S-WKL-001": {"exploitability": 3, "impact": 5, "exposure": 7, "remediation_ease": 9},

    # no resource limits. Anchor: CVE-2020-8557 (pod disk usage unaccounted,
    # node DoS), CVSS v3.1 5.5, AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H. Rule
    # class CWE-770. C:N/I:N is why impact is the lowest in the table but
    # AV:L/AC:L/PR:L keeps exploitability at the top of the middle band
    "K8S-WKL-002": {"exploitability": 7, "impact": 4, "exposure": 6, "remediation_ease": 8},
}

# all positive and they sum to 1.0. That is what keeps the score inside
# 1.0-10.0 with no offset and no clamping: a weighted average of
# values from 1 to 10 cannot land outside 1 to 10. the first version of this
# was a weighted SUM plus an offset of 5 with a clamp which saturated at 10.0
# and made the worst findings non distinct from each other

WEIGHTS = {"exploitability": 0.30, "impact": 0.35, "exposure": 0.25, "remediation_ease": 0.10}


def band_for(score):
    """ Turn a score into its band; the words match the SSVC outcomes on purpose """
    # Borrowing SSVCs four words is what makes the whole comparison possible
    # Cohens kappa needs two raters picking from one shared set of labels so
    # without this there would be nothing to compare
    if score >= 8.0:
        return "Act"
    elif score >= 6.0:
        return "Attend"
    elif score >= 4.0:
        return "Track*"
    else:
        return "Track"


def score_finding(finding, weights):
    """Score one finding and attach the result (and its inputs) to it"""
    # indexing RULE_FACTORS directly
    factors = RULE_FACTORS[finding.rule_id]
    total = 0
    for name in weights:
        total = total + weights[name] * factors[name]
    finding.score = round(total, 1)
    finding.band = band_for(finding.score)
    # keep the inputs on the finding so --report can show exactly how the score
    # was built
    finding.factors = factors
    finding.weights = weights
    return finding.score


def load_weights(path):
    """Read custom weights from a YAML file; missing keys fall back to the default"""
    # utf-8 explicitly so a weights file behaves the same on every platform
    with open(path, encoding="utf-8") as f:
        loaded = yaml.safe_load(f)
    if loaded is None:
        loaded = {}
    weights = {}
    for name in WEIGHTS:
        if name in loaded:
            weights[name] = loaded[name]
        else:
            weights[name] = WEIGHTS[name]
        if weights[name] < 0:
            raise ValueError(f"weight '{name}' is negative ({weights[name]})")
    total = weights["exploitability"] + weights["impact"] + weights["exposure"] + weights["remediation_ease"]
    
    if total < 0.99 or total > 1.01:
        raise ValueError(f"weights sum to {round(total, 3)}, they must sum to 1.0")
    return weights
