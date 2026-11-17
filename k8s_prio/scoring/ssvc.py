""" The SSVC router: sorts findings into Act / Attend / Track* / Track using
the CISA Coordinator decision tree (CISA SSVC Guide; Spring et al. 2021,
SEI/CMU)

SSVC does not produce a score, it asks a few questions and reads a recommended
action off a tree which is a different idea from CVSS and the reason it is
worth comparing against. It normally judges one specific vulnerability, here
there are no vulnerabilities only kinds of misconfiguration so the four
decision points are judged per rule """

# The four CISA Coordinator decision points and their allowed values:
#   exploitation: "none" (no public exploit) | "poc" (public proof of concept
#                 or a widely known method) | "active" (reported exploitation
#                 in the wild). SSVC spells the middle value "public poc"
#   automatable:  "no" | "yes" - can kill chain steps 1-4 (reconnaissance,
#                 weaponisation, delivery, exploitation) be reliably automated?
#   impact:       "partial" | "total" - SSVC Technical Impact is binary:
#                 total means total control of the software's behaviour
#   mission:      "low" | "medium" | "high" - Mission and Well-Being Impact
#
# one local assumption and it is the honest weak point of this half
# SSVC expects Mission and Well-Being to come from the organisation running the
# system because only they know which workloads matter. A static manifest
# scanner has none of that so it is set per rule from how central the affected
# resource type is: node-level or control-plane compromise = high, a single pod
# or workload = medium, hygiene on one workload = low. a real deployment would
# override this per organisation
#
# It is worth saying why that is a threat rather than a harmless
# default: mission is one of the four inputs, not a tie-breaker and it can move
# the outcome by two whole bands. Looking at the ("active", "no", "total") row
# below where mission alone takes it from Track to Act so a value I supplied
# myself has real control over one of the two things being compared.

RULE_SSVC = {
    # exploitation=active: privileged-pod escapes are reported in real
    # crypto-mining campaigns. automatable=yes: enumerate pods and escape is
    # scriptable. impact=total: root on the node mission=high: node level
    "K8S-SEC-001": {"exploitation": "active", "automatable": "yes",
                    "impact": "total", "mission": "high"},

    # exploitation=active: docker.sock and host-root mounts are abused in the
    # wild automatable=yes: mount then chroot is a script. impact=total: the
    # node filesystem. mission=high: node level
    "K8S-SEC-006": {"exploitation": "active", "automatable": "yes",
                    "impact": "total", "mission": "high"},


    # exploitation=poc: the SYS_ADMIN cgroup release_agent escape is published
    # (CVE-2022-0492) but not widely reported in the wild automatable=yes
    # impact=total: escape yields node root. mission=high: node level
    "K8S-SEC-005": {"exploitation": "poc", "automatable": "yes",
                    "impact": "total", "mission": "high"},

    # exploitation=poc: using a stolen bound token is a known method
    # automatable=no: the specific credential must be obtained per target
    # impact=total: cluster-admin is unlimited. mission=high: control plane
    "K8S-RBC-002": {"exploitation": "poc", "automatable": "no",
                    "impact": "total", "mission": "high"},

    # exploitation=poc: /proc based escapes are published methods
    # automatable=yes: process enumeration scripts well impact=total: host
    # process namespace leads to node compromise. mission=high: node level
    "K8S-SEC-004": {"exploitation": "poc", "automatable": "yes",
                    "impact": "total", "mission": "high"},

    # exploitation=poc: reaching node-bound services is a published method
    # (CVE-2020-8558). automatable=yes. impact=partial: network reach, not
    # control of the node. mission=high: the node's own network
    "K8S-NET-001": {"exploitation": "poc", "automatable": "yes",
                    "impact": "partial", "mission": "high"},

    # exploitation=active: root in container is the standard precondition used
    # in real container attacks automatable=yes. impact=partial: contained to
    # the container on its own. mission=medium: one workload
    "K8S-SEC-003": {"exploitation": "active", "automatable": "yes",
                    "impact": "partial", "mission": "medium"},

    # exploitation=poc: setuid escalation is a textbook method
    # automatable=no: needs a suitable setuid binary in that specific image
    # impact=partial: escalation inside the container. mission=medium
    "K8S-SEC-002": {"exploitation": "poc", "automatable": "no",
                    "impact": "partial", "mission": "medium"},

    # exploitation=none: a wildcard grant is intended behaviour until a token
    # leaks, so there is nothing to exploit automatable=no. impact=total:
    # the grant is unlimited within its scope. mission=high: control plane
    "K8S-RBC-001": {"exploitation": "none", "automatable": "no",
                    "impact": "total", "mission": "high"},

    # exploitation=none: an absent control cannot itself be exploited
    # automatable=yes: scanning a flat namespace is scriptable
    # impact=partial: enables movement, grants nothing. mission=medium
    "K8S-NET-002": {"exploitation": "none", "automatable": "yes",
                    "impact": "partial", "mission": "medium"},

    # exploitation=poc: image poisoning is a published supply chain method
    # automatable=no: the registry or build must be compromised per target
    # impact=partial: an unpredictable image mission=low: workload hygiene
    "K8S-WKL-001": {"exploitation": "poc", "automatable": "no",
                    "impact": "partial", "mission": "low"},

    # exploitation=poc: resource exhaustion is a published method
    # (CVE-2020-8557). automatable=yes: just allocate impact=partial:
    # availability only. mission=low: workload hygiene
    "K8S-WKL-002": {"exploitation": "poc", "automatable": "yes",
                    "impact": "partial", "mission": "low"},
}

# The published CISA Coordinator tree - transcribed from the CERT/CC data file
# cisa_coordinator_2_0_3.csv. 3 exploitation x 2 automatable x 2 impact gives
# the 12 keys below each holding 3 mission outcomes so all 36 published rows
# are written out here by me
#
# it is a lookup table rather than a chain of ifs so that it can be checked
# someone can sit with the published CSV and compare it line by line, Nested
# conditionals would hide the same information in a form nobody can check
#
CISA_TREE = {
    ("none", "no", "partial"): {"low": "Track", "medium": "Track", "high": "Track"},
    ("none", "no", "total"): {"low": "Track", "medium": "Track", "high": "Track*"},
    ("none", "yes", "partial"): {"low": "Track", "medium": "Track", "high": "Attend"},
    ("none", "yes", "total"): {"low": "Track", "medium": "Track", "high": "Attend"},
    ("poc", "no", "partial"): {"low": "Track", "medium": "Track", "high": "Track*"},
    ("poc", "no", "total"): {"low": "Track", "medium": "Track*", "high": "Attend"},
    ("poc", "yes", "partial"): {"low": "Track", "medium": "Track", "high": "Attend"},
    ("poc", "yes", "total"): {"low": "Track", "medium": "Track*", "high": "Attend"},
    ("active", "no", "partial"): {"low": "Track", "medium": "Track", "high": "Attend"},
    ("active", "no", "total"): {"low": "Track", "medium": "Attend", "high": "Act"},
    ("active", "yes", "partial"): {"low": "Attend", "medium": "Attend", "high": "Act"},
    ("active", "yes", "total"): {"low": "Attend", "medium": "Act", "high": "Act"},
}

# The same tree drawn out
#
#  exploitation
#  ├- none ---- automatable no --- partial --- low/med/high -> Track  Track  Track ─ 
#  │            │                 total --- low/med/high -> Track  Track  Track*
#  │            └ automatable yes  partial --- low/med/high -> Track  Track  Attend
#  │                              total ---- low/med/high -> Track  Track  Attend
#  ├- poc ---- automatable no ── partial -- low/med/high -> Track  Track  Track*
#  │            │                 total ---- low/med/high -> Track  Track* Attend
#  │            └ automatable yes  partial -- low/med/high -> Track  Track  Attend
#  │                              total ---- low/med/high -> Track  Track* Attend
#  └- active --- automatable no -- partial -- low/med/high -> Track  Track  Attend
#               │                 total -- low/med/high -> Track  Attend Act
#               └ automatable yes  partial -- low/med/high -> Attend Attend Act
#                                 total ---- low/med/high -> Attend Act    Act


def route(finding):
    """Walk the CISA Coordinator tree for one finding; attach outcome and path """
    values = RULE_SSVC[finding.rule_id]
    exploitation = values["exploitation"]
    automatable = values["automatable"]
    impact = values["impact"]
    mission = values["mission"]
    # i record the path in the order the tree asks its questions so --report can
    # show how the outcome was reached rather than just asserting it
    path = [f"exploitation={exploitation}", f"automatable={automatable}",
            f"impact={impact}", f"mission={mission}"]

    # two lines because the tree is a table
    branch = CISA_TREE[(exploitation, automatable, impact)]
    outcome = branch[mission]

    finding.ssvc_outcome = outcome
    finding.ssvc_path = path
    return outcome
