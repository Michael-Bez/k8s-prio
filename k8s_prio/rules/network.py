""" Network rules: host networking and missing NetworkPolicies """

from k8s_prio.findings import Finding
from k8s_prio.parser import WORKLOAD_KINDS, get_pod_spec, line_at, pod_spec_path


# K8S-NET-001. Fires on hostNetwork: true on any workload kind
# Why it matters: the pod shares the nodes real network stack, so it can see
# traffic meant for other pods, reach services bound to the node, and
# NetworkPolicies do not apply to it
# Source: CIS Kubernetes Benchmark v1.8 5.2.5, OWASP Kubernetes Top 10 K01
def check_host_network(resource):
    findings = []
    if resource.kind not in WORKLOAD_KINDS:
        return findings
    pod_spec = get_pod_spec(resource)
    # YAML turns the bare word true into Python's True, so == True works
    if pod_spec.get("hostNetwork") == True:
        features = {"category": "network", "owasp_top10_ref": "K01",
                    "cis_benchmark_ref": "5.2.5", "is_workload": True,
                    "affects_node_resources": True, "scope": "cluster"}
        findings.append(Finding(
            "K8S-NET-001", "hostNetwork enabled", resource,
            f"{resource.kind} '{resource.name}' runs with hostNetwork: true and shares the node's network stack.",
            "Remove hostNetwork: true unless the pod genuinely needs the node's network, which is rare.",
            features,
            line=line_at(resource, pod_spec_path(resource) + ["hostNetwork"])))
    return findings


# K8S-NET-002. Fires on a namespace that runs workloads but has no
# NetworkPolicy in it so nothing restricts pod to pod traffic there
# Why it matters: without a policy a compromised pod can reach every other pod
# in the namespace and move sideways from there
# Source: CIS Kubernetes Benchmark v1.8 5.3.2, OWASP Kubernetes Top 10 K07
#
# Known limitation: this only checks that a NetworkPolicy exist in the
# namespace. It does not check whether the policys podSelector actually
# matches any of the workloads so a policy that selects nothing still counts
# as covered. CIS 5.3.2 is phrased as "defined" too so the rule matches its
# source but a namespace can look protected while being open
def check_missing_network_policy(resources):
    """Whole-list rule: the engine calls this once with every resource."""
    findings = []
    # which namespaces have at least one NetworkPolicy
    covered = []
    for resource in resources:
        if resource.kind == "NetworkPolicy":
            covered.append(resource.namespace)
    # flag each uncovered namespace that has workloads in it, the flagged
    # list is what keeps it to one finding per namespace: a namespace with
    # twenty unprotected Deployments is still one problem not twenty
    # The finding gets pinned to whichever workload turned up first because
    # the real problem is a missing object and there is nothing better to
    # point at
    flagged = []
    for resource in resources:
        if resource.kind not in WORKLOAD_KINDS:
            continue
        if resource.namespace in covered or resource.namespace in flagged:
            continue
        flagged.append(resource.namespace)
        # is_workload is False even though it is pinned to a workload: the
        # finding is about the namespace not about that pod
        features = {"category": "network", "owasp_top10_ref": "K07",
                    "cis_benchmark_ref": "5.3.2", "is_workload": False,
                    "affects_node_resources": False, "scope": "namespace"}
        findings.append(Finding(
            "K8S-NET-002", "namespace without NetworkPolicy", resource,
            f"Namespace '{resource.namespace}' has workloads but no NetworkPolicy, so all pod traffic is allowed.",
            f"Add a default-deny NetworkPolicy to namespace '{resource.namespace}' and only open the traffic that is needed.",
            features))
    return findings
