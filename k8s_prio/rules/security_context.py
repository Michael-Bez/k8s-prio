""" Security context rules: the settings that decide what a container may do """

from k8s_prio.findings import Finding
from k8s_prio.parser import (WORKLOAD_KINDS, get_containers_with_paths,
                             get_pod_spec, line_at, pod_spec_path)

# capabilities that hand a container far too much power over the node
DANGEROUS_CAPS = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL"]


def get_security_context(container):
    """Return a container's securityContext, or {} when it has none."""
    context = container.get("securityContext")
    if context is None:
        return {}
    return context


# K8S-SEC-001, fires on privileged: true on any container, init ones included
# Why it matters: a privileged container gets full access to the node's devices
# and kernel. That is effectively root on the node so escaping is easy
# Source: CIS Kubernetes Benchmark v1.8 5.2.2, OWASP Kubernetes Top 10 K01
# No kind check needed here: get_containers_with_paths returns an empty list
# for anything that is not a workload so the loop just does nothing
def check_privileged(resource):
    findings = []
    for container, path in get_containers_with_paths(resource):
        # privileged is container level only, a pod securityContext cannot set it
        if get_security_context(container).get("privileged") == True:
            features = {"category": "security_context", "owasp_top10_ref": "K01",
                        "cis_benchmark_ref": "5.2.2", "is_workload": True,
                        "affects_node_resources": True, "scope": "cluster"}
            findings.append(Finding(
                "K8S-SEC-001", "privileged container", resource,
                f"Container '{container.get('name')}' in {resource.kind} '{resource.name}' runs privileged.",
                "Remove privileged: true; if the container needs one specific power, add that single capability instead.",
                features, container=container.get("name"),
                line=line_at(resource, path + ["securityContext", "privileged"])))
    return findings


# K8S-SEC-002, fires on allowPrivilegeEscalation: true on a container
# Why it matters: it lets a process inside the container gain more privileges
# than it started with for example through a setuid binary like sudo
# Source: CIS Kubernetes Benchmark v1.8 5.2.6, OWASP Kubernetes Top 10 K01
# Only an explicit true fires, the field actually defaults to true when unset
# so an absent field is just as unsafe but the rule as specified names the
# explicit value and the rules are not changed to match results
def check_privilege_escalation(resource):
    findings = []
    for container, path in get_containers_with_paths(resource):
        if get_security_context(container).get("allowPrivilegeEscalation") == True:
            features = {"category": "security_context", "owasp_top10_ref": "K01",
                        "cis_benchmark_ref": "5.2.6", "is_workload": True,
                        "affects_node_resources": False, "scope": "pod"}
            findings.append(Finding(
                "K8S-SEC-002", "privilege escalation allowed", resource,
                f"Container '{container.get('name')}' in {resource.kind} '{resource.name}' allows privilege escalation.",
                "Set allowPrivilegeEscalation: false in the container's securityContext.",
                features, container=container.get("name"),
                line=line_at(resource, path + ["securityContext", "allowPrivilegeEscalation"])))
    return findings


# K8S-SEC-003, fires on a container that runs as root or could
# Why it matters: a root process in a container is one kernel bug or one bad
# mount away from being root on the node
# Source: CIS Kubernetes Benchmark v1.8 5.2.7, OWASP Kubernetes Top 10 K01

# This is the only rule with two branches because there are two different
# problems with two different messages:
#   1. runAsUser: 0 is set, so it definitely runs as root
#   2. nothing is set at all so it falls back to the images user, which is
#      very often root
# A non zero runAsUser is accepted and nothing fires. The two conditions can
# never both be true so the elif is just readability. What does matter is the
# "run_as_user is None" guard on the second branch: without it a container with
# runAsUser: 1000 would be flagged which is the opposite of what we want
def check_run_as_root(resource):
    findings = []
    pod_context = get_pod_spec(resource).get("securityContext")
    if pod_context is None:
        pod_context = {}
    for container, path in get_containers_with_paths(resource):
        context = get_security_context(container)
        # the container level setting wins over the pod level one - same as
        # Kubernetes itself resolves it
        run_as_user = context.get("runAsUser")
        if run_as_user is None:
            run_as_user = pod_context.get("runAsUser")
        features = {"category": "security_context", "owasp_top10_ref": "K01",
                    "cis_benchmark_ref": "5.2.7", "is_workload": True,
                    "affects_node_resources": False, "scope": "pod"}
        if run_as_user == 0:
            findings.append(Finding(
                "K8S-SEC-003", "container runs as root", resource,
                f"Container '{container.get('name')}' in {resource.kind} '{resource.name}' sets runAsUser: 0 (root).",
                "Run as a non-root user: pick a non-zero runAsUser and set runAsNonRoot: true.",
                features, container=container.get("name"),
                line=line_at(resource, path + ["securityContext", "runAsUser"])))
        elif run_as_user is None and context.get("runAsNonRoot") != True and pod_context.get("runAsNonRoot") != True:
            # nothing anywhere stops root, there is no runAsUser key to point
            # at so line_at walks as far as it can and lands on the
            # securityContext block or the container if even that is missing
            findings.append(Finding(
                "K8S-SEC-003", "container may run as root", resource,
                f"Container '{container.get('name')}' in {resource.kind} '{resource.name}' has nothing stopping it from running as root.",
                "Set runAsNonRoot: true at pod or container level, or a non-zero runAsUser.",
                features, container=container.get("name"),
                line=line_at(resource, path + ["securityContext"])))
    return findings


# K8S-SEC-004, fires on hostPID: true or hostIPC: true on a workload
# Why it matters: with hostPID the pod can see and signal every process on the
# node; with hostIPC it can talk to any of them over shared memory
# Source: CIS Kubernetes Benchmark v1.8 5.2.3 (hostPID) and 5.2.4 (hostIPC),
# OWASP Kubernetes Top 10 K01
def check_host_pid_ipc(resource):
    findings = []
    if resource.kind not in WORKLOAD_KINDS:
        return findings
    pod_spec = get_pod_spec(resource)
    # both flags go into one finding. A pod sharing both namespaces has one
    # problem to fix not two and the message names whichever applies
    shared = []
    if pod_spec.get("hostPID") == True:
        shared.append("hostPID")
    if pod_spec.get("hostIPC") == True:
        shared.append("hostIPC")
    if shared != []:
        features = {"category": "security_context", "owasp_top10_ref": "K01",
                    "cis_benchmark_ref": "5.2.3/5.2.4", "is_workload": True,
                    "affects_node_resources": True, "scope": "cluster"}
        findings.append(Finding(
            "K8S-SEC-004", "host PID/IPC namespace shared", resource,
            f"{resource.kind} '{resource.name}' shares the node's {' and '.join(shared)} namespace.",
            "Remove hostPID/hostIPC — workloads almost never need the node's process or IPC namespace.",
            # annotate the first flag found since there is only one line to pick
            features, line=line_at(resource, pod_spec_path(resource) + [shared[0]])))
    return findings


# K8S-SEC-005, fires when a container adds SYS_ADMIN, NET_ADMIN, SYS_PTRACE
# or ALL
# Why it matters: those let it mount filesystems, rewrite the network setup or
# trace other processes which are all common container escape routes
# Source: CIS Kubernetes Benchmark v1.8 5.2.9, OWASP Kubernetes Top 10 K01

# Only the four names above count. Dropping capabilities is the safe direction
# so drop is ignored entirely and any capability outside the list does not
# fire because the rule as specified names four
def check_dangerous_capabilities(resource):
    findings = []
    for container, path in get_containers_with_paths(resource):
        capabilities = get_security_context(container).get("capabilities")
        if capabilities is None:
            capabilities = {}
        added = capabilities.get("add")
        if added is None:
            added = []
        bad = [cap for cap in added if cap in DANGEROUS_CAPS]
        # all the bad ones go in one finding listed in the message
        if bad != []:
            features = {"category": "security_context", "owasp_top10_ref": "K01",
                        "cis_benchmark_ref": "5.2.9", "is_workload": True,
                        "affects_node_resources": True, "scope": "pod"}
            findings.append(Finding(
                "K8S-SEC-005", "dangerous capabilities added", resource,
                f"Container '{container.get('name')}' in {resource.kind} '{resource.name}' adds: {', '.join(bad)}.",
                "Drop these capabilities; add only the narrow ones the process really needs (e.g. NET_BIND_SERVICE).",
                features, container=container.get("name"),
                line=line_at(resource, path + ["securityContext", "capabilities", "add"])))
    return findings


# K8S-SEC-006, fires on a hostPath volume on a workload
# Why it matters: it mounts part of the nodes own filesystem into the pod, and
# a path like / or /var/run/docker.sock hands over the whole node
# Source: CIS Kubernetes Benchmark v1.8 5.2.12, OWASP Kubernetes Top 10 K01

# This is the only rule that fires once per VOLUME rather than once per object
# or per container. Each hostPath is a separate decision by whoever wrote the
# manifest and mounting /var/log is a different problem from mounting / so
# merging them would hide information and lose the exact line. The volume name
# goes in the description so one finding can still be told from another
def check_host_path_volume(resource):
    findings = []
    if resource.kind not in WORKLOAD_KINDS:
        return findings
    # position is tracked by hand because line_at needs the index to walk into
    # the volumes, starts at -1 and increments first so it is right
    # on the first time round
    position = -1
    for volume in get_pod_spec(resource).get("volumes", []):
        position = position + 1
        if volume.get("hostPath") is not None:
            features = {"category": "security_context", "owasp_top10_ref": "K01",
                        "cis_benchmark_ref": "5.2.12", "is_workload": True,
                        "affects_node_resources": True, "scope": "cluster"}
            findings.append(Finding(
                "K8S-SEC-006", "hostPath volume", resource,
                f"{resource.kind} '{resource.name}' mounts host path '{volume['hostPath'].get('path')}' (volume '{volume.get('name')}').",
                "Use a PersistentVolumeClaim or emptyDir instead of mounting the node's filesystem.",
                features,
                line=line_at(resource, pod_spec_path(resource) + ["volumes", position, "hostPath"])))
    return findings
