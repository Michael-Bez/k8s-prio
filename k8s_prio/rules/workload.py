""" Workload hygiene rules: image tags and resource limits """

from k8s_prio.findings import Finding
from k8s_prio.parser import get_containers_with_paths, line_at


# K8S-WKL-001, fires on an image tagged :latest, or with no tag at all since
# Kubernetes treats a missing tag as :latest
# Why it matters: whatever is behind "latest" changes over time so you never
# know exactly what code is running and a poisoned latest pushed to the
# registry rolls out by itself on the next pull
# Source: OWASP Kubernetes Top 10 K02, plus a Kubernetes docs best practice
# There is no CIS item for this one
def check_latest_image_tag(resource):
    findings = []
    for container, path in get_containers_with_paths(resource):
        image = container.get("image")
        if image is None:
            continue
        # The tag is after the last ":" but only in the part after the last
        # "/" A registry address can carry a port like
        # registry.local:5000/app:2.1 and that first colon is not a tag
        last_part = image.split("/")[-1]
        if ":" not in last_part or last_part.endswith(":latest"):
            features = {"category": "workload", "owasp_top10_ref": "K02",
                        "cis_benchmark_ref": None, "is_workload": True,
                        "affects_node_resources": False, "scope": "pod"}
            findings.append(Finding(
                "K8S-WKL-001", "unpinned image tag", resource,
                f"Container '{container.get('name')}' in {resource.kind} '{resource.name}' uses image '{image}' with no fixed version tag.",
                "Pin the image to a specific version tag, e.g. nginx:1.25.3.",
                features, container=container.get("name"),
                line=line_at(resource, path + ["image"])))
    return findings


# K8S-WKL-002, fires on a container with no resources.limits for cpu or memory
# Why it matters: a runaway or malicious container with no limit can eat all
# the CPU and memory on the node and starve every other pod on it
# Source: OWASP Kubernetes Top 10 K01, plus a Kubernetes docs best practice
# No CIS item for this one either
#
# Note it is limits, not requests.
def check_missing_limits(resource):
    findings = []
    for container, path in get_containers_with_paths(resource):
        requirements = container.get("resources")
        if requirements is None:
            requirements = {}
        limits = requirements.get("limits")
        if limits is None:
            limits = {}
        # collect both and report once, rather than two findings for one
        # container that simply set no limits at all
        missing = []
        if "cpu" not in limits:
            missing.append("cpu")
        if "memory" not in limits:
            missing.append("memory")
        if missing != []:
            features = {"category": "workload", "owasp_top10_ref": "K01",
                        "cis_benchmark_ref": None, "is_workload": True,
                        "affects_node_resources": True, "scope": "pod"}
            findings.append(Finding(
                "K8S-WKL-002", "no resource limits", resource,
                f"Container '{container.get('name')}' in {resource.kind} '{resource.name}' has no {' or '.join(missing)} limit.",
                "Set resources.limits.cpu and resources.limits.memory so one container cannot starve the node.",
                features, container=container.get("name"),
                line=line_at(resource, path + ["resources", "limits"])))
    return findings
