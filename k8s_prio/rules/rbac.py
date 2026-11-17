""" RBAC rules, these read resource.raw rather than resource.spec because
Roles and RoleBindings keep their data at the top level of the YAML and not
under spec at all """

from k8s_prio.findings import Finding
from k8s_prio.parser import line_at


# K8S-RBC-001, fires on a Role or ClusterRole using "*" in verbs or resources
# Why it matters: "*" grants every action or every resource type which is far
# more than any workload needs - a leaked token then becomes a master key
# Source: CIS Kubernetes Benchmark v1.8 5.1.3, OWASP Kubernetes Top 10 K03
def check_wildcard_permissions(resource):
    findings = []
    if resource.kind not in ["Role", "ClusterRole"]:
        return findings
    rules = resource.raw.get("rules")
    if rules is None:
        rules = []
    position = -1
    for rule in rules:
        position = position + 1
        if "*" in rule.get("verbs", []) or "*" in rule.get("resources", []):
            # scope depends on the kind: a Role only reaches its own namespace
            # a ClusterRole reaches the whole cluster
            if resource.kind == "ClusterRole":
                scope = "cluster"
            else:
                scope = "namespace"
            features = {"category": "rbac", "owasp_top10_ref": "K03",
                        "cis_benchmark_ref": "5.1.3", "is_workload": False,
                        "affects_node_resources": False, "scope": scope}
            findings.append(Finding(
                "K8S-RBC-001", "wildcard in role permissions", resource,
                f"{resource.kind} '{resource.name}' uses '*' in its verbs or resources.",
                "List only the exact verbs and resource types this role really needs.",
                features, line=line_at(resource, ["rules", position])))
            break  # one finding per role is enough even if several entries use '*'
    return findings


# K8S-RBC-002, fires on a RoleBinding or ClusterRoleBinding that binds subjects
# to the built in cluster-admin role
# Why it matters: cluster-admin can do anything in the cluster so
# whoever holds the bound account owns the whole thing
# Source: CIS Kubernetes Benchmark v1.8 5.1.1, OWASP Kubernetes Top 10 K03

# It matches on the name and nothing else so a locally defined role that
# happens to be called cluster-admin will match too, a manifest scanner cannot
# tell it apart from the built in one so the name is all there is to go on
def check_cluster_admin_binding(resource):
    findings = []
    if resource.kind not in ["RoleBinding", "ClusterRoleBinding"]:
        return findings
    role_ref = resource.raw.get("roleRef")
    if role_ref is None:
        role_ref = {}
    if role_ref.get("name") == "cluster-admin":
        if resource.kind == "ClusterRoleBinding":
            scope = "cluster"
        else:
            scope = "namespace"
        features = {"category": "rbac", "owasp_top10_ref": "K03",
                    "cis_benchmark_ref": "5.1.1", "is_workload": False,
                    "affects_node_resources": False, "scope": scope}
        findings.append(Finding(
            "K8S-RBC-002", "binding to cluster-admin", resource,
            f"{resource.kind} '{resource.name}' grants the cluster-admin role.",
            "Bind to a purpose-made role that holds only the permissions the subject needs.",
            features, line=line_at(resource, ["roleRef", "name"])))
    return findings
