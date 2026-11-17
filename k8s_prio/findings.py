""" The Finding class: what a rule hands back when it spots a problem """


# every Finding carries a "features" dict with exactly these six keys and
# every rule has to fill all six, both scoring engines read them so a missing
# key would mean a finding that cannot be scored, only the two reference
# fields may be None and only because two rules genuinely have no CIS item
#
# Six and no more on purpose, features is what makes any two findings
# comparable and a seventh key that only some rules set would break that.
# When I needed somewhere to put the container name I added a field on the
# class instead (see container)
#
#   category                which family the rule belongs to: "network",
#                           "security_context", "workload" or "rbac"
#   owasp_top10_ref         the OWASP Kubernetes Top 10 (2022) entry, e.g.
#                           "K01", or None when the rule has no OWASP source
#   cis_benchmark_ref       the CIS Kubernetes Benchmark v1.8 section, e.g.
#                           "5.2.4", or None when there is no CIS item
#   is_workload             True when the finding is about something that runs
#                           containers (see WORKLOAD_KINDS in parser.py)
#   affects_node_resources  True when the problem can reach the node itself:
#                           its network, processes, filesystem, CPU or memory
#   scope                   how far the damage reaches: "pod", "namespace"
#                           or "cluster"

class Finding:
    """ One misconfiguration found in one resource """

    def __init__(self, rule_id, rule_name, resource, description, remediation_hint,
                 features, container=None, line=None):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.resource = resource
        self.description = description
        self.remediation_hint = remediation_hint
        self.features = features
        # which container this is about for the container-scoped rules, stays
        # None for the pod, object and namespace rules
        self.container = container
        # the line CI should put its annotation on, a rule passes the line of
        # the exact field when it knows it, when it does not, fall back to the
        # line the object starts on so a finding always has somewhere to
        # point, a GitHub annotation with no line does not attach to the diff
        # at all
        if line is None and resource is not None:
            line = resource.line
        self.line = line
