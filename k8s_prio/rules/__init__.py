""" Collects every per resource rule into one list for the engine to loop over """

from k8s_prio.rules import network, rbac, security_context, workload

# Each rule is a function taking one Resource and returning a list of Findings,
# empty when there is nothing wrong - add a new rule here or the engine will
# never call it

# network.check_missing_network_policy is not in this list, it cannot judge one
# resource on its own so engine.py calls it separately with everything
ALL_RULES = [
    network.check_host_network,
    security_context.check_privileged,
    security_context.check_privilege_escalation,
    security_context.check_run_as_root,
    security_context.check_host_pid_ipc,
    security_context.check_dangerous_capabilities,
    security_context.check_host_path_volume,
    workload.check_latest_image_tag,
    workload.check_missing_limits,
    rbac.check_wildcard_permissions,
    rbac.check_cluster_admin_binding,
]
