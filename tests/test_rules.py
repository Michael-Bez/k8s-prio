""" one firing test and one non firing test for every rule  """

import os

from k8s_prio.parser import parse_file
from k8s_prio.rules import network, rbac, security_context, workload

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    """ Parse a fixture file and return all its resources """
    return parse_file(os.path.join(FIXTURES, name))


def load_one(name):
    """ parse a fixture file and return its first resource """
    return load(name)[0]


# --- K8S-NET-001 hostNetwork ---

def test_host_network_fires():
    findings = network.check_host_network(load_one("host_network_bad.yaml"))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-NET-001"


def test_host_network_does_not_fire():
    assert network.check_host_network(load_one("host_network_ok.yaml")) == []


# --- K8S-NET-002 missing NetworkPolicy (whole list rule) ---

def test_missing_network_policy_fires():
    findings = network.check_missing_network_policy(load("netpol_missing_bad.yaml"))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-NET-002"
    assert findings[0].resource.namespace == "shop"


def test_missing_network_policy_does_not_fire():
    assert network.check_missing_network_policy(load("netpol_ok.yaml")) == []


# --- K8S-SEC-001 privileged ---

def test_privileged_fires_inside_deployment_template():
    findings = security_context.check_privileged(load_one("privileged_bad.yaml"))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-SEC-001"


def test_privileged_fires_for_init_container():
    findings = security_context.check_privileged(load_one("privileged_init_bad.yaml"))
    assert len(findings) == 1
    assert "setup" in findings[0].description


def test_privileged_does_not_fire():
    assert security_context.check_privileged(load_one("privileged_ok.yaml")) == []


# ---K8S-SEC-002 allowPrivilegeEscalation ---

def test_privilege_escalation_fires():
    findings = security_context.check_privilege_escalation(load_one("priv_escalation_bad.yaml"))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-SEC-002"


def test_privilege_escalation_does_not_fire():
    assert security_context.check_privilege_escalation(load_one("priv_escalation_ok.yaml")) == []


# --- K8S-SEC-003 running as root ---

def test_run_as_root_fires_for_uid_zero():
    pods = load("run_as_root_bad.yaml")
    findings = security_context.check_run_as_root(pods[0])
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-SEC-003"


def test_run_as_root_fires_when_nothing_is_set():
    pods = load("run_as_root_bad.yaml")
    findings = security_context.check_run_as_root(pods[1])
    assert len(findings) == 1


def test_run_as_root_does_not_fire_with_pod_level_run_as_non_root():
    assert security_context.check_run_as_root(load_one("run_as_root_ok.yaml")) == []


# --- K8S-SEC-004 hostPID / hostIPC ---

def test_host_pid_ipc_fires():
    findings = security_context.check_host_pid_ipc(load_one("host_pid_bad.yaml"))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-SEC-004"


def test_host_pid_ipc_does_not_fire():
    assert security_context.check_host_pid_ipc(load_one("host_pid_ok.yaml")) == []


# --- K8S-SEC-005 dangerous capabilities ---

def test_dangerous_capabilities_fire():
    findings = security_context.check_dangerous_capabilities(load_one("capabilities_bad.yaml"))
    assert len(findings) == 1
    assert "SYS_ADMIN" in findings[0].description


def test_harmless_capability_does_not_fire():
    assert security_context.check_dangerous_capabilities(load_one("capabilities_ok.yaml")) == []


# --- K8S-SEC-006 hostPath volume ---

def test_host_path_volume_fires():
    findings = security_context.check_host_path_volume(load_one("host_path_bad.yaml"))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-SEC-006"


def test_empty_dir_volume_does_not_fire():
    assert security_context.check_host_path_volume(load_one("host_path_ok.yaml")) == []


# --- K8S-WKL-001 latest / missing image tag ---

def test_latest_and_missing_tags_fire():
    findings = workload.check_latest_image_tag(load_one("latest_tag_bad.yaml"))
    # one finding for nginx:latest, one for redis with no tag
    assert len(findings) == 2
    assert findings[0].rule_id == "K8S-WKL-001"


def test_pinned_tags_do_not_fire():
    # includes a registry with a port, which must not look like a tag
    assert workload.check_latest_image_tag(load_one("latest_tag_ok.yaml")) == []


# --- K8S-WKL-002 missing resource limits ---

def test_missing_limits_fire():
    findings = workload.check_missing_limits(load_one("no_limits_bad.yaml"))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-WKL-002"


def test_set_limits_do_not_fire():
    assert workload.check_missing_limits(load_one("no_limits_ok.yaml")) == []


# --- K8S-RBC-001 wildcard permissions ---

def test_wildcard_role_fires():
    findings = rbac.check_wildcard_permissions(load_one("wildcard_role_bad.yaml"))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-RBC-001"
    assert findings[0].features["scope"] == "cluster"   # it is a ClusterRole


def test_narrow_role_does_not_fire():
    assert rbac.check_wildcard_permissions(load_one("wildcard_role_ok.yaml")) == []


# --- K8S-RBC-002 cluster-admin binding ---

def test_cluster_admin_binding_fires():
    findings = rbac.check_cluster_admin_binding(load_one("cluster_admin_bad.yaml"))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-RBC-002"


def test_view_binding_does_not_fire():
    assert rbac.check_cluster_admin_binding(load_one("cluster_admin_ok.yaml")) == []


# --- the container field, so a finding says which container it is about ---

def test_container_scoped_rules_set_the_container_field():
    findings = security_context.check_privileged(load_one("privileged_init_bad.yaml"))
    assert findings[0].container == "setup"


def test_pod_scoped_rules_leave_the_container_field_none():
    findings = security_context.check_host_pid_ipc(load_one("host_pid_bad.yaml"))
    assert findings[0].container is None
