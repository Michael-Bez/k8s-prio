""" Tests for the YAML parser """

import os

from k8s_prio.parser import parse_file, parse_dir, get_containers, get_pod_spec

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name):
    """ Full path to a file in tests/fixtures """
    return os.path.join(FIXTURES, name)


def test_multi_document_file():
    resources = parse_file(fixture("multi_doc.yaml"))
    assert len(resources) == 2
    assert resources[0].kind == "Pod"
    assert resources[0].name == "web"
    assert resources[1].kind == "Service"
    assert resources[1].name == "web-svc"


def test_namespace_defaults_to_default():
    resources = parse_file(fixture("multi_doc.yaml"))
    assert resources[0].namespace == "default"   # the Pod has no namespace set
    assert resources[1].namespace == "shop"


def test_spec_is_never_none():
    # the ConfigMap in no_kind.yaml has no spec, so it should become {}
    resources = parse_file(fixture("no_kind.yaml"))
    assert resources[0].spec == {}


def test_document_without_kind_is_skipped():
    # the first document in no_kind.yaml is a values file not an object
    resources = parse_file(fixture("no_kind.yaml"))
    assert len(resources) == 1
    assert resources[0].kind == "ConfigMap"


def test_broken_yaml_is_skipped():
    resources = parse_file(fixture("broken.yaml"))
    assert resources == []


def test_source_file_is_recorded():
    resources = parse_file(fixture("multi_doc.yaml"))
    assert resources[0].source_file == fixture("multi_doc.yaml")


def test_utf8_content_parses_regardless_of_platform_locale():
    # utf8_content.yaml holds an emoji whose bytes the Windows default codec
    # (cp1252) cannot decode. The parser opens files with encoding="utf-8"
    # explicitly, so the platform's locale default never gets a say - this
    # exact file was skipped on Windows and parsed on Fedora before the fix
    resources = parse_file(fixture("utf8_content.yaml"))
    assert len(resources) == 1
    assert resources[0].kind == "ConfigMap"
    assert resources[0].name == "greeting-config"


def test_parse_dir_combines_files():
    resources = parse_dir(FIXTURES)
    names = [r.name for r in resources]
    assert "web" in names          # from multi_doc.yaml
    assert "app-config" in names   # from no_kind.yaml


def test_get_pod_spec_looks_inside_deployment_template():
    resources = parse_file(fixture("deployment_with_init.yaml"))
    pod_spec = get_pod_spec(resources[0])
    assert "containers" in pod_spec


def test_get_containers_includes_init_containers():
    resources = parse_file(fixture("deployment_with_init.yaml"))
    containers = get_containers(resources[0])
    names = [c["name"] for c in containers]
    assert names == ["api", "migrate"]


def test_get_containers_on_a_plain_pod():
    resources = parse_file(fixture("multi_doc.yaml"))
    containers = get_containers(resources[0])
    assert len(containers) == 1
    assert containers[0]["name"] == "web"
