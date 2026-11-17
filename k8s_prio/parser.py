""" Reads Kubernetes YAML manifest files into Resource objects """

import os

import yaml

# the kinds that actually run containers, this is the place that decides
# what a "workload" is. My rules read it, the corpus profile's workload count
# reads it and the line number paths read it.
#
# Job, CronJob and ReplicaSet are in the list because every CIS and OWASP
# source these rules cite talks about the pod that ends up running 
# a privileged container is just as dangerous in a CronJob as
# in a Deployment so leaving them out was a hole rather than a choice so I fixed it
WORKLOAD_KINDS = ["Pod", "Deployment", "StatefulSet", "DaemonSet",
                  "Job", "CronJob", "ReplicaSet"]

# the controllers that wrap a pod template at spec.template.spec
# CronJob is  not here because it wraps its template one level deeper, inside a jobTemplate
TEMPLATE_KINDS = ["Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"]


class Resource:
    """one Kubernetes object loaded from a YAML file """

    def __init__(self, source_file, kind, name, namespace="default", spec=None,
                 raw=None, line=1, node=None):
        self.source_file = source_file
        self.kind = kind
        self.name = name
        self.namespace = namespace
        # the 1 based line this document starts on, and the YAML node tree for
        # the same document PyYAML only keeps line numbers in the node tree
        # so that is what lets a rule report the line of the exact field that
        # is wrong instead of just the top of the object
        self.line = line
        self.node = node
        # spec is never None, so rules can call spec.get() without checking first
        if spec is None:
            spec = {}
        self.spec = spec

        # raw is the whole document, I needed it because not everything lives under
        # spec: Roles and RoleBindings keep their data at the top level.
        if raw is None:
            raw = {}
        self.raw = raw


def pod_spec_path(resource):
    """ where the pod spec sits inside the document as a list of keys

    One definition but used twice: get_pod_spec walks it over the data and line_at
    walks it over the node tree. Because there is only one path the data and
    the line number cannot move apart, if each rule knew the depth itself
    adding ReplicaSet later would have meant editing twelve places
    """
    if resource.kind == "Pod":
        return ["spec"]
    if resource.kind == "CronJob":
        # a CronJob wraps a Job which wraps the pod template, so five deep
        return ["spec", "jobTemplate", "spec", "template", "spec"]
    if resource.kind in TEMPLATE_KINDS:
        return ["spec", "template", "spec"]
    return []


def get_pod_spec(resource):
    """ return the pod level spec of a workload resource or {} if none  """
    path = pod_spec_path(resource)
    if path == []:
        # not a workload kind so there is no pod spec to find
        return {}
    found = resource.raw
    for key in path:
        if not isinstance(found, dict):
            return {}
        found = found.get(key)
    if not isinstance(found, dict):
        return {}
    return found


def get_containers_with_paths(resource):
    """ every container in a workload paired with the route to it
    each item is [container_dict, path_list] where the path looks like
    ["spec", "containers", 0] so exactly what line_at needs """
    pod_spec = get_pod_spec(resource)
    prefix = pod_spec_path(resource)
    found = []
    # normal containers first then initContainers, Init containers are
    # included because a privileged one is just as dangerous and it has
    # already done the damage before the main container even starts
    for group in ["containers", "initContainers"]:
        position = 0
        for container in pod_spec.get(group, []):
            found.append([container, prefix + [group, position]])
            position = position + 1
    return found


def get_containers(resource):
    """ Return every container in a workload including initContainers """
    # i got tired of repeating this loop in every container rule so it lives
    # here as a shared helper next to the Resource class
    containers = []
    for container, container_path in get_containers_with_paths(resource):
        containers.append(container)
    return containers


def step_into(node, key):
    """ one step down a YAML node tree: a key for a mapping and an index for a
    sequence. Returns None when that step does not exist """
    if node is None:
        return None
    if isinstance(key, int):
        if not isinstance(node.value, list):
            return None
        if key < 0 or key >= len(node.value):
            return None
        item = node.value[key]
        # a mapping node keeps (key, value) tuples so indexing one by number
        # would hand back a tuple rather than a node
        if isinstance(item, tuple):
            return None
        return item
    if not isinstance(node.value, list):
        return None
    for pair in node.value:
        if not isinstance(pair, tuple):
            return None
        if pair[0].value == key:
            return pair[1]
    return None


def node_at(resource, path):
    """ the YAML node for a field inside a resource following path

    if part of the path is missing it stops and returns the deepest node it could
    reach: several rules fire because a field is
    absent so the path cannot be walked to the end. K8S-SEC-003 asks
    for the line of runAsUser when nothing set runAsUser. Moving to the
    securityContext block or the container, is where a person would look
    anyway and it beats having no line at all.
    returns None when the resource has no node tree
    """
    if resource.node is None:
        return None
    node = resource.node
    for key in path:
        next_node = step_into(node, key)
        if next_node is None:
            break
        node = next_node
    return node


def line_at(resource, path):
    """ The 1 based line of a field inside a resource following path
    falls back to the objects own line when there is no node tree
    The +1 is because PyYAML counts from zero and editors count from one """
    node = node_at(resource, path)
    if node is None:
        return resource.line
    return node.start_mark.line + 1


def parse_file_with_reasons(path):
    """ parse one YAML file and also say why anything was skipped

    returns the resources plus a list of short reason strings. The reasons
    matter: demo/ was three clean files but a real repository is full of Helm
    templates, values files and CI config and "16 of 28 files parsed" with no
    explanation tells you nothing about its coverage
    """
    # Always read as UTF-8 never the platform default. The default on Windows
    # is cp1252 which cannot decode plenty of valid UTF-8. One Goat file has
    # an emoji in a message, and that single file made the same corpus
    # report 34 objects on Fedora and 33 on Windows. Pinning utf-8 makes
    # every machine agree, anything that still fails to decode is probably
    # not text so skip it and count it
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return [], ["unreadable file"]
    except UnicodeDecodeError:
        return [], ["not UTF-8 text"]

    # Parse twice on purpose, safe_load_all gives plain dicts, which is what
    # the rules want to read but a dict has no idea what line it came from
    # compose_all gives the node tree which has the line numbers but is
    # awkward to read values out of so take both: dicts for the data and nodes
    # for the positions
    try:
        documents = list(yaml.safe_load_all(text))
        nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError:
        # Helm templates are the usual cause: {{ }} is not valid YAML so the
        # whole file fails to load Rendering it would mean running Helm with
        # the charts values
        if "{{" in text:
            return [], ["helm template"]
        return [], ["invalid YAML"]

    resources = []
    reasons = []
    # pair the two parses by position, safe because both calls walk the same
    # text with the same loader so document n from one is document n from the
    # other
    position = -1
    for doc in documents:
        position = position + 1
        node = None
        if position < len(nodes):
            node = nodes[position]
        if doc is None:
            # an empty document e.g. a file that ends in ---
            reasons.append("empty document")
            continue
        # only a dict can be a Kubernetes object, a Helm values file is often
        # a list
        if not isinstance(doc, dict):
            reasons.append("not a mapping (values or CI file)")
            continue
        metadata = doc.get("metadata")
        if not isinstance(metadata, dict):
            # metadata can be missing or a string in a hand written file
            metadata = {}
        kind = doc.get("kind")
        name = metadata.get("name")
        if kind is None or name is None:
            # without both there is nothing to identify the object by, and
            # every rule keys on kind
            reasons.append("no kind or metadata.name")
            continue
        namespace = metadata.get("namespace", "default")
        spec = doc.get("spec")
        # a spec that is not a mapping would break every rules .get() call
        if not isinstance(spec, dict):
            spec = {}
        line = 1
        if node is not None:
            line = node.start_mark.line + 1
        resources.append(Resource(path, kind, name, namespace, spec, doc, line, node))
    return resources, reasons


def parse_file(path):
    """ Parse one YAML file which may hold several documents split by  --- """
    # the plain version: print each skip as a warning and throw the list away.
    # This is why scan prints warning lines while evaluate prints a clean table.
    resources, reasons = parse_file_with_reasons(path)
    for reason in reasons:
        print(f"warning: skipping a document in {path} ({reason})")
    return resources


def parse_dir(path):
    """ walk a directory and parse every .yaml/.yml file found in it """
    resources = []
    # os.walk gives back three things per directory: the path, the
    # subdirectory names and the file names, we only use the first and last
    # sorted() is useful: it keeps the output order the same in every run
    for root, dirs, files in os.walk(path):
        for filename in sorted(files):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                resources.extend(parse_file(os.path.join(root, filename)))
    return resources
