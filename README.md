# k8s-prio

k8s-prio is a command line tool that scans Kubernetes YAML manifests for
security misconfigurations and then prioritises every finding in two
different ways. The first is a weighted score built from CVSS v3.1 base
metrics. The second is the CISA Coordinator SSVC decision tree. The tool then
measures how much the two methods agree and explains each finding where they
disagree.

This was my Honours project in Computer Science (Cyber Security
specialisation). The detection side is kept small on purpose. The main
contribution is the comparison between the two prioritisation methods.

## Abstract

Security scanners for Kubernetes are good at finding problems but a real
repository can produce dozens or hundreds of findings, so the question
becomes which ones to fix first. There are two well known ways to answer
that. One is a CVSS style score that weighs how exploitable, damaging and
exposed something is. The other is SSVC, a decision tree used by CISA that
asks whether something is being exploited, whether it can be automated, how
much control it gives and how important the affected system is.

The research question was:

> When two independently grounded prioritisation methods are applied to the
> same set of Kubernetes misconfiguration findings, how far do they agree,
> and what explains the divergence?

It asks about agreement and not correctness, because there is no ground
truth for the "right" order to fix misconfigurations in.

To answer it, the tool detects findings with twelve rules, scores each one
with both methods on the same four point scale (Act, Attend, Track*, Track),
measures agreement with Cohen's kappa and explains every disagreement by
re-scoring the finding with one input changed at a time to see which change
closes the gap.

On the OWASP Kubernetes Goat corpus (82 findings) the two methods agreed only
slightly: Cohen's kappa was 0.112 and the linear weighted kappa was 0.367. 59
of the 82 findings were scored differently. The biggest single cause was
remediation pricing, the heuristic gives credit for an easy fix and SSVC has
no idea of fix cost at all. Setting the remediation weight to zero raised
kappa to 0.603. On two hardened production style corpora the heuristic only
ever used one band, which makes kappa 0.000 no matter what SSVC says. So kappa
stops being useful exactly where real manifests are cleanest, while the
breakdown of divergence causes still gives a usable answer.

## What it does

- reads every `.yaml` and `.yml` file in a folder (recursively)
- runs twelve rules taken from the CIS Kubernetes Benchmark v1.8 and the OWASP
  Kubernetes Top 10 (2022)
- scores every finding with the heuristic and routes it through the SSVC tree
- prints both verdicts side by side, sorted by the heuristic score
- explains why the two verdicts differ and gives advice on what to do
- can fail a CI build when a finding reaches a chosen band
- can run a full evaluation over a folder of manifests and write the results
  to text and CSV files

It is static analysis only. It reads files, never connects to a cluster,
needs no credentials and makes no network calls.

## Install

You need Python 3.10 or newer. The only dependency is PyYAML.

On Linux or macOS:

```
git clone https://github.com/Michael-Bez/k8s-prio.git
cd k8s-prio
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

On Windows (PowerShell):

```
git clone https://github.com/Michael-Bez/k8s-prio.git
cd k8s-prio
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install .
```

If PowerShell refuses to run `Activate.ps1`, you can skip activating and call
the tool directly with `.venv\Scripts\k8s-prio.exe` instead.

For development (to run the tests as well):

```
pip install -e . pytest
```

## Usage

There are three commands:

```
k8s-prio scan ./manifests/              one line per finding, worst first
k8s-prio scan --report ./manifests/     adds the fix, the source, the score
                                        factors and the SSVC path
k8s-prio compare ./manifests/           agreement matrix and Cohen's kappa
k8s-prio evaluate ./corpus/some-repo/   full evaluation written to results/
```

### Example

The repository has some deliberately bad manifests in `demo/`. Scanning the
pull request example gives this:

```
$ k8s-prio scan demo/pr-examples/
 8.6  Act     Act     K8S-SEC-001  privileged container: Pod shop/debug-pod  [demo/pr-examples/debug-pod.yaml:22]
 7.9  Attend  Act     K8S-SEC-006  hostPath volume: Pod shop/debug-pod  [demo/pr-examples/debug-pod.yaml:31]
 7.4  Attend  Attend  K8S-SEC-004  host PID/IPC namespace shared: Pod shop/debug-pod  [demo/pr-examples/debug-pod.yaml:17]
 7.2  Attend  Attend  K8S-NET-001  hostNetwork enabled: Pod shop/debug-pod  [demo/pr-examples/debug-pod.yaml:16]
 7.0  Attend  Attend  K8S-SEC-003  container runs as root: Pod shop/debug-pod  [demo/pr-examples/debug-pod.yaml:24]
 6.4  Attend  Track   K8S-SEC-002  privilege escalation allowed: Pod shop/debug-pod  [demo/pr-examples/debug-pod.yaml:23]
 5.8  Track*  Track   K8S-WKL-002  no resource limits: Pod shop/debug-pod  [demo/pr-examples/debug-pod.yaml:19]
 5.8  Track*  Track   K8S-NET-002  namespace without NetworkPolicy: Pod shop/debug-pod  [demo/pr-examples/debug-pod.yaml:10]
 5.3  Track*  Track   K8S-WKL-001  unpinned image tag: Pod shop/debug-pod  [demo/pr-examples/debug-pod.yaml:20]
9 findings across 1 resources
```

Each line reads: heuristic score, heuristic band, SSVC outcome, rule, what was
found and where (file and line).

With `--report`, a finding where the two methods disagree gets three extra
lines, for example:

```
    diverge: heuristic Attend vs ssvc Track (2 bands, heuristic higher)
    because: the heuristic grades impact 7/10 but SSVC forces binary 'partial'; with the other value the tree would say Track*
    advice:  flag for human decision: the verdicts are 2 bands apart (Attend vs Track); do not pick a side automatically
```

### Scan options

| option | what it does |
|---|---|
| `--report` | print the details for each finding |
| `--format text` | the default, for reading in a terminal |
| `--format github` | GitHub workflow annotations, so findings show up on the lines of a pull request |
| `--output FILE` | write the GitHub annotations to a file instead of stdout |
| `--fail-on BAND` | only fail when a finding reaches `Act`, `Attend`, `Track*` or `Track` |
| `--fail-on-divergence N` | fail when a finding's two verdicts are N or more bands apart |
| `--config FILE` | use your own heuristic weights from a YAML file |

`--fail-on` counts a finding if **either** method puts it at or above the
band, so a serious finding cannot slip through just because one method
ranked it lower. The annotation level in GitHub uses the same rule, so a
finding that fails the build is never shown as a mild notice.

### Custom weights

A weights file is plain YAML. Any key you leave out keeps its default value.
The four weights must not be negative and must add up to 1.0, otherwise the
tool stops with exit code 2.

```yaml
exploitability: 0.40
impact: 0.30
exposure: 0.20
remediation_ease: 0.10
```

### Exit codes

| code | meaning |
|---|---|
| 0 | the scan ran and nothing failed |
| 1 | the scan ran and found something (or something reached your `--fail-on` threshold) |
| 2 | the scanner itself could not run, for example a missing folder or a bad weights file |

Without `--fail-on` any finding at all gives exit code 1. A short reason for
the exit code is printed to stderr, so it never mixes into the annotation
output on stdout. A scanner that could not run must never look like a clean
scan, which is why that case has its own code.

## The twelve rules

| ID | checks for | source |
|---|---|---|
| K8S-NET-001 | `hostNetwork: true` on a workload | CIS 5.2.5, OWASP K01 |
| K8S-NET-002 | a namespace with workloads but no NetworkPolicy | CIS 5.3.2, OWASP K07 |
| K8S-SEC-001 | `privileged: true` on any container, init containers included | CIS 5.2.2, OWASP K01 |
| K8S-SEC-002 | `allowPrivilegeEscalation: true` | CIS 5.2.6, OWASP K01 |
| K8S-SEC-003 | a container that runs as root, or has nothing stopping it | CIS 5.2.7, OWASP K01 |
| K8S-SEC-004 | `hostPID: true` or `hostIPC: true` | CIS 5.2.3 / 5.2.4, OWASP K01 |
| K8S-SEC-005 | adds SYS_ADMIN, NET_ADMIN, SYS_PTRACE or ALL capabilities | CIS 5.2.9, OWASP K01 |
| K8S-SEC-006 | a `hostPath` volume (one finding per volume) | CIS 5.2.12, OWASP K01 |
| K8S-WKL-001 | an image tagged `:latest` or with no tag | OWASP K02 |
| K8S-WKL-002 | a container without a cpu or memory limit | OWASP K01 |
| K8S-RBC-001 | `*` in the verbs or resources of a Role or ClusterRole | CIS 5.1.3, OWASP K03 |
| K8S-RBC-002 | a binding to the `cluster-admin` role | CIS 5.1.1, OWASP K03 |

CIS means the CIS Kubernetes Benchmark v1.8. OWASP means the OWASP Kubernetes
Top 10, **2022 edition** (the list has been renumbered since, so the edition
matters).

The workload kinds that get inspected are Pod, Deployment, StatefulSet,
DaemonSet, Job, CronJob and ReplicaSet.

K8S-NET-002 is why the clean example in `demo-manifests/webapp.yaml` needs a
Namespace and a NetworkPolicy as well as a hardened Deployment. Hardening the
pod alone is not enough if its namespace is not segmented.

## How the scoring works

Both methods score per rule, not per finding. Every hostPath finding gets the
same score whether it mounts `/` or a log folder, because there was no
sourced basis for ranking one above another and I did not want to make one
up.

### The heuristic

Each rule has four factors from 1 to 10:

- **exploitability** - from the CVSS Attack Vector, Attack Complexity and
  Privileges Required
- **impact** - from the CVSS confidentiality, integrity and availability
  values, raised when the scope changes (a container escaping to the node)
- **exposure** - how reachable it is and how far the damage travels
- **remediation ease** - how easy it is to fix, where 10 means trivial

Seven rules are anchored to a real CVE and its published CVSS vector. The
other five have no clean CVE, so the same rubric is applied to their CWE
class instead. The CVE or CWE for each rule is written in the comments of
`k8s_prio/scoring/heuristic.py`.

The score is a weighted average:

```
score = 0.30 x exploitability + 0.35 x impact + 0.25 x exposure + 0.10 x remediation_ease
```

The weights add up to 1.0, so the score always lands between 1.0 and 10.0
without any clamping. The score is then put into a band: 8.0 and above is
Act, 6.0 and above is Attend, 4.0 and above is Track*, and anything lower is
Track. The bands use the same four words as SSVC on purpose, because Cohen's
kappa needs both raters to pick from the same set of labels.

Remediation ease runs "backwards": an easy fix **raises** the score. That is
because the output is meant to be a work queue and not a severity rating. Two
equally dangerous problems are not equally urgent if one is a one line change
and the other is a storage redesign.

### SSVC

SSVC does not give a score. It asks four questions and reads the answer off
a tree:

- **exploitation** - none, public proof of concept, or active in the wild
- **automatable** - can the attack be scripted, yes or no
- **technical impact** - partial or total control
- **mission and well-being** - low, medium or high

The tree is the published CISA Coordinator tree (all 36 rows), written as a
lookup table in `k8s_prio/scoring/ssvc.py` so it can be checked row by row
against the CERT/CC data file. The mission value is the one local assumption:
a manifest scanner cannot know what an organisation cares about, so it is set
per rule from how central the affected resource is (node or control plane is
high, one workload is medium, hygiene is low).

### What each rule ends up as

| rule | heuristic score | heuristic band | SSVC outcome |
|---|---|---|---|
| K8S-SEC-001 | 8.6 | Act | Act |
| K8S-SEC-006 | 7.9 | Attend | Act |
| K8S-SEC-005 | 7.6 | Attend | Attend |
| K8S-RBC-002 | 7.5 | Attend | Attend |
| K8S-SEC-004 | 7.4 | Attend | Attend |
| K8S-NET-001 | 7.2 | Attend | Attend |
| K8S-SEC-003 | 7.0 | Attend | Attend |
| K8S-SEC-002 | 6.4 | Attend | Track |
| K8S-RBC-001 | 6.0 | Attend | Track* |
| K8S-WKL-002 | 5.8 | Track* | Track |
| K8S-NET-002 | 5.8 | Track* | Track |
| K8S-WKL-001 | 5.3 | Track* | Track |

### Why the two methods disagree

When the verdicts differ, the tool tries changing one input at a time and
re-scoring with the real engine. Whichever change closes the most bands is
reported as the cause. There are five possible causes:

1. **remediation pricing** - the heuristic prices the fix, SSVC has no fix
   cost at all
2. **exploitation gating** - SSVC holds the outcome down when exploitation is
   "none"
3. **impact granularity** - SSVC impact is only partial or total, the
   heuristic grades it from 1 to 10
4. **mission weighting** - SSVC weighs how important the system is, the
   heuristic only has exposure
5. **band-floor mismatch** - on a given set of manifests the heuristic may
   never reach its lowest band at all, so an SSVC "Track" can never be
   matched. This one is only checked after the other four fail

If nothing closes the gap the tool says "no single cause" instead of making
one up.

The advice follows a simple policy:

- one band apart: treat the more urgent verdict as the working answer
- two or more bands apart: a person should decide, the tool will not pick a
  side
- caused by fix cost: say so, because then it comes down to how much time
  the team has

A disagreement is information, not a bug. Both verdicts always stay visible
and the tool never overwrites one with the other.

### Statistics

All the statistics are written by hand with the Python standard library, so
every number can be followed in the source. `k8s_prio/comparison.py` has:

- Cohen's kappa and a linear weighted kappa (a three band gap counts as worse
  than a one band gap)
- bootstrap confidence intervals (2000 resamples, fixed seed 20260802), both
  per finding and per rule. The per rule one is the honest one, because all
  the findings from one rule get the same score and are not independent
- a paired bootstrap for comparing two weight profiles on the same findings

## Using it in CI

`.github/workflows/k8s-prio-scan.yml` installs the tool on a fresh runner and
scans `demo-manifests/` on every pull request:

```yaml
- run: pip install .
- run: k8s-prio scan ./demo-manifests/ --format github --fail-on Act
```

The annotations are plain lines in the job log, so there is no upload step
and no extra permission needed, and it works on a private repository.

To see it working, copy `demo/pr-examples/debug-pod.yaml` into
`demo-manifests/` on a new branch and open a pull request. The check fails on
two findings: the privileged container (Act on both methods) and the hostPath
volume. The hostPath one is Attend for the heuristic but Act for SSVC, so it
only blocks the merge because either method can trip the gate.

A second workflow, `.github/workflows/k8s-prio-tests.yml`, runs the tests on
Python 3.10 and 3.14.

## Running the evaluation

`evaluate` is what produced the research results. It profiles a folder (files
seen, parsed and skipped, with the reason for each skip), runs both methods,
and writes a report and CSV files.

```
k8s-prio evaluate ./corpus/kubernetes-goat-2.3.0 --sensitivity --results results
```

| option | what it does |
|---|---|
| `--sensitivity` | repeat the analysis under five different weight profiles |
| `--results DIR` | where to write the files (default `results`) |
| `--timing-runs N` | repeat the scan N times and report the median time (first run is thrown away as warm-up) |

It writes `evaluation_report.txt`, `agreement_matrix.csv`,
`per_rule_divergence.csv`, `divergence_causes.csv` and, with
`--sensitivity`, `sensitivity.csv`.

The corpora themselves are not in this repository. These are the three that
were used, pinned to an exact release:

| corpus | release | commit |
|---|---|---|
| [OWASP Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) | v2.3.0 | aa72b617 |
| [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus) | v0.18.0 | 4775d44d |
| [Online Boutique (microservices-demo)](https://github.com/GoogleCloudPlatform/microservices-demo) | v0.10.6 | 5b3a712a |

If a `corpus_manifest.txt` file sits next to the corpus folder, the report
picks up the corpus name, url, tag and commit from it. Otherwise the corpus is
reported as "unrecorded corpus".

The `results/` folder holds the Kubernetes Goat evaluation and a written
summary comparing all three corpora (`divergence_new_corpora.txt`).
`results_baseline/` holds a copy of the Goat CSV files to compare later runs
against.

## Project layout

```
k8s_prio/
    cli.py               commands, text output and the CI gates
    parser.py            reads YAML into Resource objects and finds line numbers
    findings.py          the Finding class
    engine.py            runs every rule over every resource
    scanner.py           parse, detect, score both ways, sort
    rules/               the twelve rules (network, security_context, workload, rbac)
    scoring/heuristic.py the four factors, the weights and the bands
    scoring/ssvc.py      the CISA Coordinator tree and the per rule values
    comparison.py        agreement matrix, kappa and the bootstraps
    divergence.py        the five causes and the advice
    evaluate.py          the corpus evaluation and weight profiles
    report.py            the evaluation report and CSV files
    corpus.py            walks a corpus and counts what was skipped
    formats.py           GitHub annotation output
tests/                   pytest tests and the fixture manifests they use
demo/                    deliberately bad manifests, plus the pull request example
demo-manifests/          a clean manifest that the CI workflow scans
results/                 the evaluation output
```

The code only uses the standard library and PyYAML, and it is written with
plain functions and two simple classes (`Resource` and `Finding`) so that it
is easy to read and check.

## Tests

```
pytest -q
```

There are 69 tests covering the parser, the rules, the engine, both scorers
and the comparison layer. Every rule has at least one test where it fires and
one where it does not.

## Limitations

- **Static analysis only.** It cannot see admission controllers, Pod Security
  Standards, policy engines or anything the cluster does at runtime, so a
  finding may already be blocked in practice.
- **No Helm rendering.** Templates with `{{ }}` are not valid YAML, so they
  are skipped and counted. Run `helm template` first if you need them
  scanned.
- **Twelve rules.** Coverage is narrow on purpose. This is not a replacement
  for a full policy engine.
- **Per rule scoring.** Findings from the same rule always get the same
  score, so they are not independent observations.
- **Authored values.** The rubric that turns CVSS metrics into 1 to 10
  factors, and the SSVC mission values, are my own choices. They are written
  down and sourced but they are still assumptions.
- **Round number bands.** The band thresholds (8, 6, 4) were not calibrated.
- **Small corpora.** Three corpora and 103 findings in total, so the results
  should be read as a careful first look and not a final answer.

## References

- CIS Kubernetes Benchmark v1.8
- OWASP Kubernetes Top 10 (2022)
- FIRST, Common Vulnerability Scoring System v3.1 Specification
- CISA, Stakeholder-Specific Vulnerability Categorization (SSVC) Guide
- Spring et al. (2021), Prioritizing Vulnerability Response: A
  Stakeholder-Specific Vulnerability Categorization, SEI / Carnegie Mellon
  University
- Cohen (1960) and Cohen (1968) for kappa and weighted kappa
- Landis and Koch (1977) for the kappa agreement words
