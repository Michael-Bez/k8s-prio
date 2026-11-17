""" Why a divergent finding diverges and what a team should do about it

nothing in here makes the two engines agree more, it explains a disagreement,
it does not remove one, both verdicts stay visible everywhere and the advice
is presented as advice

the guidance policy:
- one band apart: default to the more urgent verdict. Being wrong costs at most
  one band, so that is cheap insurance
- two or more bands apart: flag it for a human. Do not pick a side
- driven by remediation pricing: say so out loud, because that is where the two
  methods are genuinely answering different questions and the teams capacity
  this sprint is what settles it

the 5 causes. The first 4 are differences between the 2 specifications so they exist on any corpus and each 
one is worked out per finding by re scoring with one thing changed

  1 remediation pricing  - the heuristic prices fix cost, SSVC has no
                           remediation dimension at all (test: re-score with
                           the no-remediation weights)
  2 exploitation gating  - SSVC caps the outcome when exploitation=none, CVSS
                           base metrics have no exploitation dimension
                           (test: re-route with exploitation=poc)
  3 impact granularity   - SSVC Technical Impact is binary, the heuristic
                           grades 1-10 (test: flip partial/total)
  4 mission weighting    - SSVC weighs mission centrality, the heuristic only
                           has reachability (test: move mission one step
                           toward what exposure suggests)
  5 band-floor mismatch  - the heuristic never reaches the band SSVC assigned
                           anywhere on this corpus so no single change could
                           close the gap, this one is a property of the corpus,
                           not of the finding: it is the two scales ranges
                           failing to line up

whichever counterfactual closes the most bands wins if none of them closes
anything the floor is checked next. If neither applies the answer is "no
single cause" rather than an invented attribution """

from k8s_prio.comparison import LABELS, steps_apart
from k8s_prio.scoring.heuristic import RULE_FACTORS, band_for
from k8s_prio.scoring.ssvc import CISA_TREE, RULE_SSVC

MISSION_ORDER = ["low", "medium", "high"]


def counterfactual_band(rule_id, weights):
    """ the heuristic band this rule would get under different weights """
    # reuses the same arithmetic and the same band_for as the real scorer so a
    # counterfactual cannot disagree with the engine
    factors = RULE_FACTORS[rule_id]
    total = 0
    for name in weights:
        total = total + weights[name] * factors[name]
    return band_for(round(total, 1))


def counterfactual_outcome(values):
    """ route a set of SSVC decision point values through the published tree """
    branch = CISA_TREE[(values["exploitation"], values["automatable"], values["impact"])]
    return branch[values["mission"]]


def closed(finding, new_band, new_outcome):
    """ how many bands a counterfactual closes between the two verdicts """
    before = steps_apart(finding.band, finding.ssvc_outcome)
    return before - steps_apart(new_band, new_outcome)


def cause_effects(finding, no_remediation_weights):
    """ each applicable cause with its counterfactual effect and sentence """
    rule_id = finding.rule_id
    factors = RULE_FACTORS[rule_id]
    values = RULE_SSVC[rule_id]
    effects = []

    # 1: score again with remediation priced at zero. always tested because
    # every rule has a remediation_ease value
    new_band = counterfactual_band(rule_id, no_remediation_weights)
    effects.append((closed(finding, new_band, finding.ssvc_outcome), "remediation-pricing",
                    f"the heuristic prices the fix (remediation_ease {factors['remediation_ease']}/10); "
                    f"without that factor the band becomes {new_band}; SSVC has no remediation dimension"))

    # 2: SSVC's hard gate on exploitation=none. only applies when the rule
    # actually has that value so there is something to lift
    if values["exploitation"] == "none":
        bumped = dict(values)
        bumped["exploitation"] = "poc"
        new_outcome = counterfactual_outcome(bumped)
        effects.append((closed(finding, finding.band, new_outcome), "exploitation-gating",
                        f"SSVC records exploitation=none for this rule and caps the outcome; "
                        f"with even a public poc the tree would say {new_outcome}; CVSS base "
                        f"metrics have no exploitation dimension"))

    # 3: binary Technical Impact vs a graded heuristic impact, only tested in
    # the 5-7 middle band which is where forcing a yes/no choice throws away
    # the most information
    if 5 <= factors["impact"] <= 7:
        flipped = dict(values)
        if values["impact"] == "partial":
            flipped["impact"] = "total"
        else:
            flipped["impact"] = "partial"
        new_outcome = counterfactual_outcome(flipped)
        effects.append((closed(finding, finding.band, new_outcome), "impact-granularity",
                        f"the heuristic grades impact {factors['impact']}/10 but SSVC forces "
                        f"binary '{values['impact']}'; with the other value the tree would say "
                        f"{new_outcome}"))

    # 4: mission centrality vs reachability pointing opposite ways only tested
    # when exposure is high but mission is not or the reverse
    position = MISSION_ORDER.index(values["mission"])
    if factors["exposure"] >= 7 and values["mission"] != "high":
        moved = dict(values)
        moved["mission"] = MISSION_ORDER[position + 1]
    elif factors["exposure"] <= 4 and values["mission"] != "low":
        moved = dict(values)
        moved["mission"] = MISSION_ORDER[position - 1]
    else:
        moved = None
    if moved is not None:
        new_outcome = counterfactual_outcome(moved)
        effects.append((closed(finding, finding.band, new_outcome), "mission-weighting",
                        f"SSVC weighs mission={values['mission']} while the heuristic's exposure "
                        f"is {factors['exposure']}/10; mission at {moved['mission']} would give "
                        f"{new_outcome}"))
    return effects


def heuristic_floor(findings):
    """ The lowest heuristic score anywhere in this scan, the band that score
    falls in is the least urgent band the heuristic actually produced which
    is what makes a band-floor mismatch visible  """
    lowest = None
    for finding in findings:
        if lowest is None or finding.score < lowest:
            lowest = finding.score
    return lowest


def band_floor_sentence(finding, floor):
    """ The band floor explanation or None when the floor does not explain it
    Applies when SSVCs verdict is less urgent than every band the heuristic
    reached: labels runs most urgent first so a larger index is less urgent """
    if floor is None:
        return None
    floor_band = band_for(floor)
    if LABELS.index(finding.ssvc_outcome) <= LABELS.index(floor_band):
        return None
    return (f"the heuristic never reaches {finding.ssvc_outcome} anywhere on this corpus: "
            f"its lowest score is {floor:.2f}, which is still band {floor_band}, so no "
            f"single-factor change could match SSVC's {finding.ssvc_outcome} here. This is "
            f"a mismatch between the two scales' ranges, not a disagreement about this "
            f"finding")


def explain_divergence(finding, no_remediation_weights, floor=None):
    """ the dominant structural cause for one divergent finding
    returns a dict with cause, sentence, tied causes and lesser contributors """
    effects = cause_effects(finding, no_remediation_weights)
    best = None
    for effect in effects:
        # > 0 matters: a counterfactual that closes nothing or widens the gap
        # is not a candidate
        if effect[0] > 0 and (best is None or effect[0] > best[0]):
            best = effect
    if best is None:
        # nothing closes any part of the gap before giving up, check whether
        # the heuristics own range explains it: if SSVCs verdict sits below
        # every band the heuristic produced on this corpus the gap is a
        # calibration mismatch and no per finding counterfactual could close it
        # checked last on purpose, the first four are claims about this finding
        # the floor is a claim about the corpus and checking it first would
        # swallow findings a real single factor change could have explained
        floor_sentence = band_floor_sentence(finding, floor)
        if floor_sentence is not None:
            return {"cause": "band-floor-mismatch", "sentence": floor_sentence,
                    "tied": [], "others": []}
        # name what was tested rather than calling them "contributing"
        # because a cause that closes nothing is not contributing here
        tested = []
        for effect in effects:
            tested.append(effect[1])
        return {"cause": "no-single-cause",
                "sentence": "no single counterfactual closes the gap, so no cause dominates "
                            "(tested: " + ", ".join(tested) + ")",
                "tied": [], "others": []}
    # split the rest into real ties (closed exactly as many bands) and
    # lesser contributors (closed some but fewer)
    tied = []
    others = []
    for effect in effects:
        if effect[1] == best[1] or effect[0] <= 0:
            continue
        if effect[0] == best[0]:
            tied.append(effect[1])
        else:
            others.append(effect[1])
    sentence = best[2]
    if tied != []:
        sentence = sentence + f" (equally attributable to: {', '.join(tied)})"
    if others != []:
        sentence = sentence + f" (also contributing: {', '.join(others)})"
    return {"cause": best[1], "sentence": sentence, "tied": tied, "others": others}


def guidance_for(finding, explained):
    """ the line for one divergent finding, per the policy above
    takes the whole explanation not just the cause name so a tied
    attribution is not written up as if one cause were established """
    cause = explained["cause"]
    steps = steps_apart(finding.band, finding.ssvc_outcome)
    # the two band check comes first because it overrides everything else
    if steps >= 2:
        return (f"flag for human decision: the verdicts are {steps} bands apart "
                f"({finding.band} vs {finding.ssvc_outcome}); do not pick a side automatically")
    heuristic_higher = LABELS.index(finding.band) < LABELS.index(finding.ssvc_outcome)
    if cause == "remediation-pricing":
        if heuristic_higher:
            # "only because" would overstate it when another cause explains the gap just as well
            if explained["tied"] != []:
                return ("fix cost is one of two equally good explanations for the higher "
                        "heuristic rank: if there is capacity this sprint, do it; otherwise "
                        "SSVC's lower ranking is reasonable")
            return ("the heuristic ranks this higher only because it is cheap to fix: "
                    "if there is capacity this sprint, do it; otherwise SSVC's lower "
                    "ranking is reasonable")
        return ("SSVC ranks this higher; the heuristic sits lower partly because the fix "
                "is priced as costly - treat the SSVC verdict as the working answer and "
                "plan the larger fix")
    if heuristic_higher:
        higher = finding.band
    else:
        higher = finding.ssvc_outcome
    if cause == "band-floor-mismatch":
        return (f"one band apart: treat the higher verdict ({higher}) as the working answer. "
                f"Note this gap is a scale calibration artefact, not a judgement about this "
                f"finding, so it will look the same for every finding at the bottom of the "
                f"heuristic's range")
    return (f"one band apart: treat the higher verdict ({higher}) as the working answer; "
            f"the cost of being wrong is bounded at one band")
