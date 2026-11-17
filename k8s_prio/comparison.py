""" Compares the two scoring methods: agreement matrix, Cohens kappa
and the findings where they disagree

everything in here is written by hand with the standard library. No numpy, no
scipy, no scikit-learn, the point is that any number this project reports can
be followed in the source and redone on paper and kappa is about twelve lines
so pulling in two large dependencies for one formula is not worth it """

import random

# the four labels both methods share most urgent first. A lot of code relies
# on that order, so "lower index means more urgent" shows up all over
LABELS = ["Act", "Attend", "Track*", "Track"]


def cohens_kappa(labels_a, labels_b):
    """Cohen's kappa: agreement between two raters corrected
    for the agreement you would get by chance alone
    kappa = (observed agreement - chance agreement) / (1 - chance agreement)
    Returns None when there is not enough data to say anything """
    # two raters who both call everything "Attend"
    # agree 100% of the time while telling you nothing and kappa reports that
    # as zero rather than as perfect
    observed, chance = agreement_parts(labels_a, labels_b)
    if observed is None:
        return None
    # if both raters always give one same label, chance agreement is 1.0 and
    # the formula would divide by zero : there is nothing to correct for
    if chance == 1.0:
        return None
    return (observed - chance) / (1 - chance)


def agreement_parts(labels_a, labels_b):
    """ Return observed and expected agreement separately so the kappa
    arithmetic can be checked by hand in the report """
    n = len(labels_a)
    if n < 2:
        return None, None
    # observed agreement: how often the two lists simply match
    agree = 0
    for i in range(n):
        if labels_a[i] == labels_b[i]:
            agree = agree + 1
    observed = agree / n
    # expected agreement: for each label, the chance both raters would pick it
    # if they only kept their overall label frequencies
    expected = 0
    for label in LABELS:
        expected = expected + (labels_a.count(label) / n) * (labels_b.count(label) / n)
    return observed, expected


def steps_apart(label_a, label_b):
    """ how many bands apart two labels are, using the labels order
    Act to Track is three steps, Act to Attend is one """
    return abs(LABELS.index(label_a) - LABELS.index(label_b))


def weighted_kappa(labels_a, labels_b):
    """ Linearly weighted kappa, plain kappa treats every
    disagreement as equally bad but our four outcomes are ordered so
    Act against Track should cost more than Act against Attend. Linear
    weights make the cost proportional to how many bands apart the two
    labels are divided by the widest possible gap (three) """
    # Linear because the four bands are an ordinal scale
    # with no claim to equal intervals, saying a two band gap is twice as bad
    # as a one band gap is the weakest assumption that still respects the
    # order
    n = len(labels_a)
    if n < 2:
        return None
    widest = len(LABELS) - 1
    # observed disagreement: average cost of the pairs we actually saw
    observed_cost = 0
    for i in range(n):
        observed_cost = observed_cost + steps_apart(labels_a[i], labels_b[i]) / widest
    observed_cost = observed_cost / n
    # expected disagreement: the same average if both raters kept their own
    # label frequencies but paired them up by chance
    expected_cost = 0
    for label_a in LABELS:
        for label_b in LABELS:
            chance = (labels_a.count(label_a) / n) * (labels_b.count(label_b) / n)
            expected_cost = expected_cost + chance * steps_apart(label_a, label_b) / widest
    if expected_cost == 0:
        return None
    return 1 - (observed_cost / expected_cost)


def bootstrap_interval(labels_a, labels_b, rounds, seed):
    """ a 95% confidence interval for kappa by bootstrap resampling
    resample the finding pairs with replacement, recompute kappa each time,
    then take the 2.5th and 97.5th percentiles of the sorted results
    The seed is fixed so the run can be reproduced exactly """
    # The idea behind a bootstrap: pretend the sample is the population, draw a
    # new sample of the same size from it with replacement and see how much the
    # statistic moves, do that a few thousand times and the spread tells you
    # how much it would move if you had collected different data
    n = len(labels_a)
    if n < 2:
        return None, None
    generator = random.Random(seed)
    kappas = []
    for i in range(rounds):
        sample_a = []
        sample_b = []
        for j in range(n):
            # one pick used for both lists so the pairs stay together
            # Resampling the two sides independently would destroy the thing
            # being measured
            pick = generator.randrange(n)
            sample_a.append(labels_a[pick])
            sample_b.append(labels_b[pick])
        value = cohens_kappa(sample_a, sample_b)
        #  a resample can land on one label only which gives no kappa so skip it
        if value is not None:
            kappas.append(value)
    if len(kappas) < 2:
        return None, None
    kappas = sorted(kappas)
    low = kappas[int(0.025 * len(kappas))]
    high = kappas[int(0.975 * len(kappas))]
    return low, high


def bootstrap_interval_by_group(groups, rounds, seed):
    """ a 95% confidence interval for kappa that resamples groups of findings
    rather than single findings. Both engines score on the rule id alone so
    every finding from one rule carries the identical label pair - they are
    copies not independent observations. Resampling single findings treats
    the copies as independent and gives an interval narrower than the data
    justifies. Here one draw picks a whole rule and brings ALL of that rules
    findings along so the resamples vary the way the rules themselves vary.
    groups is a list with one entry per rule that fired, each entry is that
    rules list of (heuristic_band, ssvc_outcome) pairs """

    # This is the defensible one. On the Goat corpus 33 of the 82 findings come
    # from one rule so the finding-level interval is built on 33 copies of a
    # single observation, the two intervals differ by a lot: 0.057-0.175
    # finding level against 0.000-0.516 here
    if len(groups) < 2:
        return None, None, 0
    generator = random.Random(seed)
    kappas = []
    discarded = 0
    for i in range(rounds):
        sample_a = []
        sample_b = []
        for j in range(len(groups)):
            pick = generator.randrange(len(groups))
            for pair in groups[pick]:
                sample_a.append(pair[0])
                sample_b.append(pair[1])
        value = cohens_kappa(sample_a, sample_b)
        # count the undefined draws instead of scoring them zero which would
        # drag the interval down for a reason that is not in the data
        if value is None:
            discarded = discarded + 1
        else:
            kappas.append(value)
    if len(kappas) < 2:
        return None, None, discarded
    kappas = sorted(kappas)
    low = kappas[int(0.025 * len(kappas))]
    high = kappas[int(0.975 * len(kappas))]
    return low, high, discarded


def bootstrap_paired_difference(groups_first, groups_second, rounds, seed):
    """ paired bootstrap on the difference in kappa between two scorings of
    the same findings (e.g. default weights vs no-remediation weights) """
    # Why pairing matters: it is like measuring the same patients before and
    # after not two different groups. most of the spread in each separate
    # interval is "which findings does this corpus contain" and that is
    # identical on both sides so it cancels in the difference and does not
    # cancel between two independent intervals
    if len(groups_first) < 2 or len(groups_first) != len(groups_second):
        return None
    generator = random.Random(seed)
    count = len(groups_first)
    differences = []
    discarded = 0
    for i in range(rounds):
        first_a = []
        first_b = []
        second_a = []
        second_b = []
        for j in range(count):
            # one draw applied to both scorings
            pick = generator.randrange(count)
            for pair in groups_first[pick]:
                first_a.append(pair[0])
                first_b.append(pair[1])
            for pair in groups_second[pick]:
                second_a.append(pair[0])
                second_b.append(pair[1])
        kappa_first = cohens_kappa(first_a, first_b)
        kappa_second = cohens_kappa(second_a, second_b)
        # a difference needs both halves so either one being undefined stops
        # the whole draw
        if kappa_first is None or kappa_second is None:
            discarded = discarded + 1
        else:
            differences.append(kappa_second - kappa_first)
    if len(differences) < 2:
        return None
    differences.sort()
    middle = len(differences) // 2
    if len(differences) % 2 == 1:
        median = differences[middle]
    else:
        median = (differences[middle - 1] + differences[middle]) / 2
    # no_improvement is reported alongside the interval because it is the
    # easier number to read: "how often did removing remediation NOT help"
    no_improvement = 0
    for value in differences:
        if value <= 0:
            no_improvement = no_improvement + 1
    return {"low": differences[int(0.025 * len(differences))],
            "high": differences[int(0.975 * len(differences))],
            "median": median,
            "no_improvement": no_improvement,
            "usable": len(differences),
            "discarded": discarded}


def kappa_word(kappa):
    """ the Landis and Koch interpretation bands for a kappa value """
    if kappa is None:
        return "not enough data"
    if kappa < 0:
        return "poor"
    elif kappa <= 0.20:
        return "slight"
    elif kappa <= 0.40:
        return "fair"
    elif kappa <= 0.60:
        return "moderate"
    elif kappa <= 0.80:
        return "substantial"
    else:
        return "almost perfect"


def compare_findings(findings):
    """ compare heuristic bands with SSVC outcomes for scored findings
    returns a plain dict: matrix, kappa, divergent, n """
    heuristic_labels = []
    ssvc_labels = []
    for finding in findings:
        heuristic_labels.append(finding.band)
        ssvc_labels.append(finding.ssvc_outcome)

    # matrix[heuristic band][ssvc outcome] = count
    # every cell starts at zero so a band that never occurs still shows as a
    # row of zeros, an empty row is information: on the Goat corpus the
    # heuristic never uses Track at all and that empty row is the band-floor
    # mismatch seen from a different angle
    matrix = {}
    for band in LABELS:
        matrix[band] = {}
        for outcome in LABELS:
            matrix[band][outcome] = 0
    for finding in findings:
        matrix[finding.band][finding.ssvc_outcome] = matrix[finding.band][finding.ssvc_outcome] + 1

    divergent = []
    for finding in findings:
        if finding.band != finding.ssvc_outcome:
            divergent.append(finding)

    return {"matrix": matrix,
            "kappa": cohens_kappa(heuristic_labels, ssvc_labels),
            "divergent": divergent,
            "n": len(findings)}
