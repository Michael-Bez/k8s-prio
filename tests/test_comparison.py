""" Tests for the comparison layer (matrix, Cohen's kappa, divergent list) """

from k8s_prio.comparison import cohens_kappa, compare_findings, kappa_word
from k8s_prio.findings import Finding


def scored_finding(band, outcome):
    """ a minimal Finding carrying just the two labels the comparison reads """
    finding = Finding("K8S-TST-000", "test", None, "test", "test", {})
    finding.band = band
    finding.ssvc_outcome = outcome
    return finding


def test_kappa_worked_by_hand():
    # Worked on paper first:
    #   a = [Act, Act,   Track, Track]
    #   b = [Act, Track, Track, Track]
    #  observed agreement: 3 of 4 match            -> po = 0.75
    #  marginals: a has Act 2/4, Track 2/4; b has Act 1/4, Track 3/4
    #  chance agreement: 0.5*0.25 + 0.5*0.75       -> pe = 0.5
    #  kappa = (0.75 - 0.5) / (1 - 0.5)            -> 0.5

    a = ["Act", "Act", "Track", "Track"]
    b = ["Act", "Track", "Track", "Track"]
    assert cohens_kappa(a, b) == 0.5


def test_kappa_none_with_fewer_than_two_findings():
    assert cohens_kappa(["Act"], ["Act"]) is None


def test_kappa_none_when_chance_agreement_is_total():
    # both raters always say Act: nothing to correct for so avoid dividing by zero
    
    a = ["Act", "Act", "Act"]
    b = ["Act", "Act", "Act"]
    assert cohens_kappa(a, b) is None


def test_kappa_words():
    assert kappa_word(None) == "not enough data"
    assert kappa_word(-0.1) == "poor"
    assert kappa_word(0.1) == "slight"
    assert kappa_word(0.3) == "fair"
    assert kappa_word(0.5) == "moderate"
    assert kappa_word(0.7) == "substantial"
    assert kappa_word(0.9) == "almost perfect"


def test_matrix_counts_and_n():
    findings = [scored_finding("Act", "Act"),
                scored_finding("Act", "Attend"),
                scored_finding("Attend", "Attend"),
                scored_finding("Attend", "Attend")]
    result = compare_findings(findings)
    assert result["n"] == 4
    assert result["matrix"]["Act"]["Act"] == 1
    assert result["matrix"]["Act"]["Attend"] == 1
    assert result["matrix"]["Attend"]["Attend"] == 2
    assert result["matrix"]["Track"]["Track"] == 0


def test_divergent_list_holds_the_disagreements():
    agreeing = scored_finding("Act", "Act")
    disagreeing = scored_finding("Attend", "Track*")
    result = compare_findings([agreeing, disagreeing])
    assert result["divergent"] == [disagreeing]


def test_compare_with_no_findings():
    result = compare_findings([])
    assert result["n"] == 0
    assert result["kappa"] is None
    assert result["divergent"] == []
