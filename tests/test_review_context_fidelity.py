"""Story context instructions reach native review without changing its protocol.

Scripted replies test instruction delivery and transitions, not semantic accuracy.
"""
import copy

import pytest

from helpers import verdict
from onionflash import review
from test_review import candidate
from test_source_quote_repair import QUOTE, context, native, payload, quote_enum, source


def prompt(request):
    return " ".join(request["messages"][0]["content"].split())


def test_consequence_audit_reaches_quote_choice_and_fresh_native_verification(context, native):
    cfg, _ = context
    public, evidence = candidate(), source()
    original = copy.deepcopy((public, evidence))
    checker = native(cfg, verdict("revise", criterion="source_support", repair={"why_it_matters": QUOTE}),
                     verdict("hold", criterion="source_support"))
    result = checker.review(public, evidence)
    repaired = review.apply_repair(public, result["repair"], packet=evidence)
    checker.review(repaired, evidence, verification=True)
    assert len(checker.sent) == 2
    rules = (
        "distinguish an observed result from a claimed practical consequence",
        "context anywhere in the complete packet",
        "name the material prerequisites in source_support's reason",
        "check that the impact sentence itself retains them",
        "Verbatim wording, attribution and can/may do not supply omitted conditions",
        "A narrower observation or an explicit source recommendation need not acquire prerequisites",
        "governing only a stronger, unclaimed consequence",
        "before choosing a source quotation and again during fresh verification",
        "If a material prerequisite for the claimed effect is missing, fail source_support",
        "request the smallest permitted supported repair",
        "do not approve merely because the wording is verbatim",
    )
    for request, target in zip(checker.sent, (public, repaired)):
        assert all(rule in prompt(request) for rule in rules)
        assert "When a packet source has unquoted_content" in prompt(request)
        assert "Literal membership establishes provenance only" in prompt(request) or "literal provenance only" in prompt(request)
        assert "rather than holding the article" in prompt(request) or "select an allowed source quotation" in prompt(request)
        assert payload(request)["packet"] == evidence
        assert payload(request)["candidate"] == target
        assert len(request["messages"]) == 2
    assert QUOTE in quote_enum(checker.sent[0])
    assert quote_enum(checker.sent[1]) == [""]
    assert "source_quote_choices" not in payload(checker.sent[1])["evidence_context"]
    assert "fresh verification request" in prompt(checker.sent[1])
    assert (public, evidence) == original


@pytest.mark.parametrize("verification", [False, True])
def test_consequence_audit_stays_out_of_update_wire(context, native, verification):
    cfg, _ = context
    public, evidence = candidate(), source()
    public["updates"] = [{"at": public["updated_at"], "text": "The report describes the optional setting.",
                          "sources": copy.deepcopy(public["sources"])}]
    checker = native(cfg, verdict("hold", criterion="source_support", update=True))
    checker.review(public, evidence, update=True, verification=verification)
    request = checker.sent[0]
    expected = review.UPDATE_VERIFY_PROMPT if verification else review.UPDATE_SYSTEM_PROMPT
    assert request["messages"][0]["content"] == expected
    assert "name the material prerequisites in source_support's reason" not in prompt(request)
    assert "An attributed assessment must preserve that speaker's degree of commitment" not in prompt(request)
    assert payload(request)["review_scope"] == "latest_update"
    repair = request["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]
    assert set(repair["properties"]) == set(review.UPDATE_EDITABLE)
    assert "why_it_matters" not in repair["properties"]


@pytest.mark.parametrize("verification", [False, True])
def test_attributed_commitment_instruction_reaches_complete_story_wire(context, native, verification):
    cfg, _ = context
    public = candidate(title="A report describes a parser condition",
                       summary="Riley describes the condition as limited.", why_it_matters="",
                       confidence="reported")
    evidence = source()
    evidence["sources"][0]["passages"].extend([
        {"id": "S1:P3", "author": "Riley", "created_at": "2026-01-02T12:00:00Z",
         "text": "The parser condition seems limited."},
        {"id": "S1:P4", "author": "Riley", "created_at": "2026-01-03T12:00:00Z",
         "text": "The correction is listed as fixed."},
    ])
    original = copy.deepcopy((public, evidence))
    checker = native(cfg, verdict("hold", criterion="uncertainty_attribution"))
    checker.review(public, evidence, verification=verification)
    request = checker.sent[0]
    rules = (
        "An attributed assessment must preserve that speaker's degree of commitment",
        "seems, looks or appears cannot become a categorical assessment through says, called",
        'confidence="reported"',
        "Later actions, closure or another speaker may update facts",
        "cannot retroactively strengthen an earlier speaker's words",
        "report a revised assessment only when that speaker explicitly supplies one",
        "preserve the supported speaker and assessment with its qualification instead of deleting them",
    )
    assert all(rule in prompt(request) for rule in rules)
    assert payload(request)["candidate"] == public
    assert payload(request)["packet"] == evidence
    assert (public, evidence) == original
    assert len(request["messages"]) == 2
    assert quote_enum(request) == [""]
