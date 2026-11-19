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


def test_impact_context_reaches_quote_choice_and_fresh_native_verification(context, native):
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
        "Use only minimal directly governing supplied context needed to resolve its referents",
        "preserve audience, conditions, affected scope, timing, lifecycle and material disagreement",
        "Keep that context in the same output sentence",
        "Each separate consequence must preserve its own material qualifiers",
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
def test_story_context_stays_out_of_update_wire(context, native, verification):
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
    assert "Named software or network entities are not people" not in prompt(request)
    assert "A concrete report in a project's own upstream tracker" not in prompt(request)
    assert "A narrower accurate description need not repeat every supporting fact" not in prompt(request)
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


@pytest.mark.parametrize("verification", [False, True])
def test_entity_type_instruction_preserves_personal_attribution_boundaries(context, native, verification):
    cfg, _ = context
    public = candidate(title="A report describes a network component",
                       summary="The report identifies a DNS server handling the requests.", why_it_matters="")
    evidence = source()
    evidence["sources"][0]["passages"].append(
        {"id": "S1:P3", "text": "The DNS server handles these requests."})
    original = copy.deepcopy((public, evidence))
    checker = native(cfg, verdict("hold", criterion="actor_and_action"))
    checker.review(public, evidence, verification=verification)
    request = checker.sent[0]
    rules = (
        "Named software or network entities are not people",
        "preserve source-supported entity type and function",
        "only an unambiguous standard expansion of a technical abbreviation",
        "If expansion is uncertain, retain the source's literal entity type or identifier",
        "does not waive names-only personal attribution",
        "or permit inferred personal roles, affiliations, actor spelling aliases, or changing an object's role",
        "spelling similarity alone cannot",
        "use the literal person's name without an occupational title",
        "Discussion and sender authority alone do not establish a personal role or affiliation",
    )
    assert all(rule in prompt(request) for rule in rules)
    assert payload(request)["candidate"] == public
    assert payload(request)["packet"] == evidence
    assert (public, evidence) == original
    assert len(request["messages"]) == 2


@pytest.mark.parametrize("verification", [False, True])
def test_upstream_trust_event_category_reaches_story_wire_with_its_limits(context, native, verification):
    cfg, _ = context
    public = candidate(title="A report proposes replacing a network credential",
                       summary="The report says an operator reported a possible credential compromise.",
                       why_it_matters="", confidence="reported")
    evidence = source()
    evidence["sources"][0].update(kind="gitlab_issue", authority="community")
    evidence["sources"][0]["passages"].append({"id": "S1:P3", "text": (
        "The credential authenticates shared network state. An operator notified the project "
        "that it may have been compromised. The report proposes replacing the credential.")})
    original = copy.deepcopy((public, evidence))
    checker = native(cfg, verdict("hold", criterion="news_value"))
    checker.review(public, evidence, verification=verification)
    request = checker.sent[0]
    rules = (
        "A concrete report in a project's own upstream tracker is material security news when",
        "identifies a component or credential with an established role in the network's shared trust",
        "reports an operator notification about suspected compromise or unexpected loss of trust concerning it",
        "describes a concrete proposed or initiated response",
        "can be news before the suspected compromise is confirmed or the response completed",
        "Keep the article attributed and qualified, at the named component and response's supplied scope",
        "does not establish official confirmation, broader harm, or unstated operator duties",
        "Routine rotation/maintenance, unsubstantiated speculation without that basis or response",
        "unrelated component events, stale resurfacing and duplicate coverage",
        "remain subject to the existing exclusions",
        "Explain the actual source event and applicable condition in the news_value reason",
        "do not replace that analysis with a generic lack-of-authority refusal",
        "On tor-dev, a post passes news_value in five cases",
        "uncorroborated operational attack/compromise/DoS/flood/bypass claims on mailing lists from authority=community",
        "Contributor status does not corroborate an operational attack, compromise or defense-bypass claim",
    )
    assert all(rule in prompt(request) for rule in rules)
    assert payload(request)["candidate"] == public
    assert payload(request)["packet"] == evidence
    assert (public, evidence) == original
    assert len(request["messages"]) == 2
    assert quote_enum(request) == [""]


@pytest.mark.parametrize("verification", [False, True])
def test_faithful_story_scope_instruction_preserves_claim_checks(context, native, verification):
    cfg, _ = context
    public = candidate(title="Version 1.2 is announced",
                       summary="The announcement describes an optional diagnostic feature.",
                       why_it_matters="", state="released", confidence="confirmed")
    evidence = source()
    evidence["sources"][0]["passages"].append({"id": "S1:P3", "text": (
        "Version 1.2 is released. The diagnostic feature is available only when enabled.")})
    original = copy.deepcopy((public, evidence))
    checker = native(cfg, verdict("hold", criterion="source_support"))
    checker.review(public, evidence, verification=verification)
    request = checker.sent[0]
    instruction = prompt(request)
    assert "State and confidence can be supported by packet evidence about the same event" in instruction
    assert "without repeating that evidence in prose" in instruction
    assert "must remain consistent with the prose's actual claims" in instruction
    assert "preserves the actual actor, action, affected audience and governing conditions" in instruction
    assert "Still fail wording or omissions" in instruction
    assert "material qualifications or corrections, or add unsupported claims" in instruction
    assert "An attributed assessment must preserve that speaker's degree of commitment" in instruction
    assert "spelling similarity alone cannot" in instruction
    assert payload(request)["candidate"] == public
    assert payload(request)["packet"] == evidence
    assert (public, evidence) == original
    assert quote_enum(request) == [""]


def test_material_error_guidance_changes_policy_without_changing_update_scope(context, monkeypatch):
    cfg, _ = context
    current = review.policy_hash(cfg)
    update_prompts = review.UPDATE_SYSTEM_PROMPT, review.UPDATE_VERIFY_PROMPT
    without_guidance = review.SYSTEM_PROMPT.replace(
        "A narrower accurate description need not repeat every supporting fact.", "")
    assert without_guidance != review.SYSTEM_PROMPT
    monkeypatch.setattr(review, "SYSTEM_PROMPT", without_guidance)
    assert review.policy_hash(cfg) != current
    assert (review.UPDATE_SYSTEM_PROMPT, review.UPDATE_VERIFY_PROMPT) == update_prompts
