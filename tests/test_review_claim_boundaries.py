"""Claim boundaries reach each native review without changing its evidence or protocol."""
import copy
import json

import pytest

from helpers import completion, verdict
from onionflash import review
from test_review import candidate, packet, reviewer


def captured(monkeypatch, *, update=False, verification=False, response=None):
    public = candidate(title="A source describes a conditional observation",
                       summary="The report describes a conditional observation.",
                       why_it_matters="A log reader can read a partial token when the optional setting is enabled.")
    if update:
        public["updates"] = [{"at": public["updated_at"],
                              "text": "The report describes an additional conditional observation.",
                              "sources": copy.deepcopy(public["sources"])}]
    source = packet()
    source["sources"][0]["passages"][0]["text"] = (
        "When an optional setting is enabled, a partial token is logged. A log reader can read that token.")
    source["sources"][0]["unquoted_content"] = source["sources"][0]["passages"][0]["text"]
    before = copy.deepcopy((public, source))
    checker = reviewer(monkeypatch, completion(response or verdict(update=update)))
    result = checker.review(public, source, update=update, verification=verification)
    body = checker.client.requests[0][1]
    payload = json.loads(body["messages"][-1]["content"])
    assert (public, source) == before
    assert payload["candidate"] == public and payload["packet"] == source
    assert len(body["messages"]) == 2
    assert body["max_tokens"] == 2200 and body["temperature"] == 0
    assert body["response_format"]["json_schema"]["name"] == "onionflash_review"
    return public, source, result, body, payload


@pytest.mark.parametrize("update", [False, True])
@pytest.mark.parametrize("verification", [False, True])
def test_exact_claim_scope_rule_reaches_every_native_review(monkeypatch, update, verification):
    _, source, _, body, payload = captured(monkeypatch, update=update, verification=verification)
    prompt = body["messages"][0]["content"]
    assert review._CLAIM_SCOPE_RULE in prompt
    assert "material qualifier" in review._CLAIM_SCOPE_RULE
    assert "a stronger impact that the sentence does not assert" in review._CLAIM_SCOPE_RULE
    assert "never the readonly why" in prompt
    assert "unquoted_content" in prompt
    assert payload["packet"]["sources"][0]["unquoted_content"] == source["sources"][0]["unquoted_content"]
    schema = body["response_format"]["json_schema"]["schema"]
    assert list(schema["properties"]) == ["criteria", "verdict", "same_story", "repair"]
    assert list(schema["properties"]["criteria"]["properties"]) == list(review.CRITERIA)
    assert all(check["properties"]["reason"]["maxLength"] == 360
               for check in schema["properties"]["criteria"]["properties"].values())


def test_claim_scope_instruction_does_not_allow_unbound_evidence_or_failed_approval(monkeypatch):
    response = verdict()
    response["criteria"]["source_support"]["source_refs"] = ["S1:P404"]
    with pytest.raises(review.ReviewError):
        captured(monkeypatch, response=response)
    response = verdict()
    response["criteria"]["source_support"]["outcome"] = "fail"
    with pytest.raises(review.ReviewError):
        captured(monkeypatch, response=response)


@pytest.mark.parametrize("update", [False, True])
@pytest.mark.parametrize("verification", [False, True])
def test_temporal_rule_is_scoped_to_current_story_or_update(monkeypatch, update, verification):
    public, _, _, body, payload = captured(monkeypatch, update=update, verification=verification)
    prompt = body["messages"][0]["content"]
    assert review._TEMPORAL_SUPPORT_RULE in prompt
    assert "supplied later evidence" in review._TEMPORAL_SUPPORT_RULE
    assert "Do not infer that a distinct issue was resolved" in review._TEMPORAL_SUPPORT_RULE
    assert "passage order is not chronology" in prompt
    if update:
        assert payload["review_scope"] == "latest_update"
        assert "candidate.title, summary, why_it_matters and updates[:-1] are read-only" in prompt
        assert payload["candidate"]["why_it_matters"] == public["why_it_matters"]
    else:
        assert "more than 14 days before" in prompt
        assert "updated_at, fail news_value" in prompt


@pytest.mark.parametrize("verification", [False, True])
def test_story_field_local_repair_retains_supported_impact(monkeypatch, verification):
    response = verdict("revise", criterion="source_support", repair={"summary": "The source reports a qualified observation."})
    public, _, result, body, _ = captured(monkeypatch, verification=verification, response=response)
    prompt = " ".join(body["messages"][0]["content"].split())
    assert "Modify only fields whose own assertions you identify as defective" in prompt
    assert "set its repair value to null even if source_support fails for the title or summary" in prompt
    assert 'The only allowed why_it_matters edit is ""' in prompt
    assert result["repair"] == {"summary": "The source reports a qualified observation."}
    assert review.apply_repair(public, result["repair"])["why_it_matters"] == public["why_it_matters"]


@pytest.mark.parametrize("update", [False, True])
@pytest.mark.parametrize("verification", [False, True])
def test_standalone_impact_boundary_reaches_only_story_requests(monkeypatch, update, verification):
    _, _, _, body, payload = captured(monkeypatch, update=update, verification=verification)
    prompt = " ".join(body["messages"][0]["content"].split())
    rules = (
        "Assess why_it_matters against the supplied source alone: each assertion must be stated or directly entailed.",
        "title, summary and confidence label cannot supply missing qualifiers, scope or limitations",
        "including a borderline inference, mark source_support insufficient, not pass",
        "a hedge in one clause does not automatically qualify a following consequence",
        "If only why_it_matters is defective and the article is otherwise eligible, return revise and clear it",
        "leave supported why_it_matters unchanged",
    )
    assert all((rule in prompt) is not update for rule in rules)
    assert "necessary governing context" in prompt
    if update:
        assert payload["review_scope"] == "latest_update"
        assert "why_it_matters and updates[:-1] are read-only" in prompt
    else:
        assert "more than 14 days before" in prompt


@pytest.mark.parametrize("verification", [False, True])
def test_insufficient_impact_can_only_be_cleared_by_a_valid_repair(monkeypatch, verification):
    response = verdict("revise", criterion="source_support", repair={"why_it_matters": ""})
    response["criteria"]["source_support"]["outcome"] = "insufficient"
    public, _, result, _, _ = captured(monkeypatch, verification=verification, response=response)
    assert result["verdict"] == "revise" and result["repair"] == {"why_it_matters": ""}
    repaired = review.apply_repair(public, result["repair"])
    assert repaired == {**public, "why_it_matters": ""}


def test_impact_remains_clear_only_and_readonly_for_update_repairs(monkeypatch):
    public, _, _, body, _ = captured(monkeypatch)
    schema = body["response_format"]["json_schema"]["schema"]
    why = schema["properties"]["repair"]["anyOf"][1]["properties"]["why_it_matters"]
    assert why["anyOf"][0]["enum"] == [""]
    assert review.apply_repair(public, {"why_it_matters": ""})["why_it_matters"] == ""
    with pytest.raises(review.ReviewError):
        review.apply_repair(public, {"why_it_matters": "A newly generated impact sentence."})
    update, _, _, body, _ = captured(monkeypatch, update=True)
    assert "why_it_matters" not in body["response_format"]["json_schema"]["schema"]["properties"]["repair"]["anyOf"][1]["properties"]
    repaired = review.apply_repair(update, {"update": "The report states an additional qualified observation."}, update=True)
    assert repaired["why_it_matters"] == update["why_it_matters"]
    with pytest.raises(review.ReviewError):
        review.apply_repair(update, {"why_it_matters": ""}, update=True)


@pytest.mark.parametrize("update", [False, True])
@pytest.mark.parametrize("verification", [False, True])
def test_source_version_rule_reaches_both_scopes_without_blanket_format_inference(monkeypatch, update, verification):
    _, _, _, body, _ = captured(monkeypatch, update=update, verification=verification)
    prompt = " ".join(body["messages"][0]["content"].split())
    assert " ".join(review._VERSION_EVIDENCE_RULE.split()) in prompt
    assert "0.3.17 or 0.4.17" in prompt
    assert "[sic] or a typo attribution" in prompt
    assert "do not delete their affected scope or guess a replacement" in prompt
    assert "C Tor uses four numbers" not in prompt


@pytest.mark.parametrize("text,held", [
    ("The report concerns Tor 2.7.8 relays.", False),
    ("The report concerns Tor 0.3.17 relays.", True),
    ("The report concerns Tor 0.4.17 relays.", True),
    ("The report concerns Tor 0.4.9.17 relays.", False),
    ("The source writes the version as Tor 0.4.17 [sic].", False),
    ("The source has a version typo: Tor 0.3.17.", False),
])
@pytest.mark.parametrize("update", [False, True])
def test_source_versions_and_existing_sic_guard_keep_current_scope(text, held, update):
    from onionflash.llm import has_malformed_tor_version

    assert has_malformed_tor_version(text, ["tor"]) is held
    public = candidate(title="A source reports a version observation", summary=text, why_it_matters="")
    source = packet()
    source["sources"][0].update(kind="feed", authority="official")
    source["sources"][0]["passages"][0]["text"] = text
    if update:
        public["summary"] = "An earlier source wrote Tor 0.4.17."
        public["updates"] = [{"at": public["updated_at"], "text": text, "sources": copy.deepcopy(public["sources"])}]
    prepared = {"packet": source, "mode": "update" if update else "story",
                "payload": {"editorial_kind": "feed"}, "coverage": None}
    before = copy.deepcopy((public, prepared))
    assert ("malformed_version" in review.final_holds(public, prepared)) is held
    assert (public, prepared) == before
