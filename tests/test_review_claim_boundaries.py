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
