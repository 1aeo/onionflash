"""The pre-review completion constraint and final guard share exact source scope."""
import copy

import pytest

from onionflash import review
from test_review import candidate, unit


ISSUE_URL = "https://example.org/issues/7"


def prepared(*sources, mode="story", editorial_kind="gitlab_issue"):
    return {"packet": {"sources": list(sources)}, "mode": mode,
            "payload": {"editorial_kind": editorial_kind}}


def check(text, sources, expected, *, field="summary", editorial_kind="gitlab_issue"):
    story = candidate(**{"title": "A source reports a change", "summary": "A source reports a change.",
                         "why_it_matters": "", field: text})
    context = prepared(*sources, editorial_kind=editorial_kind)
    before = copy.deepcopy((story, context))
    assert review.unsupported_completion_claims(story, context) == expected
    assert ("completed_action" in review.final_holds(story, context)) == bool(expected)
    assert (story, context) == before


@pytest.mark.parametrize("field", ["title", "summary", "why_it_matters"])
def test_requested_work_does_not_prove_completion_in_any_current_field(field):
    check("The entry was removed.", [unit("gitlab_issue", "Remove the entry", "Please remove the entry.")],
          ("removed",), field=field)


@pytest.mark.parametrize("text", [
    "The entry should be removed.", "The issue asks that the entry be removed.",
    "The entry will be removed.", "The entry was not removed.",
])
def test_request_future_and_negative_wording_does_not_claim_completion(text):
    check(text, [unit("gitlab_issue", "Removal request", "Please remove the entry.")], ())


@pytest.mark.parametrize("proof", [
    "The entry will be removed.", "The entry was not removed.", "The entry was never removed.",
    "The entry should be removed.",
])
def test_modal_or_negative_source_word_does_not_prove_completed_claim(proof):
    check("The entry was removed.", [unit("gitlab_issue", "Removal request", proof)], ("removed",))


def test_literal_completed_source_support_remains_accepted():
    check("The entry was removed.", [unit("gitlab_issue", "Entry change", "The entry was removed.")], ())


@pytest.mark.parametrize("state,expected", [("opened", ("removed",)), ("closed", ("removed",)), ("merged", ())])
def test_only_merged_request_title_provides_existing_imperative_fallback(state, expected):
    check("The entry was removed.", [unit("gitlab_issue", "Removal request", "Please remove the entry."),
                                    unit("gitlab_mr", "Remove the entry", state=state)], expected)


def test_constraint_reports_each_unsupported_word_once_in_field_order():
    check("The entry was removed, then removed again, and its key was revoked.",
          [unit("gitlab_issue", "Entry proposal", "Remove the entry and revoke its key.")],
          ("removed", "revoked"))


def test_completion_scope_for_non_issue_stories_is_unchanged():
    check("The entry was removed.", [unit("feed", "An entry proposal", "Please remove the entry.")], (),
          editorial_kind="feed")


def update_context(text, citations):
    source = {**unit("gitlab_issue", "Entry proposal", "Please remove the entry."), "url": ISSUE_URL}
    source["passages"] += [
        {"url": ISSUE_URL + "#note_1", "text": "The entry was removed."},
        {"url": ISSUE_URL + "#note_2", "text": "The entry should be removed."},
    ]
    story = candidate(title="The entry was removed", summary="An earlier report said the key was revoked.",
                      why_it_matters="The patch was shipped.")
    story["updates"] = [{"text": "The key was revoked.", "sources": [{"url": ISSUE_URL}]},
                        {"text": text, "sources": [{"url": url} for url in citations]}]
    return story, prepared(source, mode="update")


@pytest.mark.parametrize("citation,expected", [
    (ISSUE_URL, ("removed",)),
    (ISSUE_URL + "#note_2", ("removed",)),
    (ISSUE_URL + "#note_1", ()),
])
def test_update_uses_exact_citation_not_other_notes_or_parent(citation, expected):
    story, context = update_context("The entry was removed.", [citation])
    before = copy.deepcopy((story, context))
    assert review.unsupported_completion_claims(story, context) == expected
    assert ("completed_action" in review.final_holds(story, context)) == bool(expected)
    assert (story, context) == before


def test_readonly_story_and_earlier_updates_never_add_current_completion_claims():
    story, context = update_context("The entry should be removed.", [ISSUE_URL + "#note_2"])
    assert review.unsupported_completion_claims(story, context) == ()
    assert "completed_action" not in review.final_holds(story, context)


def test_closed_issue_metadata_alone_does_not_prove_completion():
    check("The entry was removed.", [unit("gitlab_issue", "Remove the entry", "Please remove the entry.",
                                        state="closed")], ("removed",))
