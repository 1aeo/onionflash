"""Writer cache identity follows the active prompt, grammar and update inputs."""
import copy
import pytest
from onionflash import analyze
from onionflash.store import item_hash
from onionflash.util import digest

def source():
    return {"title":"A concrete source report","content":"A source describes a supported change.",
            "kind":"gitlab_issue","product":"tor","authority":"development","labels":[],
            "upstream_state":"opened","published_at":"2020-01-01T00:00:00Z","updated_at":"2020-01-02T00:00:00Z"}

def prior():
    return {"title":"Prior account","summary":"Earlier supported details.","why_it_matters":"",
            "confidence":"reported","state":"released","updated_at":"2020-01-01T00:00:00Z",
            "category":"network","sources":[{"url":"https://source.example/project/-/merge_requests/1","title":"Source"}],
            "updates":[{"at":"2020-01-01T00:00:00Z","text":"Earlier update."}]}

def key(item=None,previous=None,model="writer-model"):
    return analyze.cache_key({"content_hash":item_hash(item or source())},{"model":model},previous)

@pytest.mark.parametrize("update",[False,True])
def test_active_prompt_and_base_schema_changes_invalidate_writer_cache(monkeypatch,update):
    previous=prior() if update else None
    before=key(previous=previous)
    prompt="UPDATE_PROMPT" if update else "SYSTEM_PROMPT"
    schema=analyze.UPDATE_SCHEMA if update else analyze.SCHEMA
    with monkeypatch.context() as changed:
        changed.setattr(analyze,prompt,getattr(analyze,prompt)+"\nA changed writer instruction.")
        assert key(previous=previous)!=before
    field="update" if update else "title"
    with monkeypatch.context() as changed:
        changed.setitem(schema["properties"][field],"maxLength",schema["properties"][field]["maxLength"]-1)
        assert key(previous=previous)!=before
    assert key(previous=previous)==before

@pytest.mark.parametrize("update",[False,True])
def test_schema_property_order_is_part_of_writer_identity(monkeypatch,update):
    previous=prior() if update else None
    schema=analyze.UPDATE_SCHEMA if update else analyze.SCHEMA
    before,canonical=key(previous=previous),digest(schema)
    monkeypatch.setitem(schema,"properties",dict(reversed(list(schema["properties"].items()))))
    assert digest(schema)==canonical
    assert key(previous=previous)!=before

def test_unchanged_inputs_hit_and_existing_content_model_version_components_remain(monkeypatch):
    original=key()
    assert key(copy.deepcopy(source()))==original
    assert key({**source(),"content":"A different supported source change."})!=original
    assert key(model="another-writer-model")!=original
    monkeypatch.setattr(analyze,"PROMPT_VERSION",analyze.PROMPT_VERSION+"-next")
    assert key()!=original

@pytest.mark.parametrize("field,value",[
    ("title","Changed title"),("summary","Changed summary."),("why_it_matters","Changed impact."),
    ("confidence","confirmed"),("state","fixed"),("updated_at","2020-01-03T00:00:00Z"),
    ("updates",[{"at":"2020-01-02T00:00:00Z","text":"Another prior update."}])])
def test_prior_prompt_context_remains_in_cache_identity(field,value):
    before=prior();after={**copy.deepcopy(before),field:value}
    assert key(previous=before)!=key(previous=after)
    assert key(previous=before)!=key()

def test_prior_category_grammar_dependency_is_bound_without_changing_prompt_context():
    before=prior();after={**copy.deepcopy(before),"category":"release"}
    assert analyze.prior_context(before)==analyze.prior_context(after)
    left=analyze._writer_schema(source(),analyze.UPDATE_SCHEMA,prior=before)
    right=analyze._writer_schema(source(),analyze.UPDATE_SCHEMA,prior=after)
    assert left!=right and key(previous=before)!=key(previous=after)

def test_prior_merge_source_predicate_is_bound_without_changing_prompt_context():
    incoming={**source(),"kind":"gitlab_mr","upstream_state":"merged"}
    before={**prior(),"state":"merged"}
    after={**copy.deepcopy(before),"sources":[{"url":"https://source.example/project/-/issues/1","title":"Source"}]}
    assert analyze.prior_context(before)==analyze.prior_context(after)
    assert analyze._writer_schema(incoming,analyze.UPDATE_SCHEMA,prior=before)!=analyze._writer_schema(incoming,analyze.UPDATE_SCHEMA,prior=after)
    assert key(incoming,before)!=key(incoming,after)

def test_closed_at_and_prior_source_metadata_do_not_invalidate_writer_cache():
    incoming=source();before=prior()
    after=copy.deepcopy(before)
    after["closed_at"]="2020-02-01T00:00:00Z"
    after["sources"][0].update(closed_at="2020-02-01T00:00:00Z",title="Changed caption",id="extra-metadata")
    changed={**incoming,"closed_at":"2020-02-01T00:00:00Z"}
    assert item_hash(incoming)==item_hash(changed)
    assert key(changed)==key(incoming)
    assert key(changed,after)==key(incoming,before)
    after["sources"][0]["url"]="https://source.example/project/-/merge_requests/99"
    assert key(changed,after)==key(incoming,before)  # same grammar-driving predicate

@pytest.mark.parametrize("field,value",[("author","other-author"),("created_at","2020-01-03T00:00:00Z"),("body","A changed public observation.")])
def test_writer_visible_comment_changes_invalidate_cache(field,value):
    incoming=source()
    incoming["public_comments"]=[{"id":"note-1","url":"https://source.example/note","author":"author",
        "created_at":"2020-01-02T00:00:00Z","body":"A public source observation."}]
    changed=copy.deepcopy(incoming);changed["public_comments"][0][field]=value
    assert key(incoming)!=key(changed)

def test_comment_polling_identity_and_edit_timestamps_are_not_writer_inputs():
    incoming=source()
    incoming["public_comments"]=[{"id":"note-1","url":"https://source.example/note","author":"author",
        "created_at":"2020-01-02T00:00:00Z","body":"A public source observation."}]
    changed=copy.deepcopy(incoming)
    changed.update(comments_checked_at="2020-01-04T00:00:00Z",comments_source_key="poll-marker")
    changed["public_comments"][0].update(id="another-id",url="https://source.example/other",edited_at="2020-01-04T00:00:00Z")
    assert key(incoming)==key(changed)
