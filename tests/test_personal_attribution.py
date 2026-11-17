"""Names-only publication style preserves the underlying statement."""
import pytest

from onionflash import personal_attribution as style


@pytest.mark.parametrize('original,expected', [
    ('Arti developer Alice reports a regression.', 'Alice reports a regression.'),
    ('Relay operator river says the relay is unavailable.', 'river says the relay is unavailable.'),
    ('Developer Élodie García found a scheduling bug.', 'Élodie García found a scheduling bug.'),
    ('Maintainer @river-user explains the change.', '@river-user explains the change.'),
    ('Alice, an Arti developer, reports a regression.', 'Alice reports a regression.'),
    ('**Arti developer** Alice reports a regression.', 'Alice reports a regression.'),
    ('Arti developer **Alice** reports a regression.', '**Alice** reports a regression.'),
    ('**Arti developer Alice** reports a regression.', '**Alice** reports a regression.'),
    ('Arti developer Alice\nSmith reports a regression.', 'Alice\nSmith reports a regression.'),
])
def test_names_only_attribution(original, expected):
    assert style.normalize_text(original) == expected
    assert style.normalize_text(expected) == expected
    assert not style.unresolved_text(expected)


@pytest.mark.parametrize('text', [
    'Relay operators should upgrade when convenient.',
    'The project seeks a maintainer.',
    'Alice retires as maintainer.',
    'Alice is not a developer.',
    'Alice said, "A developer reported the issue."',
    '`developer Alice reports` is an example.',
    'Developer Tools reports a build failure.',
])
def test_content_not_personal_attribution_is_preserved(text):
    assert style.normalize_text(text) == text
    assert not style.unresolved_text(text)


def test_unsafe_personal_role_claim_is_not_reduced_to_a_name_only_sentence():
    text = 'Alice is a developer.'
    assert style.normalize_text(text) == text
    assert style.unresolved_text(text)


@pytest.mark.parametrize('original,expected', [
    ('An operator reports an outage.', 'An operator reports an outage.'),
    ('The relay operator reports an outage.', 'The relay operator reports an outage.'),
    ('Two operators reported an outage.', 'Two operators reported an outage.'),
    ('Operators report an outage.', 'Operators report an outage.'),
    ('A maintainer said the report was incomplete.', 'A maintainer said the report was incomplete.'),
])
def test_anonymous_reports_keep_identity_absence_and_number(original, expected):
    assert style.normalize_text(original) == expected
    assert not style.unresolved_text(expected)


@pytest.mark.parametrize('text', [
    'Relay operators should upgrade and report any failures.',
    'Alice is not a developer and reports an unrelated event.',
    'The project seeks two maintainers.',
])
def test_role_words_do_not_create_blanket_holds(text):
    assert style.normalize_text(text) == text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('text', [
    'Alice is an Arti developer who reports a regression.',
    'Former developer Alice reports a regression.',
    'Alice (Arti developer) reports a regression.',
    'Alice — an Arti developer — reports a regression.',
    'Alice the developer reports a regression.',
    'Developer `alice_handle` reports a regression.',
    'Developer “Alice” reports a regression.',
    'Arti developer Alice and the maintainer reported a regression.',
])
def test_ambiguous_personal_role_preserves_text_and_holds(text):
    assert style.normalize_text(text) == text
    assert style.unresolved_text(text)


@pytest.mark.parametrize('text', [
    '    Developer Alice reports a regression.',
    'Developer mode reports a missing dependency.',
    'Open Source Maintainers reports its survey results.',
    'Arti developer\n\nAlice reports a regression.',
])
def test_code_organizations_and_paragraph_boundaries(text):
    assert style.normalize_text(text) == text
    assert not style.unresolved_text(text)


def test_attribution_after_according_to():
    assert style.normalize_text('According to Arti developer Alice, the queue stalls.') == 'According to Alice, the queue stalls.'


# Runtime assertions use the native gate and saved records, not a payload-only adapter.
import copy
import json
from helpers import DATE, LATER, Reviewer, Writer, analysis, item, job, pending, run_gate, verdict, insert_approval, load_evaluator
from onionflash import review, review_gate
from onionflash.analyze import AnalysisError
from onionflash.candidate import ReviewRequired
from onionflash.util import digest


def _named_draft(**changes):
    return analysis(title='Arti developer Alice reports a scheduling issue',
                    summary='Relay operator Alice reports that requests wait for a connection.',
                    why_it_matters='Requests wait for a connection.',
                    category='network', priority='normal', tags=['network'], **changes)


def _named_item():
    return item(title='Scheduling issue', content='Alice reports that requests wait for a connection.')


def _audit(store):
    return json.loads(store.db.execute('SELECT review_record FROM analyses ORDER BY rowid DESC').fetchone()[0])


def test_initial_style_is_reviewed_and_writer_result_is_retained(context):
    cfg, store = context
    row = pending(store, _named_item())
    draft = _named_draft(); writer, checker = Writer(draft), Reviewer(verdict())
    result = run_gate(cfg, store, row, writer, checker)
    assert result['status'] == 'published' and result['review_calls'] == 2
    assert checker.calls[0][0]['title'] == 'Alice reports a scheduling issue'
    assert checker.calls[0][0]['summary'] == 'Alice reports that requests wait for a connection.'
    assert checker.calls[0][0]['why_it_matters'] == draft['why_it_matters']
    assert checker.calls[0][0] == checker.calls[1][0]
    assert all(checker.calls[1][0][key] == store.stories()[0][key] for key in review.EDITABLE)
    assert json.loads(store.db.execute('SELECT result FROM analyses').fetchone()[0]) == draft
    saved = _audit(store)
    assert saved['schema_version'] == 2
    assert {x['candidate_hash'] for x in saved['reviews']} == {digest(saved['candidate'])}
    assert saved['prepared']['candidate'] == saved['candidate']


@pytest.mark.parametrize('inconsistent', [False, True])
def test_model_repairs_are_normalized_before_durable_fresh_verification(context, inconsistent):
    cfg, store = context
    row = pending(store, _named_item()); draft = _named_draft()
    proposed = 'Developer Alice explains that queued requests wait for a connection.'
    response = verdict('revise', repair={'summary': proposed})
    if inconsistent:
        response['criteria'] = verdict()['criteria']
    first = Reviewer(response, AnalysisError('connection interrupted', retryable=True))
    with pytest.raises(AnalysisError):
        run_gate(cfg, store, row, Writer(draft), first)
    saved = json.loads(job(store)['record_json'])
    assert job(store)['stage'] == 'verify' and store.stories() == []
    assert saved['candidate']['summary'] == 'Alice explains that queued requests wait for a connection.'
    review_gate.validate_review_state(saved, 'verify', saved['candidate'], json.loads(job(store)['envelope_json']))
    if inconsistent:
        proposal = saved['untrusted_proposals'][0]
        assert proposal['repair']['summary'] == saved['candidate']['summary']  # Real v2 receipts retain the effective applied edit.
        assert proposal['candidate_after_hash'] == digest(saved['candidate'])
        assert proposal['disposition'] == 'pending'
    else:
        assert saved['reviews'][0]['result']['repair']['summary'] == proposed
    writer, checker = Writer(), Reviewer(verdict())
    result = run_gate(cfg, store, row, writer, checker)
    assert result['status'] == 'published' and result['review_calls'] == 1 and writer.calls == []
    assert checker.calls[0][0] == saved['candidate'] and checker.calls[0][2] is True
    assert _audit(store)['request_budget']['reserved'] == 3


def test_uneditable_style_holds_even_after_two_model_approvals(context):
    cfg, store = context
    row = pending(store, _named_item())
    draft = analysis(title='Alice is a developer.', summary='Alice reports that requests wait.', category='network', tags=['network'])
    result = run_gate(cfg, store, row, Writer(draft), Reviewer(verdict()))
    assert result['status'] == 'held' and result['review_calls'] == 2 and store.stories() == []
    assert json.loads(job(store)['record_json'])['hold_code'] == 'personal_attribution'
    check = review_gate.approval(cfg, store, row['id'])
    assert not check['eligible'] and 'names-only' in check['reason']


def test_commit_cannot_bypass_style_with_a_matching_cached_receipt(context):
    cfg, store = context
    row = pending(store, _named_item())
    prepared = store.prepare_candidate(row, _named_draft(), LATER)
    bad = copy.deepcopy(prepared['candidate']);bad['title'] = 'Developer Alice reports a scheduling issue'
    proof = insert_approval(store, prepared, bad)
    with pytest.raises(ReviewRequired, match='names-only'):
        store.commit_candidate(prepared, bad, 'writer-key', LATER, **proof)
    assert store.stories() == []


def test_scope_and_input_immutability_preserve_readonly_history():
    original = {'title':'Developer Alice reports an earlier event.', 'summary':'Maintainer Alice reports an earlier event.',
                'why_it_matters':'Operators should review the notes.', 'updates':[
                    {'text':'Developer Alice reports an earlier event.'},
                    {'text':'Arti developer Alice reports a new measurement.'}]}
    snapshot = copy.deepcopy(original)
    after = style.normalize(original, update=True)
    assert original == snapshot and after['updates'][0] == original['updates'][0]
    assert after['updates'][-1]['text'] == 'Alice reports a new measurement.'
    assert all(after[k] == original[k] for k in ('title','summary','why_it_matters'))
    assert not style.unresolved(after, update=True)
    story = style.normalize(original)
    assert story['updates'] == original['updates']


def test_public_evaluator_reviews_style_text_without_relabeling_input(context, tmp_path, monkeypatch):
    cfg, store = context
    row = pending(store, _named_item()); prepared = store.prepare_candidate(row, _named_draft(), LATER)
    original = copy.deepcopy(prepared['candidate']);original['title']='Arti developer Alice reports a scheduling issue'
    case={'id':'names-only-example','candidate':original,'packet':prepared['packet'],'existing_coverage':prepared['coverage'],
          'expected':'approve','scope':'story','audit':'wording'}
    evaluator=load_evaluator(); checker=Reviewer(verdict())
    monkeypatch.setattr(evaluator,'EvaluationReviewer',lambda *a,**kw:checker)
    monkeypatch.setattr(evaluator,'Analyzer',lambda *a,**kw:Writer())
    output=tmp_path/'observations.jsonl';evaluator.evaluate(cfg,[case],output)
    result=json.loads(output.read_text().splitlines()[0])
    assert result['candidate'] == original
    assert result['review_candidate']['title'] == 'Alice reports a scheduling issue'
    assert result['published_candidate'] == result['review_candidate']
    assert result['ok'] is True
    assert result['legacy_raw_ok'] is False  # Retain the original-input comparison explicitly.
    summary=json.loads(output.read_text().splitlines()[-1])['summary']
    assert summary['false_alarm_rate']==0
    assert summary['legacy_raw_false_alarm_rate']==1
    assert summary['legacy_raw_judged']['clean']['ok']==0
    assert checker.calls[0][0] == result['review_candidate']


@pytest.mark.parametrize('text', [
    'Operators can review the reported changes.',
    'Developers should report failures to the tracker.',
    'Maintainers may review and publish the proposal.',
])
def test_audience_modal_precedes_any_later_reporting_verb(text):
    assert style.normalize_text(text) == text
    assert not style.unresolved_text(text)


def test_operator_correction_rejects_new_roles_without_rewriting_history(context):
    from onionflash import editorial
    cfg,store=context
    row=pending(store,_named_item())
    assert run_gate(cfg,store,row,Writer(_named_draft()),Reviewer(verdict()))['status']=='published'
    story=store.stories()[0];view=editorial.show(store.db,story['id'])
    with pytest.raises(ValueError,match='names-only'):
        editorial.correct(store.db,story['id'],{'summary':'Developer Alice reports a new measurement.'},
                          reason='Correct attribution',expect_hash=view['hash'])
    assert editorial.show(store.db,story['id'])['hash']==view['hash']


def test_ambiguous_field_is_not_partially_rewritten():
    text='Arti developer Alice and developer Bob report a regression.'
    result=style.normalize_text(text)
    assert result==text and style.unresolved_text(result)
    assert style.normalize_text(result)==result


def test_count_before_named_people_is_not_left_dangling():
    text='Two operators Alice and Bob report a regression.'
    assert style.normalize_text(text)==text and style.unresolved_text(text)


@pytest.mark.parametrize('text', [
    'Earlier operator note.',
    'Survivor operator note.',
    'Operator reports show an increase.',
    'Operator notes are available.',
    'The maintainer comments confirm the report.',
])
def test_reporting_nouns_are_not_anonymous_people(text):
    assert style.normalize_text(text) == text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('text,expected', [
    ('Not everyone agrees, Arti developer Alice reports a failure.', 'Not everyone agrees, Alice reports a failure.'),
    ('After Bob retires, developer Alice reports a failure.', 'After Bob retires, Alice reports a failure.'),
])
def test_an_earlier_clause_does_not_exempt_a_new_attribution(text, expected):
    assert style.normalize_text(text) == expected
    assert not style.unresolved_text(expected)


@pytest.mark.parametrize('text,expected', [
    ('The issue is not resolved and Arti developer Alice reports measurements.', 'The issue is not resolved and Alice reports measurements.'),
    ('Bob retired and Arti developer Alice reports measurements.', 'Bob retired and Alice reports measurements.'),
    ('Arti developer Alice is testing the patch.', 'Alice is testing the patch.'),
    ('C Tor developer Alice requested review of the change.', 'Alice requested review of the change.'),
    ('Developer May reports a failure.', 'May reports a failure.'),
    ('Developer Will reported a failure.', 'Will reported a failure.'),
])
def test_clause_boundaries_copula_and_capitalized_modal_names(text, expected):
    assert style.normalize_text(text) == expected
    assert not style.unresolved_text(expected)


@pytest.mark.parametrize('text', [
    'Operators May Report Failures.',
    'OPERATORS MAY REPORT FAILURES.',
    'Developer mode is testing an experimental feature.',
    'Alice retired as an Arti maintainer.',
    'Alice is not an Arti developer.',
])
def test_clause_expansion_preserves_audiences_product_terms_and_role_events(text):
    assert style.normalize_text(text) == text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('verb', ['argued', 'declined'])
def test_additional_personal_reporting_actions(verb):
    text=f'Arti developer Alice {verb} the proposed change.'
    assert style.normalize_text(text)==f'Alice {verb} the proposed change.'
    assert not style.unresolved_text(style.normalize_text(text))


def test_an_unenumerated_personal_action_cannot_silently_keep_the_role():
    text='Arti developer Alice investigated the measurement.'
    assert style.normalize_text(text)==text
    assert style.unresolved_text(text)


def test_literal_grammar_is_part_of_policy_identity(context, monkeypatch):
    cfg,_=context
    before=review.policy_hash(cfg)
    monkeypatch.setitem(style.PERSONAL_ATTRIBUTION_POLICY,'patterns',{'role':'different grammar'})
    assert review.policy_hash(cfg)!=before


@pytest.mark.parametrize('text', [
    'Directory authority operators and Tor developers are affected by the change.',
    'Tor Project developers announced a release.',
    'Arti maintainers reported new measurements.',
    'The reporter alleges a vulnerability, but the response disputes it.',
    'The sender does not think a new option is needed.',
])
def test_collective_audiences_and_neutral_source_references(text):
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('text,expected', [
    ('A maintainer advised affected operators to use a workaround.', 'A maintainer advised affected operators to use a workaround.'),
    ('Arti developer Alice (@alice_handle) reports a measurement.', 'Alice (@alice_handle) reports a measurement.'),
    ('The change was authored by C Tor developer Alice.', 'The change was authored by Alice.'),
    ('Developer @operator reports a measurement.', '@operator reports a measurement.'),
    ('Tor developers Alice and Bob reported a measurement.', 'Alice and Bob reported a measurement.'),
])
def test_literal_names_handles_and_anonymous_advice(text,expected):
    assert style.normalize_text(text)==expected
    assert not style.unresolved_text(expected)


@pytest.mark.parametrize('text,expected', [
    ('In a thread reply, a developer named river asked a user to submit a patch.', 'In a thread reply, river asked a user to submit a patch.'),
    ('A relay operator named river reports measurements.', 'river reports measurements.'),
    ('An Arti developer called Alice Smith reports measurements.', 'Alice Smith reports measurements.'),
    ('A maintainer known as @alice-handle reports measurements.', '@alice-handle reports measurements.'),
])
def test_unambiguous_name_introducers_preserve_literal_identity(text,expected):
    assert style.normalize_text(text)==expected
    assert not style.unresolved_text(expected)


@pytest.mark.parametrize('text', [
    'A local Arti developer Alice reports a regression.',
    'An experienced developer Alice reports a regression.',
    'Local Arti developer Alice reports a regression.',
    'A developer named `alice_handle` reports a regression.',
    'A developer named “Alice” reports a regression.',
])
def test_ambiguous_introducers_or_unmatched_modifiers_are_not_partially_deleted(text):
    assert style.normalize_text(text)==text
    assert style.unresolved_text(text)


@pytest.mark.parametrize('text,expected', [
    ('A developer called Alice to discuss the patch.', 'A person called Alice to discuss the patch.'),
    ('A developer named Alice as maintainer.', 'A person named Alice as maintainer.'),
    ('The report rates it low severity and maintainers called it minor.', 'The report rates it low severity and maintainers called it minor.'),
])
def test_actual_calling_naming_and_judgment_keep_the_anonymous_actor(text,expected):
    assert style.normalize_text(text)==expected
    assert not style.unresolved_text(expected)


@pytest.mark.parametrize('text', ["The relay's operator reports measurements.", 'An authority’s operator reports measurements.'])
def test_possessive_qualification_cannot_turn_into_an_entities_person(text):
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


def test_name_introducer_cannot_borrow_a_verb_from_a_later_sentence():
    text='Maintainers called it minor. Alice is testing the patch.'
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(style.normalize_text(text))


def test_style_marker_collision_does_not_erase_the_remaining_false_claim(context,tmp_path,monkeypatch):
    cfg,store=context
    row=pending(store,_named_item()); prepared=store.prepare_candidate(row,_named_draft(),LATER)
    original=copy.deepcopy(prepared['candidate'])
    original['summary']='Developer Alice confirms that every client is affected.'
    case={'id':'style-marker-example','candidate':original,'packet':prepared['packet'],
          'existing_coverage':prepared['coverage'],'expected':'not_approve','scope':'story',
          'unsupported':['Developer Alice']}
    evaluator=load_evaluator();checker=Reviewer(verdict())
    monkeypatch.setattr(evaluator,'EvaluationReviewer',lambda *a,**kw:checker)
    monkeypatch.setattr(evaluator,'Analyzer',lambda *a,**kw:Writer())
    output=tmp_path/'marker-observations.jsonl';evaluator.evaluate(cfg,[case],output)
    result=json.loads(output.read_text().splitlines()[0])
    assert result['candidate']==original
    assert result['style_removed_unsupported']==['Developer Alice']
    assert result['published_candidate']['summary']=='Alice confirms that every client is affected.'
    assert result['normalized_input_unchanged'] is True
    # The legacy lexical match can succeed while an unrelated false claim stays.
    assert result['matched'] is True and 'every client is affected' in result['published_candidate']['summary']


def _native_style_reviewer(cfg, monkeypatch, *replies):
    from test_review_request_budget import reviewer
    cfg=copy.deepcopy(cfg)
    cfg['llm'].update(base_url='https://model.example/v1',fallback_base_urls=[],api_key_env='STYLE_TEST_KEY')
    monkeypatch.setenv('STYLE_TEST_KEY','synthetic-native-style-test')
    return cfg,reviewer(cfg,*replies)


def test_native_unresolved_style_issue_is_nonempty_and_disappears_after_repair(context,monkeypatch):
    cfg,store=context
    row=pending(store,_named_item())
    draft=analysis(title='Alice is a developer.',summary='Alice reports measurements.',category='network',tags=['network'])
    fixed='Alice reports measurements'
    cfg,checker=_native_style_reviewer(cfg,monkeypatch,verdict('revise',repair={'title':fixed},criterion='actor_and_action'),verdict())
    result=run_gate(cfg,store,row,Writer(draft),checker)
    bodies=[json.loads(x['messages'][1]['content'])for x in checker.client.requests]
    assert result['status']=='published'and result['review_calls']==2
    assert bodies[0]['application_issue'].startswith(review.PERSONAL_STYLE_ISSUE+'\n')
    forms=json.loads(bodies[0]['application_issue'].split('\n',1)[1])
    assert forms==style.issues(bodies[0]['candidate'])
    assert all(bodies[0]['candidate'][x['field']][x['start']:x['end']]==x['text']for x in forms)
    assert 'application_issue'not in bodies[1]
    assert bodies[1]['candidate']['title']==fixed
    assert checker.client.requests[0]['messages'][0]['content']==review.SYSTEM_PROMPT
    assert checker.client.requests[1]['messages'][0]['content']==review.VERIFY_PROMPT
    saved=_audit(store)
    assert saved['reviews'][-1]['candidate_hash']==digest(saved['candidate'])
    assert saved['request_budget']['reserved']==2


def test_style_issue_combines_with_release_issue_and_validation_feedback(context,monkeypatch):
    from test_validation_reask import unusable
    cfg,store=context
    row=pending(store,_named_item())
    draft=analysis(title='Alice is a developer.',summary='Alice reports measurements.',category='release',state='developing',tags=['release'])
    repair={'title':'Alice reports measurements','category':'network','tags':['network']}
    cfg,checker=_native_style_reviewer(cfg,monkeypatch,verdict(),unusable(),verdict('revise',repair=repair,criterion='actor_and_action'),verdict())
    result=run_gate(cfg,store,row,Writer(draft),checker)
    bodies=[json.loads(x['messages'][1]['content'])for x in checker.client.requests]
    assert result['status']=='published'and result['review_calls']==4
    assert bodies[0]['application_issue'].startswith(review.PERSONAL_STYLE_ISSUE+'\n')
    assert bodies[1]['application_issue'].startswith(review.RELEASE_ISSUE+'\n\n'+review.PERSONAL_STYLE_ISSUE+'\n')
    assert json.loads(bodies[1]['application_issue'].rsplit('\n',1)[1])==style.issues(bodies[1]['candidate'])
    assert bodies[2]=={**bodies[1],'validation_error':review.INCONSISTENT_VERDICT}
    assert 'application_issue'not in bodies[3]and 'validation_error'not in bodies[3]
    saved=_audit(store)
    assert saved['request_budget']['reserved']==4
    assert any(x.get('issue')=='release_labels'for x in saved['reviews'])
    assert saved['reviews'][-1]['stage']=='verification'


def test_native_style_repair_resume_spends_only_the_next_verification(context,monkeypatch):
    from test_review_request_budget import inconsistent
    from onionflash.transport import FetchError
    cfg,store=context
    row=pending(store,_named_item())
    draft=analysis(title='Alice is a developer.',summary='Alice reports measurements.',category='network',tags=['network'])
    cfg,checker=_native_style_reviewer(cfg,monkeypatch,inconsistent({'title':'Alice reports measurements'}),FetchError('interrupted'))
    with pytest.raises(AnalysisError):run_gate(cfg,store,row,Writer(draft),checker)
    saved=json.loads(job(store)['record_json'])
    assert saved['candidate']['title']=='Alice reports measurements'and saved['request_budget']['reserved']==2
    cfg,resumed=_native_style_reviewer(cfg,monkeypatch,verdict())
    writer=Writer();result=run_gate(cfg,store,row,writer,resumed)
    assert result['status']=='published'and result['review_calls']==1 and writer.calls==[]
    body=json.loads(resumed.client.requests[0]['messages'][1]['content'])
    assert 'application_issue'not in body and body['candidate']==saved['candidate']
    assert _audit(store)['request_budget']['reserved']==3


def test_conditional_style_instruction_is_part_of_policy_identity(context,monkeypatch):
    cfg,_=context;before=review.policy_hash(cfg)
    monkeypatch.setattr(review,'PERSONAL_STYLE_ISSUE',review.PERSONAL_STYLE_ISSUE+' Different style contract.')
    assert review.policy_hash(cfg)!=before


@pytest.mark.parametrize('text', [
    'Guard relay operators report new measurements.',
    'A community operator reports new measurements.',
    'A trusted relay operator reports new measurements.',
])
def test_anonymous_modifier_cannot_be_left_attached_to_person_or_people(text):
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('newline', ['\n', '\r\n'])
def test_complete_ascii_quote_across_soft_line_is_untouched(newline):
    text='"Arti developer Alice'+newline+'reports a regression."'
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('name', ['“Élodie” García', '"Élodie" García', '`Élodie` García'])
@pytest.mark.parametrize('template', [
    'Developer {name} found a regression.',
    'According to developer {name}, the queue stalls.',
    'The patch was written by developer {name}.',
    'A developer named {name} found a regression.',
])
def test_no_edit_branch_can_drop_a_protected_name_fragment(name,template):
    text=template.format(name=name)
    assert style.normalize_text(text)==text
    assert style.unresolved_text(text)


@pytest.mark.parametrize('subject', ['Operator', 'Operators'])
@pytest.mark.parametrize('event', ['a breach', 'a hack', 'tampering', 'an overload'])
def test_neutral_person_attribution_preserves_incident_holds(subject,event):
    draft=_named_draft()
    draft['title']=f'{subject} report{("s" if subject=="Operator" else "")} {event}.'
    draft['summary']='A mailing-list report describes measurements.'
    from helpers import STORY
    candidate={**STORY,**{k:draft[k]for k in review.EDITABLE}}
    packet={'sources':[{'id':'S1','kind':'feed','authority':'community','product':'network',
             'url':'https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/EXAMPLE/',
             'title':'Report','passages':[{'id':'S1:P1','text':candidate['title']}]}]}
    prepared={'packet':packet,'payload':{'editorial_kind':'feed'}}
    normalized=style.normalize(candidate)
    assert 'untrusted_operator_claim'in review.final_holds(candidate,prepared)
    assert 'untrusted_operator_claim'in review.final_holds(normalized,prepared)


@pytest.mark.parametrize('newline',['\n','\r\n'])
def test_multiline_quote_does_not_hide_an_independent_paragraph(newline):
    quoted='"Developer Alice'+newline+'reports a regression."'
    text=quoted+newline+newline+'Developer Bob reports a separate observation.'
    assert style.normalize_text(text)==quoted+newline+newline+'Bob reports a separate observation.'
    assert not style.unresolved_text(style.normalize_text(text))


@pytest.mark.parametrize('boundary',['\n\n','\n```\nexample\n```\n','\n    example\n'])
def test_quote_pairing_cannot_cross_paragraph_or_code_boundaries(boundary):
    text='"Developer Alice reports an issue.'+boundary+'Developer Bob reports an update."'
    assert style.normalize_text(text)==text
    assert style.unresolved_text(text)


def test_quote_inside_code_does_not_mask_an_independent_attribution():
    text='`print("example)`\n\nDeveloper Alice reports a regression.'
    assert style.normalize_text(text)=='`print("example)`\n\nAlice reports a regression.'
    assert not style.unresolved_text(style.normalize_text(text))


def test_primary_clean_score_still_penalizes_a_reviewers_extra_edit(context,tmp_path,monkeypatch):
    cfg,store=context
    row=pending(store,_named_item());prepared=store.prepare_candidate(row,_named_draft(),LATER)
    original=copy.deepcopy(prepared['candidate']);original['title']='Developer Alice reports a scheduling issue'
    case={'id':'additional-review-edit','candidate':original,'packet':prepared['packet'],
          'existing_coverage':prepared['coverage'],'expected':'approve','scope':'story','audit':'wording'}
    evaluator=load_evaluator();checker=Reviewer(verdict('revise',repair={'summary':'Alice reports additional observations.'}),verdict())
    monkeypatch.setattr(evaluator,'EvaluationReviewer',lambda *a,**kw:checker)
    monkeypatch.setattr(evaluator,'Analyzer',lambda *a,**kw:Writer())
    output=tmp_path/'extra-edit.jsonl';evaluator.evaluate(cfg,[case],output)
    records=[json.loads(line)for line in output.read_text().splitlines()]
    assert records[0]['ok'] is False and records[0]['legacy_raw_ok'] is False
    assert records[0]['candidate']==original and records[0]['review_candidate']!=original
    assert records[-1]['summary']['false_alarm_rate']==1
    assert records[-1]['summary']['legacy_raw_false_alarm_rate']==1


def test_primary_and_legacy_pairing_keep_their_own_clean_twins(context,tmp_path,monkeypatch):
    cfg,store=context
    row=pending(store,_named_item());prepared=store.prepare_candidate(row,_named_draft(),LATER)
    clean=copy.deepcopy(prepared['candidate']);clean['title']='Developer Alice reports a scheduling issue'
    flawed={**clean,'why_it_matters':'An unsupported consequence.'}
    common={'packet':prepared['packet'],'existing_coverage':prepared['coverage'],'scope':'story','audit':'pairing'}
    cases=[{**common,'id':'styled-clean','candidate':clean,'expected':'approve'},
           {**common,'id':'flawed-impact','candidate':flawed,'expected':'not_approve',
            'flaw':'invented_impact','unsupported':['An unsupported consequence.']}]
    def choose(candidate,*args,**kwargs):
        return verdict('revise',repair={'why_it_matters':''},criterion='source_support') if candidate['why_it_matters']=='An unsupported consequence.' else verdict()
    evaluator=load_evaluator();checker=Reviewer(choose,choose,choose,choose)
    monkeypatch.setattr(evaluator,'EvaluationReviewer',lambda *a,**kw:checker)
    monkeypatch.setattr(evaluator,'Analyzer',lambda *a,**kw:Writer())
    summary=evaluator.evaluate(cfg,cases,tmp_path/'paired.jsonl')
    assert summary['judged']['invented_impact']['paired']==1
    assert summary['legacy_raw_judged']['invented_impact']['paired']==0
    assert summary['false_alarm_rate']==0 and summary['legacy_raw_false_alarm_rate']==1
    assert summary['catch_rate']==summary['legacy_raw_catch_rate']==1


def test_code_quote_delimiters_cannot_consume_a_complete_prose_quote():
    text='`"a`. "Developer Alice reports a regression." `"b`.'
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('opening,closing', [('"','"'), ('“','”'), ('‘','’'), ("'","'")])
@pytest.mark.parametrize('padding',['',' '])
def test_protected_delimiters_do_not_pair_with_prose_quote_edges(opening,closing,padding):
    text=f'`{opening}a`. {opening}{padding}Developer Alice reports a regression.{padding}{closing} `{closing}b`.'
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('opening,closing', [('"','"'), ('“','”'), ('‘','’'), ("'","'")])
def test_code_quote_delimiters_do_not_hide_a_genuine_outside_attribution(opening,closing):
    prefix=f'`{opening}a`. {opening}Ordinary quoted text.{closing} '
    suffix=f' `{closing}b`.'
    text=prefix+'Developer Bob reports a regression.'+suffix
    assert style.normalize_text(text)==prefix+'Bob reports a regression.'+suffix
    assert not style.unresolved_text(style.normalize_text(text))


@pytest.mark.parametrize('newline',['\n','\r\n'])
@pytest.mark.parametrize('prefix,suffix', [('> "a','> "b'),('    "a','    "b'),('```\n"a\n```','```\n"b\n```')])
def test_protected_block_delimiters_do_not_change_prose_pairing(prefix,suffix,newline):
    text=prefix.replace('\n',newline)+newline+'"Developer Alice'+newline+'reports a regression."'+newline+suffix.replace('\n',newline)
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('text', [
    'Alice, a trusted operator, reports measurements.',
    'Alice, an experienced relay operator, reports measurements.',
    'A project-sender posted measurements.',
    'An official sender reports measurements.',
])
def test_modified_personal_or_metadata_actor_labels_cannot_silently_publish(text):
    assert style.normalize_text(text)==text
    assert style.unresolved_text(text)


@pytest.mark.parametrize('description', ['identified as a relay operator', 'who identifies as a relay operator', 'who is a maintainer'])
def test_named_relative_role_description_keeps_the_name_and_reporting_action(description):
    text=f'Alice, {description}, reports measurements.'
    assert style.normalize_text(text)=='Alice reports measurements.'
    assert not style.unresolved_text(style.normalize_text(text))


@pytest.mark.parametrize('text', [
    "Harbor's operator reports that the machine is plausibly compromised.",
    'Harbor’s operator reports that its keys cannot be trusted.',
    'The operator of Harbor reported that the keys cannot be trusted.',
    'The directory authority operator reports a possible compromise.',
    'Guard relay operators report measurements.',
    'The maintainers called the issue minor.',
    'Two relay operators reported measurements.',
])
def test_anonymous_operational_references_preserve_function_and_qualification(text):
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('text', [
    'Alice, not a trusted operator, reported measurements.',
    'Alice, appointed as maintainer, reported measurements.',
    'Alice, interviewed by an operator, reported measurements.',
    'Alice, who spoke to an operator, reported measurements.',
    '"Alice, a trusted operator, reports measurements."',
    '`Alice, identified as a relay operator, reports measurements.`',
    'The source uses the label "project-sender".',
    'Relay operators should report failures.',
])
def test_role_boundary_does_not_erase_events_quotes_code_or_audiences(text):
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


def test_style_locations_are_literal_and_limited_to_current_editable_fields():
    candidate={'title':'Alice reports measurements.','summary':'Alice, a trusted operator, reports measurements.',
               'why_it_matters':'Relay operators may be affected.', 'updates':[{'text':'Developer Bob reports earlier news.'},{'text':'A project-sender posted new measurements.'}]}
    forms=style.issues(candidate)
    assert {x['field']for x in forms}=={'summary'}
    assert all(candidate[x['field']][x['start']:x['end']]==x['text']for x in forms)
    assert all('Alice'not in x['text']for x in forms)
    updates=style.issues(candidate,update=True)
    assert {x['field']for x in updates}=={'updates[-1].text'}
    assert all(candidate['updates'][-1]['text'][x['start']:x['end']]==x['text']for x in updates)
    assert not style.issues({'title':'Alice reports measurements.','summary':"Harbor's operator reported measurements.",'why_it_matters':'Maintainers called the issue minor.'})


def test_functional_anonymous_report_can_publish_without_a_style_hold(context):
    cfg,store=context
    content="Harbor's operator reported that the machine was very plausibly compromised and its keys cannot be trusted."
    row=pending(store,item(title='Directory authority report',content=content))
    draft=analysis(title='An authority report describes a possible compromise',summary=content,
                   why_it_matters='The keys cannot be trusted.',category='security',tags=['security'])
    checker=Reviewer(verdict())
    result=run_gate(cfg,store,row,Writer(draft),checker)
    assert result['status']=='published'and result['review_calls']==2
    assert store.stories()[0]['summary']==content and store.stories()[0]['why_it_matters']==draft['why_it_matters']
    assert not style.unresolved(checker.calls[0][0])


@pytest.mark.parametrize('summary',['Alice, a trusted operator, reports measurements.','A project-sender posted measurements.'])
def test_remaining_personal_and_metadata_aliases_cannot_publish_after_model_approval(context,summary):
    cfg,store=context
    row=pending(store,_named_item())
    draft=analysis(title='Alice reports measurements',summary=summary,category='network',tags=['network'])
    result=run_gate(cfg,store,row,Writer(draft),Reviewer(verdict()))
    assert result['status']=='held'and store.stories()==[]
    assert json.loads(job(store)['record_json'])['hold_code']=='personal_attribution'
    assert not review_gate.approval(cfg,store,row['id'])['eligible']


@pytest.mark.parametrize('text', [
    'Alice, operator of the authority, reports measurements.',
    'The operator of the authority, Alice, reports measurements.',
    'Alice, a trusted operator of the authority, reports measurements.',
])
def test_anonymous_function_exception_does_not_hide_an_attached_person_name(text):
    assert style.normalize_text(text)==text
    assert style.unresolved_text(text)


def test_relative_action_involving_another_operator_is_not_a_personal_title():
    text='Alice, who interviewed a relay operator of the authority, reports measurements.'
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)


@pytest.mark.parametrize('text', [
    'The operator of the authority is Alice.',
    'The operator of the relay was Alice Smith.',
    'The operators of the authority are Alice and Bob.',
    'The operator of the authority is @alice-handle.',
])
def test_named_functional_identity_predicate_is_not_an_anonymous_reference(text):
    assert style.normalize_text(text)==text
    assert style.unresolved_text(text)


@pytest.mark.parametrize('text', [
    'The operator of the authority is unreachable.',
    'The operator of the authority is offline.',
    'The operator of the authority is reviewing logs.',
    'The operator of the authority was appointed yesterday.',
    'The operator of the authority reported a failure.',
    '"The operator of the authority is Alice."',
    '`The operator of the authority is Alice.`',
])
def test_functional_predicate_keeps_anonymous_status_actions_events_and_quotes(text):
    assert style.normalize_text(text)==text
    assert not style.unresolved_text(text)
