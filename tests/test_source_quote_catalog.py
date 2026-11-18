"""Literal span boundaries and fixed choice limits use synthetic source prose."""
import copy
import unittest
from onionflash import source_quote
from onionflash.source_quote import POLICY
from unittest.mock import patch

def build(candidate, packet, *, mode="story", preserve_rendered=None):
    if mode != "story" or not candidate.get("why_it_matters"):
        return {"choices": []}
    if preserve_rendered is not None:
        with patch.object(source_quote, "preserves_rendered", preserve_rendered):
            return source_quote.build(packet, cited_urls={s["url"] for s in candidate["sources"]})
    return source_quote.build(packet, cited_urls={s["url"] for s in candidate["sources"]})

GOOD='Users can inspect the result when the optional setting is enabled.'
def fixture(body=None,*,own=None):
 source={'id':'S1','url':'https://example.org/source','passages':[{'id':'S1:P1','text':'Source title'},
  {'id':'S1:P2','text':body if body is not None else 'Introduction.\n\n'+GOOD+'\n\nFollowing context.'}]}
 if own is not None:source['unquoted_content']=own
 return {'why_it_matters':'An existing observation.','sources':[{'url':source['url']}]},{'sources':[source],'missing_sources':[],'truncated':False}

def choices(candidate,packet,**kw):return build(candidate,packet,**kw)['choices']
class Catalog(unittest.TestCase):
 def test_exact_raw_offsets_and_only_whitespace_rendering(self):
  c,p=fixture('Introduction.\n\nUsers can inspect 51 of 52 values\nwhen the optional setting is enabled.\n\nLater context.')
  before=copy.deepcopy((c,p));out=build(c,p);self.assertEqual((c,p),before);self.assertEqual(len(out['choices']),1)
  e=out['eligible_spans'][0];self.assertEqual(p['sources'][0]['passages'][1]['text'][e['start']:e['end']],e['raw'])
  self.assertIn('51 of 52',e['rendered']);self.assertIn('when the optional setting is enabled.',e['rendered'])
 def test_empty_disabled(self):
  c,p=fixture();c['why_it_matters']='';self.assertFalse(choices(c,p))
 def test_update_disabled(self):
  c,p=fixture();self.assertFalse(choices(c,p,mode='latest_update'))
 def test_uncited_disabled(self):
  c,p=fixture();c['sources']=[];self.assertFalse(choices(c,p))
 def test_truncated_disabled(self):
  c,p=fixture();p['truncated']=True;self.assertFalse(choices(c,p))
 def test_missing_source_disabled(self):
  c,p=fixture();p['missing_sources']=['missing'];self.assertFalse(choices(c,p))
 def test_whole_chunk_edge_is_not_assumed_complete(self):
  c,p=fixture(GOOD);self.assertFalse(choices(c,p))
 def test_no_join_of_incomplete_chunks(self):
  c,p=fixture('Introduction.\n\nUsers can inspect the result when')
  p['sources'][0]['passages'].append({'id':'S1:P3','text':'the optional setting is enabled.\n\nEnd.'});self.assertFalse(choices(c,p))
 def test_parent_quote(self):
  c,p=fixture('Intro.\n\n> '+GOOD+'\n\nEnd.');self.assertFalse(choices(c,p))
 def test_unquoted_membership_required(self):
  c,p=fixture(own='The source contributes a different observation.');self.assertFalse(choices(c,p))
 def test_own_text_membership_preserves(self):
  c,p=fixture(own=GOOD);self.assertEqual(len(choices(c,p)),1)
 def test_inline_code_excluded(self):
  c,p=fixture('Intro.\n\nUsers can inspect the `result` when the optional setting is enabled.\n\nEnd.');self.assertFalse(choices(c,p))
 def test_fenced_code(self):
  c,p=fixture('```text\n\n'+GOOD+'\n\n```');self.assertFalse(choices(c,p))
 def test_fence_length_and_cross_passage_exclusion(self):
  c,p=fixture('````text\n\n'+GOOD+'\n\n```')
  p['sources'][0]['passages'].append({'id':'S1:P3','text':'Still code.\n\n'+GOOD+'\n\n````\n\nEnd.'});self.assertFalse(choices(c,p))
 def test_raw_html_parent_and_code_context_excluded(self):
  for tag in ['blockquote','pre','code']:
   with self.subTest(tag=tag):
    c,p=fixture('<'+tag+'>\n\n'+GOOD+'\n\n</'+tag+'>');self.assertFalse(choices(c,p))
 def test_html_tag_split_at_chunk_boundary_excluded(self):
  c,p=fixture('Intro.\n<block');p['sources'][0]['passages'].append({'id':'S1:P3','text':'quote>\n\n'+GOOD+'\n\n</blockquote>'});self.assertFalse(choices(c,p))
 def test_fence_closer_at_chunk_edge_is_unknown(self):
  c,p=fixture('~~~text\n'+'x'*1788+'\n~~~')
  self.assertEqual(len(p['sources'][0]['passages'][1]['text']),1800)
  p['sources'][0]['passages'].append({'id':'S1:P3','text':'not-a-closer\n\n'+GOOD+'\n\n~~~\n'});self.assertFalse(choices(c,p))
 def test_partial_opening_delimiter_excludes_continuation(self):
  for tail,nextline in [('~~','~text'),('~~~','~text')]:
   with self.subTest(tail=tail):
    c,p=fixture('Intro.\n'+tail);p['sources'][0]['passages'].append({'id':'S1:P3','text':nextline+'\n\n'+GOOD+'\n\n~~~~\n'});self.assertFalse(choices(c,p))
 def test_list_heading_table_template(self):
  for text in ['- '+GOOD,'## '+GOOD,'| '+GOOD+' |','Run ${COMMAND} when users can see the result.']:
   with self.subTest(text=text):
    c,p=fixture('Intro.\n\n'+text+'\n\nEnd.');self.assertFalse(choices(c,p))
 def test_fragment_with_period_is_not_enough(self):
  c,p=fixture('Intro.\n\nMany important useful changes to the configuration.\n\nEnd.');self.assertFalse(choices(c,p))
 def test_procedural_heading_scope_is_not_a_factual_sentence(self):
  c,p=fixture('Intro.\n\n# Release checklist\n\nUsers can publish the release after every step is checked.\n\nEnd.')
  p['sources'][0]['passages'].append({'id':'S1:P3','text':'Continued.\n\n'+GOOD+'\n\nEnd.'})
  self.assertFalse(choices(c,p))
 def test_procedural_source_title_is_not_an_event(self):
  c,p=fixture();p['sources'][0]['title']='Example maintenance template';self.assertFalse(choices(c,p))
 def test_abbreviation_cannot_create_new_sentence(self):
  c,p=fixture('Intro.\n\nDr. Morgan can inspect the result when the setting is enabled.\n\nEnd.');self.assertFalse(choices(c,p))
 def test_source_we_is_visibly_attributed(self):
  c,p=fixture('Intro.\n\nWe encourage users to inspect the documented optional setting.\n\nEnd.')
  text=choices(c,p)[0]['rendered'];self.assertTrue(text.startswith('A cited source states: “We encourage'));self.assertTrue(text.endswith('.”'))
 def test_question_excluded(self):
  c,p=fixture('Intro.\n\nCan users inspect the result when the setting is enabled?\n\nEnd.');self.assertFalse(choices(c,p))
 def test_native_render_change_rejected(self):
  c,p=fixture();self.assertFalse(choices(c,p,preserve_rendered=lambda _:False))
 def test_bounds_and_unrelated_edits_do_not_reorder(self):
  body='Intro.\n\n'+'\n\n'.join(f'Users can inspect option number {i} when the setting is enabled.'for i in range(12))+'\n\nEnd.'
  c,p=fixture(body);out=build(c,p);self.assertEqual(len(out['choices']),POLICY['max_choices']);c['title']='Unrelated new title';self.assertEqual(out['choices'],choices(c,p))
 def test_no_truncation_of_long_sentence(self):
  c,p=fixture('Intro.\n\nUsers can inspect '+('the detailed result '*60)+'when the setting is enabled.\n\nEnd.');self.assertFalse(choices(c,p))
 def test_later_correction_is_context_not_automatic_grounding(self):
  c,p=fixture('Intro.\n\nUsers may experience the documented conditional failure.\n\nLater context.')
  p['sources'][0]['passages'].append({'id':'S1:P3','author':'Morgan','created_at':'2026-01-01T12:00:00Z','text':'That earlier interpretation was incorrect.'})
  result=build(c,p);self.assertEqual(len(result['choices']),1);self.assertEqual(result['semantic_grounding'],'NOT_DETERMINED')
if __name__=='__main__':unittest.main()


def test_duplicate_renderings_keep_each_real_source_origin():
    candidate, packet = fixture()
    other = copy.deepcopy(packet['sources'][0])
    other.update(id='S2', url='https://example.org/another-source')
    for passage in other['passages']:
        passage['id'] = passage['id'].replace('S1', 'S2')
        passage.update(author='Morgan', created_at='2026-01-01T12:00:00Z')
    candidate['sources'].append({'url': other['url']})
    packet['sources'].append(other)
    result = build(candidate, packet)
    assert len(result['choices']) == 1
    origins = result['choices'][0]['origins']
    passages = source_quote.passages(result['choices'], packet)
    assert [passages[origin['ref']]['source_ref'] for origin in origins] == ['S1', 'S2']
    assert [passages[origin['ref']]['source_url'] for origin in origins] == [source['url'] for source in packet['sources']]
    assert passages[origins[1]['ref']]['author'] == 'Morgan'


def test_aggregate_byte_bound_is_fixed_without_truncating_sentences():
    text = 'Users can inspect ' + ('the detailed result ' * 32) + 'when the setting is enabled.'
    candidate, packet = fixture('Intro.\n\n' + '\n\n'.join(text.replace('Users', f'Users in group {n}') for n in range(8)) + '\n\nEnd.')
    result = build(candidate, packet)
    assert len(result['choices']) < 8
    assert result['rendered_utf8_bytes'] <= 4096
    assert all(choice['rendered'].endswith('enabled.”') for choice in result['choices'])


def test_numeric_and_version_boundaries_preserve_the_whole_sentence():
    sentence = 'Users can inspect version 2.7.1 with 3.5 seconds of data when the option is enabled.'
    candidate, packet = fixture('Intro.\n\n' + sentence + '\n\nEnd.')
    result = build(candidate, packet)
    assert [entry['raw'] for entry in result['eligible_spans']] == [sentence]
