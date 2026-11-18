"""Bounded literal source spans; structural provenance never grants approval."""
import copy
import re

from . import personal_attribution, render
from .schema import FIELD_LIMITS

POLICY = {"version": 2, "max_choices": 8, "max_rendered_chars": 800,
          "aggregate_rendered_utf8_bytes": 4096, "minimum_words": 6,
          "paragraph_edges": "both-visible-in-one-passage", "cross_passage_join": False,
          "rendering": "whitespace-only-with-neutral-curly-quotation",
          "procedural_sections": "monotone-exclude-to-source-unit-end",
          "html_context": "exclude-source-with-raw-taglike-markup",
          "fence_edges": "unknown-delimiter-keeps-unit-excluded",
          "replacement": "nonempty-to-one-neutral-quote-then-keep-or-clear",
          "normalization": "render-field-and-personal-attribution-exact",
          "context": "full-passage-and-source-metadata-once-per-reference",
          "commit_proof": "stored-receipt-and-held-proof-with-exact-publication-envelope"}
PREFIX = 'A cited source states: “'
FENCE = re.compile(r'^ {0,3}(`{3,}|~{3,})(.*)$')
BLOCK = re.compile(r'(?m)^(?:[ \t]*>| {4}|\t|[ \t]*#{1,6}\s|[ \t]*(?:[-+*]|\d+[.)])\s|[ \t]*\||[ \t]*On .+wrote:)|\$\{|\{\{')
PARAGRAPH = re.compile(r'\n[ \t]*\n')
END = re.compile(r'[.!?](?=\s+[A-Z0-9(]|\s*$)')
AMBIGUOUS = re.compile(r'\b(?:Mr|Mrs|Ms|Dr|Prof|Sr|Jr|St|vs|etc|e\.g|i\.e)\.', re.I)
INITIAL = re.compile(r'\b(?:[A-Z]\.)+(?=\s|[A-Z])')
PROCEDURAL = re.compile(r'\b(?:checklists?|templates?)\b', re.I)
PROCEDURAL_HEADING = re.compile(r'(?m)^ {0,3}#{1,6}\s+[^\n]*\b(?:checklists?|templates?)\b', re.I)
RAW_MARKUP = re.compile(r'<(?:/?[A-Za-z]|!)|<\Z')
FINITE = re.compile(r'\b(?:is|are|was|were|has|have|had|can|cannot|could|may|might|will|would|must|shall|should|does|do|did)\b', re.I)
PERSONAL_VERB = re.compile(r'^(?:I|We|You|They)\s+(?:explicitly\s+)?(?:encourage|recommend|ask|urge|request|advise|report|describe|observe|expect|intend|plan)\b')
CONCLUSION = re.compile(r'\b(?:therefore|thus|hence|consequently|accordingly|as\s+a\s+(?:result|consequence)|for\s+(?:this|that|these|those)\s+reasons?)\b', re.I)

def flat(text):
    return ' '.join(text.split())


def group_key(passage):
    return tuple(passage.get(k) for k in ('author', 'created_at', 'url'))


def code_ranges(text, opened):
    """Carry only exclusion state; never join source chunks to manufacture a span."""
    ranges = []
    offset = 0
    for line in text.splitlines(keepends=True):
        match = FENCE.match(line.rstrip('\r\n'))
        if opened:
            ranges.append((offset, offset + len(line)))
            if (offset > 0 and line.endswith(('\n', '\r')) and match
                    and match[1][0] == opened[0] and len(match[1]) >= opened[1]
                    and not match[2].strip()):
                opened = None
        elif match:
            opened = ((match[1][0], len(match[1])) if line.endswith(('\n', '\r'))
                      else ('unknown', 0))
            ranges.append((offset, offset + len(line)))
        offset += len(line)
    if re.search(r'[`~]{1,2}\Z', text):
        # A chunk may cut a delimiter; never reconstruct it from the next chunk.
        opened = ('unknown', 0)
    return ranges, opened


def rejection(sentence):
    if not sentence or not sentence[0].isupper():
        return 'uncertain_sentence_start'
    if sentence[-1] not in '.!?':
        return 'no_complete_terminal_boundary'
    if sentence[-1] == '?':
        return 'question_not_impact_assertion'
    if len(re.findall(r'\b\w+\b', sentence)) < POLICY['minimum_words']:
        return 'short_or_fragmentary'
    if '`' in sentence or re.search(r'["“”‘’]|(?<!\w)\'|\'(?!\w)', sentence):
        return 'inline_code_or_nested_quote_ambiguity'
    if AMBIGUOUS.search(sentence):
        return 'ambiguous_abbreviation_boundary'
    if CONCLUSION.search(sentence):
        return 'explicit_conclusion_requires_context'
    if not FINITE.search(sentence) and not PERSONAL_VERB.search(flat(sentence)):
        return 'no_conservative_finite_clause_witness'
    return None


def build(packet, *, cited_urls=None):
    """Return exact spans, exclusions and a bounded enum without editing inputs."""
    original = copy.deepcopy(packet)
    result = {'policy': copy.deepcopy(POLICY), 'eligible_spans': [], 'choices': [], 'excluded': [],
              'semantic_grounding': 'NOT_DETERMINED', 'full_packet_required_for_later_verification': True}
    if packet.get('truncated') or packet.get('missing_sources'):
        result['disabled_reason'] = 'incomplete_packet_context'
        return result
    for source in packet['sources']:
        if cited_urls is not None and source.get('url') not in cited_urls:
            result['excluded'].append({'source_ref': source['id'], 'reason': 'uncited_source'})
            continue
        if any(RAW_MARKUP.search(p['text']) for p in source['passages']):
            result['excluded'].append({'source_ref': source['id'], 'reason': 'raw_html_or_taglike_source_context'})
            continue
        if PROCEDURAL.search(source.get('title', '')):
            result['excluded'].append({'source_ref': source['id'], 'reason': 'procedural_source_title'})
            continue
        opened, previous_group, procedural = None, None, False
        for index, passage in enumerate(source['passages']):
            ref, text = passage['id'], passage['text']
            key = group_key(passage)
            if index == 0:
                result['excluded'].append({'ref': ref, 'reason': 'source_title_not_body_sentence'})
                continue
            if key != previous_group:
                opened = None
                procedural = False
            previous_group = key
            blocked, opened = code_ranges(text, opened)
            marker = PROCEDURAL_HEADING.search(text)
            procedural_start = 0 if procedural else marker.start() if marker else None
            procedural = procedural or marker is not None
            boundaries = list(PARAGRAPH.finditer(text))
            # Never assume a packet-chunk edge is a full paragraph or sentence.
            for pos in range(len(boundaries) + 1):
                start = boundaries[pos - 1].end() if pos else 0
                end = boundaries[pos].start() if pos < len(boundaries) else len(text)
                raw = text[start:end]
                if not raw.strip():
                    continue
                base = {'ref': ref, 'start': start, 'end': end}
                if pos == 0 or pos == len(boundaries):
                    result['excluded'].append({**base, 'reason': 'unknown_chunk_edge_paragraph'})
                    continue
                if procedural_start is not None and end > procedural_start:
                    result['excluded'].append({**base, 'reason': 'procedural_section_context'})
                    continue
                if BLOCK.search(raw) or any(a < end and b > start for a, b in blocked):
                    result['excluded'].append({**base, 'reason': 'code_parent_quote_heading_list_table_or_template'})
                    continue
                if AMBIGUOUS.search(raw) or INITIAL.search(raw):
                    result['excluded'].append({**base, 'reason': 'ambiguous_abbreviation_paragraph'})
                    continue
                cursor = 0
                for terminator in END.finditer(raw):
                    left, right = cursor, terminator.end()
                    cursor = right
                    while left < right and raw[left].isspace():
                        left += 1
                    sentence = raw[left:right]
                    absolute = start + left
                    record = {'ref': ref, 'source_ref': source['id'], 'source_url': source['url'],
                              'start': absolute, 'end': start + right, 'raw': sentence,
                              'utf8_start': len(text[:absolute].encode()), 'utf8_end': len(text[:start + right].encode()),
                              'paragraph_start': start, 'paragraph_end': end, 'passage': text,
                              'author': passage.get('author'), 'created_at': passage.get('created_at')}
                    why = rejection(sentence)
                    if not why and 'unquoted_content' in source and flat(sentence) not in flat(source['unquoted_content']):
                        why = 'not_in_supplied_unquoted_content'
                    rendered = PREFIX + flat(sentence) + '”'
                    if not why and len(rendered) > POLICY['max_rendered_chars']:
                        why = 'rendered_sentence_exceeds_bound'
                    if not why and not preserves_rendered(rendered):
                        why = 'native_normalization_would_change_quote'
                    if why:
                        result['excluded'].append({**record, 'reason': why})
                    else:
                        assert text[record['start']:record['end']] == sentence
                        result['eligible_spans'].append({**record, 'rendered': rendered,
                            'admission': ['visible_internal_paragraph_boundaries', 'single_passage_exact_span',
                                          'complete_terminal_boundary', 'conservative_finite_clause_witness',
                                          'no_detected_code_parent_or_template', 'immutable_source_cited',
                                          'native_rendering_preserves_precomputed_string'],
                            'governing_context_and_later_corrections_checked': False,
                            'usefulness_checked': False})
                if raw[cursor:].strip():
                    result['excluded'].append({'ref': ref, 'start': start + cursor, 'end': end,
                                               'reason': 'unterminated_paragraph_tail'})
    total = 0
    by_rendered = {}
    for entry in result['eligible_spans']:
        rendered = entry['rendered']
        if rendered in by_rendered:
            by_rendered[rendered]['origins'].append({k: entry[k] for k in ('ref', 'start', 'end')})
            continue
        size = len(rendered.encode())
        if len(result['choices']) >= POLICY['max_choices'] or total + size > POLICY['aggregate_rendered_utf8_bytes']:
            result['excluded'].append({'ref': entry['ref'], 'start': entry['start'], 'end': entry['end'],
                                       'reason': 'predeclared_choice_or_aggregate_bound'})
            continue
        choice = {'rendered': rendered, 'origins': [{k: entry[k] for k in ('ref', 'start', 'end')}],
                  'semantic_grounding': 'NOT_DETERMINED'}
        result['choices'].append(choice);by_rendered[rendered] = choice;total += size
    result['enum_preview'] = ['', *by_rendered]
    result['rendered_utf8_bytes'] = total
    assert packet == original
    return result


def preserves_rendered(value):
    """Use the same field normalization as public rendering and attribution style."""
    return (render._text(value, FIELD_LIMITS['why_it_matters']) == value
            and personal_attribution.normalize_text(value) == value)


def available(candidate, packet, *, update=False):
    """Offer at most one quote transition; an existing quote gets keep or clear."""
    current = candidate.get('why_it_matters', '')
    if update or not current or current.startswith(PREFIX):
        return []
    return build(packet, cited_urls={s['url'] for s in candidate.get('sources', [])})['choices']


def validate_replacement(value, packet, candidate=None):
    """Check packet membership, and the exact current origin when it is available.

    Packet-only checks precede sequential replay; they never authorize a transition.
    """
    if packet is None or not isinstance(value, str):
        raise ValueError('Source quotation repair requires its bound packet')
    # A packet-only prepass cannot apply citation-dependent caps. Sequential
    # replay checks the actual cited catalog and the current nonempty origin.
    choices = (available(candidate, packet) if candidate is not None else build(packet)['eligible_spans'])
    if value not in {choice['rendered'] for choice in choices}:
        raise ValueError('Impact repair must select an available source quotation')


def validate_transition(original, updated, packet):
    """Unchanged writer prose and clearing remain valid; new text must be a quote."""
    before, after = original.get('why_it_matters', ''), updated.get('why_it_matters', '')
    if after != before and after != '':
        validate_replacement(after, packet, original)


def passages(choices, packet):
    """Expose complete governing passages once, without repeating them per span."""
    refs = {origin['ref'] for choice in choices for origin in choice['origins']}
    return {passage['id']: {**copy.deepcopy(passage), 'source_ref': source['id'], 'source_url': source['url'],
                            **{'source_' + key: source[key] for key in ('author', 'published_at') if key in source}}
            for source in packet['sources'] for passage in source['passages'] if passage['id'] in refs}


def used_in_review(record):
    """A durable quotation path still needs its proof after the quote is cleared."""
    proofs = [record]
    while proofs:
        proof = proofs.pop()
        if not isinstance(proof, dict):
            continue
        prepared = proof.get('prepared') or {}
        reviews = proof.get('reviews', [])
        if not isinstance(prepared, dict) or not isinstance(reviews, list):
            return True
        texts = [value.get('why_it_matters') for value in
                 (proof.get('candidate'), prepared.get('candidate')) if isinstance(value, dict)]
        for entry in reviews:
            result = entry.get('result') if isinstance(entry, dict) else None
            repair = result.get('repair') if isinstance(result, dict) else None
            if isinstance(repair, dict):
                texts.append(repair.get('why_it_matters'))
        if any(isinstance(text, str) and text.startswith(PREFIX) for text in texts):
            return True
        if isinstance(proof.get('approval'), dict):
            proofs.append(proof['approval'])
    return False
