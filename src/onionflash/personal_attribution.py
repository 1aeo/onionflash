"""Names-only narrator attribution, with bounded edits before review.

This is publication style, never evidence of a person's identity or occupation.
Only literal names in a narrow attribution grammar are edited. Unresolved
personal role clauses remain intact for the existing review/hold boundary.
"""
from __future__ import annotations

import copy
import re

from .named_attribution import _tokens, _GENERIC, _ORGANIZATION_WORDS

PERSONAL_ATTRIBUTION_POLICY = {
    'version': 6, 'style': 'names-only-personal-attribution',
    'grammar': 'role-name-action-or-comma-appositive', 'maximum_name_words': 4,
    'preserve': 'quotes-code-negation-events-organizations-audiences-readonly-history',
    'unresolved': 'hold-without-postapproval-edit', 'anonymous': 'preserve-source-checked-operational-functions-and-groups',
}
_ROLES = r'(?:developers?|maintainers?|operators?|researchers?|engineers?|contributors?|reporters?|senders?)'
_QUALIFIER = r'(?:C[ -]Tor|Tor(?:\s+Project)?|Arti|relay|directory[ -]authority|core|lead|senior|security)'
_ROLE = re.compile(r'(?<![\w@])(?:(?:an?|the)\s+)?(?:' + _QUALIFIER + r'\s+){0,3}' + _ROLES + r'\b', re.I)
_ACTION = re.compile(r'\b(?:reports?|reported|says?|said|writes?|wrote|states?|stated|notes?|noted|'
                     r'claims?|claimed|explains?|explained|warns?|warned|confirms?|confirmed|'
                     r'asks?|asked|requests?|requested|calls?|called|names?|named|advises?|advised|alleges?|alleged|disputes?|disputed|posts?|posted|provides?|provided|publishes|published|'
                     r'finds?|found|discovers?|discovered|discloses?|disclosed|announces?|announced|'
                     r'closes?|closed|reviews?|reviewed|compares?|compared|describes?|described|'
                     r'comments?|commented|responds?|responded|argues?|argued|declines?|declined)\b', re.I)
_NAMED_ACTION = re.compile(_ACTION.pattern + r'|\b(?:is|are|was|were|has|have|had)\b', re.I)
_BASE_ACTIONS = frozenset('report say write state note claim explain warn confirm ask request call name advise allege dispute post provide find discover disclose announce close review compare describe comment respond argue decline'.split())
_NONPERSON = _GENERIC | _ORGANIZATION_WORDS | frozenset({
    'tools', 'tooling', 'relations', 'experience', 'documentation', 'handbook', 'guide',
    'manual', 'mode', 'who', 'which', 'so', 'error', 'errors', 'access', 'support', 'portal', 'committee', 'association',
})
_NEGATION = re.compile(r'\b(?:not|never|no|without|neither|nor)\b', re.I)
_EVENT = re.compile(r'\b(?:retir\w*|appoint\w*|elect\w*|resign\w*|replace\w*|succeed\w*|'
                    r'becom\w*|became|hire\w*|recruit\w*|seek\w*|sought|serv\w*)\b', re.I)
_PARTS = re.compile(r'```[^\n]*\n.*?(?:```|\Z)|~~~[^\n]*\n.*?(?:~~~|\Z)|`+[^`\n]*`+|\*+|_+', re.S)
# A complete ASCII quote may span soft lines, but cannot pair across a
# paragraph or a fenced/indented code boundary. An incomplete quote fragment
# remains protected and makes other proposed edits conservative.
_QUOTE_BOUNDARY = r'(?:\r\n|\r(?!\n)|\n)(?:[ \t]*(?:\r\n|\r(?!\n)|\n)| {4}|\t)|```|~~~'
_QUOTE = re.compile(
    r'"(?:(?!' + _QUOTE_BOUNDARY + r')[^"])*"|"[^"\r\n]*(?=$|[\r\n])'
    r'|“[^”]*(?:”|$)|‘[^’]*(?:’|$)|(?<!\w)\'(?:(?!' + _QUOTE_BOUNDARY + r')[^\'])*\'(?!\w)')
_QUOTE_DELIMITERS = frozenset("\"'“”‘’")
_METADATA_SENDER = re.compile(r'(?<![\w@])(?:(?:a|an|the)\s+)?(?:project[- ]senders?|(?:Tor(?:\s+Project)?|official|trusted)[- ]senders?)\b', re.I)
_ROLE_RELATIVE = re.compile(r'(?:(?:who\s+)?(?:is|was|identifies\s+as|identified\s+as|is\s+identified\s+as|was\s+identified\s+as))\s*', re.I)

# The policy binds the literal grammar too, so changing its recognized forms
# cannot accidentally reuse approvals from the prior grammar.
PERSONAL_ATTRIBUTION_POLICY.update(patterns={
    'role': _ROLE.pattern, 'action': _ACTION.pattern, 'named_action': _NAMED_ACTION.pattern,
    'negation': _NEGATION.pattern, 'event': _EVENT.pattern, 'markup': _PARTS.pattern, 'quote': _QUOTE.pattern,
    'metadata_sender': _METADATA_SENDER.pattern, 'role_relative': _ROLE_RELATIVE.pattern,
}, nonperson_tokens=sorted(_NONPERSON), base_actions=sorted(_BASE_ACTIONS),
    clause_boundaries='punctuation-and-but-while-whereas', unnamed_nouns='finite-verb-and-predicate-continuation',
    qualified_collectives='project-qualified-plural-without-named-person',
    neutral_references='unqualified-anaphoric-reporter-sender',
    name_introducers='named-called-known-as-before-finite-action', leading_modifiers='hold-when-unmatched',
    protected_edit_spans='reject-all-crossing-edits-and-incomplete-quote-ambiguity',
    quote_delimiters=sorted(_QUOTE_DELIMITERS), quote_search='mask-only-delimiters-in-protected-spans',
    issue_locations='literal-current-field-codepoint-spans', anonymous_functions='operator-maintainer-without-attached-name')


def _view(text: str):
    """Return prose projection, offsets, emphasis, and protected quote/code spans."""
    protected = set()
    for match in _PARTS.finditer(text):
        if match[0].startswith(('`', '~')):
            protected.update(range(match.start(), match.end()))
    for match in re.finditer(r'(?m)^(?:[ \t]*>| {4}|\t)[^\n]*', text):
        protected.update(range(match.start(), match.end()))
    # Quotes inside code/blockquote cannot open or close a prose quotation.
    # Mask only delimiters: original offsets, newlines and fence boundaries stay
    # intact, and all actual edits still use the untouched original text.
    quote_projection = ''.join(' ' if index in protected and char in _QUOTE_DELIMITERS else char
                               for index, char in enumerate(text))
    incomplete_quote = False
    for match in _QUOTE.finditer(quote_projection):
        if match.start() in protected:
            continue  # A quote inside code/blockquote is not a prose delimiter.
        if match[0].startswith('"') and (len(match[0]) == 1 or not match[0].endswith('"')):
            incomplete_quote = True
        protected.update(range(match.start(), match.end()))
    opened, pairs = [], []
    previous = 0
    for part in _PARTS.finditer(text):
        if re.search(r'\n[ \t]*\n', text[previous:part.start()].replace('\r\n', '\n').replace('\r', '\n')):
            opened.clear()
        previous = part.end()
        token = part[0]
        if token.startswith(('`', '~')) or any(i in protected for i in range(part.start(), part.end())):
            opened.clear()
            continue
        if len(token) > 3:
            continue
        before, after = text[part.start()-1:part.start()] if part.start() else '', text[part.end():part.end()+1]
        # Underscores within lexical handles are literal, not emphasis.
        can_open = bool(after and not after.isspace() and (not before or not (before.isalnum() or before in '@_\\')))
        can_close = bool(before and not before.isspace() and (not after or not (after.isalnum() or after in '@_\\')))
        if can_close and opened and opened[-1][0] == token:
            pairs.append((opened.pop(), part))
        elif can_open:
            opened.append(part)
    markers = {i for a,b in pairs for m in (a,b) for i in range(m.start(),m.end())}
    offsets = [i for i in range(len(text)) if i not in markers]
    plain = ''.join(' ' if i in protected else text[i] for i in offsets)
    return plain, offsets, pairs, protected, incomplete_quote


def _person(value: str) -> bool:
    """Require a whole literal name/list; never guess a suffix or expand a handle."""
    alias = re.fullmatch(r'(.+?)\s+\((@[^()\s]+)\)', value)
    if alias:
        handle = _tokens(alias[2])
        return bool(_person(alias[1]) and len(handle) == 1 and handle[0].supported)
    words = _tokens(value)
    if not words or value[:words[0].start()].strip() or value[words[-1].end():].strip():
        return False
    count, group = 0, 0
    for i,word in enumerate(words):
        gap = value[words[i-1].end():word.start()] if i else ''
        if gap.strip() not in {'', ','} or not word.supported:
            return False
        token = word.value.lstrip('@')
        if token.casefold() == 'and':
            if count == 0:
                return False
            group += 1; count = 0
            continue
        if (not word.value.startswith('@') and token.casefold() in _NONPERSON) or token.lower().endswith(("'s", '’s')):
            return False
        if count and not (token[0].isupper() or not token[0].isascii() or word.value.startswith('@')):
            return False
        count += 1
        if count > PERSONAL_ATTRIBUTION_POLICY['maximum_name_words'] or group > 2:
            return False
    return count > 0


def _unmatched_modifier(context: str, role: str) -> bool:
    """Do not leave an unmatched article/adjective attached to the kept name."""
    if re.search(r"['’]s\s*$", context):
        return True
    if re.match(r'(?:a|an|the)\s+', role, re.I):
        return False
    prefix = re.search(r'\b(?:a|an|the)\s+(?P<extra>(?:[\w-]+\s+){1,4})$', context, re.I)
    if prefix and not _ACTION.search(prefix['extra']) and not re.search(r'\b(?:to|from|by|with|on|in|of|for)\b', prefix['extra'], re.I):
        return True
    word = context.strip()
    if re.fullmatch(r'\d+|one|two|three|four|five|six|seven|eight|nine|ten|both|several|many|few|some|all', word, re.I):
        return False
    return bool(re.fullmatch(r'[\w-]+', word) and word.casefold() not in _NONPERSON)


def _clauses(text: str):
    plain, offsets, pairs, protected, incomplete_quote = _view(text)
    edits, unresolved = [], []
    # Authority classifications are not substitute people. This only locates
    # actor-shaped uses; quoted/code labels remain protected by the projection.
    for label in _METADATA_SENDER.finditer(plain):
        context = re.split(r'[.!?;,\n]|\b(?:and|but|while|whereas)\b', plain[:label.start()], flags=re.I)[-1]
        if _NEGATION.search(context) or _EVENT.search(context):
            continue
        following = plain[label.end():]
        action = _ACTION.search(following[:160])
        before_action = following[:action.start()].strip() if action else None
        if (action and (not before_action or _person(before_action) or re.fullmatch(r',\s*', before_action))
                or re.match(r"['’]s\b", following)):
            unresolved.append((label.start(), label.end()))
    for role in _ROLE.finditer(plain):
        left = plain[:role.start()]
        context = re.split(r'[.!?;,\n]|\b(?:and|but|while|whereas)\b', left, flags=re.I)[-1]
        if _NEGATION.search(context) or _EVENT.search(context):
            continue
        tail = plain[role.end():]
        boundary = re.search(r'\n[ \t]*\n|[.!?;](?=\s|$)', tail)
        if boundary:
            tail = tail[:boundary.start()]
        modal = re.match(r'\s*(should|must|may|might|can|could|will|would|need|have|has)\b\s*', tail, re.I)
        if modal:
            following = _ACTION.match(tail, modal.end())
            # Title-cased words can be literal names. A following finite verb
            # distinguishes that narrow name form from a modal plus base verb.
            named = (modal[1][0].isupper() and not modal[1].isupper() and following
                     and following[0].lower() not in _BASE_ACTIONS)
            if not named:
                continue
        action = _ACTION.search(tail[:160])
        # Reporter/sender without a named person are neutral source references,
        # not occupational titles; preserve their distinction in disagreements.
        if re.fullmatch(r'(?:(?:a|an|the)\s+)?(?:reporter|sender)', role[0], re.I) and action and not tail[:action.start()].strip():
            continue
        named_action = _NAMED_ACTION.search(tail[:160])
        # Resolve a role attached to a literal personal subject before handling
        # anonymous functional descriptions. Unknown modifiers stay intact for
        # repair; deleting arbitrary qualifiers could erase an actual fact.
        opening = re.search(r',(?P<prefix>[^,;.!?]*)$', left)
        closing = re.match(r'\s*,\s*', tail)
        if opening and closing and _NAMED_ACTION.match(tail, closing.end()):
            subject = re.split(r'[.!?;]', left[:opening.start()])[-1].strip()
            prefix = opening['prefix'].strip()
            if _person(subject):
                if not prefix or _ROLE_RELATIVE.fullmatch(prefix):
                    edits.append((opening.start(), role.end()+closing.end()-1, ''));continue
                if re.match(r'(?:a|an|the)\b', prefix) or _ROLE_RELATIVE.match(prefix):
                    # Relative actions involving another person are not a role
                    # appositive: e.g. a person who interviewed an operator.
                    if not re.search(r'\b(?:who|which|that|by|to|from|with|for|of)\b', prefix, re.I):
                        unresolved.append((opening.start(), role.end()+closing.end()));continue
                    if _ROLE_RELATIVE.match(prefix):
                        unresolved.append((opening.start(), role.end()+closing.end()));continue
        # Do not delete the complement of a role predicate or only the noun
        # after a temporal qualifier: either change would corrupt its meaning.
        pred = re.search(r'(?P<name>[^.!?;\n,]+?)\s+(?:is|was|identifies\s+as|identified\s+as|is\s+identified\s+as|was\s+identified\s+as|describes\s+\w+\s+as)\s*$', left, re.I)
        if pred and (_person(pred['name'].strip()) or re.search(r'\bwho\s+(?:is|was|identifies\s+as)\s*$', left, re.I)):
            unresolved.append((role.start(),role.end()));continue
        if re.search(r'\b(?:former|former[ -]time|acting|interim|alleged|self-described)\s*$', context, re.I):
            unresolved.append((role.start(),role.end()));continue
        # A role-like word within a multiword proper organization title is not
        # an anonymous person. Do not infer its identity from capitalization.
        if role[0][0].isupper() and re.search(r'(?:[A-Z][\w-]*\s+){2,}$', context):
            continue
        introducer = re.match(r'\s*(?:named|called|known\s+as)\s+', tail, re.I)
        if introducer:
            following = _NAMED_ACTION.search(tail, introducer.end())
            name = tail[introducer.end():following.start()].strip() if following else ''
            if following and _person(name) and not _unmatched_modifier(context, role[0]):
                middle = tail[introducer.end():following.start()]
                end = role.end() + introducer.end() + len(middle) - len(middle.lstrip())
                edits.append((role.start(),end,''));continue
            # Without a subsequent finite action, called/named can be the
            # anonymous person's actual verb. Keep it and its object intact;
            # only the anonymous role may become person/people below.
            if following or not re.match(r'\s*(?:called|named)\b', tail, re.I):
                unresolved.append((role.start(),role.end()));continue
        if re.search(r'\baccording\s+to\s*$', context, re.I):
            name = re.split(r'[,;.!?]', tail, maxsplit=1)[0].strip()
            if _person(name):
                end = role.end() + len(tail) - len(tail.lstrip())
                edits.append((role.start(),end,''));continue
            unresolved.append((role.start(),role.end()));continue
        if re.search(r'\b(?:by|from|to|with)\s*$', context, re.I):
            name = re.split(r'[;.!?]', tail, maxsplit=1)[0].strip()
            if _person(name):
                end = role.end() + len(tail) - len(tail.lstrip())
                edits.append((role.start(),end,''));continue
        if re.search(r'(?:operators?|maintainers?)$', role[0], re.I) and re.match(r'\s+of\s+', tail, re.I):
            relation = tail[:named_action.start()] if named_action else tail
            if named_action and named_action[0].casefold() in {'is', 'are', 'was', 'were'}:
                complement = tail[named_action.end():].strip()
                words = _tokens(complement)
                literal_name = bool(words and (words[0].value.startswith('@') or words[0].value[0].isupper()
                                               or not words[0].value[0].isascii()))
                if (literal_name and _person(complement) and not _NEGATION.search(complement)
                        and not _EVENT.search(complement)):
                    # Keep the relationship and identity assertion intact: a
                    # name-only rewrite could guess which entity is the person.
                    unresolved.append((role.start(), role.end()+len(tail)));continue
            if opening:
                subject = re.split(r'[.!?;]', left[:opening.start()])[-1].strip()
                prefix = opening['prefix'].strip()
                role_description = (not prefix or _ROLE_RELATIVE.fullmatch(prefix)
                                    or re.match(r'(?:a|an|the)\b', prefix)
                                    and not re.search(r'\b(?:who|which|that|by|to|from|with|for|of)\b', prefix, re.I))
                if _person(subject) and role_description:
                    unresolved.append((opening.start(), role.end()+len(relation)));continue
            named_after = re.fullmatch(r'\s*of\s+[^,;()]+,\s*(.+?),\s*', relation, re.I)
            if named_after and _person(named_after[1].strip()):
                unresolved.append((role.start(), role.end()+len(relation)));continue
            if not re.search(r'[,()]|\b(?:named|called|known\s+as)\b', relation, re.I):
                continue  # Preserve the anonymous entity/function relationship.
        # Parenthetical/dash appositives are recognized, but left intact for
        # bounded model repair rather than attempting punctuation surgery.
        if re.search(r'[(—–]\s*$', left) and re.match(r'\s*[)—–]', tail):
            unresolved.append((role.start(),role.end()));continue
        postnominal = re.search(r'(?P<name>[^.!?;\n,]+?)\s*$', left)
        if re.match(r'the\s+', role[0], re.I) and postnominal and _person(postnominal['name'].strip()):
            unresolved.append((role.start(),role.end()));continue
        # Prefix: "a relay operator <literal person> reports ...".
        if named_action:
            middle = tail[:named_action.start()]
            role_list = _ROLE.sub('', middle)
            if _ROLE.search(middle) and not re.sub(r'\b(?:and|or)\b|[,\s]', '', role_list, flags=re.I):
                continue  # A coordinated role audience is not a named person.
            name = middle.strip()
            if _person(name):
                if _unmatched_modifier(context, role[0]):
                    unresolved.append((role.start(),role.end()));continue
                if re.search(r'\b(?:\d+|one|two|three|four|both|several|many)\s*$', context, re.I):
                    unresolved.append((role.start(),role.end()));continue
                start = role.start();end = role.end() + len(middle) - len(middle.lstrip())
                # End immediately before the name, including intervening whitespace.
                edits.append((start,end,''));continue
        if action and not tail[:action.start()].strip():
            gap = text[offsets[role.end()-1]+1:offsets[role.end()+action.start()]]
            if gap.strip():
                unresolved.append((role.start(),role.end()));continue
            if re.search(r'\band\s*$', context, re.I):
                unresolved.append((role.start(),role.end()));continue
            if re.search(r'(?:operators?|maintainers?)$', role[0], re.I):
                continue  # Anonymous operational references are not personal titles.
            # Other anonymous reporting keeps its number and determiner; no name,
            # source identity, or organizational authority is inferred.
            plural = re.search(r'(?:developers|maintainers|operators|researchers|engineers|contributors|reporters|senders)$', role[0], re.I)
            if plural and re.search(r'\b(?:C[ -]Tor|Tor(?:\s+Project)?|Arti)\b', role[0], re.I):
                continue  # Keep project-qualified collective attribution literal.
            # Noun phrases such as "operator note" or "operator reports show"
            # do not identify a person performing the reporting action.
            if (not plural and action[0].lower() in _BASE_ACTIONS
                    or re.match(r'\s+(?:is|are|was|were|show|shows|suggest|suggests|contain|contains|include|includes|confirm|confirms)\b', tail[action.end():], re.I)):
                continue
            if _unmatched_modifier(context, role[0]):
                unresolved.append((role.start(),role.end()));continue
            article = re.match(r'(a|an|the)\s+', role[0], re.I)
            neutral = 'people' if plural else 'person'
            if article:
                determiner = article[1]
                neutral = ('a' if determiner.lower() == 'an' else determiner) + ' ' + neutral
            elif not plural and (not context.strip() or context.strip().lower() in {'according to'}):
                neutral = 'a person'
            if role[0][0].isupper():
                neutral = neutral[0].upper() + neutral[1:]
            edits.append((role.start(),role.end(),neutral));continue
        # Appositive: "<literal person>, a developer, reports ...".
        comma = re.search(r',\s*$', left)
        after = re.match(r'\s*,\s*', tail)
        if comma and after:
            subject = re.split(r'[.!?;\n]', left[:comma.start()])[-1].strip()
            if _person(subject) and _NAMED_ACTION.match(tail, after.end()):
                edits.append((comma.start(), role.end()+after.end()-1,''));continue
        # A role that is only an audience/object/event is not narrator attribution.
        # Recognized standalone personal role assertions cannot become "Name.".
        pred = re.search(r'(?P<name>[^.!?;\n,]+?)\s+(?:is|was|identifies\s+as|identified\s+as|is\s+identified\s+as|was\s+identified\s+as|describes\s+\w+\s+as)\s*$', left, re.I)
        if pred and _person(pred['name'].strip()):
            unresolved.append((role.start(),role.end()));continue
        if named_action and not re.search(r'[.!?;]', tail[:named_action.start()]) and not re.match(r'\s*(?:should|must|may|might|can|could|will|would|need|have|has)\b', tail, re.I):
            between = tail[:named_action.start()].strip()
            tokens = _tokens(between)
            name_like = bool(tokens and all(w.value.lstrip('@').casefold() not in _NONPERSON or w.value.casefold() in {'and','or'} for w in tokens))
            if name_like or _ROLE.search(between):
                unresolved.append((role.start(),role.end()))
        elif not named_action:
            # A literal-looking personal prefix is still recognized when the
            # following verb is outside the safe edit grammar. Do not silently
            # approve the role just because a verb was not enumerated.
            words = _tokens(tail)
            if words and words[0].supported:
                first = words[0].value.lstrip('@')
                looks_named = (words[0].value.startswith('@') or first[0].isupper()
                               or not first[0].isascii()
                               or len(words) > 1 and words[1].value.lower().endswith('ed'))
                if looks_named and (words[0].value.startswith('@') or first.casefold() not in _NONPERSON):
                    unresolved.append((role.start(),role.end()))
    safe_edits = []
    for start, end, replacement in edits:
        if incomplete_quote or any(index in protected for index in offsets[start:end]):
            unresolved.append((start, end))
        else:
            safe_edits.append((start, end, replacement))
    return plain,offsets,pairs,safe_edits,unresolved


def normalize_text(text: str) -> str:
    """Remove only safe attribution labels; leave ambiguous text for review/hold."""
    plain,offsets,pairs,edits,unresolved = _clauses(text)
    if unresolved:
        return text  # Never partially rewrite an ambiguous personal subject.
    removed = {offsets[i] for start,end,_ in edits for i in range(start,end)}
    inserted = {offsets[start]:value for start,_,value in edits if value}
    if not removed:
        return text
    # Remove an emphasis pair only when all its content was removed. Otherwise
    # preserve it around the surviving literal name, including split styling.
    for opening,closing in pairs:
        content = [i for i in range(opening.end(),closing.start()) if not text[i].isspace()]
        if content and all(i in removed for i in content):
            removed.update(range(opening.start(),opening.end()));removed.update(range(closing.start(),closing.end()))
    result = ''.join(inserted.get(i,'') + (ch if i not in removed else '') for i,ch in enumerate(text))
    return result


def unresolved_text(text: str) -> bool:
    """A normalizable or recognized uneditable personal-role clause remains."""
    *_, edits, unresolved = _clauses(text)
    return bool(edits or unresolved)


def normalize(candidate: dict, *, update: bool = False) -> dict:
    result = copy.deepcopy(candidate)
    if update:
        if result.get('updates'):
            result['updates'][-1]['text'] = normalize_text(result['updates'][-1]['text'])
    else:
        for key in ('title','summary','why_it_matters'):
            if isinstance(result.get(key),str):
                result[key] = normalize_text(result[key])
    return result


def issues(candidate: dict, *, update: bool = False) -> list[dict]:
    """Literal current-field forms with code-point offsets, never source evidence."""
    fields = [('updates[-1].text', candidate['updates'][-1]['text'])] if update and candidate.get('updates') else [] if update else [(key, candidate.get(key, '')) for key in ('title', 'summary', 'why_it_matters')]
    found = []
    for field, text in fields:
        _, offsets, _, edits, unresolved = _clauses(text)
        spans = set(unresolved) | {(start, end) for start, end, _ in edits}
        for start, end in sorted(spans):
            if 0 <= start < end <= len(offsets):
                begin, finish = offsets[start], offsets[end-1] + 1
                found.append({'field': field, 'start': begin, 'end': finish, 'text': text[begin:finish]})
    return found


def unresolved(candidate: dict, *, update: bool = False) -> bool:
    return bool(issues(candidate, update=update))
