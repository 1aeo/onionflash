"""Narrow literal-name absence checks; presence never proves attribution or identity."""
from __future__ import annotations

import re
import unicodedata
from typing import NamedTuple

from .util import safe_canonical_url


# Advance when extraction or source matching changes; review policy binds this.
NAMED_ATTRIBUTION_POLICY = {
    "version": 5, "normalization": "NFC-lower-whole-tokens-optional-at-and-organization-article", "maximum_name_words": 4,
    "patterns": "named-reporting-clause-or-according-to", "source_scope": "packet-text-unquoted-reply-author-and-sender-domain",
    "repair_context": "rematerialized-missing-name-literals",
}
_REPORTING = re.compile(
    r"\b(?:reports|reported|says|said|writes|wrote|states|stated|notes|noted|"
    r"claims|claimed|explains|explained|warns|warned|confirms|confirmed)\b"
    r"(?:\s+that\b|\s*[:,]|\s+[\"'“”‘’])", re.I)
_ACCORDING = re.compile(r"\baccording\s+to\s+", re.I)
_FENCE = re.compile(r"```.*?(?:```|\Z)", re.S)
_INLINE_CODE = re.compile(r"`([^`\n]*)`")
_EMPHASIS_PART = re.compile(r"```.*?(?:```|\Z)|`[^`\n]*`|\*+|_+", re.S)
_URL = re.compile(r"https?://\S+", re.I)
_DOCUMENT_REFERENCE = re.compile(r"(?:(?:IETF\s+)?RFC\s*[- ]?\d+\b|(?:CVE|TROVE)-\d{4}-\d+\b)", re.I)
_NARRATIVE_DASH = re.compile(r"—(?=\s*(?:[\"'“”‘’]|who\b))")
_GENERIC = frozenset("""a an the i we you he she it they this that these those one someone anyone
everyone nobody people authors author commenter commenters contributor contributors developer developers
maintainer maintainers operator operators reporter reporters researcher researchers team staff project
source sources report reports issue issues ticket tickets post posts thread threads comment comments
announcement announcements release releases note notes advisory advisories article articles blog document
documentation proposal proposals message messages email emails analysis research data evidence study studies
test tests log logs warning warnings code patch commit commits changes change software browser client clients
server servers service services relay relays authority authorities network results result update updates
description title summary body information work finding findings survey measurements measurement
application applications system systems tool tools program programs process processes package packages
library libraries account accounts website websites site sites page pages tracker trackers entry entries
notice notices newsletter newsletters webpage webpages component components module modules error errors
fault faults check checks function functions endpoint endpoints responder responders instance instances
earlier later previously recently meanwhile additionally finally today yesterday tomorrow now however
therefore still also separately in on at by from as during after before for to with without and but or
if when while although because since until unless according
merge merged pull request requests quote quotes quoted quoting new old
user users person persons member members participant participants reader readers witness witnesses
reviewer reviewers poster posters submitter submitters correspondent correspondents colleague colleagues
owner owners writer writers available provided supplied original initial latest recent current previous
public official published updated final first last name names named called
""".split())
_CONNECTORS = frozenset({"of", "the"})
_ORGANIZATION_WORDS = frozenset({"project", "foundation", "institute", "labs", "university", "group", "corporation", "network"})


def _normalized(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", value).lower().split())


class _Word(NamedTuple):
    value: str
    begin: int
    finish: int
    supported: bool

    def start(self):
        return self.begin

    def end(self):
        return self.finish


def _word_char(char: str) -> bool:
    return char == "_" or unicodedata.category(char)[0] in "LNM"


def _joiner(char: str) -> bool:
    return char in "'‘’.\"“”−-*" or unicodedata.category(char) == "Pd"


def _tokens(text: str) -> list[_Word]:
    """Keep lexical spans whole; unsupported joins never become name suffixes."""
    words, index = [], 0
    while index < len(text):
        char = text[index]
        if not (_word_char(char) or char == "@" or unicodedata.category(char) == "Cf"):
            index += 1
            continue
        start = index
        while index < len(text) and (_word_char(text[index]) or text[index] == "@"
                                     or _joiner(text[index]) or unicodedata.category(text[index]) == "Cf"):
            index += 1
        end = index
        while end > start and _joiner(text[end - 1]):
            end -= 1  # A sentence's period or closing quotation is not a name.
        value = text[start:end]
        body = value[1:] if value.startswith("@") else value
        supported = bool(body) and (value.startswith("@") or body[0].isalpha())
        for number, char in enumerate(body):
            if _word_char(char):
                continue
            if (char not in "'’.-" or number == 0 or number + 1 == len(body)
                    or not _word_char(body[number - 1]) or not _word_char(body[number + 1])):
                supported = False
        words.append(_Word(value, start, end, supported))
    return words


def _single_token(text: str) -> bool:
    words = _tokens(text)
    return bool(len(words) == 1 and words[0].supported and words[0].start() == 0 and words[0].end() == len(text))


def _numeric_boundary(word: _Word) -> bool:
    return word.value.isnumeric() or re.fullmatch(r"\d+(?:[._]\d+)*", word.value) is not None


def _emphasis_text(text: str, *, literal_tokens=()) -> str:
    """Remove balanced word-boundary emphasis, retaining code and literal handles."""
    # An exact supplied account token takes precedence over ambiguous italic
    # syntax. Preserve its entire lexical span, never an inferred alias.
    protected = {index for word in _tokens(text)
                 if _normalized(word.value).lstrip("@") in literal_tokens
                 for index in range(word.start(), word.end())}
    parts = list(_EMPHASIS_PART.finditer(text))
    opened, removed = [], set()
    previous = 0
    for index, part in enumerate(parts):
        marker = part[0]
        if "\n" in text[previous:part.start()]:
            opened.clear()
        previous = part.end()
        if marker.startswith("`"):
            opened.clear()
            continue
        if len(marker) > 3 or any(index in protected for index in range(part.start(), part.end())):
            continue
        before = text[part.start() - 1:part.start()]
        after = text[part.end():part.end() + 1]
        adjacent_open = bool(opened and opened[-1].end() == part.start())
        next_part = parts[index + 1] if index + 1 < len(parts) else None
        adjacent_close = (len(opened) > 1 and next_part is not None
                          and next_part.start() == part.end() and next_part[0] == opened[-2][0])
        can_open = bool(after and not after.isspace() and (adjacent_open or not before
                        or not (_word_char(before) or before in "@\\*_")))
        can_close = bool(before and not before.isspace() and (adjacent_close or not after
                         or not (_word_char(after) or after in "@\\*_")))
        if can_close and opened and opened[-1][0] == marker:
            opening = opened.pop()
            removed.update(range(opening.start(), opening.end()))
            removed.update(range(part.start(), part.end()))
        elif can_open:
            opened.append(part)
    return "".join(char for index, char in enumerate(text) if index not in removed)


def _literal_present(name: str, text: str, *, literal_tokens=()) -> bool:
    """Match whole lexical spans, including marks and numeric dotted handles."""
    wanted = [_normalized(word.value).lstrip("@") for word in _tokens(_normalized(name))]
    # A clear narrative aside/quotation is prose punctuation, not a compound
    # name. Keep this narrower than arbitrary dash normalization, and do not
    # apply it to author/account metadata.
    source = _normalized(_NARRATIVE_DASH.sub(" ", _emphasis_text(text, literal_tokens=literal_tokens)))
    words = _tokens(source)
    def literal(word):
        value = word.value.lstrip("@")
        return value[:-2] if value.endswith(("'s", "’s")) else value
    for start in range(len(words) - len(wanted) + 1):
        selected = words[start:start + len(wanted)]
        if (wanted and [literal(word) for word in selected] == wanted
                and all(not source[left.end():right.start()].strip() for left, right in zip(selected, selected[1:]))):
            return True
    return False


def _organization_name(name: str) -> str:
    value = _normalized(name).lstrip("@")
    if value.startswith("the ") and value.rsplit(" ", 1)[-1] in _ORGANIZATION_WORDS:
        return value[4:]
    return value


def _name_word(value: str) -> bool:
    plain = value.lstrip("@")
    if not plain:
        return False
    if value.startswith("@"):
        return True
    if plain.casefold() in _GENERIC or plain.lower().endswith(("'s", "’s")):
        return False
    first = plain[0]
    return first.isupper() or (not first.isascii() and first.isalpha() and first.lower() == first.upper())


def _names(text: str, *, literal_tokens=()) -> list[str]:
    # Code examples are not speaker attributions. Quoted prose remains a claim
    # and is checked; a quotation cannot create source evidence for its speaker.
    text = _FENCE.sub(lambda match: " " * len(match[0]), unicodedata.normalize("NFC", text))
    text = _emphasis_text(text, literal_tokens=literal_tokens)
    text = _INLINE_CODE.sub(lambda match: " " + match[1] + " " if _single_token(match[1])
                            else " " * len(match[0]), text)
    # Quoting or styling a name does not remove its attribution. Keep internal
    # apostrophes in names while treating surrounding quotation marks as markup.
    triggers = text  # Reporting verbs still need their direct-speech delimiter.
    text = "".join(" " if char in "\"'“”‘’" and not (
        index > 0 and index + 1 < len(text) and _word_char(text[index - 1]) and _word_char(text[index + 1]))
        else char for index, char in enumerate(text))
    words = _tokens(text)
    found = []
    for verb in _REPORTING.finditer(triggers):
        prior = [word for word in words if word.end() <= verb.start()]
        if (not prior or not prior[-1].supported or text[prior[-1].end():verb.start()].strip()
                or not (_name_word(prior[-1][0]) or prior[-1][0].casefold() in _ORGANIZATION_WORDS)):
            continue
        selected = [prior[-1]]
        for word in reversed(prior[:-1]):
            if text[word.end():selected[0].start()].strip():
                break
            if not word.supported:
                if not _numeric_boundary(word):
                    selected = []
                break
            if len(selected) >= NAMED_ATTRIBUTION_POLICY["maximum_name_words"]:
                if _name_word(word[0]) or word[0].casefold() in _ORGANIZATION_WORDS:
                    selected = []  # Do not turn a long name into a guessed suffix.
                break
            if not (_name_word(word[0]) or word[0].casefold() in _ORGANIZATION_WORDS or word[0].casefold() in _CONNECTORS):
                break
            selected.insert(0, word)
        while selected and selected[0][0].casefold() in _CONNECTORS:
            selected.pop(0)
        if selected:
            prefix = [word for word in prior if word.end() <= selected[0].start()]
            article = (prefix and prefix[-1][0].casefold() in {"a", "an", "the"}
                       and not text[prefix[-1].end():selected[0].start()].strip())
            if article and selected[-1][0].casefold() not in _ORGANIZATION_WORDS:
                continue
        if selected and not _DOCUMENT_REFERENCE.match(text, selected[0].start()) and any(_name_word(word[0]) for word in selected):
            found.append(text[selected[0].start():selected[-1].end()])
    for marker in _ACCORDING.finditer(text):
        following = [word for word in words if word.start() >= marker.end()]
        article = bool(following and following[0][0].casefold() == "the")
        if article:
            following = following[1:]
        if (not following or not following[0].supported or not _name_word(following[0][0])
                or _DOCUMENT_REFERENCE.match(text, following[0].start())):
            continue
        selected = [following[0]]
        for word in following[1:]:
            if text[selected[-1].end():word.start()].strip():
                break
            if not word.supported:
                if not _numeric_boundary(word):
                    selected = []
                break
            if len(selected) >= NAMED_ATTRIBUTION_POLICY["maximum_name_words"]:
                if _name_word(word[0]) or word[0].casefold() in _ORGANIZATION_WORDS:
                    selected = []
                break
            if not (_name_word(word[0]) or word[0].casefold() in _ORGANIZATION_WORDS or word[0].casefold() in _CONNECTORS):
                break
            selected.append(word)
        while selected and selected[-1][0].casefold() in _CONNECTORS:
            selected.pop()
        if article and selected and selected[-1][0].casefold() not in _ORGANIZATION_WORDS:
            continue
        if selected:
            found.append(text[selected[0].start():selected[-1].end()])
    return list(dict.fromkeys(found))


def _evidence(packet: dict, cited: set[str] | None):
    for source in packet.get("sources", []):
        whole = cited is None or safe_canonical_url(source.get("url")) in cited
        if whole:
            for field in ("title", "unquoted_content", "author", "sender_domain"):
                if isinstance(source.get(field), str):
                    yield source[field], field in {"author", "sender_domain"}
        for passage in source.get("passages", []):
            if not whole and safe_canonical_url(passage.get("url")) not in cited:
                continue
            for field in ("text", "author"):
                if isinstance(passage.get(field), str):
                    yield passage[field], field == "author"


def missing_named_attributions(candidate: dict, packet: dict, *, update: bool = False,
                               known_names=()) -> list[dict]:
    """Flag only recognized named clauses whose literal name is absent from source.

    No candidate, prior story, authority label, URL or configured source name is
    identity evidence. No fuzzy spelling, transliteration, or alias guessing is
    performed. Names and explicit aliases already written in supplied text may
    match, but a match does not prove who made a statement or authorize publication.
    """
    if not isinstance(candidate, dict):
        return []  # A locked or not-yet-prepared item has no publication text.
    if update:
        latest = candidate.get("updates", [])[-1:] or [{}]
        targets = [("updates[-1].text", latest[0].get("text", ""))]
        cited = {url for entry in latest[0].get("sources", []) if (url := safe_canonical_url(entry.get("url")))}
    else:
        targets = [(field, candidate.get(field, "")) for field in ("title", "summary", "why_it_matters")]
        cited = None
    evidence = [(_URL.sub(" ", text), author) for text, author in _evidence(packet, cited)]
    literal_tokens = frozenset(_normalized(text).lstrip("@") for text, author in evidence
                               if author and "_" in text)
    def supported(name):
        return any(_organization_name(source) == _organization_name(name) if author else _literal_present(name, source, literal_tokens=literal_tokens)
                   for source, author in evidence)

    retained = [name for name in known_names if not supported(name)]
    flags = []
    for field, text in targets:
        names = _names(text, literal_tokens=literal_tokens)
        # Names already found absent in an observed candidate cannot survive a
        # repair merely by changing case, grammar, quoting, code style, or field.
        names += [name for name in retained if _literal_present(name, text, literal_tokens=literal_tokens)]
        seen = set()
        for name in names:
            if _normalized(name).lstrip("@") in seen:
                continue
            seen.add(_normalized(name).lstrip("@"))
            if not supported(name):
                flags.append({"field": field, "name": name, "finding": "literal_name_absent_from_source"})
    return flags
