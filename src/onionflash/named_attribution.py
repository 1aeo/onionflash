"""Narrow literal-name absence checks; presence never proves attribution or identity."""
from __future__ import annotations

import re
import unicodedata

from .util import safe_canonical_url


# Advance when extraction or source matching changes; review policy binds this.
NAMED_ATTRIBUTION_POLICY = {
    "version": 1, "normalization": "NFC-lower-whitespace-optional-leading-at", "maximum_name_words": 4,
    "patterns": "named-reporting-clause-or-according-to", "source_scope": "packet-text-and-author-only",
    "repair_context": "rematerialized-missing-name-literals",
}
_TOKEN = re.compile(r"(?<![\w@])(?:@\w+|[^\W\d_]\w*)(?:['’.-][^\W_]\w*)*", re.UNICODE)
_REPORTING = re.compile(
    r"\b(?:reports|reported|says|said|writes|wrote|states|stated|notes|noted|"
    r"claims|claimed|explains|explained|warns|warned|confirms|confirmed)\b"
    r"(?:\s+that\b|\s*[:,]|\s+[\"“‘])", re.I)
_ACCORDING = re.compile(r"\baccording\s+to\s+", re.I)
_FENCE = re.compile(r"```.*?(?:```|\Z)", re.S)
_INLINE_CODE = re.compile(r"`([^`\n]*)`")
_URL = re.compile(r"https?://\S+", re.I)
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


def _names(text: str) -> list[str]:
    # Code examples are not speaker attributions. Quoted prose remains a claim
    # and is checked; a quotation cannot create source evidence for its speaker.
    text = _FENCE.sub(lambda match: " " * len(match[0]), unicodedata.normalize("NFC", text))
    text = _INLINE_CODE.sub(lambda match: " " + match[1] + " " if _TOKEN.fullmatch(match[1])
                            else " " * len(match[0]), text)
    # Quoting or styling a name does not remove its attribution. Keep internal
    # apostrophes in names while treating surrounding quotation marks as markup.
    text = re.sub(r'["“”]|(?<!\w)[\'‘’]|[\'‘’](?!\w)', " ", text)
    words = list(_TOKEN.finditer(text))
    found = []
    for verb in _REPORTING.finditer(text):
        prior = [word for word in words if word.end() <= verb.start()]
        if (not prior or text[prior[-1].end():verb.start()].strip()
                or not (_name_word(prior[-1][0]) or prior[-1][0].casefold() in _ORGANIZATION_WORDS)):
            continue
        selected = [prior[-1]]
        for word in reversed(prior[:-1]):
            if text[word.end():selected[0].start()].strip():
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
        if selected and any(_name_word(word[0]) for word in selected):
            found.append(text[selected[0].start():selected[-1].end()])
    for marker in _ACCORDING.finditer(text):
        following = [word for word in words if word.start() >= marker.end()]
        article = bool(following and following[0][0].casefold() == "the")
        if article:
            following = following[1:]
        if not following or not _name_word(following[0][0]):
            continue
        selected = [following[0]]
        for word in following[1:]:
            if text[selected[-1].end():word.start()].strip():
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
            for field in ("title", "author"):
                if isinstance(source.get(field), str):
                    yield source[field], field == "author"
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
    evidence = [(_normalized(_URL.sub(" ", text)), author) for text, author in _evidence(packet, cited)]
    def pattern(name):
        return re.compile(r"(?<![\w'’.-])" + re.escape(_normalized(name))
                          + r"(?![\w-])(?!(?:['’](?!s\b)[^\W\d_])|\.[^\W\d_])")

    def supported(name):
        literal = _normalized(name).lstrip("@")
        match = pattern(literal)
        return any(source.lstrip("@") == literal if author else match.search(source) for source, author in evidence)

    retained = [name for name in known_names if not supported(name)]
    flags = []
    for field, text in targets:
        names = _names(text)
        # Names already found absent in an observed candidate cannot survive a
        # repair merely by changing case, grammar, quoting, code style, or field.
        names += [name for name in retained if pattern(name.lstrip("@")).search(_normalized(text))]
        seen = set()
        for name in names:
            if _normalized(name).lstrip("@") in seen:
                continue
            seen.add(_normalized(name).lstrip("@"))
            if not supported(name):
                flags.append({"field": field, "name": name, "finding": "literal_name_absent_from_source"})
    return flags
