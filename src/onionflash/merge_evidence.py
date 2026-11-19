"""A missing-evidence concern, never a semantic merge verdict or approval."""

import re

from . import review_evidence, source_quote
from .llm import unquoted_mail_text
from .util import normalize_evidence, safe_canonical_url


# Advance when claim recognition, citation scope or evidence availability changes.
POLICY = {"version": 2, "scope": "current-story-citations", "update": "unchanged",
          "uncertain_language": "defer-to-semantic-review",
          "own_text": "raw-mapping-before-nonnarrative-masking",
          "raw_markup": "defer-completion-language-without-parsing"}
_ACTION = re.compile(r"\b(?:merged|landed|integrated|cherry[- ]picked|backported)\b", re.I)
_MERGED = re.compile(r"\bmerged\b", re.I)
_APPLIED = re.compile(r"\bapplied\b.{0,45}\b(?:main|master|trunk|branch)\b", re.I)
_DENIED = re.compile(r"\b(?:not|never|cannot|can't|isn't|wasn't|hasn't|haven't|hadn't|should|must|"
                     r"will|would|could|may|might|to|no)\b(?:\s+\w+){0,6}\s*$", re.I)
_DIRECT_DENIED = re.compile(
    r"\b(?:not|never|cannot|should|must|will|would|could|may|might|to|no)\s+"
    r"(?:(?:have|been|be|being|yet|now|already|ever|actually|finally|\w+ly)\s+)*$", re.I)
_CONDITION = re.compile(r"^\s*(?:if|unless)\b", re.I)
_TEMPORAL = re.compile(r"^\s*(?:once|when|before|after)\b|\bnot\s+only\b", re.I)
_OTHER = re.compile(r"\b(?:unrelated|separate|another|different|other)\b", re.I)
_ARTIFACT = re.compile(r"\b(?:patch|fix|change|changes|commit|code|MR|PR|refactor|merge request|pull request)\b", re.I)
_BRANCH = re.compile(r"\b(?:main|master|trunk|branch|branches)\b", re.I)
_CLAUSE = re.compile(r"(?<=[.!?;])\s+|\n+|\s+but\s+", re.I)


def claim_fields(candidate):
    """Locate a current merge label or a narrowly affirmative prose claim."""
    fields = ["state"] if candidate.get("state") == "merged" else []
    for field in ("title", "summary", "why_it_matters"):
        raw = candidate.get(field, "")
        if source_quote.RAW_MARKUP.search(raw):
            continue
        raw = review_evidence._NON_NARRATIVE.sub(lambda match: " " * len(match[0]), raw)
        text = normalize_evidence(raw).replace("n't", " not")
        for clause in _CLAUSE.split(text):
            if clause.endswith("?") or _CONDITION.search(clause) or _TEMPORAL.search(clause):
                continue
            if any(not _DENIED.search(clause[max(0, match.start() - 100):match.start()])
                   for match in _MERGED.finditer(clause)):
                fields.append(field)
                break
    return fields


def missing_completion(candidate, packet, *, update=False):
    """Whether current STORY merge claims lack any cited completion language.

    Metadata or text only prevents this additional concern. It does not establish
    the right object, current lifecycle or truth. Ambiguous equivalent language
    remains with ordinary semantic review rather than becoming a new hard hold.
    """
    if update or not claim_fields(candidate):
        return False
    cites = {url for source in candidate.get("sources", [])
             if (url := safe_canonical_url(source.get("url")))}
    deferred = False
    for source in packet["sources"]:
        source_url = safe_canonical_url(source.get("url"))
        whole = source_url in cites and "#" not in source_url
        if whole and source.get("kind") == "gitlab_mr" and source.get("upstream_state") == "merged":
            return False
        opened, previous = None, object()
        for passage in source["passages"]:
            if not whole and safe_canonical_url(passage.get("url", source_url)) not in cites:
                continue
            text = passage["text"]
            if "unquoted_content" in source:
                text = unquoted_mail_text(text)
                if " ".join(text.split()) not in " ".join(source["unquoted_content"].split()):
                    continue
            key = source_quote.group_key(passage)
            if key != previous:
                opened = None
            previous = key
            if source_quote.RAW_MARKUP.search(text):
                # Markup can enclose narrative, a quotation, code or attributes.
                # It is not a witness, but skipping possible completion language
                # cannot establish its absence either. Do not parse it here.
                if _ACTION.search(text) or re.search(r"\bapplied\b", text, re.I):
                    deferred = True
                continue
            first_line, _, remainder = text.partition("\n")
            boundary = source_quote.FENCE.fullmatch(first_line)
            if (opened and boundary and not boundary[2].strip()
                    and boundary[1][0] == opened[0] and len(boundary[1]) >= opened[1]
                    and (_ACTION.search(remainder) or _APPLIED.search(remainder))):
                # Optional quotation extraction deliberately distrusts a fence
                # at a chunk boundary. That uncertainty cannot prove absence
                # of a subsequent narrative statement for this hard check.
                deferred = True
            ranges, opened = source_quote.code_ranges(text, opened)
            masked = list(text)
            for start, end in ranges:
                masked[start:end] = " " * (end - start)
            text = review_evidence._NON_NARRATIVE.sub(lambda match: " " * len(match[0]), "".join(masked))
            for clause in _CLAUSE.split(text):
                for match in (*_ACTION.finditer(clause), *_APPLIED.finditer(clause)):
                    prefix = normalize_evidence(clause[max(0, match.start() - 100):match.start()]).replace("n't", " not") + " "
                    if _TEMPORAL.search(clause):
                        deferred = True
                    elif clause.rstrip().endswith("?") or _CONDITION.search(clause) or _DIRECT_DENIED.search(prefix):
                        continue
                    elif _DENIED.search(prefix):
                        # A distant modal may govern another clause, not this
                        # assertion. Do not turn uncertain scope into a hold.
                        deferred = True
                    elif _OTHER.search(clause):
                        deferred = True
                    elif (_MERGED.fullmatch(match[0]) or _ARTIFACT.search(clause)
                          or _BRANCH.search(clause) or clause.strip().casefold() in {"landed.", "integrated."}):
                        return False
                    else:
                        deferred = True
    return not deferred
