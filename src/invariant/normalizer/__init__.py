"""Converts extracted items into normalized controls."""

import re
from dataclasses import dataclass

_PROFILE_RE = re.compile(r"^Level\s+(?P<level>\d+)\s*-\s*(?P<applies_to>.+)$")

# CIS benchmark PDFs are Word exports that render bullet points as either
# a Wingdings-style glyph (private-use-area U+F0B7, older documents) or a
# real bullet character (U+2022, newer documents) -- shows up mid-paragraph
# in a few free-text fields too, not just the one-entry-per-line ones the
# extractor already handles.
_BULLET_CHARS = "\uf0b7\u2022"


@dataclass
class ProfileLevel:
    level: int
    applies_to: str


@dataclass
class Control:
    """A normalized CIS recommendation: the same facts as the extracted
    item, but with stable structure (parsed applicability levels, cleaned
    text) instead of raw PDF prose fragments -- so downstream diffing and
    assessment don't need to re-parse text.
    """

    external_id: str
    title: str
    description: str
    scored: bool
    applicability: list[ProfileLevel]
    rationale: str
    audit: str
    remediation: str


def normalize(
    *,
    external_id: str,
    title: str,
    description: str,
    scored: bool,
    profile_applicability: list[str],
    rationale: str,
    audit: str,
    remediation: str,
) -> Control:
    """Normalize one extracted recommendation's fields into a Control.

    Takes plain fields rather than invariant.extractor's
    ExtractedRecommendation directly -- this stage's real input is
    whatever ended up in the extracted_items table, not the extractor
    itself, so it shouldn't need to import that module.
    """
    return Control(
        external_id=external_id,
        title=title,
        description=_clean(description),
        scored=scored,
        applicability=[_parse_profile_level(entry) for entry in profile_applicability],
        rationale=_clean(rationale),
        audit=_clean(audit),
        remediation=_clean(remediation),
    )


def _parse_profile_level(entry: str) -> ProfileLevel:
    match = _PROFILE_RE.match(entry)
    if not match:
        raise ValueError(f"unrecognized profile applicability entry: {entry!r}")
    return ProfileLevel(level=int(match.group("level")), applies_to=match.group("applies_to"))


def _clean(text: str) -> str:
    for char in _BULLET_CHARS:
        text = text.replace(char, "")
    return text.strip()
