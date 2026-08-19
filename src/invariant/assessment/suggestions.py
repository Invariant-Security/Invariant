"""Proposes candidate checks from controls' audit text.

Extraction only -- nothing here is auto-wired into assessment.CHECKS.
CIS audit text is written for a human to interpret, not guaranteed to be
safe, complete, or context-free shell code (placeholder values, conditional
"-IF-" branches, etc.), so every candidate needs a human to read it,
validate it against a real target, and hand-write the real Check the same
way the first two were built. This tool only cuts down how many controls
need to be looked at from scratch, and groups them by how broadly they'd
apply once implemented.
"""

import re
from dataclasses import dataclass

from invariant.storage import postgres as db

_COMMAND_RE = re.compile(r"^\s*#\s+(\S.*)$", re.MULTILINE)


def extract_simple_command(audit: str) -> str | None:
    """Returns the command if the audit text has exactly one "# <command>"
    line -- the simplest, most directly reviewable case (confirmed: ~47%
    of controls in the database fit this pattern; the rest need more than
    one command, or none at all, and aren't candidates for this tool).
    """
    commands = _COMMAND_RE.findall(audit or "")
    if len(commands) == 1:
        return commands[0].strip()
    return None


@dataclass
class CheckCandidate:
    title: str
    command: str  # the shared command, or a marker if it varies by document
    document_count: int
    documents: list[str]


def suggest_checks(min_documents: int = 1) -> list[CheckCandidate]:
    """Groups controls by title across every document in the database,
    keeping only those with a single extractable command, sorted by how
    many documents they appear in (most broadly reusable first -- these
    are the best return on investment to review and implement).
    """
    conn = db.connect()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT c.title, c.normalized_data->>'audit', d.name
            FROM controls c
            JOIN document_versions dv ON dv.id = c.document_version_id
            JOIN documents d ON d.id = dv.document_id
            """
        )
        rows = cur.fetchall()
    conn.close()

    by_title: dict[str, dict] = {}
    for title, audit, document in rows:
        command = extract_simple_command(audit)
        if command is None:
            continue
        entry = by_title.setdefault(title.strip(), {"commands": set(), "documents": set()})
        entry["commands"].add(command)
        entry["documents"].add(document)

    candidates = [
        CheckCandidate(
            title=title,
            command=next(iter(info["commands"])) if len(info["commands"]) == 1 else "<VARIES BY DOCUMENT>",
            document_count=len(info["documents"]),
            documents=sorted(info["documents"]),
        )
        for title, info in by_title.items()
        if len(info["documents"]) >= min_documents
    ]
    candidates.sort(key=lambda c: -c.document_count)
    return candidates
