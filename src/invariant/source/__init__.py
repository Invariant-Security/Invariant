"""Source adapter interface that isolates source-specific complexity
(CIS, AWS, FIRST/CVSS, OWASP, ...).
"""
import httpx
from typing import Protocol

# TODO: define the minimal interface a "Source" must expose so the pipeline (collector -> extractor -> normalizer -> storage) never needs to know anything specific about CIS/AWS/etc (PRD sec. 7 and 21).
# premises to decide before implementing:
# - each Source has a stable name/id (e.g. "cis") -- what the user types in
#   `invariant fetch cis`, and what maps to a row in the `sources` table
# - Source must expose a way to download the raw document and return its
#   content (bytes) plus enough info to know the file extension/format
#   (pdf, html, ...), since fetch.py needs it to name the file in data/raw/
# - Source may (not always) expose the document's publisher_version, when
#   the source itself provides that info
# - Protocol (structural typing) vs abc.ABC (explicit inheritance) -- still
#   open, document the choice in docs/decisions/ once decided

class Source(Protocol):
    name: str
    def download(self) -> tuple[bytes, str]: ...
    def publisher_version(self) -> str: ...

class CIS:
    """CIS source adapter interface. download with httpx"""

    name = "cis"

    def download(self) -> tuple[bytes, str]:
        try:
            return httpx.get("https://www.cisecurity.org/cis-benchmarks/").content, "pdf"

        except httpx.HTTPError as e:
            print(f"Error downloading CIS document: {e}")
            raise

    def publisher_version(self) -> str:
        str: ...


class AWSSource:
    """AWS source adapter interface."""

    name = "aws"

    def download(self) -> tuple[bytes, str]:
        """Download the raw document and return its content and file extension."""
        ...

    def publisher_version(self) -> str:
        """Return the publisher version of the document, if available."""
        ...

class FIRSTSource:
    """FIRST source adapter interface."""

    name = "first"

    def download(self) -> tuple[bytes, str]:
        """Download the raw document and return its content and file extension."""
        ...

    def publisher_version(self) -> str:
        """Return the publisher version of the document, if available."""
        ...

class OWASPSource:
    """OWASP source adapter interface."""

    name = "owasp"

    def download(self) -> tuple[bytes, str]:
        """Download the raw document and return its content and file extension."""
        ...

    def publisher_version(self) -> str:
        """Return the publisher version of the document, if available."""
        ...

    