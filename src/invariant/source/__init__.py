"""Source adapter interface that isolates source-specific complexity
(CIS, AWS, FIRST/CVSS, OWASP, ...).
"""
import json
import httpx
from dataclasses import dataclass
from pathlib import Path
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

@dataclass
class BenchmarkMetadata:
    """Discovery metadata for one specific CIS benchmark PDF version.

    Returned by CIS.find_benchmark() -- discovery only, no login required.

    `download_url` is what CIS's public marketing site publishes for this
    version, but it points at a stale API route that 404s even when
    authenticated (confirmed by testing it) -- don't use it to actually
    fetch the PDF. Use CIS.download_benchmark(title, ...) instead, which
    finds the real, current download link inside the authenticated
    WorkBench app. `download_url` is kept here only as discovery evidence
    (traceability: what CIS itself claims the source location is).
    """

    title: str
    technology_version: str
    benchmark_version: str
    file_name: str
    download_url: str
    source_page: str


def _extract_jss_state(html: str) -> dict:
    """Parse the Sitecore JSS state CIS embeds as JSON on each benchmark page.

    Found by inspecting a real CIS benchmark page: it ships a
    <script type="application/json" id="__JSS_STATE__"> tag containing every
    version's file metadata (fileName/location/title) as clean JSON --
    no HTML scraping needed, just locate the tag and json.loads() it.
    """
    marker = '<script type="application/json" id="__JSS_STATE__">'
    start = html.find(marker)
    if start == -1:
        raise LookupError("__JSS_STATE__ script tag not found on CIS benchmark page")
    start = html.find(">", start) + 1
    end = html.find("</script>", start)
    return json.loads(html[start:end])


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

    def find_benchmark(
        self, product_slug: str, technology_version: str, benchmark_version: str
    ) -> BenchmarkMetadata:
        """Look up one CIS benchmark PDF's download metadata by product/version.

        Example: find_benchmark("debian_linux", "10", "1.0.0") locates
        "CIS Debian Linux 10 Benchmark v1.0.0 ARCHIVE". Does not need
        authentication -- CIS publishes this metadata openly on the product
        page, unlike the PDF download itself.
        """
        page_url = f"https://www.cisecurity.org/benchmark/{product_slug}"
        response = httpx.get(page_url, follow_redirects=True)
        response.raise_for_status()

        state = _extract_jss_state(response.text)
        versions = state["sitecore"]["route"]["fields"]["benchmarkVersions"]

        for version in versions:
            fields = version["fields"]
            if (
                fields.get("technologyVersion", {}).get("value") != technology_version
                or fields.get("benchmarkVersion", {}).get("value") != benchmark_version
            ):
                continue

            documents = fields.get("documents", [])
            if not documents:
                raise LookupError(
                    f"no downloadable document for {product_slug} "
                    f"{technology_version} v{benchmark_version}"
                )
            doc_fields = documents[0]["fields"]
            return BenchmarkMetadata(
                title=doc_fields["title"]["value"],
                technology_version=technology_version,
                benchmark_version=benchmark_version,
                file_name=doc_fields["fileName"]["value"],
                download_url=doc_fields["location"]["value"],
                source_page=page_url,
            )

        raise LookupError(
            f"benchmark not found: {product_slug} {technology_version} v{benchmark_version}"
        )

    def download_benchmark(self, product_label: str, version_label: str) -> tuple[bytes, str]:
        """Download one benchmark PDF from downloads.cisecurity.org -- no login.

        `product_label` is the product's display text on that page (e.g.
        "Debian Linux"), `version_label` is the version entry's display text
        (e.g. "CIS Debian Linux 10 Benchmark v1.0.0").

        This replaces an earlier attempt that logged into CIS WorkBench:
        that worked, but WorkBench's own search started 404-ing/returning
        empty results after repeated automated requests (looked like
        rate-limiting), and its download route needs a WorkBench account.
        downloads.cisecurity.org needs neither -- confirmed by downloading
        the same file both ways and comparing SHA-256 hashes (identical).
        """
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(accept_downloads=True)
            page = context.new_page()
            try:
                page.goto("https://downloads.cisecurity.org/#/", wait_until="networkidle")
                page.get_by_text(product_label, exact=False).first.click()
                page.wait_for_timeout(1500)

                entry = page.get_by_text(version_label, exact=True)
                if entry.count() == 0:
                    raise LookupError(f"no entry for {version_label!r} under {product_label!r}")
                download_link = entry.locator(
                    "xpath=following::a[contains(text(), 'Download PDF')][1]"
                )

                with context.expect_event("download") as download_info:
                    download_link.click()
                download = download_info.value

                content = Path(download.path()).read_bytes()
                extension = Path(download.suggested_filename).suffix.lstrip(".") or "pdf"
                return content, extension
            finally:
                browser.close()


# The CIS Debian benchmarks the bxsec Docker demo targets, one entry per
# document -- the *latest* published version of each (older archived
# versions are left out for now; document_versions supports keeping more
# than one version per document if a specific older one is ever needed).
# Keyed by the name used on the CLI (`invariant fetch <document>`).
# technology_version/benchmark_version -> CIS.find_benchmark() (discovery,
# no login). product_label/version_label -> CIS.download_benchmark() (the
# actual PDF, also no login). All 6 confirmed live against
# cisecurity.org/benchmark/debian_linux and downloads.cisecurity.org.
KNOWN_CIS_DOCUMENTS = {
    "cis-debian-linux-9": {
        "document_slug": "debian_linux_9",
        "product_slug": "debian_linux",
        "technology_version": "9",
        "benchmark_version": "1.0.1",
        "product_label": "Debian Linux",
        "version_label": "CIS Debian Linux 9 Benchmark v1.0.1",
    },
    "cis-debian-linux-10": {
        "document_slug": "debian_linux_10",
        "product_slug": "debian_linux",
        "technology_version": "10 v2.0.0",
        "benchmark_version": "2.0.0",
        "product_label": "Debian Linux",
        "version_label": "CIS Debian Linux 10 Benchmark v2.0.0",
    },
    "cis-debian-linux-11": {
        "document_slug": "debian_linux_11",
        "product_slug": "debian_linux",
        "technology_version": "11",
        "benchmark_version": "2.0.0",
        "product_label": "Debian Linux",
        "version_label": "CIS Debian Linux 11 Benchmark v2.0.0",
    },
    "cis-debian-linux-11-stig": {
        "document_slug": "debian_linux_11_stig",
        "product_slug": "debian_linux",
        "technology_version": "11STIG v1.0.0",
        "benchmark_version": "1.0.0",
        "product_label": "Debian Linux",
        "version_label": "CIS Debian Linux 11 STIG Benchmark v1.0.0",
    },
    "cis-debian-linux-12": {
        "document_slug": "debian_linux_12",
        "product_slug": "debian_linux",
        "technology_version": "12",
        "benchmark_version": "2.0.0",
        "product_label": "Debian Linux",
        "version_label": "CIS Debian Linux 12 Benchmark v2.0.0",
    },
    "cis-debian-linux-13": {
        "document_slug": "debian_linux_13",
        "product_slug": "debian_linux",
        "technology_version": "13",
        "benchmark_version": "1.0.0",
        "product_label": "Debian Linux",
        "version_label": "CIS Debian Linux 13 Benchmark v1.0.0",
    },
    "cis-ubuntu-linux-12-04": {
        "document_slug": "ubuntu_linux_12_04",
        "product_slug": "ubuntu_linux",
        "technology_version": "12.04",
        "benchmark_version": "1.1.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu 12.04 LTS Server Benchmark v1.1.0",
    },
    "cis-ubuntu-linux-14-04": {
        "document_slug": "ubuntu_linux_14_04",
        "product_slug": "ubuntu_linux",
        "technology_version": "14.04",
        "benchmark_version": "2.1.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu Linux 14.04 LTS Benchmark v2.1.0",
    },
    "cis-ubuntu-linux-16-04": {
        "document_slug": "ubuntu_linux_16_04",
        "product_slug": "ubuntu_linux",
        "technology_version": "16.04",
        "benchmark_version": "2.0.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu Linux 16.04 LTS Benchmark v2.0.0",
    },
    "cis-ubuntu-linux-18-04": {
        "document_slug": "ubuntu_linux_18_04",
        "product_slug": "ubuntu_linux",
        "technology_version": "18.04",
        "benchmark_version": "2.2.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu Linux 18.04 LTS Benchmark v2.2.0",
    },
    "cis-ubuntu-linux-20-04": {
        "document_slug": "ubuntu_linux_20_04",
        "product_slug": "ubuntu_linux",
        "technology_version": "20.04",
        "benchmark_version": "3.0.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0",
    },
    "cis-ubuntu-linux-20-04-stig": {
        "document_slug": "ubuntu_linux_20_04_stig",
        "product_slug": "ubuntu_linux",
        "technology_version": "20.04STIG",
        "benchmark_version": "2.0.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu Linux 20.04 LTS STIG Benchmark v2.0.0",
    },
    "cis-ubuntu-linux-22-04": {
        "document_slug": "ubuntu_linux_22_04",
        "product_slug": "ubuntu_linux",
        "technology_version": "22.04",
        "benchmark_version": "3.0.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0",
    },
    "cis-ubuntu-linux-22-04-stig": {
        "document_slug": "ubuntu_linux_22_04_stig",
        "product_slug": "ubuntu_linux",
        "technology_version": "Ubuntu Linux 22.04 LTS",
        "benchmark_version": "1.0.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu Linux 22.04 LTS STIG Benchmark v1.0.0",
    },
    "cis-ubuntu-linux-24-04": {
        "document_slug": "ubuntu_linux_24_04",
        "product_slug": "ubuntu_linux",
        "technology_version": "24.04",
        "benchmark_version": "2.0.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0",
    },
    "cis-ubuntu-linux-24-04-stig": {
        "document_slug": "ubuntu_linux_24_04_stig",
        "product_slug": "ubuntu_linux",
        "technology_version": "Ubuntu Linux 24.04 LTS",
        "benchmark_version": "1.0.0",
        "product_label": "Ubuntu Linux",
        "version_label": "CIS Ubuntu Linux 24.04 LTS STIG Benchmark v1.0.0",
    },
}


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

    