"""Builds the quickdemo FAIL-classification report: per target container,
splits every FAIL into "environmental" (a structural gap in
STRUCTURAL_GAP_TITLES, same on every container including the hardened
baseline) vs "today's story" (matches a misconfig recipe the manifest says
was actually applied to that container this run) vs "unexplained" (neither
-- a signal something's wrong, see the WARNING check below).

Extracted from quickdemo.sh's step 9 (previously an inline Python heredoc)
so the exact same classification is reusable elsewhere (e.g. invariant.api
in a later phase) without duplicating the logic. Not part of the installed
invariant package -- same "one-shot demo helper" posture as
apply_misconfigs.py/misconfig_catalog.py (stdlib only, see CLAUDE.md's "no
blind dependency additions" rule) -- so it uses the same bare `import
misconfig_catalog` convention, resolved the same way apply_misconfigs.py's
is: Python adds a directly-run script's own directory to sys.path
automatically; tests add it explicitly (see tests/quickdemo/conftest.py).

Run standalone: `python scripts/quickdemo/report.py <hardened> <problem1>
[<problem2> ...] [--manifest PATH] [--json-out PATH]`
"""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from misconfig_catalog import STRUCTURAL_GAP_TITLES

from invariant.assessment import Finding, assess_targets

DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "quickdemo" / "manifest.json"


def _finding_dict(finding: Finding) -> dict:
    return asdict(finding)


def build_report(targets: list[str], manifest_path: Path = DEFAULT_MANIFEST_PATH) -> dict:
    """Assesses `targets` and classifies every FAIL into environmental /
    story / unexplained -- the same three-way split quickdemo.sh's old step
    9 heredoc computed inline. `targets[0]` is treated as the hardened
    baseline by print_report() only; assess_targets() itself doesn't care
    about target order.

    Returns a JSON-serializable dict:
        {
          "targets": [container, ...],
          "containers": {
              container: {
                  "total_findings": int,
                  "fail_count": int,
                  "pass_count": int,
                  "environmental": [finding-dict, ...],
                  "story": [finding-dict, ...],
                  "unexplained": [finding-dict, ...],
              },
              ...
          },
          "unexplained_total": int,
        }
    """
    with open(manifest_path) as f:
        manifest = json.load(f)

    # container -> set of control titles a recipe actually broke this run
    story_titles_by_container = {
        container: {title for recipe in recipes for title in recipe["check_titles"]}
        for container, recipes in manifest.items()
    }

    results = assess_targets(targets)

    containers = {}
    unexplained_total = 0
    for container in targets:
        findings = results[container]
        fails = [f for f in findings if f.status == "FAIL"]
        story_titles = story_titles_by_container.get(container, set())

        environmental = [f for f in fails if f.control_title in STRUCTURAL_GAP_TITLES]
        story = [f for f in fails if f.control_title in story_titles]
        other = [f for f in fails if f not in environmental and f not in story]
        unexplained_total += len(other)

        containers[container] = {
            "total_findings": len(findings),
            "fail_count": len(fails),
            "pass_count": len(findings) - len(fails),
            "environmental": [_finding_dict(f) for f in environmental],
            "story": [_finding_dict(f) for f in story],
            "unexplained": [_finding_dict(f) for f in other],
        }

    return {
        "targets": list(targets),
        "containers": containers,
        "unexplained_total": unexplained_total,
    }


def print_report(report: dict, hardened: str) -> None:
    """Reprints build_report()'s output as the same human-readable text
    quickdemo.sh's step 9 heredoc used to print directly -- keeps the
    terminal experience unchanged even though the logic moved.
    """
    for container in report["targets"]:
        data = report["containers"][container]
        print(f"\n{container}: {data['fail_count']} FAIL(s)")
        print(f"  environmental (structural gap, same on every container): {len(data['environmental'])}")
        if data["story"] or container != hardened:
            print(f"  today's story (misconfig applied this run): {len(data['story'])}")
            for f in data["story"]:
                print(f"    - {f['external_id']}  {f['control_title']}")
        if data["unexplained"]:
            print(
                "  UNEXPLAINED (neither environmental nor today's misconfig -- investigate!): "
                f"{len(data['unexplained'])}"
            )
            for f in data["unexplained"]:
                print(f"    - {f['external_id']}  {f['control_title']}")

    if report["unexplained_total"]:
        print(f"\nWARNING: {report['unexplained_total']} unexplained FAIL(s) -- see above.")
    else:
        print("\nEvery FAIL across all demo containers is accounted for.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="+", help="Container names to assess, hardened baseline listed first.")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path to apply_misconfigs.py's manifest.json (default: data/quickdemo/manifest.json).",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to also write the report as JSON (so quickdemo.sh can reuse it, e.g. for runs.jsonl).",
    )
    args = parser.parse_args()

    report = build_report(args.targets, manifest_path=args.manifest)
    print_report(report, hardened=args.targets[0])

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
