"""Builds the demo FAIL-classification report: per target container, splits
every FAIL into "environmental" (a title in CONTAINER_IMPOSSIBLE_TITLES,
but only when the target is actually detected as running inside a
container -- see facts.is_running_in_container()) vs "today's story"
(matches a misconfig recipe the manifest says was actually applied to that
container this run) vs "unexplained" (neither -- a signal something's
wrong, see the WARNING check below). On a target NOT detected as a
container, a title in CONTAINER_IMPOSSIBLE_TITLES gets no automatic excuse
-- it's just a normal FAIL, classified as story/unexplained like any other.

Extracted from demo.sh's step 9 (previously an inline Python heredoc) so
the exact same classification is reusable elsewhere (e.g. invariant.api in
a later phase) without duplicating the logic. Not part of the installed
invariant package -- same "one-shot demo helper" posture as
apply_misconfigs.py/misconfig_catalog.py (stdlib only, see CLAUDE.md's "no
blind dependency additions" rule) -- so it uses the same bare `import
misconfig_catalog` convention, resolved the same way apply_misconfigs.py's
is: Python adds a directly-run script's own directory to sys.path
automatically; tests add it explicitly (see tests/demo/conftest.py).

Run standalone: `python scripts/demo/report.py <hardened> <problem1>
[<problem2> ...] [--manifest PATH] [--json-out PATH]`
"""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from misconfig_catalog import CONTAINER_IMPOSSIBLE_TITLES

from invariant.assessment import Finding, assess_targets
from invariant.assessment.facts import collect_facts, is_running_in_container

DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "demo" / "manifest.json"


def _finding_dict(finding: Finding) -> dict:
    return asdict(finding)


def build_report(targets: list[str], manifest_path: Path = DEFAULT_MANIFEST_PATH, is_demo: bool = True) -> dict:
    """Assesses `targets` and classifies every FAIL into environmental /
    story / unexplained -- the same three-way split demo.sh's old step 9
    heredoc computed inline. `targets[0]` is treated as the hardened
    baseline by print_report() only; assess_targets() itself doesn't care
    about target order.

    `is_demo` is pure metadata, read only by the frontend (App.jsx's
    aggregateReport()/TargetCard/TargetDetail) to decide how to *present*
    this same data -- it changes nothing about how findings are computed
    or classified here. The three-way split above is a demo-narrative
    concept (did today's rehearsed misconfig story hold up?) that doesn't
    describe a real client target at all: "story" is always empty there
    (no manifest entry ever applies), so a real FAIL always lands in
    "unexplained" by construction, and a naive UI showing "Misconfigurations:
    0" next to "Unexplained: 86" reads as if the tool is confused rather
    than reporting real findings. Default True (unchanged for demo.sh's own
    calls); callers assessing a real environment (not this repo's demo
    containers) should pass False.

    Returns a JSON-serializable dict:
        {
          "targets": [container, ...],
          "containers": {
              container: {
                  "total_findings": int,
                  "fail_count": int,
                  "pass_count": int,
                  "is_container": bool,
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

        # A second docker exec round trip per container, on top of what
        # assess_targets() already did -- purely for this demo-presentation
        # question, not plumbed through Finding/assess_target() itself (see
        # facts.is_running_in_container()'s own docstring for why).
        is_container = is_running_in_container(collect_facts(container))

        if is_container:
            environmental = [f for f in fails if f.control_title in CONTAINER_IMPOSSIBLE_TITLES]
        else:
            environmental = []
        story = [f for f in fails if f.control_title in story_titles and f not in environmental]
        other = [f for f in fails if f not in environmental and f not in story]
        unexplained_total += len(other)

        containers[container] = {
            "total_findings": len(findings),
            "fail_count": len(fails),
            "pass_count": len(findings) - len(fails),
            "is_container": is_container,
            "environmental": [_finding_dict(f) for f in environmental],
            "story": [_finding_dict(f) for f in story],
            "unexplained": [_finding_dict(f) for f in other],
        }

    return {
        "targets": list(targets),
        "containers": containers,
        "unexplained_total": unexplained_total,
        "is_demo": is_demo,
    }


def print_report(report: dict, hardened: str) -> None:
    """Reprints build_report()'s output as the same human-readable text
    demo.sh's step 9 heredoc used to print directly -- keeps the terminal
    experience unchanged even though the logic moved.
    """
    for container in report["targets"]:
        data = report["containers"][container]
        ambiente = "container Docker/OCI detectado" if data["is_container"] else "máquina real/VM (nenhum container detectado)"
        print(f"\n{container}: {data['fail_count']} FALHA(S)")
        print(f"  ambiente: {ambiente}")
        print(f"  ambiental (limitação genuína de container, só aplicada se detectado como tal): {len(data['environmental'])}")
        if data["story"] or container != hardened:
            print(f"  história de hoje (misconfiguração aplicada nesta rodada): {len(data['story'])}")
            for f in data["story"]:
                print(f"    - {f['external_id']}  {f['control_title']}")
        if data["unexplained"]:
            print(
                "  NÃO EXPLICADO (nem ambiental nem misconfiguração de hoje -- investigar!): "
                f"{len(data['unexplained'])}"
            )
            for f in data["unexplained"]:
                print(f"    - {f['external_id']}  {f['control_title']}")

    if report["unexplained_total"]:
        print(f"\nATENÇÃO: {report['unexplained_total']} falha(s) não explicada(s) -- ver acima.")
    else:
        print("\nToda falha em todos os containers da demo está explicada.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="+", help="Container names to assess, hardened baseline listed first.")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path to apply_misconfigs.py's manifest.json (default: data/demo/manifest.json).",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to also write the report as JSON (so demo.sh can reuse it, e.g. for runs.jsonl).",
    )
    args = parser.parse_args()

    report = build_report(args.targets, manifest_path=args.manifest)
    print_report(report, hardened=args.targets[0])

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
