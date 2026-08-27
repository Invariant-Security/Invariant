"""Applies 2-3 random, non-repeating misconfiguration recipes to each of the
5 "problem" demo containers (invariant-demo-debian-{1,2,3},
invariant-demo-ubuntu-{1,2}) -- step 5 of demo.sh. invariant-demo-ubuntu-
hardened is left alone; it's the demo's clean baseline.

Run standalone for rehearsal: `python scripts/demo/apply_misconfigs.py
[--seed N]`. Every run assumes the 5 problem containers already exist and
are freshly recreated from their hardened image (demo.sh does that via
`docker compose ... up -d --force-recreate` right before calling this) --
this script only ever *adds* misconfigurations via `docker exec`, it never
resets one back to clean, so re-running it against an already-misconfigured
container would just pile more recipes on top rather than draw a fresh set.

Stdlib only (argparse/random/json/subprocess/dataclasses) -- no new
dependency needed for a one-shot demo helper (see CLAUDE.md's "no blind
dependency additions" rule).
"""

import argparse
import json
import random
import subprocess
from dataclasses import asdict
from pathlib import Path

from misconfig_catalog import RECIPES, Recipe

# The 5 "problem" containers demo.sh brings up from
# infra/docker-compose.demo.yml, each paired with the distro its image is
# built from -- used to filter RECIPES down to the ones safe for that
# container (see Recipe.distro's docstring in misconfig_catalog.py).
PROBLEM_CONTAINERS = [
    ("invariant-demo-debian-1", "debian"),
    ("invariant-demo-debian-2", "debian"),
    ("invariant-demo-debian-3", "debian"),
    ("invariant-demo-ubuntu-1", "ubuntu"),
    ("invariant-demo-ubuntu-2", "ubuntu"),
]

MIN_RECIPES_PER_CONTAINER = 2
MAX_RECIPES_PER_CONTAINER = 3

DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "demo" / "manifest.json"


def recipes_for_distro(distro: str) -> list[Recipe]:
    """RECIPES eligible for a container of the given distro -- "any" plus
    an exact distro match. See Recipe.distro's docstring for why every
    current recipe is "any" (the two hardened images share an identical
    file layout for everything the catalog touches).
    """
    return [r for r in RECIPES if r.distro in ("any", distro)]


def pick_recipes(distro: str, rng: random.Random) -> list[Recipe]:
    """Picks a random, non-repeating 2-3 recipes for one container."""
    pool = recipes_for_distro(distro)
    count = rng.randint(MIN_RECIPES_PER_CONTAINER, MAX_RECIPES_PER_CONTAINER)
    return rng.sample(pool, k=min(count, len(pool)))


def apply_recipe(container: str, recipe: Recipe) -> None:
    for command in recipe.commands:
        subprocess.run(
            ["docker", "exec", container, "sh", "-c", command],
            check=True,
            capture_output=True,
            text=True,
        )


def apply_misconfigs(seed: int | None = None) -> dict[str, list[Recipe]]:
    """Draws and applies misconfigs for every container in
    PROBLEM_CONTAINERS, returning {container: [Recipe, ...]} -- the
    manifest demo.sh reprints in its final summary (step 9) to classify
    each FAIL as "today's story" (matches a recipe here) versus
    "environmental" (doesn't).
    """
    rng = random.Random(seed)
    manifest: dict[str, list[Recipe]] = {}
    for container, distro in PROBLEM_CONTAINERS:
        recipes = pick_recipes(distro, rng)
        for recipe in recipes:
            apply_recipe(container, recipe)
        manifest[container] = recipes
    return manifest


def print_manifest(manifest: dict[str, list[Recipe]]) -> None:
    print("Manifesto de misconfigurações da demo")
    print("-" * 60)
    for container, recipes in manifest.items():
        print(f"{container}:")
        for recipe in recipes:
            print(f"  - [{recipe.id}] {recipe.description}")
            print(f"      controle: {recipe.check_titles[0]} ({recipe.document})")
        print()


def save_manifest(manifest: dict[str, list[Recipe]], path: Path = DEFAULT_MANIFEST_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    serializable = {container: [asdict(recipe) for recipe in recipes] for container, recipes in manifest.items()}
    path.write_text(json.dumps(serializable, indent=2))
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed the random draw for a reproducible manifest (default: system randomness, a fresh draw every run).",
    )
    args = parser.parse_args()

    manifest = apply_misconfigs(seed=args.seed)
    print_manifest(manifest)
    saved_path = save_manifest(manifest)
    print(f"Manifesto salvo em {saved_path}")


if __name__ == "__main__":
    main()
