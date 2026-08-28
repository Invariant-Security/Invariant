import json
import random

import pytest

import apply_misconfigs
from misconfig_catalog import RECIPES


def test_recipes_for_distro_includes_any_and_exact_match():
    debian_pool = apply_misconfigs.recipes_for_distro("debian")
    assert all(r.distro in ("any", "debian") for r in debian_pool)
    # every current recipe is "any", so both pools should equal the full catalog
    assert len(debian_pool) == len(RECIPES)


def test_recipes_for_distro_excludes_other_distro(monkeypatch):
    from misconfig_catalog import Recipe

    fake_recipes = [
        Recipe(id="a", distro="any", check_titles=("t",), document="d", description="d", commands=("true",)),
        Recipe(id="b", distro="debian", check_titles=("t",), document="d", description="d", commands=("true",)),
        Recipe(id="c", distro="ubuntu", check_titles=("t",), document="d", description="d", commands=("true",)),
    ]
    monkeypatch.setattr(apply_misconfigs, "RECIPES", fake_recipes)

    ubuntu_pool = apply_misconfigs.recipes_for_distro("ubuntu")
    assert {r.id for r in ubuntu_pool} == {"a", "c"}


def test_pick_recipes_returns_two_or_three_unique_recipes():
    rng = random.Random(42)
    picked = apply_misconfigs.pick_recipes("debian", rng)

    assert 2 <= len(picked) <= 3
    assert len({r.id for r in picked}) == len(picked)


def test_pick_recipes_is_deterministic_with_same_seed():
    picked_a = apply_misconfigs.pick_recipes("ubuntu", random.Random(7))
    picked_b = apply_misconfigs.pick_recipes("ubuntu", random.Random(7))

    assert [r.id for r in picked_a] == [r.id for r in picked_b]


def test_apply_recipe_runs_each_command_via_docker_exec(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr(apply_misconfigs.subprocess, "run", fake_run)

    from misconfig_catalog import Recipe

    recipe = Recipe(
        id="x", distro="any", check_titles=("t",), document="d", description="d", commands=("cmd1", "cmd2")
    )
    apply_misconfigs.apply_recipe("some-container", recipe)

    assert calls == [
        ["docker", "exec", "some-container", "sh", "-c", "cmd1"],
        ["docker", "exec", "some-container", "sh", "-c", "cmd2"],
    ]


def test_apply_misconfigs_covers_every_problem_container(monkeypatch):
    applied = []
    monkeypatch.setattr(apply_misconfigs, "apply_recipe", lambda container, recipe: applied.append((container, recipe.id)))

    manifest = apply_misconfigs.apply_misconfigs(seed=1)

    assert set(manifest.keys()) == {c for c, _distro in apply_misconfigs.PROBLEM_CONTAINERS}
    for container, recipes in manifest.items():
        assert 2 <= len(recipes) <= 3
    assert len(applied) == sum(len(v) for v in manifest.values())


def test_apply_misconfigs_is_deterministic_with_same_seed(monkeypatch):
    monkeypatch.setattr(apply_misconfigs, "apply_recipe", lambda container, recipe: None)

    manifest_a = apply_misconfigs.apply_misconfigs(seed=99)
    manifest_b = apply_misconfigs.apply_misconfigs(seed=99)

    ids_a = {c: [r.id for r in rs] for c, rs in manifest_a.items()}
    ids_b = {c: [r.id for r in rs] for c, rs in manifest_b.items()}
    assert ids_a == ids_b


def test_save_manifest_writes_json(tmp_path):
    from misconfig_catalog import Recipe

    manifest = {
        "invariant-demo-debian-1": [
            Recipe(id="x", distro="any", check_titles=("t",), document="d", description="desc", commands=("cmd",))
        ]
    }
    out_path = tmp_path / "manifest.json"

    saved_path = apply_misconfigs.save_manifest(manifest, path=out_path)

    assert saved_path == out_path
    loaded = json.loads(out_path.read_text())
    assert loaded["invariant-demo-debian-1"][0]["id"] == "x"
    assert loaded["invariant-demo-debian-1"][0]["description"] == "desc"


def test_print_manifest_prints_container_and_recipe_ids(capsys):
    from misconfig_catalog import Recipe

    manifest = {
        "invariant-demo-debian-1": [
            Recipe(
                id="shadow-world-readable",
                distro="any",
                check_titles=("Ensure access to /etc/shadow is configured",),
                document="debian_linux_11",
                description="shadow loosened",
                commands=("chmod 644 /etc/shadow",),
            )
        ]
    }

    apply_misconfigs.print_manifest(manifest)

    out = capsys.readouterr().out
    assert "invariant-demo-debian-1" in out
    assert "shadow-world-readable" in out
    assert "shadow loosened" in out


@pytest.mark.parametrize("distro", ["debian", "ubuntu"])
def test_pick_recipes_never_exceeds_available_pool(distro):
    rng = random.Random(0)
    picked = apply_misconfigs.pick_recipes(distro, rng)
    assert len(picked) <= len(apply_misconfigs.recipes_for_distro(distro))
