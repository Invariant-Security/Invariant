from misconfig_catalog import CONTAINER_IMPOSSIBLE_TITLES, RECIPES


def test_recipe_ids_are_unique():
    ids = [r.id for r in RECIPES]
    assert len(ids) == len(set(ids))


def test_every_recipe_has_non_empty_fields():
    for recipe in RECIPES:
        assert recipe.check_titles, f"{recipe.id} has no check_titles"
        assert all(isinstance(t, str) and t for t in recipe.check_titles), recipe.id
        assert recipe.description, f"{recipe.id} has no description"
        assert recipe.commands, f"{recipe.id} has no commands"
        assert all(isinstance(c, str) and c for c in recipe.commands), recipe.id
        assert recipe.distro in ("any", "debian", "ubuntu"), recipe.id
        assert recipe.document, f"{recipe.id} has no document"


def test_recipe_check_titles_never_overlap_container_impossible_titles():
    """A recipe is only meaningful if the control it breaks actually PASSES
    on the hardened baseline first -- CONTAINER_IMPOSSIBLE_TITLES is exactly
    the set of controls that structurally can't pass inside a container
    (bootloader/journald/auditd-immutable), so no recipe should target one
    of those; doing so would silently be a no-op (already FAIL before and
    after, on a container target).
    """
    for recipe in RECIPES:
        overlap = set(recipe.check_titles) & CONTAINER_IMPOSSIBLE_TITLES
        assert not overlap, f"{recipe.id} targets a container-impossible title: {overlap}"


def test_container_impossible_titles_is_exactly_five():
    """Regression guard: the hardening work that closed 20 of the original
    25 structural-gap titles must not silently get re-widened back out by a
    future edit -- these 5 are the only ones genuinely impossible inside an
    unprivileged Docker container.
    """
    assert CONTAINER_IMPOSSIBLE_TITLES == {
        "Ensure the audit configuration is immutable",
        "Ensure journald Compress is configured",
        "Ensure journald Storage is configured",
        "Ensure journald log file rotation is configured",
        "Ensure access to bootloader config is configured",
    }


def test_container_impossible_titles_are_all_real_check_titles():
    """Guards CONTAINER_IMPOSSIBLE_TITLES against typos/drift the same way
    misconfig_catalog's module docstring promises for RECIPES.check_titles
    -- every entry must actually exist as a Check.titles entry somewhere in
    src/invariant/assessment/__init__.py.
    """
    from invariant.assessment import CHECKS

    all_titles = {t for check in CHECKS for t in check.titles}
    for title in CONTAINER_IMPOSSIBLE_TITLES:
        assert title in all_titles, f"{title!r} is not a real Check title"


def test_recipe_check_titles_are_all_real_check_titles():
    from invariant.assessment import CHECKS

    all_titles = {t for check in CHECKS for t in check.titles}
    for recipe in RECIPES:
        assert any(t in all_titles for t in recipe.check_titles), (
            f"{recipe.id}'s check_titles {recipe.check_titles!r} match no real Check"
        )
