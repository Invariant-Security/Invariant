from misconfig_catalog import RECIPES, STRUCTURAL_GAP_TITLES


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


def test_recipe_check_titles_never_overlap_structural_gaps():
    """A recipe is only meaningful if the control it breaks actually PASSES
    on the hardened baseline first -- STRUCTURAL_GAP_TITLES is exactly the
    set of controls that structurally can't pass (no sudo/cron/auditd/
    libpam-pwquality installed), so no recipe should target one of those;
    doing so would silently be a no-op (already FAIL before and after).
    """
    for recipe in RECIPES:
        overlap = set(recipe.check_titles) & STRUCTURAL_GAP_TITLES
        assert not overlap, f"{recipe.id} targets a structurally-failing title: {overlap}"


def test_structural_gap_titles_are_all_real_check_titles():
    """Guards STRUCTURAL_GAP_TITLES against typos/drift the same way
    misconfig_catalog's module docstring promises for RECIPES.check_titles
    -- every entry must actually exist as a Check.titles entry somewhere in
    src/invariant/assessment/__init__.py.
    """
    from invariant.assessment import CHECKS

    all_titles = {t for check in CHECKS for t in check.titles}
    for title in STRUCTURAL_GAP_TITLES:
        assert title in all_titles, f"{title!r} is not a real Check title"


def test_recipe_check_titles_are_all_real_check_titles():
    from invariant.assessment import CHECKS

    all_titles = {t for check in CHECKS for t in check.titles}
    for recipe in RECIPES:
        assert any(t in all_titles for t in recipe.check_titles), (
            f"{recipe.id}'s check_titles {recipe.check_titles!r} match no real Check"
        )
