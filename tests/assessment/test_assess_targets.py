from invariant import assessment
from invariant.assessment import Finding, TARGETS, assess_all, assess_targets


def _fake_finding(target: str) -> Finding:
    return Finding(
        target=target,
        external_id="1.1.1",
        status="PASS",
        control_title="fake control",
        source_name="cis",
        document_name="debian_linux_11",
        document_version="2.0.0",
        evidence_output="fake evidence",
        collected_at="2026-01-01T00:00:00+00:00",
    )


def test_assess_targets_calls_assess_target_for_each_given_target(monkeypatch):
    calls = []

    def fake_assess_target(target):
        calls.append(target)
        return [_fake_finding(target)]

    monkeypatch.setattr(assessment, "assess_target", fake_assess_target)

    results = assess_targets(["container-a", "container-b"])

    assert calls == ["container-a", "container-b"]
    assert set(results.keys()) == {"container-a", "container-b"}
    assert results["container-a"][0].target == "container-a"


def test_assess_targets_with_empty_list_returns_empty_dict(monkeypatch):
    monkeypatch.setattr(assessment, "assess_target", lambda target: [_fake_finding(target)])

    assert assess_targets([]) == {}


def test_assess_all_reuses_assess_targets_over_the_module_targets(monkeypatch):
    """assess_all() must not duplicate assess_targets()'s own loop --
    confirmed by monkeypatching assess_targets itself and checking assess_all
    calls it with exactly TARGETS.
    """
    calls = []

    def fake_assess_targets(targets):
        calls.append(list(targets))
        return {t: [] for t in targets}

    monkeypatch.setattr(assessment, "assess_targets", fake_assess_targets)

    result = assess_all()

    assert calls == [TARGETS]
    assert set(result.keys()) == set(TARGETS)
