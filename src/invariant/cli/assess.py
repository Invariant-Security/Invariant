# `invariant assess` -- run the bxsec Docker demo assessment and print
# results. Summary table always shown; full Finding -> Control -> Source ->
# Document Version -> Evidence chain printed for every FAIL, per bxsec.md
# sec. 6 ("don't stop at 'HIGH, SSH insecure' -- show why").

from invariant import assessment


def assess():
    results = assessment.assess_all()

    print("Invariant Assessment")
    print("-" * 60)
    total_findings = 0
    for target, findings in results.items():
        fails = [f for f in findings if f.status == "FAIL"]
        total_findings += len(fails)
        symbol = "PASS" if not fails else "FAIL"
        print(f"{target:<38} {symbol}  {len(fails)} finding(s)")
    print("-" * 60)
    print(f"Total findings: {total_findings}")

    for findings in results.values():
        for finding in findings:
            if finding.status != "FAIL":
                continue
            print()
            print(f"Finding: {finding.target} / {finding.external_id}")
            print(f"Status: {finding.status}")
            print(f"Control: {finding.control_title}")
            print(f"Evidence: {finding.evidence_output}")
            print(f"Source: {finding.source_name}")
            print(f"Document version: {finding.document_name} v{finding.document_version}")
            print(f"Collected at: {finding.collected_at}")

    return results
