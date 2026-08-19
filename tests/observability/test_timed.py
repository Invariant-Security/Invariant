import time

from invariant.observability import timed


def test_timed_prints_start_and_done_lines(capsys):
    with timed("some-stage"):
        pass

    output = capsys.readouterr().out
    assert "[some-stage] starting..." in output
    assert "[some-stage] done in" in output


def test_timed_measures_elapsed_time(capsys):
    with timed("sleep-stage"):
        time.sleep(0.05)

    output = capsys.readouterr().out
    elapsed_line = next(line for line in output.splitlines() if "done in" in line)
    elapsed_seconds = float(elapsed_line.split("done in")[1].strip().rstrip("s"))
    assert elapsed_seconds >= 0.05


def test_timed_still_reports_duration_when_block_raises(capsys):
    try:
        with timed("failing-stage"):
            raise RuntimeError("boom")
    except RuntimeError:
        pass

    output = capsys.readouterr().out
    assert "[failing-stage] done in" in output
