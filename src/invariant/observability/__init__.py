"""Lightweight timing instrumentation for pipeline stages.

Prints how long each stage took (download/parse/persist/...). This is
just the "logs" primitive of PRD sec. 29's future observability
direction -- metrics/traces/Prometheus/Grafana are explicitly future
there, not built here. No new dependency: stdlib time + print, matching
how the rest of the CLI already reports progress.
"""

import time
from contextlib import contextmanager


@contextmanager
def timed(label: str):
    start = time.monotonic()
    print(f"[{label}] starting...")
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        print(f"[{label}] done in {elapsed:.2f}s")
