"""Loads .env into os.environ so credentials never get hardcoded in source.

Deliberately stdlib-only (no python-dotenv): the parsing needed here is a
handful of KEY=VALUE lines, not worth a new dependency for.
"""

import os
from pathlib import Path

_ENV_PATH = Path(__file__).resolve().parents[2] / ".env"


def load_dotenv(path: Path = _ENV_PATH) -> None:
    if not path.is_file():
        return

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()
