"""scripts/quickdemo/ isn't part of the installed invariant package (it's a
one-shot demo helper, not pipeline code -- see quickdemo.sh), so its two
modules use bare `import misconfig_catalog` / `from misconfig_catalog
import ...` the same way they're run directly (`python
scripts/quickdemo/apply_misconfigs.py`, which Python resolves by adding the
script's own directory to sys.path[0] automatically). Tests need that same
directory on sys.path to import them the same way.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "quickdemo"))
