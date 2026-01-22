
from __future__ import annotations

import sys
from pathlib import Path

# Ensure config.py in the same directory is importable
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import _address, _port, _workers, _reload  # noqa: E402

bind = f"{_address}:{_port}"
workers = int(_workers)
reload = bool(_reload)