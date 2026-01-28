"""
NEXOM - A lightweight Python web framework.

NEXOM provides a simple and flexible foundation for building
WSGI-based web applications with minimal overhead.
"""

from __future__ import annotations

from nexom.app.request import Request
from nexom.app.response import Response

__all__ = [
    "Request",
    "Response",
    "__version__",
]

__version__ = "1.0.6"