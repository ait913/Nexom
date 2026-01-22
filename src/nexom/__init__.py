"""
NEXOM - A lightweight Python web framework.

NEXOM provides a simple and flexible foundation for building
WSGI-based web applications with minimal overhead.
"""

from __future__ import annotations

from nexom.web.request import Request
from nexom.web.response import Response

__all__ = [
    "Request",
    "Response",
    "__version__",
]

__version__ = "0.1.2"