"""Namazu's API security audit engine.

Non-invasive by construction: probes use read-only HTTP methods and
detection-only payloads, every run has a hard request budget, and any request
that could change server state is refused unless the operator opts in.

Public entry points live in :mod:`engine`.
"""

from .engine import DEFAULT_PROFILE, PROFILES, audit_inventory, audit_operation, summarize
from .model import Exchange, Finding

__all__ = [
    "audit_operation",
    "audit_inventory",
    "summarize",
    "PROFILES",
    "DEFAULT_PROFILE",
    "Exchange",
    "Finding",
]
