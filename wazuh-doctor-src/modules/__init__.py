"""
wazuh-doctor :: check modules

Importing this package imports every check area in this directory, which
registers each Module subclass in modules.base.REGISTRY.

Two deliberate choices here:

**Files are discovered, not listed.** A hand-maintained tuple of names
drifts. Add a check file, forget the tuple, and that area silently never
runs -- which is precisely the failure this tool exists to catch: an
absence read as health. The directory is the source of truth.

**The imports are guarded, one file at a time.** A syntax error or a bad
import in a single check file used to take the entire tool down, so one
broken area meant *no* diagnosis at all. Failures are now collected in
``IMPORT_ERRORS`` and the CLI reports each as a finding, while every other
check area still runs.

That is insurance, not an excuse -- an area listed in IMPORT_ERRORS is
broken and should be fixed. ``wazuh-doctor --list-modules`` prints them.
"""

import importlib
import os
from typing import Dict, List, Tuple

from .base import REGISTRY, Context, Module, all_modules, get_module  # noqa: F401

# Framework files, not check areas.
_EXCLUDED = frozenset({"__init__", "base"})

IMPORT_ERRORS: Dict[str, str] = {}
"""check area -> the exception that stopped it being imported."""


def module_names() -> List[str]:
    """Every check area file in this package, sorted.

    Sorted only so the recorded order is stable; the registry is sorted by
    name before anything runs.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        entries = os.listdir(here)
    except OSError:
        return []
    return sorted(
        name[:-3]
        for name in entries
        if name.endswith(".py") and name[:-3] not in _EXCLUDED
    )


def _load_all() -> None:
    for name in module_names():
        try:
            importlib.import_module(f"{__name__}.{name}")
        except Exception as exc:  # noqa: BLE001 - see the module docstring
            IMPORT_ERRORS[name] = f"{type(exc).__name__}: {exc}"


_load_all()

MODULE_NAMES: Tuple[str, ...] = tuple(module_names())
"""The check areas discovered on disk, for callers that want the list."""

__all__ = [
    "REGISTRY",
    "Context",
    "Module",
    "IMPORT_ERRORS",
    "MODULE_NAMES",
    "all_modules",
    "get_module",
    "module_names",
]
