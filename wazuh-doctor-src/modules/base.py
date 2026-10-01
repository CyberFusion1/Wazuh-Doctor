"""
wazuh-doctor :: module framework

Every check area is a subclass of ``Module``. The registry is filled by
``__init_subclass__`` so adding a file to modules/ plus one import is all
it takes to add a check area.

A module declares which components it needs. If none of them are present
on this host the module is skipped with a note rather than failing, which
is what makes one binary work across all-in-one, distributed and
agent-only deployments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Type

from wdlib.common import Config, Finding, Severity, run
from wdlib.discovery import Component, Environment

# Populated by Module.__init_subclass__
REGISTRY: Dict[str, Type["Module"]] = {}


@dataclass
class Context:
    """Everything a module needs, passed in rather than global."""

    env: Environment
    config: Config
    fixer: object = None  # wdlib.fixer.Fixer, or None in read-only mode
    verbose: bool = False
    extra: Dict[str, object] = field(default_factory=dict)

    @property
    def is_root(self) -> bool:
        return self.env.is_root

    def run(self, cmd, timeout: int = 10, use_sudo: bool = False, stdin=None):
        return run(cmd, timeout=timeout, use_sudo=use_sudo, stdin=stdin)

    def sudo_run(self, cmd, timeout: int = 10, stdin=None):
        """Run as root; transparently falls back when already root."""
        return run(cmd, timeout=timeout, use_sudo=(os.geteuid() != 0), stdin=stdin)


class Module:
    # -- metadata a subclass overrides ------------------------------------
    name: str = "unnamed"
    title: str = "Unnamed module"
    description: str = ""
    requires: Sequence[str] = ()
    """Components; the module runs if ANY of these are present.
    Empty tuple means the module always runs."""

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "name", "unnamed") != "unnamed":
            REGISTRY[cls.name] = cls

    # -- lifecycle --------------------------------------------------------

    def applicable(self, env: Environment) -> bool:
        if not self.requires:
            return True
        return env.any_of(*self.requires)

    def skip_reason(self, env: Environment) -> str:
        missing = [c for c in self.requires if not env.has(c)]
        return f"component not installed: {', '.join(missing) or 'unknown'}"

    def run(self, ctx: Context) -> List[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- helpers for subclasses -------------------------------------------

    def finding(
        self,
        severity: Severity,
        issue: str,
        root_cause: str,
        evidence: str = "",
        fix: str = "",
        verify: str = "",
        fixable: bool = False,
        fix_action: object = None,
    ) -> Finding:
        """Build a Finding already tagged with this module's name.

        Evidence is masked inside Finding, so callers may pass raw
        command output or a raw log line directly.

        ``fix_action`` is an optional wdlib.fixer.Fix; when present the
        CLI offers it under --fix.
        """
        return Finding(
            module=self.name,
            severity=severity,
            issue=issue,
            root_cause=root_cause,
            evidence=evidence,
            fix=fix,
            verify=verify,
            fixable=fixable,
            fix_action=fix_action,
        )

    def ok(self, message: str = "") -> List[Finding]:
        """Explicit clean result -- useful for verbose mode."""
        return []


def get_module(name: str) -> Optional[Type[Module]]:
    return REGISTRY.get(name)


def all_modules() -> List[Type[Module]]:
    return [REGISTRY[key] for key in sorted(REGISTRY)]
