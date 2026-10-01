"""
wazuh-doctor :: fix framework

The only part of the tool that is allowed to change the host, and it is
built so that it cannot easily do harm:

  * nothing runs without ``--fix``
  * every individual fix is confirmed interactively unless --yes is given
  * the target file is backed up first (``file.bak-<timestamp>``)
  * the config is validated *before* the change so we know the baseline
  * the config is validated *after* the change, and the backup is
    restored automatically if validation fails
  * a service is never restarted without a second, separate confirmation
  * logs, agent keys and indexer data are never touched by any fix here
"""

from __future__ import annotations

import datetime as _dt
import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

from .common import CommandResult, mask, run

# Commands that validate a config file without changing anything.
VALIDATORS: dict = {
    "/var/ossec/etc/ossec.conf": ["/var/ossec/bin/wazuh-analysisd", "-t"],
    "/var/ossec/etc/shared/agent.conf": ["/var/ossec/bin/wazuh-analysisd", "-t"],
}

ANALYSISD_TEST = ["/var/ossec/bin/wazuh-analysisd", "-t"]
VALIDATE_TIMEOUT = 30


@dataclass
class Fix:
    """A single repair the operator can opt into."""

    summary: str
    apply: Callable[[], Tuple[bool, str]]
    target: Optional[str] = None
    """File that will be modified; backed up before apply()."""
    validate_after: bool = False
    """Run the Wazuh config validator after applying."""
    restart_service: Optional[str] = None
    """Service to offer a restart for -- always a separate confirmation."""

    def __post_init__(self) -> None:
        # Guard rail: a fix may never target logs, keys or index data.
        if self.target:
            forbidden = (
                "/var/ossec/logs",
                "/var/ossec/etc/client.keys",
                "/var/lib/wazuh-indexer",
                "/var/log/wazuh-indexer",
            )
            for bad in forbidden:
                if os.path.abspath(self.target).startswith(bad):
                    raise ValueError(f"refusing to build a fix that modifies protected path: {bad}")


@dataclass
class FixOutcome:
    applied: bool = False
    confirmed: bool = False
    backup: Optional[str] = None
    rolled_back: bool = False
    message: str = ""
    restarted: bool = False


class Fixer:
    def __init__(
        self,
        assume_yes: bool = False,
        interactive: Optional[bool] = None,
        dry_run: bool = False,
    ) -> None:
        self.assume_yes = assume_yes
        self.dry_run = dry_run
        if interactive is None:
            interactive = sys.stdin.isatty()
        self.interactive = interactive

    # -- prompt helpers ---------------------------------------------------

    def _ask(self, question: str) -> bool:
        if self.assume_yes:
            print(f"  {question} [auto-yes]")
            return True
        if not self.interactive:
            # Never silently mutate a host in a non-interactive context.
            print(f"  {question} -- no TTY, skipping (use --yes to approve non-interactively)")
            return False
        while True:
            try:
                answer = input(f"  {question} [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return False
            if answer in ("y", "yes"):
                return True
            if answer in ("", "n", "no"):
                return False

    def _backup(self, path: str) -> Optional[str]:
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = f"{path}.bak-{stamp}"
        try:
            shutil.copy2(path, backup)
            return backup
        except OSError as exc:
            print(f"  ! could not back up {path}: {exc}")
            return None

    # -- validation -------------------------------------------------------

    @staticmethod
    def validate_config(path: Optional[str] = None) -> CommandResult:
        """Run the Wazuh config validator. Read-only."""
        cmd = VALIDATORS.get(path or "", ANALYSISD_TEST)
        if not os.path.exists(cmd[0]):
            return CommandResult(" ".join(cmd), 127, "", "validator not installed")
        return run(cmd, timeout=VALIDATE_TIMEOUT, use_sudo=(os.geteuid() != 0))

    # -- main entry -------------------------------------------------------

    def offer(self, fix: Fix, finding_label: str = "") -> FixOutcome:
        outcome = FixOutcome()
        print()
        print(f"  -- Proposed fix {'for ' + finding_label if finding_label else ''}")
        print(f"     {fix.summary}")
        if fix.target:
            print(f"     Target file: {fix.target}")

        if self.dry_run:
            # Before the prompt, not after: a dry run exists to show what
            # would happen. Asking "Apply this fix?" for a change that is not
            # going to be made teaches the operator to answer prompts without
            # reading them -- the exact habit this tool must not create.
            outcome.message = "dry run; nothing changed"
            print("     -> dry run, nothing changed")
            return outcome

        if not self._ask("Apply this fix?"):
            outcome.message = "declined by operator"
            print("     -> skipped")
            return outcome
        outcome.confirmed = True

        # 1. Baseline validation -- know the config was sane beforehand so
        #    we do not blame ourselves for a pre-existing failure.
        baseline_ok = True
        if fix.validate_after:
            before = self.validate_config(fix.target)
            baseline_ok = before.ok
            if not baseline_ok:
                print(f"     ! config already fails validation before the change: {before.first_line()}")
                if not self._ask("Config is ALREADY invalid. Continue anyway?"):
                    outcome.message = "aborted: pre-existing validation failure"
                    return outcome

        # 2. Backup.
        if fix.target:
            backup = self._backup(fix.target)
            if backup is None:
                outcome.message = "aborted: backup failed"
                print("     -> aborted (no backup)")
                return outcome
            outcome.backup = backup
            print(f"     backed up -> {backup}")

        # 3. Apply.
        try:
            ok, message = fix.apply()
        except Exception as exc:
            ok, message = False, f"{type(exc).__name__}: {exc}"
        if not ok:
            outcome.message = f"apply failed: {mask(message)}"
            print(f"     ! apply failed: {mask(message)}")
            if outcome.backup:
                self._restore(outcome.backup, fix.target)
                outcome.rolled_back = True
                print("     -> restored from backup")
            return outcome

        outcome.applied = True
        print(f"     applied: {mask(message)}")

        # 4. Post-change validation, with automatic rollback.
        if fix.validate_after:
            after = self.validate_config(fix.target)
            if not after.ok:
                print(f"     ! validation FAILED after change: {after.first_line()}")
                if outcome.backup:
                    self._restore(outcome.backup, fix.target)
                    outcome.rolled_back = True
                    outcome.message = "validation failed; rolled back automatically"
                    print("     -> rolled back automatically from backup")
                else:
                    outcome.message = "validation failed; no backup to roll back to"
                return outcome
            print("     validation passed")

        # 5. Restart is always a separate question.
        if fix.restart_service:
            if self._ask(f"Restart service '{fix.restart_service}' now?"):
                result = run(
                    ["systemctl", "restart", fix.restart_service],
                    timeout=120,
                    use_sudo=(os.geteuid() != 0),
                )
                outcome.restarted = result.ok
                print(f"     restart {'ok' if result.ok else 'failed: ' + result.first_line()}")
            else:
                print(f"     -> restart skipped; apply later with: systemctl restart {fix.restart_service}")

        outcome.message = outcome.message or "applied"
        return outcome

    @staticmethod
    def _restore(backup: str, target: Optional[str]) -> None:
        if not target:
            return
        try:
            shutil.copy2(backup, target)
        except OSError as exc:
            print(f"  ! ROLLBACK FAILED: {exc}")
            print(f"  ! restore manually from {backup}")
