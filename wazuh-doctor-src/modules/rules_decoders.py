"""Rules and decoders: custom file syntax, duplicate IDs, wazuh-logtest."""

from __future__ import annotations

import glob
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Dict, List, Optional, Tuple

from .base import Context, Module
from wdlib.common import Finding, Severity, path_state, read_text
from wdlib.discovery import Component

RULES_DIR = "/var/ossec/etc/rules"
DECODERS_DIR = "/var/ossec/etc/decoders"
RULES_GLOB = RULES_DIR + "/*.xml"
DECODERS_GLOB = DECODERS_DIR + "/*.xml"

LOG_TEST = "/var/ossec/bin/wazuh-logtest"


class RulesDecodersModule(Module):
    name = "rules_decoders"
    title = "Custom rules and decoders"
    description = "syntax, duplicate rule IDs, duplicate decoder names, wazuh-logtest"
    requires = (Component.MANAGER,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []

        rule_files = self._files(RULES_GLOB)
        decoder_files = self._files(DECODERS_GLOB)

        if not rule_files and not decoder_files:
            # An empty glob means "no files" OR "a directory I may not
            # search". Claiming there is nothing custom to validate on a
            # manager whose rules directory is simply unreadable is a false
            # statement of fact.
            if not ctx.env.is_root and (
                path_state(RULES_DIR) == "unknown"
                or path_state(DECODERS_DIR) == "unknown"
            ):
                return [
                    self.finding(
                        Severity.INFO,
                        "custom rules and decoders could not be read",
                        "the rules and decoders directories are root-readable only, "
                        "so custom syntax, duplicate IDs and quality could not be "
                        "validated",
                        evidence=f"unreadable: {RULES_DIR}, {DECODERS_DIR}",
                        fix="Re-run as root: sudo wazuh-doctor --module rules_decoders",
                        verify="sudo ls /var/ossec/etc/rules/ /var/ossec/etc/decoders/",
                    )
                ]
            return [
                self.finding(
                    Severity.INFO,
                    "no custom rule or decoder files found",
                    "this manager relies entirely on the shipped ruleset; there is "
                    "nothing custom to validate",
                    evidence=f"checked {RULES_GLOB} and {DECODERS_GLOB}",
                    fix="No action needed unless custom rules are expected.",
                    verify="ls /var/ossec/etc/rules/ /var/ossec/etc/decoders/",
                )
            ]

        findings.extend(self._syntax(ctx, rule_files, "rule"))
        findings.extend(self._syntax(ctx, decoder_files, "decoder"))
        findings.extend(self._duplicates(ctx, rule_files, "rule", "id"))
        findings.extend(self._duplicates(ctx, decoder_files, "decoder", "name"))
        findings.extend(self._quality(ctx, rule_files))
        findings.extend(self._logtest(ctx))
        return findings

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _files(pattern: str) -> List[str]:
        try:
            return sorted(p for p in glob.glob(pattern) if os.path.isfile(p))
        except OSError:
            return []

    @staticmethod
    def _parse(path: str) -> Tuple[Optional[ET.Element], Optional[str]]:
        content = read_text(path)
        if content is None:
            return None, "unreadable"
        try:
            return ET.fromstring(content), None
        except ET.ParseError as exc:
            return None, str(exc)

    # -- syntax -----------------------------------------------------------

    def _syntax(self, ctx: Context, files: List[str], kind: str) -> List[Finding]:
        findings: List[Finding] = []
        for path in files:
            root, error = self._parse(path)
            if error == "unreadable":
                if not ctx.env.is_root:
                    findings.append(
                        self.finding(
                            Severity.INFO,
                            f"custom {kind} file could not be read",
                            "custom rules and decoders under /var/ossec are "
                            "root-readable only",
                            evidence=f"{path}: permission denied",
                            fix="Re-run as root: sudo wazuh-doctor --module rules_decoders",
                            verify=f"sudo python3 -c \"import xml.etree.ElementTree as E; E.parse('{path}')\"",
                        )
                    )
                continue
            if error:
                findings.append(
                    self.finding(
                        Severity.CRITICAL,
                        f"custom {kind} file has invalid XML",
                        f"wazuh-analysisd refuses to load a malformed {kind} file, and in "
                        f"some versions this prevents analysisd from starting at all",
                        evidence=f"{path}\nXML parse error: {error}",
                        fix=(
                            "Fix the XML. Validate before restarting:\n"
                            f"    python3 -c \"import xml.etree.ElementTree as E; E.parse('{path}')\"\n"
                            "    sudo wazuh-analysisd -t"
                        ),
                        verify="sudo wazuh-analysisd -t",
                    )
                )
        return findings

    # -- duplicates -------------------------------------------------------

    def _duplicates(self, ctx: Context, files: List[str], kind: str, attr: str) -> List[Finding]:
        entries: Dict[str, List[str]] = {}
        for path in files:
            root, error = self._parse(path)
            if root is None:
                continue
            for element in root.iter():
                value = element.get(attr)
                if value:
                    entries.setdefault(value.strip(), []).append(os.path.basename(path))

        duplicates = {key: where for key, where in entries.items() if len(where) > 1}
        if not duplicates:
            return []

        sample = "\n".join(
            f"  {kind} {attr}={key} defined in: {', '.join(sorted(set(where)))}"
            for key, where in sorted(duplicates.items())[:10]
        )
        return [
            self.finding(
                Severity.CRITICAL if kind == "rule" else Severity.WARNING,
                f"{len(duplicates)} duplicate {kind} {attr}(s) in custom files",
                f"Wazuh loads custom {kind}s over the shipped ruleset; a duplicate "
                f"{attr} is ambiguous and rules with a repeated ID are rejected or "
                f"silently shadow each other",
                evidence=sample,
                fix=(
                    f"Assign unique {attr}s. Note that custom rules must use IDs "
                    f"100000-120000 to avoid colliding with the shipped ruleset."
                    if kind == "rule"
                    else f"Rename the duplicate decoder {attr}s so each is unique."
                ),
                # wazuh-logtest is interactive and has no validation flag.
                # wazuh-analysisd -t is the authoritative "does this ruleset
                # load" check, and is what the operator can actually run.
                verify="sudo wazuh-analysisd -t",
            )
        ]

    # -- quality ----------------------------------------------------------

    def _quality(self, ctx: Context, files: List[str]) -> List[Finding]:
        """Rules that can never fire meaningfully are worth flagging."""
        suspicious: List[str] = []
        for path in files:
            root, error = self._parse(path)
            if root is None:
                continue
            for rule in root.iter("rule"):
                level = rule.get("level")
                has_desc = rule.find("description") is not None
                has_match = any(
                    rule.find(tag) is not None
                    for tag in ("match", "regex", "decoded_as", "program_name", "if_sid", "if_group")
                )
                if not has_desc and not has_match:
                    suspicious.append(
                        f"  {os.path.basename(path)}: rule id={rule.get('id', '?')} "
                        f"level={level or '?'} has neither description nor matching criteria"
                    )
        if not suspicious:
            return []
        return [
            self.finding(
                Severity.WARNING,
                f"{len(suspicious)} custom rule(s) appear incomplete",
                "a rule with neither a description nor any matching criteria will "
                "never fire as intended, which usually indicates a copy/paste error",
                evidence="\n".join(suspicious[:10]),
                fix="Give each rule a <description> and at least one matching criterion.",
                verify="sudo wazuh-analysisd -t",
            )
        ]

    # -- logtest ----------------------------------------------------------

    # wazuh-logtest has no validation flag. `wazuh-logtest -t` does not
    # exist: running it answered "unrecognized arguments: -t", and an
    # earlier version of this module reported that as a broken ruleset --
    # a CRITICAL on a healthy manager, caused by the tool's own bad
    # argument. A failure to run a command is never evidence about the
    # thing the command was meant to inspect.
    #
    # What logtest does do is load the rule and decoder set the same way
    # analysisd does, then decode one log line. Feeding it a benign line
    # exercises that load without needing an interactive terminal.
    LOGTEST_SAMPLE = (
        "Jan  1 00:00:00 host sshd[1234]: Failed password for invalid user test "
        "from 192.0.2.1 port 40000 ssh2"
    )

    # Phrases logtest emits when it cannot load the ruleset. Deliberately
    # narrow: a load failure, not merely any output containing "error".
    LOAD_FAILURES = (
        r"error loading",
        r"failed to load",
        r"unable to load",
        r"could not load",
        r"error reading",
        r"cannot open.{0,40}rules",
    )

    def _logtest(self, ctx: Context) -> List[Finding]:
        if not os.path.exists(LOG_TEST):
            return []

        result = ctx.sudo_run(
            [LOG_TEST, "-q"], timeout=25, stdin=self.LOGTEST_SAMPLE + "\n"
        )
        if result.missing or result.ok:
            return []

        blob = result.output.lower()

        if result.denied:
            return [
                self.finding(
                    Severity.INFO,
                    "wazuh-logtest needs root",
                    "logtest could not be run without privileges, so rule and decoder "
                    "loading was not exercised",
                    evidence=result.output[:300],
                    fix="Re-run as root: sudo wazuh-doctor --module rules_decoders",
                    verify="sudo wazuh-logtest",
                )
            ]

        # A usage or argument error is about how we invoked logtest, not
        # about the ruleset. This branch exists so that the failure mode
        # described above can never come back as a CRITICAL.
        if "usage:" in blob or "unrecognized arguments" in blob or result.rc == 2:
            return [
                self.finding(
                    Severity.INFO,
                    "wazuh-logtest could not be exercised",
                    "logtest rejected the way it was invoked, which says nothing about "
                    "the ruleset; the static rule and decoder checks above still apply",
                    evidence=result.output[:300],
                    fix="Not a defect. Run logtest by hand if a full end-to-end test is wanted.",
                    verify="sudo wazuh-logtest   # then paste a sample log line",
                )
            ]

        if "terminal" in blob or "tty" in blob or "stdin" in blob:
            return [
                self.finding(
                    Severity.INFO,
                    "wazuh-logtest could not run non-interactively",
                    "logtest expects an interactive session in this version, so rule "
                    "and decoder loading could not be exercised end to end",
                    fix="Run it manually and feed a sample log line: sudo wazuh-logtest",
                    verify="sudo wazuh-logtest",
                )
            ]

        if any(re.search(pattern, blob) for pattern in self.LOAD_FAILURES):
            return [
                self.finding(
                    Severity.CRITICAL,
                    "the custom ruleset does not load",
                    "logtest loads the rule and decoder set the same way analysisd does, "
                    "and reported a failure to load it, so analysisd cannot use these "
                    "rules",
                    evidence=result.output[:1200],
                    fix=(
                        "Correct the reported problem, then re-validate. wazuh-analysisd "
                        "-t is the authoritative check for whether the ruleset loads:\n"
                        "    sudo wazuh-analysisd -t\n"
                        "    sudo wazuh-logtest   # then paste a sample log line"
                    ),
                    verify="sudo wazuh-analysisd -t",
                )
            ]

        # An unrecognised failure. Say what happened rather than guessing a
        # cause: inventing a root cause here is how a false CRITICAL gets
        # written in the first place.
        return [
            self.finding(
                Severity.WARNING,
                "wazuh-logtest exited with a non-zero status",
                "logtest failed in a way this check does not recognise, so rule and "
                "decoder loading could not be confirmed either way",
                evidence=result.output[:1200] or "no output",
                fix=(
                    "Run it manually to see the full output:\n"
                    "    sudo wazuh-logtest\n"
                    "  The authoritative load check is: sudo wazuh-analysisd -t"
                ),
                verify="sudo wazuh-analysisd -t",
            )
        ]
