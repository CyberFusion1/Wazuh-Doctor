"""Wazuh modules: vulnerability detector, SCA and active response errors."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Dict, List, Tuple

from .base import Context, Module
from wdlib.common import Finding, Severity, read_text, tail_lines
from wdlib.discovery import CONTROL, Component

OSSEC_LOG = "/var/ossec/logs/ossec.log"
OSSEC_CONF = "/var/ossec/etc/ossec.conf"

# Each module we track: the log tag it emits under, a friendly name, and
# what breaks when it is erroring.
TRACKED = (
    ("vulnerability-detector", "Vulnerability detector", "CVEs will not be reported for agents"),
    ("sca", "Security Configuration Assessment", "policy compliance results will be missing"),
    ("syscollector", "Syscollector", "inventory data feeds vulnerability detection, so VD degrades too"),
    ("active-response", "Active response", "automated responses will not fire"),
)

ERROR_RX = re.compile(r"\b(ERROR|CRITICAL|WARNING)\b", re.IGNORECASE)


class ModulesModule(Module):
    name = "modules"
    title = "Wazuh modules (VD, SCA, active response)"
    description = "vulnerability detector, SCA and active response errors"
    requires = (Component.MANAGER,)

    # ossec.log lines are stamped "2026/09/30 22:53:53".
    STAMP_RX = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")

    # VD's feed updates hourly by default, so a day without a single VD line
    # is a real signal; anything shorter is not.
    VD_STALE_HOURS = 24
    VD_LOG_WINDOW = 20_000

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._daemon(ctx))
        findings.extend(self._per_module(ctx))
        return findings

    # -- daemon -----------------------------------------------------------

    def _daemon(self, ctx: Context) -> List[Finding]:
        result = ctx.sudo_run([CONTROL, "status"], timeout=15)
        if not result.ok:
            return []
        line = "\n".join(ln for ln in result.stdout.splitlines() if "wazuh-modulesd" in ln)
        if line and ("not running" in line.lower() or "stopped" in line.lower()):
            return [
                self.finding(
                    Severity.CRITICAL,
                    "wazuh-modulesd is not running",
                    "modulesd hosts vulnerability detection, SCA and syscollector; "
                    "while it is down none of those produce data",
                    evidence=line,
                    fix="sudo /var/ossec/bin/wazuh-control restart",
                    verify="sudo /var/ossec/bin/wazuh-control status | grep wazuh-modulesd",
                )
            ]
        return []

    # -- per module -------------------------------------------------------

    def _per_module(self, ctx: Context) -> List[Finding]:
        lines = tail_lines(OSSEC_LOG, 1200)
        if not lines:
            return [
                self.finding(
                    Severity.INFO,
                    "module logs could not be read",
                    "ossec.log is root-readable only, so vulnerability detector, SCA "
                    "and active response errors were not inspected",
                    fix="Re-run as root: sudo wazuh-doctor --module modules",
                    verify="sudo tail -n 20 /var/ossec/logs/ossec.log",
                )
            ] if not ctx.env.is_root else []

        findings: List[Finding] = []
        for tag, title, consequence in TRACKED:
            hits = [
                ln for ln in lines
                if tag in ln.lower() and ERROR_RX.search(ln)
            ]
            if not hits:
                continue
            severity = Severity.CRITICAL if len(hits) >= 25 else Severity.WARNING
            findings.append(
                self.finding(
                    severity,
                    f"{title}: {len(hits)} error/warning line(s)",
                    f"the {title.lower()} module is logging problems, so {consequence}",
                    evidence="\n".join(hits[-10:]),
                    fix=(
                        f"    sudo grep -i '{tag}' /var/ossec/logs/ossec.log | tail -40\n"
                        f"  Then confirm the module is configured as intended in "
                        f"/var/ossec/etc/ossec.conf."
                    ),
                    verify=f"sudo grep -ci '{tag}' /var/ossec/logs/ossec.log",
                )
            )

        findings.extend(self._vd_freshness(ctx))
        return findings

    def _vd_freshness(self, ctx: Context) -> List[Finding]:
        """A VD feed that stopped updating is silent but serious.

        Freshness is judged by the *age of the newest VD log line*, never by
        the absence of VD lines from a fixed-size window. A window of "the
        last N lines" is not a measure of time: on a busy manager 1200 lines
        can span a few seconds, so a feed that updates hourly is legitimately
        missing from it, and an earlier version of this check warned about a
        stalled feed on perfectly healthy managers.
        """
        config = read_text(OSSEC_CONF)
        if config is None:
            return []
        if "<vulnerability-detection>" not in config and "vulnerability-detector" not in config:
            return []

        # A window of its own: the caller's is sized for error scanning, and
        # is far too short to contain an hourly feed update.
        recent = [
            ln
            for ln in tail_lines(OSSEC_LOG, self.VD_LOG_WINDOW)
            if "vulnerability" in ln.lower()
        ]

        newest = None
        for line in recent:
            match = self.STAMP_RX.match(line)
            if not match:
                continue
            try:
                stamp = datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S")
            except ValueError:
                continue
            if newest is None or stamp > newest:
                newest = stamp

        if newest is None:
            # Undated. That is a limit of the check, not a fact about the
            # feed, so it is reported as such rather than as a warning.
            return [
                self.finding(
                    Severity.INFO,
                    "vulnerability detector activity could not be dated",
                    "VD is configured but no VD line with a parseable timestamp "
                    "appears in the recent log, so feed freshness could not be "
                    "established; this is not evidence that the feed has stopped",
                    evidence=(
                        f"no timestamped 'vulnerability' line in the last "
                        f"{self.VD_LOG_WINDOW} lines of {OSSEC_LOG}"
                    ),
                    fix=(
                        "Confirm by hand whether the feed is updating:\n"
                        "    sudo grep -i vulnerability /var/ossec/logs/ossec.log | tail -20"
                    ),
                    verify="sudo grep -i 'vulnerability' /var/ossec/logs/ossec.log | tail -5",
                )
            ]

        age_hours = (datetime.now() - newest).total_seconds() / 3600.0
        if age_hours <= self.VD_STALE_HOURS:
            return []
        return [
            self.finding(
                Severity.WARNING,
                f"vulnerability detector has not logged activity for {age_hours:.0f}h",
                "VD is configured and its most recent log line is more than a day "
                "old; the CVE feed normally updates hourly, so new vulnerabilities "
                "may be going unreported",
                evidence=(
                    f"newest 'vulnerability' line: {newest.strftime('%Y/%m/%d %H:%M:%S')} "
                    f"({age_hours:.0f}h ago)"
                ),
                fix=(
                    "Check the feed state and force an update:\n"
                    "    sudo grep -i vulnerability /var/ossec/logs/ossec.log | tail -20\n"
                    "  Verify <vulnerability-detection><enabled>yes</enabled> and that "
                    "the manager can reach the CVE feed endpoint."
                ),
                verify="sudo grep -i 'vulnerability' /var/ossec/logs/ossec.log | tail -5",
            )
        ]
