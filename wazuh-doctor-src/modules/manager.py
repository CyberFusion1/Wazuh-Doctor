"""Wazuh manager daemon health and log analysis."""

from __future__ import annotations

import os
import re
from collections import Counter
from typing import Dict, List

from .base import Context, Module
from wdlib.common import Finding, Severity, path_state, tail_lines
from wdlib.discovery import CONTROL, Component

# Daemons the manager is expected to be running. wazuh-control status
# reports each one as "<name> is running..." / "<name> not running...".
EXPECTED_DAEMONS = (
    "wazuh-analysisd",
    "wazuh-remoted",
    "wazuh-db",
    "wazuh-execd",
    "wazuh-modulesd",
    "wazuh-logcollector",
    "wazuh-syscheckd",
    "wazuh-monitord",
)

OPTIONAL_DAEMONS = ("wazuh-authd", "wazuh-clusterd", "wazuh-apid", "wazuh-agentd")

# Noise that is present on healthy installs and would otherwise drown
# out real errors.
BENIGN = re.compile(
    r"(syscollector.*(finished|starting)|"
    r"Loading shared libraries|"
    r"wazuh-modulesd:syscollector.*INFO)",
    re.IGNORECASE,
)

ERROR_RX = re.compile(r"\b(ERROR|CRITICAL|FATAL)\b", re.IGNORECASE)


class ManagerModule(Module):
    name = "manager"
    title = "Manager daemon and log health"
    description = "wazuh-control daemon status and ossec.log error analysis"
    requires = (Component.MANAGER,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._daemons(ctx))
        findings.extend(self._logs(ctx))
        return findings

    # -- daemons ----------------------------------------------------------

    def _daemons(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        result = ctx.sudo_run([CONTROL, "status"], timeout=15)

        if result.missing or not result.ok:
            # We could not ask wazuh-control. Before claiming the manager is
            # down, rule out the case where we simply were not allowed to
            # run it -- a false CRITICAL here would be actively misleading.
            if result.denied:
                findings.append(
                    self.finding(
                        Severity.INFO,
                        "manager daemon status needs root",
                        "wazuh-control could not be run without privileges, so the "
                        "daemon states were not verified",
                        evidence=result.output[:400],
                        fix="Re-run as root: sudo wazuh-doctor --module manager",
                        verify="sudo /var/ossec/bin/wazuh-control status",
                    )
                )
                return findings

            # Fall back to systemd so we still say something useful.
            unit = ctx.run(["systemctl", "is-active", "wazuh-manager"], timeout=8)
            state = unit.stdout.strip() or "unknown"
            if state != "active" and not unit.denied and not unit.missing:
                findings.append(
                    self.finding(
                        Severity.CRITICAL,
                        "the Wazuh manager is not running",
                        "wazuh-control could not report status and systemd does not "
                        f"consider wazuh-manager active (state: {state})",
                        evidence=(result.output or unit.output or "no output from either check")[:800],
                        fix=(
                            "Start the manager and read why it stopped:\n"
                            "    sudo systemctl start wazuh-manager\n"
                            "    sudo journalctl -u wazuh-manager -n 100 --no-pager"
                        ),
                        verify="sudo /var/ossec/bin/wazuh-control status",
                    )
                )
            return findings

        states = self._parse_status(result.stdout)
        for daemon in EXPECTED_DAEMONS:
            running = states.get(daemon)
            if running is False:
                findings.append(
                    self.finding(
                        Severity.CRITICAL,
                        f"manager daemon {daemon} is not running",
                        f"{daemon} is a required manager daemon; while it is down its "
                        f"function is unavailable and events may be lost or unprocessed",
                        evidence=self._daemon_evidence(result.stdout, daemon),
                        fix=(
                            f"Restart the manager and inspect the log for why {daemon} exited:\n"
                            f"    sudo /var/ossec/bin/wazuh-control restart\n"
                            f"    sudo tail -n 200 /var/ossec/logs/ossec.log"
                        ),
                        verify=f"sudo /var/ossec/bin/wazuh-control status | grep {daemon}",
                    )
                )
        for daemon in OPTIONAL_DAEMONS:
            if states.get(daemon) is False and daemon == "wazuh-agentd":
                # The manager hosts an agentd; worth a warning, not critical.
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        "local wazuh-agentd is not running on the manager",
                        "the manager host also runs an agent; without agentd this host "
                        "reports no local telemetry",
                        evidence=self._daemon_evidence(result.stdout, daemon),
                        fix="sudo /var/ossec/bin/wazuh-control restart",
                        verify="sudo /var/ossec/bin/wazuh-control status | grep wazuh-agentd",
                    )
                )
        return findings

    @staticmethod
    def _parse_status(stdout: str) -> Dict[str, bool]:
        """Map daemon -> running. Handles both wordings wazuh-control uses."""
        states: Dict[str, bool] = {}
        for line in stdout.splitlines():
            match = re.match(r"\s*(wazuh-[a-z]+)\s+(.*)", line)
            if not match:
                continue
            daemon, rest = match.group(1), match.group(2).lower()
            if "not running" in rest or "stopped" in rest:
                states[daemon] = False
            elif "running" in rest:
                states[daemon] = True
        return states

    @staticmethod
    def _daemon_evidence(stdout: str, daemon: str) -> str:
        lines = [ln for ln in stdout.splitlines() if daemon in ln]
        return "\n".join(lines) or f"no status line mentioning {daemon}"

    # -- logs -------------------------------------------------------------

    def _logs(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        path = "/var/ossec/logs/ossec.log"
        lines = tail_lines(path, 800)

        if not lines:
            # "present" or "unknown" both mean the log is there and we were
            # not allowed in; claiming nothing here silently dropped the
            # "re-run as root" note on every unprivileged manager run.
            if not ctx.env.is_root and path_state(path) != "missing":
                findings.append(
                    self.finding(
                        Severity.INFO,
                        "ossec.log could not be read without root",
                        "the manager log is root-readable only, so log-based diagnosis "
                        "was skipped for this run",
                        fix="Re-run as root: sudo wazuh-doctor --module manager",
                        verify="sudo tail -n 5 /var/ossec/logs/ossec.log",
                    )
                )
            return findings

        errors = [ln for ln in lines if ERROR_RX.search(ln) and not BENIGN.search(ln)]
        if not errors:
            return findings

        # Collapse repeated errors so one looping daemon does not produce
        # hundreds of identical finding lines.
        def signature(line: str) -> str:
            return re.sub(r"\d", "#", line.split(": ", 2)[-1])[:120]

        counts = Counter(signature(ln) for ln in errors)
        top, top_count = counts.most_common(1)[0]

        findings.append(
            self.finding(
                Severity.CRITICAL if top_count >= 20 else Severity.WARNING,
                f"{len(errors)} error line(s) in ossec.log ({len(counts)} distinct)",
                "the manager log contains ERROR/CRITICAL entries; the most frequent "
                f"signature repeated {top_count} time(s)",
                evidence="\n".join(errors[-12:]),
                fix=(
                    "Inspect the errors above, then the surrounding context:\n"
                    "    sudo grep -n 'ERROR\\|CRITICAL' /var/ossec/logs/ossec.log | tail -50\n"
                    "  Common causes: analysisd rule errors, remoted queue saturation,\n"
                    "  database corruption, or an unreachable indexer."
                ),
                verify="sudo grep -c ERROR /var/ossec/logs/ossec.log",
            )
        )
        return findings

    # -- host resource pressure -------------------------------------------
    #
    # Deliberately NOT checked here. Disk, memory, swap and load were once
    # reported by both this module and modules/performance.py, so a host
    # under pressure produced two findings for every one condition and the
    # report read as noise. performance.py owns host resource pressure and
    # reports it against the Wazuh paths that actually matter; this module
    # sticks to the daemons and the manager log.

