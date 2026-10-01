"""Remoted connectivity: which agents are actually delivering events."""

from __future__ import annotations

import os
import re
from typing import List, Tuple

from .base import Context, Module
from wdlib.common import Finding, Severity, grep, read_text, tail_lines
from wdlib.discovery import CONTROL, Component

OSSEC_LOG = "/var/ossec/logs/ossec.log"
RIDS_DIR = "/var/ossec/queue/rids"

# agent_control statuses we care about, worst first.
STATUS_PATTERNS = (
    ("Never connected", re.compile(r"never\s+connected", re.IGNORECASE)),
    ("Disconnected", re.compile(r"\bdisconnected\b", re.IGNORECASE)),
    ("Pending", re.compile(r"\bpending\b", re.IGNORECASE)),
    ("Active", re.compile(r"\bactive\b", re.IGNORECASE)),
)

AGENT_LINE = re.compile(r"ID:\s*(\d+)\s*,\s*Name:\s*([^,]+?)\s*,\s*IP:\s*([^,]+?)\s*,\s*(.*)")


class RemotedConnectivityModule(Module):
    name = "remoted_connectivity"
    title = "Agent connectivity (remoted)"
    description = "disconnected and never-connected agents, remoted port and queue"
    requires = (Component.MANAGER,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._port(ctx))
        findings.extend(self._agents(ctx))
        findings.extend(self._log(ctx))
        return findings

    # -- port -------------------------------------------------------------

    def _port(self, ctx: Context) -> List[Finding]:
        if ctx.env.port_open(1514):
            return []
        return [
            self.finding(
                Severity.CRITICAL,
                "event port 1514 is not listening",
                "wazuh-remoted receives all agent traffic on 1514; while it is closed "
                "no agent can deliver events, so the deployment is blind",
                evidence="no listener on TCP 1514 in /proc/net/tcp{,6}",
                fix=(
                    "Start the manager and confirm remoted:\n"
                    "    sudo /var/ossec/bin/wazuh-control restart\n"
                    "    sudo /var/ossec/bin/wazuh-control status | grep wazuh-remoted\n"
                    "  If the port stays closed, inspect the <remote> block in "
                    "/var/ossec/etc/ossec.conf."
                ),
                verify="ss -lntp | grep :1514",
            )
        ]

    # -- agent roster -----------------------------------------------------

    def _agents(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        result = ctx.sudo_run(["/var/ossec/bin/agent_control", "-l"], timeout=15)

        if result.missing:
            return []
        if not result.ok or result.denied:
            findings.append(
                self.finding(
                    Severity.INFO,
                    "agent roster could not be read",
                    "agent_control needs root, so per-agent connection state was not checked",
                    evidence=(result.output or "no output")[:400],
                    fix="Re-run as root: sudo wazuh-doctor --module remoted_connectivity",
                    verify="sudo /var/ossec/bin/agent_control -l",
                )
            )
            return findings

        buckets = self._parse_agents(result.stdout)
        never = buckets.get("Never connected", [])
        disconnected = buckets.get("Disconnected", [])
        pending = buckets.get("Pending", [])
        active = buckets.get("Active", [])

        if never:
            findings.append(
                self.finding(
                    Severity.CRITICAL,
                    f"{len(never)} agent(s) never connected",
                    "these agents have enrolled but have never successfully delivered "
                    "an event to the manager, so the manager has no telemetry for them",
                    evidence=self._render(never),
                    fix=(
                        "On each affected agent host, check the agent can reach the "
                        "manager and that keys match:\n"
                        "    sudo /var/ossec/bin/wazuh-control status\n"
                        "    sudo tail -n 100 /var/ossec/logs/ossec.log\n"
                        "    nc -zv <manager-ip> 1514\n"
                        "  If the agent was reinstalled, remove the stale entry and "
                        "re-enroll it."
                    ),
                    verify="sudo /var/ossec/bin/agent_control -l",
                )
            )

        if disconnected:
            findings.append(
                self.finding(
                    Severity.WARNING,
                    f"{len(disconnected)} agent(s) disconnected",
                    "these agents enrolled previously but are not delivering events now; "
                    "either the agent is stopped, or the network path to 1514 is broken",
                    evidence=self._render(disconnected),
                    fix=(
                        "Check the agent service and network path on each host, and "
                        "confirm the manager is not refusing them:\n"
                        "    sudo grep -i 'not allowed\\|too many\\|queue is full' "
                        "/var/ossec/logs/ossec.log | tail -20"
                    ),
                    verify="sudo /var/ossec/bin/agent_control -l",
                )
            )

        if pending:
            findings.append(
                self.finding(
                    Severity.WARNING,
                    f"{len(pending)} agent(s) pending",
                    "these agents were added to the manager manually but have not yet "
                    "sent their first event, usually because they were never started "
                    "or cannot reach port 1514",
                    evidence=self._render(pending),
                    fix=(
                        "Start the agent on each host, or confirm it is expecting the "
                        "correct manager address:\n"
                        "    grep -A3 '<client>' /var/ossec/etc/ossec.conf"
                    ),
                    verify="sudo /var/ossec/bin/agent_control -l",
                )
            )

        if not (never or disconnected or pending) and active:
            # Healthy: report nothing. Silence is the correct output.
            return findings

        if not active and not (never or disconnected or pending) and ctx.env.agents_count in (None, 0):
            findings.append(
                self.finding(
                    Severity.WARNING,
                    "no agents are reporting to this manager",
                    "remoted is listening but the manager has no agents delivering "
                    "events, so no security telemetry is being collected",
                    evidence=(result.output or "")[:600],
                    fix="Enroll an agent: sudo /var/ossec/bin/agent-auth -m <manager-ip>",
                    verify="sudo /var/ossec/bin/agent_control -l",
                )
            )
        return findings

    @staticmethod
    def _parse_agents(stdout: str) -> dict:
        buckets: dict = {}
        for line in stdout.splitlines():
            match = AGENT_LINE.search(line)
            if not match:
                continue
            agent_id, name, ip, tail = match.groups()
            status = "Unknown"
            for label, pattern in STATUS_PATTERNS:
                if pattern.search(tail):
                    status = label
                    break
            buckets.setdefault(status, []).append(f"  ID {agent_id}: {name.strip()} ({ip.strip()})")
        return buckets

    @staticmethod
    def _render(entries: List[str], limit: int = 15) -> str:
        shown = entries[:limit]
        if len(entries) > limit:
            shown.append(f"  ... and {len(entries) - limit} more")
        return "\n".join(shown)

    @staticmethod
    def _log(ctx: Context) -> List[Finding]:
        lines = tail_lines(OSSEC_LOG, 600)
        if not lines:
            return []
        patterns = (
            r"queue is full",
            r"Too many agents",
            r"Unable to send",
            r"dropping",
        )
        hits = [ln for ln in lines if "wazuh-remoted" in ln and any(
            re.search(p, ln, re.IGNORECASE) for p in patterns
        )]
        if not hits:
            return []
        return [
            Finding(
                module="remoted_connectivity",
                severity=Severity.WARNING,
                issue=f"{len(hits)} remoted warning(s) about queue or delivery pressure",
                root_cause="remoted is reporting that it cannot keep up with inbound "
                "agent traffic or is refusing agents",
                evidence="\n".join(hits[-12:]),
                fix=(
                    "Check queue depth and agent count:\n"
                    "    ls -1 /var/ossec/queue/rids | wc -l\n"
                    "    sudo grep -c 'queue is full' /var/ossec/logs/ossec.log\n"
                    "  Raised limits (`queue_size` in <remote>) or a larger host may be needed."
                ),
                verify="sudo grep wazuh-remoted /var/ossec/logs/ossec.log | tail -20",
            )
        ]
