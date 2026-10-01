"""Linux agent: service state, log errors, and connection to the manager."""

from __future__ import annotations

import os
import re
import socket
from typing import List, Optional

from .base import Context, Module
from wdlib.common import Finding, Severity, path_state, read_text, systemd_unit_exists, tail_lines
from wdlib.discovery import CONTROL, Component

OSSEC_LOG = "/var/ossec/logs/ossec.log"
OSSEC_CONF = "/var/ossec/etc/ossec.conf"
CLIENT_KEYS = "/var/ossec/etc/client.keys"

CONNECTION_ERRORS = (
    r"Unable to connect",
    r"Connection refused",
    r"Server unavailable",
    r"Unable to resolve",
    r"Connection reset",
    r"Disconnected",
)

# <client><server><address>MANAGER</address>  (or <hostname>/<ip>)
SERVER_RX = re.compile(r"<server>\s*(?:<address>|<hostname>|<ip>)\s*([^<\s]+)", re.IGNORECASE)


class LinuxAgentModule(Module):
    name = "linux_agent"
    title = "Linux agent health"
    description = "agent service status, ossec.log errors, manager reachability"
    requires = (Component.AGENT,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._service(ctx))
        findings.extend(self._daemon(ctx))
        findings.extend(self._log(ctx))
        findings.extend(self._manager_reachable(ctx))
        findings.extend(self._keys(ctx))
        return findings

    # -- service ----------------------------------------------------------

    def _service(self, ctx: Context) -> List[Finding]:
        for unit in ("wazuh-agent", "wazuh-manager"):
            # "is-active" reports "inactive" for a unit that does not exist,
            # which would read as "the agent service is down" on a host that
            # simply does not ship that unit.
            if not systemd_unit_exists(unit):
                continue
            result = ctx.run(["systemctl", "is-active", unit], timeout=8)
            if result.missing:
                return []
            if result.output.strip() == "active":
                return []
            if "could not be found" in result.output.lower() or "not-found" in result.output.lower():
                continue
            return [
                self.finding(
                    Severity.CRITICAL,
                    f"agent service {unit} is not active",
                    "the agent service is not running, so this host is sending no "
                    "telemetry and is effectively unprotected",
                    evidence=f"systemctl is-active {unit} -> {result.output.strip()}",
                    fix=(
                        f"    sudo systemctl start {unit}\n"
                        f"    sudo systemctl enable {unit}\n"
                        f"    sudo journalctl -u {unit} -n 100 --no-pager"
                    ),
                    verify=f"systemctl is-active {unit}",
                )
            ]
        return []

    def _daemon(self, ctx: Context) -> List[Finding]:
        result = ctx.sudo_run([CONTROL, "status"], timeout=15)
        if not result.ok:
            return []
        line = "\n".join(ln for ln in result.stdout.splitlines() if "wazuh-agentd" in ln)
        if line and ("not running" in line.lower() or "stopped" in line.lower()):
            return [
                self.finding(
                    Severity.CRITICAL,
                    "wazuh-agentd is not running",
                    "the agent daemon that talks to the manager is stopped, so no "
                    "events are being forwarded",
                    evidence=line,
                    fix="sudo /var/ossec/bin/wazuh-control restart",
                    verify="sudo /var/ossec/bin/wazuh-control status | grep wazuh-agentd",
                )
            ]
        return []

    # -- log --------------------------------------------------------------

    def _log(self, ctx: Context) -> List[Finding]:
        lines = tail_lines(OSSEC_LOG, 600)
        if not lines:
            if not ctx.env.is_root and path_state(OSSEC_LOG) != "missing":
                return [
                    self.finding(
                        Severity.INFO,
                        "agent log could not be read without root",
                        "ossec.log is root-readable only, so log-based checks were skipped",
                        fix="Re-run as root: sudo wazuh-doctor --module linux_agent",
                        verify=f"sudo tail -n 5 {OSSEC_LOG}",
                    )
                ]
            return []

        # On a manager this same file carries remoted lines about *remote*
        # agents disconnecting. Restricting to the local agentd's own lines
        # keeps those from being misread as this host failing to connect.
        scope = [ln for ln in lines if "wazuh-agentd" in ln] if ctx.env.is_manager else lines

        connection_hits = [
            ln for ln in scope if any(re.search(p, ln, re.IGNORECASE) for p in CONNECTION_ERRORS)
        ]
        if connection_hits:
            return [
                self.finding(
                    Severity.CRITICAL,
                    "the agent cannot reach its manager",
                    "the agent log shows connection failures to the manager; while this "
                    "persists the manager receives no events from this host",
                    evidence="\n".join(connection_hits[-12:]),
                    fix=(
                        "Verify the manager address and that port 1514 is reachable:\n"
                        "    grep -A3 '<client>' /var/ossec/etc/ossec.conf\n"
                        "    nc -zv <manager-ip> 1514\n"
                        "  Then restart the agent: sudo /var/ossec/bin/wazuh-control restart"
                    ),
                    verify="sudo tail -n 30 /var/ossec/logs/ossec.log",
                )
            ]

        errors = [ln for ln in scope if re.search(r"\b(ERROR|CRITICAL)\b", ln, re.IGNORECASE)]
        if errors:
            return [
                self.finding(
                    Severity.WARNING,
                    f"{len(errors)} error line(s) in the agent log",
                    "the agent is logging errors, which may indicate failing log "
                    "collection, a bad rule, or partial connectivity",
                    evidence="\n".join(errors[-12:]),
                    fix=(
                        "Inspect them in context:\n"
                        "    sudo grep -nE 'ERROR|CRITICAL' /var/ossec/logs/ossec.log | tail -30"
                    ),
                    verify="sudo grep -c ERROR /var/ossec/logs/ossec.log",
                )
            ]
        return []

    # -- reachability -----------------------------------------------------

    def _manager_reachable(self, ctx: Context) -> List[Finding]:
        content = read_text(OSSEC_CONF)
        if content is None:
            return []
        match = SERVER_RX.search(content)
        if not match:
            return []
        address = match.group(1).strip()
        reachable, detail = self._tcp_probe(address, 1514, timeout=5)
        if reachable:
            return []
        return [
            self.finding(
                Severity.CRITICAL,
                f"manager address {address} is not reachable on port 1514",
                "the configured manager does not accept a TCP connection on the agent "
                "event port, so this agent cannot deliver anything",
                evidence=f"configured server address: {address}\nTCP connect to {address}:1514 -> {detail}",
                fix=(
                    f"Check the path to the manager:\n"
                    f"    nc -zv {address} 1514\n"
                    f"    ping -c2 {address}\n"
                    f"  Confirm the manager's remoted is listening and that no firewall "
                    f"between the two hosts blocks 1514."
                ),
                verify=f"nc -zv {address} 1514",
            )
        ]

    @staticmethod
    def _tcp_probe(host: str, port: int, timeout: float = 5.0):
        """Return (reachable, detail). Never raises."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, "connected"
        except socket.timeout:
            return False, f"timed out after {timeout}s"
        except socket.gaierror as exc:
            return False, f"name resolution failed: {exc}"
        except OSError as exc:
            return False, f"{type(exc).__name__}: {exc}"

    # -- enrollment -------------------------------------------------------

    def _keys(self, ctx: Context) -> List[Finding]:
        state = path_state(CLIENT_KEYS)
        if state != "present":
            if ctx.env.is_manager:
                # A manager with no client.keys simply has no agents enrolled
                # yet; authd_enrollment reports that. It does not mean "this
                # host is an unenrolled agent".
                return []
            if state == "unknown":
                # /var/ossec is 0750, so an unprivileged run cannot tell an
                # absent client.keys from one it may not read. A CRITICAL
                # "the agent has no client.keys" here would accuse a
                # correctly enrolled agent of having no identity -- and
                # agent-only hosts are where this module matters most.
                return [
                    self.finding(
                        Severity.INFO,
                        "client.keys could not be read",
                        "the agent's enrollment key is root-readable only, so "
                        "enrollment could not be verified; this is not evidence that "
                        "it is missing",
                        fix="Re-run as root: sudo wazuh-doctor --module linux_agent",
                        verify=f"sudo ls -l {CLIENT_KEYS}",
                    )
                ]
            return [
                self.finding(
                    Severity.CRITICAL,
                    "the agent has no client.keys",
                    "without an enrollment key the agent has no identity and cannot "
                    "authenticate to the manager",
                    evidence=f"{CLIENT_KEYS} is missing",
                    fix=(
                        "Enroll this agent:\n"
                        "    sudo /var/ossec/bin/agent-auth -m <manager-ip>"
                    ),
                    verify=f"sudo ls -l {CLIENT_KEYS}",
                )
            ]
        content = read_text(CLIENT_KEYS)
        if content is not None and not any(
            ln.strip() and not ln.startswith("#") for ln in content.splitlines()
        ):
            # On a manager an empty client.keys just means no agent has
            # enrolled yet -- the authd module reports that as a warning.
            if ctx.env.is_manager:
                return []
            return [
                self.finding(
                    Severity.CRITICAL,
                    "client.keys exists but is empty",
                    "the agent has no enrollment entry, so authentication to the "
                    "manager will fail",
                    evidence=f"{CLIENT_KEYS} contains no entries",
                    fix="sudo /var/ossec/bin/agent-auth -m <manager-ip>",
                    verify="sudo /var/ossec/bin/agent_control -l",
                )
            ]
        return []
