"""Agent enrollment: the authd service, port 1515, and agent key hygiene."""

from __future__ import annotations

import os
import re
import stat
from typing import List

from .base import Context, Module
from wdlib.common import Finding, Severity, grep, path_state, read_text, tail_lines
from wdlib.discovery import CONTROL, Component

CLIENT_KEYS = "/var/ossec/etc/client.keys"
AUTHD_PASS = "/var/ossec/etc/authd.pass"
OSSEC_LOG = "/var/ossec/logs/ossec.log"

ENROLLMENT_ERRORS = (
    r"Invalid password",
    r"Unable to add agent",
    r"Duplicate agent",
    r"Unable to open",
    r"Invalid IP",
)


class AuthdEnrollmentModule(Module):
    name = "authd_enrollment"
    title = "Agent enrollment (authd)"
    description = "authd service, port 1515, agent key file and password file"
    requires = (Component.MANAGER,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._port(ctx))
        findings.extend(self._daemon(ctx))
        findings.extend(self._keys(ctx))
        findings.extend(self._password_file(ctx))
        findings.extend(self._log(ctx))
        return findings

    # -- service ----------------------------------------------------------

    def _port(self, ctx: Context) -> List[Finding]:
        if ctx.env.port_open(1515):
            return []
        return [
            self.finding(
                Severity.CRITICAL,
                "enrollment port 1515 is not listening",
                "wazuh-authd is the enrollment service; with 1515 closed, no new agent "
                "can register — existing agents keep working, new ones cannot join",
                evidence="no listener on TCP 1515 in /proc/net/tcp{,6}",
                fix=(
                    "Start authd:\n"
                    "    sudo /var/ossec/bin/wazuh-control restart\n"
                    "  Then confirm the port: ss -lntp | grep :1515\n"
                    "  If the service is up but the port is closed, check the <auth> "
                    "section of /var/ossec/etc/ossec.conf."
                ),
                verify="ss -lntp | grep :1515",
            )
        ]

    def _daemon(self, ctx: Context) -> List[Finding]:
        result = ctx.sudo_run([CONTROL, "status"], timeout=15)
        if not result.ok:
            return []
        line = "\n".join(ln for ln in result.stdout.splitlines() if "wazuh-authd" in ln)
        if line and ("not running" in line.lower() or "stopped" in line.lower()):
            return [
                self.finding(
                    Severity.CRITICAL,
                    "wazuh-authd is not running",
                    "the enrollment daemon is stopped, so agent registration requests "
                    "on port 1515 are not being served",
                    evidence=line,
                    fix="sudo /var/ossec/bin/wazuh-control restart",
                    verify="sudo /var/ossec/bin/wazuh-control status | grep wazuh-authd",
                )
            ]
        return []

    # -- key material -----------------------------------------------------

    def _keys(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        # Only a genuine absence deserves a warning. /var/ossec is 0750, so
        # an unprivileged run cannot tell "client.keys is not there" from
        # "I may not look at client.keys" -- and reporting a missing key
        # file on a manager with agents enrolled is exactly the false alarm
        # this tool must not produce.
        if path_state(CLIENT_KEYS) == "missing":
            return [
                self.finding(
                    Severity.WARNING,
                    "agent key file client.keys is missing",
                    "a manager without client.keys has no enrolled agents; this is "
                    "expected only on a manager that has never had an agent enroll",
                    evidence=f"{CLIENT_KEYS} does not exist",
                    fix=(
                        "If agents should be enrolled, check that authd is running and "
                        "enroll one:\n"
                        "    sudo /var/ossec/bin/agent_control -l\n"
                        "  Do NOT create this file by hand."
                    ),
                    verify=f"sudo ls -l {CLIENT_KEYS}",
                )
            ]

        # Permissions. Agent keys are shared secrets — a world-readable
        # client.keys lets any local user impersonate an agent.
        mode = self._mode(CLIENT_KEYS)
        if mode is not None and mode & stat.S_IROTH:
            findings.append(
                self.finding(
                    Severity.CRITICAL,
                    "client.keys is world-readable",
                    "this file holds the shared secret for every enrolled agent; any "
                    "local user who reads it can impersonate an agent to the manager",
                    evidence=f"{CLIENT_KEYS} mode is {stat.filemode(mode)} (group/other bits: {oct(mode & 0o077)})",
                    fix=(
                        "Restrict the key file:\n"
                        f"    sudo chmod 640 {CLIENT_KEYS}\n"
                        f"    sudo chown root:wazuh {CLIENT_KEYS}"
                    ),
                    verify=f"sudo stat -c '%a %U:%G' {CLIENT_KEYS}",
                )
            )

        # Count only. Never emit key material.
        content = read_text(CLIENT_KEYS)
        if content is None:
            findings.append(
                self.finding(
                    Severity.INFO,
                    "client.keys could not be read",
                    "the key file is root-readable only, so enrollment could not be "
                    "counted; this is not evidence that it is missing",
                    fix="Re-run as root: sudo wazuh-doctor --module authd_enrollment",
                    verify=f"sudo wc -l {CLIENT_KEYS}",
                )
            )
            return findings

        count = sum(1 for ln in content.splitlines() if ln.strip() and not ln.startswith("#"))
        if count == 0:
            findings.append(
                self.finding(
                    Severity.WARNING,
                    "no agents are enrolled",
                    "client.keys exists but contains zero entries, so the manager is "
                    "receiving no agent telemetry",
                    evidence=f"{CLIENT_KEYS} contains 0 agent entries",
                    fix=(
                        "Enroll an agent from the agent host:\n"
                        "    sudo /var/ossec/bin/agent-auth -m <manager-ip>\n"
                        "  Or check why enrollment is failing in the manager log."
                    ),
                    verify="sudo /var/ossec/bin/agent_control -l",
                )
            )
        return findings

    def _password_file(self, ctx: Context) -> List[Finding]:
        if not os.path.exists(AUTHD_PASS):
            return []
        mode = self._mode(AUTHD_PASS)
        if mode is not None and mode & (stat.S_IROTH | stat.S_IRGRP):
            return [
                self.finding(
                    Severity.WARNING,
                    "authd.pass is group- or world-readable",
                    "the enrollment password (used with auto-enrollment) is stored in "
                    "this file; loose permissions expose the enrollment secret",
                    evidence=f"{AUTHD_PASS} mode is {stat.filemode(mode)}",
                    fix=(
                        f"    sudo chmod 640 {AUTHD_PASS}\n"
                        f"    sudo chown root:wazuh {AUTHD_PASS}"
                    ),
                    verify=f"sudo stat -c '%a %U:%G' {AUTHD_PASS}",
                )
            ]
        return []

    # -- log --------------------------------------------------------------

    def _log(self, ctx: Context) -> List[Finding]:
        lines = tail_lines(OSSEC_LOG, 600)
        if not lines:
            return []
        hits = [
            ln
            for ln in lines
            if "wazuh-authd" in ln and any(re.search(p, ln, re.IGNORECASE) for p in ENROLLMENT_ERRORS)
        ]
        if not hits:
            return []
        return [
            self.finding(
                Severity.WARNING,
                f"{len(hits)} enrollment error(s) in ossec.log",
                "authd rejected enrollment attempts; the usual causes are a wrong "
                "enrollment password, a duplicate agent name, or a blocked source IP",
                evidence="\n".join(hits[-12:]),
                fix=(
                    "Read the surrounding lines for the failing agent host:\n"
                    "    sudo grep wazuh-authd /var/ossec/logs/ossec.log | tail -30\n"
                    "  Then re-enroll the agent, removing a stale entry if the name "
                    "collides: sudo /var/ossec/bin/manage_agents -l"
                ),
                verify="sudo /var/ossec/bin/agent_control -l",
            )
        ]

    @staticmethod
    def _mode(path: str):
        try:
            return stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            return None
