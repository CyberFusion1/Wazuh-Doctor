"""Filebeat: service health, config validity and delivery to the indexer."""

from __future__ import annotations

import os
import re
from typing import List, Optional

from .base import Context, Module
from wdlib.common import Finding, Severity, read_text, systemd_unit_exists, tail_lines
from wdlib.discovery import Component

FILEBEAT_LOG = "/var/log/filebeat/filebeat"
FILEBEAT_CONF = "/etc/filebeat/filebeat.yml"

# Signatures of the two classic filebeat failures: it cannot reach the
# indexer, or the certificate/TLS handshake fails.
#
# Each pattern is deliberately specific. Bare "certificate" and bare "EOF"
# were tried first and had to go: they match healthy lines such as
# "Loading certificate /etc/.../filebeat.crt" or a clean stream close, so
# a working deployment reported delivery failures that were not happening.
DELIVERY_ERRORS = (
    r"connection refused",
    r"no route to host",
    r"i/o timeout",
    r"dial tcp",
    r"failed to connect",
    r"x509:",
    r"tls: ",
    r"certificate (?:is )?(?:expired|has expired|invalid|unknown|revoked)",
    r"unexpected EOF",
)


class FilebeatModule(Module):
    name = "filebeat"
    title = "Filebeat forwarding"
    description = "service status, config validity, connection to the indexer"
    requires = (Component.FILEBEAT,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._service(ctx))
        findings.extend(self._config(ctx))
        findings.extend(self._output(ctx))
        findings.extend(self._conf_file(ctx))
        findings.extend(self._log(ctx))
        return findings

    # -- service ----------------------------------------------------------

    def _service(self, ctx: Context) -> List[Finding]:
        if not (os.path.exists("/usr/share/filebeat/bin/filebeat") or ctx.run(["which", "filebeat"], timeout=5).ok):
            return [
                self.finding(
                    Severity.INFO,
                    "filebeat binary not found",
                    "filebeat is not installed on this host, so log forwarding could "
                    "not be checked",
                    fix="Install filebeat if this host is meant to ship alerts to the indexer.",
                    verify="which filebeat",
                )
            ]

        if not systemd_unit_exists("filebeat"):
            # Installed but no unit, or no systemd at all. Either way we
            # cannot conclude the service is down, and claiming it is would
            # be a false CRITICAL.
            return []

        result = ctx.run(["systemctl", "is-active", "filebeat"], timeout=8)
        if result.missing:
            return []
        state = result.output.strip()
        if state == "active":
            return []
        return [
            self.finding(
                Severity.CRITICAL,
                "the filebeat service is not active",
                "filebeat ships Wazuh alerts to the indexer; while it is stopped the "
                "dashboard shows no new data even though the manager is working",
                evidence=f"systemctl is-active filebeat -> {state or 'no output'}",
                fix=(
                    "    sudo systemctl start filebeat\n"
                    "    sudo systemctl enable filebeat\n"
                    "    sudo journalctl -u filebeat -n 100 --no-pager"
                ),
                verify="systemctl is-active filebeat",
            )
        ]

    # -- config -----------------------------------------------------------

    def _config(self, ctx: Context) -> List[Finding]:
        """`filebeat test config` is the canonical YAML validity check."""
        if not self._have_binary(ctx):
            return []
        result = ctx.sudo_run(["filebeat", "test", "config", "-c", FILEBEAT_CONF], timeout=30)
        if result.missing:
            return []
        if result.ok:
            return []
        if result.denied:
            # filebeat.yml is root-only, so this is far more likely to be a
            # privilege problem than a real YAML error.
            return [
                self.finding(
                    Severity.INFO,
                    "filebeat config check needs root",
                    "filebeat could not read its configuration without privileges, so "
                    "the configuration was not validated",
                    evidence=result.output[:300],
                    fix="Re-run as root: sudo wazuh-doctor --module filebeat",
                    verify=f"sudo filebeat test config -c {FILEBEAT_CONF}",
                )
            ]
        return [
            self.finding(
                Severity.CRITICAL,
                "filebeat configuration is invalid",
                "filebeat refuses to start or reload with this configuration, so no "
                "alerts are being shipped to the indexer",
                evidence=result.output[:1200] or "no output",
                fix=(
                    "Fix the error reported above, then re-validate:\n"
                    f"    sudo filebeat test config -c {FILEBEAT_CONF}\n"
                    "  A common cause is inconsistent indentation in the YAML."
                ),
                verify=f"sudo filebeat test config -c {FILEBEAT_CONF}",
            )
        ]

    # -- output -----------------------------------------------------------

    def _output(self, ctx: Context) -> List[Finding]:
        """`filebeat test output` proves whether it can actually reach the indexer."""
        if not self._have_binary(ctx):
            return []
        result = ctx.sudo_run(["filebeat", "test", "output", "-c", FILEBEAT_CONF], timeout=40)
        if result.missing:
            return []
        if result.ok:
            return []
        if result.denied:
            return [
                self.finding(
                    Severity.INFO,
                    "filebeat output test needs root",
                    "the filebeat configuration is root-readable only, so delivery to "
                    "the indexer could not be verified",
                    fix="Re-run as root: sudo wazuh-doctor --module filebeat",
                    verify=f"sudo filebeat test output -c {FILEBEAT_CONF}",
                )
            ]
        return [
            self.finding(
                Severity.CRITICAL,
                "filebeat cannot reach the indexer",
                "filebeat validated its configuration but failed to connect to the "
                "indexer output, so alerts are not being indexed and the dashboard "
                "will show stale or missing data",
                evidence=result.output[:1200] or "no output",
                fix=(
                    "Check the output block and certificate paths:\n"
                    f"    sudo grep -A10 'output.elasticsearch' {FILEBEAT_CONF}\n"
                    "    curl -k -s -o /dev/null -w '%{http_code}\\n' https://127.0.0.1:9200/\n"
                    "  Common causes: wrong host, expired or mismatched certificates, "
                    "wrong credentials, or the indexer being down."
                ),
                verify=f"sudo filebeat test output -c {FILEBEAT_CONF}",
            )
        ]

    # -- config file ------------------------------------------------------

    def _conf_file(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        content = read_text(FILEBEAT_CONF)
        if content is None:
            if not ctx.env.is_root and os.path.exists(FILEBEAT_CONF):
                findings.append(
                    self.finding(
                        Severity.INFO,
                        "filebeat.yml is root-readable only",
                        "the output host and certificate paths could not be inspected "
                        "directly; the filebeat test commands above still apply",
                        fix="Re-run as root for the full check.",
                        verify=f"sudo grep 'hosts:' {FILEBEAT_CONF}",
                    )
                )
            return findings

        if "output.elasticsearch" not in content:
            findings.append(
                self.finding(
                    Severity.WARNING,
                    "filebeat.yml has no output.elasticsearch block",
                    "without an Elasticsearch/OpenSearch output filebeat has nowhere to "
                    "send events",
                    evidence="no 'output.elasticsearch' key found in filebeat.yml",
                    fix=f"Add an output.elasticsearch block to {FILEBEAT_CONF} pointing at the indexer.",
                    verify=f"sudo grep -A5 output.elasticsearch {FILEBEAT_CONF}",
                )
            )
        if "wazuh-alerts" not in content and "filebeat.modules" not in content:
            findings.append(
                self.finding(
                    Severity.WARNING,
                    "filebeat.yml does not reference wazuh-alerts",
                    "the Wazuh filebeat module is what defines the alert input and index "
                    "template; without it alerts may not be shipped or mapped correctly",
                    evidence="no 'wazuh-alerts' or 'filebeat.modules' reference in filebeat.yml",
                    fix="Enable the module: sudo filebeat modules enable wazuh",
                    verify="sudo filebeat modules list",
                )
            )
        return findings

    # -- log --------------------------------------------------------------

    def _log(self, ctx: Context) -> List[Finding]:
        lines = tail_lines(FILEBEAT_LOG, 200)
        if not lines:
            # The filebeat log path varies: try the directory listing fallback.
            lines = tail_lines("/var/log/filebeat/filebeat-json.log", 200)
        if not lines:
            return []
        hits = [ln for ln in lines if any(re.search(p, ln, re.IGNORECASE) for p in DELIVERY_ERRORS)]
        if not hits:
            return []
        return [
            self.finding(
                Severity.WARNING,
                f"{len(hits)} filebeat log line(s) about delivery failures",
                "filebeat is logging connection or TLS errors while shipping to the indexer",
                evidence="\n".join(hits[-12:]),
                fix=(
                    "Confirm the indexer is reachable and the CA is valid:\n"
                    f"    sudo grep -E 'ERROR|WARN' {FILEBEAT_LOG} | tail -30\n"
                    "    sudo filebeat test output -c /etc/filebeat/filebeat.yml"
                ),
                verify=f"sudo filebeat test output -c {FILEBEAT_CONF}",
            )
        ]

    # -- helper -----------------------------------------------------------

    def _have_binary(self, ctx: Context) -> bool:
        if os.path.exists("/usr/share/filebeat/bin/filebeat"):
            return True
        return ctx.run(["which", "filebeat"], timeout=5).ok
