"""FIM (syscheck): configuration presence, database health and queue pressure."""

from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from .base import Context, Module
from wdlib.common import Finding, Severity, human_bytes, read_text, tail_lines
from wdlib.discovery import Component

OSSEC_CONF = "/var/ossec/etc/ossec.conf"
OSSEC_LOG = "/var/ossec/logs/ossec.log"

# Both the legacy and the current FIM database locations.
FIM_QUEUE_DIRS = (
    "/var/ossec/queue/fim/db",
    "/var/ossec/queue/fim",
    "/var/ossec/queue/syscheck",
)

DB_ERROR_SIGNATURES = (
    r"Couldn't open file",
    r"Unable to open",
    r"corrupt",
    r"database is locked",
    r"SQLITE",
    r"disk I/O error",
)

LARGE_QUEUE_BYTES = 100 * 1024 * 1024  # 100MB


class FimModule(Module):
    name = "fim"
    title = "File integrity monitoring"
    description = "syscheck configuration, database errors and queue issues"
    requires = (Component.MANAGER,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._config(ctx))
        findings.extend(self._database(ctx))
        findings.extend(self._logs(ctx))
        return findings

    # -- configuration ----------------------------------------------------

    def _config(self, ctx: Context) -> List[Finding]:
        content = read_text(OSSEC_CONF)
        if content is None:
            return []

        findings: List[Finding] = []
        match = re.search(r"<syscheck>(.*?)</syscheck>", content, re.S | re.IGNORECASE)
        if not match:
            return [
                self.finding(
                    Severity.WARNING,
                    "no <syscheck> block configured",
                    "file integrity monitoring is disabled on this manager, so file "
                    "changes on monitored hosts will not be detected",
                    evidence="no <syscheck> element found in ossec.conf",
                    fix=(
                        "Add a syscheck block to ossec.conf:\n"
                        "    <syscheck>\n"
                        "      <frequency>43200</frequency>\n"
                        "      <directories check_all=\"yes\">/etc,/usr/bin,/usr/sbin</directories>\n"
                        "    </syscheck>\n"
                        "  then: sudo wazuh-analysisd -t && sudo wazuh-control restart"
                    ),
                    verify="sudo wazuh-analysisd -t",
                )
            ]

        block = match.group(1)
        directories = re.findall(r"<directories[^>]*>\s*([^<]*)", block)
        if not directories:
            findings.append(
                self.finding(
                    Severity.WARNING,
                    "syscheck is configured without any <directories>",
                    "FIM is enabled but monitors nothing, so no integrity events will "
                    "ever be generated",
                    evidence="<syscheck> present but no <directories> entries",
                    fix="Add at least one <directories> entry inside <syscheck>.",
                    verify="sudo grep -A10 '<syscheck>' /var/ossec/etc/ossec.conf",
                )
            )

        frequency = re.search(r"<frequency>\s*(\d+)\s*</frequency>", block)
        scan_on_start = "<scan_on_start>yes</scan_on_start>" in block
        findings.append(
            self.finding(
                Severity.INFO,
                "FIM configuration summary",
                "informational: the current syscheck configuration on this manager",
                evidence=(
                    f"frequency: {frequency.group(1) + 's' if frequency else 'default'}\n"
                    f"scan_on_start: {'yes' if scan_on_start else 'no'}\n"
                    f"directories monitored: {len(directories)}\n"
                    + "\n".join(f"  {d.strip()}" for d in directories[:8] if d.strip())
                ),
                fix="No action needed.",
                verify="sudo grep -A15 '<syscheck>' /var/ossec/etc/ossec.conf",
            )
        )
        return findings

    # -- database ---------------------------------------------------------

    def _database(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        found: Optional[str] = None
        total_bytes = 0

        for directory in FIM_QUEUE_DIRS:
            if not os.path.isdir(directory):
                continue
            size, count = self._size_of(directory)
            if count == 0:
                continue
            found = directory
            total_bytes += size

            if found and size > LARGE_QUEUE_BYTES:
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        f"FIM data in {directory} is {human_bytes(size)}",
                        "the FIM database or queue has grown very large, which usually "
                        "means scans are not completing and the database is falling "
                        "behind the monitored file set",
                        evidence=f"{directory}: {count} file(s), {human_bytes(size)}",
                        fix=(
                            "Check that FIM scans complete and that the database is not "
                            "corrupt. Do NOT delete the database to 'fix' this:\n"
                            "    sudo grep -i syscheck /var/ossec/logs/ossec.log | tail -30"
                        ),
                        verify="du -sh /var/ossec/queue/fim",
                    )
                )

        if found is None:
            # No FIM data at all. Only meaningful if syscheck is configured.
            content = read_text(OSSEC_CONF)
            if content and "<syscheck>" in content:
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        "no FIM database or queue data found",
                        "syscheck is configured but no FIM database exists, which "
                        "suggests FIM has never completed a scan on this manager",
                        evidence="checked: " + ", ".join(FIM_QUEUE_DIRS) + " (all empty or absent)",
                        fix=(
                            "Confirm syscheckd is running and look for scan errors:\n"
                            "    sudo /var/ossec/bin/wazuh-control status | grep syscheckd\n"
                            "    sudo grep -i syscheck /var/ossec/logs/ossec.log | tail -30"
                        ),
                        verify="ls -la /var/ossec/queue/fim/",
                    )
                )
        return findings

    @staticmethod
    def _size_of(directory: str) -> Tuple[int, int]:
        total = 0
        count = 0
        for root, _dirs, files in os.walk(directory):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                    count += 1
                except OSError:
                    continue
        return total, count

    # -- logs -------------------------------------------------------------

    def _logs(self, ctx: Context) -> List[Finding]:
        lines = tail_lines(OSSEC_LOG, 700)
        if not lines:
            return []
        hits = [
            ln
            for ln in lines
            if "syscheck" in ln.lower()
            and any(re.search(p, ln, re.IGNORECASE) for p in DB_ERROR_SIGNATURES)
        ]
        if not hits:
            return []
        return [
            self.finding(
                Severity.CRITICAL,
                f"{len(hits)} FIM database error(s) in ossec.log",
                "syscheck is reporting database access failures, which means file "
                "integrity events are being lost and the FIM database may be corrupt",
                evidence="\n".join(hits[-12:]),
                fix=(
                    "Stop the manager before touching the FIM database, and keep a "
                    "backup. Do not delete agent keys or logs:\n"
                    "    sudo /var/ossec/bin/wazuh-control stop\n"
                    "    sudo cp -a /var/ossec/queue/fim /var/ossec/queue/fim.bak-$(date +%Y%m%d)\n"
                    "  Then investigate ownership and free space, and restart."
                ),
                verify="sudo grep -i 'syscheck' /var/ossec/logs/ossec.log | tail -20",
            )
        ]
