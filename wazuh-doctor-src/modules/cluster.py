"""Cluster: master/worker synchronisation, when clustering is enabled."""

from __future__ import annotations

import os
import re
from typing import List

from .base import Context, Module
from wdlib.common import Finding, Severity, read_text, tail_lines
from wdlib.discovery import CONTROL, Component

CLUSTER_LOG = "/var/ossec/logs/cluster.log"
CLUSTER_CONTROL = "/var/ossec/bin/cluster_control"

NODE_RX = re.compile(r"^\s*(\S+)\s+(\S+)\s+(.*)$")
SYNC_ERRORS = (
    r"ERROR",
    r"CRITICAL",
    r"out of sync",
    r"Unable to",
    r"timeout",
)


class ClusterModule(Module):
    name = "cluster"
    title = "Manager cluster"
    description = "master/worker sync state and cluster log errors"
    requires = (Component.MANAGER,)

    def run(self, ctx: Context) -> List[Finding]:
        if not ctx.env.cluster_enabled:
            return [
                self.finding(
                    Severity.INFO,
                    "clustering is not configured",
                    "no <cluster> block with a node_type was found in ossec.conf, so "
                    "this manager runs standalone and there is nothing to synchronise",
                    evidence="ossec.conf contains no active <cluster><node_type> configuration",
                    fix="No action needed unless a cluster is intended.",
                    verify="sudo grep -A4 '<cluster>' /var/ossec/etc/ossec.conf",
                )
            ]

        findings: List[Finding] = []
        findings.extend(self._daemon(ctx))
        findings.extend(self._nodes(ctx))
        findings.extend(self._integrity(ctx))
        findings.extend(self._log(ctx))
        return findings

    # -- daemon -----------------------------------------------------------

    def _daemon(self, ctx: Context) -> List[Finding]:
        result = ctx.sudo_run([CONTROL, "status"], timeout=15)
        if not result.ok:
            return []
        line = "\n".join(ln for ln in result.stdout.splitlines() if "wazuh-clusterd" in ln)
        if line and ("not running" in line.lower() or "stopped" in line.lower()):
            return [
                self.finding(
                    Severity.CRITICAL,
                    "wazuh-clusterd is not running on a clustered manager",
                    "clustering is configured but the cluster daemon is stopped, so this "
                    "node neither receives nor distributes configuration to its peers",
                    evidence=line,
                    fix="sudo /var/ossec/bin/wazuh-control restart",
                    verify="sudo /var/ossec/bin/wazuh-control status | grep wazuh-clusterd",
                )
            ]
        return []

    # -- nodes ------------------------------------------------------------

    def _nodes(self, ctx: Context) -> List[Finding]:
        if not os.path.exists(CLUSTER_CONTROL):
            return []
        result = ctx.sudo_run([CLUSTER_CONTROL, "-l"], timeout=15)
        if result.missing or not result.ok:
            if result.denied:
                return [
                    self.finding(
                        Severity.INFO,
                        "cluster node list needs root",
                        "cluster_control could not run unprivileged, so peer status was "
                        "not verified",
                        fix="Re-run as root: sudo wazuh-doctor --module cluster",
                        verify="sudo /var/ossec/bin/cluster_control -l",
                    )
                ]
            return []

        lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
        # Drop the header row if present.
        body = [ln for ln in lines if not ln.lower().startswith(("name", "node"))]
        unhealthy = [
            ln for ln in body
            if not re.search(r"\b(connected|active|master|worker)\b", ln, re.IGNORECASE)
            or re.search(r"disconnected|error|fail", ln, re.IGNORECASE)
        ]

        if ctx.env.cluster_role == "master" and unhealthy:
            return [
                self.finding(
                    Severity.CRITICAL,
                    f"{len(unhealthy)} cluster node(s) are not connected",
                    "this master cannot synchronise configuration or integrity with the "
                    "listed workers, so those nodes run stale configuration",
                    evidence="\n".join(body[:15]),
                    fix=(
                        "On each affected worker check the cluster daemon and the "
                        "connection to the master on port 1516:\n"
                        "    sudo /var/ossec/bin/wazuh-control status | grep clusterd\n"
                        "    sudo tail -n 50 /var/ossec/logs/cluster.log"
                    ),
                    verify="sudo /var/ossec/bin/cluster_control -l",
                )
            ]
        return []

    # -- integrity --------------------------------------------------------

    def _integrity(self, ctx: Context) -> List[Finding]:
        if not os.path.exists(CLUSTER_CONTROL):
            return []
        result = ctx.sudo_run([CLUSTER_CONTROL, "-i"], timeout=15)
        if result.missing or not result.ok:
            return []
        if re.search(r"out of sync|ERROR", result.stdout, re.IGNORECASE):
            return [
                self.finding(
                    Severity.WARNING,
                    "cluster integrity is out of sync",
                    "at least one node reports an integrity difference, meaning its "
                    "agent keys or shared configuration differ from the master",
                    evidence=result.output[:800],
                    fix=(
                        "Force a resync from the master:\n"
                        "    sudo /var/ossec/bin/cluster_control -i\n"
                        "  Then confirm the worker rejoins: "
                        "sudo /var/ossec/bin/cluster_control -l"
                    ),
                    verify="sudo /var/ossec/bin/cluster_control -i",
                )
            ]
        return []

    # -- log --------------------------------------------------------------

    def _log(self, ctx: Context) -> List[Finding]:
        lines = tail_lines(CLUSTER_LOG, 400)
        if not lines:
            return []
        hits = [ln for ln in lines if any(re.search(p, ln, re.IGNORECASE) for p in SYNC_ERRORS)]
        if not hits:
            return []
        return [
            self.finding(
                Severity.WARNING,
                f"{len(hits)} cluster log error(s)",
                "the cluster daemon is logging synchronisation errors, so workers may "
                "be running configuration that diverges from the master",
                evidence="\n".join(hits[-12:]),
                fix=(
                    "    sudo tail -n 100 /var/ossec/logs/cluster.log\n"
                    "  Common causes: port 1516 blocked between nodes, mismatched "
                    "certificates, or a worker name that does not match the master config."
                ),
                verify="sudo /var/ossec/bin/cluster_control -l",
            )
        ]
