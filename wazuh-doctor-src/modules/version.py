"""Version: detect and compare manager, indexer, dashboard and filebeat versions.

Wazuh requires the manager, indexer and dashboard to run matching versions.
A drift between them is a very common cause of subtle breakage that shows
up as generic API or indexing errors elsewhere.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from .base import Context, Module
from wdlib.common import Finding, Severity, http_request, read_text, run
from wdlib.discovery import Component

# The Wazuh version is the *plugin* manifest, not the top-level one. The
# top-level package.json belongs to the OpenSearch Dashboards fork that
# Wazuh's dashboard is built on and carries its own (2.x) version.
DASHBOARD_PLUGIN_PACKAGE = "/usr/share/wazuh-dashboard/plugins/wazuh/package.json"

FILEBEAT_BIN = "/usr/share/filebeat/bin/filebeat"

# Wazuh bundles its own filebeat (an Elastic 7.10.x fork). That version
# deliberately does not track the Wazuh version, so it is reported but
# never compared -- doing so would warn on a perfectly healthy install.
FILEBEAT_TRACKS_WAZUH = False


def parse_version(value: Optional[str]) -> Optional[Tuple[int, ...]]:
    """Extract a comparable tuple from a version string. None if hopeless."""
    if not value:
        return None
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(value))
    if not match:
        return None
    return tuple(int(g) for g in match.groups() if g is not None)


class VersionModule(Module):
    name = "version"
    title = "Component version consistency"
    description = "detects version mismatch across manager, indexer, dashboard and filebeat"
    # Always runs: a version mismatch is worth reporting even on a bare manager.
    requires = ()

    def run(self, ctx: Context) -> List[Finding]:
        indexer, indexer_source = self._indexer(ctx)
        versions: Dict[str, Optional[str]] = {
            "manager": ctx.env.wazuh_version if ctx.env.wazuh_version != "unknown" else None,
            "indexer": indexer,
            "filebeat": self._filebeat(ctx),
            "dashboard": self._dashboard(ctx),
        }
        # Where each version came from decides whether it may be compared.
        sources: Dict[str, str] = {"indexer": indexer_source}

        findings: List[Finding] = []
        table = self._table(versions, sources)

        detected = {k: v for k, v in versions.items() if v}
        if not detected:
            return [
                self.finding(
                    Severity.INFO,
                    "no component versions could be determined",
                    "version checks require either root access to configuration or a "
                    "reachable indexer API",
                    evidence=table,
                    fix="Re-run as root, or supply indexer credentials, to enable version comparison.",
                    verify="sudo wazuh-control info",
                )
            ]

        unknown = [k for k, v in versions.items() if not v and ctx.env.has(self._component_for(k))]
        if unknown:
            findings.append(
                self.finding(
                    Severity.INFO,
                    f"version not determined for: {', '.join(unknown)}",
                    "these components are installed but their version could not be read, "
                    "so a mismatch involving them cannot be ruled out",
                    evidence=table,
                    fix="Re-run as root, or supply indexer credentials, for a complete picture.",
                    verify="sudo wazuh-control info",
                )
            )

        findings.extend(self._compare(ctx, versions, sources, table))
        return findings

    # -- collectors -------------------------------------------------------

    @staticmethod
    def _component_for(name: str) -> str:
        return {
            "manager": Component.MANAGER,
            "indexer": Component.INDEXER,
            "filebeat": Component.FILEBEAT,
            "dashboard": Component.DASHBOARD,
        }[name]

    def _indexer(self, ctx: Context) -> Tuple[Optional[str], str]:
        """Return ``(version, source)``.

        The source decides whether the value may be compared at all.
        ``GET /`` on the Wazuh indexer answers with the **OpenSearch base
        version** it was forked from (2.x), not the Wazuh version. Comparing
        that against a 4.x manager would report an incompatible deployment on
        every healthy install, so only a value that came from the Wazuh
        package counts as comparable.
        """
        packaged = self._indexer_package_version()
        if packaged:
            return packaged, "wazuh package"
        return self._indexer_api_version(ctx), "opensearch base"

    @staticmethod
    def _indexer_package_version() -> Optional[str]:
        # opensearch.yml is root-only; the systemd unit trailer is readable.
        for unit in (
            "/lib/systemd/system/wazuh-indexer.service",
            "/usr/lib/systemd/system/wazuh-indexer.service",
        ):
            content = read_text(unit)
            if content:
                match = re.search(r"packages-([0-9][\w.\-]*)", content)
                if match:
                    return match.group(1)
        for cmd in (
            ["dpkg-query", "-W", "-f=${Version}", "wazuh-indexer"],
            ["rpm", "-q", "--qf", "%{VERSION}", "wazuh-indexer"],
        ):
            result = run(cmd, timeout=8)
            if result.ok and result.stdout.strip():
                match = re.match(r"([0-9][\w.\-]*)", result.stdout.strip())
                if match:
                    return match.group(1)
        return None

    def _indexer_api_version(self, ctx: Context) -> Optional[str]:
        base = (ctx.config.get("indexer_url") or "https://127.0.0.1:9200").rstrip("/")
        auth = None
        if ctx.config.has_indexer_creds():
            auth = (ctx.config.get("indexer_user"), ctx.config.get("indexer_password"))
        payload = http_request(base + "/", auth=auth, timeout=8, verify=False).json()
        if isinstance(payload, dict) and isinstance(payload.get("version"), dict):
            number = payload["version"].get("number")
            if number:
                return str(number)
        return None

    def _filebeat(self, ctx: Context) -> Optional[str]:
        """Wazuh's bundled filebeat is not always on PATH."""
        for cmd in (["filebeat", "version"], [FILEBEAT_BIN, "version"]):
            if cmd[0].startswith("/") and not os.path.exists(cmd[0]):
                continue
            result = ctx.run(cmd, timeout=10)
            if result.ok:
                match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
                if match:
                    return match.group(1)
        return None

    def _dashboard(self, ctx: Context) -> Optional[str]:
        content = read_text(DASHBOARD_PLUGIN_PACKAGE)
        if content:
            try:
                payload = json.loads(content)
                if isinstance(payload, dict) and payload.get("version"):
                    return str(payload["version"])
            except (ValueError, TypeError):
                pass
        # Fall back to the version banner in the startup log.
        result = ctx.sudo_run(["journalctl", "-u", "wazuh-dashboard", "-n", "200", "--no-pager"], timeout=15)
        if result.ok:
            match = re.search(r"[Ww]azuh[- ]dashboard[^\d]{0,20}(\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        return None

    # -- comparison -------------------------------------------------------

    @staticmethod
    def _table(versions: Dict[str, Optional[str]], sources: Dict[str, str]) -> str:
        rows: List[str] = []
        for name, value in versions.items():
            note = ""
            source = sources.get(name)
            if value and source and source != "wazuh package":
                note = f"   [{source} -- not version-comparable]"
            rows.append(f"  {name:<10} {value if value else 'not determined'}{note}")
        return "\n".join(rows)

    def _compare(
        self,
        ctx: Context,
        versions: Dict[str, Optional[str]],
        sources: Dict[str, str],
        table: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        manager = versions.get("manager")
        indexer = versions.get("indexer")
        indexer_source = sources.get("indexer", "unknown")

        m = parse_version(manager)
        i = parse_version(indexer)

        if indexer and indexer_source != "wazuh package":
            # Deliberately not compared. See _indexer() for why.
            findings.append(
                self.finding(
                    Severity.INFO,
                    f"indexer version {indexer} reported from {indexer_source}; not compared",
                    "the indexer's HTTP API reports the OpenSearch base version it was "
                    "forked from, not the Wazuh version, so comparing it with the "
                    "manager would raise a false mismatch. Supply root access (or a "
                    "dpkg/rpm database) for a comparable value.",
                    evidence=table,
                    fix="No action needed; this is how the Wazuh indexer reports itself.",
                    verify=(
                        "grep -i 'built for' /lib/systemd/system/wazuh-indexer.service "
                        "# or: dpkg -l wazuh-indexer"
                    ),
                )
            )
        elif m and i:
            if m[:2] != i[:2]:
                findings.append(
                    self.finding(
                        Severity.CRITICAL,
                        f"manager {manager} and indexer {indexer} versions are incompatible",
                        "the manager and indexer must run matching Wazuh versions; a "
                        "major/minor mismatch breaks the alert template, index mappings "
                        "and often the API and dashboard with it",
                        evidence=table,
                        fix=(
                            "Upgrade the lagging component so both run the same version. "
                            "Upgrade the indexer first, then the manager, then the dashboard."
                        ),
                        verify="sudo wazuh-control info; curl -k -s https://127.0.0.1:9200/",
                    )
                )
            elif m != i:
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        f"manager and indexer differ only in patch level ({manager} vs {indexer})",
                        "a patch-level difference is usually tolerated but is unsupported "
                        "and can produce inconsistent index mappings",
                        evidence=table,
                        fix="Align the patch versions.",
                        verify="sudo wazuh-control info",
                    )
                )

        # The dashboard tracks the Wazuh version, so a mismatch is meaningful.
        dashboard = versions.get("dashboard")
        if dashboard and m:
            d = parse_version(dashboard)
            if d and d[:2] != m[:2]:
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        f"dashboard {dashboard} does not match manager {manager}",
                        "the dashboard should track the manager version; a mismatch "
                        "commonly causes dashboard API errors and index-pattern problems",
                        evidence=table,
                        fix="Upgrade the dashboard (and its Wazuh plugin) to match the manager.",
                        verify="sudo wazuh-control info",
                    )
                )

        # Filebeat is deliberately not compared: Wazuh ships a 7.10.x fork of
        # Elastic's filebeat, so its version never matches the manager's.
        filebeat = versions.get("filebeat")
        if filebeat and not FILEBEAT_TRACKS_WAZUH:
            findings.append(
                self.finding(
                    Severity.INFO,
                    f"filebeat {filebeat} reported (not version-compared)",
                    "Wazuh bundles its own filebeat, a fork of Elastic filebeat 7.x, "
                    "whose version number does not track the Wazuh version; comparing "
                    "the two would produce a false alarm",
                    evidence=table,
                    fix=(
                        "No action needed. To confirm the bundled build matches the "
                        "manager, compare package versions instead:\n"
                        "    dpkg -l | grep -E 'filebeat|wazuh-manager'\n"
                        "  (or: rpm -qa | grep -E 'filebeat|wazuh-manager')"
                    ),
                    verify="filebeat version",
                )
            )
        return findings
