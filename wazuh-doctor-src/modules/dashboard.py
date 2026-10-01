"""Dashboard: service state, logs, API connection and index patterns."""

from __future__ import annotations

import json
import os
import re
from typing import List, Optional

from .base import Context, Module
from wdlib.common import (
    Finding,
    Severity,
    http_request,
    path_state,
    read_text,
    systemd_unit_exists,
    tail_lines,
)
from wdlib.discovery import Component

DASHBOARD_LOG = "/var/log/wazuh-dashboard/opensearch_dashboards.log"
DASHBOARD_CONF = "/etc/wazuh-dashboard/opensearch_dashboards.yml"

# The Wazuh plugin keeps its own API connection settings, and this is not
# the file that holds them. In Wazuh 4.x the dashboard stores the API host
# in wazuh.yml under the plugin's data directory, as a `hosts:` list.
# Checking only opensearch_dashboards.yml for a 'wazuh.api' key reported
# "no Wazuh API settings found" on every correctly configured deployment,
# and told the operator to edit a file that would not have fixed anything.
DASHBOARD_PLUGIN_CONF = "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"

# Markers any of which mean an API connection is configured. Deliberately
# broad: the cost of missing one is a warning on a working dashboard, so
# this must never be narrower than the shapes actually in use.
API_MARKERS = ("hosts:", "url:", "wazuh.api", "api_host", "api.host")

ERROR_RX = re.compile(r"\b(error|fatal|unhandled)\b|ECONNREFUSED|unable to connect", re.IGNORECASE)


class DashboardModule(Module):
    name = "dashboard"
    title = "Dashboard"
    description = "service status, journalctl, API connection, index patterns"
    requires = (Component.DASHBOARD,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._service(ctx))
        findings.extend(self._http(ctx))
        findings.extend(self._conf(ctx))
        findings.extend(self._logs(ctx))
        findings.extend(self._index_patterns(ctx))
        return findings

    # -- service ----------------------------------------------------------

    def _service(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        # "is-active" says "inactive" for a unit that does not exist, which
        # would read as "the dashboard is down" on a host whose dashboard is
        # not managed by systemd. The HTTP check below still covers reachability.
        if not systemd_unit_exists("wazuh-dashboard"):
            return findings
        result = ctx.run(["systemctl", "is-active", "wazuh-dashboard"], timeout=8)
        if result.missing:
            return findings
        state = result.output.strip()
        if state != "active":
            findings.append(
                self.finding(
                    Severity.CRITICAL,
                    "the wazuh-dashboard service is not active",
                    "the dashboard process is not running, so the web UI is unavailable",
                    evidence=f"systemctl is-active wazuh-dashboard -> {state or 'no output'}",
                    fix=(
                        "    sudo systemctl start wazuh-dashboard\n"
                        "    sudo journalctl -u wazuh-dashboard -n 150 --no-pager"
                    ),
                    verify="systemctl is-active wazuh-dashboard",
                )
            )
        return findings

    # -- http -------------------------------------------------------------

    def _http(self, ctx: Context) -> List[Finding]:
        url = (ctx.config.get("dashboard_url") or "https://127.0.0.1:443").rstrip("/") + "/"
        result = http_request(url, timeout=8, verify=False)
        if result.status is None:
            # Only complain if the service claims to be up.
            if ctx.run(["systemctl", "is-active", "wazuh-dashboard"], timeout=8).output.strip() == "active":
                return [
                    self.finding(
                        Severity.CRITICAL,
                        "the dashboard is running but not answering on its port",
                        "the systemd unit reports active while no HTTP response is "
                        "returned, so the UI is unreachable despite the process existing",
                        evidence=f"GET {url} -> {result.error or 'no response'}",
                        fix=(
                            "Check the listening port and the dashboard log:\n"
                            "    ss -lntp | grep -E ':(443|80) '\n"
                            "    sudo tail -n 100 /var/log/wazuh-dashboard/opensearch_dashboards.log"
                        ),
                        verify=f"curl -k -s -o /dev/null -w '%{{http_code}}\\n' {url}",
                    )
                ]
            return []
        if result.status in (200, 302, 401):
            return []
        return [
            self.finding(
                Severity.WARNING,
                f"the dashboard returned HTTP {result.status}",
                "the dashboard responded with an unexpected status code",
                evidence=f"GET {url} -> {result.status}\n{result.snippet(300)}",
                fix="Inspect the dashboard log for the underlying error.",
                verify=f"curl -k -s -o /dev/null -w '%{{http_code}}\\n' {url}",
            )
        ]

    # -- config -----------------------------------------------------------

    def _conf(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []

        # The plugin's own file first: that is where the API host lives.
        plugin = read_text(DASHBOARD_PLUGIN_CONF)
        if plugin is not None:
            if self._has_api_settings(plugin):
                return findings
            if not plugin.strip():
                # An empty file is what the plugin leaves behind before its
                # first start; there is nothing to conclude yet.
                return findings
            findings.append(
                self.finding(
                    Severity.WARNING,
                    "the dashboard has no Wazuh API host configured",
                    "the dashboard's Wazuh plugin config exists but carries no API "
                    "connection, so the UI cannot query the manager and will show API "
                    "errors even though the manager is healthy",
                    evidence=f"{DASHBOARD_PLUGIN_CONF} contains no hosts:/url: entry",
                    fix=(
                        f"Set the API connection in {DASHBOARD_PLUGIN_CONF}:\n"
                        "    hosts:\n"
                        "      - default:\n"
                        "          url: https://127.0.0.1\n"
                        "          port: 55000\n"
                        "          username: wazuh-wui\n"
                        "          password: <the wazuh-wui password>\n"
                        "  then: sudo systemctl restart wazuh-dashboard\n"
                        "  wazuh-doctor never prints credential values; read the "
                        "current password from the manager's API configuration."
                    ),
                    verify=f"sudo grep -A6 'hosts:' {DASHBOARD_PLUGIN_CONF}",
                )
            )
            return findings

        # Fall back to the older layout, where the API block lived in
        # opensearch_dashboards.yml.
        content = read_text(DASHBOARD_CONF)
        if content is None:
            if not ctx.env.is_root and (
                path_state(DASHBOARD_PLUGIN_CONF) == "unknown"
                or path_state(DASHBOARD_CONF) == "unknown"
            ):
                findings.append(
                    self.finding(
                        Severity.INFO,
                        "the dashboard configuration could not be read",
                        "the Wazuh API host and indexer connection could not be "
                        "inspected without privileges",
                        fix="Re-run as root: sudo wazuh-doctor --module dashboard",
                        verify=f"sudo grep -E 'hosts|url' {DASHBOARD_PLUGIN_CONF}",
                    )
                )
            return findings

        if not self._has_api_settings(content):
            findings.append(
                self.finding(
                    Severity.WARNING,
                    "the dashboard has no Wazuh API host configured",
                    "no API connection was found in either the dashboard's plugin "
                    "config or opensearch_dashboards.yml, so the UI cannot query the "
                    "manager and will show API errors",
                    evidence=(
                        f"no API marker in {DASHBOARD_PLUGIN_CONF} "
                        f"(absent) or {DASHBOARD_CONF}"
                    ),
                    fix=(
                        f"Set the API connection in {DASHBOARD_PLUGIN_CONF}:\n"
                        "    hosts:\n"
                        "      - default:\n"
                        "          url: https://127.0.0.1\n"
                        "          port: 55000\n"
                        "          username: wazuh-wui\n"
                        "          password: <the wazuh-wui password>\n"
                        "  then: sudo systemctl restart wazuh-dashboard"
                    ),
                    verify=f"sudo grep -A6 'hosts:' {DASHBOARD_PLUGIN_CONF}",
                )
            )
        return findings

    @staticmethod
    def _has_api_settings(content: str) -> bool:
        lowered = content.lower()
        return any(marker in lowered for marker in API_MARKERS)

    # -- logs -------------------------------------------------------------

    def _logs(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        lines = tail_lines(DASHBOARD_LOG, 300)

        journal = ctx.sudo_run(
            ["journalctl", "-u", "wazuh-dashboard", "-n", "200", "--no-pager"], timeout=20
        )
        if journal.ok and journal.stdout:
            lines = lines + journal.stdout.splitlines()[-200:] if lines else journal.stdout.splitlines()[-200:]

        if not lines:
            return findings

        hits = [ln for ln in lines if ERROR_RX.search(ln)]
        if hits:
            findings.append(
                self.finding(
                    Severity.WARNING,
                    f"{len(hits)} error line(s) in the dashboard logs",
                    "the dashboard is logging errors, most often a failure to reach "
                    "the Wazuh API or the indexer",
                    evidence="\n".join(hits[-12:]),
                    fix=(
                        "    sudo journalctl -u wazuh-dashboard -n 100 --no-pager\n"
                        "  Confirm the API is up: curl -k -s -o /dev/null -w '%{http_code}\\n' "
                        "https://127.0.0.1:55000/"
                    ),
                    verify="sudo journalctl -u wazuh-dashboard -n 50 --no-pager",
                )
            )
        return findings

    # -- index patterns ---------------------------------------------------

    def _index_patterns(self, ctx: Context) -> List[Finding]:
        if not (ctx.config.has("dashboard_user") and ctx.config.has("dashboard_password")):
            return [
                self.finding(
                    Severity.INFO,
                    "index pattern check skipped (no dashboard credentials)",
                    "verifying that the wazuh-* index patterns exist requires "
                    "authenticating to the dashboard, and no credentials were supplied",
                    fix=(
                        "Add dashboard_user / dashboard_password to "
                        "~/.config/wazuh-doctor/config or the matching environment "
                        "variables to enable this check."
                    ),
                    verify="curl -k -u <user> **** 'https://127.0.0.1:443/api/saved_objects/_find?type=index-pattern'",
                )
            ]

        base = (ctx.config.get("dashboard_url") or "https://127.0.0.1:443").rstrip("/")
        url = f"{base}/api/saved_objects/_find?type=index-pattern&per_page=100"
        auth = (ctx.config.get("dashboard_user"), ctx.config.get("dashboard_password"))
        result = http_request(url, auth=auth, timeout=12, verify=False,
                              headers={"osd-xsrf": "true"})

        if result.unauthorized:
            return [
                self.finding(
                    Severity.WARNING,
                    "the dashboard rejected the supplied credentials",
                    "the dashboard API returned an authentication error, so index "
                    "patterns could not be verified",
                    evidence=f"HTTP {result.status} from {base}",
                    fix="Correct dashboard_user / dashboard_password in the wazuh-doctor config.",
                    verify=f"curl -k -u <user> **** '{base}/api/status'",
                )
            ]
        if result.status is None:
            return []
        if not result.ok:
            # A 404 or 500 is not evidence that no index pattern exists.
            # Reporting "no index patterns" here would send the operator
            # after a configuration problem that is probably not there.
            return []

        payload = result.json() or {}
        titles = [
            obj.get("attributes", {}).get("title", "")
            for obj in payload.get("saved_objects", [])
            if isinstance(obj, dict)
        ]
        if not titles:
            return [
                self.finding(
                    Severity.WARNING,
                    "no index patterns are defined in the dashboard",
                    "the dashboard has no saved index patterns, so no Wazuh data will "
                    "be displayed even though alerts may be indexed",
                    evidence=result.snippet(400),
                    fix=(
                        "Wazuh installs its index patterns on first dashboard start. "
                        "Check the dashboard log for template/pattern initialisation "
                        "errors, or import the wazuh index pattern manually."
                    ),
                    verify=f"curl -k -u <user> **** '{base}/api/saved_objects/_find?type=index-pattern'",
                )
            ]
        if not any("wazuh" in title.lower() for title in titles):
            return [
                self.finding(
                    Severity.WARNING,
                    "no wazuh-* index pattern present",
                    "index patterns exist but none reference Wazuh data, so the "
                    "dashboard will not show alerts",
                    evidence="existing patterns: " + ", ".join(sorted(t for t in titles if t)[:20]),
                    fix="Confirm the filebeat index name matches the pattern, and that the wazuh template was loaded.",
                    verify="sudo filebeat test output -c /etc/filebeat/filebeat.yml",
                )
            ]
        return []
