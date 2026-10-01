"""Wazuh API: port 55000, JWT authentication and auth errors."""

from __future__ import annotations

import json
import os
import re
from typing import List, Optional

from .base import Context, Module
from wdlib.common import Finding, Severity, http_request, tail_lines
from wdlib.discovery import Component

API_LOG = "/var/ossec/logs/api.log"


class ApiModule(Module):
    name = "api"
    title = "Wazuh API"
    description = "port 55000, JWT authentication and auth errors"
    requires = (Component.MANAGER,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._port(ctx))
        findings.extend(self._auth(ctx))
        findings.extend(self._log(ctx))
        return findings

    def _base(self, ctx: Context) -> str:
        return (ctx.config.get("api_url") or "https://127.0.0.1:55000").rstrip("/")

    # -- port -------------------------------------------------------------

    def _port(self, ctx: Context) -> List[Finding]:
        if ctx.env.port_open(55000):
            return []
        probe = http_request(self._base(ctx) + "/", timeout=8, verify=False)
        if probe.status is not None:
            return []
        return [
            self.finding(
                Severity.CRITICAL,
                "the Wazuh API is not listening on port 55000",
                "the manager's REST API is unreachable, so the dashboard cannot "
                "display agent data and API automation fails",
                evidence=f"no listener on 55000; GET {probe.url} -> {probe.error or 'no response'}",
                fix=(
                    "The API runs as a manager daemon:\n"
                    "    sudo /var/ossec/bin/wazuh-control status | grep wazuh-apid\n"
                    "    sudo systemctl restart wazuh-manager\n"
                    "    sudo tail -n 100 /var/ossec/logs/api.log"
                ),
                verify="curl -k -s -o /dev/null -w '%{http_code}\\n' https://127.0.0.1:55000/",
            )
        ]

    # -- authentication ---------------------------------------------------

    def _auth(self, ctx: Context) -> List[Finding]:
        base = self._base(ctx)

        if not ctx.config.has_api_creds():
            probe = http_request(f"{base}/security/user/authenticate", method="POST", timeout=8, verify=False)
            if probe.status is None:
                return []
            if probe.unauthorized:
                return [
                    self.finding(
                        Severity.INFO,
                        "API is up but no credentials were supplied",
                        "the API answered and rejected the unauthenticated request, "
                        "which is correct behaviour; supply credentials to enable JWT "
                        "and endpoint checks",
                        evidence=f"HTTP {probe.status} from {base}",
                        fix=(
                            "Create ~/.config/wazuh-doctor/config with:\n"
                            "    api_user = <user>\n"
                            "    api_password = <password>\n"
                            "  or export WAZUH_API_USER / WAZUH_API_PASSWORD.\n"
                            "  Never pass credentials as command-line arguments."
                        ),
                        verify="curl -k -X POST -u <user> **** https://127.0.0.1:55000/security/user/authenticate",
                    )
                ]
            return []

        user = ctx.config.get("api_user")
        password = ctx.config.get("api_password")
        auth = http_request(
            f"{base}/security/user/authenticate", method="POST", auth=(user, password),
            timeout=10, verify=False,
        )

        if auth.status is None:
            return [
                self.finding(
                    Severity.CRITICAL,
                    "the API did not respond to an authentication attempt",
                    "the API is not answering requests, so the manager cannot be "
                    "administered and the dashboard cannot read data",
                    evidence=f"POST {base}/security/user/authenticate -> {auth.error}",
                    fix="Restart the manager and check the API log.",
                    verify="curl -k -s -o /dev/null -w '%{http_code}\\n' https://127.0.0.1:55000/",
                )
            ]

        if auth.unauthorized:
            return [
                self.finding(
                    Severity.WARNING,
                    "the API rejected the configured credentials",
                    "the supplied API user or password is wrong or the account is "
                    "disabled, so automation and the dashboard cannot authenticate",
                    evidence=f"HTTP {auth.status} from {base}/security/user/authenticate",
                    fix=(
                        "Verify the credentials. To reset, use the manager's user "
                        "management (the API itself needs a valid session), or check\n"
                        "    sudo grep -i 'authentication' /var/ossec/logs/api.log | tail -20"
                    ),
                    verify="curl -k -X POST -u <user> **** https://127.0.0.1:55000/security/user/authenticate",
                )
            ]

        if not auth.ok:
            return [
                self.finding(
                    Severity.WARNING,
                    f"API authentication returned HTTP {auth.status}",
                    "the API responded with an unexpected status during authentication",
                    evidence=auth.snippet(400),
                    fix="Inspect the API log for the underlying error.",
                    verify="sudo tail -n 50 /var/ossec/logs/api.log",
                )
            ]

        # Auth succeeded. Confirm the JWT actually works, and never print it.
        payload = auth.json() or {}
        token = payload.get("data", {}).get("token") if isinstance(payload.get("data"), dict) else None
        if not token:
            return [
                self.finding(
                    Severity.WARNING,
                    "the API accepted credentials but returned no JWT",
                    "authentication succeeded without a usable token, so subsequent "
                    "API calls will fail",
                    evidence=auth.snippet(300),
                    fix="Check the API version and log for a token generation error.",
                    verify="sudo tail -n 50 /var/ossec/logs/api.log",
                )
            ]

        probe = http_request(
            f"{base}/agents?limit=1", timeout=10, verify=False,
            headers={"Authorization": f"Bearer {token}"},
        )
        if not probe.ok:
            return [
                self.finding(
                    Severity.WARNING,
                    "the API issued a JWT but rejected it on a subsequent call",
                    "the token obtained from authenticate was not accepted for a normal "
                    "endpoint, which points at a token or RBAC configuration problem",
                    evidence=f"HTTP {probe.status} from {base}/agents?limit=1",
                    fix=(
                        "Inspect API/RBAC configuration and the log:\n"
                        "    sudo tail -n 50 /var/ossec/logs/api.log"
                    ),
                    verify="curl -k -H 'Authorization: Bearer ****' 'https://127.0.0.1:55000/agents?limit=1'",
                )
            ]
        return []

    # -- log --------------------------------------------------------------

    def _log(self, ctx: Context) -> List[Finding]:
        lines = tail_lines(API_LOG, 300)
        if not lines:
            return []

        errors = [ln for ln in lines if re.search(r"\b(ERROR|CRITICAL)\b", ln, re.IGNORECASE)]
        if errors:
            return [
                self.finding(
                    Severity.WARNING,
                    f"{len(errors)} API log error line(s)",
                    "the Wazuh API is logging errors, which normally means a failed "
                    "startup, a rejected request or a problem reading its configuration",
                    evidence="\n".join(errors[-12:]),
                    fix=(
                        "    sudo tail -n 100 /var/ossec/logs/api.log\n"
                        "  Check for 401/403 lines too: those are rejected "
                        "authentications, which usually mean a wrong password in the "
                        "dashboard or in an automation client."
                    ),
                    verify="sudo grep -icE 'error|critical' /var/ossec/logs/api.log",
                )
            ]

        # A handful of 401/403 lines is normal -- including from this tool's
        # own probes. Only a sustained pattern is worth reporting, and even
        # then it is framed as something to check rather than a verdict.
        rejected = [ln for ln in lines if re.search(r"\b(401|403)\b", ln)]
        if len(rejected) >= 10:
            return [
                self.finding(
                    Severity.WARNING,
                    f"{len(rejected)} rejected authentication attempt(s) in the API log",
                    "the API is repeatedly refusing authentication, so a client "
                    "(the dashboard, or a script) is using the wrong credentials; "
                    "note that wazuh-doctor's own credential probes also produce a "
                    "few 401s, which is why this needs to be a sustained pattern",
                    evidence="\n".join(rejected[-8:]),
                    fix=(
                        "Find which client is failing:\n"
                        "    sudo grep -E '401|403' /var/ossec/logs/api.log | tail -20"
                    ),
                    verify="sudo grep -cE '401|403' /var/ossec/logs/api.log",
                )
            ]
        return []
