"""Security posture: file permissions, default credentials, exposed ports."""

from __future__ import annotations

import os
import stat
from typing import List, Optional, Tuple

from .base import Context, Module
from wdlib.common import Finding, Severity, http_request
from wdlib.discovery import Component
from wdlib.fixer import Fix

# Files that must never be world-readable, with the mode we want and why.
SENSITIVE_FILES = (
    ("/var/ossec/etc/client.keys", 0o640, "holds the shared secret for every enrolled agent"),
    ("/var/ossec/etc/ossec.conf", 0o640, "reveals internal addresses and deployment layout"),
    ("/var/ossec/etc/authd.pass", 0o640, "holds the enrollment password"),
    (
        "/etc/wazuh-indexer/opensearch-security/internal_users.yml",
        0o640,
        "holds password hashes for indexer users",
    ),
    ("/var/ossec/api/configuration/api.yaml", 0o640, "holds API credentials and TLS paths"),
)

# Private key material: world-readable keys are a genuine compromise.
KEY_SUFFIXES = (".key", "-key.pem", "_key.pem")
KEY_DIRS = ("/etc/wazuh-indexer/certs", "/etc/filebeat/certs", "/etc/wazuh-dashboard/certs")

# Ports that should not be reachable off-box.
SHOULD_BE_LOCAL = (9200, 9300, 55000)


class SecurityModule(Module):
    name = "security"
    title = "Security posture"
    description = "file permissions, default passwords, exposed ports, API auth"
    requires = (Component.MANAGER, Component.INDEXER, Component.DASHBOARD)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._permissions(ctx))
        findings.extend(self._keys(ctx))
        findings.extend(self._exposure(ctx))
        findings.extend(self._default_credentials(ctx))
        return findings

    # -- permissions ------------------------------------------------------

    def _permissions(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        for path, desired, why in SENSITIVE_FILES:
            mode = self._mode(path)
            if mode is None:
                continue
            if mode & stat.S_IROTH:
                action = self._chmod_fix(path, desired)
                findings.append(
                    self.finding(
                        Severity.CRITICAL if path.endswith("client.keys") else Severity.WARNING,
                        f"{os.path.basename(path)} is world-readable",
                        f"this file {why}; any local user can read it",
                        evidence=f"{path} mode is {stat.filemode(mode)} (octal {oct(mode)})",
                        fix=(
                            f"    sudo chmod {desired:o} {path}\n"
                            f"    sudo chown root:wazuh {path}"
                            + (
                                ""
                                if action
                                else "\n  (agent keys are never touched automatically; "
                                "run the command above yourself)"
                            )
                        ),
                        verify=f"sudo stat -c '%a %U:%G' {path}",
                        fixable=action is not None,
                        fix_action=action,
                    )
                )
        return findings

    def _keys(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        for directory in KEY_DIRS:
            if not os.path.isdir(directory):
                continue
            try:
                names = os.listdir(directory)
            except OSError:
                continue
            for name in names:
                lowered = name.lower()
                if not lowered.endswith(KEY_SUFFIXES):
                    continue
                path = os.path.join(directory, name)
                mode = self._mode(path)
                if mode is None:
                    continue
                if mode & (stat.S_IROTH | stat.S_IRGRP):
                    action = self._chmod_fix(path, 0o400)
                    findings.append(
                        self.finding(
                            Severity.CRITICAL,
                            f"private key {name} is group- or world-readable",
                            "a readable private key undermines TLS entirely: anyone who "
                            "reads it can impersonate the service it belongs to",
                            evidence=f"{path} mode is {stat.filemode(mode)} (octal {oct(mode)})",
                            fix=(
                                f"    sudo chmod 400 {path}\n"
                                f"    sudo chown root:root {path}\n"
                                "  Then restart the owning service."
                            ),
                            verify=f"sudo stat -c '%a %U:%G' {path}",
                            fixable=action is not None,
                            fix_action=action,
                        )
                    )
        return findings

    @staticmethod
    def _chmod_fix(path: str, mode: int) -> Optional[Fix]:
        """Build a chmod repair, or None when the fixer refuses the target.

        The fixer deliberately protects agent keys, logs and index data.
        For a protected path we still report the problem and print the
        manual command, but we do not offer an automatic repair -- and we
        must not let its ValueError escape, or the whole module would be
        reported as crashed exactly when it has a critical finding.
        """

        def apply() -> Tuple[bool, str]:
            try:
                os.chmod(path, mode)
                return True, f"set {path} to {oct(mode)}"
            except OSError as exc:
                return False, str(exc)

        try:
            return Fix(
                summary=f"Restrict permissions on {path} to {oct(mode)}",
                apply=apply,
                target=path,
                validate_after=False,
            )
        except ValueError:
            return None

    @staticmethod
    def _mode(path: str) -> Optional[int]:
        try:
            return stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            return None

    # -- network exposure -------------------------------------------------

    def _exposure(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        for port in SHOULD_BE_LOCAL:
            exposed = [item for item in ctx.env.listeners_on(port) if item.exposed]
            if not exposed:
                continue
            # One socket appears once per address family: a service bound to
            # :: also shows up as 0.0.0.0, so this loop used to emit the
            # identical finding twice. Two copies of one condition is noise
            # that teaches the reader to skim.
            addresses = sorted({f"{item.address}:{port}" for item in exposed})
            uids = sorted({str(item.uid) for item in exposed if item.uid is not None})
            evidence = "listening on " + ", ".join(addresses)
            if uids:
                evidence += f" (uid {', '.join(uids)})"
            findings.append(
                self.finding(
                    Severity.WARNING,
                    f"port {port} is exposed on all interfaces",
                    "this service is reachable from any host that can route here, "
                    "expanding the attack surface beyond the local machine; these "
                    "services are normally bound to loopback. Note that Wazuh "
                    "installs some of these listening on 0.0.0.0 by default, so "
                    "confirm whether this host is reachable from outside before "
                    "changing it",
                    evidence=evidence,
                    fix=(
                        "Bind it to localhost, or firewall it off. Check whether the "
                        "port is genuinely needed off-box before opening it."
                    ),
                    verify=f"ss -lntp | grep ':{port} '",
                )
            )
        return findings

    # -- default credentials ----------------------------------------------

    def _default_credentials(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []

        # Each probe is paired with an unauthenticated control request. If the
        # control also succeeds then authentication is switched off entirely,
        # which is a different (and worse) problem than a default password --
        # reporting it as "accepts the default admin credentials" would send
        # the operator to change a password that is not being checked at all.

        # Indexer: the OpenSearch/Wazuh demo default is admin/admin.
        indexer_url = (ctx.config.get("indexer_url") or "https://127.0.0.1:9200").rstrip("/")
        indexer_control = http_request(f"{indexer_url}/_cluster/health", timeout=8, verify=False)
        indexer_probe = http_request(
            f"{indexer_url}/_cluster/health", auth=("admin", "admin"), timeout=8, verify=False
        )
        if indexer_probe.ok:
            if indexer_control.ok:
                findings.append(
                    self.finding(
                        Severity.CRITICAL,
                        "the indexer has authentication disabled",
                        "the indexer answered a cluster request with no credentials at "
                        "all, so the security plugin is not enforcing authentication "
                        "and anyone who can reach port 9200 has full access to all "
                        "security data",
                        evidence=f"unauthenticated GET {indexer_url}/_cluster/health returned HTTP {indexer_control.status}",
                        fix=(
                            "Re-enable the security plugin and load its configuration:\n"
                            "    grep -E 'plugins.security.(ssl|disabled)' "
                            "/etc/wazuh-indexer/opensearch.yml\n"
                            "    sudo /usr/share/wazuh-indexer/plugins/opensearch-security/"
                            "tools/securityadmin.sh -cd "
                            "/usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig "
                            "-cacert /etc/wazuh-indexer/certs/root-ca.pem "
                            "-cert /etc/wazuh-indexer/certs/admin.pem "
                            "-key /etc/wazuh-indexer/certs/admin-key.pem -icl -nhnv"
                        ),
                        verify="curl -k -s -o /dev/null -w '%{http_code}\\n' https://127.0.0.1:9200/_cluster/health",
                    )
                )
            else:
                findings.append(
                    self.finding(
                        Severity.CRITICAL,
                        "the indexer accepts the default 'admin' credentials",
                        "the indexer authenticated successfully using the documented "
                        "default password, so anyone who can reach port 9200 has full "
                        "access to all security data",
                        evidence=f"authenticated to {indexer_url} using the well-known default credential",
                        fix=(
                            "Change the admin password immediately:\n"
                            "    sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
                            "hash.sh -p '<new-password>'\n"
                            "  Put the hash in internal_users.yml and run securityadmin.sh, "
                            "then update filebeat and the dashboard."
                        ),
                        verify="curl -k -u admin:**** https://127.0.0.1:9200/_cluster/health",
                    )
                )

        # API: Wazuh's documented default is wazuh/wazuh.
        api_url = (ctx.config.get("api_url") or "https://127.0.0.1:55000").rstrip("/")
        api_control = http_request(
            f"{api_url}/agents?limit=1", timeout=8, verify=False
        )
        api_probe = http_request(
            f"{api_url}/security/user/authenticate", method="POST",
            auth=("wazuh", "wazuh"), timeout=8, verify=False,
        )
        if api_probe.ok:
            if api_control.ok:
                findings.append(
                    self.finding(
                        Severity.CRITICAL,
                        "the Wazuh API serves authenticated endpoints without credentials",
                        "a normal API endpoint answered with no authentication, so "
                        "anyone who can reach port 55000 can control the manager",
                        evidence=f"unauthenticated GET {api_url}/agents returned HTTP {api_control.status}",
                        fix=(
                            "Check the API's authentication configuration:\n"
                            "    sudo grep -A10 'auth' "
                            "/var/ossec/api/configuration/api.yaml"
                        ),
                        verify="curl -k -s -o /dev/null -w '%{http_code}\\n' 'https://127.0.0.1:55000/agents?limit=1'",
                    )
                )
            else:
                findings.append(
                    self.finding(
                        Severity.CRITICAL,
                        "the Wazuh API accepts the default 'wazuh' credentials",
                        "the API authenticated with the documented default password, so "
                        "anyone who can reach port 55000 can control the manager",
                        evidence=f"authenticated to {api_url} using the well-known default credential",
                        fix=(
                            "Change the API password:\n"
                            "    curl -k -X PUT -u <user>:<pass> "
                            "'https://127.0.0.1:55000/security/users/1' "
                            "-H 'Content-Type: application/json' "
                            "-d '{\"password\":\"<new-password>\"}'\n"
                            "  Then update the dashboard's wazuh.api.password."
                        ),
                        verify="curl -k -X POST -u wazuh:**** https://127.0.0.1:55000/security/user/authenticate",
                    )
                )
        return findings
