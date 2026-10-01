"""Configuration: ossec.conf XML validity, wazuh-analysisd -t, agent.conf."""

from __future__ import annotations

import os
import re
import stat
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

from .base import Context, Module
from wdlib.common import Finding, Severity, path_state, read_text
from wdlib.discovery import CONTROL, Component

OSSEC_CONF = "/var/ossec/etc/ossec.conf"
AGENT_CONF_CANDIDATES = (
    "/var/ossec/etc/shared/agent.conf",
    "/var/ossec/etc/shared/default/agent.conf",
)
ANALYSISD_TEST = ["/var/ossec/bin/wazuh-analysisd", "-t"]


class ConfigModule(Module):
    name = "config"
    title = "Configuration validity"
    description = "ossec.conf XML validity, wazuh-analysisd -t, agent.conf"
    requires = (Component.MANAGER,)

    def run(self, ctx: Context) -> List[Finding]:
        content = read_text(OSSEC_CONF)
        if content is None:
            findings = [self._unreadable(ctx)]
            # The authoritative validator still runs: when it cannot execute
            # it reports its own "needs root" note, which is more useful than
            # skipping the check silently.
            findings.extend(self._validator(ctx))
            findings.extend(self._agent_conf(ctx))
            return findings

        findings: List[Finding] = []
        findings.extend(self._validate_xml(ctx, content))
        findings.extend(self._directives(ctx, content))
        findings.extend(self._validator(ctx))
        findings.extend(self._agent_conf(ctx))
        findings.extend(self._permissions(ctx))
        return findings

    def _unreadable(self, ctx: Context) -> Finding:
        """Report an unreadable ossec.conf without claiming it is absent.

        Under /var/ossec a permission problem and a missing file look
        identical to os.path.exists, and "the configuration is missing"
        sends the operator to reinstall a file that was never gone.
        """
        if path_state(OSSEC_CONF) == "missing":
            return self.finding(
                Severity.WARNING,
                "ossec.conf is missing",
                "the manager configuration file does not exist at the expected path, "
                "so the manager has no usable configuration",
                evidence=f"{OSSEC_CONF} does not exist",
                fix="Reinstall or restore the manager configuration.",
                verify=f"sudo ls -l {OSSEC_CONF}",
            )
        return self.finding(
            Severity.INFO,
            "ossec.conf could not be read",
            "the manager configuration exists but is root-readable only, so XML "
            "validation and directive checks were skipped",
            evidence=f"{OSSEC_CONF} is present but not readable by uid {os.geteuid()}",
            fix="Re-run as root: sudo wazuh-doctor --module config",
            verify="sudo wazuh-analysisd -t",
        )

    # -- XML --------------------------------------------------------------

    def _validate_xml(self, ctx: Context, content: str) -> List[Finding]:
        try:
            ET.fromstring(content)
        except ET.ParseError as exc:
            return [
                self.finding(
                    Severity.CRITICAL,
                    "ossec.conf is not valid XML",
                    "the manager cannot parse its configuration, so wazuh-analysisd "
                    "will refuse to start or will start with an empty configuration",
                    evidence=f"XML parse error: {exc}",
                    fix=(
                        "Fix the XML error above. A mismatched or unclosed tag is the "
                        "usual cause:\n"
                        f"    sudo python3 -c \"import xml.etree.ElementTree as E; "
                        f"E.parse('{OSSEC_CONF}')\"\n"
                        "  Restore from a backup if the file was edited by hand."
                    ),
                    verify="sudo wazuh-analysisd -t",
                )
            ]
        return []

    def _directives(self, ctx: Context, content: str) -> List[Finding]:
        findings: List[Finding] = []
        root = self._safe_root(content)

        # A manager with no <remote><connection>secure</remote> cannot
        # receive agent events at all -- that is a hard failure when
        # agents are enrolled.
        remote = content.count("<remote>")
        secure = re.search(r"<connection>\s*secure\s*</connection>", content, re.IGNORECASE)
        if remote == 0 and (ctx.env.agents_count or 0) > 0:
            findings.append(
                self.finding(
                    Severity.CRITICAL,
                    "no <remote> block in ossec.conf but agents are enrolled",
                    "the manager is not configured to listen for agent connections, so "
                    "enrolled agents cannot deliver events",
                    evidence=f"{ctx.env.agents_count} agent(s) enrolled, 0 <remote> blocks found",
                    fix=(
                        "Add a remote block to ossec.conf inside <ossec_config>:\n"
                        "    <remote>\n"
                        "      <connection>secure</connection>\n"
                        "      <port>1514</port>\n"
                        "      <protocol>tcp</protocol>\n"
                        "    </remote>\n"
                        "  then: sudo wazuh-analysisd -t && sudo wazuh-control restart"
                    ),
                    verify="sudo wazuh-analysisd -t",
                )
            )
        elif remote and not secure and (ctx.env.agents_count or 0) > 0:
            findings.append(
                self.finding(
                    Severity.WARNING,
                    "no secure <connection> found in the <remote> block",
                    "agents normally connect over the encrypted 'secure' connection "
                    "on 1514; without it, event delivery depends on another transport",
                    evidence="<remote> present but no <connection>secure</connection>",
                    fix="Set <connection>secure</connection> in the <remote> block.",
                    verify="sudo grep -A5 '<remote>' /var/ossec/etc/ossec.conf",
                )
            )

        if root is not None:
            # ElementTree tags carry no angle brackets, so compare the bare
            # tag names -- "<syscheck>" would never match and this would
            # claim the blocks are absent on every healthy manager.
            blocks = {child.tag for child in root}
            for tag, severity in (("syscheck", "FIM"), ("rootcheck", "rootcheck")):
                if tag not in blocks:
                    findings.append(
                        self.finding(
                            Severity.INFO,
                            f"no <{tag}> block configured",
                            f"{severity} is not configured on this manager, so that "
                            f"detection capability is inactive by design",
                            evidence=f"top-level blocks present: {', '.join(sorted(blocks))}",
                            fix=f"Add a <{tag}> block if {severity} is required.",
                            verify=f"sudo grep -c '<{tag}>' /var/ossec/etc/ossec.conf",
                        )
                    )
        return findings

    @staticmethod
    def _safe_root(content: str):
        try:
            return ET.fromstring(content)
        except ET.ParseError:
            return None

    # -- validator --------------------------------------------------------

    def _validator(self, ctx: Context) -> List[Finding]:
        result = ctx.sudo_run(ANALYSISD_TEST, timeout=30)
        if result.missing:
            return []
        if result.ok:
            return []
        if result.denied:
            return [
                self.finding(
                    Severity.INFO,
                    "wazuh-analysisd -t could not run without root",
                    "the authoritative configuration validator needs root, so this "
                    "check was skipped",
                    fix="Re-run as root: sudo wazuh-analysisd -t",
                    verify="sudo wazuh-analysisd -t",
                )
            ]
        return [
            self.finding(
                Severity.CRITICAL,
                "wazuh-analysisd -t reports the configuration is invalid",
                "the authoritative validator rejects the current configuration, so "
                "analysisd is running with errors or may fail to start entirely",
                evidence=result.output[:1200] or "no output",
                fix=(
                    "Correct the reported problem. Validate before and after every "
                    "edit, and keep a backup:\n"
                    f"    sudo cp {OSSEC_CONF} {OSSEC_CONF}.bak-$(date +%Y%m%d-%H%M%S)\n"
                    "    sudo wazuh-analysisd -t\n"
                    "    sudo wazuh-control restart"
                ),
                verify="sudo wazuh-analysisd -t",
            )
        ]

    # -- agent.conf -------------------------------------------------------

    def _agent_conf(self, ctx: Context) -> List[Finding]:
        for path in AGENT_CONF_CANDIDATES:
            content = read_text(path)
            if content is None:
                continue
            try:
                ET.fromstring(content)
            except ET.ParseError as exc:
                return [
                    self.finding(
                        Severity.CRITICAL,
                        f"shared agent.conf is not valid XML ({os.path.basename(path)})",
                        "every agent that receives this file will fail to parse its "
                        "configuration, breaking centralised agent configuration",
                        evidence=f"{path}\nXML parse error: {exc}",
                        fix=(
                            "Fix the XML in the shared agent.conf. Validate it, then "
                            "the manager will redistribute it to agents."
                        ),
                        verify=f"python3 -c \"import xml.etree.ElementTree as E; E.parse('{path}')\"",
                    )
                ]
        return []

    # -- permissions ------------------------------------------------------

    def _permissions(self, ctx: Context) -> List[Finding]:
        try:
            mode = stat.S_IMODE(os.stat(OSSEC_CONF).st_mode)
        except OSError:
            return []
        if mode & stat.S_IROTH:
            return [
                self.finding(
                    Severity.WARNING,
                    "ossec.conf is world-readable",
                    "the manager configuration can reveal internal addresses and "
                    "deployment details to any local user",
                    evidence=f"{OSSEC_CONF} mode is {stat.filemode(mode)}",
                    fix=(
                        f"    sudo chmod 640 {OSSEC_CONF}\n"
                        f"    sudo chown root:wazuh {OSSEC_CONF}"
                    ),
                    verify=f"sudo stat -c '%a %U:%G' {OSSEC_CONF}",
                )
            ]
        return []
