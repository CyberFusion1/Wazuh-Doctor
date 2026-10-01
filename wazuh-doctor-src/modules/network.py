"""Network reachability: required listening ports, firewall state and DNS."""

from __future__ import annotations

import socket
from typing import List

from .base import Context, Module
from wdlib.common import Finding, Severity, run
from wdlib.discovery import Component, WELL_KNOWN_PORTS

# Which TCP ports must be listening for each component to work.
REQUIRED_PORTS = {
    Component.MANAGER: (1514, 1515, 55000),
    Component.INDEXER: (9200, 9300),
    Component.DASHBOARD: (443,),
}

# Ports whose absence genuinely blocks the deployment.
CRITICAL_PORTS = frozenset({1514, 1515, 9200})


class NetworkModule(Module):
    name = "network"
    title = "Network reachability and ports"
    description = "checks listening ports, firewall rules and DNS resolution"
    requires = (Component.MANAGER, Component.INDEXER, Component.DASHBOARD, Component.FILEBEAT)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._check_ports(ctx))
        findings.extend(self._check_firewall(ctx))
        findings.extend(self._check_dns(ctx))
        return findings

    # -- ports ------------------------------------------------------------

    def _check_ports(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        for component, ports in REQUIRED_PORTS.items():
            if not ctx.env.has(component):
                continue
            for port in ports:
                listeners = ctx.env.listeners_on(port)
                if listeners:
                    continue
                # Nothing on the port. Confirm once with ss before shouting,
                # so a /proc parsing quirk cannot raise a false CRITICAL.
                confirmed = self._confirm_closed(ctx, port)
                severity = Severity.CRITICAL if (port in CRITICAL_PORTS and confirmed) else Severity.WARNING
                what = WELL_KNOWN_PORTS.get(port, f"{component} service")
                findings.append(
                    self.finding(
                        severity,
                        f"{component}: TCP port {port} is not listening",
                        f"nothing is bound to TCP {port}; {what} cannot serve requests",
                        evidence=self._port_evidence(ctx, port, confirmed),
                        fix=(
                            f"Start the service that owns port {port}:\n"
                            f"    sudo systemctl restart wazuh-manager     # 1514/1515/55000\n"
                            f"    sudo systemctl restart wazuh-indexer     # 9200/9300\n"
                            f"    sudo systemctl restart wazuh-dashboard   # 443\n"
                            f"  Then check why it stopped: journalctl -u <service> -n 100"
                        ),
                        verify=f"ss -lntp | grep ':{port} '",
                    )
                )
        return findings

    @staticmethod
    def _confirm_closed(ctx: Context, port: int) -> bool:
        """Independently confirm a port is closed. True = really closed."""
        result = ctx.run(["ss", "-lnt"], timeout=8)
        if result.missing or not result.ok:
            # Cannot confirm; trust only the strong /proc evidence if it
            # found the port truly absent (it did, since we are here).
            return True
        return f":{port} " not in result.output and not any(
            line.split()[3].endswith(f":{port}") for line in result.stdout.splitlines() if len(line.split()) > 3
        )

    @staticmethod
    def _port_evidence(ctx: Context, port: int, confirmed: bool) -> str:
        listeners = ctx.env.listeners_on(port)
        lines = [f"port {port}: {len(listeners)} listener(s) found in /proc/net/tcp{{,6}}"]
        result = run(["ss", "-lnt"], timeout=8)
        if result.ok:
            matching = [ln for ln in result.stdout.splitlines() if f":{port} " in ln]
            lines.append("ss -lnt match for this port:")
            lines.extend(matching or ["  (none)"])
        elif result.missing:
            lines.append("ss: not installed, could not cross-check")
        lines.append(f"conclusion: {'confirmed closed' if confirmed else 'unconfirmed'}")
        return "\n".join(lines)

    # -- exposure ---------------------------------------------------------
    #
    # Deliberately NOT checked here. "This port is bound to 0.0.0.0" is a
    # security-posture finding, and modules/security.py already reports it
    # for exactly these ports. Having both modules emit it produced two
    # identical warnings for one condition, which is how a report trains its
    # reader to skim. security owns it; network sticks to reachability.

    # -- firewall ---------------------------------------------------------

    def _check_firewall(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        must_be_open = [p for c, ports in REQUIRED_PORTS.items() if ctx.env.has(c) for p in ports]

        ufw = ctx.sudo_run(["ufw", "status", "verbose"], timeout=10)
        if ufw.ok and "Status: active" in ufw.stdout:
            blocked = [
                port
                for port in must_be_open
                if not any(
                    f"{port}" in line and ("ALLOW" in line or "ALLOW IN" in line)
                    for line in ufw.stdout.splitlines()
                )
            ]
            if blocked:
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        f"ufw is active and has no allow rule for: {', '.join(map(str, blocked))}",
                        "the host firewall is enabled but does not explicitly permit these "
                        "Wazuh ports, so remote agents or the dashboard may be unable to connect",
                        evidence="\n".join(
                            [ln for ln in ufw.stdout.splitlines() if ln.strip()][:12]
                        ),
                        fix="\n".join(
                            [f"    sudo ufw allow {p}/tcp" for p in blocked]
                            + ["    sudo ufw reload"]
                        ),
                        verify="sudo ufw status verbose",
                    )
                )
            return findings

        firewalld = ctx.sudo_run(["firewall-cmd", "--state"], timeout=8)
        if firewalld.ok and "running" in firewalld.stdout.lower():
            listed = ctx.sudo_run(["firewall-cmd", "--list-all"], timeout=10)
            if listed.ok:
                blocked = [p for p in must_be_open if str(p) not in listed.stdout]
                if blocked:
                    findings.append(
                        self.finding(
                            Severity.WARNING,
                            f"firewalld is running and does not open: {', '.join(map(str, blocked))}",
                            "firewalld is active but these Wazuh ports are absent from the "
                            "active zone, so remote components may be unable to connect",
                            evidence="\n".join(listed.stdout.splitlines()[:12]),
                            fix="\n".join(
                                f"    sudo firewall-cmd --permanent --add-port={p}/tcp" for p in blocked
                            )
                            + "\n    sudo firewall-cmd --reload",
                            verify="sudo firewall-cmd --list-all",
                        )
                    )
            return findings

        iptables = ctx.sudo_run(["iptables", "-S"], timeout=10)
        if iptables.ok and iptables.stdout.strip():
            drops = [
                ln
                for ln in iptables.stdout.splitlines()
                if ("DROP" in ln or "REJECT" in ln) and ln.strip().startswith("-A")
            ]
            if drops:
                findings.append(
                    self.finding(
                        Severity.INFO,
                        "iptables rules present; verify they do not block Wazuh traffic",
                        "raw iptables has DROP/REJECT rules; determining whether they affect "
                        "Wazuh ports requires knowledge of the intended network design",
                        evidence="\n".join(drops[:12]),
                        fix=(
                            f"Confirm these ports are reachable from an agent host:\n"
                            f"    {', '.join(map(str, must_be_open))}\n"
                            f"  Check with: nc -zv <manager-ip> 1514"
                        ),
                        verify="sudo iptables -S | grep -E 'DROP|REJECT'",
                    )
                )
        return findings

    # -- DNS --------------------------------------------------------------

    def _check_dns(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        for probe in ("localhost", ctx.env.hostname):
            if not probe:
                continue
            try:
                socket.getaddrinfo(probe, None)
            except socket.gaierror as exc:
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        f"DNS resolution fails for '{probe}'",
                        "name resolution failed locally; if components address each other by "
                        "hostname rather than IP, they will not connect",
                        evidence=f"socket.getaddrinfo({probe!r}) -> {exc}",
                        fix=(
                            "Ensure the hostname resolves, normally via /etc/hosts:\n"
                            f"    127.0.0.1   {probe}\n"
                            "  Check with: getent hosts " + probe
                        ),
                        verify=f"getent hosts {probe}",
                    )
                )
        return findings
