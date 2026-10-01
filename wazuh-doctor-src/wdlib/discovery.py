"""
wazuh-doctor :: environment discovery

Works out what this machine actually is before any check runs:

  * OS / distribution family
  * Wazuh version
  * which components are installed locally
  * deployment shape (all-in-one / distributed / docker / agent-only)
  * which ports are listening, and under which uid

Everything here is read-only and works unprivileged where possible.
Listening sockets are parsed straight out of /proc/net/tcp{,6} rather
than shelling out to ss, which keeps discovery working on a minimal
host and avoids the false negative where an indexer bound to
IPv4-mapped IPv6 looks like it is not listening at all.
"""

from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import common
from .common import CommandResult, read_text, run


# --------------------------------------------------------------------------
# Components
# --------------------------------------------------------------------------


class Component:
    MANAGER = "manager"
    INDEXER = "indexer"
    DASHBOARD = "dashboard"
    FILEBEAT = "filebeat"
    AGENT = "agent"


ALL_COMPONENTS = (
    Component.MANAGER,
    Component.INDEXER,
    Component.DASHBOARD,
    Component.FILEBEAT,
    Component.AGENT,
)

# Canonical on-disk locations (Ubuntu/Debian and RHEL/CentOS use the same
# paths for Wazuh 4.x packages).
PATH_MARKERS: Dict[str, Tuple[str, ...]] = {
    Component.MANAGER: (
        "/var/ossec/bin/wazuh-control",
        "/var/ossec/bin/wazuh-analysisd",
    ),
    Component.INDEXER: (
        "/usr/share/wazuh-indexer/bin/opensearch",
        "/etc/wazuh-indexer",
    ),
    Component.DASHBOARD: ("/usr/share/wazuh-dashboard",),
    Component.FILEBEAT: ("/usr/share/filebeat/bin/filebeat", "/etc/filebeat"),
    Component.AGENT: ("/var/ossec/bin/wazuh-agentd",),
}

# Service account created by each package. Useful as a second opinion when
# the binary path check is inconclusive.
USER_MARKERS: Dict[str, str] = {
    Component.MANAGER: "wazuh",
    Component.INDEXER: "wazuh-indexer",
    Component.DASHBOARD: "wazuh-dashboard",
}

WELL_KNOWN_PORTS: Dict[int, str] = {
    1514: "wazuh-remoted (agent -> manager events)",
    1515: "wazuh-authd (agent enrollment)",
    55000: "wazuh-api (REST)",
    9200: "indexer HTTP",
    9300: "indexer transport",
    443: "dashboard",
    80: "dashboard (http redirect)",
}

CONFIG_FILES: Dict[str, str] = {
    Component.MANAGER: "/var/ossec/etc/ossec.conf",
    Component.INDEXER: "/etc/wazuh-indexer/opensearch.yml",
    Component.DASHBOARD: "/etc/wazuh-dashboard/opensearch_dashboards.yml",
    Component.FILEBEAT: "/etc/filebeat/filebeat.yml",
}

LOG_FILES: Dict[str, str] = {
    Component.MANAGER: "/var/ossec/logs/ossec.log",
    Component.INDEXER: "/var/log/wazuh-indexer/wazuh-indexer.log",
    Component.DASHBOARD: "/var/log/wazuh-dashboard/opensearch_dashboards.log",
    Component.FILEBEAT: "/var/log/filebeat/filebeat",
    Component.AGENT: "/var/ossec/logs/ossec.log",
}

MANAGER_BIN = "/var/ossec/bin"
CONTROL = "/var/ossec/bin/wazuh-control"


# --------------------------------------------------------------------------
# Listening sockets
# --------------------------------------------------------------------------


@dataclass
class Listener:
    port: int
    address: str
    uid: int
    family: str

    @property
    def scope(self) -> str:
        """loopback / all / specific"""
        bare = self.address.strip("[]")
        if bare in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            if bare in ("127.0.0.1", "::1"):
                return "loopback"
            return "all"
        if bare.startswith("127."):
            return "loopback"
        return "specific"

    @property
    def exposed(self) -> bool:
        """Bound to every interface -- reachable off-box."""
        return self.scope == "all"


def _parse_hex_addr(raw: str, family: str) -> str:
    """Turn the /proc encoding back into a readable address."""
    if family == "inet":
        host_hex, _, _port = raw.rpartition(":")
        try:
            le = bytes.fromhex(host_hex)
            return socket.inet_ntoa(le[::-1])
        except Exception:
            return host_hex
    # inet6: 32 hex chars, little-endian per 4-byte word.
    host_hex, _, _port = raw.rpartition(":")
    try:
        raw_bytes = bytes.fromhex(host_hex)
        words = [raw_bytes[i : i + 4][::-1] for i in range(0, 16, 4)]
        packed = b"".join(words)
        addr = socket.inet_ntop(socket.AF_INET6, packed)
        if addr.startswith("::ffff:"):
            return addr[len("::ffff:") :]
        return addr
    except Exception:
        return host_hex


def listening_ports() -> List[Listener]:
    """Every LISTEN socket, straight from the kernel.

    Reading /proc/net/tcp needs no privileges, so this works even when
    ``ss`` is absent or we are not root.
    """
    listeners: List[Listener] = []
    for path, family in (("/proc/net/tcp", "inet"), ("/proc/net/tcp6", "inet6")):
        content = read_text(path)
        if not content:
            continue
        for line in content.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                continue
            local, state, uid_raw = fields[1], fields[3], fields[7]
            if state != "0A":  # TCP_LISTEN
                continue
            _addr_hex, _, port_hex = local.rpartition(":")
            try:
                port = int(port_hex, 16)
                uid = int(uid_raw)
            except ValueError:
                continue
            listeners.append(
                Listener(
                    port=port,
                    address=_parse_hex_addr(local, family),
                    uid=uid,
                    family=family,
                )
            )
    return listeners


def uid_to_name(uid: int) -> str:
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------


@dataclass
class Environment:
    os_name: str = "unknown"
    os_id: str = "unknown"
    os_version: str = "unknown"
    os_family: str = "unknown"  # debian | rhel | unknown
    kernel: str = "unknown"
    hostname: str = "unknown"
    is_root: bool = False
    has_sudo: bool = False
    python_version: str = "unknown"

    wazuh_version: str = "unknown"
    version_source: str = "unknown"

    components: Dict[str, bool] = field(default_factory=dict)
    component_paths: Dict[str, str] = field(default_factory=dict)
    deployment: str = "unknown"
    is_manager: bool = False
    is_agent: bool = False
    is_docker: bool = False

    listeners: List[Listener] = field(default_factory=list)
    agents_count: Optional[int] = None
    cluster_enabled: bool = False
    cluster_role: str = "unknown"

    warnings: List[str] = field(default_factory=list)

    # -- convenience ------------------------------------------------------

    def has(self, component: str) -> bool:
        return bool(self.components.get(component))

    def any_of(self, *components: str) -> bool:
        return any(self.has(c) for c in components)

    def port_open(self, port: int) -> bool:
        return any(listener.port == port for listener in self.listeners)

    def listeners_on(self, port: int) -> List[Listener]:
        return [l for l in self.listeners if l.port == port]

    def describe(self) -> str:
        return (
            f"{self.os_name} | Wazuh {self.wazuh_version} | {self.deployment} | "
            f"components: {', '.join(sorted(c for c, ok in self.components.items() if ok)) or 'none'}"
        )


def _detect_os(env: Environment) -> None:
    content = read_text("/etc/os-release") or ""
    values: Dict[str, str] = {}
    for line in content.splitlines():
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip().strip('"')
    env.os_name = values.get("PRETTY_NAME") or values.get("NAME") or "unknown"
    env.os_id = values.get("ID", "unknown")
    env.os_version = values.get("VERSION_ID", "unknown")

    like = (values.get("ID", "") + " " + values.get("ID_LIKE", "")).lower()
    if any(tag in like for tag in ("debian", "ubuntu", "kali", "mint")):
        env.os_family = "debian"
    elif any(tag in like for tag in ("rhel", "centos", "fedora", "rocky", "almalinux", "amzn")):
        env.os_family = "rhel"
    else:
        # Fall back to which package manager is on the box.
        if common.have("dpkg"):
            env.os_family = "debian"
        elif common.have("rpm"):
            env.os_family = "rhel"

    uname = os.uname()
    env.kernel = f"{uname.sysname} {uname.release} {uname.machine}"
    env.hostname = uname.nodename
    env.python_version = f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"


def _detect_version(env: Environment) -> None:
    """Try several sources; the indexer unit file is the most reliable
    when configs are root-only, because systemd units are world-readable."""
    # 1. wazuh-control info (authoritative, needs root)
    result = run([CONTROL, "info"], timeout=8, use_sudo=True)
    if result.ok:
        match = re.search(r"(?im)^\s*WAZUH_VERSION\s*=\s*['\"]?([\w.\-]+)", result.stdout)
        if not match:
            match = re.search(r"(?im)^\s*VERSION\s*=\s*['\"]?([\w.\-]+)", result.stdout)
        if match:
            env.wazuh_version = match.group(1)
            env.version_source = "wazuh-control info"
            return

    # 2. ossec.conf <version>
    content = read_text(CONFIG_FILES[Component.MANAGER])
    if content:
        match = re.search(r"<version>\s*([^<\s]+)\s*</version>", content)
        if match:
            env.wazuh_version = match.group(1)
            env.version_source = "ossec.conf"
            return

    # 3. indexer systemd unit trailer: "# Built for packages-4.14.7"
    for unit in (
        "/lib/systemd/system/wazuh-indexer.service",
        "/usr/lib/systemd/system/wazuh-indexer.service",
        "/etc/systemd/system/wazuh-dashboard.service",
    ):
        content = read_text(unit)
        if not content:
            continue
        match = re.search(r"packages-([0-9][\w.\-]*)", content)
        if match:
            env.wazuh_version = match.group(1)
            env.version_source = f"unit file {os.path.basename(unit)}"
            return

    # 4. Package database.
    if env.os_family == "debian":
        result = run(["dpkg-query", "-W", "-f=${Version}", "wazuh-manager"], timeout=8)
        if result.ok and result.stdout.strip():
            env.wazuh_version = result.stdout.strip().split("-")[0]
            env.version_source = "dpkg"
            return
    elif env.os_family == "rhel":
        result = run(["rpm", "-q", "--qf", "%{VERSION}", "wazuh-manager"], timeout=8)
        if result.ok and result.stdout.strip():
            env.wazuh_version = result.stdout.strip()
            env.version_source = "rpm"
            return


def _detect_components(env: Environment) -> None:
    passwd = read_text("/etc/passwd") or ""
    for component in ALL_COMPONENTS:
        found = any(common.path_exists(p) for p in PATH_MARKERS.get(component, ()))
        if not found:
            user = USER_MARKERS.get(component)
            if user and re.search(rf"(?m)^{re.escape(user)}:", passwd):
                found = True
        env.components[component] = found
        for candidate in PATH_MARKERS.get(component, ()):
            if common.path_exists(candidate):
                env.component_paths[component] = candidate
                break


def _detect_role(env: Environment) -> None:
    """Manager vs agent.

    The manager runs remoted + authd; an agent-only install has
    wazuh-agentd and a client.keys but no remoted binary.
    """
    env.is_agent = common.path_exists("/var/ossec/bin/wazuh-agentd")
    remoted = common.path_exists(f"{MANAGER_BIN}/wazuh-remoted")
    authd = common.path_exists(f"{MANAGER_BIN}/wazuh-authd")
    analysisd = common.path_exists(f"{MANAGER_BIN}/wazuh-analysisd")

    listening_1514 = env.port_open(1514)
    listening_1515 = env.port_open(1515)

    manager_markers = sum([remoted, authd, analysisd, listening_1514, listening_1515])
    env.is_manager = manager_markers >= 2

    if env.is_manager:
        # An agent-only host would not normally have these components at all.
        env.components[Component.MANAGER] = True
        env.components[Component.AGENT] = True  # manager runs an agentd too


def _detect_docker(env: Environment) -> None:
    if common.path_exists("/.dockerenv") or common.path_exists("/run/.containerenv"):
        env.is_docker = True
        return
    content = read_text("/proc/1/cgroup") or ""
    if "docker" in content or "containerd" in content or "kubepods" in content:
        env.is_docker = True
        return
    # A dockerised Wazuh usually exposes the components through the
    # daemon rather than local packages.
    if common.have("docker"):
        result = run(["docker", "ps", "--format", "{{.Image}}"], timeout=8)
        if result.ok and "wazuh" in result.stdout.lower():
            env.is_docker = True


def _detect_deployment(env: Environment) -> None:
    if env.is_docker:
        env.deployment = "docker"
        return

    manager_local = env.has(Component.MANAGER)
    indexer_local = env.has(Component.INDEXER)
    dashboard_local = env.has(Component.DASHBOARD)
    filebeat_local = env.has(Component.FILEBEAT)

    if manager_local and indexer_local and dashboard_local:
        env.deployment = "all-in-one"
    elif manager_local and not indexer_local:
        env.deployment = "distributed"
    elif env.is_agent and not manager_local:
        env.deployment = "agent-only"
    elif manager_local:
        env.deployment = "manager-only"
    elif env.any_of(Component.INDEXER, Component.DASHBOARD) and not manager_local:
        env.deployment = "indexer-only"
    elif filebeat_local:
        env.deployment = "forwarder-only"
    else:
        env.deployment = "unknown"


def _detect_cluster(env: Environment) -> None:
    """Cluster config lives in ossec.conf; only readable as root."""
    content = read_text(CONFIG_FILES[Component.MANAGER])
    if content is None:
        if common.unreadable_because_unprivileged(CONFIG_FILES[Component.MANAGER]):
            env.warnings.append(
                "ossec.conf is root-only; cluster configuration could not be inspected"
            )
        return
    match = re.search(r"<cluster>\s*<name>([^<]*)</name>.*?<node_type>\s*([^<\s]+)", content, re.S | re.I)
    if match:
        env.cluster_enabled = True
        env.cluster_role = match.group(2).strip().lower()
        if env.cluster_role not in ("master", "worker"):
            env.cluster_role = "unknown"


def _count_agents(env: Environment) -> None:
    """Count enrolled agents without ever printing key material."""
    keys_path = "/var/ossec/etc/client.keys"
    content = read_text(keys_path)
    if content is None:
        return
    count = 0
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            count += 1
    env.agents_count = count


def discover(use_sudo_for_config: bool = True) -> Environment:
    """Build the full environment picture. Never raises."""
    env = Environment()
    env.is_root = os.geteuid() == 0
    env.has_sudo = common.have("sudo")

    try:
        _detect_os(env)
        _detect_components(env)
        _detect_docker(env)
        # Listeners must be collected *before* role detection. _detect_role
        # asks whether 1514/1515 are open, to recognise a manager whose
        # binaries live outside /var/ossec. With the listener list still
        # empty those two checks silently always answered "no".
        env.listeners = listening_ports()
        _detect_role(env)
        _detect_version(env)
        _detect_deployment(env)
        _detect_cluster(env)
        _count_agents(env)
    except Exception as exc:  # discovery must never abort the run
        env.warnings.append(f"discovery incomplete: {type(exc).__name__}: {exc}")
    return env
