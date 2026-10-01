"""
wazuh-doctor :: common primitives

Shared building blocks: the severity model, the finding record, safe
command execution with hard timeouts, secret masking, and credential
loading.

Nothing in this module mutates the host. Every helper degrades to a
neutral result (None / empty / rc=127) instead of raising, so a module
can never take down the whole run.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

DEFAULT_TIMEOUT = 10
"""Seconds. Every external command gets one; nothing is allowed to hang."""


# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------


class Severity(IntEnum):
    """Ordered so sorting/ranking is just a numeric compare."""

    INFO = 0
    WARNING = 1
    CRITICAL = 2

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            return cls.INFO


# --------------------------------------------------------------------------
# Finding -- the single record shape every module emits
# --------------------------------------------------------------------------


@dataclass
class Finding:
    """One diagnosed problem.

    The fixed shape the report renders is:

        Issue -> Root Cause -> Evidence -> Fix -> Verify

    ``evidence`` is masked in ``__post_init__`` so raw command output or a
    raw log line can be passed in without leaking a credential into the
    terminal or the saved report.
    """

    module: str
    severity: Severity
    issue: str
    root_cause: str
    evidence: str = ""
    fix: str = ""
    verify: str = ""
    fixable: bool = False
    fix_action: Any = None
    """An optional wdlib.fixer.Fix. Kept out of to_dict() and the report;
    it is how an automatable repair is carried alongside its finding."""

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity.parse(self.severity)
        self.evidence = mask(self.evidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "severity": self.severity.label,
            "issue": self.issue,
            "root_cause": self.root_cause,
            "evidence": self.evidence,
            "fix": self.fix,
            "verify": self.verify,
            "fixable": self.fixable,
        }


# --------------------------------------------------------------------------
# Secret masking
# --------------------------------------------------------------------------

_SECRET_PATTERNS: Sequence[tuple] = (
    # password=..., token: ..., api_key = ..., "authorization": ...
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)"
            r"\b(\s*[:=]\s*)(\S+)"
        ),
        r"\1\2***MASKED***",
    ),
    # Authorization: Bearer eyJ...
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer ***MASKED***"),
    # https://user:password@host
    (
        re.compile(r"(?i)\b(https?://[^:/\s@]+:)([^@/\s]+)(@)"),
        r"\1***MASKED***\3",
    ),
    # A bare JWT anywhere in the text.
    (re.compile(r"\beyJ[A-Za-z0-9._\-]{10,}"), "***MASKED-JWT***"),
    # Wazuh/OpenSearch basic-auth style user:pass in JSON or YAML.
    (
        re.compile(r"(?i)(\"?(?:username|user)\"?\s*[:=]\s*\"?)([^\",\s]+)"),
        r"\1***MASKED-USER***",
    ),
)

_REDACT_KEYS = frozenset(
    {
        "api_password",
        "api_user",
        "indexer_password",
        "indexer_user",
        "dashboard_password",
        "dashboard_user",
        "password",
        "token",
    }
)


def mask(text: Optional[str]) -> str:
    """Redact anything that looks like a credential.

    Applied to every piece of evidence before it is stored in a Finding,
    so a secret cannot reach the terminal or the report file by accident.
    """
    if not text:
        return ""
    out = str(text)
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    return out


# --------------------------------------------------------------------------
# Command execution
# --------------------------------------------------------------------------


@dataclass
class CommandResult:
    """Outcome of one external command. Never raises."""

    cmd: str
    rc: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """Combined output, masked. Use this for evidence."""
        return mask((self.stdout + "\n" + self.stderr).strip())

    @property
    def missing(self) -> bool:
        """True when the binary simply is not installed."""
        return self.rc == 127

    @property
    def denied(self) -> bool:
        """True when we lacked privilege to run it.

        Covers both a plain permission denial and sudo refusing to run
        non-interactively (``sudo -n`` on a host that wants a password).
        Without the sudo cases this would be misread as "the service is
        down" rather than "re-run this as root".
        """
        blob = (self.stderr + self.stdout).lower()
        if self.rc in (1, 126) and (
            "permission denied" in blob
            or "must be root" in blob
            or "are you root" in blob
            or "operation not permitted" in blob
        ):
            return True
        return self.rc in (1, 126, 127) and (
            "a password is required" in blob
            or "a terminal is required" in blob
            or "no tty present" in blob
            or "may not run sudo" in blob
            or "not allowed to execute" in blob
        )

    def first_line(self, default: str = "") -> str:
        for line in self.output.splitlines():
            if line.strip():
                return line.strip()
        return default


def run(
    cmd: Any,
    timeout: int = DEFAULT_TIMEOUT,
    use_sudo: bool = False,
    stdin: Optional[str] = None,
) -> CommandResult:
    """Run a command read-only, with a hard timeout.

    ``cmd`` may be a list or a shell-ish string. A string is split with
    shlex rather than handed to a shell, so nothing here can be tricked
    into evaluating a metacharacter.
    """
    if isinstance(cmd, str):
        try:
            argv: List[str] = shlex.split(cmd)
        except ValueError:
            argv = cmd.split()
    else:
        argv = [str(c) for c in cmd]

    if not argv:
        return CommandResult("", 127, "", "empty command")

    if use_sudo and os.geteuid() != 0:
        argv = ["sudo", "-n"] + argv

    printable = " ".join(argv)
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        return CommandResult(printable, proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return CommandResult(printable, 124, out, (err + f"\n[timed out after {timeout}s]").strip(), timed_out=True)
    except FileNotFoundError:
        return CommandResult(printable, 127, "", f"command not found: {argv[0]}")
    except PermissionError:
        return CommandResult(printable, 126, "", f"permission denied: {argv[0]}")
    except Exception as exc:  # never let a helper kill the run
        return CommandResult(printable, 1, "", f"{type(exc).__name__}: {exc}")


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def have(name: str) -> bool:
    return shutil.which(name) is not None


_UNIT_CACHE: Dict[str, bool] = {}


def systemd_unit_exists(unit: str) -> bool:
    """True when systemd actually knows this unit.

    ``systemctl is-active`` answers "inactive" for a unit that does not
    exist at all, which is indistinguishable from a stopped service. That
    difference matters a great deal here: reporting "the service is not
    active" for a unit that was never installed turns a host that simply
    lacks that package into a false CRITICAL.

    Cached, because modules ask about the same unit more than once.
    """
    if unit in _UNIT_CACHE:
        return _UNIT_CACHE[unit]
    # `systemctl cat` exits non-zero for an unknown unit and is cheap.
    result = run(["systemctl", "cat", unit], timeout=8)
    exists = result.ok
    _UNIT_CACHE[unit] = exists
    return exists


# --------------------------------------------------------------------------
# Filesystem helpers
# --------------------------------------------------------------------------


def read_text(path: str, max_bytes: int = 512_000) -> Optional[str]:
    """Read a file, or return None if absent/unreadable.

    Returns None (rather than raising) for the common case of a Wazuh
    config owned by root and mode 0640, which is exactly what an
    unprivileged run sees.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read(max_bytes)
    except (OSError, IOError):
        return None
    return raw.decode("utf-8", "replace")


def path_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except OSError:
        return False


def path_is_dir(path: str) -> bool:
    try:
        return os.path.isdir(path)
    except OSError:
        return False


def unreadable_because_unprivileged(path: str) -> bool:
    """True when a root-only file exists but we cannot read it.

    Distinguishes EACCES from ENOENT so the report can say
    "re-run as root" instead of the misleading "not installed".
    """
    if os.geteuid() == 0:
        return False
    if not path_exists(path):
        return False
    return not os.access(path, os.R_OK)


def path_state(path: str) -> str:
    """Classify ``path`` as ``"present"``, ``"missing"`` or ``"unknown"``.

    ``os.path.exists`` answers False both for a file that is not there and
    for one we are not allowed to look at. The Wazuh tree makes that
    difference load-bearing: ``/var/ossec`` is 0750 root:wazuh, so on a
    healthy manager an unprivileged run sees
    ``/var/ossec/etc/ossec.conf`` as ENOENT. A module that trusts
    ``exists()`` then reports "the configuration is missing" -- sending an
    operator to rebuild a file that was never absent.

    The walk upwards is what separates the two cases. The first ancestor
    that exists but that we cannot traverse is the boundary of what we are
    entitled to know; above it, absence is real.

    Root can traverse everything, so for root the answer is always
    present-or-missing.
    """
    try:
        if os.path.exists(path):
            return "present"
    except OSError:
        pass
    if os.geteuid() == 0:
        return "missing"

    parent = os.path.dirname(os.path.abspath(path))
    while True:
        grandparent = os.path.dirname(parent)
        if grandparent == parent:  # reached "/"
            return "missing"
        try:
            if os.path.exists(parent):
                # An entry we cannot search hides everything beneath it.
                return "missing" if os.access(parent, os.R_OK | os.X_OK) else "unknown"
        except OSError:
            return "unknown"
        parent = grandparent


def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}PB"


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

CONFIG_PATHS: Sequence[str] = (
    os.path.expanduser("~/.config/wazuh-doctor/config"),
    "/etc/wazuh-doctor/config",
)

_ENV_MAP: Dict[str, str] = {
    "api_user": "WAZUH_API_USER",
    "api_password": "WAZUH_API_PASSWORD",
    "indexer_user": "WAZUH_INDEXER_USER",
    "indexer_password": "WAZUH_INDEXER_PASSWORD",
    "dashboard_user": "WAZUH_DASHBOARD_USER",
    "dashboard_password": "WAZUH_DASHBOARD_PASSWORD",
    "api_url": "WAZUH_API_URL",
    "indexer_url": "WAZUH_INDEXER_URL",
    "dashboard_url": "WAZUH_DASHBOARD_URL",
}

_DEFAULTS: Dict[str, str] = {
    "api_url": "https://127.0.0.1:55000",
    "indexer_url": "https://127.0.0.1:9200",
    "dashboard_url": "https://127.0.0.1:443",
}


class Config:
    """Credential store: config file first, environment overrides.

    Credentials are never hardcoded and never printed -- ``__repr__`` and
    ``__str__`` are masked so they cannot leak through a traceback, a
    debug print, or a log line.
    """

    def __init__(self, values: Optional[Dict[str, str]] = None) -> None:
        self._values: Dict[str, str] = dict(_DEFAULTS)
        if values:
            self._values.update({k: v for k, v in values.items() if v})

    @classmethod
    def load(cls, extra_paths: Iterable[str] = ()) -> "Config":
        values: Dict[str, str] = {}
        # Lowest priority first; later files win.
        for path in list(CONFIG_PATHS) + list(extra_paths):
            content = read_text(path)
            if not content:
                continue
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("'\"")
                if key and val:
                    values[key] = val
        # Environment wins over any file.
        for key, env_name in _ENV_MAP.items():
            env_val = os.environ.get(env_name)
            if env_val:
                values[key] = env_val
        return cls(values)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._values.get(key, default)

    def has(self, key: str) -> bool:
        return bool(self._values.get(key))

    def has_api_creds(self) -> bool:
        return self.has("api_user") and self.has("api_password")

    def has_indexer_creds(self) -> bool:
        return self.has("indexer_user") and self.has("indexer_password")

    def describe_sources(self) -> str:
        found = [p for p in CONFIG_PATHS if path_exists(p)]
        envs = [e for e in _ENV_MAP.values() if os.environ.get(e)]
        bits = []
        if found:
            bits.append("file: " + ", ".join(found))
        if envs:
            bits.append("env: " + ", ".join(envs))
        return "; ".join(bits) if bits else "none"

    def __repr__(self) -> str:
        return f"Config({self._masked_view()})"

    __str__ = __repr__

    def _masked_view(self) -> str:
        parts = []
        for key in sorted(self._values):
            if key in _REDACT_KEYS:
                parts.append(f"{key}={'set' if self._values[key] else 'unset'}")
            else:
                parts.append(f"{key}={self._values[key]}")
        return ", ".join(parts)


# --------------------------------------------------------------------------
# Log tailing
# --------------------------------------------------------------------------


_TAIL_INITIAL_WINDOW = 256 * 1024
_TAIL_MAX_WINDOW = 64 * 1024 * 1024


def tail_lines(path: str, count: int = 200) -> List[str]:
    """Return up to ``count`` trailing lines, or [] if unreadable.

    This reads from the *end* of the file. The obvious implementation --
    ``read_text(path)`` and then take the last ``count`` lines -- reads the
    first ``max_bytes`` of the file and returns the last lines *of that
    prefix*. On any log bigger than the cap, which ``ossec.log`` passes
    quickly, that hands back lines from hours or days ago while every caller
    labels them as the deployment's current state: the manager module
    announces "N error line(s) in ossec.log" about errors that have long
    since stopped.

    The window is grown until ``count`` lines are available, so a log of
    very long lines still works, and capped so a multi-gigabyte log cannot
    be read into memory in one go.
    """
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size == 0:
                return []
            window = _TAIL_INITIAL_WINDOW
            while True:
                start = max(0, size - window)
                handle.seek(start)
                chunk = handle.read(size - start)
                if start > 0:
                    # The window probably opened mid-line. Drop that partial
                    # line rather than reporting half of one as evidence.
                    newline = chunk.find(b"\n")
                    if newline != -1:
                        chunk = chunk[newline + 1 :]
                lines = chunk.decode("utf-8", "replace").splitlines()
                if len(lines) >= count or start == 0 or window >= _TAIL_MAX_WINDOW:
                    return lines[-count:] if count > 0 else []
                window = min(window * 4, _TAIL_MAX_WINDOW)
    except (OSError, IOError):
        return []


def grep(lines: Iterable[str], pattern: str, flags: int = re.IGNORECASE) -> List[str]:
    rx = re.compile(pattern, flags)
    return [ln for ln in lines if rx.search(ln)]


# --------------------------------------------------------------------------
# HTTPS
# --------------------------------------------------------------------------


@dataclass
class HttpResult:
    """Outcome of one HTTP request. Never raises."""

    url: str
    status: Optional[int] = None
    body: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def unauthorized(self) -> bool:
        return self.status in (401, 403)

    @property
    def refused(self) -> bool:
        return self.status is None and (
            "refused" in self.error.lower() or "connect" in self.error.lower()
        )

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except Exception:
            return None

    def snippet(self, limit: int = 600) -> str:
        text = mask(self.body or self.error)
        return text[:limit]


def http_request(
    url: str,
    method: str = "GET",
    auth: Optional[Tuple[str, str]] = None,
    timeout: int = 10,
    verify: bool = False,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
) -> HttpResult:
    """Minimal HTTP client used for indexer / API / dashboard probes.

    Credentials are passed as an Authorization header built in-process.
    They are never placed on a command line, so they cannot leak into a
    Finding's evidence via a rendered command string -- which is exactly
    what happens if you shell out to ``curl -u user:pass``.
    """
    request_headers: Dict[str, str] = dict(headers or {})
    if auth:
        user, password = auth
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        request_headers["Authorization"] = f"Basic {token}"

    context = None
    if url.lower().startswith("https"):
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    try:
        request = urllib.request.Request(
            url, data=body, headers=request_headers, method=method.upper()
        )
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read(1_000_000)
            return HttpResult(url, response.status, raw.decode("utf-8", "replace"), "")
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(200_000)
        except Exception:
            raw = b""
        return HttpResult(url, exc.code, raw.decode("utf-8", "replace"), str(exc.reason))
    except urllib.error.URLError as exc:
        return HttpResult(url, None, "", str(exc.reason))
    except Exception as exc:
        return HttpResult(url, None, "", f"{type(exc).__name__}: {exc}")
