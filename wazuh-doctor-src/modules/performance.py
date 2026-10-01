"""Performance: analysisd queue pressure, event backlog, disk and memory."""

from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from .base import Context, Module
from wdlib.common import Finding, Severity, human_bytes, read_text, tail_lines
from wdlib.discovery import CONTROL, Component

OSSEC_LOG = "/var/ossec/logs/ossec.log"

# Queues whose growth indicates a consumer that cannot keep up.
QUEUE_DIRS = (
    "/var/ossec/queue/alerts",
    "/var/ossec/queue/events",
    "/var/ossec/queue/archive",
)

OVERLOAD_SIGNATURES = (
    (r"queue is full", "an internal queue filled up; events are being dropped"),
    (r"Analysis queue is full", "the analysis queue filled up; events are being dropped"),
    (r"dropping events", "events are being dropped because a queue overflowed"),
    (r"Too many events", "the manager is receiving more events than it can process"),
    (r"events dropped", "events were discarded"),
    (r"Unable to process", "analysisd could not process an incoming event"),
)

# A queue past this size is not keeping up on a normal deployment.
LARGE_QUEUE_BYTES = 1024 * 1024 * 1024  # 1GB
HUGE_QUEUE_BYTES = 5 * 1024 * 1024 * 1024  # 5GB


class PerformanceModule(Module):
    name = "performance"
    title = "Performance and throughput"
    description = "analysisd queue full/drops, event backlog, disk and memory pressure"
    requires = (Component.MANAGER,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._queues(ctx))
        findings.extend(self._drops(ctx))
        findings.extend(self._disk(ctx))
        findings.extend(self._memory(ctx))
        findings.extend(self._load(ctx))
        return findings

    # -- queues -----------------------------------------------------------

    def _queues(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        for directory in QUEUE_DIRS:
            if not os.path.isdir(directory):
                continue
            size, count = self._size_of(directory)
            if count == 0:
                continue
            if size >= HUGE_QUEUE_BYTES:
                severity = Severity.CRITICAL
            elif size >= LARGE_QUEUE_BYTES:
                severity = Severity.WARNING
            else:
                continue
            findings.append(
                self.finding(
                    severity,
                    f"queue {os.path.basename(directory)} is backed up ({human_bytes(size)})",
                    "events are accumulating faster than they are consumed, so the "
                    "manager is falling behind and will begin dropping events",
                    evidence=f"{directory}: {count} file(s), {human_bytes(size)}",
                    fix=(
                        "Identify the bottleneck before clearing anything. Do NOT "
                        "delete queue contents by hand while the manager runs:\n"
                        "    sudo /var/ossec/bin/wazuh-control status\n"
                        "    sudo grep -iE 'queue is full|dropping' "
                        "/var/ossec/logs/ossec.log | tail -20\n"
                        "  Typical causes: indexer unreachable (filebeat backed up), "
                        "a slow custom rule/decoder, or too many agents for this host."
                    ),
                    verify="du -sh /var/ossec/queue/*",
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

    # -- drops ------------------------------------------------------------

    def _drops(self, ctx: Context) -> List[Finding]:
        lines = tail_lines(OSSEC_LOG, 1000)
        if not lines:
            return []

        matched: List[str] = []
        reasons: List[str] = []
        total = 0
        for pattern, reason in OVERLOAD_SIGNATURES:
            hits = [ln for ln in lines if re.search(pattern, ln, re.IGNORECASE)]
            if hits:
                total += len(hits)
                matched.extend(hits[-4:])
                reasons.append(f"{pattern} ({len(hits)}x): {reason}")

        if not matched:
            return []

        # A single line can be one transient burst at startup; a sustained
        # pattern means the manager is genuinely shedding events. Calling
        # every first match CRITICAL trained the reader to ignore it.
        if total >= 10:
            severity = Severity.CRITICAL
            cause = (
                "ossec.log shows repeated queue saturation, so the manager is "
                "discarding events and detections are being missed"
            )
        else:
            severity = Severity.WARNING
            cause = (
                f"ossec.log shows {total} queue-saturation line(s). An isolated "
                "occurrence is usually a transient burst that the manager recovered "
                "from, but any recurrence means events were dropped and detections missed"
            )

        return [
            self.finding(
                severity,
                f"queue saturation logged {total} time(s) in ossec.log",
                cause,
                evidence="\n".join(reasons[:4]) + "\n--- sample lines ---\n" + "\n".join(matched[:8]),
                fix=(
                    "Reduce ingest pressure or raise capacity:\n"
                    "    sudo grep -icE 'queue is full|dropping' /var/ossec/logs/ossec.log\n"
                    "  Check the indexer/filebeat path first, then consider tuning "
                    "<analysisd> queue_size and the syscheck/logcollector frequencies."
                ),
                verify="sudo grep -iE 'queue is full|dropping events' /var/ossec/logs/ossec.log | tail",
            )
        ]

    # -- disk -------------------------------------------------------------

    def _disk(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        paths = ["/var/ossec", "/var/lib/wazuh-indexer", "/var"]
        seen: set = set()
        for path in paths:
            if not os.path.isdir(path):
                continue
            result = ctx.run(["df", "-P", path], timeout=8)
            if not result.ok:
                continue
            device = None
            percent = None
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    device = parts[0]
                    try:
                        percent = int(parts[4].rstrip("%"))
                    except ValueError:
                        continue
            if device is None or percent is None or device in seen:
                continue
            seen.add(device)

            if percent >= 95:
                severity = Severity.CRITICAL
            elif percent >= 85:
                severity = Severity.WARNING
            else:
                continue

            findings.append(
                self.finding(
                    severity,
                    f"filesystem {device} holding {path} is {percent}% full",
                    "a full disk stops log writing, index allocation and rule updates; "
                    "Wazuh behaviour becomes unreliable well before 100%",
                    evidence="\n".join(result.stdout.splitlines()[:4]),
                    fix=(
                        "Free space without deleting agent keys, logs or index data "
                        "outright — rotate or archive instead:\n"
                        f"    sudo du -xh --max-depth=2 {path} | sort -rh | head -20"
                    ),
                    verify=f"df -h {path}",
                )
            )
        return findings

    # -- memory -----------------------------------------------------------

    def _memory(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        content = read_text("/proc/meminfo")
        if content:
            values = {}
            for line in content.splitlines():
                key, _, rest = line.partition(":")
                try:
                    values[key.strip()] = int(rest.strip().split()[0])
                except (IndexError, ValueError):
                    continue
            total = values.get("MemTotal", 0)
            available = values.get("MemAvailable", 0)
            if total and available < total * 0.10:
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        f"only {available * 100 // total}% of RAM is available",
                        "the manager is under memory pressure; allocation failures "
                        "cause dropped events and can trigger the OOM killer",
                        evidence=f"MemTotal={total} kB, MemAvailable={available} kB",
                        fix="Find the consumer and reduce the indexer heap if needed.",
                        verify="free -h",
                    )
                )

        swaps = read_text("/proc/swaps") or ""
        for line in swaps.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                try:
                    size, used = int(parts[2]), int(parts[3])
                except ValueError:
                    continue
                if size and used > size * 0.5:
                    findings.append(
                        self.finding(
                            Severity.WARNING,
                            f"swap is {used * 100 // size}% used",
                            "active swapping means the working set does not fit in RAM; "
                            "throughput drops sharply as the manager pages",
                            evidence=line.strip(),
                            fix="Reduce memory pressure; swapping during event bursts causes drop-outs.",
                            verify="cat /proc/swaps; free -h",
                        )
                    )
        return findings

    def _load(self, ctx: Context) -> List[Finding]:
        content = read_text("/proc/loadavg")
        if not content:
            return []
        try:
            load1 = float(content.split()[0])
        except (IndexError, ValueError):
            return []
        cores = os.cpu_count() or 1
        if load1 > cores * 2:
            return [
                self.finding(
                    Severity.WARNING,
                    f"1-minute load {load1:.2f} exceeds twice the {cores} core(s)",
                    "the host is CPU-saturated, so event processing lags and queues build up",
                    evidence=f"/proc/loadavg: {content.strip()}",
                    fix="Identify the hot process and consider reducing scan frequency or shard count.",
                    verify="uptime; top -b -n1 | head -15",
                )
            ]
        return []
