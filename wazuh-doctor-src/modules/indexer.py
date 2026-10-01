"""Indexer: cluster health, shards, disk watermark and JVM heap."""

from __future__ import annotations

import os
import re
from typing import List

from .base import Context, Module
from wdlib.common import Finding, Severity, http_request, read_text, tail_lines
from wdlib.discovery import Component

INDEXER_LOG = "/var/log/wazuh-indexer/wazuh-indexer.log"
BASE_DEFAULT = "/etc/default/wazuh-indexer"

OVERLOAD = (
    r"OutOfMemory",
    r"GC overhead",
    r"circuit_breaking_exception",
    r"unassigned_shards",
    r"flood stage",
)


class IndexerModule(Module):
    name = "indexer"
    title = "Indexer cluster health"
    description = "cluster health, shards, disk watermark and JVM heap"
    requires = (Component.INDEXER,)

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._port(ctx))
        findings.extend(self._cluster(ctx))
        findings.extend(self._shards(ctx))
        findings.extend(self._heap(ctx))
        findings.extend(self._log(ctx))
        return findings

    # -- helpers ----------------------------------------------------------

    def _cred(self, ctx: Context):
        if ctx.config.has_indexer_creds():
            return (ctx.config.get("indexer_user"), ctx.config.get("indexer_password"))
        return None

    def _url(self, ctx: Context, path: str) -> str:
        base = (ctx.config.get("indexer_url") or "https://127.0.0.1:9200").rstrip("/")
        return f"{base}{path}"

    def _get(self, ctx: Context, path: str, timeout: int = 10):
        return http_request(self._url(ctx, path), auth=self._cred(ctx), timeout=timeout, verify=False)

    # -- port -------------------------------------------------------------

    def _port(self, ctx: Context) -> List[Finding]:
        # 9200 is normally bound to IPv4-mapped IPv6 on loopback, so an
        # IPv4-only check reports a false negative. Ask the API directly
        # before declaring it down.
        if ctx.env.listeners_on(9200):
            return []
        probe = self._get(ctx, "/", timeout=8)
        if probe.status is not None:
            return []
        return [
            self.finding(
                Severity.CRITICAL,
                "the indexer HTTP API is not reachable on port 9200",
                "no socket is listening on 9200 and an HTTPS request to the API "
                "failed, so the indexer is down and nothing can be indexed",
                evidence=f"GET {probe.url} -> {probe.error or 'no response'}",
                fix=(
                    "Start the indexer and read why it stopped:\n"
                    "    sudo systemctl start wazuh-indexer\n"
                    "    sudo journalctl -u wazuh-indexer -n 150 --no-pager\n"
                    "    sudo tail -n 150 /var/log/wazuh-indexer/wazuh-indexer.log"
                ),
                verify="curl -k -s -o /dev/null -w '%{http_code}\\n' https://127.0.0.1:9200/",
            )
        ]

    # -- cluster ----------------------------------------------------------

    def _cluster(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        result = self._get(ctx, "/_cluster/health")
        if result.unauthorized:
            if not self._cred(ctx):
                findings.append(
                    self.finding(
                        Severity.INFO,
                        "indexer requires credentials for a full health check",
                        "the indexer rejected an unauthenticated request; supply credentials "
                        "via WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD or the config file "
                        "to enable cluster, shard and heap checks",
                        evidence=f"HTTP {result.status} from {result.url}",
                        fix=(
                            "Create ~/.config/wazuh-doctor/config with:\n"
                            "    indexer_user = admin\n"
                            "    indexer_password = <password>\n"
                            "  or export WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD.\n"
                            "  Never put credentials on the command line."
                        ),
                        verify="curl -k -u admin:**** https://127.0.0.1:9200/_cluster/health",
                    )
                )
            else:
                # Credentials were supplied and rejected. Without this branch
                # the 401 fell through to the "no payload" path and the run
                # reported nothing at all -- the cluster could be red and the
                # operator would never be told.
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        "the indexer rejected the configured credentials",
                        "cluster, shard and heap health could not be read, so an "
                        "unhealthy indexer would go unnoticed; the configured user or "
                        "password is wrong or the account is disabled",
                        evidence=f"HTTP {result.status} from {result.url} using the configured indexer user",
                        fix=(
                            "Correct indexer_user / indexer_password in "
                            "~/.config/wazuh-doctor/config (or the WAZUH_INDEXER_* "
                            "environment variables)."
                        ),
                        verify="curl -k -u <user> **** https://127.0.0.1:9200/_cluster/health",
                    )
                )
            return findings
        if result.status is None:
            return findings

        payload = result.json() or {}
        status = payload.get("status")
        if status == "red":
            findings.append(
                self.finding(
                    Severity.CRITICAL,
                    "indexer cluster health is RED",
                    "at least one primary shard is unassigned, so some indices are "
                    "unavailable and Wazuh cannot index or query all of its data",
                    evidence=result.snippet(),
                    fix=(
                        "Find which shards are unassigned and why:\n"
                        "    curl -k -u admin **** 'https://127.0.0.1:9200/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason'\n"
                        "  A single-node cluster commonly goes red when a replica is "
                        "expected but no second node exists; set replicas to 0 for "
                        "single-node deployments."
                    ),
                    verify="curl -k -u admin **** 'https://127.0.0.1:9200/_cluster/health?pretty'",
                )
            )
        elif status == "yellow":
            findings.append(
                self.finding(
                    Severity.WARNING,
                    "indexer cluster health is YELLOW",
                    "replica shards are unassigned; on a single-node cluster this is "
                    "expected and harmless, but on a multi-node cluster it means a "
                    "node is missing or shards cannot be allocated",
                    evidence=result.snippet(),
                    fix=(
                        "On a single-node deployment, this is normal and can be left "
                        "alone (or replicas set to 0). On a cluster, check node count:\n"
                        "    curl -k -u admin **** 'https://127.0.0.1:9200/_cat/nodes?v'"
                    ),
                    verify="curl -k -u admin **** 'https://127.0.0.1:9200/_cat/nodes?v'",
                )
            )

        # Disk watermark from the same payload.
        disk = payload.get("disk") if isinstance(payload.get("disk"), dict) else None
        if disk and isinstance(disk.get("used_percent"), float):
            used = disk["used_percent"]
            if used >= 90:
                findings.append(
                    self.finding(
                        Severity.CRITICAL,
                        f"indexer disk usage is {used:.1f}%, at or above the high watermark",
                        "once the high watermark is reached the indexer stops allocating "
                        "shards to this node and indexing stalls",
                        evidence=f"used_percent={used}",
                        fix=(
                            "Free space or delete old indices by age (never remove the "
                            "indexer directory by hand):\n"
                            "    curl -k -u admin **** 'https://127.0.0.1:9200/_cat/indices?v&s=store.size:desc'\n"
                            "  Remove aged indices with the indexer's delete API, or "
                            "reduce retention in the indexer ISM policy."
                        ),
                        verify="df -h /var/lib/wazuh-indexer",
                    )
                )
            elif used >= 85:
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        f"indexer disk usage is {used:.1f}%, near the low watermark",
                        "the indexer will soon stop allocating shards to this node",
                        evidence=f"used_percent={used}",
                        fix="Plan to free space or reduce retention before 90%.",
                        verify="df -h /var/lib/wazuh-indexer",
                    )
                )
        return findings

    # -- shards -----------------------------------------------------------

    def _shards(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        result = self._get(ctx, "/_cat/shards?format=json&h=index,shard,prirep,state,unassigned.reason")
        rows = result.json()
        if not isinstance(rows, list):
            return findings

        unassigned_primary = [
            r for r in rows
            if str(r.get("state", "")).upper().startswith("UNASSIGNED")
            and r.get("prirep") == "p"
        ]
        unassigned_any = [r for r in rows if str(r.get("state", "")).upper().startswith("UNASSIGNED")]

        if unassigned_primary:
            sample = "\n".join(
                f"  {r.get('index')} shard {r.get('shard')} ({r.get('prirep')}) "
                f"-> {r.get('unassigned.reason') or 'unknown reason'}"
                for r in unassigned_primary[:10]
            )
            findings.append(
                self.finding(
                    Severity.CRITICAL,
                    f"{len(unassigned_primary)} primary shard(s) unassigned",
                    "primary shards hold the authoritative copy of the data; while they "
                    "are unassigned those indices cannot be read or written",
                    evidence=sample,
                    fix=(
                        "Inspect allocation:\n"
                        "    curl -k -u admin **** 'https://127.0.0.1:9200/_cluster/allocation/explain?pretty'"
                    ),
                    verify="curl -k -u admin **** 'https://127.0.0.1:9200/_cat/shards?v' | grep -i unassigned",
                )
            )
        elif unassigned_any:
            findings.append(
                self.finding(
                    Severity.WARNING,
                    f"{len(unassigned_any)} shard(s) unassigned",
                    "replica shards are not allocated; on a single-node cluster this is "
                    "expected, on a cluster it indicates a missing or unhealthy node",
                    evidence="\n".join(
                        f"  {r.get('index')} shard {r.get('shard')} ({r.get('prirep')})" for r in unassigned_any[:10]
                    ),
                    fix="Confirm node count and health: curl -k -u admin **** 'https://127.0.0.1:9200/_cat/nodes?v'",
                    verify="curl -k -u admin **** 'https://127.0.0.1:9200/_cluster/health?level=shards&pretty'",
                )
            )
        return findings

    # -- heap -------------------------------------------------------------

    def _heap(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        result = self._get(ctx, "/_cat/nodes?format=json&h=name,heap.percent,heap.current,heap.max,ram.percent")
        rows = result.json()
        if isinstance(rows, list) and rows:
            hot = []
            for row in rows:
                try:
                    percent = int(str(row.get("heap.percent", "")).strip())
                except ValueError:
                    continue
                if percent > 85:
                    hot.append((row.get("name"), percent, row.get("heap.max")))
            if hot:
                findings.append(
                    self.finding(
                        Severity.WARNING,
                        f"JVM heap above 85% on {len(hot)} node(s)",
                        "the indexer is close to heap exhaustion; sustained pressure "
                        "leads to long GC pauses, circuit breakers and failed queries",
                        evidence="\n".join(f"  {name}: {percent}% of {mx}" for name, percent, mx in hot),
                        fix=(
                            "Raise the heap (the standard guidance is 50% of RAM, never "
                            "above ~31GB) in /etc/default/wazuh-indexer:\n"
                            "    OPENSEARCH_JAVA_OPTS=-Xms4g -Xmx4g\n"
                            "  then: sudo systemctl restart wazuh-indexer"
                        ),
                        verify="curl -k -u admin **** 'https://127.0.0.1:9200/_cat/nodes?v&h=name,heap.percent'",
                    )
                )

        # Compare the configured heap against physical RAM.
        defaults = read_text(BASE_DEFAULT)
        meminfo = read_text("/proc/meminfo") or ""
        if defaults and meminfo:
            match = re.search(r"-Xmx(\d+)([gGmM])", defaults)
            total_match = re.search(r"MemTotal:\s+(\d+)\s+kB", meminfo)
            if match and total_match:
                size, unit = int(match.group(1)), match.group(2).lower()
                heap_gb = size if unit == "g" else size / 1024.0
                total_gb = int(total_match.group(1)) / 1024.0 / 1024.0
                if total_gb and heap_gb > total_gb * 0.5:
                    findings.append(
                        self.finding(
                            Severity.WARNING,
                            f"configured indexer heap ({heap_gb:.1f}GB) exceeds half of RAM ({total_gb:.1f}GB)",
                            "the JVM is sized above the recommended 50% of physical memory, "
                            "which starves the OS page cache and can trigger the OOM killer",
                            evidence=f"configured -Xmx{match.group(1)}{match.group(2)} against MemTotal {total_gb:.1f}GB",
                            fix=(
                                f"Lower the heap in {BASE_DEFAULT} to about "
                                f"{total_gb / 2:.0f}g and restart wazuh-indexer."
                            ),
                            verify="grep OPENSEARCH_JAVA_OPTS /etc/default/wazuh-indexer",
                        )
                    )
        return findings

    # -- log --------------------------------------------------------------

    def _log(self, ctx: Context) -> List[Finding]:
        lines = tail_lines(INDEXER_LOG, 500)
        if not lines:
            return []
        hits = [
            ln for ln in lines
            if any(re.search(p, ln, re.IGNORECASE) for p in OVERLOAD)
        ]
        if not hits:
            return []
        return [
            self.finding(
                Severity.WARNING,
                f"{len(hits)} indexer log line(s) indicating pressure or shard problems",
                "the indexer log shows memory or shard allocation trouble",
                evidence="\n".join(hits[-12:]),
                fix=(
                    "Review heap and disk headroom:\n"
                    "    sudo grep -iE 'OutOfMemory|circuit_breaking|flood' "
                    f"{INDEXER_LOG} | tail -30"
                ),
                verify="sudo tail -n 100 /var/log/wazuh-indexer/wazuh-indexer.log",
            )
        ]
