# wazuh-doctor

One command that diagnoses a complete Wazuh deployment and reports every
problem it finds with its **root cause, evidence and the fix** — and then
the command to verify the fix worked.

Built for **Wazuh 4.x** on Ubuntu/Debian and RHEL/CentOS, across
all-in-one, distributed, Docker and agent-only layouts.

```bash
sudo wazuh-doctor --all
```

Read-only by default. It changes nothing unless you pass `--fix`, and then
only after you approve each individual repair.

---

## Contents

- [What it is](#what-it-is)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Exit codes](#exit-codes)
- [The output](#the-output)
- [Reports](#reports)
- [Check reference](#check-reference)
- [Credentials](#credentials)
- [Safety model](#safety-model)
- [Running unprivileged](#running-unprivileged)
- [How it works](#how-it-works)
- [Design rules](#design-rules)
- [Known limitations](#known-limitations)
- [Maintainer notes](#maintainer-notes)
- [Troubleshooting the tool](#troubleshooting-the-tool)
- [Uninstall](#uninstall)

---

## What it is

Wazuh failures are usually not where they appear. An agent that will not
connect is as likely to be a firewall rule as a wrong key; an empty
dashboard is as likely to be a stopped filebeat as a broken manager; a
"certificate problem" is often an expired CA *or* a file the operator is
not allowed to read.

wazuh-doctor exists to shorten that hunt. It looks at every layer of the
deployment — ports, daemons, logs, configuration, certificates, indexer
health, version consistency — and for each problem states:

| Field | Meaning |
| --- | --- |
| **Issue** | What is wrong, in one line |
| **Root cause** | Why it produces the symptom you are seeing |
| **Evidence** | The raw command output, log line or HTTP response behind the claim |
| **Fix** | Copy-pasteable commands to repair it |
| **Verify** | How to confirm the repair worked |

**What it covers, by layer** — 19 check areas, each of which can be run on
its own with `--module`:

| Layer | Checks |
| --- | --- |
| Reachability | ports 1514/1515/55000/9200/9300/443 listening, host firewall rules, DNS, agent→manager TCP |
| Processes | `wazuh-control status` daemons, agent service, filebeat, dashboard, indexer |
| Configuration | `ossec.conf` XML + `analysisd -t`, custom rules and decoders, FIM, cluster, shared `agent.conf` |
| Data path | indexer cluster health, shards, watermark, JVM heap; filebeat config + delivery; dashboard index patterns; API auth |
| Security | sensitive file modes, private key material, ports exposed off-box, default credentials |
| Consistency | manager/indexer/dashboard version drift, certificate expiry, chain validity, SAN names |
| Resources | queue backlog, event drops, disk, RAM, swap, load |

Design commitments, in priority order:

1. **Never report a false positive.** A missed problem costs you one
   debugging session; a wrong CRITICAL on a healthy host costs you trust
   in the tool and sends you chasing a fault that does not exist. See
   [Design rules](#design-rules).
2. **Never change anything without being asked.** Read-only by default.
3. **Never print a secret.** Passwords, tokens and JWTs are masked before
   they can reach a terminal, a log or a report.
4. **Always say what was *not* checked**, so silence is never mistaken for
   a clean bill of health.

---

## Requirements

| | |
| --- | --- |
| OS | Ubuntu/Debian or RHEL/CentOS (also works on anything with Python 3 and `/proc`) |
| Python | **3.8 or newer** |
| Packages | **none** — Python standard library only, no `pip install` |
| Privileges | root for a complete scan; works unprivileged with reduced coverage |
| Wazuh | 4.x (manager, agent, indexer, filebeat, dashboard — any subset) |

External binaries are used when present and skipped politely when not:
`systemctl`, `ss`, `df`, `du`, `ufw`/`firewall-cmd`/`iptables`, `dpkg-query`
or `rpm`, `filebeat`, and the Wazuh binaries in `/var/ossec/bin`. Nothing
is required for the tool to start.

---

## Install

```bash
sudo cp -r wazuh-doctor-src /opt/wazuh-doctor
sudo chmod +x /opt/wazuh-doctor/wazuh-doctor
sudo ln -sf /opt/wazuh-doctor/wazuh-doctor /usr/local/bin/wazuh-doctor
```

Verify:

```bash
wazuh-doctor --version
wazuh-doctor --list-modules
```

### Upgrading

`/opt/wazuh-doctor` is a copy, not a link. After changing the source tree,
copy it across again:

```bash
sudo cp -r /path/to/wazuh-doctor-src/. /opt/wazuh-doctor/
sudo chmod +x /opt/wazuh-doctor/wazuh-doctor
```

Do not use `cp -r src /opt/wazuh-doctor` when the destination already
exists — that nests a second copy at `/opt/wazuh-doctor/wazuh-doctor-src`
and the launcher keeps running the old code. The trailing `/.` in the
command above avoids this. Nothing outside `/opt/wazuh-doctor` needs to
change: the tool keeps no state, no database and no daemon.

### A different interpreter

The launcher uses `python3` unless told otherwise:

```bash
sudo WAZUH_DOCTOR_PYTHON=/usr/bin/python3.11 wazuh-doctor --all
```

---

## Quick start

```bash
# 1. What is on this host, and which checks will run?
wazuh-doctor --list-modules

# 2. Full read-only diagnosis (root, so nothing is skipped)
sudo wazuh-doctor --all

# 3. Read the report it wrote
less /var/log/wazuh-doctor/report-*.md
```

If you are chasing one specific symptom:

```bash
# An agent will not enrol
sudo wazuh-doctor -m authd_enrollment -m remoted_connectivity

# The dashboard is empty or stale
sudo wazuh-doctor -m filebeat -m indexer -m dashboard -m api

# Everything is slow, or alerts are missing
sudo wazuh-doctor -m performance -m manager

# Certificate expiry sweep
sudo wazuh-doctor -m certificate
```

---

## Usage

```
wazuh-doctor [options]
```

### Selecting checks

| Option | Meaning |
| --- | --- |
| *(none)* | Run every check area that applies to this host. Read-only. |
| `--all` | Same as above, stated explicitly. Useful in scripts. |
| `--module NAME`, `-m NAME` | Run only this area. Repeatable. An unknown name exits **64** and lists the valid ones. A known name that does not apply to this host is run anyway, with a note on stderr. |
| `--list-modules` | Print every check area, whether it would run here, and why not. Also lists any area that failed to load. |

### Repair

| Option | Meaning |
| --- | --- |
| `--fix` | Offer the automatable repairs found. **One confirmation per fix.** Nothing is offered unless this is given. |
| `--fix --dry-run` | Show each proposed repair and change nothing. Does not prompt. |
| `--yes` | Auto-confirm every fix prompt. **Dangerous** — it exists for rebuilding lab hosts, not for production. |

See [Safety model](#safety-model) for what a fix is allowed to do.

### Output

| Option | Meaning |
| --- | --- |
| `--report` | Write the markdown report. **On by default.** |
| `--no-report` | Terminal output only. |
| `--report-dir DIR` | Where to write reports. Default `/var/log/wazuh-doctor`. |
| `--json` | Emit findings as JSON on stdout instead of the terminal view. |
| `--quiet`, `-q` | Print only CRITICAL findings. The counts and exit code still reflect *everything* found. |
| `--no-color` | Disable ANSI colour. `NO_COLOR=1` in the environment does the same. |
| `--verbose`, `-v` | Include skip reasons and full tracebacks for a crashed check area. |

### Other

| Option | Meaning |
| --- | --- |
| `--watch [SECONDS]` | Re-scan on an interval (default 60s) until Ctrl-C. Prints only what changed: `+ new` and `- resolved` findings. |
| `--config FILE` | Read an extra credentials file. Repeatable; later files win. |
| `--timeout SECONDS` | Per-command timeout. Default 10. |
| `--version` | Print the version and exit. |

### Examples

```bash
wazuh-doctor                            # every applicable check, read-only
wazuh-doctor --module indexer           # one area
wazuh-doctor -m api -m network          # several areas
wazuh-doctor --all --no-color           # plain output for logs
wazuh-doctor --all --json | jq .        # machine-readable
wazuh-doctor --watch 60                 # watch for changes
sudo wazuh-doctor --all                 # full scan, including root-only files
sudo wazuh-doctor --all --quiet         # CRITICAL only
sudo wazuh-doctor --all --fix --dry-run # show repairs, change nothing
sudo wazuh-doctor --all --fix           # offer repairs, one prompt each
```

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No issues found |
| `1` | Warnings found |
| `2` | Critical findings |
| `3` | Not a Wazuh host — nothing to diagnose |
| `64` | Bad usage (an unknown `--module` name) |

These are meant for cron and CI, so `--quiet` deliberately does **not**
change them: hiding the warning lines must never turn a failing host into
an exit `0`.

```bash
sudo wazuh-doctor --all --no-report --quiet || echo "wazuh needs attention"
```

Code `64` is separate from `2` on purpose: a typo in a job's module list
should not be indistinguishable from a critical health failure.

---

## The output

```
========================================================================
  WAZUH DOCTOR
========================================================================
  Host           : wazuh-01
  OS             : Ubuntu 22.04.4 LTS  (5.15.0-105-generic)
  Wazuh          : 4.14.7  (via wazuh-control)
  Deployment     : all-in-one
  Components     : dashboard, filebeat, indexer, manager
  Privilege      : root
  Agents         : 12
  Scanned in     : 4.3s

   1 critical    2 warning    1 info
========================================================================

[WARNING]  filebeat: 3 filebeat log line(s) about delivery failures
    Root cause : filebeat is logging connection or TLS errors while shipping
                 to the indexer
    Evidence   : 2024-05-02T09:14:02Z WARN [publisher_pipeline_output]
                 failed to connect: dial tcp 127.0.0.1:9200: connect:
                 connection refused
    Fix        : Confirm the indexer is reachable and the CA is valid:
                     sudo grep -E 'ERROR|WARN' /var/log/filebeat/filebeat | tail -30
                     sudo filebeat test output -c /etc/filebeat/filebeat.yml
    Verify     : sudo filebeat test output -c /etc/filebeat/filebeat.yml

========================================================================
  Skipped modules: windows_agent
  Modules run    : api, certificate, config, dashboard, filebeat, ...
  Report         : /var/log/wazuh-doctor/report-20240502-091402.md
========================================================================
```

Every finding has the same five fields, so the report is skimmable and
each claim is checkable against its own evidence.

The frame is laid out on a single 19-column gutter — header, findings and
footer all line up — and long values wrap under their own label rather
than breaking the column. A multi-line `Fix` keeps its command block
indented inside the finding, where it can be copied from as one piece.

---

## Reports

Each run (unless `--no-report`) writes a standalone markdown document:

```
/var/log/wazuh-doctor/report-20240502-091402.md
```

It contains the host summary, a severity table, any scan limitations, then
every finding grouped CRITICAL → WARNING → INFO, with the same five fields.
The file is mode `0640`.

If `/var/log` is not writable — the usual case for an unprivileged run —
the report falls back to `~/.local/share/wazuh-doctor/` rather than being
lost. `--report-dir DIR` overrides both.

The saved report always contains **every** finding, including those
`--quiet` hid from the terminal. The report is the record; the terminal is
the view.

The terminal is also the *abbreviated* view in one respect: an INFO
finding whose evidence runs past 12 lines is truncated with a
`... N more line(s) in the saved report` marker. This is for the Windows
probe, whose evidence is a PowerShell script — printing it in full on
every run buries the findings underneath it. WARNING and CRITICAL evidence
is never truncated. If you want the whole thing, read the report.

Rotate or delete old reports freely — they are plain text and nothing
reads them back.

---

## Check reference

19 independent check areas. Each one declares which Wazuh components it
needs and is **skipped with a note** when none are present, which is what
lets one binary run on a manager, an agent, an indexer node or an
all-in-one host without configuration.

| Module | Needs | Covers |
| --- | --- | --- |
| [`network`](#network) | manager/indexer/dashboard/filebeat | required ports, firewall, DNS |
| [`manager`](#manager) | manager | daemon states, ossec.log errors |
| [`authd_enrollment`](#authd_enrollment) | manager | port 1515, `client.keys` |
| [`remoted_connectivity`](#remoted_connectivity) | manager | port 1514, agent connections |
| [`linux_agent`](#linux_agent) | agent | agent service, agentd, key state |
| [`windows_agent`](#windows_agent) | agent | PowerShell probe for a Windows agent |
| [`indexer`](#indexer) | indexer | cluster health, shards, watermark, heap |
| [`filebeat`](#filebeat) | filebeat | service, config, output, delivery |
| [`dashboard`](#dashboard) | dashboard | service, HTTP, config, index patterns |
| [`config`](#config) | manager | ossec.conf XML, directives, `-t` |
| [`rules_decoders`](#rules_decoders) | manager | rule/decoder syntax, duplicate IDs |
| [`fim`](#fim) | manager | syscheck config, queues, database |
| [`certificate`](#certificate) | manager/indexer/dashboard | expiry, chain, hostname |
| [`security`](#security) | manager/indexer/dashboard | file modes, keys, exposure, default passwords |
| [`cluster`](#cluster) | manager | master/worker sync, integrity |
| [`api`](#api) | manager | port 55000, JWT auth, API log |
| [`performance`](#performance) | manager | queues, drops, disk, RAM, swap, load |
| [`modules`](#modules) | manager | vulnerability detector, SCA, active response |
| [`version`](#version) | *(always runs)* | version consistency |

### network

Reachability only — it answers "can these services talk to each other".

- Required listening ports per component: **1514**, **1515**, **55000**
  (manager), **9200**, **9300** (indexer), **443** (dashboard).
- A port reported closed by `/proc/net/tcp{,6}` is **cross-checked with
  `ss -lnt`** before it is called closed, so one parsing quirk cannot
  raise a false CRITICAL. 1514/1515/9200 are CRITICAL when confirmed
  closed; the rest are WARNING.
- Host firewall: `ufw`, `firewalld` or raw `iptables` — reports a Wazuh
  port that the active rules do not permit.
- DNS: resolves `localhost` and the host's own hostname, because
  components that address each other by name break silently when that
  fails.

Port *exposure* ("this is bound to 0.0.0.0") is deliberately **not**
checked here — `security` owns it. Two modules reporting one condition
twice trains you to skim.

### manager

- `wazuh-control status` for the eight daemons that must be running:
  `analysisd`, `remoted`, `db`, `execd`, `modulesd`, `logcollector`,
  `syscheckd`, `monitord`. A stopped required daemon is CRITICAL.
- A stopped local `wazuh-agentd` on the manager is a WARNING.
- If `wazuh-control` cannot be run at all, the tool says whether that is
  a privilege problem (INFO: re-run as root) or a genuinely dead manager
  (CRITICAL), rather than guessing.
- Last 800 lines of `ossec.log`: `ERROR`/`CRITICAL`/`FATAL` lines, with a
  benign-noise filter and near-identical lines collapsed into signatures.
  One repeating signature ≥20 times is CRITICAL; otherwise WARNING.

Disk, memory and load are **not** checked here — `performance` owns them.

### authd_enrollment

- Port **1515** listening.
- `client.keys`: existence, permissions, and entry count.
- Enrollment-adjacent configuration and `authd`-related errors.

### remoted_connectivity

- Port **1514** listening.
- Agent connection state as the manager sees it: which agents have
  connected, which have not, and any remoted errors explaining why.

### linux_agent

- `wazuh-agent` service state — only when systemd actually knows that
  unit, so a host without it is not reported as "the agent is down".
- `wazuh-agentd` process and connection errors from `ossec.log`.
- `client.keys` state, with a manager guard: a manager that has enrolled
  no agents yet is not an unenrolled agent.
- Agent-side configuration problems.

### windows_agent

Windows agents cannot be inspected from the manager. This module emits a
ready-to-paste **PowerShell probe script** covering the Windows-side checks
(service state, `ossec.conf`, connectivity to 1514, log errors), so the
same five-field answer is available for a Windows host.

### indexer

- Port **9200**, confirmed by an actual HTTPS request to the API before
  being called down — the indexer binds IPv4-mapped IPv6 on loopback, so
  a naive IPv4 check reports a false negative.
- `_cluster/health`: **RED** is CRITICAL, **YELLOW** is a WARNING that
  explains the single-node replica case rather than alarming about it.
- A `401` is reported as INFO when no credentials were configured (with
  instructions to add them) and as a **WARNING when configured
  credentials were rejected** — otherwise a red cluster could go
  completely unreported.
- Disk watermark from the health payload: ≥90% CRITICAL, ≥85% WARNING.
- Shards: unassigned **primary** shards CRITICAL, replica shards WARNING.
- JVM heap above 85%, and a configured `-Xmx` larger than half of
  physical RAM.
- Log scan for `OutOfMemory`, `circuit_breaking_exception` and flood-stage
  markers.

### filebeat

- Service state — again only for a unit systemd knows about.
- `filebeat test config` — the canonical YAML validity check. A privilege
  failure is reported as "needs root", not as "your config is invalid".
- `filebeat test output` — proves whether filebeat can actually reach the
  indexer, as distinct from validating its own config.
- `filebeat.yml`: presence of an `output.elasticsearch` block and of the
  `wazuh-alerts` module reference.
- Delivery errors in the filebeat log, matched on specific signatures
  (`connection refused`, `x509:`, `dial tcp`, expired/invalid
  certificate, `unexpected EOF`). Bare `certificate` and bare `EOF` were
  tried and removed: they match healthy lines like "Loading certificate".

### dashboard

- `wazuh-dashboard` service state (unit-guarded).
- HTTP response from the dashboard.
- API connection settings, read from the plugin's own
  `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` — which is where
  Wazuh 4.x keeps the API `hosts:` list. Checking only
  `opensearch_dashboards.yml` for a `wazuh.api` key reported "no Wazuh API
  settings" on correctly configured deployments, and pointed the operator
  at a file that would not have fixed anything. `opensearch_dashboards.yml`
  is still read as the fallback for the older layout.
- Index patterns — and a `404`/`500` is *not* read as "no index patterns
  exist", because that is a statement about a request that never
  succeeded.

### config

- `ossec.conf` parses as XML (a malformed file takes the whole manager
  down at start-up).
- Required directives are present and sane, including the `<remote>`
  block, `syscheck`/`rootcheck` presence, and the agent count.
- `wazuh-analysisd -t` config validation — the authoritative check, run
  even when the file itself could not be read.
- A missing `ossec.conf` and an unreadable one are distinguished
  (design rule 9): only a genuine absence is reported as "missing".

### rules_decoders

- Rule and decoder syntax in `/var/ossec/etc/rules` and `.../decoders`.
- Duplicate rule IDs, which silently shadow one another.
- Rules with neither a description nor any matching criterion, usually a
  copy/paste error.
- Ruleset loading, exercised by feeding `wazuh-logtest` a benign log line —
  which makes it load the rule and decoder set exactly as analysisd does.
  `wazuh-logtest` has **no validation flag**: `-t` does not exist, and an
  earlier version of this check read its own
  `error: unrecognized arguments: -t` as a broken ruleset, producing a
  CRITICAL on a healthy manager. A usage error is now INFO, because it is a
  statement about the invocation and not about the rules. The authoritative
  load check remains `wazuh-analysisd -t`.

### fim

- `syscheck` configuration: directories watched, frequency, `report_changes`.
- syscheck queue sizes, which grow when FIM cannot keep up.
- FIM database errors.

### certificate

- Expiry dates for the indexer, filebeat and dashboard certificate chains,
  with days remaining.
- Chain verification (does the leaf actually verify against the CA?).
- Name/SAN match. A certificate that does not name this host is **INFO,
  not a warning**: Wazuh's installer issues certificates named after the
  component they belong to (`wazuh-indexer`, `wazuh-server`,
  `wazuh-dashboard`) and its own components verify the chain with
  `verification_mode: certificate`, which does not check the hostname. On a
  stock single-node install every certificate "mismatches" while TLS works
  perfectly, and three warnings to that effect is noise you would learn to
  skim. It is reported with the explanation and the `verification_mode:
  full` caveat instead.
- A missing certificate directory and an unreadable one are distinguished,
  so TLS material you cannot read is not reported as TLS that is not
  configured.
- `openssl x509 -checkend` answers `0` or `1` and nothing else. Any other
  exit status, or a message about being unable to open the file, is
  recorded as *"could not determine"* rather than as expiry — otherwise an
  openssl that could not read the file would accuse every certificate on
  the host of having expired.

### security

- Sensitive file modes: `client.keys` (CRITICAL if world-readable),
  `ossec.conf`, `authd.pass`, `internal_users.yml`, `api.yaml`.
- Private key material in the certificate directories readable by group or
  other — CRITICAL, with an offered `chmod` repair. Agent keys are
  **reported but never repaired automatically**.
- Ports **9200**, **9300**, **55000** reachable off-box: WARNING, with
  every bound address listed. One socket appears in both address families,
  so the addresses are collapsed per port — one condition, one finding.
- Default credentials, probed only locally: indexer `admin/admin` and API
  `wazuh/wazuh`. Each probe is paired with an **unauthenticated control
  request**, so "authentication is disabled entirely" (which is worse) is
  reported as itself and not as "the default password works".

### cluster

- Cluster enabled/disabled, node types, and master/worker agreement.
- Integrity/sync state between nodes.
- `cluster.log` errors.

### api

- Port **55000** listening and the API answering.
- JWT authentication: whether a token can actually be obtained with the
  configured credentials.
- `api.log`: `ERROR`/`CRITICAL` lines immediately; `401`/`403` lines only
  when there are 10 or more, because a handful is normal — including from
  this tool's own probes, which would otherwise make the tool report
  itself.

### performance

- Queue backlog under `/var/ossec/queue/{alerts,events,archive}`:
  ≥1 GB WARNING, ≥5 GB CRITICAL.
- Event-drop and queue-full signatures in `ossec.log`: WARNING below 10
  occurrences, CRITICAL at 10 or more. A single transient burst is not
  treated as systemic overload.
- Disk: ≥85% WARNING, ≥95% CRITICAL, deduplicated by device so three
  paths on one filesystem give one finding.
- Available RAM below 10%, swap more than half used, and 1-minute load
  above twice the core count.

### modules

- Per-module error scan of `ossec.log`, one finding per tracked tag
  (`vulnerability-detector`, `sca`, `syscollector`, `active-response`)
  rather than one generic "the log has errors" line, because the fix
  depends on which module is unhappy.
- **Vulnerability detector freshness**: the age of the newest VD log line,
  compared against the hourly feed interval — see design rule 12. A stale
  feed is a WARNING; a VD line with no parseable timestamp is INFO, since
  that is a limit of the check and not a fact about the feed.

### version

Always runs, even on a bare manager.

- Reports the manager, indexer, filebeat and dashboard versions.
- Compares the manager and indexer **only when the indexer version came
  from the Wazuh package** (systemd unit trailer, then `dpkg-query`/`rpm`).
  The indexer's HTTP API answers with the **OpenSearch base version** it
  was forked from — comparing that against a 4.x manager would report an
  incompatible deployment on every healthy install. When only the API
  value is available it is reported as INFO and explicitly marked
  *not version-comparable*.
- Compares the dashboard against the manager, since it should track it.
- Reports filebeat's version but never compares it: Wazuh bundles a
  7.10.x fork of Elastic's filebeat, so its numbers never match Wazuh's.

---

## Credentials

Some checks (indexer cluster health, API authentication) need credentials.
They are **never** hardcoded, never taken from an argument, and never
placed on a command line — they are sent as an in-process HTTP header, and
masked before they can reach the terminal or the report.

### Configuration file

```bash
mkdir -p ~/.config/wazuh-doctor
cat > ~/.config/wazuh-doctor/config <<'EOF'
api_user = wazuh
api_password = <your password>
indexer_user = admin
indexer_password = <your password>
EOF
chmod 600 ~/.config/wazuh-doctor/config
```

Read (later wins): `~/.config/wazuh-doctor/config`, `/etc/wazuh-doctor/config`,
then any `--config FILE`.

### Environment variables

These override the files:

| Variable | Purpose |
| --- | --- |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | Wazuh API |
| `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` | Wazuh indexer |
| `WAZUH_DASHBOARD_USER` / `WAZUH_DASHBOARD_PASSWORD` | Dashboard |
| `WAZUH_API_URL` | default `https://127.0.0.1:55000` |
| `WAZUH_INDEXER_URL` | default `https://127.0.0.1:9200` |
| `WAZUH_DASHBOARD_URL` | default `https://127.0.0.1:443` |
| `WAZUH_DOCTOR_PYTHON` | interpreter for the launcher |
| `NO_COLOR` | disable ANSI colour |

Known keys for the config file: `api_user`, `api_password`,
`indexer_user`, `indexer_password`, `dashboard_user`,
`dashboard_password`, `api_url`, `indexer_url`, `dashboard_url`.

Without credentials the tool still runs every check that does not need
them, and says which ones it could not complete and how to enable them.

---

## Safety model

Enforced in code, not by convention.

### Diagnosis is read-only

Nothing in the diagnosis path writes, deletes or restarts anything. Every
helper runs a command with a hard timeout, captures output, and returns a
neutral result on failure — `None`, empty, or rc 127 — instead of raising.
No check can hang the run or take the tool down.

### `--fix` is the only path that changes the host

A repair is offered only for a finding that carries one, only when `--fix`
was given, and it goes through `wdlib/fixer.py`, which enforces all of the
following in order:

1. **Per-fix confirmation.** A prompt for that specific repair, showing
   what it will do and which file it will touch. Declining is one keypress
   and the default.
2. **No TTY, no change.** In a non-interactive context (cron, CI, a pipe)
   a fix is **skipped**, never silently applied. `--yes` is the only way
   to approve non-interactively, and it is not the default.
3. **Baseline validation.** Where the change touches a Wazuh config, the
   config is validated *first*, so a pre-existing failure is not blamed on
   the fix. If it is already invalid, the tool says so and asks separately
   whether to continue.
4. **Backup first.** The target file is copied to
   `<file>.bak-<timestamp>` before anything is written. If the backup
   fails, the fix is abandoned — the tool will not edit a file it could
   not save.
5. **Apply, then re-validate.** `wazuh-analysisd -t` is run again
   afterwards. **If validation fails, the backup is restored
   automatically** and the outcome says so. A failed rollback prints the
   backup path and says loudly that manual recovery is needed.
6. **Restart is a separate question.** A service is never restarted as
   part of a fix. If a repair needs one, that is asked on its own, after
   the change is applied and validated.

### Protected paths, refused in code

`Fix.__post_init__` raises rather than build a repair that targets:

```
/var/ossec/logs
/var/ossec/etc/client.keys
/var/lib/wazuh-indexer
/var/log/wazuh-indexer
```

This is a guard rail, not a policy note: a module that tries to
auto-repair one of these fails as a bug in the tool rather than as a
mutation on your host. Such findings are still reported, with the manual
command printed, and the module catches the refusal so it does not itself
look crashed.

### No destructive operations, ever

Logs, agent keys, queue contents and indexer data are never deleted,
truncated, rotated or moved by any code path. Where a fix is warranted
(freeing disk, removing aged indices), the tool prints the documented
command and leaves the decision to you.

### Secrets

`Finding.evidence` is masked on construction, so a module can pass raw
command output or a raw log line without thinking about it. Masked:
`password`/`passwd`/`secret`/`token`/`api_key`/`authorization` values,
`Bearer` tokens, credentials in URLs, bare JWTs, and
username/password pairs in JSON or YAML. `Config` masks itself in
`__repr__`/`__str__`, so it cannot leak through a traceback or a debug
print either.

Masking applies to **evidence, not to commands**. `CommandResult.cmd`
holds the literal argv, so a credential placed on a command line would
appear there. Nothing in this tree does that — credentials go through
`http_request()` as an in-process header — and nothing should start to.

### `--yes`

`--fix --yes` approves every repair without prompting. It is genuinely
dangerous and it is documented as such. Everything else in the list above
— backup, validation, automatic rollback, the protected-path guard —
still applies. It exists for rebuilding throwaway lab hosts.

---

## Running unprivileged

`ossec.conf`, `opensearch.yml`, `filebeat.yml`, the logs and
`client.keys` are root-owned. An unprivileged run is a legitimate
reconnaissance tool, not a broken one: it distinguishes **"this file
exists but I may not read it"** from **"this component is not installed"**,
and reports the first as an INFO telling you to re-run as root — never as
something alarming.

The header shows which mode you are in:

```
  Privilege   : unprivileged (some checks skipped)
```

and the report carries a **Scan limitations** section listing exactly what
was skipped and why. For a complete picture:

```bash
sudo wazuh-doctor --all
```

`--fix` unprivileged prints a note and continues; repairs that need root
fail cleanly with the reason rather than half-applying.

---

## How it works

### Layout

```
wazuh-doctor                 bash launcher: resolves symlinks, finds an
                             interpreter, sets PYTHONPATH, execs Python
wdlib/
  __init__.py                version
  cli.py                     argument parsing, module selection, --fix loop
  common.py                  Severity, Finding, safe run(), masking, Config,
                             HTTP client, systemd_unit_exists()
  discovery.py               what is on this host: OS, components, deployment
                             shape, listeners, Wazuh version
  fixer.py                   the only code that may change the host
  reporter.py                terminal view + markdown report + exit code
modules/
  __init__.py                loads every check area, records failures
  base.py                    Module, Context, REGISTRY, Finding construction
  <19 check areas>.py
```

The launcher resolves symlinks before deriving its own directory, so the
`/usr/local/bin/wazuh-doctor` symlink does not send it looking for
`wdlib/` in `/usr/local/bin`. It also sets `PYTHONDONTWRITEBYTECODE=1`, so
a root-owned install directory does not produce permission errors when run
unprivileged.

### Discovery

`discovery.py` runs once per scan and builds an `Environment`: OS and
kernel, which of the five components are installed (by path markers, not
by a single brittle file), the Wazuh version and where it was read from,
the deployment shape (all-in-one, distributed, agent-only, Docker), the
listening sockets parsed from `/proc/net/tcp{,6}`, and the enrolled agent
count.

Listeners are collected **before** role detection, because role detection
asks whether 1514/1515 are open to recognise a manager whose binaries live
outside `/var/ossec`. Modules then ask the environment rather than
re-running `ss` each time.

### Check areas

A check area is a subclass of `Module` declaring metadata and a `run()`
method. `Module.__init_subclass__` registers it, and `modules/__init__.py`
imports **every `.py` file in the directory**, so adding a check area is
one new file — there is no list to update and therefore no way to add a
file that silently never runs.

```python
class ExampleModule(Module):
    name = "example"
    title = "Example check"
    description = "what it covers"
    requires = (Component.MANAGER,)   # run if ANY of these are installed
                                      # empty tuple = always runs

    def run(self, ctx: Context) -> List[Finding]:
        return [
            self.finding(
                Severity.WARNING,
                "what is wrong",
                "why it produces the symptom",
                evidence=result.output,      # masked automatically
                fix="commands to repair it",
                verify="command to confirm",
            )
        ]
```

`requires` is what makes one binary work everywhere: a module whose
components are absent is skipped with a reason, not failed.

### Failure isolation

Three layers, because a diagnostics tool that dies is useless exactly when
you need it:

- **Per check area.** Every `run()` is called inside a `try`. A module
  that raises is reported as a WARNING finding naming the area, and the
  scan continues.
- **Per import.** `modules/__init__.py` loads each file individually and
  records failures in `IMPORT_ERRORS`. One file with a syntax error used
  to disable the entire tool; now every other area still runs, and
  `--list-modules` prints which area did not load.
- **Per command.** Every external command has a timeout and returns a
  result object instead of raising.

A check area that did not run is always visible as a finding — never as
silence.

### Performance

A full scan is typically a few seconds. The slowest checks are
`filebeat test output` (up to 40s against an unreachable indexer) and the
`journalctl`/`ossec.log` reads. `--timeout` bounds everything else.

---

## Design rules

These are the rules that keep the report trustworthy. They exist because
each one was violated at some point and produced a confident, wrong
answer.

**1. A failure to ask is not an answer.** The most expensive class of bug
in this tool is reading "the command did not run" as "the answer is bad" —
a permission error reported as an expired certificate, a missing binary as
a stopped service. `CommandResult` therefore distinguishes explicitly:

| State | Meaning |
| --- | --- |
| `ok` | ran, exited 0 |
| `missing` | rc 127 — the binary is not installed |
| `denied` | permission denial, or `sudo -n` refusing because it wants a password |
| `timed_out` | hit the timeout |

Every check must decide what each state means *before* it reports
anything. "Could not determine" is a legitimate finding; a false CRITICAL
is not.

The same applies to a command that runs and then rejects **its own
arguments**. `wazuh-logtest -t` does not exist; the tool ran it anyway,
and read logtest's `error: unrecognized arguments: -t` as evidence that
the ruleset was broken — a CRITICAL on a healthy manager, caused entirely
by how the tool called the command. A check must separate "the command
told me the subject is broken" from "the command told me I called it
wrongly".

**2. `systemctl is-active` lies about units that do not exist.** It
answers `inactive` for a unit systemd has never heard of, which is
indistinguishable from a stopped service. `systemd_unit_exists()` (via
`systemctl cat`) is required before concluding a service is down —
otherwise a host that simply lacks the filebeat package gets a CRITICAL.

**3. Compare like with like.** The indexer's HTTP API reports its
OpenSearch base version (2.x), not its Wazuh version (4.x). The filebeat
binary reports an Elastic fork's version. Neither belongs in a version
comparison, and both are now reported with their source and explicitly
marked as not comparable.

**4. One condition, one finding.** Port exposure was reported by both
`network` and `security`; disk, memory and load by both `manager` and
`performance`. Duplicates are how a report teaches its reader to skim, so
each condition now has exactly one owner.

**5. Do not report your own side effects.** The default-credential probe
writes `401` lines into `api.log`, which the API log check then reported.
Checks that cause log noise must account for it.

**6. Threshold, do not fire on first match.** One queue-full line can be a
transient burst; ten is a pattern. Severity escalates with evidence.

**7. Severity must mean something.** CRITICAL is reserved for conditions
that break the deployment now — a required daemon down, primary shards
unassigned, a world-readable `client.keys`, default credentials in use. A
replica shard on a single-node cluster, an expected fork version, or an
unreadable root-owned file are not critical, and are reported as INFO or
WARNING with the reason.

**8. State what was not checked.** Skipped modules, unreadable files,
missing credentials and failed imports are all reported. An empty report
must mean "nothing is wrong", not "nothing ran".

**9. A permission failure is not a statement about the file.** Under
`/var/ossec` — mode 0750, root:wazuh — `os.path.exists()` answers **False**
both for a file that is absent and for one the caller may not look at. An
unprivileged run therefore reported *"ossec.conf is missing"* and
*"client.keys is missing"* on a healthy manager with two agents enrolled,
while the root run of the same tool on the same host found both files
present. `path_state()` classifies a path as `present`, `missing` or
`unknown` by walking up to the first ancestor that exists but cannot be
traversed — that boundary is the edge of what the caller is entitled to
know. Every check that asserts **absence** goes through it. Assert absence
only when you are entitled to know.

**10. One condition, one finding — including across address families.**
A socket bound to `::` also appears as `0.0.0.0`, so port exposure was
reported twice for the same listener. Before emitting, collapse to the
condition, not the rows that describe it.

**11. "The last N lines" must mean the last N lines.** `tail_lines()` used
to read the first 4 MB of a file and return the last lines *of that
prefix*. Every log on a working manager outgrows 4 MB quickly, so `manager`
was announcing *"N error line(s) in ossec.log"* about errors from days ago,
as though they were happening now — and the recent error that actually
mattered had fallen off the end of the window being read. It now seeks to
the end and grows the window until it has enough lines. The lesson
generalises: a helper whose name states a guarantee must be checked against
its name, not against its behaviour on the small file you tested with.

**12. Absence is measured in time, not in lines.** The vulnerability
detector check warned whenever no VD line appeared in the last 1200 lines
of `ossec.log`. On a busy manager 1200 lines can span a few seconds, while
the CVE feed updates hourly — so the check fired on healthy deployments.
A window of "the last N lines" is not a period of time. It now dates the
newest VD line and compares its age against the feed interval, and reports
*"could not be dated"* as INFO when no timestamp is parseable, because a
gap in the tool's knowledge is not a fact about the feed.

---

## Known limitations

- **It diagnoses files and live probes, not intent.** It can prove
  `allowed-ips` does not include an agent; it cannot tell you whether that
  was deliberate.
- **Root-only files need root.** Unprivileged runs cover ports, services,
  processes and reachable APIs, not `ossec.conf` or `opensearch.yml`.
- **Indexer checks need credentials.** Without them, cluster health, shards
  and heap are unavailable, and the tool says so rather than assuming the
  indexer is healthy.
- **Version comparison needs a package database or root.** On a host with
  neither, the indexer version is reported as not comparable.
- **`--fix` automations are deliberately few.** The tool would rather
  print the right command than run a repair it cannot validate. Most
  findings are advisory.
- **Firewall analysis is best-effort.** `iptables` rules are reported for
  a human to judge; only `ufw` and `firewalld` are interpreted.
- **Windows is probe-only**, via the script `windows_agent` emits.
- **Docker deployments** are detected, and the tool should be run *inside*
  the container whose logs and config it is meant to inspect; a host-level
  run sees the host, not the container's Wazuh.
- **Validated end-to-end once, on one deployment shape.** The first full
  run was on a Wazuh 4.14.7 all-in-one host (Ubuntu 26.04, manager +
  indexer + filebeat + dashboard + agent), unprivileged and again as root.
  That run is what exposed the last round of false positives: the
  `wazuh-logtest -t` CRITICAL, the unprivileged *"ossec.conf is missing"*
  and *"client.keys is missing"* warnings, the doubled port-exposure
  finding, and the dashboard API check reading the wrong file. All are
  fixed, and each has a design rule behind it. Still **not** exercised on a
  distributed, Docker or agent-only host, and `--fix` has not yet been run
  on a throwaway host.
- **The second pass was a code audit, not a run.** Reading the tree against
  the two bug patterns above found three more defects that no single run
  would have made obvious, because all three fail *quietly* or fail only
  past a size threshold: `tail_lines()` reading the head of the file
  (rule 11), the line-window vulnerability-detector check (rule 12), and
  `openssl -checkend` treating an unreadable file as an expired
  certificate. That is worth stating plainly: **the tests that matter here
  are the ones with an adversarial input** — a log bigger than the read
  cap, a directory the caller cannot enter, a command that exits 1 without
  meaning what the caller assumed. A happy-path run on one host proves very
  little about this tool.

---


## Maintainer notes

Things that are not obvious from reading the code once.

**`/opt/wazuh-doctor` is a copy, not a symlink.** Edit
`/home/mani/wazuh-doctor-src/`, then copy with the trailing `/.`:

```bash
sudo cp -r /home/mani/wazuh-doctor-src/. /opt/wazuh-doctor/
```

Editing `/opt` directly is lost on the next copy. (Converting the install
to a symlink would be an improvement.)

**Every check that asserts a file is *absent* must use `path_state()`.**
Not `os.path.exists`. Under `/var/ossec` (0750 root:wazuh) the two are
indistinguishable, and the difference is the single largest source of false
findings this tool has produced. `path_state()` returns `present`,
`missing` or `unknown`, and walks upwards to the first ancestor that exists
but cannot be traversed. `read_text()` returning `None` is likewise *not*
evidence of absence — it means "not readable", which on a root-owned
config is the expected answer for an unprivileged run.

**`sudo -n` is used for every privileged command.** On a host where sudo
wants a password, these fail immediately instead of hanging a scan on a
prompt. That is deliberate — but it means an unprivileged run gets
`denied`, and every check that shells out through privilege must handle
`denied` before it concludes anything. Any new privileged check needs that
branch; design rule 1 is the reason.

**`/proc/net/tcp{,6}` is parsed by hand** for listeners, because `ss` may
be absent and because the indexer binds 9200 as IPv4-mapped IPv6 on
loopback — an IPv4-only check reports a false "indexer is down". **Keep
both tables**, and keep the `ss` cross-check that confirms a "closed"
verdict before it becomes CRITICAL.

**The protected-path guard raises, and that has a trap.** `Fix.__post_init__`
raises `ValueError` for a protected target, and the CLI reports a module
that raises as "module crashed" — *discarding every finding from that
module*. So `security._chmod_fix()` catches the `ValueError` and returns
`None`, reporting the problem without offering the repair. Any new fixable
finding must do the same, or a critical finding will vanish the moment it
is found. **Do not remove the guard itself.**

**`tail_lines()` is the helper to be most suspicious of.** Its name is a
guarantee, and the obvious implementation does not keep it: reading the
first *N* bytes and taking the last lines of that prefix is correct only
for files smaller than the cap. `ossec.log` on a working manager is not.
If you change it, test it against a file larger than the window, not a
small one — the small case passes either way.

### Defects already found and fixed

Almost every one shared a root cause: **a failure to run a command being
read as a positive finding about the subject.** That is the dangerous
direction for a tool whose whole value depends on CRITICAL meaning
something, and it is the first thing to look for in review.

| Where | Defect | What it produced |
| --- | --- | --- |
| `wazuh-doctor` | launcher did not resolve symlinks | run via `/usr/local/bin/wazuh-doctor`, it looked for `wdlib/` there → false "installation looks broken" |
| `common.py` | `denied` did not recognise `sudo: a password is required` | every `sudo_run` failure misread as a real failure |
| `common.py` | `tail_lines` read the head of the file | "recent" errors from days ago, reported as current (rule 11) |
| `certificate.py` | `_checkend` treated any non-zero rc as expired | every certificate reported expired when openssl could not run |
| `certificate.py` | same, via `_openssl` | every certificate reported "could not be parsed" |
| `filebeat.py` | `_config` had no `denied` guard, unlike `_output` | unreadable yml → "filebeat configuration is invalid" |
| `rules_decoders.py` | `_logtest` had no `denied` guard, then used a flag that does not exist | sudo failure, then `-t`, both → "rules or decoders problem" |
| `config.py` | compared `"<syscheck>"` against `child.tag`, which has no angle brackets | claimed FIM unconfigured on every healthy manager |
| `config.py`, `authd_enrollment.py`, `linux_agent.py`, `manager.py`, `certificate.py` | `os.path.exists()` on root-only paths under 0750 `/var/ossec` | "ossec.conf is missing", "client.keys is missing" on a healthy manager (rule 9) |
| `security.py` | `_chmod_fix` on `client.keys` raised `ValueError` | the module crashed and **lost every finding it had**, exactly when `client.keys` was world-readable |
| `security.py` | exposure emitted one finding per address family | the same listener reported twice (rule 10) |
| `dashboard.py` | looked for the API host in `opensearch_dashboards.yml` | "no Wazuh API settings" on every correctly configured 4.x dashboard |
| `dashboard.py` | read a `404`/`500` as "no index patterns exist" | sent the operator after a config problem that was not there |
| `indexer.py` | `401` with credentials configured fell through to "no payload" | a RED cluster could go completely unreported |
| `modules.py` | VD freshness judged from a 1200-line window | "the feed may not be updating" on healthy managers (rule 12) |
| `version.py` | compared the indexer's OpenSearch base version against the manager | "incompatible versions" on every healthy install (rule 3) |
| `cli.py` | a repeated `--module` ran that area twice | every finding from it printed twice (rule 10, one level up) |

**There is no test suite, and no CI.** Every change so far was verified by
reading, except the first end-to-end run, which found four separate
false-positive patterns that reading had missed. The pure functions are
the ones worth a pytest suite first, and each needs an *adversarial*
fixture rather than a happy path:

| Function | Fixture it needs |
| --- | --- |
| `common.path_state` | a tree with a non-traversable directory in it |
| `common.tail_lines` | a file larger than the read window, with a known tail |
| `common.mask` | each secret shape, plus a near-miss that must survive |
| `ManagerModule._parse_status` | both `wazuh-control` wordings, and a daemon absent from the output |
| `discovery.listening_ports` | `/proc/net/tcp` and `/proc/net/tcp6` samples holding the same socket |
| `version.parse_version` | a version with a suffix, and one with no digits |
| `PerformanceModule._size_of` | an unreadable file inside the directory |
| `Reporter._block` | a value longer than the terminal width, and a multi-line fix |

### First-run checklist

In this order, on a real deployment, before calling the tool verified.
Steps 1 and 2 are **done** on the 4.14.7 all-in-one host; steps 3–5 are
not yet.

```bash
# 1. DONE. unprivileged: expect "re-run as root" INFO notes, NOT expired
#    certificates or invalid configs
wazuh-doctor --all

# 2. DONE. root, read-only
sudo wazuh-doctor --all

# 3. TODO -- the modes
wazuh-doctor --list-modules
wazuh-doctor -m indexer -m filebeat
wazuh-doctor --all --json | python3 -m json.tool
wazuh-doctor --all --no-report
wazuh-doctor --watch 30
sudo wazuh-doctor --all --fix --dry-run

# 4. TODO -- --fix only on a throwaway host, never production. Start with
#    a security chmod fix on a scratch file.

# 5. TODO -- the adversarial cases, which a happy-path run does not reach.
#    These are the defects the audit found; each needs a fixture, not a
#    healthy host.
#    - a log file larger than the tail window: the newest line must be the
#      one reported
sudo sh -c 'printf "old ERROR\n" > /tmp/big.log; for i in $(seq 1 200000); do printf "2026/01/01 00:00:00 filler line %s\n" $i >> /tmp/big.log; done; printf "2026/01/01 00:00:00 NEWEST MARKER\n" >> /tmp/big.log'
python3 -c "import sys; sys.path.insert(0,'/home/mani/wazuh-doctor-src'); from wdlib.common import tail_lines; print(tail_lines('/tmp/big.log', 5)[-1])"
#    expect: NEWEST MARKER, not a filler line
```

Expect surprises on the first real run — a tool that reads a deployment it
has never seen will misread something, and this one did: the first run
produced one false CRITICAL and three false warnings, and the audit that
followed found three more defects that the run had not. What matters is the
direction of the failure: **"I could not determine this" is acceptable;
"your healthy host is broken" is not.**

### Open questions

- Should this run from a systemd timer and alert on findings? The exit
  codes are already CI-friendly (`0/1/2/3`, plus `64` for bad usage).
- Should `--fix` gain a non-interactive allow-list, rather than the
  all-or-nothing `--yes`?
- Windows support is a script generator. Is remote inspection over WinRM
  wanted instead?
- There is no distribution mechanism; hosts receive the tree by hand.

---

## Troubleshooting the tool

**`installation looks broken: /opt/wazuh-doctor/wdlib/cli.py missing`**
The launcher found itself somewhere without `wdlib/` next to it. Check the
copy — a nested `cp -r` is the usual cause:

```bash
ls /opt/wazuh-doctor            # expect: wazuh-doctor  wdlib  modules
sudo cp -r /path/to/wazuh-doctor-src/. /opt/wazuh-doctor/
```

**`python 3.8+ required, found 2.7`**
`python3` on `PATH` is too old or is not Python 3. Point the launcher at
the right one:

```bash
WAZUH_DOCTOR_PYTHON=/usr/bin/python3.11 wazuh-doctor --all
```

**`check module 'x' could not be loaded`**
A file in `modules/` failed to import and that area did not run. This is a
bug in wazuh-doctor, not in your Wazuh deployment. Reproduce it directly:

```bash
cd /opt/wazuh-doctor && python3 -c 'import modules.x'
```

**`module 'x' crashed`**
Re-run with `--verbose` for the traceback, and please report it.

**`wazuh-doctor: note: 'x' does not apply to this host`**
You asked for an area explicitly `--module`, but this host has none of its
components. It runs anyway so you get an answer rather than silence — but
"port 9200 is not listening" means "there is no indexer here", not "your
indexer is down".

**The report was not written to `/var/log/wazuh-doctor`**
`/var/log` is root-owned. The report falls back to
`~/.local/share/wazuh-doctor/` and the path is printed. Use
`--report-dir DIR` to choose your own.

**Colour codes in a log file**
`--no-color`, or `NO_COLOR=1`.

---

## Uninstall

The tool keeps no state. Removing it is two paths:

```bash
sudo rm -f  /usr/local/bin/wazuh-doctor
sudo rm -rf /opt/wazuh-doctor
sudo rm -rf /var/log/wazuh-doctor        # reports you want to keep? copy first
rm -rf ~/.local/share/wazuh-doctor ~/.config/wazuh-doctor
```

Nothing it does to a *Wazuh* host needs undoing: no service, unit, cron
job, user or database is created, and without `--fix` nothing on the host
was ever modified. If you did run `--fix`, every change it made has a
`<file>.bak-<timestamp>` next to it.
