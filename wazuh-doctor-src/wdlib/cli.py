"""
wazuh-doctor :: command line interface

Read-only diagnosis by default. ``--fix`` is the only path that can
change the host, and it goes through wdlib.fixer, which confirms,
backs up, validates and rolls back.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import traceback
from typing import List, Optional, Sequence

from . import __version__
from .common import Config, Finding, Severity
from .discovery import ALL_COMPONENTS, Component, Environment, discover, listening_ports
from .fixer import Fixer
from .reporter import Reporter

# Importing the package registers every Module subclass.
import modules as _modules  # noqa: F401
from modules.base import REGISTRY, Context, Module


BANNER = "wazuh-doctor -- Wazuh deployment diagnostics"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wazuh-doctor",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  wazuh-doctor                          run every applicable check (read-only)
  wazuh-doctor --module indexer         run one area only
  wazuh-doctor --module api --module network
  wazuh-doctor --all --no-color         full scan, plain output
  wazuh-doctor --list-modules           show every check area
  sudo wazuh-doctor --all               full scan including root-only files
  sudo wazuh-doctor --all --fix         offer repairs interactively
  sudo wazuh-doctor --all --fix --dry-run
                                        show the repairs without changing anything
  wazuh-doctor --watch 60               re-scan every 60s until Ctrl-C

exit codes:
  0 clean   1 warnings found   2 critical found   3 not a Wazuh host
  64 bad usage (unknown --module name)
""",
    )

    parser.add_argument("--all", action="store_true", help="run every applicable module (default)")
    parser.add_argument(
        "--module",
        "-m",
        action="append",
        default=[],
        metavar="NAME",
        help="run only this module; repeatable",
    )
    parser.add_argument("--list-modules", action="store_true", help="list check areas and exit")

    fix_group = parser.add_argument_group("repair")
    fix_group.add_argument(
        "--fix",
        action="store_true",
        help="offer interactive repairs (implies confirmation per fix)",
    )
    fix_group.add_argument("--yes", action="store_true", help="auto-confirm every fix prompt (dangerous)")
    fix_group.add_argument(
        "--dry-run",
        action="store_true",
        help="with --fix, show each proposed repair and change nothing",
    )

    report_group = parser.add_argument_group("reporting")
    report_group.add_argument("--report", dest="report", action="store_true", default=True,
                              help="write the markdown report (default)")
    report_group.add_argument("--no-report", dest="report", action="store_false",
                              help="skip writing the markdown report")
    report_group.add_argument("--report-dir", default="/var/log/wazuh-doctor", metavar="DIR",
                              help="where to write reports (default: /var/log/wazuh-doctor)")
    report_group.add_argument("--json", action="store_true", help="emit findings as JSON on stdout")

    watch_group = parser.add_argument_group("watch")
    watch_group.add_argument("--watch", nargs="?", const=60, type=int, default=None, metavar="SECONDS",
                             help="re-scan on an interval until interrupted (default 60s)")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--config", action="append", default=[], metavar="FILE",
                      help="extra credential file to read; repeatable")
    misc.add_argument("--timeout", type=int, default=10, metavar="SECONDS",
                      help="per-command timeout (default 10)")
    misc.add_argument("--verbose", "-v", action="store_true", help="include skip reasons and timings")
    misc.add_argument("--quiet", "-q", action="store_true", help="only CRITICAL findings")
    misc.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    misc.add_argument("--version", action="version", version=f"wazuh-doctor {__version__}")
    return parser


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------


class Scan:
    def __init__(self, env: Environment, findings: List[Finding], run: Sequence[str], skipped: Sequence[str], duration: float):
        self.env = env
        self.findings = findings
        self.run = run
        self.skipped = skipped
        self.duration = duration


def select_modules(env: Environment, requested: Sequence[str]) -> tuple:
    """Return (modules_to_run, skipped_names)."""
    if requested:
        chosen = []
        # dict.fromkeys, not a set: order is the operator's, and repeats are
        # dropped. `-m api -m api` would otherwise run the area twice and
        # print every one of its findings twice, which reads as two separate
        # problems rather than one.
        for name in dict.fromkeys(requested):
            cls = REGISTRY.get(name)
            if cls is None:
                continue
            instance = cls()
            if not instance.applicable(env):
                # The operator named this area explicitly, so run it -- but say
                # so, because "port 9200 is not listening" is a misleading
                # answer on a host that has no indexer to begin with.
                print(
                    f"wazuh-doctor: note: '{name}' does not apply to this host "
                    f"({instance.skip_reason(env)}); running it anyway",
                    file=sys.stderr,
                )
            chosen.append(instance)
        return chosen, []

    run_list, skipped = [], []
    for key in sorted(REGISTRY):
        instance = REGISTRY[key]()
        if instance.applicable(env):
            run_list.append(instance)
        else:
            skipped.append(instance.name)
    return run_list, skipped


def do_scan(env: Environment, config: Config, args, fixer: Optional[Fixer]) -> Scan:
    started = time.time()
    ctx = Context(env=env, config=config, fixer=fixer, verbose=args.verbose)

    modules_to_run, skipped = select_modules(env, args.module)

    findings: List[Finding] = []

    # A check area that failed to import is a bug in wazuh-doctor itself, and
    # the operator must be told which area went unchecked rather than being
    # handed a report that quietly omits it.
    for broken, error in sorted(getattr(_modules, "IMPORT_ERRORS", {}).items()):
        findings.append(
            Finding(
                module=broken,
                severity=Severity.WARNING,
                issue=f"check module '{broken}' could not be loaded",
                root_cause=f"importing modules/{broken}.py failed: {error}",
                evidence=error,
                fix=(
                    "This is a defect in wazuh-doctor, not in the Wazuh deployment. "
                    f"That check area did not run at all. Verify with:\n"
                    f"    python3 -c 'import modules.{broken}'"
                ),
                verify=f"python3 -c 'import modules.{broken}'",
            )
        )

    ran: List[str] = []
    for module in modules_to_run:
        ran.append(module.name)
        try:
            results = module.run(ctx) or []
            findings.extend(results)
        except Exception as exc:
            # A broken module must not abort the whole scan.
            findings.append(
                Finding(
                    module=module.name,
                    severity=Severity.WARNING,
                    issue=f"module '{module.name}' crashed",
                    root_cause=f"{type(exc).__name__}: {exc}",
                    evidence=traceback.format_exc(limit=3) if args.verbose else "",
                    fix="Re-run with --verbose for the traceback and report this as a bug.",
                    verify=f"wazuh-doctor --module {module.name} --verbose",
                )
            )
    return Scan(env, findings, ran, skipped, time.time() - started)


def apply_fixes(scan: Scan, fixer: Fixer, findings: Sequence[Finding]) -> None:
    """Offer every automatable repair, one confirmation at a time."""
    candidates = [f for f in findings if f.fix_action is not None]
    if not candidates:
        return
    print()
    print("=" * 72)
    print(f"  {len(candidates)} automatable fix(es) available")
    if fixer.dry_run:
        print("  (dry run -- nothing will be changed)")
    print("=" * 72)
    for finding in candidates:
        fixer.offer(finding.fix_action, finding_label=f"{finding.module}: {finding.issue}")


# --------------------------------------------------------------------------
# Watch mode
# --------------------------------------------------------------------------


def watch_loop(env_fn, args, config: Config, fixer) -> int:
    interval = args.watch
    seen = set()
    first = True
    try:
        while True:
            env = env_fn()
            scan = do_scan(env, config, args, fixer)
            reporter = Reporter(
                env,
                scan.findings,
                scan.duration,
                scan.run,
                scan.skipped,
                min_severity=Severity.CRITICAL if args.quiet else None,
            )
            if first:
                print(reporter.render_terminal(colour=not args.no_color and not args.json))
                first = False
            else:
                by_key = {(f.module, f.issue): f for f in scan.findings}
                new_keys = [k for k in by_key if k not in seen]
                gone = [k for k in seen if k not in by_key]
                stamp = time.strftime("%H:%M:%S")
                if new_keys or gone:
                    print(f"\n[{stamp}] changes detected")
                    for key in new_keys:
                        f = by_key[key]
                        print(f"  + {f.severity.label:8} {f.module}: {f.issue}")
                    for key in gone:
                        print(f"  - resolved  {key[0]}: {key[1]}")
                else:
                    print(f"[{stamp}] no change ({len(scan.findings)} findings)")
            seen = {(f.module, f.issue) for f in scan.findings}

            if args.fix or args.dry_run:
                apply_fixes(scan, fixer, scan.findings)
            time.sleep(max(1, interval))
    except KeyboardInterrupt:
        print("\nwazuh-doctor: watch stopped")
        return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_modules:
        from .discovery import discover as _d

        env = _d()
        print(f"{BANNER}\n")
        print(f"Detected: {env.describe()}\n")
        print(f"{'module':<24} {'status':<10} description")
        print("-" * 78)
        for key in sorted(REGISTRY):
            instance = REGISTRY[key]()
            if instance.applicable(env):
                status = "will run"
            else:
                status = "skipped"
            print(f"{key:<24} {status:<10} {instance.description}")
        print()
        print("Skipped modules are those whose component is not installed on this host.")
        broken = getattr(_modules, "IMPORT_ERRORS", {})
        if broken:
            print()
            print("WARNING -- these check areas failed to import and will not run:")
            for name, error in sorted(broken.items()):
                print(f"  {name}: {error}")
        return 0

    # A mistyped module name used to run zero checks, find nothing and exit 0
    # -- which reads exactly like a clean bill of health. Fail loudly instead.
    #
    # Not via parser.error(): argparse exits 2, and this tool already uses 2
    # for "critical findings found". A typo in a CI job would then be
    # indistinguishable from a failed health check. EX_USAGE (64) is not
    # otherwise used and says plainly "you invoked me wrongly".
    unknown = [name for name in args.module if name not in REGISTRY]
    if unknown:
        print(f"wazuh-doctor: unknown module(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"  available: {', '.join(sorted(REGISTRY))}", file=sys.stderr)
        return 64

    # --fix belongs to root. Warn rather than refuse, so a dry run still works.
    if args.fix and os.geteuid() != 0 and not args.dry_run:
        print("wazuh-doctor: --fix usually needs root; re-run with sudo.", file=sys.stderr)
        print("             (continuing -- fixes that need root will fail)", file=sys.stderr)

    config = Config.load(extra_paths=args.config)
    fixer = Fixer(assume_yes=args.yes, dry_run=args.dry_run) if (args.fix or args.dry_run) else None

    def fresh_env() -> Environment:
        return discover()

    if args.watch:
        return watch_loop(fresh_env, args, config, fixer)

    env = fresh_env()

    # Nothing installed at all -> say so clearly instead of dumping noise.
    if not any(env.components.values()):
        print(BANNER, file=sys.stderr)
        print(
            "\nNo Wazuh components detected on this host.\n"
            "\nLooked for:\n"
            + "\n".join(f"  - {c:<10} {p}" for c, p in _first_markers().items())
            + f"\n\nDetection: {env.os_name}, kernel {env.kernel}\n"
            "If Wazuh runs in a container, run wazuh-doctor inside that container.\n",
            file=sys.stderr,
        )
        return 3

    if not env.is_root:
        env.warnings.append(
            "running unprivileged: root-owned configs, logs and agent keys were skipped"
        )

    scan = do_scan(env, config, args, fixer)

    # --quiet narrows what is *shown*, not what is *judged*: the reporter
    # still counts and ranks every finding for the exit code, so a cron job
    # cannot be told "clean" merely because the interesting lines were
    # hidden.
    reporter = Reporter(
        env,
        scan.findings,
        scan.duration,
        scan.run,
        scan.skipped,
        min_severity=Severity.CRITICAL if args.quiet else None,
    )

    # Write the report before rendering the terminal output so the footer can
    # carry the path inside the frame, rather than the path being printed on
    # its own line after the closing rule.
    if args.report and not args.json:
        path = reporter.save(directory=args.report_dir)
        if path:
            reporter.report_path = path
        else:
            reporter.report_error = "could not be written (try sudo, or --report-dir)"

    if args.json:
        import json

        print(json.dumps([f.to_dict() for f in reporter.findings], indent=2))
    else:
        print(reporter.render_terminal(colour=False if args.no_color else None))

        # --dry-run must reach this line too: it exists to show the repairs
        # that --fix would offer, so requiring --fix as well would make it
        # print nothing at all.
        if args.fix or args.dry_run:
            apply_fixes(scan, fixer, scan.findings)

    return reporter.exit_code()


def _first_markers() -> dict:
    from .discovery import PATH_MARKERS

    return {component: markers[0] for component, markers in PATH_MARKERS.items()}


if __name__ == "__main__":
    sys.exit(main())
