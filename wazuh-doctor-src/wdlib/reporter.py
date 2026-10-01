"""
wazuh-doctor :: report rendering

Turns findings into the two outputs the tool promises: a coloured
terminal summary and a standalone markdown document.

Every finding renders in the fixed shape:

    Issue -> Root Cause -> Evidence -> Fix -> Verify

Evidence has already been masked on the way into the Finding, so this
module never has to think about secrets.
"""

from __future__ import annotations

import datetime as _dt
import os
import shutil
import sys
import textwrap
from typing import Dict, List, Optional, Sequence

from .common import Finding, Severity, human_bytes
from .discovery import Environment

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

SEVERITY_COLOUR = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.WARNING: "\033[1;33m",  # bold yellow
    Severity.INFO: "\033[1;36m",  # bold cyan
}

SEVERITY_ICON = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.WARNING: "[WARNING] ",
    Severity.INFO: "[INFO]    ",
}

REPORT_DIR = "/var/log/wazuh-doctor"


def _use_colour(force: Optional[bool] = None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


class Reporter:
    def __init__(
        self,
        env: Environment,
        findings: Sequence[Finding],
        duration: float = 0.0,
        modules_run: Sequence[str] = (),
        modules_skipped: Sequence[str] = (),
        min_severity: Optional[Severity] = None,
    ) -> None:
        self.env = env
        # Most severe first; stable within a severity by module name.
        self.all_findings: List[Finding] = sorted(
            findings, key=lambda f: (-int(f.severity), f.module, f.issue)
        )
        # ``min_severity`` (--quiet) narrows what is *printed*. It must not
        # narrow what is *counted*: the exit code and the summary are read by
        # cron and CI, and a run that hides warnings must still exit 1 rather
        # than report a clean host.
        self.min_severity = min_severity
        self.findings: List[Finding] = [
            f for f in self.all_findings if min_severity is None or f.severity >= min_severity
        ]
        self.hidden = len(self.all_findings) - len(self.findings)
        self.duration = duration
        self.modules_run = list(modules_run)
        self.modules_skipped = list(modules_skipped)
        self.generated = _dt.datetime.now()
        # Filled in by the CLI once the markdown report has been written, so
        # the footer can carry the path inside the frame instead of the path
        # being printed on its own line after the frame has closed.
        self.report_path: Optional[str] = None
        self.report_error: str = ""

    # -- summary ----------------------------------------------------------

    @property
    def counts(self) -> Dict[Severity, int]:
        counts = {sev: 0 for sev in Severity}
        for finding in self.all_findings:
            counts[finding.severity] += 1
        return counts

    def worst(self) -> Severity:
        return max((f.severity for f in self.all_findings), default=Severity.INFO)

    def exit_code(self) -> int:
        """2 = critical, 1 = warning, 0 = clean. Handy for cron/CI."""
        worst = self.worst() if self.findings else None
        if worst == Severity.CRITICAL:
            return 2
        if worst == Severity.WARNING:
            return 1
        return 0

    # -- terminal ---------------------------------------------------------

    def _c(self, text: str, code: str, colour: bool) -> str:
        return f"{code}{text}{RESET}" if colour else text

    # -- terminal layout --------------------------------------------------
    #
    # A finding is five labelled fields. The label column is 17 characters
    # wide and every continuation line is indented to match it:
    #
    #     Fix        : Fix the XML error above. A mismatched tag is usual:
    #                    sudo wazuh-analysisd -t
    #
    # Multi-line fixes used to print their second line flush-left, so a
    # command block fell outside the finding it belonged to and the whole
    # report read as unaligned text -- which is exactly the "looks odd"
    # that makes an operator skim past a critical finding.

    LABEL_WIDTH = 11  # label + padding, before the ": "
    INDENT = " " * (4 + LABEL_WIDTH + 2)

    # A single INFO finding can carry a long artefact (the Windows agent
    # diagnostic is a PowerShell script). Printing all of it buries the
    # findings underneath it; the terminal gets a preview and the saved
    # report always keeps the whole thing.
    TERMINAL_EVIDENCE_LINES = 12

    @staticmethod
    def _width() -> int:
        """Usable text width for the value column."""
        try:
            columns = shutil.get_terminal_size((100, 24)).columns
        except OSError:  # not a terminal
            columns = 100
        return max(60, columns - len(Reporter.INDENT))

    def _block(self, label: str, text: str) -> List[str]:
        """Render one labelled field with aligned, wrapped continuation."""
        prefix = f"    {label:<{self.LABEL_WIDTH}}: "
        width = self._width()
        rendered: List[str] = []
        for raw in (text or "").splitlines() or [""]:
            stripped = raw.rstrip()
            if not stripped:
                rendered.append("")
                continue
            # drop_whitespace=False keeps the leading indentation of a fix's
            # command block, so shell lines still read as a block.
            rendered.extend(
                textwrap.wrap(
                    stripped,
                    width=width,
                    subsequent_indent="",
                    break_long_words=True,
                    break_on_hyphens=False,
                    drop_whitespace=False,
                )
                or [""]
            )
        lines = [f"{prefix}{rendered[0]}"]
        lines.extend(f"{self.INDENT}{line}" if line else "" for line in rendered[1:])
        return lines

    def _terminal_evidence(self, finding: Finding) -> str:
        lines = finding.evidence.splitlines()
        if finding.severity != Severity.INFO or len(lines) <= self.TERMINAL_EVIDENCE_LINES:
            return finding.evidence
        kept = lines[: self.TERMINAL_EVIDENCE_LINES]
        kept.append(
            f"... {len(lines) - self.TERMINAL_EVIDENCE_LINES} more line(s) "
            "in the saved report"
        )
        return "\n".join(kept)

    def _gutter(self, label: str, text: str) -> List[str]:
        """A frame line wrapped so continuations stay under its own label.

        19 columns: two of indent, a 15-wide label, then ": ". The header
        block and the footer block share it, so the whole frame reads as one
        column of values rather than three nearly-aligned ones.
        """
        prefix = f"  {label:<15}: "
        return textwrap.wrap(
            text or "",
            width=self._width() + len(self.INDENT),
            initial_indent=prefix,
            subsequent_indent=" " * len(prefix),
            break_long_words=True,
            break_on_hyphens=False,
        ) or [prefix.rstrip()]

    def _frame_footer(self, rule: str, colour: bool) -> List[str]:
        """The closing band: what ran, what was skipped, where the report is.

        Shared by the clean path and the findings path. A run that found
        nothing used to end at "No issues found." with no closing rule and
        no report path, so a clean host and a crashed one looked the same
        from the last line of the output.
        """
        out: List[str] = []
        if self.hidden:
            out.extend(self._gutter("Hidden", f"{self.hidden} lower-severity finding(s), hidden by --quiet"))
        if self.modules_skipped:
            out.extend(self._gutter("Skipped modules", ", ".join(self.modules_skipped)))
        if self.modules_run:
            out.extend(self._gutter("Modules run", ", ".join(self.modules_run)))
        if self.report_path:
            out.extend(self._gutter("Report", self.report_path))
        elif self.report_error:
            out.extend(self._gutter("Report", self.report_error))
        out.append(self._c(rule, BOLD, colour))
        return out

    def render_terminal(self, colour: Optional[bool] = None) -> str:
        colour = _use_colour(colour)
        out: List[str] = []
        rule = "=" * 72

        out.append(self._c(rule, BOLD, colour))
        out.append(self._c("  WAZUH DOCTOR", BOLD, colour))
        out.append(self._c(rule, BOLD, colour))

        wazuh = self.env.wazuh_version + (
            f"  (via {self.env.version_source})"
            if self.env.version_source != "unknown"
            else ""
        )
        components = ", ".join(sorted(c for c, ok in self.env.components.items() if ok))
        out.extend(self._gutter("Host", self.env.hostname))
        out.extend(self._gutter("OS", f"{self.env.os_name}  ({self.env.kernel})"))
        out.extend(self._gutter("Wazuh", wazuh))
        out.extend(self._gutter("Deployment", self.env.deployment))
        out.extend(self._gutter("Components", components or "none detected"))
        out.extend(
            self._gutter(
                "Privilege",
                "root" if self.env.is_root else "unprivileged (some checks skipped)",
            )
        )
        if self.env.agents_count is not None:
            out.extend(self._gutter("Agents", str(self.env.agents_count)))
        out.extend(self._gutter("Scanned in", f"{self.duration:.1f}s"))

        for warning in self.env.warnings:
            out.append(self._c(f"  ! {warning}", SEVERITY_COLOUR[Severity.WARNING], colour))

        counts = self.counts
        out.append("")
        # Padded to two digits: a host with ten findings used to shift the
        # columns on the one line an operator reads first.
        out.append(
            "  "
            + self._c(f"{counts[Severity.CRITICAL]:>2} critical", SEVERITY_COLOUR[Severity.CRITICAL], colour)
            + "   "
            + self._c(f"{counts[Severity.WARNING]:>2} warning", SEVERITY_COLOUR[Severity.WARNING], colour)
            + "   "
            + self._c(f"{counts[Severity.INFO]:>2} info", SEVERITY_COLOUR[Severity.INFO], colour)
        )
        out.append(self._c(rule, BOLD, colour))

        if not self.findings:
            out.append("")
            if self.all_findings:
                # --quiet hid everything. Say so rather than print a clean
                # bill of health over a host that has problems.
                message = f"{len(self.all_findings)} finding(s) found, all hidden by --quiet."
            else:
                message = "No issues found."
            out.append(self._c(f"  {message}", SEVERITY_COLOUR[Severity.INFO], colour))
            out.append("")
            out.extend(self._frame_footer(rule, colour))
            return "\n".join(out)

        for finding in self.findings:
            out.append("")
            header = f"{SEVERITY_ICON[finding.severity]} {finding.module}: {finding.issue}"
            out.append(self._c(header, SEVERITY_COLOUR[finding.severity], colour))
            out.extend(self._block("Root cause", finding.root_cause))
            if finding.evidence:
                out.extend(self._block("Evidence", self._terminal_evidence(finding)))
            if finding.fix:
                out.extend(self._block("Fix", finding.fix))
            if finding.verify:
                out.extend(self._block("Verify", finding.verify))

        out.append("")
        out.append(self._c(rule, BOLD, colour))
        out.extend(self._frame_footer(rule, colour))
        return "\n".join(out)

    # -- markdown ---------------------------------------------------------

    def render_markdown(self) -> str:
        counts = self.counts
        lines: List[str] = []
        lines.append("# Wazuh Doctor Report")
        lines.append("")
        lines.append(f"**Generated:** {self.generated.strftime('%Y-%m-%d %H:%M:%S')}  ")
        lines.append(f"**Host:** `{self.env.hostname}`  ")
        lines.append(f"**OS:** {self.env.os_name} (`{self.env.kernel}`)  ")
        lines.append(
            f"**Wazuh:** {self.env.wazuh_version}"
            + (f" (source: {self.env.version_source})" if self.env.version_source != "unknown" else "")
            + "  "
        )
        lines.append(f"**Deployment:** {self.env.deployment}  ")
        lines.append(
            "**Components:** "
            + (
                ", ".join(sorted(c for c, ok in self.env.components.items() if ok))
                or "none detected"
            )
            + "  "
        )
        lines.append(f"**Privilege:** {'root' if self.env.is_root else 'unprivileged'}  ")
        if self.env.agents_count is not None:
            lines.append(f"**Enrolled agents:** {self.env.agents_count}  ")
        lines.append(f"**Scan duration:** {self.duration:.1f}s")
        lines.append("")

        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        lines.append(f"| CRITICAL | {counts[Severity.CRITICAL]} |")
        lines.append(f"| WARNING | {counts[Severity.WARNING]} |")
        lines.append(f"| INFO | {counts[Severity.INFO]} |")
        lines.append("")

        if self.env.warnings:
            lines.append("### Scan limitations")
            lines.append("")
            for warning in self.env.warnings:
                lines.append(f"- {warning}")
            lines.append("")

        if not self.all_findings:
            lines.append("**No issues found.**")
            lines.append("")
        else:
            for severity in (Severity.CRITICAL, Severity.WARNING, Severity.INFO):
                group = [f for f in self.all_findings if f.severity == severity]
                if not group:
                    continue
                lines.append(f"## {severity.label} ({len(group)})")
                lines.append("")
                for finding in group:
                    lines.extend(self._finding_markdown(finding))

        lines.append("---")
        lines.append("")
        lines.append(f"_Modules run: {', '.join(self.modules_run) or 'none'}_  ")
        if self.modules_skipped:
            lines.append(f"_Modules skipped (component absent): {', '.join(self.modules_skipped)}_  ")
        lines.append("")
        lines.append("_Generated by wazuh-doctor. Read-only diagnosis unless `--fix` was given._")
        lines.append("")
        return "\n".join(lines)

    def _finding_markdown(self, finding: Finding) -> List[str]:
        lines: List[str] = []
        lines.append(f"### `{finding.module}` — {finding.issue}")
        lines.append("")
        lines.append(f"- **Root cause:** {finding.root_cause}")
        if finding.evidence:
            lines.append("- **Evidence:**")
            lines.append("")
            lines.append("  ```")
            for line in finding.evidence.splitlines():
                lines.append(f"  {line}")
            lines.append("  ```")
            lines.append("")
        if "\n" in finding.fix:
            # A multi-line fix is a command block. Inlined after "**Fix:**"
            # markdown collapses the newlines and the commands read as one
            # run-on sentence, which is unusable to copy from.
            lines.append("- **Fix:**")
            lines.append("")
            lines.append("  ```")
            for line in finding.fix.splitlines():
                lines.append(f"  {line}" if line.strip() else "")
            lines.append("  ```")
            lines.append("")
        elif finding.fix:
            lines.append(f"- **Fix:** {finding.fix}")
        if finding.verify:
            lines.append(f"- **Verify:** `{finding.verify}`")
        if finding.fixable:
            lines.append("- **Automatable:** yes — re-run with `--fix` to be offered this repair")
        lines.append("")
        return lines

    # -- output -----------------------------------------------------------

    def save(self, directory: str = REPORT_DIR, quiet: bool = False) -> Optional[str]:
        """Write the markdown report. Returns the path, or None on failure."""
        stamp = self.generated.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(directory, f"report-{stamp}.md")
        try:
            os.makedirs(directory, exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.render_markdown())
            try:
                os.chmod(path, 0o640)
            except OSError:
                pass
            return path
        except OSError:
            # /var/log is root-only; fall back to a writable location
            # rather than losing the report entirely.
            fallback_dir = os.path.expanduser("~/.local/share/wazuh-doctor")
            try:
                os.makedirs(fallback_dir, exist_ok=True)
                fallback = os.path.join(fallback_dir, f"report-{stamp}.md")
                with open(fallback, "w", encoding="utf-8") as handle:
                    handle.write(self.render_markdown())
                return fallback
            except OSError:
                return None
