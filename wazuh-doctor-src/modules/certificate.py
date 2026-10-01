"""Certificate: expiry, chain validity and CN/SAN match for Wazuh TLS material."""

from __future__ import annotations

import os
import re
import time
from typing import List, Optional, Tuple

from .base import Context, Module
from wdlib.common import Finding, Severity, path_state, run
from wdlib.discovery import Component

CERT_DIRS = (
    "/etc/wazuh-indexer/certs",
    "/etc/filebeat/certs",
    "/etc/wazuh-dashboard/certs",
)

# Files that are keys, not certificates -- never pass these to x509.
KEY_HINTS = ("key", "key.pem", "key.pem")
WARN_DAYS = 30
WARN_SECONDS = WARN_DAYS * 24 * 3600


class CertificateModule(Module):
    name = "certificate"
    title = "TLS certificates"
    description = "expiry dates, CN/SAN match and chain validity (openssl)"
    requires = (Component.INDEXER, Component.DASHBOARD, Component.FILEBEAT)

    def run(self, ctx: Context) -> List[Finding]:
        if run(["openssl", "version"], timeout=6).missing:
            return [
                self.finding(
                    Severity.INFO,
                    "openssl is not installed",
                    "certificate expiry and chain checks require the openssl CLI",
                    fix="Install openssl, then re-run: sudo wazuh-doctor --module certificate",
                    verify="openssl version",
                )
            ]

        findings: List[Finding] = []
        seen_any = False
        unseen = False
        for directory in CERT_DIRS:
            if not os.path.isdir(directory):
                # Under /etc/wazuh-* an unprivileged run cannot tell an
                # absent directory from one it may not enter. Saying "no
                # certificates found" on a host that is using TLS is a
                # false statement of fact.
                if path_state(directory) == "unknown":
                    unseen = True
                continue
            certs = self._list_certs(directory)
            if not certs:
                continue
            seen_any = True
            findings.extend(self._check_dir(ctx, directory, certs))

        if not seen_any and unseen:
            findings.append(
                self.finding(
                    Severity.INFO,
                    "certificate directories could not be read",
                    "TLS material is present but is not readable without privileges, "
                    "so expiry, chain and name checks were skipped",
                    evidence="unreadable: " + ", ".join(CERT_DIRS),
                    fix="Re-run as root: sudo wazuh-doctor --module certificate",
                    verify="sudo ls -d /etc/wazuh-*/certs",
                )
            )
        elif not seen_any:
            findings.append(
                self.finding(
                    Severity.INFO,
                    "no certificate directories found",
                    "none of the standard Wazuh certificate directories exist; this is "
                    "normal if TLS was never configured for this deployment",
                    evidence="checked: " + ", ".join(CERT_DIRS),
                    fix="No action needed unless this deployment is expected to use TLS.",
                    verify="ls -d /etc/wazuh-*/certs 2>/dev/null",
                )
            )
        return findings

    # -- directory handling -----------------------------------------------

    @staticmethod
    def _list_certs(directory: str) -> List[str]:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            return []
        out = []
        for name in names:
            lowered = name.lower()
            if lowered.endswith((".pem", ".crt", ".cert")):
                # admin-key.pem, root-ca.key etc. are keys, not certs.
                if "key" in lowered and not lowered.endswith(".crt"):
                    continue
                out.append(os.path.join(directory, name))
        return out

    def _check_dir(self, ctx: Context, directory: str, certs: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for path in certs:
            findings.extend(self._check_cert(ctx, path))

        # Chain verification, when a CA bundle lives alongside the certs.
        ca = self._find_ca(directory)
        if ca:
            for path in certs:
                if os.path.basename(path) == os.path.basename(ca):
                    continue
                findings.extend(self._verify_chain(ctx, ca, path))
        return findings

    @staticmethod
    def _find_ca(directory: str) -> Optional[str]:
        for candidate in ("root-ca.pem", "root-ca.crt", "ca.pem", "ca.crt"):
            path = os.path.join(directory, candidate)
            if os.path.exists(path):
                return path
        return None

    # -- single certificate -----------------------------------------------

    def _check_cert(self, ctx: Context, path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            if os.path.getsize(path) == 0:
                return [
                    self.finding(
                        Severity.CRITICAL,
                        f"certificate {os.path.basename(path)} is empty",
                        "a zero-length certificate file cannot be parsed, so TLS "
                        "handshakes using it will fail",
                        evidence=f"{path} is 0 bytes",
                        fix="Regenerate the certificate, or restore it from backup.",
                        verify=f"openssl x509 -in {path} -noout -subject",
                    )
                ]
        except OSError:
            pass

        subject = self._openssl(ctx, ["x509", "-in", path, "-noout", "-subject"])
        if subject is None or not subject.ok:
            # Distinguish "we were not allowed to look" from "the file is
            # broken". Reading a permission failure as a parse failure would
            # report every certificate as corrupt on an unprivileged run.
            if subject is not None and (subject.denied or subject.missing):
                return [
                    self.finding(
                        Severity.INFO,
                        "certificate checks need root",
                        "openssl could not read the certificate material without "
                        "privileges, so expiry and chain checks were skipped",
                        evidence=(subject.output or "")[:300],
                        fix="Re-run as root: sudo wazuh-doctor --module certificate",
                        verify=f"sudo openssl x509 -in {path} -noout -subject",
                    )
                ]
            return [
                self.finding(
                    Severity.CRITICAL,
                    f"certificate {os.path.basename(path)} could not be parsed",
                    "openssl could not read this file as an X.509 certificate, so any "
                    "service configured to use it will fail to establish TLS",
                    evidence=(subject.output[:400] if subject else "openssl unavailable"),
                    fix="Verify the file is a valid PEM certificate, or regenerate it.",
                    verify=f"openssl x509 -in {path} -noout -subject",
                )
            ]

        details = self._openssl(
            ctx, ["x509", "-in", path, "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"]
        )
        evidence = details.output if details else subject.output

        # Expiry: -checkend exits non-zero when the cert WILL expire within
        # N seconds. None means we could not determine it -- which is not
        # the same as "expired" and must never be reported as such.
        expired_state = self._checkend(ctx, path, 0)
        expiring_state = self._checkend(ctx, path, WARN_SECONDS)
        expired = expired_state is False
        expiring = expiring_state is False
        enddate = self._openssl(ctx, ["x509", "-in", path, "-noout", "-enddate"])

        if expired:
            findings.append(
                self.finding(
                    Severity.CRITICAL,
                    f"certificate {os.path.basename(path)} has expired",
                    "an expired certificate breaks the TLS handshake, so the components "
                    "sharing it stop communicating",
                    evidence=self._crop(evidence),
                    fix=(
                        "Regenerate the certificates from the Wazuh cert tool and "
                        "redeploy them to every component, then restart the services."
                    ),
                    verify=f"openssl x509 -in {path} -noout -checkend 0",
                )
            )
        elif expiring:
            remaining = self._remaining_days(ctx, path)
            findings.append(
                self.finding(
                    Severity.WARNING,
                    f"certificate {os.path.basename(path)} expires within {WARN_DAYS} days",
                    "an expiring certificate will break component communication once it "
                    "lapses, and the expiry is easy to miss",
                    evidence=self._crop((enddate.output if enddate else "") + "\n" + evidence),
                    fix="Renew ahead of the expiry date and redeploy to all components.",
                    verify=f"openssl x509 -in {path} -noout -enddate",
                )
            )

        # CN / SAN match against this host.
        findings.extend(self._check_names(ctx, path, evidence))
        return findings

    def _check_names(self, ctx: Context, path: str, evidence: str) -> List[Finding]:
        names = set()
        for match in re.finditer(r"DNS:([^,\s]+)", evidence):
            names.add(match.group(1).strip().lower())
        cn_match = re.search(r"CN\s*=\s*([^,\n]+)", evidence)
        if cn_match:
            names.add(cn_match.group(1).strip().lower())

        if not names:
            return []

        hostname = (ctx.env.hostname or "").lower()
        # localhost/loopback names are legitimate for a loopback-only setup.
        benign = {"localhost", "127.0.0.1", "::1", "wazuh", "admin", "node-1"}

        if hostname and hostname not in names and not (names & benign):
            # INFO, deliberately. Wazuh's installer issues certificates
            # named after the component that owns them (wazuh-indexer,
            # wazuh-server, wazuh-dashboard) and its components then
            # validate the chain with verification_mode: certificate, which
            # does not check the hostname. On a stock single-node install
            # every certificate "mismatches" while TLS works perfectly, so
            # three warnings here is noise that teaches the operator to
            # skim the report -- and to miss the one that matters.
            return [
                self.finding(
                    Severity.INFO,
                    f"certificate {os.path.basename(path)} does not name this host",
                    "the certificate carries no CN or SAN matching this machine's "
                    "hostname. Wazuh's default components verify the certificate "
                    "chain but not the hostname, so this is expected on a stock "
                    "install; it only matters if something is configured to verify "
                    "the hostname",
                    evidence=(
                        f"hostname: {hostname}\n"
                        f"names in certificate: {', '.join(sorted(names))}"
                    ),
                    fix=(
                        "No action needed for a default Wazuh install. If a client "
                        "uses verification_mode: full, regenerate the certificate with "
                        "this hostname (or this host's IP) in its SAN list so that "
                        "client can verify it."
                    ),
                    verify=f"openssl x509 -in {path} -noout -text | grep -A1 'Subject Alternative Name'",
                )
            ]
        return []

    # -- chain ------------------------------------------------------------

    def _verify_chain(self, ctx: Context, ca: str, path: str) -> List[Finding]:
        result = self._openssl(ctx, ["verify", "-CAfile", ca, path], timeout=20)
        if result is None or result.ok:
            return []
        return [
            self.finding(
                Severity.WARNING,
                f"certificate {os.path.basename(path)} does not verify against {os.path.basename(ca)}",
                "the certificate chain is broken or the certificate was signed by a "
                "different CA, so strict TLS verification will fail",
                evidence=result.output[:600],
                fix=(
                    "Ensure every component uses certificates signed by the same CA:\n"
                    f"    openssl verify -CAfile {ca} {path}"
                ),
                verify=f"openssl verify -CAfile {ca} {path}",
            )
        ]

    # -- openssl helpers --------------------------------------------------

    @staticmethod
    def _openssl(ctx: Context, args: List[str], timeout: int = 15):
        return ctx.sudo_run(["openssl"] + args, timeout=timeout)

    @staticmethod
    def _checkend(ctx: Context, path: str, seconds: int) -> Optional[bool]:
        """True = survives at least ``seconds``; False = expires within the
        window; None = undetermined (could not run openssl).

        The distinction matters: treating None as "expires" would report
        every certificate as expired whenever openssl cannot be run.
        """
        result = ctx.sudo_run(
            ["openssl", "x509", "-in", path, "-noout", "-checkend", str(seconds)],
            timeout=12,
        )
        if result.missing or result.denied:
            return None
        # `openssl x509 -checkend` answers 0 or 1 and nothing else. Any other
        # status -- or a message about not being able to read the file -- means
        # we could not determine the expiry, and the caller treats False as
        # "expired". Without this, an openssl that could not open the file
        # would accuse every certificate on the host of having expired.
        blob = (result.stderr + result.stdout).lower()
        if result.rc not in (0, 1) or "could not open" in blob or "unable to load" in blob:
            return None
        return result.rc == 0

    @staticmethod
    def _remaining_days(ctx: Context, path: str) -> Optional[int]:
        result = CertificateModule._openssl(ctx, ["x509", "-in", path, "-noout", "-enddate"])
        match = re.search(r"notAfter=(.+)", result.stdout if result else "")
        if not match:
            return None
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                when = time.mktime(time.strptime(match.group(1).strip(), fmt))
                return max(0, int((when - time.time()) / 86400))
            except ValueError:
                continue
        return None

    @staticmethod
    def _crop(text: str, limit: int = 700) -> str:
        lines = [ln for ln in (text or "").splitlines() if ln.strip()]
        return "\n".join(lines[:14])[:limit]
