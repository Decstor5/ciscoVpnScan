#!/usr/bin/env python3
"""
cisco_vpn_scan.py — Cisco SSL VPN / AnyConnect / ASA detection scanner (v2.0).

Template-driven, detection-only. Inspired by the nuclei template model:
CVE checks live in YAML files under ./templates/ so new detections can be
added without touching this file. Three template types are supported:

  * type: http        — send a safe GET and evaluate matchers
  * type: version     — compare parsed version against per-train boundaries
  * type: fingerprint — flag when a specific fingerprint was observed

All probes are read-only. No exploit code, no destructive requests.

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import aiohttp
    from aiohttp import ClientTimeout, TCPConnector
except ImportError:  # pragma: no cover
    sys.stderr.write("[-] aiohttp is required. pip install -r requirements.txt\n")
    sys.exit(1)

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("[-] PyYAML is required. pip install -r requirements.txt\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
 ______ __                    _______
|      |__|.-----.----.-----.|     __|.----.---.-.-----.
|   ---|  ||__ --|  __|  _  ||__     ||  __|  _  |     |
|______|__||_____|____|_____||_______||____|___._|__|__|

       Cisco SSL VPN / AnyConnect / ASA Detection Scanner
            v2.0  --  template-driven, detection-only
                     Design by ex5loid
"""


# ---------------------------------------------------------------------------
# Fingerprinting: paths, headers, signatures
# ---------------------------------------------------------------------------

# Paths probed during fingerprinting. Purely passive GETs.
PORTAL_PATHS: List[str] = [
    "/",
    "/+CSCOE+/logon.html",
    "/+CSCOE+/session_password.html",
    "/+CSCOU+/",
    "/+CSCOL+/",
    "/webvpn.html",
    "/+webvpn+/index.html",
    "/CSCOSSLC/config-auth",
]

# Paths used to detect Cisco IOS XE Web UI (for CVE-2023-20198 context).
IOSXE_WEBUI_PATHS: List[str] = ["/webui/", "/webui/login.html"]

# Headers we surface in the output. X-Transcend-Version is a Pulse Secure /
# Ivanti signal, not Cisco — we capture it only to help analysts distinguish
# mixed SSL-VPN fleets.
INTERESTING_HEADERS: List[str] = [
    "Server", "Set-Cookie", "X-Powered-By", "X-Transcend-Version",
    "WWW-Authenticate", "X-AppWeb-Version", "Via", "X-Cisco-ASA-Custom",
]

# Heuristic signatures.
SIGS: Dict[str, re.Pattern[str]] = {
    "anyconnect_html": re.compile(
        r"(SSL VPN Service|WebVPN Service|AnyConnect|Cisco Secure Client|Cisco Systems VPN|CSCOE)",
        re.I,
    ),
    "asa_server_header": re.compile(r"Cisco[- ]?ASA|Cisco\s*Adaptive", re.I),
    "webvpn_cookie": re.compile(r"webvpn|webvpnlogin|webvpnPluginAuth|webvpncontext", re.I),
    "iosxe_webui": re.compile(
        r"Cisco\s+IOS\s+XE|id=\"cisco_logo\"|/webui/|WebUI\s+Controller",
        re.I,
    ),
    "logon_form": re.compile(r'name="username".*?name="password"', re.I | re.S),
    # Version strings across several Cisco product surfaces.
    "version_asa": re.compile(
        r"(?:ASA\s+Software|Adaptive\s+Security\s+Appliance|ASA)"
        r"[^0-9]{0,40}([0-9]+\.[0-9]+(?:\.[0-9]+){0,3})",
        re.I,
    ),
    "version_anyconnect": re.compile(
        r"(?:AnyConnect|Cisco\s+Secure\s+Client)"
        r"[^0-9]{0,40}([0-9]+\.[0-9]+(?:\.[0-9]+){0,3})",
        re.I,
    ),
    "version_build": re.compile(
        r"build[^0-9]{0,10}([0-9]+\.[0-9]+(?:\.[0-9]+){0,3})", re.I,
    ),
    "version_generic": re.compile(
        r"\bversion[^0-9]{0,10}([0-9]+\.[0-9]+(?:\.[0-9]+){0,3})\b", re.I,
    ),
    # Сигнатуры для AnyConnect-пробы.
    # Техника позаимствована из nuclei-templates (cisco-asa-detect.yaml,
    # автор: sdcampbell). ASA отвечает на запрос с заголовком
    # X-Aggregate-Auth: 1 XML-документом, содержащим config-auth и
    # версию в явном виде.
    "asa_config_auth": re.compile(r'config-auth\s+client="vpn"', re.I),
    "asa_version_xml": re.compile(
        r'<version\s+who="sg">([^<]+)</version>', re.I,
    ),
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Schema per the spec: cve, name, evidence, confidence.

    severity and reference are supplementary metadata (inherent to the CVE,
    not remediation advice) and are included for analyst context.
    """
    cve: str
    name: str
    evidence: str
    confidence: str              # "low" | "medium" | "high"
    severity: str = "unknown"
    reference: str = ""


@dataclass
class ScanResult:
    target: str
    url: str
    reachable: bool = False
    is_cisco_vpn: bool = False
    service: str = "unknown"
    version: Optional[str] = None
    version_source: Optional[str] = None
    banner: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    certificate: Dict[str, Any] = field(default_factory=dict)
    login_portal: bool = False
    fingerprints: List[str] = field(default_factory=list)
    vulnerabilities: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scanned_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["vulnerabilities"] = [asdict(f) for f in self.vulnerabilities]
        return d


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def normalize_target(raw: str) -> Tuple[str, str, int]:
    """Accept 'host', 'host:port', or a full URL; return (url, host, port)."""
    raw = raw.strip()
    if not raw:
        raise ValueError("empty target")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"cannot parse host from {raw!r}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme or "https"
    return f"{scheme}://{host}:{port}", host, port


def version_tuple(v: str) -> Tuple[int, ...]:
    """'9.8.2.14' -> (9, 8, 2, 14)."""
    parts = re.split(r"[^\d]+", v.strip())
    return tuple(int(p) for p in parts if p.isdigit())


def version_le(a: str, b: str) -> bool:
    """Segment-wise <= comparison, zero-padded to equal length."""
    ta, tb = version_tuple(a), version_tuple(b)
    length = max(len(ta), len(tb))
    ta = ta + (0,) * (length - len(ta))
    tb = tb + (0,) * (length - len(tb))
    return ta <= tb


# ---------------------------------------------------------------------------
# TLS certificate (out-of-band, blocking, run in executor)
# ---------------------------------------------------------------------------

def _fetch_certificate_sync(host: str, port: int, timeout: float) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
            cipher = tls.cipher()
            tls_version = tls.version()
    subject = {k: v for item in cert.get("subject", ()) for k, v in item}
    issuer = {k: v for item in cert.get("issuer", ()) for k, v in item}
    sans = [name for _t, name in cert.get("subjectAltName", ())]
    return {
        "subject": subject,
        "issuer": issuer,
        "subject_alt_names": sans,
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "serial": cert.get("serialNumber"),
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
    }


async def fetch_certificate(host: str, port: int, timeout: float) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(
            None, _fetch_certificate_sync, host, port, timeout,
        )
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Template loader + matcher engine
# ---------------------------------------------------------------------------

class Template:
    """In-memory representation of a detection template (YAML file)."""

    def __init__(self, data: Dict[str, Any], path: Optional[str] = None) -> None:
        self.raw = data
        self.path = path
        self.id: str = data.get("id", "UNKNOWN")
        self.name: str = data.get("name", self.id)
        self.severity: str = data.get("severity", "unknown")
        self.confidence: str = data.get("confidence", "medium")
        self.reference: str = data.get("reference", "")
        self.type: str = data.get("type", "http")
        self.applies_to: List[str] = data.get("applies_to", [])
        self.require_fingerprint: Optional[str] = data.get("require_fingerprint")
        self.requests: List[Dict[str, Any]] = data.get("requests", [])
        self.affected_at_or_below: List[str] = data.get("affected_at_or_below", [])
        self.evidence_template: str = data.get("evidence_template", "")

    def applies(self, result: ScanResult) -> bool:
        """Scope filter: should we run this template for this target?"""
        if not self.applies_to:
            return True
        return result.service in self.applies_to or "unknown" in self.applies_to


def load_templates(directory: str) -> List[Template]:
    """Load every *.yaml / *.yml under directory."""
    templates: List[Template] = []
    root = Path(directory)
    if not root.is_dir():
        return templates
    for path in sorted(root.glob("*.y*ml")):
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            templates.append(Template(data, path=str(path)))
        except Exception as exc:
            sys.stderr.write(f"[!] failed to load template {path}: {exc}\n")
    return templates


def _get_header_blob(headers: Dict[str, str]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


def evaluate_matcher(
    matcher: Dict[str, Any],
    status: int,
    headers: Dict[str, str],
    body: str,
) -> Tuple[bool, List[str]]:
    """Return (pass, hits) where `hits` is the list of matched tokens/patterns."""
    mtype = matcher.get("type")

    if mtype == "status":
        wanted = matcher.get("values", [])
        return status in wanted, [str(status)] if status in wanted else []

    if mtype in ("word", "regex"):
        part = matcher.get("part", "body")
        haystack = body if part == "body" else _get_header_blob(headers)
        case_insensitive = matcher.get("case_insensitive", True)
        hay_cmp = haystack.lower() if case_insensitive else haystack
        hits: List[str] = []

        if mtype == "word":
            words = matcher.get("words", [])
            for w in words:
                needle = w.lower() if case_insensitive else w
                if needle in hay_cmp:
                    hits.append(w)
            condition = matcher.get("condition", "or")
            if condition == "and":
                return len(hits) == len(words), hits
            if condition == "min_matches":
                min_count = int(matcher.get("min_matches", 2))
                return len(hits) >= min_count, hits
            # default: or
            return len(hits) > 0, hits

        # regex
        patterns = matcher.get("patterns", [])
        flags = re.I if case_insensitive else 0
        for pat in patterns:
            m = re.search(pat, haystack, flags)
            if m:
                hits.append(pat)
        condition = matcher.get("condition", "or")
        if condition == "and":
            return len(hits) == len(patterns), hits
        return len(hits) > 0, hits

    if mtype == "header":
        name = matcher.get("name", "")
        values = matcher.get("values", [])
        got = headers.get(name) or headers.get(name.lower()) or ""
        if not values:
            return bool(got), [name] if got else []
        for v in values:
            if v.lower() in got.lower():
                return True, [v]
        return False, []

    return False, []


def evaluate_matchers(
    matchers: List[Dict[str, Any]],
    condition: str,
    status: int,
    headers: Dict[str, str],
    body: str,
) -> Tuple[bool, List[str]]:
    """Run a list of matchers under 'and' (default) or 'or' semantics."""
    all_hits: List[str] = []
    results: List[bool] = []
    for m in matchers:
        ok, hits = evaluate_matcher(m, status, headers, body)
        results.append(ok)
        all_hits.extend(hits)
    if condition == "or":
        return any(results), all_hits
    return all(results), all_hits


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class CiscoVPNScanner:
    """Template-driven, detection-only Cisco SSL VPN scanner."""

    def __init__(
        self,
        templates: List[Template],
        timeout: float = 10.0,
        proxy: Optional[str] = None,
        rate_limit: float = 0.0,
        user_agent: Optional[str] = None,
        concurrency: int = 20,
    ) -> None:
        self.templates = templates
        self.timeout = timeout
        self.proxy = proxy
        self.rate_limit = rate_limit
        self.user_agent = user_agent or (
            "Mozilla/5.0 (compatible; CiscoVPNScan/2.0; detection-only)"
        )
        self._semaphore = asyncio.Semaphore(concurrency)

    # -- session & fetch -----------------------------------------------------

    def _make_session(self) -> aiohttp.ClientSession:
        connector = TCPConnector(ssl=False, limit=0)
        timeout = ClientTimeout(total=self.timeout)
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        return aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers,
        )

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str = "GET",
    ) -> Optional[Tuple[int, Dict[str, str], str]]:
        try:
            async with session.request(
                method, url, allow_redirects=False, proxy=self.proxy,
            ) as resp:
                body = await resp.text(errors="replace")
                headers = {k: v for k, v in resp.headers.items()}
                if self.rate_limit:
                    await asyncio.sleep(self.rate_limit)
                return resp.status, headers, body
        except (asyncio.TimeoutError, aiohttp.ClientError, Exception):
            return None

    # -- top-level scan ------------------------------------------------------

    async def scan(self, target_raw: str) -> ScanResult:
        async with self._semaphore:
            return await self._scan_inner(target_raw)

    async def _scan_inner(self, target_raw: str) -> ScanResult:
        try:
            url, host, port = normalize_target(target_raw)
        except ValueError as exc:
            r = ScanResult(target=target_raw, url="", scanned_at=_now_iso())
            r.errors.append(f"invalid target: {exc}")
            return r

        result = ScanResult(target=target_raw, url=url, scanned_at=_now_iso())
        result.certificate = await fetch_certificate(host, port, self.timeout)

        async with self._make_session() as session:
            await self._fingerprint(session, url, result)

            if not result.reachable:
                return result

            for tmpl in self.templates:
                if not tmpl.applies(result):
                    continue
                try:
                    await self._run_template(session, url, tmpl, result)
                except Exception as exc:
                    result.errors.append(
                        f"template {tmpl.id} failed: {type(exc).__name__}: {exc}"
                    )

        return result

    # -- fingerprinting ------------------------------------------------------

    async def _fingerprint(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        result: ScanResult,
    ) -> None:
        """Probe a handful of paths to identify service, version, and login portal."""
        for path in PORTAL_PATHS + IOSXE_WEBUI_PATHS:
            resp = await self._fetch(session, base_url + path)
            if resp is None:
                continue
            status, headers, body = resp
            result.reachable = True

            # Capture interesting headers once.
            for h in INTERESTING_HEADERS:
                if h not in result.headers:
                    v = headers.get(h) or headers.get(h.lower())
                    if v:
                        result.headers[h] = v

            server = headers.get("Server", "") or headers.get("server", "")
            if result.banner is None and server:
                result.banner = server

            # --- ASA / WebVPN signals --------------------------------------
            if SIGS["asa_server_header"].search(server):
                result.is_cisco_vpn = True
                if result.service == "unknown":
                    result.service = "cisco-asa-webvpn"
                fp = f"server-header:{server}"
                if fp not in result.fingerprints:
                    result.fingerprints.append(fp)

            set_cookie = (
                headers.get("Set-Cookie", "") + headers.get("set-cookie", "")
            )
            if SIGS["webvpn_cookie"].search(set_cookie):
                result.is_cisco_vpn = True
                if result.service == "unknown":
                    result.service = "cisco-asa-webvpn"
                fp = "cookie:webvpn"
                if fp not in result.fingerprints:
                    result.fingerprints.append(fp)

            if SIGS["anyconnect_html"].search(body):
                result.is_cisco_vpn = True
                if result.service == "unknown":
                    result.service = "cisco-anyconnect-webvpn"
                fp = f"html-sig:{path}"
                if fp not in result.fingerprints:
                    result.fingerprints.append(fp)

            if SIGS["logon_form"].search(body):
                result.login_portal = True
                fp = f"logon-form:{path}"
                if fp not in result.fingerprints:
                    result.fingerprints.append(fp)

            # --- IOS XE Web UI signal -------------------------------------
            if SIGS["iosxe_webui"].search(body) or SIGS["iosxe_webui"].search(server):
                result.is_cisco_vpn = True
                # IOS XE mgmt UI takes precedence if we saw nothing ASA-ish.
                if result.service in ("unknown", ""):
                    result.service = "cisco-ios-xe-webui"
                fp = f"iosxe-webui:{path}"
                if fp not in result.fingerprints:
                    result.fingerprints.append(fp)

            # --- version extraction ---------------------------------------
            if not result.version:
                v, src = self._extract_version(body, headers)
                if v:
                    result.version = v
                    result.version_source = src

        # AnyConnect-проба: более надёжный способ идентификации ASA.
        # Отправляем один GET с заголовком X-Aggregate-Auth: 1 — ASA
        # отвечает XML-документом с config-auth и точной версией.
        await self._probe_anyconnect_header(session, base_url, result)

        # Certificate-based fallback for Cisco identification.
        cert_blob = json.dumps(result.certificate or {}, default=str)
        if not result.is_cisco_vpn and re.search(
            r"Cisco|ASA|AnyConnect", cert_blob, re.I,
        ):
            result.is_cisco_vpn = True
            if result.service == "unknown":
                result.service = "cisco-asa-webvpn"
            result.fingerprints.append("cert:cisco-keyword")

    @staticmethod
    def _extract_version(
        body: str, headers: Dict[str, str],
    ) -> Tuple[Optional[str], Optional[str]]:
        """Try progressively more specific patterns. Return (version, source)."""
        # Most specific first.
        for key, source in (
            ("version_asa", "html:asa"),
            ("version_anyconnect", "html:anyconnect"),
            ("version_build", "html:build"),
        ):
            m = SIGS[key].search(body)
            if m:
                return m.group(1), source

        # Header-side fallback.
        header_blob = _get_header_blob(headers)
        for key, source in (
            ("version_asa", "header:asa"),
            ("version_anyconnect", "header:anyconnect"),
            ("version_generic", "header:generic"),
        ):
            m = SIGS[key].search(header_blob)
            if m:
                return m.group(1), source

        # Last-resort generic pattern in body.
        m = SIGS["version_generic"].search(body)
        if m:
            return m.group(1), "html:generic"
        return None, None

    # -- anyconnect probe ----------------------------------------------------

    async def _probe_anyconnect_header(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        result: ScanResult,
    ) -> None:
        """Более надёжный детект ASA: GET / с заголовком X-Aggregate-Auth.

        Техника позаимствована из проекта projectdiscovery/nuclei-templates
        (cisco-asa-detect.yaml, автор: sdcampbell). ASA отвечает на такой
        запрос XML-документом вида:

            <?xml version="1.0" encoding="UTF-8"?>
            <config-auth client="vpn" type="hello" aggregate-auth-version="2">
              <version who="sg">9.18.3</version>
              ...
            </config-auth>

        Это даёт и точный отпечаток ASA, и версию в явном виде, без
        необходимости парсить HTML.
        """
        url = base_url + "/"
        try:
            async with session.get(
                url,
                allow_redirects=False,
                proxy=self.proxy,
                headers={"X-Aggregate-Auth": "1"},
            ) as resp:
                if resp.status != 200:
                    return
                body = await resp.text(errors="replace")
        except (asyncio.TimeoutError, aiohttp.ClientError, Exception):
            return

        if SIGS["asa_config_auth"].search(body):
            result.is_cisco_vpn = True
            if result.service == "unknown":
                result.service = "cisco-asa-webvpn"
            fp = "anyconnect-probe:config-auth"
            if fp not in result.fingerprints:
                result.fingerprints.append(fp)

        # Явная версия из XML — перетирает менее точные источники.
        m = SIGS["asa_version_xml"].search(body)
        if m:
            version = m.group(1).strip()
            if version and (not result.version or
                            result.version_source != "xml:anyconnect-probe"):
                result.version = version
                result.version_source = "xml:anyconnect-probe"

    # -- template dispatch ---------------------------------------------------

    async def _run_template(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        tmpl: Template,
        result: ScanResult,
    ) -> None:
        if tmpl.type == "version":
            self._run_version_template(tmpl, result)
        elif tmpl.type == "fingerprint":
            self._run_fingerprint_template(tmpl, result)
        elif tmpl.type == "http":
            await self._run_http_template(session, base_url, tmpl, result)
        # Unknown types are silently skipped (forward-compat).

    def _run_version_template(self, tmpl: Template, result: ScanResult) -> None:
        if not result.version or not tmpl.affected_at_or_below:
            return
        parsed_train = version_tuple(result.version)[:2]
        for boundary in tmpl.affected_at_or_below:
            if version_tuple(boundary)[:2] != parsed_train:
                continue
            if version_le(result.version, boundary):
                evidence = (
                    f"parsed version {result.version} "
                    f"(source: {result.version_source or 'unknown'}) "
                    f"<= vulnerable boundary {boundary}"
                )
                result.vulnerabilities.append(Finding(
                    cve=tmpl.id,
                    name=tmpl.name,
                    evidence=evidence,
                    confidence=tmpl.confidence,
                    severity=tmpl.severity,
                    reference=tmpl.reference,
                ))
                return

    def _run_fingerprint_template(self, tmpl: Template, result: ScanResult) -> None:
        if not tmpl.require_fingerprint:
            return
        target = tmpl.require_fingerprint
        if result.service == target or any(
            target in fp for fp in result.fingerprints
        ):
            evidence = (
                tmpl.evidence_template
                or f"fingerprint {target!r} present on target"
            )
            result.vulnerabilities.append(Finding(
                cve=tmpl.id,
                name=tmpl.name,
                evidence=evidence,
                confidence=tmpl.confidence,
                severity=tmpl.severity,
                reference=tmpl.reference,
            ))

    async def _run_http_template(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        tmpl: Template,
        result: ScanResult,
    ) -> None:
        for req in tmpl.requests:
            method = req.get("method", "GET").upper()
            path = req.get("path", "/")
            url = base_url + path

            resp = await self._fetch(session, url, method=method)
            if resp is None:
                continue
            status, headers, body = resp

            condition = req.get("matchers_condition", "and")
            matchers = req.get("matchers", [])
            passed, hits = evaluate_matchers(
                matchers, condition, status, headers, body,
            )
            if not passed:
                continue

            # Render evidence_template with captured hits / path / status.
            tmpl_str = req.get("evidence_template") or tmpl.evidence_template \
                or "template {cve} matched at {path} (HTTP {status}); hits={hits}"
            evidence = tmpl_str.format(
                cve=tmpl.id, path=path, status=status,
                hits=hits, url=url,
            )
            result.vulnerabilities.append(Finding(
                cve=tmpl.id,
                name=tmpl.name,
                evidence=evidence,
                confidence=tmpl.confidence,
                severity=tmpl.severity,
                reference=tmpl.reference,
            ))
            return  # one hit per template is enough


# ---------------------------------------------------------------------------
# Rendering (console)
# ---------------------------------------------------------------------------

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m",
    "red": "\033[31m", "green": "\033[32m",
    "yellow": "\033[33m", "blue": "\033[34m",
    "magenta": "\033[35m", "cyan": "\033[36m", "grey": "\033[90m",
}
SEV_COLOR = {
    "critical": ANSI["red"] + ANSI["bold"],
    "high":     ANSI["red"],
    "medium":   ANSI["yellow"],
    "low":      ANSI["cyan"],
}
CONF_COLOR = {
    "high":   ANSI["green"],
    "medium": ANSI["yellow"],
    "low":    ANSI["grey"],
}


def render_console(r: ScanResult, use_color: bool = True) -> str:
    def c(code: str) -> str:
        return ANSI[code] if use_color else ""

    out: List[str] = []
    head_color = c("green") if r.is_cisco_vpn else c("grey")
    out.append(f"{head_color}{c('bold')}[*] {r.target}{c('reset')}  ->  {r.url}")

    for e in r.errors:
        out.append(f"    {c('red')}[!] {e}{c('reset')}")

    if not r.reachable:
        out.append(f"    {c('grey')}[-] unreachable / no HTTP(S) response{c('reset')}")
        return "\n".join(out)

    tag = "Cisco SSL VPN detected" if r.is_cisco_vpn else "not identified as Cisco"
    out.append(f"    {c('cyan')}service :{c('reset')} {r.service}   ({tag})")
    if r.version:
        out.append(f"    {c('cyan')}version :{c('reset')} {r.version}"
                   f"  (source: {r.version_source})")
    if r.banner:
        out.append(f"    {c('cyan')}banner  :{c('reset')} {r.banner}")
    if r.headers:
        hdrs = ", ".join(f"{k}={v[:60]}" for k, v in r.headers.items())
        out.append(f"    {c('cyan')}headers :{c('reset')} {hdrs}")
    if r.login_portal:
        out.append(f"    {c('cyan')}portal  :{c('reset')} login form present")
    if r.fingerprints:
        out.append(f"    {c('cyan')}fprints :{c('reset')} " + ", ".join(r.fingerprints))

    cert = r.certificate or {}
    if cert and "error" not in cert:
        out.append(
            f"    {c('cyan')}tls     :{c('reset')} "
            f"CN={cert.get('subject', {}).get('commonName', '-')} "
            f"issuer={cert.get('issuer', {}).get('commonName', '-')} "
            f"tls={cert.get('tls_version')}"
        )

    if not r.vulnerabilities:
        out.append(f"    {c('green')}[+] no known-CVE indicators found{c('reset')}")
        return "\n".join(out)

    out.append(f"    {c('bold')}vulnerabilities:{c('reset')}")
    for v in r.vulnerabilities:
        sev = SEV_COLOR.get(v.severity, "") if use_color else ""
        conf = CONF_COLOR.get(v.confidence, "") if use_color else ""
        out.append(
            f"      {sev}[{v.severity.upper():<8}]{c('reset')} "
            f"{v.cve} — {v.name}"
        )
        out.append(f"          confidence : {conf}{v.confidence}{c('reset')}")
        out.append(f"          evidence   : {v.evidence}")
        if v.reference:
            out.append(f"          reference  : {v.reference}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_targets(single: Optional[str], list_path: Optional[str]) -> List[str]:
    targets: List[str] = []
    if single:
        targets.append(single)
    if list_path:
        with open(list_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    seen = set()
    out: List[str] = []
    for t in targets:
        if t not in seen:
            out.append(t)
            seen.add(t)
    return out


async def run(args: argparse.Namespace) -> int:
    targets = load_targets(args.target, args.list)
    if not targets:
        print("[-] no targets supplied (use -t or -l)", file=sys.stderr)
        return 2

    templates_dir = args.templates or _default_templates_dir()
    templates = load_templates(templates_dir)
    if not templates:
        print(f"[!] no templates loaded from {templates_dir}", file=sys.stderr)

    if not args.no_banner:
        print(BANNER)
    print(f"[*] loaded {len(templates)} template(s) from {templates_dir}")
    print(f"[*] scanning {len(targets)} target(s), "
          f"concurrency={args.concurrency}, timeout={args.timeout}s")

    scanner = CiscoVPNScanner(
        templates=templates,
        timeout=args.timeout,
        proxy=args.proxy,
        rate_limit=args.rate_limit,
        user_agent=args.user_agent,
        concurrency=args.concurrency,
    )

    start = time.monotonic()
    tasks = [scanner.scan(t) for t in targets]
    results: List[ScanResult] = []
    for coro in asyncio.as_completed(tasks):
        r = await coro
        results.append(r)
        print(render_console(r, use_color=sys.stdout.isatty() and not args.no_color))

    elapsed = time.monotonic() - start
    print(f"\n[*] scanned {len(results)} target(s) in {elapsed:.1f}s")

    if args.json:
        report = {
            "scanner": "cisco_vpn_scan",
            "version": "2.0",
            "scanned_at": _now_iso(),
            "templates_loaded": [t.id for t in templates],
            "targets": [r.to_dict() for r in results],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[*] JSON report written to {args.json}")

    return 0


def _default_templates_dir() -> str:
    here = Path(__file__).resolve().parent
    return str(here / "templates")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cisco_vpn_scan",
        description=("Detection-only Cisco SSL VPN / AnyConnect / ASA scanner. "
                     "Template-driven. For AUTHORIZED testing only."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python cisco_vpn_scan.py -t vpn.example.com\n"
               "  python cisco_vpn_scan.py -l targets.txt -j report.json\n"
               "  python cisco_vpn_scan.py -t 10.0.0.5 --templates ./templates\n",
    )
    p.add_argument("-t", "--target", help="single target (IP, domain, or URL)")
    p.add_argument("-l", "--list", help="file containing one target per line")
    p.add_argument("-j", "--json", help="write JSON report to this path")
    p.add_argument("--templates", help="directory containing YAML templates")
    p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout [10]")
    p.add_argument("--concurrency", type=int, default=20, help="max concurrent targets [20]")
    p.add_argument("--rate-limit", type=float, default=0.0,
                   help="sleep seconds between requests on a single target [0]")
    p.add_argument("--proxy", help="HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--user-agent", help="override User-Agent header")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--no-banner", action="store_true", help="suppress startup banner")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        rc = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
