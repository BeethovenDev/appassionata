"""Passive TLS & HTTP header probing.

Every probe is a single connection — one TLS handshake, one GET, following
redirects. Nothing is parsed beyond response metadata; no content is stored.

This module has no network access at import time and exposes pure helpers
(:func:`score_host`, :func:`render_table`) that are easy to unit test.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

DEFAULT_USER_AGENT = "appassionata/0.1 (passive scanner; https://github.com/BeethovenDev/appassionata)"

CORE_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
)

_DT_PLAIN = re.compile(r"([0-9]{2}) ([A-Z][a-z]{2}) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2})")
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass
class ProbeResult:
    """Everything a passive probe learns about one endpoint."""

    target: str
    scheme: str
    host: str
    port: int
    ip: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    cert_cn: str | None = None
    cert_san: list[str] = field(default_factory=list)
    cert_issuer: str | None = None
    cert_days_left: int | None = None
    status: int | None = None
    final_url: str | None = None
    redirects: int = 0
    downgrade: bool = False
    hsts: bool = False
    hsts_max_age: int = 0
    hsts_include_subdomains: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    cookies_total: int = 0
    cookies_secure: int = 0
    cookies_httponly: int = 0
    error: str | None = None

    @property
    def score(self) -> int:
        return score_host(self)

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "ip": self.ip,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "cert_cn": self.cert_cn,
            "cert_san": self.cert_san,
            "cert_issuer": self.cert_issuer,
            "cert_days_left": self.cert_days_left,
            "status": self.status,
            "final_url": self.final_url,
            "redirects": self.redirects,
            "downgrade": self.downgrade,
            "hsts": self.hsts,
            "hsts_max_age": self.hsts_max_age,
            "hsts_include_subdomains": self.hsts_include_subdomains,
            "headers": self.headers,
            "cookies_total": self.cookies_total,
            "cookies_secure": self.cookies_secure,
            "cookies_httponly": self.cookies_httponly,
            "score": self.score,
            "error": self.error,
        }


def split_url(target: str) -> tuple[str, str, int]:
    """Return ``(scheme, host, port)`` for a target string."""
    if "://" not in target:
        target = "https://" + target
    parts = urlsplit(target)
    if not parts.hostname:
        raise ValueError(f"no host in target: {target!r}")
    scheme = (parts.scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {scheme!r} in {target!r}")
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, parts.hostname, port


def resolve_ip(host: str) -> str | None:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except OSError:
        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_INET6)
        except OSError:
            return None
    if not infos:
        return None
    return str(infos[0][4][0])


def _parse_cert_not_after(not_after: str) -> int | None:
    """Days until expiry for OpenSSL's ``%b %d %H:%M:%S %Y GMT`` form."""
    m = _DT_PLAIN.fullmatch(not_after.strip())
    if not m:
        return None
    day, mon, year, hour, minute, second = m.groups()
    month = _MONTHS.get(mon)
    if month is None:
        return None
    try:
        expiry = datetime(
            int(year), month, int(day), int(hour), int(minute), int(second),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None
    delta = expiry - datetime.now(timezone.utc)
    return delta.days


def _cert_summary(cert: dict[str, Any]) -> tuple[str | None, list[str], str | None, int | None]:
    cn: str | None = None
    issuer: str | None = None
    for rdn in cert.get("subject") or ():
        for key, value in rdn:
            if key == "commonName":
                cn = value
    for rdn in cert.get("issuer") or ():
        for key, value in rdn:
            if key == "commonName":
                issuer = value
    san = [value for _kind, value in cert.get("subjectAltName") or ()]
    days = _parse_cert_not_after(cert.get("notAfter", "")) if "notAfter" in cert else None
    return cn, san, issuer, days


def _parse_hsts(value: str) -> tuple[bool, int, bool]:
    if not value:
        return False, 0, False
    max_age = 0
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if m:
        max_age = int(m.group(1))
    return True, max_age, "includesubdomains" in value.lower()


def probe_one(
    target: str,
    timeout: float = 5.0,
    max_redirects: int = 5,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ProbeResult:
    """Probe one endpoint and return its :class:`ProbeResult`.

    Network failures never raise: they are reported in ``result.error`` so the
    scan can continue and the score table stays aligned.
    """
    try:
        scheme, host, port = split_url(target)
    except ValueError as exc:
        return ProbeResult(target=target, scheme="", host="", port=0, error=str(exc))

    ip = resolve_ip(host)
    tls_version: str | None = None
    cipher: str | None = None
    cert_summary: tuple[str | None, list[str], str | None, int | None] = (None, [], None, None)

    if scheme == "https":
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    tls_version = tls.version()
                    info = tls.cipher()
                    cipher = info[0] if info else None
                    cert_summary = _cert_summary(tls.getpeercert() or {})
        except (OSError, ssl.SSLError) as exc:
            return ProbeResult(
                target=target, scheme=scheme, host=host, port=port, ip=ip,
                tls_version=tls_version, cipher=cipher,
                cert_cn=cert_summary[0], cert_san=cert_summary[1],
                cert_issuer=cert_summary[2], cert_days_left=cert_summary[3],
                error=f"TLS: {exc.__class__.__name__}: {exc}",
            )

    all_headers: dict[str, str] = {}
    cookies_total = cookies_secure = cookies_httponly = 0
    status: int | None = None
    final_url = target
    redirects = 0
    downgrade = False
    current = target
    current_scheme, current_host, current_port = scheme, host, port

    for _hop in range(max_redirects + 1):
        try:
            if current_scheme == "https":
                conn: http.client.HTTPSConnection | http.client.HTTPConnection
                conn = http.client.HTTPSConnection(
                    current_host, current_port, timeout=timeout
                )
            else:
                conn = http.client.HTTPConnection(current_host, current_port, timeout=timeout)
            path = urlsplit(current).path or "/"
            if urlsplit(current).query:
                path += "?" + urlsplit(current).query
            conn.request(
                "GET", path,
                headers={"User-Agent": user_agent, "Accept": "*/*", "Connection": "close"},
            )
            resp = conn.getresponse()
            status = resp.status
            resp.read(4096)
            for name, value in resp.getheaders():
                lower = name.lower()
                if lower == "set-cookie":
                    cookies_total += 1
                    flags = value.split(";")
                    if any(f.strip().lower() == "secure" for f in flags):
                        cookies_secure += 1
                    if any(f.strip().lower() == "httponly" for f in flags):
                        cookies_httponly += 1
                elif lower not in all_headers:
                    all_headers[lower] = value
            location = resp.getheader("Location")
            conn.close()
        except (OSError, http.client.HTTPException, ValueError) as exc:
            return ProbeResult(
                target=target, scheme=scheme, host=host, port=port, ip=ip,
                tls_version=tls_version, cipher=cipher,
                cert_cn=cert_summary[0], cert_san=cert_summary[1],
                cert_issuer=cert_summary[2], cert_days_left=cert_summary[3],
                status=status, headers=all_headers,
                cookies_total=cookies_total, cookies_secure=cookies_secure,
                cookies_httponly=cookies_httponly,
                error=f"HTTP: {exc.__class__.__name__}: {exc}",
            )
        if 300 <= resp.status < 400 and location:
            if current_scheme == "https" and location.lower().startswith("http://"):
                downgrade = True
            redirects += 1
            current = urljoin(current, location)
            final_url = current
            current_scheme, current_host, current_port = split_url(current)
            continue
        break

    hsts, hsts_max_age, hsts_sub = _parse_hsts(all_headers.get("strict-transport-security", ""))

    cn, san, issuer, days = cert_summary
    return ProbeResult(
        target=target, scheme=scheme, host=host, port=port, ip=ip,
        tls_version=tls_version, cipher=cipher,
        cert_cn=cn, cert_san=san, cert_issuer=issuer, cert_days_left=days,
        status=status, final_url=final_url, redirects=redirects, downgrade=downgrade,
        hsts=hsts, hsts_max_age=hsts_max_age, hsts_include_subdomains=hsts_sub,
        headers=all_headers,
        cookies_total=cookies_total, cookies_secure=cookies_secure,
        cookies_httponly=cookies_httponly,
    )


def score_host(result: ProbeResult) -> int:
    """Score one host on a 0-100 transport-hygiene scale.

    TLS 1.3 / 1.2 with a valid certificate and HSTS starts near the top; each
    missing hardening header and every insecure cookie is a deduction.
    """
    if result.error:
        return 0
    score = 100

    if result.scheme == "http":
        score -= 40
    elif result.tls_version not in (None, "TLSv1.3", "TLSv1.2"):
        score -= 20

    cert_problem = (result.cert_cn is None and result.scheme == "https") or (
        result.cert_days_left is not None and result.cert_days_left < 30
    )
    if cert_problem:
        score -= 15

    if result.downgrade:
        score -= 25
    if result.redirects > 3:
        score -= 5

    headers = {k.lower(): v for k, v in result.headers.items()}
    if headers.get("strict-transport-security"):
        if result.hsts_max_age < 15768000:
            score -= 10
        if not result.hsts_include_subdomains:
            score -= 5
    else:
        score -= 20

    for name, deduction in (
        ("x-content-type-options", 8),
        ("x-frame-options", 6),
        ("referrer-policy", 5),
        ("content-security-policy", 8),
        ("permissions-policy", 5),
    ):
        if name not in headers:
            score -= deduction

    if result.cookies_total:
        secure = result.cookies_secure
        httponly = result.cookies_httponly
        if secure != result.cookies_total:
            score -= 8 * (result.cookies_total - secure)
        if httponly != result.cookies_total:
            score -= 5 * (result.cookies_total - httponly)

    return max(0, min(100, score))


def _truncate(value: str | None, width: int) -> str:
    if value is None:
        return "—"
    value = value.replace("\n", " ")
    return value if len(value) <= width else value[: width - 1] + "…"


def render_table(results: list[ProbeResult]) -> str:
    """Render results as fixed-width text, worst score first.

    Stable tie-break keeps output deterministic for tests and diffs.
    """
    ordered = sorted(results, key=lambda r: (r.score, r.target))
    lines = [
        "SCORE  TARGET                          TLS        STATUS  PII-KEY DETAILS",
    ]
    for r in ordered:
        tls = r.tls_version or ("http" if r.scheme == "http" else "—")
        status = str(r.status) if r.status is not None else "—"
        detail = _truncate(r.error, 24) if r.error else _score_detail(r)
        lines.append(
            f"{r.score:>5}  {_truncate(r.target, 30):<30} "
            f"{tls:<10} {status:<6} {detail}"
        )
    return "\n".join(lines)


def _score_detail(r: ProbeResult) -> str:
    parts: list[str] = []
    if r.cookies_total:
        parts.append(f"{r.cookies_secure}/{r.cookies_total} secure-cookies")
    else:
        parts.append("no cookies")
    if r.hsts:
        parts.append(f"HSTS {r.hsts_max_age}")
    else:
        parts.append("no HSTS")
    if r.cert_days_left is not None:
        parts.append(f"cert {max(r.cert_days_left, 0)}d")
    return "; ".join(parts)
