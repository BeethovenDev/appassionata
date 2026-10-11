"""Tests for appassionata.probe — pure scoring and formatting logic."""

from __future__ import annotations

from appassionata.probe import (
    ProbeResult,
    score_host,
    split_url,
)


def make_result(**over) -> ProbeResult:
    defaults: dict[str, object] = dict(
        target="https://good.example",
        scheme="https",
        host="good.example",
        port=443,
        ip="192.0.2.1",
        tls_version="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        cert_cn="good.example",
        cert_san=["good.example"],
        cert_issuer="Let's Encrypt",
        cert_days_left=80,
        status=200,
        final_url="https://good.example/",
        redirects=0,
        downgrade=False,
        hsts=True,
        hsts_max_age=31536000,
        hsts_include_subdomains=True,
        headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "content-security-policy": "default-src 'none'",
            "permissions-policy": "geolocation=()",
        },
        cookies_total=0,
        cookies_secure=0,
        cookies_httponly=0,
        error=None,
    )
    defaults.update(over)
    return ProbeResult(**defaults)


def test_score_full_hardening_is_100() -> None:
    assert score_host(make_result()) == 100


def test_score_missing_headers_deduction() -> None:
    r = make_result()
    r.headers = {}
    assert score_host(r) == 100 - 20 - 8 - 6 - 5 - 8 - 5  # no HSTS, no hardeners


def test_score_plain_http_is_heavily_penalised() -> None:
    r = make_result(scheme="http", port=80, tls_version=None, cert_cn=None)
    assert score_host(r) <= 60


def test_score_error_is_zero() -> None:
    r = make_result(error="HTTP: socket timeout")
    assert score_host(r) == 0


def test_score_weak_tls_penalised() -> None:
    r = make_result(tls_version="TLSv1.0")
    assert score_host(r) < 100


def test_score_expiring_cert_penalised() -> None:
    r = make_result(cert_days_left=10)
    assert score_host(r) < 100


def test_score_downgrade_penalised() -> None:
    r = make_result(downgrade=True)
    assert score_host(r) < 100


def test_score_cookie_flags() -> None:
    r = make_result(cookies_total=3, cookies_secure=2, cookies_httponly=1)
    base = score_host(make_result())
    assert score_host(r) == base - 8 - 10


def test_score_never_negative() -> None:
    r = make_result(
        scheme="http", tls_version="TLSv1.0", cert_cn=None,
        downgrade=True, headers={}, cookies_total=10, cookies_secure=0,
        cookies_httponly=0,
    )
    assert 0 <= score_host(r) <= 100


def test_split_url_normalises() -> None:
    assert split_url("example.com") == ("https", "example.com", 443)
    assert split_url("http://example.com:8080") == ("http", "example.com", 8080)
    assert split_url("HTTPS://EXAMPLE.ORG") == ("https", "example.org", 443)


def test_split_url_rejects_bad_target() -> None:
    import pytest

    with pytest.raises(ValueError):
        split_url("ftp://example.com")
    with pytest.raises(ValueError):
        split_url("")
