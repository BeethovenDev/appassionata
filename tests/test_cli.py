"""Tests for the appassionata CLI, using an in-process fake prober."""

from __future__ import annotations

import json

import pytest

import appassionata.cli as cli
from appassionata.probe import ProbeResult


def fake_result(
    target: str,
    hsts: bool = True,
    headers: dict[str, str] | None = None,
    error: str | None = None,
    status: int = 200,
) -> ProbeResult:
    h = {
        "content-security-policy": "default-src 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
    }
    if headers:
        h.update(headers)
    return ProbeResult(
        target=target,
        scheme="https",
        host=target,
        port=443,
        ip="192.0.2.10",
        tls_version="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        cert_cn=target,
        status=status,
        final_url=f"https://{target}/",
        hsts=hsts,
        hsts_max_age=31536000,
        hsts_include_subdomains=True,
        headers=h,
        cookies_total=0,
        cookies_secure=0,
        cookies_httponly=0,
        error=error,
    )


@pytest.fixture
def _fake_prober(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch ``cli.probe_one`` with a deterministic fake (setup side-effect)."""

    def probe(target: str, timeout: float) -> ProbeResult:  # noqa: ARG001
        if target == "broken.example":
            return fake_result("broken.example", error="HTTP: socket timeout")
        return fake_result(target)

    monkeypatch.setattr(cli, "probe_one", probe)


def test_scan_human_sorted(capsys: pytest.CaptureFixture[str], _fake_prober: None) -> None:
    code = cli.main(["scan", "good.example", "also.example"])
    out = capsys.readouterr().out
    assert code == 0
    assert "SCORE  TARGET" in out
    assert "good.example" in out
    assert "also.example" in out


def test_scan_json_pure(capsys: pytest.CaptureFixture[str], _fake_prober: None) -> None:
    code = cli.main(["scan", "good.example", "--json"])
    out = capsys.readouterr().out
    assert code == 0
    payload = json.loads(out)  # must be pure JSON
    assert payload["results"][0]["target"] == "good.example"
    assert "score" in payload["results"][0]


def test_scan_error_host_in_json(capsys: pytest.CaptureFixture[str], _fake_prober: None) -> None:
    cli.main(["scan", "broken.example", "--json"])
    out = capsys.readouterr().out
    entry = json.loads(out)["results"][0]
    assert entry["error"] == "HTTP: socket timeout"
    assert entry["score"] == 0


def test_scan_min_score_gate(capsys: pytest.CaptureFixture[str], _fake_prober: None) -> None:
    # fake always returns 80; require 90 → exit 1
    assert cli.main(["scan", "good.example", "--min-score", "90"]) == 1
    capsys.readouterr()
    assert cli.main(["scan", "good.example", "--min-score", "70"]) == 0


def test_scan_require_header_gate(capsys: pytest.CaptureFixture[str], _fake_prober: None) -> None:
    assert cli.main(["scan", "good.example", "--require-header", "content-security-policy"]) == 0
    capsys.readouterr()
    assert cli.main(["scan", "good.example", "--require-header", "report-to"]) == 1


def test_scan_csv_stdout(capsys: pytest.CaptureFixture[str], _fake_prober: None) -> None:
    code = cli.main(["scan", "good.example", "--csv"])
    out = capsys.readouterr().out
    assert code == 0
    rows = out.strip().splitlines()
    header = (
        "score,target,scheme,host,ip,tls_version,cipher,cert_cn,cert_days_left,"
        "status,final_url,redirects,downgrade,hsts,hsts_max_age,"
        "hsts_include_subdomains,cookies_total,cookies_secure,cookies_httponly,error"
    )
    assert rows[0] == header
    assert "good.example" in rows[1]


def test_scan_save_and_diff(tmp_path: pytest.TempPathFactory) -> None:
    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"

    def probe_a(target: str, timeout: float) -> ProbeResult:  # noqa: ARG001
        return fake_result(target, hsts=False)

    monkey_a = pytest.MonkeyPatch()
    monkey_a.setattr(cli, "probe_one", probe_a)
    try:
        cli.main(["scan", "good.example", "--save", str(path_a)])
    finally:
        monkey_a.undo()

    def probe_b(target: str, timeout: float) -> ProbeResult:  # noqa: ARG001
        return fake_result(target)

    monkey_b = pytest.MonkeyPatch()
    monkey_b.setattr(cli, "probe_one", probe_b)
    try:
        cli.main(["scan", "good.example", "--save", str(path_b)])
    finally:
        monkey_b.undo()

    out = path_a.read_text(encoding="utf-8")
    assert json.loads(out)["results"][0]["hsts"] is False


def test_diff_detects_improvement(
    capsys: pytest.CaptureFixture[str], tmp_path: pytest.TempPathFactory
) -> None:
    snap_a = {
        "captured_at": "2026-01-01T00:00:00+00:00",
        "results": [
            {
                "target": "good.example",
                "score": 70,
                "hsts": False,
                "headers": {"x-content-type-options": "nosniff"},
            }
        ],
    }
    snap_b = {
        "captured_at": "2026-02-01T00:00:00+00:00",
        "results": [
            {
                "target": "good.example",
                "score": 90,
                "hsts": True,
                "headers": {
                    "x-content-type-options": "nosniff",
                    "strict-transport-security": "max-age=31536000",
                },
            }
        ],
    }
    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"
    path_a.write_text(json.dumps(snap_a), encoding="utf-8")
    path_b.write_text(json.dumps(snap_b), encoding="utf-8")

    # improvement only → no failure
    assert cli.main(["diff", str(path_a), str(path_b)]) == 0
    out = capsys.readouterr().out
    assert "[diff] good.example: 70 → 90 (+20) UP" in out
    assert "+ header: strict-transport-security" in out


def test_diff_regression_fails(
    capsys: pytest.CaptureFixture[str], tmp_path: pytest.TempPathFactory
) -> None:
    snap_a = {
        "captured_at": "2026-01-01T00:00:00+00:00",
        "results": [
            {
                "target": "good.example",
                "score": 90,
                "hsts": True,
                "headers": {"strict-transport-security": "max-age=31536000"},
            }
        ],
    }
    snap_b = {
        "captured_at": "2026-02-01T00:00:00+00:00",
        "results": [
            {
                "target": "good.example",
                "score": 70,
                "hsts": False,
                "headers": {},
            }
        ],
    }
    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"
    path_a.write_text(json.dumps(snap_a), encoding="utf-8")
    path_b.write_text(json.dumps(snap_b), encoding="utf-8")

    assert cli.main(["diff", str(path_a), str(path_b)]) == 1
    out = capsys.readouterr().out
    assert "[diff] good.example: 90 → 70 (-20) DOWN" in out
    assert "hsts: present → absent" in out


def test_diff_new_host_fails(
    capsys: pytest.CaptureFixture[str], tmp_path: pytest.TempPathFactory
) -> None:
    snap_a = {"captured_at": "2026-01-01T00:00:00+00:00", "results": []}
    snap_b = {
        "captured_at": "2026-02-01T00:00:00+00:00",
        "results": [{"target": "new.example", "score": 100, "hsts": True, "headers": {}}],
    }
    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"
    path_a.write_text(json.dumps(snap_a), encoding="utf-8")
    path_b.write_text(json.dumps(snap_b), encoding="utf-8")

    assert cli.main(["diff", str(path_a), str(path_b)]) == 1
    assert "[new]  new.example" in capsys.readouterr().out
