"""Command-line interface for APPASSIONATA."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, cast

from appassionata.probe import ProbeResult, probe_one, render_table

SNAPSHOT_STRUCT = (
    "captured_at",
    "results",
)


def _snapshot(results: list[ProbeResult]) -> dict[str, object]:
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "results": [r.to_dict() for r in results],
    }


def _load_snapshot(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return cast(dict[str, Any], json.load(fh))


def _json_out(payload: str) -> None:
    sys.stdout.write(payload)
    if not payload.endswith("\n"):
        sys.stdout.write("\n")


def _csv_out(results: list[ProbeResult], path: str | None) -> None:
    fieldnames = [
        "score", "target", "scheme", "host", "ip", "tls_version", "cipher",
        "cert_cn", "cert_days_left", "status", "final_url", "redirects",
        "downgrade", "hsts", "hsts_max_age", "hsts_include_subdomains",
        "cookies_total", "cookies_secure", "cookies_httponly", "error",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in results:
        writer.writerow(r.to_dict())
    payload = buffer.getvalue()
    if path and path != "-":
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(payload)
    else:
        sys.stdout.write(payload)


def _render_human(
    results: list[ProbeResult],
    require_header: str | None,
    min_score: int | None,
) -> None:
    print(render_table(results))
    if require_header or min_score is not None:
        print()
    if require_header:
        missing = [r for r in results if require_header.lower() not in r.headers]
        if missing:
            print(f"missing '{require_header}' on {len(missing)} host(s):")
            for r in missing:
                print(f"  - {r.target}")
    if min_score is not None:
        below = [r for r in results if r.score < min_score]
        if below:
            print(f"score below {min_score} on {len(below)} host(s):")
            for r in below:
                why = f" ({r.error})" if r.error else ""
                print(f"  - {r.target}: {r.score}{why}")


def _gates_fail(
    results: list[ProbeResult],
    require_header: str | None,
    min_score: int | None,
) -> bool:
    """Return True when any gate (required header / minimum score) fails."""
    header_gate = (
        require_header is not None
        and any(require_header.lower() not in r.headers for r in results)
    )
    score_gate = min_score is not None and any(r.score < min_score for r in results)
    return header_gate or score_gate


def _cmd_scan(args: argparse.Namespace) -> int:
    results: list[ProbeResult] = []
    for target in args.targets:
        results.append(probe_one(target, timeout=args.timeout))

    ordered = sorted(results, key=lambda r: (r.score, r.target))

    if args.json:
        _json_out(json.dumps(_snapshot(ordered), indent=2))
    elif args.csv:
        _csv_out(ordered, args.csv)
    else:
        _render_human(ordered, args.require_header, args.min_score)

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fh:
            json.dump(_snapshot(ordered), fh, indent=2)
        print(f"saved snapshot → {args.save}", file=sys.stderr)

    code = 0
    if _gates_fail(ordered, args.require_header, args.min_score):
        code = 1
    return code


def _cmd_diff(path_a: str, path_b: str) -> int:
    """Compare snapshot A (older) against snapshot B.

    Exit 1 when anything *regressed*: a new host appeared or a host lost
    score / HSTS / response headers. Improvements leave the diff unchanged
    but are still printed.
    """
    snap_a = _load_snapshot(path_a)
    snap_b = _load_snapshot(path_b)
    by_target = {str(r["target"]): r for r in snap_a["results"]}
    regressed = False
    for entry in snap_b["results"]:
        target = str(entry["target"])
        old = by_target.get(target)
        if old is None:
            print(f"[new]  {target}")
            regressed = True
            continue
        delta = int(entry["score"]) - int(old["score"])
        sign = "+" if delta > 0 else ""
        marker = "" if delta == 0 else (" UP" if delta > 0 else " DOWN")
        line = f"[diff] {target}: {old['score']} → {entry['score']} ({sign}{delta}){marker}"
        print(line)
        if bool(entry["hsts"]) != bool(old["hsts"]):
            hsts_now = "present" if entry["hsts"] else "absent"
            hsts_was = "present" if old["hsts"] else "absent"
            print(f"       hsts: {hsts_was} → {hsts_now}")
        old_keys = set(old.get("headers", {}))
        new_keys = set(entry.get("headers", {}))
        added = sorted(new_keys - old_keys)
        removed = sorted(old_keys - new_keys)
        for h in added:
            print(f"       + header: {h}")
        for h in removed:
            print(f"       - header: {h}")
        lost_hsts = bool(old["hsts"]) and not bool(entry["hsts"])
        if delta < 0 or removed or lost_hsts:
            regressed = True
    return 1 if regressed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appassionata",
        description="Passive TLS & HTTP transport-hygiene scanner. "
        "Reads what each host announces in one GET — nothing more.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="probe hosts (equal to 'pip'-installed default)")
    scan.add_argument("targets", nargs="+", metavar="HOST", help="host[:port] or scheme://host[:port]")
    scan.add_argument("--timeout", type=float, default=5.0, metavar="SEC",
                      help="per-connection timeout (default: 5)")
    scan.add_argument("--require-header", metavar="NAME", default=None,
                      help="exit 1 unless every host sends this header")
    scan.add_argument("--min-score", type=int, default=None, metavar="N",
                      help="exit 1 unless every host scores >= N (0-100)")
    out = scan.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="emit JSON snapshot to stdout")
    out.add_argument("--csv", nargs="?", const="-", metavar="FILE",
                     help="emit CSV (to FILE, or '-' for stdout)")
    scan.add_argument("--save", metavar="FILE", default=None,
                      help="write a JSON snapshot for later --diff comparisons")

    diff = sub.add_parser("diff", help="compare two saved snapshots")
    diff.add_argument("snapshot_a", metavar="SNAPSHOT-A")
    diff.add_argument("snapshot_b", metavar="SNAPSHOT-B")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "diff":
        return _cmd_diff(args.snapshot_a, args.snapshot_b)
    parser.error(f"unknown command: {args.command}")
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
