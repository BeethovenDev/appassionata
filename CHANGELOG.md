# Changelog

All notable changes to APPASSIONATA are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-11

### Added

- `scan` command: passive TLS handshake + one GET per host, following
  redirects; reads TLS version, cipher, certificate summary (CN, SAN, issuer,
  days-to-expiry), response status/headers and per-cookie `Secure`/`HttpOnly`
  flags.
- 0–100 transport-hygiene score with itemised deductions (plain HTTP, weak
  TLS, downgrade redirects, missing HSTS/hardening headers, insecure cookies).
- `--require-header` and `--min-score` audit gates with non-zero exit codes.
- `--json` (snapshot-shaped), `--csv FILE` output; `--save FILE` snapshots and
  `diff A B` drift comparison between two snapshots.
- Humans-first table rendered worst-first with stable tie-breaking.
- Network failures captured as `error` fields (never raise, never gap).
- Zero runtime dependencies, Python 3.10+ `src` layout; ruff + mypy strict
  clean test suite.