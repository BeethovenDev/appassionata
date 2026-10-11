# APPASSIONATA

> **Passive TLS & HTTP header scanner** — *how loudly does each host broadcast
> the state of its transport?*

Named after Beethoven's *Piano Sonata No. 23 in F minor, Op. 57* — a piece of
furious, continuous insistence. Every host on the internet is equally insistent
about its own state: the TLS version it accepts, the headers it refuses to
send, the cookies it forgets to guard. APPASSIONATA listens once and reports.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-263238?style=flat&labelColor=0d1117)](https://www.python.org/)
[![Zero dependencies](https://img.shields.io/badge/dependencies-none-263238?style=flat&labelColor=0d1117)](https://github.com/BeethovenDev/appassionata/blob/main/pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-263238?style=flat&labelColor=0d1117)](https://github.com/BeethovenDev/appassionata/blob/main/LICENSE)

## What it is

A **defensive**, read-only transport-hygiene audit for hosts you own or manage.
For each target APPASSIONATA:

- completes **one TLS handshake** and reads the negotiated version, cipher and
  peer certificate;
- performs **one GET** (following redirects) and reads response headers and
  cookie flags;
- computes a **0–100 transport score** with itemised deductions;
- ranks hosts worst-first, optionally failing the audit on a minimum score or
  a mandatory header.

It sends **no payloads**, scans **no ranges**, and stores **no response
content** beyond header metadata. Every network failure is captured as an
`error` field and scored 0 — the table never leaves gaps.

## Install

```bash
python -m pip install -e .      # from the repository root (src layout)
```

Requires Python 3.10+; zero runtime dependencies.

## Usage

```bash
# Probe a couple of hosts, human table, worst first
appassionata scan example.com www.example.org

# Machine-readable, for pipelines
appassionata scan example.com --json
appassionata scan example.com --csv scan.csv

# Gates: exit non-zero unless every host satisfies them
appassionata scan example.com --require-header strict-transport-security
appassionata scan example.com --min-score 70

# Snapshots and drift
appassionata scan example.com --save week1.json
appassionata scan example.com --save week2.json
appassionata diff week1.json week2.json
```

Also available as a module: `python -m appassionata scan example.com`.

## Scoring (0–100)

| Area | Deduction |
| --- | --- |
| Plain HTTP | −40 |
| TLS older than 1.2 / invalid handshake | −20 |
| No certificate / cert expiring < 30 days | −15 |
| HTTPS → HTTP downgrade redirect | −25 |
| No `Strict-Transport-Security` | −20 |
| HSTS max-age < 180 days | −10 |
| HSTS without `includeSubDomains` | −5 |
| No `X-Content-Type-Options` | −8 |
| No `Content-Security-Policy` | −8 |
| No `X-Frame-Options` | −6 |
| No `Referrer-Policy` | −5 |
| No `Permissions-Policy` | −5 |
| Cookie missing `Secure` | −8 each |
| Cookie missing `HttpOnly` | −5 each |
| More than 3 redirects | −5 |

Anything that prevents measurement (timeout, TLS error, DNS failure) scores 0
with an `error` field explaining why.

## Layout

```
src/appassionata/
    __init__.py   # banner + version
    __main__.py   # python -m entry
    cli.py        # argparse, snapshots, diff, CSV/JSON output
    probe.py      # probing, HSTS/cert parsing, scoring, table rendering
```

## Development

```bash
python -m pip install -e . pytest ruff mypy
ruff check . --fix
mypy src/appassionata
pytest -q
```

---

*“The storm does not last long; the return to the light is swift.”* — κ.τ.λ.