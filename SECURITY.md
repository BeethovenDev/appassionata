# Security Policy

## Scope

APPASSIONATA is a **defensive, read-only** audit tool. It performs exactly one
TLS handshake and one HTTP GET per target and stores no response body content.
It is not an offensive scanner and has no exploit surface by design.

## Reporting a vulnerability

Please **do not** open a public issue. Write to the maintainers privately
through a GitHub security advisory at:

<https://github.com/BeethovenDev/appassionata/security/advisories/new>

Advisories are acknowledged within 72 hours. A fix is released under the next
patch or minor version depending on severity.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ |
| < 0.1 | ❌ |

## Responsible use

Use APPASSIONATA only against endpoints you own, operate, or are explicitly
authorised to measure. Scanning systems you do not control may violate terms
of service or local law.