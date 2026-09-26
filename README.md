# WebGoat 2025.3 — Vulnerability Writeups

Hands-on writeups of vulnerabilities solved in [WebGoat](https://owasp.org/www-project-webgoat/) v2025.3, OWASP's deliberately insecure training application. Each writeup covers the exploitation approach, the payload used, why the vulnerability exists, and how it should be fixed.

## Index

| # | Vulnerability | Category | Writeup |
|---|---------------|----------|---------|
| 1 | Hijack a Session | A1 Broken Access Control | [Link](./a1-broken-access-control/hijack-a-session.md) |
| 2 | Insecure Direct Object References (IDOR) | A1 Broken Access Control | [Link](./a1-broken-access-control/insecure-direct-object-references.md) |

*(Keep on updating as new lessons are finished.)*

## Categories

Mirrors WebGoat's own OWASP Top 10 (2021) sidebar grouping:

- [`a1-broken-access-control/`](./a1-broken-access-control) — Hijack a session, IDOR, missing function-level access control, cookie spoofing
- [`a2-cryptographic-failures/`](./a2-cryptographic-failures) — Weak crypto, insecure storage of sensitive data
- [`a3-injection/`](./a3-injection) — SQL injection, command injection, path traversal
- [`a5-security-misconfiguration/`](./a5-security-misconfiguration) — Misconfigured defaults, verbose errors, unnecessary features
- [`a6-vulnerable-outdated-components/`](./a6-vulnerable-outdated-components) — Exploiting known-vulnerable dependencies
- [`a7-identification-authentication-failures/`](./a7-identification-authentication-failures) — Auth bypass, weak password/session handling, JWT issues
- [`a8-software-data-integrity-failures/`](./a8-software-data-integrity-failures) — Insecure deserialization, unsigned/unverified updates
- [`a9-security-logging-monitoring-failures/`](./a9-security-logging-monitoring-failures) — Insufficient logging, log injection
- [`a10-server-side-request-forgery/`](./a10-server-side-request-forgery) — SSRF
- [`general/`](./general), [`client-side/`](./client-side), [`challenges/`](./challenges) — Lessons outside the numbered OWASP categories (general web security, client-side attacks, and WebGoat's standalone challenges)

## About

WebGoat is maintained by OWASP for security education purposes. All exploitation shown here was performed against a local WebGoat instance for learning purposes only.

## ⚠️ Disclaimer

Everything in this repository was performed against a **local, self-hosted WebGoat instance** (v2025.3) for educational purposes as part of learning application security. None of the techniques described here were used against systems the author does not own or have explicit permission to test. Do not use this content against any application or system without authorization — unauthorized access is illegal in most jurisdictions.

## License

This project is licensed under the [MIT License](./LICENSE) — see the LICENSE file for details. The writeups and explanations are the author's own original work; WebGoat itself is a separate OWASP project licensed under its own terms.