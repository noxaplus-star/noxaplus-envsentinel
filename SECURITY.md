# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| Earlier | No |

## Reporting a vulnerability

Email **NoxaPlus2025@gmail.com** with a description, reproduction steps, and the affected version. Do not open a public issue for a suspected vulnerability.

Please include:

- the EnvSentinel version (`envsentinel --version`);
- the command you ran and the file or line pattern that triggers the problem, with secrets removed;
- what you expected and what happened;
- relevant output, redacted.

You can expect an initial response within seven days. Confirmed issues are fixed in a patch release and credited unless you ask to stay anonymous. There is no paid bug bounty.

## What counts as a vulnerability

EnvSentinel handles data that is sensitive by definition, so these are treated as security issues:

- a real secret being printed, written, or transmitted unmasked when the rule intended to mask it;
- a path traversal or glob bug that reads files outside the scan root;
- a way to make the scanner execute code from a scanned file or config;
- a staged-scan bug that reports content that is not in the index, or misses content that is;
- a SARIF or JSON output bug that exposes a full value instead of a masked one.

## What is not a scope violation

- **A missed secret.** No rule set is complete. Report a missing pattern as a bug with the shape you expected, but a clean scan is not a security guarantee.
- **A false positive.** Use `allowPatterns` or inline suppression, and open an issue if the rule is too broad.
- **The scanner does not rotate keys.** EnvSentinel detects and blocks; it cannot revoke a credential.

## Handling a real leak

If you believe a real credential was committed to this repository, contact **NoxaPlus2025@gmail.com** before opening an issue. Assume the value is compromised, revoke it with the provider, then coordinate history cleanup. Do not paste the value into a public issue.
