# Security Policy

## Supported versions

Only the latest tagged release receives security fixes. The project is
pre-1.0; breaking changes can ship in minor versions.

| Version | Supported |
| ------- | --------- |
| latest release | yes |
| older releases | no |

## Reporting a vulnerability

Do not open a public issue for security reports.

Email the details to the maintainer (see the git author field or the
repository's security tab). Include the rule id or code path involved,
a reproduction or proof of concept, and the impact you believe it has.
Reports get acknowledged; fixes ship in the next release with credit
unless you ask otherwise.

argus runs untrusted-input scans under a Landlock sandbox on Linux.
A finding that crashes the scanner is a bug; a finding that escapes the
sandbox or exfiltrates data is a vulnerability - report it that way.
