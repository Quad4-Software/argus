# Changelog

## [Unreleased]

- `image --remote`: OCI registry API audit without a container runtime
- `--history-secrets`: scans git diffs for committed-and-removed secrets
- RPM rpmdb.sqlite extraction for image OSV lookups
- Maven, NuGet, Packagist, Hex, Pub dep ecosystems
- SPDX 2.3 SBOM output (`--sbom-format spdx`)
- OSV fix versions surface in remediation text
- Entropy-based secret detection (SEC-090)
- Typosquat edit-distance checks on dep names (DEP-020)
- dataflow rule kind: source + sink co-occurrence per file
- iac ruleset: Terraform/CloudFormation misconfigs
- 4 more verify providers (Anthropic, DO, PyPI, crates.io)
- nginx/apache/mysql/postgres/redis service checks in `system`
- WFA-013: checkout persist-credentials audit

## [0.1.0] - 2026-09-28

First tagged release. argus is one static binary. Point it at a local
checkout, a GitHub, GitLab or Gitea account, a container image, a web
page, or the machine it is running on.

It looks for known supply-chain campaigns (Shai-Hulud, TeamPCP, typosquats
and an actor watchlist), leftover secrets, bad lockfile hygiene, and
unsafe workflow, container and host settings. Built-in rules ship with
the binary. Extra rules load from a directory or a git feed.

Reports print in the terminal, or as JSON, Markdown, SARIF, Code Climate
or a single HTML file. In CI it can fail the job on a severity, or only
on findings that are new since a saved baseline.

A few commands sit beside the scan. `fix` pins GitHub Actions to commit
SHAs. `verify` checks whether a found token still works. `publish` scans
the files that would actually ship. `watch` and `daemon` recheck a repo
when it changes. `sbom` writes CycloneDX.

[0.1.0]: https://github.com/Quad4-Software/argus/tree/v0.1.0
