# Changelog

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
