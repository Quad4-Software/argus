# argus

argus is a supply-chain security and repository-forensics scanner. It reads
repositories, CI workflows, container images, web front-ends, and the host
itself, then reports concrete problems: leaked secrets, known-bad action
tags, malicious package versions, dependency-confusion exposure, weak
workflow and container configuration, and evidence that a repo's history
does not match its claimed authorship.

## What it does

- Finds secrets and checks whether they still work
- Detects known compromise campaigns (Shai-Hulud, TeamPCP, litellm)
- Audits CI workflows for the patterns those campaigns used
- Checks dependencies against OSV advisories and registry hygiene
- Audits Dockerfiles, compose files, Kubernetes manifests, and images
- Audits web responses: headers, cookies, TLS, exposed paths, JS bundles
- Audits the host: kernel, sshd, accounts, services, logging (Lynis-class)
- Watches repositories and feeds for new pushes, diffs, maintainer changes
- Scores repositories for evidence of agent-generated authorship

## The 30-second tour

```sh
cargo install --path .
argus scan .                          # this repo, all rulesets
argus github --org my-org             # everything in the org
argus web https://example.com         # web audit + client-js secrets
argus system                          # host hardening audit
argus scan . --format sarif -o r.sarif  # CI-ready output
```

Findings include a severity, a stable rule id, the file and line, the
matched evidence, and a remediation hint. Exit code 1 when findings meet
`--fail-on`, 0 otherwise, 2 on operational error.

## Design notes

- One static binary, no daemon required for normal scanning
- Rules live in TOML and can be replaced or extended without rebuilding
- Scans run under Linux Landlock: no network for local scans, read-only
  filesystem, writes only where the command needs them
- Everything argus can do is also a `cargo test` contract: the ruleset
  corpus and the arch gate keep new rules and code honest
