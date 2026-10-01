# argus

argus is a local security scanner and a defensive OSINT toolkit. It reads
repositories, CI workflows, container images, web pages, public records,
and the host it is running on. It reports leaked secrets, known-bad
packages, weak workflow and container settings, and public facts about a
domain, mailbox, address, or file you already have.

## What it does

- Finds secrets and checks whether they still work
- Detects known compromise campaigns (Shai-Hulud, TeamPCP, Nx, axios, and the Python ruleset)
- Audits CI workflows, Dockerfiles, compose files, Kubernetes manifests, and images
- Checks dependencies against OSV, including nested and transitive locks
- Audits web responses: headers, cookie flags, HSTS, CSP, exposed paths, JS bundles
- Looks up public DNS, mail policy, IP, hash, and URL records
- Reads local file metadata, provenance markers, and streams searches over large files
- Scores copied code by winnowing, and prose or code distance as a lead
- Audits the host: kernel, sshd, accounts, services, logging (Lynis-class)
- Lists sockets and can fail a CI command on unexpected egress
- Scans files with hash signatures and heuristics
- Watches repositories and feeds, and can keep reports in SQLite

## The 30-second tour

```sh
cargo install argus-scanner
argus scan .                          # this repo, all rulesets
argus github --org my-org             # everything in the org
argus web https://example.com         # web audit + client-js secrets
argus domain example.com              # public records for one name
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
