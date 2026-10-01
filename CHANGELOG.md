# Changelog

## [Unreleased]

## [0.3.0] - Unreleased

The next release is 0.3.0. There is no 0.2.1.

- campaign rules for Nx s1ngularity, Shai-Hulud 2.0, the Sept 2025 qix
  phishing wave, the axios RAT, the keyv/cacheable worm, and MemTensor sckit
- package version checks no longer treat a longer version as a hit
  (6.0.0 does not match 16.0.0, 5.6.1 does not match 5.6.10)
- `--progress auto|always|never` + `defaults.progress`: live stderr
  spinner with file and finding counters while scanning (auto = tty
  only, hidden under `-v`)
- elapsed time on the text/markdown `Scan:` summary line (kept out of
  JSON so report bytes stay deterministic)
- `argus rules` colorizes the severity column. Text output prints a
  green `no findings` line on a clean run
- crate renamed to `argus-scanner` for crates.io (binary stays `argus`)
- defensive OSINT commands: `domain`, `email`, `ip`, `hash`, `url`,
  `ports`, `intel`, `account`, `socials`, `feed`, `gitmeta`
- `intel` queries OTX, ThreatFox, Feodo, and CIRCL. A missing key is
  inconclusive, not a failed scan
- tracker and analytics detection, including Cloudflare edge and
  Cloudflare Insights. The label is a product name, not a legal claim
- WAF and challenge-page markers (Anubis, Altcha, Cap, SHA-256 proof of
  work, SafeLine, BunkerWeb, and common commercial products). Markers
  are reported. Challenge pages are not solved
- port checks are TCP connect, with modern ports first. No SYN, decoy,
  or wide CIDR sweeps
- optional store for reports: SQLite by default, Postgres with
  `--features postgres`, SurrealDB over its HTTP API. `records` searches
  what `--store` saved
- local API on `127.0.0.1:9876`, signed webhooks, and an MCP stdio
  server (initialize `2025-06-18` and `2025-11-25`, plus `server/discover`
  for `2026-07-28`). ACP is not implemented
- `supply` walks nested npm trees, `go.sum`, and NuGet direct and
  transitive packages
- `stego` reports appended payloads and zero-width text. It does not
  extract a hidden message
- `codec` is RFC 4648 base64 and base32. Output is printed, not executed
- `style` is a pairwise prose or code distance. It is a lead, not an
  identification
- `account` reads public GitHub and GitLab profiles. `socials` extracts
  profile and resume links, including link-in-bio hubs. `feed` reads
  RSS, Atom, and JSON Feed. `gitmeta` reads local authors and a public
  `.git/HEAD` plus config when that file is exposed. Git objects are
  not downloaded
- `grep` streams text, CSV, TSV, JSON, JSONL, and SQLite. Lines over
  1 MiB are skipped, matches print as they are found, and SQLite is
  opened read-only with bound parameters. Hits are not stored, uploaded,
  or exposed as an MCP tool
- `extract` pulls emails, URLs, addresses, hashes, and wallet-shaped
  strings. A report keeps a sample. `grep --pick` is the full stream
- `meta` reads PDF, JPEG, PNG, and docx metadata by seeking. It is a
  subset of a full EXIF tool
- `dork` prints search links only. Nothing is fetched
- `favicon` computes the published Shodan `http.favicon.hash` and FOFA
  `icon_hash` locally. Shodan is not queried
- `user` checks one username against a small public API table (GitHub,
  GitLab, Codeberg, crates.io, Keybase). It does not call password-reset
  endpoints
- `modules` lists built-in commands from `src/catalog.rs`. Dropping a
  command means deleting its source, its catalog row, and its CLI arm
- domain page files now include `ads.txt` and `humans.txt` beside
  robots, security.txt, and llms.txt
- `web` reads cookie attributes instead of searching the raw header,
  treats HSTS `max-age=0` as unset, and flags CSP `unsafe-inline` or
  `unsafe-eval`. COOP and CORP are reported when missing
- page description, Open Graph, Twitter, and generator tags are read
  by `domain`, `url`, and `web`. An em dash in those fields is an info
  lead. It is not an identification
- `domain` asks Quad9 and AdGuard whether a name that Cloudflare still
  answers is blocked. A block is a reputation lead
- `media` looks for C2PA blocks (JPEG APP11, PNG caBX, ISO boxes),
  IPTC `trainedAlgorithmicMedia`, and a short list of generator tags
  in images, audio, and video. It reads the head and tail of large
  files. A square canvas is noted only next to another marker. The
  manifest signature is not checked
- `python` ruleset covers pickle loads, unsafe `yaml.load`,
  `shell=True`, `eval`/`exec`, disabled TLS checks, and `tempfile.mktemp`

## [0.2.0] - 2026-09-29

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

[0.2.0]: https://github.com/Quad4-Software/argus/tree/v0.2.0
[0.1.0]: https://github.com/Quad4-Software/argus/tree/v0.1.0
