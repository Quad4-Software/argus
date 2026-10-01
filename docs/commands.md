# Commands

Global options apply to every command: `--format`, `--output`,
`--severity`, `--fail-on`, `--color`, `--progress`, `--jobs`,
`--exclude`, `--offline`, `--no-sandbox`, `--baseline`, `--vex`,
`--vex-out`, `--staged`, `--diff`, `-v/-vv`.

`--progress` draws a live spinner with file/finding counters on stderr
(`auto`: tty only, hidden with `-v`; `always`/`never` force it).

## scan [paths]

Scan local files with the full ruleset set. Defaults to `.`.

```sh
argus scan . --osv --dep-check     # files + dependency advisories + hygiene
argus scan . --include-git         # also read .git internals
argus scan . --diff origin/main    # only files changed vs a ref
argus scan . --staged              # only staged files (pre-commit use)
argus scan . --yara rules/yara     # real YARA evaluation (default build)
argus scan . --iocs iocs.txt       # flat IoC list, one per line
```

## github / gitlab / gitea

Enumerate and scan remote repositories. Pick a scope with `--org`,
`--user`, or `--me` (needs a token).

```sh
argus github --org Quad4-Software
GITLAB_TOKEN=... argus gitlab --org my-group --host gitlab.example.com
argus github --org my-org --settings     # + org/repo security settings
```

Filtering: `--skip-archived`, `--skip-forks`, `--skip-private`,
`--limit`, `--updated-since`, `--updated-before`, `--workdir`.

## domain &lt;name&gt;

Public records for one domain. DNS over HTTPS including PTR, RDAP, certificate names, passive host indexes, Wayback host names, the homepage title, description meta, and mailboxes, response headers, WAF and challenge markers, analytics and advertising tags, robots.txt, ads.txt, humans.txt, llms.txt, tdmrep.json, security.txt, the Hudson Rock free index, and public urlscan results. Quad9 and AdGuard are compared with Cloudflare for filter blocks. Certificate names fall back to another log when Cert Spotter is rate limited.

```sh
argus domain quad4.io
argus --format json domain https://quad4.io
```

## email &lt;address&gt;

Public records for one mailbox. Syntax, role, provider, and disposable catalogs, then MX, SPF, DMARC, BIMI, TLS-RPT, MTA-STS, DKIM selectors, DNSSEC, SRV, DANE, the mail host network, RDAP, certificates, autoconfig, security.txt, Gravatar, and OpenPGP (WKD, VKS, HKP, and DNS OPENPGPKEY). Have I Been Pwned breach and paste lookups run when HIBP_API_KEY is set. The Hudson Rock free index is checked for infostealer exposure. Pass `--smtp` to ask the mail server whether the address is accepted. That check is off by default. A miss in a catalog is not proof the address is private.

```sh
argus email argus@quad4.io
argus --format json email argus@quad4.io
argus email --smtp argus@quad4.io
```

## ip [address]

Geolocation, origin ASN, proxy and VPN classification, reverse DNS, RDAP, Shodan InternetDB, and the Hudson Rock free index for one public address. `--download` saves the DB-IP City Lite database in the cache so later lookups work with `--offline`. That database is CC BY 4.0. Results that use it keep the DB-IP attribution. The VPN row reports the proxycheck.io verdict.

```sh
argus ip 1.1.1.1
argus ip --download
argus --offline ip 1.1.1.1
```

## hash &lt;digest&gt;

Look up an MD5, SHA-1, or SHA-256 hex digest in CIRCL hashlookup. A hit is a known file. If the record names a malware source, that source is listed separately. MalwareBazaar is checked only when `ABUSECH_AUTH_KEY` is set. No sample is downloaded.

```sh
argus hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

## url &lt;url&gt;

Fetch one public http or https URL. Redirects are followed up to five hops, and a hop to a loopback, private, or link-local address is refused. The report includes the status, the redirect chain, WAF and challenge markers, analytics and advertising tags, and public urlscan results for the host. A missing marker is not proof that the site is unprotected. Markers cover common commercial WAFs plus Anubis, Altcha, Cap, a generic SHA-256 proof of work page, SafeLine, and BunkerWeb.

```sh
argus url https://quad4.io
```

## ports &lt;host&gt;

TCP connect scan of one host. The default list starts with the ports people run now (443, 80, 8443, 8080, application ports, then mail, databases, and admin services). `--ports` takes a comma list or ranges. `--all` checks ports 1 through 65535 and still tries the modern list first. A network range is refused, as are link-local and multicast addresses. Closed means the host refused the connection. Filtered means it did not answer in time.

```sh
argus ports 127.0.0.1 --ports 22,80,443
argus ports quad4.io
```

## web &lt;url&gt;

Fetch a URL and audit the response: security headers (including COOP and CORP), cookie flags parsed from attributes, HSTS with a zero max-age, CSP sources that allow unsafe-inline or unsafe-eval, server disclosure, TLS expiry, exposed `/.git`, `/.env`, `/.aws/credentials` (with SPA-fallback detection), `robots.txt`, `security.txt`, generator and description meta, and secrets embedded in inline and bundled JavaScript and source maps. An em dash in a description field is an info lead. `--depth N` crawls same-origin links (max 30 pages).

## image &lt;ref&gt;

Audit a container image through docker or podman: root user, `latest`
tag, baked-in env secrets, secret-looking history entries. `--deep`
exports the filesystem and runs the full rules engine; with `--osv` it
also maps dpkg/apk package lists to advisories.

## system

Lynis-class host audit: sysctl hardening, account and file
permissions, sshd configuration, risky listeners and services,
firewall presence, logging, integrity tooling, home directory modes,
and quick malware checks (`ld.so.preload`, `/tmp` executables,
deleted-but-running binaries).

## similar &lt;a&gt; [b]

Code similarity scoring using normalized-token winnowing fingerprints
(MOSS/SCANOSS lineage). Two paths print similarity findings for every
matching pair; one path finds near-duplicate pairs inside it.
Tokenization normalizes identifiers and literals, so renaming does not
hide copying. `SIM-001` (jaccard over 70%) marks likely vendored code,
`SIM-002` marks embedded copies inside larger files.

```sh
argus similar file.rs other.rs         # pair score
argus similar src/                     # near-dups inside the tree
argus scan . --similar /opt/reference  # flag files copied FROM the reference
```

## secrets / history

```text
argus scan <repo> --history-secrets
```

Scans `git log -p` for secrets committed and later removed (up to 500
commits). Secrets flagged in history must be rotated - deleting the file
does not help.

## review [paths]

Interactive triage: runs the normal scan then walks findings one by
one. `d` shows detail, `s` appends `RULE path` to `.argusignore`, `q`
quits.

## trends <path>

Diff the two most recent stored scans of a root: `+new`, `-fixed`,
persistent count. Requires `argus scan <path> --store` to have run at
least once. Stored in `~/.local/share/argus/argus.db`.

## ruleset signing

Custom `--rules` files can carry detached ed25519 signatures
(`<file>.toml.sig`). With `--rules-pubkey <file>` argus refuses unsigned
or tampered rulesets - builtin rules are always trusted.

```text
argus rules-keygen --privkey key.priv --pubkey key.pub
argus rules-sign rules.toml --key key.priv
argus scan . --rules rules.toml --rules-pubkey key.pub
```

## incremental scans + suppressions

`argus scan <path> --incremental` reuses findings for files whose
mtime+size and ruleset fingerprint are unchanged. Cache lives in
`~/.cache/argus/<root-hash>.json`.

`.argusignore` at a scan root suppresses findings:

```text
SEC-001                    # rule id, everywhere
SEC-001 tests/fixtures/**  # rule id under a glob
* vendor/                  # everything under a path
```

## verify [paths]

Extract provider-shaped tokens from scan paths and ask the provider
whether each is still valid. Live credentials report as critical
(`VER-001`); dead ones as info (`VER-002`). Tokens are masked in output
and capped at 25 checks per run.

## fix [paths]

Dry-run remediation. Without `--write` it prints before/after edits.

- Workflows: pin mutable `uses:` refs to commit SHAs (tag kept as a
  comment), inject a top-level `permissions: {}` when missing.
- `--containers`: inject `USER` before CMD/ENTRYPOINT, pin FROM digests
  (via crane/skopeo/docker/podman), add `no-new-privileges` to compose
  services lacking it.
- `--iac`: flip unsafe IaC booleans - `encrypted`, `deletion_protection`,
  `skip_final_snapshot`, `map_public_ip_on_launch`, `acl = "public-*"`.
- `--deps`: rewrite pinned deps (`requirements.txt`, `Cargo.toml`) to
  the first OSV-fixed version. Queries OSV (fetches full advisories for
  fix fields); needs network.

## license [paths]

Detect the project license, compare it with manifest fields, and with
`--deps` check dependency licenses against a copyleft list.

## publish [path]

Scan only what a package would actually ship: `npm pack --dry-run`,
`cargo package --list`, or `git ls-files` as fallback. Catches secrets
and internal files that tree scans never notice.

## sbom [path]

Emit a CycloneDX 1.5 or SPDX 2.3 SBOM from lockfiles.

```text
argus sbom .                  # CycloneDX (default)
argus sbom . --format spdx    # SPDX 2.3
```

## dependency reachability

OSV hits for deps never referenced in source get downgraded to medium
and tagged "(no source reference - likely not reachable)". It's a
content heuristic, not a callgraph - the signal stays honest.

## taint rules

`type = "taint"` tracks variables assigned from `source`-matching
expressions and fires when a `sink` line references a tainted var.
Sequential and intra-file only - no interproc or branch tracking, but a
real upgrade from whole-file co-occurrence.

## authors [paths]

Commit-author identity analysis plus optional watchlist checks.

## ai [paths]

Evidence-tiered AI-provenance report: agent trailers, agent config
files, volume velocity, history integrity, provenance laundering, and
human-agency counter-evidence. Output is a score with named evidence,
never a bare verdict.

## roam

Search remote forges for repositories matching a topic or code pattern
and scan them.

## watch / daemon

Continuous monitoring. `watch` polls `git ls-remote` plus optional
RSS/Atom feeds; `daemon` adds an HTTP control plane and signed
webhooks (`/healthz`, `/report`, `/state`, `/scan`,
`/webhook/{github,gitlab,gitea}`). Pushes rescan only the changed
files, diff the dependency set (added/removed/version-changed), and
with `--dep-watch` alert on registry maintainer changes.

## init

Install a pre-commit hook running `argus scan --staged --fail-on medium`.
`--force` overwrites an existing hook.

## intel &lt;indicator&gt;

Look up an IP, domain, URL, or file hash. AlienVault OTX runs when `OTX_API_KEY` is set. ThreatFox runs when `ABUSECH_AUTH_KEY` is set. Feodo Tracker is a public botnet IP list and needs no key. File hashes also go to CIRCL hashlookup. A miss is not proof the indicator is safe.

```sh
argus intel 1.1.1.1
argus --store intel example.com
```

## supply [path]

Walk a project tree for lockfiles and count the pinned closure, including nested npm dependencies, `go.sum`, and transitive NuGet locks. `node_modules` and build output are skipped.

```sh
argus supply .
```

## records &lt;query&gt;

Search records saved with `--store`. The default driver is SQLite at `~/.local/share/argus/argus.db`. Set `ARGUS_STORE_URL` or `[store] url` to `postgres://...` (build with `--features postgres`) or `surreal://user:pass@host:8000/namespace/database`.

```sh
argus --store domain example.com
argus records example.com
```

## api

Local JSON API on `127.0.0.1:9876`. `GET /health`, `GET /v1/records?q=`, `POST /v1/intel` with `{"indicator":"..."}`, `POST /v1/account`, `POST /v1/socials`, `POST /v1/feed`, and `POST /v1/trackers` with `{"url":"..."}`.

Outbound webhooks are `[[webhook]]` entries in the config, with `url` and optional `events`. `ARGUS_WEBHOOK_SECRET` signs the body as `X-Argus-Signature: sha256=...`. Link-local webhook targets are refused.

```sh
argus api
argus api --listen 127.0.0.1:9876
```

## stego [path]

Look for appended bytes after PNG, JPEG, GIF, BMP, RIFF, PDF, and ZIP end markers, odd PNG chunks, and zero-width characters in text. A hit means a channel is present. The hidden message is not extracted.

```sh
argus stego ./images
```

## codec &lt;encode|decode&gt; &lt;base64|base32&gt; [text]

RFC 4648 base64 and base32. Omit the text or pass `-` to read stdin. The result is printed and not executed.

```sh
argus codec encode base64 hello
argus codec decode base32 MZXW6YTBOI======
```

## style &lt;a&gt; &lt;b&gt;

Pairwise style distance. Prose uses English closed-class word rates and character trigrams. Code adds layout ratios such as indent, identifier shape, and comment density. There is no reference corpus, so this is not a calibrated percentile. The result is a lead, not an identification. Short samples are marked unreliable.

```sh
argus style notes/a.md notes/b.md
argus style --kind code src/a.rs src/b.rs
```

## account &lt;github|gitlab&gt; &lt;login&gt;

Public profile age, followers, following, repo counts, stars, forks, and social links from the profile site. GitHub works without a token. GitLab often hides created date and follower counts unless `GITLAB_TOKEN` is set. `GITHUB_TOKEN` raises the GitHub rate limit. Tokens are not printed.

```sh
argus account github octocat
argus account gitlab dzaporozhets
```

## socials &lt;url&gt;

Extract social profile links and resume or CV document links from one public page. Link-in-bio hosts (linktr.ee, bio.link, beacons.ai, solo.to, carrd, and similar) are fetched and parsed with the same extractor. A challenge page is reported as a challenge. It is not solved.

```sh
argus socials https://example.com
```

## feed &lt;url&gt;

Fetch an RSS, Atom, or JSON feed and list titles, links, and dates. `--query` filters titles and summaries. `--store` keeps the report for a later `records` search.

```sh
argus feed https://blog.rust-lang.org/feed.xml --query rust
```

## gitmeta [path-or-url]

Local git author and committer names, emails, first and last dates, remotes, and addresses in `.mailmap`, Cargo.toml, package.json, and pyproject.toml. A public URL is checked for `.git/HEAD` and, when that is exposed, `.git/config`. Passwords in URLs are removed. Git objects are not downloaded.

```sh
argus gitmeta .
argus gitmeta https://example.com
```

## grep [pattern] [paths...]

Stream a search over text, CSV, TSV, JSON, JSONL, or SQLite. Matches print as they are found. The file is not loaded whole. A line longer than 1 MiB is skipped. Binary files (a NUL in the first 8 KiB) are skipped. Directories skip `.git`, `node_modules`, `target`, and `vendor`.

The first positional is the regex and the rest are paths. When `--pick` or `--eq` is set, every positional is a path. Pass `--pattern` when a regex is combined with those filters.

`--kind` is `auto`, `text`, `csv`, `tsv`, `json`, `jsonl`, or `sqlite`. Auto follows the extension. `--column` picks a CSV header or a JSON field (one dot is allowed). `--eq` is an exact field value. `--pick` is `emails`, `urls`, `addrs`, `hashes`, or `wallets`. `-i` makes the regex case-insensitive. `--max` stops after N matches (default 100, `0` means no cap). `--table` limits a SQLite walk to one table.

SQLite is opened read-only with `query_only`. Table and column names must be identifiers. Values are bound parameters. Output is not written back, not saved with `--store`, and not exposed as an MCP tool. Pass `-` to read stdin. JSON, SARIF, and Code Climate formats print one JSON object per match.

```sh
argus grep --column email --eq ada@example.com rows.csv
argus grep --pick emails ./notes
argus grep -i 'example\.com' dump.jsonl --max 0
```

## extract &lt;target&gt;

Emails, URLs, addresses, hashes, and wallet-shaped strings from a file, a public URL, or a short blob. A file read stops at 8 MiB and the report keeps 40 values per kind. `grep --pick` is the exhaustive stream. A hit is a lead.

```sh
argus extract notes.txt
argus extract https://example.com
```

## meta &lt;path&gt;

PDF, JPEG, PNG, and docx metadata. PDF reads the head and tail for Author, Creator, Producer, Title, and CreationDate. JPEG reads early Exif tags. PNG text chunks are skipped by size. docx reads `docProps/core.xml` from the zip when the method is stored or deflate. This is a subset of a full metadata tool.

```sh
argus meta report.pdf
```

## media [path]

Provenance markers in images, audio, and video. JPEG APP11 and PNG caBX chunks are read as C2PA content credentials. IPTC `trainedAlgorithmicMedia` and a short generator list (Midjourney, Stable Diffusion, Firefly, ElevenLabs, and similar) are read from metadata regions. Audio and video are checked at the head and tail so a large file is not loaded. A common square canvas is mentioned only when another marker is present. The C2PA signature is not validated. A missing marker does not mean the file is human-made.

```sh
argus media ./photos
```

## dork &lt;query&gt;

Search links for a domain, email, or name. The command prints URLs (archives, certificate logs, urlscan, site and filetype queries, code search). Nothing is fetched and nothing is cached.

```sh
argus dork example.com
argus dork argus@quad4.io
```

## favicon &lt;url&gt;

Download one public favicon (1 MiB cap) and print the MurmurHash3 used by Shodan `http.favicon.hash` and FOFA `icon_hash`. The hash is computed locally. Shodan is not queried.

```sh
argus favicon https://example.com
```

## user &lt;name&gt;

One username against a small public API table: GitHub, GitLab, Codeberg, crates.io, and Keybase. A 200 with the expected key is a lead. A 404 is absent. Anything else is inconclusive. Add or remove a site by editing `SITES` in `src/osint/user.rs`. This does not call password-reset or login endpoints.

```sh
argus user octocat
```

## modules

Print the built-in command list from `src/catalog.rs`. Removing a command means deleting its source, its catalog row, and its CLI arm.

```sh
argus modules
```

## mcp

Stdio JSON-RPC server. Legacy clients use `initialize` (protocol `2025-06-18` or `2025-11-25`). Current clients can call `server/discover` and send protocol `2026-07-28` on each request. Tools include `scan`, `scan_system`, `list_rules`, `intel`, `store_search`, `supply`, `stego`, `codec`, `style`, `account`, `socials`, `feed`, and `gitmeta`. `grep` and `extract` stay off this list so local file contents are not sent to a model.

ACP is the editor-to-agent protocol. Argus is not a coding agent, so automation goes through MCP, the local API, and webhooks.

## rules / rules-update / completions

`rules` lists loaded rulesets and rules; `rules-update --feed <git-url>`
pulls a rules repo into `~/.config/argus/rules`; `completions <shell>`
prints shell completions.
