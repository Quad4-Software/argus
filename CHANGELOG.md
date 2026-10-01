# Changelog

## [0.3.0] - Unreleased

The crates.io package is `argus-scanner`. The command you run is still `argus`.

A scan on a terminal shows a progress line with the file count and the finding count. `--progress auto` does that only on a tty, `always` forces it, and `never` keeps stderr quiet. `-v` hides the line because the verbose log already says what is happening. The text and markdown summary includes how long the scan took. JSON leaves that number out, so two runs of the same tree still match byte for byte. `argus rules` colors the severity column, and a clean text run prints `no findings` in green.

Version checks compare the whole version. `6.0.0` is not treated as `16.0.0`, and `5.6.1` is not treated as `5.6.10`. Campaign rules cover Nx s1ngularity, Shai-Hulud 2.0, the September 2025 qix phishing wave, the axios RAT, the keyv/cacheable worm, and MemTensor sckit.

The new lookup commands are `domain`, `email`, `ip`, `hash`, `url`, `ports`, `intel`, `account`, `socials`, `feed`, and `gitmeta`. `intel` asks OTX, ThreatFox, Feodo, and CIRCL, and a missing API key is an inconclusive row rather than a failed scan. `ports` is a TCP connect scan that tries common modern ports first. It does not send SYN packets, decoys, or a wide CIDR sweep. `account` reads a public GitHub or GitLab profile. `socials` pulls profile and resume links from a page, including link-in-bio hubs. `feed` reads RSS, Atom, and JSON Feed. `gitmeta` reads author names from a local checkout, and it reads `.git/HEAD` and config when a site leaves those files public. It does not download git objects. `dork` only prints search links. `favicon` computes the Shodan `http.favicon.hash` and the FOFA `icon_hash` on this machine and does not call Shodan. `user` checks one name against GitHub, GitLab, Codeberg, crates.io, and Keybase. It does not hit password-reset forms.

`domain` also fetches `ads.txt` and `humans.txt` next to robots, security.txt, and llms.txt. If Cloudflare still resolves a name but Quad9 or AdGuard refuses it, that block is reported as a reputation lead. `web` parses cookie attributes instead of searching the raw header, treats HSTS `max-age=0` as unset, and flags CSP `unsafe-inline` or `unsafe-eval`. Missing COOP and CORP are reported. The same page read covers CORS `*`, CORS `null`, TRACE in the allow list, mixed content, a directory listing, a database error, a cacheable session cookie, and a public `server-status`, `actuator/env`, pprof, or `phpinfo.php` page. `email` flags SPF `+all` or `?all`, DMARC `p=none`, MTA-STS still in testing, and BIMI on a domain that does not quarantine or reject. `chat` looks up XMPP and IRC SRV records and does not open a connection.

Tracker and analytics names are detected on a page, including Cloudflare edge and Cloudflare Insights. The name is the product, not a legal finding. Challenge pages are recognized for Anubis, Altcha, Cap, a SHA-256 proof of work, SafeLine, BunkerWeb, and the usual commercial WAFs. The marker is reported. The challenge is not solved.

`domain`, `url`, and `web` read the page description, Open Graph, Twitter, and generator tags. An em dash in one of those fields is an info lead. It does not mean the page was written by a model. `media` looks for C2PA blocks (JPEG APP11, PNG caBX, ISO boxes), IPTC `trainedAlgorithmicMedia`, and a short list of generator names in images, audio, and video. Large files are read at the head and the tail. A square canvas is mentioned only when another marker is already there. The C2PA signature is not checked.

Reports can be stored. SQLite is the default, Postgres needs `--features postgres`, and SurrealDB is used over its HTTP API. `records` searches what `--store` saved. `api` listens on `127.0.0.1:9876`. Webhooks are signed. The MCP server speaks initialize `2025-06-18` and `2025-11-25`, and `server/discover` for `2026-07-28`. `supply` walks nested npm trees, `go.sum`, and NuGet packages, direct and transitive.

`grep` streams text, CSV, TSV, JSON, JSONL, and SQLite. A line over 1 MiB is skipped, matches print as they are found, and SQLite is opened read-only with bound parameters. Those hits are not stored, uploaded, or exposed as an MCP tool. `extract` keeps a sample of emails, URLs, addresses, hashes, and wallet-shaped strings. `grep --pick` is the full stream. `codec` encodes and decodes RFC 4648 base64 and base32 and prints the result. `style` is a pairwise distance between two prose or code samples. A close score is a lead, not an identification of who wrote the text. `modules` prints the command list from `src/catalog.rs`.

`meta` reads PDF info and XMP, JPEG and WebP Exif (including a GPS fix when the file has one), PNG text chunks, GIF comments, ID3 title and artist frames, and docx `core.xml`. It also prints the file size and modification time. `stego` still looks for bytes after an image, PDF, or zip end marker, and for zero-width characters. When that tail is readable text, the finding includes it. Unicode tag characters and a zero-width bit string are turned back into text. The tool does not rebuild a message out of pixel bit planes.

`conns` lists sockets with the process name and, for up to 16 public addresses, a reverse name. It can sample while a command runs. An allow file fails the process when something connects outside the list, and cloud metadata addresses fail even if you wrote them down. `files` lists the executable, working directory, and open files for each process. `--path` limits that to one file or directory, so you can see which process has it open. It polls while `--watch` or a command is running, and it will miss a file that is opened and closed between samples. `signatures` streams hash rows from ClamAV `main.cvd` and `daily.cvd`, plus a few file heuristics. Bytecode signatures are not run. The cache refreshes unless you pass `--no-update`. `threats` looks for a preload library, a cron line that downloads into a shell, browser files staged under temp, a running binary whose path is deleted, and a module list that does not match sysfs.

`system` now also reads the firewall default policy, systemd-resolved DNSSEC and DNS-over-TLS, the NTP allow list, Secure Boot and kernel lockdown, the CPU vulnerability files, GRUB, unit files under `/etc/systemd/system`, processes holding `/dev/input/event*`, remote logins from `who`, and enabled serial consoles. The running kernel version is compared with the upstream fixes for CVE-2025-39682, CVE-2025-39964, and CVE-2026-53266. A distribution kernel can already contain the backport even when `uname` looks older than those patch numbers. Firmware chip images are not scanned.

Source checks grew past the Python rules (pickle, `yaml.load`, `shell=True`, `eval` and `exec`, TLS verification turned off, `tempfile.mktemp`). JavaScript, Go, Java, PHP, Ruby, and C# rules look for command execution, deserialization, SQL built from a request value, and TLS checks turned off. `owasp` covers a JWT `none` algorithm and a secret written to a log. `agent` covers model text passed into a shell. These are text matches. They cannot decide broken object authorization, and they cannot decide whether a prompt would jailbreak a model.

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
