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
argus scan . --verify-secrets      # check found tokens against issuer APIs (network)
argus scan . --no-prune            # walk ignored, vendored, and build dirs too
argus scan . --no-enrich           # skip EPSS/KEV annotation of advisory findings
```

The walk honors `.gitignore`, `.ignore`, and git excludes, and prunes
vendored and build directories (`node_modules`, `target`, `dist`,
`vendor`, `.venv`, `__pycache__`, and similar). `--no-prune` disables
both. Secret-shaped names that ignore rules hide (`.env`, key material,
credential stores) are still collected. Advisory findings from `--osv`
carry an EPSS score and a KEV marker unless `--no-enrich` is passed;
enrichment is skipped in offline mode. `--verify-secrets` sends a token
only to the provider whose shape it matches.

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

Open SPF (`+all`, `?all`), DMARC `p=none`, MTA-STS `testing`, and BIMI without quarantine or reject are called out as their own rows.

## chat &lt;domain&gt;

XMPP and IRC DNS SRV records for one domain: client and server, STARTTLS and direct TLS. A cleartext IRC SRV without an IRC-over-TLS SRV is reported. This command does not connect.

```sh
argus chat example.com
```

## files

Open files for processes on this host. Linux `/proc/<pid>` supplies the executable, the working directory, and fd symlinks. With no `--path`, the report is a snapshot of those paths. `--path` keeps only that file or the files under that directory, so you can see which process has a folder open. `--watch N` polls for N seconds. A command after `--` is sampled until it exits, and the process stays unsandboxed so the command can run. A process that opens a file and closes it between samples will not appear.

```sh
argus files
argus files --path /var/log
argus files --watch 5 --path /tmp
argus files --path ./build -- cargo test
```

## conns

Sockets from `/proc/net` on Linux, with the process name when the inode can be matched. Public addresses get a reverse name, up to 16. `--watch N` samples for N seconds. A command after `--` is sampled until it exits, and the process stays unsandboxed so the command can run.

`--allow file` is the CI check. Each line is an IP, `ip:port`, a name, `name:port`, `*:port`, or an IPv4 CIDR. Outbound sockets that are not listed fail the process. Cloud metadata addresses (`169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`) fail even when listed. Names in the allow file are resolved when the command is not `--offline`.

```sh
argus conns
argus conns --allow ci-allow.txt -- cargo test
```

## signatures [path]

Hash signatures plus file heuristics. With no `--db` and no `--no-update`, a cached database older than `--max-age-hours` (default 24) is replaced from the ClamAV daily CVD. That mirror only answers clients whose agent starts with `ClamAV/1`, so the request is `ClamAV/1.4.3 (argus/version)`. `main.cvd` is loaded first and `daily.cvd` is appended. Only `.hsb` and `.hdb` rows are kept. The scan hashes the tree first and streams the signature file once. ClamAV bytecode is not executed. Heuristics cover a double extension, UPX on an executable, a script after image bytes, and high entropy in an executable. Those are leads.

```sh
argus signatures ./downloads
argus --offline signatures --no-update --db hashes.txt ./downloads
```

## threats

Reads a tree (default `/`) for `ld.so.preload`, cron lines that download a script into a shell, browser credential filenames under temp, a process whose executable is deleted, module names present in sysfs and missing from `/proc/modules`, and pinned bpf objects. A hit is a lead.

```sh
argus threats
argus threats --root /tmp
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

Fetch a URL and audit the response. Headers include CSP, HSTS, COOP, CORP, and cookie flags. The body is checked for mixed content, directory listings, stack traces, and a cacheable `Set-Cookie`. CORS `*`, `null`, and TRACE are reported from the headers that came back. Exposed paths include `/.git`, `/.env`, `/.aws/credentials`, Apache `server-status`, Spring `actuator/env`, Go pprof, and `phpinfo.php`, with SPA-fallback detection. `robots.txt`, `security.txt`, generator meta, and secrets in inline and bundled JavaScript are included. An em dash in a description field is an info lead. `--depth N` crawls same-origin links (max 30 pages). This pass does not send attack strings, and it cannot decide broken object authorization.

## image &lt;ref&gt;

Audit a container image through docker or podman: root user, `latest`
tag, baked-in env secrets, secret-looking history entries. `--deep`
exports the filesystem and runs the full rules engine; with `--osv` it
also maps dpkg/apk package lists to advisories.

## system

Lynis-class host audit: sysctl hardening, account and file
permissions, sshd configuration, risky listeners and services,
firewall presence and default-accept policies, DNSSEC and DNS-over-TLS
in systemd-resolved, NTP clients, Secure Boot, lockdown, the kernel's
own CPU vulnerability files, GRUB passwords and command lines, local
systemd units, input-device readers, remote logins, and serial consoles.
It also compares `uname` with the upstream fixes for three kernel flaws
on the CISA known-exploited list as of 18 September 2026. A distribution
kernel can carry those fixes without the upstream patch number. Firmware
chip images are not scanned.

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
argus similar corpus/ --index-build    # fingerprint a reference corpus
argus similar src/ --index-query       # LSH lookups against the index

`--index-build` writes MinHash bands to a SQLite index (default
`~/.local/share/argus/similar.db`, `--index FILE` overrides). `--index-query`
compares files under the path against indexed candidates; a band hit is
confirmed with the exact Jaccard and containment checks used by pair mode.
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

## attest <bundle> [--artifact f] | --npm pkg[@ver] | --sig s --cert c

Verify supply-chain signatures and attestations offline, without
installing cosign. Three modes:

* a sigstore bundle file (`.sigstore.json`, `.bundle`) - DSSE envelope
  signature under the embedded Fulcio cert, certificate chain to the
  pinned Fulcio roots, Rekor signed-entry-timestamp, compact merkle
  inclusion proof, and signed checkpoint note. `--artifact` also checks
  the sha256/sha512 of a file against the attested subject digest.
* `--npm name@ver` fetches npm publish attestations and verifies each
  bundle, including registry-key `publicKey` attestations whose signing
  key is recovered from the Rekor entry.
* `--sig s --cert c --artifact blob` verifies a legacy cosign detached
  signature over a blob.

`--rekor-pub FILE` swaps the transparency-log key for a private rekor
instance (P-256, P-384 or RSA PEM). Without it, any tlog entry whose
logId does not match the embedded production key fails closed with an
"unknown rekor instance" error rather than being silently untrusted.
Signer certs may be ECDSA P-256/P-384 or RSA-PKCS1v15
(SHA-256/384/512) - only the Fulcio roots embedded under trust/ are
accepted as chain heads.

A fully checked bundle reports `VERIFIED` (`AT-001`); a missing
transparency-log proof drops to `PARTIAL` (`AT-002`); bad signature or
tampered payload reports `FAIL` (`AT-003`). Fulcio roots and the Rekor
key are embedded under `trust/`, so bundle files verify with no network
at all - `--npm` is the only mode that needs a connection.

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

OSV hits are tagged by how the dep shows up in scanned sources.
An import/require/use of the dep's own spelling (`lodash` -> `require
"lodash"`, `serde-json` -> `use serde_json`, maven group -> `import
group.`) counts as imported and keeps the default severity. A bare name
mention in comments or strings without an import counts as mentioned and
is tagged "(referenced in source, no import found)". A dep that shows up
nowhere is downgraded to medium with "(no source reference - likely not
reachable)".

For Go and crates.io deps there is a second, deeper level: OSV advisories
list the affected symbols (`golang.org/x/net/proxy`'s `FromEnvironment`,
RustSec affected functions). Argus fetches each advisory's symbol list
and greps source files for actual call sites - a referenced vulnerable
symbol upgrades the finding to critical with
`vulnerable symbols referenced: X` evidence, while an advisory whose
symbols are never called stays at its base severity with
`none referenced in sources` evidence. Symbol checks only run when
source roots exist (image and remote scans skip them), and a dep that is
not imported at all is not re-grepped per advisory.

## taint rules

`type = "taint"` tracks variables assigned from `source`-matching
expressions and fires when a `sink` line references a tainted var.
Reassignment to a clean value untaints the name, and `sanitizers` (a list
of RHS regexes such as `encodeURIComponent(` or `escape_string(`) clears
taint instead of spreading it. Scope is tracked loosely: module-level
assignments survive into functions, while same-named locals in different
functions do not share taint. Identifier matches are word-boundary, so
`x` never resolves to `x1` or `foo_x`. Still sequential and intra-file -
no interproc or branch tracking - but a real upgrade from whole-file
co-occurrence.

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

Look for appended bytes after PNG, JPEG, GIF, BMP, RIFF, PDF, and ZIP end markers, odd PNG chunks, and zero-width characters in text. When the tail is mostly text, the finding includes it. Unicode tag characters and a zero-width bit string are decoded back to text when that decoding stays printable. Pixel bit planes are not reconstructed.

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

PDF, JPEG, PNG, GIF, WebP, ID3, and docx metadata, plus the file size and modification time. PDF reads the head and tail for the info dictionary and a short XMP packet. JPEG and WebP read Exif text tags, a GPS fix when the rationals are present, and an XMP packet. PNG reads tEXt, zTXt, and iTXt. GIF reads comment extensions. ID3 reads the common text frames. docx reads `docProps/core.xml` when the zip method is stored or deflate. Image pixels are not loaded.

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
