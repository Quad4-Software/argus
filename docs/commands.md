# Commands

Global options apply to every command: `--format`, `--output`,
`--severity`, `--fail-on`, `--color`, `--jobs`, `--exclude`,
`--offline`, `--no-sandbox`, `--baseline`, `--vex`, `--vex-out`,
`--staged`, `--diff`, `-v/-vv`.

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

## web &lt;url&gt;

Fetch a URL and audit the response: security headers, cookie flags,
server disclosure, TLS expiry, exposed `/.git`, `/.env`,
`/.aws/credentials` (with SPA-fallback detection), `robots.txt`,
`security.txt`, and secrets embedded in inline + bundled JavaScript and
source maps. `--depth N` crawls same-origin links (max 30 pages).

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

## mcp

Stdio JSON-RPC server exposing `scan`, `scan_system`, and `list_rules`
for MCP clients.

## rules / rules-update / completions

`rules` lists loaded rulesets and rules; `rules-update --feed <git-url>`
pulls a rules repo into `~/.config/argus/rules`; `completions <shell>`
prints shell completions.
