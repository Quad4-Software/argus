# argus

[![version](https://img.shields.io/badge/version-0.1.0-1f2430?style=flat-square)](https://github.com/Quad4-Software/argus)
[![license](https://img.shields.io/badge/license-MIT--0-1f2430?style=flat-square)](LICENSE)
[![rust](https://img.shields.io/badge/rust-edition_2021-1f2430?style=flat-square&logo=rust&logoColor=d6a300)](Cargo.toml)
[![tests](https://img.shields.io/badge/tests-60%20pass-1f2430?style=flat-square)](tests/)
[![last commit](https://img.shields.io/github/last-commit/Quad4-Software/argus?style=flat-square&color=1f2430&label=last%20commit)](https://github.com/Quad4-Software/argus)
[![top language](https://img.shields.io/github/languages/top/Quad4-Software/argus?style=flat-square&color=1f2430)](https://github.com/Quad4-Software/argus)

Supply-chain security and repository-forensics scanner. One static binary
checks local checkouts, whole GitHub / GitLab / Gitea accounts, container
images, web front-ends and the host itself for indicators of known
compromises (Shai-Hulud family, TeamPCP/trivy-action, malicious litellm),
secrets and secret liveness, dependency confusion and hygiene, malicious
workflow/container/host configuration, and agent-substituted authorship.



## Usage

```sh
# scan local paths (defaults to .)
argus scan /path/to/repo [more/paths...]

# scan this machine: /tmp, systemd units, shell rc, pacman -Qqm vs known-bad AUR list
argus system
argus system --extra /opt/custom/dir

# scan with YARA rules (real evaluation via yara-x)
argus scan . --yara rules/yara --yara ~/more-rules/

# scan with a flat IoC list (sha256/domain/IP/URL/string per line)
argus scan . --iocs iocs.txt --ioc-severity critical

# include .git internals (worm-created branches/hooks/config)
argus scan . --include-git

# scan a GitHub org / user / everything your token can see
argus github --org my-org
argus github --user someuser
GITHUB_TOKEN=ghp_... argus github --me

# GitLab (groups, incl. self-hosted)
GITLAB_TOKEN=glpat-... argus gitlab --org my-group --host gitlab.example.com

# Gitea / Forgejo
GITEA_TOKEN=... argus gitea --host git.example.com --org my-org

# output and behavior
argus scan . --format json            # machine-readable report
argus scan . --format markdown        # PR comment / step summary table
argus scan . --format sarif           # GitHub code scanning upload
argus scan . --format codeclimate     # GitLab codequality artifact
argus scan . --output report.json     # write report to file
argus scan . --ci                     # ::error/::warning annotations +
                                         # GITHUB_STEP_SUMMARY append (auto in CI)
argus scan . --color never            # or NO_COLOR=1
argus scan . --severity medium        # only report >= medium
argus scan . --fail-on high           # exit 1 only if >= high found
argus scan . --exclude 'node_modules' # skip path regex (repeatable)
argus scan . -j 32                    # parallelism
argus rules                           # list loaded rulesets/rules

# CI: examples/ has ready-made GitHub/Forgejo workflow + GitLab CI fragments.
# Composite action for reuse: uses: Quad4-Software/argus@<sha> (see action.yml)

# deeper verification modes
argus scan . --osv              # OSV.dev advisories for pinned deps + action refs
argus scan . --audit-history    # commits inside known compromise windows
argus scan . --check-runs       # GitHub: did flagged workflows actually run in-window?
argus scan . --ruleset mini-shai-hulud --disable-rule HYG-001
argus scan . --baseline base.json --fail-on-new   # gate only NEW findings
argus scan . --write-baseline base.json           # record accepted findings
argus rules-update --feed https://host/rules.git  # git clone/pull into ~/.config/argus/rules
argus completions bash > ~/.local/share/bash-completion/completions/argus

# PR mode: only files changed vs a ref (plus untracked) - sub-second PR gates
argus scan . --diff origin/main

# Discovery + monitoring:
argus roam --forge github --topic aur-helper --limit 20      # search + scan
argus roam --code-search "m-kosche.com"                      # find repos carrying an IoC (needs GITHUB_TOKEN)
argus watch --repo owner/repo --interval 300                 # rescan on push (ls-remote)
argus watch --feed https://github.com/o/r/commits/main.atom  # RSS/Atom entry polling
argus watch --advisories --rescan-on-feed --repo o/r          # GH advisories -> rules refresh + rescan
argus authors .                                              # commit-author intel per repo
argus daemon --listen 127.0.0.1:8694 --repo o/r --notify-url https://ntfy.sh/MYTOPIC
#   daemon endpoints: /healthz /report /state /scan /webhook/{github,gitlab,gitea}
#   (HMAC-signed push webhooks -> instant rescan + new-finding notifications)
argus sbom .                                                 # CycloneDX 1.5 JSON from lockfiles
argus ai .                                                   # AI-provenance: agent trailers, velocity, style tells
argus fix .                                                  # pin mutable uses: to SHA + add permissions block (dry-run, --write applies)
argus license . --deps                                       # license audit + copyleft dep check via registry
argus publish .                                              # pre-flight: scan only files npm pack/cargo package would ship
argus scan . --dep-check --internal-prefix "@myorg"            # registry hygiene: confusion, missing, unmaintained deps
argus github --org my-org --settings                         # + org/repo settings audit (branch protection, actions perms)
argus image debian:bookworm-slim --deep                      # image audit: secrets, root user, history - --deep scans every layer
argus web https://example.com --depth 1                     # web audit: headers, cookies, TLS, exposed .git/.env, secrets in JS bundles + source maps, --depth crawls same-origin links
argus system                                                 # Lynis-class host audit: kernel/auth/ssh/net/fs/services/logging/integrity/malware checks
argus verify .                                               # secrets liveness: are found tokens still valid? live = critical
argus fix --containers .                                     # container fixes: USER injection, FROM digest pin, compose hardening
argus init                                                   # install pre-commit hook (argus scan --staged)
argus scan . --format html -o report.html                    # self-contained interactive HTML report
argus --osv scan . --vex triage.vex.json --vex-out out.json  # OpenVEX: suppress not_affected/fixed, emit docs for found vulns
argus watch --repo o/r --dep-watch                           # + maintainer-change alerts and dep deltas on push

# MCP server for AI agents (stdio JSON-RPC, spec 2025-06-18):
# client config: {"mcpServers": {"argus": {"command": "argus", "args": ["mcp"]}}}
argus mcp
# tools exposed: scan(paths, min_severity, include_git, diff), scan_system, list_rules
```

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` operational error.

## Resilience

- `--offline` / `ARGUS_OFFLINE=1` / `defaults.offline` - zero network activity. Remote subcommands refuse cleanly, `--osv`/`--check-runs` are skipped, scanning stays local (rules are compiled in).
- HTTP layer: 30s global timeout, retry on 429/5xx/connect/timeouts with backoff + `Retry-After`, rate-limit and auth diagnostics in error text, per-repo clone failures degrade to `errors[]` instead of aborting.
- Sandbox (Linux Landlock): local scans get **zero network** and read-only filesystem. Remote commands get their workdir + the forge's network only. Daemon gets its listen port. `--no-sandbox` to disable.

## Daemon mode

`argus daemon` runs a persistent watcher: forge webhooks trigger instant rescans,
a poll loop (`--interval`, default 900s) catches pushes when webhooks are
unreachable, and new findings get POSTed to `--notify-url` (ntfy.sh or any JSON
webhook). See `examples/argus-daemon.service` for the systemd unit.

Webhook secret: set `ARGUS_WEBHOOK_SECRET` or `--webhook-secret` and configure
the same secret on the forge. GitHub uses `X-Hub-Signature-256`, GitLab
`X-Gitlab-Token`, Gitea `X-Gitea-Signature`.

## Rulesets

Rules live in TOML files. Four sets are compiled in (`--no-builtin-rules` to
skip) - extra `.toml` files load from `--rules <file|dir>`,
`defaults.rules_dirs` in the config, and `~/.config/argus/rules/`.

```toml
[ruleset]
name = "my-rules"
version = "2026.01.01"

[[rule]]
id = "MINE-001"
type = "action_ref"            # match `uses: owner/repo@ref`
severity = "critical"          # info|low|medium|high|critical
repo = "owner/repo"            # or "*" for any action
unsafe_refs = "tags"           # tags = non-SHA refs, all = every ref
malicious_shas = ["40-char..."]
description = "..."
remediation = "..."
reference = "https://..."

[[rule]]
id = "MINE-002"
type = "content"               # file content match
severity = "high"
path = '(^|/)package\.json$'   # regex on repo-relative path (optional)
contains = ["str1", "str2"]    # any substring; add contains_all = true for all
regex = 'pat'                  # content regex (optional)
unless = 'safe-pattern'        # suppression regex (optional)
description = "..."

[[rule]]
id = "MINE-003"
type = "path"                  # file-existence match
severity = "critical"
regex = '(^|/)suspicious\.sh$'
description = "..."

[[rule]]
id = "MINE-004"
type = "package"               # dependency manifest match
severity = "critical"
names = ["left-pad", "@evil-scope/"]   # trailing "/" = scope prefix match
versions = ["9.9.9"]                   # optional: only these versions flag
description = "..."
```

Package rules scan dependency manifests and lockfiles (package.json,
package-lock, pnpm/yarn/bun locks, requirements.txt, pyproject.toml,
setup.py/cfg, Pipfile, poetry.lock, uv.lock, environment.yml).```

Builtin sets (~76 rules):

| ruleset | covers |
|---|---|
| `mini-shai-hulud` | actions-cool re-armed Sept 2026 + npm payload IoCs |
| `shai-hulud-classic` | Sept 2025 self-replicating npm worm |
| `action-compromises` | tj-actions, reviewdog Mar 2025 tag hijacks |
| `aur-attacks` | CHAOS RAT Jul 2025 + atomic-lockfile Jun 2026 AUR campaigns, PKGBUILD/.install/.hook injection patterns |
| `teampcp` | Mar 2026 Trivy/trivy-action/setup-trivy hijack, CanisterWorm npm scopes, litellm/telnyx PyPI backdoors |
| `pypi` | ultralytics/torchtriton bad versions, executable .pth, setup.py RCE, interpreter persistence |
| `npm-generic` | lifecycle-script remote fetch, eval-of-encoded-blob loaders |
| `manifest-hygiene` | non-registry lockfile sources, git deps, composer/cargo/build hooks, VS Code folderOpen tasks, Dockerfile/git/pip/npmrc source hygiene, git hooksPath |
| `aur-pkglists` | 1943 known-compromised AUR package names vs PKGBUILD/.SRCINFO and `pacman -Qqm` output |
| `workflow-security` | TOML-level trigger/permission/include/secret-flow checks |
| `workflow-audit` | code-driven zizmor-class audits (WFA-*): template injection, secrets-inherit, GITHUB_ENV writes, artipacked, cache poisoning, self-hosted runners, unpinned images, ref-confusion, bot conditions, insecure commands |
| `typosquat` | edit-distance-1 + confusable unicode vs curated top npm/PyPI lists |
| `actor-watchlist` | known attacker handles (danikpapas, herbsobering, campaign sockpuppets) + disposable-email commit authors, evaluated over git author metadata via `argus authors` |
| `osint` | young-repo detection (repos <30d old are a throwaway-account signal on remote scans) |
| `crates` | Cargo ecosystem: `[patch.*]` registry redirects, build.rs network/env access, proc-macro flags, known-bad crates (rustdecimal incident) |
| `secrets` | structured token regexes (AWS/GitHub/npm/PyPI/OpenAI/Stripe/Slack/Google/GitLab/SendGrid/Telegram/JWT/private keys/creds-in-URL) + entropy-gated generic assignments - secrets are masked in excerpts |
| `hygiene` | mutable tags, curl\|sh, committed tokens, pull_request_target |

Suppression comments: `argus:ignore ID` on a line, `argus:ignore-next-line ID`,
`argus:ignore-file` near the top. `--ruleset`/`--disable-rule` filter coverage.

Extra rule types: `hash` (`sha256 = [...]` file hashing) and `source_url`
(`allowed_hosts` allowlist for dependency-fetch URLs in manifests/lockfiles).

## Config and auth

See `argus.example.toml`. Precedence: flag > env > config file.

- Tokens: `--token`, `ARGUS_TOKEN`, or per-provider `GITHUB_TOKEN` /
  `GH_TOKEN`, `GITLAB_TOKEN`, `GITEA_TOKEN` / `FORGEJO_TOKEN`.
- Clone auth uses GIT_ASKPASS, so tokens never appear in argv or logs.
- Remote scans shallow-clone (`--depth 1`) into a temp dir (or `--workdir`,
  `--keep`).

## Notes

- The scanner matches indicators - a clean result is not proof of safety.
- SHA-pinned refs are only reported when the SHA is a known-malicious commit or
  the rule uses `unsafe_refs = "all"` - arbitrary SHAs cannot be verified offline.
- For repos that ran a compromised workflow, rotate secrets and audit run
  history - this tool finds the exposure, not the blast radius.


## AI provenance (`argus ai`)

Evidence-based AI-code detection - outputs a score + evidence list, never a bare verdict:

- **High**: `Co-Authored-By:`/`Generated with/by` trailers naming agents (Claude, Copilot, Cursor, Aider, Devin, OpenHands, Sweep, CodeRabbit, Gemini, Windsurf, ...), commits authored by agent bot accounts
- **Medium**: commit bursts (60+/24h), median inter-commit gap <90s at scale, median LoC/commit ≥2500, pervasive uniform style across 10+ files
- **Low**: em-dash density in prose/comments, AI-cliche phrasing ("seamlessly", "it's important to note", "delve into", ...)

Low-tier signals alone cap at "some AI indicators" - a verdict of *likely AI-assisted* requires a high-tier signal or medium-tier clustering.

### Hiding-attempt forensics

`argus ai` also inspects git internals for signs that attribution was scrubbed:

- **scrubbed AI commits** (high): unreachable objects (`git fsck --no-reflogs`) carrying agent attribution that was amended/rebased away
- **rewritten history** (medium/low): amend/rebase/reset/filter-branch residue in reflog
- **signature discontinuity** (medium): signing regime breaks mid-history
- **message-mutating hooks** (medium): `commit-msg`/`prepare-commit-msg` hooks that rewrite message content (e.g. stripping Co-Authored-By lines)
- **hooksPath redirect** (medium): `core.hooksPath` hides hooks outside `.git/hooks`
- **git notes**, **truncated/shallow history** caveats

## System audit (`argus system`)

Lynis-class host hardening checks alongside the usual file scan:

- kernel/sysctl: ASLR, kptr, ptrace scope, kexec, suid dumps, userns,
  core_pattern pipes, Secure Boot
- auth: UID-0 accounts, empty passwords, file perms on passwd/shadow,
  aging policy, sudoers NOPASSWD/env_keep/perms
- sshd: root login, password auth, empty passwords, weak ciphers,
  forwarding, MaxAuthTries/GraceTime, AllowUsers/Groups
- network: ip_forward/rp_filter/redirects/syncookies, dangerous listeners
  via ss (telnet/ftp/vnc/db ports/docker 2375), promiscuous interfaces,
  firewall ruleset presence
- filesystem: nosuid/nodev/noexec on tmp mounts, sticky bits
- services: risky enabled units (telnet/ftp/rsh/avahi/cups/rpcbind...),
  systemd-analyze security UNSAFE units
- logging: journald persistence, auditd, syslog presence
- scheduler: cron/at allow-files, world-writable cron entries
- integrity: aide/rkhunter/fail2ban presence, MAC (AppArmor/SELinux),
  time sync
- home dirs: permissions, ~/.ssh modes, key file perms
- malware quick-checks: ld.so.preload, /tmp|/dev/shm executables,
  deleted-but-running binaries, hidden temp entries

## Malware behavioral ruleset

`malware` ruleset (built in, runs on every scan): obfuscation (long
base64, eval-of-decode, Function-constructor, hex/unicode escapes,
python marshal/zlib exec), exfil endpoints (request-bins, OAST domains,
telegram bots, paste sites, IP-discovery), lifecycle abuse (install
hooks spawning interpreters, child_process in libs, credential env
reads), persistence primitives (cron/systemd/registry writes, history
wiping, LD_PRELOAD, ptrace), raw-IP URLs (public only - private ranges
excluded), mining pool refs, reverse shells, credential-file staging.

## Web audit (`argus web <url>`)

Fetches the URL and audits what a browser sees:

- `--depth N` crawls same-origin links (cap 30 pages) running secrets
  and form-action plaintext checks on every page
- Security headers (CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy),
  banner disclosure, CORS wildcard+credentials, cookie flags
- TLS leaf expiry (<30d medium, expired high) via openssl
- Exposed metadata probes: `/.git/HEAD`, `/.env`, `/.aws/credentials`
  (SPA-fallback aware: validates content, not just 200s)
- robots.txt sensitive-path disclosure, missing security.txt (RFC 9116)
- Client-side secrets: inline `<script>` plus up to 30 referenced JS bundles
  and their `.map` source maps go through the secrets ruleset and a
  JS-assignment detector (`*_API_KEY:"..."`, `*_TOKEN:"..."`) with calibrated
  severities - genuine secrets (API keys, access tokens) report high,
  public-by-design shapes (Stripe pk_, Algolia, Firebase/Google client keys)
  report info/medium with a "verify restrictions" note. Live-verified on
  protondb.com: found its exposed Steam API key, Lambda access token, and
  GSheets/Algolia keys.

## Container audit (built in)

`--osv`/`--dep-check` on a deep image scan also maps OS packages to
OSV advisories: dpkg (`var/lib/dpkg/status`) and apk
(`lib/apk/db/installed`) are parsed into Debian/Alpine ecosystems and
batch-queried alongside normal scan findings.

`argus fix --containers` also remediates: pins mutable `FROM` refs to
resolved digests (crane/skopeo/docker/podman), injects `USER 1000:1000`
before CMD/ENTRYPOINT, and adds `security_opt: [no-new-privileges:true]`
to compose services lacking it.

## Container audit (built in)

`container-audit` ruleset runs on every scan:

- Dockerfiles/Containerfiles: missing USER (root, OWASP #2), pipe-to-shell
  installs, remote ADD, unpinned/`latest` base, literal ENV/ARG secrets,
  sensitive COPY paths, chmod 777, sshd EXPOSE 22
- docker-compose/compose: privileged, docker.sock/root mounts, host
  namespaces, latest tags, inline env secrets, dangerous cap_add,
  unconfined seccomp/apparmor, published docker API 2375
- Kubernetes manifests (k8s/, kubernetes/, manifests/): privileged
  containers, allowPrivilegeEscalation, uid-0, host namespaces, hostPath
  mounts, latest images, inline env secrets

`argus image <ref>` audits the image itself via docker/podman: baked-in
ENV secrets, root user, mutable tag, image age, and secrets left in build
history. `--deep` exports every layer and runs the full rules engine over
the merged filesystem. The image command runs the container runtime
unsandboxed (rootless runtimes manage their own namespaces). Scanning a
runtime does not need the sandbox anyway.

## Dependency hygiene (`--dep-check`)

`argus scan <p> --dep-check` runs registry lookups (npm/PyPI/crates.io, 24h
cache) and reports:

- `DEP-001` dep not found on the public registry (typo, renamed, or private name)
- `DEP-002` internal-looking name resolving publicly (dependency-confusion exposure -
  mark your prefixes via `--internal-prefix` or `defaults.internal_prefixes`)
- `DEP-010` dep dormant >2 years (takeover target)
- `DEP-011` upstream repository archived/read-only

`argus watch` tracks the dep set per repo: pushes report `DEPD-001..003`
(added/removed/version-changed). With `--dep-watch` it also tracks registry
maintainer sets per dep and fires `DEPD-010` (high) when a maintainer list
changes - the package-hijack signal. The daemon's webhook rescans get the
same dep delta.

## License

MIT-0 - see LICENSE. Use, copy and redistribute without attribution.

## Testing

`cargo test` runs unit + binary-level tests plus three structural
suites:

- `tests/corpus/` - rule fixture corpus - each case dir holds a fixture and `expected.txt` (rule ids that MUST fire, `!id` = MUST NOT)
- `tests/arch.rs` - god-file gate: main.rs is dispatch-only (command
  bodies live in `src/cmd/`), no source file over 1000 lines
- `tests/hardening.rs` - adversarial/FP/determinism checks

## Contributing

Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`,
`refactor:`, `chore:`) enforced by `scripts/commit-msg` - install with
`git config core.hooksPath scripts/git-hooks` or copy it into `.git/hooks/`.
