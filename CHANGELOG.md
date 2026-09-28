# Changelog

## [0.1.0] - 2026-04-14

First tagged tree. argus scans local checkouts, remote orgs, container
images, web front-ends and the host for supply-chain compromise
indicators, secrets, dependency hygiene and misconfiguration.

### Added

- Core scanner: parallel file walk, TOML rulesets (builtin + `--rules-dir`
  + git rules feeds), content/path/env/yara matchers, severity model,
  suppression markers, per-rule `--disable-rule`/`--ruleset` selection
- Output: terminal colors, JSON, Markdown, SARIF 2.1.0, Code Climate,
  single-file interactive HTML; `--output` file; `--ci` annotations +
  step-summary append; `--fail-on`, `--fail-on-new`, baselines
- Built-in rulesets: shai-hulud (classic + mini), teampcp, secrets,
  npm/pypi/crates/aur hygiene, typosquats, workflow security, workflow
  audit (zizmor-style), container audit (OWASP-mapped Docker/Compose/k8s),
  malware behavioral set (obfuscation/exfil/lifecycle/persistence),
  IoC lists, actor watchlist
- Remote scanning: `github`/`gitlab`/`gitea` over org/user/token scopes
  with include/fork/archived/privacy filters, `--settings` org+repo
  security audit (branch protection, Actions perms, secret scanning)
- Git forensics: `--include-git` internals scan, `--diff` and `--staged`
  file selection, `--audit-history` compromise-window commit checks,
  `--check-runs` workflow-run corroboration, `authors` identity OSINT
- Dependencies: lockfile/manifest extraction (npm, PyPI, crates.io, Go,
  RubyGems, GitHub Actions), OSV batch queries, `--dep-check` registry
  hygiene (confusion, missing, unmaintained, archived), watch-mode dep
  deltas and maintainer-change alerts
- Containers: `image <ref>` metadata/history/secret audit, `--deep`
  layer-export full scan, dpkg/apk OS packages mapped to OSV advisories;
  `fix --containers` USER injection, digest pinning, compose hardening
- Web: `web <url>` header/cookie/TLS/exposure audit, robots+security.txt,
  inline and bundled JS secret detection incl. source maps, severity
  tiers for public-by-design keys, `--depth` same-origin crawl
- Host: `system` Lynis-class audit (sysctl/auth/sshd/net/fs/services/
  logging/scheduler/integrity/homes/malware quick-checks)
- Secrets liveness: `verify` checks found tokens against provider APIs
  (GitHub, GitLab, Telegram, npm, Slack, HuggingFace, Stripe, SendGrid,
  OpenAI) and reports live credentials as critical
- Remediation: `fix` pins mutable action refs to SHAs and injects
  `permissions: {}`; `init` installs a `--staged` pre-commit hook
- Packages: `publish` pre-flight scan of the real ship-set (npm pack /
  cargo package / git ls-files), `license` audit + dep copyleft check,
  `sbom` CycloneDX output
- AI provenance: `ai` evidence-tiered report (trailers, agent configs,
  volume, history integrity, provenance laundering) with human-agency
  counter-evidence
- Monitoring: `watch` push polling + feed events, `daemon` HTTP control
  plane + HMAC-signed forge webhooks + notify-url, delta rescans on
  changed files only
- VEX: `--vex` suppresses not_affected/fixed and annotates
  under_investigation; `--vex-out` emits spec-compliant OpenVEX
- MCP: `mcp` stdio JSON-RPC server (scan, scan_system, list_rules)
- Sandboxing: Landlock read-only FS + zero network for local scans;
  per-command grants for remote/watch/daemon paths
- Config: flags < env < TOML (`~/.config/argus/config.toml` + per-repo
  `argus.toml`), tokens via `--token`/env/config, `--offline` mode
- Testing: `tests/corpus/` rule fixture corpus, `tests/arch.rs` god-file
  gate, `tests/hardening.rs` adversarial/FP/determinism suite

[0.1.0]: https://github.com/Quad4-Software/argus/tree/v0.1.0
