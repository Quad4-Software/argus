# Rulesets

Rules live in TOML. Four kinds of matcher cover files, workflows,
dependencies, and YARA.

## Loading

Builtin rulesets are compiled in (`--no-builtin-rules` to skip). Extra
`.toml` files load from `--rules <file|dir>`, `defaults.rules_dirs`,
`~/.config/argus/rules/`, and git feeds refreshed by
`argus rules-update`. `--ruleset <name>` selects a subset;
`--disable-rule <id>` removes individual rules.

## Anatomy

```toml
[[rule]]
id = "MYRULE-01"
type = "content"            # content | path | action | package | env
severity = "high"           # info|low|medium|high|critical
regex = 'suspicious.*pattern'
contains = ["str1", "str2"] # substrings; contains_all = true for all
exclude = 'safe.*pattern'   # per-match suppressor on the same line/span
path = '\.env$'             # path regex scoping (optional)
description = "what this flags"
remediation = "what to do"
reference = "https://..."
```

`type = "action"` matches `uses:` refs in workflows
(`repo = "owner/name"`, `unsafe_refs = "tags|all"`). `type = "package"`
inspects dependency manifests (`names`, `versions`, `allowed_hosts`).
`type = "yara"` attaches a `.yar` file evaluated by yara-x.
The `python` ruleset is ordinary `content` rules (pickle, `yaml.load`,
`shell=True`, `eval`/`exec`, disabled TLS verification, `tempfile.mktemp`).
`javascript`, `go`, `java`, `php`, `ruby`, and `csharp` are the same kind of
text match for injection, deserialization, and TLS checks in those languages.
`owasp` covers JWT `none`, disabled JWT verification, and secrets written to
logs. `agent` flags model or tool text passed into `eval` or a shell.
These match text. They do not parse an AST, and they do not prove broken
access control, insecure design, or prompt injection.

## The corpus

`tests/corpus/<case>/` holds one fixture plus `expected.txt` with rule
ids that MUST fire and `!id` entries that MUST NOT.
`cargo test --test corpus` runs every case. New rules without fixtures
are unproven; add the case in the same commit as the rule.

## False-positive hygiene

- `exclude` regexes suppress specific matches, not whole files
- secrets in binary files are skipped (ELF test vectors, not leaks)
- public-by-design key shapes (Stripe `pk_`, Algolia, Sentry DSN)
  downgrade so real secrets stay loud
- the `hardening` suite proves suppression markers and baseline
  round-trips keep working
