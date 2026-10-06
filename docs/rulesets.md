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
keywords = ["token"]        # gate: case-insensitive keyword within 250 bytes of the hit
path = '\.env$'             # path regex scoping (optional)
description = "what this flags"
remediation = "what to do"
reference = "https://..."
```

`type = "ast"` runs a tree-sitter query on the parsed syntax tree
(`lang = "python|javascript|typescript|go|rust|tsx"`, `query` in the S-expression
form, `capture` names which `@name` pins the finding position). Comments and
string literals never match. A `typescript` rule also covers `.tsx` sources
via a second compiled query on the TSX grammar; `.jsx` is handled by the
JavaScript grammar. Rules without a compiled grammar for the file
extension fall back to the regex kinds; an `ast` rule on a file the grammar
does not cover is simply silent.

`type = "action"` matches `uses:` refs in workflows
(`repo = "owner/name"`, `unsafe_refs = "tags|all"`). `type = "package"`
inspects dependency manifests (`names`, `versions`, `allowed_hosts`).
`type = "yara"` attaches a `.yar` file evaluated by yara-x.
`type = "taint"` takes `source` and `sink` regexes plus an optional
`sanitizers` list of regexes that clear taint (`sanitizers =
["encodeURIComponent\(", "escape\("]`).
`type = "secret"` takes `regex` with the candidate in capture group `group`
(default 1), an `entropy` floor (default 3.8 bits/char), `min_len`, and
`keywords`. `type = "content"` and `type = "secret"` accept `keywords` as a
proximity gate; the `gitleaks` builtin ruleset uses this to reproduce
gitleaks fragment matching.

The `python` ruleset is ordinary `content` rules (pickle, `yaml.load`,
`shell=True`, `eval`/`exec`, disabled TLS verification, `tempfile.mktemp`).
The `ast` ruleset flags `eval`/`exec` calls, `new Function`, `innerHTML`
assignment, `subprocess` with `shell=True`, deserialization on
pickle/marshal/yaml objects, `exec.Command`, and `env!()` in Rust.
`javascript`, `go`, `java`, `php`, `ruby`, and `csharp` are the same kind of
text match for injection, deserialization, and TLS checks in those languages.
`owasp` covers JWT `none`, disabled JWT verification, and secrets written to
logs. `agent` flags model or tool text passed into `eval` or a shell.

`agent-surface` audits the files an AI agent consumes or is configured
by: MCP server configs (`.mcp.json`, `claude_desktop_config.json`,
per-client `*.json` under agent dirs), instruction files (`CLAUDE.md`,
`AGENTS.md`, `SKILL.md`, `.cursorrules`, `copilot-instructions.md`, rules
and skills under agent directories), and agent settings files. It flags
remote-script launchers, unpinned install-and-run commands, hardcoded env
credentials, approval bypasses, remote transports, risky or lookalike MCP
packages, privileged docker launches, inline interpreter payloads,
invisible unicode in instructions, override and concealment phrasing,
credential-path targeting, remote instruction fetches, encoded payloads,
wildcard tool grants, permissive modes, and hook-executed commands. A
dataflow rule also fires when an instruction file names credential
stores and a network egress channel in the same file.

`agent-ioc` is the companion feed ruleset: sha256 file hashes of
captured malicious skill/config payloads plus named-bad package and
tool identifiers from public MCP incident disclosures. Feeds publish
new hashes through `rules-update`.

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
