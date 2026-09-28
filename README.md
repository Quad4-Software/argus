# argus

[![version](https://img.shields.io/badge/version-0.1.0-1f2430?style=flat-square)](https://github.com/Quad4-Software/argus)
[![license](https://img.shields.io/badge/license-MIT--0-1f2430?style=flat-square)](LICENSE)
[![rust](https://img.shields.io/badge/rust-edition_2024-1f2430?style=flat-square&logo=rust&logoColor=d6a300)](Cargo.toml)
[![tests](https://img.shields.io/badge/tests-60%20pass-1f2430?style=flat-square)](tests/)
[![last commit](https://img.shields.io/github/last-commit/Quad4-Software/argus?style=flat-square&color=1f2430&label=last%20commit)](https://github.com/Quad4-Software/argus)
[![top language](https://img.shields.io/github/languages/top/Quad4-Software/argus?style=flat-square&color=1f2430)](https://github.com/Quad4-Software/argus)

> [!IMPORTANT]
> Open-weight LLMs are used to assist development of this tool. Those
> models are: GLM 5.3-flash, Qwen 3.8 and Kimi K3.

Supply-chain security and repository-forensics scanner. One static
binary checks local checkouts, GitHub/GitLab/Gitea orgs, container
images, web front-ends, and the host for leaked secrets, known-bad
action tags, malicious packages, dependency confusion, weak
workflow/container/host configuration, and substituted authorship.

## Install

```sh
cargo install --path .          # or grab a release binary + checksums
```

## Quickstart

```sh
argus scan .                     # this repo, all rulesets
argus github --org my-org        # scan an org end to end
argus web https://example.com    # web audit + client-js secrets
argus system                     # Lynis-class host audit
argus scan . --osv --dep-check   # + dependency advisories and hygiene
```

Findings carry severity, a stable rule id, evidence, and a fix hint.
Exit 1 when findings meet `--fail-on`, 0 otherwise, 2 on error.
Outputs: text, JSON, Markdown, SARIF, Code Climate, HTML.

## Docs

Full documentation lives in [docs/](docs/index.md) and on the
[documentation site](https://quad4-software.github.io/argus/):

- [Commands](docs/commands.md) - every subcommand, what it does, examples
- `argus similar` and `scan --similar` find copied or vendored code by
  normalized-token winnowing fingerprints, robust to renames
- [Configuration](docs/config.md) - flags < env < TOML, tokens, offline, sandbox
- [Output and CI](docs/output.md) - formats, baselines, VEX, CI wiring
- [Rulesets](docs/rulesets.md) - TOML rule format and the test corpus
- [Architecture](docs/architecture.md) - module map, sandboxing, gates
- [Releasing](docs/releasing.md) - tagged releases, signatures, immutability

## License

MIT-0 - see LICENSE. Use, copy, and redistribute without attribution.
