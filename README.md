<p align="center">
<img src="docs/mascot.gif" width="140" alt="argus">
</p>

# argus

[![version](https://img.shields.io/badge/version-0.3.0-1f2430?style=flat-square)](https://github.com/Quad4-Software/argus)
[![license](https://img.shields.io/badge/license-QSL--1.0--0BSD-1f2430?style=flat-square)](https://quad4.io/licenses)
[![rust](https://img.shields.io/badge/rust-edition_2024-1f2430?style=flat-square&logo=rust&logoColor=d6a300)](Cargo.toml)
[![ci](https://img.shields.io/github/actions/workflow/status/Quad4-Software/argus/ci.yml?style=flat-square&label=ci)](https://github.com/Quad4-Software/argus/actions/workflows/ci.yml)
[![last commit](https://img.shields.io/github/last-commit/Quad4-Software/argus?style=flat-square&color=1f2430&label=last%20commit)](https://github.com/Quad4-Software/argus)
[![top language](https://img.shields.io/github/languages/top/Quad4-Software/argus?style=flat-square&color=1f2430)](https://github.com/Quad4-Software/argus)

> [!IMPORTANT]
> Open-weight LLMs are used to assist development of this tool. Those
> models are: GLM 5.3-flash, Qwen 3.8 and Kimi K3.

Are you tired of having 50+ different tools for scanning and linting? Well Argus is all of them combined and blazinly fast! 🦀⚡⚡

## Install

The crate is https://crates.io/crates/argus-scanner

```sh
cargo install argus-scanner
```

## Quickstart

```sh
argus scan .                     # this repo, all rulesets
argus github --org my-org        # scan an org end to end
argus web https://example.com    # web audit + client-js secrets
argus domain quad4.io            # DNS, RDAP, certs, page
argus email argus@quad4.io       # mail policy, keys, breach hook
argus ip 1.1.1.1                 # geolocation, ASN, VPN, InternetDB
argus hash <sha256>              # CIRCL hashlookup, optional MalwareBazaar
argus url https://quad4.io       # fetch, redirects, WAF and challenge markers
argus ports 127.0.0.1 --ports 22 # TCP connect, modern ports first
argus system                     # Lynis-class host audit
argus scan . --osv --dep-check   # + dependency advisories and hygiene
argus account github octocat    # public profile, repos, stars
argus socials https://example.com
argus feed https://blog.rust-lang.org/feed.xml
argus style a.txt b.txt         # style distance, not an identification
argus stego .                   # appended payloads and zero-width text
argus gitmeta .                 # names, emails, remotes
argus modules                    # built-in command list
argus grep --pick emails ./notes # stream a local file, no upload
argus extract notes.txt          # capped sample of the same shapes
argus meta report.pdf            # PDF, JPEG, PNG, or docx fields
argus media ./photos             # C2PA, IPTC, generator tags
argus dork example.com           # search links only
argus favicon https://example.com
argus user octocat
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

[QSL-1.0-0BSD](https://quad4.io/licenses).
