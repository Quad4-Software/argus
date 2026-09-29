# Configuration

Precedence, lowest to highest: TOML config < environment variables <
command-line flags.

## Config files

`~/.config/argus/config.toml` applies globally; `argus.toml` in the
scanned repo overrides per-project values. `argus.example.toml` in the
repository lists every key.

```toml
[tokens]
github = "ghp_..."          # or GITHUB_TOKEN / GH_TOKEN env
gitlab = "glpat-..."        # or GITLAB_TOKEN
gitea = "..."               # or GITEA_TOKEN / FORGEJO_TOKEN

[defaults]
jobs = 8                    # scanner parallelism
color = "auto"              # auto|always|never
progress = "auto"           # auto|always|never (stderr spinner)
severity = "info"           # minimum reported severity
fail_on = "high"            # exit-1 threshold
osv = false                 # default for --osv
offline = false             # default for --offline
no_sandbox = false
internal_prefixes = ["@acme", "acme-"]   # dep-confusion markers
rules_dirs = ["~/rules"]    # extra TOML ruleset dirs

[github]
git_user = "x-access-token"

[gitlab]
host = "gitlab.example.com"
git_user = "oauth2"

[gitea]
host = "git.example.com"
```

## Tokens

Resolution order per forge: `--token` flag, env var, config file.
Token source is never printed; clone auth uses `GIT_ASKPASS` so the
credential never appears in `argv`.

## Offline

`--offline`, `ARGUS_OFFLINE=1`, or `defaults.offline` disables all
network access: remote subcommands refuse, `--osv`/`--check-runs`
report as skipped, scanning stays local.

## Sandbox

On Linux, Landlock restricts every command: local scans get zero
network and a read-only filesystem, remote commands get only their
workdir and the forge's network. `--no-sandbox` or
`defaults.no_sandbox` disables it; non-Linux hosts warn and run
unsandboxed. `argus image` runs the container runtime unsandboxed
(rootless runtimes manage their own namespaces).
