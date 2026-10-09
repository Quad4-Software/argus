# Architecture

```
src/
  main.rs              dispatch + report pipeline only (kept thin by tests/arch.rs)
  cli.rs               clap surface
  cmd/                 one module per command family
    remote.rs          provider enumeration + clone scan pool
    deps.rs            dependency collect + OSV + hygiene findings
    watcher.rs         watch loops, feed events, delta scans
    daemon_cmd.rs      daemon orchestration + webhook rescan
    misc.rs            roam, authors, system glue, git diff helpers
    sandbox_apply.rs   per-command Landlock grants
  rules.rs             TOML ruleset model + compiled matchers
  scan.rs              file walk + rule application
  finding.rs           finding/report types + text/json/md/sarif/cc/html
  provider/            github/gitlab/gitea listing
  http.rs              retrying HTTP client (timeout, backoff, status-aware)
  http_server.rs       daemon listener (bounded, deadline-scoped)
  osv.rs depcheck.rs registry.rs sbom.rs
  workflow_audit.rs container_audit.rs image.rs sysaudit/ webscan.rs
  fix.rs verify.rs vex.rs license.rs publish.rs
  ai/                  git-history provenance evidence + analyze()
  osint/               public lookups (domain, mail, chat, ip, url, ports, meta,
                       platforms: account, user, keybase, steam, bluesky, mastodon,
                       reddit, youtube, tiktok, lemmy)
  host/                sockets, open files, hash signatures, threat leads
  webpassive.rs        passive page checks used by webscan.rs
  search.rs            streaming grep over text, CSV, JSON, SQLite
  extract.rs media.rs seometa.rs stego.rs style.rs codec.rs
  similar.rs           winnowing fingerprints for copied code
  supply.rs store.rs catalog.rs
  audit.rs ioc.rs roam.rs watch.rs daemon.rs mcp.rs settings.rs
  clone.rs config.rs color.rs baseline.rs sandbox.rs yarascan.rs
```

## Dataflow

Every command builds findings into a shared `Report`; `finalize()`
sorts and counts; the formatter emits the chosen representation.
Scanning uses a thread pool over `Mutex`-shared queues, so memory stays
flat on huge trees (files stream, findings accumulate).

## Sandboxing

On Linux each command builds a `Sandbox` grant set: scan roots read-only,
clone/output dirs writable, TCP only for remote work and only on needed
ports (or open for forge APIs). Missing kernel support degrades to a
warning. The `image` command skips it because rootless podman/docker
manage their own user and mount namespaces.
