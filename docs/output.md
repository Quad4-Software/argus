# Output and CI integration

## Formats

| `--format` | Produces |
|---|---|
| `text` | colored findings grouped by target (default) |
| `json` | full report object for piping and archival |
| `markdown` | findings table, PR comments, step summaries |
| `sarif` | SARIF 2.1.0 for code scanning uploads |
| `codeclimate` | GitLab codequality artifact |
| `html` | self-contained interactive report (filter/search) |

`--output <file>` writes to a file instead of stdout.

## Thresholds

- `--severity low` drops everything below the level
- `--fail-on medium` exits 1 only when findings reach the level
- Exit codes: 0 clean, 1 threshold met, 2 operational error

## Baselines and VEX

`--baseline base.json --fail-on-new` gates only findings that were not
accepted before; `--write-baseline base.json` records the current set.
`--vex doc.vex.json` suppresses `not_affected`/`fixed` statements and
annotates `under_investigation`; `--vex-out out.json` emits an OpenVEX
document for the advisories found.

## CI

`--ci` prints `::error`/`::warning` annotations and appends the
markdown report to `GITHUB_STEP_SUMMARY`. When argus detects a CI
environment it does the same for text output only, so JSON stays
parseable. A minimal GitHub gate:

```yaml
- run: argus scan . --diff origin/main --fail-on medium --format sarif --output r.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: r.sarif
```

`examples/` ships ready-made GitHub Actions, GitLab CI, and pre-commit
fragments.

## Reports

Terminal output sorts findings by severity and shows the matched
evidence with a remediation hint. The HTML report groups the same data
behind severity cards with a text filter; JSON carries the full
finding schema including rule id, target, path, line, excerpt,
remediation, reference, and ruleset.
