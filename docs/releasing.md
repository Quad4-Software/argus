# Releasing

Releases cut from `v*` tags. The workflow builds per-platform binaries,
generates `SHA256SUMS.txt`, signs every artifact with cosign keyless
(Fulcio + Rekor), attaches everything to a **draft** release, then
publishes.

```sh
git tag v0.3.0 && git push origin v0.3.0
```

The 0BSD Effective Date in `LICENSE` belongs to that tagged version. It is the second anniversary of the day the version is first published, and the date written in the file is the one that counts. Set it in the release commit. Later commits on the same version do not move it, and nothing in the repo rewrites it.

## Immutable releases

Enable release immutability in the repository settings
(Settings > Releases > Enable release immutability). The workflow is
compatible: it publishes only after all assets are attached, so nothing
needs to change once the release locks. Do not retag - an immutable
release pins the tag to the commit permanently.

## Artifacts

- `argus-<tag>-x86_64-unknown-linux-musl.tar.gz` (static)
- `argus-<tag>-aarch64-unknown-linux-musl.tar.gz` (experimental cross)
- `argus-<tag>-x86_64-apple-darwin.tar.gz` / `-aarch64-apple-darwin.tar.gz`
- `argus-<tag>-x86_64-pc-windows-msvc.zip`
- `SHA256SUMS.txt` + `*.sigstore.json` bundles

## Checks before tagging

- `cargo test` green on both feature sets and all three OSes
- `CHANGELOG.md` entry added
- `Cargo.toml` version bumped to match the tag
- `LICENSE` states this version's 0BSD Effective Date, two years after the publication day
