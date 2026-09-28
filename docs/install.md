# Install

## From source

```sh
git clone https://github.com/Quad4-Software/argus
cd argus
cargo install --path .          # lands in ~/.cargo/bin
```

Rust 1.85+ is required (edition 2024). The default build includes YARA
support via `yara-x`; use `cargo install --path . --no-default-features`
for a smaller binary without it.

## Prebuilt binaries

Release builds are published on the GitHub releases page for
Linux (x86_64, aarch64, musl), macOS (Intel and Apple Silicon), and
Windows (MSVC). Each artifact ships with `SHA256SUMS.txt` and a
Sigstore (cosign keyless) signature bundle.

Verify a download:

```sh
cosign verify-blob --bundle argus.tar.gz.sigstore.json \
  --certificate-identity-regexp '.*Quad4-Software/argus.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  argus.tar.gz
sha256sum -c SHA256SUMS.txt --ignore-missing
```

## Shell completions

```sh
argus completions bash > ~/.local/share/bash-completion/completions/argus
argus completions zsh > ~/.zfunc/_argus
```

## Pre-commit hook

```sh
cd your-repo
argus init           # writes .git/hooks/pre-commit -> argus scan --staged
```
