#!/usr/bin/env python3
"""Build and sign an argus vendored-code similarity corpus.

Maintainer-side glue for CI. Produces two artifacts next to each other:

    corpus.db       sqlite fingerprint db (argus similar --corpus-build)
    corpus.db.sig   detached ed25519 signature, base64 (argus rules-sign)

Publish both at the same URL prefix: argus similar --fetch-corpus <URL>
fetches <URL> and <URL>.sig, verifies the signature against the embedded
release pubkey (or --corpus-pubkey), and only then installs the db at
~/.local/share/argus/corpus.db.

Inputs: a directory holding one checkout per package (each subdirectory
name becomes the corpus path prefix, e.g. openssl-3.0.1/ssl/ssl_lib.c),
or --manifest FILE with one package per line as either "name<TAB>path"
or a bare path (basename is used as the name).

Signing key: a rulesign-format ed25519 private key file (64 hex chars),
kept in CI secrets. Generate with: argus rules-keygen --privkey priv.hex
--pubkey pub.hex. Never commit the private key.
"""

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

# mirrors the schema argus writes (src/similar.rs index_connect) so merged
# dbs are identical to a single-shot build
SCHEMA = """
CREATE TABLE IF NOT EXISTS files(
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    root TEXT NOT NULL,
    mtime INTEGER NOT NULL,
    size INTEGER NOT NULL,
    total_shingles INTEGER NOT NULL,
    fp BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS bands(
    band_idx INTEGER NOT NULL,
    band_key BLOB NOT NULL,
    file_id INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS bands_idx ON bands(band_idx, band_key);
CREATE TABLE IF NOT EXISTS corpus_meta(
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    built_at TEXT NOT NULL);
"""


def die(msg):
    sys.exit(f"error: {msg}")


def run(cmd):
    print("+", " ".join(str(c) for c in cmd), file=sys.stderr)
    subprocess.run([str(c) for c in cmd], check=True)


def packages_from_dir(root):
    out = []
    for e in sorted(os.scandir(root), key=lambda e: e.name):
        if e.is_dir() and not e.name.startswith("."):
            out.append((e.name, e.path))
    return out


def packages_from_manifest(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                name, p = line.split("\t", 1)
            else:
                name, p = os.path.basename(line), line
            out.append((name.strip(), p.strip()))
    return out


def merge_dbs(part_dbs, out):
    # each part db has files+bands (+corpus_meta); band file_ids are local
    # to each part, so remap through the unique files.path on the way in
    if os.path.exists(out):
        os.remove(out)
    con = sqlite3.connect(out)
    try:
        con.executescript(SCHEMA)
        for part in part_dbs:
            con.execute("ATTACH ? AS part", (part,))
            con.execute(
                "INSERT OR REPLACE INTO main.files"
                "(path,root,mtime,size,total_shingles,fp)"
                " SELECT path,root,mtime,size,total_shingles,fp FROM part.files"
            )
            con.execute(
                "INSERT INTO main.bands(band_idx,band_key,file_id)"
                " SELECT b.band_idx, b.band_key, m.id"
                " FROM part.bands b"
                " JOIN part.files f ON f.id = b.file_id"
                " JOIN main.files m ON m.path = f.path"
            )
            try:
                row = con.execute(
                    "SELECT name,version,built_at FROM part.corpus_meta LIMIT 1"
                ).fetchone()
            except sqlite3.OperationalError:
                row = None
            if row and not con.execute(
                "SELECT 1 FROM main.corpus_meta LIMIT 1"
            ).fetchone():
                con.execute(
                    "INSERT INTO corpus_meta(name,version,built_at) VALUES(?,?,?)",
                    row,
                )
            # DETACH is refused inside an open transaction
            con.commit()
            con.execute("DETACH part")
        con.commit()
    finally:
        con.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "packages",
        nargs="?",
        help="directory holding one subdirectory per package checkout",
    )
    ap.add_argument(
        "--manifest",
        help="file listing packages: 'name<TAB>path' or bare path per line",
    )
    ap.add_argument("--out", default="corpus.db", help="output db (default: corpus.db)")
    ap.add_argument(
        "--name",
        default="argus-corpus",
        help="corpus name recorded in corpus_meta (default: argus-corpus)",
    )
    ap.add_argument("--key", help="rulesign-format ed25519 private key (hex)")
    ap.add_argument(
        "--argus",
        default=os.environ.get("ARGUS_BIN", "argus"),
        help="argus binary to invoke (default: $ARGUS_BIN or 'argus')",
    )
    a = ap.parse_args()

    if bool(a.packages) == bool(a.manifest):
        die("give exactly one of PACKAGES_DIR or --manifest FILE")

    pkgs = (
        packages_from_manifest(a.manifest)
        if a.manifest
        else packages_from_dir(a.packages)
    )
    if not pkgs:
        die("no packages found")

    out = os.path.abspath(a.out)
    with tempfile.TemporaryDirectory(prefix="argus-corpus-") as tmp:
        parts = []
        for i, (name, path) in enumerate(pkgs):
            if not os.path.isdir(path):
                die(f"{path}: not a directory")
            part = os.path.join(tmp, f"part{i}.db")
            # --no-sandbox: landlock grants for 'similar' cover the index db,
            # not arbitrary corpus outputs
            run([a.argus, "--no-sandbox", "similar", path,
                 "--corpus-build", a.name, "--corpus-db", part])
            parts.append(part)
            print(f"[{i + 1}/{len(pkgs)}] {name}: {path}", file=sys.stderr)
        merge_dbs(parts, out)

    if a.key:
        # argus rules-sign writes <stem>.toml.sig (it assumes rulesets);
        # the fetch side expects <file>.sig, so rename
        run([a.argus, "--no-sandbox", "rules-sign", out, "--key", a.key])
        produced = os.path.splitext(out)[0] + ".toml.sig"
        sig_out = out + ".sig"
        os.replace(produced, sig_out)
        print(f"signed: {sig_out}", file=sys.stderr)
    else:
        print(
            "note: --key not given; corpus is unsigned."
            " Sign before publishing: argus rules-sign corpus.db --key priv.hex"
            " then rename the produced .toml.sig to corpus.db.sig",
            file=sys.stderr,
        )

    size = os.path.getsize(out)
    con = sqlite3.connect(out)
    nfiles = con.execute("SELECT count(*) FROM files").fetchone()[0]
    con.close()
    print(f"corpus: {out} ({nfiles} files, {size} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
