#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
# Copyright (c) 2026 Quad4
#
# Secrets-detection benchmark for argus.
#
# Runs `argus scan CORPUS --format json` and scores findings that belong to
# the secrets ruleset (ruleset == "secrets" or rule_id starting with SEC-,
# VER- or GL-) against ground-truth labels.
#
# Labels come from either:
#   --labels FILE   CSV with rows: relpath,label   (label = true|false,
#                   paths relative to the corpus root)
#   (default)       corpus/true/** is positive, corpus/false/** is negative
#
# A file with secret findings that is not labeled positive counts as a
# false positive; labeled positives with no secret finding are false
# negatives. Prints a per-file verdict table plus precision/recall/F1
# totals. Exit code: 0 on success, 1 if any FP or FN, 2 on tool errors.
#
# SecretBench (Basak et al., arXiv:2303.06729) and FPSecretBench are the
# public labeled corpora this is built for, but both are hosted on Google
# Cloud, not plain downloads:
#   - BigQuery table dev-range-332204.secretbench.secrets holds the labels
#     (secret text, repo, file path, start line, true/false).
#   - gs://secretbench Files.zip holds the files containing secrets.
# Export the BigQuery table to CSV, map its file-path column to relpath and
# its label column to true|false, extract Files.zip as --corpus, and pass
# the mapped CSV as --labels. The repo ships a small seeded corpus under
# tests/bench/seed for the CI gate; the full dataset needs a GCP account.

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys

SECRET_RULESETS = {"secrets", "verify"}
SECRET_PREFIXES = ("SEC-", "VER-", "GL-")


def find_binary(override):
    if override:
        return override
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.normpath(os.path.join(here, "..", "target", "release", "argus"))
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    path_hit = shutil.which("argus")
    if path_hit:
        return path_hit
    sys.exit("error: argus binary not found (build --release or put argus on PATH)")


def is_secret_finding(f):
    rid = f.get("rule_id") or ""
    return f.get("ruleset") in SECRET_RULESETS or rid.startswith(SECRET_PREFIXES)


def load_labels(corpus, labels_file):
    labels = {}
    if labels_file:
        with open(labels_file, newline="") as fh:
            for row in csv.reader(fh):
                if not row or len(row) < 2:
                    continue
                rel, lab = row[0].strip(), row[1].strip().lower()
                if not rel or rel.startswith("#"):
                    continue
                if rel.lower() in ("relpath", "path", "file"):
                    continue  # header row
                labels[rel] = lab == "true"
    else:
        for sub, val in (("true", True), ("false", False)):
            base = os.path.join(corpus, sub)
            for root, _dirs, files in os.walk(base):
                for name in files:
                    rel = os.path.relpath(os.path.join(root, name), corpus)
                    labels[rel] = val
    return labels


def main():
    ap = argparse.ArgumentParser(description="Benchmark argus secrets detection against a labeled corpus.")
    ap.add_argument("--corpus", required=True, help="corpus root directory to scan")
    ap.add_argument("--labels", default=None, help="CSV of relpath,true|false (default: corpus/true|false dirs)")
    ap.add_argument("--argus", default=None, help="path to argus binary")
    args = ap.parse_args()

    corpus = os.path.abspath(args.corpus)
    if not os.path.isdir(corpus):
        sys.exit(f"error: corpus {corpus} is not a directory")
    argus = find_binary(args.argus)

    proc = subprocess.run(
        [argus, "scan", corpus, "--format", "json"],
        capture_output=True,
        text=True,
    )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        sys.stderr.write(proc.stderr)
        sys.exit(f"error: argus did not emit JSON on stdout (exit {proc.returncode})")

    hits = {}
    for f in report.get("findings", []):
        if is_secret_finding(f):
            path = f.get("path") or ""
            hits[path] = hits.get(path, 0) + 1

    labels = load_labels(corpus, args.labels)

    tp = fp = fn = tn = 0
    rows = []
    # labeled files first, then unlabeled files that still produced hits
    for rel in sorted(set(labels) | set(hits)):
        expected = labels.get(rel, False)
        n = hits.get(rel, 0)
        predicted = n > 0
        if expected and predicted:
            verdict, tp_ = "TP", 1
            tp += 1
        elif expected and not predicted:
            verdict = "FN"
            fn += 1
        elif not expected and predicted:
            verdict = "FP"
            fp += 1
        else:
            verdict = "TN"
            tn += 1
        rows.append((rel, "true" if expected else "false", n, verdict))

    width = max([len(r[0]) for r in rows] + [4])
    print(f"{'file'.ljust(width)}  label  hits  verdict")
    for rel, lab, n, verdict in rows:
        mark = {"TP": "TP", "FP": "FP <-- false positive", "FN": "FN <-- missed", "TN": "ok"}[verdict]
        print(f"{rel.ljust(width)}  {lab:5}  {n:4}  {mark}")

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    print()
    print(f"files: {len(rows)}  TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"precision={precision:.3f}  recall={recall:.3f}  f1={f1:.3f}")
    if not labels:
        print("note: no labels found (empty corpus or missing true/false dirs)")

    sys.exit(1 if (fp or fn) else 0)


if __name__ == "__main__":
    main()
