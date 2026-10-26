#!/usr/bin/env python3
"""Regenerate rules/data/cve-ghsa.toml from published GitHub security advisories.

Covers Traefik (v2 and v3) and Caddy (v2). The hand-curated feed for nginx,
PHP, Brotli and Apache httpd lives in rules/data/cve-web.toml and is not
touched. Set GITHUB_TOKEN to raise the API rate limit.

    python3 scripts/build_cve_db.py > rules/data/cve-ghsa.toml

Version ranges that only describe pre-release builds are dropped. A lower
bound that names a pre-release is widened to its release.
"""

import json
import os
import re
import sys
import urllib.request

REPOS = {
    "traefik/traefik": ("traefik", 2),
    "caddyserver/caddy": ("caddy", 2),
}
SEV = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


def fetch(repo):
    url = f"https://api.github.com/repos/{repo}/security-advisories?per_page=100&state=published"
    out = {}
    while url:
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
        tok = os.environ.get("GITHUB_TOKEN")
        if tok:
            req.add_header("Authorization", f"Bearer {tok}")
        with urllib.request.urlopen(req, timeout=60) as resp:
            for adv in json.load(resp):
                out[adv["ghsa_id"]] = adv
            link = resp.headers.get("Link", "")
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = m.group(1) if m else None
    return list(out.values())


PKGS = {
    "github.com/traefik/traefik/v2": "traefik/traefik",
    "github.com/traefik/traefik/v3": "traefik/traefik",
    "github.com/caddyserver/caddy/v2": "caddyserver/caddy",
}


def fetch_global(pkg):
    url = f"https://api.github.com/advisories?ecosystem=go&affects={pkg}&per_page=100"
    out = {}
    while url:
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
        tok = os.environ.get("GITHUB_TOKEN")
        if tok:
            req.add_header("Authorization", f"Bearer {tok}")
        with urllib.request.urlopen(req, timeout=60) as resp:
            for adv in json.load(resp):
                for v in adv["vulnerabilities"]:
                    fp = v.get("first_patched_version")
                    v["patched_versions"] = fp if isinstance(fp, str) else (fp or {}).get("identifier", "")
                adv["html_url"] = adv.get("html_url") or adv.get("url")
                out[adv["ghsa_id"]] = adv
            link = resp.headers.get("Link", "")
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = m.group(1) if m else None
    return list(out.values())


def num(v):
    v = v.strip().lstrip("v").lstrip(".")
    base = re.split(r"[-+]", v, maxsplit=1)[0]
    pre = base != v and "-" in v
    parts = [int(p) for p in base.split(".") if p.isdigit()]
    return parts, pre


def ver(parts):
    return ".".join(str(p) for p in parts)


def convert(rng, min_major, floor):
    lo = hi = None
    for part in rng.split(","):
        part = part.strip()
        m = re.match(r"(>=|<=|>|<|=)\s*(\S+)", part)
        if not m:
            return None
        op, raw = m.groups()
        parts, pre = num(raw)
        if not parts:
            return None
        if op in ("<", "<="):
            if pre:
                return None
            hi = (op, parts)
        elif op in (">", ">="):
            lo = (op, parts)
        else:
            lo = (">=", parts)
            hi = ("<=", parts)
    if not lo:
        lo = (">=", [floor, 0, 0])
    cons = []
    if lo:
        cons.append(f"{lo[0]}{ver(lo[1])}")
    if hi:
        top = hi[1]
        if hi[0] == "<=" and not lo:
            pass
        cons.append(f"{hi[0]}{ver(top)}")
    if not cons:
        return None
    top = hi[1] if hi else (lo[1] if lo else [0])
    if top[0] < min_major:
        return None
    return " ".join(cons)


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main():
    rows = []
    for repo, (product, min_major) in REPOS.items():
        merged = {}
        for pkg, r in PKGS.items():
            if r == repo:
                for a in fetch_global(pkg):
                    merged[a["ghsa_id"]] = a
        for a in fetch(repo):
            if a["ghsa_id"] not in merged and any(
                v.get("vulnerable_version_range") for v in a["vulnerabilities"]
            ):
                merged[a["ghsa_id"]] = a
        for adv in merged.values():
            if adv.get("withdrawn_at") or adv["severity"] not in SEV:
                continue
            ranges, fixed = [], []
            for v in adv["vulnerabilities"]:
                r = v.get("vulnerable_version_range") or ""
                pkg = v["package"]["name"]
                m = re.search(r"/v(\d+)$", pkg)
                floor = int(m.group(1)) if m else min_major
                c = convert(r, min_major, floor) if r else None
                if c and c not in ranges:
                    ranges.append(c)
                    p = (v.get("patched_versions") or "").strip().lstrip("v.").lstrip("v")
                    if p and "-" not in p and p not in fixed:
                        fixed.append(p)
            if not ranges:
                continue
            cve = adv.get("cve_id")
            rows.append(
                {
                    "id": cve or adv["ghsa_id"],
                    "aliases": [adv["ghsa_id"]] if cve else [],
                    "product": product,
                    "severity": SEV[adv["severity"]],
                    "title": re.sub(r"\s+", " ", adv["summary"]).encode("ascii", "ignore").decode().strip(),
                    "affected": ranges,
                    "fixed": " / ".join(sorted(fixed, key=lambda s: num(s)[0])),
                    "ref": adv["html_url"],
                    "published": adv["published_at"][:10],
                }
            )
    rows.sort(key=lambda r: (r["product"], r["published"], r["id"]))
    print("# Generated by scripts/build_cve_db.py from GitHub security advisories.")
    print("# Do not edit by hand. Re-run the script to refresh.\n")
    for r in rows:
        print("[[advisory]]")
        print(f'id = "{esc(r["id"])}"')
        if r["aliases"]:
            print("aliases = [" + ", ".join(f'"{a}"' for a in r["aliases"]) + "]")
        print(f'product = "{r["product"]}"')
        print(f'severity = "{r["severity"]}"')
        print(f'title = "{esc(r["title"])}"')
        print("affected = [" + ", ".join(f'"{a}"' for a in r["affected"]) + "]")
        print(f'fixed = "{esc(r["fixed"])}"')
        print(f'ref = "{esc(r["ref"])}"')
        print(f'published = "{r["published"]}"')
        print()


if __name__ == "__main__":
    sys.exit(main())
