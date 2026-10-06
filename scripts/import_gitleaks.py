#!/usr/bin/env python3
"""Import gitleaks' default config as a native argus ruleset.

Resolves the latest stable gitleaks release tag via
git ls-remote --tags, fetches config/gitleaks.toml at that tag, maps each
[[rules]] entry to an argus rule, and writes rules/gitleaks.toml.

gitleaks is MIT-licensed (Copyright (c) 2019 Zachary Rice); the emitted file
carries an attribution header.

Usage: python3 scripts/import_gitleaks.py [--tag vX.Y.Z] [--out PATH]
       python3 scripts/import_gitleaks.py --check   # verify output is current
"""

import re
import subprocess
import sys
import tomllib
import urllib.request

REPO = "https://github.com/gitleaks/gitleaks"
RAW = "https://raw.githubusercontent.com/gitleaks/gitleaks/{tag}/config/gitleaks.toml"
OUT = "rules/gitleaks.toml"

REMEDIATION = "Rotate the credential and remove it from history."
SEVERITY = "high"


def latest_tag() -> str:
    """Newest vX.Y.Z tag on the gitleaks repo (prereleases ignored)."""
    out = subprocess.check_output(
        ["git", "ls-remote", "--tags", REPO], text=True
    )
    best = None
    for line in out.splitlines():
        ref = line.split("\t")[-1]
        if ref.endswith("^{}"):
            continue
        m = re.fullmatch(r"refs/tags/v(\d+)\.(\d+)\.(\d+)", ref)
        if m:
            ver = tuple(int(g) for g in m.groups())
            if best is None or ver > best[0]:
                best = (ver, ref.rsplit("/", 1)[-1])
    if best is None:
        sys.exit("no stable vX.Y.Z tag found on " + REPO)
    return best[1]


def fetch_config(tag: str) -> bytes:
    url = RAW.format(tag=tag)
    with urllib.request.urlopen(url) as r:
        return r.read()


def toml_str(s: str) -> str:
    """Emit s as a TOML basic string."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20 or o == 0x7F:
            out.append(f"\\u{o:04X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


# Go RE2 \w \d \s are ASCII-only; Rust regex makes them Unicode-aware, which
# both diverges semantically and explodes compiled size under large counted
# reps. Expand them to their ASCII forms. Uppercase negations (\W \D \S)
# inside a character class cannot be expanded inline - wrap the class in
# (?-u:...) instead. \b/\B become (?-u:\b)/(?-u:\B), matching RE2's ASCII
# word boundary.
PERL_ASCII = {
    "w": "[A-Za-z0-9_]",
    "W": "[^A-Za-z0-9_]",
    "d": "[0-9]",
    "D": "[^0-9]",
    "s": "[\\t\\n\\f\\r ]",
    "S": "[^\\t\\n\\f\\r ]",
}
PERL_CLASS_PART = {"w": "A-Za-z0-9_", "d": "0-9", "s": "\\t\\n\\f\\r "}
PERL_CLASS_NEG = {"W": "A-Za-z0-9_", "D": "0-9", "S": "\\t\\n\\f\\r "}


def ascii_classes(rx: str) -> str:
    out = []
    i = 0
    while i < len(rx):
        c = rx[i]
        if c == "\\" and i + 1 < len(rx):
            n = rx[i + 1]
            if n in PERL_ASCII:
                out.append(PERL_ASCII[n])
            elif n in "bB":
                out.append(f"(?-u:\\{n})")
            else:
                out.append(rx[i : i + 2])
            i += 2
            continue
        if c == "[":
            j = i + 1
            negated = j < len(rx) and rx[j] == "^"
            if negated:
                j += 1
            if j < len(rx) and rx[j] == "]":
                j += 1
            inner = []      # expanded inner text, minus uppercase escapes
            uppers = []     # letters of \W \D \S seen
            lowers = set()  # letters of \w \d \s seen
            if j < len(rx) and rx[j] == "]":  # literal ] first
                inner.append("]")
                j += 1
            while j < len(rx) and rx[j] != "]":
                if rx[j] == "\\" and j + 1 < len(rx):
                    n = rx[j + 1]
                    if n in PERL_CLASS_PART:
                        lowers.add(n)
                        inner.append(PERL_CLASS_PART[n])
                    elif n in PERL_CLASS_NEG:
                        uppers.append(n)
                    else:
                        inner.append(rx[j : j + 2])
                    j += 2
                    continue
                inner.append(rx[j])
                j += 1
            close = "]" if j < len(rx) else ""
            rest = "".join(inner)
            if not uppers:
                out.append("[" + ("^" if negated else "") + rest + close)
            else:
                out.append(_expand_class(negated, uppers, lowers, rest))
            i = j + 1 if j < len(rx) else j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _expand_class(negated: bool, uppers: list, lowers: set, rest: str) -> str:
    """Expand a class containing \\W \\D \\S without (?-u), which Rust rejects
    when the class could match invalid UTF-8."""
    # complementary pair present (e.g. [\s\S-]) -> matches every char
    if any(u.lower() in lowers for u in uppers):
        return "[^\\s\\S]" if negated else "[\\s\\S]"
    if not negated:
        # [\Wabc] -> (?:[^A-Za-z0-9_]|[abc]); [\S] -> [^\t\n\f\r ]
        branches = [f"[^{PERL_CLASS_NEG[u]}]" for u in uppers]
        if rest:
            branches.append(f"[{rest}]")
        if len(branches) == 1:
            return branches[0]
        return "(?:" + "|".join(branches) + ")"
    # [^\Wabc] -> chars matching all lowercase sets and not rest
    parts = [f"[{PERL_CLASS_NEG[u]}]" for u in uppers]
    if rest:
        parts.append(f"[^{rest}]")
    if len(parts) == 1:
        return parts[0]
    return "[" + "&&".join(parts) + "]"


QUANT = re.compile(r"\{(\d+)(?:,(\d*))?\}\??")

# Pathological counted-repetition upper bounds are flattened to {m,}:
# detection-equivalent for secret scanning while bounding compiled size.
MAX_REP_BOUND = 4096


def rustify(rx: str) -> str:
    """Adapt a Go RE2 pattern to Rust's regex crate: ASCII-ify Perl classes,
    escape literal { (RE2 treats a { that does not start a valid
    quantifier as a literal; Rust errors on it) and cap large
    counted-repetition upper bounds."""
    rx = ascii_classes(rx)
    out = []
    i, inclass = 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\" and i + 1 < len(rx):
            out.append(rx[i : i + 2])
            i += 2
            continue
        if c == "[" and not inclass:
            inclass = True
        elif c == "]" and inclass:
            inclass = False
        elif c == "{" and not inclass:
            m = QUANT.match(rx, i)
            if m is None:
                out.append("\\")
            else:
                token = m.group(0)
                hi = m.group(2)
                if hi and int(hi) >= MAX_REP_BOUND:
                    token = "{%s,}" % m.group(1)
                    if rx[m.end() - 1] == "?":
                        token += "?"
                out.append(token)
                i = m.end()
                continue
        out.append(c)
        i += 1
    return "".join(out)


def allowlist_exclude(rule: dict):
    """Combined per-match suppression regex if the rule's allowlists are
    expressible as an argus exclude, else None.

    Expressible: every allowlist entry is regexes-only with regexTarget
    'match' (or unset; gitleaks default), or 'secret' when the rule has no
    secretGroup (secret == match). Entries with paths, stopwords, commits,
    line-target or AND conditions cannot be expressed.
    """
    als = rule.get("allowlists")
    if not als:
        return ""
    has_group = bool(rule.get("secretGroup"))
    parts = []
    for a in als:
        extra = set(a) - {"description", "regexes", "regexTarget"}
        if extra or not a.get("regexes"):
            return None
        target = a.get("regexTarget", "match")
        if target == "secret" and has_group:
            return None
        if target not in ("match", "secret"):
            return None
        parts.extend(a["regexes"])
    return "|".join(f"(?:{rustify(p)})" for p in parts)


def convert(rule: dict, log):
    """Map one gitleaks rule to an argus rule dict, or None to skip."""
    rid = "GL-" + rule["id"]
    regex = rule.get("regex")
    path = rule.get("path")
    entropy = rule.get("entropy")
    sgroup = rule.get("secretGroup")
    rtarget = rule.get("regexTarget", "match")

    # keywords become argus' proximity gate: lowercased (the automaton is
    # case-sensitive over raw text), deduplicated, non-empty only. The path
    # kind has no keyword support, so they are dropped there.
    keywords = sorted(
        {k.lower() for k in rule.get("keywords", []) if k.strip()}
    )

    exclude = allowlist_exclude(rule)
    if exclude is None:
        log(f"SKIP {rid}: allowlist uses paths/stopwords/line-target/AND "
            f"conditions that argus cannot express")
        return None

    if regex is None:
        if path is None:
            log(f"SKIP {rid}: no regex and no path")
            return None
        # path-only rule
        return {
            "id": rid, "kind": "path", "regex": rustify(path),
            "description": rule["description"],
        }

    regex = rustify(regex)
    wants_secret = (entropy is not None or sgroup) and rtarget == "match"
    if wants_secret and path is None and not exclude:
        # gitleaks: no secretGroup means the whole match is the secret.
        # gitleaks has no length floor, so min_len is pinned to 1.
        out = {
            "id": rid, "kind": "secret", "regex": regex,
            "group": sgroup or 0,
            "entropy": entropy,
            "min_len": 1,
            "description": rule["description"],
        }
        if keywords:
            out["keywords"] = keywords
        return out

    if wants_secret:
        why = []
        if path is not None:
            why.append("path scope")
        if exclude:
            why.append("allowlist")
        log(f"DOWNGRADE {rid}: secret rule emitted as content "
            f"({', '.join(why)}); entropy floor dropped")
    elif rtarget != "match":
        log(f"NOTE {rid}: regexTarget={rtarget!r} emitted as content rule")

    out = {
        "id": rid, "kind": "content", "regex": regex,
        "description": rule["description"],
    }
    if path is not None:
        out["path"] = rustify(path)
    if exclude:
        out["exclude"] = exclude
    if keywords:
        out["keywords"] = keywords
    return out


def emit(tag: str, rules: list) -> str:
    lines = [
        "# Generated by scripts/import_gitleaks.py - do not edit by hand.",
        f"# Source: gitleaks {tag} config/gitleaks.toml",
        "#",
        "# gitleaks is MIT-licensed: Copyright (c) 2019 Zachary Rice.",
        "# These rules are adapted from the gitleaks default configuration",
        "# under the terms of the MIT license.",
        "#",
        "# Mapping notes:",
        "#   - rules with entropy/secretGroup emit as type=\"secret\"; the",
        "#     group field is gitleaks' secretGroup (0 = whole match).",
        "#   - min_len = 1 preserves gitleaks semantics (it has no length",
        "#     floor); the entropy check still gates candidates.",
        "#   - secret rules needing path scope or an allowlist degrade to",
        "#     type=\"content\" (argus secret rules support neither); the",
        "#     allowlist regexes fold into exclude, the entropy floor is",
        "#     dropped. Rules whose allowlists cannot be expressed are",
        "#     skipped entirely - see importer stderr.",
        "#   - \\w \\d \\s (and negations) are expanded to ASCII - Go RE2",
        "#     classes are ASCII-only while Rust defaults to Unicode;",
        "#     \\b/\\B become (?-u:\\b)/(?-u:\\B), literal { is escaped,",
        "#     and {m,n} reps with n >= 4096 become {m,}. All rewrites",
        "#     preserve detection semantics.",
        "#   - gitleaks keywords emit as the keywords proximity gate",
        "#     (lowercased, deduplicated): a hit fires only when a keyword",
        "#     appears within 250 bytes of the match.",
        "",
        "[ruleset]",
        'name = "gitleaks"',
        f'version = "{tag.lstrip("v")}"',
        'description = "gitleaks default ruleset, adapted"',
        f'source = "gitleaks {tag} config/gitleaks.toml (MIT)"',
        "",
    ]
    for r in rules:
        lines.append("[[rule]]")
        lines.append(f"id = {toml_str(r['id'])}")
        lines.append(f'type = "{r["kind"]}"')
        lines.append(f'severity = "{SEVERITY}"')
        if r["kind"] == "path":
            lines.append(f"regex = {toml_str(r['regex'])}")
        else:
            if "path" in r:
                lines.append(f"path = {toml_str(r['path'])}")
            lines.append(f"regex = {toml_str(r['regex'])}")
            if r["kind"] == "secret":
                lines.append(f"group = {r['group']}")
                if r.get("entropy") is not None:
                    lines.append(f"entropy = {r['entropy']}")
                lines.append(f"min_len = {r['min_len']}")
            if "exclude" in r:
                lines.append(f"exclude = {toml_str(r['exclude'])}")
            if r.get("keywords"):
                kws = ", ".join(toml_str(k) for k in r["keywords"])
                lines.append(f"keywords = [{kws}]")
        lines.append(f"description = {toml_str(r['description'])}")
        lines.append(f"remediation = {toml_str(REMEDIATION)}")
        lines.append(
            f'reference = "https://github.com/gitleaks/gitleaks/blob/{tag}/config/gitleaks.toml"'
        )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = sys.argv[1:]
    tag = None
    out_path = OUT
    check = "--check" in args
    if "--tag" in args:
        tag = args[args.index("--tag") + 1]
    if "--out" in args:
        out_path = args[args.index("--out") + 1]

    if tag is None:
        tag = latest_tag()
    cfg = tomllib.loads(fetch_config(tag).decode("utf-8"))

    log = lambda m: print(f"import_gitleaks: {m}", file=sys.stderr)
    log(f"pinned tag: {tag}")

    emitted, seen = [], set()
    for rule in cfg["rules"]:
        conv = convert(rule, log)
        if conv is None:
            continue
        if conv["id"] in seen:
            log(f"SKIP {conv['id']}: duplicate id")
            continue
        seen.add(conv["id"])
        emitted.append(conv)

    text = emit(tag, emitted)
    if check:
        try:
            cur = open(out_path, encoding="utf-8").read()
        except OSError:
            cur = None
        if cur == text:
            print(f"{out_path}: up to date ({len(emitted)} rules, {tag})")
            return 0
        print(f"{out_path}: STALE", file=sys.stderr)
        return 1

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    log(f"wrote {out_path}: {len(emitted)} rules "
        f"({len(cfg['rules']) - len(emitted)} skipped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
