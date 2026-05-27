"""process-yara-forge-pack.py

Process the YARA-Forge concatenated rule pack into two outputs:

  1. A *scrubbed* `.yar` file containing only rule-sets whose
     comment-block LICENSE is in the project's permissive allowlist
     (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, CC0-1.0, MPL-2.0,
     Unicode-3.0 — per ATTRIBUTIONS.txt § 1.3 and deny.toml).

  2. `YARA-RULE-AUTHORS.txt` — a per-rule attribution manifest
     grouped by author, sourcing the rule-set license (which is
     declared at the rule-set comment-block level in YARA-Forge,
     NOT at the per-rule meta level — most rules in core declare
     `license_url = "N/A"` in their meta block).

Why this script exists separately from
`scripts/license-scrub-yara.ts`:

The YARA-Forge `core` release tier ships as ONE concatenated .yar
file under `packages/core/yara-rules-core.yar`. The .ts scrubber
handles the "one rule per file in a directory" shape; YARA-Forge
doesn't ship that shape. This Python tool handles the actual shape.

YARA-Forge's `core` tier filters by detection quality and importance,
not by license — the pack contains many "NO LICENSE SET" and even
GPL-3 / proprietary rule-sets that the project CANNOT redistribute
with its binary. The scrub here is therefore *load-bearing*, not
defense-in-depth.

Usage:

    python scripts/process-yara-forge-pack.py \
        <input.yar> <scrubbed_output.yar> <authors_output.txt>

Exits non-zero on any malformed input or when the resulting pack is
empty (all sections rejected — would be a release-blocking surprise
that warrants a human look at the upstream pack).
"""
from __future__ import annotations

import collections
import re
import sys
from pathlib import Path


# ----------------------------------------------------------------
# Licensing
# ----------------------------------------------------------------

# Allowed-license matchers. Each entry is (canonical SPDX label,
# matcher function). The matcher takes the raw license text from a
# rule-set comment block (multi-line) and returns True iff the text
# is unambiguously that license.
#
# YARA-Forge embeds the full license TEXT in the comment block, not
# just the SPDX ID — so the matchers look for distinctive phrases
# that only appear in the canonical license. We deliberately err
# strict: a comment block that mentions "Apache" but not the actual
# Apache License phrasing does not match.

def _has(text: str, *needles: str) -> bool:
    """All of *needles* must appear in *text* (case-insensitive)."""
    low = text.lower()
    return all(n.lower() in low for n in needles)


def _has_any(text: str, *needles: str) -> bool:
    low = text.lower()
    return any(n.lower() in low for n in needles)


def classify_license(license_text: str) -> str:
    """Return the canonical SPDX label this license text matches, or
    "" if no allowed license matches. Strict order: more-specific
    first."""

    t = license_text.strip()
    if not t:
        return ""

    # Sentinel value used by YARA-Forge when a rule-set has no
    # declared license. Always reject — we cannot publish what is
    # not licensed.
    if "no license set" in t.lower():
        return ""

    # Hard rejections — common non-allowed patterns. Checked before
    # the positive matchers so an "Apache 2.0 ... but only for
    # non-commercial use" rider would be caught here.
    if _has_any(t, "gnu general public license", "gnu gpl", "gplv3", "gpl-3", "gpl 3"):
        # GPL excluded per deny.toml.
        return ""
    if _has_any(t, "agpl", "affero"):
        return ""
    if _has_any(t, "all rights reserved") and not _has_any(
        t, "apache license", "mit license", "bsd", "creative commons zero"
    ):
        # Proprietary "all rights reserved" with no fallback license.
        return ""
    if _has_any(t, "detection rule license", "drl-1.1", "drl 1.1"):
        return ""
    if _has_any(t, "creative commons attribution-noncommercial", "cc-by-nc", "cc by-nc"):
        return ""
    if _has(t, "creative commons attribution") and not _has(t, "zero"):
        # CC-BY-* (not CC0). Rejected — attribution carries forward
        # to the binary distribution in a way we don't currently
        # surface per-asset.
        return ""

    # Positive matchers, most-specific first.
    if _has(t, "apache license", "version 2.0"):
        return "Apache-2.0"
    if _has(t, "bsd 2-clause license") or _has(t, "bsd 2 clause license"):
        return "BSD-2-Clause"
    if _has(t, "bsd 3-clause license") or _has(t, "bsd 3 clause license"):
        return "BSD-3-Clause"
    if _has(t, "redistribution and use in source and binary forms"):
        # Vanilla BSD license without an explicit clause-count
        # header. Look for the 3-clause marker (the "neither the name")
        # phrase; otherwise treat as 2-clause.
        if _has(t, "neither the name of"):
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    if _has(t, "permission is hereby granted, free of charge"):
        # The MIT license's defining sentence. Several
        # MIT-derivatives use it verbatim.
        return "MIT"
    if _has(t, "creative commons zero") or _has(t, "cc0"):
        return "CC0-1.0"
    if _has(t, "mozilla public license", "version 2.0"):
        return "MPL-2.0"
    if _has(t, "unicode license") and _has_any(t, "v3", "version 3"):
        return "Unicode-3.0"

    return ""


# ----------------------------------------------------------------
# Pack parsing
# ----------------------------------------------------------------

# Each rule-set begins with a block-comment that starts with
# `/* YARA Rule Set` on the SECOND line (the first line is just `/*`).
# We use a regex to find the *opening* of each rule-set comment in
# the pack; everything between two consecutive openings (or between
# the last opening and EOF) is one rule-set's territory.
_RULESET_OPEN_RE = re.compile(r"^/\*\r?\n \* YARA Rule Set\r?\n", re.MULTILINE)

# Inside a rule-set's leading comment block, find the LICENSE
# sub-section. It begins with ` * LICENSE` on its own line and
# continues until the closing ` */` of the comment block. We strip
# the leading ` * ` prefix from each captured line.
_LICENSE_HEADER_RE = re.compile(
    r"^ \* LICENSE\r?\n \* \r?\n(?P<body>(?:.|\n)*?)(?=\n \*/)",
    re.MULTILINE,
)

# Per-rule meta extraction (used for the attribution manifest only).
_RULE_OPEN_RE = re.compile(r"\brule\s+([A-Za-z0-9_]+)\b")
_META_AUTHOR_RE = re.compile(r'\bauthor\s*=\s*"([^"]*)"')
_META_REF_RE = re.compile(r'\breference\s*=\s*"([^"]*)"')


def split_into_rulesets(pack: str) -> list[tuple[int, int]]:
    """Return list of (start_offset, end_offset) for each rule-set
    in *pack*. The first section (before any rule-set) is the file
    header (imports etc.) — we DO NOT include it in the output list."""
    opens = [m.start() for m in _RULESET_OPEN_RE.finditer(pack)]
    if not opens:
        return []
    sections: list[tuple[int, int]] = []
    for i, start in enumerate(opens):
        end = opens[i + 1] if i + 1 < len(opens) else len(pack)
        sections.append((start, end))
    return sections


def extract_license_text(section: str) -> str:
    """Pull the multi-line LICENSE body from a rule-set's leading
    comment block. Returns the raw text (with leading ` * ` prefixes
    stripped from each line), or "" if no LICENSE header found."""
    m = _LICENSE_HEADER_RE.search(section)
    if not m:
        return ""
    body = m.group("body")
    out_lines = []
    for line in body.splitlines():
        # Each line is prefixed with ` * ` (or ` *` for blank lines).
        if line.startswith(" * "):
            out_lines.append(line[3:])
        elif line.startswith(" *"):
            out_lines.append(line[2:])
        else:
            out_lines.append(line)
    return "\n".join(out_lines).strip()


def extract_rules(section: str) -> list[tuple[str, str, str]]:
    """For each rule block in *section*, return (rule_name, author,
    reference). Used to build the attribution manifest."""
    positions = [(m.start(), m.group(1)) for m in _RULE_OPEN_RE.finditer(section)]
    out: list[tuple[str, str, str]] = []
    for i, (start, name) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(section)
        block = section[start:end]
        a = _META_AUTHOR_RE.search(block)
        r = _META_REF_RE.search(block)
        out.append((
            name,
            " ".join(a.group(1).split()) if a else "(unknown)",
            " ".join(r.group(1).split()) if r else "",
        ))
    return out


def extract_repo_name(section: str) -> str:
    m = re.search(r"^ \* Repository Name:\s*(.+)$", section, re.MULTILINE)
    return m.group(1).strip() if m else "(unknown)"


# ----------------------------------------------------------------
# Main
# ----------------------------------------------------------------

def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: process-yara-forge-pack.py <input.yar> "
            "<scrubbed_output.yar> <authors_output.txt>",
            file=sys.stderr,
        )
        return 2

    input_path = Path(argv[1])
    scrubbed_path = Path(argv[2])
    authors_path = Path(argv[3])

    if not input_path.is_file():
        print(f"input pack not found: {input_path}", file=sys.stderr)
        return 2

    pack = input_path.read_text(encoding="utf-8", errors="replace")
    sections = split_into_rulesets(pack)

    if not sections:
        print(
            "no `YARA Rule Set` sections found — wrong file format?",
            file=sys.stderr,
        )
        return 2

    # The original file's first bytes (before the first rule-set) are
    # the pack-level header + `import` lines. Preserve them so the
    # scrubbed output is still parseable as a standalone YARA pack.
    header = pack[: sections[0][0]]

    kept_chunks: list[str] = [header]
    kept_rulesets = 0
    rejected_rulesets = 0
    kept_rules_total = 0
    rejected_rules_total = 0
    rejected_by_license: dict[str, int] = collections.Counter()
    kept_by_license: dict[str, int] = collections.Counter()

    # Per-rule records for the attribution manifest. Each entry:
    # {rule, author, license_spdx, reference, ruleset_repo}.
    authors_records: list[dict[str, str]] = []

    for start, end in sections:
        section = pack[start:end]
        license_text = extract_license_text(section)
        spdx = classify_license(license_text)
        rules_in_section = extract_rules(section)
        repo = extract_repo_name(section)

        if spdx:
            kept_chunks.append(section)
            kept_rulesets += 1
            kept_rules_total += len(rules_in_section)
            kept_by_license[spdx] += 1
            for name, author, reference in rules_in_section:
                authors_records.append({
                    "rule": name,
                    "author": author,
                    "license_spdx": spdx,
                    "reference": reference,
                    "ruleset_repo": repo,
                })
        else:
            rejected_rulesets += 1
            rejected_rules_total += len(rules_in_section)
            # Bucket the rejection reason by the first non-blank line
            # of the license text, falling back to "(no LICENSE header)"
            # or "(empty)" so we get a useful breakdown.
            if not license_text:
                reason = "(no LICENSE header)"
            else:
                first_line = next(
                    (ln for ln in license_text.splitlines() if ln.strip()),
                    "(empty)",
                )
                reason = first_line.strip()[:80]
            rejected_by_license[reason] += 1

    if kept_rulesets == 0:
        print(
            "FATAL: 0 rule-sets allowed after scrub. Refusing to "
            "write an empty pack — inspect the upstream release.",
            file=sys.stderr,
        )
        return 1

    # ----------------------------------------------------------------
    # Write the scrubbed pack.
    # ----------------------------------------------------------------
    scrubbed_path.write_text("".join(kept_chunks), encoding="utf-8")

    # ----------------------------------------------------------------
    # Write the attribution manifest.
    # ----------------------------------------------------------------
    by_author: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    for rec in authors_records:
        by_author[rec["author"]].append(rec)

    license_counts = collections.Counter(r["license_spdx"] for r in authors_records)

    with authors_path.open("w", encoding="utf-8") as f:
        f.write("MYTHODIKAL ANTI-VIRUS — YARA RULE AUTHORS\n")
        f.write("=" * 64 + "\n\n")
        f.write(
            "This file lists every YARA rule shipped with Mythodikal\n"
            "Anti-Virus's bundled rule pack, grouped by author, with\n"
            "the rule-set's declared SPDX license and reference URL.\n"
            "Generated by `scripts/process-yara-forge-pack.py` from\n"
            "the YARA-Forge `core` release. Ships alongside\n"
            "ATTRIBUTIONS.txt (see ATTRIBUTIONS.txt § 1.3).\n\n"
            "License resolution is at the rule-set level (per\n"
            "YARA-Forge's pack format), not per-rule meta. Every\n"
            "license shown below is one of the project's permitted\n"
            "SPDX identifiers: MIT, Apache-2.0, BSD-2-Clause,\n"
            "BSD-3-Clause, CC0-1.0, MPL-2.0, Unicode-3.0.\n\n"
        )
        f.write(f"Total rules    : {len(authors_records)}\n")
        f.write(f"Unique authors : {len(by_author)}\n")
        f.write(f"Rule-sets kept : {kept_rulesets}\n")
        f.write(f"Rule-sets cut  : {rejected_rulesets}\n\n")
        f.write("License distribution (per rule, by allowed SPDX):\n")
        for lic, count in sorted(license_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            f.write(f"  {count:>5}  {lic}\n")
        f.write("\n" + "=" * 64 + "\n\n")
        for author in sorted(by_author):
            f.write(f"Author: {author}\n")
            f.write("-" * 64 + "\n")
            for rec in sorted(by_author[author], key=lambda r: r["rule"]):
                line = f"  {rec['rule']}  [{rec['license_spdx']}, set: {rec['ruleset_repo']}]"
                if rec["reference"]:
                    line += f"\n      ref: {rec['reference']}"
                f.write(line + "\n")
            f.write("\n")
        f.write("=" * 64 + "\n")
        f.write("End of YARA rule authors.\n")

    # ----------------------------------------------------------------
    # Console summary (CI logs).
    # ----------------------------------------------------------------
    print(f"process-yara-forge-pack: input  = {input_path}")
    print(f"                         output = {scrubbed_path}")
    print(f"                         authors= {authors_path}")
    print()
    print(f"  kept    : {kept_rulesets} rule-sets ({kept_rules_total} rules)")
    print(f"  rejected: {rejected_rulesets} rule-sets ({rejected_rules_total} rules)")
    print()
    if kept_by_license:
        print("  kept-license distribution (rule-sets, by SPDX):")
        for lic, n in sorted(kept_by_license.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"    {n:>5}  {lic}")
        print()
    if rejected_by_license:
        print("  rejected-license distribution (first line of LICENSE header):")
        for reason, n in sorted(rejected_by_license.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"    {n:>5}  {reason}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
