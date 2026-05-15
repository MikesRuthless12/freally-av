/**
 * license-scrub-yara.ts
 *
 * Per-file scrubber for YARA rule packs whose input shape is a
 * **directory of individual `.yar` files** with `meta: license = "..."`
 * declared inside each rule's meta block. Removes any file containing
 * any rule whose meta license is not on the project's permissive
 * allowlist (MIT / Apache-2.0 / BSD-2-Clause / BSD-3-Clause /
 * CC0-1.0 / MPL-2.0 / Unicode-3.0 — per ATTRIBUTIONS.txt § 1.3).
 *
 * NOT used by `.github/workflows/bundle-attributions.yml` —
 * YARA-Forge's `core` release ships ONE concatenated .yar file, not
 * a directory of individual files. For that format, the workflow
 * uses `scripts/process-yara-forge-pack.py` which does rule-set-level
 * scrubbing from comment-block LICENSE headers (the location YARA-Forge
 * actually puts the license info).
 *
 * Kept in the tree because the directory + per-rule-meta shape is
 * common for other YARA pack sources — Sigma's rule pack, the
 * maintainer's `tools/feed-builder/yara_rules/`, third-party packs
 * downloaded loose, etc. — and this scrubber is a clean fit for that
 * shape. If a future workflow ever ingests one of those, plug this
 * script in.
 *
 * Allowed SPDX identifiers (mirrors ATTRIBUTIONS.txt § 1.3 + deny.toml):
 *
 *     MIT
 *     Apache-2.0
 *     BSD-2-Clause
 *     BSD-3-Clause
 *     CC0-1.0
 *     MPL-2.0
 *     Unicode-3.0
 *
 * NOT allowed (rejected intentionally):
 *
 *     Detection Rule License (DRL-1.1)   — non-commercial-style restrictions
 *     CC-BY-* / CC-BY-NC-*               — attribution / NC clauses don't
 *                                           survive a binary-only ship
 *     UK Open Government Licence         — bespoke terms
 *     Any custom upstream license link   — bespoke terms
 *     (unspecified) / (unknown) / ""     — no license declared
 *
 * The scrub bias is STRICT: false-positive drops are tolerable; false-
 * negative passes are a compliance breach. A rule's license must match
 * an allowed SPDX ID exactly (after light normalization) or the rule
 * is rejected.
 *
 * File-level vs rule-level: this script removes whole .yar files when
 * any rule inside has a disallowed license. We do NOT surgically rewrite
 * .yar files to keep some rules and drop others; that adds risk (parse
 * errors, broken module imports). The YARA-Forge core pack is grouped
 * by family / source per-file already, so file-level granularity is
 * fine in practice.
 *
 * Usage:
 *
 *     npx tsx scripts/license-scrub-yara.ts <unzipped-core-dir>
 *
 * Exits non-zero if no .yar files are found (treated as a programming
 * error — the caller passed the wrong directory).
 */
import { existsSync, readdirSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

const ALLOWED_SPDX = new Set([
    "MIT",
    "APACHE-2.0",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "CC0-1.0",
    "MPL-2.0",
    "UNICODE-3.0",
]);

/**
 * Normalize a `meta: license = "..."` value into a canonical
 * upper-case SPDX-ish token if we can recognize it; otherwise
 * return the original (upper-cased) string so the caller can log
 * exactly what was rejected.
 *
 * We deliberately do NOT try to parse compound expressions
 * ("MIT OR Apache-2.0"). YARA rules in practice declare a single
 * license per rule. A compound expression is treated as "unknown"
 * and rejected — that's the safe direction.
 */
function normalizeLicense(raw: string): string {
    const trimmed = raw.trim();
    if (trimmed === "") return "";

    // Strip trailing URL fragments — many DRL-1.1 entries are
    // `Detection Rule License 1.1 https://github.com/...`. The URL
    // adds noise; the license name is what matters.
    const withoutUrl = trimmed.replace(/https?:\/\/\S+/gi, "").trim();
    const upper = withoutUrl.toUpperCase();

    // Light normalization: collapse internal whitespace, normalize
    // common "BSD 2 Clause" / "BSD-2-Clause" / "BSD-2 CLAUSE" variants.
    const collapsed = upper.replace(/\s+/g, " ");

    if (collapsed === "MIT" || collapsed === "MIT LICENSE") return "MIT";
    if (collapsed === "APACHE-2.0" || collapsed === "APACHE 2.0" || collapsed === "APACHE LICENSE 2.0") {
        return "APACHE-2.0";
    }
    if (collapsed === "BSD-2-CLAUSE" || collapsed === "BSD 2-CLAUSE" || collapsed === "BSD 2 CLAUSE") {
        return "BSD-2-CLAUSE";
    }
    if (collapsed === "BSD-3-CLAUSE" || collapsed === "BSD 3-CLAUSE" || collapsed === "BSD 3 CLAUSE") {
        return "BSD-3-CLAUSE";
    }
    if (collapsed === "CC0-1.0" || collapsed === "CC0 1.0" || collapsed === "CC0") return "CC0-1.0";
    if (collapsed === "MPL-2.0" || collapsed === "MPL 2.0") return "MPL-2.0";
    if (collapsed === "UNICODE-3.0" || collapsed === "UNICODE 3.0") return "UNICODE-3.0";

    return collapsed;
}

interface RuleInfo {
    name: string;
    license: string;
}

/**
 * Extract `(rule_name, normalized_license)` for every rule block in a
 * .yar source file. Whole-source regex walk: split on `rule X { ... }`
 * boundaries, then within each block scope the license search to the
 * `meta:` section only. Scoping is important — a rule's `strings:`
 * section can declare literal string content like
 *   `$a = "license = \"MIT\""` — and we must NOT mistake that for a
 * meta-declared license. The meta scope is always between `meta:` and
 * the first of `strings:` / `condition:` (or end-of-block).
 *
 * If a rule has no `meta:` section at all, or no `license = "..."`
 * inside it, the license is "" (treated as unspecified → rejected).
 *
 * This intentionally mirrors what `build_rule_index.py` does, except
 * the Python script is permissive (records "unknown" for missing
 * licenses; doesn't drop the file). The scrubber here is the
 * enforcement layer.
 */
function extractRules(source: string): RuleInfo[] {
    const ruleOpen = /\brule\s+([A-Za-z0-9_]+)\b/g;
    const metaOpen = /\bmeta\s*:/;
    // Any of these tokens ends the meta block in a well-formed rule.
    const metaEnd = /\b(?:strings|condition|variables)\s*:|\}/;
    const licenseLine = /\blicense\s*=\s*"([^"]*)"/;

    const positions: Array<{ start: number; name: string }> = [];
    let m: RegExpExecArray | null;
    while ((m = ruleOpen.exec(source)) !== null) {
        positions.push({ start: m.index, name: m[1] });
    }

    const rules: RuleInfo[] = [];
    for (let i = 0; i < positions.length; i++) {
        const start = positions[i].start;
        const end = i + 1 < positions.length ? positions[i + 1].start : source.length;
        const block = source.slice(start, end);

        let license = "";
        const metaMatch = block.match(metaOpen);
        if (metaMatch && metaMatch.index !== undefined) {
            const metaStart = metaMatch.index + metaMatch[0].length;
            const afterMeta = block.slice(metaStart);
            const endMatch = afterMeta.match(metaEnd);
            const metaEndIdx = endMatch && endMatch.index !== undefined
                ? endMatch.index
                : afterMeta.length;
            const metaSection = afterMeta.slice(0, metaEndIdx);
            const lm = metaSection.match(licenseLine);
            license = normalizeLicense(lm ? lm[1] : "");
        }

        rules.push({ name: positions[i].name, license });
    }
    return rules;
}

/** Recursively yield every .yar file path under `root`. */
function* walkYar(root: string): Generator<string> {
    const stack: string[] = [root];
    while (stack.length > 0) {
        const dir = stack.pop()!;
        let entries: string[];
        try {
            entries = readdirSync(dir);
        } catch {
            continue;
        }
        for (const entry of entries) {
            const path = join(dir, entry);
            let st;
            try {
                st = statSync(path);
            } catch {
                continue;
            }
            if (st.isDirectory()) {
                stack.push(path);
            } else if (st.isFile() && entry.endsWith(".yar")) {
                yield path;
            }
        }
    }
}

function main(): number {
    const root = process.argv[2];
    if (!root) {
        console.error("usage: tsx scripts/license-scrub-yara.ts <unzipped-core-dir>");
        return 2;
    }
    if (!existsSync(root)) {
        console.error(`scrub: input directory does not exist: ${root}`);
        return 2;
    }

    const droppedReason = new Map<string, number>();
    const keptLicenseCount = new Map<string, number>();
    let filesSeen = 0;
    let filesKept = 0;
    let filesDropped = 0;
    let rulesSeen = 0;
    let rulesAllowed = 0;
    let rulesRejected = 0;

    for (const path of walkYar(root)) {
        filesSeen++;
        let source: string;
        try {
            source = readFileSync(path, "utf8");
        } catch (err) {
            console.error(`scrub: cannot read ${path}: ${(err as Error).message}`);
            filesDropped++;
            try { unlinkSync(path); } catch {}
            continue;
        }
        const rules = extractRules(source);
        if (rules.length === 0) {
            // No rule blocks — not a YARA source we recognize. Drop it.
            filesDropped++;
            droppedReason.set("(no rule blocks)", (droppedReason.get("(no rule blocks)") || 0) + 1);
            try { unlinkSync(path); } catch {}
            continue;
        }
        rulesSeen += rules.length;

        let allRulesAllowed = true;
        let firstDisallowedLicense = "";
        for (const r of rules) {
            if (r.license === "" || !ALLOWED_SPDX.has(r.license)) {
                allRulesAllowed = false;
                firstDisallowedLicense = r.license || "(unspecified)";
                break;
            }
        }

        if (allRulesAllowed) {
            filesKept++;
            rulesAllowed += rules.length;
            for (const r of rules) {
                keptLicenseCount.set(r.license, (keptLicenseCount.get(r.license) || 0) + 1);
            }
        } else {
            filesDropped++;
            rulesRejected += rules.length;
            droppedReason.set(firstDisallowedLicense, (droppedReason.get(firstDisallowedLicense) || 0) + 1);
            try { unlinkSync(path); } catch (err) {
                console.error(`scrub: cannot unlink ${path}: ${(err as Error).message}`);
            }
        }
    }

    if (filesSeen === 0) {
        console.error(`scrub: no .yar files found under ${root} — wrong directory?`);
        return 2;
    }

    // Summary report. Print to stdout so CI logs capture it.
    console.log(`license-scrub-yara: scanned ${filesSeen} .yar files (${rulesSeen} rule blocks)`);
    console.log(`  kept    : ${filesKept} files (${rulesAllowed} rules)`);
    console.log(`  dropped : ${filesDropped} files (${rulesRejected} rules)`);
    console.log();
    if (filesKept > 0) {
        console.log("  kept-license distribution:");
        const sortedKept = Array.from(keptLicenseCount.entries()).sort((a, b) => b[1] - a[1]);
        for (const [lic, n] of sortedKept) {
            console.log(`    ${String(n).padStart(6)}  ${lic}`);
        }
        console.log();
    }
    if (filesDropped > 0) {
        console.log("  drop-reason distribution (first disallowed license per file):");
        const sortedDropped = Array.from(droppedReason.entries()).sort((a, b) => b[1] - a[1]);
        for (const [reason, n] of sortedDropped) {
            console.log(`    ${String(n).padStart(6)}  ${reason}`);
        }
    }
    return 0;
}

process.exit(main());
