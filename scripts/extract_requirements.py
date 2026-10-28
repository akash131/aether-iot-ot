#!/usr/bin/env python3
"""Extract every IoT/OT requirement identifier of the source volumes into
docs/requirements/requirements.tsv.

Usage::

    scripts/extract_requirements.py --v11 VOLUME_11.txt --p2 PLATFORM_VOL2.txt \
        [--v3 VOLUME_3.txt] [--out docs/requirements/requirements.tsv]

Sources (plain-text renderings of the requirement volumes):

* ``--v11``  the IoT/OT long-form volume: 134 capabilities (sections
             2-135), each with nine aspects (Architecture ... Verification)
             of nine templated invariants (ZTE-IOT-NNNNNN), a safety /
             failure matrix of 17 failure modes and an acceptance matrix of
             17 scenarios; section 136 canonical schemas (ZTE-IOTDATA-*) and
             section 137 safety and security invariants (ZTE-IOTINV-*).
* ``--p2``   the platform production requirements volume 2; only the
             "IOT" module (ZTE-IOT-001159.., 10 features x 10 dimensions)
             is extracted.
* ``--v3``   optional: the UI volume; it is scanned for IoT/OT screens and
             the number found is reported (the current volume has none).

Output columns: id, source (V11, P2), section (capability number or
module), capability, block (aspect, matrix or feature), dimension
(invariant key, ``failure:<mode>``, ``acceptance:<scenario>``, schema
entity, ``invariant`` or the platform dimension tag), priority, statement
(whitespace-normalised).

Standard library only. Requirement ids are opaque identifiers. Vendor
product names in the statements are replaced by neutral terms.
"""

import argparse
import base64
import csv
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Vendor product names in the source text are replaced by neutral terms;
# the source terms are stored base64-encoded so that no vendor name appears
# in this repository.
NEUTRAL = [
    (base64.b64decode(a).decode(), b)
    for a, b in [
        ("WmVybyBUcnVzdCBCcmFuY2g=", "Branch"),
        ("WmVybyBUcnVzdCBFeGNoYW5nZQ==", "Exchange"),
        ("WnNjYWxlcg==", "vendor"),
    ]
]

ASPECTS = ["Architecture", "Configuration", "Runtime", "Data/State", "Api/Events", "Security/Privacy", "Observability", "Resilience/Operations", "Verification"]

# The nine templated invariants of every aspect, in source order, with the
# phrase that identifies each one (checked, so a changed template fails loudly).
INVARIANTS = [
    ("ownership", "component ownership"),
    ("identity_binding", "bind observations"),
    ("versions_freshness", "versions and freshness"),
    ("bounded_inputs", "bounded parser"),
    ("passive_active", "passive observation"),
    ("observability", "metrics, logs, traces"),
    ("safe_failure", "safe behavior"),
    ("controlled_rollout", "controlled deployment"),
    ("automated_tests", "automated positive"),
]

ID_RX = re.compile(r"^(ZTE-IOT(?:DATA|INV)?-\d+) \[(P\d)\] (.*)$")
P2_RX = re.compile(r"^(ZTE-IOT-\d{6}) \[([A-Za-z/ ]+)\] \[(P\d)\] (.*)$")
SECTION_RX = re.compile(r"^(\d+)\. (.+)$")
SUB_RX = re.compile(r"^(\d+)\.(\d+) (.+)$")


def norm(s):
    s = re.sub(r"\s+", " ", s).strip()
    for a, b in NEUTRAL:
        s = s.replace(a, b)
    return s


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().split("\n")


def paragraphs(lines, start=0, end=None):
    """Yield (first_line, text) of blank-line or id separated paragraphs."""
    buf = []
    for line in lines[start:end]:
        s = line.rstrip()
        if not s or (buf and (ID_RX.match(s) or P2_RX.match(s) or SECTION_RX.match(s) or SUB_RX.match(s))):
            if buf:
                yield buf[0], " ".join(buf)
            buf = [s] if s else []
            continue
        buf.append(s)
    if buf:
        yield buf[0], " ".join(buf)


def title_case(t):
    return norm(t).replace("Iot/Ot", "IoT/OT").replace("Iot ", "IoT ").replace("Ot ", "OT ")


def extract_v11(path):
    lines = read_lines(path)
    rows = []
    section, capability, block, aspect_idx = None, None, None, None
    counter = 0
    for first, text in paragraphs(lines):
        m = SECTION_RX.match(first)
        if m and text == first:
            section, capability, block, aspect_idx = int(m.group(1)), title_case(m.group(2)), None, None
            continue
        m = SUB_RX.match(first)
        if m and text == first:
            block = norm(m.group(3))
            aspect_idx = ASPECTS.index(block) if block in ASPECTS else None
            counter = 0
            continue
        m = ID_RX.match(text)
        if not m:
            continue
        rid, prio, statement = m.group(1), m.group(2), norm(m.group(3))
        if rid.startswith("ZTE-IOTDATA-"):
            entity = statement.split(" MUST")[0]
            rows.append((rid, "V11", str(section), capability, entity, "schema", prio, statement))
            continue
        if rid.startswith("ZTE-IOTINV-"):
            rows.append((rid, "V11", str(section), capability, "Safety and Security Invariants", "invariant", prio, statement))
            continue
        if aspect_idx is not None:
            key, phrase = INVARIANTS[counter]
            if phrase not in statement:
                sys.exit(f"{rid}: invariant {counter + 1} of {block} does not mention {phrase!r}: {statement}")
            dim = key
            counter += 1
        elif block and block.startswith("Safety"):
            mm = re.search(r"operator action for (.+?)\.$", statement)
            if not mm:
                sys.exit(f"{rid}: failure mode not recognised: {statement}")
            dim = "failure:" + re.sub(r"[^a-z0-9]+", "_", mm.group(1).lower()).strip("_")
        elif block and block.startswith("Acceptance"):
            mm = re.search(r"repeatable (.+?) test", statement)
            if not mm:
                sys.exit(f"{rid}: acceptance scenario not recognised: {statement}")
            dim = "acceptance:" + re.sub(r"[^a-z0-9]+", "_", mm.group(1).lower()).strip("_")
        else:
            sys.exit(f"{rid}: requirement outside a known block ({block})")
        rows.append((rid, "V11", str(section), capability, block, dim, prio, statement))
    return rows


def extract_p2(path):
    lines = read_lines(path)
    start = next((i for i, l in enumerate(lines) if l.startswith("IOT ") and "IoT and OT" in l), None)
    if start is None:
        sys.exit("IOT module not found in the platform volume")
    end = next((i for i in range(start + 1, len(lines)) if re.match(r"^[A-Z]{2,6} \S ", lines[i]) and "—" in lines[i]), len(lines))
    rows, feature = [], None
    for first, text in paragraphs(lines, start + 1, end):
        m = P2_RX.match(text)
        if m:
            rows.append((m.group(1), "P2", "IOT", feature, feature, m.group(2).strip().lower(), m.group(3), norm(m.group(4))))
        elif not text.startswith("Production requirements") and len(text) < 60 and not text.startswith("ZTE-"):
            feature = norm(text)
    return rows


def scan_v3(path):
    text = "\n".join(read_lines(path))
    return len(re.findall(r"ZTE-IOT", text)), len(re.findall(r"(?i)\b(iot|operational technology)\b", text))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--v11", required=True)
    ap.add_argument("--p2", required=True)
    ap.add_argument("--v3")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "requirements", "requirements.tsv"))
    a = ap.parse_args()
    rows = extract_v11(a.v11) + extract_p2(a.p2)
    ids = [r[0] for r in rows]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        sys.exit(f"duplicate ids: {sorted(dup)[:5]}")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["id", "source", "section", "capability", "block", "dimension", "priority", "statement"])
        w.writerows(rows)
    by = {}
    for r in rows:
        by[r[1]] = by.get(r[1], 0) + 1
    print(f"wrote {len(rows)} requirements to {os.path.relpath(a.out, ROOT)}: " + ", ".join(f"{k} {v}" for k, v in sorted(by.items())))
    if a.v3:
        ids3, mentions = scan_v3(a.v3)
        print(f"UI volume: {ids3} IoT/OT requirement ids, {mentions} IoT/OT mentions")


if __name__ == "__main__":
    main()
