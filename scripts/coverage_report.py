#!/usr/bin/env python3
"""Build docs/requirements/coverage.tsv from the requirement inventory and
the mapping rules, check it, and render docs/requirements/coverage.md.

Usage::

    scripts/coverage_report.py [--check]

Inputs (docs/requirements/):

* ``requirements.tsv``   every source requirement (scripts/extract_requirements.py)
* ``added.tsv``          authored requirements AE-IOT-NNNN (parity research)
* ``rules/capabilities.tsv``  per capability (sections 2-135): status, modules, tests, notes
* ``rules/invariants.tsv``    the nine templated aspect invariants
* ``rules/failure_modes.tsv`` the 17 safety/failure matrix modes
* ``rules/acceptance.tsv``    the 17 acceptance matrix scenarios
* ``rules/data.tsv``          canonical schemas (ZTE-IOTDATA) and invariants (ZTE-IOTINV)
* ``rules/features.tsv``, ``rules/dimensions.tsv``  the platform volume 2 IOT module
* ``rules/overrides.tsv``     per-id exceptions (applied last)

A requirement of a capability takes the weaker of the capability status
and the rule status (missing < partial < implemented; platform and
not_applicable capabilities pass through). "implemented" means the code
exists and a named test exercises it: ``--check`` fails when an
implemented row has no module or test, when a referenced test function
does not exist, or when a requirement id has no row.

Standard library only.
"""

import argparse
import collections
import csv
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REQ = os.path.join(ROOT, "docs", "requirements")
STATUSES = ["implemented", "partial", "missing", "platform", "not_applicable"]
RANK = {"missing": 0, "partial": 1, "implemented": 2}


def rows(name):
    with open(os.path.join(REQ, name), encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def weaker(a, b):
    if a in ("platform", "not_applicable"):
        return a
    if b in ("platform", "not_applicable"):
        return b
    return a if RANK[a] <= RANK[b] else b


def join(*parts):
    out = []
    for p in parts:
        for x in (p or "").split(";"):
            x = x.strip()
            if x and x not in out:
                out.append(x)
    return "; ".join(out)


def build():
    reqs = rows("requirements.tsv")
    caps = {int(r["section"]): r for r in rows("rules/capabilities.tsv")}
    inv = {r["invariant"]: r for r in rows("rules/invariants.tsv")}
    fm = {r["mode"]: r for r in rows("rules/failure_modes.tsv")}
    acc = {r["scenario"]: r for r in rows("rules/acceptance.tsv")}
    data = {r["id"]: r for r in rows("rules/data.tsv")}
    feats = {r["feature"]: r for r in rows("rules/features.tsv")}
    dims = {r["dimension"]: r for r in rows("rules/dimensions.tsv")}
    over = {r["id"]: r for r in rows("rules/overrides.tsv")}
    out = []
    for r in reqs:
        rid, dim = r["id"], r["dimension"]
        if r["source"] == "P2":
            f, d = feats[r["capability"]], dims[dim]
            row = dict(status=weaker(f["status"], d["status"]), module=join(f["module"], d["module"]), test=join(f["test"], d["test"]), notes="")
        elif rid in data:
            d = data[rid]
            row = dict(status=d["status"], module=d["module"], test=d["test"], notes=d["notes"])
        else:
            c = caps[int(r["section"])]
            if dim.startswith("failure:"):
                rule = fm[dim.split(":", 1)[1]]
            elif dim.startswith("acceptance:"):
                rule = acc[dim.split(":", 1)[1]]
            else:
                rule = inv[dim]
            tests = c["test"].split(";")[:2]
            row = dict(status=weaker(c["status"], rule["status"]), module=join(c["module"], rule["module"]), test=join(*tests, rule["test"]), notes=join(c["notes"], rule["notes"]))
        if rid in over:
            o = over[rid]
            row = dict(status=o["status"], module=o["module"] or row["module"], test=o["test"] or row["test"], notes=o["notes"])
        out.append(dict(id=rid, source=r["source"], section=r["section"], capability=r["capability"], block=r["block"], dimension=dim, **row))
    for a in rows("added.tsv"):
        out.append(dict(id=a["id"], source="AE", section="added", capability=a["area"], block=a["area"], dimension="authored", status="implemented", module=a["module"], test=a["test"], notes=""))
    return reqs, out


def check(reqs, out):
    errors = []
    ids = {r["id"] for r in reqs}
    covered = {r["id"] for r in out}
    for m in sorted(ids - covered):
        errors.append(f"{m}: no coverage row")
    cache = {}
    for r in out:
        if r["status"] not in STATUSES:
            errors.append(f"{r['id']}: invalid status {r['status']}")
        if r["status"] == "implemented" and (not r["module"] or not r["test"]):
            errors.append(f"{r['id']}: implemented without module or test")
        if r["status"] in ("partial", "missing", "platform", "not_applicable") and not r["notes"] and r["source"] != "AE":
            errors.append(f"{r['id']}: {r['status']} without a reason")
        for t in [x.strip() for x in r["test"].split(";") if x.strip()]:
            if t in cache:
                ok = cache[t]
            else:
                path, _, fn = t.partition("::")
                p = os.path.join(ROOT, "crates", path)
                ok = os.path.exists(p) and re.search(r"fn " + re.escape(fn) + r"\b", open(p, encoding="utf-8").read()) is not None
                cache[t] = ok
            if not ok:
                errors.append(f"{r['id']}: test {t} not found")
    return errors


def render(out):
    by_status = collections.Counter(r["status"] for r in out)
    by_source = collections.defaultdict(collections.Counter)
    for r in out:
        by_source[r["source"]][r["status"]] += 1
    lines = ["# Requirements coverage", "", "Generated by `scripts/coverage_report.py` from `requirements.tsv`, `added.tsv` and `rules/*.tsv`. Do not edit by hand.", ""]
    total = len(out)
    lines += ["## Totals", "", "| Status | Requirements | Share |", "|---|---:|---:|"]
    for s in STATUSES:
        lines.append(f"| {s} | {by_status[s]} | {100.0 * by_status[s] / total:.2f}% |")
    lines += [f"| **total** | **{total}** | |", ""]
    lines += ["## By source", "", "| Source | " + " | ".join(STATUSES) + " | total |", "|---|" + "---:|" * (len(STATUSES) + 1)]
    names = {"V11": "IoT/OT volume (ZTE-IOT, ZTE-IOTDATA, ZTE-IOTINV)", "P2": "Platform volume 2, IOT module", "AE": "Authored (AE-IOT)"}
    for src in ("V11", "P2", "AE"):
        c = by_source[src]
        lines.append(f"| {names[src]} | " + " | ".join(str(c[s]) for s in STATUSES) + f" | {sum(c.values())} |")
    lines.append("")
    lines += ["## By capability", "", "| Section | Capability | Requirements | implemented | partial | other | Note |", "|---:|---|---:|---:|---:|---:|---|"]
    caps = collections.OrderedDict()
    for r in out:
        if r["source"] == "V11":
            caps.setdefault((r["section"], r["capability"]), []).append(r)
    for (sec, name), rs in caps.items():
        c = collections.Counter(x["status"] for x in rs)
        note = next((x["notes"].split(";")[0] for x in rs if x["status"] != "implemented" and x["notes"]), "")
        lines.append(f"| {sec} | {name} | {len(rs)} | {c['implemented']} | {c['partial']} | {len(rs) - c['implemented'] - c['partial']} | {note} |")
    lines.append("")
    rest = [r for r in out if r["status"] != "implemented"]
    lines += ["## Requirements not fully implemented", ""]
    groups = collections.OrderedDict()
    for r in rest:
        groups.setdefault((r["status"], r["capability"], r["notes"]), []).append(r["id"])
    lines += ["| Status | Capability | Requirements | Reason |", "|---|---|---:|---|"]
    for (s, cap, notes), ids in groups.items():
        lines.append(f"| {s} | {cap} | {len(ids)} ({ids[0]} … {ids[-1]}) | {notes} |")
    lines.append("")
    with open(os.path.join(REQ, "coverage.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return by_status, total


def short(tests, n=3):
    out = []
    for t in [x.strip() for x in tests.split(";") if x.strip()][:n]:
        path, _, fn = t.partition("::")
        out.append(f"`{path.split('/')[-1]}::{fn}`")
    return ", ".join(out)


def render_traceability():
    caps = rows("rules/capabilities.tsv")
    lines = [
        "# Traceability",
        "",
        "Generated by `scripts/coverage_report.py` from `docs/requirements/rules/*.tsv` and `added.tsv`. Every requirement id with its status, module and tests is in `docs/requirements/coverage.tsv`; totals in `docs/requirements/coverage.md`.",
        "",
        "Each capability of the IoT/OT volume (sections 2–135) has 81 aspect requirements (nine aspects × nine invariants), 17 failure-matrix and 17 acceptance-matrix requirements. A requirement takes the weaker of its capability status and the status of its invariant, failure mode or scenario.",
        "",
        "## Capabilities",
        "",
        "| § | Capability | Component | Status | Implementation | Tests (first three) | Note |",
        "|---:|---|---|---|---|---|---|",
    ]
    for c in caps:
        lines.append(f"| {c['section']} | {c['capability']} | {c['component']} | {c['status']} | {c['module']} | {short(c['test'])} | {c['notes']} |")
    lines += ["", "## Aspect invariants", "", "| Invariant | Implementation | Tests |", "|---|---|---|"]
    for r in rows("rules/invariants.tsv"):
        lines.append(f"| {r['invariant']} | {r['module']} | {short(r['test'], 5)} |")
    lines += ["", "## Failure modes", "", "| Mode | Tests |", "|---|---|"]
    for r in rows("rules/failure_modes.tsv"):
        lines.append(f"| {r['mode']} | {short(r['test'])} |")
    lines += ["", "## Acceptance scenarios", "", "| Scenario | Tests |", "|---|---|"]
    for r in rows("rules/acceptance.tsv"):
        lines.append(f"| {r['scenario']} | {short(r['test'])} |")
    lines += ["", "## Schemas and invariants (sections 136–137)", "", "| Id | Implementation | Tests |", "|---|---|---|"]
    for r in rows("rules/data.tsv"):
        if r["id"].startswith("ZTE-IOTINV"):
            lines.append(f"| {r['id']} | {r['module']} | {short(r['test'])} |")
    lines.append("| ZTE-IOTDATA-153133 … 153160 | iot-core schemas.rs (28 entities); migrations/0001_iot.sql | `schemas.rs::every_canonical_entity_is_described`, `api.rs::operations_catalogues` |")
    lines += ["", "## Platform volume 2, IOT module", "", "| Feature | Sections | Implementation | Tests |", "|---|---|---|---|"]
    for r in rows("rules/features.tsv"):
        lines.append(f"| {r['feature']} | {r['sections']} | {r['module']} | {short(r['test'])} |")
    lines += ["", "## Authored requirements", "", "| Id | Requirement | Implementation | Tests |", "|---|---|---|---|"]
    for r in rows("added.tsv"):
        lines.append(f"| {r['id']} | {r['statement']} | {r['module']} | {short(r['test'])} |")
    lines.append("")
    with open(os.path.join(ROOT, "docs", "traceability.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail on unmapped ids, missing tests or unexplained gaps")
    a = ap.parse_args()
    reqs, out = build()
    with open(os.path.join(REQ, "coverage.tsv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        cols = ["id", "source", "section", "capability", "block", "dimension", "status", "module", "test", "notes"]
        w.writerow(cols)
        for r in out:
            w.writerow([r[c] for c in cols])
    by_status, total = render(out)
    render_traceability()
    print(f"{total} requirements: " + ", ".join(f"{s} {by_status[s]}" for s in STATUSES))
    errors = check(reqs, out)
    if errors:
        for e in errors[:50]:
            print("ERROR", e, file=sys.stderr)
        print(f"{len(errors)} coverage errors", file=sys.stderr)
        if a.check:
            sys.exit(1)


if __name__ == "__main__":
    main()
