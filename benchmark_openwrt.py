"""Run labeled mutations on official OpenWrt BOM/rootfs pairs.

The labels are defined by the transformations below.  Original build pairs
are unmodified; this is not a field study of naturally occurring tampering.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import statistics
import time
from pathlib import Path

from jsonschema import Draft7Validator

from verify_openwrt_bom import read_status, verify


SOURCES = {
    "24.10.4-x86-64": ("openwrt-24.10.4-x86-64", "https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/", "e7f8ab84eef55c7eb23492de7b0517dbc23fbedaa4abbb680fe64720c309dc03", "c35c542daff86733081d685ea4ee7f44f24a9094cf84bfd99e6eee32a45e9f99"),
    "24.10.4-armsr-armv7": ("openwrt-24.10.4-armsr-armv7", "https://downloads.openwrt.org/releases/24.10.4/targets/armsr/armv7/", "d3ff8e6186cbe2b0423cdbe1f898d5002799f25604334d2bb4ccb3cd1b650494", "95f4900f8cae85df0c1ec4a0b57d5903463b6f74006e93e79fdeae67a4cd650c"),
    "24.10.4-armsr-armv8": ("openwrt-24.10.4-armsr-armv8", "https://downloads.openwrt.org/releases/24.10.4/targets/armsr/armv8/", "b9e784570872f0c3875d75c54eba842fa6f8a9fb2503897080db240fff6431a3", "cd08a3d1ca3406fafca1e75bcf034b9c927bce164450b4b4b4b5622b9be8aebe"),
    "23.05.5-x86-64": ("openwrt-23.05.5-x86-64", "https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/", "383311300e1fd796f5a39bf09ad87bcedec61a7f09263f79cd1352757a3573a9", "1f5972b44c19f49914e21654f13dceb7db4c59f79d6a4e0f7b19a95da9a62e07"),
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def key(finding: dict) -> str:
    return f"{finding['rule_id']}|{finding['package']}"


def metrics(found: set[str], expected: set[str]) -> dict:
    tp, fp, fn = len(found & expected), len(found - expected), len(expected - found)
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None}


def mutate(bom: dict, status: str, scenario: str) -> tuple[dict, str, set[str]]:
    bom = copy.deepcopy(bom)
    if scenario == "clean":
        return bom, status, set()
    target = next(c for c in bom["components"] if c["name"] == "busybox")
    if scenario == "bom_version_drift":
        target["version"] = "0.0.0-mutated"
        return bom, status, {"PACKAGE_VERSION_MISMATCH|busybox"}
    if scenario == "bom_omission":
        bom["components"].remove(target)
        return bom, status, {"INSTALLED_PACKAGE_UNDECLARED|busybox"}
    if scenario == "bom_ghost":
        bom["components"].append({"type": "application", "name": "bomtrace-ghost", "version": "1.0"})
        return bom, status, {"DECLARED_PACKAGE_ABSENT|bomtrace-ghost"}
    if scenario == "bom_duplicate":
        bom["components"].append(copy.deepcopy(target))
        return bom, status, {"DUPLICATE_BOM_COMPONENT|busybox"}
    if scenario == "status_version_drift":
        blocks = status.split("\n\n")
        for i, block in enumerate(blocks):
            if block.startswith("Package: busybox\n"):
                lines = block.splitlines()
                blocks[i] = "\n".join("Version: 0.0.0-r1" if line.startswith("Version: ") else line for line in lines)
                return bom, "\n\n".join(blocks), {"PACKAGE_VERSION_MISMATCH|busybox"}
        raise ValueError("busybox status record missing")
    raise ValueError(scenario)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-dir", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--schema", type=Path, default=Path(__file__).with_name("bom-1.4.schema.json"))
    args = p.parse_args()
    validator = Draft7Validator(json.loads(args.schema.read_text(encoding="utf-8")))
    scenarios = ("clean", "bom_version_drift", "bom_omission", "bom_ghost", "bom_duplicate", "status_version_drift")
    rows = []
    pooled = {k: [set(), set()] for k in ("full", "version_only", "inventory_only")}
    alerted = {k: [set(), set()] for k in (*pooled, "schema_only")}
    manifest = []
    for build, (stem, base, archive_hash, bom_hash) in SOURCES.items():
        archive, bom_path = args.source_dir / f"{stem}-rootfs.tar.gz", args.source_dir / f"{stem}.bom.cdx.json"
        for path, expected_hash in ((archive, archive_hash), (bom_path, bom_hash)):
            observed = sha256(path)
            if observed != expected_hash:
                raise ValueError(f"source hash mismatch: {path} {observed}")
            manifest.append({"build": build, "url": base + path.name, "sha256": observed, "bytes": path.stat().st_size})
        original_bom = json.loads(bom_path.read_text(encoding="utf-8"))
        original_status = read_status(archive)
        for scenario in scenarios:
            bom, status, expected = mutate(original_bom, original_status, scenario)
            start = time.perf_counter()
            report = verify(bom, status)
            elapsed = (time.perf_counter() - start) * 1000
            schema_errors = list(validator.iter_errors(bom))
            full = {key(f) for f in report["findings"]}
            # Controlled ablations, not independently published tools.
            found = {
                "full": full,
                "version_only": {x for x in full if x.startswith("PACKAGE_VERSION_MISMATCH|")},
                "inventory_only": {x for x in full if x.startswith(("DECLARED_PACKAGE_ABSENT|", "INSTALLED_PACKAGE_UNDECLARED|"))},
                "schema_only": {"SCHEMA_INVALID|document"} if schema_errors else set(),
            }
            for method, values in found.items():
                if method in pooled:
                    pooled[method][0].update(f"{build}:{scenario}:{x}" for x in values)
                    pooled[method][1].update(f"{build}:{scenario}:{x}" for x in expected)
                if values:
                    alerted[method][0].add(f"{build}:{scenario}")
                if expected:
                    alerted[method][1].add(f"{build}:{scenario}")
            rows.append({"build": build, "scenario": scenario, "expected": sorted(expected),
                         "found": sorted(full), "unresolved": report["unresolved"],
                         "schema_error_count": len(schema_errors),
                         "runtime_ms": round(elapsed, 3), "bom_components": report["bom_component_count"],
                         "installed_packages": report["installed_package_count"],
                         "matched_installed": report["matched_installed_count"]})
    result = {
        "design": "4 unmodified official OpenWrt BOM/rootfs pairs plus 5 controlled metadata mutations per pair",
        "labels": "defined by the explicit mutation operators; no naturally occurring attack labels",
        "source_manifest": manifest,
        "cases": len(rows), "positive_cases": sum(bool(r["expected"]) for r in rows),
        "unmodified_builds": len(SOURCES), "findings_expected": sum(len(r["expected"]) for r in rows),
        "finding_level_metrics": {name: metrics(*sets) for name, sets in pooled.items()},
        "case_alert_metrics": {name: metrics(*sets) for name, sets in alerted.items()},
        "runtime_ms_median": round(statistics.median(r["runtime_ms"] for r in rows), 3),
        "runtime_ms_max": round(max(r["runtime_ms"] for r in rows), 3),
        "runtime_scope": "verify() in-memory only; excludes rootfs archive read and CycloneDX schema validation",
        "rows": rows,
        "limitations": "Verification reads opkg metadata from official rootfs archives. It cannot detect file-byte drift because the published BOMs have no file digests; these mutations do not test cryptographic or AI BOM verification.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("cases", "findings_expected", "finding_level_metrics", "case_alert_metrics", "runtime_ms_median", "runtime_ms_max")}, indent=2))


if __name__ == "__main__":
    main()
