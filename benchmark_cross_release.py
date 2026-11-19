"""Compare official OpenWrt BOMs with same- and different-release rootfs pairs.

Cross-release cases deliberately pair unmodified files from different releases
on the same target architecture. Their label is a release-pair mismatch, not a
human-verified label for each reported package finding or a field attack.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

from jsonschema import Draft7Validator

from benchmark_openwrt import SOURCES, metrics, sha256
from verify_openwrt_bom import package_database, read_status, verify


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=Path(__file__).with_name("bom-1.4.schema.json"))
    args = parser.parse_args()
    validator = Draft7Validator(json.loads(args.schema.read_text(encoding="utf-8")))

    builds: dict[str, tuple[dict, str, dict[str, dict[str, str]], str]] = {}
    provenance = []
    groups: dict[str, list[str]] = defaultdict(list)
    for build, (stem, base, archive_hash, bom_hash) in SOURCES.items():
        archive = args.source_dir / f"{stem}-rootfs.tar.gz"
        bom_file = args.source_dir / f"{stem}.bom.cdx.json"
        for path, expected in ((archive, archive_hash), (bom_file, bom_hash)):
            actual = sha256(path)
            if actual != expected:
                raise ValueError(f"source hash mismatch: {path}: {actual}")
            provenance.append({"build": build, "url": base + path.name, "sha256": actual})
        bom = json.loads(bom_file.read_text(encoding="utf-8"))
        if list(validator.iter_errors(bom)):
            raise ValueError(f"official BOM fails schema validation: {build}")
        status = read_status(archive)
        installed, database_format = package_database(status)
        builds[build] = (bom, status, installed, database_format)
        groups[build.split("-", 1)[1]].append(build)

    rows = []
    for architecture, members in sorted(groups.items()):
        for bom_build in members:
            for rootfs_build in members:
                bom, _, _, _ = builds[bom_build]
                _, status, installed, database_format = builds[rootfs_build]
                start = time.perf_counter()
                report = verify(bom, status)
                elapsed_ms = (time.perf_counter() - start) * 1000
                published = {item["name"]: item["version"] for item in bom["components"]}
                raw = {name: fields["Version"] for name, fields in installed.items()}
                raw_counts = {
                    "bom_only_names": len(published.keys() - raw.keys()),
                    "installed_only_names": len(raw.keys() - published.keys()),
                    "version_disagreements_on_shared_names": sum(
                        published[name] != raw[name] for name in published.keys() & raw.keys()),
                }
                rows.append({
                    "architecture": architecture,
                    "bom_build": bom_build,
                    "rootfs_build": rootfs_build,
                    "rootfs_database_format": database_format,
                    "expected_case_alert": bom_build != rootfs_build,
                    "bomtrace_case_alert": bool(report["findings"]),
                    "raw_string_case_alert": any(raw_counts.values()),
                    "schema_only_case_alert": bool(list(validator.iter_errors(bom))),
                    "bomtrace_finding_counts": dict(sorted(Counter(
                        finding["rule_id"] for finding in report["findings"]).items())),
                    "bomtrace_findings": report["findings"],
                    "unresolved": report["unresolved"],
                    "raw_string_counts": raw_counts,
                    "verify_runtime_ms": round(elapsed_ms, 3),
                })

    positive = {index for index, row in enumerate(rows) if row["expected_case_alert"]}
    comparison = {}
    for method, field in (("bomtrace", "bomtrace_case_alert"),
                          ("raw_string", "raw_string_case_alert"),
                          ("schema_only", "schema_only_case_alert")):
        comparison[method] = metrics({index for index, row in enumerate(rows) if row[field]}, positive)
    result = {
        "design": "all ordered BOM/rootfs pairs within each architecture group; same-build controls and deliberately mismatched cross-release pairs",
        "labels": "case-level release identity: same-build versus deliberately paired different releases; not independently adjudicated package defects or natural tampering",
        "baseline_notes": "raw_string is a deliberately naive exact name/version comparator, not an existing product; schema_only validates the unchanged BOM independently of rootfs and therefore cannot detect pair mismatch",
        "source_manifest": provenance,
        "cases": len(rows),
        "same_build_controls": sum(not row["expected_case_alert"] for row in rows),
        "cross_release_pairs": len(positive),
        "case_alert_metrics": comparison,
        "verify_runtime_ms_median": round(statistics.median(row["verify_runtime_ms"] for row in rows), 3),
        "runtime_scope": "in-memory verify() only; excludes archive reading, downloads and schema validation",
        "rows": rows,
        "limitations": "A deliberately mismatched release pair is not a naturally occurring attack. A case-level alert does not independently validate each finding. All files come from one firmware family and the two baselines are not established artifact verifiers.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in
                      ("cases", "same_build_controls", "cross_release_pairs", "case_alert_metrics")}, indent=2))


if __name__ == "__main__":
    main()
