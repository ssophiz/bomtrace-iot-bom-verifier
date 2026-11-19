"""Compare OpenWrt release pairs with the official CycloneDX CLI diff command.

Syft first catalogues installed packages from each rootfs. Both the published
BOM and Syft inventory are projected to name/version-only CycloneDX 1.4 BOMs.
This measures a document-diff pipeline, not a direct rootfs verifier or a
claim that CycloneDX CLI has OpenWrt-specific reconciliation rules.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

from benchmark_openwrt import SOURCES, metrics, sha256
from syft_crosscheck import status_components
from verify_openwrt_bom import package_database, read_status, verify


CDX_CLI_HASH = "9b360974c41a5d612eb026fb5e3bb1fa28e08865f7a4f915665b8bc94bd3bc31"
SYFT_HASH = "5c9d2ba5affae29c3c5ba5796ad28fc72780189fafcb893544325902a298b17e"


def minimal_bom(rows: dict[str, str]) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
            "components": [{"type": "library", "name": name, "version": version}
                           for name, version in sorted(rows.items())]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--syft-exe", type=Path, required=True)
    parser.add_argument("--cyclonedx-exe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    syft = args.syft_exe.resolve(strict=True)
    cdx = args.cyclonedx_exe.resolve(strict=True)
    for path, expected in ((syft, SYFT_HASH), (cdx, CDX_CLI_HASH)):
        if sha256(path) != expected:
            raise ValueError(f"tool hash mismatch: {path}")
    syft_version = subprocess.run([str(syft), "version"], capture_output=True, text=True, check=True).stdout
    cdx_version = subprocess.run([str(cdx), "--version"], capture_output=True, text=True, check=True).stdout.strip()
    if "Version:       1.57.2" not in syft_version or not cdx_version.startswith("0.33.1+"):
        raise ValueError("unexpected tool version")

    builds = {}
    groups: dict[str, list[str]] = defaultdict(list)
    provenance = []
    with tempfile.TemporaryDirectory(prefix="bomtrace-cdx-cli-") as temp:
        work = Path(temp)
        for build, (stem, base, archive_hash, bom_hash) in SOURCES.items():
            archive = args.source_dir / f"{stem}-rootfs.tar.gz"
            bom_file = args.source_dir / f"{stem}.bom.cdx.json"
            for path, expected in ((archive, archive_hash), (bom_file, bom_hash)):
                actual = sha256(path)
                if actual != expected:
                    raise ValueError(f"source hash mismatch: {path}")
                provenance.append({"build": build, "url": base + path.name, "sha256": actual})
            official = json.loads(bom_file.read_text(encoding="utf-8"))
            published = {item["name"]: item["version"] for item in official["components"]}
            if len(published) != len(official["components"]):
                raise ValueError(f"duplicate published package: {build}")
            syft_bom = work / f"{stem}.syft.json"
            subprocess.run([str(syft), "scan", str(archive), "--output", f"cyclonedx-json={syft_bom}", "--quiet"],
                           check=True, capture_output=True, text=True)
            installed = status_components(json.loads(syft_bom.read_text(encoding="utf-8")))
            package_rows, database_format = package_database(read_status(archive))
            if installed != {name: row["Version"] for name, row in package_rows.items()}:
                raise ValueError(f"Syft and package database differ: {build}")
            published_path = work / f"{stem}.published-min.json"
            installed_path = work / f"{stem}.installed-min.json"
            published_path.write_text(json.dumps(minimal_bom(published)), encoding="utf-8")
            installed_path.write_text(json.dumps(minimal_bom(installed)), encoding="utf-8")
            builds[build] = (published_path, installed_path, official, read_status(archive),
                             len(published), len(installed), database_format)
            groups[build.split("-", 1)[1]].append(build)

        rows = []
        for architecture, members in sorted(groups.items()):
            for bom_build in members:
                for rootfs_build in members:
                    published_path, _, official, _, published_count, _, _ = builds[bom_build]
                    _, installed_path, _, status, _, installed_count, database_format = builds[rootfs_build]
                    proc = subprocess.run(
                        [str(cdx), "diff", str(published_path), str(installed_path),
                         "--component-versions", "--output-format", "json"],
                        capture_output=True, text=True, check=True)
                    diff = json.loads(proc.stdout)
                    versions = diff["componentVersions"]
                    counts = {key: sum(len(item[key]) for item in versions.values())
                              for key in ("added", "removed", "unchanged")}
                    if (counts["added"] + counts["unchanged"] != installed_count or
                            counts["removed"] + counts["unchanged"] != published_count):
                        raise ValueError(f"unexpected CycloneDX diff counts: {bom_build}, {rootfs_build}")
                    report = verify(official, status)
                    rows.append({
                        "architecture": architecture,
                        "bom_build": bom_build,
                        "rootfs_build": rootfs_build,
                        "rootfs_database_format": database_format,
                        "expected_case_alert": bom_build != rootfs_build,
                        "cyclonedx_cli_case_alert": counts["added"] + counts["removed"] > 0,
                        "bomtrace_case_alert": bool(report["findings"]),
                        "cyclonedx_cli_component_versions": counts,
                        "bomtrace_finding_count": len(report["findings"]),
                        "bomtrace_unresolved_count": len(report["unresolved"]),
                    })

    expected = {i for i, row in enumerate(rows) if row["expected_case_alert"]}
    comparison = {method: metrics({i for i, row in enumerate(rows) if row[field]}, expected)
                  for method, field in (("cyclonedx_cli_diff", "cyclonedx_cli_case_alert"),
                                        ("bomtrace", "bomtrace_case_alert"))}
    result = {
        "design": "same-architecture ordered release-pair matrix; Syft package database inventory and published BOM projected to name/version-only CycloneDX 1.4; official CycloneDX CLI diff --component-versions",
        "label_scope": "case-level release identity; deliberately mismatched pairs are not naturally occurring attacks or per-package ground truth",
        "tool_scope": "CycloneDX CLI is a BOM-to-BOM diff tool, not a direct rootfs verifier. Its output is reported as a pipeline baseline, not a claim of errors in the tool.",
        "cyclonedx_cli_version": cdx_version,
        "cyclonedx_cli_exe_sha256": CDX_CLI_HASH,
        "syft_version": "1.57.2",
        "syft_exe_sha256": SYFT_HASH,
        "source_manifest": provenance,
        "cases": len(rows),
        "same_build_controls": len(rows) - len(expected),
        "cross_release_pairs": len(expected),
        "case_alert_metrics": comparison,
        "rows": rows,
        "limitations": "The adapter discards all non-name/version BOM fields. Neither CycloneDX CLI nor Syft claims OpenWrt-specific Provides and upstream-version reconciliation. This is not a general existing-verifier head-to-head or field accuracy estimate.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("cases", "same_build_controls",
                                               "cross_release_pairs", "case_alert_metrics")}, indent=2))


if __name__ == "__main__":
    main()
