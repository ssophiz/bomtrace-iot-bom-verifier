"""Cross-check OpenWrt package extraction with Syft 1.57.2.

Syft is an SBOM generator, not a published-BOM verifier. The raw comparison
reported here is deliberately naive and must not be called a Syft false alarm.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from benchmark_openwrt import SOURCES
from verify_openwrt_bom import package_database, read_status, verify


STATUS_PATHS = {"/usr/lib/opkg/status", "/var/lib/opkg/status", "/lib/apk/db/installed"}


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def status_components(cdx: dict) -> dict[str, str]:
    result = {}
    for item in cdx.get("components", []):
        locations = {prop.get("value") for prop in item.get("properties", [])
                     if prop.get("name", "").startswith("syft:location:")}
        if not locations & STATUS_PATHS:
            continue
        name, version = item["name"], item["version"]
        if name in result:
            raise ValueError(f"duplicate Syft status component: {name}")
        result[name] = version
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--syft-exe", type=Path, required=True)
    p.add_argument("--source-dir", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    syft = args.syft_exe.resolve(strict=True)
    version = subprocess.run([str(syft), "version"], capture_output=True, text=True, check=True).stdout
    if "Version:       1.57.2" not in version:
        raise ValueError("this comparison is pinned to Syft 1.57.2")
    rows = []
    with tempfile.TemporaryDirectory(prefix="bomtrace-syft-") as temp:
        for build, (stem, _, archive_hash, bom_hash) in SOURCES.items():
            archive = args.source_dir / f"{stem}-rootfs.tar.gz"
            bom_file = args.source_dir / f"{stem}.bom.cdx.json"
            if file_hash(archive) != archive_hash or file_hash(bom_file) != bom_hash:
                raise ValueError(f"source hash mismatch: {build}")
            out = Path(temp) / f"{stem}.syft.json"
            subprocess.run([str(syft), "scan", str(archive), "--output", f"cyclonedx-json={out}", "--quiet"], check=True)
            syft_inventory = status_components(json.loads(out.read_text(encoding="utf-8")))
            package_rows, database_format = package_database(read_status(archive))
            raw_status = {name: item["Version"] for name, item in package_rows.items()}
            published = {item["name"]: item["version"] for item in json.loads(bom_file.read_text(encoding="utf-8"))["components"]}
            if syft_inventory != raw_status:
                raise ValueError(f"Syft and package database differ: {build}")
            actual_report = verify(json.loads(bom_file.read_text(encoding="utf-8")), read_status(archive))
            row = {
                "build": build,
                "package_database_format": database_format,
                "syft_status_packages": len(syft_inventory),
                "package_database_packages": len(raw_status),
                "exact_syft_database_pairs": len(syft_inventory),
                "published_bom_components": len(published),
                "raw_diff_bom_only_names": len(published.keys() - syft_inventory.keys()),
                "raw_diff_status_only_names": len(syft_inventory.keys() - published.keys()),
                "raw_diff_version_disagreements_on_shared_names": sum(
                    published[name] != syft_inventory[name] for name in published.keys() & syft_inventory.keys()),
                "bomtrace_findings_on_unmodified_pair": len(actual_report["findings"]),
            }
            rows.append(row)
    totals = {key: sum(row[key] for row in rows) for key in rows[0] if key not in ("build", "package_database_format")}
    result = {
        "tool": "Anchore Syft 1.57.2, official Windows AMD64 release",
        "syft_exe_sha256": file_hash(syft),
        "syft_release_zip_sha256": "0a10e03ffd124c304fd7e7491262dba2e5f68eb12378b106d7525146675b2e3a",
        "method": "Syft scans each original rootfs tar.gz. Only components whose evidence location is an opkg status or apk installed database are retained. Compare those name/version pairs to the package database text and to the published BOM without normalization; separately run BomTrace normalization.",
        "rows": rows,
        "totals": totals,
        "interpretation": "Syft generated the package inventory and agreed exactly with the parsed opkg or apk database. The raw BOM-versus-inventory diff is a deliberately naive comparator that ignores Provides aliases and OpenWrt version conventions; its differences are not Syft errors or confirmed BOM defects. BomTrace adds the reconciliation step.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"tool": result["tool"], "totals": totals}, indent=2))


if __name__ == "__main__":
    main()
