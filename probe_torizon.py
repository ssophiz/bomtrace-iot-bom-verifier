"""Show why an actionable Yocto BOM is not an OpenWrt-style package inventory.

This is a transferability probe, not a discrepancy detector. It reads the
official Toradex BOM and same-build manifest, then reports join coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


SOURCES = {
    "bom": {
        "url": "https://artifacts.toradex.com/artifactory/torizoncore-oe-prerelease-frankfurt/scarthgap-7.x.y/monthly/19/verdin-am62/torizon/torizon-docker/oedeploy/bom.json",
        "sha256": "2b0c99272721b7241667c23c0e927e6ca34ea4c2d217591f05b5aaa238de3b26",
    },
    "manifest": {
        "url": "https://artifacts.toradex.com/artifactory/torizoncore-oe-prerelease-frankfurt/scarthgap-7.x.y/monthly/19/verdin-am62/torizon/torizon-docker/oedeploy/torizon-docker-verdin-am62-20260506185053.manifest",
        "sha256": "2f7ff6d397ed9f2a7cb7f5037e6e7655ec06769047ea995f56a0f16d553888df",
    },
}


def checked_bytes(path: Path, key: str) -> bytes:
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != SOURCES[key]["sha256"]:
        raise ValueError(f"{key} checksum mismatch: {actual}")
    return data


def probe(bom_data: bytes, manifest_data: bytes) -> dict:
    bom = json.loads(bom_data)
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.4":
        raise ValueError("unexpected BOM format")
    components = bom["components"]
    manifest = {}
    for line in manifest_data.decode("utf-8").splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] in manifest:
            raise ValueError("unexpected manifest line or duplicate name")
        manifest[parts[0]] = parts[2]
    names = Counter(c["name"] for c in components)
    unique = set(names)
    shared = unique & manifest.keys()
    exact_components = sum(c["name"] in manifest and c.get("version") == manifest[c["name"]] for c in components)
    return {
        "status": "unsupported for OpenWrt package-inventory reconciliation",
        "evidence_level": "published actionable BOM versus same-build published package manifest; no firmware bytes checked",
        "bom_component_count": len(components),
        "bom_unique_names": len(unique),
        "manifest_package_count": len(manifest),
        "unique_names_shared_exactly": len(shared),
        "components_with_exact_name_and_version": exact_components,
        "bom_unique_names_without_exact_manifest_name": len(unique - manifest.keys()),
        "manifest_names_without_exact_bom_name": len(manifest.keys() - unique),
        "bom_duplicate_name_count": sum(count - 1 for count in names.values() if count > 1),
        "interpretation": "Toradex documents its CycloneDX BOM as an actionable view with vulnerability-oriented names/versions and its complete SPDX BOM as a different view. A naive one-to-one package join would create unsupported mismatch claims. This probe reports coverage only and makes no error or accuracy assertion.",
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bom", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    result = probe(checked_bytes(args.bom, "bom"), checked_bytes(args.manifest, "manifest"))
    result["sources"] = SOURCES
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
