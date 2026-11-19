"""Reconcile a published OpenWrt CycloneDX BOM with its rootfs opkg database.

This verifies package inventory metadata, not firmware file bytes.  OpenWrt's
published CycloneDX 1.4 BOM has no file paths or hashes for these components.
"""

from __future__ import annotations

import argparse
import json
import re
import tarfile
from collections import defaultdict
from pathlib import Path


REVISION = re.compile(r"-r?\d+$")
KERNEL_BUILD = re.compile(r"~[0-9a-f]{16,64}$")
LEGACY_KERNEL_BUILD = re.compile(r"-\d+-[0-9a-f]{32,64}$")


def parse_status(text: str) -> dict[str, dict[str, str]]:
    packages = {}
    for block in re.split(r"\n\s*\n", text):
        fields = dict(re.findall(r"^([^:\n]+):\s*(.+)$", block, re.M))
        name = fields.get("Package")
        if name and fields.get("Status", "").startswith("install ") and fields["Status"].endswith(" installed"):
            if name in packages:
                raise ValueError(f"duplicate installed package: {name}")
            packages[name] = fields
    return packages


def read_status(archive: Path) -> str:
    with tarfile.open(archive, "r:gz") as tar:
        names = [m for m in tar if m.name.lstrip("./") in ("usr/lib/opkg/status", "var/lib/opkg/status")]
        if len(names) != 1 or not names[0].isfile() or names[0].size > 8 * 1024 * 1024:
            raise ValueError("expected one regular opkg status file")
        stream = tar.extractfile(names[0])
        if stream is None:
            raise ValueError("opkg status unreadable")
        return stream.read().decode("utf-8", errors="replace")


def aliases(packages: dict[str, dict[str, str]]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for name, fields in packages.items():
        result[name].add(name)
        for token in fields.get("Provides", "").split(","):
            alias = token.strip().split(" ")[0]
            if alias:
                result[alias].add(name)
    return result


def upstream_version(name: str, installed_version: str) -> str:
    value = REVISION.sub("", installed_version)
    # OpenWrt's kernel package encodes a build hash after upstream version.
    if name == "kernel":
        value = KERNEL_BUILD.sub("", value)
        value = LEGACY_KERNEL_BUILD.sub("", value)
    return value


def verify(bom: dict, status_text: str) -> dict:
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.4":
        raise ValueError("expected the published OpenWrt CycloneDX 1.4 format")
    components = bom.get("components")
    if not isinstance(components, list):
        raise ValueError("BOM components must be a list")
    installed = parse_status(status_text)
    lookup = aliases(installed)
    claimed_names = set()
    matched_installed = set()
    claims_for_installed: dict[str, list[str]] = defaultdict(list)
    findings = []
    unresolved = []
    for item in components:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("version"), str):
            unresolved.append({"reason": "component lacks name/version"})
            continue
        name, claimed = item["name"], item["version"]
        if name in claimed_names:
            findings.append({"rule_id": "DUPLICATE_BOM_COMPONENT", "package": name})
            continue
        claimed_names.add(name)
        candidates = {name} if name in installed else lookup.get(name, set())
        if not candidates:
            findings.append({"rule_id": "DECLARED_PACKAGE_ABSENT", "package": name, "claimed_version": claimed})
            continue
        if len(candidates) != 1:
            unresolved.append({"reason": "ambiguous provider", "package": name, "providers": sorted(candidates)})
            continue
        actual_name = next(iter(candidates))
        matched_installed.add(actual_name)
        claims_for_installed[actual_name].append(name)
        actual = installed[actual_name]["Version"]
        normalized = upstream_version(name, actual)
        if claimed != actual and claimed != normalized:
            findings.append({"rule_id": "PACKAGE_VERSION_MISMATCH", "package": name, "installed_package": actual_name, "claimed_version": claimed, "installed_version": actual, "compared_version": normalized})
    for name in sorted(installed.keys() - matched_installed):
        findings.append({"rule_id": "INSTALLED_PACKAGE_UNDECLARED", "package": name, "installed_version": installed[name]["Version"]})
    for name, claims in claims_for_installed.items():
        if len(claims) > 1:
            findings.append({"rule_id": "MULTIPLE_CLAIMS_ONE_PACKAGE", "package": name, "claims": sorted(claims)})
    findings.sort(key=lambda x: (x["rule_id"], x["package"]))
    return {
        "format": "bomtrace-openwrt-report-0.1",
        "evidence_level": "published BOM versus installed-package database",
        "bom_component_count": len(components),
        "installed_package_count": len(installed),
        "matched_installed_count": len(matched_installed),
        "findings": findings,
        "unresolved": unresolved,
        "limitations": [
            "The opkg database is not independently authenticated; a tampered database can mislead this check.",
            "The published BOM has no per-file path or digest, so file-byte drift cannot be determined.",
            "A package match does not establish runtime use or absence of vulnerabilities.",
            "OpenWrt-specific Provides, -r revision and kernel build-id rules are not portable to other package managers.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bom", type=Path, required=True)
    p.add_argument("--rootfs-tar", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    result = verify(json.loads(args.bom.read_text(encoding="utf-8")), read_status(args.rootfs_tar))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"{len(result['findings'])} findings; {result['matched_installed_count']}/{result['installed_package_count']} installed packages matched")


if __name__ == "__main__":
    main()
