"""Make a provenance-checked real-file trial from an official OpenWrt rootfs.

The BOMs are generated for this experiment; OpenWrt did not publish them.
Only two regular archive members are copied. Firmware is never executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tarfile
from pathlib import Path

from make_fixtures import bom, component, save_case, write


EXPECTED_SHA256 = "e7f8ab84eef55c7eb23492de7b0517dbc23fbedaa4abbb680fe64720c309dc03"
SOURCE_URL = "https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/openwrt-24.10.4-x86-64-rootfs.tar.gz"
MEMBERS = {"./bin/busybox": "bin/busybox", "./usr/lib/opkg/status": "usr/lib/opkg/status"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error("output already exists; choose a new directory")
    actual_sha = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if actual_sha != EXPECTED_SHA256:
        parser.error(f"archive SHA-256 mismatch: {actual_sha}")
    out.mkdir(parents=True)
    clean = out / "real_clean"
    root = clean / "rootfs"
    with tarfile.open(args.archive, "r:gz") as tar:
        for member_name, relative in MEMBERS.items():
            member = tar.getmember(member_name)
            if not member.isfile() or member.size > 64 * 1024 * 1024:
                raise ValueError(f"unexpected archive member: {member_name}")
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError(f"member not readable: {member_name}")
            write(root / relative, stream.read())

    status = (root / "usr/lib/opkg/status").read_text(encoding="utf-8", errors="replace")
    busybox = next(block for block in status.split("\n\n") if block.startswith("Package: busybox\n"))
    version = next(line.removeprefix("Version: ") for line in busybox.splitlines() if line.startswith("Version: "))
    sbom = bom([component("application", "busybox", "bin/busybox", root / "bin/busybox", version)])
    save_case(clean, sbom, bom([]), bom([]))

    drift = out / "real_version_drift"
    shutil.copytree(clean, drift)
    drift_bom = json.loads((drift / "sbom.json").read_text(encoding="utf-8"))
    drift_bom["components"][0]["version"] = "0.0.0-synthetic-drift"
    save_case(drift, drift_bom, bom([]), bom([]))
    (out / "ground_truth.json").write_text(
        json.dumps({"real_clean": [], "real_version_drift": ["PACKAGE_VERSION_MISMATCH|sbom|bin/busybox"]}, indent=2) + "\n",
        encoding="utf-8",
    )
    (out / "source_manifest.json").write_text(
        json.dumps({"url": SOURCE_URL, "archive_sha256": actual_sha, "members": MEMBERS, "bom_origin": "experiment-generated, not vendor-published"}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Extracted OpenWrt BusyBox {version} and opkg status; made clean and version-drift cases")


if __name__ == "__main__":
    main()
