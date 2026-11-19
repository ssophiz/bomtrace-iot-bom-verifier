"""Demonstrate the detection boundary of a package-only published BOM."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path

from verify_openwrt_bom import read_status, verify


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--bom", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    bom = json.loads(args.bom.read_text(encoding="utf-8"))
    if sha(args.archive.read_bytes()) != "e7f8ab84eef55c7eb23492de7b0517dbc23fbedaa4abbb680fe64720c309dc03":
        raise ValueError("unexpected source archive")
    original = verify(bom, read_status(args.archive))
    with tempfile.TemporaryDirectory(prefix="bomtrace-byte-probe-") as tmp:
        altered = Path(tmp) / "altered-rootfs.tar.gz"
        before_hash = after_hash = None
        with tarfile.open(args.archive, "r:gz") as src, tarfile.open(altered, "w:gz") as dst:
            for member in src:
                if not member.isfile():
                    dst.addfile(member)
                    continue
                stream = src.extractfile(member)
                if stream is None:
                    raise ValueError(f"unreadable member: {member.name}")
                data = stream.read()
                if member.name.lstrip("./") == "bin/busybox":
                    before_hash = sha(data)
                    changed = bytearray(data)
                    changed[-1] ^= 1
                    data = bytes(changed)
                    after_hash = sha(data)
                dst.addfile(member, io.BytesIO(data))
        if before_hash is None or before_hash == after_hash:
            raise ValueError("BusyBox was not changed")
        altered_report = verify(bom, read_status(altered))
    result = {
        "source": "official OpenWrt 24.10.4 x86-64 rootfs and published CycloneDX 1.4 BOM",
        "mutation": "flip the last byte of bin/busybox in a temporary rootfs archive; leave opkg status unchanged",
        "before_busybox_sha256": before_hash,
        "after_busybox_sha256": after_hash,
        "original_findings": len(original["findings"]),
        "altered_findings": len(altered_report["findings"]),
        "interpretation": "The published BOM has no per-file digest. Package-metadata reconciliation cannot observe this byte change; this is an explicit coverage gap, not a clean bill of health.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
