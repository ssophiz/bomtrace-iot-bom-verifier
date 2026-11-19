"""Download and hash-check the official OpenWrt inputs for the benchmark.

Run this explicitly; the verifier itself never downloads or executes firmware.
Upstream archives and BOMs remain outside the public code repository.
"""

from __future__ import annotations

import argparse
import hashlib
import urllib.request
from pathlib import Path

from benchmark_openwrt import SOURCES


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for build, (stem, base, archive_hash, bom_hash) in SOURCES.items():
        for name, expected in ((f"{stem}-rootfs.tar.gz", archive_hash), (f"{stem}.bom.cdx.json", bom_hash)):
            target = args.out / name
            if not target.is_file():
                with urllib.request.urlopen(base + name, timeout=60) as response, target.open("wb") as stream:
                    for chunk in iter(lambda: response.read(1024 * 1024), b""):
                        stream.write(chunk)
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual != expected:
                raise ValueError(f"SHA-256 mismatch for {build}/{name}: {actual}")
            print(f"{name}: {actual}")


if __name__ == "__main__":
    main()
