"""Check regenerated evaluation evidence against the committed reference runs.

Wall-clock timings vary by host, so only those fields are excluded. Source
hashes, labels, per-case findings, schema outcomes, and coverage remain exact.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


TIMING_FIELDS = {"runtime_ms", "runtime_ms_median", "runtime_ms_max",
                 "verify_runtime_ms", "verify_runtime_ms_median"}


def without_timings(value):
    if isinstance(value, dict):
        return {key: without_timings(item) for key, item in value.items()
                if key not in TIMING_FIELDS}
    if isinstance(value, list):
        return [without_timings(item) for item in value]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--synthetic", type=Path, required=True)
    parser.add_argument("--official", type=Path, required=True)
    parser.add_argument("--cross-release", type=Path, required=True)
    parser.add_argument("--byte-probe", type=Path, required=True)
    args = parser.parse_args()
    reference_dir = Path(__file__).with_name("results")
    pairs = ((args.synthetic, reference_dir / "synthetic_benchmark.json"),
             (args.official, reference_dir / "openwrt_official_benchmark.json"),
             (args.cross_release, reference_dir / "cross_release_benchmark.json"),
             (args.byte_probe, reference_dir / "byte_drift_probe.json"))
    for generated_path, saved_path in pairs:
        generated = json.loads(generated_path.read_text(encoding="utf-8"))
        saved = json.loads(saved_path.read_text(encoding="utf-8"))
        if without_timings(generated) != without_timings(saved):
            raise ValueError(f"regenerated evidence differs from committed reference: {generated_path}")
        print(f"MATCH {generated_path.name} -> {saved_path.name}")


if __name__ == "__main__":
    main()
