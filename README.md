# BomTrace

BomTrace checks what an IoT bill of materials (BOM) can actually support with firmware evidence. It is an offline Python prototype for the [SafeIoT 2026 Hackathon Track 2](https://safe-iot.com/#hackathon). It does not execute firmware or claim to find vulnerabilities.

## Two evidence levels

1. `verify_openwrt_bom.py` compares a **published** OpenWrt CycloneDX 1.4 BOM with `opkg` status in the matching official rootfs tar archive. It resolves package `Provides` aliases, strips OpenWrt package revisions and kernel build identifiers for upstream-version comparison, and reports duplicate, absent, undeclared and mismatched package claims. This is **package inventory evidence**, not file integrity. The published BOMs used here have no per-file hashes.
2. `bomtrace.py` checks an **experimental** three-view CycloneDX 1.6 profile against an extracted filesystem. The SBOM, CBOM and AI-BOM components must carry `bomtrace:path` and SHA-256 claims. It checks paths and hashes, `opkg` versions, X.509 certificate fields, a TensorFlow Lite header, and explicit `cert_file` / `model_file` configuration references. A header check does not validate model semantics or runtime loading.

The modes are intentionally distinct because a published package-only BOM cannot be silently upgraded into a byte-level assertion. Both modes report the limitations of their evidence.

## Reproduce the official OpenWrt evaluation

Tested on Python 3.13. Install `requirements.txt`. The source downloader fetches four official BOM/rootfs pairs, checks each against hard-coded SHA-256 values from the official release indexes, and keeps upstream bytes in an ignored local directory. No firmware is executed.

```powershell
python -m pip install -r requirements.txt
python download_sources.py --out upstream_sources
python benchmark_openwrt.py --source-dir upstream_sources --out official_benchmark_local.json
python verify_openwrt_bom.py --bom upstream_sources\openwrt-24.10.4-x86-64.bom.cdx.json --rootfs-tar upstream_sources\openwrt-24.10.4-x86-64-rootfs.tar.gz --out clean_local.json
python probe_byte_drift.py --bom upstream_sources\openwrt-24.10.4-x86-64.bom.cdx.json --archive upstream_sources\openwrt-24.10.4-x86-64-rootfs.tar.gz --out byte_probe_local.json
```

The four unmodified pairs cover OpenWrt 24.10.4 on x86-64, ARMv7 and ARMv8 and 23.05.5 on x86-64. Their 504 published components mapped to installed package records with zero findings. Five isolated, explicitly labeled metadata mutations per build produced 20 positive cases; BomTrace located 20/20 with no extra findings in these 24 controlled cases. The CycloneDX 1.4 schema validator raised a **case-level** alert on the four duplicate-component cases. Version-only and inventory-only rule ablations each located 8/20 exact labels. These are mutation tests on one firmware family, **not field precision/recall estimates** or an independent-tool comparison. `results/` holds the saved output; the scripts recompute it.

The byte-drift probe changes one BusyBox byte in a temporary archive but leaves `opkg` status unchanged. The file hashes differ and the inventory verifier produces no finding. This is an explicit coverage gap caused by missing file digests in the published BOM.

## Reproduce the three-view smoke test

```powershell
python make_fixtures.py --out fixtures_local
python benchmark.py --fixtures fixtures_local --out synthetic_local.json
python test_paths.py -v
```

The synthetic fixtures have five mutation-defined findings. BomTrace located five; the digest-only comparator located two. The certificate is generated for the fixture and its private key is discarded. The `.tflite` file is a header stub, not a working model. The separate two-file OpenWrt trial generated its own BOM and should not be confused with the published BOM evaluation.

## Scope and limits

- The `opkg` database is read from firmware and is not independently authenticated. An attacker who changes both it and the BOM may make them agree.
- File presence and a matching hash do not prove benign behavior or runtime use. Static configuration references are not runtime traces.
- The OpenWrt-specific alias and version rules do not apply to arbitrary package managers. Encrypted images, proprietary formats, and full AI/CBOM semantics are outside this prototype.
- OpenWrt archives and published BOM bytes are not redistributed here. `download_sources.py` records source URLs and rejects checksum mismatches.

## License

BomTrace source code is MIT licensed. The bundled CycloneDX schemas are Apache 2.0 material with attribution in `THIRD_PARTY_NOTICES.md`.
