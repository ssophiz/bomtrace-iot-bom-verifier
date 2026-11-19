# BomTrace

BomTrace checks what an IoT bill of materials (BOM) can actually support with firmware evidence. It is an offline Python prototype for the [SafeIoT 2026 Hackathon Track 2](https://safe-iot.com/#hackathon). It does not execute firmware or claim to find vulnerabilities.

## Two evidence levels

1. `verify_openwrt_bom.py` compares a **published** OpenWrt CycloneDX 1.4 BOM with `opkg` status or the `apk` installed database in the matching official rootfs tar archive. It resolves package `Provides` aliases, strips OpenWrt package revisions and kernel build identifiers for upstream-version comparison, and reports duplicate, absent, undeclared and mismatched package claims. This is **package inventory evidence**, not file integrity. The published BOMs used here have no per-file hashes.
2. `bomtrace.py` checks an **experimental** three-view CycloneDX 1.6 profile against an extracted filesystem. The SBOM, CBOM and AI-BOM components must carry `bomtrace:path` and SHA-256 claims. It checks paths and hashes, `opkg` versions, X.509 certificate fields, a TensorFlow Lite header, and explicit `cert_file` / `model_file` configuration references. A header check does not validate model semantics or runtime loading.

The modes are intentionally distinct because a published package-only BOM cannot be silently upgraded into a byte-level assertion. Both modes report the limitations of their evidence.

## Reproduce the official OpenWrt evaluation

Tested on Python 3.13. Install `requirements.txt`. The source downloader fetches six official BOM/rootfs pairs, checks each against hard-coded SHA-256 values from the official release indexes, and keeps upstream bytes in an ignored local directory. No firmware is executed.

```powershell
python -m pip install -r requirements.txt
python download_sources.py --out upstream_sources
python benchmark_openwrt.py --source-dir upstream_sources --out official_benchmark_local.json
python verify_openwrt_bom.py --bom upstream_sources\openwrt-24.10.4-x86-64.bom.cdx.json --rootfs-tar upstream_sources\openwrt-24.10.4-x86-64-rootfs.tar.gz --out clean_local.json
python probe_byte_drift.py --bom upstream_sources\openwrt-24.10.4-x86-64.bom.cdx.json --archive upstream_sources\openwrt-24.10.4-x86-64-rootfs.tar.gz --out byte_probe_local.json
```

The six unmodified pairs cover OpenWrt 24.10.4 on x86-64, ARMv7 and ARMv8; 23.05.5 on x86-64; and 25.12.6 on ARMv8 and x86-64. Four use `opkg` and two use `apk`. Their 771 published components mapped to installed package records with zero findings. Five isolated, explicitly labeled metadata mutations per build produced 30 positive cases; BomTrace located 30/30 with no extra findings in these 36 controlled cases. The CycloneDX 1.4 schema validator raised a **case-level** alert on the six duplicate-component cases. Version-only and inventory-only rule ablations each located 12/30 exact labels. These are mutation tests on one firmware family, **not field precision/recall estimates** or an independent-tool comparison. `results/` holds the saved output; the scripts recompute it.

## Cross-release pairing check

`benchmark_cross_release.py` pairs each unmodified official BOM with every downloaded rootfs from the same target architecture. The 14 cases contain six same-build controls and eight **deliberately mismatched releases**. BomTrace raised a case-level alert on all eight mismatches and none of the controls. An intentionally naive exact name/version comparator alerted on all eight mismatches **and all six controls**; schema-only validation alerted on none. These are release-pair identity labels, not independently adjudicated package defects or naturally occurring attacks. The raw comparator is not an existing product. `results/cross_release_benchmark.json` records every pair, finding, source hash, and baseline count.

```powershell
python benchmark_cross_release.py --source-dir upstream_sources --out cross_release_local.json
```

The byte-drift probe changes one BusyBox byte in a temporary archive but leaves `opkg` status unchanged. The file hashes differ and the inventory verifier produces no finding. This is an explicit coverage gap caused by missing file digests in the published BOM.

## Existing-tool cross-check

We ran the official [Syft v1.57.2](https://github.com/anchore/syft/releases/tag/v1.57.2) package cataloger on the six original OpenWrt archives. `syft_crosscheck.py` retains only components whose evidence location is an `opkg` status or `apk` installed-database file; the 771 retained name/version pairs exactly match the directly parsed package databases. Syft is an SBOM **generator**, not a verifier of OpenWrt's separately published BOM. A deliberately naive raw-string diff between its package records and the published BOM would mark 146 BOM-only names, 146 installed-only names and 500 version disagreements on shared names. Those are not Syft errors or confirmed BOM defects; OpenWrt's published upstream names and versions differ from installed ABI package names and revision-bearing versions. BomTrace supplies the reconciliation step. The saved summary is in `results/syft_crosscheck.json`; the Syft binary is not redistributed here.

```powershell
python syft_crosscheck.py --syft-exe path\to\syft.exe --source-dir upstream_sources --out syft_local.json
```

## Transferability check: Torizon OS

Toradex [documents](https://developer.toradex.com/torizon/traceability/sbom/) its CycloneDX BOM as an actionable, vulnerability-oriented view and its SPDX BOM as the complete file inventory. `probe_torizon.py` compares one official Verdin AM62 build's [CycloneDX BOM](https://artifacts.toradex.com/artifactory/torizoncore-oe-prerelease-frankfurt/scarthgap-7.x.y/monthly/19/verdin-am62/torizon/torizon-docker/oedeploy/bom.json) with its [package manifest](https://artifacts.toradex.com/artifactory/torizoncore-oe-prerelease-frankfurt/scarthgap-7.x.y/monthly/19/verdin-am62/torizon/torizon-docker/oedeploy/torizon-docker-verdin-am62-20260506185053.manifest). It checks both files against the publisher's Artifactory SHA-256 values, then reports exact-name join coverage without labeling absent packages. The BOM has 218 component rows and 212 unique names; the manifest has 1,839 package names; only 134 names overlap exactly. These are **coverage counts, not defect or accuracy measurements**. OpenWrt-specific matching is not applied to this Yocto-style view. The saved result is in `results/torizon_transfer_probe.json`; upstream Toradex bytes are not in this repository.

```powershell
python probe_torizon.py --bom path\to\bom.json --manifest path\to\torizon-docker-verdin-am62-20260506185053.manifest --out torizon_local.json
```

## Reproduce the three-view smoke test

```powershell
python make_fixtures.py --out fixtures_local
python benchmark.py --fixtures fixtures_local --out synthetic_local.json
python test_paths.py -v
```

The synthetic fixtures have five mutation-defined findings. BomTrace located five; the digest-only comparator located two. The certificate is generated for the fixture and its private key is discarded. The `.tflite` file is a header stub, not a working model. The separate two-file OpenWrt trial generated its own BOM and should not be confused with the published BOM evaluation.

## Scope and limits

- The `opkg` or `apk` database is read from firmware and is not independently authenticated. An attacker who changes both it and the BOM may make them agree.
- File presence and a matching hash do not prove benign behavior or runtime use. Static configuration references are not runtime traces.
- The OpenWrt-specific alias and version rules do not apply to arbitrary package managers. Encrypted images, proprietary formats, and full AI/CBOM semantics are outside this prototype. No established artifact verifier has been benchmarked head to head.
- OpenWrt archives and published BOM bytes are not redistributed here. `download_sources.py` records source URLs and rejects checksum mismatches.

## License

BomTrace source code is MIT licensed. The bundled CycloneDX schemas are Apache 2.0 material with attribution in `THIRD_PARTY_NOTICES.md`.
