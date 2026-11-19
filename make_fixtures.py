"""Build a small synthetic IoT rootfs benchmark with declared ground truth.

The generated certificate has a fresh key that is discarded. The .tflite file
is only a format-header fixture, not a functional model. Use a new --out path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def component(kind: str, name: str, rel: str, path: Path, version: str | None = None, extra: dict | None = None) -> dict:
    item = {
        "bom-ref": f"{kind}:{name}",
        "type": kind,
        "name": name,
        "hashes": [{"alg": "SHA-256", "content": digest(path)}],
        "properties": [{"name": "bomtrace:path", "value": rel}],
    }
    if version:
        item["version"] = version
    for key, value in (extra or {}).items():
        item["properties"].append({"name": key, "value": value})
    return item


def bom(components: list[dict]) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}


def save_case(case: Path, sbom: dict, cbom: dict, aibom: dict) -> None:
    for name, data in (("sbom", sbom), ("cbom", cbom), ("aibom", aibom)):
        (case / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def certificate() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.example.invalid")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1001)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new output directory; must not exist")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error("output already exists; choose a new directory")
    out.mkdir(parents=True)

    clean = out / "clean"
    root = clean / "rootfs"
    write(root / "usr/bin/edge-agent", b"#!/bin/sh\n# synthetic IoT edge agent fixture\nexit 0\n")
    write(root / "var/lib/opkg/status", b"Package: edge-agent\nVersion: 1.2.0\nStatus: install ok installed\n\n")
    write(root / "etc/device/app.ini", b"[edge-agent]\ncert_file=/etc/device/edge.pem\nmodel_file=/usr/share/models/detector.tflite\n")
    write(root / "etc/device/edge.pem", certificate())
    write(root / "usr/share/models/detector.tflite", b"\x1c\x00\x00\x00TFL3synthetic-header-only")

    sbom = bom([component("application", "edge-agent", "usr/bin/edge-agent", root / "usr/bin/edge-agent", "1.2.0")])
    cbom = bom([component("cryptographic-asset", "edge-cert", "etc/device/edge.pem", root / "etc/device/edge.pem", extra={"bomtrace:key-algorithm": "RSA"})])
    aibom = bom([component("machine-learning-model", "detector", "usr/share/models/detector.tflite", root / "usr/share/models/detector.tflite")])
    save_case(clean, sbom, cbom, aibom)

    drift = out / "drift"
    shutil.copytree(clean, drift)
    drift_sbom = json.loads((drift / "sbom.json").read_text(encoding="utf-8"))
    drift_sbom["components"][0]["version"] = "1.0.0"
    drift_sbom["components"][0]["hashes"][0]["content"] = "0" * 64
    save_case(drift, drift_sbom, bom([]), bom([]))

    unreferenced = out / "unreferenced"
    shutil.copytree(clean, unreferenced)
    write(unreferenced / "rootfs/etc/device/unused.pem", certificate())
    write(unreferenced / "rootfs/usr/share/models/unused.tflite", b"\x1c\x00\x00\x00TFL3unused-header-only")

    missing = out / "missing"
    shutil.copytree(clean, missing)
    (missing / "rootfs/usr/bin/edge-agent").unlink()

    truth = {
        "clean": [],
        "drift": [
            "SHA256_MISMATCH|sbom|usr/bin/edge-agent",
            "PACKAGE_VERSION_MISMATCH|sbom|usr/bin/edge-agent",
            "REFERENCED_ASSET_UNDECLARED|cbom|etc/device/edge.pem",
            "REFERENCED_ASSET_UNDECLARED|aibom|usr/share/models/detector.tflite",
        ],
        "unreferenced": [],
        "missing": ["DECLARED_FILE_MISSING|sbom|usr/bin/edge-agent"],
    }
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    print(f"Generated four cases and five labeled inconsistencies under {out}")


if __name__ == "__main__":
    main()
