"""Evidence-bound checks for three CycloneDX BOM views of one IoT filesystem.

This prototype does not execute firmware or infer that a file is used merely
because it exists. A config reference is stronger evidence of possible use,
but still does not establish runtime behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath


MAX_FILE_BYTES = 64 * 1024 * 1024
REF_RE = re.compile(r"^\s*(cert_file|model_file)\s*=\s*([^#;\r\n]+)", re.I | re.M)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def firmware_path(root: Path, value: str) -> tuple[Path, str]:
    if not isinstance(value, str) or not value or value.startswith(("\\\\", "//")) or ":" in value:
        raise ValueError("invalid firmware path")
    rel = PurePosixPath(value.replace("\\", "/").lstrip("/"))
    if not rel.parts or any(part in ("..", ".") for part in rel.parts):
        raise ValueError("path traversal or empty path")
    target = (root / Path(*rel.parts)).resolve()
    if not target.is_relative_to(root):
        raise ValueError("path leaves firmware root")
    return target, rel.as_posix()


def properties(component: dict) -> dict[str, str]:
    return {
        item["name"]: item["value"]
        for item in component.get("properties", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("value"), str)
    }


def sha_claim(component: dict) -> str | None:
    claims = [
        item.get("content", "").lower()
        for item in component.get("hashes", [])
        if isinstance(item, dict) and item.get("alg", "").upper().replace("-", "") == "SHA256"
    ]
    if len(claims) != 1 or not re.fullmatch(r"[0-9a-f]{64}", claims[0]):
        return None
    return claims[0]


def load_bom(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("bomFormat") != "CycloneDX" or data.get("specVersion") != "1.6":
        raise ValueError(f"{path}: expected CycloneDX 1.6 JSON")
    components = data.get("components")
    if not isinstance(components, list) or any(not isinstance(item, dict) for item in components):
        raise ValueError(f"{path}: components must be an array of objects")
    return components


def opkg_versions(root: Path) -> tuple[dict[str, str], str | None]:
    candidates = ("usr/lib/opkg/status", "var/lib/opkg/status")
    status = next((root / rel for rel in candidates if (root / rel).is_file()), None)
    if status is None:
        return {}, None
    text = status.read_text(encoding="utf-8", errors="replace")
    result = {}
    for block in re.split(r"\n\s*\n", text):
        fields = dict(re.findall(r"^(Package|Version):\s*(.+)$", block, re.M))
        if fields.get("Package") and fields.get("Version"):
            result[fields["Package"]] = fields["Version"]
    return result, status.relative_to(root).as_posix()


def cert_details(path: Path) -> dict:
    from cryptography import x509

    data = path.read_bytes()
    cert = x509.load_pem_x509_certificate(data) if b"-----BEGIN CERTIFICATE-----" in data else x509.load_der_x509_certificate(data)
    key = cert.public_key()
    algorithm = key.__class__.__name__.removeprefix("RSAPublicKey").lower()
    if "RSA" in key.__class__.__name__:
        algorithm = "RSA"
    elif "EllipticCurve" in key.__class__.__name__:
        algorithm = "EC"
    elif "Ed25519" in key.__class__.__name__:
        algorithm = "Ed25519"
    return {
        "public_key_algorithm": algorithm or key.__class__.__name__,
        "public_key_bits": getattr(key, "key_size", None),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_after_utc": cert.not_valid_after_utc.isoformat(),
    }


def config_references(root: Path) -> list[dict]:
    refs = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in (".ini", ".conf"):
            continue
        if path.stat().st_size > 1024 * 1024:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in REF_RE.finditer(text):
            raw = match.group(2).strip().strip("\"'")
            try:
                _, rel = firmware_path(root, raw)
            except ValueError:
                continue
            refs.append({"config": path.relative_to(root).as_posix(), "key": match.group(1).lower(), "path": rel})
    return refs


def verify(root: Path, sbom: Path, cbom: Path, aibom: Path) -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("firmware root must be a directory")
    inputs = {"sbom": sbom, "cbom": cbom, "aibom": aibom}
    components = {kind: load_bom(path) for kind, path in inputs.items()}
    findings = []
    observations = []
    declared_paths: dict[str, set[str]] = {kind: set() for kind in inputs}
    versions, status_path = opkg_versions(root)

    def finding(rule: str, kind: str, ref: str, path: str | None, evidence: dict) -> None:
        findings.append({"rule_id": rule, "bom": kind, "bom_ref": ref, "path": path, "evidence": evidence})

    for kind, entries in components.items():
        for index, component in enumerate(entries):
            ref = str(component.get("bom-ref") or f"component-{index}")
            props = properties(component)
            raw_path = props.get("bomtrace:path")
            if raw_path is None:
                finding("CLAIM_PATH_ABSENT", kind, ref, None, {})
                continue
            try:
                path, rel = firmware_path(root, raw_path)
            except ValueError as exc:
                finding("CLAIM_PATH_INVALID", kind, ref, raw_path, {"reason": str(exc)})
                continue
            declared_paths[kind].add(rel)
            if not path.is_file() or path.is_symlink():
                finding("DECLARED_FILE_MISSING", kind, ref, rel, {})
                continue
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                finding("FILE_TOO_LARGE_TO_HASH", kind, ref, rel, {"bytes": size, "limit": MAX_FILE_BYTES})
                continue
            actual = digest(path)
            claimed = sha_claim(component)
            observation = {"bom": kind, "bom_ref": ref, "path": rel, "bytes": size, "sha256": actual}
            if claimed is None:
                finding("SHA256_CLAIM_ABSENT", kind, ref, rel, {"actual_sha256": actual})
            elif claimed != actual:
                finding("SHA256_MISMATCH", kind, ref, rel, {"claimed": claimed, "actual": actual})

            if kind == "sbom":
                name, version = component.get("name"), component.get("version")
                if isinstance(name, str) and name in versions:
                    observation["opkg_version"] = versions[name]
                    if version != versions[name]:
                        finding("PACKAGE_VERSION_MISMATCH", kind, ref, rel, {"claimed": version, "opkg_status": versions[name]})
            elif kind == "cbom":
                try:
                    details = cert_details(path)
                    observation["certificate"] = details
                    expected = props.get("bomtrace:key-algorithm")
                    if expected and expected.upper() != details["public_key_algorithm"].upper():
                        finding("KEY_ALGORITHM_MISMATCH", kind, ref, rel, {"claimed": expected, "observed": details["public_key_algorithm"]})
                except (ValueError, ImportError) as exc:
                    finding("CERTIFICATE_UNREADABLE", kind, ref, rel, {"reason": type(exc).__name__})
            elif kind == "aibom":
                if path.suffix.lower() == ".tflite":
                    header_ok = path.read_bytes()[:8][4:8] == b"TFL3"
                    observation["format_check"] = "TFLite header only"
                    if not header_ok:
                        finding("TFLITE_HEADER_INVALID", kind, ref, rel, {"checked_offset": 4})
                else:
                    observation["format_check"] = "not implemented; digest only"
            observations.append(observation)

    refs = config_references(root)
    for item in refs:
        kind = "cbom" if item["key"] == "cert_file" else "aibom"
        if item["path"] not in declared_paths[kind]:
            finding("REFERENCED_ASSET_UNDECLARED", kind, item["config"], item["path"], {"config_key": item["key"]})

    findings.sort(key=lambda f: (f["rule_id"], f["bom"], f["path"] or "", f["bom_ref"]))
    observations.sort(key=lambda o: (o["bom"], o["path"]))
    return {
        "schema": "bomtrace-report-0.1",
        "input": {"root": str(root), **{kind: str(path.resolve()) for kind, path in inputs.items()}},
        "component_counts": {kind: len(entries) for kind, entries in components.items()},
        "opkg_package_count": len(versions),
        "opkg_status_path": status_path,
        "config_references": refs,
        "observations": observations,
        "findings": findings,
        "limitations": [
            "A digest match binds a declared file to bytes; it does not establish runtime use or benign behavior.",
            "An opkg status entry is file-system metadata, not an independently authenticated package identity.",
            "A config reference is static evidence only; runtime loading is not tested.",
            "The TFLite check tests only the eight-byte header, not model semantics or safety.",
            "Missing or encrypted files and unsupported BOM formats are outside this prototype's coverage.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="extracted IoT filesystem directory")
    parser.add_argument("--sbom", type=Path, required=True, help="CycloneDX 1.6 software BOM JSON")
    parser.add_argument("--cbom", type=Path, required=True, help="CycloneDX 1.6 cryptographic BOM JSON")
    parser.add_argument("--aibom", type=Path, required=True, help="CycloneDX 1.6 AI BOM JSON")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.root, args.sbom, args.cbom, args.aibom)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{len(report['findings'])} findings across {sum(report['component_counts'].values())} BOM claims: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
