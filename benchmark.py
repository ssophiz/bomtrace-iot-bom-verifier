"""Evaluate BomTrace and a digest-only baseline on generated labeled cases."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from jsonschema import Draft7Validator

from bomtrace import digest, firmware_path, sha_claim, verify


def label(finding: dict) -> str:
    return f"{finding['rule_id']}|{finding['bom']}|{finding['path']}"


def hash_baseline(case: Path) -> set[str]:
    root = (case / "rootfs").resolve()
    found = set()
    for kind in ("sbom", "cbom", "aibom"):
        bom = json.loads((case / f"{kind}.json").read_text(encoding="utf-8"))
        for component in bom["components"]:
            paths = [p["value"] for p in component.get("properties", []) if p.get("name") == "bomtrace:path"]
            if len(paths) != 1:
                continue
            try:
                path, rel = firmware_path(root, paths[0])
            except ValueError:
                continue
            if not path.is_file():
                found.add(f"DECLARED_FILE_MISSING|{kind}|{rel}")
            elif (claimed := sha_claim(component)) and claimed != digest(path):
                found.add(f"SHA256_MISMATCH|{kind}|{rel}")
    return found


def metrics(actual: set[str], expected: set[str]) -> dict:
    tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(tp / (tp + fp), 3) if tp + fp else 1.0,
        "recall": round(tp / (tp + fn), 3) if tp + fn else 1.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=Path(__file__).with_name("bom-1.6.schema.json"))
    args = parser.parse_args()
    truth = json.loads((args.fixtures / "ground_truth.json").read_text(encoding="utf-8"))
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    schema_validator = Draft7Validator(schema)
    rows = []
    pooled_tool, pooled_baseline, pooled_schema, pooled_truth = set(), set(), set(), set()
    schema_valid_views = 0
    for case_name in sorted(truth):
        case = args.fixtures / case_name
        start = time.perf_counter()
        report = verify(case / "rootfs", case / "sbom.json", case / "cbom.json", case / "aibom.json")
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        actual = {label(f) for f in report["findings"]}
        baseline = hash_baseline(case)
        expected = set(truth[case_name])
        schema_errors = []
        schema_findings = set()
        for kind in ("sbom", "cbom", "aibom"):
            data = json.loads((case / f"{kind}.json").read_text(encoding="utf-8"))
            errors = list(schema_validator.iter_errors(data))
            if not errors:
                schema_valid_views += 1
            for error in errors:
                schema_errors.append(f"{kind}: {error.message}")
                schema_findings.add(f"SCHEMA_INVALID|{kind}|{error.json_path}")
        rows.append({
            "case": case_name,
            "expected": sorted(expected),
            "tool_findings": sorted(actual),
            "hash_baseline_findings": sorted(baseline),
            "schema_only_findings": sorted(schema_findings),
            "tool": metrics(actual, expected),
            "hash_baseline": metrics(baseline, expected),
            "schema_only": metrics(schema_findings, expected),
            "schema_errors": schema_errors,
            "runtime_ms": elapsed_ms,
        })
        pooled_tool |= {f"{case_name}:{x}" for x in actual}
        pooled_baseline |= {f"{case_name}:{x}" for x in baseline}
        pooled_schema |= {f"{case_name}:{x}" for x in schema_findings}
        pooled_truth |= {f"{case_name}:{x}" for x in expected}
    result = {
        "benchmark": "four synthetic cases with five mutation-defined inconsistencies",
        "tool": metrics(pooled_tool, pooled_truth),
        "hash_only_baseline": metrics(pooled_baseline, pooled_truth),
        "schema_only_baseline": metrics(pooled_schema, pooled_truth),
        "schema_valid_views": schema_valid_views,
        "cases": rows,
        "interpretation_limit": "Labels are generated from the mutation procedure; this small synthetic set is a smoke benchmark, not evidence of performance on real IoT firmware.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"tool": result["tool"], "hash_only_baseline": result["hash_only_baseline"], "schema_only_baseline": result["schema_only_baseline"], "schema_valid_views": schema_valid_views}))


if __name__ == "__main__":
    main()
