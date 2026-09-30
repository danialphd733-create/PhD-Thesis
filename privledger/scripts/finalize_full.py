"""Validate and finalize staged full results without modifying prior run directories."""
from __future__ import annotations

import csv
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from privledger.reporting import generate_plots, generate_report

FIGURES = ["gas_by_operation", "latency_p95_by_operation", "runtime_vs_artifacts",
           "throughput_vs_artifacts", "storage_vs_artifacts", "roc_static_vs_rotated",
           "linkability_metric_comparison", "linkability_ablation", "access_policy_outcomes",
           "redaction_deletion_summary"]
REQUIRED = ["config_used.yaml", "environment.json", "artifact_failures.csv", "e0_threat_coverage.csv",
            "e1_integrity_results.csv", "e1_integrity_summary.json", "e2_access_results.csv",
            "e2_access_summary.json", "e3_pii_scan.json", "linkability_results.csv",
            "linkability_results.json", "linkability_predictions.csv", "e4_redaction_results.csv",
            "e4_deletion_results.csv", "e4_summary.json", "gas_results.csv", "latency_results.csv",
            "scalability_results.csv", "e7_reliability_results.csv", "e7_reliability_summary.json"]
REQUIRED += [f"{name}_{n}.{ext}" for n in (1000, 5000, 10000) for name, ext in (("manifest", "json"), ("metadata", "csv"))]


def read_csv(path):
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"CSV lacks header: {path.name}")
        rows = list(reader)
        if any(None in row or any(v is None for v in row.values()) for row in rows):
            raise ValueError(f"Malformed CSV row: {path.name}")
        return rows


def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def number(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Nonfinite metric")
    return result


def classify(value):
    if isinstance(value, list):
        return [classify(item) for item in value]
    if isinstance(value, dict):
        return {key: ("measured controlled-prototype" if key == "evidence_type" and item == "measured" else classify(item)) for key, item in value.items()}
    return value


def preflight(out):
    """Fail before drawing figures if a required full experiment is incomplete."""
    for name in REQUIRED:
        path = out / name
        if not path.is_file() or not path.stat().st_size:
            raise ValueError(f"Missing/empty required result: {name}")
    for path in out.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not data:
            raise ValueError(f"Empty JSON result: {path.name}")
    for path in out.glob("*.csv"):
        rows = read_csv(path)
        if not rows and path.name != "artifact_failures.csv":
            raise ValueError(f"Empty result dataset: {path.name}")
    scales = read_csv(out / "scalability_results.csv")
    if sorted(int(r["sample_size"]) for r in scales) != [1000, 5000, 10000]:
        raise ValueError("Exactly three completed workload rows 1000/5000/10000 required")
    for row in scales:
        n = int(row["sample_size"])
        if int(row["selected_artifact_count"]) != n or int(row["successful_registrations"]) + int(row["failed_registrations"]) != n:
            raise ValueError(f"Incomplete workload {n}")
        if len(read_csv(out / f"metadata_{n}.csv")) != int(row["successful_registrations"]):
            raise ValueError(f"Metadata count mismatch for workload {n}")
        for key in ("dataset_selection_seconds", "dataset_preprocessing_seconds", "experiment_execution_seconds", "total_wall_clock_seconds"):
            if number(row[key]) < 0:
                raise ValueError(f"Negative timing {key}")
        if number(row["total_wall_clock_seconds"]) < max(number(row[k]) for k in ("dataset_selection_seconds", "dataset_preprocessing_seconds", "experiment_execution_seconds")):
            raise ValueError("Total wall-clock time cannot be shorter than a complete individual phase")
    for filename, minimum in (("e2_access_results.csv", 200), ("e4_redaction_results.csv", 100), ("e4_deletion_results.csv", 100)):
        if len(read_csv(out / filename)) < minimum:
            raise ValueError(f"Insufficient cases: {filename} requires {minimum}")
    for filename, success_keys in (("e4_redaction_results.csv", ("lineage_valid", "replacement_verified", "event_emitted", "proof_reference_available")),
                                   ("e4_deletion_results.csv", ("local_unpin_success", "logical_deleted", "event_emitted", "proof_reference_available"))):
        rows = read_csv(out / filename)
        successes = sum(all(str(row.get(k, "")).lower() in ("true", "1") for k in success_keys) for row in rows)
        if successes < 100:
            raise ValueError(f"At least 100 successful workflows required: {filename}; found {successes}")
    link = json.loads((out / "linkability_results.json").read_text())
    if (link.get("pairs"), link.get("same_actor_pairs"), link.get("different_actor_pairs"), link.get("seed")) != (10000, 5000, 5000, 42):
        raise ValueError("Linkability sample contract mismatch")
    e7 = json.loads((out / "e7_reliability_summary.json").read_text())
    # Accept the current measured restart schema (startup and retrieval timings)
    # as well as the legacy single-duration field.
    measured = e7.get("measured_ipfs_recovery_ms")
    if measured is None:
        measured = (number(e7.get("api_ready_seconds", 0)) + number(e7.get("retrieval_ready_seconds", 0))) * 1000
    if e7.get("status") != "passed" or measured < 0 or not e7.get("old_process_exited") or not e7.get("api_observed_unavailable"):
        raise ValueError("Executed E7 restart measurement required")
    gas = {r["operation"]: r for r in read_csv(out / "gas_results.csv")}
    for op in ("register", "access", "redact", "delete"):
        if op not in gas or int(gas[op].get("count", gas[op].get("N", 0))) < 100:
            raise ValueError(f"At least 100 gas receipts required for {op}")
    return scales, link, e7


def comparisons(summary, gas, link):
    rows = []
    def add(metric, value, reference, evidence, reference_evidence="thesis-reference"):
        value, reference = number(value), number(reference)
        difference = value - reference
        rows.append(dict(metric=metric, our_value=value, thesis_value=reference,
                         our_evidence_type=evidence, thesis_evidence_type=reference_evidence,
                         difference=difference, percent_difference=100*difference/reference if reference else "",
                         interpretation="Independent observations and reference; settings and workload differ. No tuning to reference."))
    e1 = summary.get("E1", {})
    for name, key in (("hash_fidelity", "hash_fidelity_rate"), ("registration_event_completeness", "registration_event_completeness")):
        if e1.get(key) is not None:
            add(name, e1[key], 1, "measured controlled-prototype")
    for row in link["results"]:
        if row["ablation"] != "all":
            continue
        reference = {"roc_auc": 1, "accuracy": 1, "f1": 1} if row["condition"] == "static" else {"roc_auc": .909, "accuracy": .877, "f1": .890}
        for metric, value in reference.items():
            add(f"{row['condition']}_linkability_{metric}", row[metric], value, "simulation-derived", "simulation-derived/thesis-reference")
    for row in gas:
        references = {"register": 750000, "delete": 420000}
        if row["operation"] in references:
            add(f"privledger_{row['operation']}_gas", row["mean"], references[row["operation"]], "measured controlled-prototype", "simulation-derived/thesis-reference")
    return rows


def finalize_outputs(out, summary):
    """Only modify the current staging directory; caller publishes it after success."""
    out = Path(out).resolve()
    if out != (ROOT / "results" / "checkpoints" / "staging").resolve():
        raise ValueError("Finalization is restricted to results/checkpoints/staging; prior runs are immutable")
    scales, link, e7 = preflight(out)
    # Canonical scientific labels are applied only to the new staging artifacts.
    for path in out.glob("*.csv"):
        rows = read_csv(path)
        if rows and "evidence_type" in rows[0]:
            rows = classify(rows)
            if path.name == "e0_threat_coverage.csv":
                for row in rows:
                    row["evidence_type"] = "analytical/methodological"
            write_csv(path, rows)
    for path in out.glob("*.json"):
        data = classify(json.loads(path.read_text(encoding="utf-8")))
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    summary.update(classify(summary))
    link["provenance"] = link["evidence_type"] = "simulation-derived"
    for row in link["results"]:
        row["evidence_type"] = "simulation-derived"
    write_csv(out / "linkability_results.csv", link["results"])
    (out / "linkability_results.json").write_text(json.dumps(link, indent=2), encoding="utf-8")
    summary["linkability"] = link
    summary.setdefault("E3", {})["linkability"] = link
    e7.pop("live_restart", None)
    e7["evidence_type"] = "measured controlled-prototype"
    e7.setdefault("analytical_reference", {"rpo": 0, "rto_target_seconds": 60, "evidence_loss": 0})["evidence_type"] = "analytical/thesis-reference"
    summary["E7"] = e7
    summary["scalability"] = classify([{k: (number(v) if k not in ("evidence_type", "status", "workload_evidence_type", "timing_scope") and str(v).replace(".", "", 1).replace("-", "", 1).isdigit() else v) for k, v in row.items()} for row in scales])
    (out / "e7_reliability_summary.json").write_text(json.dumps(e7, indent=2), encoding="utf-8")
    write_csv(out / "measured_vs_thesis.csv", comparisons(summary, read_csv(out / "gas_results.csv"), link))
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    generate_plots(out)
    generate_report(out, summary)
    for name in FIGURES:
        for extension in ("png", "svg"):
            path = out / "figures" / f"{name}.{extension}"
            if not path.is_file() or path.stat().st_size == 0:
                raise ValueError(f"Missing final figure: {path.name}")
    validation = {"status": "passed", "workloads": [1000, 5000, 10000], "linkability_pairs": 10000,
                  "e2_cases": len(read_csv(out / "e2_access_results.csv")),
                  "redactions": len(read_csv(out / "e4_redaction_results.csv")),
                  "deletions": len(read_csv(out / "e4_deletion_results.csv")),
                  "validation_scope": "File parsing, completion counts, timing invariants, gas sample minimums and nonempty figures; not an independent transaction replay."}
    (out / "final_validation.json").write_text(json.dumps(validation, indent=2), encoding="utf-8")
    inventory = []
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "inventory.json":
            with path.open("rb") as handle:
                digest = hashlib.file_digest(handle, "sha256").hexdigest()
            inventory.append({"path": path.relative_to(out).as_posix(), "bytes": path.stat().st_size, "sha256": digest})
    (out / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    return validation


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--staging", type=Path, default=ROOT / "results/checkpoints/staging")
    args = parser.parse_args()
    print(json.dumps(finalize_outputs(args.staging, json.loads((args.staging / "summary.json").read_text())), indent=2))
