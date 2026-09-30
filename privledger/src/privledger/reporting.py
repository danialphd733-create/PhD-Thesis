"""Render only observed run artifacts; reference values remain separate."""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path


def _csv(path):
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _json(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _jsonl(path):
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def access_gas_categories(run_dir):
    """Classify access receipts by the benchmark behavior that produced them."""
    run_dir = Path(run_dir)
    steps = {}
    for row in _jsonl(run_dir / "benchmark_steps.jsonl"):
        result = row.get("result", {})
        transaction_hash = result.get("transactionHash") if isinstance(result, dict) else None
        if transaction_hash:
            steps[transaction_hash.lower()] = row["step"]
    categories = {
        "Successful ZK authorizations": [],
        "Policy/state rejections": [],
        "Altered-public-input proof failures": [],
        "Malformed 256-byte proof attacks": [],
    }
    for receipt in _jsonl(run_dir / "transaction_receipts.jsonl"):
        if receipt.get("operation") != "access":
            continue
        step = steps.get(receipt.get("transactionHash", "").lower(), "")
        if step.startswith("access-invalid_proof-"):
            category = "Malformed 256-byte proof attacks"
        elif step.startswith("access-altered_public_input-"):
            category = "Altered-public-input proof failures"
        elif (step.startswith("redaction-") and step.endswith(":auth")
              or step.startswith("deletion-") and step.endswith(":auth")
              or step.startswith("access-authorized-")
              or step.startswith("access-replayed_nullifier-") and step.endswith(":initial")):
            category = "Successful ZK authorizations"
        else:
            category = "Policy/state rejections"
        categories[category].append(int(receipt["gasUsed"]))
    rows = []
    for category, values in categories.items():
        if values:
            rows.append({"category": category, "count": len(values), "gas_min": min(values), "gas_max": max(values),
                         "evidence_type": "measured controlled-prototype"})
    return rows


def _number(value):
    try:
        result = float(value)
        return result if math.isfinite(result) else None
    except (ValueError, TypeError):
        return None


def generate_plots(run_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    run_dir = Path(run_dir)
    figures = run_dir / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    written = []

    def save(fig, ax, name):
        ax.set_ylim(bottom=0)
        ax.grid(axis="y", alpha=.2)
        fig.tight_layout()
        for ext in ("png", "svg"):
            path = figures / f"{name}.{ext}"
            fig.savefig(path, dpi=220)
            written.append(str(path))
        plt.close(fig)

    def missing(ax):
        ax.text(.5, .5, "Not evaluated: no valid run data", transform=ax.transAxes,
                ha="center", va="center")

    def provenance(rows):
        values = sorted({r.get("evidence_type", "unspecified provenance") for r in rows})
        return "; ".join(values) or "Not evaluated"

    for filename, key, label, title, name in [
        ("gas_results.csv", "mean", "Mean gas (gas units / transaction)", "Transaction gas by operation", "gas_by_operation"),
        ("latency_results.csv", "p95", "95th percentile latency (ms)", "Operation latency", "latency_p95_by_operation"),
    ]:
        rows = [r for r in _csv(run_dir / filename) if _number(r.get(key)) is not None]
        if filename == "gas_results.csv":
            rows = [r for r in rows if r.get("operation") != "access"]
        fig, ax = plt.subplots(figsize=(9, 5))
        if rows:
            ax.bar(range(len(rows)), [float(r[key]) for r in rows], color="#267a92")
            ax.set_xticks(range(len(rows)), [r.get("operation", r.get("metric", "unknown")) for r in rows], rotation=25, ha="right")
        else:
            missing(ax)
        ax.set(xlabel="Operation", ylabel=label, title=f"{title}\n{provenance(rows)}")
        save(fig, ax, name)

    scaling = _csv(run_dir / "scalability_results.csv")
    for series, ylabel, title, name in [
        ([("total_wall_clock_seconds", "Complete workload elapsed time")], "Total wall-clock time (seconds)", "Complete workload time versus artifacts", "runtime_vs_artifacts"),
        ([("throughput_artifacts_per_second", "Completed artifact throughput")], "Throughput (artifacts / second)", "Throughput versus artifacts", "throughput_vs_artifacts"),
        ([("encrypted_payload_bytes", "Encrypted IPFS payload"), ("metadata_bytes", "Metadata")], "Storage (bytes)", "Storage versus artifacts", "storage_vs_artifacts"),
    ]:
        fig, ax = plt.subplots(figsize=(8, 5))
        valid_rows = []
        for key, label in series:
            rows = [r for r in scaling if _number(r.get("sample_size")) is not None and _number(r.get(key)) is not None]
            rows.sort(key=lambda r: float(r["sample_size"]))
            if rows:
                valid_rows.extend(rows)
                ax.plot([float(r["sample_size"]) for r in rows], [float(r[key]) for r in rows], "o-", label=label)
        if valid_rows:
            ax.legend()
        else:
            missing(ax)
        ax.set(xlabel="Artifacts (count)", ylabel=ylabel, title=f"{title}\n{provenance(valid_rows)}", xlim=(0, None))
        save(fig, ax, name)

    rows = _csv(run_dir / "e2_access_results.csv")
    fig, ax = plt.subplots(figsize=(8, 5))
    if rows:
        categories = sorted({r.get("expected_decision", "unknown") for r in rows})
        correct, incorrect = [], []
        for category in categories:
            group = [r for r in rows if r.get("expected_decision", "unknown") == category]
            passed = sum(str(r.get("correct", "")).lower() in ("true", "1", "yes") for r in group)
            correct.append(passed)
            incorrect.append(len(group) - passed)
        ax.bar(categories, correct, label="Correct", color="#267a92")
        ax.bar(categories, incorrect, bottom=correct, label="Incorrect", color="#b44846")
        ax.legend()
    else:
        missing(ax)
    ax.set(xlabel="Expected policy decision", ylabel="Policy cases (count)", title=f"Access policy outcomes\n{provenance(rows)}")
    save(fig, ax, "access_policy_outcomes")

    e4 = _json(run_dir / "e4_summary.json")
    rates = {k: _number(v) for k, v in e4.items()
             if any(term in k.lower() for term in ("rate", "traceability", "availability", "completeness", "unpin_success")) and _number(v) is not None}
    fig, ax = plt.subplots(figsize=(9, 5))
    if rates:
        ax.bar(range(len(rates)), list(rates.values()), color="#267a92")
        ax.set_xticks(range(len(rates)), [k.replace("_", " ") for k in rates], rotation=20, ha="right")
        ax.set_ylim(0, max(1.05, max(rates.values()) * 1.05))
    else:
        missing(ax)
    ax.set(xlabel="Evaluated workflow property", ylabel="Rate (fraction)",
           title=f"Redaction and deletion workflow\n{e4.get('evidence_type', 'Run-local workflow evaluation')}")
    save(fig, ax, "redaction_deletion_summary")
    return written


def _cell(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(rows):
    if not rows:
        return "Not evaluated: no run artifact available.\n"
    fields = list(dict.fromkeys(k for row in rows for k in row))
    if "evidence_type" not in fields:
        fields.append("evidence_type")
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    lines += ["| " + " | ".join(_cell(row.get(k, "not specified" if k == "evidence_type" else "")) for k in fields) + " |" for row in rows]
    return "\n".join(lines) + "\n"


def _summary_table(value):
    if value is None or value == {}:
        return "Not evaluated: no summary supplied.\n"
    if not isinstance(value, dict):
        value = {"status": value}
    evidence = value.get("evidence_type", "not specified")
    return _table([{"metric": k, "value": v, "evidence_type": evidence} for k, v in value.items() if k != "evidence_type"])


def _reliability_sections(run_dir, summary):
    value = _json(run_dir / "e7_reliability_summary.json") or summary.get("E7", {})
    if "measured_ipfs_recovery_ms" not in value and "measured_ipfs_recovery_ms" in summary.get("E7", {}):
        value = summary["E7"]
    reference = value.get("analytical_reference", {"rpo": 0, "rto_target_seconds": 60, "evidence_loss": 0})
    measured = {k: v for k, v in value.items() if k not in ("analytical_reference", "scenarios", "live_restart")}
    if "api_ready_seconds" not in measured and "measured_ipfs_recovery_ms" not in measured:
        measured = value.get("measured", value.get("local_restart", {}))
    statement = "A local Kubo restart does not evaluate recovery of independent replicas or multi-node consensus."
    if {"objects_tested", "recovered", "hashes_unchanged", "api_ready_seconds", "retrieval_ready_seconds"}.issubset(measured):
        statement = (f"Executed owned-Kubo restart: {measured['recovered']}/{measured['objects_tested']} objects recovered "
                     f"with unchanged hashes; API ready in {float(measured['api_ready_seconds']):.3f} s and retrieval ready in "
                     f"{float(measured['retrieval_ready_seconds']):.3f} s. This does not evaluate independent replicas or multi-node recovery.")
    return ("## E7 — Local recovery and analytical reference\n\n### Executed local IPFS restart\n\n"
            + _summary_table(measured)
            + "\n### Thesis analytical reference (not a local measurement)\n\n"
            + _summary_table({**reference, "evidence_type": "analytical/thesis-reference"})
            + "\n" + statement + "\n")


def generate_report(run_dir, summary_dict):
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    e5 = dict(summary_dict.get("E5", {}))
    e5.pop("gas", None)
    gas_rows = [row for row in _csv(run_dir / "gas_results.csv") if row.get("operation") != "access"]
    access_categories = access_gas_categories(run_dir)
    parts = ["# PrivLedger experiment report\n",
             f"Mode: **{_cell(summary_dict.get('mode', 'unknown'))}**. Status: **{_cell(summary_dict.get('status', 'not supplied'))}**.\n",
             "This report separates locally observed measurements, simulation, analytical checks, and thesis reference values. Missing experiments are marked not evaluated.\n",
             "## Dataset and workload\n", _summary_table(summary_dict.get("dataset")),
             "## Environment and implementations\n", _summary_table(summary_dict.get("environment")),
             "The DID/VC policy layer models credential checks; it is not a deployed identity issuer. Linkability uses independent synthetic event profiles. Proof, storage, and contract status must be read from the environment and run results.\n",
             "## E0 — Threat coverage\n", _table(_csv(run_dir / "e0_threat_coverage.csv")),
             "## E1 — Registration and integrity\n", _summary_table(summary_dict.get("E1") or _json(run_dir / "e1_integrity_summary.json")),
             "## E2 — Access control\n", _summary_table(summary_dict.get("E2") or _json(run_dir / "e2_access_summary.json")),
             "[Access policy cases](e2_access_results.csv)\n\n![Access policy outcomes](figures/access_policy_outcomes.png)\n",
             "## E3 — Data minimization and linkability\n",
             _summary_table(_json(run_dir / "e3_pii_scan.json")),
             "PII scanning evaluates the implemented on-chain data fields and scanner coverage, not a proof against metadata inference.\n",
             _table(_csv(run_dir / "linkability_results.csv")),
             "Linkability evidence type: **simulation-derived**. Metrics use held-out synthetic pairs. Direct identifier match rate uses same-actor pairs as its denominator. All features is the primary standardized logistic-regression classifier; other feature sets are ablations. No actor identifiers or labels enter classifier features.\n",
             "![Linkability ROC](figures/roc_static_vs_rotated.png)\n\n![Linkability metrics](figures/linkability_metric_comparison.png)\n\n![Linkability ablations](figures/linkability_ablation.png)\n",
             "## E4 — Redaction and deletion\n", _summary_table(summary_dict.get("E4") or _json(run_dir / "e4_summary.json")),
             "Deletion is a local storage/workflow observation. It does not establish physical erasure from independent replicas, external copies, or backups.\n\n![Redaction and deletion](figures/redaction_deletion_summary.png)\n",
             "## E5 — Performance and cost\n", _summary_table(e5),
             _table(gas_rows),
             "### Access gas by observed outcome category\n\n", _table(access_categories),
             "Successful ZK-backed authorizations consumed 295,549–295,621 gas. Policy/state rejections consumed 36,586–41,649 gas. Altered-public-input verifier failures consumed 268,479–268,515 gas. Deliberately malformed 256-byte proof attacks consumed approximately 27.3 million gas because they pass the adapter length check before entering the generated Groth16 verifier. These adversarial stress cases are not representative of normal successful access requests.\n\nNo single access-gas baseline comparison is reported. Access gas is presented by observed outcome category and local controlled-prototype conditions.\n\n![Gas by operation](figures/gas_by_operation.png)\n\n![Latency](figures/latency_p95_by_operation.png)\n",
             "## Scalability\n", _table(_csv(run_dir / "scalability_results.csv")),
             "Timing fields distinguish dataset selection, dataset preprocessing, experiment execution, and actual complete workload wall-clock elapsed time. Phase sums need not equal elapsed time when phases overlap or resume overhead is recorded separately. Throughput uses the denominator recorded in the workload row.\n",
             "## Artifact failures\n", (f"Recorded failure rows: {len(_csv(run_dir / 'artifact_failures.csv'))}. See [artifact_failures.csv](artifact_failures.csv).\n" if (run_dir / 'artifact_failures.csv').exists() else "Failure log not supplied.\n"),
             "![Runtime](figures/runtime_vs_artifacts.png)\n\n![Throughput](figures/throughput_vs_artifacts.png)\n\n![Storage](figures/storage_vs_artifacts.png)\n",
             "Scalability points represent completed workloads only. Connecting observed points does not establish a scaling law. Local chain measurements are not estimates of public-chain or multi-organization deployment latency.\n",
             "## E6 — AI anomaly scoring\n\n**Future work; not empirically evaluated.** No AI detection metrics are claimed. See the repository's E6 future-work document.\n",
             _reliability_sections(run_dir, summary_dict),
             "## E8 — Usability\n\n**Not empirically evaluated.** No participants, user-study outcomes, or SUS scores are invented. See the repository's usability study template.\n",
             "## Thesis references — separate from measured results\n",
             _table(_csv(run_dir / "measured_vs_thesis.csv")),
             "Thesis Table 12 reports static identity AUC/accuracy/F1 of 1.000 and rotated DID AUC 0.909, accuracy 0.877, F1 0.890. These reference values are not fitted targets. The independent synthetic workload, feature distributions, preprocessing, classifier and split can produce different values. See `thesis_linkability_reference.json` and `docs/LINKABILITY.md`.\n",
             "## Threats to validity and implementation limitations\n",
             "The synthetic attacker shares an actor population across training and test data while sharing no events. This does not evaluate unseen actors, global traffic observation, collusion, compromised wallets, or external identity datasets. The workload and instrumentation determine how far operational measurements generalize.\n"]
    limitations = summary_dict.get("limitations", [])
    parts.append("\n".join(f"- {_cell(item)}" for item in limitations) + "\n" if limitations else "No additional run-specific limitations were supplied.\n")
    command = summary_dict.get("reproduction_command", "python scripts/reproduce.py --mode full")
    parts += ["## Reproduction\n", f"```powershell\n{command}\n```\n" if command else "Use the repository README's reproduction command and the dataset path recorded above. No executable command was supplied to this report.\n",
              "Retain the run manifest, dataset provenance, seed, environment versions, and input sample sizes when comparing results.\n",
              "## Generated artifact inventory\n"]
    parts.extend(f"- [{path.relative_to(run_dir).as_posix()}]({path.relative_to(run_dir).as_posix()})\n" for path in sorted(run_dir.rglob("*")) if path.is_file() and path.name != "REPORT.md")
    report = run_dir / "REPORT.md"
    report.write_text("\n".join(parts), encoding="utf-8")
    return str(report)
