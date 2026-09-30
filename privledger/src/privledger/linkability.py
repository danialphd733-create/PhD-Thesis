"""Synthetic E3B attacker experiment; no thesis metrics are fitted or hard-coded."""
from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np

FEATURES = ["identifier_equal", "role_equal", "action_equal", "case_category_equal",
            "absolute_time_difference", "time_of_day_similarity"]


def generate_pairs(pairs=10000, seed=42):
    """Return attacker-visible pair features and separate evaluation ground truth.

    Every pair receives two fresh events: no event can occur in another pair.
    Actor identities are never exposed to feature extraction or the classifier.
    """
    if isinstance(pairs, bool) or not isinstance(pairs, int) or pairs < 20 or pairs % 2:
        raise ValueError("pairs must be an even integer >= 20")
    rng = np.random.default_rng(seed)
    n_actors = 200
    roles = rng.integers(0, 5, n_actors)
    actions = rng.integers(0, 6, n_actors)
    categories = rng.integers(0, 8, n_actors)
    hours = rng.uniform(0, 24, n_actors)
    labels = np.repeat([0, 1], pairs // 2)
    rng.shuffle(labels)
    actor_left = rng.integers(0, n_actors, pairs)
    offsets = rng.integers(1, n_actors, pairs)
    actor_right = np.where(labels == 1, actor_left, (actor_left + offsets) % n_actors)

    def events(actors, parity):
        event_hours = (hours[actors] + rng.normal(0, 2.5, pairs)) % 24
        return {
            "static_did": np.array([f"did:synthetic:actor:{a}" for a in actors]),
            "rotated_did": np.array([f"did:synthetic:event:{2*i+parity}" for i in range(pairs)]),
            "event_id": np.arange(pairs) * 2 + parity,
            "role": roles[actors],
            "action": np.where(rng.random(pairs) < .8, actions[actors], rng.integers(0, 6, pairs)),
            "category": np.where(rng.random(pairs) < .7, categories[actors], rng.integers(0, 8, pairs)),
            "hour": event_hours,
            "timestamp": rng.integers(0, 30, pairs) * 24 + event_hours,
        }

    left, right = events(actor_left, 0), events(actor_right, 1)
    # Only public event fields cross this boundary; no label/actor inputs.
    matrices = {condition: pair_features(left, right, condition) for condition in ("static", "rotated")}
    return matrices, labels, np.column_stack([left["event_id"], right["event_id"]])


def pair_features(left, right, condition):
    hour_diff = np.abs(left["hour"] - right["hour"])
    circular_hours = np.minimum(hour_diff, 24 - hour_diff)
    return np.column_stack([
        left[f"{condition}_did"] == right[f"{condition}_did"],
        left["role"] == right["role"], left["action"] == right["action"],
        left["category"] == right["category"],
        np.abs(left["timestamp"] - right["timestamp"]),
        1 - circular_hours / 12,
    ]).astype(float)


def run_linkability(output_dir, pairs=10000, seed=42):
    """Run six fixed classifiers, save held-out predictions and measured figures."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                                 precision_score, recall_score, roc_auc_score, roc_curve)
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    matrices, labels, event_ids = generate_pairs(pairs, seed)
    train, test = train_test_split(np.arange(pairs), test_size=.3, stratify=labels, random_state=seed)
    assert not set(event_ids[train].ravel()).intersection(event_ids[test].ravel())
    ablations = {"identifier_only": [0], "context_only": list(range(1, 6)), "all": list(range(6))}
    rows, predictions, curves = [], [], {}
    for condition, matrix in matrices.items():
        for ablation, columns in ablations.items():
            x = matrix[:, columns]
            model = make_pipeline(StandardScaler(), LogisticRegression(C=1.0, solver="lbfgs", random_state=seed, max_iter=1000))
            model.fit(x[train], labels[train])
            probability = model.predict_proba(x[test])[:, 1]
            predicted = (probability >= .5).astype(int)
            tn, fp, fn, tp = confusion_matrix(labels[test], predicted, labels=[0, 1]).ravel()
            rows.append({
                "condition": condition, "ablation": ablation,
                "evidence_type": "simulation-derived",
                "direct_identifier_match_rate": float(matrix[labels == 1, 0].mean()),
                "different_actor_identifier_match_rate": float(matrix[labels == 0, 0].mean()),
                "roc_auc": float(roc_auc_score(labels[test], probability)),
                "accuracy": float(accuracy_score(labels[test], predicted)),
                "precision": float(precision_score(labels[test], predicted, zero_division=0)),
                "recall": float(recall_score(labels[test], predicted, zero_division=0)),
                "f1": float(f1_score(labels[test], predicted, zero_division=0)),
                "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
                "train_pairs": len(train), "test_pairs": len(test),
            })
            curves[(condition, ablation)] = roc_curve(labels[test], probability)
            for idx, prob, pred in zip(test, probability, predicted):
                predictions.append({"pair_id": int(idx), "left_event_id": int(event_ids[idx, 0]),
                                    "right_event_id": int(event_ids[idx, 1]), "split": "test",
                                    "condition": condition, "ablation": ablation,
                                    "same_actor": int(labels[idx]), "probability": float(prob),
                                    "prediction": int(pred)})

    summary = {"provenance": "simulation-derived", "evidence_type": "simulation-derived", "seed": seed, "pairs": pairs,
               "same_actor_pairs": int(labels.sum()), "different_actor_pairs": int((1-labels).sum()),
               "train_pairs": len(train), "test_pairs": len(test), "shared_train_test_events": 0,
               "primary_classifier": "StandardScaler + LogisticRegression, all features, threshold 0.5",
               "direct_match_denominator": "all same-actor pairs (not all pairs)",
               "actor_population": 200, "results": rows}
    for name, values in [("linkability_results.csv", rows), ("linkability_predictions.csv", predictions)]:
        with (output_dir / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(values[0]))
            writer.writeheader()
            writer.writerows(values)
    (output_dir / "linkability_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    reference = {"provenance": "thesis_reference_only", "source": "danial.pdf, Table 12, PDF page 48",
                 "static": {"direct_identifier_match_rate": 1, "roc_auc": 1, "accuracy": 1, "f1": 1},
                 "rotated": {"direct_identifier_match_rate": 0, "roc_auc": .909, "accuracy": .877, "f1": .890}}
    (output_dir / "thesis_linkability_reference.json").write_text(json.dumps(reference, indent=2), encoding="utf-8")

    def save(fig, name):
        figures = output_dir / "figures"
        figures.mkdir(exist_ok=True)
        fig.tight_layout()
        for extension in ("png", "svg"):
            fig.savefig(figures / f"{name}.{extension}", dpi=180)
        plt.close(fig)

    fig, ax = plt.subplots(figsize=(6, 5))
    for condition in matrices:
        fpr, tpr, _ = curves[(condition, "all")]
        score = next(r["roc_auc"] for r in rows if r["condition"] == condition and r["ablation"] == "all")
        ax.plot(fpr, tpr, label=f"{condition.title()} (AUC {score:.3f})")
    ax.plot([0, 1], [0, 1], "--", color="gray")
    ax.set(xlabel="False positive rate", ylabel="True positive rate", title="Synthetic linkability: held-out ROC")
    ax.legend()
    save(fig, "roc_static_vs_rotated")
    fig, ax = plt.subplots(figsize=(8, 4))
    metrics = ["roc_auc", "accuracy", "precision", "recall", "f1"]
    for offset, condition in [(-.19, "static"), (.19, "rotated")]:
        row = next(r for r in rows if r["condition"] == condition and r["ablation"] == "all")
        ax.bar(np.arange(len(metrics)) + offset, [row[m] for m in metrics], .38, label=condition.title())
    ax.set(xticks=np.arange(len(metrics)), xticklabels=[m.replace("_", " ").upper() for m in metrics],
           ylim=(0, 1.08), ylabel="Held-out score", title="Synthetic linkability: primary classifier")
    ax.legend(loc="lower right")
    save(fig, "linkability_metric_comparison")
    fig, ax = plt.subplots(figsize=(7, 4))
    for offset, condition in [(-.19, "static"), (.19, "rotated")]:
        scores = [next(r["roc_auc"] for r in rows if r["condition"] == condition and r["ablation"] == a) for a in ablations]
        ax.bar(np.arange(3) + offset, scores, .38, label=condition.title())
    ax.set(xticks=np.arange(3), xticklabels=[a.replace("_", " ").title() for a in ablations],
           ylim=(0, 1.08), ylabel="Held-out ROC-AUC", title="Synthetic linkability: feature ablation")
    ax.legend(loc="lower right")
    save(fig, "linkability_ablation")
    return summary
