"""Summary statistics for actual observed measurements."""
import numpy as np


def summarize(values):
    data = np.asarray(list(values), dtype=float)
    if not np.all(np.isfinite(data)):
        raise ValueError("Measurements must be finite")
    if not len(data):
        return {"count": 0, "N": 0, **{k: None for k in ("mean", "median", "std", "p50", "p90", "p95", "p99", "min", "max")}}
    return {"count": len(data), "N": len(data), "mean": float(data.mean()),
            "median": float(np.median(data)), "std": float(data.std(ddof=1)) if len(data) > 1 else 0.0,
            **{f"p{p}": float(np.percentile(data, p)) for p in (50, 90, 95, 99)},
            "min": float(data.min()), "max": float(data.max())}
