"""
calculate_wilson_ci.py — Add 95% Wilson score confidence intervals to results.

Reads results/tables/asr_summary.csv (long format produced by the experiment
runner) and writes results/tables/asr_summary_with_ci.csv, annotating every
proportion (ASR and False-Block Rate) with its 95% Wilson score interval.

Why Wilson: for proportions near 0% or 100% with modest n, the normal
("Wald") interval is badly miscalibrated and can fall outside [0, 1]. The
Wilson score interval stays in bounds and is the standard recommendation for
binomial proportions — appropriate here where many cells sit at 0% or 100%.

Sample size per cell (n):
    ASR cells              : 20 attack variants × 3 runs              = 60
    FALSE_BLOCK clean_all   : (10 easy + 10 hard) clean CVs × 3 runs  = 60
    FALSE_BLOCK clean_easy  : 10 clean CVs × 3 runs                   = 30
    FALSE_BLOCK clean_hard  : 10 hard-negative CVs × 3 runs           = 30

No external APIs, no LLM calls — only the standard library (math, csv).

Usage:
    python calculate_wilson_ci.py
    python calculate_wilson_ci.py --in path/to/asr_summary.csv --out out.csv
"""

import argparse
import csv
import math
from pathlib import Path

# 95% two-sided normal quantile (z for 0.975).
Z_95 = 1.959963984540054

# Experiment design constants — edit if the corpus/run count changes.
NUM_RUNS = 3
ATTACK_VARIANTS = 20
EASY_CLEAN = 10
HARD_CLEAN = 10


def sample_size(metric: str, attack_family: str) -> int:
    """Return the number of trials (n) backing a given CSV row."""
    if metric == "ASR":
        return ATTACK_VARIANTS * NUM_RUNS
    if metric == "FALSE_BLOCK":
        if attack_family == "clean_easy":
            return EASY_CLEAN * NUM_RUNS
        if attack_family == "clean_hard":
            return HARD_CLEAN * NUM_RUNS
        return (EASY_CLEAN + HARD_CLEAN) * NUM_RUNS  # clean_all
    # Fallback: assume the standard attack cell size.
    return ATTACK_VARIANTS * NUM_RUNS


def wilson_interval(successes: int, n: int, z: float = Z_95):
    """
    95% Wilson score interval for a binomial proportion.

    Args:
        successes: number of positive outcomes (k).
        n: number of trials.
        z: normal quantile (default 1.96 for 95%).

    Returns:
        (low, high) as proportions in [0, 1]. Returns (0.0, 0.0) if n == 0.
    """
    if n <= 0:
        return 0.0, 0.0
    p = successes / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, center - margin), min(1.0, center + margin)


def successes_from_percent(value_percent: float, n: int) -> int:
    """Recover the integer success count from a rounded percentage and n."""
    return int(round((value_percent / 100.0) * n))


def annotate(in_path: Path, out_path: Path) -> int:
    with open(in_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        raise SystemExit(f"No rows found in {in_path}")

    fieldnames = [
        "model_id", "metric", "attack_family", "baseline",
        "value_percent", "n",
        "ci_low_percent", "ci_high_percent", "ci_margin_percent",
        "display",
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for r in rows:
            metric = r.get("metric", "ASR")
            attack_family = r.get("attack_family", "")
            value = float(r["value_percent"])
            n = sample_size(metric, attack_family)

            k = successes_from_percent(value, n)
            low, high = wilson_interval(k, n)
            low_pct, high_pct = low * 100.0, high * 100.0
            # Symmetric ± margin = half the (asymmetric) Wilson width; exact
            # bounds are kept in ci_low/ci_high for rigour.
            margin = (high_pct - low_pct) / 2.0

            writer.writerow({
                "model_id": r["model_id"],
                "metric": metric,
                "attack_family": attack_family,
                "baseline": r["baseline"],
                "value_percent": f"{value:.1f}",
                "n": n,
                "ci_low_percent": f"{low_pct:.1f}",
                "ci_high_percent": f"{high_pct:.1f}",
                "ci_margin_percent": f"{margin:.1f}",
                "display": f"{value:.1f}% ± {margin:.1f}%",
            })

    return len(rows)


def main():
    default_in = Path(__file__).parent / "results" / "tables" / "asr_summary.csv"
    default_out = Path(__file__).parent / "results" / "tables" / "asr_summary_with_ci.csv"

    parser = argparse.ArgumentParser(description="Add 95% Wilson CIs to ASR results.")
    parser.add_argument("--in", dest="in_path", type=Path, default=default_in,
                        help=f"Input CSV (default: {default_in})")
    parser.add_argument("--out", dest="out_path", type=Path, default=default_out,
                        help=f"Output CSV (default: {default_out})")
    args = parser.parse_args()

    if not args.in_path.exists():
        raise SystemExit(
            f"Input not found: {args.in_path}\n"
            f"Run `python run_experiment.py --generate-tables` first."
        )

    count = annotate(args.in_path, args.out_path)
    print(f"Wrote {args.out_path} ({count} rows, 95% Wilson score intervals).")


if __name__ == "__main__":
    main()
