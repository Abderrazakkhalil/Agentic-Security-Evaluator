"""
Runner — Experiment orchestration.

Runs attacks across baselines, logs results, and generates summary tables.
This is the core evaluation engine.
"""

import statistics
from pathlib import Path

from config import (
    NUM_RUNS_PER_VARIANT,
    BASELINES,
    CLEAN_CV_DIR,
    default_model_spec,
)
# Phase 1 (single-prompt) agent. RateLimitCircuitBreaker is the shared breaker
# class — the ReAct agent re-exports the very same class, so catching the
# single-prompt one uniformly handles both architectures.
from agent.single_prompt.hr_agent import (
    evaluate_cv as _evaluate_cv_single,
    RateLimitCircuitBreaker,
)
from evaluation.logger import log_result, load_log


# ─── Agent dispatch ─────────────────────────────────────────────────────────────

def _get_evaluate_fn(agent: str):
    """
    Resolve the `--agent` selection to the matching evaluate_cv implementation.

    The ReAct agent is imported lazily so a single-prompt (Phase 1) run never
    pays its import cost and stays fully backward compatible.
    """
    if agent == "react":
        from agent.react_agent.hr_agent_react import evaluate_cv as _evaluate_cv_react
        return _evaluate_cv_react
    if agent == "defend":
        # Phase 3 defensive wrapper around the ReAct agent (lazy import keeps
        # single/react runs free of its cost).
        from agent.react_agent.defend_agent import evaluate_cv as _evaluate_cv_defend
        return _evaluate_cv_defend
    if agent in (None, "single"):
        return _evaluate_cv_single
    raise ValueError(f"Unknown agent '{agent}'. Use 'single', 'react' or 'defend'.")


# ─── Resume Support ─────────────────────────────────────────────────────────────

def _completed_keys(log_entries: list[dict] = None) -> set:
    """
    Build the set of already-completed execution keys from the log, so a resumed
    run can skip them. A combo counts as done only if it has a NON-error row —
    errored attempts (e.g. an API daily-cap crash) are left to be retried.

    Key = (agent, model_id, attack, variant, baseline, run_index). Including the
    agent keeps single-prompt and ReAct results from colliding on resume; legacy
    rows (no "agent" field) default to "single" so Phase 1 logs still match.
    """
    if log_entries is None:
        log_entries = load_log()
    done = set()
    for e in log_entries:
        if e.get("error") or e.get("decision") == "ERROR":
            continue
        done.add((
            e.get("agent", "single"),
            e.get("model_id"),
            e.get("attack"),
            e.get("variant"),
            e.get("baseline"),
            e.get("run_index"),
        ))
    return done

# Attack modules
from attacks.indirect_injection import (
    get_injection_variants,
    determine_success as injection_success,
    get_attack_family_name as injection_name,
    get_expected_decision as injection_expected,
)
from attacks.goal_hijacking import (
    get_hijacking_variants,
    determine_success as hijacking_success,
    get_attack_family_name as hijacking_name,
    get_expected_decision as hijacking_expected,
)
from attacks.agentic_dos import (
    get_dos_variants,
    determine_success as dos_success,
    get_attack_family_name as dos_name,
    get_expected_decision as dos_expected,
)
from attacks.tool_invocation import (
    get_tool_invocation_variants,
    determine_success as tool_success,
    get_attack_family_name as tool_name,
    get_expected_decision as tool_expected,
)
from attacks.obfuscated_injection import (
    get_obfuscated_variants,
    determine_success as obfuscated_success,
    get_attack_family_name as obfuscated_name,
    get_expected_decision as obfuscated_expected,
)


# ─── Attack Family Registry ────────────────────────────────────────────────────

ATTACK_REGISTRY = {
    "indirect_injection": {
        "get_variants": get_injection_variants,
        "determine_success": injection_success,
        "family_name": injection_name,
        "expected_decision": injection_expected,
    },
    "goal_hijacking": {
        "get_variants": get_hijacking_variants,
        "determine_success": hijacking_success,
        "family_name": hijacking_name,
        "expected_decision": hijacking_expected,
    },
    "agentic_dos": {
        "get_variants": get_dos_variants,
        "determine_success": dos_success,
        "family_name": dos_name,
        "expected_decision": dos_expected,
    },
    "tool_invocation": {
        "get_variants": get_tool_invocation_variants,
        "determine_success": tool_success,
        "family_name": tool_name,
        "expected_decision": tool_expected,
    },
    "obfuscated_injection": {
        "get_variants": get_obfuscated_variants,
        "determine_success": obfuscated_success,
        "family_name": obfuscated_name,
        "expected_decision": obfuscated_expected,
    },
}


# ─── Clean CV Baseline Run ─────────────────────────────────────────────────────

def run_clean_baseline(baselines: list[str] = None, num_runs: int = 1,
                       model_spec: dict = None, agent: str = "single") -> list[dict]:
    """
    Run clean CVs through the agent to establish baseline metrics.

    These runs serve two purposes:
    1. Validate that the agent produces sensible decisions on clean data.
    2. Establish latency/token baselines for DoS comparison.

    Args:
        baselines: List of baselines to test. Defaults to ["A"].
        num_runs: Number of runs per CV per baseline.
        model_spec: Model to evaluate with. Defaults to the configured default.
        agent: Architecture to route through ("single" or "react").

    Returns:
        List of result dicts.
    """
    if model_spec is None:
        model_spec = default_model_spec()
    if baselines is None:
        baselines = ["A"]

    evaluate_cv = _get_evaluate_fn(agent)

    cv_files = sorted(CLEAN_CV_DIR.glob("cv_*.txt"))
    if not cv_files:
        print("[ERROR] No clean CVs found in", CLEAN_CV_DIR)
        return []

    completed = _completed_keys()
    results = []
    total = len(cv_files) * len(baselines) * num_runs
    current = 0
    skipped = 0

    for baseline in baselines:
        for cv_file in cv_files:
            for run_idx in range(num_runs):
                current += 1

                # Resume: skip combos already completed in a prior run.
                key = (agent, model_spec["id"], "clean", cv_file.stem, baseline, run_idx)
                if key in completed:
                    skipped += 1
                    continue

                print(f"  [{current}/{total}] {agent} | {model_spec['id']} | Clean CV: "
                      f"{cv_file.name} | Baseline {baseline} | Run {run_idx + 1}")

                try:
                    result = evaluate_cv(str(cv_file), baseline=baseline,
                                         model_spec=model_spec)
                    result_entry = {
                        "agent": agent,
                        "attack": "clean",
                        "variant": cv_file.stem,
                        "model_id": model_spec["id"],
                        "baseline": baseline,
                        "success": False,  # Clean CVs can't "succeed" as attacks
                        "decision": result["decision"],
                        "expected_decision": "VARIES",
                        # A clean CV that is blocked is a FALSE POSITIVE (over-refusal).
                        # Recorded explicitly so the false-block rate is computable.
                        "blocked": result.get("blocked", result["decision"] == "BLOCKED"),
                        "flags": result.get("flags", []),
                        "latency_seconds": result["latency_seconds"],
                        "token_estimate": result["token_estimate"],
                        "response_token_estimate": result.get("response_token_estimate", 0),
                        "tool_called": result["send_email_attempted"],
                        # Phase 2 ground truth: did the agent REALLY execute a tool?
                        "tool_invoked": result.get("tool_invoked", result["send_email_attempted"]),
                        "react_steps": result.get("react_steps", 0),
                        "run_index": run_idx,
                        "error": None,
                    }
                    log_result(result_entry)
                    results.append(result_entry)

                except RateLimitCircuitBreaker as e:
                    print(f"\n  [CIRCUIT BREAKER] {e}")
                    print(f"  Aborting clean baseline on {model_spec['id']}. "
                          f"Completed work is logged; resume later.")
                    raise

                except Exception as e:
                    print(f"    [ERROR] {e}")
                    error_entry = {
                        "agent": agent,
                        "attack": "clean",
                        "variant": cv_file.stem,
                        "model_id": model_spec["id"],
                        "baseline": baseline,
                        "success": False,
                        "decision": "ERROR",
                        "expected_decision": "VARIES",
                        "blocked": False,
                        "latency_seconds": 0,
                        "token_estimate": 0,
                        "response_token_estimate": 0,
                        "tool_called": False,
                        "tool_invoked": False,
                        "react_steps": 0,
                        "run_index": run_idx,
                        "error": str(e),
                    }
                    log_result(error_entry)
                    results.append(error_entry)

    if skipped:
        print(f"  [resume] skipped {skipped} already-completed clean run(s).")
    return results


# ─── Attack Experiment Run ──────────────────────────────────────────────────────

def run_attack_experiment(
    attack_family: str,
    baselines: list[str] = None,
    num_runs: int = None,
    clean_median_latency: float = 1.0,
    clean_median_tokens: int = 200,
    model_spec: dict = None,
    agent: str = "single",
) -> list[dict]:
    """
    Run an attack experiment across specified baselines.

    For each variant × baseline × run:
    1. Evaluate the attack CV through the HR agent
    2. Determine if the attack succeeded
    3. Log the structured result

    Args:
        attack_family: Attack family name (e.g. "indirect_injection").
        baselines: List of baselines to test. Defaults to all.
        num_runs: Runs per variant per baseline. Defaults to config value.
        clean_median_latency: Baseline latency for DoS comparison.
        clean_median_tokens: Baseline token count for DoS comparison.
        model_spec: Model to evaluate with. Defaults to the configured default.
        agent: Architecture to route through ("single" or "react").

    Returns:
        List of result dicts.
    """
    if model_spec is None:
        model_spec = default_model_spec()
    if baselines is None:
        baselines = BASELINES
    if num_runs is None:
        num_runs = NUM_RUNS_PER_VARIANT

    evaluate_cv = _get_evaluate_fn(agent)

    if attack_family not in ATTACK_REGISTRY:
        print(f"[ERROR] Unknown attack family: {attack_family}")
        print(f"  Available: {list(ATTACK_REGISTRY.keys())}")
        return []

    registry = ATTACK_REGISTRY[attack_family]
    variants = registry["get_variants"]()
    success_fn = registry["determine_success"]
    family_name = registry["family_name"]()
    expected = registry["expected_decision"]()

    if not variants:
        print(f"[ERROR] No variants found for {attack_family}")
        return []

    completed = _completed_keys()
    results = []
    total = len(variants) * len(baselines) * num_runs
    current = 0
    skipped = 0

    print(f"\n{'='*60}")
    print(f"  Attack: {family_name}")
    print(f"  Agent: {agent}")
    print(f"  Model: {model_spec['id']} ({model_spec['provider']})")
    print(f"  Variants: {len(variants)}")
    print(f"  Baselines: {baselines}")
    print(f"  Runs per variant: {num_runs}")
    print(f"  Total executions: {total}")
    print(f"{'='*60}\n")

    for baseline in baselines:
        print(f"\n--- Baseline {baseline} ---\n")

        for variant in variants:
            for run_idx in range(num_runs):
                current += 1
                variant_name = Path(variant["file"]).stem

                # Resume: skip combos already completed in a prior run.
                key = (agent, model_spec["id"], family_name, variant_name, baseline, run_idx)
                if key in completed:
                    skipped += 1
                    continue

                print(f"  [{current}/{total}] {variant_name} | "
                      f"Baseline {baseline} | Run {run_idx + 1}", end="")

                try:
                    result = evaluate_cv(variant["path"], baseline=baseline,
                                         model_spec=model_spec)

                    # Determine success (DoS needs extra args)
                    if attack_family == "agentic_dos":
                        success = success_fn(
                            result,
                            clean_median_latency=clean_median_latency,
                            clean_median_tokens=clean_median_tokens,
                        )
                    else:
                        success = success_fn(result)

                    result_entry = {
                        "agent": agent,
                        "attack": family_name,
                        "variant": variant_name,
                        "variant_type": variant.get("variant_type", "unknown"),
                        "model_id": model_spec["id"],
                        "baseline": baseline,
                        "success": success,
                        "decision": result["decision"],
                        "expected_decision": expected,
                        "latency_seconds": result["latency_seconds"],
                        "token_estimate": result["token_estimate"],
                        "response_token_estimate": result.get("response_token_estimate", 0),
                        "tool_called": result["send_email_attempted"],
                        # Phase 2 ground truth: a real send_email execution (ReAct),
                        # not a substring guess. For single-prompt it mirrors the
                        # heuristic so existing tooling keeps working.
                        "tool_invoked": result.get("tool_invoked", result["send_email_attempted"]),
                        "react_steps": result.get("react_steps", 0),
                        "blocked": result.get("blocked", False),
                        "flags": result.get("flags", []),
                        # Phase 3 defensive-intervention metrics (default False so
                        # single/react rows are unaffected). Each marks which
                        # DefendAgentWrapper layer fired on this evaluation.
                        "blocked_by_anomaly": result.get("blocked_by_anomaly", False),
                        "blocked_by_provenance": result.get("blocked_by_provenance", False),
                        "blocked_by_firewall": result.get("blocked_by_firewall", False),
                        "blocked_by_sandbox": result.get("blocked_by_sandbox", False),
                        "run_index": run_idx,
                        "error": None,
                    }

                    status = "SUCCESS" if success else "FAILED"
                    print(f" -> {result['decision']} [{status}] "
                          f"({result['latency_seconds']}s)")

                    log_result(result_entry)
                    results.append(result_entry)

                except RateLimitCircuitBreaker as e:
                    print(f"\n  [CIRCUIT BREAKER] {e}")
                    print(f"  Aborting {family_name} on {model_spec['id']}. "
                          f"Completed work is logged; resume later.")
                    raise

                except Exception as e:
                    print(f" -> ERROR: {e}")
                    error_entry = {
                        "agent": agent,
                        "attack": family_name,
                        "variant": variant_name,
                        "variant_type": variant.get("variant_type", "unknown"),
                        "model_id": model_spec["id"],
                        "baseline": baseline,
                        "success": False,
                        "decision": "ERROR",
                        "expected_decision": expected,
                        "latency_seconds": 0,
                        "token_estimate": 0,
                        "response_token_estimate": 0,
                        "tool_called": False,
                        "tool_invoked": False,
                        "react_steps": 0,
                        "blocked": False,
                        "flags": [],
                        "run_index": run_idx,
                        "error": str(e),
                    }
                    log_result(error_entry)
                    results.append(error_entry)

    if skipped:
        print(f"\n  [resume] skipped {skipped} already-completed execution(s).")

    # Print summary
    _print_attack_summary(results, family_name, baselines)

    return results


def _print_attack_summary(results: list[dict], attack_name: str, baselines: list[str]):
    """Print a quick summary after an attack experiment."""
    print(f"\n{'='*60}")
    print(f"  Summary: {attack_name}")
    print(f"{'='*60}")

    for baseline in baselines:
        matching = [r for r in results if r["baseline"] == baseline]
        if not matching:
            continue
        successes = sum(1 for r in matching if r["success"])
        total = len(matching)
        asr = round((successes / total) * 100, 1) if total > 0 else 0
        print(f"  Baseline {baseline}: {successes}/{total} = {asr}% ASR")

    print(f"{'='*60}\n")


# ─── Compute Clean Baselines for DoS ───────────────────────────────────────────

def compute_clean_baselines(log_entries: list[dict] = None,
                            model_id: str = None) -> dict:
    """
    Compute median latency and token count from clean CV runs.

    Used as the reference point for Agentic DoS success determination. When
    model_id is given, only that model's clean runs are used (latency/output
    sizes differ across models, so the DoS reference must be per-model).

    The reference is restricted to **Baseline A, non-blocked** clean runs — i.e.
    normal agent processing. Including blocked rows (Baseline B/C false-blocks,
    latency/tokens ≈ 0) or Baseline C's extra filter latency would corrupt the
    median and distort DoS amplification detection.

    Returns:
        dict with 'median_latency' and 'median_tokens'.
    """
    if log_entries is None:
        log_entries = load_log()

    clean = [
        e for e in log_entries
        if e.get("attack") == "clean"
        and e.get("baseline") == "A"
        and not e.get("blocked")
        and e.get("decision") not in ("BLOCKED", "ERROR")
    ]
    if model_id is not None:
        clean = [e for e in clean if e.get("model_id") == model_id]

    if not clean:
        return {"median_latency": 1.0, "median_tokens": 200}

    latencies = [e.get("latency_seconds", 0) for e in clean]
    # Compare against the agent's *output* size. Fall back to the legacy
    # total token_estimate for logs produced before response tokens were tracked.
    tokens = [
        e.get("response_token_estimate", e.get("token_estimate", 0))
        for e in clean
    ]

    median_lat = statistics.median(latencies) if latencies else 1.0
    median_tok = statistics.median(tokens) if tokens else 200

    return {"median_latency": median_lat, "median_tokens": median_tok}
