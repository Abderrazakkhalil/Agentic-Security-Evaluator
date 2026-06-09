"""
run_experiment.py — CLI entry point for the Agent Security Research Framework.

Usage:
    python run_experiment.py --attack indirect_injection --baseline A
    python run_experiment.py --attack indirect_injection --baseline all
    python run_experiment.py --attack all --baseline all
    python run_experiment.py --clean-baseline
    python run_experiment.py --generate-tables
    python run_experiment.py --clear-logs

Environment variables:
    GEMINI_API_KEY    — API key for Gemini (if using Gemini)
    OPENAI_API_KEY    — API key for OpenAI (if using OpenAI)
    DRY_RUN=true      — Run without making LLM calls (mock responses)
    LLM_PROVIDER      — "gemini" or "openai"
    MODEL_NAME        — Model identifier (e.g. "gemini-2.0-flash")
    NUM_RUNS          — Runs per variant (default: 3)
"""

import argparse
import sys

from config import (
    AGENTS,
    BASELINES,
    ATTACK_FAMILIES,
    NUM_RUNS_PER_VARIANT,
    DRY_RUN,
    MODEL_NAME,
    LLM_PROVIDER,
    GEMINI_API_KEY,
    OPENAI_API_KEY,
    MODELS_BY_ID,
    resolve_model_specs,
)
from evaluation.runner import run_clean_baseline, run_attack_experiment, compute_clean_baselines
from evaluation.metrics import generate_summary_table, generate_detailed_report, save_tables
from evaluation.logger import clear_log, load_log
from dotenv import load_dotenv
load_dotenv()


def main():
    parser = argparse.ArgumentParser(
        description="Agent Security Research Framework — Experiment Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--attack",
        type=str,
        help="Attack family to evaluate: a single family, 'all', or a "
             "comma-separated list (e.g. 'obfuscated_injection,tool_invocation'). "
             f"Valid families: {ATTACK_FAMILIES}.",
    )
    parser.add_argument(
        "--baseline",
        type=str,
        choices=BASELINES + ["all"],
        help="Baseline to use (or 'all').",
    )
    parser.add_argument(
        "--num-runs",
        type=int,
        default=NUM_RUNS_PER_VARIANT,
        help=f"Number of runs per variant per baseline (default: {NUM_RUNS_PER_VARIANT}).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="default",
        help="Model to evaluate: 'default', 'all' (the MODELS comparison set), "
             f"or an id from config.MODELS ({list(MODELS_BY_ID)}).",
    )
    parser.add_argument(
        "--agent",
        type=str,
        choices=AGENTS,
        default="single",
        help="Agent architecture: 'single' (Phase 1 single-prompt, default) or "
             "'react' (Phase 2 autonomous Thought/Action/Observation agent with "
             "real tool execution).",
    )
    parser.add_argument(
        "--clean-baseline",
        action="store_true",
        help="Run clean CVs to establish baseline metrics.",
    )
    parser.add_argument(
        "--generate-tables",
        action="store_true",
        help="Generate summary tables from existing logs.",
    )
    parser.add_argument(
        "--clear-logs",
        action="store_true",
        help="Clear all experiment logs (use with caution).",
    )

    args = parser.parse_args()

    # Print configuration
    print(f"\n{'='*60}")
    print(f"  Agent Security Research Framework")
    print(f"  Agent: {args.agent} | Provider: {LLM_PROVIDER} | Model: {MODEL_NAME}")
    print(f"  Dry Run: {DRY_RUN}")
    print(f"{'='*60}\n")

    # Loud, impossible-to-miss warnings about misconfiguration that would
    # silently invalidate results.
    if DRY_RUN:
        print("  " + "!" * 56)
        print("  !!  DRY_RUN IS ON — responses are MOCKED, not from an LLM.  !!")
        print("  !!  Results will be MEANINGLESS. Set DRY_RUN=false in .env. !!")
        print("  " + "!" * 56 + "\n")
    else:
        key = GEMINI_API_KEY if LLM_PROVIDER == "gemini" else OPENAI_API_KEY
        if not key:
            print(f"  [WARN] No API key set for provider '{LLM_PROVIDER}'. "
                  f"Calls will fail.\n")
        elif LLM_PROVIDER == "gemini" and not key.startswith("AIza"):
            print("  [WARN] GEMINI_API_KEY does not look like an AI Studio key "
                  "(expected 'AIza...').")
            print("         If calls fail with auth/quota errors, verify the key "
                  "at https://aistudio.google.com/apikey\n")

    # Handle --clear-logs
    if args.clear_logs:
        confirm = input("Clear all experiment logs? This cannot be undone. [y/N]: ")
        if confirm.lower() == "y":
            clear_log()
            print("Logs cleared.")
        else:
            print("Cancelled.")
        return

    # Handle --generate-tables
    if args.generate_tables:
        print("Generating summary tables...\n")
        saved = save_tables()
        print(f"\nFiles written:")
        for f in saved:
            print(f"  {f}")

        print("\n--- ASR Summary ---\n")
        print(generate_summary_table())

        print("\n--- Detailed Report ---\n")
        print(generate_detailed_report())
        return

    # Resolve which model(s) to run
    try:
        model_specs = resolve_model_specs(args.model)
    except ValueError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
    print(f"Models: {[m['id'] for m in model_specs]}\n")

    # Handle --clean-baseline
    if args.clean_baseline:
        baselines = BASELINES if args.baseline == "all" else [args.baseline] if args.baseline else ["A"]
        total = 0
        for spec in model_specs:
            print(f"\n{'#'*60}\n  Clean baseline | Agent: {args.agent} | "
                  f"Model: {spec['id']}\n{'#'*60}")
            results = run_clean_baseline(baselines=baselines,
                                         num_runs=args.num_runs, model_spec=spec,
                                         agent=args.agent)
            total += len(results)
        print(f"\nCompleted {total} clean CV evaluations across "
              f"{len(model_specs)} model(s).")
        return

    # Handle --attack
    if args.attack:
        if not args.baseline:
            print("[ERROR] --baseline is required when running attacks.")
            parser.print_help()
            sys.exit(1)

        baselines = BASELINES if args.baseline == "all" else [args.baseline]

        # --attack accepts a single family, 'all', or a comma-separated subset
        # (the Phase 2 "surgical strike" targets a few families at once).
        requested = [a.strip() for a in args.attack.split(",") if a.strip()]
        if "all" in requested:
            attacks = ATTACK_FAMILIES
        else:
            unknown = [a for a in requested if a not in ATTACK_FAMILIES]
            if unknown:
                print(f"[ERROR] Unknown attack family/families: {unknown}")
                print(f"  Valid: {ATTACK_FAMILIES + ['all']}")
                sys.exit(1)
            attacks = requested

        for spec in model_specs:
            print(f"\n{'#'*60}\n  MODEL: {spec['id']} ({spec['provider']})\n{'#'*60}")

            # Per-model clean baselines for DoS comparison
            clean_baselines = compute_clean_baselines(model_id=spec["id"])

            for attack in attacks:
                print(f"\n  Running: {attack} on {spec['id']} (agent={args.agent})")
                run_attack_experiment(
                    attack_family=attack,
                    baselines=baselines,
                    num_runs=args.num_runs,
                    clean_median_latency=clean_baselines["median_latency"],
                    clean_median_tokens=clean_baselines["median_tokens"],
                    model_spec=spec,
                    agent=args.agent,
                )

        # Generate tables after all attacks
        print("\n\nGenerating summary tables...\n")
        saved = save_tables()
        print(f"Files written:")
        for f in saved:
            print(f"  {f}")

        print("\n--- ASR Summary ---\n")
        print(generate_summary_table())
        return

    # No action specified
    parser.print_help()


if __name__ == "__main__":
    main()
