"""
verify_obfuscation.py — Prove Baseline B's structural failure (offline, no API).

Runs every obfuscated_NN.txt payload through Baseline B (regex guardrails) and
reports how many are blocked. The adaptive corpus is engineered so that NONE of
the payloads match `config.GUARDRAIL_PATTERNS`, even though each retains malicious
intent (forced ACCEPT or unauthorized send_email). A 0% block rate here is the
empirical demonstration that exact-match regex defenses do not generalize to
paraphrased / obfuscated / fragmented attacks.

Usage:
    python scripts/verify_obfuscation.py
Exits non-zero if any payload is unexpectedly blocked (i.e. the obfuscation
leaked a literal trigger and needs fixing).
"""

import sys
from pathlib import Path

# Allow running as `python scripts/verify_obfuscation.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import ATTACK_CV_DIR
from agent.single_prompt.baselines import apply_baseline_b


def main() -> int:
    payloads = sorted(ATTACK_CV_DIR.glob("obfuscated_*.txt"))
    if not payloads:
        print("[ERROR] No obfuscated_*.txt payloads found in", ATTACK_CV_DIR)
        return 1

    blocked = 0
    print(f"\nBaseline B (regex guardrails) vs. {len(payloads)} obfuscated payloads")
    print("=" * 64)

    for path in payloads:
        content = path.read_text(encoding="utf-8")
        result = apply_baseline_b(content)
        is_blocked = result["blocked"]
        blocked += int(is_blocked)
        status = "BLOCKED" if is_blocked else "PASSED THROUGH"
        flags = f"  flags={result['flags']}" if result["flags"] else ""
        print(f"  {path.name:24s} -> {status}{flags}")

    rate = 100.0 * blocked / len(payloads)
    print("=" * 64)
    print(f"  Block rate: {blocked}/{len(payloads)} = {rate:.1f}%")
    print(f"  Bypass rate: {len(payloads) - blocked}/{len(payloads)} = "
          f"{100.0 - rate:.1f}%")
    print("=" * 64)

    if blocked == 0:
        print("\n[OK] Every obfuscated payload bypassed Baseline B's regex — "
              "structural failure demonstrated.\n")
        return 0
    print(f"\n[WARN] {blocked} payload(s) matched a guardrail pattern. "
          "Re-obfuscate those to keep the corpus regex-clean.\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
