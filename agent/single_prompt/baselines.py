"""
Baselines — Three experimental defense configurations.

Baseline A: No Protection (raw CV → LLM)
Baseline B: Simple Guardrails (regex pattern detection → reject or flag)
Baseline C: Semantic Isolation (LLM security filter → HR agent)
"""

import re
from config import GUARDRAIL_PATTERNS, GUARDRAIL_MODE, PROMPTS_DIR


def apply_baseline_a(cv_content: str) -> dict:
    """
    Baseline A — No Protection.

    Pass the CV content through without any modification or filtering.

    Returns:
        dict with:
            - content: str (unmodified CV)
            - blocked: False
            - flags: []
    """
    return {
        "content": cv_content,
        "blocked": False,
        "flags": [],
    }


def apply_baseline_b(cv_content: str) -> dict:
    """
    Baseline B — Simple Guardrails.

    Scan CV content against known attack patterns using regex.
    If any pattern matches and mode is 'reject', block processing.
    If mode is 'flag', allow processing but record warnings.

    Returns:
        dict with:
            - content: str (original CV if not blocked, empty if blocked)
            - blocked: bool
            - flags: list[str] (matched pattern descriptions)
    """
    flags = []

    for pattern in GUARDRAIL_PATTERNS:
        matches = re.findall(pattern, cv_content, re.IGNORECASE)
        if matches:
            flags.append(f"Pattern matched: '{pattern}'")

    if flags and GUARDRAIL_MODE == "reject":
        return {
            "content": "",
            "blocked": True,
            "flags": flags,
        }

    return {
        "content": cv_content,
        "blocked": False,
        "flags": flags,
    }


def apply_baseline_c(cv_content: str, call_llm_fn) -> dict:
    """
    Baseline C — Semantic Isolation.

    Two-stage pipeline:
    1. Security Filter: Ask an LLM if the CV contains manipulation attempts.
    2. If SAFE → pass to HR Agent. If SUSPICIOUS → block.

    Args:
        cv_content: The raw CV text.
        call_llm_fn: The LLM calling function (injected to avoid circular imports).

    Returns:
        dict with:
            - content: str (original CV if safe, empty if blocked)
            - blocked: bool
            - flags: list[str]
            - filter_response: str (raw LLM filter response)
    """
    filter_prompt = _build_security_filter_prompt(cv_content)
    filter_response = call_llm_fn(filter_prompt)

    # Parse the filter response — look for SAFE or SUSPICIOUS
    response_upper = filter_response.upper().strip()

    if "SUSPICIOUS" in response_upper:
        return {
            "content": "",
            "blocked": True,
            "flags": ["Semantic filter: SUSPICIOUS"],
            "filter_response": filter_response,
        }

    # Default to SAFE if the filter doesn't clearly say SUSPICIOUS
    return {
        "content": cv_content,
        "blocked": False,
        "flags": [],
        "filter_response": filter_response,
    }


_security_filter_template_cache = None


def _build_security_filter_prompt(cv_content: str) -> str:
    """
    Build the prompt for the Baseline C security filter.

    The template lives in prompts/defenses/security_filter.txt (with a
    {cv_content} placeholder) so the defense can be edited without touching code.
    """
    global _security_filter_template_cache
    if _security_filter_template_cache is None:
        template_path = PROMPTS_DIR / "defenses" / "security_filter.txt"
        _security_filter_template_cache = template_path.read_text(encoding="utf-8")
    return _security_filter_template_cache.replace("{cv_content}", cv_content)


# ─── Dispatcher ─────────────────────────────────────────────────────────────────

def apply_baseline(baseline: str, cv_content: str, call_llm_fn=None) -> dict:
    """
    Apply the specified baseline defense to CV content.

    Args:
        baseline: One of "A", "B", "C"
        cv_content: Raw CV text
        call_llm_fn: LLM calling function (required for Baseline C)

    Returns:
        Baseline result dict with 'content', 'blocked', and 'flags' keys.
    """
    if baseline == "A":
        return apply_baseline_a(cv_content)
    elif baseline == "B":
        return apply_baseline_b(cv_content)
    elif baseline == "C":
        if call_llm_fn is None:
            raise ValueError("Baseline C requires a call_llm_fn argument.")
        return apply_baseline_c(cv_content, call_llm_fn)
    else:
        raise ValueError(f"Unknown baseline: {baseline}. Must be A, B, or C.")
