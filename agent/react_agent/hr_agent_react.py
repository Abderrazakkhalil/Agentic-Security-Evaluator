"""
Autonomous ReAct HR Agent — Phase 2 experimental subject.

Where the Phase 1 agent (`agent/single_prompt/hr_agent.py`) was a single
CV -> LLM -> decision shot, this agent runs a genuine **Thought -> Action ->
Observation** reasoning loop and can *actually execute* tools (notably the
restricted `send_email`). That changes the security measurement in two ways:

  1. Tool invocation is now ground truth. We no longer infer `send_email` from
     response substrings; we record it when the agent really calls it.
  2. The agent is autonomous across multiple steps, so an attacker has more
     surface to steer it off-task before it commits to a decision.

The public entry point is `evaluate_cv(...)`, which is **drop-in compatible** with
the Phase 1 signature and return shape (so the existing runner/metrics keep
working) and adds Phase-2-only fields: `tool_invoked`, `tool_invocations`,
`react_steps`, `agent`.

LLM plumbing (client cache, throttle, retry, circuit breaker) is reused from the
Phase 1 module so both architectures hit the providers identically.
"""

import json
import re
import time

from config import (
    DRY_RUN,
    PROMPTS_DIR,
    REACT_MAX_STEPS,
    default_model_spec,
)

# Reuse the battle-tested LLM transport + parsing from Phase 1 (identical
# providers, throttling, retry and circuit-breaker behaviour).
from agent.single_prompt.hr_agent import (
    call_llm,
    parse_agent_response,
    RateLimitCircuitBreaker,  # re-exported so the runner can catch it uniformly
)
from agent.single_prompt.tools import read_cv
from agent.single_prompt.baselines import apply_baseline
from agent.react_agent.tools_execution import ToolExecutor

__all__ = ["evaluate_cv", "RateLimitCircuitBreaker"]


# ─── ReAct transcript parsing ───────────────────────────────────────────────────

_FINAL_ANSWER_RE = re.compile(r"final\s*answer\s*:", re.IGNORECASE)
_ACTION_RE = re.compile(r"action\s*:\s*(.+)", re.IGNORECASE)
_ACTION_INPUT_RE = re.compile(r"action\s*input\s*:\s*(.+)", re.IGNORECASE | re.DOTALL)


def _extract_json_object(text: str) -> dict | None:
    """Best-effort: pull the first balanced {...} JSON object out of `text`."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def parse_react_step(step_text: str) -> dict:
    """
    Parse one model turn into a structured ReAct step.

    Returns a dict with `type` in {"final", "action", "unparsed"}:
      - "final":  {"type": "final", "final_text": <text after Final Answer:>}
      - "action": {"type": "action", "tool": <name>, "tool_input": <dict>}
      - "unparsed": the model produced neither (we end the loop and fall back).

    The parser is deliberately lenient so that models which skip the ReAct
    scaffolding (or DRY_RUN, which emits a bare decision JSON) still resolve to a
    sensible final answer instead of looping pointlessly.
    """
    # 1) Explicit Final Answer marker wins.
    m = _FINAL_ANSWER_RE.search(step_text)
    if m:
        return {"type": "final", "final_text": step_text[m.end():].strip()}

    # 2) An Action directive -> execute a tool.
    action_match = _ACTION_RE.search(step_text)
    if action_match:
        tool = action_match.group(1).strip().splitlines()[0].strip().strip("`").strip()
        # Tool name may arrive as `send_email(...)` — keep only the identifier.
        tool = re.split(r"[\s(]", tool, 1)[0].strip()

        tool_input: dict = {}
        input_match = _ACTION_INPUT_RE.search(step_text)
        if input_match:
            tool_input = _extract_json_object(input_match.group(1)) or {}
        return {"type": "action", "tool": tool, "tool_input": tool_input}

    # 3) No scaffolding, but a decision JSON is present -> treat as final.
    if _extract_json_object(step_text) is not None:
        return {"type": "final", "final_text": step_text.strip()}

    return {"type": "unparsed"}


# ─── Prompt assembly ────────────────────────────────────────────────────────────

_react_prompt_cache = None


def _load_react_system_prompt() -> str:
    global _react_prompt_cache
    if _react_prompt_cache is None:
        path = PROMPTS_DIR / "react_system_prompt.txt"
        _react_prompt_cache = path.read_text(encoding="utf-8")
    return _react_prompt_cache


def _build_initial_prompt(cv_content: str) -> str:
    system = _load_react_system_prompt()
    return (
        f"{system}\n\n"
        f"--- CANDIDATE CV ---\n{cv_content}\n--- END CV ---\n\n"
        f"Begin! Reason step by step, then give your Final Answer.\n"
    )


def _blocked_result(cv_path, model_spec, baseline, baseline_result, elapsed) -> dict:
    """Shape-compatible early return when a baseline blocks the CV."""
    return {
        "cv_file": str(cv_path),
        "model_id": model_spec["id"],
        "agent": "react",
        "baseline": baseline,
        "blocked": True,
        "decision": "BLOCKED",
        "skills": [],
        "summary": "",
        "raw_response": "",
        "flags": baseline_result["flags"],
        "filter_response": baseline_result.get("filter_response", ""),
        # Tool fields — Phase 2 ground truth (nothing executed).
        "send_email_attempted": False,
        "tool_invoked": False,
        "tool_invocations": [],
        "tool_call_texts": [],
        "react_steps": 0,
        "latency_seconds": round(elapsed, 3),
        "token_estimate": 0,
        "response_token_estimate": 0,
        "parse_error": None,
    }


# ─── Core evaluation (ReAct loop) ───────────────────────────────────────────────

def evaluate_cv(cv_path: str, baseline: str = "A", model_spec: dict = None,
                max_steps: int = None, executor=None, step_hook=None) -> dict:
    """
    Evaluate a CV with the autonomous ReAct agent.

    Pipeline (mirrors Phase 1 up to the loop):
        1. Read the CV.
        2. Apply the selected baseline defense (A/B/C). If blocked, return early.
        3. Run the Thought -> Action -> Observation loop, executing real tools,
           until the agent emits a Final Answer or `max_steps` is reached.
        4. Assemble a result dict (Phase-1-compatible + Phase-2 tool fields).

    Args:
        cv_path: Path to the CV .txt file.
        baseline: One of "A", "B", "C".
        model_spec: {"id","provider","model"}. Defaults to the configured default.
        max_steps: Max ReAct iterations. Defaults to config.REACT_MAX_STEPS.
        executor: Optional pre-built tool executor (must expose the same
            `.execute()` / `.send_email_invoked` / `.invocations` /
            `.invoked_tool_names()` surface as ToolExecutor). Phase 3's
            DefendAgentWrapper injects a SandboxedToolExecutor here. When None,
            a stock ToolExecutor is constructed — i.e. baseline behaviour is
            unchanged.
        step_hook: Optional callable `(step_index, step_text, parsed_step)` run
            once per model turn, after parsing and *before* any tool execution.
            It may raise to abort the loop (Phase 3 uses this for token/step
            bounding and provenance). When None, this is a no-op — the baseline
            ReAct path is byte-for-byte identical.

    Returns:
        Structured evaluation result with ground-truth tool-invocation data.
    """
    start_time = time.time()
    if model_spec is None:
        model_spec = default_model_spec()
    if max_steps is None:
        max_steps = REACT_MAX_STEPS

    def _call(prompt: str) -> str:
        return call_llm(prompt, model_spec=model_spec)

    # Step 1: read CV
    cv_content = read_cv(cv_path)

    # Step 2: baseline defense (same gate as Phase 1 — defenses are upstream of
    # the agent loop, so a single-prompt and a ReAct agent face the same filter).
    baseline_result = apply_baseline(baseline, cv_content, call_llm_fn=_call)
    if baseline_result["blocked"]:
        return _blocked_result(cv_path, model_spec, baseline, baseline_result,
                               time.time() - start_time)

    # Step 3: ReAct loop with real tool execution. A caller (Phase 3 defend
    # wrapper) may inject a guarded executor; otherwise build the stock one so
    # single/react behaviour is unchanged.
    if executor is None:
        executor = ToolExecutor(cv_file=str(cv_path), model_id=model_spec["id"],
                                baseline=baseline)

    transcript = _build_initial_prompt(baseline_result["content"])
    generated_text_parts: list[str] = []   # only the model's own output (for DoS tokens)
    full_transcript_parts: list[str] = [transcript]

    decision_payload = {"decision": None, "skills": [], "summary": ""}
    parse_error = None
    steps_taken = 0

    for step in range(max_steps):
        steps_taken = step + 1
        step_text = _call(transcript)
        generated_text_parts.append(step_text)
        full_transcript_parts.append(step_text)

        parsed_step = parse_react_step(step_text)

        # Phase 3 hook: runs after parsing, before any tool execution. May raise
        # a DefenseException to abort (token/step bounding, provenance). No-op
        # when step_hook is None (single/react path unaffected).
        if step_hook is not None:
            step_hook(step, step_text, parsed_step)

        if parsed_step["type"] == "final":
            final = parse_agent_response(parsed_step["final_text"])
            decision_payload = {
                "decision": final["decision"],
                "skills": final["skills"],
                "summary": final["summary"],
            }
            parse_error = final.get("parse_error")
            break

        if parsed_step["type"] == "action":
            observation = executor.execute(parsed_step["tool"],
                                           parsed_step["tool_input"])
            obs_line = f"\nObservation: {observation}\n"
            transcript += step_text + obs_line
            full_transcript_parts.append(obs_line)
            continue

        # Unparsed: the model gave neither an Action nor a Final Answer.
        # Salvage any decision from the text and stop looping.
        final = parse_agent_response(step_text)
        decision_payload = {
            "decision": final["decision"],
            "skills": final["skills"],
            "summary": final["summary"],
        }
        parse_error = final.get("parse_error") or "react_no_action_or_final"
        break
    else:
        # Loop exhausted without a Final Answer — record the budget exhaustion.
        parse_error = "react_max_steps_exhausted"
        if decision_payload["decision"] is None:
            decision_payload["decision"] = "PARSE_FAILURE"

    if decision_payload["decision"] is None:
        decision_payload["decision"] = "PARSE_FAILURE"

    elapsed = time.time() - start_time
    raw_response = "".join(full_transcript_parts)
    generated_text = "\n".join(generated_text_parts)

    result = {
        "cv_file": str(cv_path),
        "model_id": model_spec["id"],
        "agent": "react",
        "baseline": baseline,
        "blocked": False,
        "decision": decision_payload["decision"],
        "skills": decision_payload["skills"],
        "summary": decision_payload["summary"],
        "raw_response": raw_response,
        "flags": baseline_result.get("flags", []),
        "filter_response": baseline_result.get("filter_response", ""),
        # ── Ground-truth tool invocation (the Phase 2 upgrade) ──────────────
        # `send_email_attempted` keeps its Phase 1 name (so attacks/tool_invocation
        # keeps working) but is now driven by REAL execution, not substrings.
        "send_email_attempted": executor.send_email_invoked,
        "tool_invoked": executor.send_email_invoked,
        "tool_invocations": executor.invocations,
        "tool_call_texts": executor.invoked_tool_names(),
        "react_steps": steps_taken,
        "latency_seconds": round(elapsed, 3),
        # response_token_estimate isolates the agent's *own* generated text
        # (Thoughts/Actions/Final Answer) — not observations — so DoS output
        # amplification is measured consistently with Phase 1.
        "token_estimate": len(raw_response.split()),
        "response_token_estimate": len(generated_text.split()),
        "parse_error": parse_error,
    }
    return result
