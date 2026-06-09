"""
Logger — Structured JSON logging for experiment results.

Every experiment execution produces a log entry in JSONL format.
This ensures reproducibility and enables automated analysis.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from config import LOGS_DIR


# ─── Experiment Log ─────────────────────────────────────────────────────────────

EXPERIMENT_LOG_FILE = LOGS_DIR / "experiment_log.jsonl"

# All append-only artifacts produced during a run. Kept here so that clearing
# logs for a fresh, reproducible run removes every one of them — not just the
# primary experiment log that metrics are computed from.
ALL_LOG_FILES = [
    EXPERIMENT_LOG_FILE,
    LOGS_DIR / "evaluations.jsonl",
    LOGS_DIR / "tool_invocation_attempts.jsonl",
    # Phase 2 — ground-truth tool executions from the autonomous ReAct agent.
    LOGS_DIR / "react_tool_executions.jsonl",
]


def log_result(entry: dict) -> None:
    """
    Append a structured log entry to the experiment log.

    Args:
        entry: Dictionary containing experiment result fields.
            Required keys:
                - attack: str (attack family name)
                - variant: str (variant identifier, e.g. "injection_03")
                - baseline: str ("A", "B", or "C")
                - success: bool (whether the attack succeeded)
                - decision: str (agent's decision)
                - latency_seconds: float
            Optional keys:
                - expected_decision: str
                - token_estimate: int
                - tool_called: bool
                - error: str or None
                - run_index: int
                - flags: list[str]
                - raw_response: str
    """
    EXPERIMENT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **entry,
    }

    with open(EXPERIMENT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, default=str) + "\n")


def load_log(log_path: Path = None) -> list[dict]:
    """
    Load all log entries from a JSONL log file.

    Args:
        log_path: Path to the log file. Defaults to the experiment log.

    Returns:
        List of log entry dicts.
    """
    if log_path is None:
        log_path = EXPERIMENT_LOG_FILE

    if not log_path.exists():
        return []

    entries = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    return entries


def clear_log(log_path: Path = None) -> None:
    """
    Clear experiment logs.

    With no argument, removes every append-only artifact in ALL_LOG_FILES so a
    fresh run starts from a clean state (metrics aggregate over the whole log,
    so leftover entries from a previous run/model would corrupt results).
    Pass an explicit log_path to clear only that file.

    Use with caution — this deletes logged results.
    """
    targets = [log_path] if log_path is not None else ALL_LOG_FILES

    for target in targets:
        if target.exists():
            target.unlink()
