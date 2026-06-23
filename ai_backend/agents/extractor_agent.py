from __future__ import annotations

from pathlib import Path

from ai_backend.config import Settings
from ai_backend.connectors.log_loader import load_local_logs
from ai_backend.connectors.ssh_log_collector import collect_logs_over_ssh
from ai_backend.llm_utils import ask_phi3, build_prompt
from ai_backend.models import NormalizedEvent, SOCState

MAX_LLM_AMBIGUOUS_LINES = 3
AMBIGUOUS_FILE_CANDIDATES = {"fast.log", "apache_access.log", "apache_error.log"}


def _assist_ambiguous_lines(raw: list[dict[str, str]], settings: Settings) -> list[NormalizedEvent]:
    if not getattr(settings, "use_llm_in_extractor", False):
        return []
    notes: list[NormalizedEvent] = []
    for item in raw:
        recognized = item.get("recognized")
        source_file = item.get("source_file", "unknown")
        if recognized not in {"false", "error"}:
            continue
        if recognized == "false" and Path(source_file).name not in AMBIGUOUS_FILE_CANDIDATES:
            continue
        try:
            prompt = build_prompt("extractor_prompt.txt", {
                "source_file": source_file,
                "line": item.get("line", ""),
            })
        except (OSError, ValueError):
            continue
        note = ask_phi3(prompt, settings, "")
        if note:
            notes.append(NormalizedEvent(
                source_type="llm_assisted_log",
                source_file=source_file,
                event_type="ambiguous_log_note",
                severity="Low",
                message=f"Note Phi-3 non décisionnelle : {note}",
                raw_event=item.get("line", ""),
            ))
        if len(notes) >= MAX_LLM_AMBIGUOUS_LINES:
            break
    return notes


def run_extractor(state: SOCState, settings: Settings) -> dict:
    errors = list(state.get("errors", []))
    if settings.log_mode == "ssh":
        _, ssh_errors = collect_logs_over_ssh(settings)
        errors.extend(ssh_errors)
    limit = state["run_metadata"].limit
    raw, normalized, parser_errors = load_local_logs(settings, limit)
    normalized.extend(_assist_ambiguous_lines(raw, settings))
    errors.extend(parser_errors)
    return {"raw_events": raw, "normalized_events": normalized, "errors": errors}
