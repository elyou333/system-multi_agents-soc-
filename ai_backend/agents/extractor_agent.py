from __future__ import annotations

from ai_backend.config import Settings
from ai_backend.connectors.log_loader import load_local_logs
from ai_backend.connectors.ssh_log_collector import collect_logs_over_ssh
from ai_backend.models import SOCState


def run_extractor(state: SOCState, settings: Settings) -> dict:
    errors = list(state.get("errors", []))
    if settings.log_mode == "ssh":
        _, ssh_errors = collect_logs_over_ssh(settings)
        errors.extend(ssh_errors)
    limit = state["run_metadata"].limit
    raw, normalized, parser_errors = load_local_logs(settings, limit)
    errors.extend(parser_errors)
    return {"raw_events": raw, "normalized_events": normalized, "errors": errors}
