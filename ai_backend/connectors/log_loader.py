from __future__ import annotations

from pathlib import Path
from typing import Callable

from ai_backend.config import Settings
from ai_backend.connectors.apache_connector import parse_access_line, parse_error_line
from ai_backend.connectors.linux_auth_connector import parse_auth_line
from ai_backend.connectors.siem_connector import collect_siem_alerts
from ai_backend.connectors.suricata_connector import read_suricata
from ai_backend.connectors.syslog_connector import parse_syslog_line
from ai_backend.models import NormalizedEvent


def _read_text_log(path: Path, parser: Callable[[str, str], NormalizedEvent | None], limit: int | None) -> tuple[list[dict[str, str]], list[NormalizedEvent], list[str]]:
    if not path.exists():
        return [], [], [f"Journal absent: {path}"]
    raw, events, errors = [], [], []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            if limit is not None and len(raw) >= limit:
                break
            if not line.strip():
                continue
            raw_item = {"source_file": str(path), "line": line.rstrip(), "recognized": "false"}
            raw.append(raw_item)
            try:
                event = parser(line, str(path))
                if event:
                    events.append(event)
                    raw_item["recognized"] = "true"
            except (ValueError, TypeError) as exc:
                raw_item["recognized"] = "error"
                errors.append(f"{path.name}:{line_number}: {exc}")
    return raw, events, errors


def load_local_logs(settings: Settings, limit: int | None = None) -> tuple[list[dict[str, str]], list[NormalizedEvent], list[str]]:
    specs = [
        (settings.soc_logs_dir / "eve.json", None, True),
        (settings.soc_logs_dir / "fast.log", None, False),
        (settings.victim_logs_dir / "apache_access.log", parse_access_line, None),
        (settings.victim_logs_dir / "apache_error.log", parse_error_line, None),
        (settings.victim_logs_dir / "auth.log", parse_auth_line, None),
        (settings.victim_logs_dir / "syslog", parse_syslog_line, None),
    ]
    all_raw: list[dict[str, str]] = []
    all_events: list[NormalizedEvent] = []
    errors: list[str] = []
    remaining = limit
    for path, parser, eve in specs:
        if remaining is not None and remaining <= 0:
            break
        result = read_suricata(path, bool(eve), remaining) if parser is None else _read_text_log(path, parser, remaining)
        raw, events, current_errors = result
        all_raw.extend(raw)
        all_events.extend(events)
        errors.extend(current_errors)
        if remaining is not None:
            remaining -= len(raw)
    if remaining is None or remaining > 0:
        raw, events, current_errors = collect_siem_alerts(settings, remaining)
        all_raw.extend(raw)
        all_events.extend(events)
        errors.extend(current_errors)
    return all_raw, all_events, errors
