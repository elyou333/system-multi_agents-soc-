from __future__ import annotations

import json
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib import parse, request

from ai_backend.config import Settings
from ai_backend.models import NormalizedEvent


def _nested(item: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        current: Any = item
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, ""):
            return current
    return None


def _severity(value: Any) -> str:
    if isinstance(value, str) and not value.isdigit():
        return {
            "informational": "Low", "info": "Low", "low": "Low",
            "medium": "Medium", "moderate": "Medium",
            "high": "High", "critical": "Critical", "severe": "Critical",
        }.get(value.lower(), "Medium")
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "Medium"
    if score <= 4:
        return {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}.get(int(score), "Medium")
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def parse_siem_record(record: dict[str, Any], provider: str, source_file: str) -> NormalizedEvent:
    data = record.get("_source") or record.get("result") or record
    timestamp = _nested(data, "@timestamp", "timestamp", "_time") or datetime.now(timezone.utc)
    title = _nested(data, "kibana.alert.rule.name", "rule.name", "alert.signature", "signature", "search_name")
    message = _nested(data, "message", "event.original", "description") or title or "Alerte SIEM"
    event_type = _nested(data, "event.kind", "event.type", "alert_type") or "siem_alert"
    if isinstance(event_type, list):
        event_type = ",".join(str(item) for item in event_type)
    return NormalizedEvent(
        timestamp=timestamp,
        source_type=f"siem_{provider}",
        source_file=source_file,
        event_type=str(event_type),
        src_ip=_nested(data, "source.ip", "src_ip", "src"),
        src_port=_nested(data, "source.port", "src_port"),
        dest_ip=_nested(data, "destination.ip", "dest_ip", "dest"),
        dest_port=_nested(data, "destination.port", "dest_port"),
        protocol=_nested(data, "network.transport", "network.protocol", "protocol"),
        host=_nested(data, "host.name", "host", "device_name"),
        user=_nested(data, "user.name", "user"),
        signature=str(title or "Alerte SIEM"),
        severity=_severity(_nested(data, "kibana.alert.severity", "event.severity", "risk_score", "severity")),
        message=str(message),
        raw_event=record,
    )


def _decode_records(text: str) -> Iterable[dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        value = json.loads(stripped)
        return value if isinstance(value, list) else [value]
    return [json.loads(line) for line in stripped.splitlines() if line.strip()]


def read_siem_export(path: Path, provider: str, limit: int | None = None) -> tuple[list[dict[str, Any]], list[NormalizedEvent], list[str]]:
    if not path.exists():
        return [], [], []
    raw: list[dict[str, Any]] = []
    events: list[NormalizedEvent] = []
    errors: list[str] = []
    try:
        records = _decode_records(path.read_text(encoding="utf-8", errors="replace"))
        for index, record in enumerate(records, 1):
            if limit is not None and len(raw) >= limit:
                break
            if not isinstance(record, dict):
                errors.append(f"{path.name}:{index}: objet JSON attendu")
                continue
            raw.append({"source_file": str(path), "record": record})
            try:
                events.append(parse_siem_record(record, provider, str(path)))
            except (TypeError, ValueError) as exc:
                errors.append(f"{path.name}:{index}: {exc}")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"Export SIEM invalide {path.name}: {exc}")
    return raw, events, errors


def _open_json(req: request.Request, verify_ssl: bool, timeout: int) -> str:
    context = None if verify_ssl else ssl._create_unverified_context()
    with request.urlopen(req, timeout=timeout, context=context) as response:
        return response.read().decode("utf-8", errors="replace")


def _fetch_elastic(settings: Settings, limit: int | None) -> list[dict[str, Any]]:
    size = min(limit or 500, 10_000)
    url = f"{settings.elastic_url.rstrip('/')}/{parse.quote(settings.elastic_index, safe='*,-_')}/_search"
    body = json.dumps({"size": size, "sort": [{"@timestamp": "desc"}], "query": {"match_all": {}}}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if settings.elastic_api_key:
        headers["Authorization"] = f"ApiKey {settings.elastic_api_key}"
    payload = json.loads(_open_json(request.Request(url, data=body, headers=headers, method="POST"), settings.siem_verify_ssl, settings.ssh_timeout))
    return payload.get("hits", {}).get("hits", [])


def _fetch_splunk(settings: Settings, limit: int | None) -> list[dict[str, Any]]:
    url = f"{settings.splunk_url.rstrip('/')}/services/search/jobs/export"
    search = f"{settings.splunk_search} | head {min(limit or 500, 10_000)}"
    body = parse.urlencode({"search": search, "output_mode": "json", "earliest_time": "-24h"}).encode()
    headers = {"Authorization": f"Splunk {settings.splunk_token}", "Content-Type": "application/x-www-form-urlencoded"}
    text = _open_json(request.Request(url, data=body, headers=headers, method="POST"), settings.siem_verify_ssl, settings.ssh_timeout)
    return list(_decode_records(text))


def collect_siem_alerts(settings: Settings, limit: int | None = None) -> tuple[list[dict[str, Any]], list[NormalizedEvent], list[str]]:
    if not settings.siem_enabled:
        return [], [], []
    raw: list[dict[str, Any]] = []
    events: list[NormalizedEvent] = []
    errors: list[str] = []
    sources = [
        ("elastic", settings.siem_logs_dir / "elastic_alerts.jsonl", settings.elastic_url, _fetch_elastic),
        ("splunk", settings.siem_logs_dir / "splunk_alerts.jsonl", settings.splunk_url, _fetch_splunk),
    ]
    for provider, path, endpoint, fetcher in sources:
        remaining = None if limit is None else max(0, limit - len(raw))
        if remaining == 0:
            break
        if endpoint:
            try:
                records = fetcher(settings, remaining)
                for record in records:
                    raw.append({"source_file": endpoint, "record": record})
                    events.append(parse_siem_record(record, provider, endpoint))
                continue
            except Exception as exc:
                errors.append(f"{provider.title()} indisponible ({type(exc).__name__}); repli sur l'export local.")
        current_raw, current_events, current_errors = read_siem_export(path, provider, remaining)
        raw.extend(current_raw)
        events.extend(current_events)
        errors.extend(current_errors)
    return raw, events, errors
