from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai_backend.models import NormalizedEvent

FAST_PATTERN = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<signature>.*?)\s+\[\*\*\].*?"
    r"(?:\[Priority:\s*(?P<priority>\d+)\]\s+)?"
    r"\{(?P<protocol>[^}]+)\}\s+(?P<src_ip>[^: ]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dest_ip>[^: ]+):(?P<dest_port>\d+)"
)


def _severity(priority: Any) -> str:
    try:
        return {1: "Critical", 2: "High", 3: "Medium"}.get(int(priority), "Low")
    except (TypeError, ValueError):
        return "Medium"


def parse_eve_line(line: str, source_file: str = "eve.json") -> NormalizedEvent | None:
    data = json.loads(line)
    if data.get("event_type") != "alert":
        return None
    alert = data.get("alert", {})
    return NormalizedEvent(
        timestamp=data.get("timestamp") or datetime.now(timezone.utc),
        source_type="suricata_eve", source_file=source_file, event_type="alert",
        src_ip=data.get("src_ip"), src_port=data.get("src_port"),
        dest_ip=data.get("dest_ip"), dest_port=data.get("dest_port"),
        protocol=data.get("proto"), host=data.get("host"),
        signature=alert.get("signature"), severity=_severity(alert.get("severity")),
        message=alert.get("signature") or "Alerte Suricata", raw_event=data,
    )


def parse_fast_line(line: str, source_file: str = "fast.log") -> NormalizedEvent | None:
    match = FAST_PATTERN.search(line.strip())
    if not match:
        return None
    item = match.groupdict()
    timestamp = datetime.strptime(item["timestamp"], "%m/%d/%Y-%H:%M:%S.%f").replace(tzinfo=timezone.utc)
    signature = item["signature"].strip()
    return NormalizedEvent(
        timestamp=timestamp, source_type="suricata_fast", source_file=source_file,
        event_type="alert", src_ip=item["src_ip"], src_port=int(item["src_port"]),
        dest_ip=item["dest_ip"], dest_port=int(item["dest_port"]),
        protocol=item["protocol"], signature=signature,
        severity=_severity(item.get("priority")), message=signature, raw_event=line.strip(),
    )


def read_suricata(path: Path, eve: bool, limit: int | None = None) -> tuple[list[dict[str, Any]], list[NormalizedEvent], list[str]]:
    raw: list[dict[str, Any]] = []
    events: list[NormalizedEvent] = []
    errors: list[str] = []
    if not path.exists():
        return raw, events, [f"Journal absent: {path}"]
    parser = parse_eve_line if eve else parse_fast_line
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            if limit is not None and len(raw) >= limit:
                break
            if not line.strip():
                continue
            raw.append({"source_file": str(path), "line": line.rstrip()})
            try:
                event = parser(line, str(path))
                if event:
                    events.append(event)
            except (ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{path.name}:{line_number}: {exc}")
    return raw, events, errors
