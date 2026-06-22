from __future__ import annotations

import re
from datetime import datetime, timezone

from ai_backend.models import NormalizedEvent

ACCESS_PATTERN = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<protocol>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)
ERROR_PATTERN = re.compile(
    r"^\[(?P<timestamp>[^]]+)\]\s+\[(?P<module>[^]]+)\]\s+"
    r"(?:\[pid\s+\d+(?::tid\s+\d+)?\]\s+)?(?:\[client\s+(?P<src_ip>[^]:]+)(?::\d+)?\]\s+)?(?P<message>.*)$"
)


def parse_access_line(line: str, source_file: str = "apache_access.log") -> NormalizedEvent | None:
    match = ACCESS_PATTERN.search(line.strip())
    if not match:
        return None
    item = match.groupdict()
    timestamp = datetime.strptime(item["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
    status, path = int(item["status"]), item["path"]
    suspicious = any(token in path.lower() for token in ("wp-admin", ".env", "../", "phpmyadmin", "cgi-bin", "nikto"))
    severity = "Medium" if suspicious or status in {401, 403} else "Low"
    return NormalizedEvent(
        timestamp=timestamp, source_type="apache_access", source_file=source_file,
        event_type="http_request", src_ip=item["src_ip"], dest_port=80,
        protocol=item.get("protocol") or "HTTP", user=None if item["user"] == "-" else item["user"],
        signature="Web reconnaissance" if suspicious else "HTTP access",
        severity=severity, message=f'{item["method"]} {path} -> {status}', raw_event=line.strip(),
    )


def parse_error_line(line: str, source_file: str = "apache_error.log") -> NormalizedEvent | None:
    match = ERROR_PATTERN.search(line.strip())
    if not match:
        return None
    item = match.groupdict()
    timestamp_text = item["timestamp"]
    try:
        timestamp = datetime.strptime(timestamp_text, "%a %b %d %H:%M:%S.%f %Y").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            timestamp = datetime.strptime(timestamp_text, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
    return NormalizedEvent(
        timestamp=timestamp, source_type="apache_error", source_file=source_file,
        event_type="http_error", src_ip=item.get("src_ip"), dest_port=80,
        protocol="HTTP", signature=item.get("module"), severity="Medium",
        message=item["message"], raw_event=line.strip(),
    )
