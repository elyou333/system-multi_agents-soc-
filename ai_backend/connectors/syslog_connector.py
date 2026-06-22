from __future__ import annotations

from ai_backend.connectors.linux_auth_connector import SYSLOG_PREFIX, parse_syslog_timestamp
from ai_backend.models import NormalizedEvent

SUSPICIOUS_TERMS = ("segfault", "denied", "failed", "error", "oom-killer", "promiscuous", "invalid")


def parse_syslog_line(line: str, source_file: str = "syslog") -> NormalizedEvent | None:
    match = SYSLOG_PREFIX.search(line.strip())
    if not match:
        return None
    item = match.groupdict()
    if not any(term in item["message"].lower() for term in SUSPICIOUS_TERMS):
        return None
    return NormalizedEvent(
        timestamp=parse_syslog_timestamp(item), source_type="linux_syslog", source_file=source_file,
        event_type="suspicious_system_event", host=item["host"],
        signature=item["process"], severity="Medium", message=item["message"], raw_event=line.strip(),
    )
