from __future__ import annotations

import re
from datetime import datetime, timezone

from ai_backend.models import NormalizedEvent

SYSLOG_PREFIX = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>[^:]+):\s*(?P<message>.*)$")
FAILED_SSH = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[0-9a-fA-F:.]+) port (?P<src_port>\d+)", re.I)


def parse_syslog_timestamp(item: dict[str, str]) -> datetime:
    return datetime.strptime(f'{datetime.now().year} {item["month"]} {item["day"]} {item["time"]}', "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)


def parse_auth_line(line: str, source_file: str = "auth.log") -> NormalizedEvent | None:
    prefix = SYSLOG_PREFIX.search(line.strip())
    if not prefix:
        return None
    item, message = prefix.groupdict(), prefix.group("message")
    failed = FAILED_SSH.search(message)
    if failed:
        ssh = failed.groupdict()
        return NormalizedEvent(
            timestamp=parse_syslog_timestamp(item), source_type="linux_auth", source_file=source_file,
            event_type="ssh_failed_login", src_ip=ssh["src_ip"], src_port=int(ssh["src_port"]),
            dest_port=22, protocol="SSH", host=item["host"], user=ssh["user"],
            signature="Failed SSH login", severity="Medium", message=message, raw_event=line.strip(),
        )
    lowered = message.lower()
    if any(token in lowered for token in ("authentication failure", "incorrect password", "not in sudoers")):
        user_match = re.search(r"(?:user|ruser|USER)=(?P<user>[^ ;]+)", message)
        return NormalizedEvent(
            timestamp=parse_syslog_timestamp(item), source_type="linux_auth", source_file=source_file,
            event_type="authentication_failure", host=item["host"],
            user=user_match.group("user") if user_match else None,
            signature="Authentication failure", severity="Medium", message=message, raw_event=line.strip(),
        )
    return None
