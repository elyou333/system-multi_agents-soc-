from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ai_backend.database.db import connect

DEFAULT_THRESHOLDS = {"ssh_brute_force": 5, "web_recon_high": 5, "port_scan": 5}
RULE_FOR_INCIDENT = {
    "SSH brute force suspicion": "ssh_brute_force",
    "Suspicious authentication activity": "ssh_brute_force",
    "Web reconnaissance": "web_recon_high",
    "Port scan suspicion": "port_scan",
}


def _bounded_threshold(default: int, total: int, false_positives: int) -> int:
    if total < 3:
        return default
    rate = false_positives / total
    adjustment = 2 if rate >= 0.6 else 1 if rate >= 0.4 else -1 if rate <= 0.1 else 0
    return max(3, min(10, default + adjustment))


def load_adaptive_profile(database_path: Path) -> dict[str, int]:
    profile = dict(DEFAULT_THRESHOLDS)
    with connect(database_path) as connection:
        rows = connection.execute(
            """SELECT incident_type, COUNT(*) AS total,
            SUM(CASE WHEN verdict='false_positive' THEN 1 ELSE 0 END) AS false_positives
            FROM analyst_feedback GROUP BY incident_type"""
        ).fetchall()
    aggregated: dict[str, tuple[int, int]] = {}
    for row in rows:
        rule = RULE_FOR_INCIDENT.get(row["incident_type"])
        if not rule:
            continue
        total, false_positives = aggregated.get(rule, (0, 0))
        aggregated[rule] = (total + int(row["total"]), false_positives + int(row["false_positives"] or 0))
    for rule, (total, false_positives) in aggregated.items():
        profile[rule] = _bounded_threshold(DEFAULT_THRESHOLDS[rule], total, false_positives)
    return profile


def record_analyst_feedback(database_path: Path, incident_uid: str, verdict: str, notes: str = "") -> None:
    if verdict not in {"true_positive", "false_positive", "needs_review"}:
        raise ValueError("Verdict de feedback invalide")
    with connect(database_path) as connection:
        incident = connection.execute(
            "SELECT incident_type FROM incidents WHERE incident_uid=?", (incident_uid,)
        ).fetchone()
        if not incident:
            raise ValueError("Incident introuvable")
        connection.execute(
            """INSERT INTO analyst_feedback(incident_uid,incident_type,verdict,notes,created_at)
            VALUES(?,?,?,?,?) ON CONFLICT(incident_uid) DO UPDATE SET
            incident_type=excluded.incident_type, verdict=excluded.verdict,
            notes=excluded.notes, created_at=excluded.created_at""",
            (incident_uid, incident["incident_type"], verdict, notes.strip(), datetime.now(timezone.utc).isoformat()),
        )


def feedback_statistics(database_path: Path) -> list[dict[str, object]]:
    with connect(database_path) as connection:
        rows = connection.execute(
            """SELECT incident_type, COUNT(*) AS total,
            SUM(CASE WHEN verdict='true_positive' THEN 1 ELSE 0 END) AS true_positives,
            SUM(CASE WHEN verdict='false_positive' THEN 1 ELSE 0 END) AS false_positives,
            SUM(CASE WHEN verdict='needs_review' THEN 1 ELSE 0 END) AS needs_review
            FROM analyst_feedback GROUP BY incident_type ORDER BY total DESC"""
        ).fetchall()
    return [dict(row) for row in rows]
