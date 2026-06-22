from pathlib import Path
from types import SimpleNamespace

from ai_backend.adaptive import load_adaptive_profile, record_analyst_feedback
from ai_backend.agents.executor_agent import run_executor
from ai_backend.connectors.siem_connector import parse_siem_record
from ai_backend.database.db import connect
from ai_backend.experiments import detection_metrics
from ai_backend.models import Incident


def test_parse_elastic_ecs_alert():
    record = {
        "_source": {
            "@timestamp": "2026-06-21T12:00:00+00:00",
            "event": {"severity": 80},
            "rule": {"name": "Credential attack"},
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "10.0.0.10", "port": 22},
            "message": "Repeated failures",
        }
    }
    event = parse_siem_record(record, "elastic", "elastic")
    assert event.source_type == "siem_elastic"
    assert event.src_ip == "10.0.0.5" and event.dest_port == 22
    assert event.severity == "High"


def test_parse_splunk_result():
    event = parse_siem_record(
        {"result": {"_time": "2026-06-21T12:00:00+00:00", "search_name": "Scan", "severity": "critical", "src_ip": "10.0.0.8"}},
        "splunk",
        "splunk",
    )
    assert event.source_type == "siem_splunk"
    assert event.signature == "Scan" and event.severity == "Critical"


def test_feedback_changes_threshold_only_after_three_labels(tmp_path: Path):
    database = tmp_path / "test.db"
    with connect(database) as connection:
        for index in range(3):
            connection.execute(
                "INSERT INTO incidents(incident_uid,incident_type,created_at) VALUES(?,?,?)",
                (f"INC-{index}", "SSH brute force suspicion", "2026-06-21T12:00:00+00:00"),
            )
    for index in range(3):
        record_analyst_feedback(database, f"INC-{index}", "false_positive")
    profile = load_adaptive_profile(database)
    assert profile["ssh_brute_force"] == 7
    assert 3 <= profile["ssh_brute_force"] <= 10


def test_high_incident_creates_simulated_isolation_and_playbook(tmp_path: Path):
    incident = Incident(
        title="Test", incident_type="SIEM correlated alert", severity="High", confidence=0.9,
        src_ip="10.0.0.5", dest_ip="10.0.0.10", affected_host="server-01",
    )
    result = run_executor({"incidents": [incident]}, SimpleNamespace(audit_dir=tmp_path))
    action_types = {action.action_type for action in result["actions"]}
    assert "SIMULATED_ISOLATE_HOST" in action_types
    assert "SIMULATED_REMEDIATION_PLAYBOOK" in action_types
    assert "SIMULATED_ONLY" in (tmp_path / "quarantine_plan.jsonl").read_text(encoding="utf-8")


def test_detection_metrics_count_surplus_as_false_positive():
    from collections import Counter

    metrics = detection_metrics(Counter({"a": 2, "b": 1}), Counter({"a": 1, "c": 1}))
    assert metrics["true_positive"] == 1
    assert metrics["false_positive"] == 2
    assert metrics["false_negative"] == 1
