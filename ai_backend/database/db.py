from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ai_backend.models import SOCState

SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_type TEXT, source_file TEXT,
 event_type TEXT, src_ip TEXT, src_port INTEGER, dest_ip TEXT, dest_port INTEGER,
 protocol TEXT, host TEXT, user TEXT, signature TEXT, severity TEXT, message TEXT,
 raw_event_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_uid TEXT UNIQUE, timestamp TEXT, title TEXT,
 incident_type TEXT, severity TEXT, confidence REAL, src_ip TEXT, dest_ip TEXT,
 affected_host TEXT, mitre_tactic TEXT, mitre_technique TEXT, explanation TEXT,
 recommendation TEXT, report_path TEXT, status TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS actions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_uid TEXT, timestamp TEXT, action_type TEXT,
 action_status TEXT, details TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, run_uid TEXT UNIQUE, started_at TEXT, finished_at TEXT,
 total_raw_events INTEGER, total_normalized_events INTEGER, total_incidents INTEGER,
 total_actions INTEGER, status TEXT, errors TEXT);
CREATE TABLE IF NOT EXISTS analyst_feedback (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_uid TEXT NOT NULL UNIQUE,
 incident_type TEXT NOT NULL, verdict TEXT NOT NULL,
 notes TEXT, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_raw_source ON raw_events(source_type);
CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_action_incident ON actions(incident_uid);
CREATE INDEX IF NOT EXISTS idx_feedback_type ON analyst_feedback(incident_type);
"""


def connect(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    return connection


def persist_state(state: SOCState, database_path: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with connect(database_path) as connection:
        for event in state.get("normalized_events", []):
            item = event.model_dump(mode="json")
            connection.execute(
                """INSERT INTO raw_events(timestamp,source_type,source_file,event_type,src_ip,src_port,
                dest_ip,dest_port,protocol,host,user,signature,severity,message,raw_event_json,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (item["timestamp"], item["source_type"], item["source_file"], item["event_type"],
                 item["src_ip"], item["src_port"], item["dest_ip"], item["dest_port"], item["protocol"],
                 item["host"], item["user"], item["signature"], item["severity"], item["message"],
                 json.dumps(item["raw_event"], ensure_ascii=False), now),
            )
        for incident in state.get("incidents", []):
            item = incident.model_dump(mode="json")
            connection.execute(
                """INSERT OR REPLACE INTO incidents(incident_uid,timestamp,title,incident_type,severity,
                confidence,src_ip,dest_ip,affected_host,mitre_tactic,mitre_technique,explanation,
                recommendation,report_path,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (item["incident_uid"], item["timestamp"], item["title"], item["incident_type"], item["severity"],
                 item["confidence"], item["src_ip"], item["dest_ip"], item["affected_host"], item["mitre_tactic"],
                 item["mitre_technique"], item["explanation"], item["recommendation"], item["report_path"],
                 item["status"], now),
            )
        for action in state.get("actions", []):
            item = action.model_dump(mode="json")
            connection.execute(
                "INSERT INTO actions(incident_uid,timestamp,action_type,action_status,details,created_at) VALUES(?,?,?,?,?,?)",
                (item["incident_uid"], item["timestamp"], item["action_type"], item["action_status"], item["details"], now),
            )
        run = state["run_metadata"]
        connection.execute(
            """INSERT OR REPLACE INTO runs(run_uid,started_at,finished_at,total_raw_events,total_normalized_events,
            total_incidents,total_actions,status,errors) VALUES(?,?,?,?,?,?,?,?,?)""",
            (run.run_uid, run.started_at.isoformat(), run.finished_at.isoformat() if run.finished_at else None,
             len(state.get("raw_events", [])), len(state.get("normalized_events", [])),
             len(state.get("incidents", [])), len(state.get("actions", [])), run.status,
             json.dumps(state.get("errors", []), ensure_ascii=False)),
        )
