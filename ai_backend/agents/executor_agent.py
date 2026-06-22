from __future__ import annotations

import json
from datetime import datetime, timezone

from ai_backend.config import Settings
from ai_backend.models import ResponseAction, SOCState


def _action(incident_uid: str, action_type: str, details: str) -> ResponseAction:
    return ResponseAction(incident_uid=incident_uid, action_type=action_type, details=details)


def run_executor(state: SOCState, settings: Settings) -> dict:
    actions: list[ResponseAction] = []
    blocklist = settings.audit_dir / "blocklist.txt"
    notifications = settings.audit_dir / "notifications.log"
    quarantine = settings.audit_dir / "quarantine_plan.jsonl"
    remediation = settings.audit_dir / "remediation.log"
    for incident in state.get("incidents", []):
        timestamp = datetime.now(timezone.utc).isoformat()
        if incident.src_ip and incident.severity in {"High", "Critical"}:
            existing = set(blocklist.read_text(encoding="utf-8").splitlines()) if blocklist.exists() else set()
            if incident.src_ip not in existing:
                with blocklist.open("a", encoding="utf-8") as handle:
                    handle.write(f"{incident.src_ip}\n")
            actions.append(_action(incident.incident_uid, "SIMULATED_BLOCK_IP", f"Ajout simulé de {incident.src_ip} à la blocklist locale."))
        isolation_target = incident.affected_host or incident.dest_ip
        if isolation_target and incident.severity in {"High", "Critical"}:
            plan = {
                "timestamp": timestamp,
                "incident_uid": incident.incident_uid,
                "target": isolation_target,
                "action": "isolate_from_network",
                "status": "SIMULATED_ONLY",
                "approval_required": True,
            }
            with quarantine.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(plan, ensure_ascii=False) + "\n")
            actions.append(_action(
                incident.incident_uid,
                "SIMULATED_ISOLATE_HOST",
                f"Plan d'isolation simulé pour {isolation_target}; validation humaine obligatoire.",
            ))
        with notifications.open("a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} | {incident.incident_uid} | {incident.severity} | {incident.title}\n")
        playbook = (
            "préserver les preuves; vérifier les IOC; réinitialiser les accès concernés; "
            "corriger l'actif; surveiller 24 h; clôturer après validation analyste"
        )
        with remediation.open("a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} | {incident.incident_uid} | {playbook}\n")
        actions.extend([
            _action(incident.incident_uid, "SIMULATED_NOTIFY_ADMIN", "Notification locale simulée et auditée."),
            _action(incident.incident_uid, "SIMULATED_CREATE_TICKET", "Ticket d'incident simulé."),
            _action(incident.incident_uid, "SIMULATED_REMEDIATION_PLAYBOOK", playbook),
            _action(incident.incident_uid, "SIMULATED_MARK_CONTAINED", "Incident marqué comme contenu en simulation."),
        ])
        incident.status = "contained_simulated"
    return {"incidents": state.get("incidents", []), "actions": actions}
