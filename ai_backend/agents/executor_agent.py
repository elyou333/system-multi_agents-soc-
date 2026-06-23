from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from ai_backend.config import Settings
from ai_backend.llm_utils import ask_phi3, build_prompt
from ai_backend.models import Incident, ResponseAction, SOCState

LLM_ACTION_WHITELIST = frozenset({
    "SIMULATED_BLOCK_IP",
    "SIMULATED_NOTIFY_ADMIN",
    "SIMULATED_CREATE_TICKET",
    "SIMULATED_MARK_CONTAINED",
})


def _action(incident_uid: str, action_type: str, details: str) -> ResponseAction:
    return ResponseAction(incident_uid=incident_uid, action_type=action_type, details=details)


def _fallback_proposal(incident: Incident) -> str:
    if incident.src_ip and incident.severity in {"High", "Critical"}:
        return "SIMULATED_BLOCK_IP"
    return "SIMULATED_NOTIFY_ADMIN"


def _llm_action_proposal(incident: Incident, settings: Settings) -> tuple[str, bool]:
    fallback = _fallback_proposal(incident)
    if not getattr(settings, "use_llm_in_executor", False):
        return fallback, False
    try:
        prompt = build_prompt("executor_prompt.txt", {
            "incident_type": incident.incident_type,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "src_ip": incident.src_ip or "inconnue",
            "dest_ip": incident.dest_ip or "inconnue",
            "evidence": incident.evidence[:5],
            "recommendation": incident.recommendation,
        })
    except (OSError, ValueError):
        return fallback, False
    response = ask_phi3(prompt, settings, fallback)
    candidates = set(re.findall(r"\bSIMULATED_[A-Z_]+\b", response))
    allowed = set(LLM_ACTION_WHITELIST)
    if not (incident.src_ip and incident.severity in {"High", "Critical"}):
        allowed.discard("SIMULATED_BLOCK_IP")
    if len(candidates) == 1:
        candidate = next(iter(candidates))
        if candidate in allowed:
            return candidate, response.strip() != fallback
    return fallback, False


def _annotate_proposal(details: str, action_type: str, proposal: str, assisted: bool) -> str:
    if assisted and action_type == proposal:
        return f"Proposition Phi-3 validée par la liste blanche Python. {details}"
    return details


def run_executor(state: SOCState, settings: Settings) -> dict:
    actions: list[ResponseAction] = []
    blocklist = settings.audit_dir / "blocklist.txt"
    notifications = settings.audit_dir / "notifications.log"
    quarantine = settings.audit_dir / "quarantine_plan.jsonl"
    remediation = settings.audit_dir / "remediation.log"
    for incident in state.get("incidents", []):
        timestamp = datetime.now(timezone.utc).isoformat()
        proposal, assisted = _llm_action_proposal(incident, settings)
        if incident.src_ip and incident.severity in {"High", "Critical"}:
            existing = set(blocklist.read_text(encoding="utf-8").splitlines()) if blocklist.exists() else set()
            if incident.src_ip not in existing:
                with blocklist.open("a", encoding="utf-8") as handle:
                    handle.write(f"{incident.src_ip}\n")
            details = _annotate_proposal(
                f"Ajout simulé de {incident.src_ip} à la blocklist locale.",
                "SIMULATED_BLOCK_IP", proposal, assisted,
            )
            actions.append(_action(incident.incident_uid, "SIMULATED_BLOCK_IP", details))
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
            _action(incident.incident_uid, "SIMULATED_NOTIFY_ADMIN", _annotate_proposal(
                "Notification locale simulée et auditée.", "SIMULATED_NOTIFY_ADMIN", proposal, assisted,
            )),
            _action(incident.incident_uid, "SIMULATED_CREATE_TICKET", _annotate_proposal(
                "Ticket d'incident simulé.", "SIMULATED_CREATE_TICKET", proposal, assisted,
            )),
            _action(incident.incident_uid, "SIMULATED_REMEDIATION_PLAYBOOK", playbook),
            _action(incident.incident_uid, "SIMULATED_MARK_CONTAINED", _annotate_proposal(
                "Incident marqué comme contenu en simulation.", "SIMULATED_MARK_CONTAINED", proposal, assisted,
            )),
        ])
        incident.status = "contained_simulated"
    return {"incidents": state.get("incidents", []), "actions": actions}
