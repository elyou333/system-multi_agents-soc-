from __future__ import annotations

from pathlib import Path

from ai_backend.config import Settings
from ai_backend.models import Report, SOCState


def _report_content(incident) -> str:
    evidence = "\n".join(f"- {item}" for item in incident.evidence) or "- Aucune preuve textuelle."
    simulated_actions = [
        "- SIMULATED_NOTIFY_ADMIN : notification locale auditée.",
        "- SIMULATED_CREATE_TICKET : création d'un ticket fictif.",
        "- SIMULATED_REMEDIATION_PLAYBOOK : préparation d'une remédiation contrôlée.",
        "- SIMULATED_MARK_CONTAINED : passage au statut de confinement simulé.",
    ]
    if incident.src_ip and incident.severity in {"High", "Critical"}:
        simulated_actions.insert(0, f"- SIMULATED_BLOCK_IP : ajout local simulé de {incident.src_ip}.")
    if (incident.affected_host or incident.dest_ip) and incident.severity in {"High", "Critical"}:
        target = incident.affected_host or incident.dest_ip
        simulated_actions.insert(1, f"- SIMULATED_ISOLATE_HOST : plan d'isolation de {target}, soumis à validation humaine.")
    return f"""# Rapport d'incident — {incident.title}

## Identification

- **Identifiant :** {incident.incident_uid}
- **Horodatage de détection :** {incident.timestamp.isoformat()}
- **Sévérité :** {incident.severity}
- **Confiance :** {incident.confidence:.0%}
- **Statut :** {incident.status}

## Périmètre

- **Adresse source :** {incident.src_ip or "Non déterminée"}
- **Adresse destination :** {incident.dest_ip or "Non déterminée"}
- **Hôte affecté :** {incident.affected_host or "Non déterminé"}
- **Type :** {incident.incident_type}
- **MITRE ATT&CK :** {incident.mitre_tactic or "Non déterminée"} / {incident.mitre_technique or "Non déterminée"}

## Éléments de preuve

{evidence}

## Analyse SOC

{incident.explanation}

## Mesures recommandées

{incident.recommendation}

## Actions de réponse simulées

{chr(10).join(simulated_actions)}

Ces actions sont ajoutées au journal d'audit après génération du rapport. Aucun blocage, isolement ou changement système réel n'est exécuté.

## Limites

Cette analyse est produite à partir des seuls journaux disponibles. La corrélation et l'explication du SLM peuvent contenir des incertitudes. Une validation humaine et des sources complémentaires sont nécessaires avant toute réponse réelle.
"""


def run_reporter(state: SOCState, settings: Settings) -> dict:
    reports: list[Report] = []
    for incident in state.get("incidents", []):
        path = settings.reports_dir / f"{incident.incident_uid}.md"
        content = _report_content(incident)
        path.write_text(content, encoding="utf-8")
        incident.report_path = str(path)
        summary = incident.dashboard_summary or f"{incident.severity} · {incident.title}"
        reports.append(Report(incident_uid=incident.incident_uid, path=str(path), content=content, summary=summary))
    return {"incidents": state.get("incidents", []), "reports": reports}
