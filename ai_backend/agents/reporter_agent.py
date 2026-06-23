from __future__ import annotations

import re
from pathlib import Path

from ai_backend.config import Settings
from ai_backend.llm_utils import ask_phi3, build_prompt
from ai_backend.models import Incident, Report, SOCState


def _llm_report_enrichment(incident: Incident, settings: Settings) -> str:
    if not getattr(settings, "use_llm_in_reporter", False):
        return ""
    try:
        prompt = build_prompt("report_prompt.txt", {
            "incident": f"{incident.incident_type} — {incident.title}",
            "severity": incident.severity,
            "confidence": incident.confidence,
            "evidence": incident.evidence[:10],
            "explanation": incident.explanation,
            "recommendation": incident.recommendation,
        })
    except (OSError, ValueError):
        return ""
    content = ask_phi3(prompt, settings, "")
    required = ("RÉSUMÉ EXÉCUTIF", "ANALYSE SOC", "RECOMMANDATIONS", "CONCLUSION")
    if len(content) > 2200 or any(marker in content for marker in (
        "\nTu es ", "\nType :", "Réponds en français",
    )):
        return ""
    if not all(re.search(rf"{re.escape(label)}\s*:", content) for label in required):
        return ""
    return content


def _report_content(incident: Incident, ai_enrichment: str = "") -> str:
    evidence = "\n".join(f"- {item}" for item in incident.evidence) or "- Aucune preuve textuelle."
    ai_section = (
        f"\n## Synthèse assistée par Phi-3\n\n{ai_enrichment}\n"
        if ai_enrichment else ""
    )
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
{ai_section}

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
        content = _report_content(incident, _llm_report_enrichment(incident, settings))
        path.write_text(content, encoding="utf-8")
        incident.report_path = str(path)
        summary = incident.dashboard_summary or f"{incident.severity} · {incident.title}"
        reports.append(Report(incident_uid=incident.incident_uid, path=str(path), content=content, summary=summary))
    return {"incidents": state.get("incidents", []), "reports": reports}
