from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from ai_backend.adaptive import load_adaptive_profile
from ai_backend.config import Settings
from ai_backend.models import Incident, NormalizedEvent, SOCState

SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _fallback(incident: Incident, count: int) -> tuple[str, str]:
    explanation = (
        f"La corrélation déterministe a regroupé {count} événement(s) compatible(s) avec "
        f"« {incident.incident_type} ». La sévérité {incident.severity} repose sur la fréquence, "
        "la nature des signatures et les actifs concernés. Cette conclusion doit être validée par un analyste."
    )
    recommendation = (
        "Vérifier la chronologie et les journaux de l'hôte, confirmer la légitimité de la source, "
        "conserver les preuves et appliquer une mesure de confinement uniquement après validation humaine."
    )
    return explanation, recommendation


def _llm_enrich(incident: Incident, count: int, settings: Settings) -> tuple[str, str]:
    fallback = _fallback(incident, count)
    if not settings.ollama_enabled:
        return fallback
    try:
        from langchain_ollama import ChatOllama
        prompt = (
            "Tu es analyste SOC. Réponds en français avec exactement deux paragraphes courts, "
            "le premier commençant par EXPLICATION: et le second par RECOMMANDATION:. "
            f"Incident={incident.incident_type}; sévérité={incident.severity}; confiance={incident.confidence}; "
            f"source={incident.src_ip}; destination={incident.dest_ip}; nombre de preuves={count}; "
            f"preuves={incident.evidence[:5]}. N'invente aucun fait."
        )
        content = ChatOllama(model=settings.ollama_model, temperature=0).invoke(prompt).content.strip()
        if "RECOMMANDATION:" not in content:
            return content, fallback[1]
        explanation, recommendation = content.split("RECOMMANDATION:", 1)
        return explanation.replace("EXPLICATION:", "").strip(), recommendation.strip()
    except Exception:
        return fallback


def _make_incident(events: list[NormalizedEvent], indexes: list[int], incident_type: str, title: str,
                   severity: str, confidence: float, tactic: str, technique: str) -> Incident:
    selected = [events[index] for index in indexes]
    first = min(selected, key=lambda event: event.timestamp)
    return Incident(
        timestamp=first.timestamp, title=title, incident_type=incident_type,
        severity=severity, confidence=confidence, src_ip=first.src_ip,
        dest_ip=next((event.dest_ip for event in selected if event.dest_ip), None),
        affected_host=next((event.host for event in selected if event.host), None),
        mitre_tactic=tactic, mitre_technique=technique,
        evidence=[event.message for event in selected[:10]], event_indexes=indexes,
    )


def correlate_events(events: list[NormalizedEvent], settings: Settings) -> list[Incident]:
    incidents: list[Incident] = []
    consumed: set[int] = set()
    ssh_groups: dict[tuple[str, str, int], list[int]] = defaultdict(list)
    web_groups: dict[tuple[str, int], list[int]] = defaultdict(list)
    network_groups: dict[tuple[str, int], list[int]] = defaultdict(list)
    window_seconds = max(60, settings.correlation_window_minutes * 60)
    adaptive = load_adaptive_profile(settings.database_path)
    ssh_threshold = adaptive["ssh_brute_force"]
    web_threshold = adaptive["web_recon_high"]
    port_threshold = adaptive["port_scan"]

    for index, event in enumerate(events):
        bucket = int(event.timestamp.timestamp() // window_seconds)
        if event.event_type == "ssh_failed_login":
            ssh_groups[(event.src_ip or "unknown", event.host or "unknown", bucket)].append(index)
        if event.source_type == "apache_access" and event.signature == "Web reconnaissance":
            web_groups[(event.src_ip or "unknown", bucket)].append(index)
        if event.source_type.startswith("suricata"):
            network_groups[(event.src_ip or "unknown", bucket)].append(index)

    for (src_ip, _, _), indexes in ssh_groups.items():
        count = len(indexes)
        incident = _make_incident(
            events, indexes,
            "SSH brute force suspicion" if count >= ssh_threshold else "Suspicious authentication activity",
            f"Suspicion de brute force SSH depuis {src_ip}" if count >= ssh_threshold else f"Échecs SSH depuis {src_ip}",
            "High" if count >= ssh_threshold else "Medium", min(0.98, 0.55 + count * 0.07),
            "Credential Access", "T1110 - Brute Force",
        )
        incidents.append(incident)
        consumed.update(indexes)

    for (src_ip, _), indexes in web_groups.items():
        count = len(indexes)
        incidents.append(_make_incident(
            events, indexes, "Web reconnaissance", f"Reconnaissance web depuis {src_ip}",
            "High" if count >= web_threshold else "Medium", min(0.95, 0.6 + count * 0.05),
            "Reconnaissance", "T1595 - Active Scanning",
        ))
        consumed.update(indexes)

    for (src_ip, _), indexes in network_groups.items():
        ports = {events[index].dest_port for index in indexes if events[index].dest_port}
        if len(ports) >= port_threshold:
            incidents.append(_make_incident(
                events, indexes, "Port scan suspicion", f"Balayage de ports suspect depuis {src_ip}",
                "High", min(0.98, 0.65 + len(ports) * 0.03), "Discovery", "T1046 - Network Service Discovery",
            ))
            consumed.update(indexes)

    for index, event in enumerate(events):
        if index in consumed:
            continue
        if event.source_type.startswith("siem_"):
            is_credential = event.dest_port == 22 or "credential" in (event.signature or "").lower()
            incidents.append(_make_incident(
                events, [index], "SIEM correlated alert", event.signature or "Alerte SIEM corrélée",
                event.severity, 0.9, "Credential Access" if is_credential else "Initial Access",
                "T1110 - Brute Force" if is_credential else "T1190 - Exploit Public-Facing Application",
            ))
        elif event.source_type.startswith("suricata"):
            is_http = event.dest_port == 80 or "HTTP" in (event.signature or "").upper()
            incidents.append(_make_incident(
                events, [index], "HTTP connection alert" if is_http else "Suspicious network activity",
                event.signature or "Activité réseau suspecte", event.severity,
                0.85 if event.signature else 0.65,
                "Initial Access" if is_http else "Discovery",
                "T1190 - Exploit Public-Facing Application" if is_http else "T1046 - Network Service Discovery",
            ))
        elif event.event_type in {"authentication_failure", "suspicious_system_event", "http_error"}:
            incidents.append(_make_incident(
                events, [index], "Suspicious authentication activity" if event.event_type == "authentication_failure" else "Suspicious system activity",
                event.signature or "Événement système suspect", event.severity, 0.62,
                "Credential Access" if event.event_type == "authentication_failure" else "Execution",
                "T1078 - Valid Accounts" if event.event_type == "authentication_failure" else "À confirmer",
            ))

    for incident in incidents:
        incident.explanation, incident.recommendation = _llm_enrich(incident, len(incident.event_indexes), settings)
        incident.dashboard_summary = f"{incident.severity} · {incident.incident_type} · source {incident.src_ip or 'inconnue'}"
    return sorted(incidents, key=lambda item: (SEVERITY_ORDER.get(item.severity, 0), item.timestamp), reverse=True)


def run_analyzer(state: SOCState, settings: Settings) -> dict:
    return {"incidents": correlate_events(state.get("normalized_events", []), settings)}
