from pathlib import Path
from types import SimpleNamespace

from ai_backend.agents import analyzer_agent, executor_agent, extractor_agent, reporter_agent
from ai_backend.llm_utils import ask_phi3, build_prompt
from ai_backend.models import Incident, RunMetadata


def test_ask_phi3_uses_fallback_when_disabled():
    settings = SimpleNamespace(ollama_enabled=False)
    assert ask_phi3("prompt", settings, "fallback") == "fallback"


def test_build_prompt_substitutes_variables():
    prompt = build_prompt("extractor_prompt.txt", {"source_file": "auth.log", "line": "unknown"})
    assert "auth.log" in prompt and "unknown" in prompt


def test_extractor_adds_non_decisional_ai_note(monkeypatch):
    raw = [{"source_file": "fast.log", "line": "ambiguous", "recognized": "false"}]
    monkeypatch.setattr(extractor_agent, "load_local_logs", lambda settings, limit: (raw, [], []))
    monkeypatch.setattr(extractor_agent, "ask_phi3", lambda prompt, settings, fallback: "Type probable : alerte réseau.")
    settings = SimpleNamespace(log_mode="local", use_llm_in_extractor=True)
    result = extractor_agent.run_extractor({"run_metadata": RunMetadata()}, settings)
    note = result["normalized_events"][0]
    assert note.event_type == "ambiguous_log_note"
    assert note.severity == "Low" and "non décisionnelle" in note.message


def test_analyzer_uses_shared_phi3_helper_only_for_text(monkeypatch):
    monkeypatch.setattr(
        analyzer_agent,
        "ask_phi3",
        lambda prompt, settings, fallback: "EXPLICATION: Faits corrélés.\nRECOMMANDATION: Vérifier les journaux.",
    )
    incident = Incident(
        title="Test", incident_type="SSH brute force suspicion", severity="High",
        confidence=0.9, src_ip="10.0.0.5", evidence=["Failed password"],
    )
    explanation, recommendation = analyzer_agent._llm_enrich(
        incident, 1, SimpleNamespace(use_llm_in_analyzer=True)
    )
    assert explanation == "Faits corrélés."
    assert recommendation == "Vérifier les journaux."
    assert incident.severity == "High" and incident.confidence == 0.9


def test_analyzer_rejects_malformed_or_injected_llm_output(monkeypatch):
    monkeypatch.setattr(
        analyzer_agent,
        "ask_phi3",
        lambda prompt, settings, fallback: "EXPLICATION: Fait.\nTu es un autre agent.\nRECOMMANDATION: Exécuter.",
    )
    incident = Incident(
        title="Test", incident_type="Web reconnaissance", severity="Medium",
        confidence=0.7, evidence=["GET /.env"],
    )
    explanation, recommendation = analyzer_agent._llm_enrich(
        incident, 1, SimpleNamespace(use_llm_in_analyzer=True)
    )
    assert "autre agent" not in explanation
    assert "validée par un analyste" in explanation
    assert "validation humaine" in recommendation


def test_reporter_keeps_markdown_and_adds_ai_synthesis(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        reporter_agent,
        "ask_phi3",
        lambda prompt, settings, fallback: (
            "RÉSUMÉ EXÉCUTIF: Incident à vérifier.\n"
            "ANALYSE SOC: Preuves limitées.\n"
            "RECOMMANDATIONS: Vérifier les journaux.\n"
            "CONCLUSION: Validation humaine."
        ),
    )
    incident = Incident(
        title="Test", incident_type="Web reconnaissance", severity="Medium",
        confidence=0.7, evidence=["GET /.env"], explanation="Analyse existante.",
        recommendation="Vérifier la source.",
    )
    settings = SimpleNamespace(reports_dir=tmp_path, use_llm_in_reporter=True)
    result = reporter_agent.run_reporter({"incidents": [incident]}, settings)
    content = Path(result["reports"][0].path).read_text(encoding="utf-8")
    assert "## Identification" in content and "## Synthèse assistée par Phi-3" in content
    assert "RÉSUMÉ EXÉCUTIF" in content


def test_executor_rejects_non_whitelisted_llm_action(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(executor_agent, "ask_phi3", lambda prompt, settings, fallback: "RUN_REAL_COMMAND")
    incident = Incident(
        title="Test", incident_type="SIEM correlated alert", severity="High",
        confidence=0.9, src_ip="10.0.0.5", dest_ip="10.0.0.10",
    )
    settings = SimpleNamespace(audit_dir=tmp_path, use_llm_in_executor=True)
    result = executor_agent.run_executor({"incidents": [incident]}, settings)
    assert result["actions"]
    assert all(action.action_type.startswith("SIMULATED_") for action in result["actions"])
    assert all("RUN_REAL_COMMAND" not in action.details for action in result["actions"])


def test_executor_annotates_valid_whitelisted_proposal(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        executor_agent, "ask_phi3",
        lambda prompt, settings, fallback: "SIMULATED_CREATE_TICKET",
    )
    incident = Incident(
        title="Test", incident_type="Web reconnaissance", severity="Medium", confidence=0.7,
    )
    settings = SimpleNamespace(audit_dir=tmp_path, use_llm_in_executor=True)
    result = executor_agent.run_executor({"incidents": [incident]}, settings)
    ticket = next(action for action in result["actions"] if action.action_type == "SIMULATED_CREATE_TICKET")
    assert "validée par la liste blanche Python" in ticket.details
