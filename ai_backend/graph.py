from __future__ import annotations

from datetime import datetime, timezone

from langgraph.graph import END, START, StateGraph

from ai_backend.agents.analyzer_agent import run_analyzer
from ai_backend.agents.executor_agent import run_executor
from ai_backend.agents.extractor_agent import run_extractor
from ai_backend.agents.reporter_agent import run_reporter
from ai_backend.config import Settings
from ai_backend.database.db import persist_state
from ai_backend.models import SOCState


def build_graph(settings: Settings):
    workflow = StateGraph(SOCState)
    workflow.add_node("extractor", lambda state: run_extractor(state, settings))
    workflow.add_node("analyzer", lambda state: run_analyzer(state, settings))
    workflow.add_node("reporter", lambda state: run_reporter(state, settings))
    workflow.add_node("executor", lambda state: run_executor(state, settings))

    def persistence(state: SOCState) -> dict:
        run = state["run_metadata"]
        run.finished_at = datetime.now(timezone.utc)
        run.status = "completed_with_warnings" if state.get("errors") else "completed"
        persist_state(state, settings.database_path)
        return {"run_metadata": run}

    workflow.add_node("persistence", persistence)
    workflow.add_edge(START, "extractor")
    workflow.add_edge("extractor", "analyzer")
    workflow.add_edge("analyzer", "reporter")
    workflow.add_edge("reporter", "executor")
    workflow.add_edge("executor", "persistence")
    workflow.add_edge("persistence", END)
    return workflow.compile()
