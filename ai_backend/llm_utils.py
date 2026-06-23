from __future__ import annotations

import logging
from pathlib import Path
from typing import Mapping

from ai_backend.config import Settings

LOGGER = logging.getLogger(__name__)
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


class _PromptVariables(dict[str, str]):
    def __missing__(self, key: str) -> str:
        return ""


def build_prompt(template_name: str, variables: Mapping[str, object]) -> str:
    """Load a project prompt and substitute its named variables."""
    safe_name = Path(template_name).name
    if safe_name != template_name or not safe_name.endswith(".txt"):
        raise ValueError("Nom de template de prompt invalide")
    template = (PROMPTS_DIR / safe_name).read_text(encoding="utf-8")
    values = _PromptVariables({key: str(value) for key, value in variables.items()})
    return template.format_map(values).strip()


def ask_phi3(prompt: str, settings: Settings, fallback: str) -> str:
    """Call the local SLM without ever making the SOC pipeline depend on it."""
    if not getattr(settings, "ollama_enabled", False) or not prompt.strip():
        return fallback
    try:
        from langchain_ollama import ChatOllama

        timeout = max(1, int(getattr(settings, "llm_timeout", 30)))
        model = getattr(settings, "ollama_model", "phi3") or "phi3"
        base_url = getattr(settings, "ollama_base_url", None) or None
        response = ChatOllama(
            model=model,
            temperature=0,
            num_predict=160,
            keep_alive="10m",
            base_url=base_url,
            client_kwargs={"timeout": timeout},
            async_client_kwargs={"timeout": timeout},
        ).invoke(prompt)
        content = response.content if isinstance(response.content, str) else str(response.content)
        return content.strip() or fallback
    except Exception as exc:
        LOGGER.warning("Assistance Phi-3 indisponible; fallback déterministe utilisé (%s)", exc)
        return fallback
