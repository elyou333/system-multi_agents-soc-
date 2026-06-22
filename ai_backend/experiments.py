from __future__ import annotations

import argparse
import json
import statistics
import time
import tracemalloc
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai_backend.agents.analyzer_agent import correlate_events
from ai_backend.config import Settings, get_settings
from ai_backend.connectors.log_loader import load_local_logs


def _key(incident_type: str, src_ip: str | None) -> str:
    return f"{incident_type}|{src_ip or 'unknown'}"


def detection_metrics(predicted: Counter[str], expected: Counter[str]) -> dict[str, float | int]:
    keys = set(predicted) | set(expected)
    true_positive = sum(min(predicted[key], expected[key]) for key in keys)
    false_positive = sum(max(0, predicted[key] - expected[key]) for key in keys)
    false_negative = sum(max(0, expected[key] - predicted[key]) for key in keys)
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _load_ground_truth(path: Path) -> Counter[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Counter({str(key): int(value) for key, value in data["expected_incidents"].items()})


def _benchmark_variant(settings: Settings, runs: int, ollama_enabled: bool) -> dict[str, Any]:
    durations: list[float] = []
    peaks: list[int] = []
    last_incidents = []
    variant_settings = replace(settings, ollama_enabled=ollama_enabled)
    for _ in range(runs):
        tracemalloc.start()
        started = time.perf_counter()
        _, events, _ = load_local_logs(variant_settings)
        last_incidents = correlate_events(events, variant_settings)
        durations.append(time.perf_counter() - started)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    return {
        "runs": runs,
        "ollama_enabled": ollama_enabled,
        "duration_mean_seconds": round(statistics.mean(durations), 4),
        "duration_std_seconds": round(statistics.pstdev(durations), 4),
        "peak_memory_mean_mb": round(statistics.mean(peaks) / 1024 / 1024, 3),
        "incidents_per_run": len(last_incidents),
        "predicted": dict(Counter(_key(item.incident_type, item.src_ip) for item in last_incidents)),
    }


def _markdown(result: dict[str, Any]) -> str:
    metrics = result["detection_metrics"]
    rows = []
    for name, variant in result["performance"].items():
        rows.append(
            f"| {name} | {variant['runs']} | {variant['duration_mean_seconds']:.4f} | "
            f"{variant['duration_std_seconds']:.4f} | {variant['peak_memory_mean_mb']:.3f} |"
        )
    return f"""# Rapport expérimental reproductible

Généré le {result['generated_at']} à partir du jeu de laboratoire versionné et de sa vérité terrain.

## Efficacité de détection

| Mesure | Valeur |
|---|---:|
| Vrais positifs | {metrics['true_positive']} |
| Faux positifs | {metrics['false_positive']} |
| Faux négatifs | {metrics['false_negative']} |
| Précision | {metrics['precision']:.2%} |
| Rappel | {metrics['recall']:.2%} |
| F1 | {metrics['f1']:.2%} |

## Performance

| Variante | Répétitions | Durée moyenne (s) | Écart-type (s) | Mémoire pic (MB) |
|---|---:|---:|---:|---:|
{chr(10).join(rows)}

## Protocole et limites

- Les incidents sont comparés comme un multiensemble `(type, IP source)` à `experiments/ground_truth.json`.
- La variante déterministe mesure parsing, normalisation, corrélation et repli local.
- La variante Ollama, lorsqu'elle est demandée, ajoute l'enrichissement Phi-3 pour chaque incident.
- Ce petit dataset de laboratoire valide la reproductibilité, pas une précision de production.
- Les mesures dépendent du matériel, de la charge et de l'état du modèle local.
"""


def run_experiment(settings: Settings, runs: int = 10, include_ollama: bool = False) -> dict[str, Any]:
    if runs < 1:
        raise ValueError("Le nombre de répétitions doit être positif")
    experiment_dir = settings.project_root / "experiments"
    ground_truth = _load_ground_truth(experiment_dir / "ground_truth.json")
    performance = {"deterministic": _benchmark_variant(settings, runs, False)}
    if include_ollama:
        performance["ollama_phi3"] = _benchmark_variant(settings, runs, True)
    predicted = Counter(performance["deterministic"]["predicted"])
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ground_truth": dict(ground_truth),
        "detection_metrics": detection_metrics(predicted, ground_truth),
        "performance": performance,
    }
    results_dir = experiment_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "latest.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (settings.project_root / "docs" / "rapport_experimentation_genere.md").write_text(_markdown(result), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark reproductible du pipeline SOC")
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--with-ollama", action="store_true")
    args = parser.parse_args()
    result = run_experiment(get_settings("local"), args.runs, args.with_ollama)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
