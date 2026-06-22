from __future__ import annotations

import argparse
import logging
import sys

from rich.console import Console
from rich.table import Table

from ai_backend.config import get_settings
from ai_backend.database.db import connect
from ai_backend.graph import build_graph
from ai_backend.models import RunMetadata, SOCState

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assistant SOC multi-agents local")
    parser.add_argument("--mode", choices=("local", "ssh"), help="Mode de collecte")
    parser.add_argument("--limit", type=int, help="Nombre maximal de lignes brutes à lire")
    return parser.parse_args()


def run(mode: str | None = None, limit: int | None = None) -> SOCState:
    settings = get_settings(mode)
    connect(settings.database_path).close()
    initial: SOCState = {
        "raw_events": [], "normalized_events": [], "incidents": [], "reports": [],
        "actions": [], "errors": [], "run_metadata": RunMetadata(mode=settings.log_mode, limit=limit),
    }
    return build_graph(settings).invoke(initial)


def print_summary(state: SOCState, database_path: str) -> None:
    table = Table(title="Résumé de l'exécution SOC")
    table.add_column("Mesure")
    table.add_column("Valeur", justify="right")
    table.add_row("Événements bruts chargés", str(len(state.get("raw_events", []))))
    table.add_row("Événements normalisés", str(len(state.get("normalized_events", []))))
    table.add_row("Incidents détectés", str(len(state.get("incidents", []))))
    table.add_row("Rapports générés", str(len(state.get("reports", []))))
    table.add_row("Actions simulées", str(len(state.get("actions", []))))
    console.print(table)
    console.print(f"Base SQLite : [cyan]{database_path}[/cyan]")
    if state.get("errors"):
        console.print(f"[yellow]{len(state['errors'])} avertissement(s) — voir la table runs.[/yellow]")


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = get_settings(args.mode)
    try:
        state = run(args.mode, args.limit)
        print_summary(state, str(settings.database_path))
        return 0
    except Exception as exc:
        console.print(f"[bold red]Échec du workflow :[/bold red] {exc}")
        logging.exception("Erreur non récupérable")
        return 1


if __name__ == "__main__":
    sys.exit(main())
