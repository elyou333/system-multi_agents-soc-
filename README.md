# Système Multi-Agents IA pour l'automatisation des tâches d'un SOC Analyst

Prototype académique d'assistant SOC local orchestré avec LangGraph. Il collecte
des journaux Suricata, Apache et Linux, les normalise, corrèle les événements,
assiste les quatre agents avec Ollama et Phi-3 (avec repli déterministe), génère
des rapports Markdown et simule des réponses entièrement auditables.

> **Sécurité :** aucun pare-feu, service, fichier système ou hôte n'est modifié.
> Les blocages, notifications, tickets et confinements sont des simulations
> stockées dans audit/ et SQLite.

## Architecture

ELK/Splunk + VM SOC/Suricata + VM victime/Apache/auth → Extracteur → Analyseur → Rapporteur
→ Exécuteur simulé → SQLite + Streamlit

Le modèle local explique les décisions, mais ne choisit ni le type ni la
sévérité : ces décisions restent déterministes et auditables. Voir
[l'architecture](docs/architecture.md).

Tous les agents sont IA-assistés par Phi-3 via Ollama, mais les décisions
critiques restent contrôlées par des règles Python afin de garantir
l'explicabilité, la sécurité et la traçabilité.

## Installation Windows

    cd "C:\Users\XPS\OneDrive\Desktop\soc-project-2"
    py -3.12 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    Copy-Item .env.example .env
    ollama pull phi3

`PROJECT_ROOT` est détecté automatiquement; ne le renseignez que pour utiliser
un autre dossier de données.
Pour une démonstration sans Ollama, définissez OLLAMA_ENABLED=false.

## Collecte des journaux

Mode local : copiez les fichiers vers shared_logs/soc et shared_logs/victim.
Depuis PowerShell avec OpenSSH :

    scp ubuntu@192.168.231.128:/var/log/suricata/eve.json shared_logs/soc/eve.json
    scp ubuntu@192.168.231.128:/var/log/suricata/fast.log shared_logs/soc/fast.log
    scp ubuntu@192.168.231.129:/var/log/apache2/access.log shared_logs/victim/apache_access.log
    scp ubuntu@192.168.231.129:/var/log/apache2/error.log shared_logs/victim/apache_error.log
    scp ubuntu@192.168.231.129:/var/log/auth.log shared_logs/victim/auth.log
    scp ubuntu@192.168.231.129:/var/log/syslog shared_logs/victim/syslog

Le mode SSH utilise Paramiko avec les clés/agent SSH ou, pour le laboratoire,
la variable locale `SSH_PASSWORD` dans `.env` (fichier ignoré par Git). Les clés
hôtes doivent déjà figurer dans `known_hosts`; en cas d'échec, le programme
utilise les fichiers locaux. Une clé SSH reste recommandée hors laboratoire.

## Alertes SIEM ELK et Splunk

Les exports `shared_logs/siem/elastic_alerts.jsonl` et `splunk_alerts.jsonl`
sont chargés en mode laboratoire. Pour une intégration réelle, renseignez
`ELASTIC_URL`/`ELASTIC_API_KEY` ou `SPLUNK_URL`/`SPLUNK_TOKEN`. Les données ECS
Elastic et les résultats Splunk sont normalisés dans le même schéma Pydantic.
En cas d'indisponibilité, le connecteur utilise l'export local et inscrit un
avertissement sans exposer les jetons.

## Exécution

    python -m ai_backend.main
    python -m ai_backend.main --mode local --limit 500
    python -m ai_backend.main --mode ssh
    streamlit run dashboard/app.py
    pytest -q
    python -m ai_backend.experiments --runs 10
    python -m ai_backend.experiments --runs 3 --with-ollama

Le dépôt contient un petit jeu de journaux de laboratoire reproductible. Chaque
exécution crée automatiquement les dossiers, soc_ai.db, les rapports et la
piste d'audit. Voir aussi le [guide d'installation](docs/guide_installation.md).

Le dashboard permet à l'analyste de qualifier un incident. Après au moins trois
labels, les seuils concernés peuvent évoluer dans des bornes strictes de 3 à 10.
Les blocages, isolations et remédiations restent toujours des simulations.

Guide détaillé : [installation des VM et des SIEM](docs/installation_vms_siem.md).

Rapport complet : [architecture, agents et expérimentation](docs/rapport_final_projet.md).
