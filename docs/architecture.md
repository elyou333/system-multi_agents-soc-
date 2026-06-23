# Architecture du laboratoire

## Composants

- **Hôte Windows** : VS Code, Python 3.11, Git et Ollama. Il exécute LangGraph,
  SQLite et Streamlit.
- **VM SOC Ubuntu (ubuntu2404)** : Suricata écoute ens37 et écrit eve.json et
  fast.log.
- **VM victime Ubuntu (ubuntu2404)** : Apache, SSH et journaux Linux.

## Plan d'adressage

| Machine | Interface | Adresse |
|---|---|---|
| SOC Ubuntu | NAT ens33 | 192.168.10.132 |
| SOC Ubuntu | Host-only ens37 | 192.168.231.128 |
| Victime Ubuntu | NAT ens33 | 192.168.10.133 |
| Victime Ubuntu | Host-only ens37 | 192.168.231.129 |
| Hôte Windows | Adaptateur lab | 192.168.231.1 (habituel) |

## Flux de données

    Elastic / Splunk / Suricata / Apache / auth.log / syslog
                      |
              Agent Extracteur
                      | parsing Python + note Phi-3 bornée
              Agent Analyseur
                      | règles Python + explication Phi-3
              Agent Rapporteur
                      | structure Python + synthèse Phi-3
              Agent Exécuteur
                      | liste blanche Python + proposition Phi-3
                      v
           SQLite / audit / Dashboard

Le dashboard renvoie les verdicts analyste dans `analyst_feedback`. Au prochain
lot, un profil adaptatif calcule des seuils bornés pour le brute force SSH, la
reconnaissance web et le scan de ports. Trois labels au minimum sont exigés;
aucun feedback ne peut activer une action système réelle.

L'état LangGraph partagé contient raw_events, normalized_events, incidents,
reports, actions, errors et run_metadata. La persistance est la dernière étape
afin d'enregistrer un lot cohérent et son statut.

## Frontières de confiance

Les journaux et toutes les sorties du SLM sont non fiables. Les parseurs ignorent les
lignes invalides et les erreurs sont inscrites dans runs.errors. L'analyse
déterministe conserve l'autorité sur le type, la sévérité et la confiance.
L'exécuteur ne possède aucune primitive de blocage ou d'isolation réelle.
Il produit uniquement une blocklist locale, des notifications, un plan
d'isolation JSONL et un playbook de remédiation auditable.
