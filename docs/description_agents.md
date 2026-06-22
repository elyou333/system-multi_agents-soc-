# Description des agents

## Agent Extracteur

Charge huit sources locales, dont les exports Elastic et Splunk, ou déclenche
d'abord une copie SSH. Des API SIEM optionnelles permettent aussi de lire
Elastic `_search` et Splunk `search/jobs/export`. Il conserve les
lignes brutes, ne garde que les événements utiles et les transforme dans un
schéma Pydantic commun. Une ligne invalide devient un avertissement, jamais un
arrêt global.

## Agent Analyseur

Regroupe les échecs SSH, les indices de reconnaissance web et les alertes réseau
par source. Des règles déterministes fixent le type, la sévérité, la confiance
et le mapping MITRE ATT&CK. phi3 formule ensuite une explication courte. Si
Ollama est absent, une explication locale de repli est utilisée.

## Agent Rapporteur

Génère un fichier Markdown français par incident avec identification, preuves,
périmètre, analyse, recommandations, limites et rappel de simulation. Il crée
aussi un résumé adapté au tableau de bord.

## Agent Exécuteur

Écrit uniquement des artefacts locaux : blocklist simulée, notification,
ticket, plan d'isolation, playbook de remédiation et statut contained_simulated.
Toutes les actions sont historisées dans
SQLite. Il ne contient aucun appel système de pare-feu, d'arrêt de service, de
suppression ou d'isolement réel.

## Boucle adaptative supervisée

Le dashboard collecte les verdicts vrai positif, faux positif ou à revoir. Les
seuils changent seulement après trois validations et restent compris entre 3 et
10. Cette adaptation est explicable, réversible et sans apprentissage autonome
sur les sorties du SLM.
