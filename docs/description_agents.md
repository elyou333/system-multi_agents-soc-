# Description des agents

Tous les agents sont IA-assistés par Phi-3 via Ollama, mais les décisions
critiques restent contrôlées par des règles Python afin de garantir
l'explicabilité, la sécurité et la traçabilité.

| Agent | Utilisation de Phi-3 | Décision critique faite par |
|---|---|---|
| Extracteur | Compréhension bornée de quelques logs ambigus | Python et les parseurs |
| Analyseur | Explication et recommandation | Python et les règles de corrélation |
| Rapporteur | Rédaction d'une synthèse professionnelle | Python pour la structure, Phi-3 pour le texte |
| Exécuteur | Proposition d'une action simulée | Python avec liste blanche |

## Agent Extracteur

Charge huit sources locales, dont les exports Elastic et Splunk, ou déclenche
d'abord une copie SSH. Des API SIEM optionnelles permettent aussi de lire
Elastic `_search` et Splunk `search/jobs/export`. Il conserve les
lignes brutes, ne garde que les événements utiles et les transforme dans un
schéma Pydantic commun. Une ligne invalide devient un avertissement, jamais un
arrêt global. Pour au plus trois lignes ambiguës d'un lot, Phi-3 peut ajouter
une note de lecture de faible sévérité. Il ne remplace jamais les parseurs et ne
décide aucun champ critique.

## Agent Analyseur

Regroupe les échecs SSH, les indices de reconnaissance web et les alertes réseau
par source. Des règles déterministes fixent le type, la sévérité, la confiance
et le mapping MITRE ATT&CK. Phi-3 formule ensuite une explication courte. Si
Ollama est absent, une explication locale de repli est utilisée.

## Agent Rapporteur

Génère un fichier Markdown français par incident avec identification, preuves,
périmètre, analyse, recommandations, limites et rappel de simulation. Phi-3
ajoute une synthèse professionnelle, sans modifier la structure contrôlée par
Python. En cas d'échec, le rapport déterministe original est conservé.

## Agent Exécuteur

Écrit uniquement des artefacts locaux : blocklist simulée, notification,
ticket, plan d'isolation, playbook de remédiation et statut contained_simulated.
Phi-3 peut proposer une action parmi quatre identifiants simulés. Python rejette
toute proposition hors liste blanche ou incompatible avec l'incident. Toutes
les actions sont historisées dans SQLite. Il ne contient aucun appel système de
pare-feu, d'arrêt de service, de suppression ou d'isolement réel.

## Boucle adaptative supervisée

Le dashboard collecte les verdicts vrai positif, faux positif ou à revoir. Les
seuils changent seulement après trois validations et restent compris entre 3 et
10. Cette adaptation est explicable, réversible et sans apprentissage autonome
sur les sorties du SLM.
