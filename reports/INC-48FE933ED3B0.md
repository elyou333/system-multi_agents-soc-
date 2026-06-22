# Rapport d'incident — Suspicion de brute force SSH depuis 192.168.231.1

## Identification

- **Identifiant :** INC-48FE933ED3B0
- **Horodatage de détection :** 2026-06-21T12:01:00+00:00
- **Sévérité :** High
- **Confiance :** 90%
- **Statut :** open

## Périmètre

- **Adresse source :** 192.168.231.1
- **Adresse destination :** Non déterminée
- **Hôte affecté :** ubuntu2404
- **Type :** SSH brute force suspicion
- **MITRE ATT&CK :** Credential Access / T1110 - Brute Force

## Éléments de preuve

- Failed password for invalid user admin from 192.168.231.1 port 55121 ssh2
- Failed password for invalid user admin from 192.168.231.1 port 55122 ssh2
- Failed password for invalid user admin from 192.168.231.1 port 55123 ssh2
- Failed password for invalid user admin from 192.168.231.1 port 55124 ssh2
- Failed password for invalid user admin from 192.168.231.1 port 55125 ssh2

## Analyse SOC

La corrélation déterministe a regroupé 5 événement(s) compatible(s) avec « SSH brute force suspicion ». La sévérité High repose sur la fréquence, la nature des signatures et les actifs concernés. Cette conclusion doit être validée par un analyste.

## Mesures recommandées

Vérifier la chronologie et les journaux de l'hôte, confirmer la légitimité de la source, conserver les preuves et appliquer une mesure de confinement uniquement après validation humaine.

## Actions de réponse simulées

- SIMULATED_BLOCK_IP : ajout local simulé de 192.168.231.1.
- SIMULATED_ISOLATE_HOST : plan d'isolation de ubuntu2404, soumis à validation humaine.
- SIMULATED_NOTIFY_ADMIN : notification locale auditée.
- SIMULATED_CREATE_TICKET : création d'un ticket fictif.
- SIMULATED_REMEDIATION_PLAYBOOK : préparation d'une remédiation contrôlée.
- SIMULATED_MARK_CONTAINED : passage au statut de confinement simulé.

Ces actions sont ajoutées au journal d'audit après génération du rapport. Aucun blocage, isolement ou changement système réel n'est exécuté.

## Limites

Cette analyse est produite à partir des seuls journaux disponibles. La corrélation et l'explication du SLM peuvent contenir des incertitudes. Une validation humaine et des sources complémentaires sont nécessaires avant toute réponse réelle.
