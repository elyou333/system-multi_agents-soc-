# Rapport d'incident — Reconnaissance web depuis 192.168.231.1

## Identification

- **Identifiant :** INC-CD03A0EA5E7D
- **Horodatage de détection :** 2026-06-21T12:00:04+00:00
- **Sévérité :** Medium
- **Confiance :** 75%
- **Statut :** open

## Périmètre

- **Adresse source :** 192.168.231.1
- **Adresse destination :** Non déterminée
- **Hôte affecté :** Non déterminé
- **Type :** Web reconnaissance
- **MITRE ATT&CK :** Reconnaissance / T1595 - Active Scanning

## Éléments de preuve

- GET /.env -> 404
- GET /wp-admin -> 404
- GET /phpmyadmin -> 404

## Analyse SOC

La corrélation déterministe a regroupé 3 événement(s) compatible(s) avec « Web reconnaissance ». La sévérité Medium repose sur la fréquence, la nature des signatures et les actifs concernés. Cette conclusion doit être validée par un analyste.

## Mesures recommandées

Vérifier la chronologie et les journaux de l'hôte, confirmer la légitimité de la source, conserver les preuves et appliquer une mesure de confinement uniquement après validation humaine.

## Actions de réponse simulées

- SIMULATED_NOTIFY_ADMIN : notification locale auditée.
- SIMULATED_CREATE_TICKET : création d'un ticket fictif.
- SIMULATED_MARK_CONTAINED : passage au statut de confinement simulé.

Ces actions sont ajoutées au journal d'audit après génération du rapport. Aucun blocage, isolement ou changement système réel n'est exécuté.

## Limites

Cette analyse est produite à partir des seuls journaux disponibles. La corrélation et l'explication du SLM peuvent contenir des incertitudes. Une validation humaine et des sources complémentaires sont nécessaires avant toute réponse réelle.
