# Rapport d'incident — Web reconnaissance correlation

## Identification

- **Identifiant :** INC-2E99A1CDDC63
- **Horodatage de détection :** 2026-06-21T12:04:00+00:00
- **Sévérité :** Medium
- **Confiance :** 90%
- **Statut :** open

## Périmètre

- **Adresse source :** 192.168.231.1
- **Adresse destination :** 192.168.231.129
- **Hôte affecté :** ubuntu2404
- **Type :** SIEM correlated alert
- **MITRE ATT&CK :** Initial Access / T1190 - Exploit Public-Facing Application

## Éléments de preuve

- Splunk correlation search matched sensitive path enumeration

## Analyse SOC

La corrélation déterministe a regroupé 1 événement(s) compatible(s) avec « SIEM correlated alert ». La sévérité Medium repose sur la fréquence, la nature des signatures et les actifs concernés. Cette conclusion doit être validée par un analyste.

## Mesures recommandées

Vérifier la chronologie et les journaux de l'hôte, confirmer la légitimité de la source, conserver les preuves et appliquer une mesure de confinement uniquement après validation humaine.

## Actions de réponse simulées

- SIMULATED_NOTIFY_ADMIN : notification locale auditée.
- SIMULATED_CREATE_TICKET : création d'un ticket fictif.
- SIMULATED_REMEDIATION_PLAYBOOK : préparation d'une remédiation contrôlée.
- SIMULATED_MARK_CONTAINED : passage au statut de confinement simulé.

Ces actions sont ajoutées au journal d'audit après génération du rapport. Aucun blocage, isolement ou changement système réel n'est exécuté.

## Limites

Cette analyse est produite à partir des seuls journaux disponibles. La corrélation et l'explication du SLM peuvent contenir des incertitudes. Une validation humaine et des sources complémentaires sont nécessaires avant toute réponse réelle.
