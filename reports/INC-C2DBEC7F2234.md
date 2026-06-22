# Rapport d'incident — Possible credential access after SSH failures

## Identification

- **Identifiant :** INC-C2DBEC7F2234
- **Horodatage de détection :** 2026-06-21T12:03:00+00:00
- **Sévérité :** High
- **Confiance :** 90%
- **Statut :** open

## Périmètre

- **Adresse source :** 192.168.231.1
- **Adresse destination :** 192.168.231.129
- **Hôte affecté :** ubuntu2404
- **Type :** SIEM correlated alert
- **MITRE ATT&CK :** Credential Access / T1110 - Brute Force

## Éléments de preuve

- Elastic detection rule matched repeated authentication failures

## Analyse SOC

La corrélation déterministe a regroupé 1 événement(s) compatible(s) avec « SIEM correlated alert ». La sévérité High repose sur la fréquence, la nature des signatures et les actifs concernés. Cette conclusion doit être validée par un analyste.

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
