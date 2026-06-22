# Rapport d'incident — Web reconnaissance correlation

## Identification

- **Identifiant :** INC-EB27DAD9870F
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

L'alerte SIEM liée à la corrélation a été émise avec une sévéritité moyenne, indiquant que l'incident pourrait potentner affecter les opérations mais n'est pas immédiatement critique. La confiance de 0.9 suggère qu'il y a un fort niveau d'assurance dans la validité des preuves fournies par le SIEM, qui incluent une recherche de corrélation au sein du système Splunk ayant révélé une tentative d'enumeration sensible sur un chemin réseau. La source et la destination indiquent que l'activité suspecte s'est produite entre des machines internes à l'organisation sans qu'il y ait de communication externe directement liée, ce qui pourrait impliquer une menace interne ou une vulnérabilité exploitée.

## Mesures recommandées

Il est recommandé d'examiner immédiatement les machines concernées par l'alerte SIEM et de vérifier s'il y a eu des modifications non autorisées sur ces systèmes, en particulier dans le chemin réseau mentionné. Une enquête plus approfondie devrait être menée pour identifier la source interne du comportement suspecté, si possible sans perturber les opérations normales de l'entreprise. Il est également conseillé d'effectuer une mise à jour des systèmes et un renforcement des politiques de sécurité réseau afin de prévenir tout autre tentative similaire ou liée à cette alerte, en sachant que la confiance dans les alertes SIEM reste élevée.

## Actions de réponse simulées

- SIMULATED_NOTIFY_ADMIN : notification locale auditée.
- SIMULATED_CREATE_TICKET : création d'un ticket fictif.
- SIMULATED_REMEDIATION_PLAYBOOK : préparation d'une remédiation contrôlée.
- SIMULATED_MARK_CONTAINED : passage au statut de confinement simulé.

Ces actions sont ajoutées au journal d'audit après génération du rapport. Aucun blocage, isolement ou changement système réel n'est exécuté.

## Limites

Cette analyse est produite à partir des seuls journaux disponibles. La corrélation et l'explication du SLM peuvent contenir des incertitudes. Une validation humaine et des sources complémentaires sont nécessaires avant toute réponse réelle.
