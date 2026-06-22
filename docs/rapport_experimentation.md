# Rapport d'expérimentation

## Protocole

Le jeu de démonstration fourni simule une connexion HTTP observée par Suricata,
trois requêtes de reconnaissance web, cinq échecs SSH, une erreur Apache et un
événement système suspect. Les métriques réelles de chaque essai sont conservées
dans la table runs et affichées dans Streamlit.

## Résultat de la démonstration locale initiale du 21 juin 2026

| Mesure | Valeur |
|---|---:|
| Lignes brutes analysées | 14 |
| Événements normalisés | 13 |
| Incidents générés | 6 |
| Actions simulées | 21 |
| Tests de parseurs | 5/5 réussis |

Cette mesure historique est conservée comme référence avant l'ajout SIEM. Le
benchmark reproductible actuel, avec précision, rappel, F1, durée, écart-type et
mémoire, est généré dans [rapport_experimentation_genere.md](rapport_experimentation_genere.md).
La suite automatisée comprend désormais 10 tests.

Cet essai a été exécuté avec Ollama désactivé afin de valider indépendamment le
repli déterministe. Les résultats de production dépendent des journaux copiés;
chaque nouvelle mesure reste consultable dans runs.

## Classification

Les seuils sont explicites : cinq échecs SSH déclenchent une suspicion de brute
force de sévérité High; les chemins web sensibles déclenchent une reconnaissance
de sévérité Medium ou High selon le volume; les priorités Suricata sont
converties en Low, Medium, High ou Critical. La confiance augmente avec le nombre
d'indices sans dépasser 1.

## Rôle et limites du SLM

phi3 reformule les preuves et les recommandations en français. Il n'attribue pas
le type ni la sévérité. Ses limites incluent hallucination, sensibilité au
prompt, fenêtre de contexte et latence matérielle. Le repli déterministe assure
la continuité mais produit une analyse moins contextualisée.

## Performance et reproductibilité

Le traitement local évite la dépendance au réseau. Le paramètre --limit borne la
lecture lors d'un essai. Le script `python -m ai_backend.experiments` répète les
essais, mesure durée et mémoire, puis compare les incidents à une vérité terrain
versionnée. L'option `--with-ollama` mesure séparément Phi-3; son coût rend utile
un nombre de répétitions adapté au matériel.

## Améliorations futures

- corrélation temporelle glissante stricte et déduplication eve/fast;
- enrichissement local des IOC et inventaire des actifs;
- élargissement de la vérité terrain à des datasets publics et à davantage d'attaques;
- gestion incrémentale des offsets de fichiers;
- authentification du dashboard et chiffrement des données sensibles;
- validation humaine formalisée avant toute intégration de réponse réelle.
