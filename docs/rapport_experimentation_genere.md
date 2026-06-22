# Rapport expérimental reproductible

Généré le 2026-06-21T20:29:15.852938+00:00 à partir du jeu de laboratoire versionné et de sa vérité terrain.

## Efficacité de détection

| Mesure | Valeur |
|---|---:|
| Vrais positifs | 8 |
| Faux positifs | 0 |
| Faux négatifs | 0 |
| Précision | 100.00% |
| Rappel | 100.00% |
| F1 | 100.00% |

## Performance

| Variante | Répétitions | Durée moyenne (s) | Écart-type (s) | Mémoire pic (MB) |
|---|---:|---:|---:|---:|
| deterministic | 3 | 0.0138 | 0.0078 | 0.074 |
| ollama_phi3 | 3 | 27.2040 | 1.6087 | 9.069 |

## Protocole et limites

- Les incidents sont comparés comme un multiensemble `(type, IP source)` à `experiments/ground_truth.json`.
- La variante déterministe mesure parsing, normalisation, corrélation et repli local.
- La variante Ollama, lorsqu'elle est demandée, ajoute l'enrichissement Phi-3 pour chaque incident.
- Ce petit dataset de laboratoire valide la reproductibilité, pas une précision de production.
- Les mesures dépendent du matériel, de la charge et de l'état du modèle local.
