# Guide d'installation et d'exploitation

## 1. Préparer Windows

Installer Python 3.11, Git, VS Code et Ollama. Cloner ou copier le projet dans
C:\SOC-AI-Agent, puis ouvrir PowerShell dans ce dossier.

    py -3.11 -m venv venv
    .\venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    Copy-Item .env.example .env

Si PowerShell bloque le script d'activation, exécuter temporairement
Set-ExecutionPolicy -Scope Process Bypass.

## 2. Préparer Ollama

    ollama pull phi3
    ollama list

Ollama doit tourner sur l'hôte Windows. Le workflow continue sans lui grâce à
l'explication de repli. Pour forcer ce mode, placer OLLAMA_ENABLED=false dans
.env.

## 3. Préparer les VM

Vérifier Suricata sur la VM SOC :

    sudo systemctl status suricata
    sudo tail -f /var/log/suricata/eve.json

Vérifier Apache et SSH sur la victime :

    sudo systemctl status apache2 ssh
    sudo tail -f /var/log/apache2/access.log /var/log/auth.log

La lecture SSH doit être autorisée explicitement à l'utilisateur ubuntu (par
groupe, ACL ou copie contrôlée). Ne jamais rendre les journaux sensibles
universellement lisibles.

## 4. Importer les journaux

Les commandes SCP complètes figurent dans le README. Le mode automatique utilise
une clé SSH ou ssh-agent et known_hosts; aucun mot de passe n'est codé. Configurer
SSH_KEY_PATH si nécessaire, puis exécuter :

    python -m ai_backend.main --mode ssh --limit 500

Si la connexion échoue, les copies déjà présentes dans shared_logs sont
analysées et l'échec est consigné comme avertissement.

## 5. Lancer et vérifier

    pytest -q
    python -m ai_backend.main --mode local
    streamlit run dashboard/app.py

## 6. Connecter un SIEM (optionnel)

Pour Elastic Security, définir `ELASTIC_URL`, `ELASTIC_INDEX` et
`ELASTIC_API_KEY`. Pour Splunk, définir `SPLUNK_URL`, `SPLUNK_TOKEN` et
`SPLUNK_SEARCH`. Conserver `SIEM_VERIFY_SSL=true` en production. Si aucune API
n'est configurée, les exports JSONL de `shared_logs/siem` servent de simulation.

## 7. Mesurer le système

    python -m ai_backend.experiments --runs 10
    python -m ai_backend.experiments --runs 3 --with-ollama

Les résultats JSON sont enregistrés dans `experiments/results/latest.json` et
le rapport lisible dans `docs/rapport_experimentation_genere.md`.

Vérifier les rapports, audit/blocklist.txt, audit/notifications.log et
soc_ai.db. Toute action est simulée : aucune commande de pare-feu ou d'isolement
n'est appelée.
