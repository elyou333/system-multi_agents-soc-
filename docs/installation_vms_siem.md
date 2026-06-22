# Installation des VM et des SIEM

## Ce qui est obligatoire

Le mode de démonstration ne nécessite pas d'installer ELK ou Splunk. Il utilise
les exports présents dans `shared_logs/siem`. Sur Windows, il suffit de préparer
l'environnement Python :

```powershell
cd "C:\Users\XPS\OneDrive\Desktop\soc-project-2"
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
streamlit run dashboard/app.py
```

Après une modification de `config.py`, arrêter Streamlit avec `Ctrl+C` et le
relancer. Un simple rafraîchissement du navigateur peut conserver d'anciens
modules Python en mémoire.

## VM SOC Ubuntu

Adresse prévue : `192.168.231.128`, interface de laboratoire `ens37`.

```bash
sudo apt update
sudo apt install -y suricata openssh-server acl
sudo systemctl enable --now ssh suricata
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo setfacl -Rm u:ubuntu:rX /var/log/suricata
sudo setfacl -m d:u:ubuntu:rX /var/log/suricata
sudo tail -f /var/log/suricata/eve.json
```

Dans `/etc/suricata/suricata.yaml`, vérifier que la section `af-packet` écoute
`ens37`. Suricata ne voit pas automatiquement tout le trafic d'un réseau
virtuel : pour une capture réelle, faire transiter le trafic par la VM SOC ou
configurer la mise en miroir du port virtuel.

## VM victime Ubuntu

Adresse prévue : `192.168.231.129`, interface de laboratoire `ens37`.

```bash
sudo apt update
sudo apt install -y apache2 openssh-server rsyslog acl
sudo systemctl enable --now apache2 ssh rsyslog
sudo setfacl -m u:ubuntu:rx /var/log /var/log/apache2
sudo setfacl -m u:ubuntu:r /var/log/auth.log /var/log/syslog
sudo setfacl -Rm u:ubuntu:rX /var/log/apache2
sudo setfacl -m d:u:ubuntu:rX /var/log/apache2
sudo systemctl status apache2 ssh rsyslog
```

Ne jamais utiliser `chmod 777` sur les journaux. Si `auth.log` n'existe pas,
vérifier `rsyslog` et consulter temporairement `journalctl -u ssh`.

## Vérification depuis Windows

```powershell
Test-NetConnection 192.168.231.128 -Port 22
Test-NetConnection 192.168.231.129 -Port 22
scp ubuntu@192.168.231.128:/var/log/suricata/eve.json shared_logs/soc/eve.json
scp ubuntu@192.168.231.129:/var/log/apache2/access.log shared_logs/victim/apache_access.log
scp ubuntu@192.168.231.129:/var/log/auth.log shared_logs/victim/auth.log
python -m ai_backend.main --mode ssh --limit 500
```

## ELK réel, optionnel

Ne pas installer Elasticsearch/Kibana sur la VM victime. Utiliser une troisième
VM Ubuntu dédiée, idéalement avec au moins 4 processeurs virtuels et 8 Go de RAM.
Suivre les paquets Debian officiels :

- <https://www.elastic.co/downloads/elasticsearch>
- <https://www.elastic.co/downloads/kibana>

Créer ensuite une clé API de lecture et configurer `.env` sur Windows :

```dotenv
SIEM_ENABLED=true
ELASTIC_URL=https://192.168.231.130:9200
ELASTIC_INDEX=.alerts-security.alerts-*,logs-*
ELASTIC_API_KEY=REMPLACER_PAR_UNE_CLE_LECTURE_SEULE
SIEM_VERIFY_SSL=true
```

Pour un certificat autosigné de laboratoire, `SIEM_VERIFY_SSL=false` peut être
utilisé temporairement. Ne jamais le conserver en production.

## Splunk réel, optionnel

Choisir Splunk **ou** ELK pour un petit laboratoire; ne pas installer les deux
sur la même VM. Utiliser une troisième VM dédiée et le paquet Linux officiel :

- <https://www.splunk.com/en_us/download/splunk-enterprise.html>

Activer le port de gestion `8089`, créer un jeton avec droits de recherche en
lecture seule, puis configurer `.env` :

```dotenv
SIEM_ENABLED=true
SPLUNK_URL=https://192.168.231.131:8089
SPLUNK_TOKEN=REMPLACER_PAR_UN_JETON_LECTURE_SEULE
SPLUNK_SEARCH=search index=* (tag=attack OR sourcetype=suricata)
SIEM_VERIFY_SSL=true
```

Les ports `9200`, `5601` et `8089` doivent rester limités au réseau host-only du
laboratoire. Ne pas les publier sur Internet.

## Choix recommandé pour la soutenance

1. Conserver ELK/Splunk en simulation JSON pour une démonstration stable.
2. Utiliser les deux VM existantes pour Suricata, Apache, SSH et les logs Linux.
3. Montrer que les API réelles sont configurables dans `.env` sans exposer de
   secret dans Git.
4. Si une intégration réelle est exigée, choisir un seul SIEM sur une troisième
   VM et conserver le repli JSON.
