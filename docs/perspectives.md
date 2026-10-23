# Perspectives

## 1. Payload detection (multiplexage)

**Implémenté** (`src/core/detecteur_payload.py`, `src/core/multiplexeur.py`) : un port unique accepte toutes les
connexions, inspecte les premiers octets (`MSG_PEEK`) et aiguille vers le bon leurre.
L'approche est celle du framework [Honeytrap](https://github.com/honeytrap/honeytrap) (listener unique + détection du
protocole + services interchangeables), réécrite en Python avec des signatures simples (regex sur les premiers octets).

Points forts pour la soutenance :
- un attaquant qui scanne un seul port voit **tous** les services ;
- chaque décision est tracée (`MUX_DETECTION` avec signature hexadécimale) : on mesure ce que les scanners envoient vraiment ;
- le détecteur est une fonction pure, testée par 15+ cas paramétrés.

Pistes d'amélioration :
- **Protocoles « serveur d'abord »** (FTP, SMTP, MySQL, POP3) : le client n'envoie rien, on bascule aujourd'hui sur un
  service par défaut. Piste : retrouver le port de destination d'origine (redirection `iptables REDIRECT` +
  `SO_ORIGINAL_DST`) pour router vers le bon leurre sans attendre.
- Signatures supplémentaires (SMB, VNC, MQTT, Modbus...) et score de confiance plutôt que « première signature gagnante ».
- Après détection, enrichir l'événement : empreinte JA3 des handshakes TLS, user-agent HTTP, famille de botnet probable.
- Capture et analyse automatique des payloads/fichiers déposés (hash, VirusTotal, sandbox).

## 2. Intégration SIEM (Stack ELK)

Le format **JSON Lines** (`logs/events.jsonl`) est directement exploitable :

```mermaid
flowchart LR
    H["Honeypot (Docker)"] -->|"logs/events.jsonl"| F["Filebeat"]
    F --> L["Logstash (optionnel)"]
    L --> E["Elasticsearch"]
    F --> E
    E --> K["Kibana : dashboards"]
```

1. **Filebeat** lit `logs/events.jsonl` (`json.keys_under_root: true`).
2. **Elasticsearch** indexe ; l'`horodatage` (UTC, ISO 8601) devient le `@timestamp`.
3. **Kibana** : top IP sources, mots de passe les plus testés, commandes SSH, carte GeoIP (processeur `geoip` sur `ip_source`).
4. Alertes : même IP touchant plusieurs protocoles, commande `wget|curl` en SSH, accès à `/.env`.

Extension possible : un « pusher » (concept de Honeytrap) directement dans `gestionnaire_logs.py` pour envoyer
les événements à Elasticsearch/Syslog sans passer par un fichier.

## 3. Autres idées

- Géolocalisation / réputation des IP (AbuseIPDB).
- Limitation du débit par IP pour éviter qu'un seul bot sature les threads.
- Rotation des logs (`logrotate`) pour un déploiement longue durée.
- Moyenne interaction supplémentaire : Telnet et SMTP interactifs, SQL basique pour MySQL.
