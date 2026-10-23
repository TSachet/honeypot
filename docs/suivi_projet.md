##### **12/10/2026 :**



**Gestion des logs (gestionnaire\_logs.py)** : Un module central pour écrire chaque attaque au format JSON (journal\_attaques.json).



**SSH interactif + Sandbox (honeypot\_ssh.py)** : Un serveur SSH (via paramiko) qui accepte tous les mots de passe, simule un shell et exécute les commandes de l'attaquant dans un conteneur Docker alpine totalement isolé sans réseau (--network none).



**Modules interactifs dédiés :**



**HTTP (honeypot\_http.py) :** Fausse page WordPress (/wp-login.php), leurre sur les fichiers .env et fausse 404.



**FTP (honeypot\_ftp.py) :** Simulation des commandes USER, PASS, PWD, CWD, et capture des tentatives STOR/RETR.



**Redis (honeypot\_redis.py) :** Capture des commandes INFO, PING, AUTH.



**MySQL (honeypot\_mysql.py) :** Envoi du handshake binaire MySQL 5.7 et capture du paquet de login.



**Moteur générique (honeypot\_generique.py) :** Un socket générique pour gérer en faible interaction les autres protocoles (Telnet, SMTP, POP3, LDAP, RDP).



**Point d'entrée (main.py) :** Un script multi-threadé qui lance tous les services en parallèle sur leurs ports respectifs.



**Arborescence \& Git :** Structuration propre dans sources/services/ avec les \_\_init\_\_.py, le requirements.txt (paramiko), et le tout pushé sur GitHub.





##### **23/10/2026 :**

**Restructuration (Phase 1) :** passage à `src/core` (config, logs, détecteur, multiplexeur) et `src/services`, ports lus via `.env` (`python-dotenv`), logs JSONL dans `logs/events.jsonl`, écoute sur `0.0.0.0`.

**Corrections de bugs :** imports `sources.` -> `src.` ; FTP et MySQL passaient le tuple `(ip, port)` à la place de l'IP et du port dans les logs ; variable `transport` non initialisée dans le SSH ; longueur RESP de la réponse Redis `INFO`.

**Conteneurisation (Phase 2) :** `Dockerfile` (python:3.11-slim, utilisateur non-root) et `docker-compose.yml` (mapping 21/22/80..., volume `./logs`, conteneur durci). Le SSH utilise par défaut un shell simulé (`SSH_SANDBOX=simulate`) car le conteneur n'a pas accès à Docker.

**Tests (Phase 3) :** `test_unitaires.py` et `test_integration.py` (ftplib, paramiko, sockets, vérification de `events.jsonl`), CI GitHub Actions.

**Payload detection :** `detecteur_payload.py` + `multiplexeur.py` (port unique 9000, détection par les premiers octets, inspiré de Honeytrap).

**À faire :** mettre à jour le schéma d'architecture (diagramme_archi.jpg), tester `docker compose up` sur une machine avec Docker lancé, préparer la soutenance.
