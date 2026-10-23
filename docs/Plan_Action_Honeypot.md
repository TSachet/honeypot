# Projet Honeypot - Plan d'Action et état d'avancement

Arborescence cible réalisée dans ce dépôt (voir [README.md](../README.md)) :

```text
├── .gitignore  .env.example  .dockerignore  Dockerfile  docker-compose.yml  requirements.txt  pytest.ini
├── .github/workflows/ci.yml
├── docs/        (suivi_projet.md, Plan_Action_Honeypot.md, perspectives.md)
├── logs/        (.gitkeep)
├── src/         (main.py, core/, services/)
└── tests/       (test_unitaires.py, test_integration.py)
```

## Phase 1 : Restructuration du code

* [x] Déplacer les fichiers selon l'arborescence (`src/core`, `src/services`).
* [x] `python-dotenv` ajouté à `requirements.txt`.
* [x] `.env.example` créé (copier en `.env`, ignoré par git).
* [x] Ports lus via `os.getenv()` ([config.py](../src/core/config.py)).
* [x] Écoute sur `0.0.0.0` (`BIND_HOST`).
* [x] Logs JSONL dans `logs/events.jsonl` (verrou pour les threads).
* [x] Bugs corrigés : imports `sources.`, tuple ip/port en FTP et MySQL, `transport` non initialisé en SSH, longueur Redis INFO.

## Phase 2 : Conteneurisation

* [x] `Dockerfile` : `python:3.11-slim`, utilisateur non-root.
* [x] `docker-compose.yml` : mapping de ports (`21:2121`...), volume `./logs:/var/log/honeypot`, conteneur durci.
* [ ] **À faire par vous** : `docker compose up --build` sur une machine avec Docker lancé (le démon n'était pas démarré pendant la réalisation ; seule la syntaxe du compose a été validée avec `docker compose config`).

## Phase 3 : Validation et tests

* [x] `test_unitaires.py` (format JSON des logs, config, détecteur de payload).
* [x] `test_integration.py` (ftplib, paramiko, HTTP, Redis, MySQL, multiplexeur) avec `assert` sur `events.jsonl`.
* [x] CI GitHub Actions (`pytest` + build Docker).
* Résultat local : 36 tests passés.

## Payload detection (inspiré de Honeytrap)

* [x] [detecteur_payload.py](../src/core/detecteur_payload.py) : signatures sur les premiers octets (SSH, HTTP, Redis, FTP, SMTP, POP3, TLS, RDP, LDAP, Telnet, PostgreSQL).
* [x] [multiplexeur.py](../src/core/multiplexeur.py) : port unique (`PORT_MUX`, 9000), `MSG_PEEK`, aiguillage vers le bon leurre, événement `MUX_DETECTION`.

## Phase 4 : Soutenance

* [ ] **À faire par vous** : mettre à jour le schéma d'architecture (`diagramme_archi.jpg`) : flèches bidirectionnelles, séparer « Attaquant/Internet » et « Opérateur/Admin ». Un diagramme Mermaid du multiplexeur est déjà dans le README.
* [x] README avec lancement Docker en une ligne.
* [x] Argumentaire « Perspectives » : [perspectives.md](perspectives.md) (payload detection, SIEM / ELK).
