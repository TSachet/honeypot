"""Configuration centralisée du honeypot.

Toutes les valeurs (ports, chemins, options) viennent de variables d'environnement,
éventuellement chargées depuis un fichier .env (python-dotenv) en local.
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv est optionnel : en Docker les variables sont injectées
    load_dotenv = None

#racine du projet (le dossier qui contient src/, logs/, .env...)
RACINE_PROJET = Path(__file__).resolve().parents[2]

#ports par défaut de chaque service (hauts ports : pas besoin d'être root)
PORTS_PAR_DEFAUT = {
    "HTTP": 8080,
    "SSH": 2222,
    "FTP": 2121,
    "REDIS": 6379,
    "MYSQL": 3306,
    "TELNET": 2323,
    "SMTP": 2525,
    "POP3": 1110,
    "LDAP": 3890,
    "RDP": 3389,
    "POSTGRESQL": 5432,
    "MUX": 9000,
}


def charger_env():
    """Charge le fichier .env s'il existe (sans écraser les variables déjà définies)."""
    if load_dotenv is not None:
        load_dotenv(RACINE_PROJET / ".env", override=False)


def hote_ecoute():
    """Interface d'écoute : 0.0.0.0 = toutes les interfaces (obligatoire sous Docker)."""
    return os.getenv("BIND_HOST", "0.0.0.0")


def port_service(nom, defaut=None):
    """Port d'un service, lu dans PORT_<NOM> (ex: PORT_SSH=2222)."""
    if defaut is None:
        defaut = PORTS_PAR_DEFAUT[nom.upper()]
    return int(os.getenv(f"PORT_{nom.upper()}", defaut))


def chemin_journal():
    """Chemin du journal JSONL. Relu à chaque appel pour rester configurable (et testable)."""
    valeur = os.getenv("LOG_FILE")
    if valeur:
        chemin = Path(valeur)
        return chemin if chemin.is_absolute() else RACINE_PROJET / chemin
    return RACINE_PROJET / "logs" / "events.jsonl"


def option_active(nom, defaut=True):
    """Lit une option booléenne (true/1/yes/on)."""
    valeur = os.getenv(nom)
    if valeur is None:
        return defaut
    return valeur.strip().lower() in ("1", "true", "yes", "on")
