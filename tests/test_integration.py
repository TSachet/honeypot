"""Tests d'intégration : on simule de vraies attaques sur les sockets puis on vérifie le journal JSONL.

Deux modes :
- par défaut : les leurres sont démarrés dans le processus de test, sur des ports libres.
- HONEYPOT_EXTERNAL=1 : on attaque un honeypot déjà lancé (ex: `docker compose up`) via les ports
  publiés (HOST_PORT_* ou valeurs par défaut) et on relit ./logs/events.jsonl.
"""
import ftplib
import http.client
import json
import os
import socket
import threading
import time
from pathlib import Path

import paramiko
import pytest

from src.core.multiplexeur import demarrer_multiplexeur
from src.main import construire_handlers
from src.services.honeypot_ftp import demarrer_honeypot_ftp
from src.services.honeypot_http import demarrer_honeypot_http
from src.services.honeypot_mysql import demarrer_honeypot_mysql
from src.services.honeypot_redis import demarrer_honeypot_redis
from src.services.honeypot_ssh import demarrer_honeypot_ssh

HOTE = "127.0.0.1"
EXTERNE = os.getenv("HONEYPOT_EXTERNAL") == "1"


def port_libre():
    with socket.socket() as s:
        s.bind((HOTE, 0))
        return s.getsockname()[1]


def attendre_port(port, delai=5):
    fin = time.time() + delai
    while time.time() < fin:
        try:
            with socket.create_connection((HOTE, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"le port {port} ne répond pas")


def lancer(cible, **kwargs):
    threading.Thread(target=cible, kwargs=kwargs, daemon=True).start()


class Honeypot:
    def __init__(self, ports, journal):
        self.ports = ports
        self.journal = Path(journal)

    def evenements(self):
        if not self.journal.exists():
            return []
        return [json.loads(l) for l in self.journal.read_text(encoding="utf-8").splitlines() if l.strip()]

    def attendre_evenement(self, condition, delai=5):
        #le serveur logue parfois juste après avoir répondu : on interroge le journal jusqu'au délai
        fin = time.time() + delai
        while time.time() < fin:
            for e in self.evenements():
                if condition(e):
                    return e
            time.sleep(0.1)
        pytest.fail(f"événement attendu absent du journal : {self.evenements()}")


@pytest.fixture(scope="module")
def honeypot(tmp_path_factory):
    if EXTERNE:
        defauts = {"ftp": 21, "ssh": 22, "http": 80, "redis": 6379, "mysql": 3306, "mux": 9000}
        ports = {k: int(os.getenv(f"HOST_PORT_{k.upper()}", v)) for k, v in defauts.items()}
        journal = os.getenv("LOG_FILE", "logs/events.jsonl")
        return Honeypot(ports, journal)

    journal = tmp_path_factory.mktemp("logs") / "events.jsonl"
    os.environ["LOG_FILE"] = str(journal)
    os.environ["SSH_SANDBOX"] = "simulate"
    ports = {k: port_libre() for k in ("ftp", "ssh", "http", "redis", "mysql", "mux")}

    lancer(demarrer_honeypot_ftp, hote=HOTE, port=ports["ftp"])
    lancer(demarrer_honeypot_ssh, hote=HOTE, port=ports["ssh"])
    lancer(demarrer_honeypot_http, hote=HOTE, port=ports["http"])
    lancer(demarrer_honeypot_redis, hote=HOTE, port=ports["redis"])
    lancer(demarrer_honeypot_mysql, hote=HOTE, port=ports["mysql"])
    lancer(
        demarrer_multiplexeur,
        handlers=construire_handlers(), hote=HOTE, port=ports["mux"], defaut="FTP", delai_detection=0.5,
    )
    for p in ports.values():
        attendre_port(p)
    yield Honeypot(ports, journal)
    os.environ.pop("LOG_FILE", None)


def test_attaque_ftp_est_journalisee(honeypot):
    ftp = ftplib.FTP()
    ftp.connect(HOTE, honeypot.ports["ftp"], timeout=5)
    ftp.login("admin", "motdepasse_ftp_test")
    ftp.quit()

    e = honeypot.attendre_evenement(lambda e: e["protocole"] == "FTP_AUTH" and e["donnees"].get("pass") == "motdepasse_ftp_test")
    assert e["ip_source"] == "127.0.0.1"
    assert isinstance(e["port_source"], int)


def test_attaque_ssh_identifiants_et_commande(honeypot):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOTE, honeypot.ports["ssh"], username="root", password="ssh_pass_test",
                   allow_agent=False, look_for_keys=False, timeout=10)
    canal = client.invoke_shell()
    canal.settimeout(5)
    canal.recv(1024)  #bannière + prompt
    canal.send("whoami\n")
    time.sleep(0.5)
    reponse = canal.recv(1024).decode(errors="ignore")
    client.close()

    assert "root" in reponse
    honeypot.attendre_evenement(
        lambda e: e["protocole"] == "SSH_AUTH" and e["donnees"] == {"nom_utilisateur": "root", "mot_de_passe": "ssh_pass_test"}
    )
    honeypot.attendre_evenement(lambda e: e["protocole"] == "SSH_CMD" and e["donnees"]["commande"] == "whoami")


def test_attaque_http_scan_env(honeypot):
    conn = http.client.HTTPConnection(HOTE, honeypot.ports["http"], timeout=5)
    conn.request("GET", "/.env")
    corps = conn.getresponse().read().decode()
    conn.close()

    assert "DB_PASS=" in corps
    honeypot.attendre_evenement(lambda e: e["protocole"] == "HTTP" and e["donnees"]["chemin"] == "/.env")


def test_attaque_redis_ping(honeypot):
    with socket.create_connection((HOTE, honeypot.ports["redis"]), timeout=5) as s:
        s.sendall(b"PING\r\n")
        assert s.recv(64) == b"+PONG\r\n"
    honeypot.attendre_evenement(lambda e: e["protocole"] == "REDIS_CMD" and "PING" in e["donnees"]["commande"])


def test_attaque_mysql_login(honeypot):
    with socket.create_connection((HOTE, honeypot.ports["mysql"]), timeout=5) as s:
        assert b"5.7.40-log" in s.recv(256)
        s.sendall(b"\x20\x00\x00\x01\x85\xa6\x3f\x20root\x00")
        assert b"Access denied" in s.recv(256)
    honeypot.attendre_evenement(lambda e: e["protocole"] == "MYSQL_AUTH" and "726f6f74" in e["donnees"]["charge_utile_hex"])


# ---------- multiplexeur (payload detection) ----------

def test_multiplexeur_aiguille_http(honeypot):
    with socket.create_connection((HOTE, honeypot.ports["mux"]), timeout=5) as s:
        s.sendall(b"GET /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b"WordPress" in s.recv(4096)
    honeypot.attendre_evenement(
        lambda e: e["protocole"] == "MUX_DETECTION" and e["donnees"]["protocole_detecte"] == "HTTP" and e["donnees"]["methode"] == "payload"
    )


def test_multiplexeur_aiguille_redis(honeypot):
    with socket.create_connection((HOTE, honeypot.ports["mux"]), timeout=5) as s:
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        assert s.recv(64) == b"+PONG\r\n"
    honeypot.attendre_evenement(lambda e: e["protocole"] == "MUX_DETECTION" and e["donnees"]["protocole_detecte"] == "REDIS")


def test_multiplexeur_client_muet_bascule_sur_defaut(honeypot):
    with socket.create_connection((HOTE, honeypot.ports["mux"]), timeout=5) as s:
        assert s.recv(64).startswith(b"220 ")
    honeypot.attendre_evenement(
        lambda e: e["protocole"] == "MUX_DETECTION" and e["donnees"]["methode"] == "defaut_client_muet"
    )


def test_multiplexeur_protocole_inconnu_est_capture(honeypot):
    with socket.create_connection((HOTE, honeypot.ports["mux"]), timeout=5) as s:
        s.sendall(b"\x01\x02\x03payload-bizarre")
    honeypot.attendre_evenement(lambda e: e["protocole"] == "RAW_INCONNU")
