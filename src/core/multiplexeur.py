"""Multiplexeur : un seul port, plusieurs leurres.

La connexion entrante est inspectée (MSG_PEEK : les octets restent dans le socket),
le protocole est deviné par detecteur_payload, puis la connexion est transmise
au handler du leurre correspondant.

Limite connue : les protocoles où le serveur parle en premier (FTP, SMTP, MySQL, POP3...)
n'envoient rien avant la bannière. Si le client reste muet, on bascule sur un
service par défaut (variable MUX_DEFAUT, FTP par défaut).
"""
import socket
import threading

from src.core.detecteur_payload import detecter_protocole
from src.core.gestionnaire_logs import enregistrer_attaque

#nombre d'octets inspectés pour la détection
TAILLE_PEEK = 512


def traiter_client_brut(client_socket, adresse_client, nom_protocole="INCONNU"):
    #leurre de dernier recours : protocole non reconnu, on capture simplement ce qui arrive
    try:
        client_socket.settimeout(5)
        donnees = client_socket.recv(1024)
        if donnees:
            enregistrer_attaque(
                protocole=f"RAW_{nom_protocole}",
                ip_source=adresse_client[0],
                port_source=adresse_client[1],
                donnees={"charge_utile": repr(donnees), "charge_utile_hex": donnees.hex()},
            )
    except Exception:
        pass
    finally:
        client_socket.close()


def aiguiller_client(client_socket, adresse_client, handlers, defaut, delai_detection):
    """Détecte le protocole du client puis appelle le bon handler(client, adresse)."""
    try:
        #on attend un peu que le client parle en premier, sans consommer les octets
        client_socket.settimeout(delai_detection)
        try:
            apercu = client_socket.recv(TAILLE_PEEK, socket.MSG_PEEK)
        except socket.timeout:
            apercu = b""
        #on remet le socket en mode bloquant pour les handlers
        client_socket.settimeout(None)

        detecte = detecter_protocole(apercu)
        if detecte:
            cible, methode = detecte, "payload"
        elif apercu:
            cible, methode = "INCONNU", "inconnu"
        else:
            cible, methode = defaut, "defaut_client_muet"

        enregistrer_attaque(
            protocole="MUX_DETECTION",
            ip_source=adresse_client[0],
            port_source=adresse_client[1],
            donnees={
                "protocole_detecte": cible,
                "methode": methode,
                "signature_hex": apercu[:32].hex(),
            },
        )

        handler = handlers.get(cible)
        if handler is None:
            #protocole reconnu (ex: TLS) mais sans leurre dédié, ou totalement inconnu
            traiter_client_brut(client_socket, adresse_client, cible)
        else:
            handler(client_socket, adresse_client)
    except Exception:
        client_socket.close()


def demarrer_multiplexeur(handlers, hote="0.0.0.0", port=9000, defaut="FTP", delai_detection=2.0):
    """Écoute sur un port unique et aiguille chaque connexion vers le bon leurre.

    handlers : dict {"HTTP": fonction(client, adresse), ...}
    """
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serveur.bind((hote, port))
    serveur.listen(50)
    print(f"[+] Multiplexeur (payload detection) en écoute sur le port {port}...", flush=True)

    while True:
        client, adresse = serveur.accept()
        #la détection peut durer jusqu'au délai : on la fait dans un thread pour ne pas bloquer accept()
        threading.Thread(
            target=aiguiller_client,
            args=(client, adresse, handlers, defaut, delai_detection),
            daemon=True,
        ).start()
