import functools
import os
import signal
import sys
import threading
import time

from src.core import config
from src.core.multiplexeur import demarrer_multiplexeur
from src.services.honeypot_generique import SERVICES_TEXTE, demarrer_service_texte, traiter_client_texte
from src.services.honeypot_http import demarrer_honeypot_http, traiter_client_http
from src.services.honeypot_ssh import demarrer_honeypot_ssh, traiter_client_ssh
from src.services.honeypot_ftp import demarrer_honeypot_ftp, traiter_client_ftp
from src.services.honeypot_redis import demarrer_honeypot_redis, traiter_client_redis
from src.services.honeypot_mysql import demarrer_honeypot_mysql, traiter_client_mysql


def construire_handlers():
    #table de routage du multiplexeur : nom de protocole détecté -> fonction(client, adresse)
    handlers = {
        "HTTP": traiter_client_http,
        "SSH": traiter_client_ssh,
        "FTP": traiter_client_ftp,
        "REDIS": traiter_client_redis,
        "MYSQL": traiter_client_mysql,
    }
    #les protocoles génériques (telnet, smtp, pop3, ldap, rdp, postgresql) partagent le même handler
    for nom_service in SERVICES_TEXTE:
        if nom_service not in handlers:
            handlers[nom_service] = functools.partial(traiter_client_texte, nom_service=nom_service)
    return handlers


def main():
    #charge le .env (ports, chemins...) s'il existe
    config.charger_env()
    hote = config.hote_ecoute()

    print("=== DÉMARRAGE DU HONEYPOT ===", flush=True)

    #1. modules à moyenne interaction
    #on lance chaque serveur spécifique dans son propre thread indépendant en arrière-plan
    threading.Thread(target=demarrer_honeypot_http, kwargs={"hote": hote, "port": config.port_service("HTTP")}, daemon=True).start()
    threading.Thread(target=demarrer_honeypot_ssh, kwargs={"hote": hote, "port": config.port_service("SSH")}, daemon=True).start()
    threading.Thread(target=demarrer_honeypot_ftp, kwargs={"hote": hote, "port": config.port_service("FTP")}, daemon=True).start()
    threading.Thread(target=demarrer_honeypot_redis, kwargs={"hote": hote, "port": config.port_service("REDIS")}, daemon=True).start()
    threading.Thread(target=demarrer_honeypot_mysql, kwargs={"hote": hote, "port": config.port_service("MYSQL")}, daemon=True).start()

    #2. modules génériques (LDAP, RDP, Telnet, SMTP...)
    #on boucle sur le dictionnaire pour pas avoir à écrire chaque service à la main
    for nom_service in SERVICES_TEXTE:
        #on esquive ceux qu'on a déjà codé de manière plus interactive au-dessus
        if nom_service not in ["FTP", "MYSQL", "REDIS"]:
            #on crée un thread à la volée pour chaque protocole restant dans la liste
            threading.Thread(
                target=demarrer_service_texte,
                args=(nom_service, hote, config.port_service(nom_service, SERVICES_TEXTE[nom_service]["port"])),
                daemon=True,
            ).start()

    #3. multiplexeur (payload detection) : un port unique qui devine le protocole et aiguille vers le bon leurre
    if config.option_active("MUX_ENABLED", True):
        threading.Thread(
            target=demarrer_multiplexeur,
            kwargs={
                "handlers": construire_handlers(),
                "hote": hote,
                "port": config.port_service("MUX"),
                "defaut": os.getenv("MUX_DEFAUT", "FTP").upper(),
                "delai_detection": float(os.getenv("MUX_DELAI", "2.0")),
            },
            daemon=True,
        ).start()

    print("[+] Tous les modules sont opérationnels !", flush=True)

    #docker stop envoie SIGTERM : on le traite comme un ctrl+c pour s'arrêter proprement
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    try:
        #on bloque le script principal ici pour que l'ensemble des threads continue de tourner
        while True:
            #la petite pause d'une seconde évite de surcharger inutilement le processeur
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        #si on fait un ctrl+c on intercepte le signal pour fermer l'application proprement
        print("\n[-] Arrêt du Honeypot.", flush=True)

if __name__ == "__main__":
    main()
