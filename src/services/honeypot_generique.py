import socket
import threading
from src.core.gestionnaire_logs import enregistrer_attaque

#mettre à jour le dictionnaire avec les nouveaux protocoles
SERVICES_TEXTE = {
    #protocoles réseau & administration
    "TELNET": {"port": 2323, "banniere": "Ubuntu 22.04 LTS\r\nlogin: "},
    "FTP": {"port": 2121, "banniere": "220 ProFTPD 1.3.5 Server ready.\r\n"},
    "SMTP": {"port": 2525, "banniere": "220 mail.entreprise.local ESMTP Postfix\r\n"},
    "POP3": {"port": 1110, "banniere": "+OK POP3 server ready\r\n"},
    #annuaire & bureau à distance
    "LDAP": {
        "port": 3890,
        "banniere": "\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00",
    },  #paquet de réponse LDAP léger
    "RDP": {
        "port": 3389,
        "banniere": "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x09\x08\x00\x00\x00\x00\x00",
    },  #paquet x.224 rdp connection confirm
    #bases de données
    "MYSQL": {
        "port": 3306,
        "banniere": "5.7.40-log\x00\x01\x00\x00\x00\x4a\x5b\x2a\x3a\x00",
    },  #handshake mysql
    "POSTGRESQL": {
        "port": 5432,
        "banniere": "E\x00\x00\x00\x50SFATAL\x00C28000\x00Mno pg_hba.conf entry\x00",
    },
    "REDIS": {
        "port": 6379,
        "banniere": "-NOAUTH Authentication required.\r\n",
    },
}


def traiter_client_texte(client_socket, adresse_client, nom_service):
    try:
        #on récupère la configuration propre au protocole ciblé
        config = SERVICES_TEXTE[nom_service]
        banniere = config["banniere"]

        #envoi de la bannière (texte ou octets bruts)
        #on vérifie si c'est du string ou déjà des octets pour pas faire planter l'envoi
        if isinstance(banniere, str):
            client_socket.sendall(banniere.encode("utf-8"))
        else:
            client_socket.sendall(banniere)

        commandes_recues = []
        #on limite à 3 interactions maximum pour piéger le bot sans lui donner trop de temps de calcul
        for _ in range(3):
            donnees = client_socket.recv(1024)
            if not donnees:
                #si le client envoie rien ou coupe on s'arrête là
                break

            #représentation lisible des octets capturés
            #repr permet d'afficher les caractères invisibles ou bizarre sans tout casser
            donnees_lisibles = repr(donnees)
            commandes_recues.append(donnees_lisibles)

            #fausse réponse de refus d'accès
            #on n'envoie l'erreur standard que si c'est un protocole texte simple
            if isinstance(banniere, str):
                client_socket.sendall(
                    b"500 Command not recognized or Access Denied\r\n"
                )

        #enregistrement dans les logs json
        #on stocke toute la liste des commandes capturées durant l'échange
        enregistrer_attaque(
            protocole=nom_service,
            ip_source=adresse_client[0],
            port_source=adresse_client[1],
            donnees={"charge_utile": commandes_recues},
        )
    except Exception:
        #on passe les erreurs pour pas bloquer la boucle du serveur principal
        pass
    finally:
        #libération immédiate du socket de l attaquant
        client_socket.close()


def demarrer_service_texte(nom_service, hote="0.0.0.0", port=None):
    #on cherche le bon port à ouvrir : celui passé en paramètre (venant du .env) sinon celui du dico de config
    config = SERVICES_TEXTE[nom_service]
    if port is None:
        port = config["port"]

    #initialisation classique du socket réseau tcp ip
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serveur.bind((hote, port))
    serveur.listen(5)
    print(f"[+] Honeypot Générique [{nom_service}] actif sur le port {port}", flush=True)

    while True:
        #réception de la tentative de connexion de l'attaquant
        client, adresse = serveur.accept()
        #on lui attribue un thread en lui passant bien le nom du service en paramètre additionnel
        t = threading.Thread(
            target=traiter_client_texte,
            args=(client, adresse, nom_service),
            daemon=True,
        )
        t.start()
