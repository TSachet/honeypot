import socket
import threading
from src.core.gestionnaire_logs import enregistrer_attaque

def traiter_client_mysql(client_socket, adresse_client):
    try:
        #on donne le paquet binaire officiel pour faire croire à un vrai serveur mysql
        greeting = b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x34\x30\x2d\x6c\x6f\x67\x00\x01\x00\x00\x00\x4a\x5b\x2a\x3a\x00\xff\xff\x08\x02\x00\xff\xc1\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        client_socket.sendall(greeting)

        #on attend le retour de l'attaquant qui contient ses identifiants de connexion
        donnees = client_socket.recv(1024)
        if donnees:
            #on extrait tout en hexa car le pseudo est souvent lisible au milieu des octets bruts
            enregistrer_attaque(
                protocole="MYSQL_AUTH",
                ip_source=adresse_client[0],
                port_source=adresse_client[1],
                donnees={"charge_utile_hex": donnees.hex()}
            )
            
            #on lui répond avec le paquet d'erreur officiel d'accès refusé pour clore l'échange proprement
            erreur_denied = b"\x23\x00\x00\x02\xff\x15\x04\x28\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64"
            client_socket.sendall(erreur_denied)
            
    except Exception:
        pass
    finally:
        #on oublie pas de déconnecter le socket pour libérer le système
        client_socket.close()

def demarrer_honeypot_mysql(hote="0.0.0.0", port=3306):
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serveur.bind((hote, port))
    serveur.listen(5)
    print(f"[+] Honeypot MYSQL en écoute sur le port {port}...", flush=True)

    while True:
        client, adresse = serveur.accept()
        #on envoie l'attaquant dans un fil d'exécution séparé pour rester dispo
        threading.Thread(target=traiter_client_mysql, args=(client, adresse), daemon=True).start()
