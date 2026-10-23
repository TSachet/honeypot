import socket
import threading
from src.core.gestionnaire_logs import enregistrer_attaque

def traiter_client_ftp(client_socket, adresse_client):
    try:
        #on envoie le faux message de bienvenue
        client_socket.sendall(b"220 ProFTPD 1.3.5 Server ready.\r\n")
        est_authentifie = False

        while True:
            #on intercepte la commande tapée par l'attaquant
            donnees = client_socket.recv(1024).decode("utf-8", errors="ignore").strip()
            if not donnees:
                break

            #on sépare le nom de la commande et ses arguments associés
            commande = donnees.split(" ")[0].upper()
            arguments = donnees[len(commande)+1:]

            #machine à états ftp pour simuler un vrai comportement de serveur
            if commande == "USER":
                #on valide n'importe quel pseudo et on demande la suite
                client_socket.sendall(f"331 Password required for {arguments}\r\n".encode())
            
            elif commande == "PASS":
                #accepte tout le monde
                est_authentifie = True
                #on log le mot de passe (avant la réponse, pour que l'événement soit écrit même si le client coupe)
                enregistrer_attaque("FTP_AUTH", adresse_client[0], adresse_client[1], {"pass": arguments})
                client_socket.sendall(b"230 User logged in.\r\n")
            
            elif commande == "SYST":
                #on lui fait croire qu'on est sur une machine unix standard
                client_socket.sendall(b"215 UNIX Type: L8\r\n")
            
            elif commande == "PWD":
                #on lui balance un faux dossier racine typique d'un serveur web
                client_socket.sendall(b"257 \"/var/www/html\" is the current directory\r\n")
            
            elif commande in ["CWD", "CDUP"]:
                #on valide ses changements de répertoires fictifs
                client_socket.sendall(b"250 CWD command successful\r\n")
            
            elif commande in ["STOR", "RETR"]:
                #le bot tente d'uploader un malware ou de chasser une base de données
                #on capture le nom du fichier cible dans notre rapport d'attaque
                enregistrer_attaque(f"FTP_{commande}", adresse_client[0], adresse_client[1], {"fichier_cible": arguments})
                #on simule une erreur réseau pour pas s'embêter à coder les canaux passifs/actifs du ftp
                client_socket.sendall(b"425 Failed to establish connection.\r\n")
            
            elif commande == "QUIT":
                #on gère sa déconnexion poliment
                client_socket.sendall(b"221 Goodbye.\r\n")
                break
            
            else:
                #sécurité si le bot essaie de tricher avant de donner ses identifiants
                if not est_authentifie:
                    client_socket.sendall(b"530 Please login with USER and PASS.\r\n")
                else:
                    client_socket.sendall(b"500 Unknown command.\r\n")

    except Exception:
        pass
    finally:
        #on ferme la connexion réseau proprement
        client_socket.close()

def demarrer_honeypot_ftp(hote="0.0.0.0", port=2121):
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serveur.bind((hote, port))
    serveur.listen(5)
    print(f"[+] Honeypot FTP (Interactif) en écoute sur le port {port}...", flush=True)

    while True:
        client, adresse = serveur.accept()
        #on détache l'attaquant dans son propre thread indépendant
        threading.Thread(target=traiter_client_ftp, args=(client, adresse), daemon=True).start()
