import socket
import threading
from src.core.gestionnaire_logs import enregistrer_attaque

def traiter_client_redis(client_socket, adresse_client):
    try:
        while True:
            #on intercepte le paquet envoyé par l'attaquant ou son script de scan
            donnees = client_socket.recv(1024).decode("utf-8", errors="ignore").strip()
            if not donnees:
                break

            #on passe tout en majuscules pour analyser l'intention du bot facilement
            commande = donnees.upper()
            
            #on log la commande brute pour garder la trace exacte du scan ou de l'injection
            enregistrer_attaque(
                protocole="REDIS_CMD", 
                ip_source=adresse_client[0], 
                port_source=adresse_client[1], 
                donnees={"commande": commande}
            )

            #on simule le protocole de réponse de redis avec le bon formatage de chaîne
            if "INFO" in commande:
                #on fait croire qu'on est une vraie instance active avec le nombre d'octets requis
                #la longueur annoncée est calculée pour rester cohérente avec le contenu
                info = b"# Server\r\nredis_version:6.2.6\r\n"
                client_socket.sendall(b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n")
            elif "PING" in commande:
                #c'est le test de santé classique on lui répond le ping-pong
                client_socket.sendall(b"+PONG\r\n")
            elif "AUTH" in commande:
                #on lui valide son authentification au hasard s'il tente d'envoyer un mot de passe
                client_socket.sendall(b"+OK\r\n")
            else:
                #on lui renvoie une fausse erreur pour le forcer à tester une autre commande
                client_socket.sendall(b"-ERR unknown command\r\n")

    except Exception:
        pass
    finally:
        #on coupe le flux proprement à la fin de l'échange
        client_socket.close()

def demarrer_honeypot_redis(hote="0.0.0.0", port=6379):
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serveur.bind((hote, port))
    serveur.listen(5)
    print(f"[+] Honeypot REDIS en écoute sur le port {port}...", flush=True)

    while True:
        client, adresse = serveur.accept()
        #on bascule chaque nouveau scan redis dans son propre thread léger
        threading.Thread(target=traiter_client_redis, args=(client, adresse), daemon=True).start()
