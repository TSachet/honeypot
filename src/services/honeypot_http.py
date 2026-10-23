import socket
import threading
from src.core.gestionnaire_logs import enregistrer_attaque

#fausse page de connexion wordpress basique pour piéger les bots de brute-force
FAUSSE_PAGE_WP = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n
<!DOCTYPE html><html><head><title>WordPress &rsaquo; Log In</title></head>
<body><form action="/wp-login.php" method="post">
Username: <input type="text" name="log"><br>
Password: <input type="password" name="pwd"><br>
<input type="submit" value="Log In"></form></body></html>"""

#fausse réponse 404 pour paraître réel quand l'attaquant cherche une page au au hasard
FAUSSE_404 = """HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n
<html><body><h1>404 Not Found</h1></body></html>"""

def traiter_client_http(client_socket, adresse_client):
    try:
        #on prend une taille de buffer plus grande de 2048 octets pour capter le corps de la requête
        requete_brute = client_socket.recv(2048).decode("utf-8", errors="ignore")
        if not requete_brute:
            return

        lignes = requete_brute.split("\r\n")
        ligne_commande = lignes[0].split(" ")
        
        if len(ligne_commande) >= 2:
            methode = ligne_commande[0] #get ou post
            chemin = ligne_commande[1]  #ex: /wp-login.php ou /.env
            
            #on cherche les données postées après le double retour à la ligne réglementaire du http
            corps_requete = requete_brute.split("\r\n\r\n")[1] if "\r\n\r\n" in requete_brute else ""

            #on enregistre tout dans le json pour analyser le comportement du bot
            enregistrer_attaque(
                protocole="HTTP",
                ip_source=adresse_client[0],
                port_source=adresse_client[1],
                donnees={"methode": methode, "chemin": chemin, "payload": corps_requete}
            )

            #interaction conditionnelle selon ce que le bot essaie de scanner
            if "wp-login.php" in chemin or "admin" in chemin:
                #on lui sert le faux formulaire wordpress pour qu'il essaie de s'authentifier
                client_socket.sendall(FAUSSE_PAGE_WP.encode("utf-8"))
            elif ".env" in chemin or "config" in chemin:
                #si le bot cherche des secrets dans les fichiers de config on lui donne des fausses clés
                fausse_config = "HTTP/1.1 200 OK\r\n\r\nDB_PASS=f4k3_p4ssw0rd!\r\nAWS_KEY=AKIAIOSFODNN7EXAMPLE"
                client_socket.sendall(fausse_config.encode("utf-8"))
            else:
                #sinon on lui dit que la page n'existe pas
                client_socket.sendall(FAUSSE_404.encode("utf-8"))

    except Exception:
        pass
    finally:
        #on ferme la connexion pour libérer le socket
        client_socket.close()

def demarrer_honeypot_http(hote="0.0.0.0", port=8080):
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serveur.bind((hote, port))
    serveur.listen(5)
    print(f"[+] Honeypot HTTP (Interactif) en écoute sur le port {port}...", flush=True)

    while True:
        client, adresse = serveur.accept()
        #on génère un thread à la volée en mode daemon pour chaque requête web arrivant
        threading.Thread(target=traiter_client_http, args=(client, adresse), daemon=True).start()
