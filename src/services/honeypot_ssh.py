import os
import socket
import threading
import paramiko
import subprocess
from src.core.gestionnaire_logs import enregistrer_attaque

#on génère une clé rsa de 2048 bits pour que le serveur ssh ait l'air légitime
CLE_HOTE = paramiko.RSAKey.generate(2048)

#fausses réponses du shell quand on n'a pas de sandbox docker (ex: honeypot lui-même dans un conteneur)
REPONSES_SIMULEES = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "hostname": "server",
    "uname": "Linux",
    "uname -a": "Linux server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "ls": "backup.tar.gz  notes.txt",
    "ls -la": "total 12\ndrwx------ 2 root root 4096 Oct 12 10:00 .\n-rw-r--r-- 1 root root  120 Oct 12 10:00 notes.txt",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
}


def executer_commande_simulee(commande):
    #renvoie une réponse plausible sans rien exécuter du tout
    if commande in REPONSES_SIMULEES:
        return REPONSES_SIMULEES[commande]
    nom = commande.split(" ")[0]
    return f"bash: {nom}: command not found"


def executer_commande(commande):
    #mode "docker" : exécution réelle dans un conteneur sandbox isolé (nécessite le cli docker sur la machine)
    #mode "simulate" (défaut) : réponses simulées, aucune exécution
    if os.getenv("SSH_SANDBOX", "simulate").lower() == "docker":
        try:
            #c'est ici qu'on exécute la commande de manière sécurisée dans docker
            #le timeout de 10s évite que l'attaquant freeze notre script avec un ping infini
            resultat = subprocess.run(
                ["docker", "exec", "sandbox_generique", "sh", "-c", commande],
                capture_output=True,
                text=True,
                timeout=10
            )
            #on fusionne la sortie standard et les erreurs pour tout renvoyer
            return resultat.stdout if resultat.stdout else resultat.stderr
        except FileNotFoundError:
            #le cli docker n'existe pas ici : on retombe sur la simulation plutôt que de planter
            pass
    return executer_commande_simulee(commande)


class InterfaceServeurSSH(paramiko.ServerInterface):
    def __init__(self, adresse_client):
        self.adresse_client = adresse_client
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        #on intercepte les identifiants tapés pour notre fichier de logs
        enregistrer_attaque(
            protocole="SSH_AUTH",
            ip_source=self.adresse_client[0],
            port_source=self.adresse_client[1],
            donnees={"nom_utilisateur": username, "mot_de_passe": password},
        )
        #ici on a notre piege on accepte n'importe quel pass pour le laisser entrer
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        #on l'autorise à ouvrir une session de terminal
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        #on dit oui quand l'attaquant réclame un terminal interactif
        return True

    def check_channel_shell_request(self, channel):
        #on valide la création du shell et on débloque l'événement d'attente
        self.event.set()
        return True


def traiter_client_ssh(client_socket, adresse_client):
    transport = None
    try:
        #on initie la couche de transport sécurisée paramiko
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(CLE_HOTE)
        serveur = InterfaceServeurSSH(adresse_client)
        transport.start_server(server=serveur)

        #on attend que le canal s'ouvre avec un timeout de 20 secondes max
        canal = transport.accept(20)
        if canal is None:
            return

        #on attend la validation définitive du shell pendant 10 secondes
        serveur.event.wait(10)
        if not serveur.event.is_set():
            return

        #on envoie une fausse bannière d'accueil ubuntu et le prompt de root
        canal.send(b"Welcome to Ubuntu 22.04 LTS\r\nroot@server:~# ")

        while True:
            #on écoute en continu ce que tape l'attaquant dans sa console
            commande_brute = canal.recv(1024)
            if not commande_brute:
                #s'il coupe le flux on sort de la boucle
                break
                
            commande = commande_brute.decode('utf-8', errors='ignore').strip()
            
            if not commande:
                #si c'est juste un coup de touche entrée on réaffiche le prompt
                canal.send(b"\r\nroot@server:~# ")
                continue
                
            if commande in ["exit", "quit", "logout"]:
                #on gère la sortie propre s'il demande à quitter
                canal.send(b"\r\nlogout\r\n")
                break

            #on enregistre tout de suite la commande secrète dans nos logs json
            enregistrer_attaque(
                protocole="SSH_CMD",
                ip_source=adresse_client[0],
                port_source=adresse_client[1],
                donnees={"commande": commande}
            )

            try:
                #retour à la ligne pour préparer l'affichage du résultat
                canal.send(b"\r\n") 
                
                reponse = executer_commande(commande)
                #on adapte les sauts de ligne pour l'affichage ssh linux standard
                reponse_encodee = reponse.replace('\n', '\r\n').encode('utf-8')
                
                canal.send(reponse_encodee)
                if not reponse.endswith('\n') and reponse != "":
                    canal.send(b"\r\n")
                    
            except subprocess.TimeoutExpired:
                #on prévient l'attaquant si sa commande a été trop longue
                canal.send(b"Command timed out\r\n")
            except Exception:
                #erreur générique de shell si l'exécution docker plante
                canal.send(b"bash: command error\r\n")

            #on lui remet l'invite de commande pour la prochaine interaction
            canal.send(b"root@server:~# ")

    except Exception:
        pass
    finally:
        #on nettoie toujours le flux de transport à la fin
        if transport is not None:
            transport.close()
        client_socket.close()


def demarrer_honeypot_ssh(hote="0.0.0.0", port=2222):
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serveur.bind((hote, port))
    serveur.listen(5)
    print(f"[+] Honeypot SSH en écoute sur le port {port}...", flush=True)

    while True:
        client, adresse = serveur.accept()
        t = threading.Thread(
            target=traiter_client_ssh, args=(client, adresse), daemon=True
        )
        t.start()
