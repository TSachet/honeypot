import json
import threading
from datetime import datetime, timezone

from src.core.config import chemin_journal

#verrou partagé : plusieurs threads écrivent en même temps, on évite les lignes json mélangées
_VERROU = threading.Lock()


def formater_evenement(protocole, ip_source, port_source, donnees):
    #construit le dictionnaire d'un événement (séparé de l'écriture pour pouvoir le tester)
    return {
        #on prend l'heure utc actuelle pour être précis et calé sur le bon fuseau
        "horodatage": datetime.now(timezone.utc).isoformat(),
        "protocole": protocole,
        "ip_source": ip_source,
        "port_source": port_source,
        "donnees": donnees,
    }


def enregistrer_attaque(protocole, ip_source, port_source, donnees):
    evenement = formater_evenement(protocole, ip_source, port_source, donnees)

    #un petit print rapide pour voir ce qui se passe en direct dans le terminal
    print(
        f"[{protocole}] Attaque détectée depuis {ip_source}:{port_source} - {donnees}",
        flush=True,
    )

    #le fichier où on stocke toutes les attaques au format json lines (une ligne = un événement)
    chemin = chemin_journal()
    chemin.parent.mkdir(parents=True, exist_ok=True)

    with _VERROU:
        #on ouvre le fichier en mode ajout pour pas écraser les anciens logs
        with open(chemin, "a", encoding="utf-8") as f:
            #on transforme le dico en texte json propre avec un saut de ligne pour séparer les entrées
            f.write(json.dumps(evenement, ensure_ascii=False) + "\n")
