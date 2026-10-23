"""Détecteur de protocole par analyse des premiers octets (payload detection).

Principe inspiré de Honeytrap : un seul port d'écoute reçoit toutes les connexions,
on regarde les premiers octets envoyés par le client pour deviner le protocole,
puis on aiguille la connexion vers le bon leurre (voir multiplexeur.py).

Cette fonction est pure (octets -> nom de protocole) donc facile à tester.
"""
import re

_I = re.IGNORECASE
_S = re.DOTALL

#liste ordonnée de (protocole, regex) : la première signature qui correspond gagne.
#l'ordre compte : les signatures binaires précises passent avant les mots-clés texte.
SIGNATURES = [
    ("SSH", re.compile(rb"^SSH-")),
    ("TLS", re.compile(rb"^\x16\x03[\x00-\x04]", _S)),
    #tpkt (03 00 + longueur) puis x.224 connection request (0xe0)
    ("RDP", re.compile(rb"^\x03\x00.{2}.\xe0", _S)),
    #startup postgresql (v3.0) ou sslrequest / gssencrequest
    (
        "POSTGRESQL",
        re.compile(rb"^\x00\x00.{2}(?:\x00\x03\x00\x00|\x04\xd2\x16[\x2f\x30])", _S),
    ),
    #ldap bindrequest : sequence(0x30) + longueur + messageid(02 01 xx) + bindrequest(0x60)
    (
        "LDAP",
        re.compile(rb"^\x30(?:[\x00-\x7f]|\x81.|\x82..)\x02\x01.\x60", _S),
    ),
    #telnet : iac (0xff) suivi de will/wont/do/dont
    ("TELNET", re.compile(rb"^\xff[\xfb-\xfe]")),
    (
        "HTTP",
        re.compile(
            rb"^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND) ", _I
        ),
    ),
    #"AUTH TLS" est du ftp : il doit passer avant le "AUTH" de redis
    ("FTP", re.compile(rb"^AUTH (?:TLS|SSL)\b", _I)),
    #resp (*<n>\r\n) ou commandes inline redis courantes
    (
        "REDIS",
        re.compile(
            rb"^(?:\*\d+\r\n|(?:PING|INFO|AUTH|CONFIG|FLUSHALL|FLUSHDB|KEYS|SLAVEOF"
            rb"|REPLICAOF|MODULE|CLIENT|COMMAND|SELECT|EVAL|DBSIZE|SET|GET)\b)",
            _I,
        ),
    ),
    ("SMTP", re.compile(rb"^(?:EHLO|HELO|MAIL FROM|RCPT TO|VRFY|EXPN|STARTTLS)\b", _I)),
    ("POP3", re.compile(rb"^(?:CAPA|APOP|STLS)\b", _I)),
    #"USER" est aussi une commande pop3, mais ftp reste le cas le plus fréquent
    (
        "FTP",
        re.compile(
            rb"^(?:USER|PASS|SYST|FEAT|PWD|CWD|TYPE|PASV|EPSV|LIST|OPTS)\b", _I
        ),
    ),
]


def detecter_protocole(octets):
    """Renvoie le nom du protocole reconnu (ex: "HTTP") ou None si inconnu."""
    if not octets:
        return None
    for nom, motif in SIGNATURES:
        if motif.match(octets):
            return nom
    return None
