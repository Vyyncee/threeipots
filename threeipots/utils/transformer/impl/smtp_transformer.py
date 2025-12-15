from ..protocol_transformer import ProtocolTransformer
from .. import register_transformer
from ...protocol import Protocol

@register_transformer
class SmtpTransformer(ProtocolTransformer):

    NAME = Protocol.SMTP

    TRANSFORMATIONS = {
        # Identifiant de flux bidirectionnel (même connexion vue dans les deux sens)
        # Sert de clé stable pour l’agrégation et l’analyse comportementale
        "flow_id": lambda row: tuple(sorted([
            (row["ip.src"], row["tcp.srcport"]),
            (row["ip.dst"], row["tcp.dstport"])
        ])),

        # TTL anormalement bas ou élevé
        # Peut indiquer un bot, un scan ou une pile réseau atypique
        "ttl_suspect": lambda r: int(r["ip.ttl"] < 32 or r["ip.ttl"] > 128),

        # Taille de paquet IP anormalement petite ou grande
        # Petit : probe / scan – Grand : flood ou tentative de saturation
        "ip_len_anormal": lambda r: int(r["ip.len"] < 60 or r["ip.len"] > 1500),

        # Connexion interrompue par un reset TCP
        # Fréquent dans les scans, brute-force ou implémentations SMTP instables
        "tcp_reset": lambda r: int(r.get("tcp.connection_rst", 0) == 1),

        # Connexion sans fermeture TCP propre (absence de FIN)
        # Indice de scan ou de script interrompu
        "tcp_no_fin": lambda r: int(r.get("tcp.connection_fin", 0) == 0),

        # Intervalle inter-paquet extrêmement faible
        # Typique d’un comportement automatisé (bot)
        "delta_time_low": lambda r: int(r.get("tcp.time_delta", 1) < 0.001),

        # RTT initial très bas
        # Souvent observé dans des environnements automatisés ou locaux
        "initial_rtt_suspect": lambda r: int(
            0 < r.get("tcp.analysis_initial_rtt", 1) < 0.01
        ),

        # Aucune commande SMTP valide détectée
        # Correspond à des probes TCP ou des scans de service
        "smtp_cmd_missing": lambda r: int(r.get("smtp.req_command") is None),

        # Commandes SMTP rarement utilisées en usage légitime
        # Souvent exploitées pour l’énumération (VRFY, EXPN)
        "smtp_cmd_suspect": lambda r: int(
            str(r.get("smtp.req_command")).upper() in {"VRFY", "EXPN", "TURN"}
        ),

        # Tentative d’authentification SMTP sans chiffrement
        # Typique des bots de brute-force
        "smtp_auth_no_tls": lambda r: int(
            r.get("smtp.auth_username_password") is not None
            and r["tcp.dstport"] == 25
        ),

        # Contenu SMTP DATA anormalement court
        # Indique souvent un test, une erreur ou une reconnaissance
        "smtp_data_too_short": lambda r: int(
            0 < r.get("smtp.data_reassembled_length", 0) < 50
        ),

        # Contenu SMTP DATA très volumineux
        # Peut indiquer du spam massif ou une tentative de DoS applicatif
        "smtp_data_too_long": lambda r: int(
            r.get("smtp.data_reassembled_length", 0) > 500_000
        ),

        # Absence de header FROM
        # Non conforme RFC, fréquent dans les implémentations malveillantes
        "missing_from": lambda r: int(r.get("imf.from") is None),

        # Absence de sujet
        # Fréquent dans les envois automatisés ou tests
        "missing_subject": lambda r: int(r.get("imf.subject") is None),

        # Message multipart (HTML / pièces jointes)
        # Signal structurel utile sans analyser le contenu
        "mime_multipart": lambda r: int(
            r.get("imf.mime_multipart_type") is not None
        )
    }

