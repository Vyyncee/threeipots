from ..protocol_transformer import ProtocolTransformer
from .. import register_transformer
from ...protocol import Protocol

@register_transformer
class SmtpTransformer(ProtocolTransformer):

    NAME = Protocol.SMTP

    TRANSFORMATIONS = {
        # -----------------------------
        #           TCP / IP
        # -----------------------------

        "src_ip": lambda row: row.get("ip.src"),  # Adresse IP source
        "dst_ip": lambda row: row.get("ip.dst"),  # Adresse IP destination

        "src_port": lambda row: row.get("tcp.srcport"),  # Port source TCP
        "dst_port": lambda row: row.get("tcp.dstport"),  # Port destination TCP

        "is_smtp_port": lambda row: 1 if str(row.get("tcp.dstport")) in ["25","465","587"] else 0,  
        # Indique si le trafic vise un port SMTP légitime

        "ip_ttl": lambda row: int(row.get("ip.ttl") or 0),  
        # Time-to-live utile pour repérer anomalies (bots, proxys, scanners)

        "tcp_flags_syn": lambda row: int(row.get("tcp.flags_syn") or 0),  # Indicateur SYN
        "tcp_flags_ack": lambda row: int(row.get("tcp.flags_ack") or 0),  # Indicateur ACK
        "tcp_flags_fin": lambda row: int(row.get("tcp.flags_fin") or 0),  # Indicateur FIN
        "tcp_flags_rst": lambda row: int(row.get("tcp.flags_reset") or 0),  # Indicateur RST (souvent attaques)

        "tcp_payload_len": lambda row: len(row.get("tcp.payload") or ""),  
        # Taille des données TCP transportées

        "tcp_retransmissions": lambda row: 1 if row.get("tcp.analysis_retransmission") else 0,  
        # Retransmission = congestion ou attaque

        "tcp_out_of_order": lambda row: 1 if row.get("tcp.analysis_out_of_order") else 0,  
        # Paquets reçus hors ordre (souvent scanners/attaques)

        "tcp_dup_ack": lambda row: int(row.get("tcp.analysis_duplicate_ack") or 0),  
        # ACK dupliqué = anomalie réseau ou brute-force

        "tcp_window_size": lambda row: int(row.get("tcp.window_size_value") or 0),  
        # Fenêtre TCP → utile pour détecter comportements anormaux

        "tcp_rtt": lambda row: float(row.get("tcp.analysis_ack_rtt") or 0.0),  
        # Round-trip time (RTT) → détecte proxys, bots, VM, etc.

        # -----------------------------
        #              SMTP
        # -----------------------------

        "smtp_command": lambda row: row.get("smtp.req_command"),  
        # Commande SMTP brute (HELO, MAIL, RCPT…)

        "smtp_has_auth": lambda row: 1 if row.get("smtp.req_command") == "AUTH" else 0,  
        # Indique une tentative d’authentification

        "smtp_auth_username_password": lambda row: 1 if row.get("smtp.auth_username_password") else 0,  
        # Auth SMTP utilisant username/password embarqué (souvent attaques)

        "smtp_data_fragment_count": lambda row: int(row.get("smtp.data_fragment_count") or 0),  
        # Nombre de fragments SMTP → gros emails / attaques

        "smtp_eom": lambda row: 1 if row.get("smtp.eom") else 0,  
        # Détection du tag de fin d’email

        "smtp_command_count": lambda row: len(str(row.get("smtp.command_line") or "").split()),  
        # Nombre de commandes dans la ligne SMTP (utile pour repérer spam bots)

        "smtp_command_entropy": lambda row: ProtocolTransformer.entropy(row.get("smtp.command_line") or ""),  
        # Entropie des commandes SMTP → anomalies/séquences automatiques

        # -----------------------------
        #       SMTP Payload
        # -----------------------------

        "smtp_payload_len": lambda row: len(row.get("smtp.payload") or ""),  
        # Taille du contenu SMTP → souvent lié à spam/phishing

        "smtp_payload_entropy": lambda row: ProtocolTransformer.entropy(row.get("smtp.payload") or ""),  
        # Entropie du payload (détecte obfuscation, base64, scripts)

        # -----------------------------
        #        IMF / Email Data
        # -----------------------------

        "imf_subject_len": lambda row: len(row.get("imf.subject") or ""),  
        # Longueur du sujet

        "imf_subject_entropy": lambda row: ProtocolTransformer.entropy(row.get("imf.subject") or ""),  
        # Entropie du sujet → détecte spam/phishing

        "imf_from_domain": lambda row: (row.get("imf.from") or "").split("@")[-1] if "@" in (row.get("imf.from") or "") else "",  
        # Domaine de l'expéditeur

        "imf_to_count": lambda row: len(str(row.get("imf.to") or "").split(",")),  
        # Nombre de destinataires → souvent élevé dans spam

        "imf_has_multipart": lambda row: 1 if row.get("imf.mime_multipart_type") else 0,  
        # Email avec multipart (pièces jointes, HTML…)

        "imf_content_type": lambda row: row.get("imf.content_type_type"),  
        # Content-Type (text/plain, text/html, multipart…)

        "imf_message_text_len": lambda row: len(row.get("imf.message_text") or ""),  
        # Longueur du corps du message

        "imf_message_text_entropy": lambda row: ProtocolTransformer.entropy(row.get("imf.message_text") or "")  
        # Entropie du texte → détecte obfuscation, encodages, scripts
    }

