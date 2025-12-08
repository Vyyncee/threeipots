from ..protocol_transformer import ProtocolTransformer
from .. import register_transformer
from ...protocol import Protocol

@register_transformer
class HttpTransformer(ProtocolTransformer):

    NAME = Protocol.HTTP

    TRANSFORMATIONS = {
        # -----------------------------
        #        Réseau / TCP
        # -----------------------------

        "src_ip": lambda row: row.get("ip.src"),  # Adresse IP source
        "dst_ip": lambda row: row.get("ip.dst"),  # Adresse IP destination

        "src_port": lambda row: row.get("tcp.srcport"),  # Port source TCP
        "dst_port": lambda row: row.get("tcp.dstport"),  # Port destination TCP

        "ip_ttl": lambda row: int(row.get("ip.ttl") or 0),  # Time-To-Live du paquet IP

        "tcp_flags_syn": lambda row: int(row.get("tcp.flags_syn") or 0),  # Flag SYN
        "tcp_flags_ack": lambda row: int(row.get("tcp.flags_ack") or 0),  # Flag ACK
        "tcp_flags_fin": lambda row: int(row.get("tcp.flags_fin") or 0),  # Flag FIN
        "tcp_flags_rst": lambda row: int(row.get("tcp.flags_reset") or 0),  # Flag RST

        "tcp_retransmissions": lambda row: 1 if row.get("tcp.analysis_retransmission") else 0,  
        # Indique une retransmission TCP (anomalie possible)

        "tcp_out_of_order": lambda row: 1 if row.get("tcp.analysis_out_of_order") else 0,  
        # Paquets hors séquence

        "tcp_dup_ack": lambda row: int(row.get("tcp.analysis_duplicate_ack") or 0),  
        # ACK dupliqués (souvent scans ou attaques)

        "tcp_payload_len": lambda row: len(str(row.get("tcp.payload")) or ""),  
        # Taille du payload TCP brut

        # -----------------------------
        #        HTTP Request
        # -----------------------------

        "http_method": lambda row: row.get("http.request_method"),  
        # Méthode HTTP (GET, POST…)

        "http_uri": lambda row: row.get("http.request_uri"),  
        # URI complète brute

        "http_path": lambda row: row.get("http.request_uri_path"),  
        # Chemin de l'URL (ex: /login)

        "http_query": lambda row: row.get("http.request_uri_query"),  
        # Partie query string (?id=1&test=2)

        "http_host": lambda row: row.get("http.host"),  
        # Host HTTP

        "http_user_agent": lambda row: row.get("http.user_agent"),  
        # User-Agent du client

        "http_referer": lambda row: row.get("http.referer"),  
        # Header Referer

        "http_content_type": lambda row: row.get("http.content_type"),  
        # Content-Type de la requête

        "http_content_length": lambda row: int(row.get("http.content_length") or 0),  
        # Taille du corps HTTP déclarée

        # -----------------------------
        #      Features dérivées
        # -----------------------------

        "url_length": lambda row: len(str(row.get("http.request_uri")) or ""),  
        # Longueur de l’URL

        "path_depth": lambda row: ProtocolTransformer.path_depth(row.get("http.request_uri_path")),  
        # Profondeur du chemin /test/a/b → 3

        "url_entropy": lambda row: ProtocolTransformer.entropy(row.get("http.request_uri") or ""),  
        # Entropie de l’URL (utile pour détecter fuzzing/encoded payloads)

        "query_entropy": lambda row: ProtocolTransformer.entropy(row.get("http.request_uri_query") or ""),  
        # Entropie de la query string

        "has_query": lambda row: 1 if row.get("http.request_uri_query") else 0,  
        # Présence d'une query string

        "num_query_params": lambda row: len(str(row.get("http.request_uri_query_parameter") or "").split("&")),  
        # Nombre de paramètres GET

        "special_char_ratio": lambda row: ProtocolTransformer.special_char_ratio(row.get("http.request_uri") or ""),  
        # Ratio de caractères spéciaux dans l’URL

        "ua_length": lambda row: len(str(row.get("http.user_agent")) or ""),  
        # Longueur du User-Agent (bots → petits, scanners → vides)

        "ua_entropy": lambda row: ProtocolTransformer.entropy(row.get("http.user_agent") or ""),  
        # Entropie du User-Agent

        "is_attack_method": lambda row: 1 if row.get("http.request_method") in ["OPTIONS","PROPFIND","SEARCH"] else 0,  
        # Méthodes rarement légitimes → indicateur d’attaque

        "content_length_anomaly": lambda row: 1 if (row.get("http.content_length") and int(row.get("http.content_length")) > 2000000) else 0,  
        # Corps HTTP anormalement gros

        # -----------------------------
        #        HTTP Body
        # -----------------------------

        "http_body_len": lambda row: len(str(row.get("http.data") or "")),  
        # Taille du corps HTTP réel

        "http_body_entropy": lambda row: ProtocolTransformer.entropy(row.get("http.data") or "")  
        # Entropie du body (utile pour détecter uploads malicieux, shells, injections)
    }