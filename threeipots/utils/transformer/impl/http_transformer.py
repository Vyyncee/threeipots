from ..protocol_transformer import ProtocolTransformer
from .. import register_transformer
from ...protocol import Protocol

@register_transformer
class HttpTransformer(ProtocolTransformer):

    NAME = Protocol.HTTP

    TRANSFORMATIONS = {

        # Identifiant de flux bidirectionnel (client ↔ serveur)
        # Permet l’agrégation par connexion HTTP indépendamment du sens
        "flow_id": lambda row: tuple(sorted([
            (row["ip.src"], row["tcp.srcport"]),
            (row["ip.dst"], row["tcp.dstport"])
        ])),

        # TTL anormalement bas ou élevé
        # Indice de bot, scan automatisé ou pile réseau atypique
        "ttl_suspect": lambda r: int(r["ip.ttl"] < 32 or r["ip.ttl"] > 128),

        # Taille de paquet IP anormale
        # Petit : probe / scan – Grand : flood ou tentative de surcharge
        "ip_len_anormal": lambda r: int(r["ip.len"] < 60 or r["ip.len"] > 1500),

        # Connexion interrompue par un reset TCP
        # Fréquent dans les scans HTTP ou outils automatisés
        "tcp_reset": lambda r: int(r.get("tcp.connection_rst", 0) == 1),

        # Connexion sans fermeture TCP propre (pas de FIN)
        # Indice de scan ou d’outil mal implémenté
        "tcp_no_fin": lambda r: int(r.get("tcp.connection_fin", 0) == 0),

        # Intervalle inter-paquet extrêmement faible
        # Typique d’un comportement automatisé (scanner, bot)
        "delta_time_low": lambda r: int(r.get("tcp.time_delta", 1) < 0.001),

        # RTT initial très faible
        # Souvent observé pour des scripts ou outils automatisés
        "initial_rtt_suspect": lambda r: int(
            0 < r.get("tcp.analysis_initial_rtt", 1) < 0.01
        ),

        # Méthode HTTP absente
        # Correspond souvent à un scan TCP ou une tentative incomplète
        "http_method_missing": lambda r: int(r.get("http.request_method") is None),

        # Méthode HTTP inhabituelle
        # Souvent utilisée pour tests, fuzzing ou exploitation
        "http_method_suspect": lambda r: int(
            str(r.get("http.request_method")).upper()
            not in {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"}
            if r.get("http.request_method") is not None else 0
        ),

        # URI absente ou vide
        # Indique souvent un scan ou une requête malformée
        "http_uri_missing": lambda r: int(r.get("http.request_uri") is None),

        # URI très longue
        # Typique des fuzzers, injections ou tentatives d’exploitation
        "http_uri_too_long": lambda r: int(
            len(str(r.get("http.request_uri", ""))) > 200
        ),

        # Présence de paramètres de requête
        # Surface d’attaque accrue (injection, traversal, etc.)
        "http_has_query": lambda r: int(
            r.get("http.request_uri_query") is not None
        ),

        # User-Agent absent
        # Fréquent dans les scans et outils automatisés
        "missing_user_agent": lambda r: int(r.get("http.user_agent") is None),

        # User-Agent très court
        # Indice de bot ou d’outil minimaliste
        "short_user_agent": lambda r: int(
            0 < len(str(r.get("http.user_agent", ""))) < 10
        ),

        # Header Host absent
        # Non conforme HTTP/1.1, souvent vu dans des scans
        "missing_host_header": lambda r: int(r.get("http.host") is None),

        # Content-Length anormalement grand
        # Peut indiquer tentative de DoS ou upload malveillant
        "content_length_large": lambda r: int(
            r.get("http.content_length", 0) is not None
            and r.get("http.content_length", 0) > 1_000_000
        ),

        # Données HTTP présentes sans méthode POST/PUT
        # Souvent observé dans des requêtes malformées ou fuzzées
        "unexpected_http_body": lambda r: int(
            r.get("http.data_len", 0) > 0
            and str(r.get("http.request_method")).upper() not in {"POST", "PUT"}
        ),

        # Multipart HTTP (upload de fichiers, formulaires complexes)
        # Signal structurel utile sans analyser le contenu
        "mime_multipart": lambda r: int(
            r.get("mime_multipart.type") is not None
        ),

        # Réutilisation anormale du même port TCP
        # Typique de certains scanners HTTP agressifs
        "tcp_reused_ports": lambda r: int(
            r.get("tcp.analysis_reused_ports", 0) == 1
        ),

        "tcp_retransmissions": lambda row: 1 if row.get("tcp.analysis_retransmission") else 0,  
        # Indique une retransmission TCP (anomalie possible)

        "tcp_out_of_order": lambda row: 1 if row.get("tcp.analysis_out_of_order") else 0,  
        # Paquets hors séquence

        "tcp_dup_ack": lambda row: int(row.get("tcp.analysis_duplicate_ack") or 0),  
        # ACK dupliqués (souvent scans ou attaques)

        "tcp_payload_len": lambda row: len(str(row.get("tcp.payload")) or ""),  
        # Taille du payload TCP brut

        # -----------------------------
        #      Features dérivées
        # -----------------------------

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