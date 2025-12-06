from ..protocol_transformer import ProtocolTransformer
from .. import register_transformer

@register_transformer
class SshTelnetTransformer(ProtocolTransformer):

    NAME = "SSH_TELNET"

    TRANSFORMATION = {
        # ===================== TEMPS ===================== #

        # Temps écoulé depuis le paquet précédent dans le même flux
        "time_delta": lambda row: float(row.get("tcp.time_delta", 0)),

        # Temps relatif depuis le début de la capture
        "time_relative": lambda row: float(row.get("tcp.time_relative", 0)),

        # Indique si deux paquets arrivent extrêmement vite (signes de brute-force)
        "is_fast_packets": lambda row: 1 if float(row.get("tcp.time_delta", 1)) < 0.001 else 0,


        # ===================== TAILLES / LONGUEURS ===================== #

        # Longueur du segment TCP
        "packet_length": lambda row: int(row.get("tcp.len", 0)),

        # Longueur totale du paquet IP
        "ip_total_length": lambda row: int(row.get("ip.len", 0)),

        # Taille du payload TCP en caractères (utile pour Telnet / commandes)
        "tcp_payload_length": lambda row: len(str(row.get("tcp.payload", ""))),

        # Longueur totale reconstruite du flux TCP (assemblage)
        "reassembled_length": lambda row: int(row.get("DATA.tcp_reassembled_length", 0)),


        # ===================== FLAGS TCP ===================== #

        # Drapeau SYN (début de connexion)
        "flag_syn": lambda row: 1 if row.get("tcp.flags_syn") == "1" else 0,

        # Drapeau ACK (accusé de réception)
        "flag_ack": lambda row: 1 if row.get("tcp.flags_ack") == "1" else 0,

        # Drapeau FIN (fin normale d’une connexion)
        "flag_fin": lambda row: 1 if row.get("tcp.flags_fin") == "1" else 0,

        # Drapeau RST (réinitialisation, souvent suspect)
        "flag_rst": lambda row: 1 if row.get("tcp.flags_reset") == "1" else 0,

        # Drapeau PUSH (envoi immédiat, typique Telnet / commande interactive)
        "flag_push": lambda row: 1 if row.get("tcp.flags_push") == "1" else 0,

        # Score de dangerosité basé sur la présence de flags suspects
        "flags_score": lambda row: sum([
            1 if row.get("tcp.flags_syn") == "1" else 0,
            1 if row.get("tcp.flags_fin") == "1" else 0,
            1 if row.get("tcp.flags_reset") == "1" else 0,
            1 if row.get("tcp.flags_urg") == "1" else 0,
            1 if row.get("tcp.flags_cwr") == "1" else 0
        ]),


        # ===================== ANALYSE TCP ===================== #

        # Indique un paquet retransmis (perte, tempête, DOS)
        "is_retransmission": lambda row: 1 if row.get("tcp.analysis_retransmission") else 0,

        # Paquet reçu hors ordre (flood / déstabilisation du flux)
        "is_out_of_order": lambda row: 1 if row.get("tcp.analysis_out_of_order") else 0,

        # Nombre d’ACK dupliqués (pertes ou attaque)
        "dup_ack": lambda row: int(row.get("tcp.analysis_duplicate_ack_num", 0)),

        # Temps de latence initial du flux TCP
        "initial_rtt": lambda row: float(row.get("tcp.analysis_initial_rtt", 0)),


        # ===================== FENÊTRE / CONTRÔLE FLUX ===================== #

        # Fenêtre TCP brute (indicateur de bande passante et stabilité)
        "window_size": lambda row: int(row.get("tcp.window_size_value", 0)),

        # Facteur d’échelle de la fenêtre (amplifie la fenêtre TCP)
        "window_scale": lambda row: int(row.get("tcp.window_size_scalefactor", 1)),

        # Nombre d’octets encore non confirmés (activité/risk)
        "bytes_in_flight": lambda row: int(row.get("tcp.analysis_bytes_in_flight", 0)),


        # ===================== IP ===================== #

        # Time To Live (TTL) — utile pour identifier bots IoT / scans
        "ttl": lambda row: int(row.get("ip.ttl", 0)),

        # Indique si la source est dans un réseau privé (trafic interne vs externe)
        "is_private_src": lambda row: 1 if str(row.get("ip.src","")).startswith(("10.","192.168.","172.")) else 0,


        # ===================== SSH ===================== #

        # Indique si le paquet appartient à SSH
        "is_ssh": lambda row: 1 if row.get("ssh.protocol") else 0,

        # Longueur du paquet SSH (utile pour distinguer commandes/encrypted)
        "ssh_packet_length": lambda row: int(row.get("ssh.packet_length", 0)),

        # Présence d’un échange de clés (KEX)
        "is_ssh_kex": lambda row: 1 if row.get("ssh.kex_algorithms") else 0,

        # Indique que le paquet est chiffré (normal, sauf avant authent)
        "ssh_encrypted": lambda row: 1 if row.get("ssh.encrypted_packet") else 0,


        # ===================== TELNET ===================== #

        # Indique que c’est du Telnet
        "is_telnet": lambda row: 1 if row.get("telnet.cmd") or row.get("telnet.data") else 0,

        # Indique un paquet contenant une commande Telnet
        "is_telnet_cmd": lambda row: 1 if row.get("telnet.cmd") else 0,


        # ===================== ENTROPIE DU PAYLOAD ===================== #

        # Entropie du payload (SSH = élevé, malware brute-force = faible)
        "payload_entropy": lambda row: ProtocolTransformer.entropy(str(row.get("tcp.payload", ""))),


        # ===================== MALFORMED / ALERTES ===================== #

        # Paquet corrompu / structure anormale
        "ws_malformed": lambda row: 1 if row.get("_ws.malformed.expert") else 0,

        # Niveau des alertes expert Wireshark (0 = OK → 3 = critical)
        "expert_severity": lambda row: int(row.get("tcp._ws_expert_severity", 0)),


        # ===================== FLUX ===================== #

        # Identifiant de flux TCP (permet regroupement)
        "stream_id": lambda row: int(row.get("tcp.stream", -1)),
    }

    @property
    def NAME(self):
        return self.__class__.NAME
    
    @property
    def TRANSFORMATIONS(self) -> dict :
        return self.__class__.TRANSFORMATION

