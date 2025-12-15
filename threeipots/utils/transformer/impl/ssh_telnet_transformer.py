from ..protocol_transformer import ProtocolTransformer
from .. import register_transformer
from ...protocol import Protocol

@register_transformer
class SshTelnetTransformer(ProtocolTransformer):

    NAME = Protocol.SSH_TELNET

    TRANSFORMATIONS = {
        
        "flow_id": lambda row: tuple(sorted([
            (row["ip.src"], row["tcp.srcport"]),
            (row["ip.dst"], row["tcp.dstport"])
        ])),

        # ===================== TEMPS ===================== #
        "time_delta": lambda row: float(row.get("tcp.time_delta", 0)),  # Temps écoulé depuis le paquet précédent dans le même flux
        "time_relative": lambda row: float(row.get("tcp.time_relative", 0)),  # Temps relatif depuis le début de la capture
        "is_fast_packets": lambda row: float(row.get("tcp.time_delta", 1)) < 0.001,  # True si deux paquets arrivent très vite (brute-force)

        # ===================== TAILLES / LONGUEURS ===================== #
        "packet_length": lambda row: int(row.get("tcp.len", 0)),  # Longueur du segment TCP
        "ip_total_length": lambda row: int(row.get("ip.len", 0)),  # Longueur totale du paquet IP
        "tcp_payload_length": lambda row: len(str(row.get("tcp.payload", ""))),  # Taille du payload TCP
        "reassembled_length": lambda row: int(row.get("DATA.tcp_reassembled_length", 0)),  # Longueur totale reconstruite du flux TCP

        # ===================== FLAGS TCP ===================== #
        "flag_syn": lambda row: row.get("tcp.flags_syn") == "1",  # Drapeau SYN (début de connexion)
        "flag_ack": lambda row: row.get("tcp.flags_ack") == "1",  # Drapeau ACK (accusé de réception)
        "flag_fin": lambda row: row.get("tcp.flags_fin") == "1",  # Drapeau FIN (fin normale)
        "flag_rst": lambda row: row.get("tcp.flags_reset") == "1",  # Drapeau RST (réinitialisation)
        "flag_push": lambda row: row.get("tcp.flags_push") == "1",  # Drapeau PUSH (envoi immédiat)

        # ===================== ANALYSE TCP ===================== #
        "is_retransmission": lambda row: bool(row.get("tcp.analysis_retransmission")),  # Paquet retransmis (perte, tempête, DOS)
        "is_out_of_order": lambda row: bool(row.get("tcp.analysis_out_of_order")),  # Paquet reçu hors ordre (flood)
        "dup_ack": lambda row: int(row.get("tcp.analysis_duplicate_ack_num", 0)),  # Nombre d’ACK dupliqués
        "initial_rtt": lambda row: float(row.get("tcp.analysis_initial_rtt", 0)),  # Temps de latence initial du flux TCP

        # ===================== FENÊTRE / CONTRÔLE FLUX ===================== #
        "window_size": lambda row: int(row.get("tcp.window_size_value", 0)),  # Fenêtre TCP brute (bande passante / stabilité)
        "window_scale": lambda row: int(row.get("tcp.window_size_scalefactor", 1)),  # Facteur d’échelle de la fenêtre TCP
        "bytes_in_flight": lambda row: int(row.get("tcp.analysis_bytes_in_flight", 0)),  # Octets non confirmés en vol

        # ===================== IP ===================== #
        "ttl": lambda row: int(row.get("ip.ttl", 0)),  # Time To Live (TTL)
        "is_private_src": lambda row: str(row.get("ip.src","")).startswith(("10.","192.168.","172.")),  # True si source réseau privé

        # ===================== SSH ===================== #
        "is_ssh": lambda row: bool(row.get("ssh.protocol")),  # True si paquet SSH
        "ssh_packet_length": lambda row: int(row.get("ssh.packet_length", 0)),  # Longueur du paquet SSH
        "is_ssh_kex": lambda row: bool(row.get("ssh.kex_algorithms")),  # True si échange de clés SSH (KEX)
        "ssh_encrypted": lambda row: bool(row.get("ssh.encrypted_packet")),  # True si paquet chiffré

        # ===================== TELNET ===================== #
        "is_telnet": lambda row: bool(row.get("telnet.cmd") or row.get("telnet.data")),  # True si paquet Telnet
        "is_telnet_cmd": lambda row: bool(row.get("telnet.cmd")),  # True si paquet contient commande Telnet

        # ===================== ENTROPIE DU PAYLOAD ===================== #
        "payload_entropy": lambda row: ProtocolTransformer.entropy(str(row.get("tcp.payload", ""))),  # Entropie du payload (SSH élevé, brute-force faible)

        # ===================== MALFORMED / ALERTES ===================== #
        "ws_malformed": lambda row: bool(row.get("_ws.malformed.expert"))  # True si paquet corrompu / structure anormale

    }

