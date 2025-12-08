from ..protocol_transformer import ProtocolTransformer
from .. import register_transformer
from ...protocol import Protocol

@register_transformer
class RawTransformer(ProtocolTransformer):

    NAME = Protocol.RAW

    TRANSFORMATIONS = {
        # ===================== 1) Informations IP/TCP ===================== #

        "src_ip": lambda row: row.get("ip.src"),  # Adresse IP source
        "dst_ip": lambda row: row.get("ip.dst"),  # Adresse IP destination

        "src_port": lambda row: row.get("tcp.srcport"),  # Port source TCP
        "dst_port": lambda row: row.get("tcp.dstport"),  # Port destination TCP

        # Longueur du segment TCP (identifie bursts et trames suspectes).
        "tcp_len": lambda row: int(row.get("tcp.len", 0)),

        # Flags TCP utilisés pour fingerprinting des attaquants.
        "tcp_flags": lambda row: str(row.get("tcp.flags", "")),


        # ===================== 2) Payload RAW brut ===================== #

        # Payload brut tel que capturé.
        "raw_payload": lambda row: str(row.get("tcp.payload") or row.get("DATA.data") or ""),

        # Longueur du payload RAW.
        "raw_payload_len": lambda row: len(
            str(row.get("tcp.payload") or row.get("DATA.data") or "")
        ),

        # Entropie du payload, utile pour repérer du chiffrement, de la compression ou du fuzzing.
        "raw_payload_entropy": lambda row: ProtocolTransformer.entropy(
            str(row.get("tcp.payload") or row.get("DATA.data") or "")
        ),


        # ===================== 3) Détection de commandes PJL ===================== #

        # Détection générique de "@PJL", signature principale des attaques 9100.
        "contains_pjl": lambda row: int(
            "@PJL" in str(row.get("tcp.payload", "")).upper()
        ),

        # Détection de la commande FSUPLOAD (exfiltration depuis imprimante).
        "contains_pjl_fsupload": lambda row: int(
            "FSUPLOAD" in str(row.get("tcp.payload", "")).upper()
        ),

        # Détection de la commande FSDOWNLOAD (malware upload dans la RAM imprimante).
        "contains_pjl_fsdownload": lambda row: int(
            "FSDOWNLOAD" in str(row.get("tcp.payload", "")).upper()
        ),

        # Détection de la commande INFO (reconnaissance système).
        "contains_pjl_info": lambda row: int(
            "INFO" in str(row.get("tcp.payload", "")).upper()
        ),

        # Détection de SET (modification de configuration).
        "contains_pjl_set": lambda row: int(
            "SET " in str(row.get("tcp.payload", "")).upper()
        ),


        # ===================== 4) Analyse statistique du contenu ===================== #

        # Ratio de majuscules (souvent élevé dans PJL et les attaques).
        "uppercase_ratio": lambda row: (
            sum(1 for c in str(row.get("tcp.payload", "")) if c.isupper()) /
            len(str(row.get("tcp.payload", "")))
            if row.get("tcp.payload") else 0
        ),

        # Ratio de chiffres (utile pour repérer des paramètres PJL, du fuzzing).
        "digit_ratio": lambda row: (
            sum(1 for c in str(row.get("tcp.payload", "")) if c.isdigit()) /
            len(str(row.get("tcp.payload", "")))
            if row.get("tcp.payload") else 0
        ),

        # Ratio de symboles non alphanumériques (exploit patterns).
        "symbol_ratio": lambda row: (
            sum(1 for c in str(row.get("tcp.payload", "")) if not c.isalnum()) /
            len(str(row.get("tcp.payload", "")))
            if row.get("tcp.payload") else 0
        ),

        # Détection de caractères non ASCII (exploits, fuzzing).
        "contains_non_ascii": lambda row: int(
            any(ord(c) < 32 or ord(c) > 126 for c in str(row.get("tcp.payload") or ""))
        ),


        # ===================== 5) Séquences RAW suspectes ===================== #

        # Détection de null bytes, souvent utilisés dans les exploiteurs.
        "contains_null_bytes": lambda row: int(
            "\\x00" in str(row.get("tcp.payload", ""))
        ),

        # Détection de patterns répétitifs typiques des fuzzers ou exploit dev.
        "repeated_patterns": lambda row: int(
            any(pattern in str(row.get("tcp.payload", ""))
                for pattern in ["AAAA", "BBBB", "CCCC", "DDDD", "\x90\x90"])
        ),

        # Détection du caractère ESC (0x1B), utilisé dans les formats PCL/ESC.
        "contains_esc": lambda row: int(
            "\x1B" in str(row.get("tcp.payload", ""))
        )
    }

