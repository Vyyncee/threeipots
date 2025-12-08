from . import TRANSFORMER_REGISTRY

# Import des transformer
from .impl.ssh_telnet_transformer import SshTelnetTransformer
from .impl.http_transformer import HttpTransformer
from .impl.raw_transformer import RawTransformer
from .impl.smtp_transformer import SmtpTransformer

def transform_row(row, protocol):
    """
    row : une ligne du DataFrame
    protocol : Emun.Protocol
    """

    transformer = TRANSFORMER_REGISTRY.get(protocol)

    if transformer is None:
        raise ValueError(f"Protocole inconnu : {protocol}")

    return transformer.apply(row)