from . import TRANSFORMER_REGISTRY

def transform_row(row, protocol):
    """
    row : une ligne du DataFrame
    protocol : "SSH_TELNET", "HTTP", "SMTP", etc.
    """
    transformer = TRANSFORMER_REGISTRY.get(protocol)

    if transformer is None:
        raise ValueError(f"Protocole inconnu : {protocol}")

    return transformer.apply(row)