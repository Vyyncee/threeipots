from ..protocol_transformer import ProtocolTransformer
from .. import register_transformer

@register_transformer
class IppRawLpdTransformer(ProtocolTransformer):

    NAME = "IPP_RAW_LPD"

    TRANSFORMATION = {

    }

    @property
    def NAME(self):
        return self.__class__.NAME
    
    @property
    def TRANSFORMATIONS(self) -> dict :
        return self.__class__.TRANSFORMATION

