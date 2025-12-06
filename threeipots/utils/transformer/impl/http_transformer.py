from ..protocol_transformer import ProtocolTransformer
from .. import register_transformer

@register_transformer
class HttpTransformer(ProtocolTransformer):

    NAME = "HTTP"

    TRANSFORMATION = {

    }

    @property
    def NAME(self):
        return self.__class__.NAME
    
    @property
    def TRANSFORMATIONS(self) -> dict :
        return self.__class__.TRANSFORMATION