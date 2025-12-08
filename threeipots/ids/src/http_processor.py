from .abstract_port_processor import AbstractPortProcessor
from ...utils.protocol import Protocol

class HttpProcessor(AbstractPortProcessor):

    NAME = Protocol.HTTP.name

    @property
    def NAME(self):
        return self.__class__.NAME

    def __init__(self):
        super().__init__(self.NAME)