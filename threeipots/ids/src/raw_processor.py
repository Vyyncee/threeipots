from .abstract_port_processor import AbstractPortProcessor
from ...utils.protocol import Protocol

class RawProcessor(AbstractPortProcessor):

    NAME = Protocol.RAW

    def __init__(self):
        super().__init__(self.NAME)