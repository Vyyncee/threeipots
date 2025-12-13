from .abstract_port_processor import AbstractPortProcessor
from threeipots.utils.protocol import Protocol

class HttpProcessor(AbstractPortProcessor):

    NAME = Protocol.HTTP

    def __init__(self):
        super().__init__()