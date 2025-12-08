from .abstract_port_processor import AbstractPortProcessor
from ...utils.protocol import Protocol

class SshTelnetProcessor(AbstractPortProcessor):

    NAME = Protocol.SSH_TELNET.name

    @property
    def NAME(self):
        return self.__class__.NAME

    def __init__(self):
        super().__init__(self.NAME)