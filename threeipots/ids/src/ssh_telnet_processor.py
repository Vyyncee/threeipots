from .abstract_port_processor import AbstractPortProcessor
from threeipots.utils.protocol import Protocol

class SshTelnetProcessor(AbstractPortProcessor):

    NAME = Protocol.SSH_TELNET

    def __init__(self):
        super().__init__()