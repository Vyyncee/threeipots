from .abstract_port_processor import AbstractPortProcessor
from threeipots.utils.protocol import Protocol

class SmtpProcessor(AbstractPortProcessor):

    NAME = Protocol.SMTP

    def __init__(self):
        super().__init__()