from abstract_port_processor import AbstractPortProcessor

class SshTelnetProcessor(AbstractPortProcessor):

    NAME = "SSH_TELNET"

    def __init__(self):
        super(self.NAME)

    def predict(self, x):
        return self.pipeline.predict(x)