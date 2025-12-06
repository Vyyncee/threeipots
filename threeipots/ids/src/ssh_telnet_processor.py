from .abstract_port_processor import AbstractPortProcessor

class SshTelnetProcessor(AbstractPortProcessor):

    NAME = "SSH_TELNET"

    @property
    def NAME(self):
        return self.__class__.NAME

    def __init__(self):
        super().__init__(self.NAME)

    def predict(self, x):
        x = super().transformer(x)
        return self.model.predict(x)