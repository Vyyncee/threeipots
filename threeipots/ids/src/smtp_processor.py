from .abstract_port_processor import AbstractPortProcessor

class SmtpProcessor(AbstractPortProcessor):

    NAME = "SMTP"

    @property
    def NAME(self):
        return self.__class__.NAME

    def __init__(self):
        super().__init__(self.NAME)

    def predict(self, trame):
        x = super().transformer(x)
        return self.model.predict(x)