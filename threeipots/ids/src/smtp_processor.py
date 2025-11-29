from abstract_port_processor import AbstractPortProcessor

class SmtpProcessor(AbstractPortProcessor):

    NAME = "SMTP"

    def __init__(self):
        super(self.NAME)

    def predict(self, trame):
        x = self.transformer(x)
        return self.model.predict(x)