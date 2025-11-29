from abstract_port_processor import AbstractPortProcessor

class SmtpProcessor(AbstractPortProcessor):

    NAME = "SMTP"

    def __init__(self):
        super(self.NAME)
        # TODO nom des colonnes a récup
        self.columns = []

    def predict(self, trame):
        # TODO Garder que les features que l'on a besoin
        # TODO Creer X un dataframe d'une ligne
        x = trame
        return self.pipeline.predict(x)