from abstract_port_processor import AbstractPortProcessor

class IppRawLpdProcessor(AbstractPortProcessor):

    NAME = "IPP_RAW_LPD"

    def __init__(self):
        super(self.NAME)
        # TODO nom des colonnes a récup
        self.columns = []

    def predict(self, x):
        # TODO Garder que les features que l'on a besoin
        return self.pipeline.predict(x)