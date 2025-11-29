from abstract_port_processor import AbstractPortProcessor

class HttpProcessor(AbstractPortProcessor):

    NAME = "HTTP"

    def __init__(self):
        super(self.NAME)

    def predict(self, x):
        x = self.transformer(x)
        return self.model.predict(x)