from abc import ABC, abstractmethod
from joblib import load


class AbstractPortProcessor(ABC):

    def __init__(self, name):
        self.pipeline = load('../models/'+ name + '.joblib')

    @abstractmethod
    def predict(self):
        pass