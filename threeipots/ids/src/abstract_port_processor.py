from abc import ABC, abstractmethod
from joblib import load
import pandas as pd


class AbstractPortProcessor(ABC):

    def __init__(self, name):
        self.model = load('../models/'+ name + '.joblib')
        self.columns = pd.read_csv('../columns/' + name +'.csv', header=None)[0].tolist()

    def transformer(self, trame):
        return trame[self.columns]

    @abstractmethod
    def predict(self):
        pass