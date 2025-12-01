from abc import ABC, abstractmethod
from joblib import load
import pandas as pd
import os


class AbstractPortProcessor(ABC):

    def __init__(self, name):
        model_path = os.path.join(
            os.path.dirname(__file__),
            '..', 'models', f'{name}.joblib'
        )
        model_path = os.path.abspath(model_path)
        self.model = load(model_path)

        columns_path = os.path.join(
            os.path.dirname(__file__),
            '..', 'columns', f'{name}.joblib'
        )
        columns_path = os.path.abspath(columns_path)
        self.columns = load(columns_path)

    def transformer(self, trame):
        # Gestion des colonnes manquantes
        for key, value in self.columns.items():
            if key not in trame.columns:
                if value:
                    trame[key] = ''
                else:
                    trame[key] = 0

        return trame[self.columns.keys()]

    @abstractmethod
    def predict(self):
        pass