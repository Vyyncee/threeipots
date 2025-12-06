from abc import ABC, abstractmethod
from joblib import load
import pandas as pd
import os

from ...utils.transformer.transform import transform_row


class AbstractPortProcessor(ABC):

    @property
    @abstractmethod
    def NAME(self) -> str:
        pass

    def __init__(self):
        model_path = os.path.join(
            os.path.dirname(__file__),
            '..', 'models', f'{self.NAME}.joblib'
        )
        model_path = os.path.abspath(model_path)
        self.model = load(model_path)

        columns_path = os.path.join(
            os.path.dirname(__file__),
            '..', 'columns', f'{self.NAME}.joblib'
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

        return trame.apply(lambda row: transform_row(row, self.NAME), axis=1)

    @abstractmethod
    def predict(self):
        pass