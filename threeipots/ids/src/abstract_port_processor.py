from abc import ABC, abstractmethod
from joblib import load
import pandas as pd
import os

from ...utils.transformer.transform import transform_row
from ...utils.protocol import Protocol


class AbstractPortProcessor(ABC):

    NAME: Protocol

    def __init__(self):
        # Retrieve model
        model_path = os.path.join(
            os.path.dirname(__file__),
            '..', 'models', f'{self.NAME.name}.joblib'
        )
        model_path = os.path.abspath(model_path)
        self.model = load(model_path)

        columns_path = os.path.join(
            os.path.dirname(__file__),
            '..', 'columns', f'{self.NAME.name}.joblib'
        )
        columns_path = os.path.abspath(columns_path)
        self.columns = load(columns_path)

    def transformer(self, trame):
        trame = pd.DataFrame(trame.apply(lambda row: transform_row(row, self.NAME), axis=1).tolist())
        return trame[self.columns.keys()]

    def predict(self, x):
        x = self.transformer(x)

        # Prédiction
        pred = self.model.predict(x)
        x['label'] = int(pred[0])

        # Enregistrement
        path = os.path.join(
            os.path.dirname(__file__),
            '..', 'front/public/result', f'{self.NAME.name}.joblib'
        )
        x.to_csv(
            path,
            mode='a',
            index=False,
            header=False
        )