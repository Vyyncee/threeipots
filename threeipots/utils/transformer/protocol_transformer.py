from abc import ABC, abstractmethod
import math
from collections import Counter

class ProtocolTransformer(ABC):

    @property
    @abstractmethod
    def NAME(self) -> str:
        pass

    @property
    @abstractmethod
    def TRANSFORMATIONS(self) -> dict:
        pass

    @staticmethod
    def entropy(s):
        if not s:
            return 0
        p = [count/len(s) for count in Counter(str(s)).values()]
        return -sum(x * math.log2(x) for x in p)

    @classmethod
    def apply(classe, row):
        output = {}
        for feature, func in classe.TRANSFORMATIONS.items():
            try:
                output[feature] = func(row)
            except Exception as e:
                output[feature] = None
                print(f"[{classe.name}] Erreur pour {feature}: {e}")
        return output
