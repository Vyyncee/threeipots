from abc import ABC, abstractmethod
import math
from collections import Counter
import re

class ProtocolTransformer(ABC):

    NAME: str
    TRANSFORMATIONS: dict

    @staticmethod
    def entropy(s):
        if isinstance(s, str) and len(s) > 0:
            if not s:
                return 0
            p = [count/len(s) for count in Counter(str(s)).values()]
            return -sum(x * math.log2(x) for x in p)
        return 0

    @staticmethod
    def path_depth(path):
        if not isinstance(path, str) or not path:
            return 0
        return len([x for x in path.split('/') if x])

    @staticmethod
    def special_char_ratio(s):
        if not isinstance(s, str) or not s:
            return 0
        special = re.findall(r"[^a-zA-Z0-9]", s)
        return len(special) / max(1, len(s))

    @classmethod
    def apply(classe, row):
        output = {}
        for feature, func in classe.TRANSFORMATIONS.items():
            try:
                output[feature] = func(row)
            except Exception as e:
                output[feature] = None
                print(f"[{classe.NAME.name}] Erreur pour {feature}: {e}")
        return output
