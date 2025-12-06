TRANSFORMER_REGISTRY = {}

def register_transformer(transformer_class):
    TRANSFORMER_REGISTRY[transformer_class.NAME] = transformer_class
    return transformer_class