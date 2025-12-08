class PacketUtils:

    @staticmethod
    def toDict(pkt):
        dict = {}

        for layer in pkt.layers:
            for field in layer.field_names:
                key = f"{layer.layer_name}.{field}"
                value = getattr(layer, field, None)
                dict[key] = str(value)

        return dict