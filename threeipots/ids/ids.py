from src.port_factory import PortFactory
import pyshark
import queue
import threading
import pandas as pd

PORT_FILTER = "tcp port 80 or tcp port 22 or tcp port 23 or tcp port 25 or tcp port 587 or tcp port 9100"
CSV_FILE = "./threeipots/ids/result.csv"

packet_queue = queue.Queue()

def green(text):
    return f"\033[92m{text}\033[0m"

def red(text):
    return f"\033[91m{text}\033[0m"

def packet_worker():
    portFactory = PortFactory()

    while True:
        pkt = packet_queue.get()

        if pkt is None:
            continue

        flat = {}

        # key: Nom de la colonne, valeur: Valeur de la trame
        for layer in pkt.layers:
            for field in layer.field_names:
                key = f"{layer.layer_name}.{field}"
                value = getattr(layer, field, None)
                flat[key] = str(value)

        trame = pd.DataFrame([flat])

        processor = portFactory.create_processor(trame)

        if processor is None:
            continue

        prediction = processor.predict(trame)
        trame['label'] = int(prediction[0])

        if int(prediction[0]) == 0 :
            print(green(trame))
        else:
            print(red(trame))

        # TODO ça marche pas
        # Enregistrement dans un fichier csv
        trame.to_csv(
            CSV_FILE,
            mode='a',
            index=False,
            header=False
        )

        packet_queue.task_done()

threading.Thread(target=packet_worker, daemon=True).start()

capture = pyshark.LiveCapture(
    interface='eno1',
    bpf_filter=PORT_FILTER
)

for pkt in capture.sniff_continuously():
    packet_queue.put(pkt)