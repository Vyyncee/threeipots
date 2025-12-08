from src.port_factory import PortFactory
import pyshark
import queue
import threading
import pandas as pd
from utils.protocol import Protocol
from utils.packet_utils import PacketUtils


# Construire le filtre
# Récupérer tous les ports
all_ports = [str(port) for proto in Protocol for port in proto.value]
PORT_FILTER = " or ".join(f"tcp port {port}" for port in all_ports)

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

        dict = PacketUtils.toDict(pkt)

        trame = pd.DataFrame([dict])

        processor = portFactory.create_processor(trame)

        if processor is None:
            continue

        prediction = processor.predict(trame)
        trame['label'] = int(prediction[0])

        if int(prediction[0]) == 0 :
            print(green(trame))
        else:
            print(red(trame))

        # TODO
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